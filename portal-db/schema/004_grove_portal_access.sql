-- ============================================================================
-- AUTH0 JWT INTEGRATION FOR FRONTEND USER ACCESS
-- ============================================================================
-- This migration adds user-scoped access control for frontend users
-- authenticating via Auth0. Existing roles (portal_db_admin, portal_db_reader)
-- remain unchanged and are used by backend services.
--
-- Overview:
-- - Creates 'authenticated_user' role for Auth0-authenticated frontend users
-- - Implements Row-Level Security (RLS) policies based on portal_account_rbac
-- - Users can only access portal accounts/applications they have RBAC permissions for
-- - Permission levels: 'legacy_read' (SELECT) and 'legacy_write' (INSERT/UPDATE/DELETE)
-- ============================================================================

-- ============================================================================
-- ROLES
-- ============================================================================

-- New role for Auth0-authenticated frontend users
CREATE ROLE authenticated_user NOLOGIN;
COMMENT ON ROLE authenticated_user IS 'Role for Auth0-authenticated frontend users with user-scoped RLS policies';

-- Allow PostgREST authenticator to impersonate this role
GRANT authenticated_user TO authenticator;

-- ============================================================================
-- SCHEMA ACCESS
-- ============================================================================

-- Grant schema access
GRANT USAGE ON SCHEMA public, api TO authenticated_user;

-- ============================================================================
-- TABLE PERMISSIONS
-- ============================================================================

-- Grant table access (users will only be able to see/modify their own data via RLS)
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    portal_accounts,
    portal_account_rbac,
    portal_applications,
    portal_users
TO authenticated_user;

-- Grant access to public tables used by the UI (read-only, contains no sensitive data)
GRANT SELECT ON TABLE
    services,
    portal_plans
TO authenticated_user;

-- Grant access to portal_user_auth for JWT sub claim lookup
GRANT SELECT ON TABLE portal_user_auth TO authenticated_user;

-- Grant sequence access for inserts
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authenticated_user;

-- ============================================================================
-- HELPER FUNCTION: Extract portal_user_id from Auth0 JWT sub claim
-- ============================================================================

CREATE OR REPLACE FUNCTION api.current_portal_user_id()
RETURNS VARCHAR(36) AS $$
DECLARE
    auth_sub TEXT;
    user_id VARCHAR(36);
BEGIN
    -- Prefer upstream Auth0 subject if provided, otherwise fallback to standard sub
    auth_sub := COALESCE(
        current_setting('request.jwt.claims', true)::json->>'auth0_sub',
        current_setting('request.jwt.claims', true)::json->>'sub'
    );

    IF auth_sub IS NULL THEN
        RETURN NULL;
    END IF;

    -- Look up portal_user_id from portal_user_auth
    SELECT pua.portal_user_id INTO user_id
    FROM public.portal_user_auth pua
    WHERE pua.auth_provider_user_id = auth_sub
    LIMIT 1;

    RETURN user_id;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

COMMENT ON FUNCTION api.current_portal_user_id() IS 'Extracts portal_user_id from Auth0 JWT sub claim by looking up auth_provider_user_id';

-- =========================================================================
-- RPC: Ensure portal user and mapping (admin-triggered, explicit params)
-- =========================================================================
-- Intended for backend service calls using a portal_db_admin JWT via PostgREST.
-- Upserts a portal_users row by email and ensures a portal_user_auth mapping
-- for the provided provider/type/user_id.
--
-- Usage (PostgREST):
--   POST /rpc/ensure_portal_user
--   {
--     "p_email": "user@example.com",
--     "p_auth_provider": "auth0",          -- or 'clerk'
--     "p_auth_type": "auth0_username",     -- or 'auth0_github', 'clerk_google', etc.
--     "p_auth_provider_user_id": "auth0|abc123",
--     "p_federated": true                   -- optional
--   }
-- Returns: { portal_user_id, portal_user_email }

CREATE OR REPLACE FUNCTION api.ensure_portal_user(
    p_email TEXT,
    p_auth_provider portal_auth_provider,
    p_auth_type portal_auth_type,
    p_auth_provider_user_id TEXT,
    p_federated BOOL DEFAULT FALSE
)
RETURNS TABLE (
  portal_user_id    VARCHAR(36),
  portal_user_email VARCHAR(255)
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = public, pg_catalog
AS $$
DECLARE
    v_user_id VARCHAR(36);
    v_deleted_at TIMESTAMPTZ;
BEGIN
    IF p_email IS NULL OR length(trim(p_email)) = 0 THEN
        RAISE EXCEPTION 'p_email is required';
    END IF;
    IF p_auth_provider_user_id IS NULL OR length(trim(p_auth_provider_user_id)) = 0 THEN
        RAISE EXCEPTION 'p_auth_provider_user_id is required';
    END IF;

    -- Step 1: Ensure a portal_users row exists for p_email
    -- Try to find any existing user by email (including soft-deleted)
    SELECT pu.portal_user_id, pu.deleted_at
        INTO v_user_id, v_deleted_at
    FROM public.portal_users pu
    WHERE pu.portal_user_email = p_email
    LIMIT 1;

        IF v_user_id IS NULL THEN
            -- No existing user, create a new one
            INSERT INTO public.portal_users AS pu (portal_user_id, portal_user_email, signed_up)
            VALUES (gen_random_uuid()::text, p_email, TRUE)
            RETURNING pu.portal_user_id INTO v_user_id;
        ELSIF v_deleted_at IS NOT NULL THEN
            -- Revive soft-deleted user for this email
            UPDATE public.portal_users AS pu
                 SET deleted_at = NULL,
                         signed_up   = TRUE,
                         updated_at  = CURRENT_TIMESTAMP
             WHERE pu.portal_user_id = v_user_id;
    END IF;

            -- Step 2: Ensure a portal_user_auth mapping exists for this provider/type/user_id
            UPDATE public.portal_user_auth AS pua
                 SET portal_user_id       = v_user_id,
                         portal_auth_provider = p_auth_provider,
                         portal_auth_type     = p_auth_type,
                         federated            = COALESCE(p_federated, FALSE),
                         updated_at           = CURRENT_TIMESTAMP
             WHERE pua.auth_provider_user_id = p_auth_provider_user_id;

            IF NOT FOUND THEN
                INSERT INTO public.portal_user_auth (
                    portal_user_id,
                    portal_auth_provider,
                    portal_auth_type,
                    auth_provider_user_id,
                    federated
                ) VALUES (
                    v_user_id,
                    p_auth_provider,
                    p_auth_type,
                    p_auth_provider_user_id,
                    COALESCE(p_federated, FALSE)
                );
            END IF;

    -- Return minimal result shape expected by RPC
    RETURN QUERY SELECT v_user_id, p_email::varchar(255);
END;
$$;

GRANT EXECUTE ON FUNCTION api.ensure_portal_user(TEXT, portal_auth_provider, portal_auth_type, TEXT, BOOL) TO portal_db_admin, anon;

-- ============================================================================
-- RLS POLICIES: portal_accounts (user-scoped access)
-- ============================================================================

-- Users can SELECT accounts they have RBAC access to
CREATE POLICY portal_accounts_user_select ON portal_accounts
    FOR SELECT
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            WHERE par.portal_user_id = api.current_portal_user_id()
        )
    );

-- Users can INSERT new accounts (WITH CHECK will verify they have write permission)
CREATE POLICY portal_accounts_user_insert ON portal_accounts
    FOR INSERT
    TO authenticated_user
    WITH CHECK (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'legacy_write' = ANY(r.permissions)
        )
    );

-- Users can UPDATE accounts where they have 'legacy_write' permission
CREATE POLICY portal_accounts_user_update ON portal_accounts
    FOR UPDATE
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'legacy_write' = ANY(r.permissions)
        )
    )
    WITH CHECK (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'legacy_write' = ANY(r.permissions)
        )
    );

-- Users can DELETE accounts where they have 'legacy_write' permission
CREATE POLICY portal_accounts_user_delete ON portal_accounts
    FOR DELETE
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'legacy_write' = ANY(r.permissions)
        )
    );

-- ============================================================================
-- RLS POLICIES: portal_applications (user-scoped access)
-- ============================================================================
-- Note: Application access inherits from parent account permissions

-- Users can SELECT applications if they have access to the parent account
CREATE POLICY portal_applications_user_select ON portal_applications
    FOR SELECT
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            WHERE par.portal_user_id = api.current_portal_user_id()
        )
    );

-- Users can INSERT applications if they have 'legacy_write' on parent account
CREATE POLICY portal_applications_user_insert ON portal_applications
    FOR INSERT
    TO authenticated_user
    WITH CHECK (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'legacy_write' = ANY(r.permissions)
        )
    );

-- Users can UPDATE applications if they have 'legacy_write' on parent account
CREATE POLICY portal_applications_user_update ON portal_applications
    FOR UPDATE
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'legacy_write' = ANY(r.permissions)
        )
    )
    WITH CHECK (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'legacy_write' = ANY(r.permissions)
        )
    );

-- Users can DELETE applications if they have 'legacy_write' on parent account
CREATE POLICY portal_applications_user_delete ON portal_applications
    FOR DELETE
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'legacy_write' = ANY(r.permissions)
        )
    );

-- ============================================================================
-- RLS POLICIES: portal_account_rbac (user-scoped access)
-- ============================================================================

-- Users can view their own RBAC entries
-- IMPORTANT: This policy must be simple to avoid infinite recursion when other
-- tables query portal_account_rbac. Users can only see RBAC rows that directly
-- reference their portal_user_id.
CREATE POLICY portal_account_rbac_user_select ON portal_account_rbac
    FOR SELECT
    TO authenticated_user
    USING (portal_user_id = api.current_portal_user_id());

-- Users can INSERT RBAC entries if they have 'legacy_write' on the account
CREATE POLICY portal_account_rbac_user_insert ON portal_account_rbac
    FOR INSERT
    TO authenticated_user
    WITH CHECK (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'legacy_write' = ANY(r.permissions)
        )
    );

-- Users can UPDATE RBAC entries if they have 'legacy_write' on the account
CREATE POLICY portal_account_rbac_user_update ON portal_account_rbac
    FOR UPDATE
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'legacy_write' = ANY(r.permissions)
        )
    )
    WITH CHECK (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'legacy_write' = ANY(r.permissions)
        )
    );

-- Users can DELETE RBAC entries if they have 'legacy_write' on the account
CREATE POLICY portal_account_rbac_user_delete ON portal_account_rbac
    FOR DELETE
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'legacy_write' = ANY(r.permissions)
        )
    );

-- ============================================================================
-- RLS POLICIES: portal_users (self-access only)
-- ============================================================================

-- Users can view their own user record
CREATE POLICY portal_users_self_select ON portal_users
    FOR SELECT
    TO authenticated_user
    USING (portal_user_id = api.current_portal_user_id());

-- Users can update their own record
CREATE POLICY portal_users_self_update ON portal_users
    FOR UPDATE
    TO authenticated_user
    USING (portal_user_id = api.current_portal_user_id())
    WITH CHECK (portal_user_id = api.current_portal_user_id());
