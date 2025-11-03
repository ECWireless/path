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
-- - Permission levels:
--   * 'read': View data (VIEWER role)
--   * 'write': Modify account data and use apps (MEMBER role)
--   * 'admin': Create/delete apps, manage users, invite/remove team members (ADMIN role)
--   * OWNER: Same as ADMIN + billing, account deletion, ownership transfer
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
    portal_plans,
    rbac
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
-- Additionally creates a personal portal_account with OWNER role if user doesn't have one.
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
-- Returns: { portal_user_id, portal_user_email, portal_account_id, portal_plan_type }

CREATE OR REPLACE FUNCTION api.ensure_portal_user(
    p_email TEXT,
    p_auth_provider portal_auth_provider,
    p_auth_type portal_auth_type,
    p_auth_provider_user_id TEXT,
    p_federated BOOL DEFAULT FALSE
)
RETURNS TABLE (
    portal_user_id VARCHAR(36),
    portal_user_email VARCHAR(255),
    portal_account_id VARCHAR(36),
    portal_plan_type VARCHAR(42)
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = public, pg_catalog
AS $$
DECLARE
    v_user_id VARCHAR(36);
    v_deleted_at TIMESTAMPTZ;
    v_account_id VARCHAR(36);
    v_plan_type VARCHAR(42) := 'PLAN_FREE'; -- Default plan for new users
    v_account_exists BOOLEAN;
BEGIN
    -- Validate inputs
    IF p_email IS NULL OR length(trim(p_email)) = 0 THEN
        RAISE EXCEPTION 'p_email is required';
    END IF;
    IF p_auth_provider_user_id IS NULL OR length(trim(p_auth_provider_user_id)) = 0 THEN
        RAISE EXCEPTION 'p_auth_provider_user_id is required';
    END IF;

    -- ========================================================================
    -- STEP 1: Ensure portal_users record exists
    -- ========================================================================
    SELECT pu.portal_user_id, pu.deleted_at
        INTO v_user_id, v_deleted_at
    FROM public.portal_users pu
    WHERE pu.portal_user_email = p_email
    LIMIT 1;

    IF v_user_id IS NULL THEN
        -- Create new user
        INSERT INTO public.portal_users (portal_user_id, portal_user_email, signed_up)
        VALUES (gen_random_uuid()::text, p_email, TRUE)
        RETURNING portal_users.portal_user_id INTO v_user_id;
        
        RAISE NOTICE 'Created new portal_user: %', v_user_id;
    ELSIF v_deleted_at IS NOT NULL THEN
        -- Revive soft-deleted user
        UPDATE public.portal_users
            SET deleted_at = NULL,
                signed_up = TRUE,
                updated_at = CURRENT_TIMESTAMP
        WHERE portal_users.portal_user_id = v_user_id;
        
        RAISE NOTICE 'Revived soft-deleted portal_user: %', v_user_id;
    END IF;

    -- ========================================================================
    -- STEP 2: Ensure portal_user_auth mapping exists
    -- ========================================================================
    UPDATE public.portal_user_auth
        SET portal_user_id = v_user_id,
            portal_auth_provider = p_auth_provider,
            portal_auth_type = p_auth_type,
            federated = COALESCE(p_federated, FALSE),
            updated_at = CURRENT_TIMESTAMP
    WHERE auth_provider_user_id = p_auth_provider_user_id;

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
        
        RAISE NOTICE 'Created portal_user_auth mapping for user: %', v_user_id;
    END IF;

    -- ========================================================================
    -- STEP 3: Check if user has a personal account
    -- ========================================================================
    SELECT EXISTS(
        SELECT 1
        FROM public.portal_account_rbac par
        WHERE par.portal_user_id = v_user_id
        AND par.role_name = 'OWNER'
    ) INTO v_account_exists;

    -- ========================================================================
    -- STEP 4: Create personal account if user doesn't have one
    -- ========================================================================
    IF NOT v_account_exists THEN
        -- Create personal portal account
        INSERT INTO public.portal_accounts (
            portal_account_id,
            portal_plan_type,
            user_account_name,
            internal_account_name
        ) VALUES (
            gen_random_uuid()::text,
            v_plan_type,
            split_part(p_email, '@', 1), -- Use email username as account name
            'Personal Account'
        )
        RETURNING portal_accounts.portal_account_id INTO v_account_id;
        
        RAISE NOTICE 'Created personal account: % for user: %', v_account_id, v_user_id;

        -- Create RBAC entry with OWNER role
        INSERT INTO public.portal_account_rbac (
            portal_account_id,
            portal_user_id,
            role_name,
            user_joined_account
        ) VALUES (
            v_account_id,
            v_user_id,
            'OWNER',
            TRUE
        );
        
        RAISE NOTICE 'Granted OWNER role on account: % to user: %', v_account_id, v_user_id;
    ELSE
        -- Get existing account (prefer OWNER role)
        SELECT par.portal_account_id, pa.portal_plan_type
            INTO v_account_id, v_plan_type
        FROM public.portal_account_rbac par
        JOIN public.portal_accounts pa ON pa.portal_account_id = par.portal_account_id
        WHERE par.portal_user_id = v_user_id
        AND par.role_name = 'OWNER'
        AND pa.deleted_at IS NULL
        LIMIT 1;
        
        -- If no OWNER account found, get first available account
        IF v_account_id IS NULL THEN
            SELECT par.portal_account_id, pa.portal_plan_type
                INTO v_account_id, v_plan_type
            FROM public.portal_account_rbac par
            JOIN public.portal_accounts pa ON pa.portal_account_id = par.portal_account_id
            WHERE par.portal_user_id = v_user_id
            AND pa.deleted_at IS NULL
            LIMIT 1;
        END IF;
    END IF;

    -- ========================================================================
    -- STEP 5: Return user and account information
    -- ========================================================================
    RETURN QUERY SELECT 
        v_user_id,
        p_email::varchar(255),
        v_account_id,
        v_plan_type;
END;
$$;

COMMENT ON FUNCTION api.ensure_portal_user(TEXT, portal_auth_provider, portal_auth_type, TEXT, BOOL) IS 
'Ensures user exists, creates auth mapping, auto-creates personal account with OWNER role if needed. Returns user and account info.';

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

-- Only ADMIN/OWNER can INSERT (create) new accounts
CREATE POLICY portal_accounts_user_insert ON portal_accounts
    FOR INSERT
    TO authenticated_user
    WITH CHECK (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'admin' = ANY(r.permissions)
        )
    );

-- Only ADMIN/OWNER can UPDATE account settings (name, plan, billing, etc.)
CREATE POLICY portal_accounts_user_update ON portal_accounts
    FOR UPDATE
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'admin' = ANY(r.permissions)
        )
    )
    WITH CHECK (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'admin' = ANY(r.permissions)
        )
    );

-- Only account OWNER can DELETE accounts
CREATE POLICY portal_accounts_user_delete ON portal_accounts
    FOR DELETE
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND par.role_name = 'OWNER'
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

-- Users can INSERT applications if they have 'admin' on parent account
CREATE POLICY portal_applications_user_insert ON portal_applications
    FOR INSERT
    TO authenticated_user
    WITH CHECK (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'admin' = ANY(r.permissions)
        )
    );

-- Users can UPDATE applications if they have 'admin' on parent account
CREATE POLICY portal_applications_user_update ON portal_applications
    FOR UPDATE
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'admin' = ANY(r.permissions)
        )
    )
    WITH CHECK (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'admin' = ANY(r.permissions)
        )
    );

-- Users can DELETE applications if they have 'admin' on parent account
CREATE POLICY portal_applications_user_delete ON portal_applications
    FOR DELETE
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'admin' = ANY(r.permissions)
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

-- Users can INSERT RBAC entries if they have 'admin' on the account
CREATE POLICY portal_account_rbac_user_insert ON portal_account_rbac
    FOR INSERT
    TO authenticated_user
    WITH CHECK (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'admin' = ANY(r.permissions)
        )
    );

-- Users can UPDATE RBAC entries if they have 'admin' on the account
CREATE POLICY portal_account_rbac_user_update ON portal_account_rbac
    FOR UPDATE
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'admin' = ANY(r.permissions)
        )
    )
    WITH CHECK (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'admin' = ANY(r.permissions)
        )
    );

-- Users can DELETE RBAC entries if they have 'admin' on the account
CREATE POLICY portal_account_rbac_user_delete ON portal_account_rbac
    FOR DELETE
    TO authenticated_user
    USING (
        portal_account_id IN (
            SELECT par.portal_account_id
            FROM portal_account_rbac par
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'admin' = ANY(r.permissions)
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

-- ============================================================================
-- PORTAL APPLICATION RBAC: Simple Allowlist Implementation
-- ============================================================================
-- portal_application_rbac implements a simple allowlist:
-- - By default, all account members can access all applications in their account
-- - portal_application_rbac entries optionally restrict access to specific users
-- - Permissions are inherited from portal_account_rbac (account-level roles)
-- - If portal_application_rbac has entries for an app, ONLY those users can access it
-- ============================================================================

-- Grant CRUD access to portal_application_rbac for authenticated users
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE portal_application_rbac TO authenticated_user;

-- ============================================================================
-- HELPER FUNCTION: Check if user has access to application
-- ============================================================================

CREATE OR REPLACE FUNCTION api.user_has_application_access(
    p_user_id VARCHAR(36),
    p_application_id VARCHAR(36)
)
RETURNS BOOLEAN AS $$
DECLARE
    v_account_id VARCHAR(36);
    v_has_account_access BOOLEAN;
    v_rbac_entry_exists BOOLEAN;
    v_has_app_rbac BOOLEAN;
BEGIN
    -- Get the parent account for this application
    SELECT portal_account_id INTO v_account_id
    FROM portal_applications
    WHERE portal_application_id = p_application_id
    AND deleted_at IS NULL;

    -- If application doesn't exist, no access
    IF v_account_id IS NULL THEN
        RETURN FALSE;
    END IF;

    -- Check if user has access to the parent account
    SELECT EXISTS(
        SELECT 1
        FROM portal_account_rbac
        WHERE portal_account_id = v_account_id
        AND portal_user_id = p_user_id
    ) INTO v_has_account_access;

    -- If user doesn't have account access, they can't access the app
    IF NOT v_has_account_access THEN
        RETURN FALSE;
    END IF;

    -- Check if any portal_application_rbac entries exist for this app
    SELECT EXISTS(
        SELECT 1
        FROM portal_application_rbac
        WHERE portal_application_id = p_application_id
    ) INTO v_rbac_entry_exists;

    -- If no RBAC entries exist, all account members have access
    IF NOT v_rbac_entry_exists THEN
        RETURN TRUE;
    END IF;

    -- If RBAC entries exist, check if user has one
    SELECT EXISTS(
        SELECT 1
        FROM portal_application_rbac
        WHERE portal_application_id = p_application_id
        AND portal_user_id = p_user_id
    ) INTO v_has_app_rbac;

    RETURN v_has_app_rbac;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

COMMENT ON FUNCTION api.user_has_application_access(VARCHAR(36), VARCHAR(36)) IS
'Checks if user has access to an application. Returns TRUE if:
1. User has account access AND
2. Either no app RBAC entries exist (open to all account members) OR user has an app RBAC entry';

GRANT EXECUTE ON FUNCTION api.user_has_application_access(VARCHAR(36), VARCHAR(36))
    TO authenticated_user, portal_db_admin, portal_db_reader;

-- ============================================================================
-- RLS POLICIES: portal_application_rbac
-- ============================================================================

-- Users can view app RBAC entries for applications they have access to
CREATE POLICY portal_application_rbac_user_select ON portal_application_rbac
    FOR SELECT
    TO authenticated_user
    USING (
        portal_application_id IN (
            SELECT pa.portal_application_id
            FROM portal_applications pa
            WHERE pa.portal_account_id IN (
                SELECT par.portal_account_id
                FROM portal_account_rbac par
                WHERE par.portal_user_id = api.current_portal_user_id()
            )
            AND pa.deleted_at IS NULL
        )
    );

-- Users with ADMIN or OWNER can add app RBAC entries
CREATE POLICY portal_application_rbac_user_insert ON portal_application_rbac
    FOR INSERT
    TO authenticated_user
    WITH CHECK (
        portal_application_id IN (
            SELECT pa.portal_application_id
            FROM portal_applications pa
            JOIN portal_account_rbac par ON par.portal_account_id = pa.portal_account_id
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'admin' = ANY(r.permissions)
              AND pa.deleted_at IS NULL
        )
    );

-- Users with ADMIN or OWNER can remove app RBAC entries
CREATE POLICY portal_application_rbac_user_delete ON portal_application_rbac
    FOR DELETE
    TO authenticated_user
    USING (
        portal_application_id IN (
            SELECT pa.portal_application_id
            FROM portal_applications pa
            JOIN portal_account_rbac par ON par.portal_account_id = pa.portal_account_id
            JOIN rbac r ON r.role_name = par.role_name
            WHERE par.portal_user_id = api.current_portal_user_id()
              AND 'admin' = ANY(r.permissions)
              AND pa.deleted_at IS NULL
        )
    );

-- ============================================================================
-- UPDATE portal_applications SELECT POLICY to respect application RBAC
-- ============================================================================

-- Drop existing policy
DROP POLICY IF EXISTS portal_applications_user_select ON portal_applications;

-- Recreate with application RBAC check
CREATE POLICY portal_applications_user_select ON portal_applications
    FOR SELECT
    TO authenticated_user
    USING (
        api.user_has_application_access(
            api.current_portal_user_id(),
            portal_application_id
        )
    );

COMMENT ON POLICY portal_applications_user_select ON portal_applications IS
'Users can view applications if they have account access AND either:
- No portal_application_rbac entries exist for the app (open to all account members), OR
- They have a portal_application_rbac entry for the app';

-- ============================================================================
-- HELPER RPC: Add user to application allowlist
-- ============================================================================

CREATE OR REPLACE FUNCTION api.add_user_to_application(
    p_application_id VARCHAR(36),
    p_user_id VARCHAR(36)
)
RETURNS TABLE (
    id INT,
    portal_application_id VARCHAR(36),
    portal_user_id VARCHAR(36)
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = public, pg_catalog
AS $$
DECLARE
    v_current_user_id VARCHAR(36);
    v_account_id VARCHAR(36);
    v_has_admin BOOLEAN;
    v_user_has_account_access BOOLEAN;
BEGIN
    v_current_user_id := api.current_portal_user_id();

    -- Get application's account
    SELECT pa.portal_account_id INTO v_account_id
    FROM portal_applications pa
    WHERE pa.portal_application_id = p_application_id
    AND pa.deleted_at IS NULL;

    IF v_account_id IS NULL THEN
        RAISE EXCEPTION 'Application not found';
    END IF;

    -- Check if current user has admin permissions on the account
    SELECT EXISTS(
        SELECT 1
        FROM portal_account_rbac par
        JOIN rbac r ON r.role_name = par.role_name
        WHERE par.portal_account_id = v_account_id
        AND par.portal_user_id = v_current_user_id
        AND 'admin' = ANY(r.permissions)
    ) INTO v_has_admin;

    IF NOT v_has_admin THEN
        RAISE EXCEPTION 'Insufficient permissions. Must be account ADMIN or OWNER.';
    END IF;

    -- Check if target user has access to the account
    SELECT EXISTS(
        SELECT 1
        FROM portal_account_rbac par
        WHERE par.portal_account_id = v_account_id
        AND par.portal_user_id = p_user_id
    ) INTO v_user_has_account_access;

    IF NOT v_user_has_account_access THEN
        RAISE EXCEPTION 'User does not have access to this account';
    END IF;

    -- Insert or ignore if already exists
    INSERT INTO portal_application_rbac (portal_application_id, portal_user_id)
    VALUES (p_application_id, p_user_id)
    ON CONFLICT (portal_application_id, portal_user_id) DO NOTHING;

    -- Return the entry
    RETURN QUERY
    SELECT par.id, par.portal_application_id, par.portal_user_id
    FROM portal_application_rbac par
    WHERE par.portal_application_id = p_application_id
    AND par.portal_user_id = p_user_id;
END;
$$;

COMMENT ON FUNCTION api.add_user_to_application(VARCHAR(36), VARCHAR(36)) IS
'Adds a user to an application allowlist. Only account ADMIN/OWNER can call this.
Target user must already be a member of the parent account.';

GRANT EXECUTE ON FUNCTION api.add_user_to_application(VARCHAR(36), VARCHAR(36))
    TO authenticated_user, portal_db_admin;

-- ============================================================================
-- HELPER RPC: Remove user from application allowlist
-- ============================================================================

CREATE OR REPLACE FUNCTION api.remove_user_from_application(
    p_application_id VARCHAR(36),
    p_user_id VARCHAR(36)
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = public, pg_catalog
AS $$
DECLARE
    v_current_user_id VARCHAR(36);
    v_account_id VARCHAR(36);
    v_has_admin BOOLEAN;
BEGIN
    v_current_user_id := api.current_portal_user_id();

    -- Get application's account
    SELECT pa.portal_account_id INTO v_account_id
    FROM portal_applications pa
    WHERE pa.portal_application_id = p_application_id
    AND pa.deleted_at IS NULL;

    IF v_account_id IS NULL THEN
        RAISE EXCEPTION 'Application not found';
    END IF;

    -- Check if current user has admin permissions
    SELECT EXISTS(
        SELECT 1
        FROM portal_account_rbac par
        JOIN rbac r ON r.role_name = par.role_name
        WHERE par.portal_account_id = v_account_id
        AND par.portal_user_id = v_current_user_id
        AND 'admin' = ANY(r.permissions)
    ) INTO v_has_admin;

    IF NOT v_has_admin THEN
        RAISE EXCEPTION 'Insufficient permissions. Must be account ADMIN or OWNER.';
    END IF;

    -- Remove the entry
    DELETE FROM portal_application_rbac
    WHERE portal_application_id = p_application_id
    AND portal_user_id = p_user_id;

    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION api.remove_user_from_application(VARCHAR(36), VARCHAR(36)) IS
'Removes a user from an application allowlist. Only account ADMIN/OWNER can call this.
Returns TRUE if an entry was removed, FALSE otherwise.';

GRANT EXECUTE ON FUNCTION api.remove_user_from_application(VARCHAR(36), VARCHAR(36))
    TO authenticated_user, portal_db_admin;
