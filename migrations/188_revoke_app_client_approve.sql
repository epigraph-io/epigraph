-- Migration 188: the application role may no longer EXECUTE
-- `epigraph_oauth_client_approve` (backlog ca3968f6). Approving an OAuth client
-- becomes a maintenance act.
--
-- WHY. 118 made `public.epigraph_oauth_client_approve(uuid, text[], uuid)` a
-- maintenance-owned SECURITY DEFINER and granted EXECUTE on it to
-- `epigraph_app`, for the REST admin approval
-- (`POST /api/v1/admin/clients/:id/approve`). The definer sets
-- `status = 'active'` and writes the caller-supplied `granted_scopes`
-- verbatim. The `clients:admin` scope check and the admin-scope refusals
-- (`platform:admin`, migration 128's switch) live in the ROUTE, not in the
-- function. So any session on the application role, which is not only the API
-- process, could activate a pending client with any scope set, admin-only
-- scopes included while 128 is unarmed. The REVOKE moves the authority to the
-- database: only the definer's owner (`epigraph_maintenance`) and privileged
-- sessions may approve.
--
-- WHAT STILL APPROVES. A maintenance session calls the definer directly
-- (`SELECT public.epigraph_oauth_client_approve(<oauth_clients.id>,
-- ARRAY[...], <approver client uuid or NULL>)`); it still writes its
-- `oauth.client_approved` security event. The REST route answers 501 MOVED
-- (operator decision D9: a request-serving process holds no maintenance
-- connection) after its own scope checks, the shape plan EQ-5 already gave
-- approvals once 128 is armed. An operator CLI verb for it is a follow-up.
--
-- WHAT IS UNCHANGED. The function body, owner (`epigraph_maintenance`, 118)
-- and `search_path` pin are untouched: no CREATE OR REPLACE here. PUBLIC
-- already holds no EXECUTE (118). 122's `oauth_clients_reactivation_guard`
-- stays; it still refuses a non-privileged re-activation reaching the table by
-- any other path. The other 118 definers the application role executes
-- (refresh, code, session, link, agent-key) are request-path credential flows
-- and keep their grants.
--
-- DEPLOY ORDER: a binary from before this change, with 188 applied, answers
-- the approve route with a 500 (42501 from the definer) instead of approving;
-- the new binary answers 501 whether or not 188 is applied. Apply with or after
-- the new binary. No other migration depends on it.
--
-- UNDO:
--   GRANT EXECUTE ON FUNCTION public.epigraph_oauth_client_approve(uuid, text[], uuid)
--       TO epigraph_app;
-- Checked before claiming: no `origin/main` migration, open PR or origin
-- branch carries a `188`.

SET LOCAL lock_timeout = '3s';

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_oauth_client_approve(uuid, text[], uuid) FROM epigraph_app';
    END IF;
END $$;
