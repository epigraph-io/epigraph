-- ===================================================================
-- 252-undo.sql: take migration 252 (the admin audit definer's two agent-key
-- event types) back out, in ONE transaction, on the migration (superuser)
-- DSN.
--
-- WHAT IT DOES: re-states `public.epigraph_admin_audit_write` with 112's
-- body verbatim (event types: `workflows.admin_write` only) on the path 190
-- gave it (`pg_catalog, public, pg_temp`; NOT 112's original
-- `pg_catalog, public`, which 190's postcondition and
-- `definer_search_path_ratchet.rs` refuse). CREATE OR REPLACE keeps owner and
-- grants. Idempotent: running it twice leaves the same function.
--
-- ROLL THE BINARY BACK FIRST. A binary that writes `agent_keys.admin_rotate`
-- / `agent_keys.admin_revoke` is refused `ADM03` after this file, so an
-- admin's rotation or revocation of another agent's key then fails (and
-- writes nothing). Self-rotation and self-revocation are unaffected.
--
-- WHAT IT LEAVES:
--   * every `security_events` row already written with the two event types
--     (`security_events` is append-only). List them with:
--       SELECT created_at, event_type, agent_id, details
--         FROM public.security_events
--        WHERE event_type IN ('agent_keys.admin_rotate', 'agent_keys.admin_revoke');
--   * 252's `_sqlx_migrations` row. Re-introducing the event types is a NEW
--     migration, never a re-run of 252.
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_admin_audit_write(
    p_client_id  uuid,
    p_token_jti  uuid,
    p_admin      uuid,
    p_event_type text,
    p_details    jsonb)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    IF p_admin IS NULL THEN
        RAISE EXCEPTION 'ADM01: the admin audit write needs the admin agent; nothing was written'
            USING ERRCODE = '42501';
    END IF;
    IF p_event_type IS NULL OR p_event_type NOT IN ('workflows.admin_write') THEN
        RAISE EXCEPTION 'ADM03: unknown admin audit event type %', p_event_type
            USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.oauth_clients c
         WHERE c.id = p_client_id
           AND c.agent_id = p_admin
           AND c.status = 'active'
           AND 'claims:admin' = ANY (c.granted_scopes)) THEN
        RAISE EXCEPTION 'ADM02: principal % holds no active claims:admin grant through '
            'client %; nothing was written', p_admin, p_client_id
            USING ERRCODE = '42501';
    END IF;

    INSERT INTO public.security_events (event_type, agent_id, success, details, correlation_id)
    VALUES (
        p_event_type,
        p_admin,
        true,
        COALESCE(p_details, '{}'::jsonb) || jsonb_build_object(
            'admin_agent_id', p_admin,
            'client_id',      p_client_id,
            'token_jti',      p_token_jti),
        left(p_token_jti::text, 64));
END
$$;

COMMIT;
