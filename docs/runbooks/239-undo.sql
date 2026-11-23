-- ===================================================================
-- 239-undo.sql: take migration 239 (the application role adds no agent key,
-- and moves or rotates a key only for the key's own agent or an admin) back
-- out, in ONE transaction, on the migration (superuser) DSN.
--
-- WHAT IT DOES:
--   * re-states `epigraph_agent_key_set_status` verbatim from 163 (161's AK02
--     gate and 162's closed window, no caller gate, path
--     `pg_catalog, public`); CREATE OR REPLACE keeps its owner and grants;
--   * drops `epigraph_agent_key_rotate(uuid, bytea)`;
--   * grants INSERT on `agent_keys` back to `epigraph_app`.
--
-- WHAT IT LEAVES: every key row the rotation definer wrote (each is an
-- ordinary `agent_keys` row) and 239's `_sqlx_migrations` row. Re-applying
-- the change is a NEW migration, never a re-run of 239.
--
-- ORDER: roll every 239 binary back FIRST. Its HTTP rotation calls the
-- definer this file drops (it then answers 500 for every rotation).
-- Tested by `epigraph-db/tests/agent_keys_app_role_writes.rs`
-- (`the_undo_restores_the_pre_239_grants_and_body`, run twice).
-- ===================================================================

BEGIN;
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_agent_key_set_status(
    p_key_id uuid, p_status text, p_revocation_reason text, p_revoked_by uuid)
RETURNS SETOF public.agent_keys
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_cur text;
        v_type text;
BEGIN
    SELECT k.status, k.key_type INTO v_cur, v_type
      FROM public.agent_keys k WHERE k.id = p_key_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF lower(btrim(v_type)) IN ('signing', 'identity-legacy')
       AND NOT (public.epigraph_bypass()
                OR COALESCE((SELECT r.rolsuper OR r.rolbypassrls
                               FROM pg_catalog.pg_roles r
                              WHERE r.rolname = session_user), false)) THEN
        RAISE EXCEPTION 'AK02: agent key % is a % key, attested state; only a maintenance '
                        'session changes its status (migration 161)', p_key_id, v_type
            USING ERRCODE = '42501';
    END IF;
    IF NOT ((p_status = 'rotated' AND v_cur = 'active')
            OR (p_status = 'revoked' AND v_cur IS DISTINCT FROM 'revoked')) THEN
        RAISE EXCEPTION 'AK01: agent key % cannot move from % to %', p_key_id, v_cur, p_status
            USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
        UPDATE public.agent_keys
           SET status = p_status,
               valid_until = LEAST(valid_until, now()),
               revocation_reason = COALESCE(p_revocation_reason, revocation_reason),
               revoked_by = COALESCE(p_revoked_by, revoked_by)
         WHERE id = p_key_id
        RETURNING *;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_key_set_status(uuid, text, text, uuid)
    FROM PUBLIC;

DROP FUNCTION IF EXISTS public.epigraph_agent_key_rotate(uuid, bytea);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT INSERT ON public.agent_keys TO epigraph_app';
    END IF;
END $$;

COMMIT;
