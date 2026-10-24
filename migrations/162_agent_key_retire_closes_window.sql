-- Migration 162: retiring an agent key closes its validity window.
--
-- EVIDENCE
-- 118's `epigraph_agent_key_set_status` moves a key active -> rotated, or
-- anything but revoked -> revoked, and changes no column but status,
-- revocation_reason and revoked_by. It never sets `valid_until`, and the
-- application role holds no UPDATE on `agent_keys`, so nothing else can. A
-- rotated or revoked key therefore keeps an open-ended window
-- [valid_from, NULL). A verifier that binds a signature to "a key of the
-- author that was valid at the claim's created_at" would keep binding
-- signatures made AFTER the key was retired, including signatures by whoever
-- recomputed a derived key that was rotated out for being computable.
--
-- CHANGE
-- The same body as 161 (118's, plus 161's attested-type gate AK02: a
-- `signing` or `identity-legacy` key's status moves only on a maintenance or
-- superuser session) with one difference: both transitions also set
-- `valid_until = LEAST(valid_until, now())`. The 161 gate is kept verbatim;
-- dropping it here would reopen what 161 closed. `LEAST` ignores NULL, so an
-- open-ended window ends at the transition; a window that already ended
-- earlier (an expired key still marked active) keeps its earlier end, so
-- retirement only ever shortens a window and never reopens or extends one.
-- `valid_from` is untouched. The signature, `RETURNS SETOF`, owner and ACL are
-- unchanged; owner and grant are re-asserted below, idempotently, as 140 does
-- for its 118 definer.
--
-- The rotate handler (`routes/agent_keys.rs::rotate_agent_key`) opens the new
-- key's window no earlier than the returned `valid_until`, so the old and new
-- windows never overlap even when the API host's clock is behind the
-- database's.
--
-- Existing rows keep what they store: keys rotated or revoked before this
-- migration keep `valid_until` NULL (their retirement time was not recorded
-- and is not reconstructed here).
--
-- UNDO: re-run 161's `CREATE OR REPLACE FUNCTION
-- public.epigraph_agent_key_set_status` block verbatim (NOT 118's, which has
-- no attested-type gate) (owner and ACL survive
-- `CREATE OR REPLACE`). Windows closed in between stay closed.
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

-- Owner and grant as 118 section 3e (and 161) left them (`CREATE OR REPLACE` keeps both;
-- re-asserted so a database where they drifted is corrected here).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_agent_key_set_status(uuid, text, text, uuid) OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_key_set_status(uuid, text, text, uuid) TO epigraph_app';
    END IF;
END $$;
