-- Migration 163: retiring an agent key closes its validity window, keeping
-- 161's attested-key gate.
--
-- EVIDENCE
-- `epigraph_agent_key_set_status` (118, re-stated by 161 with the AK02 gate)
-- moves a key active -> rotated, or anything but revoked -> revoked, and
-- changes no column but status, revocation_reason and revoked_by. It never
-- sets `valid_until`, and the application role holds no UPDATE on
-- `agent_keys`, so nothing else does. `verify_claim` (agent identity lineage
-- design D2) binds a claim to a key of its author that was valid at the
-- claim's created_at; a rotated key records no end, so it binds nothing, and
-- one rotation (the documented maintenance flow for a signing key) unbinds
-- every claim the key signed while it was active.
--
-- CHANGE
-- 161's body with one difference: both transitions also set
-- `valid_until = LEAST(valid_until, now())`. `LEAST` ignores NULL, so an
-- open-ended window ends at the transition; a window that already ended
-- earlier keeps its earlier end, so retirement only ever shortens a window.
-- `valid_from` is untouched. Signature, `RETURNS SETOF`, owner and ACL are
-- unchanged (`CREATE OR REPLACE` keeps owner and ACL).
--
-- THE SAME CHANGE ON ANOTHER BRANCH
-- The rotate-route caller-check slice carries
-- `162_agent_key_retire_closes_window.sql`, which makes this change to 118's
-- body, WITHOUT 161's AK02 gate. Applied after 161 it would drop that gate;
-- applied before 161 (that slice deploys first) it would be replaced by
-- 161's body and lose the window. This file states the union, and as the
-- highest number it is the last to apply in either order, so every database
-- converges on: AK02 gate AND closed window. A later re-statement of this
-- function must start from this body.
--
-- Existing rows keep what they store: keys rotated or revoked before this
-- migration keep `valid_until` NULL (their retirement time was not recorded
-- and is not reconstructed here).
--
-- UNDO: re-run 161's `CREATE OR REPLACE FUNCTION
-- public.epigraph_agent_key_set_status` block verbatim. Windows closed in
-- between stay closed.
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
