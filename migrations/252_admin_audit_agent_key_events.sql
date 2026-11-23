-- 252: migration 112's admin audit definer, `epigraph_admin_audit_write`,
-- re-stated to accept two more event types: an admin's rotation or
-- revocation of ANOTHER agent's key (backlog 6492de67).
--
-- ===================================================================
-- 1. WHY
-- ===================================================================
--
-- `POST /api/v1/agents/:id/keys/rotate` and `.../keys/:key_id/revoke` admit a
-- caller that is the target agent OR holds `claims:admin` (the admin override,
-- reachable while the admin-scope switch of migration 128 is unarmed). An
-- admin who rotated or revoked another agent's key left no audit row: the
-- handlers wrote the key change and nothing else. A key change decides who
-- can sign as that agent, so an override that leaves no record of WHICH admin
-- made it, on which token, is not attributable afterwards.
--
-- The handlers now write the audit row through 112's definer, on the SAME
-- transaction as the key change, so the two commit together or not at all.
-- 112's definer accepts a closed set of event types (`ADM03`) and its header
-- says a new admin audit event is a new decision and a new line there; this
-- file is that line.
--
-- ===================================================================
-- 2. THE CHANGE
-- ===================================================================
--
-- `CREATE OR REPLACE` of the one function, same signature, same body as 112's
-- but for the event-type list, which gains:
--
--   * `agent_keys.admin_rotate`: an admin rotated another agent's active
--     signing key;
--   * `agent_keys.admin_revoke`: an admin revoked another agent's key.
--
-- `workflows.admin_write` stays (the API and MCP workflow admin arms write
-- it). Everything else is 112's: `ADM01` without an admin, `ADM03` for any
-- other type, `ADM02` unless the token's client record (`oauth_clients`,
-- `p_client_id`) is active, bound to `p_admin` and grants `claims:admin`
-- (111's predicate), and one `security_events` row attributed to the admin,
-- written under the definer's bypass on the caller's transaction.
--
-- Path: `pg_catalog, public, pg_temp`, the path 190's sweep gave 112's
-- function (`CREATE OR REPLACE` replaces the path, and 190 requires `pg_temp`
-- last). The function stays in
-- `definer_search_path_ratchet.rs::PUBLIC_PATH_REGISTER`.
--
-- `CREATE OR REPLACE` keeps 112's owner (`epigraph_maintenance`) and grants
-- (EXECUTE revoked from PUBLIC, granted to `epigraph_app` and
-- `epigraph_maintenance`), so nothing is re-owned or re-granted here, and the
-- function stays registered at 112 in
-- `crates/epigraph-cli/src/bin/tenancy_backfill.rs`
-- (`DEFERRED_DEFINER_FUNCTIONS`) and pinned by
-- `schema_contract.rs::migration_112_admin_audit_definer_is_owned_and_granted`.
--
-- NOT CHANGED: `epigraph_agent_key_set_status` (118, re-stated by 161, 162
-- and 163). The key change itself is unchanged; only the audit row is new. A
-- later re-statement of that function starts from 163's body (AK02 gate and
-- `LEAST(valid_until, now())`).
--
-- PRECONDITION: the body in place must be 112's (md5 of `prosrc`
-- `6c9a51969e80c7d47233cbc85659d911`; 190 changed only the path, not the
-- body), so that this file never silently discards another migration's
-- re-statement; over any other body it raises 55000 and changes nothing. A
-- later re-statement starts from this body.
--
-- ===================================================================
-- 3. DEPLOY ORDER AND UNDO
-- ===================================================================
--
-- MIGRATE FIRST, then deploy the binary. A binary that writes the new event
-- types against a database without this file is refused `ADM03` on every
-- admin rotation or revocation of another agent's key (the key change rolls
-- back with it; self-rotation and self-revocation are unaffected). This file
-- with the old binary changes nothing observable.
--
-- UNDO: `docs/runbooks/252-undo.sql` restores 112's body (on 190's path).
-- Roll the binary back FIRST: after the undo, the new binary's admin key
-- override is refused `ADM03`. Rows already written with the new types stay
-- (`security_events` is append-only).
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_found text;
BEGIN
    SELECT pg_catalog.md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
                       'public.epigraph_admin_audit_write(uuid, uuid, uuid, text, jsonb)');
    IF v_found IS DISTINCT FROM '6c9a51969e80c7d47233cbc85659d911' THEN
        RAISE EXCEPTION '252: public.epigraph_admin_audit_write(uuid, uuid, uuid, text, jsonb) '
                        'is not the body 252 re-states (112''s, md5 '
                        '6c9a51969e80c7d47233cbc85659d911); found md5 %. Another migration '
                        're-bodied it, or 112 is not applied; nothing was changed',
                        COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the function with '
                         'every delta instead of this one.';
    END IF;
END $$;

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
    IF p_event_type IS NULL OR p_event_type NOT IN (
           'workflows.admin_write',
           'agent_keys.admin_rotate',
           'agent_keys.admin_revoke') THEN
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
