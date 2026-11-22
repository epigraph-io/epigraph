-- Migration 239: the application role adds no agent key, and moves or
-- rotates a key only for the key's own agent or an admin (backlog 54018ca1).
--
-- ===================================================================
-- 0. EVIDENCE
-- ===================================================================
--
-- 118 revoked UPDATE, DELETE and TRUNCATE on `agent_keys` from `epigraph_app`
-- but kept INSERT ("registration, provisioning and token minting insert on
-- the application role"), and granted the application role
-- `epigraph_agent_key_set_status` with no caller check. Its header named the
-- consequence and left it as a follow-up: "an agent key inserted for a chosen
-- agent can be used as that principal". 161 (section 7a) then closed the two
-- ATTESTED key types, `signing` and `identity-legacy`, with a guard trigger
-- and a session test in the status definer; 162 and 163 re-stated the definer
-- and re-granted it. Through 238 nothing else changed. So a session on the
-- application DSN (which agent containers hold) could still:
--   * INSERT a key of any other `key_type` for any agent;
--   * rotate or revoke any agent's key of any other type through the status
--     definer, whoever it was stamped as, or unstamped.
-- The HTTP routes refuse both unless the caller is the agent or an admin
-- (`routes/agent_keys.rs::require_self_or_admin`, PR #660); the database did
-- not. No application path inserts a key any more: the only one, the HTTP
-- rotation, inserts a `signing` key, which 161's guard already refuses to an
-- application session.
--
-- ===================================================================
-- 1. CHANGE
-- ===================================================================
--
--   a. REVOKE INSERT ON `agent_keys` FROM `epigraph_app`. With 118's revoke
--      the application role now holds SELECT only. A table-level REVOKE also
--      removes any column-level INSERT. Every writer left is the identity
--      registration (161, attestor-owned), the legacy backfills (161, 166,
--      180, 195, 230; maintenance-owned), the two definers below, or a
--      maintenance session.
--
--   b. `epigraph_agent_key_set_status` (163's body, which states 161's AK02
--      gate and 162's closed window): one new gate, for EVERY key type, after
--      AK02 and before the transition check. The caller must be:
--        * a privileged session (the AK02 test: `epigraph_bypass()`, which is
--          a `session_user` membership in `epigraph_maintenance`, or a
--          superuser or BYPASSRLS `session_user`); or
--        * the key's own agent: `epigraph_principal_id() = agent_id`; or
--        * an admin by the predicate of 129 / 169 / 199: while the
--          admin-scope switch is armed an elevated session
--          (`epigraph_is_elevated()`), otherwise a live instance admin
--          (`epigraph_is_instance_admin(principal)`).
--      Anything else, an unstamped application session included, is refused
--      `AK03` with SQLSTATE 42501 and nothing changes. The body moves to 172's
--      path form (`pg_catalog, pg_temp`, every name qualified), so its entry
--      leaves `definer_search_path_ratchet.rs`'s public-path register.
--
--   c. NEW `epigraph_agent_key_rotate(p_old_key uuid, p_new_public_key bytea)`
--      RETURNS SETOF `agent_keys` (the new row; no row when the old key does
--      not exist). SECURITY DEFINER, owner `epigraph_maintenance`, EXECUTE
--      revoked from PUBLIC and granted to `epigraph_app` and
--      `epigraph_maintenance`. In one statement it locks the old key, applies
--      the same AK02 and AK03 gates, refuses (`AK01`, 22023) a key that is no
--      longer `active`, retires it (`rotated`, `valid_until = LEAST(
--      valid_until, now())`, as 163) and inserts the new key `active` with
--      `valid_from = now()`, where the old window closed. The new row's
--      `agent_id` and `key_type` are the OLD row's: the caller names neither,
--      which is the "derive the security-relevant columns from checked state"
--      follow-up 118's header names. The new key must be 32 bytes (Ed25519;
--      `AK04`, 22023). The HTTP rotation calls it instead of the status
--      definer plus a direct INSERT, so a failure between the two no longer
--      leaves an agent with its old key retired and no new one.
--
-- ===================================================================
-- 2. WHAT IT DOES NOT CLOSE
-- ===================================================================
--
-- `epigraph.principal_id` is a session GUC any session on the application DSN
-- may SET (199's note; docs/tenancy.md). Against a DSN holder:
--   * the INSERT revoke holds outright, and so do the AK02 gates (they read
--     the session login, not the GUC);
--   * the AK03 gate holds only under the stamping convention: a DSN holder
--     that stamps itself as the victim passes it. What it closes is the
--     request path: every HTTP caller is stamped from its verified token, and
--     an unstamped connection can no longer move any key.
-- The attested types stay a maintenance act, as 161 ruled: the HTTP rotation
-- of a `signing` key on an application session is refused AK02 before and
-- after this file.
--
-- The admin arm is the database's, not the token's: the database cannot see
-- an OAuth scope. While the switch is unarmed, a `claims:admin` caller whose
-- principal is not a live instance admin passes the route's check and is now
-- refused AK03 at the database.
--
-- ===================================================================
-- 3. UNDO
-- ===================================================================
--
-- docs/runbooks/239-undo.sql: re-states 163's body, drops the rotation
-- definer, and grants INSERT on `agent_keys` back to `epigraph_app`. Roll the
-- 239 binary back first: its rotation calls the dropped definer.

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- b. THE STATUS DEFINER
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_agent_key_set_status(
    p_key_id uuid, p_status text, p_revocation_reason text, p_revoked_by uuid)
RETURNS SETOF public.agent_keys
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_cur       text;
        v_type      text;
        v_agent     uuid;
        v_principal uuid;
        v_session   boolean;
BEGIN
    SELECT k.status, k.key_type, k.agent_id INTO v_cur, v_type, v_agent
      FROM public.agent_keys k WHERE k.id = p_key_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    v_session := public.epigraph_bypass()
                 OR COALESCE((SELECT r.rolsuper OR r.rolbypassrls
                                FROM pg_catalog.pg_roles r
                               WHERE r.rolname = session_user), false);
    IF pg_catalog.lower(pg_catalog.btrim(v_type)) IN ('signing', 'identity-legacy')
       AND NOT v_session THEN
        RAISE EXCEPTION 'AK02: agent key % is a % key, attested state; only a maintenance '
                        'session changes its status (migration 161)', p_key_id, v_type
            USING ERRCODE = '42501';
    END IF;
    v_principal := public.epigraph_principal_id();
    IF NOT (v_session
            OR (v_principal IS NOT NULL
                AND (v_principal = v_agent
                     OR COALESCE(CASE WHEN public.epigraph_admin_scopes_armed()
                                      THEN public.epigraph_is_elevated()
                                      ELSE public.epigraph_is_instance_admin(v_principal)
                                 END, false)))) THEN
        RAISE EXCEPTION 'AK03: agent key % belongs to another agent; only that agent, an '
                        'admin or a maintenance session changes its status (migration 239)',
                        p_key_id
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
               valid_until = LEAST(valid_until, pg_catalog.now()),
               revocation_reason = COALESCE(p_revocation_reason, revocation_reason),
               revoked_by = COALESCE(p_revoked_by, revoked_by)
         WHERE id = p_key_id
        RETURNING *;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_key_set_status(uuid, text, text, uuid)
    FROM PUBLIC;

-- ===================================================================
-- c. THE ROTATION DEFINER
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_agent_key_rotate(
    p_old_key uuid, p_new_public_key bytea)
RETURNS SETOF public.agent_keys
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_cur       text;
        v_type      text;
        v_agent     uuid;
        v_principal uuid;
        v_session   boolean;
BEGIN
    IF p_new_public_key IS NULL OR pg_catalog.octet_length(p_new_public_key) <> 32 THEN
        RAISE EXCEPTION 'AK04: a new agent key is 32 bytes (Ed25519), got %',
                        COALESCE(pg_catalog.octet_length(p_new_public_key), 0)
            USING ERRCODE = '22023';
    END IF;
    SELECT k.status, k.key_type, k.agent_id INTO v_cur, v_type, v_agent
      FROM public.agent_keys k WHERE k.id = p_old_key FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    v_session := public.epigraph_bypass()
                 OR COALESCE((SELECT r.rolsuper OR r.rolbypassrls
                                FROM pg_catalog.pg_roles r
                               WHERE r.rolname = session_user), false);
    IF pg_catalog.lower(pg_catalog.btrim(v_type)) IN ('signing', 'identity-legacy')
       AND NOT v_session THEN
        RAISE EXCEPTION 'AK02: agent key % is a % key, attested state; only a maintenance '
                        'session rotates it (migration 161)', p_old_key, v_type
            USING ERRCODE = '42501';
    END IF;
    v_principal := public.epigraph_principal_id();
    IF NOT (v_session
            OR (v_principal IS NOT NULL
                AND (v_principal = v_agent
                     OR COALESCE(CASE WHEN public.epigraph_admin_scopes_armed()
                                      THEN public.epigraph_is_elevated()
                                      ELSE public.epigraph_is_instance_admin(v_principal)
                                 END, false)))) THEN
        RAISE EXCEPTION 'AK03: agent key % belongs to another agent; only that agent, an '
                        'admin or a maintenance session rotates it (migration 239)', p_old_key
            USING ERRCODE = '42501';
    END IF;
    IF v_cur IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'AK01: agent key % cannot move from % to rotated', p_old_key, v_cur
            USING ERRCODE = '22023';
    END IF;
    UPDATE public.agent_keys
       SET status = 'rotated',
           valid_until = LEAST(valid_until, pg_catalog.now())
     WHERE id = p_old_key;
    RETURN QUERY
        INSERT INTO public.agent_keys (agent_id, public_key, key_type, status, valid_from)
        VALUES (v_agent, p_new_public_key, v_type, 'active', pg_catalog.now())
        RETURNING *;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_agent_key_rotate(uuid, bytea) FROM PUBLIC;

-- ===================================================================
-- a. THE REVOKE, OWNERSHIP AND GRANTS
-- ===================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_agent_key_rotate(uuid, bytea) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_key_rotate(uuid, bytea) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_agent_key_rotate(uuid, bytea) '
                'TO epigraph_app';
        EXECUTE 'REVOKE INSERT ON public.agent_keys FROM epigraph_app';
    END IF;
END $$;
