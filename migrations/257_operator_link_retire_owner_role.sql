-- 257_operator_link_retire_owner_role.sql
-- Retiring an operator link has ONE non-superuser path, the audited verb, and
-- the verb's audit attribution can no longer be forged (backlog 9cec11f7).
--
-- ===================================================================
-- 1. WHY
--
-- 191 added `epigraph_retire_operator_link` and, because the verb ran as its
-- owner `epigraph_maintenance`, granted that role UPDATE (retired) on
-- `operator_links`. Every maintenance LOGIN inherits that grant, so a
-- maintenance login could also retire a link with a plain
-- `UPDATE operator_links SET retired = true`. 191's header states two limits
-- of that direct path:
--   (1) it is NOT serialised. The verb takes 107's `epigraph.operator_links`
--       advisory lock before any row lock; the direct statement takes none
--       (taking it in the row trigger, after the row lock, would invert the
--       verb's order and could deadlock). A direct retire racing a link
--       writer or a membership grant can leave a RETIRED link whose agent
--       still holds a live writer row in the operator group: the state 107
--       section 7 and 109 refuse;
--   (2) its audit attribution is advisory. The audit trigger reads `via` and
--       the reason from the session-settable `epigraph.operator_link_retire`,
--       so a maintenance login could set it before a direct UPDATE and the
--       audit row would claim the verb, with any reason.
-- Neither can be fixed while the verb is owned by `epigraph_maintenance`:
-- nothing the verb does as that role is distinguishable from what a
-- maintenance login does itself (`SET ROLE epigraph_maintenance` included).
-- Revoking the column grant alone would break the verb, which needs it.
--
-- ===================================================================
-- 2. WHAT THIS FILE DOES
--
-- (a) A dedicated owner role, `epigraph_operator_link_retirer`: NOLOGIN, a
--     member of `epigraph_maintenance` only (so inside the verb
--     `epigraph_definer_bypass()` still holds and every grant and policy the
--     verb used still applies), and no other role may act as it. Created as
--     060/161 create theirs (guarded; a role that already exists is CHECKED,
--     not trusted: any elevated attribute, LOGIN, another membership, or a
--     non-superuser role that can SET ROLE to it or inherit it raises 55000
--     and nothing is changed).
-- (b) The verb is re-owned to that role. EXECUTE stays the maintenance
--     role's alone (re-granted: `ALTER ... OWNER` moves the old owner's ACL
--     entry to the new owner).
-- (c) UPDATE (retired) on `operator_links` moves from `epigraph_maintenance`
--     to the new role. A maintenance login's direct UPDATE is now refused
--     by the privilege check (42501) before any trigger runs; the only
--     non-superuser path that flips `retired` is the verb, which takes 107's
--     advisory lock first. Limit (1) is closed for every non-superuser.
-- (d) 191's retire-only guard `epigraph_operator_links_retire_only` is
--     re-bodied (md5 precondition on 191's body). `current_user` names the
--     new role only inside the verb (a definer runs as its owner, and no
--     login can act as that role), so:
--       * a non-superuser false -> true flip outside the verb is refused
--         (OLR05, 42501). Unreachable on today's grants; it holds if a later
--         migration or an operator re-grants the column to another role;
--       * on any UPDATE outside the verb, the superuser's included, the
--         guard clears `epigraph.operator_link_retire` before the AFTER audit
--         trigger reads it. So `via` and the reason in an audit row come
--         from the verb's own arguments or not at all: a forged setting is
--         recorded `via = direct` with no reason. Limit (2) is closed.
--     The rest of the body is 191's: OLR04 for a non-superuser un-retire or
--     re-point, OLR03 while the agent holds a live writer/admin row in the
--     operator group, a superuser outside the guard.
--
-- What it does NOT change:
--   * a SUPERUSER still retires (and un-retires) directly, unserialised; it
--     is outside every guard here (it can disable a trigger). Its flip is
--     still audited, now always `via = direct`;
--   * the window 109 section 2 records between the verb and a concurrent
--     roster INSERT whose BEFORE trigger ran before the retire committed and
--     whose foreign-key check then waited on it. No shipped route writes a
--     writer row into an operator's (keyless, personal) group on the
--     application role (176, GRM02's note), and every maintenance-path
--     writer of such a row takes 107's advisory lock, as the verb does.
--
-- If this file cannot create the role, grant it the maintenance role or
-- re-own the verb (a migrating login that is not a superuser), it says so
-- with a NOTICE and leaves 191's grants in place: the verb keeps working and
-- the guard's new arms stay off (they key on the verb's owner being the new
-- role). `tenancy_backfill verify` reports that state as a FAILURE. Provision
-- the role out of band and re-run this file's last DO block as a superuser
-- (docs/runbooks/257-undo.sql names the statements).
--
-- Convention for the re-bodied guard as 191 (172's form): `SET search_path =
-- pg_catalog, pg_temp`, every public object schema-qualified.
--
-- ===================================================================
-- 3. UNDO: docs/runbooks/257-undo.sql (re-owns the verb to
-- `epigraph_maintenance`, moves the column grant back, re-states 191's guard).
-- **Applied to throwaway databases only, NOT to any deployed database.**

SET LOCAL lock_timeout = '3s';

-- -------------------------------------------------------------------
-- Precondition: the guard still carries 191's body, which (d) re-states.
-- CREATE OR REPLACE replaces a body whole, so applying this over another body
-- would silently drop that body's arms. The md5 is of `prosrc`.
-- -------------------------------------------------------------------
DO $$
DECLARE
    v_found text;
BEGIN
    SELECT md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
     WHERE p.oid = to_regprocedure('public.epigraph_operator_links_retire_only()');
    IF v_found IS DISTINCT FROM '6a81b8a7fac6cc83782db54edc0e4d33' THEN
        RAISE EXCEPTION '257: public.epigraph_operator_links_retire_only() is not the body 257 '
                        're-states (191''s, md5 6a81b8a7fac6cc83782db54edc0e4d33); found md5 %. '
                        'Another migration re-bodied it, or 191 is not applied; nothing was '
                        'changed', COALESCE(v_found, '(absent)')
            USING ERRCODE = '55000',
                  HINT = 'Apply a reconciling migration that re-states the guard with every '
                         'delta instead of this one.';
    END IF;
END $$;

-- ===================================================================
-- (d) THE GUARD: only the verb retires; only the verb's context is audited
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_operator_links_retire_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    -- Inside the verb `current_user` is its owner (257). No login can act as
    -- that role, so outside the verb nothing makes this true.
    v_in_verb  boolean := current_user = 'epigraph_operator_link_retirer';
    v_enforced boolean;
BEGIN
    -- 257's arms are on once the verb is owned by the retirer role; until
    -- then (a cluster where 257 could not re-own it) the verb runs as
    -- `epigraph_maintenance` and 191's behaviour stands.
    SELECT pg_catalog.pg_get_userbyid(p.proowner) = 'epigraph_operator_link_retirer'
      INTO v_enforced
      FROM pg_catalog.pg_proc p
     WHERE p.oid = pg_catalog.to_regprocedure(
               'public.epigraph_retire_operator_link(uuid, text, boolean)');
    v_enforced := COALESCE(v_enforced, false);
    -- The audit trigger (AFTER) reads the verb's context from this setting.
    -- Outside the verb it is whatever the session set, so it is cleared.
    IF v_enforced AND NOT v_in_verb THEN
        PERFORM pg_catalog.set_config('epigraph.operator_link_retire', '', true);
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                WHERE r.rolname = session_user AND r.rolsuper) THEN
        RETURN NEW;
    END IF;
    IF NEW.agent_id IS DISTINCT FROM OLD.agent_id
       OR NEW.operator_id IS DISTINCT FROM OLD.operator_id
       OR NEW.operator_group_id IS DISTINCT FROM OLD.operator_group_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (OLD.retired AND NOT NEW.retired) THEN
        RAISE EXCEPTION 'OLR04: an operator link is only ever retired (retired false -> true); '
                        'a retired link is permanent and a link is never re-pointed (agent %); '
                        'nothing was changed', OLD.agent_id
            USING ERRCODE = '42501';
    END IF;
    IF NOT OLD.retired AND NEW.retired AND v_enforced AND NOT v_in_verb THEN
        RAISE EXCEPTION 'OLR05: only epigraph_retire_operator_link retires an operator link '
                        '(agent %); a direct UPDATE is neither serialised nor attributable; '
                        'nothing was changed', OLD.agent_id
            USING ERRCODE = '42501',
                  HINT = 'epigraph-operator retire-link --agent <id> --reason <why>.';
    END IF;
    -- ZERO write authority is a precondition of a retire on EVERY path, not
    -- only the verb's (107/122 section 7).
    IF NOT OLD.retired AND NEW.retired
       AND EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = OLD.operator_group_id
                      AND m.agent_id = OLD.agent_id
                      AND m.revoked_at IS NULL
                      AND m.role IN ('writer', 'admin')) THEN
        RAISE EXCEPTION 'OLR03: agent % holds a live writer/admin membership in operator '
                        'group %, and a retired identity may hold no write authority there; '
                        'nothing was changed', OLD.agent_id, OLD.operator_group_id
            USING ERRCODE = '55000',
                  HINT = 'Revoke that membership in the same act: epigraph-operator '
                         'retire-link --revoke-membership.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_links_retire_only() FROM PUBLIC;

-- ===================================================================
-- (a)-(c) THE ROLE, THE OWNER, THE COLUMN GRANT
-- ===================================================================
DO $$
DECLARE
    c_role   constant text := 'epigraph_operator_link_retirer';
    c_verb   constant text := 'public.epigraph_retire_operator_link(uuid, text, boolean)';
    v_role   oid;
    v_faults text[];
    -- PostgreSQL 16 split membership into SET / USAGE (INHERIT) / ADMIN, as
    -- 161's attestor check: only SET and USAGE let a role act as this one.
    v_set    text := CASE WHEN current_setting('server_version_num')::integer >= 160000
                          THEN 'SET' ELSE 'MEMBER' END;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        RAISE NOTICE '257: epigraph_maintenance does not exist; the retire verb keeps 191''s '
                     'owner and grants (257 is inert until the role is provisioned)';
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = c_role) THEN
        BEGIN
            CREATE ROLE epigraph_operator_link_retirer NOLOGIN;
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE NOTICE '257: cannot CREATE ROLE epigraph_operator_link_retirer; the '
                             'retire verb keeps 191''s owner and grants. Provision the role '
                             '(NOLOGIN, a member of epigraph_maintenance only) and re-run '
                             'this block as a superuser.';
                RETURN;
            WHEN duplicate_object THEN NULL;
            WHEN unique_violation THEN NULL;
        END;
    END IF;
    SELECT r.oid INTO v_role FROM pg_roles r WHERE r.rolname = c_role;

    -- An existing role is checked, not trusted.
    SELECT array_remove(ARRAY[
               CASE WHEN r.rolsuper THEN c_role || ' is SUPERUSER' END,
               CASE WHEN r.rolbypassrls THEN c_role || ' is BYPASSRLS' END,
               CASE WHEN r.rolcreaterole THEN c_role || ' is CREATEROLE' END,
               CASE WHEN r.rolcreatedb THEN c_role || ' is CREATEDB' END,
               CASE WHEN r.rolreplication THEN c_role || ' is REPLICATION' END,
               CASE WHEN r.rolcanlogin THEN c_role || ' can LOGIN' END],
           NULL)
      INTO v_faults
      FROM pg_roles r WHERE r.oid = v_role;
    v_faults := v_faults || ARRAY(
        SELECT c_role || ' is a member of ' || r.rolname
          FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid
         WHERE m.member = v_role AND r.rolname <> 'epigraph_maintenance'
         ORDER BY 1);
    v_faults := v_faults || ARRAY(
        SELECT r.rolname || ' can act as ' || c_role
          FROM pg_roles r
         WHERE r.oid <> v_role AND NOT r.rolsuper
           AND (pg_has_role(r.oid, v_role, 'USAGE') OR pg_has_role(r.oid, v_role, v_set))
         ORDER BY 1);
    IF cardinality(v_faults) > 0 THEN
        RAISE EXCEPTION '257: % exists but is not isolated: %', c_role, v_faults
            USING ERRCODE = '55000',
                  HINT = 'Only the retire verb may run as this role; remove the attributes '
                         'and grants named before applying migration 257.';
    END IF;

    IF NOT pg_has_role(v_role, 'epigraph_maintenance', 'USAGE') THEN
        BEGIN
            EXECUTE 'GRANT epigraph_maintenance TO epigraph_operator_link_retirer';
        EXCEPTION
            WHEN insufficient_privilege THEN
                RAISE NOTICE '257: cannot GRANT epigraph_maintenance TO %; the retire verb '
                             'keeps 191''s owner and grants', c_role;
                RETURN;
            -- A parallel database granted it first.
            WHEN unique_violation OR duplicate_object THEN NULL;
        END;
    END IF;

    BEGIN
        EXECUTE format('ALTER FUNCTION %s OWNER TO %I', c_verb, c_role);
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE '257: cannot re-own % to % (the migrating login must be a superuser); '
                         'the verb keeps 191''s owner and grants', c_verb, c_role;
            RETURN;
    END;
    -- `ALTER ... OWNER` moved the maintenance role's ACL entry to the new
    -- owner; the maintenance role calls the verb, nobody else does.
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', c_verb);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO epigraph_maintenance', c_verb);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM epigraph_app', c_verb);
    END IF;
    -- The verb's UPDATE needs the column; a maintenance login no longer has it.
    EXECUTE format('GRANT UPDATE (retired) ON public.operator_links TO %I', c_role);
    EXECUTE 'REVOKE UPDATE (retired) ON public.operator_links FROM epigraph_maintenance';
END $$;
