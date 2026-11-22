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
-- (e) The verb and the audit are re-bodied (md5 preconditions on 191's
--     bodies) so a `--revoke-membership` retire records each revoked
--     membership's id and role (`revoked_memberships`), not only the count
--     (backlog 452a1330).
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
-- `epigraph_maintenance`, moves the column grant back, re-states 191's guard,
-- audit and verb bodies).
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

-- -------------------------------------------------------------------
-- Precondition: the verb and the audit still carry 191's bodies, which (e)
-- re-states (same rule, same md5-of-`prosrc` form).
-- -------------------------------------------------------------------
DO $$
DECLARE
    v_found text;
    r       record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('public.epigraph_retire_operator_link(uuid, text, boolean)',
         'fec45262e52a68a4d3f1389f66e13a18'),
        ('public.epigraph_operator_links_audit()', '0820315e8520d8ed4bf4bbfb4a8568fa'))
        AS t(sig, md5)
    LOOP
        SELECT md5(p.prosrc) INTO v_found FROM pg_catalog.pg_proc p
         WHERE p.oid = to_regprocedure(r.sig);
        IF v_found IS DISTINCT FROM r.md5 THEN
            RAISE EXCEPTION '257: % is not the body 257 re-states (191''s, md5 %); found md5 %. '
                            'Another migration re-bodied it, or 191 is not applied; nothing '
                            'was changed', r.sig, r.md5, COALESCE(v_found, '(absent)')
                USING ERRCODE = '55000',
                      HINT = 'Apply a reconciling migration that re-states it with every '
                             'delta instead of this one.';
        END IF;
    END LOOP;
END $$;

-- ===================================================================
-- (e) THE REVOKED MEMBERSHIPS, BY ID AND ROLE, IN THE AUDIT ROW
-- ===================================================================
-- 191's verb recorded only how many membership rows `revoke_membership`
-- revoked, so a revocation could not be reviewed or reversed from its audit
-- row (backlog 452a1330). The verb now passes each revoked row's id and its
-- role (unchanged by the revoke, so the role it held) to the audit as
-- `revoked_memberships` (`[]` when it revoked none), and the audit records
-- it next to the count. Both bodies are otherwise 191's; CREATE OR REPLACE
-- keeps each one's owner, ACL and path.
CREATE OR REPLACE FUNCTION public.epigraph_operator_links_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_ctx jsonb;
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('operator.link_recorded', NEW.agent_id, true,
                jsonb_build_object('operator_id', NEW.operator_id,
                                   'operator_group_id', NEW.operator_group_id,
                                   'retired', NEW.retired,
                                   'recorded_by', session_user));
    ELSIF OLD.retired IS DISTINCT FROM NEW.retired THEN
        -- Set by `epigraph_retire_operator_link` for its own UPDATE only.
        v_ctx := NULLIF(pg_catalog.current_setting('epigraph.operator_link_retire', true),
                        '')::jsonb;
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES (CASE WHEN NEW.retired THEN 'operator.link_retired'
                     ELSE 'operator.link_unretired' END,
                NEW.agent_id, true,
                pg_catalog.jsonb_build_object(
                    'operator_id', NEW.operator_id,
                    'operator_group_id', NEW.operator_group_id,
                    'retired_before', OLD.retired,
                    'retired', NEW.retired,
                    'reason', v_ctx ->> 'reason',
                    'memberships_revoked', (v_ctx ->> 'memberships_revoked')::integer,
                    'revoked_memberships', v_ctx -> 'revoked_memberships',
                    'via', COALESCE(v_ctx ->> 'via', 'direct'),
                    'recorded_by', session_user));
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_retire_operator_link(
    p_agent             uuid,
    p_reason            text,
    p_revoke_membership boolean DEFAULT false)
RETURNS TABLE (outcome text, operator_id uuid, operator_group_id uuid,
               memberships_revoked integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_operator uuid;
    v_group    uuid;
    v_retired  boolean;
    v_revoked  integer := 0;
    v_rows     jsonb := '[]'::jsonb;
BEGIN
    IF public.epigraph_is_elevated() THEN
        RAISE EXCEPTION 'OLR02: an elevated session retires no operator link; nothing was changed'
            USING ERRCODE = '42501';
    END IF;
    IF NOT (public.epigraph_bypass()
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE r.rolname = session_user AND r.rolsuper)) THEN
        RAISE EXCEPTION 'OLR01: only a maintenance session retires an operator link; nothing '
                        'was changed'
            USING ERRCODE = '42501';
    END IF;
    IF p_agent IS NULL OR p_reason IS NULL OR pg_catalog.btrim(p_reason) = ''
       OR p_revoke_membership IS NULL THEN
        RAISE EXCEPTION 'epigraph_retire_operator_link: an agent and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    IF pg_catalog.length(p_reason) > 1000 THEN
        RAISE EXCEPTION 'epigraph_retire_operator_link: the reason is at most 1000 characters'
            USING ERRCODE = '22023';
    END IF;

    -- Every link write and every registration, one at a time (107 section 10).
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('epigraph.operator_links'));

    SELECT l.operator_id, l.operator_group_id, l.retired
      INTO v_operator, v_group, v_retired
      FROM public.operator_links l
     WHERE l.agent_id = p_agent
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'no_link'::text, NULL::uuid, NULL::uuid, 0;
        RETURN;
    END IF;
    IF v_retired THEN
        RETURN QUERY SELECT 'already_retired'::text, v_operator, v_group, 0;
        RETURN;
    END IF;

    -- ZERO write authority is a precondition (122's retire, section 7): the
    -- agent's rows in the operator group, then the group row, locked first.
    PERFORM 1 FROM public.group_memberships m
     WHERE m.group_id = v_group AND m.agent_id = p_agent
       FOR UPDATE;
    PERFORM 1 FROM public.groups g WHERE g.id = v_group FOR UPDATE;
    IF EXISTS (SELECT 1 FROM public.group_memberships m
                WHERE m.group_id = v_group AND m.agent_id = p_agent
                  AND m.revoked_at IS NULL AND m.role IN ('writer', 'admin')) THEN
        IF NOT p_revoke_membership THEN
            RAISE EXCEPTION 'OLR03: agent % holds a live writer/admin membership in operator '
                            'group %, and a retired identity may hold no write authority there; '
                            'nothing was changed', p_agent, v_group
                USING ERRCODE = '55000',
                      HINT = 'Revoke that membership in the same act: epigraph-operator '
                             'retire-link --revoke-membership.';
        END IF;
        -- 257: each revoked row and its role, so the audit row can be
        -- reviewed and the revocation reversed from the record alone.
        WITH revoked AS (
            UPDATE public.group_memberships m
               SET revoked_at = pg_catalog.now()
             WHERE m.group_id = v_group AND m.agent_id = p_agent
               AND m.revoked_at IS NULL AND m.role IN ('writer', 'admin')
            RETURNING m.id, m.role)
        SELECT pg_catalog.count(*)::integer,
               COALESCE(pg_catalog.jsonb_agg(
                            pg_catalog.jsonb_build_object('membership_id', r.id,
                                                          'role', r.role)
                            ORDER BY r.id),
                        '[]'::jsonb)
          INTO v_revoked, v_rows
          FROM revoked r;
    END IF;

    PERFORM pg_catalog.set_config(
        'epigraph.operator_link_retire',
        pg_catalog.jsonb_build_object('reason', p_reason,
                                      'memberships_revoked', v_revoked,
                                      'revoked_memberships', v_rows,
                                      'via', 'epigraph_retire_operator_link')::text,
        true);
    UPDATE public.operator_links l
       SET retired = true
     WHERE l.agent_id = p_agent AND NOT l.retired;
    PERFORM pg_catalog.set_config('epigraph.operator_link_retire', '', true);

    RETURN QUERY SELECT 'retired'::text, v_operator, v_group, v_revoked;
END $$;

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
