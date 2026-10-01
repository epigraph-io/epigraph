-- ===================================================================
-- 123-undo.sql: take migration 123 (the custodian role) back to 122's
-- behaviour, in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST. Roll back every binary that calls a 123 function BEFORE this
-- runs (docs/deploy.md, "The custodian role (migration 123)"):
-- epigraph-operator (grant-role, end-role-assignment, list-role-assignments,
-- custodial-supersede), epigraph-api (privatization records custodial acts
-- and reads the assignment) and epigraph-tenancy-backfill (its verify lists
-- the 123 definers; presence-gated, so an older verify is fine). A new binary
-- left serving after this script fails every such call with 42883.
--
-- WHAT IT DOES
--   1. THE RESURRECTION GUARD. 083's body (restored in step 3) reads
--      `instance_admins`. Every live legacy row whose agent holds NO live
--      custodian assignment now is stamped `revoked_at = now()` first, so an
--      authority ended after 123 (an ended assignment, a revoked human, an
--      agent that was skipped at migration time) does not come back. 123's
--      mirrors should already have stamped them; this is the belt.
--      083 has no window: a holder whose live assignment ENDS at a
--      `valid_to` keeps an open-ended legacy row after the undo. Step 1 lists
--      each such holder (NOTICE) so the operator ends it by hand at its
--      `valid_to`; the script does not cut a live custodian short.
--   2. Drops 123's triggers on `instance_admins`, `human_operators` and
--      `operator_links` (the freeze, the revoke mirror, the role-node guards).
--   3. Re-applies, VERBATIM, 083's `epigraph_is_instance_admin` and 122's
--      `epigraph_operator_scope_exempt`, `epigraph_require_operator_scope`,
--      `epigraph_require_writer_scope`, `epigraph_require_attributable` and
--      `epigraph_claims_require_operator_binding`: the round-4 fixes
--      (self-supersede refusal, restate-at-most-once, the privileged-only
--      re-open relief) revert with them, and so does OQ-1 (b): under 122's
--      `epigraph_operator_scope_exempt` an instance-admin PRINCIPAL is
--      relieved of the cross-human scope on an application session again.
--      `custodian_role.rs::the_rollback_restores_122_and_083` pins each body
--      byte-equal to a database at 122.
--   4. Drops the `platform.` restrictive policy on `security_events`, the
--      triggers on `role_assignments` / `platform_roles`, and every 123
--      definer.
--   5. Lists, for the operator, every assignment granted AFTER 123 that is
--      still un-ended: those holders exist only in `role_assignments`, and
--      re-granting any of them in `instance_admins` (writable again after
--      step 2) is a deliberate operator act, not this script's.
--
-- WHAT IT LEAVES: `role_assignments`, `platform_roles`, the role nodes, the
-- `platform.` audit rows and the OCCUPIES edges (history; forward-fix only),
-- and 123's `_sqlx_migrations` row. Re-introducing the role is a NEW
-- migration, never a re-run of 123.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

-- 1. The resurrection guard (the freeze trigger admits exactly this stamp).
UPDATE public.instance_admins ia
   SET revoked_at = now()
 WHERE ia.revoked_at IS NULL
   AND public.epigraph_live_role_assignment(ia.agent_id, 'role:platform-custodian', now())
       IS NULL;

-- 1b. Time-bounded holders become open-ended under 083: listed, not changed.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT ra.holder_person_id, ra.id, ra.valid_to
               FROM public.role_assignments ra
               JOIN public.instance_admins ia
                 ON ia.agent_id = ra.holder_person_id AND ia.revoked_at IS NULL
              WHERE ra.id = public.epigraph_live_role_assignment(ra.holder_person_id,
                                                                 'role:platform-custodian', now())
                AND ra.valid_to IS NOT NULL
              ORDER BY ra.valid_to LOOP
        RAISE NOTICE '123-undo: % holds role:platform-custodian until % (assignment %); under '
                     '083 its instance_admins row has no end. Revoke it by hand at that time.',
                     r.holder_person_id, r.valid_to, r.id;
    END LOOP;
END $$;

-- 2. 123's triggers on tables 122 and 083 own.
DROP TRIGGER IF EXISTS instance_admins_frozen ON public.instance_admins;
DROP TRIGGER IF EXISTS human_operators_mirror_instance_admins ON public.human_operators;
DROP TRIGGER IF EXISTS human_operators_refuse_role_node ON public.human_operators;
DROP TRIGGER IF EXISTS operator_links_refuse_role_node ON public.operator_links;

-- 3. 083's and 122's bodies, verbatim (copied from the migration files; do
--    not re-type them).
-- from migration 083
CREATE OR REPLACE FUNCTION public.epigraph_is_instance_admin(p_agent uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT COALESCE(
        p_agent IS NOT NULL
        AND (p_agent = public.epigraph_principal_id() OR public.epigraph_bypass())
        AND EXISTS (
            SELECT 1 FROM public.instance_admins
             WHERE agent_id = p_agent AND revoked_at IS NULL),
        false)
$$;

-- from migration 122
CREATE OR REPLACE FUNCTION public.epigraph_operator_scope_exempt()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT public.epigraph_bypass()
        OR public.epigraph_is_instance_admin(public.epigraph_principal_id())
$$;

-- from migration 122
CREATE OR REPLACE FUNCTION public.epigraph_require_operator_scope(p_agent uuid, p_group uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_operator uuid;
BEGIN
    IF NOT public.epigraph_operator_binding_armed() THEN
        RETURN;
    END IF;
    IF public.epigraph_is_human_operator(p_agent) THEN
        RETURN;
    END IF;
    SELECT l.operator_id INTO v_operator
      FROM public.operator_links l
     WHERE l.agent_id = p_agent AND NOT l.retired;
    IF v_operator IS NULL OR public.epigraph_operator_writes_group(v_operator, p_group) THEN
        RETURN;
    END IF;
    IF public.epigraph_operator_scope_exempt() THEN
        RETURN;
    END IF;
    RAISE EXCEPTION 'OPL02: agent % is linked to operator %, which holds no writer/admin '
                    'membership in group %; a linked agent writes only where its own operator '
                    'writes', p_agent, v_operator, p_group
        USING ERRCODE = 'OPL02',
              HINT = 'Write into a group the operator writes (its personal group is the '
                     'default), or have the operator join the group first. Admin access '
                     'crosses groups; nothing else does.';
END $$;

-- from migration 122
CREATE OR REPLACE FUNCTION public.epigraph_require_writer_scope(p_agent uuid, p_group uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_human uuid;
BEGIN
    IF NOT public.epigraph_operator_binding_armed() THEN
        RETURN;
    END IF;
    v_human := public.epigraph_human_of(p_agent, false);
    IF v_human IS NULL OR public.epigraph_operator_writes_group(v_human, p_group) THEN
        RETURN;
    END IF;
    IF public.epigraph_operator_scope_exempt() THEN
        RETURN;
    END IF;
    IF v_human = p_agent THEN
        RAISE EXCEPTION 'OPL02: human operator % holds no writer/admin membership in group %; '
                        'a human writes only where it writes', p_agent, p_group
            USING ERRCODE = 'OPL02',
                  HINT = 'Write into a group you write (your personal group is the default). '
                         'Admin access crosses groups; nothing else does.';
    END IF;
    RAISE EXCEPTION 'OPL02: agent % is linked to operator %, which holds no writer/admin '
                    'membership in group %; a linked agent writes only where its own operator '
                    'writes', p_agent, v_human, p_group
        USING ERRCODE = 'OPL02',
              HINT = 'Write into a group the operator writes (its personal group is the '
                     'default), or have the operator join the group first. Admin access '
                     'crosses groups; nothing else does.';
END $$;

-- from migration 122
CREATE OR REPLACE FUNCTION public.epigraph_require_attributable(
    p_author uuid, p_writer uuid, p_inherited boolean)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_author_human uuid;
    v_writer_human uuid;
BEGIN
    IF NOT public.epigraph_operator_binding_armed() THEN
        RETURN;
    END IF;
    v_writer_human := public.epigraph_human_of(p_writer, true);
    v_author_human := public.epigraph_human_of(p_author, NOT COALESCE(p_inherited, false));
    IF v_author_human IS NULL THEN
        -- No human for this row's kind. A RETIRED identity still belongs to
        -- its human: a writer outside that human is refused below (OPL02,
        -- whatever the valve), before the binding check the valve relieves.
        v_author_human := public.epigraph_human_of(p_author, false);
        IF v_author_human IS NULL OR v_author_human = v_writer_human
           OR public.epigraph_operator_scope_exempt() THEN
            PERFORM public.epigraph_require_bound_author(p_author);
            RETURN;
        END IF;
    ELSIF v_writer_human = v_author_human THEN
        RETURN;
    ELSIF public.epigraph_operator_scope_exempt() THEN
        RETURN;
    END IF;
    IF v_writer_human IS NULL THEN
        RAISE EXCEPTION 'OPL02: the writing principal % belongs to no human operator, and a claim '
                        'it writes may not be attributed to %, which belongs to human operator %; '
                        'an unbound writer names no bound author', p_writer, p_author,
                        v_author_human
            USING ERRCODE = 'OPL02',
                  HINT = 'Author the claim as the writing agent itself. The valve relieves the '
                         'binding (OPL01) only; admin access crosses humans; nothing else does.';
    END IF;
    RAISE EXCEPTION 'OPL02: agent % writes a claim attributed to %, which belongs to human '
                    'operator %, not to the writer''s operator %; a claim may name only an '
                    'author of the writer''s own human', p_writer, p_author, v_author_human,
                    v_writer_human
        USING ERRCODE = 'OPL02',
              HINT = 'Author the claim as the writing agent itself. Admin access crosses '
                     'humans; nothing else does.';
END $$;

-- from migration 122
CREATE OR REPLACE FUNCTION public.epigraph_claims_require_operator_binding()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_writer uuid;
    v_inherited boolean := false;
    v_reopen boolean := false;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.agent_id IS NOT DISTINCT FROM OLD.agent_id THEN
        -- Only `supersedes` / `is_current` (the trigger's other columns) can
        -- have changed. Cheap OLD/NEW tests first: a retire or an untouched
        -- column returns before any table is read.
        v_reopen := NOT COALESCE(OLD.is_current, true) AND COALESCE(NEW.is_current, true);
        IF NOT v_reopen
           AND (NEW.supersedes IS NOT DISTINCT FROM OLD.supersedes OR OLD.supersedes IS NULL) THEN
            RETURN NEW;
        END IF;
        IF NOT public.epigraph_operator_binding_armed()
           OR public.epigraph_operator_scope_exempt() THEN
            RETURN NEW;
        END IF;
        IF NEW.supersedes IS DISTINCT FROM OLD.supersedes AND OLD.supersedes IS NOT NULL
           AND (NEW.supersedes IS NULL OR COALESCE(NEW.is_current, true)) THEN
            RAISE EXCEPTION 'OPL02: claim % records that it supersedes %; an application session '
                            'does not clear, or re-point on a current claim, the lineage of an '
                            'existing claim', NEW.id, OLD.supersedes
                USING ERRCODE = 'OPL02',
                      HINT = 'Supersede the claim instead, or retire it in the same statement '
                             '(the dedup act). Admin access crosses humans; nothing else does.';
        END IF;
        IF NOT v_reopen THEN
            RETURN NEW;
        END IF;
        -- A RE-OPEN on a non-exempt session: checked below as an INSERT of NEW.
    ELSIF NOT public.epigraph_operator_binding_armed() THEN
        RETURN NEW;
    END IF;
    -- RE-ATTRIBUTION. Every check below reads the NEW author only, so an
    -- UPDATE that changes it would let a writer take over (or hand off) a
    -- claim someone else said, including another human's claim in a group
    -- both humans write. No repository or route changes `claims.agent_id`;
    -- only the exemption (a privileged session, an instance-admin principal)
    -- may, and it is then checked like an insert below. OPL02, keyed on the
    -- arming: it is attribution, which the valve never relieves.
    IF TG_OP = 'UPDATE' AND NOT v_reopen AND NOT public.epigraph_operator_scope_exempt() THEN
        RAISE EXCEPTION 'OPL02: claim % is attributed to %; an application session does not '
                        're-attribute an existing claim (here to %)', NEW.id, OLD.agent_id,
                        NEW.agent_id
            USING ERRCODE = 'OPL02',
                  HINT = 'Supersede the claim instead: the successor is written, and attributed, '
                         'by the writer. Admin access crosses humans; nothing else does.';
    END IF;
    v_writer := public.epigraph_principal_id();
    -- NO PRINCIPAL on an application session is an unbound writer, not a
    -- licence to be checked on the author column alone: a route that forgot
    -- to stamp its viewer would otherwise write as whatever bound author its
    -- request body named, into that author's group. Fail closed (OPL01, so
    -- the valve relieves it and nothing else does); with the valve open the
    -- author arm below still applies its OPL02.
    IF v_writer IS NULL AND NOT public.epigraph_bypass()
       AND public.epigraph_operator_binding_enforced() THEN
        RAISE EXCEPTION 'OPL01: this application session carries no authenticated principal, '
                        'so the writer of this claim (attributed to %) is not bound to a human '
                        'operator; once armed, a claim is written only by a bound, stamped '
                        'writer', NEW.agent_id
            USING ERRCODE = 'OPL01',
                  HINT = 'Write on a transaction stamped with the request''s viewer '
                         '(ScopedPool::begin_as). See docs/tenancy.md "Operator binding".';
    END IF;
    IF (TG_OP = 'INSERT' OR v_reopen) AND NEW.supersedes IS NOT NULL THEN
        v_inherited :=
            EXISTS (SELECT 1 FROM public.claims p
                     WHERE p.id = NEW.supersedes
                       AND p.agent_id IS NOT DISTINCT FROM NEW.agent_id
                       AND p.owner_group_id IS NOT DISTINCT FROM NEW.owner_group_id
                       AND NOT COALESCE(p.is_current, true))
            AND NOT EXISTS (SELECT 1 FROM public.claims s
                             WHERE s.supersedes = NEW.supersedes AND s.id <> NEW.id
                               AND COALESCE(s.is_current, true));
    END IF;
    IF v_writer IS NULL OR v_writer = NEW.agent_id OR public.epigraph_bypass() THEN
        -- THE PLATFORM CORPUS'S EDIT PATH. A PRIVILEGED session (the
        -- maintenance role or a superuser: `epigraph_bypass()`, which no
        -- application session can forge) restating a retired predecessor
        -- carries that predecessor's author whatever its binding: world-owned
        -- legacy rows are authored by retired-linked or unlinked identities by
        -- construction, so the author check would refuse every such supersede.
        -- Nothing else is relieved: a fresh claim, or a posed successor, is
        -- checked on its author as always, and an instance-admin PRINCIPAL
        -- writing as itself is not relieved here (it is a stamp an application
        -- session sets). Its supersede of ANOTHER author's retired-linked claim
        -- takes the ELSE branch: the attribution check's inherited rule.
        IF NOT (v_inherited AND public.epigraph_bypass()) THEN
            PERFORM public.epigraph_require_bound_author(NEW.agent_id);
        END IF;
        PERFORM public.epigraph_require_writer_scope(NEW.agent_id, NEW.owner_group_id);
    ELSE
        PERFORM public.epigraph_require_bound_writer(v_writer);
        PERFORM public.epigraph_require_writer_scope(v_writer, NEW.owner_group_id);
        PERFORM public.epigraph_require_attributable(NEW.agent_id, v_writer, v_inherited);
    END IF;
    RETURN NEW;
END $$;

-- 4. 123's audit reservation, its table triggers, and its definers.
DROP POLICY IF EXISTS security_events_platform_privileged ON public.security_events;
DROP TRIGGER IF EXISTS role_assignments_audit ON public.role_assignments;
DROP TRIGGER IF EXISTS role_assignments_guard_insert ON public.role_assignments;
DROP TRIGGER IF EXISTS role_assignments_guard_update ON public.role_assignments;
DROP TRIGGER IF EXISTS platform_roles_guard_update ON public.platform_roles;
DROP FUNCTION IF EXISTS public.epigraph_record_custodial_act(uuid, uuid, text, text, uuid, jsonb);
DROP FUNCTION IF EXISTS public.epigraph_platform_audit(timestamptz, integer);
DROP FUNCTION IF EXISTS public.epigraph_end_role_assignment(uuid, text);
DROP FUNCTION IF EXISTS public.epigraph_grant_role(text, uuid, timestamptz, timestamptz, uuid, text);
DROP FUNCTION IF EXISTS public.epigraph_human_operators_mirror_instance_admins();
DROP FUNCTION IF EXISTS public.epigraph_instance_admins_frozen();
DROP FUNCTION IF EXISTS public.epigraph_refuse_role_node_subject();
DROP FUNCTION IF EXISTS public.epigraph_role_assignments_audit();
DROP FUNCTION IF EXISTS public.epigraph_holds_role(uuid, text, timestamptz);
DROP FUNCTION IF EXISTS public.epigraph_role_assignment_for(uuid, text, timestamptz);
DROP FUNCTION IF EXISTS public.epigraph_role_assignments_guard_update();
DROP FUNCTION IF EXISTS public.epigraph_role_assignments_guard_insert();
DROP FUNCTION IF EXISTS public.epigraph_live_role_assignment(uuid, text, timestamptz);
DROP FUNCTION IF EXISTS public.epigraph_platform_roles_guard_update();

-- 5. For the operator: holders granted after 123 and still un-ended. Each
--    exists only here; re-grant in instance_admins by hand if it must
--    survive the rollback.
SELECT ra.holder_person_id, ra.valid_from, ra.valid_to, ra.reason
  FROM public.role_assignments ra
 WHERE ra.role = 'role:platform-custodian' AND ra.revoked_at IS NULL
   AND ra.granted_via <> 'migration 123'
 ORDER BY ra.valid_from;

COMMIT;
