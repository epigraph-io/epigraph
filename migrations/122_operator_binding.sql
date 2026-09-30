-- Migration 122: operator binding. Every claim is authored by an agent that is
-- bound to a human operator.
--
-- ===================================================================
-- 1. THE INVARIANT
--
-- Design rule: every WRITING agent is irrevocably tied to one individual human
-- account. Migration 107 recorded the tie (`operator_links`) but nothing
-- required it: `ClaimRepository::default_decl_for_author` authors an unlinked
-- agent's claim into that agent's OWN personal group, and an explicit tenancy
-- declaration never consults a link at all. This file makes the tie a write
-- precondition.
--
-- A claim INSERT (and an UPDATE that changes `claims.agent_id`) is admitted
-- only when its author is BOUND:
--
--   (a) a HUMAN OPERATOR: the agent of an ACTIVE `client_type = 'human'` OAuth
--       client (`epigraph_is_human_operator`). Many humans, each its own
--       operator; nothing here assumes one.
--   (b) holds a LIVE link to a human operator: an `operator_links` row for the
--       agent with `retired = false` whose `operator_id` is (a). A link to
--       anything that is not (a) binds nobody to a human, so it binds nothing.
--
-- Anything else raises SQLSTATE `OPL01` (a custom class, like 105's `RVK01`:
-- `OP` is outside every class PostgreSQL raises), whose message names the fix:
-- record a live link for the agent with the maintenance command
-- `epigraph-operator link`. `epigraph_db::DbError::OperatorLinkRequired` is its
-- named form; HTTP maps it to 403 and MCP to INVALID_REQUEST.
--
-- LIVE means `retired = false`, deliberately NOT the 107 actor read (which also
-- requires a live writer membership): a link is permanent (107), so the tie
-- never lapses. What a live-linked agent may WRITE is section 1b.
--
-- ===================================================================
-- 1b. A LINKED AGENT WRITES ONLY WHERE ITS OWN OPERATOR WRITES (`OPL02`)
--
-- Every agent is tied to exactly one human for life (`operator_links` is keyed
-- on the agent, and 107 refuses a second operator, live or retired), and
-- admin access is the only thing that crosses groups. So a claim authored by a
-- live-linked agent must be owned by a group its OPERATOR holds a live
-- `writer`/`admin` membership in (`epigraph_operator_writes_group`), never by
-- another human's personal or private group and never by the agent's own
-- personal group (which no human holds). A revoked agent therefore writes
-- nothing: its default declaration falls back to its own group, which this
-- refuses. Refused with SQLSTATE `OPL02` (`DbError::OperatorScopeRefused`).
--
-- The same rule guards the door every other write goes through: a `writer` /
-- `admin` row in `group_memberships` for a live-linked agent is refused
-- (`OPL02`) unless its operator writes that group
-- (`group_memberships_operator_scope`), so another human cannot enrol my agent
-- into their group and let it write evidence, edges or beliefs there. A
-- membership that PREDATES the link (or outlives the operator's own) is not
-- revisited; it is a residual this file names rather than hides.
--
-- EXEMPT from 1b only (never from section 1's binding): a privileged session
-- (`epigraph_bypass()`: the maintenance role or a superuser, i.e. the operator
-- CLIs and the audited admin definers) and a session whose principal is a
-- live instance admin (`epigraph_is_instance_admin`, 083). Admin access crosses
-- groups; nothing else does.
--
-- ===================================================================
-- 2. WHERE IT IS ENFORCED: A TRIGGER, SO NO WRITE PATH CAN SKIP IT
--
-- `claims_require_operator_binding` is a BEFORE INSERT OR UPDATE OF agent_id
-- row trigger on `claims`. Every claim write reaches it: REST, MCP over HTTP
-- and stdio, the CLIs, workflow ingest, default and explicit declarations, and
-- a raw INSERT on any role (a superuser included: triggers are not bypassed by
-- BYPASSRLS). It is named to sort BEFORE `claims_require_tenancy`, so an
-- unbound author is refused before any tenancy work.
--
-- `default_decl_for_author` calls the same check
-- (`epigraph_require_bound_author`) BEFORE it resolves a personal group, so the
-- default path refuses before 105's definer can provision a group for an
-- author that may not write at all. The trigger is the guarantee; the early
-- call is a cleaner failure, never a second rule.
--
-- ===================================================================
-- 3. ARMING: ONE-WAY, AND SEPARATE FROM THE MIGRATION
--
-- Applying this file changes NO write. Enforcement starts when a maintenance
-- session calls `epigraph_arm_operator_binding()`
-- (`epigraph-operator arm-operator-binding --apply`), which inserts the single
-- row of `operator_binding_arming` and writes one `security_events` row. Two
-- reasons it is not armed here:
--
--   * DEPLOY ORDER. The operator's order is: migrate, LIVE-link the live
--     writers, tie the legacy authors, backfill, re-own, verify, and only THEN
--     deploy the enforcing binaries. A migration that enforced at once would
--     refuse the still-unlinked live writers between the migrate and the link
--     step, through binaries that map `OPL01` to a bare 500.
--   * A fresh database (every `#[sqlx::test]`, every new install) starts with
--     no human and no links, so enforcing from the first INSERT would refuse
--     every fixture and every bootstrap write.
--
-- ONE-WAY: there is no disarm function, the table grants the maintenance role
-- SELECT and INSERT only (no UPDATE, no DELETE), and the application role
-- nothing but SELECT. Only a superuser can remove the row. The only runtime
-- relief is the valve (section 4).
--
-- ===================================================================
-- 4. THE EMERGENCY VALVE: `EPIGRAPH_OPERATOR_LINK_ENFORCEMENT=off`
--
-- A process reads that variable ONCE, at boot (`epigraph_db::operator_binding`),
-- logs a WARN on every boot while it is off, and then stamps
-- `epigraph.operator_link_enforcement = 'off'` on every connection its
-- `ScopedPool` opens. `epigraph_operator_binding_enforced()` honours that
-- session setting. Default (unset, or any other value): ON.
--
-- The setting is the valve's TRANSPORT, not an authority boundary. Any session
-- can set a custom GUC; a session that can do so can equally INSERT a claim
-- naming any bound agent as its author (`claims.agent_id` is a column the
-- writing session supplies, and 077's policies check the OWNER group, not the
-- author). So the setting adds no capability a database session did not
-- already have; what it guards against is a CODE PATH forgetting the rule,
-- which it does, because nothing sets it but the valve.
--
-- ===================================================================
-- 5. DISCLOSURE, ACCEPTED
--
-- `epigraph_author_binding(agent)`, `epigraph_is_human_operator(agent)` and
-- `epigraph_operator_writes_group(operator, group)` are EXECUTE-able by
-- `epigraph_app` (the repository calls them on the request path) and answer
-- for any id. What they add to 107's accepted disclosure is one bit per agent
-- (whether it is a human operator) and one bit per (operator, group) pair
-- (whether that operator holds a live writer/admin row there), which
-- `group_memberships_tenancy` would otherwise hide from a non-member. Accepted
-- for 107's reason: the request path must ask about the AUTHOR and its
-- OPERATOR, neither of which is the session principal.
--
-- ===================================================================
-- 6. UNDO
--
-- `DROP TRIGGER IF EXISTS claims_require_operator_binding ON public.claims;`
-- then drop the functions and `operator_binding_arming`. To stop enforcing
-- without DDL, set the valve (section 4) on every writing unit and restart it.
-- A link `epigraph_link_legacy_authors` (section 7) recorded is an
-- `operator_links` row like 107's and is permanent by the same rule.
-- **Applied to a throwaway database only, NOT to any deployed database.**

SET LOCAL lock_timeout = '3s';

-- The arming record (section 3). One row or none. Rowless on purpose: its
-- protection is the grant set below, which admits no UPDATE or DELETE to any
-- role but a superuser. No `visibility` / `owner_group_id` columns: it is
-- control state, not a tier-A entity.
CREATE TABLE IF NOT EXISTS public.operator_binding_arming (
    singleton boolean PRIMARY KEY DEFAULT true CONSTRAINT operator_binding_arming_singleton
        CHECK (singleton),
    armed_at  timestamptz NOT NULL DEFAULT now(),
    armed_by  text NOT NULL DEFAULT session_user
);
REVOKE ALL ON public.operator_binding_arming FROM PUBLIC;

-- (a): is this agent a human operator? The agent of an ACTIVE human OAuth
-- client, and nothing else: in particular NOT "some link names it as an
-- operator", because a stdio self-link on a maintenance DSN never asks whether
-- its operator is a human, and a link must not be able to make one.
CREATE OR REPLACE FUNCTION public.epigraph_is_human_operator(p_agent uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT p_agent IS NOT NULL
       AND EXISTS (SELECT 1 FROM public.oauth_clients c
                    WHERE c.agent_id = p_agent
                      AND c.client_type = 'human'
                      AND c.status = 'active')
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_is_human_operator(uuid) FROM PUBLIC;

-- How is this author bound? 'live_link' (b), 'human_operator' (a), or NULL.
CREATE OR REPLACE FUNCTION public.epigraph_author_binding(p_agent uuid)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT CASE
             WHEN p_agent IS NULL THEN NULL
             WHEN public.epigraph_is_human_operator(p_agent) THEN 'human_operator'
             WHEN EXISTS (SELECT 1 FROM public.operator_links l
                           WHERE l.agent_id = p_agent AND NOT l.retired
                             AND public.epigraph_is_human_operator(l.operator_id))
                  THEN 'live_link'
           END
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_author_binding(uuid) FROM PUBLIC;

-- Is enforcement in force on THIS session? Armed, and the valve not off.
CREATE OR REPLACE FUNCTION public.epigraph_operator_binding_enforced()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM public.operator_binding_arming)
       AND COALESCE(current_setting('epigraph.operator_link_enforcement', true), '') <> 'off'
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_binding_enforced() FROM PUBLIC;

-- The check itself: returns quietly, or raises OPL01 naming the fix.
CREATE OR REPLACE FUNCTION public.epigraph_require_bound_author(p_agent uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NOT public.epigraph_operator_binding_enforced() THEN
        RETURN;
    END IF;
    IF public.epigraph_author_binding(p_agent) IS NOT NULL THEN
        RETURN;
    END IF;
    RAISE EXCEPTION 'OPL01: agent % is not bound to a human operator (it is neither a human '
                    'operator nor the holder of a live operator link), and every claim must be '
                    'authored by a bound agent', p_agent
        USING ERRCODE = 'OPL01',
              HINT = 'Record a live link for this agent on a maintenance DSN: '
                     'epigraph-operator link --agent <agent id> --operator <human operator '
                     'agent id> --apply. See docs/tenancy.md "Operator binding".';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_require_bound_author(uuid) FROM PUBLIC;

-- Section 1b: does this operator hold a live writer/admin row in this group?
CREATE OR REPLACE FUNCTION public.epigraph_operator_writes_group(p_operator uuid, p_group uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT p_operator IS NOT NULL AND p_group IS NOT NULL
       AND EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = p_group AND m.agent_id = p_operator
                      AND m.revoked_at IS NULL AND m.role IN ('writer', 'admin'))
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_writes_group(uuid, uuid) FROM PUBLIC;

-- Section 1b's exemption: a privileged session, or an instance-admin principal.
CREATE OR REPLACE FUNCTION public.epigraph_operator_scope_exempt()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT public.epigraph_bypass()
        OR public.epigraph_is_instance_admin(public.epigraph_principal_id())
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_scope_exempt() FROM PUBLIC;

-- Section 1b's check: a live-linked author (not itself a human) may be named on
-- a row owned by `p_group` only if its operator writes that group. Quiet for a
-- human author, an unbound author (section 1 refuses those first), an unarmed
-- database, the valve, and the exemption.
CREATE OR REPLACE FUNCTION public.epigraph_require_operator_scope(p_agent uuid, p_group uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_operator uuid;
BEGIN
    IF NOT public.epigraph_operator_binding_enforced() THEN
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
REVOKE EXECUTE ON FUNCTION public.epigraph_require_operator_scope(uuid, uuid) FROM PUBLIC;

-- The trigger body. A DEFINER owned by the maintenance role, like 070's
-- trigger bodies: PostgreSQL checks EXECUTE on a trigger function when the
-- trigger is CREATED, not when it fires, and the definer frame is what calls
-- the check above. So no writing role (an operator script's login included)
-- needs a grant of its own, and none can meet a 42501 here instead of the
-- rule. It reads nothing itself; the check reads the link and client tables.
CREATE OR REPLACE FUNCTION public.epigraph_claims_require_operator_binding()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.agent_id IS NOT DISTINCT FROM OLD.agent_id THEN
        RETURN NEW;
    END IF;
    PERFORM public.epigraph_require_bound_author(NEW.agent_id);
    PERFORM public.epigraph_require_operator_scope(NEW.agent_id, NEW.owner_group_id);
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_claims_require_operator_binding() FROM PUBLIC;

DROP TRIGGER IF EXISTS claims_require_operator_binding ON public.claims;
CREATE TRIGGER claims_require_operator_binding
    BEFORE INSERT OR UPDATE OF agent_id ON public.claims
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_claims_require_operator_binding();

-- Section 1b at the membership door: a writer/admin row for a live-linked agent
-- only in a group its operator writes. `epigraph_link_operator` inserts the
-- agent's row into the operator's OWN group, which the operator administers,
-- so every link passes.
CREATE OR REPLACE FUNCTION public.epigraph_group_memberships_operator_scope()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL OR NEW.role NOT IN ('writer', 'admin') THEN
        RETURN NEW;
    END IF;
    PERFORM public.epigraph_require_operator_scope(NEW.agent_id, NEW.group_id);
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_group_memberships_operator_scope() FROM PUBLIC;

DROP TRIGGER IF EXISTS group_memberships_operator_scope ON public.group_memberships;
CREATE TRIGGER group_memberships_operator_scope
    BEFORE INSERT OR UPDATE OF role, revoked_at, group_id, agent_id ON public.group_memberships
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_group_memberships_operator_scope();

-- Arm enforcement, once (section 3). Maintenance only; audited.
CREATE OR REPLACE FUNCTION public.epigraph_arm_operator_binding()
RETURNS TABLE (armed_now boolean, armed_at timestamptz, armed_by text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    INSERT INTO public.operator_binding_arming (singleton, armed_by)
    VALUES (true, session_user)
    ON CONFLICT (singleton) DO NOTHING;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows > 0 THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('operator.binding_armed', NULL, true,
                jsonb_build_object('recorded_by', session_user));
    END IF;
    RETURN QUERY
    SELECT v_rows > 0, a.armed_at, a.armed_by FROM public.operator_binding_arming a;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_arm_operator_binding() FROM PUBLIC;

-- Ownership and grants, guarded as every such block since 060 is.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_is_human_operator(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_author_binding(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_operator_binding_enforced() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_require_bound_author(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_arm_operator_binding() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_claims_require_operator_binding() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_operator_writes_group(uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_operator_scope_exempt() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_require_operator_scope(uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_group_memberships_operator_scope() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_writes_group(uuid, uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_scope_exempt() '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_require_operator_scope(uuid, uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_is_human_operator(uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_author_binding(uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_binding_enforced() '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_require_bound_author(uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_arm_operator_binding() '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT SELECT, INSERT ON public.operator_binding_arming '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        -- 077's ALTER DEFAULT PRIVILEGES handed the app role DML on the new
        -- table; take it back and leave SELECT (the arming state is not
        -- secret, and every relation must be app-readable).
        EXECUTE 'REVOKE ALL ON public.operator_binding_arming FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.operator_binding_arming TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_arm_operator_binding() '
                'FROM epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_is_human_operator(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_author_binding(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_binding_enforced() '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_require_bound_author(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_writes_group(uuid, uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_require_operator_scope(uuid, uuid) '
                'TO epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 7. TYING THE LEGACY AUTHORS: `epigraph_link_legacy_authors`
--
-- The rule covers EXISTING rows too: every agent that ever authored a tier-A
-- row must be tied to a human. Most historical identities will never run
-- again, so the tie is 107's RETIRED link (section 7 there): the operator owns
-- what they wrote, and they gain ZERO write authority (no membership is
-- created or touched). This definer records one for every agent that
-- authored a tier-A row and has NO `operator_links` row of any state, in one
-- audited call.
--
-- "Authored" means named in an author column: `claims.agent_id`,
-- `evidence.signer_id`, `claim_versions.created_by`,
-- `mass_functions.source_agent_id`, `challenges.challenger_id`,
-- `claim_signature_revocations.revoked_by`, `perspectives.owner_agent_id`,
-- `recall_events.agent_id`. NOT `edges.signer_id`, which on legacy rows is a
-- bulk attestation key rather than an author (`epigraph-operator`'s
-- `tables::EDGE_WRITER` records why).
--
-- REFUSED (55000 / 22023 / 22004, nothing written): an operator that is not a
-- HUMAN operator (section 1 arm (a)); an operator that is itself operated; an
-- operator carrying 107's shared-signer fingerprint; 105's RVK01 / RVK02 on the
-- operator's personal group; a NULL operator or a NULL in the exclusion set.
--
-- SKIPPED, per agent, reported and never written (a retired link is permanent
-- and never promoted, so a wrong one strands an agent for good):
--
--   excluded          the caller listed it (`p_exclude`);
--   human_operator    a human operator itself (arm (a)): it binds on its own,
--                     and an agent that operates others cannot be operated
--                     (107's single hop);
--   oauth_principal   the agent of an un-revoked OAuth client: ANY link makes
--                     an agent stdio-only (its token and viewer are refused),
--                     so an HTTP principal is not tied by side effect;
--   write_authority   a live writer/admin row in the operator's group: 107's
--                     retire refuses that, and such an agent wants a LIVE link;
--   foreign_write_authority
--                     a live writer/admin row in a group (other than its own
--                     personal group) that the operator does NOT write: it acts
--                     in someone else's group, possibly another human's, and
--                     tying it to this operator would misattribute that;
--   shared_signer     107's fingerprint (OPERATED_BY lineage to more than one
--                     principal): retire it with 116's attested variant;
--   recent_writer     it authored a claim at or after `p_quiet_since`: it may
--                     still be running, and a retired identity can never write
--                     again once binding is armed. Give it a LIVE link, or pass
--                     no cutoff once it is known to be retired.
--
-- Idempotent: an agent with any link is not a candidate, so a re-run links
-- only what is new. ONE `security_events` row per call
-- (`operator.legacy_authors_linked`), with the counts. Serialised with every
-- other link write by 107 section 10's advisory lock; the operator's group row
-- is locked FOR UPDATE before the write-authority check, as 107's retire does.

CREATE OR REPLACE FUNCTION public.epigraph_link_legacy_authors(
    p_operator    uuid,
    p_exclude     uuid[] DEFAULT '{}',
    p_quiet_since timestamptz DEFAULT NULL)
RETURNS TABLE (agent_id uuid, outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
#variable_conflict use_column
DECLARE
    v_group      uuid;
    v_agent      uuid;
    v_outcome    text;
    v_counts     jsonb := '{}'::jsonb;
    v_candidates integer := 0;
    v_linked     integer := 0;
    v_rows       integer;
BEGIN
    IF p_operator IS NULL THEN
        RAISE EXCEPTION 'epigraph_link_legacy_authors: the operator is required'
            USING ERRCODE = '22004';
    END IF;
    p_exclude := COALESCE(p_exclude, '{}');
    IF array_position(p_exclude, NULL) IS NOT NULL THEN
        RAISE EXCEPTION 'epigraph_link_legacy_authors: the exclusion set contains a NULL'
            USING ERRCODE = '22004';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    IF NOT EXISTS (SELECT 1 FROM public.agents a WHERE a.id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_legacy_authors: operator % does not exist', p_operator
            USING ERRCODE = '22023';
    END IF;
    IF NOT public.epigraph_is_human_operator(p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_legacy_authors: % is not a human operator (not the agent '
                        'of an active human OAuth client, and no link names it as an operator); '
                        'legacy authors are tied to a human or not at all', p_operator
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_legacy_authors: % is itself operated by another agent '
                        'and cannot be an operator', p_operator
            USING ERRCODE = '55000';
    END IF;
    IF (SELECT count(DISTINCT e.target_id) FROM public.edges e
         WHERE e.source_id = p_operator AND e.relationship = 'OPERATED_BY') > 1 THEN
        RAISE EXCEPTION 'epigraph_link_legacy_authors: operator % carries OPERATED_BY '
                        'auth-lineage edges to more than one principal, the fingerprint of a '
                        'shared HTTP signer; refusing it as an operator', p_operator
            USING ERRCODE = '55000';
    END IF;

    -- The operator's personal group, through 105's definer (RVK01 / RVK02
    -- abort the call before anything is written).
    v_group := public.epigraph_ensure_personal_group(p_operator);
    PERFORM 1 FROM public.groups g WHERE g.id = v_group FOR UPDATE;

    FOR v_agent IN
        SELECT x.id
          FROM (SELECT c.agent_id AS id FROM public.claims c
                UNION SELECT v.signer_id FROM public.evidence v
                UNION SELECT cv.created_by FROM public.claim_versions cv
                UNION SELECT mf.source_agent_id FROM public.mass_functions mf
                UNION SELECT ch.challenger_id FROM public.challenges ch
                UNION SELECT r.revoked_by FROM public.claim_signature_revocations r
                UNION SELECT p.owner_agent_id FROM public.perspectives p
                UNION SELECT re.agent_id FROM public.recall_events re) x
          JOIN public.agents a ON a.id = x.id
         WHERE x.id <> p_operator
           AND NOT EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = x.id)
         ORDER BY x.id
    LOOP
        v_candidates := v_candidates + 1;
        v_outcome := CASE
            WHEN v_agent = ANY (p_exclude) THEN 'skipped:excluded'
            WHEN public.epigraph_is_human_operator(v_agent) THEN 'skipped:human_operator'
            WHEN EXISTS (SELECT 1 FROM public.oauth_clients c
                          WHERE c.agent_id = v_agent AND c.status <> 'revoked')
                THEN 'skipped:oauth_principal'
            WHEN EXISTS (SELECT 1 FROM public.group_memberships m
                          WHERE m.group_id = v_group AND m.agent_id = v_agent
                            AND m.revoked_at IS NULL AND m.role IN ('writer', 'admin'))
                THEN 'skipped:write_authority'
            WHEN EXISTS (SELECT 1 FROM public.group_memberships m
                           JOIN public.groups g ON g.id = m.group_id
                          WHERE m.agent_id = v_agent
                            AND m.revoked_at IS NULL AND m.role IN ('writer', 'admin')
                            AND NOT (g.kind = 'personal' AND g.created_by_agent_id = v_agent)
                            AND NOT public.epigraph_operator_writes_group(p_operator, m.group_id))
                THEN 'skipped:foreign_write_authority'
            WHEN (SELECT count(DISTINCT e.target_id) FROM public.edges e
                   WHERE e.source_id = v_agent AND e.relationship = 'OPERATED_BY') > 1
                THEN 'skipped:shared_signer'
            WHEN p_quiet_since IS NOT NULL
                 AND EXISTS (SELECT 1 FROM public.claims c
                              WHERE c.agent_id = v_agent AND c.created_at >= p_quiet_since)
                THEN 'skipped:recent_writer'
            ELSE 'linked'
        END;

        IF v_outcome = 'linked' THEN
            INSERT INTO public.operator_links (agent_id, operator_id, operator_group_id, retired)
            VALUES (v_agent, p_operator, v_group, true)
            ON CONFLICT (agent_id) DO NOTHING;
            GET DIAGNOSTICS v_rows = ROW_COUNT;
            IF v_rows = 0 THEN
                v_outcome := 'skipped:raced';
            ELSE
                v_linked := v_linked + 1;
                INSERT INTO public.edges (source_id, source_type, target_id, target_type,
                                          relationship, properties)
                SELECT v_agent, 'agent', p_operator, 'agent', 'OPERATED_BY',
                       jsonb_build_object('source', 'epigraph_link_legacy_authors')
                 WHERE NOT EXISTS (SELECT 1 FROM public.edges e
                                    WHERE e.source_id = v_agent AND e.target_id = p_operator
                                      AND e.relationship = 'OPERATED_BY');
            END IF;
        END IF;

        v_counts := jsonb_set(v_counts, ARRAY[v_outcome],
                              to_jsonb(COALESCE((v_counts ->> v_outcome)::integer, 0) + 1));
        agent_id := v_agent;
        outcome := v_outcome;
        RETURN NEXT;
    END LOOP;

    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('operator.legacy_authors_linked', p_operator, true,
            jsonb_build_object('operator_id', p_operator,
                               'operator_group_id', v_group,
                               'candidates', v_candidates,
                               'linked', v_linked,
                               'outcomes', v_counts,
                               'excluded', cardinality(p_exclude),
                               'quiet_since', p_quiet_since,
                               'recorded_by', session_user));
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_link_legacy_authors(uuid, uuid[], timestamptz)
    FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_link_legacy_authors(uuid, uuid[], timestamptz) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_link_legacy_authors(uuid, uuid[], timestamptz) '
                'TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'REVOKE EXECUTE ON FUNCTION '
                'public.epigraph_link_legacy_authors(uuid, uuid[], timestamptz) '
                'FROM epigraph_app';
    END IF;
END $$;
