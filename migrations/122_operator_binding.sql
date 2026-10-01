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
-- A claim INSERT (and an UPDATE that changes `claims.agent_id`, which only a
-- privileged session or an instance-admin principal may make: section 2) is
-- admitted only when its author is BOUND, and, when the session's authenticated
-- principal is not the author, only when that WRITER is bound too (section 2;
-- the one privileged-session exception, restating a retired claim, is in 1b):
--
--   (a) a HUMAN OPERATOR (`epigraph_is_human_operator`): an agent with a live
--       row in the maintenance-only registry `human_operators` (section 1c)
--       AND the agent of an ACTIVE `client_type = 'human'` OAuth client. Many
--       humans, each its own operator; nothing here assumes one.
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
-- admin access is the only thing that crosses groups. So a claim written by a
-- live-linked agent must be owned by a group its OPERATOR holds a live
-- `writer`/`admin` membership in (`epigraph_operator_writes_group`), never by
-- another human's personal or private group and never by the agent's own
-- personal group (which no human holds); and a claim written by a human must be
-- owned by a group that human writes (`epigraph_require_writer_scope`: on the
-- claims path a human is scoped like everyone). A revoked agent therefore
-- writes nothing: its default declaration falls back to its own group, which
-- this refuses. A claim may also NAME, as its author, only an agent of the
-- writer's own human (`epigraph_require_attributable`), so one human's agent
-- cannot put words in another human's mouth. Refused with SQLSTATE `OPL02`
-- (`DbError::OperatorScopeRefused`).
--
-- The same rule guards the door every other write goes through: a `writer` /
-- `admin` row in `group_memberships` for a live-linked agent is refused
-- (`OPL02`) unless its operator writes that group
-- (`group_memberships_operator_scope`), so another human cannot enrol my agent
-- into their group and let it write evidence, edges or beliefs there. A
-- membership that PREDATES the link (or outlives the operator's own) is not
-- revisited here; `epigraph-operator link` lists such rows and revokes them on
-- request (`--revoke-foreign-writes`). The link definer does not refuse them:
-- any application session can enrol an unlinked agent as a writer in its own
-- group, so a refusal would let it strand every new agent (measured by review).
--
-- Section 1b is enforced whenever the database is ARMED, whatever the
-- session's valve (section 4): the valve relieves the binding, never the
-- cross-human scope.
--
-- EXEMPT from 1b only: a privileged session (`epigraph_bypass()`: the
-- maintenance role or a superuser, i.e. the operator CLIs and the audited
-- admin definers) and a session whose principal is a live instance admin
-- (`epigraph_is_instance_admin`, 083). Admin access crosses groups; nothing
-- else does. Neither is exempt from section 1's binding, with ONE exception
-- for the privileged session alone: its supersede, whose successor inherits a
-- retired predecessor's author and group (section 2), is admitted whatever
-- that author's binding. That is the platform corpus's edit path: world-owned
-- legacy rows are authored by retired-linked or unlinked identities by
-- construction. An instance-admin principal is not relieved of the binding,
-- because it is a stamp an application session sets (section 4).
--
-- ===================================================================
-- 1c. WHO IS A HUMAN: AN EXPLICIT, AUDITED REGISTRY (OB7)
--
-- Neither signal the schema already had is proof of a human. "Some link names
-- it as an operator" certified itself: 107's `epigraph_link_operator` never
-- asked whether its operator is a human, so linking X to Y made Y one. And
-- `client_type = 'human'` alone is what an unauthenticated dynamic client
-- registration is typed as. So (a) requires BOTH a live row in
-- `human_operators`, which only a maintenance session writes, AND the ONE
-- OAuth client that row names (`client_id`) still being an active human client
-- of the agent. Keyed on that client, not on "any active human client": the
-- application role may INSERT `oauth_clients` (dynamic registration) but not
-- UPDATE it, so it cannot undo a suspension by minting a fresh active client.
-- Nor can it re-activate the suspended client itself through 118's approval
-- definer: `oauth_clients_reactivation_guard` lets only a privileged session
-- take a client out of `suspended` or `revoked`.
--
-- The rules live on the TABLE, not only in the two definers
-- (`epigraph_register_human_operator`, `epigraph_revoke_human_operator`): a
-- BEFORE INSERT trigger requires the named (or the agent's one) active human
-- client; a BEFORE UPDATE trigger admits only a revoke, and nothing at all on
-- a revoked row (revoke is final); an AFTER trigger writes the one
-- `security_events` row per registration and per revoke
-- (`operator.human_registered` / `operator.human_revoked`). So a maintenance
-- login's direct INSERT or UPDATE, which its grants admit because the definers
-- run as that role, meets the same checks and leaves the same audit. The app
-- role may only SELECT.
--
-- The registry also gates the LINK RECORD: `operator_links_operator_is_human`
-- (BEFORE INSERT on `operator_links`) refuses a new link whose operator is not
-- (a), on every path (107's two link functions, 116's attested retire, a raw
-- INSERT), ARMED OR NOT: a link row is permanent, so a link to a non-human
-- recorded before arming could never be corrected. It fires after each link
-- function's own refusals (they raise before their INSERT), and it is skipped
-- when a row for the agent already exists (the INSERT is an `ON CONFLICT DO
-- NOTHING` re-link that will be discarded): an exact re-link of an existing
-- link is never refused by it. Because (b) re-checks (a) at write time, a live
-- link whose operator is revoked from the registry, or whose human client is
-- suspended, stops authorising at once.
--
-- ===================================================================
-- 2. WHERE IT IS ENFORCED: A TRIGGER, SO NO WRITE PATH CAN SKIP IT
--
-- `claims_require_tenancy_then_operator_binding` is a BEFORE INSERT OR UPDATE
-- OF agent_id, supersedes row trigger on `claims` (the `supersedes` half only
-- guards an existing claim's lineage; see the trigger body's comment). Every
-- claim write reaches it: REST, MCP over HTTP and stdio, the CLIs, workflow
-- ingest, default and explicit
-- declarations, and a raw INSERT on any role (a superuser included: triggers
-- are not bypassed by BYPASSRLS). It is named to sort AFTER
-- `claims_require_tenancy`, because section 1b reads `owner_group_id`, which
-- that trigger fills for a supersede or a step-lineage insert.
--
-- WHO it binds. `claims.agent_id` is a column the writing session supplies
-- (REST takes it from the request body), so binding it alone let any session
-- write as any bound author. The trigger therefore binds the session's
-- authenticated PRINCIPAL (`epigraph_principal_id()`, stamped by `ScopedPool`
-- from the viewer) whenever it differs from the author: the writer must be
-- bound (OPL01), must write the owner group (OPL02), and may name as author
-- only a bound agent of its own human (OPL01 / OPL02 otherwise); the author a
-- supersede INHERITS (a new row naming `supersedes` whose predecessor has that
-- author and group, is already retired, and has no other current successor:
-- what the supersede act writes) may also be a RETIRED agent of that human, so
-- a human superseding its own legacy author's claim is admitted, while a fresh
-- claim naming a retired identity is not, however `supersedes` is posed. With a
-- principal equal to the author, or on a privileged session, the author is
-- the one checked. With NO principal on an application session the writer is
-- unbound: refused OPL01 (fail closed, so a route that forgot to stamp its
-- viewer cannot write as the author its request body names); only the valve
-- relieves that, and then the author is the one checked. Workflow ingest writes as one shared system
-- agent under that agent's own stamp, so its request paths bind their CALLER
-- before stamping (`AgentRepository::require_writer_authority`).
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
-- The valve relieves the BINDING (OPL01) only. The cross-human scope (OPL02,
-- section 1b) keys on the arming alone, so no valve lets one human's agent
-- write into another human's group.
--
-- The setting is the valve's TRANSPORT, not an authority boundary. Any session
-- can set a custom GUC, so a raw session that sets it writes as an unbound
-- agent; what the setting guards against is a CODE PATH forgetting the rule,
-- which it does, because nothing sets it but the valve.
--
-- The same holds for the PRINCIPAL (section 2) and its exemption (section 1b).
-- `epigraph.principal_id` and the group settings are session GUCs that the
-- application role sets (that is how `ScopedPool` stamps a request), and
-- tenancy row security trusts the same stamp. So a holder of the application
-- DSN that issues raw SQL can stamp any identity: a bound agent's, a human's,
-- or a live instance admin's (and so be exempt from OPL02). Agent and human ids
-- are not secrets. The binding constrains the CODE PATHS that stamp from an
-- authenticated viewer; it is not a boundary against a process that holds the
-- application DSN and misbehaves. That boundary is the DSN itself (who holds
-- it, and a maintenance-only DSN for everything privileged).
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
-- OPERATOR, neither of which is the session principal. `epigraph_human_of`
-- adds nothing to that: `operator_links` is already app-readable (107).
--
-- ===================================================================
-- 6. UNDO
--
-- `DROP TRIGGER IF EXISTS claims_require_tenancy_then_operator_binding ON
-- public.claims;` then drop the functions and `operator_binding_arming`; re-run
-- 107's and 116's link definers (section 9) and 120's `epigraph_propagate_tenancy`
-- (section 8). To stop enforcing
-- without DDL, set the valve (section 4) on every writing unit and restart it.
-- A link `epigraph_link_legacy_authors` (section 7) recorded is an
-- `operator_links` row like 107's and is permanent by the same rule. Drop
-- `operator_links_operator_is_human` and `operator_links_audit` before
-- `human_operators` (the first trigger's body reads it through
-- `epigraph_is_human_operator`). Drop `oauth_clients_reactivation_guard` and
-- its function too (section 1c).
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

-- The human-operator registry (section 1c). Rowless on purpose; see there.
-- `client_id` is the ONE OAuth client (oauth_clients.id) the registration was
-- made for: the human test reads that row's status, not "any active human
-- client of the agent", because the application role may INSERT
-- `oauth_clients` rows (dynamic client registration) and could otherwise mint a
-- fresh active client to undo a suspension. It holds no UPDATE there, and
-- `oauth_clients_reactivation_guard` refuses the approval definer's move out of
-- `suspended` / `revoked` on a non-privileged session, so a suspended recorded
-- client stays suspended.
CREATE TABLE IF NOT EXISTS public.human_operators (
    agent_id       uuid PRIMARY KEY REFERENCES public.agents(id) ON DELETE RESTRICT,
    client_id      uuid NOT NULL REFERENCES public.oauth_clients(id) ON DELETE RESTRICT,
    created_at     timestamptz NOT NULL DEFAULT now(),
    created_by     text NOT NULL DEFAULT session_user,
    reason         text NOT NULL,
    revoked_at     timestamptz,
    revoked_by     text,
    revoked_reason text
);
REVOKE ALL ON public.human_operators FROM PUBLIC;

-- (a): is this agent a human operator? A live registry row AND its RECORDED
-- human OAuth client still active, and nothing else: in particular NOT "some
-- link names it as an operator" (a link must not be able to make a human), NOT
-- a human client alone (a dynamic client registration is typed 'human' too),
-- and NOT some other active human client of the same agent (section 1c).
CREATE OR REPLACE FUNCTION public.epigraph_is_human_operator(p_agent uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT p_agent IS NOT NULL
       AND EXISTS (SELECT 1 FROM public.human_operators h
                     JOIN public.oauth_clients c ON c.id = h.client_id
                    WHERE h.agent_id = p_agent AND h.revoked_at IS NULL
                      AND c.agent_id = p_agent
                      AND c.client_type = 'human'
                      AND c.status = 'active')
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_is_human_operator(uuid) FROM PUBLIC;

-- The human an agent belongs to: itself when it is a human operator; else the
-- operator of its link (`p_live_only`: a live link only; otherwise a link of
-- any state, which is how a RETIRED legacy author still belongs to a human);
-- else NULL. Never more than one: `operator_links` is keyed on the agent.
CREATE OR REPLACE FUNCTION public.epigraph_human_of(p_agent uuid, p_live_only boolean)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT CASE
             WHEN p_agent IS NULL THEN NULL
             WHEN public.epigraph_is_human_operator(p_agent) THEN p_agent
             ELSE (SELECT l.operator_id FROM public.operator_links l
                    WHERE l.agent_id = p_agent AND (NOT p_live_only OR NOT l.retired))
           END
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_human_of(uuid, boolean) FROM PUBLIC;

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

-- Is the database ARMED (section 3)? Whatever this session's valve says: the
-- cross-human scope (OPL02, section 1b) keys on this, because the valve is
-- relief for section 1's binding only (section 4).
CREATE OR REPLACE FUNCTION public.epigraph_operator_binding_armed()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM public.operator_binding_arming)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_binding_armed() FROM PUBLIC;

-- Is the BINDING (OPL01) in force on THIS session? Armed, and the valve not off.
CREATE OR REPLACE FUNCTION public.epigraph_operator_binding_enforced()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT public.epigraph_operator_binding_armed()
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

-- Section 2's WRITER check: the session principal that writes a claim naming
-- another agent as its author must itself be bound. NULL (no principal) is
-- unbound. Same code, same fix, its own wording.
CREATE OR REPLACE FUNCTION public.epigraph_require_bound_writer(p_writer uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NOT public.epigraph_operator_binding_enforced() THEN
        RETURN;
    END IF;
    IF public.epigraph_author_binding(p_writer) IS NOT NULL THEN
        RETURN;
    END IF;
    RAISE EXCEPTION 'OPL01: the writing principal % is not bound to a human operator (it is '
                    'neither a human operator nor the holder of a live operator link), and '
                    'every claim must be written by a bound agent', p_writer
        USING ERRCODE = 'OPL01',
              HINT = 'Record a live link for the writing agent on a maintenance DSN: '
                     'epigraph-operator link --agent <agent id> --operator <human operator '
                     'agent id> --apply. See docs/tenancy.md "Operator binding".';
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_require_bound_writer(uuid) FROM PUBLIC;

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

-- Section 1b at the MEMBERSHIP DOOR: a live-linked agent (not itself a human)
-- may be given a writer/admin row in `p_group` only if its operator writes that
-- group. Quiet for a human (the row being written is what makes a human a
-- writer of a group: its own first admin row, or any group it is enrolled in),
-- an unbound agent, an unarmed database, and the exemption. NOT quiet under the
-- valve (section 4): the valve relieves the binding, never the cross-human
-- scope. The claims path uses the stricter `epigraph_require_writer_scope`.
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
REVOKE EXECUTE ON FUNCTION public.epigraph_require_operator_scope(uuid, uuid) FROM PUBLIC;

-- Section 1b on the CLAIMS path: the agent that writes a claim owned by
-- `p_group` must belong to a human (itself, or its live link's operator) who
-- holds a live writer/admin row in `p_group`. Unlike the membership door, a
-- HUMAN is not exempt here: a human writes only where it writes, like
-- everyone. Quiet for an unbound agent (section 1's OPL01 is the refusal for
-- it), an unarmed database, and the exemption; NOT for the valve (section 4).
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
    v_human := public.epigraph_human_of(p_agent, true);
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
REVOKE EXECUTE ON FUNCTION public.epigraph_require_writer_scope(uuid, uuid) FROM PUBLIC;

-- Section 2's ATTRIBUTION check, for a claim whose author is not its writer:
-- the author must be BOUND (section 1) and belong to the WRITER's own human.
-- One exception, for the author a supersede INHERITS rather than chooses
-- (`p_inherited`: an INSERT restating one RETIRED predecessor with that
-- predecessor's author and group and no other current successor, which is
-- what `supersede_act_conn` writes; the trigger decides it, see its body's
-- comment): there a RETIRED link to the writer's human
-- counts, so a human can supersede its own legacy author's claim. A fresh
-- claim may never name a retired identity (OB1). An author that belongs to no
-- human at all is unbound (OPL01, under the valve's rule); so is a RETIRED
-- identity of the writer's OWN human named on a fresh claim (OPL01: the valve
-- may relieve it, and it stays inside one human). One that belongs to ANOTHER
-- human, by a link of ANY state, is a cross-human attribution (OPL02, armed; an
-- instance-admin principal and a privileged session are exempt for a live-bound
-- author, as everywhere in section 1b, and meet OPL01 for a retired one). So is
-- an author that belongs to a human while the WRITER belongs to none: with the
-- valve closed the writer's own OPL01 comes first, and with it open (section 4)
-- the valve relieves that OPL01 only, never lets an unbound writer (or another
-- human's agent) put words in a bound identity's mouth, a retired one included.
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
REVOKE EXECUTE ON FUNCTION public.epigraph_require_attributable(uuid, uuid, boolean) FROM PUBLIC;

-- The trigger body. A DEFINER owned by the maintenance role, like 070's
-- trigger bodies: PostgreSQL checks EXECUTE on a trigger function when the
-- trigger is CREATED, not when it fires, and the definer frame is what calls
-- the checks above. So no writing role (an operator script's login included)
-- needs a grant of its own, and none can meet a 42501 here instead of the
-- rule. It reads nothing itself; the checks read the link and client tables.
--
-- WHO is checked (section 2): the AUTHOR (`NEW.agent_id`) when the principal
-- IS the author, on a privileged session, or (valve open only) when an
-- application session has no principal, which is otherwise refused OPL01;
-- otherwise the WRITER (the session principal) is bound and scoped, and the
-- author must be the writer's own human's (`epigraph_require_attributable`).
-- `epigraph_principal_id()` is what `ScopedPool` stamps from the viewer, so
-- this binds the identity a request authenticated as, not a column the request
-- body supplied (section 4 says what that stamp is, and is not, a boundary
-- against).
--
-- INHERITED (the one admission of a RETIRED author) means exactly what
-- `supersede_act_conn` writes, and nothing a writer can pose: an INSERT that
-- names `supersedes`, where that predecessor carries the SAME author, is owned
-- by the SAME group, is already RETIRED (`is_current = false`: the act retires
-- it first, in the same transaction), and has no other CURRENT successor. So a
-- supersede re-states one retired claim once, in its own group; it does not
-- mint fresh claims under a retired identity (a current predecessor, a second
-- successor, or a different group is refused as a fresh claim naming that
-- identity), and a group the writer cannot write is refused OPL02 before the
-- predecessor's author is compared, so the answer never says who authored a
-- claim the writer could not read. One current successor is an INSERT-side
-- rule: claim UPDATEs outside `agent_id` / `supersedes` stay governed by row
-- security alone ("Scope" in docs/tenancy.md).
--
-- LINEAGE. `supersedes` on an existing claim is also guarded (the trigger
-- fires on UPDATE OF `supersedes`): once armed, a non-exempt session may not
-- clear it, nor re-point it while the claim stays current. Otherwise an
-- inherited successor could be laundered into a plain fresh claim by the
-- retired identity (OPL02, keyed on the arming). Setting it on a claim that
-- had none, and re-pointing it on a claim retired in the same statement (the
-- dedup and consolidate acts), are untouched.
CREATE OR REPLACE FUNCTION public.epigraph_claims_require_operator_binding()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_writer uuid;
    v_inherited boolean := false;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.agent_id IS NOT DISTINCT FROM OLD.agent_id THEN
        -- Only `supersedes` (the trigger's other column) can have changed.
        IF NEW.supersedes IS NOT DISTINCT FROM OLD.supersedes OR OLD.supersedes IS NULL
           OR NOT public.epigraph_operator_binding_armed() THEN
            RETURN NEW;
        END IF;
        IF (NEW.supersedes IS NULL OR COALESCE(NEW.is_current, true))
           AND NOT public.epigraph_operator_scope_exempt() THEN
            RAISE EXCEPTION 'OPL02: claim % records that it supersedes %; an application session '
                            'does not clear, or re-point on a current claim, the lineage of an '
                            'existing claim', NEW.id, OLD.supersedes
                USING ERRCODE = 'OPL02',
                      HINT = 'Supersede the claim instead, or retire it in the same statement '
                             '(the dedup act). Admin access crosses humans; nothing else does.';
        END IF;
        RETURN NEW;
    END IF;
    IF NOT public.epigraph_operator_binding_armed() THEN
        RETURN NEW;
    END IF;
    -- RE-ATTRIBUTION. Every check below reads the NEW author only, so an
    -- UPDATE that changes it would let a writer take over (or hand off) a
    -- claim someone else said, including another human's claim in a group
    -- both humans write. No repository or route changes `claims.agent_id`;
    -- only the exemption (a privileged session, an instance-admin principal)
    -- may, and it is then checked like an insert below. OPL02, keyed on the
    -- arming: it is attribution, which the valve never relieves.
    IF TG_OP = 'UPDATE' AND NOT public.epigraph_operator_scope_exempt() THEN
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
    IF TG_OP = 'INSERT' AND NEW.supersedes IS NOT NULL THEN
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
        -- checked on its author as always, and an instance-admin PRINCIPAL is
        -- not relieved here (it is a stamp an application session sets).
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
REVOKE EXECUTE ON FUNCTION public.epigraph_claims_require_operator_binding() FROM PUBLIC;

-- Named to sort AFTER `claims_require_tenancy` (PostgreSQL fires same-event
-- row triggers in name order): the scope check reads `owner_group_id`, which
-- that trigger fills for a supersede or a step-lineage insert. Sorting first,
-- it read NULL and refused every such write (review SEC-4).
DROP TRIGGER IF EXISTS claims_require_operator_binding ON public.claims;
DROP TRIGGER IF EXISTS claims_require_tenancy_then_operator_binding ON public.claims;
CREATE TRIGGER claims_require_tenancy_then_operator_binding
    BEFORE INSERT OR UPDATE OF agent_id, supersedes ON public.claims
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

-- Section 1c: the registry's rules live on the TABLE, so a maintenance
-- login's direct INSERT / UPDATE (which its grants admit, because the
-- definers below run as that role) meets exactly the definers' checks and
-- leaves exactly their audit rows (review SEC-8).
--
-- BEFORE INSERT: the row is live; `client_id` is the agent's own ACTIVE human
-- client (resolved when omitted, and then only if it is the agent's ONE active
-- human client); and a revoked registration is never revived (the INSERT of
-- an existing agent conflicts on the key and is discarded by an `ON CONFLICT
-- DO NOTHING`, or fails on it).
CREATE OR REPLACE FUNCTION public.epigraph_human_operators_guard_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_n integer;
BEGIN
    IF NEW.revoked_at IS NOT NULL OR NEW.revoked_by IS NOT NULL
       OR NEW.revoked_reason IS NOT NULL THEN
        RAISE EXCEPTION 'human_operators: a registration is recorded live; revoke it with '
                        'epigraph_revoke_human_operator' USING ERRCODE = '55000';
    END IF;
    IF NEW.reason IS NULL OR length(trim(NEW.reason)) = 0 THEN
        RAISE EXCEPTION 'human_operators: a reason is required' USING ERRCODE = '22004';
    END IF;
    IF NEW.client_id IS NULL THEN
        SELECT count(*) INTO v_n FROM public.oauth_clients c
         WHERE c.agent_id = NEW.agent_id AND c.client_type = 'human' AND c.status = 'active';
        IF v_n > 1 THEN
            RAISE EXCEPTION 'human_operators: % has % active human OAuth clients; name the one '
                            'this registration is for', NEW.agent_id, v_n
                USING ERRCODE = '55000';
        END IF;
        SELECT c.id INTO NEW.client_id FROM public.oauth_clients c
         WHERE c.agent_id = NEW.agent_id AND c.client_type = 'human' AND c.status = 'active';
    END IF;
    IF NEW.client_id IS NULL OR NOT EXISTS (
            SELECT 1 FROM public.oauth_clients c
             WHERE c.id = NEW.client_id AND c.agent_id = NEW.agent_id
               AND c.client_type = 'human' AND c.status = 'active') THEN
        RAISE EXCEPTION 'human_operators: % is not the agent of that ACTIVE human OAuth client; '
                        'only a human''s own principal can be registered', NEW.agent_id
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_human_operators_guard_insert() FROM PUBLIC;

-- BEFORE UPDATE: the ONLY change a registration ever takes is its revoke
-- (revoked_at NULL -> set, with who and why). Revoke is final: a revoked row
-- takes no change at all, so it cannot be un-revoked by a direct UPDATE.
CREATE OR REPLACE FUNCTION public.epigraph_human_operators_guard_update()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'human_operators: the registration of % was REVOKED, and revoke is '
                        'final; nothing was changed', OLD.agent_id USING ERRCODE = '55000';
    END IF;
    IF NEW.revoked_at IS NULL
       OR NEW.revoked_reason IS NULL OR length(trim(NEW.revoked_reason)) = 0
       OR (NEW.agent_id, NEW.client_id, NEW.created_at, NEW.created_by, NEW.reason)
          IS DISTINCT FROM (OLD.agent_id, OLD.client_id, OLD.created_at, OLD.created_by,
                            OLD.reason) THEN
        RAISE EXCEPTION 'human_operators: a registration is only ever revoked (revoked_at, '
                        'revoked_by and a revoked_reason set); nothing was changed'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_human_operators_guard_update() FROM PUBLIC;

-- AFTER INSERT / UPDATE: one `security_events` row per registration and per
-- revoke, whatever path wrote it.
CREATE OR REPLACE FUNCTION public.epigraph_human_operators_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('operator.human_registered', NEW.agent_id, true,
                jsonb_build_object('reason', NEW.reason, 'client_id', NEW.client_id,
                                   'recorded_by', session_user));
    ELSE
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('operator.human_revoked', NEW.agent_id, true,
                jsonb_build_object('reason', NEW.revoked_reason, 'client_id', NEW.client_id,
                                   'recorded_by', session_user));
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_human_operators_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS human_operators_guard_insert ON public.human_operators;
CREATE TRIGGER human_operators_guard_insert
    BEFORE INSERT ON public.human_operators
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_human_operators_guard_insert();
DROP TRIGGER IF EXISTS human_operators_guard_update ON public.human_operators;
CREATE TRIGGER human_operators_guard_update
    BEFORE UPDATE ON public.human_operators
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_human_operators_guard_update();
DROP TRIGGER IF EXISTS human_operators_audit ON public.human_operators;
CREATE TRIGGER human_operators_audit
    AFTER INSERT OR UPDATE ON public.human_operators
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_human_operators_audit();

-- Section 1c: register a human operator. Maintenance only; audited (by the
-- table's trigger); refuses an agent that is not the agent of an ACTIVE human
-- OAuth client (`p_client`, or the agent's one active human client when NULL).
-- Idempotent for a live row; a REVOKED row is not revived by it (a
-- re-registration is an explicit, separate decision: revoke is final for that
-- row).
CREATE OR REPLACE FUNCTION public.epigraph_register_human_operator(
    p_agent uuid, p_reason text, p_client uuid DEFAULT NULL)
RETURNS TABLE (registered_now boolean, created_at timestamptz, created_by text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF p_agent IS NULL OR p_reason IS NULL OR length(trim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_register_human_operator: the agent and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    IF EXISTS (SELECT 1 FROM public.human_operators h
                WHERE h.agent_id = p_agent AND h.revoked_at IS NOT NULL) THEN
        RAISE EXCEPTION 'epigraph_register_human_operator: % was registered and REVOKED; a '
                        'revoked registration is not revived', p_agent
            USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.human_operators h WHERE h.agent_id = p_agent) THEN
        IF NOT EXISTS (SELECT 1 FROM public.oauth_clients c
                        WHERE c.agent_id = p_agent AND c.client_type = 'human'
                          AND c.status = 'active'
                          AND (p_client IS NULL OR c.id = p_client)) THEN
            RAISE EXCEPTION 'epigraph_register_human_operator: % is not the agent of an ACTIVE '
                            'human OAuth client; only a human''s own principal can be '
                            'registered', p_agent
                USING ERRCODE = '55000';
        END IF;
        INSERT INTO public.human_operators (agent_id, client_id, reason)
        VALUES (p_agent, p_client, p_reason)
        ON CONFLICT (agent_id) DO NOTHING;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
    END IF;
    RETURN QUERY SELECT v_rows > 0, h.created_at, h.created_by
                   FROM public.human_operators h WHERE h.agent_id = p_agent;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_register_human_operator(uuid, text, uuid) FROM PUBLIC;

-- Section 1c: revoke a registration. Maintenance only; audited (by the
-- table's trigger); final.
CREATE OR REPLACE FUNCTION public.epigraph_revoke_human_operator(p_agent uuid, p_reason text)
RETURNS TABLE (revoked_now boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_rows integer := 0;
BEGIN
    IF p_agent IS NULL OR p_reason IS NULL OR length(trim(p_reason)) = 0 THEN
        RAISE EXCEPTION 'epigraph_revoke_human_operator: the agent and a reason are required'
            USING ERRCODE = '22004';
    END IF;
    UPDATE public.human_operators h
       SET revoked_at = now(), revoked_by = session_user, revoked_reason = p_reason
     WHERE h.agent_id = p_agent AND h.revoked_at IS NULL;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    RETURN QUERY SELECT v_rows > 0;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_revoke_human_operator(uuid, text) FROM PUBLIC;

-- Section 1c at the link record: a NEW link only to a registered human.
CREATE OR REPLACE FUNCTION public.epigraph_operator_links_operator_is_human()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    -- An exact re-link (a row for this agent exists) is discarded by the
    -- caller's ON CONFLICT DO NOTHING; never refuse it here.
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = NEW.agent_id) THEN
        RETURN NEW;
    END IF;
    IF NOT public.epigraph_is_human_operator(NEW.operator_id) THEN
        RAISE EXCEPTION 'operator % is not a registered human operator (a live human_operators '
                        'row and an active human OAuth client are both required); no agent is '
                        'linked to it', NEW.operator_id
            USING ERRCODE = '55000',
                  HINT = 'A maintenance session registers a human with '
                         'epigraph-operator register-human-operator --agent <id> --client '
                         '<its human OAuth client id> --reason <text> --apply.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_links_operator_is_human() FROM PUBLIC;

DROP TRIGGER IF EXISTS operator_links_operator_is_human ON public.operator_links;
CREATE TRIGGER operator_links_operator_is_human
    BEFORE INSERT ON public.operator_links
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_operator_links_operator_is_human();

-- Section 1c at the link record: once armed, a LIVE link is exactly what turns
-- a refused agent into a writer, so every link row is audited where it is
-- written, on every path (107's two link functions, 116's attested retire,
-- section 7's legacy tie, a raw INSERT): one `operator.link_recorded`
-- `security_events` row per row inserted, naming the agent, the operator, the
-- state and the session that recorded it. An `ON CONFLICT DO NOTHING` re-link
-- inserts nothing and records nothing.
CREATE OR REPLACE FUNCTION public.epigraph_operator_links_audit()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    INSERT INTO public.security_events (event_type, agent_id, success, details)
    VALUES ('operator.link_recorded', NEW.agent_id, true,
            jsonb_build_object('operator_id', NEW.operator_id,
                               'operator_group_id', NEW.operator_group_id,
                               'retired', NEW.retired,
                               'recorded_by', session_user));
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_operator_links_audit() FROM PUBLIC;

DROP TRIGGER IF EXISTS operator_links_audit ON public.operator_links;
CREATE TRIGGER operator_links_audit
    AFTER INSERT ON public.operator_links
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_operator_links_audit();

-- Section 1c at the CLIENT record: only a privileged session takes a client
-- back out of `suspended` or `revoked`. The human test (a) reads the status of
-- the ONE client a registration names, and the link definers refuse an agent
-- that is the principal of an un-revoked client (section 9), so that move
-- decides who is a human and who can be linked. The application role holds no
-- UPDATE on `oauth_clients`, but 118's `epigraph_oauth_client_approve`, which
-- it may EXECUTE (the REST admin approval), sets `status = 'active'` whatever
-- the previous status. Without this guard a request-path caller could
-- re-activate a client that a maintenance session had suspended or revoked,
-- which would re-register a suspended human. Promoting a `pending` client, and
-- taking authority away (to `suspended`, or to `revoked`), stay open to every
-- path. The guard does not key on the arming: the registry and the link record
-- read the status before the database is armed as well. It is an INVOKER on
-- purpose, because it reads only OLD/NEW and `epigraph_bypass()` (which keys
-- on `session_user`), so the caller's definer frame cannot change the answer.
CREATE OR REPLACE FUNCTION public.epigraph_oauth_clients_reactivation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp AS $$
BEGIN
    IF ((OLD.status = 'revoked' AND NEW.status IS DISTINCT FROM 'revoked')
        OR (OLD.status = 'suspended' AND NEW.status IS DISTINCT FROM 'suspended'
            AND NEW.status IS DISTINCT FROM 'revoked'))
       AND NOT public.epigraph_bypass() THEN
        RAISE EXCEPTION 'OC02: OAuth client % is %; only a maintenance session takes a client '
                        'out of suspended or revoked (here to %)', OLD.id, OLD.status, NEW.status
            USING ERRCODE = '42501',
                  HINT = 'Re-activate it on a maintenance or admin DSN, recorded. A suspended '
                         'human client un-registers that human until then.';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_oauth_clients_reactivation_guard() FROM PUBLIC;

DROP TRIGGER IF EXISTS oauth_clients_reactivation_guard ON public.oauth_clients;
CREATE TRIGGER oauth_clients_reactivation_guard
    BEFORE UPDATE OF status ON public.oauth_clients
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_oauth_clients_reactivation_guard();

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
        EXECUTE 'ALTER FUNCTION public.epigraph_register_human_operator(uuid, text, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_revoke_human_operator(uuid, text) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_operator_links_operator_is_human() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_operator_links_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_human_operators_guard_insert() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_human_operators_guard_update() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_human_operators_audit() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_human_of(uuid, boolean) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_operator_binding_armed() '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_require_bound_writer(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_require_writer_scope(uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_require_attributable(uuid, uuid, boolean) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_register_human_operator(uuid, text, uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_revoke_human_operator(uuid, text) '
                'TO epigraph_maintenance';
        -- The definers run as this role, so it holds the DML they issue; the
        -- table's own triggers (section 1c) hold a direct write to the same
        -- rules and the same audit as the definers.
        EXECUTE 'GRANT SELECT, INSERT ON public.human_operators TO epigraph_maintenance';
        EXECUTE 'GRANT UPDATE (revoked_at, revoked_by, revoked_reason) ON public.human_operators '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_human_of(uuid, boolean) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_binding_armed() '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_require_bound_writer(uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_require_writer_scope(uuid, uuid) '
                'TO epigraph_maintenance';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_require_attributable(uuid, uuid, boolean) '
                'TO epigraph_maintenance';
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
        EXECUTE 'REVOKE ALL ON public.human_operators FROM epigraph_app';
        EXECUTE 'GRANT SELECT ON public.human_operators TO epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_register_human_operator(uuid, text, uuid) '
                'FROM epigraph_app';
        EXECUTE 'REVOKE EXECUTE ON FUNCTION public.epigraph_revoke_human_operator(uuid, text) '
                'FROM epigraph_app';
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
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_human_of(uuid, boolean) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_operator_binding_armed() '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_require_bound_writer(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_require_writer_scope(uuid, uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_require_attributable(uuid, uuid, boolean) '
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
-- `challenges.resolved_by` (resolving a challenge is a write to it),
-- `claim_signature_revocations.revoked_by`, `perspectives.owner_agent_id`,
-- `recall_events.agent_id`. NOT the three SIGNING-KEY columns, which name the
-- key that signed a row rather than the agent that wrote it: `edges.signer_id`
-- (on legacy rows a bulk attestation key; `epigraph-operator`'s
-- `tables::EDGE_WRITER` records why), `claims.signer_id` (for HTTP-era rows
-- the shared signer's key, whose tie is 116's attested retire, never a bulk
-- one) and `claim_signature_revocations.previous_signer_id` (the key a
-- revocation replaced; its author is `revoked_by`).
--
-- REFUSED (55000 / 22023 / 22004, nothing written): an operator that is not a
-- HUMAN operator (section 1 arm (a)); an operator that is itself operated;
-- 105's RVK01 / RVK02 on the operator's personal group; a NULL operator or a
-- NULL in the exclusion set.
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
--   operated_by_other_human
--                     an OPERATED_BY edge from it names a registered human
--                     operator OTHER than this one: its own auth lineage says
--                     it acts for another human, and a tie (permanent) to this
--                     one would misattribute it for good (OB5). An app session
--                     can forge such an edge, which can only make an agent
--                     SKIPPED, never tied;
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
        RAISE EXCEPTION 'epigraph_link_legacy_authors: % is not a human operator (a live '
                        'human_operators row and an active human OAuth client are both '
                        'required); legacy authors are tied to a human or not at all', p_operator
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_legacy_authors: % is itself operated by another agent '
                        'and cannot be an operator', p_operator
            USING ERRCODE = '55000';
    END IF;
    -- No operator-side shared-signer fingerprint here (107 section 9 has one):
    -- the operator was just proven a registered human operator, which no
    -- shared HTTP signer is, and the OPERATED_BY edges that fingerprint counts
    -- are writable by any application session. Counting them let any session
    -- block every legacy tie to a human by forging two edges from it (review
    -- SEC-5).

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
                UNION SELECT ch.resolved_by FROM public.challenges ch
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
            WHEN EXISTS (SELECT 1 FROM public.edges e
                          WHERE e.source_id = v_agent AND e.relationship = 'OPERATED_BY'
                            AND e.target_id <> p_operator
                            AND public.epigraph_is_human_operator(e.target_id))
                THEN 'skipped:operated_by_other_human'
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

-- ===================================================================
-- 8. ARM (d) PROPAGATION, SET-BASED FOR THE EDGES MEET (OB6)
--
-- The tenancy backfill and every re-own are claims UPDATEs, and 070's arm (d)
-- (`claims_propagate_tenancy`, a STATEMENT-level trigger) propagates them: one
-- UPDATE per derived table per statement, joined to the transition table. Its
-- LAST statement, the edges meet, was the expensive one, measured on a 5433
-- `*_test` database seeded prod-shaped (200k claims, 400k edges, rows in all
-- 17 derived tables), per 5,000-claim batch:
--
--   * the edges were found by ONE join with an OR condition (source side OR
--     target side). With an unfavourable estimate the planner takes a nested
--     loop that tests every edge against every changed claim (5,000 x 400k
--     comparisons: 86 s for one batch here; the production batch that took 16
--     minutes in the aborted backfill has 1M edges); with a favourable one it
--     takes a BitmapOr per changed row. The plan was a coin flip on
--     statistics. Two equi-joins (source side UNION target side) have no such
--     degenerate plan.
--   * each touched edge called `epigraph_node_tenancy` twice (a plpgsql
--     SECURITY DEFINER with a `SET` clause, so never inlined): ~7 of the ~10
--     seconds a batch spent in the trigger. The endpoint's tenancy is now two
--     LEFT JOINs per side (claims, evidence) with the function's exact
--     fallback: an endpoint that is neither a found claim nor a found evidence
--     row contributes `('public', world)`.
--
-- Everything else in the body is 120's, byte for byte (the `derived text[]`
-- literal, the pin and writer-owned arms, the fragments statement, the three
-- CASE expressions of the meet, and every guard of the edges UPDATE). Same
-- rows, same meet: pinned by `epigraph-cli/tests/backfill_equivalence.rs` and
-- the existing arm (d) suites (`tenancy_triggers.rs`, `writer_owned_edges.rs`,
-- `privatization_boundary.rs`).
--
-- UNDO: re-run 120's section 4 (`CREATE OR REPLACE` from its text); the ACL and
-- the owner are kept by `CREATE OR REPLACE`, and re-set below regardless.
CREATE OR REPLACE FUNCTION public.epigraph_propagate_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE t text; expected bigint; actual bigint; pin_skip text;
        derived text[] := ARRAY[
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance','evidence',
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations'];
        writer_tables text[] := ARRAY['evidence','mass_functions','reasoning_traces'];
BEGIN
    -- The firing gate. MUST stay ahead of the assertion below.
    IF NOT EXISTS (
        SELECT 1 FROM changed ch JOIN prev p ON p.id = ch.id
         WHERE (ch.owner_group_id, ch.visibility)
               IS DISTINCT FROM (p.owner_group_id, p.visibility))
    THEN RETURN NULL; END IF;

    IF NOT public.epigraph_definer_bypass() THEN
        RAISE EXCEPTION 'epigraph tenancy: propagation requires a maintenance-role '
                        'owner; refusing to run RLS-filtered' USING ERRCODE = '42501';
    END IF;
    FOREACH t IN ARRAY derived LOOP
        -- 110: a PINNED evidence row is left to the statement after the loop.
        -- (An IF, not a conditional expression: `tenancy_triggers.rs` counts
        -- this body's conditional expressions to pin the edges meet at three.)
        IF t = 'evidence' THEN
            pin_skip := ' AND NOT EXISTS (SELECT 1 FROM public.evidence_visibility_pins vp'
                        ' WHERE vp.evidence_id = d.id)';
        ELSE
            pin_skip := '';
        END IF;
        -- 114: a WRITER-OWNED row is left to the statement after the loop.
        IF t = ANY (writer_tables) THEN
            pin_skip := pin_skip || ' AND NOT d.writer_owned';
        END IF;
        EXECUTE format(
          'SELECT count(*) FROM %I d JOIN changed ch ON ch.id = d.claim_id
             WHERE (d.owner_group_id, d.visibility)
                   IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t) || pin_skip
          INTO expected;
        EXECUTE format(
          'UPDATE %I d SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
             FROM changed ch
            WHERE ch.id = d.claim_id
              AND (d.owner_group_id, d.visibility)
                  IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t) || pin_skip;
        GET DIAGNOSTICS actual = ROW_COUNT;
        IF actual <> expected THEN
            RAISE EXCEPTION 'epigraph tenancy: propagation to % updated % of % rows '
                            '(RLS filtered?)', t, actual, expected;
        END IF;
    END LOOP;
    -- 110: PINNED evidence. Never widened, owner never changed.
    SELECT count(*) INTO expected
      FROM public.evidence d
      JOIN changed ch ON ch.id = d.claim_id
      JOIN public.evidence_visibility_pins vp ON vp.evidence_id = d.id
     WHERE d.visibility IS DISTINCT FROM 'group'::character varying(16);
    IF expected > 0 THEN
        UPDATE public.evidence d
           SET visibility = 'group'::character varying(16)
          FROM changed ch, public.evidence_visibility_pins vp
         WHERE ch.id = d.claim_id
           AND vp.evidence_id = d.id
           AND d.visibility IS DISTINCT FROM 'group'::character varying(16);
        GET DIAGNOSTICS actual = ROW_COUNT;
        IF actual <> expected THEN
            RAISE EXCEPTION 'epigraph tenancy: propagation to pinned evidence updated % '
                            'of % rows (RLS filtered?)', actual, expected;
        END IF;
    END IF;
    -- 114: WRITER-OWNED rows. While the claim stays public they are left
    -- alone: their owner is the writer's whoever the claim moves to, and their
    -- visibility is already the claim's (or narrower, for pinned evidence).
    -- When the claim NARROWS to non-public they become the claim's: owner and
    -- visibility follow the claim and the flag is cleared (review finding W5).
    -- Keeping the writer as owner there would leave rows about a private claim
    -- readable by the writer's group and hidden from the claim's own owner,
    -- which is sequestering evidence from the one party who now holds the
    -- claim; privatization's seal already encrypts every evidence row of the
    -- claim with the claim group's key, the writer's included. Pinned evidence
    -- is re-owned too (its visibility is 'group' either way, set above).
    -- Issued only when a count finds a row to change.
    FOREACH t IN ARRAY writer_tables LOOP
        EXECUTE format(
          'SELECT count(*) FROM %I d JOIN changed ch ON ch.id = d.claim_id
             WHERE d.writer_owned
               AND ch.visibility IS DISTINCT FROM ''public''', t)
          INTO expected;
        IF expected > 0 THEN
            EXECUTE format(
              'UPDATE %I d SET owner_group_id = ch.owner_group_id,
                               visibility     = ch.visibility,
                               writer_owned   = false
                 FROM changed ch
                WHERE ch.id = d.claim_id
                  AND d.writer_owned
                  AND ch.visibility IS DISTINCT FROM ''public''', t);
            GET DIAGNOSTICS actual = ROW_COUNT;
            IF actual <> expected THEN
                RAISE EXCEPTION 'epigraph tenancy: propagation to writer-owned % updated % '
                                'of % rows (RLS filtered?)', t, actual, expected;
            END IF;
        END IF;
    END LOOP;
    -- Harvester fragments hang off provenance, not off claim_id.
    UPDATE public.harvester_fragments f
       SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
      FROM public.harvester_claim_provenance p JOIN changed ch ON ch.id = p.claim_id
     WHERE f.id = p.fragment_id
       AND (f.owner_group_id, f.visibility)
           IS DISTINCT FROM (ch.owner_group_id, ch.visibility);
    -- Edges are the MEET of their (possibly changed) endpoints, recomputed from
    -- BOTH endpoints (072's header). 122 (OB6): the edges touching the batch
    -- are found by two equi-joins (source side, target side) instead of one OR
    -- join, and each endpoint's tenancy is read by a join, not by one
    -- `epigraph_node_tenancy` call per endpoint; same edges, same meet.
    UPDATE public.edges e
       SET owner_group_id    = m.g,
           visibility        = m.v,
           co_owner_group_id = m.co
      FROM (
        SELECT DISTINCT e2.id,
               CASE WHEN s.v = 'public' AND t.v = 'public'
                         THEN '00000000-0000-0000-0000-000000000000'::uuid
                    WHEN s.v = 'public' THEN t.g
                    WHEN t.v = 'public' THEN s.g
                    ELSE s.g END AS g,
               CASE WHEN s.v = 'public' AND t.v = 'public'
                         THEN 'public'::character varying(16)
                    ELSE 'group'::character varying(16) END AS v,
               CASE WHEN s.v = 'group' AND t.v = 'group' AND s.g <> t.g
                         THEN t.g
                    ELSE NULL END AS co
          FROM (SELECT x.id, x.source_id, x.source_type, x.target_id, x.target_type
                  FROM public.edges x
                  JOIN changed ch ON x.source_id = ch.id AND x.source_type = 'claim'
                UNION
                SELECT x.id, x.source_id, x.source_type, x.target_id, x.target_type
                  FROM public.edges x
                  JOIN changed ch ON x.target_id = ch.id AND x.target_type = 'claim') e2
          LEFT JOIN public.claims   sc ON e2.source_type = 'claim'    AND sc.id = e2.source_id
          LEFT JOIN public.evidence se ON e2.source_type = 'evidence' AND se.id = e2.source_id
          LEFT JOIN public.claims   tc ON e2.target_type = 'claim'    AND tc.id = e2.target_id
          LEFT JOIN public.evidence te ON e2.target_type = 'evidence' AND te.id = e2.target_id
          CROSS JOIN LATERAL (
            SELECT COALESCE(sc.owner_group_id, se.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(sc.visibility, se.visibility,
                            'public'::character varying(16)) AS v) s
          CROSS JOIN LATERAL (
            SELECT COALESCE(tc.owner_group_id, te.owner_group_id,
                            '00000000-0000-0000-0000-000000000000'::uuid) AS g,
                   COALESCE(tc.visibility, te.visibility,
                            'public'::character varying(16)) AS v) t
      ) m
     WHERE e.id = m.id
       AND m.g IS NOT NULL
       AND m.v = 'group'
       AND NOT (e.visibility = 'group' AND m.v = 'public')
       AND (e.owner_group_id, e.visibility, e.co_owner_group_id)
           IS DISTINCT FROM (m.g, m.v, m.co);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_propagate_tenancy() FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_propagate_tenancy() OWNER TO epigraph_maintenance';
    END IF;
END $$;

-- ===================================================================
-- 9. THE LINK DEFINERS: NO FORGEABLE FINGERPRINT ON A HUMAN OPERATOR (SEC-5)
--
-- 107's `epigraph_link_operator` and `epigraph_link_retired_agent` and 116's
-- `epigraph_link_retired_shared_signer` refuse, on a first link, an OPERATOR
-- carrying OPERATED_BY edges to more than one principal (107 section 9, the
-- shared-signer fingerprint). Those edges are writable by any application
-- session (107 says so), and since section 1c every new link's operator must be
-- a registered human operator, which is never a shared HTTP signer. So the
-- check had become a lever and nothing else: two forged edges FROM a human made
-- every new link to that human fail, and once armed an agent that cannot be
-- linked cannot write, which strands every new agent of that human (measured
-- by review on a throwaway database).
--
-- The three bodies below are 107's and 116's, byte for byte, except that the
-- operator-side fingerprint is skipped when the operator is a human operator
-- (`NOT public.epigraph_is_human_operator(p_operator) AND` added to its
-- condition; a non-human operator is refused anyway, by
-- `operator_links_operator_is_human`). The AGENT-side fingerprint is kept: it
-- is what 116's attested retire exists for. `CREATE OR REPLACE` keeps each
-- function's owner and ACL; both are re-asserted below.
--
-- UNDO: re-run the three `CREATE OR REPLACE FUNCTION` texts from 107 and 116.
CREATE OR REPLACE FUNCTION public.epigraph_link_operator(p_agent uuid, p_operator uuid)
RETURNS TABLE (operator_group_id uuid,
               group_created boolean,
               membership_created boolean,
               membership_live boolean,
               edge_created boolean,
               link_live boolean,
               link_retired boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_group     uuid;
    v_other     uuid;
    v_group_existed boolean;
    v_link_rows integer := 0;
    v_mem_rows  integer := 0;
    v_edge_rows integer := 0;
BEGIN
    IF p_agent IS NULL OR p_operator IS NULL THEN
        RAISE EXCEPTION 'epigraph_link_operator: agent and operator are both required'
            USING ERRCODE = '22004';
    END IF;
    IF p_agent = p_operator THEN
        RAISE EXCEPTION 'epigraph_link_operator: agent % cannot be its own operator', p_agent
            USING ERRCODE = '22023';
    END IF;
    -- Serialise every link write (section 10). Taken before any check reads
    -- `operator_links`, so under READ COMMITTED each check below sees every
    -- link committed by the call this one waited for.
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    IF NOT EXISTS (SELECT 1 FROM public.agents WHERE id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_link_operator: agent % does not exist', p_agent
            USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.agents WHERE id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_operator: operator % does not exist', p_operator
            USING ERRCODE = '22023';
    END IF;
    -- Single hop, enforced from BOTH ends. An operator that is itself
    -- operated, or an agent that already operates others, would make "who
    -- owns this" depend on a chain nobody declared as a whole. Checking only
    -- the first end let the order link(X, O) then link(O, P) build X -> O -> P
    -- (measured by review); the second check closes that order.
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_operator: % is itself operated by another agent and '
                        'cannot be an operator', p_operator
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.operator_id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_link_operator: % already operates other agents and cannot '
                        'itself be operated', p_agent
            USING ERRCODE = '55000';
    END IF;
    -- One operator per agent, ever. A second declaration is a configuration
    -- error to surface, not a link to add or a link to silently replace --
    -- whatever the state of the first link's membership.
    SELECT l.operator_id INTO v_other
      FROM public.operator_links l
     WHERE l.agent_id = p_agent AND l.operator_id <> p_operator;
    IF v_other IS NOT NULL THEN
        RAISE EXCEPTION 'epigraph_link_operator: agent % already has a link to operator %; '
                        'an agent is linked to one operator, and re-pointing it is an '
                        'out-of-band act', p_agent, v_other
            USING ERRCODE = '55000';
    END IF;
    -- A SHARED SIGNER is neither linkable nor an operator (section 9). Checked
    -- on a FIRST link only: an exact relink (a row for this very pair already
    -- exists) records nothing new, and the edges the check counts are
    -- writable by any app session, so counting them on a relink turned forged
    -- edges into a fatal stdio startup for an agent that was already linked.
    IF NOT EXISTS (SELECT 1 FROM public.operator_links l
                    WHERE l.agent_id = p_agent AND l.operator_id = p_operator) THEN
        IF (SELECT count(DISTINCT e.target_id) FROM public.edges e
             WHERE e.source_id = p_agent AND e.relationship = 'OPERATED_BY') > 1 THEN
            RAISE EXCEPTION 'epigraph_link_operator: agent % carries OPERATED_BY auth-lineage edges to '
                            'more than one principal, the fingerprint of a shared HTTP '
                            'signer; refusing to link it', p_agent
                USING ERRCODE = '55000';
        END IF;
        IF NOT public.epigraph_is_human_operator(p_operator)
           AND (SELECT count(DISTINCT e.target_id) FROM public.edges e
             WHERE e.source_id = p_operator AND e.relationship = 'OPERATED_BY') > 1 THEN
            RAISE EXCEPTION 'epigraph_link_operator: operator % carries OPERATED_BY auth-lineage edges to '
                            'more than one principal, the fingerprint of a shared HTTP '
                            'signer; refusing it as an operator', p_operator
                USING ERRCODE = '55000';
        END IF;
    END IF;

    -- (a) The operator's personal group, through THE personal-group definer,
    -- `epigraph_ensure_personal_group` (migration 105), and nothing else. It is
    -- the one place a personal group and its first admin row are minted, and
    -- its contract is exactly what this link needs (section 3):
    --   * a live row for the operator -> the group, nothing written;
    --   * no row of any state         -> the group (if absent) and the
    --                                    operator's own epoch-0 admin row;
    --   * only REVOKED rows            -> RAISE 'RVK01': the operator's own
    --                                    membership of its own group was
    --                                    revoked, and linking agents into that
    --                                    group is refused, not papered over;
    --   * a group under the key that is not the operator's own (a squat that
    --     predates 108) -> RAISE 'RVK02'.
    -- Both RAISEs abort this whole call before anything below is written; the
    -- Rust callers map them to `DbError::MembershipRevoked` /
    -- `DbError::PersonalGroupNotOwned`.
    v_group_existed := EXISTS (SELECT 1 FROM public.groups g
                                WHERE g.did_key = 'did:epigraph:personal:' || p_operator::text);
    v_group := public.epigraph_ensure_personal_group(p_operator);

    -- (b) The link record: recorded once. See section 4.
    INSERT INTO public.operator_links (agent_id, operator_id, operator_group_id)
    VALUES (p_agent, p_operator, v_group)
    ON CONFLICT (agent_id) DO NOTHING;
    GET DIAGNOSTICS v_link_rows = ROW_COUNT;

    -- (c) The agent's writer membership: recorded once, and ONLY by the call
    -- that recorded the link row (section 3). Keying on `v_link_rows` makes
    -- "never revive" rest on the app-immutable `operator_links` table rather
    -- than on membership history, which a hard DELETE can erase. The two
    -- membership guards stay as defense in depth. A RETIRED row is never
    -- promoted (section 7): its ON CONFLICT above affected nothing, so
    -- `v_link_rows` is 0.
    IF v_link_rows > 0 THEN
        INSERT INTO public.group_memberships (group_id, agent_id, wrapped_key_share,
                                              epoch, role)
        SELECT v_group, p_agent, ''::bytea, 0, 'writer'
         WHERE NOT EXISTS (SELECT 1 FROM public.group_memberships m
                            WHERE m.group_id = v_group AND m.agent_id = p_agent)
           AND NOT EXISTS (SELECT 1 FROM public.operator_links l
                            WHERE l.agent_id = p_agent AND l.retired)
        ON CONFLICT DO NOTHING;
        GET DIAGNOSTICS v_mem_rows = ROW_COUNT;
    END IF;

    -- (d) The graph record, if no OPERATED_BY edge exists between the pair in
    -- any state. It grants nothing; see section 4.
    INSERT INTO public.edges (source_id, source_type, target_id, target_type,
                              relationship, properties)
    SELECT p_agent, 'agent', p_operator, 'agent', 'OPERATED_BY',
           jsonb_build_object('source', 'epigraph_link_operator')
     WHERE NOT EXISTS (SELECT 1 FROM public.edges e
                        WHERE e.source_id = p_agent AND e.target_id = p_operator
                          AND e.relationship = 'OPERATED_BY');
    GET DIAGNOSTICS v_edge_rows = ROW_COUNT;

    -- `link_live` is computed by the SAME actor read the authoring and
    -- ownership paths use, not re-derived here. `membership_live` alone over-reports: a
    -- live membership whose role is no longer writer/admin (review probe: role
    -- set to 'reader', then re-link) returned membership_live=t while
    -- the actor read returned nothing, and the startup log said the
    -- agent authored into the operator's group when it did not.
    RETURN QUERY
    SELECT v_group,
           NOT v_group_existed,
           v_mem_rows > 0,
           EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = v_group AND m.agent_id = p_agent
                      AND m.revoked_at IS NULL),
           v_edge_rows > 0,
           EXISTS (SELECT 1 FROM public.epigraph_operator_actor(p_agent) o
                    WHERE o.operator_id = p_operator),
           EXISTS (SELECT 1 FROM public.operator_links l
                    WHERE l.agent_id = p_agent AND l.retired);
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_link_retired_agent(p_agent uuid, p_operator uuid)
RETURNS TABLE (operator_group_id uuid,
               group_created boolean,
               link_created boolean,
               link_retired boolean,
               edge_created boolean,
               membership_live boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_group     uuid;
    v_other     uuid;
    v_group_existed boolean;
    v_link_rows integer := 0;
    v_edge_rows integer := 0;
BEGIN
    IF p_agent IS NULL OR p_operator IS NULL THEN
        RAISE EXCEPTION 'epigraph_link_retired_agent: agent and operator are both required'
            USING ERRCODE = '22004';
    END IF;
    IF p_agent = p_operator THEN
        RAISE EXCEPTION 'epigraph_link_retired_agent: agent % cannot be its own operator',
                        p_agent
            USING ERRCODE = '22023';
    END IF;
    -- Serialise every link write (section 10). Taken before any check reads
    -- `operator_links`, so under READ COMMITTED each check below sees every
    -- link committed by the call this one waited for.
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    IF NOT EXISTS (SELECT 1 FROM public.agents WHERE id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_link_retired_agent: agent % does not exist', p_agent
            USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.agents WHERE id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_retired_agent: operator % does not exist', p_operator
            USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_retired_agent: % is itself operated by another agent '
                        'and cannot be an operator', p_operator
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.operator_id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_link_retired_agent: % already operates other agents and '
                        'cannot itself be operated', p_agent
            USING ERRCODE = '55000';
    END IF;
    SELECT l.operator_id INTO v_other
      FROM public.operator_links l
     WHERE l.agent_id = p_agent AND l.operator_id <> p_operator;
    IF v_other IS NOT NULL THEN
        RAISE EXCEPTION 'epigraph_link_retired_agent: agent % already has a link to operator '
                        '%; an agent is linked to one operator, and re-pointing it is an '
                        'out-of-band act', p_agent, v_other
            USING ERRCODE = '55000';
    END IF;
    -- A retire is not a demotion (section 7). An ACTOR row for this very pair
    -- cannot be turned into a retired one -- `operator_links` rows are never
    -- edited -- so `ON CONFLICT (agent_id) DO NOTHING` below would leave it
    -- acting and report success. Refused instead, so the caller cannot
    -- believe a key was de-authorized when it was not.
    IF EXISTS (SELECT 1 FROM public.operator_links l
                WHERE l.agent_id = p_agent AND l.operator_id = p_operator
                  AND NOT l.retired) THEN
        RAISE EXCEPTION 'epigraph_link_retired_agent: agent % already has an ACTOR (not '
                        'retired) link to operator %, and a retired link cannot replace it',
                        p_agent, p_operator
            USING ERRCODE = '55000',
                  HINT = 'End its authority by revoking its membership in the operator''s '
                         'group; the operator keeps ownership of its claims either way.';
    END IF;
    -- A SHARED SIGNER is neither linkable nor an operator (section 9). Checked
    -- on a FIRST link only: an exact relink (a row for this very pair already
    -- exists) records nothing new, and the edges the check counts are
    -- writable by any app session, so counting them on a relink turned forged
    -- edges into a fatal stdio startup for an agent that was already linked.
    IF NOT EXISTS (SELECT 1 FROM public.operator_links l
                    WHERE l.agent_id = p_agent AND l.operator_id = p_operator) THEN
        IF (SELECT count(DISTINCT e.target_id) FROM public.edges e
             WHERE e.source_id = p_agent AND e.relationship = 'OPERATED_BY') > 1 THEN
            RAISE EXCEPTION 'epigraph_link_retired_agent: agent % carries OPERATED_BY auth-lineage edges to '
                            'more than one principal, the fingerprint of a shared HTTP '
                            'signer; refusing to link it', p_agent
                USING ERRCODE = '55000';
        END IF;
        IF NOT public.epigraph_is_human_operator(p_operator)
           AND (SELECT count(DISTINCT e.target_id) FROM public.edges e
             WHERE e.source_id = p_operator AND e.relationship = 'OPERATED_BY') > 1 THEN
            RAISE EXCEPTION 'epigraph_link_retired_agent: operator % carries OPERATED_BY auth-lineage edges to '
                            'more than one principal, the fingerprint of a shared HTTP '
                            'signer; refusing it as an operator', p_operator
                USING ERRCODE = '55000';
        END IF;
    END IF;

    -- The operator's personal group, through the one personal-group definer:
    -- see `epigraph_link_operator` step (a). RVK01 / RVK02 abort the call.
    v_group_existed := EXISTS (SELECT 1 FROM public.groups g
                                WHERE g.did_key = 'did:epigraph:personal:' || p_operator::text);
    v_group := public.epigraph_ensure_personal_group(p_operator);

    -- ZERO write authority is a precondition, not a hope (section 7). A live
    -- `writer`/`admin` row for the agent in the operator's group -- the
    -- routine "add my agents to my group", made BEFORE the retire -- would
    -- survive it, and `Viewer::resolve` counts it: review measured a retired
    -- identity inserting a claim owned by the operator's group through exactly
    -- that row. Refused, not revoked here: revoking is the operator's decision
    -- and has its own last-admin rules. Locked first, in the order every
    -- roster writer takes them (the agent's rows in the group, then the
    -- `groups` row, whose FOR UPDATE also conflicts with a concurrent
    -- membership INSERT's foreign-key share lock). That closes a concurrent
    -- promotion and an INSERT whose foreign-key check got there first; one
    -- trigger-first INSERT order remains open (section 7's RESIDUAL).
    PERFORM 1 FROM public.group_memberships m
     WHERE m.group_id = v_group AND m.agent_id = p_agent
       FOR UPDATE;
    PERFORM 1 FROM public.groups g WHERE g.id = v_group FOR UPDATE;
    IF EXISTS (SELECT 1 FROM public.group_memberships m
                WHERE m.group_id = v_group AND m.agent_id = p_agent
                  AND m.revoked_at IS NULL AND m.role IN ('writer', 'admin')) THEN
        RAISE EXCEPTION 'epigraph_link_retired_agent: agent % holds a live writer/admin '
                        'membership in operator group %, and a retired identity may hold no '
                        'write authority there', p_agent, v_group
            USING ERRCODE = '55000',
                  HINT = 'Revoke that membership first, then retire the agent.';
    END IF;

    -- The record, retired. No membership: see section 7.
    INSERT INTO public.operator_links (agent_id, operator_id, operator_group_id, retired)
    VALUES (p_agent, p_operator, v_group, true)
    ON CONFLICT (agent_id) DO NOTHING;
    GET DIAGNOSTICS v_link_rows = ROW_COUNT;

    INSERT INTO public.edges (source_id, source_type, target_id, target_type,
                              relationship, properties)
    SELECT p_agent, 'agent', p_operator, 'agent', 'OPERATED_BY',
           jsonb_build_object('source', 'epigraph_link_retired_agent')
     WHERE NOT EXISTS (SELECT 1 FROM public.edges e
                        WHERE e.source_id = p_agent AND e.target_id = p_operator
                          AND e.relationship = 'OPERATED_BY');
    GET DIAGNOSTICS v_edge_rows = ROW_COUNT;

    -- `membership_live` REPORTS a live membership of any role; it is never
    -- created or changed here. A live writer/admin row was refused above, so
    -- a true value here is a `reader` row (no write authority). Callers still
    -- treat it as a refusal-worthy surprise, not a success.
    RETURN QUERY
    SELECT v_group,
           NOT v_group_existed,
           v_link_rows > 0,
           EXISTS (SELECT 1 FROM public.operator_links l
                    WHERE l.agent_id = p_agent AND l.retired),
           v_edge_rows > 0,
           EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = v_group AND m.agent_id = p_agent
                      AND m.revoked_at IS NULL);
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_link_retired_shared_signer(
    p_agent    uuid,
    p_operator uuid,
    p_attested uuid[])
RETURNS TABLE (operator_group_id uuid,
               group_created boolean,
               link_created boolean,
               link_retired boolean,
               edge_created boolean,
               membership_live boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE
    v_group         uuid;
    v_other         uuid;
    v_group_existed boolean;
    v_first_link    boolean;
    v_lineage       uuid[] := '{}';
    v_unattested    uuid[] := '{}';
    v_link_rows     integer := 0;
    v_edge_rows     integer := 0;
BEGIN
    IF p_agent IS NULL OR p_operator IS NULL OR p_attested IS NULL THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent, operator and the attested '
                        'principal set are all required (the set may be empty)'
            USING ERRCODE = '22004';
    END IF;
    -- A NULL element would make `t = ANY (p_attested)` NULL for every t it does
    -- not match, and the NOT below would then drop t from the unattested set:
    -- an attestation of nothing would pass the check. Refuse it outright.
    IF array_position(p_attested, NULL) IS NOT NULL THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: the attested principal set '
                        'contains a NULL; attest principals by id only'
            USING ERRCODE = '22004';
    END IF;
    IF p_agent = p_operator THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent % cannot be its own operator',
                        p_agent
            USING ERRCODE = '22023';
    END IF;
    -- 107 section 10: every link write takes this lock before reading links.
    PERFORM pg_advisory_xact_lock(hashtext('epigraph.operator_links'));
    IF NOT EXISTS (SELECT 1 FROM public.agents WHERE id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent % does not exist', p_agent
            USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.agents WHERE id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: operator % does not exist',
                        p_operator
            USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.agent_id = p_operator) THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: % is itself operated by another '
                        'agent and cannot be an operator', p_operator
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l WHERE l.operator_id = p_agent) THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: % already operates other agents '
                        'and cannot itself be operated', p_agent
            USING ERRCODE = '55000';
    END IF;
    SELECT l.operator_id INTO v_other
      FROM public.operator_links l
     WHERE l.agent_id = p_agent AND l.operator_id <> p_operator;
    IF v_other IS NOT NULL THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent % already has a link to '
                        'operator %; an agent is linked to one operator, and re-pointing it is '
                        'an out-of-band act', p_agent, v_other
            USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM public.operator_links l
                WHERE l.agent_id = p_agent AND l.operator_id = p_operator
                  AND NOT l.retired) THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent % already has an ACTOR (not '
                        'retired) link to operator %, and a retired link cannot replace it',
                        p_agent, p_operator
            USING ERRCODE = '55000',
                  HINT = 'End its authority by revoking its membership in the operator''s '
                         'group; the operator keeps ownership of its claims either way.';
    END IF;

    v_first_link := NOT EXISTS (SELECT 1 FROM public.operator_links l
                                 WHERE l.agent_id = p_agent AND l.operator_id = p_operator);
    IF v_first_link THEN
        -- The AGENT side: every principal it carried, except itself and the
        -- operator, must be attested (section 2).
        SELECT COALESCE(array_agg(DISTINCT e.target_id ORDER BY e.target_id), '{}')
          INTO v_lineage
          FROM public.edges e
         WHERE e.source_id = p_agent AND e.relationship = 'OPERATED_BY'
           AND e.target_id <> p_agent;
        SELECT COALESCE(array_agg(t ORDER BY t), '{}')
          INTO v_unattested
          FROM unnest(v_lineage) AS t
         WHERE t <> p_operator AND NOT COALESCE(t = ANY (p_attested), false);
        IF cardinality(v_unattested) > 0 THEN
            RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent % carried OPERATED_BY '
                            'auth-lineage to principals that were not attested: %; nothing was '
                            'written', p_agent, v_unattested
                USING ERRCODE = '55000',
                      HINT = 'Attest a principal only if every write the signer made for it '
                             'belongs to the operator.';
        END IF;
        -- The OPERATOR side: unchanged from 107 section 9.
        IF NOT public.epigraph_is_human_operator(p_operator)
           AND (SELECT count(DISTINCT e.target_id) FROM public.edges e
             WHERE e.source_id = p_operator AND e.relationship = 'OPERATED_BY') > 1 THEN
            RAISE EXCEPTION 'epigraph_link_retired_shared_signer: operator % carries OPERATED_BY '
                            'auth-lineage edges to more than one principal, the fingerprint of a '
                            'shared HTTP signer; refusing it as an operator', p_operator
                USING ERRCODE = '55000';
        END IF;
    END IF;

    -- The operator's personal group, through 105's definer (107 section 3).
    v_group_existed := EXISTS (SELECT 1 FROM public.groups g
                                WHERE g.did_key = 'did:epigraph:personal:' || p_operator::text);
    v_group := public.epigraph_ensure_personal_group(p_operator);

    -- ZERO write authority is a precondition (107 section 7), locked in the
    -- order every roster writer takes them.
    PERFORM 1 FROM public.group_memberships m
     WHERE m.group_id = v_group AND m.agent_id = p_agent
       FOR UPDATE;
    PERFORM 1 FROM public.groups g WHERE g.id = v_group FOR UPDATE;
    IF EXISTS (SELECT 1 FROM public.group_memberships m
                WHERE m.group_id = v_group AND m.agent_id = p_agent
                  AND m.revoked_at IS NULL AND m.role IN ('writer', 'admin')) THEN
        RAISE EXCEPTION 'epigraph_link_retired_shared_signer: agent % holds a live writer/admin '
                        'membership in operator group %, and a retired identity may hold no '
                        'write authority there', p_agent, v_group
            USING ERRCODE = '55000',
                  HINT = 'Revoke that membership first, then retire the agent.';
    END IF;

    INSERT INTO public.operator_links (agent_id, operator_id, operator_group_id, retired)
    VALUES (p_agent, p_operator, v_group, true)
    ON CONFLICT (agent_id) DO NOTHING;
    GET DIAGNOSTICS v_link_rows = ROW_COUNT;

    INSERT INTO public.edges (source_id, source_type, target_id, target_type,
                              relationship, properties)
    SELECT p_agent, 'agent', p_operator, 'agent', 'OPERATED_BY',
           jsonb_build_object('source', 'epigraph_link_retired_shared_signer',
                              'attested', to_jsonb(p_attested))
     WHERE NOT EXISTS (SELECT 1 FROM public.edges e
                        WHERE e.source_id = p_agent AND e.target_id = p_operator
                          AND e.relationship = 'OPERATED_BY');
    GET DIAGNOSTICS v_edge_rows = ROW_COUNT;

    -- The attestation, on the record, once: only when this call created the
    -- link (an exact relink attests nothing new).
    IF v_link_rows > 0 THEN
        INSERT INTO public.security_events (event_type, agent_id, success, details)
        VALUES ('operator.shared_signer_retired', p_agent, true,
                jsonb_build_object('operator_id', p_operator,
                                   'operator_group_id', v_group,
                                   'attested', to_jsonb(p_attested),
                                   'lineage_targets', to_jsonb(v_lineage),
                                   'recorded_by', session_user));
    END IF;

    RETURN QUERY
    SELECT v_group,
           NOT v_group_existed,
           v_link_rows > 0,
           EXISTS (SELECT 1 FROM public.operator_links l
                    WHERE l.agent_id = p_agent AND l.retired),
           v_edge_rows > 0,
           EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = v_group AND m.agent_id = p_agent
                      AND m.revoked_at IS NULL);
END $$;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_link_operator(uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_link_retired_agent(uuid, uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_link_retired_shared_signer(uuid, uuid, uuid[]) '
                'OWNER TO epigraph_maintenance';
    END IF;
END $$;
