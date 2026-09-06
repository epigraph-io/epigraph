-- ===================================================================
-- 077 — ROW LEVEL SECURITY POLICIES. `ENABLE` ONLY; 079 FLIPS `FORCE`.
--
-- ===================================================================
-- THE MIGRATION NUMBER. The plan's PR-17 *Files* line says "migrations
-- 073/074/075" and its §3 dependency table (lines 402-404) says "074/075/076".
-- BOTH ARE WRONG, for the seventh time in this series: 073 is PR-13's
-- `073_idx_edges_co_owner.sql` and 074/075/076 are PR-16's, all four APPLIED.
-- Editing an applied version is a checksum mismatch, which panics the api
-- binary on restart. `migrations/README.md` is authoritative and assigns PR-17
-- 077 (policies) / 078 (canary) / 079 (FORCE). Two in-tree doc comments already
-- agree with the README against the plan:
-- `visibility.rs::edge_predicate_fragment` says "migration 077's `edges_tenancy`
-- USING clause", and `072_edge_co_ownership.sql`'s header says "PRE-STAGED FOR
-- MIGRATION 077 (PR-17)".
--
-- ===================================================================
-- ENFORCEMENT BEGINS HERE, NOT AT 079.
--
-- In PostgreSQL a policy filters every role EXCEPT the table's owner and
-- holders of `BYPASSRLS`. `FORCE` only ADDITIONALLY subjects the owner. Every
-- table below is owned by the superuser `epigraph`; every role the app and the
-- job fleet connect as (`epigraph_app`, `epigraph_admin`, `epigraph_maintenance`)
-- is a non-owner without `BYPASSRLS`. So from THIS file onward the policies are
-- already filtering for every role that matters, and 079 closes only the owner
-- hole. `epigraph-db/src/pool.rs`'s `MaintenancePrivilege::rls_active` was
-- widened to `(relrowsecurity OR relforcerowsecurity)` for exactly this reason;
-- anything keyed on `relforcerowsecurity` alone repeats the bug PR-15 fixed.
--
-- The corollary that makes this file safe to land: the DSN in every environment
-- today is the superuser `epigraph`, for whom `epigraph_bypass()` is
-- unconditionally true AND who is the table owner. This migration is therefore
-- OBSERVABLY INERT until plan §9.2 step 11d repoints `DATABASE_URL`. The
-- migrations are not the landmine; the DSN repoint is.
--
-- ===================================================================
-- FOUR CORRECTIONS TO THE PLAN'S 077 SKETCH, EACH MEASURED.
--
-- (1) `epigraph_definer_bypass()` IS MISSING FROM EVERY PREDICATE THE PLAN
--     WRITES, AND WITHOUT IT MIGRATION 070's OWN DOCUMENTED LEAK REOPENS.
--     `epigraph_bypass()` keys on `session_user` (067, deliberately: SECURITY
--     DEFINER does not change it), so inside the eight `prosecdef` bodies —
--     all owned by `epigraph_maintenance` — it is FALSE once the app connects
--     as `epigraph_app`. `epigraph_node_tenancy` then runs an RLS-FILTERED
--     `SELECT ... FROM public.claims WHERE id = p_id`, and 070's header
--     describes the outcome in its own words: "a filtered read of `claims`
--     returns NOT FOUND, `epigraph_node_tenancy` then yields its
--     ('public', world) fallback, and a private endpoint would be stamped
--     PUBLIC. That is a LEAK, not an error." 070:316 states the assumption
--     this file has to make true — "the function is still re-owned to
--     epigraph_maintenance below so its UPDATE is not RLS-filtered at PR-17".
--     Function ownership does NOT exempt a body from RLS on tables it does not
--     own, so the exemption has to be written into the policies. Every USING
--     and WITH CHECK below therefore carries the definer disjunct.
--
--     The EXECUTE grant is not optional. 067 does `REVOKE EXECUTE ON FUNCTION
--     epigraph_definer_bypass() FROM PUBLIC`, so naming it in a policy body
--     that an `epigraph_app` statement evaluates raises `42501 permission
--     denied for function epigraph_definer_bypass` on every ordinary read.
--     `OR` is not a guaranteed short circuit and function permission checks are
--     made at execution time, so the grant below is a correctness requirement,
--     not a hardening nicety. Granting it leaks nothing: the function is
--     `pg_has_role(current_user, 'epigraph_maintenance', 'MEMBER')`, i.e. it
--     reports on the CALLER'S OWN role and returns false for `epigraph_app` by
--     construction. It is not an oracle over anything. It stays REVOKEd from
--     PUBLIC, so `schema_contract.rs`'s assertion is unaffected.
--
-- (2) THE TOKEN MINT BREAKS IN FOUR PLACES, NOT ONE (sec-F13). The plan
--     anticipates only the `agents` FOR-SELECT-only trap. Traced through
--     `repos/agent.rs::ensure_for_client` and `::ensure_personal_group`, an
--     unauthenticated mint — where no principal exists and therefore no
--     principal GUC can — issues:
--       (a) `INSERT INTO agents ... ON CONFLICT (public_key) DO UPDATE`
--       (b) `INSERT INTO groups ... ON CONFLICT (did_key) DO UPDATE`
--       (c) `INSERT INTO group_memberships ... ON CONFLICT (...) DO UPDATE`
--     An `ON CONFLICT DO UPDATE` needs the INSERT `WITH CHECK` *and* the UPDATE
--     `USING` *and* the UPDATE `WITH CHECK`. The plan's `agents_self_update`
--     (`id = epigraph_principal_id()`) is NULL-valued at mint time and denies
--     (a); the plan writes no `groups` policy at all, so (b) is default-denied;
--     and its `group_memberships` `WITH CHECK` requires group-admin, which a
--     principal-less session cannot satisfy, so (c) is denied. Every
--     authentication would break the day 079 lands. Each of the three gets a
--     narrow, STRUCTURALLY self-certifying provisioning arm below, and
--     `rls_enforcement.rs` runs the real `ensure_for_client` as `epigraph_app`
--     to prove it.
--
-- (3) `Viewer::resolve` READS `group_memberships` UPSTREAM OF THE GUC IT
--     POPULATES, so a GUC-keyed SELECT policy on that table empties every
--     viewer's group set AT THE SOURCE. `visibility.rs::Viewer::resolve` calls
--     `GroupMembershipRepository::list_live_for_agent(pool, principal)` on a
--     raw pool connection — it must, because `acquire_as` needs the very
--     `Viewer` this call is constructing. Under the plan's policy that read
--     returns ZERO rows for every principal, every viewer resolves to
--     `group_ids = []`, and the whole corpus silently narrows to
--     `visibility='public'` for its own owners. That is sec-F1, one layer above
--     where the plan looks for it, and it defeats RLS from above rather than
--     from below. Closed here by `epigraph_live_memberships()`, a SECURITY
--     DEFINER reader owned by `epigraph_maintenance`, which the definer
--     disjunct from (1) admits.
--
-- (4) THE SKETCH DOES NOT APPLY AS WRITTEN. Its `security_events_read` calls
--     `public.epigraph_is_instance_admin(...)`, which does not exist in
--     `pg_proc` — `instance_admins` is PR-18's 083 — so the policy fails to
--     create and takes the whole migration with it. That disjunct is dropped
--     here and belongs to PR-18. Related count corrections: there are FOUR
--     encryption tables, not the "three" the plan's prose at :1657 says (its own
--     079 array lists four, and all four exist).
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 0. PRIVILEGES. See correction (1) for the definer-bypass grant.
--
-- The app-role table grants are here because `docs/deploy.md` assigns them to
-- PR-17 by name ("NOLOGIN today; PR-17 gives it a login and makes
-- `current_user = 'epigraph_app'` a boot assertion") and because plan §9.2 step
-- 11d is not attemptable without them: migration 060 says in its own comment
-- "(060 itself issues no GRANT.)", 070 grants only `epigraph_maintenance`, and
-- an `epigraph_app` connection therefore fails with `42501 permission denied
-- for table claims` BEFORE RLS is ever consulted. Grants are the migration-
-- shaped half of that obligation.
--
-- THE LOGIN AND THE PASSWORD ARE DELIBERATELY NOT HERE. `epigraph_app` stays
-- `NOLOGIN`. `ALTER ROLE epigraph_app LOGIN PASSWORD '...'` is an out-of-band
-- operator step in the 11d runbook: this repository is PUBLIC and a credential
-- must never land in it. Nothing can use these grants until an operator issues
-- that statement, which is also what makes this file inert.
--
-- DELETE is granted, unlike 070's maintenance grant which is deliberately
-- SELECT/INSERT/UPDATE only. The app role really does delete —
-- `evidence.rs::delete`, `claim.rs::delete` — whereas the tenancy maintenance
-- role stamps and reads and never destroys.
--
-- `ON ALL TABLES IN SCHEMA public` binds the tables that exist NOW, and NOW is
-- version 077 — so on a FRESH migrate (CI, a new cluster, a restore) every table
-- created by a LATER migration is missed, while on the already-deployed database
-- the same statement catches them because they exist by the time 077 runs. That
-- divergence is not hypothetical: `webhook_subscriptions` is migration 085's,
-- and MEASURED at head on a freshly-migrated database it was the ONE relation in
-- `public` for which `has_table_privilege('epigraph_app', …, 'SELECT')` was
-- false, on live app-pool webhook routes. 078 issuing its own grant for
-- `rls_canary` shows the hazard was seen for one table and not generalised.
--
-- BOTH HALVES ARE NEEDED AND NEITHER IS REDUNDANT:
--   * `ON ALL TABLES` covers the already-deployed database, where 080+ relations
--     exist before 077 runs. `ALTER DEFAULT PRIVILEGES` does NOT apply
--     retroactively, so it cannot.
--   * `ALTER DEFAULT PRIVILEGES FOR ROLE epigraph` covers every table a LATER
--     migration creates, which is the fresh-migrate case. It is scoped to
--     objects created BY `epigraph`, which is correct precisely because
--     migrations run as the superuser DSN; a table created by any other role is
--     deliberately not covered.
-- `migrations/README.md` states the resulting rule for the rest of the series.
-- ===================================================================
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_definer_bypass() '
                'TO epigraph_app';
        EXECUTE 'GRANT USAGE ON SCHEMA public TO epigraph_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES '
                'IN SCHEMA public TO epigraph_app';
        EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public '
                'TO epigraph_app';
        -- The forward half. `FOR ROLE epigraph` is the migration runner.
        EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE epigraph IN SCHEMA public '
                'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO epigraph_app';
        EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE epigraph IN SCHEMA public '
                'GRANT USAGE, SELECT ON SEQUENCES TO epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 1. POLICY HELPERS.
--
-- All FOUR are SECURITY DEFINER and are re-owned to `epigraph_maintenance` at
-- the end of this section, for the same reason 070 re-owns its bodies: inside
-- the frame `current_user` becomes the owner, so `epigraph_definer_bypass()` is
-- true and the body's own reads are not RLS-filtered. An owner of `epigraph`
-- would work too but would make the bodies superuser-owned, which 070
-- deliberately moved away from.
-- ===================================================================

-- `group_memberships` needs a SECURITY DEFINER helper, NOT an inline EXISTS over
-- itself: a policy ON group_memberships whose WITH CHECK selects FROM
-- group_memberships re-applies the policy to the inner scan and raises
-- `infinite recursion detected in policy for relation "group_memberships"`.
--
-- The recursion really is closed, and not merely moved: the inner SELECT is a
-- separate query in which `current_user` is `epigraph_maintenance`, so the
-- table's USING clause is satisfied by its DEFINER-BYPASS disjunct — a constant
-- that does not reference `group_memberships`. The self-referencing predicate
-- appears only in WITH CHECK, which is not applied to a SELECT. Pinned by
-- `rls_enforcement.rs::group_memberships_policy_does_not_recurse`.
--
-- IT TAKES NO `p_agent`, AND THAT IS THE POINT. An earlier draft took
-- `(p_group, p_agent)` and was granted to `epigraph_app`. Because a SECURITY
-- DEFINER frame satisfies `epigraph_definer_bypass()`, such a function answers
-- TRUTHFULLY about groups the caller is not a member of — i.e. it is a
-- membership oracle over the whole instance, reachable by any app connection,
-- and one that no pre-077 API exposed. Every policy call site passed
-- `epigraph_principal_id()` as `p_agent` anyway, so binding the subject to the
-- CALLING PRINCIPAL inside the body loses nothing and removes the oracle.
-- Session GUCs are not affected by a definer frame, so `epigraph_principal_id()`
-- still reads the caller's session here.
CREATE OR REPLACE FUNCTION public.epigraph_is_group_admin(p_group uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT public.epigraph_principal_id() IS NOT NULL AND EXISTS (
      SELECT 1 FROM public.group_memberships m
       WHERE m.group_id = p_group
         AND m.agent_id = public.epigraph_principal_id()
         AND m.role = 'admin' AND m.revoked_at IS NULL)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_is_group_admin(uuid) FROM PUBLIC;

-- THE PERSONAL-GROUP BOOTSTRAP, AS A DEFINER *WRITER* RATHER THAN A POLICY ARM.
--
-- An earlier draft expressed this as a "structural, self-certifying" predicate
-- in the policies themselves —
--   groups:             kind = 'personal'
--                       AND did_key = 'did:epigraph:personal:' || created_by_agent_id
--   group_memberships:  role = 'admin' AND <that group is that agent's personal group>
-- — on the reasoning that a row naming its own subject can be admitted without
-- trusting session state.
--
-- THAT REASONING IS WRONG, AND THE WAY IT IS WRONG GENERALISES. Both arguments
-- come from the ROW, not from the SESSION. `did_key` is DERIVED from
-- `created_by_agent_id`, so the conjunct is a tautology for every well-formed
-- personal group: it filters nothing. An arm that mentions none of
-- `epigraph_session_groups()`, `epigraph_writable_groups()`,
-- `epigraph_principal_id()`, `epigraph_bypass()` or `epigraph_definer_bypass()`
-- is not a narrowing, it is an UNCONDITIONAL GRANT — and because these arms sat
-- in USING as well as WITH CHECK (an `ON CONFLICT` needs the SELECT side), they
-- granted READ. MEASURED as `epigraph_app` with no GUCs at all: 194 of 198
-- `groups` rows and 193 of 195 `group_memberships` rows were visible, the latter
-- including the `wrapped_key_share` column — the very column whose existence is
-- the reason `group_memberships` is in the protected set at all, and which this
-- file elsewhere refuses to expose via a permissive SELECT policy.
-- `rls_enforcement.rs::no_policy_arm_is_session_independent` is the detector
-- that makes the general property a ratchet rather than a lesson.
--
-- The bootstrap is a WRITE, so it belongs in a definer WRITER, not in a read
-- predicate. This function performs exactly the two statements
-- `agent.rs::ensure_personal_group` used to issue inline, so the policies need
-- no personal-group arm in either direction. VOLATILE (the default) because it
-- modifies; the read-only helpers around it are STABLE and that difference is
-- load-bearing, not cosmetic.
--
-- It grants no read: it returns one group id, which is already derivable from
-- the deterministic `did:epigraph:personal:<uuid>` key without calling anything.
CREATE OR REPLACE FUNCTION public.epigraph_ensure_personal_group(p_agent uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
DECLARE v_group uuid;
BEGIN
    INSERT INTO public.groups (display_name, did_key, public_key, kind,
                               created_by_agent_id)
    VALUES ('personal:' || p_agent::text,
            'did:epigraph:personal:' || p_agent::text,
            ''::bytea, 'personal', p_agent)
    ON CONFLICT (did_key) DO UPDATE SET updated_at = now()
    RETURNING id INTO v_group;

    INSERT INTO public.group_memberships (group_id, agent_id, wrapped_key_share,
                                          epoch, role)
    VALUES (v_group, p_agent, ''::bytea, 0, 'admin')
    ON CONFLICT (group_id, agent_id, epoch)
    DO UPDATE SET revoked_at = NULL, role = 'admin';

    RETURN v_group;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_ensure_personal_group(uuid) FROM PUBLIC;

-- THE OAUTH PRINCIPAL MINT, for the same reason and with the same shape.
--
-- An earlier draft carried `agents_self_update`'s arm
--   key_kind = 'derived' AND epigraph_principal_id() IS NULL
-- justified as "only when the session has NO principal, i.e. genuinely
-- pre-authentication". That premise does not hold in this tree: the request path
-- does not stamp the session GUCs at any of its `state.db_pool` sites
-- (`D-PR17-request-path-never-stamps-session-gucs`), so a NULL principal is the
-- STEADY STATE of an app connection, not a pre-authentication instant. The arm
-- was therefore live on every statement, and it admitted UPDATEs to `role` and
-- `default_group_id` — the column that decides where an agent's future claims
-- are owned — on any derived row, not just the mint's own.
--
-- The mint is the only writer of `key_kind = 'derived'` rows in the workspace,
-- so it moves into a definer frame and the policy keeps only `id = principal`.
-- `agents_provision` then refuses `derived` from the app role outright: after
-- this function exists, NO legitimate app-role path creates one.
--
-- The `WHERE agents.key_kind = 'derived'` guard on the conflict branch is
-- preserved verbatim from `ensure_for_client`: it is what stops a derived
-- principal from being grafted onto a real `ed25519` signer row. When it fails
-- the statement returns zero rows, so this function returns NULL, and the Rust
-- caller must keep mapping NULL to its `DuplicateKey` refusal rather than
-- treating a returned row as success.
CREATE OR REPLACE FUNCTION public.epigraph_provision_oauth_agent(
    p_public_key bytea, p_display_name text, p_agent_type text)
RETURNS uuid LANGUAGE sql SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    INSERT INTO public.agents (public_key, display_name, agent_type, key_kind, labels)
    VALUES (p_public_key, p_display_name, p_agent_type, 'derived',
            ARRAY['oauth-principal'])
    ON CONFLICT (public_key) DO UPDATE SET updated_at = now()
        WHERE agents.key_kind = 'derived'
    RETURNING id
$$;
REVOKE EXECUTE ON FUNCTION
    public.epigraph_provision_oauth_agent(bytea, text, text) FROM PUBLIC;

-- THE CHICKEN-AND-EGG READER. See correction (3).
--
-- `Viewer::resolve` cannot use `ScopedPool::acquire_as` — that call needs the
-- Viewer it is constructing — so its membership read is the one statement in
-- the system that provably runs with no tenancy GUC. Routing it through a
-- definer frame is what keeps `group_memberships` tightly policed for every
-- OTHER reader while still letting a principal discover its own groups.
--
-- The exposure is unchanged from today: `list_live_for_agent` is already
-- callable with an arbitrary `agent_id` and already returns exactly
-- `(group_id, role)`. It is not widened here, only made to keep working.
-- `m.role::text` is an EXPLICIT cast, not decoration: the column is
-- `character varying(20)` and a `RETURNS TABLE (… role text)` mismatch raises
-- `42804 structure of query does not match function result type` at CALL time,
-- not at CREATE time — so the migration would apply clean and the failure would
-- wait for the first `Viewer::resolve` on a live request.
CREATE OR REPLACE FUNCTION public.epigraph_live_memberships(p_agent uuid)
RETURNS TABLE (group_id uuid, role text) LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT m.group_id, m.role::text FROM public.group_memberships m
     WHERE m.agent_id = p_agent AND m.revoked_at IS NULL
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_live_memberships(uuid) FROM PUBLIC;

-- ===================================================================
-- THE GROUP-CREATION BOOTSTRAP, which no membership-keyed policy can express.
--
-- Creating a group and becoming its first administrator is inherently circular:
-- at the instant the `groups` row is written the creator is a member of nothing,
-- so `epigraph_is_group_admin` is false and `epigraph_session_groups()` cannot
-- contain an id that did not exist when the connection was stamped.
--
-- MEASURED as `epigraph_app`: without this arm, `GroupRepository::create_with_admin`
-- (`routes/groups.rs::create_group`) and `CommunityRepository::create`
-- (`routes/community.rs`) are each denied at three consecutive statements —
-- the `groups` insert, the `group_key_epochs` epoch-0 insert, and the
-- `group_memberships` admin insert — all inside one transaction, on live HTTP
-- paths. Neither runs on a maintenance pool, so `epigraph_bypass()` does not
-- save them.
--
-- The arm is keyed on `groups.created_by_agent_id`, which BOTH call sites bind
-- from `Viewer::principal()`. It says: you may write and read a group you
-- declared yourself the creator of, seed its key epoch, and enrol members in
-- it. It does NOT let you touch a group somebody else created — that needs
-- `epigraph_is_group_admin`, which is the steady-state control.
--
-- The creator arm is in `groups_tenancy`'s USING as well as its WITH CHECK
-- because `community.rs`'s `ON CONFLICT` needs the SELECT side, and
-- `created_by_agent_id` is never rewritten, so the arm outlives the creator's
-- own membership. Narrowing it needs a liveness conjunct that the bootstrap it
-- exists for cannot satisfy. Recorded as
-- `D-PR17-creator-arm-outlives-membership` in `docs/tenancy/progress.json`. It
-- reaches a group's identity row and roster only, never claim content:
-- `claims_tenancy` keys on `epigraph_session_groups()`, which a revoked member
-- no longer carries.
--
-- ONE RESIDUAL, RECORDED AT MECHANISM LEVEL.
--
-- `epigraph_live_memberships(uuid)` is granted to `epigraph_app` and is
-- parameterised by agent rather than bound to the calling principal, because its
-- one caller — `Viewer::resolve` — runs BEFORE the principal GUC it is helping
-- to compute exists, so there is no session subject to bind to. The Rust
-- caller's surface is unchanged (`list_live_for_agent` already took an agent id
-- and already returned exactly `(group_id, role)`), but the SQL surface is new
-- and calling that a no-op would be wrong. Recorded as
-- `D-PR17-live-memberships-is-parameterised-not-principal-bound` in
-- `docs/tenancy/progress.json`; it is the only definer helper here that is not
-- bound to the caller.
--
-- The three sibling helpers ARE bound to the caller — see
-- `epigraph_is_group_admin` above for why that mattered — and the two
-- provisioning helpers are writers that return nothing a caller could not
-- already derive.
CREATE OR REPLACE FUNCTION public.epigraph_is_group_creator(p_group uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT public.epigraph_principal_id() IS NOT NULL AND EXISTS (
      SELECT 1 FROM public.groups g
       WHERE g.id = p_group
         AND g.created_by_agent_id = public.epigraph_principal_id())
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_is_group_creator(uuid) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_is_group_admin(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_live_memberships(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_is_group_creator(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION public.epigraph_ensure_personal_group(uuid) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION '
                'public.epigraph_provision_oauth_agent(bytea, text, text) '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_is_group_admin(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_live_memberships(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_is_group_creator(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION public.epigraph_ensure_personal_group(uuid) '
                'TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_provision_oauth_agent(bytea, text, text) '
                'TO epigraph_app';
    END IF;
END $$;

-- ===================================================================
-- 2. THE OWNED TIER-A POLICY — 19 TABLES.
--
-- The plan's sketch writes out SEVEN tables and its prose says "the full
-- generated tier-A set". Measured: 062's `tier_a` array is 25 relations and
-- exactly 25 relations in `public` carry both `visibility` and
-- `owner_group_id`. Four of the 25 are bespoke here (`edges` carries the
-- co-ownership INTERSECTION; `recall_events` is principal-keyed) or need the
-- registry variant in section 2b (`frames`, `contexts`, `perspectives`,
-- `communities`) — see below. A loop, not 19 transcriptions, so the set cannot
-- drift from 062's.
--
-- `(SELECT f())` is a sublink, so it plans as an InitPlan evaluated ONCE per
-- statement rather than once per row.
--
-- THE CONSTANTS COME FIRST, and the two tenancy disjuncts that follow are the
-- same disjuncts, in the same order, that `Viewer::predicate_fragment` emits
-- for a `Scoped` viewer (`visibility = 'public' OR owner_group_id = ANY($V)`).
-- That is what makes the app-emitted qual IMPLY the policy's, so the RLS filter
-- can never reject a row the index already returned (§4.5). A correction to the
-- plan's comment while we are here: `predicate_fragment` emits NO bypass
-- constant at all, so the sentence "it is the same disjunct, in the same order,
-- that Viewer::predicate_fragment emits" is not a literal description of the
-- code. The implication still holds — widening a policy with extra OR-disjuncts
-- preserves it, and `qual_guc_coherence.rs` pins `$V` == `epigraph_session_groups()`.
--
-- WITH CHECK IS WRITTEN EXPLICITLY on every FOR ALL policy. `FOR ALL USING (…)`
-- alone silently reuses USING as WITH CHECK, which is how the enterprise policy
-- set degenerated to a no-op for INSERT.
--
-- NO WORLD-GROUP ARM ON THESE 19, DELIBERATELY, and that IS the plan's rule:
-- "under §2.3 a public claim is owned by its author's group, so publishing
-- publicly is an ORDINARY write into a group you can write to". §8.2 acceptance
-- query A4 asserts `count(*) FROM claims WHERE owner_group_id = <world>` is 0,
-- and `TenancyDecl::instance_wide()`'s doc says in as many words that it "is not
-- available for `claims`". What the plan then got wrong is applying that
-- deletion to the WHOLE generated set — see 2b.
-- ===================================================================
DO $$
DECLARE t text;
        owned text[] := ARRAY[
          'claims','evidence',
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance',
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations',
          'harvester_fragments'];
BEGIN
    FOREACH t IN ARRAY owned LOOP
        -- relkind guard: `alternative_set` and `alt_set_decisions` are VIEWs in
        -- the §2.4 generated protected set and `ALTER TABLE … ENABLE ROW LEVEL
        -- SECURITY` errors on a view. None of THIS array is a view today, but
        -- the guard is what keeps that true if the array ever widens.
        IF NOT EXISTS (SELECT 1 FROM pg_class c
                         JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public' AND c.relname = t
                          AND c.relkind IN ('r', 'p')) THEN
            CONTINUE;
        END IF;
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', t || '_tenancy', t);
        EXECUTE format($f$
            CREATE POLICY %I ON public.%I FOR ALL TO PUBLIC
                USING (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR visibility = 'public'
                    OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]))
                WITH CHECK (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]))
        $f$, t || '_tenancy', t);
    END LOOP;
END $$;

-- ===================================================================
-- 2b. THE FOUR INSTANCE-WIDE REGISTRIES.
--
-- ===================================================================
-- THE LARGEST DEFECT IN THE PLAN'S 077 SKETCH, AND IT IS RECORDED NOWHERE.
--
-- The plan deletes the draft's third WITH CHECK arm — `OR (visibility='public'
-- AND owner_group_id=<world>)` — and gives a correct reason for CLAIMS. It then
-- applies that deletion to the whole generated tier-A set. Four members of that
-- set are ownerless INSTANCE-WIDE REGISTRIES whose only legal declaration is
-- exactly the arm that was deleted.
--
-- `epigraph-core/src/tenancy.rs::TenancyDecl::instance_wide()` is
-- `('public', WORLD_GROUP)` and its doc names these four by name: "`frames`,
-- `contexts`, `perspectives` and `communities` are instance-wide registries — a
-- frame is a shared hypothesis space, and giving it an owner group would make
-- Dempster-Shafer mass functions unreadable across groups for no gain."
-- `repos/{frame,context,perspective,community}.rs` bind it at seven production
-- write sites.
--
-- The world group is MEMBERLESS BY DESIGN
-- (`locked_decisions.rs::d2_world_and_seed_remain_memberless`), so it is in
-- NOBODY's `epigraph_writable_groups()`, ever. Under the generic WITH CHECK
-- every `CREATE FRAME`, every context, every perspective and every community
-- write raises `42501` for the app role the moment 077 lands and the DSN is
-- repointed — a total outage on four tables, with no test in the suite able to
-- see it because CI connects as a `BYPASSRLS` superuser.
--
-- MEASURED on the throwaway, as `epigraph_app` under these policies: the strict
-- form denies a `('public', world)` insert; this form admits it.
--
-- The arm is NARROW. It admits `('public', world)` and nothing else: pairing
-- `'group'` with the world group is already refused outright by
-- `<table>_group_needs_real_group` (062), so this cannot be used to write a
-- private row nobody owns. It is not extended to `claims`, `evidence` or the 17
-- derived tables, where §8.2's A4 acceptance query requires the world-owned
-- count to stay at zero.
-- ===================================================================
DO $$
DECLARE t text;
        registry text[] := ARRAY['frames','contexts','perspectives','communities'];
BEGIN
    FOREACH t IN ARRAY registry LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_class c
                         JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public' AND c.relname = t
                          AND c.relkind IN ('r', 'p')) THEN
            CONTINUE;
        END IF;
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', t || '_tenancy', t);
        EXECUTE format($f$
            CREATE POLICY %I ON public.%I FOR ALL TO PUBLIC
                USING (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR visibility = 'public'
                    OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]))
                WITH CHECK (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    -- TenancyDecl::instance_wide(), and only that.
                    OR (visibility = 'public'
                        AND owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid)
                    OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]))
        $f$, t || '_tenancy', t);
    END LOOP;
END $$;

-- ===================================================================
-- 3. edges — THE CO-OWNERSHIP INTERSECTION.
--
-- The USING clause is transcribed from `072_edge_co_ownership.sql`'s header,
-- which carries it verbatim next to the column precisely so PR-17 cannot
-- re-derive a non-matching one. INTERSECTION, not union: a co-owned edge is
-- visible only to a principal in BOTH owning groups, and a union would defeat
-- the point of the column.
--
-- THE WITH CHECK CARRIES THE WORLD ARM, AND FOR A STRONGER REASON THAN 2b's.
-- On `frames` the world declaration is what the CALL SITE chooses; on `edges` it
-- is what a TRIGGER IMPOSES. `070_tenancy_triggers.sql::epigraph_edges_tenancy`
-- computes the endpoint meet and, when both endpoints are public, executes
-- `NEW.owner_group_id := '00000000-…-0000'::uuid`. A BEFORE trigger runs ahead
-- of the WITH CHECK, so EVERY edge between two public claims arrives at the
-- policy world-owned no matter what the writer declared. Without this arm the
-- strict form rejects every one of them — `link_hierarchical`,
-- `link_epistemic`, every ingestion edge. MEASURED as `epigraph_app`: denied
-- without the arm, admitted with it.
-- ===================================================================
ALTER TABLE public.edges ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS edges_tenancy ON public.edges;
CREATE POLICY edges_tenancy ON public.edges FOR ALL TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR visibility = 'public'
        OR (owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[])
            AND (co_owner_group_id IS NULL
                 OR co_owner_group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]))))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        -- What 070's BEFORE trigger stamps on an edge between two public
        -- endpoints. Not a widening: `('group', world)` is refused by
        -- `edges_group_needs_real_group`.
        OR (visibility = 'public'
            AND owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid)
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]));

-- ===================================================================
-- 4. recall_events — KEYED ON THE QUERYING AGENT, not on visibility/ownership.
--
-- It carries the tier-A columns because 062 gave them to it, but the thing that
-- must not leak is one agent's raw search text and returned claim ids to
-- another agent, so the policy is principal-keyed.
--
-- NOTE the `IS NOT NULL` conjunct. Without it the predicate degenerates to
-- `agent_id IS NOT DISTINCT FROM NULL` on an unstamped session, which is TRUE
-- for every NULL-agent_id row — the exact inverse of the leak this policy
-- closes (sec-F1). §0.5's checkout stamping means the GUC is always set; this
-- conjunct means the policy is still correct if it ever is not. Asserted by
-- `rls_enforcement.rs::a_null_agent_recall_event_is_invisible_without_a_principal`.
-- ===================================================================
ALTER TABLE public.recall_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recall_events_tenancy ON public.recall_events;
CREATE POLICY recall_events_tenancy ON public.recall_events FOR ALL TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR ((SELECT public.epigraph_principal_id()) IS NOT NULL
            AND agent_id IS NOT DISTINCT FROM (SELECT public.epigraph_principal_id())))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR ((SELECT public.epigraph_principal_id()) IS NOT NULL
            AND agent_id IS NOT DISTINCT FROM (SELECT public.epigraph_principal_id())));

-- ===================================================================
-- 5. THE FOUR ENCRYPTION TABLES — keyed on `group_id`, not `owner_group_id`.
--
-- The plan's prose at :1657 says "the three encryption tables"; its own 079
-- array lists four and all four exist. They hold wrapped key material for a
-- group, so read follows group membership and write follows WRITE membership.
-- ===================================================================
DO $$
DECLARE t text;
        enc text[] := ARRAY['claim_encryption','claim_version_encryption',
                            'evidence_encryption','edge_encryption'];
BEGIN
    FOREACH t IN ARRAY enc LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_class c
                         JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public' AND c.relname = t
                          AND c.relkind IN ('r', 'p')) THEN
            CONTINUE;
        END IF;
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', t || '_tenancy', t);
        EXECUTE format($f$
            CREATE POLICY %I ON public.%I FOR ALL TO PUBLIC
                USING (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[]))
                WITH CHECK (
                    (SELECT public.epigraph_bypass())
                    OR (SELECT public.epigraph_definer_bypass())
                    OR group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[]))
        $f$, t || '_tenancy', t);
    END LOOP;
END $$;

-- ===================================================================
-- 6. groups — READ BY MEMBERSHIP, PLUS THE PERSONAL-GROUP PROVISIONING ARM.
--
-- The plan lists `groups` in 077's prose and in 079's FORCE array but writes no
-- policy for it, which means default-deny — and default-deny on `groups` breaks
-- `ensure_personal_group`, i.e. every token mint. See correction (2)(b).
--
-- THE PERSONAL-GROUP ARM IS GONE. It was session-independent and therefore an
-- unconditional read grant over every personal group in the instance; the mint
-- now provisions through `epigraph_ensure_personal_group()` and is admitted by
-- the DEFINER-BYPASS disjunct. See section 1 for the measurement and for why
-- "the row certifies its own subject" was the wrong test.
-- ===================================================================
ALTER TABLE public.groups ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS groups_tenancy ON public.groups;
CREATE POLICY groups_tenancy ON public.groups FOR ALL TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR id = ANY ((SELECT public.epigraph_session_groups())::uuid[])
        -- The group-creation bootstrap. See section 1.
        OR created_by_agent_id = (SELECT public.epigraph_principal_id()))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR created_by_agent_id = (SELECT public.epigraph_principal_id()));

-- ===================================================================
-- 7. group_memberships — NON-RECURSIVE, AND STILL READABLE BY `Viewer::resolve`.
--
-- USING carries no reference to `group_memberships`, which is what makes the
-- SECURITY DEFINER helper in WITH CHECK safe (see section 1).
--
-- `Viewer::resolve`'s read does NOT go through this policy's principal arm — it
-- cannot, see correction (3) — it goes through `epigraph_live_memberships()`
-- and is admitted by the DEFINER-BYPASS disjunct.
--
-- THE PERSONAL-GROUP PROVISIONING ARM IS GONE, from USING and from WITH CHECK.
--
-- It had to be in USING as well as WITH CHECK, because `INSERT … ON CONFLICT`
-- requires the SELECT policy to admit the row and on a `FOR ALL` policy the
-- SELECT policy IS the USING clause — MEASURED: as `epigraph_app` the bare
-- `INSERT` succeeded while the identical statement with `ON CONFLICT … DO
-- UPDATE` was refused, even with no conflicting row. That is a real trap and it
-- is why the arm was written; but the arm itself referenced only ROW columns, so
-- putting it in USING granted every session read of every personal-group
-- membership row in the instance — `wrapped_key_share` included. The
-- provisioning write moved into `epigraph_ensure_personal_group()` instead,
-- where the `ON CONFLICT` runs inside a definer frame and needs no arm at all.
-- ===================================================================
ALTER TABLE public.group_memberships ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS group_memberships_tenancy ON public.group_memberships;
CREATE POLICY group_memberships_tenancy ON public.group_memberships FOR ALL TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[])
        OR agent_id = (SELECT public.epigraph_principal_id())
        OR public.epigraph_is_group_creator(group_id))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR public.epigraph_is_group_admin(group_id)
        -- The creator's own first admin row, written in the same transaction
        -- as the group. See section 1.
        OR public.epigraph_is_group_creator(group_id));

-- ===================================================================
-- 8. group_key_epochs — key material, read and written by group membership.
-- ===================================================================
ALTER TABLE public.group_key_epochs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS group_key_epochs_tenancy ON public.group_key_epochs;
CREATE POLICY group_key_epochs_tenancy ON public.group_key_epochs FOR ALL TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR group_id = ANY ((SELECT public.epigraph_session_groups())::uuid[])
        -- Epoch 0 is written in the SAME transaction as the group, before the
        -- creator is a member of anything. See section 1.
        OR public.epigraph_is_group_creator(group_id))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR group_id = ANY ((SELECT public.epigraph_writable_groups())::uuid[])
        OR public.epigraph_is_group_creator(group_id));

-- ===================================================================
-- 9. agents — THE FOR-SELECT-ONLY TRAP (sec F13).
--
-- `ENABLE ROW LEVEL SECURITY` already applies to non-owner roles, and
-- `epigraph_app` is a non-owner by construction. With ONLY a FOR SELECT policy,
-- PostgreSQL DEFAULT-DENIES INSERT and UPDATE — so
-- `AgentRepository::ensure_for_client`, called at all three token-mint sites,
-- is denied and `UPDATE oauth_clients SET agent_id` never runs. EVERY
-- AUTHENTICATION WOULD BREAK THE DAY 079 LANDS.
--
-- `oauth_clients` deliberately gets NO policy and is NOT in 079's array: it
-- carries neither `visibility` nor `owner_group_id`, and a policy on it would
-- make the mint's `UPDATE oauth_clients SET agent_id` match zero rows. That is
-- the other half of sec-F13.
-- ===================================================================
ALTER TABLE public.agents ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS agents_identity ON public.agents;
CREATE POLICY agents_identity ON public.agents FOR SELECT TO PUBLIC
    USING (true);
-- VISIBILITY-EXEMPT, stated as it actually is rather than as one call site
-- implies. `agents.id`/`display_name`/`public_key` must render authorship on
-- public claims, so the ROW is universally readable and PostgreSQL has no
-- column-level RLS to narrow it. The compensating projection —
-- `profile_visibility` gating `properties`, `orcid` and `ror_id` — is
-- implemented in EXACTLY ONE function, `agent.rs::get_public_profile`.
-- `AgentRepository::get_by_id`, `list`, `list_by_label`, `get_by_public_key` and
-- `find_by_role` take no `Viewer` and return the full row; `routes/agents.rs`'s
-- `list_agents` and `get_agent` reach `orcid`/`ror_id` through them regardless
-- of `profile_visibility`. `AgentResponse` does NOT serialize `properties`, so
-- `full_name`/`email`/`affiliations` do not escape over HTTP — the accepted
-- exposure is `orcid` and `ror_id`. Universalising the projection is a
-- public-API change and is deliberately not made inside an RLS migration;
-- recorded as `D-PR17-agent-projection-enforced-at-one-call-site`.

DROP POLICY IF EXISTS agents_provision ON public.agents;
CREATE POLICY agents_provision ON public.agents FOR INSERT TO PUBLIC
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        -- `derived` is the OAuth-principal namespace and, after
        -- `epigraph_provision_oauth_agent()` exists, the mint is its ONLY writer
        -- in the workspace. A forged `derived` row is the one an `ensure_for_client`
        -- would later ADOPT as a principal, so the app role is refused it.
        OR key_kind <> 'derived');
-- NOTE ON THE INVERSE, which is what review first proposed: narrowing this to
-- `key_kind = 'derived'` to stop the app role minting a real `ed25519` signer.
-- MEASURED: `agents.key_kind` DEFAULTs to `'ed25519'`, and the six live non-mint
-- writers — `AgentRepository::create`, reached from `routes/provenance.rs`,
-- `routes/conventions.rs` (three sites), `epigraph-mcp/src/server.rs` and
-- `novelty_gate.rs` — never name the column. That predicate refuses all of them.
-- Creating a signer row is an existing route-authorized capability, gated above
-- the database; RLS is not where it is narrowed. The `derived` namespace is.

-- The UPDATE half of correction (2)(a). `ensure_for_client`'s upsert takes the
-- DO UPDATE branch whenever the derived principal already exists — which is the
-- COMMON case, every re-mint after the first — and an `ON CONFLICT DO UPDATE`
-- is checked against the UPDATE policy's USING *and* WITH CHECK. At mint time
-- there is no principal, so `id = epigraph_principal_id()` is NULL and denies.
--
-- AN EARLIER DRAFT SOLVED THAT WITH A POLICY ARM AND THE ARM WAS WRONG:
-- `key_kind = 'derived' AND epigraph_principal_id() IS NULL`, justified as
-- "genuinely pre-authentication". The request path does not stamp the session
-- GUCs (`D-PR17-request-path-never-stamps-session-gucs`), so a NULL principal is
-- an app connection's STEADY state and the arm was live on every statement —
-- reaching `role` and `default_group_id` on any derived row, not just the
-- mint's own. It is deleted; the mint goes through
-- `epigraph_provision_oauth_agent()` and is admitted by DEFINER-BYPASS.
-- What remains is the property the arm only claimed to have: a session can
-- update ITSELF and nothing else.
DROP POLICY IF EXISTS agents_self_update ON public.agents;
CREATE POLICY agents_self_update ON public.agents FOR UPDATE TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR id = (SELECT public.epigraph_principal_id()))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR id = (SELECT public.epigraph_principal_id()));
-- No DELETE policy: agents are never deleted through the app role. Recorded as
-- a deliberate uncovered command in `rls_enforcement.rs`'s polcmd table.

-- ===================================================================
-- 10. jobs — anything that can INSERT a jobs row can dispatch work that later
-- runs with `epigraph_bypass()` TRUE (sec F5).
--
-- CORRECTION TO AN EARLIER DRAFT OF THIS COMMENT, which said "`PostgresJobQueue`'s
-- two `INSERT INTO jobs` statements run from the ordinary app role". THEY DO NOT.
-- `bin/server.rs` builds `job_pool` from `maintenance_url` via
-- `ScopedPool::connect_with_options`, and both `PostgresJobQueue::new` sites in
-- the workspace (the queue and the reaper) take it, so the queue runs as
-- `epigraph_maintenance`, for whom `epigraph_bypass()` is TRUE. The
-- `job_type NOT IN (…)` arm below is therefore FORWARD-STAGING for PR-18, not an
-- active control, and it is kept as such rather than deleted.
--
-- WHY THE CORRECTION MATTERS BEYOND THE COMMENT, and the general property:
-- `jobs_app`'s USING is bypass-only, so for a NON-bypass role every read of
-- `jobs` returns zero rows. `PostgresJobQueue::enqueue_unique_pending` guards
-- with `WHERE NOT EXISTS (SELECT 1 FROM jobs WHERE job_type = $2 AND state =
-- 'pending')`. AN RLS-FILTERED READ INSIDE A WRITE'S GUARD PREDICATE WIDENS THE
-- WRITE: the guard degrades from a dedup check to an unconditional insert, with
-- no error and no warning. MEASURED as `epigraph_app`: three successive "unique"
-- enqueues of one job_type produced three rows. This is the same mechanism as
-- the `ON CONFLICT`/USING interaction in correction (7), and the sweep for that
-- one did not cover it. `rls_enforcement.rs::guard_subquery_sites_are_enumerated`
-- records the enumeration of correlated `EXISTS`/`NOT EXISTS` guards over
-- protected tables together with the pool each runs on.
-- ===================================================================
ALTER TABLE public.jobs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jobs_app ON public.jobs;
CREATE POLICY jobs_app ON public.jobs FOR ALL TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass()))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        -- The app role may enqueue ordinary work, never privatization work.
        OR job_type NOT IN ('privatization_apply','privatization_revert',
                            'privatization_reseal'));
-- Reading the queue is a maintenance operation; the app enqueues, and polls
-- through repo functions that run on the maintenance pool after PR-15.

-- ===================================================================
-- 11. security_events — append-only from the app, self-readable.
--
-- The plan's `security_events_read` also ORs
-- `public.epigraph_is_instance_admin((SELECT epigraph_principal_id()))`. THE
-- FUNCTION DOES NOT EXIST — `instance_admins` is PR-18's migration 083 — so the
-- policy as written fails to create and aborts the migration. The disjunct is
-- dropped here and is PR-18's to add back alongside the function.
--
-- No UPDATE and no DELETE policy, so both are DEFAULT-DENIED. The plan puts an
-- immutability trigger "in 078"; under the README that is PR-18's 082, so
-- PR-17 delivers the default-deny half only.
-- ===================================================================
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS security_events_append ON public.security_events;
CREATE POLICY security_events_append ON public.security_events FOR INSERT TO PUBLIC
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        -- No principal to check against: admit, so a pre-authentication failure
        -- is still recorded. An actor must never be able to suppress its own
        -- audit record by failing a predicate.
        OR (SELECT public.epigraph_principal_id()) IS NULL
        -- An UNATTRIBUTED event is always writable, and this arm is not
        -- redundant with the one above it. `NULL IS NOT DISTINCT FROM <uuid>` is
        -- FALSE, so without this a session that HAS a principal is refused an
        -- `agent_id IS NULL` row — which is exactly what
        -- `oauth/providers/provision.rs::record_oauth_event` writes, hard-coded.
        -- Today that survives on the NULL-principal arm above; the moment the
        -- request path starts stamping GUCs it would not, and both call sites
        -- swallow the error, so the OAuth provisioning audit trail would go
        -- silently missing — the same failure this section removed a `RETURNING`
        -- to prevent. Permitting an unattributed row admits noise, never
        -- MISattribution, so the property below is unaffected.
        OR agent_id IS NULL
        -- A session that HAS a principal may only write events attributed to
        -- itself. `WITH CHECK (true)` argued anti-suppression correctly and then
        -- said nothing about ATTRIBUTION, so any session could forge an event
        -- naming another principal — permanently, since UPDATE and DELETE are
        -- default-denied.
        OR agent_id = (SELECT public.epigraph_principal_id()));
-- FULL attribution binding — refusing a NON-NULL `agent_id` from a session with
-- no principal — is deliberately NOT armed. It is unreachable-safe only once the
-- request path stamps the session GUCs, and until then it would refuse every
-- authenticated rate-limit event while both call sites swallow the error, i.e.
-- it would trade fail-open-on-attribution for a silently absent audit trail.
-- It rides the same `acquire_as` precondition 11d already depends on.
DROP POLICY IF EXISTS security_events_read ON public.security_events;
CREATE POLICY security_events_read ON public.security_events FOR SELECT TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR (SELECT public.epigraph_definer_bypass())
        OR agent_id = (SELECT public.epigraph_principal_id()));

-- ===================================================================
-- 12. THE TWO VIEWS — CLOSING AN OPEN RLS BYPASS.
--
-- `public.tenancy_exempt` records this obligation against PR-17 in the strongest
-- terms it had available: "relkind='v' with security_invoker UNSET: after
-- migration 079's FORCE it executes as the view OWNER and BYPASSES the
-- invoker's RLS … Migration 077 MUST set security_invoker=true on it or drop
-- it. THIS IS AN OPEN RLS BYPASS, RECORDED HERE SO PR-17 CANNOT MISS IT."
--
-- The plan's PR-17 section mentions neither view. `migrations/README.md` states
-- the general rule ("Any VIEW added in this range must set it") and
-- `tenancy_coverage.rs::the_two_view_exemptions_are_still_security_definer`
-- holds the assertion that this statement inverts — it is updated in the same
-- commit, as its own failure message demands.
--
-- Measured before: `reloptions` NULL on both; only
-- `ownership_key_id_quarantine` carried `security_invoker=true`.
-- ===================================================================
ALTER VIEW public.alternative_set SET (security_invoker = true);
ALTER VIEW public.alt_set_decisions SET (security_invoker = true);

UPDATE public.tenancy_exempt SET
    residual = 'CLOSED by migration 077: security_invoker=true, so the view '
               'executes as the INVOKER and the underlying edges/claims policies '
               'apply to it. The relation still carries no tenancy columns of its '
               'own, which is correct for a view.',
    reviewed_by = 'PR-17',
    reviewed_at = now()
 WHERE table_name IN ('alternative_set', 'alt_set_decisions');
