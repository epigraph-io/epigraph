-- 094_definer_bodies_fail_closed.sql
-- Make the two tenancy definer bodies whose correctness rests on their OWNER
-- refuse to answer when `epigraph_definer_bypass()` does not admit their frame,
-- instead of answering from a policy-filtered read.
--
-- Deferred-commitment screen key `definer-authority-degrade-fail-open`. Claimed
-- from the reserved tenancy block 092-099 in `migrations/README.md`, in the SAME
-- commit, as 093 was. 086 and 092 are APPLIED and therefore FROZEN, so the
-- bodies are replaced here and the corrections to their headers live in this
-- one. `lock_timeout` mirrors 086.
--
-- Kept at mechanism level, as 086's and 092's headers are: this repository is
-- public.
--
-- ===================================================================
-- 1. THE RESIDUAL, AND WHY THE CONTROL CITED FOR IT NEVER RAN
--
-- Both bodies read a FORCEd table. What admits the read is the table policy's
-- `OR (SELECT public.epigraph_definer_bypass())` disjunct, and that function
-- (067) is `pg_has_role(current_user, 'epigraph_maintenance', 'MEMBER')`, where
-- `current_user` inside a SECURITY DEFINER frame is the FUNCTION OWNER. 086 and
-- 092 each set that owner with an `ALTER FUNCTION ... OWNER TO` inside an
-- `IF EXISTS (pg_roles)` guard, which silently no-ops on the cluster 060 could
-- only `RAISE NOTICE` on. An operator re-own or a restore reaches the same
-- catalog state.
--
-- The residual was ACCEPTED as "instrumented by verify's
-- DEFERRED_DEFINER_FUNCTIONS pre-flight (plan 9.2 step 11c)". That instrument
-- skips each entry while its function is absent from `pg_proc`, and still exits
-- 0. Every documented `verify` run (11c, and the two in `docs/deploy.md`, before
-- 074 and before 084) happens BEFORE 086, 089 and 092 exist. No documented step,
-- CI job or boot check re-runs it afterwards. So the control the acceptance
-- rested on never checked these functions under the procedure it cited. This
-- file removes the dependency on it rather than relying on an operator to
-- notice a stderr NOTE.
--
-- ===================================================================
-- 2. WHAT A DEGRADED FRAME ACTUALLY DID, MEASURED BEFORE THIS FILE
--
-- Measured on a clone of the lane database at head 100 + 093, with each body
-- re-owned to `epigraph_app` (not a member of `epigraph_maintenance`) and its
-- grants intact. The acceptance tests are in
-- `crates/epigraph-db/tests/rls_enforcement.rs`, and both FAIL without this
-- file on their `epigraph_app` arms:
--
--   * `epigraph_claim_tenancy_by_ids` (086) -- FAIL-OPEN ON THE APP ROLE, as
--     086 recorded. On an `epigraph_app` session the frame reads `claims` under
--     `claims_tenancy` with neither bypass arm true, so a group-private row
--     vanishes from BOTH arms of each set difference at once.
--     `ClaimRepository::hidden_claim_ids` returned `Ok({})`, and its callers read
--     that as "nothing is hidden". `EventRepository::list` returned the event
--     naming the private claim to a stranger. No error was raised.
--     NOT on a superuser or maintenance-member session. The frame fixes
--     `current_user` to the owner, but `claims_tenancy` also admits through
--     `(SELECT epigraph_bypass())`, which reads `session_user`, and a superuser
--     is a member of every role. There the frame's read was COMPLETE and the
--     classification CORRECT. Re-measured on a template clone of the lane
--     database with 086's own `LANGUAGE sql` body re-owned to `epigraph_app`:
--     five group-private ids in, five rows out as the superuser and under
--     `SET SESSION AUTHORIZATION epigraph_maintenance`, zero rows out under
--     `SET SESSION AUTHORIZATION epigraph_app`. This agrees with PR-24's record
--     that the superuser harness returned identical answers before and after
--     086 (`docs/tenancy/progress.json`).
--     (`a_tenancy_read_definer_whose_owner_is_not_admitted_refuses_to_classify`)
--
--   * `epigraph_group_roster_admits_principal` (092) -- NOT the silent revert
--     that 092 section 5, `tenancy_backfill.rs` and `schema_contract.rs` all
--     predicted. 092 section 6 says the definer frame is what stops
--     `group_memberships_tenancy` -> `epigraph_is_group_creator` -> this
--     predicate from recursing. With the frame unadmitted, every roster row
--     other than the principal's own re-enters the predicate, until PostgreSQL
--     raises `54001 stack depth limit exceeded`. On an `epigraph_app` session,
--     a creator removed from a group that still has other members got that
--     ERROR, not an admit. A LIVE creator got it too whenever another member's
--     row was scanned first. Group creation (an empty roster) still succeeded.
--     Only such a session reaches the creator arm at all: a superuser skips row
--     security, and a maintenance member is admitted by the policies'
--     `epigraph_bypass()` arm first. So the residual was
--     FAIL-ERRATIC, and nothing designed was stopping the `NOT EXISTS` from
--     admitting. An unplanned recursion was, and any edit to 077's policy
--     shape could remove it.
--     (`a_roster_predicate_whose_owner_is_not_admitted_answers_false`)
--
-- ===================================================================
-- 3. THE GUARD, AND EXACTLY WHAT IT TESTS
--
-- Each body now opens with `IF NOT public.epigraph_definer_bypass()`. Inside the
-- frame that asks the one question the body's correctness depends on: "is my
-- owner a member of epigraph_maintenance?" This is the same predicate
-- `tenancy_backfill.rs::verify_definer_ownership` applies, so the runtime guard
-- and the deploy gate cannot disagree. Consequences, stated rather than left to
-- be discovered:
--
--   * A SUPERUSER owner passes when the role exists (a superuser is a member of
--     every role) and is correct, since it bypasses row security anyway.
--   * A MISSING `epigraph_maintenance` role fails the guard even for a
--     superuser owner, because 067 returns FALSE rather than calling
--     `pg_has_role` on an absent role. `verify` already reports that state as
--     a FAIL, and 086's own COMMENT states the invariant ("Owner must satisfy
--     epigraph_definer_bypass()"), so the guard enforces what was documented
--     and not the incidental ways a frame might happen to read unfiltered.
--   * An owner lacking EXECUTE on `epigraph_definer_bypass()` gets `42501`
--     from the call itself. That fails closed too, with a less specific
--     message.
--
-- ===================================================================
-- 4. EACH BODY FAILS TOWARD ITS OWN "DENY", AND THE PRICE OF EACH
--
-- `epigraph_claim_tenancy_by_ids` RAISES `42501`. It returns rows, so it has no
-- value that means "deny". Returning nothing is the collapse in section 2.
-- Returning every id as private would drop every event naming any uuid, with a
-- 200 and no error. Every caller already maps an error to a refusal:
-- `routes/webhooks.rs::agent_may_receive` suppresses the delivery, and
-- `routes/events.rs` (both halves), `graph_snapshot` and MCP `list_events` fail
-- the request. THE PRICE: while the owner is wrong, those surfaces are DOWN,
-- not leaking. `EventRepository::list` calls the function inline once per
-- payload uuid, so one call raising fails the whole page. Every event page
-- carrying a uuid fails, not just the affected event. This is the same outage
-- 086 already accepted for a missing `GRANT EXECUTE`. The message names the
-- function, the current owner and the fix.
--
-- `epigraph_group_roster_admits_principal` RETURNS FALSE without reading. It
-- is a boolean policy predicate, and false is its deny. That is the direction
-- 092 section 5 says every sibling body (`epigraph_is_group_creator` and the
-- rest, which ask `EXISTS`) already fails in. It does not raise. Its call
-- sites are policy clauses, where a raise would fail every statement that
-- touches `groups` while the principal is NULL (`NULL AND f(x)` still
-- evaluates `f(x)`). That is far wider than the one arm this predicate bounds.
-- THE PRICE is group creation. The bootstrap is this predicate, so while the
-- owner is wrong `GroupRepository::create_with_admin`'s
-- `INSERT INTO groups ... RETURNING` is refused by `groups_tenancy` (42501),
-- where before this file it succeeded. A creator reading a group outside
-- `epigraph_session_groups()` through the creator arm alone is also denied.
-- Commit db2ac67b declined this trade-off, to avoid "a group-creation outage on
-- the very cluster the guard exists for". Section 2's measurement changes the
-- basis for that. The alternative was not a working cluster but an erratic
-- one: its removed and live creators already failed with 54001, and its
-- `NOT EXISTS` was one policy edit away from admitting. This choice is recorded
-- as an explicit decision in `docs/tenancy/progress.json`
-- (`decisions_taken.definer_bodies_fail_closed_2026_09_22`), not left as an
-- override of the earlier one.
--
-- ===================================================================
-- 5. WHAT THIS DOES NOT CHANGE
--
-- * No policy. No `CREATE`/`ALTER`/`DROP POLICY`, no `ROW LEVEL SECURITY`, no
--   `ALTER TABLE`. What the three 092 policies and `claims_tenancy` ADMIT is
--   unchanged whenever the owner is admitted, which is every correctly migrated
--   database. Asserted from this file's source by
--   `locked_decisions.rs::d4_migration_094_installs_no_policy`.
-- * No signature or return type. `CREATE OR REPLACE` cannot change either, and
--   `hidden_claim_ids`, `EventRepository::list` and the policies call both
--   functions exactly as before. `LANGUAGE sql` becomes `plpgsql` only so the
--   guard can run before the read. Both stay `STABLE SECURITY DEFINER` with
--   `search_path = public, pg_temp`, and plpgsql STABLE reads the calling
--   statement's snapshot as a SQL STABLE body does. That is what 092 section 4's
--   `INSERT ... RETURNING` argument depends on, and it is re-asserted by
--   `rls_enforcement.rs::the_three_statement_bootstrap_still_succeeds_under_the_roster_bound_arm`.
-- * Every column the plpgsql body names is qualified (`c.id`, `m.group_id`),
--   so `RETURNS TABLE`'s OUT variables (`id`, `visibility`, `owner_group_id`)
--   cannot shadow a column.
-- * `epigraph_is_instance_admin` (083) and `epigraph_inherit_fragment_tenancy_stmt`
--   (089) are not touched. Their bodies ask `EXISTS` / join through the
--   filtered table, so a degraded frame answers "no" / stamps less. Those are
--   the fail-safe and coverage directions, and `verify` still reports them.
--   `epigraph_is_group_creator` and the other 077 helpers are not touched,
--   for the same reason.
--
-- UNDO. No runbook ships, on the same ground as 089, 090, 092 and 093:
-- reversing this file is `CREATE OR REPLACE FUNCTION` of the two bodies back to
-- 086's and 092's text (both `LANGUAGE sql`, quoted in those files). It creates
-- no rows. **Applied to the lane throwaway database only, NOT to any deployed
-- database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

-- 086's read helper. Body unchanged below the guard: 086's SELECT, verbatim.
CREATE OR REPLACE FUNCTION public.epigraph_claim_tenancy_by_ids(p_ids uuid[])
RETURNS TABLE (id uuid, visibility text, owner_group_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    IF NOT public.epigraph_definer_bypass() THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = format(
                'epigraph_claim_tenancy_by_ids: refusing to classify claim ids: this '
                'SECURITY DEFINER frame runs as %I, which is not a member of '
                'epigraph_maintenance, so its read of claims would be filtered by '
                'claims_tenancy and would report nothing hidden', current_user),
            HINT = 'Re-own it: ALTER FUNCTION public.epigraph_claim_tenancy_by_ids(uuid[]) '
                   'OWNER TO epigraph_maintenance; then run epigraph-tenancy-backfill '
                   'verify. See migrations 086 and 094.';
    END IF;
    RETURN QUERY
        SELECT c.id, c.visibility::text, c.owner_group_id
          FROM public.claims c
         WHERE c.id = ANY(p_ids);
END
$$;

COMMENT ON FUNCTION public.epigraph_claim_tenancy_by_ids(uuid[]) IS
    'Tenancy label (id, visibility, owner_group_id) for caller-named claim ids. '
    'Never content. Backs ClaimRepository::hidden_claim_ids and '
    'EventRepository::list. Owner must satisfy epigraph_definer_bypass(); since '
    'migration 094 the body RAISES 42501 when it does not, rather than answering '
    'from a policy-filtered read. See migrations 086 and 094.';

-- 092's roster predicate. Body unchanged below the guard: 092's two
-- disjuncts, verbatim.
CREATE OR REPLACE FUNCTION public.epigraph_group_roster_admits_principal(p_group uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
BEGIN
    -- An unadmitted frame reads group_memberships under its own policy, and
    -- the first disjunct below is a NOT EXISTS: an incomplete read would
    -- ADMIT. Answer FALSE instead, without reading. See 094 section 4.
    IF NOT public.epigraph_definer_bypass() THEN
        RETURN false;
    END IF;
    RETURN NOT EXISTS (
             SELECT 1 FROM public.group_memberships m WHERE m.group_id = p_group)
        OR EXISTS (
             SELECT 1 FROM public.group_memberships m
              WHERE m.group_id = p_group
                AND m.agent_id = public.epigraph_principal_id()
                AND m.revoked_at IS NULL);
END
$$;

-- Ownership and grants, re-issued exactly as 086 and 092 issue them.
-- `CREATE OR REPLACE` preserves both (measured on 16.13, see
-- `schema_contract.rs`), so on a correctly migrated database these are no-ops.
-- They are repeated because the REVOKE is what keeps the bodies off PUBLIC, and
-- this file must stay correct against a database where an earlier guarded block
-- took the no-role branch.
REVOKE EXECUTE ON FUNCTION public.epigraph_claim_tenancy_by_ids(uuid[]) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.epigraph_group_roster_admits_principal(uuid) FROM PUBLIC;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_claim_tenancy_by_ids(uuid[]) '
                'OWNER TO epigraph_maintenance';
        EXECUTE 'ALTER FUNCTION '
                'public.epigraph_group_roster_admits_principal(uuid) '
                'OWNER TO epigraph_maintenance';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_app') THEN
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_claim_tenancy_by_ids(uuid[]) TO epigraph_app';
        EXECUTE 'GRANT EXECUTE ON FUNCTION '
                'public.epigraph_group_roster_admits_principal(uuid) '
                'TO epigraph_app';
    END IF;
END $$;
