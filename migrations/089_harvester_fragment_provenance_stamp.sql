-- 089_harvester_fragment_provenance_stamp.sql
-- Closes the harvester-fragment insert-order gap left open by migration 070.
--
-- NOT A PLAN SECTION. All 22 sections of docs/tenancy/FINAL-PLAN.md are
-- delivered; this file is a cleanup batch that closes one recorded finding.
-- migrations/README.md is authoritative for the number: 089 was headroom, is
-- claimed here, and 090 stays headroom. `epigraph-internal` shares this version
-- space, so the README row and this file land in the same commit.
--
-- 089 IS BELOW AN EXISTING HEAD (091). sqlx applies out of order and records
-- the row either way; both orders were exercised before this file was committed.
--
-- ===================================================================
-- WHAT WAS WRONG, AND WHY NO EXISTING ARM COVERED IT
--
-- `harvester_fragments` carries tenancy columns (062's tier_a includes it) but
-- has NO `claim_id`. It reaches a claim only through the join table
-- `harvester_claim_provenance(claim_id, fragment_id)`. Migration 070 says so in
-- its own comment above arm (c):
--
--     "harvester_fragments has no claim_id either -- it hangs off
--      harvester_claim_provenance; see arm (d) and the backfill's explicit arm
--      for it."
--
-- That leaves exactly one uncovered moment:
--
--   * arm (c) stamps on INSERT, but only for the 17 tables that HAVE a
--     `claim_id`. `harvester_fragments` is not one and cannot be one.
--   * arm (d) re-stamps on a `claims` UPDATE -- including, correctly, the
--     harvester fragments reachable through provenance. But it fires only when
--     a claim's tenancy actually CHANGES, which need never happen.
--   * 074 makes `harvester_fragments` a parentless ROOT: the writer must
--     declare both columns, or (under the seed escape hatch) the row is stamped
--     ('public', <seed group>).
--
-- So a fragment written BEFORE the provenance row that links it to its claim is
-- stamped by no trigger at all, and stays public for the lifetime of the row.
-- PR-12's backfill (`tenancy_backfill.rs::backfill_harvester_fragments`) closed
-- this for rows that existed when it ran; its own doc comment records that new
-- rows written in that order remain a live gap. This file closes that gap at the
-- moment the missing link appears.
--
-- `harvester_fragments.content_text` is chunked source text -- the same class of
-- claim-derived plaintext 070's own comment calls out for `evidence`, where a
-- draft that omitted the table "stamped evidence of a group-private claim as
-- world/public".
--
-- ===================================================================
-- COMPANION TO ARM (c), NOT A REPLACEMENT
--
-- `harvester_claim_provenance` HAS a `claim_id` and is in 070's inheritor list,
-- so it already carries `harvester_claim_provenance_inherit_tenancy`, which
-- stamps the provenance row's OWN tenancy from its claim. That trigger is
-- untouched and still required. This one stamps a DIFFERENT row -- the fragment
-- the provenance row points at -- from the same claim. Two AFTER INSERT
-- statement triggers on one table is supported and is what is intended here.
--
-- FIRING ORDER IS NOT LOAD-BEARING, AND THAT IS A PROPERTY OF THE BODY.
-- Postgres fires AFTER triggers in `tgname` order, so
-- `harvester_claim_provenance_fragment_inherit_tenancy` sorts BEFORE
-- `harvester_claim_provenance_inherit_tenancy` ('f' < 'i'). That is safe only
-- because the body below joins `public.claims` directly and never reads the
-- provenance row's own `owner_group_id` / `visibility`. A body that copied the
-- provenance row instead would make alphabetical trigger order a silent
-- correctness dependency on arm (c) having already run. Do not rewrite it that
-- way.
--
-- THE NAME ENDS `_inherit_tenancy` DELIBERATELY. Three census assertions and one
-- boot-time refusal select tenancy triggers by that suffix
-- (`tenancy_triggers.rs::every_tenancy_trigger_is_enabled`,
-- `locked_decisions.rs::d1_tenancy_stamping_triggers_are_armed`,
-- `tenancy_required.rs::a5_every_tenancy_trigger_is_enabled`, and
-- `AppState::assert_tenancy_triggers_armed`). A name outside the pattern would
-- compile, apply, and be invisible to every one of them -- a stamping trigger
-- that could be left DISABLED with nothing to say so. The two exact counts that
-- move (20 -> 21) are edited in this same commit WITH their reason, because
-- those assertions' own messages forbid a silent count edit.
--
-- ===================================================================
-- THE PREDICATE. FAIL-CLOSED HERE MEANS "STAMP THE UNSTAMPED, NEVER RE-STAMP
-- THE STAMPED", AND BOTH HALVES ARE LOAD-BEARING.
--
-- TARGET SIDE -- `f.owner_group_id IN (world, seed)`. Without it a later
-- provenance row could re-stamp an already-owned fragment to a DIFFERENT group,
-- which is a tenancy widening: the direction that leaks. The set is the two
-- sentinels, not one, and that is measured rather than assumed. The schema
-- itself defines "not a real owner" as exactly this pair -- 062 installs
--
--     CHECK (visibility <> 'group' OR owner_group_id NOT IN
--            ('00000000-0000-0000-0000-000000000000'::uuid,
--             '00000000-0000-0000-0000-00000000dead'::uuid))
--
-- on every tier-A table, because both groups are memberless by design and a
-- 'group'-visible row owned by either is unreadable by anybody. A fragment
-- owned by either therefore has no tenancy at all, and stamping it is not a
-- re-stamp.
--
-- WHY BOTH SENTINELS, AND THE ROLE PRECONDITION THAT MAKES THE SEED ONE
-- REACHABLE. The backfill's predicate (written before 074) names world alone.
-- Since 074, `harvester_fragments` is a ROOT armed by
-- `epigraph_root_require_tenancy()`, whose seed arm COALESCEs an undeclared
-- insert to ('public', '...0000dead') -- the SEED group, not world.
--
-- THAT ARM IS GATED ON THE CONNECTING ROLE, and saying so is the difference
-- between a measurement and a slogan. 074 reaches it only for a session where
-- `pg_has_role(session_user, 'epigraph_seed', 'MEMBER')` holds; otherwise it
-- RAISEs 23502 and nothing is written at all. A superuser satisfies pg_has_role
-- for every role, so the `#[sqlx::test]` harness takes the seed arm, and so does
-- a deployment that has not yet done plan 9.2's week-11d credential split.
-- Measured on a throwaway database at head, in rolled-back transactions: an
-- undeclared fragment insert lands ('public', seed) on such a session, and a
-- world-only predicate leaves it exactly there when its provenance row for a
-- group-private claim arrives.
--
-- So both sentinel spellings are named because both are REACHABLE -- not
-- because world is unreachable. On a seed-member session the undeclared case is
-- seed-stamped and a world-only predicate is a no-op for it; a writer that
-- declares ('public', world) explicitly produces the other spelling. A fix
-- matching one of the two would have read as if it had closed both.
--
-- AND THE SCOPE OF WHAT THE TARGET SIDE REACHES, STATED RATHER THAN IMPLIED.
-- The predicate matches only the two sentinel owners. Under 079's FORCE,
-- `harvester_fragments_tenancy`'s WITH CHECK admits a write naming a sentinel
-- owner only through a bypass disjunct, so the rows this trigger stamps are
-- those written by a bypassing or seed-member session and those already on disk.
-- An application-role writer must still declare the fragment's tenancy at its
-- own insert site; 089 does not relieve it of that, and `docs/tenancy.md` says
-- so in the same words. The residual coverage question is recorded as finding
-- F-089-C in docs/tenancy/progress.json with its location and its owner.
--
-- SOURCE SIDE -- `c.owner_group_id <> world`, unchanged from the backfill. A
-- claim owned by the world group is a shape constant, not an owner, and has no
-- tenancy to donate; copying it would be a write with no meaning. This clause is
-- NOT extended to the seed group, deliberately: a ('public', seed) claim
-- stamping a ('public', world) fragment to ('public', seed) is public-to-public,
-- changes no visibility, and -- because the target side treats seed as still
-- unstamped -- costs the fragment no later opportunity to inherit a real group.
-- Adding the clause would be narrowing logic this batch was told not to invent.
--
-- `IS DISTINCT FROM` is the idempotence guard every other arm of 070 carries,
-- for 070's stated reason: idempotence is what makes a kill -9 recoverable.
--
-- NO ROW_COUNT GUARD, MATCHING 070. Arm (d)'s FOREACH loop over the 17 derived
-- tables checks `GET DIAGNOSTICS actual = ROW_COUNT` against an expected count;
-- the `harvester_fragments` UPDATE that immediately follows that loop does not.
-- This file follows the precedent set for this table. There is also no expected
-- count to check it against: a provenance insert for an already-owned fragment,
-- or for a public claim, legitimately stamps zero rows. See "WHAT THE OWNERSHIP
-- ACTUALLY BUYS" below for why an instrument that tried to tell those apart from
-- a real shortfall would be blind to the shortfall.
--
-- NO `epigraph_definer_bypass()` ASSERTION, FOR ARM (c)'s REASON AND NOT BY
-- OVERSIGHT. Arm (d) asserts it because it fires only on maintenance-driven
-- UPDATEs of `claims`. This trigger, like arm (c), fires on ORDINARY APPLICATION
-- INSERTS -- every harvest that records provenance. A 42501 raised here would
-- convert a stamping shortfall into a total write outage on the harvest path.
-- The ownership is still required and is still asserted, but from the catalog by
-- `tenancy_triggers.rs::propagation_function_is_owned_by_the_maintenance_role`
-- and by `epigraph-tenancy-backfill verify`, where an operator can act on it.
--
-- WHAT THE OWNERSHIP ACTUALLY BUYS. MEASURED OUT OF BAND, BECAUSE THE SUITE
-- CANNOT ASK. 079 FORCEs row security on `harvester_fragments`, and
-- `harvester_fragments_tenancy` admits a write only through `epigraph_bypass()`,
-- `epigraph_definer_bypass()`, or `owner_group_id = ANY(
-- epigraph_writable_groups())`. `epigraph_bypass()` reads `session_user`, which
-- in every `#[sqlx::test]` is the superuser, so the policy is never the binding
-- constraint in CI -- the pre-existing finding
-- `F-PR12-ci-runs-as-superuser-so-the-42501-arm-is-untestable` is about exactly
-- this. So the enforced path was exercised on a scratch database by connecting
-- as a genuine non-bypassing application role, and the result is NOT the tidy
-- one an earlier draft of this comment asserted:
--
--   * owned by `epigraph_maintenance`: the link is stamped;
--   * owned by a role that is NOT a member of `epigraph_maintenance`: a link to
--     a claim the writing session can ALREADY see is still stamped, because the
--     WITH CHECK's writable-group disjunct is satisfied by the session's own
--     `epigraph.writable_group_ids`. The write is not filtered;
--   * owned by that same non-member role, but a link to a claim the writing
--     session cannot see: the body's read of `public.claims` is itself
--     RLS-filtered, so the join matches nothing and the UPDATE affects zero rows
--     with no error raised.
--
-- The ownership is therefore load-bearing for COVERAGE -- it is what lets this
-- trigger stamp a link whose claim the writer cannot read -- and NOT for
-- "otherwise it fails loudly". Ownership is asserted from the catalog for that
-- reason, and a non-member owner is a deploy defect rather than a no-op.
--
-- AND THAT IS WHY THERE IS NO ROW_COUNT INSTRUMENT HERE. An instrument would
-- have to ask "did a stampable candidate exist?", and the only way to ask is the
-- same join on `public.claims` the UPDATE just made -- filtered identically. An
-- in-trigger counter is therefore blind to precisely the state it would report,
-- and a counter keyed on the target side alone would fire on every legitimate
-- public-claim link. The catalog assertions and `verify` are the honest
-- instruments; a blind one in the write path would be worse than none.
--
-- ===================================================================
-- NO RE-GRANT IS NEEDED, AND 070's NOTE IS DISCHARGED HERE.
--
-- 070 ends its privilege block with: "NOTE FOR A LATER MIGRATION: `ON ALL TABLES
-- IN SCHEMA public` binds the tables that exist NOW. A migration that adds a
-- tier-A table must re-issue this grant." This file adds NO table.
-- `harvester_fragments` and `harvester_claim_provenance` both date from
-- `001_initial_schema.sql`, so both were already inside 070's grant when it ran.
-- Stated rather than left silent, so a reader does not have to re-derive it.
--
-- ===================================================================
-- WHAT THIS FILE DOES NOT DO.
--
-- A fragment may be cited by more than one claim. The selection rule among
-- equally-valid candidates is unresolved, is pre-existing, and is NOT decided
-- here: choosing one would be a design decision rather than a bug fix, and it
-- would also change what the backfill did to rows that already exist. It is
-- recorded as finding F-089-A in docs/tenancy/progress.json with its location
-- and its owner.
--
-- IT FIRES ON INSERT ONLY. An UPDATE that re-points an existing provenance row's
-- `fragment_id` or `claim_id` runs no stamping trigger: there is no AFTER UPDATE
-- arm here, and arm (d) fires only on a `claims` UPDATE that actually changes
-- tenancy. 070's arm (c) is INSERT-only for all 17 of its tables for the same
-- reason, so this is the established shape rather than an omission -- but it is
-- an ASSUMPTION about writers, not an enforced property. Widening the event list
-- in place is not available: PostgreSQL forbids `REFERENCING NEW TABLE` on a
-- trigger defined for more than one event, so covering it needs a SECOND trigger
-- and moves four pinned trigger counts. Recorded as finding F-089-E.
--
-- IT COPIES TENANCY FROM A CLAIM THE WRITER NAMED. The body joins `public.claims`
-- on `n.claim_id` and does not constrain which claims a writer may cite. What
-- follows from that is recorded as finding F-089-F with its location and owner.
-- The no-widening property is unaffected and is measured separately: 062's
-- visibility CHECKs restrict both tables to exactly {public, group} and
-- `harvester_fragments_group_needs_real_group` makes a sentinel-owned fragment
-- necessarily public, so a stamp can only move a fragment public->public or
-- public->group. There is no path by which it becomes MORE readable.
--
-- NO UNDO RUNBOOK SHIPS FOR IT, DELIBERATELY. 070, 074, 079 and 084 each ship one
-- under docs/runbooks/ because each is a multi-object or destructive change.
-- Reversing this file is `DROP TRIGGER IF EXISTS
-- harvester_claim_provenance_fragment_inherit_tenancy ON
-- public.harvester_claim_provenance;` plus `DROP FUNCTION IF EXISTS
-- public.epigraph_inherit_fragment_tenancy_stmt();`, and the rows it stamped are
-- deliberately NOT un-stamped -- `docs/runbooks/070-undo.sql` takes the same
-- stance for the same reason. `migrations/README.md`'s 089 row records that
-- decision so it is not inferred from the absence of a file.
--
-- Idempotent (CREATE OR REPLACE FUNCTION; DROP TRIGGER IF EXISTS before CREATE
-- TRIGGER), because sqlx records no row for a failed migration and a re-run must
-- be safe.
-- ===================================================================
SET LOCAL lock_timeout = '3s';

CREATE OR REPLACE FUNCTION public.epigraph_inherit_fragment_tenancy_stmt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    -- The transition table is named `newprov`, NOT `newrows`. Each trigger gets
    -- its own tuplestore so a collision with arm (c)'s `newrows` on the same
    -- statement would be harmless -- but it would read as a bug to anyone
    -- checking whether the two triggers can see each other's rows.
    UPDATE public.harvester_fragments f
       SET owner_group_id = c.owner_group_id,
           visibility     = c.visibility
      FROM newprov n
      JOIN public.claims c ON c.id = n.claim_id
     WHERE f.id = n.fragment_id
       AND f.owner_group_id IN (
             '00000000-0000-0000-0000-000000000000'::uuid,
             '00000000-0000-0000-0000-00000000dead'::uuid)
       AND c.owner_group_id <> '00000000-0000-0000-0000-000000000000'::uuid
       AND (f.owner_group_id, f.visibility)
           IS DISTINCT FROM (c.owner_group_id, c.visibility);
    RETURN NULL;
END $$;

-- REQUIRED, because a FIRST creation leaves `proacl` NULL and a NULL proacl MEANS
-- implicit EXECUTE to PUBLIC. 070 does the same on each of its bodies.
--
-- IT IS NOT NEEDED AGAINST A RE-RUN OF THIS FILE, and the reason matters because
-- an earlier draft of this comment (and 086's, inherited) had it backwards.
-- MEASURED on PostgreSQL 16.13 in a rolled-back transaction: CREATE ->
-- proacl NULL, PUBLIC holds EXECUTE; REVOKE -> {epigraph=X/epigraph}, PUBLIC
-- does not; CREATE OR REPLACE of the same signature -> the SAME acl, PUBLIC
-- still does not. Replacement PRESERVES the ACL. What does reset it is DROP
-- FUNCTION followed by CREATE: proacl returns to NULL and the PUBLIC grant comes
-- back silently. That is the hazard `schema_contract.rs::
-- migration_089_stamping_definer_is_revoked_from_public`'s `proacl IS NOT NULL`
-- pin exists to catch, and it is a hazard a LATER migration creates, not this one.
REVOKE EXECUTE ON FUNCTION public.epigraph_inherit_fragment_tenancy_stmt() FROM PUBLIC;

DROP TRIGGER IF EXISTS harvester_claim_provenance_fragment_inherit_tenancy
    ON public.harvester_claim_provenance;
CREATE TRIGGER harvester_claim_provenance_fragment_inherit_tenancy
    AFTER INSERT ON public.harvester_claim_provenance
    REFERENCING NEW TABLE AS newprov
    FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_inherit_fragment_tenancy_stmt();

-- Re-own to epigraph_maintenance, guarded on the role's existence exactly the
-- way 070 and 074 guard theirs. Migration 060 creates the role inside a DO block
-- that only RAISE NOTICEs on insufficient_privilege, so the role is not
-- guaranteed, and a hard failure here would turn a missing role into a permanent
-- deploy outage: a failed migration records no row, so the next restart re-runs
-- the file. The check therefore lives where an operator can act on it --
-- `epigraph-tenancy-backfill verify`, which carries this function in its
-- DEFERRED list because 089 is later than the migrations the week-11c pre-flight
-- applies.
--
-- WHICH BRANCH OF `verify` CATCHES WHICH STATE, because the two are different and
-- an earlier draft of this comment conflated them. On the cluster this guard
-- exists for -- 060 could only RAISE NOTICE, so the role is ABSENT -- `verify`
-- reports it at its role-existence branch, which returns BEFORE the per-function
-- loop and says so. The per-function check is `pg_has_role(owner,
-- 'epigraph_maintenance', 'MEMBER')`, deliberately not string equality, so it
-- catches an owner that is not a MEMBER: an operator re-own, a restore, a
-- migration runner that is neither a superuser nor a member. A superuser-owned
-- body PASSES it, which is correct -- it satisfies `epigraph_definer_bypass()`
-- and bypasses row security outright, so the stamp is not degraded. `schema_
-- contract.rs::migration_089_stamping_definer_is_revoked_from_public` pins the
-- owner by string equality instead, and that divergence is intended: that test
-- pins what THIS FILE installs, `verify` gates what a DEPLOY tolerates.
--
-- CREATE OR REPLACE preserves ownership, so a re-run of this file is a no-op.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        EXECUTE 'ALTER FUNCTION public.epigraph_inherit_fragment_tenancy_stmt() '
                'OWNER TO epigraph_maintenance';
    END IF;
END $$;
