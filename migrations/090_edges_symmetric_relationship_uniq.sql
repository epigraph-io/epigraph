-- 090_edges_symmetric_relationship_uniq.sql
-- Back the symmetric-dedup guard in `EdgeRepository::create_symmetric_if_absent`
-- with a real UNIQUE index instead of a read that the writer might not be able
-- to perform.
--
-- Recorded as `D-PR17-read-guards-widen-under-rls` (COMPLETION-PLAN 2.2.1). This
-- is the FORCE-precondition batch's one migration; `migrations/README.md` is
-- updated in the same commit and 060-090 is now fully allocated.
--
-- ===================================================================
-- WHAT IT CLOSES, AND A CORRECTION TO WHAT THE OBLIGATION SAYS IT CLOSES
--
-- The obligation states the general mechanism: a `WHERE NOT EXISTS (SELECT 1
-- FROM t ...)` guard over an RLS-protected `t` returns nothing to a non-bypass
-- role, so the guard degrades from a dedup check into an unconditional insert.
--
-- MEASURED on this tree, that general statement does NOT hold for the two
-- `edges` write guards as written, and the reason is worth recording because it
-- is what makes this index narrow rather than broad:
--
--   * `edges_validate_refs` (`trigger_validate_edge_refs`, BEFORE INSERT, and
--     SECURITY INVOKER, so it IS RLS-filtered) refuses the insert outright when
--     the writing session cannot see BOTH endpoint rows. That is fail-CLOSED,
--     not a silent duplicate.
--   * When a session CAN see both endpoints, every branch of
--     `epigraph_edges_tenancy`'s stamp derives the edge's owner/co-owner from
--     those same endpoints, so a trigger-stamped edge between two visible
--     claims is itself visible to that session. The guard's subquery therefore
--     is not blind for any edge the trigger stamped.
--
-- TWO CASES SURVIVE, and they are what this index is for:
--
--   1. NON-ATOMICITY, which has nothing to do with RLS and is live today.
--      `NOT EXISTS` and the `INSERT` are one statement but not one lock: two
--      concurrent promote decisions over the same pair both observe an empty
--      guard and both insert. Nothing in the schema stops the second one.
--
--   2. AN EDGE WHOSE OWNERSHIP NO LONGER FOLLOWS ITS ENDPOINTS'. Migration
--      072 arm (d) carries a deliberate NO-WIDENING guard, so an edge stamped
--      ('group', G) KEEPS that stamp when its endpoints are later widened to
--      public. Both endpoints are then visible to everyone and the edge is
--      visible only to G. A writer outside G sees the endpoints, does not see
--      the edge, and the guard permits a second row for the same pair. Latent
--      until step 11d, because until then the application connects as a role no
--      policy applies to.
--
--      WHICH WRITERS REACH THAT STATE, MEASURED RATHER THAN ASSUMED. NOT the
--      privatization revert path, and an earlier draft of this header said
--      otherwise. `PrivatizationRepository::restore_claims_conn` is the only
--      caller of `SET LOCAL epigraph.allow_declassify = 'yes'` in the tree, and
--      `epigraph-jobs/src/privatization.rs` follows it with
--      `recompute_boundary_meet_conn` in the SAME transaction, precisely so
--      "an edge is never committed disagreeing with its endpoints" -- that
--      function exists because 072's trigger refuses to widen. So the reachable
--      writers are an operator-issued declassification that does not re-run the
--      boundary meet, and any future writer that widens claims without it. The
--      state is real -- `rls_enforcement.rs::symmetric_dedup_holds_when_the_existing_edge_is_invisible_to_the_writer`
--      plants it and asserts it as a PREMISE -- but it is not produced by the
--      one production surface that widens claims today.
--
--      CASE 1 STANDS ALONE. It is RLS-independent and live on today's corpus,
--      so this index does not depend on case 2 being common.
--
-- Neither case is a read leak; both are correctness degradations (a duplicate
-- edge), which is what the obligation says about this site set.
--
-- ===================================================================
-- INDEX SHAPE, AND WHAT IT FORBIDS
--
--   UNIQUE (LEAST(source_id,target_id), GREATEST(source_id,target_id),
--           relationship)
--   WHERE relationship IN ('CORROBORATES','contradicts')
--     AND source_type = 'claim' AND target_type = 'claim'
--     AND properties->>'source' = 'cross_source_matcher'
--     AND valid_to IS NULL
--
-- `relationship` IS IN THE KEY, deliberately. Dropping it would make
-- `edges` hold at most one edge per claim pair across all relationships, which
-- `edge_repo_tests.rs::create_symmetric_if_absent_distinguishes_by_relationship`
-- pins against: a pair may be both CORROBORATES-linked and contradicts-linked
-- by two different matcher runs, and those are different facts.
--
-- THE PREDICATE NAMES A CLOSED SET, because the domain on this path is closed.
-- `create_symmetric_if_absent` takes `relationship: &str`, but all four
-- production callers OF THE TWO FUNCTIONS -- three of
-- `create_symmetric_if_absent` and one of `create_symmetric_if_absent_returning`
-- -- pass a constant or a value bound from a three-variant
-- enum: `matching::policy::Policy::write_edge` passes
-- CORROBORATES_RELATIONSHIP / CONTRADICTS_RELATIONSHIP; the two decide-candidate
-- PROMOTE arms (`routes/cross_source.rs`, `tools/matching.rs`) pass
-- `PromotionDisposition::edge_relationship()`, which returns exactly those two
-- `&'static str` constants or None; `tools/link_alternative.rs` passes the
-- literal "alternative_of". The domain is {CORROBORATES, contradicts,
-- alternative_of}, and all three are semantically symmetric.
--
-- `alternative_of` IS DELIBERATELY ABSENT from this predicate. It already has
-- `edges_alternative_of_symmetric_uniq` (migration 042, narrowed by 091). A
-- second unique index over the same rows would add a redundant constraint and a
-- second name for one rule.
--
-- A BLANKET INDEX OVER ALL RELATIONSHIPS WOULD BE WRONG. `decomposes_to`,
-- `supersedes`, `variant_of` and most of the vocabulary are ASYMMETRIC: (a,b)
-- and (b,a) are different facts and both must be storable. Restricting the
-- predicate to the two symmetric relationships this path writes is what keeps
-- that true.
--
-- THE CLAIM-TYPE CONJUNCTS are the same narrowing argument one level down.
-- `create_symmetric_if_absent` hardcodes 'claim' for both endpoints. The
-- generic `POST /edges` path admits 'CORROBORATES' between other entity types,
-- where nothing has established that the relationship is symmetric.
--
-- THE `source` CONJUNCT IS THE SAME IDENTITY KEY THE SUBSYSTEM ALREADY USES,
-- not a new one. `MatchCandidateRepo::retire` finds the edges to retract with
-- exactly `((source_id,target_id) either way) AND properties->>'source' =
-- 'cross_source_matcher'` -- symmetric over the pair, deliberately NOT filtered
-- by relationship. This index is keyed the same way, and all three production
-- callers of `create_symmetric_if_absent` stamp that marker:
-- `matching/policy.rs::write_edge` and both decide-candidate PROMOTE arms.
--
-- A BROADER PREDICATE WAS WRITTEN FIRST AND REJECTED ON MEASUREMENT. Without
-- the `source` conjunct the index forbids ANY second in-force claim-claim
-- CORROBORATES or contradicts edge over a pair, whoever wrote it -- which is a
-- change to what the generic `POST /edges` path may do, in a batch whose scope
-- is FORCE preconditions. Two existing tests failed on it and both were right
-- to: `cross_source_route_tests.rs::retire_leaves_non_matcher_edges_between_the_same_pair_alone`
-- plants a `{"source":"human"}` edge beside a matcher one precisely to pin that
-- retire scopes on the marker rather than on the pair, and
-- `privatization_boundary.rs::the_omitted_edge_type_warning_names_only_what_was_left_untraversed`
-- seeds two operator-authored `contradicts` edges over one pair. Both pass
-- unmodified under the narrow predicate; NEITHER was edited.
--
-- There IS an argument for the broad version and it is recorded rather than
-- taken: `edges_auto_factor` materialises one factor per edge and BBAs are keyed
-- `perspective_id = edge_id`, so two in-force corroboration edges over one pair
-- double-count in belief propagation. That is a belief-graph correctness
-- question with its own owner, and settling it here would be a silent scope
-- expansion.
--
-- `valid_to IS NULL` IS REQUIRED, and 091 states the rule this file obeys:
-- "any uniqueness constraint over edges must exclude retracted rows or
-- retraction silently becomes a weaker operation than deletion." An index
-- predicate must be IMMUTABLE, so `EDGE_IN_FORCE`'s `valid_to > now()` arm
-- cannot appear here; `valid_to IS NULL` is the immutable subset, exactly as in
-- 091.
--
-- THE RESIDUAL THAT LEAVES IS REACHABLE, and is recorded so the next reader
-- does not have to re-derive it: a row with a FUTURE `valid_to` is in force per
-- `EDGE_IN_FORCE` and OUTSIDE this index, so the dedup repair does not cover it.
-- `EdgeRepository::update_valid_to_and_properties` takes a caller-supplied
-- timestamp and is exposed by `routes/edges.rs` and `tools/edge_mutation.rs`.
-- Accepted: the alternative is a mutable predicate, which Postgres does not
-- allow in an index at all.
--
-- ===================================================================
-- WHY THIS INDEX CANNOT REJECT A ROW THE GUARD WOULD HAVE ACCEPTED
--
-- `create_symmetric_if_absent`'s guard blocks the insert when ANY edge for the
-- pair with that relationship exists -- retracted or not, whatever its
-- endpoints' types, whoever wrote it. This index rejects only the subset of
-- those where the existing row is IN FORCE, both endpoints are claims, and the
-- row carries the matcher marker. The set of rows the index rejects is
-- therefore a strict subset of the set the guard already blocks, so on the path
-- the guard can see, behaviour is unchanged; on the path it cannot see, the
-- index supplies the answer the guard was supposed to give. Same containment
-- argument 091 made for itself, and it is what makes the recon brief's warning
-- -- that under FORCE an over-broad constraint's refusal is indistinguishable
-- from the guard working -- not reachable here: this index cannot refuse
-- anything the guard would have accepted.
--
-- The guard predicate is intentionally left WIDER than the index rather than
-- narrowed to match: narrowing it to `valid_to IS NULL` would change what
-- re-linking a retracted pair does, which is a production behaviour question no
-- obligation in this batch asks, and narrowing it to `EDGE_IN_FORCE` cannot be
-- mirrored in an index predicate at all.
--
-- CALLER CONTRACT. Both guarded statements gain `ON CONFLICT DO NOTHING` in the
-- same commit, so a conflict resolves to "already linked" (`Ok(false)`) rather
-- than to a 23505 the caller maps to a 500. Bare `DO NOTHING`, with no arbiter
-- inference: inference against a partial expression index requires the
-- `ON CONFLICT ... WHERE` clause to imply the index predicate exactly, and a
-- mismatch is a RUNTIME error from a `sqlx::query` that no compile step sees.
-- `DO NOTHING` swallows unique and exclusion violations only — 074's tenancy
-- RAISE, `edges_validate_refs` and every CHECK still propagate. This retires
-- `create_symmetric_if_absent`'s standing note that there is "no constraint to
-- infer on" because 017/018 dropped the unique triple index.
--
-- ===================================================================
-- DEPLOY PRECONDITION -- ANSWERED ON THE DAY, NOT ASSUMED HERE
--
-- `CREATE UNIQUE INDEX` FAILS if violating rows already exist, and a failed
-- migration panics the api binary on restart (migration 013's lesson, restated
-- by 091). Case 1 above means duplicates can have accumulated for the life of
-- the corpus. Before applying this file to any database that carries real data,
-- run the census and resolve what it returns -- this migration deliberately
-- does NOT retract or delete rows to make itself apply:
--
--   SELECT LEAST(source_id,target_id) AS a, GREATEST(source_id,target_id) AS b,
--          relationship, count(*)
--     FROM public.edges
--    WHERE relationship IN ('CORROBORATES','contradicts')
--      AND source_type = 'claim' AND target_type = 'claim'
--      AND properties->>'source' = 'cross_source_matcher'
--      AND valid_to IS NULL
--    GROUP BY 1,2,3
--   HAVING count(*) > 1;
--
-- Measured zero on the throwaway this batch was developed against. Production
-- is at migration 59 with the whole 060-091 series unapplied, so its answer is
-- one of the §2.4 deploy-day measurements and is not knowable from here.
--
-- Not CONCURRENTLY: sqlx wraps each migration in a transaction and
-- CREATE INDEX CONCURRENTLY cannot run inside one. Same reasoning as 091.
--
-- Idempotent: DROP INDEX IF EXISTS before CREATE, so a lock_timeout abort is
-- recoverable by re-running the file (sqlx records no row for a failed
-- migration).
--
-- OUT OF ORDER BY DESIGN. 091 already exists and is applied on development
-- databases. sqlx applies a lower version arriving later without complaint
-- (measured in PR-18a and re-verified for this file in both orders); 090 and
-- 091 touch different indexes and do not interact.

SET LOCAL lock_timeout = '3s';

DROP INDEX IF EXISTS edges_symmetric_relationship_uniq;

CREATE UNIQUE INDEX edges_symmetric_relationship_uniq
    ON public.edges USING btree (
        LEAST(source_id, target_id),
        GREATEST(source_id, target_id),
        relationship
    )
    WHERE ((relationship)::text IN ('CORROBORATES', 'contradicts')
           AND (source_type)::text = 'claim'
           AND (target_type)::text = 'claim'
           AND properties ->> 'source' = 'cross_source_matcher'
           AND valid_to IS NULL);

COMMENT ON INDEX public.edges_symmetric_relationship_uniq IS
  'Symmetric dedup for the matcher-written claim-claim edges in the two '
  'symmetric relationships EdgeRepository::create_symmetric_if_absent is called '
  'with. Backs the read guard in that function, which is not atomic and which '
  'cannot see an edge whose ownership no longer follows its endpoints. Keyed on '
  'the same (pair + properties->>''source'') identity MatchCandidateRepo::retire '
  'already uses, so an operator-authored edge over the same pair is unaffected. '
  'alternative_of is covered separately by edges_alternative_of_symmetric_uniq. '
  'Migration 090, D-PR17-read-guards-widen-under-rls.';
