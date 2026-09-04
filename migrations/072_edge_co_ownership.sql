-- 072_edge_co_ownership.sql -- making the endpoint meet EXPRESSIBLE (transactional)
-- PR-13 of the multi-user tenancy series.
--
-- NUMBERING. Plan §3 calls this file "068" and its §3.1 reservation table calls
-- it "069 (planned 068)". Both are pre-shift text. migrations/README.md is
-- authoritative and pins PR-13 at 072 (this file, transactional) and 073 (the
-- index, `-- no-transaction`).
--
-- WHICH FILE HOLDS THE ARMS. The plan's *Files* line says this migration
-- CREATE OR REPLACEs "066(b) and 066(d)"; its §3.1 row says "067(b)/(d)". Both
-- are wrong in this tree: 066 is PR-04's idx_claims_world_owned and 067 is the
-- session functions. **Both arms live in migrations/070_tenancy_triggers.sql**
-- (`epigraph_edges_tenancy()` and `epigraph_propagate_tenancy()`), and the
-- bodies below are 070's bodies plus co-ownership -- NOT the plan's printed
-- SQL, which drops two guards PR-12 added against measured leaks. See the
-- "GUARDS KEPT" note on each function.
--
-- WHY THIS FILE EXISTS. `edges.owner_group_id` is a single uuid. It can express
-- both-endpoints-public, one-public-one-in-G, and both-in-G -- but NOT
-- endpoints in different groups G and H. 070 arm (b) resolves that at write
-- time by RAISING, and arm (d) resolves it by leaving the edge unchanged.
-- Neither is tenable once 071's transcription makes two claims genuinely
-- ('group', G) with different owners:
--   * arm (b)'s RAISE hard-fails every cross-owner link_epistemic /
--     link_hierarchical / decomposition write (070:213-217 says so, and says
--     THIS migration closes the window);
--   * privatization CANNOT raise -- the edge already exists, and refusing to
--     privatize because of it would let any writer veto privatization by
--     planting one edge. Silently picking G grants G read access to an edge
--     whose other endpoint is H's; silently deleting it destroys corpus data.
-- A second owning group is the only resolution that neither leaks nor vetoes.
--
-- READ SEMANTICS ARE AN INTERSECTION, NOT A UNION. A co-owned edge is visible
-- only to a principal in BOTH groups -- see `Viewer::edge_predicate_fragment`
-- in crates/epigraph-db/src/visibility.rs, whose Scoped arm is:
--
--     AND (e.visibility = 'public'
--          OR (e.owner_group_id = ANY($V::uuid[])
--              AND (e.co_owner_group_id IS NULL
--                   OR e.co_owner_group_id = ANY($V::uuid[]))))
--
-- PRE-STAGED FOR MIGRATION 077 (PR-17), NOT FOR THIS FILE. The plan's *Files*
-- line says "the `edges_tenancy` policy clause pre-staged for 073". That is a
-- number collision: README pins 073 as PR-13's index-only `-- no-transaction`
-- file and 077 as PR-17's RLS policies. Read literally the plan would put a
-- CREATE POLICY in the index migration. No policy is created here or in 073.
-- The clause 077 must carry is the fragment above with
-- `(SELECT public.epigraph_session_groups())` in place of `$V`:
--
--     CREATE POLICY edges_tenancy ON public.edges FOR ALL TO PUBLIC
--         USING ((SELECT public.epigraph_bypass())
--                OR visibility = 'public'
--                OR (owner_group_id = ANY ((SELECT public.epigraph_session_groups()))
--                    AND (co_owner_group_id IS NULL
--                         OR co_owner_group_id
--                            = ANY ((SELECT public.epigraph_session_groups())))))
--         WITH CHECK ((SELECT public.epigraph_bypass())
--                     OR owner_group_id
--                        = ANY ((SELECT public.epigraph_writable_groups())));
--
-- It is written here, next to the column, so PR-17 cannot re-derive a
-- non-matching clause: qual/GUC coherence (plan §4.5) requires the policy's
-- USING to be a syntactic match for the app-emitted qual, and
-- crates/epigraph-db/tests/qual_guc_coherence.rs is the file that will check it.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS, catalog-guarded ADD CONSTRAINT,
-- CREATE OR REPLACE FUNCTION. `crates/epigraph-db/tests/tenancy_coverage.rs::
-- migration_072_applies_twice` runs the file twice against a live database.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- 1. THE COLUMN AND ITS CONSTRAINTS.
--
-- NULL = single-owner, which is the common case and stays free: no index entry
-- (073's index is partial), no extra predicate work (the fragment's
-- `co_owner_group_id IS NULL` disjunct short-circuits).
--
-- BOTH CONSTRAINTS SHIP `NOT VALID`, deliberately. NOT VALID skips only the
-- backfill scan of existing rows; NEW WRITES ARE ENFORCED FROM THIS MIGRATION
-- ON. Validation is PR-16's 075/076 -- `progress.json` assigns every
-- VALIDATE CONSTRAINT there and `locked_decisions.rs` pins that split.
--
-- CONRELID-QUALIFIED catalog guards, for 062's stated reason:
-- pg_constraint.conname is unique per RELATION, not per database, so a bare
-- `WHERE conname = ...` is satisfied by a same-named constraint on any other
-- table and this migration would silently skip creating the real one.
--
-- edges_co_owner_shape PERMITS THE WORLD/DEAD SENTINELS, and that asymmetry
-- with 062's edges_group_needs_real_group (which excludes them for
-- owner_group_id) IS DELIBERATE. This CHECK is on the arm (d) path: arm (d) is
-- a statement-level AFTER UPDATE on `claims` that fires on EVERY claims
-- UPDATE, so a CHECK violation raised from it is a TOTAL WRITE OUTAGE, not a
-- rejected row. Every extra conjunct here is an outage vector. The stamping
-- arms below never write a sentinel into co_owner_group_id (a sentinel-owned
-- endpoint is `visibility = 'public'` and takes an earlier branch), so the
-- extra conjunct would buy nothing and cost an outage mode.
ALTER TABLE public.edges
    ADD COLUMN IF NOT EXISTS co_owner_group_id uuid;   -- NULL = single-owner

DO $$ BEGIN
    -- Identical shape to 062's edges_owner_group_fkey: RESTRICT, NOT VALID.
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.edges'::regclass
                      AND conname = 'edges_co_owner_fkey') THEN
        ALTER TABLE public.edges ADD CONSTRAINT edges_co_owner_fkey
            FOREIGN KEY (co_owner_group_id) REFERENCES public.groups(id)
            ON DELETE RESTRICT NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'public.edges'::regclass
                      AND conname = 'edges_co_owner_shape') THEN
        ALTER TABLE public.edges ADD CONSTRAINT edges_co_owner_shape CHECK (
            co_owner_group_id IS NULL
            OR (visibility = 'group' AND co_owner_group_id <> owner_group_id))
            NOT VALID;
    END IF;
END $$;

COMMENT ON COLUMN public.edges.co_owner_group_id IS
  'The SECOND owning group of a cross-group edge. NULL means single-owner. '
  'Read semantics are an INTERSECTION: a co-owned edge is visible only to a '
  'principal in both owner_group_id and co_owner_group_id. Written only by '
  'epigraph_edges_tenancy() (INSERT/endpoint UPDATE) and '
  'epigraph_propagate_tenancy() (claims privatization). Migration 072, PR-13.';

-- ===================================================================
-- 2. ARM (b) -- the write-time stamp. THE CROSS-GROUP RAISE BECOMES A STAMP.
--
-- GUARDS KEPT (the plan's printed body drops both, and doing so is a measured
-- regression -- this is the twelfth verified plan error in this series):
--
--   1. THE NO-WIDENING GUARD, verbatim from 070. The plan's body begins
--      straight at `IF sv = 'public' AND tv = 'public'`, which makes the meet
--      UNCONDITIONAL and silently rewrites an edge EXPLICITLY declared
--      ('group', G) between two PUBLIC endpoints to ('public', world) -- a
--      declared-private row made public by a trigger. PR-12 measured exactly
--      that against `epigraph-api/tests/structural_features_authz.rs::
--      owner_sees_the_whole_subgraph_and_a_stranger_only_its_public_part`,
--      where the stranger saw 2 edges where it must see 1, and against
--      `tenancy_triggers.rs::arm_b_does_not_widen_an_explicitly_private_edge`.
--
--   2. epigraph_node_tenancy IS STILL THE ORACLE for both endpoints, so an
--      edge onto a frame/agent/paper/task still contributes 'public' and never
--      blocks a write.
--
-- WHAT IS REMOVED, AND WHY IT IS NOT A REGRESSION. 070's cross-group branch was
--
--     IF NOT (sg = ANY (public.epigraph_session_groups())
--         AND tg = ANY (public.epigraph_session_groups())) THEN
--         RAISE EXCEPTION '... edge spans groups % and %; writer is not a
--                          member of both' USING ERRCODE = '23514';
--     END IF;
--
-- Both the RAISE and its session-membership hatch are gone. The RAISE is the
-- window this PR exists to close. The hatch goes with it because:
--
--   * IT NEVER FIRED. 070's own comment (070:196-203) records that for PERSONAL
--     groups one principal can never be a live member of two distinct ones, so
--     the conjunction is unsatisfiable by construction; and every production
--     edge writer reaches this trigger on a bare `&PgPool`
--     (`EdgeRepository::create`, `create_if_not_exists`,
--     `create_symmetric_if_absent*` take no ScopedPool), where
--     epigraph_session_groups() is empty and the hatch cannot be satisfied
--     regardless of membership. Removing an unsatisfiable escape hatch removes
--     nothing that worked.
--   * IT IS WRITE-SIDE AUTHORIZATION, WHICH THIS PR DOES NOT OWN.
--     `locked_decisions.rs` states the split: "No RLS policy, no WITH CHECK, no
--     write-side SQL predicate. That half is PR-16/PR-17's." A membership test
--     inside a stamping trigger is a write-side predicate wearing a trigger's
--     clothes. PR-16's 074 is where it belongs, expressed once, next to
--     claims_block_widening, rather than in one arm of one table's stamper.
--   * THE ACCEPTANCE CRITERION REQUIRES ITS REMOVAL. "An edge between a group-G
--     claim and a group-H claim is stored as ('group', G, co_owner = H)" is not
--     reachable while a membership-gated RAISE stands in front of it.
--
-- CONSEQUENCE FOR THE 23514 MAPPING. After this migration arm (b) no longer
-- raises 23514, so the residual 23514 on the edge write path is
-- edges_co_owner_shape (and 062's edges_group_needs_real_group) -- i.e. genuine
-- bad input, not "you are not a member of both groups". The API mapping added
-- in this PR (`DbError::CheckViolation` -> 400) is written to that meaning.
--
-- EVERY BRANCH ASSIGNS co_owner_group_id EXPLICITLY. This trigger fires on
-- `UPDATE OF source_id, target_id` as well as INSERT, so a branch that left
-- NEW.co_owner_group_id alone would carry a STALE co-owner across a
-- re-pointing of the edge -- either a phantom restriction or, if the new
-- co-owner equals the new owner, an edges_co_owner_shape violation. The single
-- exception is the no-widening early RETURN, which honours the writer's whole
-- declaration; a writer-supplied co-owner there is STRICTER than the meet, in
-- the same direction as the declaration that branch exists to preserve.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_edges_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE sg uuid; sv varchar(16); tg uuid; tv varchar(16);
BEGIN
    SELECT g, v INTO sg, sv FROM public.epigraph_node_tenancy(NEW.source_id, NEW.source_type);
    SELECT g, v INTO tg, tv FROM public.epigraph_node_tenancy(NEW.target_id, NEW.target_type);

    -- No-widening. Explicitly declared private, endpoints both public: the meet
    -- would WIDEN it. Keep the declaration, co-ownership included.
    IF NEW.visibility = 'group'
       AND NEW.owner_group_id <> '00000000-0000-0000-0000-000000000000'::uuid
       AND NOT (sv = 'group' OR tv = 'group') THEN
        RETURN NEW;
    END IF;

    IF sv = 'public' AND tv = 'public' THEN
        NEW.owner_group_id := '00000000-0000-0000-0000-000000000000'::uuid;
        NEW.visibility := 'public';
        NEW.co_owner_group_id := NULL;
    ELSIF sv = 'public' THEN
        NEW.owner_group_id := tg; NEW.visibility := 'group';
        NEW.co_owner_group_id := NULL;
    ELSIF tv = 'public' THEN
        NEW.owner_group_id := sg; NEW.visibility := 'group';
        NEW.co_owner_group_id := NULL;
    ELSIF sg = tg THEN
        NEW.owner_group_id := sg; NEW.visibility := 'group';
        NEW.co_owner_group_id := NULL;
    ELSE
        -- Expressible now. The edge is owned by BOTH groups and, under the
        -- INTERSECTION read fragment, visible to neither group alone.
        NEW.owner_group_id := sg; NEW.visibility := 'group';
        NEW.co_owner_group_id := tg;
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_edges_tenancy() FROM PUBLIC;   -- ops F18

-- ===================================================================
-- 3. ARM (d) -- privatization propagation. THE THREE-CASE MEET.
--
-- This is the acceptance criterion the plan asserts from `pg_proc.prosrc`
-- rather than from this file's text, so that prose and SQL cannot diverge
-- again: `crates/epigraph-db/tests/tenancy_triggers.rs::
-- arm_d_body_carries_the_three_case_meet_over_co_ownership` reads the catalog.
--
-- "THREE-CASE" MEANS THREE CASE **EXPRESSIONS** -- owner_group_id, visibility
-- and co_owner_group_id -- not three WHEN branches. Three WHENs is
-- arithmetically impossible: the meet needs both-public, source-public,
-- target-public and same-group before the cross-group case is even reached.
-- 070's body has two CASE expressions; this one has three.
--
-- EVERYTHING ABOVE THE EDGES UPDATE IS 070'S BODY, UNCHANGED: the firing gate
-- (which MUST stay ahead of the assertion -- an UPDATE that changes no tenancy
-- is none of this trigger's business and must not be made to depend on the
-- maintenance role), the epigraph_definer_bypass() assertion, the 17-table
-- derived loop with its expected/actual RLS-filtering check, and
-- harvester_fragments. Only the trailing `UPDATE public.edges` changes.
--
-- GUARDS KEPT from 070 (the plan ships only a prose stub here -- "identical to
-- 066(d) except the final edges UPDATE" -- so there is no SQL to copy and both
-- guards are easy to lose):
--
--   1. NO WIDENING: `AND NOT (e.visibility = 'group' AND m.v = 'public')`.
--      `structural_features_authz.rs::seed_corpus` seeds an edge explicitly
--      declared ('group', G) between two PUBLIC claims and then stamps
--      ownership rows over those claims, which fires this arm. Without the
--      guard the meet re-widened that edge and the stranger counted it. A
--      declassification that SHOULD widen an edge is PR-16's business,
--      alongside its claims_block_widening trigger.
--   2. IDEMPOTENCE: `IS DISTINCT FROM` on the whole tuple, now the TRIPLE
--      including co_owner_group_id (the plan says "IS DISTINCT FROM on the
--      whole triple" and this is that). Without the third element a
--      co-ownership change alone would not be written.
--   3. `m.g IS NOT NULL`. With `ELSE s.g` replacing 070's `ELSE NULL` this can
--      no longer fire, and it is kept anyway: owner_group_id is NOT NULL, and a
--      future edit to the first CASE that reintroduces a NULL arm would
--      otherwise turn a stale-but-private edge into a 23502 raised from a
--      statement-level AFTER UPDATE on claims -- a total write outage on
--      privatization. It costs one comparison.
--
-- IT STILL NEVER RAISES. Arm (d) fires on every claims UPDATE, including this
-- series' own backfill; an exception here is a write outage, not a rejected
-- row. That is why 070 left a cross-group edge UNCHANGED instead of raising,
-- and why the co-owner CASE below is written to yield NULL on EVERY collapse
-- path. Trace the case that makes this load-bearing: edge (owner = G,
-- co_owner = H, 'group'), then G's endpoint is declassified to public. The meet
-- collapses to (H, 'group'); if the third CASE left H in co_owner_group_id the
-- row would be (owner = H, co_owner = H) and edges_co_owner_shape's
-- `co_owner_group_id <> owner_group_id` would raise 23514 FROM THE TRIGGER --
-- the outage this arm must never cause. The `s.v = 'group' AND t.v = 'group'`
-- conjuncts, not just `s.g <> t.g`, are what prevent it, and
-- `crates/epigraph-db/tests/privatization_boundary.rs::
-- declassifying_one_endpoint_of_a_co_owned_edge_clears_the_co_owner` is the
-- test that fails if they are ever dropped.
--
-- NO `ORDER BY e.id` HERE -- A CORRECTION TO THE PLAN. Plan §6.5's `ORDER BY
-- e.id -- ops F12: fixed lock order` belongs to the PRIVATIZATION BACKFILL's
-- batched `ep` CTE, a resumable multi-batch UPDATE where lock order across
-- batches is real. This is a single statement-level trigger already scoped to
-- `changed`, and an ORDER BY inside a subquery of UPDATE ... FROM does not
-- establish lock acquisition order in PostgreSQL -- it is a hint the planner
-- may drop. Adding it would document a guarantee that does not exist.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_propagate_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE t text; expected bigint; actual bigint;
        derived text[] := ARRAY[
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance','evidence',
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations'];
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
        EXECUTE format(
          'SELECT count(*) FROM %I d JOIN changed ch ON ch.id = d.claim_id
             WHERE (d.owner_group_id, d.visibility)
                   IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t)
          INTO expected;
        EXECUTE format(
          'UPDATE %I d SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
             FROM changed ch
            WHERE ch.id = d.claim_id
              AND (d.owner_group_id, d.visibility)
                  IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t);
        GET DIAGNOSTICS actual = ROW_COUNT;
        IF actual <> expected THEN
            RAISE EXCEPTION 'epigraph tenancy: propagation to % updated % of % rows '
                            '(RLS filtered?)', t, actual, expected;
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
    -- BOTH endpoints -- `edges` is the only two-parent relation here, which is
    -- why the 17 derived tables above can legitimately copy their single parent
    -- and this one cannot. See the header for the three CASE expressions, the
    -- two guards and why the co-owner CASE must collapse to NULL.
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
          FROM public.edges e2
          JOIN changed ch
            ON ((e2.source_id = ch.id AND e2.source_type = 'claim')
             OR (e2.target_id = ch.id AND e2.target_type = 'claim'))
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e2.source_id, e2.source_type) s
          CROSS JOIN LATERAL public.epigraph_node_tenancy(e2.target_id, e2.target_type) t
      ) m
     WHERE e.id = m.id
       AND m.g IS NOT NULL
       AND NOT (e.visibility = 'group' AND m.v = 'public')
       AND (e.owner_group_id, e.visibility, e.co_owner_group_id)
           IS DISTINCT FROM (m.g, m.v, m.co);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_propagate_tenancy() FROM PUBLIC;  -- ops F18

-- ===================================================================
-- 4. OWNERSHIP.
--
-- CREATE OR REPLACE FUNCTION PRESERVES OWNERSHIP, so the two bodies above are
-- still owned by epigraph_maintenance wherever 070's tail DO block ran. The
-- re-own is repeated anyway, for the case 070's own header calls out: on a
-- managed cluster whose migration role lacks CREATEROLE, migration 060's
-- CREATE ROLE was caught and only NOTICEd, 070's guard silently no-opped, and
-- these bodies are app-owned. Arm (d) ASSERTS epigraph_definer_bypass() and
-- would raise 42501 on every claims UPDATE; arm (b) would read `claims`
-- RLS-filtered, get NOT FOUND, take epigraph_node_tenancy's ('public', world)
-- fallback and STAMP A PRIVATE ENDPOINT PUBLIC -- a leak with no error.
--
-- A hard failure here is still wrong: a failed migration records no sqlx row,
-- so the next restart re-runs it and a missing role becomes a permanent deploy
-- outage. The check that fails loudly lives in
-- `epigraph-tenancy-backfill verify`, whose exit code is the documented
-- week-11c pre-flight.
-- ===================================================================
DO $$
DECLARE f text;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance') THEN
        FOREACH f IN ARRAY ARRAY[
            'public.epigraph_edges_tenancy()',
            'public.epigraph_propagate_tenancy()'] LOOP
            EXECUTE format('ALTER FUNCTION %s OWNER TO epigraph_maintenance', f);
        END LOOP;
    ELSE
        RAISE NOTICE 'epigraph tenancy: role epigraph_maintenance absent; '
                     'the 072 function bodies stay app-owned. Run '
                     '`epigraph-tenancy-backfill verify` before deploying.';
    END IF;
END $$;
