-- 308: one stored `ds_combined_beliefs` row per (frame, claim, scope), the
-- global scope included. Backlog 3adc219b.
--
-- ===================================================================
-- 1. WHY
--
-- 001 keys the table with
--   ds_combined_beliefs_frame_id_claim_id_scope_type_scope_id_key
--     UNIQUE (frame_id, claim_id, scope_type, scope_id)
-- under PostgreSQL's default NULLS DISTINCT. A `global` row has
-- `scope_id IS NULL`, so two global rows of one (frame, claim) never
-- conflict. `ScopedBeliefRepository::upsert`'s
-- `ON CONFLICT (frame_id, claim_id, scope_type, scope_id) DO UPDATE` therefore
-- never fired for the global scope: every `POST /frames/:id/evidence` (step
-- 15) and every widening act's recompute of a global key INSERTED one more
-- row instead of replacing the one there. Readers that list a claim's scoped
-- beliefs (`list_for_claim`, `list_for_scope`) then returned every historic
-- global row, and a frame-agnostic `get` returned whichever was newest. It is
-- 034's defect (`mass_functions_unique_per_perspective`) on another table, and
-- this is 034's fix (also 267's key).
--
-- ===================================================================
-- 2. WHAT IT DOES
--
--   (1) Counts, with a NOTICE, the duplicate rows and the (frame, claim,
--       scope) keys that carry them.
--   (2) Deletes every row but the newest of each key, partitioned by ALL
--       FOUR key columns (a PARTITION BY groups NULLs together, which is the
--       grouping the new constraint enforces): latest `computed_at`, ties
--       broken by the larger `id`. The newest row is the one
--       `ScopedBeliefRepository::get` (`ORDER BY computed_at DESC LIMIT 1`)
--       already served, so a single-row reader sees no change. Only global
--       rows can be duplicates under 001's key, unless a non-global row also
--       carries a NULL `scope_id`; partitioning by the full key removes those
--       too, so (3) cannot fail on them.
--   (3) Drops 001's constraint and re-adds it under the SAME name as
--       `UNIQUE NULLS NOT DISTINCT (frame_id, claim_id, scope_type,
--       scope_id)`. The upsert's ON CONFLICT target resolves against it with
--       no code change: the second global write of a (frame, claim) now
--       updates the row in place.
--
-- The rows are derived caches (each is rewritten by the next computation
-- that stores its scope), so a deleted duplicate is an older fold of the
-- same key, never the only record of anything.
--
-- ===================================================================
-- 3. ROW SECURITY
--
-- Nothing here changes a policy, a grant or a trigger. The upsert's DO UPDATE
-- arm, which a global write now reaches, is held to the same
-- `ds_combined_beliefs_tenancy` policy and owner trigger as every scoped
-- write already was; `epigraph-api/tests/frames_evidence_app_role.rs` pins
-- that two global writes by the claim's owner on the application role leave
-- one row holding the second value.
--
-- ===================================================================
-- 4. COST AND DEPLOY ORDER
--
-- The DELETE scans the table once, and ADD CONSTRAINT builds a unique btree
-- under ACCESS EXCLUSIVE. `lock_timeout` 3 s refuses rather than queue
-- behind a live writer; re-run when it refuses. No binary changes with this
-- file, so it may be applied before or after any deploy. The operator
-- measures the duplicate count before and after (the PR's deploy notes).
--
-- ===================================================================
-- UNDO: `docs/runbooks/308-undo.sql` (restores 001's NULLS DISTINCT
-- constraint; the deleted duplicates are NOT restored).
-- **Applied to throwaway databases only, NOT to any deployed database.**
-- ===================================================================

SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    v_rows bigint;
    v_keys bigint;
BEGIN
    SELECT COALESCE(SUM(n - 1), 0), COUNT(*)
      INTO v_rows, v_keys
      FROM (SELECT COUNT(*) AS n
              FROM public.ds_combined_beliefs
             GROUP BY frame_id, claim_id, scope_type, scope_id
            HAVING COUNT(*) > 1) dup;
    RAISE NOTICE '308: deleting % duplicate ds_combined_beliefs rows over % (frame, claim, scope) keys; the newest row of each key is kept',
                 v_rows, v_keys;
END $$;

WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY frame_id, claim_id, scope_type, scope_id
               ORDER BY computed_at DESC, id DESC
           ) AS rn
      FROM public.ds_combined_beliefs
)
DELETE FROM public.ds_combined_beliefs d
 USING ranked
 WHERE d.id = ranked.id
   AND ranked.rn > 1;

ALTER TABLE public.ds_combined_beliefs
    DROP CONSTRAINT ds_combined_beliefs_frame_id_claim_id_scope_type_scope_id_key;

ALTER TABLE public.ds_combined_beliefs
    ADD CONSTRAINT ds_combined_beliefs_frame_id_claim_id_scope_type_scope_id_key
        UNIQUE NULLS NOT DISTINCT (frame_id, claim_id, scope_type, scope_id);
