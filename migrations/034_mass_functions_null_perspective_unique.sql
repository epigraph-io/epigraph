-- 034_mass_functions_null_perspective_unique.sql
--
-- Fix BBA duplication caused by PostgreSQL's default NULL-distinct unique
-- semantics on mass_functions_unique_per_perspective.
--
-- Background:
--   `store_with_perspective` performs an upsert with
--   `ON CONFLICT (claim_id, frame_id, source_agent_id, perspective_id)`.
--   Because the unique constraint was created with default NULL-distinct
--   semantics, two rows with `perspective_id IS NULL` and otherwise
--   identical key columns never conflicted. Every `auto_wire_ds_for_claim`
--   call (and any auto_cdst / discount BBA write with perspective_id = NULL)
--   inserted a *new* row instead of updating the existing one. This
--   structurally amplified belief for hub claims (e.g. NEMS hubs, Hero's
--   Journey hub) and inflated sheaf-cohomology h1.
--
-- Fix:
--   1. Collapse each (claim_id, frame_id, source_agent_id, perspective_id)
--      group to a single row, keeping the most recent write (latest
--      `created_at`, tie-broken by `id`). Latest-wins matches the existing
--      ON CONFLICT DO UPDATE semantics — the constraint's original design
--      intent was one BBA per (claim, frame, agent, perspective); the NULL
--      bug just suppressed the conflict.
--   2. Rebuild `mass_functions_unique_per_perspective` with
--      `NULLS NOT DISTINCT` (PostgreSQL >= 15) so NULL perspective_id and
--      NULL source_agent_id participate in conflict detection. The existing
--      ON CONFLICT target then resolves against this constraint without
--      any code change.
--
-- Post-migration verification lives in the PR description; cached BetP
-- columns on `claims` are not recomputed here — the
-- `report_workflow_outcome` / sheaf_cohomology paths re-derive them.

BEGIN;

-- Step 1: dedup. Use a CTE-based DELETE so the row_number window is
-- evaluated once over the full table. PARTITION BY treats NULL as equal,
-- which is exactly the grouping the new constraint enforces.
--
-- Note: cached BetP columns on `claims` (belief, plausibility, pignistic_prob,
-- truth_value, mass_on_empty, mass_on_missing, open_world_mass) are NOT
-- recomputed here. For claims whose surviving BBA differs from the previous
-- Dempster-combination of all duplicates, cached values will be stale until
-- the next sheaf_cohomology / report_workflow_outcome pass. The follow-up
-- recompute script is tracked separately (see backlog).
DO $$
DECLARE
    affected_claims integer;
BEGIN
    SELECT COUNT(DISTINCT claim_id) INTO affected_claims
    FROM (
        SELECT claim_id,
               row_number() OVER (
                   PARTITION BY claim_id, frame_id, source_agent_id, perspective_id
                   ORDER BY created_at DESC, id DESC
               ) AS rn
        FROM mass_functions
    ) sub
    WHERE rn > 1;
    RAISE NOTICE 'mass_functions dedup: % distinct claims have BBAs deleted; cached BetP on those claims is now stale until next recompute', affected_claims;
END $$;

WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY claim_id, frame_id, source_agent_id, perspective_id
               ORDER BY created_at DESC, id DESC
           ) AS rn
    FROM mass_functions
)
DELETE FROM mass_functions mf
USING ranked
WHERE mf.id = ranked.id
  AND ranked.rn > 1;

-- Step 2: replace the unique constraint with a NULLS NOT DISTINCT variant.
ALTER TABLE mass_functions
    DROP CONSTRAINT mass_functions_unique_per_perspective;

ALTER TABLE mass_functions
    ADD CONSTRAINT mass_functions_unique_per_perspective
    UNIQUE NULLS NOT DISTINCT (claim_id, frame_id, source_agent_id, perspective_id);

COMMIT;
