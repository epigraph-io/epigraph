-- Drop orphan BBAs + claim assignments on the legacy `graph-topology` frame.
--
-- PR #172 unified the HTTP edge-triggered DS recomputation path onto the
-- canonical `binary_truth` frame, replacing the parallel `graph-topology`
-- implementation (hypotheses {supported, contradicted}, hardcoded math
-- `mass = source_truth * 0.7 * 0.5`). After the merge, no code path reads
-- or writes the graph-topology mass_function rows; they are dead data.
--
-- This migration removes the orphans but **keeps the `frames` row itself**
-- so historical references (older migrations, archived audit logs) stay
-- coherent.
--
-- Pre-migration audit (run on prod 2026-05-26):
--   orphan_bbas        = 62 (last write 2026-05-16)
--   orphan_assignments = 4
-- Post-migration: both should be 0.

BEGIN;

DELETE FROM mass_functions
WHERE frame_id IN (SELECT id FROM frames WHERE name = 'graph-topology');

DELETE FROM claim_frames
WHERE frame_id IN (SELECT id FROM frames WHERE name = 'graph-topology');

COMMIT;
