-- 060_shifted_to_edge_type.sql
--
-- `shifted_to` — TEMPORAL SUCCESSION between two claims. The SOURCE end is the
-- value that held in an earlier world; the TARGET end is the value that holds
-- now. "The throughput ceiling shifted from 400/s to 900/s" is written
-- `400/s -shifted_to-> 900/s`.
--
-- Deliberately NOT an epistemic relationship: succession is not
-- counter-evidence. 400/s was TRUE of its own era, and a later remeasurement
-- does not retroactively falsify it, so `shifted_to` must never move belief
-- (it is absent from `edge_to_factor_type` in 001, so
-- `auto_create_factor_from_edge` mints no BP factor, and the engine's
-- `restriction_kind_with_profile` falls through to `Neutral`, which
-- short-circuits `auto_wire_ds_for_edge` to `NonEpistemic`). What succession
-- DOES license is a RETRIEVAL preference: recall de-ranks the source end
-- below its live successor.
--
-- The index below is the same `(LEAST, GREATEST)` shape as migration 042's
-- `edges_alternative_of_symmetric_uniq`, but it does a DIFFERENT job. 042
-- enforces that a genuinely SYMMETRIC fact is stored once. On a DIRECTIONAL
-- relation this enforces ANTI-SYMMETRY: `A shifted_to B` and `B shifted_to A`
-- are a temporal contradiction, not two facts, so the pair key rejects the
-- reversal as well as the exact duplicate. Migration 053 dropped the
-- workspace-wide `(source_id, target_id, relationship)` unique index, so
-- without this nothing in the schema stops either shape.
--
-- Deliberately NOT `UNIQUE (source_id)`: 400 -> 900 -> 1500 is a legitimate
-- succession chain, and one-successor-per-source is a stronger claim than the
-- relationship needs.
--
-- Unlike 042 there is no closure VIEW: succession is a chain, not an
-- equivalence class, so a transitive closure would assert that the first value
-- in a chain shifted directly to the last.
--
-- COST THIS INDEX IMPOSES ON THE MERGE PATHS: `ClaimRepository::mark_duplicate`
-- and `ClaimRepository::consolidate` must treat `shifted_to` as
-- direction-agnostic-unique when they re-point edges, exactly as they already
-- do for `alternative_of`. Both are driven from
-- `epigraph_db::PAIR_UNIQUE_RELATIONSHIPS`, which lists both relationships;
-- without that, a merge re-pointing a `shifted_to` edge trips this index and
-- rolls the whole transaction back before `is_current` flips (backlog
-- 2905150e / issue #286, reproduced verbatim for a second relationship).

CREATE UNIQUE INDEX IF NOT EXISTS edges_shifted_to_pair_uniq
  ON edges (LEAST(source_id, target_id), GREATEST(source_id, target_id))
  WHERE relationship = 'shifted_to';

COMMENT ON INDEX edges_shifted_to_pair_uniq IS
'Anti-symmetric pair uniqueness for shifted_to (temporal succession). Rejects '
'both an exact duplicate A->B and the reversed B->A, which would assert that '
'each of two values succeeded the other. Directional analogue of migration '
'042''s edges_alternative_of_symmetric_uniq; both are listed in '
'epigraph_db::PAIR_UNIQUE_RELATIONSHIPS, which drives the merge paths.';
