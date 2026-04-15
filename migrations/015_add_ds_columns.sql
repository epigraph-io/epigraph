-- Migration 015: Add Dempster-Shafer columns to claims + synchronize entity types
--
-- Adds belief/plausibility interval columns alongside existing truth_value.
-- All columns are nullable for backward compatibility — existing claims
-- continue to work with scalar truth_value only.
--
-- Evidence:
-- - dekg-planning-doc.md: TBM requires belief-plausibility intervals
-- - epigraph-nano already stores [belief, plausibility] in JSONB EpistemicState
--
-- Reasoning:
-- - Additive schema change: all new columns NULL-defaulted, no breakage
-- - mass_on_empty defaults to 0.0 (classical DST assumes no open-world conflict)
-- - CHECK constraints enforce Bel(A) <= Pl(A) invariant from DS theory
-- - Entity types expanded: 'paper' (from epigraph-nano), plus DEKG stubs

-- 1. Add DS-specific columns to claims
ALTER TABLE claims ADD COLUMN IF NOT EXISTS belief DOUBLE PRECISION;
ALTER TABLE claims ADD COLUMN IF NOT EXISTS plausibility DOUBLE PRECISION;
ALTER TABLE claims ADD COLUMN IF NOT EXISTS mass_on_empty DOUBLE PRECISION DEFAULT 0.0;

-- 2. Bounds checks matching DS theory invariants
ALTER TABLE claims ADD CONSTRAINT claims_belief_bounds
    CHECK (belief IS NULL OR (belief >= 0.0 AND belief <= 1.0));
ALTER TABLE claims ADD CONSTRAINT claims_plausibility_bounds
    CHECK (plausibility IS NULL OR (plausibility >= 0.0 AND plausibility <= 1.0));
ALTER TABLE claims ADD CONSTRAINT claims_bel_pl_order
    CHECK (belief IS NULL OR plausibility IS NULL OR belief <= plausibility);
ALTER TABLE claims ADD CONSTRAINT claims_mass_empty_bounds
    CHECK (mass_on_empty >= 0.0 AND mass_on_empty <= 1.0);

-- 3. Synchronize entity types: add 'paper', 'perspective', 'community', 'context'
-- EpiGraphV2 has 'activity' (from 013), epigraph-nano has 'paper' — unify both
ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid;
ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid CHECK (
    source_type IN ('claim','agent','evidence','trace','node','activity',
                    'paper','perspective','community','context') AND
    target_type IN ('claim','agent','evidence','trace','node','activity',
                    'paper','perspective','community','context')
);
