-- Migration 023: Add pignistic probability columns + enrich contexts table
--
-- Evidence:
-- - dekg-planning-doc.md: BetP is the TBM decision-making transform (§2.1, §6.1)
-- - Phase 4 gap assessment: multi-hypothesis Bel/Pl broken, pignistic not exposed
-- - Context node type (§1.1) has stub table from migration 018 but no enrichment
--
-- Reasoning:
-- - Pignistic probability stored alongside Bel/Pl enables decision-level queries
--   without recomputing from raw mass functions on every read
-- - Context enrichment adds fields needed for scoped evidence filtering:
--   description, applicable frames, parameters, modifier type

-- 1. Pignistic probability on claims
ALTER TABLE claims ADD COLUMN IF NOT EXISTS pignistic_prob DOUBLE PRECISION;

-- 2. Pignistic probability on scoped belief cache
ALTER TABLE ds_combined_beliefs ADD COLUMN IF NOT EXISTS pignistic_prob DOUBLE PRECISION;

-- 3. Enrich contexts stub table
ALTER TABLE contexts ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE contexts ADD COLUMN IF NOT EXISTS applicable_frame_ids UUID[] DEFAULT '{}';
ALTER TABLE contexts ADD COLUMN IF NOT EXISTS parameters JSONB DEFAULT '{}';
ALTER TABLE contexts ADD COLUMN IF NOT EXISTS modifier_type TEXT DEFAULT 'filter';

CREATE INDEX IF NOT EXISTS idx_contexts_modifier_type ON contexts(modifier_type);
