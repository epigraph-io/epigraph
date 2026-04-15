-- Migration 022: Enrich Perspective/Community stubs + scoped combined beliefs
--
-- Evidence:
-- - dekg-planning-doc.md §1.1, §2.3, §4.1: scoped combination across global/community/perspective
-- - Migration 018 created stub tables with minimal columns
--
-- Reasoning:
-- - Perspectives need type, frame association, and calibration for scoped belief
-- - Communities need governance/ownership metadata and member junction
-- - mass_functions needs perspective_id so an agent can submit different BBAs per perspective
-- - ds_combined_beliefs caches scoped combination results for fast queries
-- - Frame refinement columns (parent_frame_id, is_refinable) enable hierarchical frames

-- Enrich perspectives with DS-relevant columns
ALTER TABLE perspectives ADD COLUMN IF NOT EXISTS perspective_type TEXT DEFAULT 'analytical';
ALTER TABLE perspectives ADD COLUMN IF NOT EXISTS frame_ids UUID[] DEFAULT '{}';
ALTER TABLE perspectives ADD COLUMN IF NOT EXISTS extraction_method TEXT DEFAULT 'ai_generated';
ALTER TABLE perspectives ADD COLUMN IF NOT EXISTS confidence_calibration DOUBLE PRECISION DEFAULT 0.5;

-- Enrich communities with governance metadata
ALTER TABLE communities ADD COLUMN IF NOT EXISTS governance_type TEXT DEFAULT 'open';
ALTER TABLE communities ADD COLUMN IF NOT EXISTS ownership_type TEXT DEFAULT 'public';

-- Junction: community <-> perspective membership
CREATE TABLE IF NOT EXISTS community_members (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    perspective_id UUID NOT NULL REFERENCES perspectives(id) ON DELETE CASCADE,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, perspective_id)
);

-- Link mass functions to submitting perspective
ALTER TABLE mass_functions ADD COLUMN IF NOT EXISTS perspective_id UUID REFERENCES perspectives(id);

-- Replace unique constraint: agent may submit different BBAs from different perspectives
ALTER TABLE mass_functions DROP CONSTRAINT IF EXISTS mass_functions_claim_id_frame_id_source_agent_id_key;
ALTER TABLE mass_functions ADD CONSTRAINT mass_functions_unique_per_perspective
    UNIQUE (claim_id, frame_id, source_agent_id, perspective_id);

-- Scoped combined beliefs cache (doc §2.3)
CREATE TABLE IF NOT EXISTS ds_combined_beliefs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    frame_id UUID NOT NULL REFERENCES frames(id) ON DELETE CASCADE,
    claim_id UUID NOT NULL,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('global', 'community', 'perspective')),
    scope_id UUID,  -- NULL for global, community/perspective UUID otherwise
    belief DOUBLE PRECISION NOT NULL,
    plausibility DOUBLE PRECISION NOT NULL,
    mass_on_empty DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    conflict_k DOUBLE PRECISION,
    strategy_used TEXT,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(frame_id, claim_id, scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_scoped_beliefs_claim ON ds_combined_beliefs(claim_id, scope_type);
CREATE INDEX IF NOT EXISTS idx_scoped_beliefs_scope ON ds_combined_beliefs(scope_type, scope_id);

-- Frame refinement columns (doc §1.3)
ALTER TABLE frames ADD COLUMN IF NOT EXISTS parent_frame_id UUID REFERENCES frames(id);
ALTER TABLE frames ADD COLUMN IF NOT EXISTS is_refinable BOOLEAN DEFAULT TRUE;
