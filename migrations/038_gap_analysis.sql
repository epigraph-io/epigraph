-- Migration 038: Gap Analysis Persistence
-- Stores results from epistemic gap analyses for learning and trend tracking.
-- Links to the Analysis nodes created in migration 037.

CREATE TABLE IF NOT EXISTS gap_analyses (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    question                    TEXT NOT NULL,
    analysis_a_id               UUID REFERENCES analyses(id),  -- graph-constrained
    analysis_b_id               UUID REFERENCES analyses(id),  -- unconstrained
    graph_claims_count          INT NOT NULL,
    unconstrained_claims_count  INT NOT NULL,
    matched_count               INT NOT NULL,
    gap_count                   INT NOT NULL,
    proprietary_count           INT NOT NULL,
    confidence_boundary         TEXT,
    gaps                        JSONB NOT NULL DEFAULT '[]',
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_gap_analyses_created ON gap_analyses(created_at DESC);

-- Link challenges back to the gap analysis that originated them
ALTER TABLE challenges ADD COLUMN IF NOT EXISTS gap_analysis_id UUID REFERENCES gap_analyses(id);
