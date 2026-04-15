-- Migration 037: Analysis Node
-- Introduces the Analysis entity between Evidence and Claim.
-- An Analysis represents a specific analytical process applied to evidence,
-- capturing constraints, inference path, and coverage context.

CREATE TABLE IF NOT EXISTS analyses (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_type   VARCHAR(50) NOT NULL,        -- 'graph_constrained', 'unconstrained', 'expert', 'automated'
    method_description TEXT NOT NULL,             -- human-readable description of analytical approach
    inference_path  VARCHAR(30) NOT NULL          -- 'retrieved', 'inferred', 'analogical', 'novel'
                    DEFAULT 'novel',
    constraints     TEXT,                         -- what the analysis could NOT access
    coverage_context JSONB DEFAULT '{}',          -- {dense_regions, sparse_regions, void_regions}
    input_evidence_ids UUID[] DEFAULT '{}',       -- evidence consumed by this analysis
    agent_id        UUID NOT NULL REFERENCES agents(id),
    properties      JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Analysis → Claim link uses existing edges table:
--   relationship = 'concludes', source_type = 'analysis', target_type = 'claim'
-- Evidence → Analysis link uses existing edges table:
--   relationship = 'interpreted_by', source_type = 'evidence', target_type = 'analysis'

CREATE INDEX IF NOT EXISTS idx_analyses_type ON analyses(analysis_type);
CREATE INDEX IF NOT EXISTS idx_analyses_inference ON analyses(inference_path);
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_agent ON analyses(agent_id);
