-- Migration 040: Structured method entities
-- Upgrades from claim-based method_node/capability_node to structured tables
-- for experiment design method discovery and gap analysis.

-- Structured method entity
CREATE TABLE IF NOT EXISTS methods (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    canonical_name  TEXT NOT NULL,
    technique_type  VARCHAR(50) NOT NULL,
    measures        TEXT,
    resolution      TEXT,
    sensitivity     TEXT,
    limitations     TEXT[],
    required_equipment TEXT[],
    typical_conditions JSONB,
    source_claim_ids UUID[],
    properties      JSONB DEFAULT '{}',
    embedding       vector(1536),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_methods_canonical ON methods (canonical_name);
CREATE INDEX IF NOT EXISTS idx_methods_type ON methods (technique_type);
CREATE INDEX IF NOT EXISTS idx_methods_embedding ON methods USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- Method ↔ Capability junction
CREATE TABLE IF NOT EXISTS method_capabilities (
    method_id       UUID REFERENCES methods(id),
    capability      TEXT NOT NULL,
    specificity     SMALLINT DEFAULT 1,
    evidence_count  INT DEFAULT 0,
    PRIMARY KEY (method_id, capability)
);

-- Method usage in analyses
CREATE TABLE IF NOT EXISTS analysis_methods (
    analysis_id     UUID REFERENCES analyses(id),
    method_id       UUID REFERENCES methods(id),
    role            VARCHAR(30) DEFAULT 'primary',
    conditions_used JSONB,
    PRIMARY KEY (analysis_id, method_id)
);
