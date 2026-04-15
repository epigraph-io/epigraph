-- Migration: 003_create_claims
-- Description: Create claims table for epistemic assertions
--
-- Claims are the core nodes in the epistemic graph.
-- Each claim has a probabilistic truth value [0.0, 1.0].
--
-- Evidence:
-- - IMPLEMENTATION_PLAN.md §1.4 specifies Claim model
-- - truth.rs defines TruthValue as bounded f64
--
-- Reasoning:
-- - content_hash (BLAKE3, 32 bytes) ensures content integrity
-- - truth_value bounded [0.0, 1.0] enforced by CHECK constraint
-- - trace_id nullable here, FK added in 006 to avoid circular dependency
-- - embedding vector(1536) for OpenAI text-embedding-3-small
-- - labels/properties support LPG extensions
--
-- Verification:
-- - CHECK constraint prevents truth values outside [0.0, 1.0]
-- - content_hash exactly 32 bytes for BLAKE3

CREATE TABLE claims (
    -- Primary identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Claim content
    content TEXT NOT NULL,

    -- BLAKE3 hash of canonical content (32 bytes)
    content_hash BYTEA NOT NULL,

    -- Truth value [0.0, 1.0]
    -- 0.0 = definitely false, 0.5 = uncertain, 1.0 = definitely true
    truth_value DOUBLE PRECISION NOT NULL DEFAULT 0.5,

    -- Reference to agent who created this claim
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,

    -- Reference to reasoning trace (nullable, FK added in migration 006)
    trace_id UUID,

    -- LPG: Labels for categorization (e.g., ['scientific', 'verified'])
    labels TEXT[] NOT NULL DEFAULT '{}',

    -- LPG: Flexible properties as JSONB
    -- Example: {"domain": "physics", "confidence_interval": 0.1}
    properties JSONB NOT NULL DEFAULT '{}',

    -- Vector embedding for semantic search (OpenAI text-embedding-3-small)
    embedding vector(1536),

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT claims_truth_value_bounds CHECK (
        truth_value >= 0.0 AND truth_value <= 1.0
    ),
    CONSTRAINT claims_content_hash_length CHECK (
        octet_length(content_hash) = 32
    ),
    CONSTRAINT claims_content_not_empty CHECK (
        length(trim(content)) > 0
    )
);

-- Index for agent lookups
CREATE INDEX idx_claims_agent_id ON claims(agent_id);

-- Index for truth value filtering and sorting
CREATE INDEX idx_claims_truth_value ON claims(truth_value DESC);

-- Index for content hash lookups (deduplication)
CREATE INDEX idx_claims_content_hash ON claims(content_hash);

-- Index for trace lookups (will be used after FK added)
CREATE INDEX idx_claims_trace_id ON claims(trace_id) WHERE trace_id IS NOT NULL;

-- GIN index for label queries
CREATE INDEX idx_claims_labels ON claims USING GIN(labels);

-- GIN index for property queries
CREATE INDEX idx_claims_properties ON claims USING GIN(properties);

-- Index for time-based queries
CREATE INDEX idx_claims_created_at ON claims(created_at DESC);

-- Trigger to update updated_at timestamp
CREATE TRIGGER claims_updated_at
    BEFORE UPDATE ON claims
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Note: Vector index for embeddings added in migration 007
-- (requires embeddings to be populated first for optimal index parameters)
