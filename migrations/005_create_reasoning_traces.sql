-- Migration: 005_create_reasoning_traces
-- Description: Create reasoning traces table for epistemic provenance
--
-- Reasoning traces form a DAG (Directed Acyclic Graph) showing how
-- claims are derived from evidence and other claims.
--
-- Evidence:
-- - IMPLEMENTATION_PLAN.md §1.4 specifies ReasoningTrace model
-- - DAG structure prevents circular reasoning
--
-- Reasoning:
-- - reasoning_type as VARCHAR for flexibility (enum in Rust)
-- - confidence [0.0, 1.0] represents reasoning quality
-- - explanation provides human-readable justification
-- - Parent-child relationships stored in junction table for DAG
-- - labels/properties support LPG extensions
--
-- Verification:
-- - CHECK constraint validates reasoning_type enum values
-- - CHECK constraint ensures confidence [0.0, 1.0]
-- - Junction table PRIMARY KEY prevents duplicate edges
-- - CHECK constraint prevents self-references

CREATE TABLE reasoning_traces (
    -- Primary identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Reference to claim this trace generates
    claim_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,

    -- Reasoning methodology type
    reasoning_type VARCHAR(50) NOT NULL,

    -- Confidence in the reasoning [0.0, 1.0]
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.5,

    -- Human-readable explanation of reasoning
    explanation TEXT NOT NULL,

    -- LPG: Labels for categorization (e.g., ['verified', 'peer-reviewed'])
    labels TEXT[] NOT NULL DEFAULT '{}',

    -- LPG: Flexible properties as JSONB
    -- Example: {"methodology_version": "1.0", "inputs": [...]}
    properties JSONB NOT NULL DEFAULT '{}',

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT reasoning_type_valid CHECK (
        reasoning_type IN (
            'deductive',
            'inductive',
            'abductive',
            'analogical',
            'statistical'
        )
    ),
    CONSTRAINT reasoning_confidence_bounds CHECK (
        confidence >= 0.0 AND confidence <= 1.0
    ),
    CONSTRAINT reasoning_explanation_not_empty CHECK (
        length(trim(explanation)) > 0
    )
);

-- Index for claim lookups
CREATE INDEX idx_reasoning_traces_claim_id ON reasoning_traces(claim_id);

-- Index for reasoning type filtering
CREATE INDEX idx_reasoning_traces_type ON reasoning_traces(reasoning_type);

-- Index for confidence filtering
CREATE INDEX idx_reasoning_traces_confidence ON reasoning_traces(confidence DESC);

-- GIN index for label queries
CREATE INDEX idx_reasoning_traces_labels ON reasoning_traces USING GIN(labels);

-- GIN index for property queries
CREATE INDEX idx_reasoning_traces_properties ON reasoning_traces USING GIN(properties);

-- Index for time-based queries
CREATE INDEX idx_reasoning_traces_created_at ON reasoning_traces(created_at DESC);

-- Trace parents junction table (DAG edges)
--
-- This table represents the parent-child relationships between traces,
-- forming a Directed Acyclic Graph (DAG). Each edge means:
-- "trace_id depends on/derives from parent_id"
--
-- The DAG structure ensures:
-- - No circular reasoning (cycles detected by application layer)
-- - Clear lineage tracing from conclusion back to evidence
-- - Multiple evidence sources can support one conclusion

CREATE TABLE trace_parents (
    -- Child trace (depends on parent)
    trace_id UUID NOT NULL REFERENCES reasoning_traces(id) ON DELETE CASCADE,

    -- Parent trace (provides input to child)
    parent_id UUID NOT NULL REFERENCES reasoning_traces(id) ON DELETE CASCADE,

    -- Primary key prevents duplicate edges
    PRIMARY KEY (trace_id, parent_id),

    -- Prevent self-references (trace cannot depend on itself)
    CONSTRAINT trace_parents_no_self_reference CHECK (trace_id != parent_id)
);

-- Index for forward traversal (find children of a trace)
CREATE INDEX idx_trace_parents_parent_id ON trace_parents(parent_id);

-- Index for reverse traversal (find parents of a trace)
CREATE INDEX idx_trace_parents_trace_id ON trace_parents(trace_id);

-- Comment for future developers
COMMENT ON TABLE trace_parents IS
'DAG edges for reasoning trace dependencies. Cycle detection must be performed '
'at application layer before inserting new edges. See epigraph-engine DAG validator.';
