-- Migration: 006_create_relationships
-- Description: Create LPG edges table and add deferred foreign keys
--
-- This migration:
-- 1. Adds the deferred FK for claims.trace_id (circular dependency resolution)
-- 2. Creates the generic edges table for LPG-style relationships
--
-- Evidence:
-- - claims.trace_id FK deferred to avoid circular dependency
-- - LPG pattern requires flexible edge table for arbitrary relationships
--
-- Reasoning:
-- - Deferred FK allows claims and traces to reference each other
-- - Generic edges table supports graph queries beyond fixed schema
-- - source/target type fields enable heterogeneous graph
-- - relationship field stores edge label (e.g., 'supports', 'refutes')
--
-- Verification:
-- - FK constraint added successfully
-- - edges table supports multi-entity relationships

-- Add foreign key for claims.trace_id (deferred from migration 003)
--
-- This FK was deferred because of circular dependency:
-- - claims references reasoning_traces (trace_id)
-- - reasoning_traces references claims (claim_id)
--
-- Now that both tables exist, we can add the FK constraint.

ALTER TABLE claims
    ADD CONSTRAINT claims_trace_id_fkey
    FOREIGN KEY (trace_id)
    REFERENCES reasoning_traces(id)
    ON DELETE SET NULL;

-- LPG-style edges table
--
-- This table provides a flexible way to represent arbitrary relationships
-- between any entities in the graph. Unlike fixed schema relationships
-- (FK constraints), this table supports:
-- - Dynamic relationship types
-- - Relationships between different entity types
-- - Property-decorated edges
-- - Query-time relationship discovery
--
-- Example edges:
-- - Claim A "supports" Claim B
-- - Claim X "contradicts" Claim Y
-- - Agent A "authored" Claim C
-- - Evidence E "cites" Evidence F

CREATE TABLE edges (
    -- Primary identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Source entity ID
    source_id UUID NOT NULL,

    -- Target entity ID
    target_id UUID NOT NULL,

    -- Source entity type (e.g., 'claim', 'agent', 'evidence', 'trace')
    source_type VARCHAR(50) NOT NULL,

    -- Target entity type
    target_type VARCHAR(50) NOT NULL,

    -- Relationship label (e.g., 'supports', 'refutes', 'cites', 'authored')
    relationship VARCHAR(100) NOT NULL,

    -- LPG: Labels for edge categorization
    labels TEXT[] NOT NULL DEFAULT '{}',

    -- LPG: Flexible properties as JSONB
    -- Example: {"weight": 0.8, "confidence": 0.95, "created_by": "agent-uuid"}
    properties JSONB NOT NULL DEFAULT '{}',

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT edges_entity_types_valid CHECK (
        source_type IN ('claim', 'agent', 'evidence', 'trace', 'node') AND
        target_type IN ('claim', 'agent', 'evidence', 'trace', 'node')
    ),
    CONSTRAINT edges_relationship_not_empty CHECK (
        length(trim(relationship)) > 0
    ),
    CONSTRAINT edges_no_self_loop CHECK (
        source_id != target_id OR source_type != target_type
    )
);

-- Index for source lookups
CREATE INDEX idx_edges_source ON edges(source_id, source_type);

-- Index for target lookups
CREATE INDEX idx_edges_target ON edges(target_id, target_type);

-- Index for relationship filtering
CREATE INDEX idx_edges_relationship ON edges(relationship);

-- Composite index for specific edge queries
CREATE INDEX idx_edges_source_target ON edges(source_id, target_id);

-- GIN index for label queries
CREATE INDEX idx_edges_labels ON edges USING GIN(labels);

-- GIN index for property queries
CREATE INDEX idx_edges_properties ON edges USING GIN(properties);

-- Index for time-based queries
CREATE INDEX idx_edges_created_at ON edges(created_at DESC);

-- Composite index for typed relationship queries
-- Example: Find all 'supports' relationships between claims
CREATE INDEX idx_edges_typed_relationship ON edges(source_type, relationship, target_type);

-- Comment for future developers
COMMENT ON TABLE edges IS
'LPG-style edges table for flexible graph relationships. This table complements '
'the fixed schema FK relationships and enables dynamic graph queries. Use this '
'for relationships that don''t fit the core schema (e.g., claim supports/refutes '
'another claim, agent endorses claim, etc.).';
