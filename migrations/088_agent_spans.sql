-- migrations/088_agent_spans.sql
-- OTel-compatible span tracking for software agent sessions.
-- Spans are first-class graph entities that link to claims via edges.

-- 1. Create agent_spans table
CREATE TABLE IF NOT EXISTS agent_spans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- W3C Trace Context
    trace_id        VARCHAR(32) NOT NULL,
    span_id         VARCHAR(16) NOT NULL,
    parent_span_id  VARCHAR(16),

    -- Span identity
    span_name       VARCHAR(200) NOT NULL,
    span_kind       VARCHAR(20) NOT NULL DEFAULT 'INTERNAL',

    -- Timing
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at        TIMESTAMPTZ,
    duration_ms     DOUBLE PRECISION,

    -- Status (OTel StatusCode)
    status          VARCHAR(10) NOT NULL DEFAULT 'UNSET',
    status_message  TEXT,

    -- Identity
    agent_id        UUID REFERENCES agents(id),
    user_id         UUID REFERENCES agents(id),
    session_id      UUID,

    -- Payload
    attributes      JSONB NOT NULL DEFAULT '{}',

    -- Graph linkage
    generated_ids   UUID[] NOT NULL DEFAULT '{}',
    consumed_ids    UUID[] NOT NULL DEFAULT '{}',

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT agent_spans_span_kind_valid CHECK (
        span_kind IN ('SERVER', 'CLIENT', 'INTERNAL', 'PRODUCER', 'CONSUMER')
    ),
    CONSTRAINT agent_spans_status_valid CHECK (
        status IN ('UNSET', 'OK', 'ERROR')
    ),
    CONSTRAINT agent_spans_trace_id_hex CHECK (
        trace_id ~ '^[0-9a-f]{32}$'
    ),
    CONSTRAINT agent_spans_span_id_hex CHECK (
        span_id ~ '^[0-9a-f]{16}$'
    ),
    CONSTRAINT agent_spans_parent_span_id_hex CHECK (
        parent_span_id IS NULL OR parent_span_id ~ '^[0-9a-f]{16}$'
    )
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_agent_spans_trace ON agent_spans(trace_id);
CREATE INDEX IF NOT EXISTS idx_agent_spans_session ON agent_spans(session_id);
CREATE INDEX IF NOT EXISTS idx_agent_spans_parent ON agent_spans(parent_span_id) WHERE parent_span_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_agent_spans_agent ON agent_spans(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_spans_user ON agent_spans(user_id);
CREATE INDEX IF NOT EXISTS idx_agent_spans_started ON agent_spans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_spans_name ON agent_spans(span_name);
CREATE INDEX IF NOT EXISTS idx_agent_spans_inflight ON agent_spans(status) WHERE ended_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_agent_spans_generated ON agent_spans USING GIN(generated_ids);
CREATE INDEX IF NOT EXISTS idx_agent_spans_consumed ON agent_spans USING GIN(consumed_ids);

-- 2. Widen edges CHECK constraint to include 'span'
ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid;

ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid CHECK (
    source_type IN (
        'claim', 'agent', 'evidence', 'trace', 'node',
        'activity', 'paper', 'perspective', 'community', 'context', 'frame',
        'analysis', 'experiment', 'experiment_result',
        'propaganda_technique', 'coalition', 'source_artifact', 'span'
    ) AND
    target_type IN (
        'claim', 'agent', 'evidence', 'trace', 'node',
        'activity', 'paper', 'perspective', 'community', 'context', 'frame',
        'analysis', 'experiment', 'experiment_result',
        'propaganda_technique', 'coalition', 'source_artifact', 'span'
    )
);

-- 3. Update referential integrity trigger to validate span references
CREATE OR REPLACE FUNCTION validate_edge_reference(
    entity_id UUID,
    entity_type VARCHAR
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN CASE entity_type
        WHEN 'claim'                 THEN EXISTS (SELECT 1 FROM claims WHERE id = entity_id)
        WHEN 'agent'                 THEN EXISTS (SELECT 1 FROM agents WHERE id = entity_id)
        WHEN 'evidence'              THEN EXISTS (SELECT 1 FROM evidence WHERE id = entity_id)
        WHEN 'trace'                 THEN EXISTS (SELECT 1 FROM reasoning_traces WHERE id = entity_id)
        WHEN 'paper'                 THEN EXISTS (SELECT 1 FROM papers WHERE id = entity_id)
        WHEN 'analysis'              THEN EXISTS (SELECT 1 FROM analyses WHERE id = entity_id)
        WHEN 'activity'              THEN EXISTS (SELECT 1 FROM activities WHERE id = entity_id)
        WHEN 'source_artifact'       THEN EXISTS (SELECT 1 FROM source_artifacts WHERE id = entity_id)
        WHEN 'propaganda_technique'  THEN EXISTS (SELECT 1 FROM propaganda_techniques WHERE id = entity_id)
        WHEN 'coalition'             THEN EXISTS (SELECT 1 FROM coalitions WHERE id = entity_id)
        WHEN 'span'                  THEN EXISTS (SELECT 1 FROM agent_spans WHERE id = entity_id)
        WHEN 'node'                  THEN TRUE
        ELSE FALSE
    END;
END;
$$ LANGUAGE plpgsql STABLE;
