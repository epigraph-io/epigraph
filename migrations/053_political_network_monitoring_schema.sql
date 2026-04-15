-- Migration 053: Political Network Monitoring Schema
--
-- Adds schema support for narrative propagation tracking (Items 3, 6, 7, 12):
-- - propaganda_techniques table (first-class node type for technique classification)
-- - coalitions table (narrative coalition detection, Item 7)
-- - Widens edges entity type CHECK constraint for new entity types
-- - Updates validate_edge_reference() to support propaganda_technique + coalition
-- - Adds cascade delete triggers for new entity types
--
-- Evidence:
-- - Feature planning document Items 3-12 requires ORIGINATED_BY, AMPLIFIED_BY,
--   COORDINATED_WITH, USES_TECHNIQUE edge types with propaganda_technique targets
-- - Item 7 (Coalition Detector) requires a coalitions table with MEMBER_OF edges
-- - Item 12 (Mirror Narrative Detection) requires MIRROR_NARRATIVE edges between coalitions
--
-- Reasoning:
-- - propaganda_technique needs a backing table so validate_edge_reference() can
--   enforce referential integrity on USES_TECHNIQUE edges
-- - coalitions need a backing table for MEMBER_OF edge targets and coalition queries
-- - Entity type CHECK constraint must include new types so edges can reference them
-- - Edge types (ORIGINATED_BY, etc.) are stored as relationship strings, no schema change needed
--
-- Verification:
-- - After migration: edges can reference propaganda_technique and coalition entity types
-- - validate_edge_reference() returns TRUE for valid propaganda_technique/coalition IDs
-- - Cascade delete triggers clean up edges when techniques/coalitions are deleted

-- ============================================================================
-- 1. propaganda_techniques table
-- ============================================================================

CREATE TABLE IF NOT EXISTS propaganda_techniques (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    category VARCHAR(100),           -- e.g., "emotional_appeal", "logical_fallacy", "narrative_framing"
    description TEXT,
    detection_guidance TEXT,          -- LLM prompt guidance for detecting this technique
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_propaganda_techniques_category
    ON propaganda_techniques(category);

CREATE INDEX IF NOT EXISTS idx_propaganda_techniques_name
    ON propaganda_techniques(name);

COMMENT ON TABLE propaganda_techniques IS
    'First-class propaganda technique nodes for USES_TECHNIQUE edge targets. '
    'Techniques are classified by category and carry detection guidance for LLM classifiers.';

-- ============================================================================
-- 2. coalitions table (Item 7: Narrative Coalition Detector)
-- ============================================================================

CREATE TABLE IF NOT EXISTS coalitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255),
    archetype VARCHAR(100),              -- Booker archetype: overcoming_the_monster, quest, etc.
    dominant_antagonist TEXT,             -- Semantic description of the shared antagonist
    cognitive_shape VARCHAR(100),        -- Vonnegut shape: man_in_hole, rags_to_riches, etc.
    member_count INT NOT NULL DEFAULT 0,
    start_date TIMESTAMPTZ,
    peak_date TIMESTAMPTZ,
    end_date TIMESTAMPTZ,
    reach_estimate BIGINT DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    detection_method VARCHAR(50) NOT NULL DEFAULT 'embedding+time',
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coalitions_active ON coalitions(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_coalitions_archetype ON coalitions(archetype);
CREATE INDEX IF NOT EXISTS idx_coalitions_start_date ON coalitions(start_date DESC);

COMMENT ON TABLE coalitions IS
    'Narrative coalitions detected when multiple agents run structurally similar narratives '
    'within a sliding time window. Claims link to coalitions via MEMBER_OF edges.';

-- ============================================================================
-- 3. Widen edges entity type CHECK constraint
-- ============================================================================

ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid;

ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid CHECK (
    source_type IN (
        'claim', 'agent', 'evidence', 'trace', 'node',
        'activity', 'paper', 'perspective', 'community', 'context', 'frame',
        'analysis', 'experiment', 'experiment_result',
        'propaganda_technique', 'coalition'
    ) AND
    target_type IN (
        'claim', 'agent', 'evidence', 'trace', 'node',
        'activity', 'paper', 'perspective', 'community', 'context', 'frame',
        'analysis', 'experiment', 'experiment_result',
        'propaganda_technique', 'coalition'
    )
);

-- ============================================================================
-- 4. Update validate_edge_reference() for new entity types
-- ============================================================================

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
        WHEN 'propaganda_technique'  THEN EXISTS (SELECT 1 FROM propaganda_techniques WHERE id = entity_id)
        WHEN 'coalition'             THEN EXISTS (SELECT 1 FROM coalitions WHERE id = entity_id)
        WHEN 'node'                  THEN TRUE  -- no backing table; skip validation
        ELSE FALSE
    END;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- 5. Cascade delete triggers for new entity types
-- ============================================================================

CREATE TRIGGER propaganda_techniques_cascade_edges
    BEFORE DELETE ON propaganda_techniques
    FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('propaganda_technique');

CREATE TRIGGER coalitions_cascade_edges
    BEFORE DELETE ON coalitions
    FOR EACH ROW EXECUTE FUNCTION cascade_delete_edges('coalition');

-- ============================================================================
-- 6. Useful indexes for narrative propagation queries
-- ============================================================================

-- Fast lookup: all claims originated by an agent (Item 8: Genealogy)
CREATE INDEX IF NOT EXISTS idx_edges_originated_by
    ON edges(target_id, target_type)
    WHERE relationship = 'ORIGINATED_BY';

-- Fast lookup: all claims amplified by an agent (Item 8: Genealogy)
CREATE INDEX IF NOT EXISTS idx_edges_amplified_by
    ON edges(source_id, source_type)
    WHERE relationship = 'AMPLIFIED_BY';

-- Fast lookup: coordinated claim pairs (Item 7: Coalition Detector)
CREATE INDEX IF NOT EXISTS idx_edges_coordinated_with
    ON edges(source_id, target_id)
    WHERE relationship = 'COORDINATED_WITH';

-- Fast lookup: propaganda technique usage (Item 3: USES_TECHNIQUE)
CREATE INDEX IF NOT EXISTS idx_edges_uses_technique
    ON edges(source_id, target_id)
    WHERE relationship = 'USES_TECHNIQUE';

-- Fast lookup: coalition membership (Item 7)
CREATE INDEX IF NOT EXISTS idx_edges_member_of_coalition
    ON edges(target_id, target_type)
    WHERE relationship = 'MEMBER_OF' AND target_type = 'coalition';

-- Index on edges.properties for date-based queries on propagation edges
CREATE INDEX IF NOT EXISTS idx_edges_properties_date
    ON edges USING GIN (properties jsonb_path_ops);
