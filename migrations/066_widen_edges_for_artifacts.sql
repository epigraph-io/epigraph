-- migrations/066_widen_edges_for_artifacts.sql
-- Add 'source_artifact' to the edges entity type CHECK constraint
-- and update the referential integrity trigger to validate against source_artifacts table.

-- 1. Widen the CHECK constraint
ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid;

ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid CHECK (
    source_type IN (
        'claim', 'agent', 'evidence', 'trace', 'node',
        'activity', 'paper', 'perspective', 'community', 'context', 'frame',
        'analysis', 'experiment', 'experiment_result',
        'propaganda_technique', 'coalition', 'source_artifact'
    ) AND
    target_type IN (
        'claim', 'agent', 'evidence', 'trace', 'node',
        'activity', 'paper', 'perspective', 'community', 'context', 'frame',
        'analysis', 'experiment', 'experiment_result',
        'propaganda_technique', 'coalition', 'source_artifact'
    )
);

-- 2. Update referential integrity trigger to validate source_artifact references
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
        WHEN 'node'                  THEN TRUE
        ELSE FALSE
    END;
END;
$$ LANGUAGE plpgsql STABLE;
