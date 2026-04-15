-- Migration 095: add 'task' and 'event' to edges type constraint and referential trigger
-- Required for governance bridge TRIGGERED_BY (task→event) and PROVENANCE (task→claim) edges

-- Step 1: Drop the existing CHECK constraint
ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid;

-- Step 2: Re-create with 'task' and 'event' added to both source_type and target_type
ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid CHECK (
    (source_type::text = ANY (ARRAY[
        'claim', 'agent', 'evidence', 'trace', 'node', 'activity', 'paper',
        'perspective', 'community', 'context', 'frame', 'analysis', 'experiment',
        'experiment_result', 'propaganda_technique', 'coalition', 'source_artifact',
        'span', 'entity', 'task', 'event'
    ]))
    AND
    (target_type::text = ANY (ARRAY[
        'claim', 'agent', 'evidence', 'trace', 'node', 'activity', 'paper',
        'perspective', 'community', 'context', 'frame', 'analysis', 'experiment',
        'experiment_result', 'propaganda_technique', 'coalition', 'source_artifact',
        'span', 'entity', 'task', 'event'
    ]))
);

-- Step 3: Replace BOTH overloads of validate_edge_reference with task and event branches
-- The trigger calls (uuid, varchar) overload; there's also a (text, uuid) overload.
-- Both must be updated.

CREATE OR REPLACE FUNCTION validate_edge_reference(entity_type TEXT, entity_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
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
        WHEN 'entity'                THEN EXISTS (SELECT 1 FROM entities WHERE id = entity_id)
        WHEN 'task'                  THEN EXISTS (SELECT 1 FROM tasks WHERE id = entity_id)
        WHEN 'event'                 THEN EXISTS (SELECT 1 FROM events WHERE id = entity_id)
        WHEN 'node'                  THEN TRUE
        ELSE FALSE
    END;
END;
$$;

-- The trigger actually calls the (uuid, varchar) overload, so update that too
CREATE OR REPLACE FUNCTION validate_edge_reference(entity_id UUID, entity_type CHARACTER VARYING)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
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
        WHEN 'entity'                THEN EXISTS (SELECT 1 FROM entities WHERE id = entity_id)
        WHEN 'task'                  THEN EXISTS (SELECT 1 FROM tasks WHERE id = entity_id)
        WHEN 'event'                 THEN EXISTS (SELECT 1 FROM events WHERE id = entity_id)
        WHEN 'node'                  THEN TRUE
        ELSE FALSE
    END;
END;
$$;
