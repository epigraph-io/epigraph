-- Migration 019: admit 'experiment' / 'experiment_result' to edges entity-type constraints (#38)
--
-- The experiments and experiment_results tables exist with proper PKs, FKs,
-- CHECKs, and cascade_delete_edges triggers. They participate in first-class
-- edge relationships:
--     experiment        --tests_hypothesis--> claim
--     experiment_result --result_of-->        experiment
--     analysis          --analyzes-->         experiment_result
--
-- But the edges_entity_types_valid CHECK (last redefined in migration 005) and
-- both validate_edge_reference(...) trigger overloads do not list
-- 'experiment' or 'experiment_result' in their allow-lists. The schema
-- advertises a contract it doesn't enforce. This was discovered while
-- preparing migration 020 (workflows table for #34), whose ADD CONSTRAINT
-- step failed because of pre-existing rows the CHECK never permitted.
--
-- This migration formalizes what the schema already supports. No data
-- changes — only constraint and trigger-function definitions.

-- Step 1: rebuild edges_entity_types_valid with experiment + experiment_result
ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid;
ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid CHECK (
    (source_type::text = ANY (ARRAY[
        'claim', 'agent', 'evidence', 'trace', 'node', 'activity', 'paper',
        'perspective', 'community', 'context', 'frame', 'analysis',
        'source_artifact', 'span', 'entity', 'task', 'event',
        'experiment', 'experiment_result'
    ]))
    AND
    (target_type::text = ANY (ARRAY[
        'claim', 'agent', 'evidence', 'trace', 'node', 'activity', 'paper',
        'perspective', 'community', 'context', 'frame', 'analysis',
        'source_artifact', 'span', 'entity', 'task', 'event',
        'experiment', 'experiment_result'
    ]))
);

-- Step 2: replace BOTH overloads of validate_edge_reference with the missing branches
CREATE OR REPLACE FUNCTION validate_edge_reference(entity_type TEXT, entity_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN CASE entity_type
        WHEN 'claim'              THEN EXISTS (SELECT 1 FROM claims WHERE id = entity_id)
        WHEN 'agent'              THEN EXISTS (SELECT 1 FROM agents WHERE id = entity_id)
        WHEN 'evidence'           THEN EXISTS (SELECT 1 FROM evidence WHERE id = entity_id)
        WHEN 'trace'              THEN EXISTS (SELECT 1 FROM reasoning_traces WHERE id = entity_id)
        WHEN 'paper'              THEN EXISTS (SELECT 1 FROM papers WHERE id = entity_id)
        WHEN 'analysis'           THEN EXISTS (SELECT 1 FROM analyses WHERE id = entity_id)
        WHEN 'activity'           THEN EXISTS (SELECT 1 FROM activities WHERE id = entity_id)
        WHEN 'source_artifact'    THEN EXISTS (SELECT 1 FROM source_artifacts WHERE id = entity_id)
        WHEN 'span'               THEN EXISTS (SELECT 1 FROM agent_spans WHERE id = entity_id)
        WHEN 'entity'             THEN EXISTS (SELECT 1 FROM entities WHERE id = entity_id)
        WHEN 'task'               THEN EXISTS (SELECT 1 FROM tasks WHERE id = entity_id)
        WHEN 'event'              THEN EXISTS (SELECT 1 FROM events WHERE id = entity_id)
        WHEN 'experiment'         THEN EXISTS (SELECT 1 FROM experiments WHERE id = entity_id)
        WHEN 'experiment_result'  THEN EXISTS (SELECT 1 FROM experiment_results WHERE id = entity_id)
        WHEN 'node'               THEN TRUE
        ELSE FALSE
    END;
END;
$$;

CREATE OR REPLACE FUNCTION validate_edge_reference(entity_id UUID, entity_type CHARACTER VARYING)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN CASE entity_type
        WHEN 'claim'              THEN EXISTS (SELECT 1 FROM claims WHERE id = entity_id)
        WHEN 'agent'              THEN EXISTS (SELECT 1 FROM agents WHERE id = entity_id)
        WHEN 'evidence'           THEN EXISTS (SELECT 1 FROM evidence WHERE id = entity_id)
        WHEN 'trace'              THEN EXISTS (SELECT 1 FROM reasoning_traces WHERE id = entity_id)
        WHEN 'paper'              THEN EXISTS (SELECT 1 FROM papers WHERE id = entity_id)
        WHEN 'analysis'           THEN EXISTS (SELECT 1 FROM analyses WHERE id = entity_id)
        WHEN 'activity'           THEN EXISTS (SELECT 1 FROM activities WHERE id = entity_id)
        WHEN 'source_artifact'    THEN EXISTS (SELECT 1 FROM source_artifacts WHERE id = entity_id)
        WHEN 'span'               THEN EXISTS (SELECT 1 FROM agent_spans WHERE id = entity_id)
        WHEN 'entity'             THEN EXISTS (SELECT 1 FROM entities WHERE id = entity_id)
        WHEN 'task'               THEN EXISTS (SELECT 1 FROM tasks WHERE id = entity_id)
        WHEN 'event'              THEN EXISTS (SELECT 1 FROM events WHERE id = entity_id)
        WHEN 'experiment'         THEN EXISTS (SELECT 1 FROM experiments WHERE id = entity_id)
        WHEN 'experiment_result'  THEN EXISTS (SELECT 1 FROM experiment_results WHERE id = entity_id)
        WHEN 'node'               THEN TRUE
        ELSE FALSE
    END;
END;
$$;
