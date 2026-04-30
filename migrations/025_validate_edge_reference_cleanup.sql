-- Migration 025: validate_edge_reference cleanup
--
-- Two cleanups in one:
--   1. Drop the unused (text, uuid) overload — only (uuid, varchar) is invoked
--      from trigger_validate_edge_refs and from any Rust callsite (#41).
--   2. Add the missing perspective / community / context / frame branches so
--      the function aligns with the edges_entity_types_valid CHECK constraint
--      (#40).
--
-- Drops a function used by zero callers; idempotent on a DB where the function
-- has already been removed (DROP FUNCTION IF EXISTS).

DROP FUNCTION IF EXISTS validate_edge_reference(text, uuid);

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
        WHEN 'workflow'           THEN EXISTS (SELECT 1 FROM workflows WHERE id = entity_id)
        WHEN 'perspective'        THEN EXISTS (SELECT 1 FROM perspectives WHERE id = entity_id)
        WHEN 'community'          THEN EXISTS (SELECT 1 FROM communities WHERE id = entity_id)
        WHEN 'context'            THEN EXISTS (SELECT 1 FROM contexts WHERE id = entity_id)
        WHEN 'frame'              THEN EXISTS (SELECT 1 FROM frames WHERE id = entity_id)
        WHEN 'node'               THEN TRUE
        ELSE FALSE
    END;
END;
$$;
