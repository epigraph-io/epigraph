-- Migration 020: workflows table + edges constraint expansion + trigger update for #34
--
-- Adds the `workflows` source-node type as the metadata anchor for hierarchical
-- workflows (parallel to `papers`). Expands the edges_entity_types_valid CHECK
-- and both validate_edge_reference overloads so workflow→claim edges (executes,
-- supersedes, variant_of) can be inserted.
--
-- Depends on migration 019 (experiment edge-type fix). The constraint and
-- trigger function definitions here include 'experiment' and 'experiment_result'
-- in their allow-lists because 019 introduced them; this migration extends the
-- list with 'workflow'.

-- Step 1: workflows table (parallel to papers)
CREATE TABLE workflows (
    id              uuid PRIMARY KEY,
    canonical_name  text NOT NULL,
    generation      integer NOT NULL DEFAULT 0,
    goal            text NOT NULL,
    parent_id       uuid REFERENCES workflows(id),
    metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (canonical_name, generation)
);
CREATE INDEX workflows_canonical_name_idx ON workflows (canonical_name);
CREATE INDEX workflows_goal_trgm_idx ON workflows USING gin (goal gin_trgm_ops);

-- Step 2: extend edges_entity_types_valid CHECK with 'workflow'
ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid;
ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid CHECK (
    (source_type::text = ANY (ARRAY[
        'claim', 'agent', 'evidence', 'trace', 'node', 'activity', 'paper',
        'perspective', 'community', 'context', 'frame', 'analysis',
        'source_artifact', 'span', 'entity', 'task', 'event',
        'experiment', 'experiment_result', 'workflow'
    ]))
    AND
    (target_type::text = ANY (ARRAY[
        'claim', 'agent', 'evidence', 'trace', 'node', 'activity', 'paper',
        'perspective', 'community', 'context', 'frame', 'analysis',
        'source_artifact', 'span', 'entity', 'task', 'event',
        'experiment', 'experiment_result', 'workflow'
    ]))
);

-- Step 3: replace BOTH overloads of validate_edge_reference with the workflow branch
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
        WHEN 'workflow'           THEN EXISTS (SELECT 1 FROM workflows WHERE id = entity_id)
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
        WHEN 'workflow'           THEN EXISTS (SELECT 1 FROM workflows WHERE id = entity_id)
        WHEN 'node'               THEN TRUE
        ELSE FALSE
    END;
END;
$$;
