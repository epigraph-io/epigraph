-- 093_business_function_entity_type.sql
-- Add BusinessFunction to entity type_top and 'entity' to edges type constraints
-- for corporate governance GOVERNS edges (claim -> entity).

-- 1. Extend entities type_top to include BusinessFunction
ALTER TABLE entities DROP CONSTRAINT entities_type_top_valid;
ALTER TABLE entities ADD CONSTRAINT entities_type_top_valid
  CHECK (type_top IN (
    'Material', 'Molecule', 'Method', 'Instrument', 'Property',
    'Measurement', 'Condition', 'Organism', 'Software',
    'Person', 'Organization', 'Location', 'Concept',
    'BusinessFunction'
  ));

-- 3. Add 'entity' branch to validate_edge_reference trigger function
--    Required for GOVERNS edges: source_type='claim', target_type='entity'
CREATE OR REPLACE FUNCTION validate_edge_reference(entity_id uuid, entity_type character varying)
RETURNS boolean
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
        WHEN 'span'                  THEN EXISTS (SELECT 1 FROM agent_spans WHERE id = entity_id)
        WHEN 'entity'                THEN EXISTS (SELECT 1 FROM entities WHERE id = entity_id)
        WHEN 'node'                  THEN TRUE
        ELSE FALSE
    END;
END;
$$;

-- 2. Extend edges source_type/target_type to include 'entity'
-- Needed for GOVERNS edges: claim -> entity (BusinessFunction node)
ALTER TABLE edges DROP CONSTRAINT edges_entity_types_valid;
ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid
  CHECK (
    source_type = ANY(ARRAY[
      'claim', 'agent', 'evidence', 'trace', 'node', 'activity',
      'paper', 'perspective', 'community', 'context', 'frame',
      'analysis', 'source_artifact', 'span',
      'entity'
    ])
    AND
    target_type = ANY(ARRAY[
      'claim', 'agent', 'evidence', 'trace', 'node', 'activity',
      'paper', 'perspective', 'community', 'context', 'frame',
      'analysis', 'source_artifact', 'span',
      'entity'
    ])
  );
