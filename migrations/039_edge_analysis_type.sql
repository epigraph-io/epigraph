-- Add 'analysis' as a valid entity type in edges
-- Required for Evidence→Analysis→Claim pathway (migration 037)

ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid;
ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid CHECK (
    source_type IN ('claim', 'agent', 'evidence', 'trace', 'node', 'paper', 'analysis')
    AND target_type IN ('claim', 'agent', 'evidence', 'trace', 'node', 'paper', 'analysis')
);
