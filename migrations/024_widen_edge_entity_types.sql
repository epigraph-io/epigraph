-- Migration: 024_widen_edge_entity_types
-- Description: Expand edges CHECK constraint to allow DEKG entity types
--
-- Evidence:
-- - Phase 3-4 introduced perspectives, communities, contexts, frames as first-class entities
-- - Phase 6 materializes PERSPECTIVE_OF, MEMBER_OF, WITHIN_FRAME edges
-- - Runtime ALTER TABLE confirmed these edges work correctly (E2E tests pass)
-- - Original constraint in 006 only allowed: claim, agent, evidence, trace, node
--
-- Reasoning:
-- - Planning doc §1.2 requires 10 edge types including PERSPECTIVE_OF, MEMBER_OF, WITHIN_FRAME
-- - These edges need source/target types beyond the original 5
-- - Adding activity, paper, perspective, community, context, frame covers all DEKG entities
--
-- Verification:
-- - E2E tests confirm PERSPECTIVE_OF (perspective→agent), MEMBER_OF (perspective→community),
--   WITHIN_FRAME (claim→frame) edges created successfully after constraint update

ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid;

ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid CHECK (
    source_type IN ('claim', 'agent', 'evidence', 'trace', 'node', 'activity', 'paper', 'perspective', 'community', 'context', 'frame') AND
    target_type IN ('claim', 'agent', 'evidence', 'trace', 'node', 'activity', 'paper', 'perspective', 'community', 'context', 'frame')
);
