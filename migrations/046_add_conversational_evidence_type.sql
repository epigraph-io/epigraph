-- Migration 046: Add 'conversational' to evidence_type CHECK constraint
-- Supports epistemic session compaction — claims extracted from agent conversations.

ALTER TABLE evidence DROP CONSTRAINT IF EXISTS evidence_type_valid;
ALTER TABLE evidence ADD CONSTRAINT evidence_type_valid CHECK (
    evidence_type IN ('document', 'observation', 'testimony', 'computation', 'reference', 'figure', 'conversational')
);
