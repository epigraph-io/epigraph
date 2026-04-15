-- Migration: Add 'figure' to evidence_type CHECK constraint
-- This allows storing figure/image evidence extracted from scientific PDFs.

ALTER TABLE evidence DROP CONSTRAINT IF EXISTS evidence_type_valid;
ALTER TABLE evidence ADD CONSTRAINT evidence_type_valid CHECK (
    evidence_type IN ('document', 'observation', 'testimony', 'computation', 'reference', 'figure')
);
