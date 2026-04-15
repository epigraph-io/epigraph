-- Migration: 010_add_evidence_embedding
-- Description: Add vector embedding column to evidence table for semantic search
--
-- Evidence:
-- - LLM_ENRICHMENT_PLAN.md Phase 5.2 specifies evidence-level embedding
-- - Claims table already uses pgvector for embedding (003_create_claims.sql)
-- - Same dimension (1536) as claim embeddings for consistency
--
-- Reasoning:
-- - Enables evidence-level semantic search ("find evidence mentioning X")
-- - Uses same vector dimension as claims for embedding model consistency
-- - Nullable: existing evidence rows won't have embeddings initially
-- - HNSW index for fast approximate nearest neighbor search
--
-- Verification:
-- - Column is nullable (backwards compatible with existing data)
-- - pgvector extension already enabled in 001_create_extensions.sql
-- - Index type matches claims table pattern

-- Add embedding column for vector similarity search
ALTER TABLE evidence ADD COLUMN embedding vector(1536);

-- HNSW index for fast cosine-distance nearest neighbor search
-- Uses same operator class as claims.embedding index
CREATE INDEX idx_evidence_embedding
    ON evidence
    USING hnsw (embedding vector_cosine_ops)
    WHERE embedding IS NOT NULL;
