-- Migration: 001_create_extensions
-- Description: Enable required PostgreSQL extensions for EpiGraph
--
-- Extensions:
-- - vector (pgvector): For semantic embeddings and similarity search
-- - uuid-ossp: For UUID generation functions
--
-- Evidence:
-- - pgvector required for claim embeddings (1536-dim OpenAI vectors)
-- - uuid-ossp provides gen_random_uuid() and other UUID utilities
--
-- Reasoning:
-- - pgvector enables HNSW/IVFFlat indexing for fast vector similarity
-- - uuid-ossp is standard for UUID generation in PostgreSQL
--
-- Verification:
-- - Extensions can be created idempotently with IF NOT EXISTS
-- - No data dependencies (runs first)

-- Enable pgvector for embedding storage and similarity search
CREATE EXTENSION IF NOT EXISTS vector;

-- Enable uuid-ossp for UUID generation utilities
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
