-- Migration: 007_create_indexes
-- Description: Create performance indexes for EpiGraph queries
--
-- This migration adds specialized indexes that were deferred from earlier
-- migrations, particularly the vector similarity index which requires
-- populated data for optimal configuration.
--
-- Evidence:
-- - IMPLEMENTATION_PLAN.md §Performance Considerations specifies indexing strategy
-- - HNSW index recommended for vector similarity (faster than IVFFlat for < 1M vectors)
-- - Composite indexes improve multi-column query performance
--
-- Reasoning:
-- - HNSW index on embeddings enables fast approximate nearest neighbor search
-- - Composite indexes support common query patterns (e.g., agent claims sorted by truth)
-- - Partial indexes reduce index size for filtered queries
-- - GIN indexes already created in previous migrations
--
-- Verification:
-- - Vector index creation succeeds (requires pgvector extension)
-- - All indexes use appropriate index types for their data

-- ============================================================================
-- VECTOR SIMILARITY INDEXES
-- ============================================================================

-- HNSW index for vector similarity search on claim embeddings
--
-- HNSW (Hierarchical Navigable Small World) provides fast approximate
-- nearest neighbor search. Configuration:
-- - m = 16: number of connections per layer (default, good for most cases)
-- - ef_construction = 64: size of dynamic candidate list (higher = better recall, slower build)
--
-- Reasoning for HNSW over IVFFlat:
-- - Better query performance for datasets < 1M vectors
-- - No need for training data or list parameter tuning
-- - Simpler to maintain and more predictable performance
--
-- Note: For very large datasets (> 1M claims), consider switching to IVFFlat
-- with appropriate list parameter (sqrt(num_rows) is typical).

CREATE INDEX idx_claims_embedding_hnsw ON claims
USING hnsw (embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64)
WHERE embedding IS NOT NULL;

-- ============================================================================
-- COMPOSITE INDEXES FOR COMMON QUERY PATTERNS
-- ============================================================================

-- Agent claims sorted by truth value (for reputation calculation)
CREATE INDEX idx_claims_agent_truth ON claims(agent_id, truth_value DESC);

-- Agent claims sorted by creation time
CREATE INDEX idx_claims_agent_created ON claims(agent_id, created_at DESC);

-- High-truth claims for verified queries (partial index)
-- Only indexes claims with truth_value >= 0.7 (reduces index size)
CREATE INDEX idx_claims_high_truth ON claims(truth_value DESC)
WHERE truth_value >= 0.7;

-- Low-truth claims for flagged/disputed queries (partial index)
CREATE INDEX idx_claims_low_truth ON claims(truth_value ASC)
WHERE truth_value <= 0.3;

-- Claims with embeddings and high truth (for RAG queries)
CREATE INDEX idx_claims_verified_with_embedding ON claims(truth_value DESC, created_at DESC)
WHERE embedding IS NOT NULL AND truth_value >= 0.7;

-- ============================================================================
-- EVIDENCE COMPOSITE INDEXES
-- ============================================================================

-- Evidence by claim and signer (for provenance queries)
CREATE INDEX idx_evidence_claim_signer ON evidence(claim_id, signer_id)
WHERE signer_id IS NOT NULL;

-- Signed evidence only (partial index)
CREATE INDEX idx_evidence_signed ON evidence(created_at DESC)
WHERE signature IS NOT NULL;

-- ============================================================================
-- REASONING TRACE COMPOSITE INDEXES
-- ============================================================================

-- Traces by claim and type (for methodology analysis)
CREATE INDEX idx_traces_claim_type ON reasoning_traces(claim_id, reasoning_type);

-- High-confidence traces (partial index)
CREATE INDEX idx_traces_high_confidence ON reasoning_traces(confidence DESC)
WHERE confidence >= 0.7;

-- ============================================================================
-- PERFORMANCE STATISTICS
-- ============================================================================

-- Analyze all tables to update query planner statistics
ANALYZE agents;
ANALYZE claims;
ANALYZE evidence;
ANALYZE reasoning_traces;
ANALYZE trace_parents;
ANALYZE edges;

-- ============================================================================
-- INDEX MONITORING QUERIES (for future optimization)
-- ============================================================================

-- Uncomment to check index usage:
-- SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
-- FROM pg_stat_user_indexes
-- WHERE schemaname = 'public'
-- ORDER BY idx_scan ASC;

-- Uncomment to check table sizes:
-- SELECT
--     tablename,
--     pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
-- FROM pg_tables
-- WHERE schemaname = 'public'
-- ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Comment for future developers
COMMENT ON INDEX idx_claims_embedding_hnsw IS
'HNSW index for fast vector similarity search. For datasets > 1M claims, '
'consider migrating to IVFFlat with lists = sqrt(num_rows). Monitor query '
'performance with EXPLAIN ANALYZE on semantic search queries.';
