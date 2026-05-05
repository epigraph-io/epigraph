-- Partial HNSW index on level=2 (paragraph) claims for recall_with_context kNN.
-- Spec §3.3. The 3072d path stays seq-scan (paragraph counts ≤10^4).
CREATE INDEX IF NOT EXISTS idx_claims_paragraph_embedding
    ON claims USING hnsw (embedding vector_cosine_ops)
    WITH (m=16, ef_construction=64)
    WHERE (properties->>'level')::int = 2 AND embedding IS NOT NULL;
