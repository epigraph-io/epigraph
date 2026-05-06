-- Partial HNSW index on level=3 (atom) claims for cross-component bridge
-- sweep (issue #53). Bridge candidates are atom-to-atom; paragraph-level
-- partial index from migration 029 is non-overlapping. 3072d path stays
-- seq-scan (atom counts ≤ ~150k; HNSW build cost not justified for the
-- second column).
--
-- Expected sequential build duration: 5-15 minutes on a 150k-atom corpus
-- with m=16, ef_construction=64. Holds ACCESS EXCLUSIVE on `claims` for
-- the duration. Operators who can't tolerate the lock should skip this
-- migration in `sqlx migrate run`, then apply manually with:
--   psql -c "CREATE INDEX CONCURRENTLY idx_claims_atom_embedding ..."
-- and stamp `_sqlx_migrations` after.
CREATE INDEX IF NOT EXISTS idx_claims_atom_embedding
    ON claims USING hnsw (embedding vector_cosine_ops)
    WITH (m=16, ef_construction=64)
    WHERE (properties->>'level')::int = 3 AND embedding IS NOT NULL;
