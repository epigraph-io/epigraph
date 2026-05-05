-- migrations/027_centroids_3072d.sql
-- Adds 3072-dimensional centroid columns alongside the existing 1536d
-- columns. NEW columns; no ALTER TYPE on existing columns to avoid HNSW
-- index rebuild. The legacy 1536d columns remain populated and queried
-- until the operator runs the reembed CLI and switches callers via
-- the centroid_dim query parameter.

ALTER TABLE claim_themes      ADD COLUMN centroid_3072 vector(3072);
ALTER TABLE cluster_centroids ADD COLUMN centroid_3072 vector(3072);
ALTER TABLE claims            ADD COLUMN embedding_3072 vector(3072);
ALTER TABLE evidence          ADD COLUMN embedding_3072 vector(3072);

-- No HNSW indexes on 3072d columns initially. Theme/cluster counts are
-- small enough that seq-scan (<5ms for 10² centroids) is acceptable.
-- For claims/evidence at scale, revisit if recall/latency demands.
