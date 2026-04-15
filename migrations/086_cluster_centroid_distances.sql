-- Create claim_clusters if it doesn't exist yet.
-- This table was originally created outside of migrations; this migration
-- previously assumed the table existed and only added centroid_distances.
-- Making the CREATE idempotent ensures a clean DB can apply all migrations.
CREATE TABLE IF NOT EXISTS claim_clusters (
    claim_id             UUID        PRIMARY KEY REFERENCES claims(id) ON DELETE CASCADE,
    cluster_id           INT         NOT NULL,
    cluster_run_id       UUID        NOT NULL,
    centroid_distance    DOUBLE PRECISION,
    second_centroid_dist DOUBLE PRECISION,
    boundary_ratio       DOUBLE PRECISION,
    silhouette_score     DOUBLE PRECISION,
    computed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_claim_clusters_cluster_id ON claim_clusters(cluster_id);
CREATE INDEX IF NOT EXISTS idx_claim_clusters_run       ON claim_clusters(cluster_run_id);

-- Add centroid_distances array: distance from each claim to EVERY centroid,
-- giving a k-dimensional coordinate vector in centroid space.
ALTER TABLE claim_clusters
    ADD COLUMN IF NOT EXISTS centroid_distances double precision[];

-- Centroid vectors: one row per centroid per run.
CREATE TABLE IF NOT EXISTS cluster_centroids (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_run_id  UUID NOT NULL,
    cluster_id      INT NOT NULL,
    centroid        vector(1536) NOT NULL,
    claim_count     INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(cluster_run_id, cluster_id)
);

CREATE INDEX IF NOT EXISTS idx_cluster_centroids_run ON cluster_centroids(cluster_run_id);
