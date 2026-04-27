-- 015_graph_clusters.sql
-- Tables produced by the nightly cluster_graph job.

CREATE TABLE IF NOT EXISTS graph_clusters (
    id                 UUID PRIMARY KEY,
    run_id             UUID NOT NULL,
    label              TEXT NOT NULL,
    size               INTEGER NOT NULL,
    mean_betp          DOUBLE PRECISION,
    dominant_type      TEXT,
    dominant_frame_id  UUID,
    degraded           BOOLEAN NOT NULL DEFAULT FALSE,
    generated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS graph_clusters_run_id_idx
    ON graph_clusters (run_id);
CREATE INDEX IF NOT EXISTS graph_clusters_generated_at_idx
    ON graph_clusters (generated_at DESC);

CREATE TABLE IF NOT EXISTS claim_cluster_membership (
    claim_id    UUID NOT NULL,
    cluster_id  UUID NOT NULL REFERENCES graph_clusters(id) ON DELETE CASCADE,
    run_id      UUID NOT NULL,
    PRIMARY KEY (claim_id, run_id)
);

CREATE INDEX IF NOT EXISTS claim_cluster_membership_cluster_idx
    ON claim_cluster_membership (cluster_id);
CREATE INDEX IF NOT EXISTS claim_cluster_membership_run_idx
    ON claim_cluster_membership (run_id);

CREATE TABLE IF NOT EXISTS cluster_edges (
    run_id     UUID NOT NULL,
    cluster_a  UUID NOT NULL,
    cluster_b  UUID NOT NULL,
    weight     INTEGER NOT NULL,
    PRIMARY KEY (run_id, cluster_a, cluster_b),
    CHECK (cluster_a < cluster_b)
);

-- Tracks which run is the latest *successful* run for /overview to read.
CREATE TABLE IF NOT EXISTS graph_cluster_runs (
    run_id        UUID PRIMARY KEY,
    completed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cluster_count INTEGER NOT NULL,
    degraded      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS graph_cluster_runs_completed_idx
    ON graph_cluster_runs (completed_at DESC);
