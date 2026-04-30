-- migrations/024_graph_neighborhoods.sql
-- Per-theme Louvain communities for the graph visualizer drilldown.
--
-- NUMBERING NOTE (2026-04-30): the live production DB tracks migrations
-- through a separate `_sqlx_migrations` table (numeric IDs, descriptive
-- names) that diverges from the file-based 001-023 lineage in this repo.
-- This migration is numbered 024 to follow the file-based lineage; when
-- this branch is merged and the live DB is reconciled with file-based
-- migrations, this file may need to be renumbered (or wrapped in an
-- equivalent _sqlx_migrations entry) to land cleanly on production.

CREATE TABLE IF NOT EXISTS graph_neighborhoods (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id              UUID NOT NULL REFERENCES graph_cluster_runs(run_id) ON DELETE CASCADE,
    theme_id            UUID NOT NULL REFERENCES claim_themes(id) ON DELETE CASCADE,
    label               TEXT NOT NULL,
    size                INTEGER NOT NULL,
    mean_betp           DOUBLE PRECISION,
    dominant_frame_id   UUID,
    generated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_graph_neighborhoods_run_theme
    ON graph_neighborhoods(run_id, theme_id);

CREATE TABLE IF NOT EXISTS claim_neighborhood_membership (
    run_id              UUID NOT NULL,
    claim_id            UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    neighborhood_id     UUID NOT NULL REFERENCES graph_neighborhoods(id) ON DELETE CASCADE,
    PRIMARY KEY (run_id, claim_id)
);

CREATE INDEX IF NOT EXISTS idx_claim_neighborhood_membership_run_neighborhood
    ON claim_neighborhood_membership(run_id, neighborhood_id);

CREATE TABLE IF NOT EXISTS neighborhood_edges (
    run_id              UUID NOT NULL,
    neighborhood_a      UUID NOT NULL REFERENCES graph_neighborhoods(id) ON DELETE CASCADE,
    neighborhood_b      UUID NOT NULL REFERENCES graph_neighborhoods(id) ON DELETE CASCADE,
    weight              DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (run_id, neighborhood_a, neighborhood_b),
    CHECK (neighborhood_a < neighborhood_b)
);
