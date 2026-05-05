-- 027_graph_cluster_runs_algo.sql
-- Adds an `algo` discriminator column to `graph_cluster_runs` so that we can
-- have multiple parallel clustering algorithms (epistemic edges vs. structural
-- bridges) co-existing without colliding on retention/GC.
--
-- Existing runs are produced by the nightly `cluster_graph` job which runs
-- Louvain over SUPPORTS / CONTRADICTS edges; back-fill them as 'louvain'.
--
-- Phase 5.B introduces 'louvain_bridge' for paragraphs (level=2) clustered by
-- decomposes_to atom-sharing.

ALTER TABLE graph_cluster_runs
    ADD COLUMN IF NOT EXISTS algo TEXT NOT NULL DEFAULT 'louvain';

CREATE INDEX IF NOT EXISTS graph_cluster_runs_algo_completed_idx
    ON graph_cluster_runs (algo, completed_at DESC);
