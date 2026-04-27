-- Tables for community-detection results computed offline by
-- scripts/cluster_graph.py (Leiden / Louvain on the claim↔claim edge graph).
--
-- One `graph_community_runs` row per execution; assignments and labels are
-- keyed off `run_id` so multiple runs can coexist (the API exposes the most
-- recent one by default).

CREATE TABLE IF NOT EXISTS graph_community_runs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    algorithm       text NOT NULL,                 -- 'leiden' | 'louvain' | ...
    edge_filter     text NOT NULL DEFAULT 'all',   -- describes which relationships were considered
    n_nodes         integer NOT NULL,
    n_edges         integer NOT NULL,
    n_communities   integer NOT NULL,
    modularity      double precision,
    generated_at    timestamptz NOT NULL DEFAULT now(),
    notes           text
);

CREATE TABLE IF NOT EXISTS graph_communities (
    run_id        uuid NOT NULL REFERENCES graph_community_runs(id) ON DELETE CASCADE,
    claim_id      uuid NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    community_id  integer NOT NULL,
    PRIMARY KEY (run_id, claim_id)
);

CREATE INDEX IF NOT EXISTS idx_graph_communities_run_community
    ON graph_communities (run_id, community_id);

CREATE TABLE IF NOT EXISTS graph_community_labels (
    run_id        uuid NOT NULL REFERENCES graph_community_runs(id) ON DELETE CASCADE,
    community_id  integer NOT NULL,
    label         text NOT NULL,
    size          integer NOT NULL,
    -- Optional: the dominant claim_theme.id within this community (NULL if unknown).
    dominant_theme_id uuid REFERENCES claim_themes(id),
    PRIMARY KEY (run_id, community_id)
);
