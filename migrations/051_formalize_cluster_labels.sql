-- Formalize the cluster_labels table (present in prod, absent from migrations)
-- and add the cluster-run grouping index used by discover/projection queries.
-- IF NOT EXISTS makes this idempotent against DBs where it already drifted in.

CREATE TABLE IF NOT EXISTS cluster_labels (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    cluster_run_id uuid NOT NULL,
    cluster_id integer NOT NULL,
    label text NOT NULL,
    sample_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT cluster_labels_pkey PRIMARY KEY (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS cluster_labels_run_cluster_key
    ON cluster_labels (cluster_run_id, cluster_id);

CREATE INDEX IF NOT EXISTS claim_clusters_run_cluster_idx
    ON claim_clusters (cluster_run_id, cluster_id);
