-- 222: cluster_centroids stores its UMAP centroid at the UMAP size (backlog
-- 58452334).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- `scripts/cluster_claims.py` fits UMAP(n_components=32) + k-means and stored
-- each 32-d centroid zero-padded into `cluster_centroids.centroid`, a
-- vector(1536) column (001) sized for raw claim embeddings. The dimensionality
-- was implicit: the reader sliced the first 32 elements back out, and nothing
-- in the schema said the trailing 1504 were padding. This adds a column of the
-- right size, `umap_centroid vector(32)`, backfills it from the padded rows,
-- and lets new rows leave `centroid` NULL. The script (same change) writes and
-- reads only `umap_centroid`.
--
-- `cluster_claims.py` is the only writer and the only reader of
-- `cluster_centroids.centroid` in the tree (`project_to_themes.py` reads the
-- table's run ids only and computes true 1536-d theme centroids from claim
-- embeddings). No index exists on the column.
--
-- ===================================================================
-- 1. WHAT IT DOES
-- ===================================================================
--
--   * ADD COLUMN umap_centroid vector(32) (nullable);
--   * backfill: a row whose `centroid` elements 33..1536 are all zero (a padded
--     32-d centroid, the only shape the script ever wrote) gets its first 32
--     elements. A row with a non-zero tail is NOT a padded UMAP centroid; it
--     is left with umap_centroid NULL rather than truncated, and the script
--     refuses to load a run holding one;
--   * `centroid` DROP NOT NULL (new rows store only umap_centroid) and is kept
--     with its old values: it is legacy, has no writer after this change, and
--     is left for the undo and for a later migration to drop;
--   * CHECK cluster_centroids_has_a_centroid: every row keeps at least one.
--
-- No tenancy change: cluster_centroids is not in 062's tier_a and carries no
-- policy; the column inherits the table-level grants 118 set (SCRIPT_UPSERT in
-- app_role_table_lockdown.rs).
--
-- Idempotent (re-running changes nothing), so the undo test can re-apply it.
--
-- DEPLOY CENSUS (read-only; run before, compare after). Not measured on any
-- deployed database:
--   SELECT count(*) AS rows,
--          count(*) FILTER (WHERE EXISTS (
--            SELECT 1 FROM unnest((centroid::real[])[33:1536]) AS t(x)
--            WHERE x <> 0)) AS non_zero_tail
--     FROM public.cluster_centroids;
-- After: umap_centroid IS NULL on exactly `non_zero_tail` rows.
--
-- Undo: docs/runbooks/222-undo.sql.

ALTER TABLE public.cluster_centroids
    ADD COLUMN IF NOT EXISTS umap_centroid vector(32);

UPDATE public.cluster_centroids
   SET umap_centroid = ((centroid::real[])[1:32])::vector(32)
 WHERE umap_centroid IS NULL
   AND centroid IS NOT NULL
   AND NOT EXISTS (
         SELECT 1 FROM unnest((centroid::real[])[33:1536]) AS t(x)
          WHERE x <> 0);

ALTER TABLE public.cluster_centroids
    ALTER COLUMN centroid DROP NOT NULL;

ALTER TABLE public.cluster_centroids
    DROP CONSTRAINT IF EXISTS cluster_centroids_has_a_centroid;
ALTER TABLE public.cluster_centroids
    ADD CONSTRAINT cluster_centroids_has_a_centroid
    CHECK (umap_centroid IS NOT NULL OR centroid IS NOT NULL);

COMMENT ON COLUMN public.cluster_centroids.umap_centroid IS
    'k-means centroid in the 32-d UMAP space of scripts/cluster_claims.py (migration 222).';
COMMENT ON COLUMN public.cluster_centroids.centroid IS
    'LEGACY (migration 222): the same 32-d UMAP centroid zero-padded to 1536; no writer. Read umap_centroid.';
