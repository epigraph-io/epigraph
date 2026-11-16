-- ===================================================================
-- 222-undo.sql: take migration 222 (cluster_centroids.umap_centroid) back out,
-- in ONE transaction, on the migration (superuser) DSN.
--
-- READ FIRST: ROLL scripts/cluster_claims.py BACK BEFORE THIS RUNS. A 222
-- script writes and reads only `umap_centroid`; after this undo it fails on the
-- missing column. A pre-222 script writes and reads the padded `centroid`.
--
-- WHAT IT DOES:
--   * re-pads every row written after 222 (centroid NULL) from umap_centroid,
--     the zero-padded 1536-d shape the pre-222 script wrote and reads back, so
--     `centroid` can be NOT NULL again;
--   * drops the CHECK cluster_centroids_has_a_centroid, restores
--     `centroid` NOT NULL and 001's empty column comment, and drops
--     `umap_centroid`.
--
-- WHAT IT LOSES AND LEAVES:
--   * nothing a pre-222 reader used: every row keeps a padded `centroid`;
--   * 222's `_sqlx_migrations` row. Re-introducing the column is a NEW
--     migration, never a re-run of 222.
-- Idempotent: a second run changes nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_attribute
                WHERE attrelid = 'public.cluster_centroids'::regclass
                  AND attname = 'umap_centroid' AND NOT attisdropped) THEN
        EXECUTE $q$
            UPDATE public.cluster_centroids
               SET centroid = (umap_centroid::real[]
                               || array_fill(0::real, ARRAY[1536 - 32]))::vector(1536)
             WHERE centroid IS NULL AND umap_centroid IS NOT NULL
        $q$;
    END IF;
END
$$;

ALTER TABLE public.cluster_centroids
    DROP CONSTRAINT IF EXISTS cluster_centroids_has_a_centroid;
ALTER TABLE public.cluster_centroids
    ALTER COLUMN centroid SET NOT NULL;
COMMENT ON COLUMN public.cluster_centroids.centroid IS NULL;
ALTER TABLE public.cluster_centroids
    DROP COLUMN IF EXISTS umap_centroid;

COMMIT;
