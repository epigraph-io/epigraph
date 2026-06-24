-- 050_claims_content_tsv.sql
-- Reconcile the `content_tsv` generated column + its GIN index into version
-- control. Both already exist on prod (added manually, never migrated); this
-- records them so fresh DBs (sqlx::test, new deploys) are reproducible.
-- IF NOT EXISTS makes it a no-op where they already exist.
ALTER TABLE claims
  ADD COLUMN IF NOT EXISTS content_tsv tsvector
  GENERATED ALWAYS AS (to_tsvector('english', content)) STORED;

CREATE INDEX IF NOT EXISTS idx_claims_content_tsv
  ON claims USING gin (content_tsv);
