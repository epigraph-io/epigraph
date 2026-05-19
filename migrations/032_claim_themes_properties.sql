-- migrations/032_claim_themes_properties.sql
-- Per design 2026-05-18-cross-source-anchor.
-- Adds free-form metadata to claim_themes so textbook-seeded themes can
-- record `source_textbook_claim_id` (the L1 section they were derived from)
-- without inventing a side table. Existing rows default to '{}'::jsonb.

ALTER TABLE claim_themes
    ADD COLUMN IF NOT EXISTS properties JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_claim_themes_properties
    ON claim_themes USING gin (properties jsonb_path_ops);
