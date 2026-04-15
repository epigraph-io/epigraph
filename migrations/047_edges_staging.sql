-- Migration 047: Formalize edges_staging table
--
-- The edges_staging table holds proposed edges from universal_match_staging.py
-- for human review before promotion to the production edges table.
--
-- Evidence:
-- - universal_match_staging.py creates this table ad-hoc with CREATE IF NOT EXISTS
-- - Production workflow requires a migration-managed schema
--
-- Reasoning:
-- - review_status column enables approve/reject workflow without deleting rows
-- - reviewed_at and reviewed_by support audit trail
-- - Column types match production edges table (VARCHAR not TEXT)
-- - ON CONFLICT uses (source_id, target_id, relationship) matching production
-- - 'promoted' status tracks edges that have been moved to production

CREATE TABLE IF NOT EXISTS edges_staging (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID NOT NULL,
    source_type VARCHAR(50) NOT NULL DEFAULT 'claim',
    target_id UUID NOT NULL,
    target_type VARCHAR(50) NOT NULL DEFAULT 'claim',
    relationship VARCHAR(100) NOT NULL DEFAULT 'CORROBORATES',
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Review workflow columns
    review_status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CONSTRAINT edges_staging_review_status_check
        CHECK (review_status IN ('pending', 'approved', 'rejected', 'reclassified', 'promoted')),
    reviewed_at TIMESTAMPTZ,
    reviewed_by TEXT,
    review_notes TEXT,

    UNIQUE (source_id, target_id, relationship)
);

CREATE INDEX IF NOT EXISTS idx_staging_review_status ON edges_staging(review_status);
CREATE INDEX IF NOT EXISTS idx_staging_relationship ON edges_staging(relationship);
CREATE INDEX IF NOT EXISTS idx_staging_similarity ON edges_staging(((properties->>'similarity')::float));

-- Idempotent column additions for tables created by earlier script runs.
-- Uses named constraint to avoid duplicates if CREATE TABLE above already ran.
DO $$ BEGIN
    ALTER TABLE edges_staging ADD COLUMN review_status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CONSTRAINT edges_staging_review_status_check
        CHECK (review_status IN ('pending', 'approved', 'rejected', 'reclassified', 'promoted'));
EXCEPTION WHEN duplicate_column THEN
    -- Column exists; ensure the CHECK constraint allows 'promoted'
    -- (may have been created without it by earlier script runs)
    ALTER TABLE edges_staging DROP CONSTRAINT IF EXISTS edges_staging_review_status_check;
    ALTER TABLE edges_staging ADD CONSTRAINT edges_staging_review_status_check
        CHECK (review_status IN ('pending', 'approved', 'rejected', 'reclassified', 'promoted'));
END $$;

DO $$ BEGIN
    ALTER TABLE edges_staging ADD COLUMN reviewed_at TIMESTAMPTZ;
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE edges_staging ADD COLUMN reviewed_by TEXT;
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE edges_staging ADD COLUMN review_notes TEXT;
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;

-- If table pre-existed with TEXT columns, alter to match production types
DO $$ BEGIN
    ALTER TABLE edges_staging ALTER COLUMN source_type TYPE VARCHAR(50);
    ALTER TABLE edges_staging ALTER COLUMN target_type TYPE VARCHAR(50);
    ALTER TABLE edges_staging ALTER COLUMN relationship TYPE VARCHAR(100);
EXCEPTION WHEN others THEN NULL;
END $$;

COMMENT ON TABLE edges_staging IS
'Proposed edges from universal_match_staging.py awaiting human review. '
'Approved rows are promoted to the production edges table by promote_staged_edges.py.';
