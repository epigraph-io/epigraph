-- Papers table for tracking research paper sources
-- Used by ingestion scripts to link claims to their source papers via 'asserts' edges

CREATE TABLE IF NOT EXISTS papers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    doi TEXT NOT NULL UNIQUE,
    title TEXT,
    journal TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_papers_doi ON papers (doi);

-- Unique constraint on edges triple — required for ON CONFLICT in ingestion scripts
CREATE UNIQUE INDEX IF NOT EXISTS idx_edges_unique_triple ON edges (source_id, target_id, relationship);
