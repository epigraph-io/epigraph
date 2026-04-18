-- Migration 097: Add unique constraint on papers.doi
--
-- The papers table has idx_papers_doi (btree) but no UNIQUE constraint,
-- causing ON CONFLICT (doi) to fail in the API upsert path.
-- This migration reconciles edges attached to duplicate papers (repointing
-- from the younger row to the canonical oldest row), drops the younger
-- duplicate rows, then adds the UNIQUE constraint.
--
-- Reconciliation is required because the papers table has a
-- `cascade_delete_edges('paper')` BEFORE DELETE trigger: a naive
-- `DELETE FROM papers` would silently destroy every edge incident on the
-- duplicate row. Before this revision was made, applying that naive delete
-- against the current DB would have cascaded 1,759 edges on two duplicate
-- DOI groups (10.48550/arXiv.2512.24431 and 10.48550/arXiv.2603.11781).

-- ---------------------------------------------------------------------------
-- Step 1: Materialize duplicate→canonical pairs for the whole migration.
-- Canonical = oldest row per doi. Pairs survive across the following DML.
-- ---------------------------------------------------------------------------
CREATE TEMP TABLE paper_dedup_pairs ON COMMIT DROP AS
WITH canonicals AS (
    SELECT DISTINCT ON (doi) id AS canonical_id, doi
    FROM papers
    WHERE doi IN (SELECT doi FROM papers GROUP BY doi HAVING COUNT(*) > 1)
    ORDER BY doi, created_at ASC
)
SELECT p.id AS dup_id, c.canonical_id
FROM papers p
JOIN canonicals c ON p.doi = c.doi
WHERE p.id <> c.canonical_id;

-- ---------------------------------------------------------------------------
-- Step 2: Drop colliding edges.
-- An edge (dup_id → target, relationship) collides if the canonical already
-- has (canonical_id → target, relationship) — the edges table has
-- idx_edges_source_target_relationship UNIQUE on (source_id, target_id,
-- relationship), so the UPDATE in Step 3 would otherwise fail.
-- Current DB: 98 such collisions — the duplicate is redundant; dropping it
-- collapses the duplicate reference without losing information.
-- ---------------------------------------------------------------------------
DELETE FROM edges e
USING paper_dedup_pairs p
WHERE e.source_type = 'paper'
  AND e.source_id = p.dup_id
  AND EXISTS (
      SELECT 1 FROM edges e2
      WHERE e2.source_id = p.canonical_id
        AND e2.target_id = e.target_id
        AND e2.relationship = e.relationship
  );

-- Symmetric handling for paper-as-target edges. No such edges exist in the
-- current DB (verified: 0 rows with target_type='paper' AND target_id ∈ dups)
-- but defensive coverage keeps the migration robust against future data.
DELETE FROM edges e
USING paper_dedup_pairs p
WHERE e.target_type = 'paper'
  AND e.target_id = p.dup_id
  AND EXISTS (
      SELECT 1 FROM edges e2
      WHERE e2.target_id = p.canonical_id
        AND e2.source_id = e.source_id
        AND e2.relationship = e.relationship
  );

-- ---------------------------------------------------------------------------
-- Step 3: Repoint surviving edges from duplicate → canonical.
-- Current DB: 1,759 edges total on duplicates (all as source); after Step 2
-- drops 98 collisions, 1,661 will be repointed.
-- ---------------------------------------------------------------------------
UPDATE edges e
SET source_id = p.canonical_id
FROM paper_dedup_pairs p
WHERE e.source_type = 'paper'
  AND e.source_id = p.dup_id;

UPDATE edges e
SET target_id = p.canonical_id
FROM paper_dedup_pairs p
WHERE e.target_type = 'paper'
  AND e.target_id = p.dup_id;

-- ---------------------------------------------------------------------------
-- Step 4: Sanity check — no edges should remain on duplicate paper rows.
-- If any remain, the cascade trigger in Step 5 would quietly destroy them.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    orphan_count INT;
BEGIN
    SELECT COUNT(*) INTO orphan_count
    FROM edges e
    JOIN paper_dedup_pairs p ON
        (e.source_type = 'paper' AND e.source_id = p.dup_id)
        OR (e.target_type = 'paper' AND e.target_id = p.dup_id);
    IF orphan_count > 0 THEN
        RAISE EXCEPTION
            'Migration 097: % edges remain on duplicate papers after Step 3; aborting to avoid cascade loss',
            orphan_count;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Step 5: Drop the duplicate paper rows. The `cascade_delete_edges('paper')`
-- BEFORE DELETE trigger will run but find no matching edges (Step 4 verified).
-- ---------------------------------------------------------------------------
DELETE FROM papers p
USING paper_dedup_pairs d
WHERE p.id = d.dup_id;

-- ---------------------------------------------------------------------------
-- Step 6: Replace the non-unique index with a unique constraint.
-- ---------------------------------------------------------------------------
DROP INDEX IF EXISTS idx_papers_doi;
ALTER TABLE papers ADD CONSTRAINT papers_doi_unique UNIQUE (doi);
