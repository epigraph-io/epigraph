-- Enforce the is_current=false → embedding=NULL invariant.
--
-- Code paths that flip is_current=false must also null the embedding so
-- deprecated claims do not contaminate semantic recall.  Three paths were
-- missing the nullification step before this fix:
--   1. evolve_step() with edge_type='supersedes' (claim.rs)
--   2. deprecate_workflow() inline UPDATEs (workflows.rs, fixed via
--      ClaimRepository::deprecate_claim which includes embedding=NULL)
--   3. Historical claims deprecated before nullification was added
--
-- Backfill: null embeddings on all currently-deprecated claims that have one.
-- Restricted to the standard 1536-dim column; embedding_3072 follows the
-- same invariant but is always NULL in practice for step/workflow claims.
UPDATE claims
SET    embedding = NULL
WHERE  is_current = false
  AND  embedding  IS NOT NULL;

-- Database-level guard: prevents future violations from any code path.
-- Reads: "a claim may have an embedding only when it is current".
ALTER TABLE claims
    ADD CONSTRAINT chk_deprecated_no_embedding
    CHECK (is_current OR embedding IS NULL);
