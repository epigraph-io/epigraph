-- Migration 144: chk_deprecated_no_embedding covers embedding_3072 too.
--
-- INVARIANT: a claim may hold a vector in EITHER ANN column only while it is
-- current. Same constraint NAME as 052, widened to both columns, so every
-- reference to `chk_deprecated_no_embedding` (claim.rs doc comments, the
-- *_nulls_embedding tests, CLAUDE.md) keeps naming the one invariant.
--
-- WHY 052 WAS NOT ENOUGH. 052 restricted the guard to the 1536-d `embedding`
-- column on the premise that `embedding_3072` "is always NULL in practice".
-- `epigraph-cli reembed` made that false: it selected every row with a NULL
-- 3072 column, retired claims included, and wrote a vector onto each. Recall
-- at centroid_dim = 3072 (`ClaimRepository::search_by_embedding_since`) has no
-- `is_current` filter, so a retired claim carrying a 3072 vector stayed
-- retrievable, and the documented `stale_present` audit (1536 only) reported
-- zero. The five retirement write paths in `crates/epigraph-db/src/repos/claim.rs`
-- null both columns since #490/#495; `reembed::fetch_batch` selects only
-- current claims since this file's PR. This file backfills the leftovers and
-- makes the database refuse any new ones.
--
-- DEPLOY ORDER. The `epigraph-cli reembed` binary that filters `is_current`
-- must be installed BEFORE this file is applied: an older reembed run after it
-- raises 23514 on the first retired row and aborts. No reembed run may be in
-- flight while it applies.
--
-- BACKFILL SIDE EFFECTS. The UPDATE touches only `embedding_3072`, so the
-- `claims_require_tenancy_then_operator_binding` trigger (UPDATE OF agent_id,
-- supersedes, is_current) and `claims_deactivate_factors` (UPDATE OF
-- is_current) do not fire. `claims_updated_at` bumps `updated_at` on each
-- backfilled row, the same bump 052 accepted. The statement-level
-- `claims_propagate_tenancy` trigger runs once; the backfill changes no
-- tenancy column.
--
-- ROW SECURITY. `claims` is FORCE ROW LEVEL SECURITY (079), so the backfill
-- UPDATE reaches only the rows the applying session can see. Apply as a role
-- that bypasses row security (superuser or BYPASSRLS). If it does not, the
-- ADD CONSTRAINT below is expected to fail closed: constraint validation
-- scans the whole heap regardless of policies, so it should raise 23514 on a
-- row the backfill could not see and roll the whole file back with nothing
-- half-applied. No test exercises this path (the replay test runs as the
-- sqlx::test superuser), so treat the BYPASSRLS requirement as mandatory.
--
-- LOCKING. One transaction (sqlx default). The DROP/ADD takes ACCESS EXCLUSIVE
-- on `claims` and the ADD validates every row in one pass with no rewrite, the
-- shape 052 used. NOT VALID + VALIDATE in the same transaction would hold the
-- same ACCESS EXCLUSIVE until commit and buy nothing; a two-file split
-- (061-style) is the alternative if `claims` is too large for one locked scan.
-- `lock_timeout = '3s'` like 111-121: on a timeout, re-run in a quiet window.
--
-- UNDO (restores 052's guard; the nulled 3072 vectors are not restored, and
-- `epigraph-cli reembed` will not regenerate them for retired claims):
--   ALTER TABLE claims DROP CONSTRAINT chk_deprecated_no_embedding;
--   ALTER TABLE claims ADD CONSTRAINT chk_deprecated_no_embedding
--       CHECK (is_current OR embedding IS NULL);

SET LOCAL lock_timeout = '3s';

UPDATE claims
SET    embedding_3072 = NULL
WHERE  is_current = false
  AND  embedding_3072 IS NOT NULL;

ALTER TABLE claims DROP CONSTRAINT chk_deprecated_no_embedding;

ALTER TABLE claims
    ADD CONSTRAINT chk_deprecated_no_embedding
    CHECK (is_current OR (embedding IS NULL AND embedding_3072 IS NULL));
