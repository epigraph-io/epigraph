-- 101_null_retired_claim_embedding_3072.sql
--
-- Extend migration 052's "a retired claim carries no vector" invariant to the
-- SECOND ANN column, `claims.embedding_3072` (migration 027).
--
-- WHY. 052 constrained `embedding` only, and excused this column as "always
-- NULL in practice". That stopped holding once `epigraph-cli reembed` became
-- the documented way to fill it. Its selection had no `is_current` clause, so a
-- run wrote 3072-d vectors onto superseded, duplicate, deprecated and
-- consolidated claims, and no retirement path nulled this column afterwards.
-- Recall and theme k-means at centroid_dim=3072 and
-- `ClaimRepository::search_by_embedding_since(dim=3072)` treat
-- `embedding_3072 IS NOT NULL` as "live", so retired claims came back.
--
-- WHY A CONSTRAINT AND NOT A DAILY SWEEPER. The 2026-05-18 embedding-pipeline
-- plan (follow-up 2) asked for a daily job that nulls stale vectors. A CHECK is
-- strictly stronger: a retired row can never hold a vector, not even for the
-- hours until the next sweep. A sweep would also hide a missed null instead of
-- failing the write that missed it. 052 already made that choice for
-- `embedding`, and this file makes the same one for the second column.
--
-- ORDER MATTERS. The backfill runs first because ADD CONSTRAINT validates every
-- existing row. sqlx runs this whole file in one transaction, so a NOT VALID +
-- VALIDATE split would buy no shorter lock and is not used.
--
-- THE BACKFILL MUST SEE EVERY ROW. The runner is `epigraph`, which is a
-- superuser with BYPASSRLS (docs/deploy.md, role table), so row security on
-- `claims` (FORCEd by 079) does not filter the UPDATE. A runner that row
-- security DID filter would miss rows, but the migration still fails closed.
-- The validation scan below is not subject to row security, so it rejects any
-- row the UPDATE could not see, and the migration aborts instead of recording
-- success over a stale vector.
--
-- CALLERS SHIP FIRST. The CHECK is evaluated per statement, so every UPDATE
-- that sets `is_current = false` on a row with a 3072-d vector must null the
-- vector IN THE SAME STATEMENT. All five in `ClaimRepository` do so since the
-- commit before this one. `epigraph-cli reembed` re-checks `is_current` in its
-- write, so a claim retired mid-run is skipped rather than failing the run. A
-- binary older than that commit fails with 23514 when it retires a claim that
-- carries a 3072-d vector, and an older `reembed` aborts on the first retired
-- claim it selects. Both fail loud and write nothing. Migrate and restart
-- together.
--
-- `is_current` is NOT NULL (default true), so the CHECK has no NULL case.

UPDATE claims
SET    embedding_3072 = NULL
WHERE  NOT is_current
  AND  embedding_3072 IS NOT NULL;

-- Reads: "a claim may have a 3072-d vector only when it is current".
ALTER TABLE claims
    ADD CONSTRAINT chk_deprecated_no_embedding_3072
    CHECK (is_current OR embedding_3072 IS NULL);
