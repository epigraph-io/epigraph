-- 171: drop 001's evidence uniqueness key; evidence is de-duplicated per
-- owner in the application (backlog 12b68201, operator ruling R-77).
--
-- ===================================================================
-- 0. WHY THIS FILE EXISTS
-- ===================================================================
--
-- Migration 001's `evidence_content_hash_claim_unique UNIQUE (content_hash,
-- claim_id)` spans every owner of a claim's evidence. Since 114 a claim's
-- evidence can be owned by several groups (a writer-owned row is the
-- WRITER's), and one group's rows can be unreadable to another. An evidence
-- write by group A whose body equalled a row group B holds on the same claim
-- was refused with a unique violation, on every write path (POST
-- /api/v1/evidence, the `raw_content` rewrite of PUT /api/v1/evidence/:id, MCP
-- `update_with_evidence` / `submit_claim`), and the refusal confirmed that B's
-- unreadable row exists and holds exactly the guessed body.
--
-- The long-lived database never carried this key: it has `evidence_pkey`
-- only, and holds same-owner duplicate rows. That is schema drift of the same
-- class as 013's `uq_claims_content_hash_agent` (migrations/README.md, "Known
-- schema drift"), and this file resolves it the way 150 resolved that one: the
-- key goes everywhere, and the de-duplication contract moves into the
-- application.
--
-- ===================================================================
-- 1. WHAT REPLACES IT
-- ===================================================================
--
-- `EvidenceRepository` (`create`, `create_with_source_url`, `batch_create`,
-- `record_derivation_conn`, `update_raw_content`) writes the row, reads the
-- owner and visibility the tenancy triggers gave it, takes a
-- transaction-scoped advisory lock on `(content_hash, claim_id, owner)`, and
-- then looks for ANOTHER row with the same digest, claim, owner and
-- visibility. If there is one, the write is undone (a savepoint) and answered
-- as the duplicate it always was (`DbError::DuplicateKey`; derivation:
-- `AlreadyPresent`). The lock makes two concurrent first writes serialize
-- instead of both landing. Pinned by `epigraph-db/tests/evidence_dedup_per_owner.rs`,
-- `epigraph-api/tests/evidence_content_oracle_test.rs` and
-- `epigraph-mcp/tests/evidence_content_oracle_app_role.rs`.
--
-- So a duplicate is only ever a row in the SAME tenancy as the row the caller
-- just wrote: a body another owner holds is never consulted, and a write that
-- collides with it lands exactly as a fresh body does. Existing same-owner
-- duplicates stay valid: nothing here builds an index over the data.
--
-- ===================================================================
-- 2. THE STATEMENT
-- ===================================================================
--
-- On the long-lived database this is a no-op (`IF EXISTS`; the constraint is
-- absent) and cannot fail on data. ALTER TABLE still takes ACCESS EXCLUSIVE on
-- `evidence`, held until this migration's transaction commits, so
-- `lock_timeout = '3s'` like 111-121 and 144-150: on a timeout, re-run in a
-- quiet window. The closing DO block refuses (55000) if any unique index on
-- `evidence` still covers both `content_hash` and `claim_id`, whatever its
-- name; it does not require that 001's key ever existed.
--
-- ===================================================================
-- 3. EVIDENCE ROWS SEALED BEFORE THE DIGEST SENTINEL (statement below)
-- ===================================================================
--
-- The seal now replaces a sealed row's `content_hash` with a per-row sentinel
-- (`privatization::SEAL_EVIDENCE_DIGEST_SENTINEL`), because BLAKE3 of the
-- plaintext body confirms a guessed body to anyone who can read the row. Rows
-- sealed before that change still carry it; section 3 gives them the same
-- sentinel. Unseal rebuilds such a row's digest as BLAKE3 of the restored body,
-- recognising the sentinel in the column. IRREVERSIBLE for a sealed row whose
-- body was NULL (external evidence): its writer-supplied digest exists nowhere
-- else and stays the sentinel after unseal. Count the sealed rows first,
-- read-only: `SELECT count(*) FROM evidence_encryption;` (which of them had no
-- body is recorded only inside the ciphertext). The long-lived database had no
-- sealed evidence when this was written, so there the statement changes
-- nothing. A closing DO block refuses (55000) if any sealed row is left
-- without the sentinel, so a filtered UPDATE cannot pass silently.
--
-- DEPLOY ORDER: the matching binaries FIRST (the epigraph-api server, with
-- the hosted jobs it runs, and epigraph-mcp), then this migration. A binary
-- built before this file names `ON CONFLICT (content_hash, claim_id)` in
-- `EvidenceRepository::record_derivation_conn`, which fails 42P10 (no matching
-- unique constraint) once the key is gone; that is already the case on any
-- database that never had the key. Its other evidence writes are not
-- de-duplicated at all against this file (an identical retry adds a row, as on
-- the long-lived database today), and after section 3 its seal would leave the
-- plaintext digest on rows it seals while its unseal would keep the sentinel on
-- rows it restores. No seal or unseal may be in flight while this applies. The
-- new binaries work on either side: where the key is still present, a
-- re-applied derivation is answered `AlreadyPresent` as before, but a write
-- that collides with another owner's row is still refused by the key, so the
-- cross-owner refusal ends when this file applies, not when the binary ships.
--
-- UNDO of section 1 (only on a database with no duplicate (content_hash,
-- claim_id) rows;
-- count them first, read-only, with
--   SELECT count(*) FROM (SELECT 1 FROM evidence GROUP BY content_hash, claim_id
--                          HAVING count(*) > 1) d;):
--   ALTER TABLE evidence ADD CONSTRAINT evidence_content_hash_claim_unique
--       UNIQUE (content_hash, claim_id);

SET LOCAL lock_timeout = '3s';

ALTER TABLE public.evidence DROP CONSTRAINT IF EXISTS evidence_content_hash_claim_unique;

DO $$
DECLARE offending text;
BEGIN
    SELECT string_agg(ic.relname, ', ') INTO offending
      FROM pg_index i
      JOIN pg_class ic ON ic.oid = i.indexrelid
     WHERE i.indrelid = 'public.evidence'::regclass
       AND i.indisunique
       AND EXISTS (SELECT 1 FROM pg_attribute a
                    WHERE a.attrelid = i.indrelid AND a.attname = 'content_hash'
                      AND a.attnum = ANY (i.indkey))
       AND EXISTS (SELECT 1 FROM pg_attribute a
                    WHERE a.attrelid = i.indrelid AND a.attname = 'claim_id'
                      AND a.attnum = ANY (i.indkey));
    IF offending IS NOT NULL THEN
        RAISE EXCEPTION '171: a unique index on evidence still covers (content_hash, claim_id): %',
                        offending
            USING ERRCODE = '55000';
    END IF;
END $$;

-- ===================================================================
-- 3. ROWS SEALED BEFORE THE DIGEST SENTINEL
-- ===================================================================
--
-- An `evidence_encryption` row exists exactly while its evidence row is
-- sealed. The expression is the seal's `SEAL_EVIDENCE_DIGEST_SENTINEL`
-- verbatim (alias `e`); the two must not drift, or unseal stops recognising a
-- backfilled row and keeps the sentinel instead of recomputing the digest
-- (`epigraph-db/tests/evidence_seal_digest_backfill.rs` round-trips it).
-- Idempotent: a row already holding the sentinel is not touched. Runs as the
-- migration owner, so row security does not filter it.
UPDATE public.evidence e
   SET content_hash = sha256(convert_to('[sealed:x' || replace(e.id::text, '-', '') || ']', 'UTF8'))
 WHERE EXISTS (SELECT 1 FROM public.evidence_encryption ee WHERE ee.evidence_id = e.id)
   AND e.content_hash IS DISTINCT FROM
       sha256(convert_to('[sealed:x' || replace(e.id::text, '-', '') || ']', 'UTF8'));

DO $$
DECLARE left_over bigint;
BEGIN
    SELECT count(*) INTO left_over
      FROM public.evidence e
     WHERE EXISTS (SELECT 1 FROM public.evidence_encryption ee WHERE ee.evidence_id = e.id)
       AND e.content_hash IS DISTINCT FROM
           sha256(convert_to('[sealed:x' || replace(e.id::text, '-', '') || ']', 'UTF8'));
    IF left_over > 0 THEN
        RAISE EXCEPTION '171: % sealed evidence row(s) still carry a plaintext digest', left_over
            USING ERRCODE = '55000';
    END IF;
END $$;
