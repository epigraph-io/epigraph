-- 357: keep a sealed row's pre-seal signature in its ciphertext row, so the
-- seal can re-sign the sealed form (backlog aa366aa6, split 1/2 of 7d68aa40).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- `claims.signature` is a v1 Ed25519 signature over `claims.content_hash`,
-- and before the seal that digest is BLAKE3 of the PLAINTEXT. The seal
-- (`PrivatizationRepository::seal_claims_conn`) replaced `content_hash` with
-- BLAKE3 of the ciphertext and left `signature` / `signer_id` as they were,
-- so a sealed claim carried:
--
--   * a signature that no longer verifies over the row it sits on, so a
--     verifier cannot tell a sealed row from a tampered one; and
--   * a guess-confirmation oracle: anyone who can read the row and the
--     signer's public key can confirm a guessed plaintext by verifying the
--     signature over BLAKE3(guess). Backlog 12b68201 closed the same oracle
--     on `evidence.content_hash`; `evidence.signature` (over that digest) kept
--     it.
--
-- The seal now moves the original into the ciphertext row (these columns),
-- re-signs the claim with the API server's signing key over the new
-- (ciphertext) digest, and NULLs the evidence row's signature (its digest is
-- an id-derived sentinel, so a server signature over it would attest
-- nothing). Unseal puts the original back and the ciphertext row, columns
-- and all, is deleted.
--
-- ===================================================================
-- 1. THE COLUMNS
-- ===================================================================
--
-- On `claim_encryption` and `evidence_encryption`, all three:
--
--   * `pre_seal_signature bytea` / `pre_seal_signer_id uuid`: the row's
--     `signature` / `signer_id` as they were when the seal ran. Both NULL
--     when the original was unsigned (the source tables' own
--     `*_signature_requires_signer` rule, re-stated here).
--   * `pre_seal_stashed boolean NOT NULL DEFAULT false`: whether the seal
--     that wrote this row took the stash. Two nullable columns cannot tell
--     "the original was unsigned" (restore NULL) from "this row was sealed
--     by a binary that took no stash" (a row sealed before 357, or by an
--     older binary between this migration and the binary deploy, whose
--     source row still carries its original signature: leave it). Unseal
--     restores only where this is true. A row with it false holds no stash.
--
-- `pre_seal_signer_id` REFERENCES `agents(id)` ON DELETE RESTRICT. While a
-- row is unsealed, its signer cannot be deleted: `claims.signer_id` /
-- `evidence.signer_id` are `ON DELETE SET NULL`, and nulling them under a
-- live signature violates `*_signature_requires_signer`, so the delete is
-- refused. While the row is sealed its `signer_id` names the server (or
-- nothing), so without this key the original signer could be deleted and
-- unseal would then write a dangling `signer_id` (23503) and roll back on
-- every retry. RESTRICT keeps the sealed row's refusal the same as the
-- unsealed row's. The columns are new and all NULL, so validating the key
-- reads nothing; `lock_timeout` bounds the SHARE ROW EXCLUSIVE it takes on
-- `agents`.
--
-- ===================================================================
-- 2. WHO CAN READ THEM
-- ===================================================================
--
-- Nothing is granted or revoked. The columns inherit their table's privileges
-- (077's table-level grants) and its row security: 077 section 5's
-- `<table>_tenancy` policy reads by `group_id` membership of the SEALING
-- group, FORCEd by 079, plus 232/233's owner-scope write policies and 126's
-- elevated-write refusals. A non-member reads no row, so no stashed
-- signature. No definer or view projects these tables whole, and this adds
-- none.
--
-- ===================================================================
-- 3. EXISTING ROWS
-- ===================================================================
--
-- DDL only. `ADD COLUMN ... DEFAULT false` on a NOT NULL boolean is a catalog
-- change (no rewrite). Every row that exists when this runs keeps
-- `pre_seal_stashed = false` and NULL stash columns, and its source row keeps
-- the signature it already has: the seal that wrote it never touched the
-- signature, so unseal leaving it alone is correct. Those rows still carry
-- the pre-seal signature on `claims` / `evidence` (the oracle in section 0)
-- until a re-seal; re-signing them needs the API's private key, which SQL
-- does not hold. Measure: `SELECT count(*) FROM claim_encryption` and
-- `SELECT count(*) FROM evidence_encryption` (every row is pre-357).
--
-- Deploy order: this migration, then the binary that writes the columns.
-- Undo: docs/runbooks/357-undo.sql, BEFORE rolling the binary back (its
-- header says why).
SET LOCAL lock_timeout = '3s';

ALTER TABLE public.claim_encryption
    ADD COLUMN IF NOT EXISTS pre_seal_signature bytea,
    ADD COLUMN IF NOT EXISTS pre_seal_signer_id uuid,
    ADD COLUMN IF NOT EXISTS pre_seal_stashed boolean NOT NULL DEFAULT false;

ALTER TABLE public.claim_encryption
    DROP CONSTRAINT IF EXISTS claim_encryption_pre_seal_signature_length,
    ADD CONSTRAINT claim_encryption_pre_seal_signature_length
        CHECK (pre_seal_signature IS NULL OR octet_length(pre_seal_signature) = 64),
    DROP CONSTRAINT IF EXISTS claim_encryption_pre_seal_signature_requires_signer,
    ADD CONSTRAINT claim_encryption_pre_seal_signature_requires_signer
        CHECK ((pre_seal_signature IS NULL) = (pre_seal_signer_id IS NULL)),
    DROP CONSTRAINT IF EXISTS claim_encryption_pre_seal_only_when_stashed,
    ADD CONSTRAINT claim_encryption_pre_seal_only_when_stashed
        CHECK (pre_seal_stashed OR pre_seal_signature IS NULL),
    DROP CONSTRAINT IF EXISTS claim_encryption_pre_seal_signer_id_fkey,
    ADD CONSTRAINT claim_encryption_pre_seal_signer_id_fkey
        FOREIGN KEY (pre_seal_signer_id) REFERENCES public.agents (id) ON DELETE RESTRICT;

ALTER TABLE public.evidence_encryption
    ADD COLUMN IF NOT EXISTS pre_seal_signature bytea,
    ADD COLUMN IF NOT EXISTS pre_seal_signer_id uuid,
    ADD COLUMN IF NOT EXISTS pre_seal_stashed boolean NOT NULL DEFAULT false;

ALTER TABLE public.evidence_encryption
    DROP CONSTRAINT IF EXISTS evidence_encryption_pre_seal_signature_length,
    ADD CONSTRAINT evidence_encryption_pre_seal_signature_length
        CHECK (pre_seal_signature IS NULL OR octet_length(pre_seal_signature) = 64),
    DROP CONSTRAINT IF EXISTS evidence_encryption_pre_seal_signature_requires_signer,
    ADD CONSTRAINT evidence_encryption_pre_seal_signature_requires_signer
        CHECK ((pre_seal_signature IS NULL) = (pre_seal_signer_id IS NULL)),
    DROP CONSTRAINT IF EXISTS evidence_encryption_pre_seal_only_when_stashed,
    ADD CONSTRAINT evidence_encryption_pre_seal_only_when_stashed
        CHECK (pre_seal_stashed OR pre_seal_signature IS NULL),
    DROP CONSTRAINT IF EXISTS evidence_encryption_pre_seal_signer_id_fkey,
    ADD CONSTRAINT evidence_encryption_pre_seal_signer_id_fkey
        FOREIGN KEY (pre_seal_signer_id) REFERENCES public.agents (id) ON DELETE RESTRICT;

COMMENT ON COLUMN public.claim_encryption.pre_seal_signature IS
    'claims.signature as it was when the seal ran (migration 357); unseal restores it.';
COMMENT ON COLUMN public.claim_encryption.pre_seal_signer_id IS
    'claims.signer_id as it was when the seal ran (migration 357); unseal restores it.';
COMMENT ON COLUMN public.claim_encryption.pre_seal_stashed IS
    'true when the seal took the pre-seal stash; unseal restores only then (migration 357).';
COMMENT ON COLUMN public.evidence_encryption.pre_seal_signature IS
    'evidence.signature as it was when the seal ran (migration 357); unseal restores it.';
COMMENT ON COLUMN public.evidence_encryption.pre_seal_signer_id IS
    'evidence.signer_id as it was when the seal ran (migration 357); unseal restores it.';
COMMENT ON COLUMN public.evidence_encryption.pre_seal_stashed IS
    'true when the seal took the pre-seal stash; unseal restores only then (migration 357).';
