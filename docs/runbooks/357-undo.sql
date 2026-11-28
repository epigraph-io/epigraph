-- ===================================================================
-- 357-undo.sql: take migration 357 (the pre-seal signature stash on
-- `claim_encryption` / `evidence_encryption`; backlog aa366aa6) back out, in
-- ONE transaction, on the migration (superuser) DSN.
--
-- RUN THIS BEFORE ROLLING THE BINARY BACK. A binary built with 357 writes
-- and reads the stash columns in the seal and unseal mutations; once they are
-- gone, its seal-commit and unseal-commit fail (42703) with nothing written,
-- which is the safe direction. The other order is not: a binary without 357
-- unseals by deleting the ciphertext row WITHOUT restoring the stash, so a
-- claim that the 357 binary re-signed would come back carrying the server's
-- signature over the ciphertext digest instead of its own, and the original
-- would be gone with the row.
--
-- WHAT IT DOES, for every row whose seal took the stash
-- (`pre_seal_stashed`): copies `pre_seal_signature` / `pre_seal_signer_id`
-- back onto `claims.signature` / `signer_id` and `evidence.signature` /
-- `signer_id`, i.e. the sealed rows go back to the shape a seal below 357
-- left (the original signature over the plaintext digest, on the row). Then
-- drops the three columns of each table (their CHECK and foreign-key
-- constraints go with them). Rows sealed without the stash are not touched.
--
-- EXCEPT a claim whose signature was REVOKED after the seal took the stash
-- (a `claim_signature_revocations` row for the sealed digest or for the
-- stashed original; the same two arms as
-- `PrivatizationRepository::unseal_claims_conn`): it is left as the revoke
-- left it, unsigned. Copying the stash back would bring a revoked signature
-- back to life while the audit table still says it is revoked.
--
-- WHAT IT LEAVES: every ciphertext row; 357's `_sqlx_migrations` row.
-- Re-introducing the columns is a NEW migration, never a re-run of 357.
-- Idempotent: a second run finds no columns and does nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'claim_encryption'
                  AND column_name = 'pre_seal_stashed') THEN
        UPDATE public.claims c
           SET signature = ce.pre_seal_signature,
               signer_id = ce.pre_seal_signer_id
          FROM public.claim_encryption ce
         WHERE ce.claim_id = c.id AND ce.pre_seal_stashed
           AND NOT EXISTS (
                 SELECT 1 FROM public.claim_signature_revocations r
                  WHERE r.claim_id = c.id
                    AND (r.previous_content_hash = c.content_hash
                         OR r.previous_signature = ce.pre_seal_signature));
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'evidence_encryption'
                  AND column_name = 'pre_seal_stashed') THEN
        UPDATE public.evidence e
           SET signature = ee.pre_seal_signature,
               signer_id = ee.pre_seal_signer_id
          FROM public.evidence_encryption ee
         WHERE ee.evidence_id = e.id AND ee.pre_seal_stashed;
    END IF;
END $$;

ALTER TABLE public.claim_encryption
    DROP COLUMN IF EXISTS pre_seal_signature,
    DROP COLUMN IF EXISTS pre_seal_signer_id,
    DROP COLUMN IF EXISTS pre_seal_stashed;

ALTER TABLE public.evidence_encryption
    DROP COLUMN IF EXISTS pre_seal_signature,
    DROP COLUMN IF EXISTS pre_seal_signer_id,
    DROP COLUMN IF EXISTS pre_seal_stashed;

COMMIT;
