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
-- drops the three columns of each table (their CHECK constraints go with
-- them). Rows sealed without the stash are not touched.
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
         WHERE ce.claim_id = c.id AND ce.pre_seal_stashed;
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
