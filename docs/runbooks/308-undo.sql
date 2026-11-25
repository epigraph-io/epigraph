-- ===================================================================
-- 308-undo.sql: take migration 308 (one `ds_combined_beliefs` row per
-- (frame, claim, scope), the global scope included) back out, in ONE
-- transaction, on the migration (superuser) DSN.
--
-- WHAT IT DOES: re-adds 001's constraint, under the same name, with the
-- default NULLS DISTINCT semantics. After it, every global write inserts a
-- new row again (the defect 308 fixed, backlog 3adc219b). No binary depends
-- on 308, so no rollback order applies.
--
-- WHAT IT CANNOT DO: restore the duplicate global rows 308 deleted. They were
-- older folds of the same key (derived caches, rewritten by the next
-- computation that stores the scope); none is recoverable from this file.
--
-- WHAT IT LEAVES: 308's `_sqlx_migrations` row. Delete it as well if 308 is
-- to be re-applied by `epigraph-migrate`:
--   DELETE FROM _sqlx_migrations WHERE version = 308;
-- Idempotent.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';
ALTER TABLE public.ds_combined_beliefs
    DROP CONSTRAINT IF EXISTS ds_combined_beliefs_frame_id_claim_id_scope_type_scope_id_key;
ALTER TABLE public.ds_combined_beliefs
    ADD CONSTRAINT ds_combined_beliefs_frame_id_claim_id_scope_type_scope_id_key
        UNIQUE (frame_id, claim_id, scope_type, scope_id);
COMMIT;
