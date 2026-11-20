-- ===================================================================
-- 232-undo.sql: take migration 232 (a `claim_encryption` row is bound to its
-- claim's owner group) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- WHAT IT DOES:
--   * drops `claim_encryption_owner_scope_insert` and
--     `claim_encryption_owner_scope_update`, the two RESTRICTIVE policies
--     232 added. 077's `claim_encryption_tenancy`, 115's
--     `claim_encryption_delete_writer` and 126's
--     `claim_encryption_elevated_no_*` are not touched.
--
-- WHAT IT LEAVES:
--   * every claim and `claim_encryption` row as it stands;
--   * 232's `_sqlx_migrations` row. Re-introducing the binding is a NEW
--     migration, never a re-run of 232.
--
-- WHAT COMES BACK: an application session that writes one group can again
-- seal (or move a seal row onto) a claim another group owns, under its own
-- key. Check for rows in that state (expected 0):
--   SELECT count(*) FROM public.claim_encryption ce
--     JOIN public.claims c ON c.id = ce.claim_id
--    WHERE ce.group_id IS DISTINCT FROM c.owner_group_id;
--
-- No binary depends on 232, so there is no rollout order.
-- Idempotent: a second run changes nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP POLICY IF EXISTS claim_encryption_owner_scope_insert ON public.claim_encryption;
DROP POLICY IF EXISTS claim_encryption_owner_scope_update ON public.claim_encryption;

COMMIT;
