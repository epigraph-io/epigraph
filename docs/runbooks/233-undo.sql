-- ===================================================================
-- 233-undo.sql: take migration 233 (a `claim_version_encryption`,
-- `evidence_encryption` or `edge_encryption` row is bound to the owner group
-- of the row it seals) back out, in ONE transaction, on the migration
-- (superuser) DSN.
--
-- WHAT IT DOES:
--   * drops the six RESTRICTIVE policies 233 added,
--     `<table>_owner_scope_insert` and `<table>_owner_scope_update` on each
--     of the three tables. 077's `<table>_tenancy`, 115's
--     `<table>_delete_writer` and 126's `<table>_elevated_no_*` are not
--     touched; neither is anything on `claim_encryption` (232).
--
-- WHAT IT LEAVES:
--   * every claim version, evidence row, edge and ciphertext row as it
--     stands;
--   * 233's `_sqlx_migrations` row. Re-introducing the binding is a NEW
--     migration, never a re-run of 233.
--
-- WHAT COMES BACK: an application session that writes one group can again
-- seal (or move a seal row onto) a claim version, evidence row or edge
-- another group owns, under its own key. Check for rows in that state
-- (expected 0 each):
--   SELECT count(*) FROM public.claim_version_encryption cve
--     LEFT JOIN public.claim_versions v ON v.id = cve.claim_version_id
--    WHERE v.claim_id IS DISTINCT FROM cve.claim_id
--       OR v.owner_group_id IS DISTINCT FROM cve.group_id;
--   SELECT count(*) FROM public.evidence_encryption ee
--     JOIN public.evidence e ON e.id = ee.evidence_id
--    WHERE ee.group_id IS DISTINCT FROM e.owner_group_id;
--   SELECT count(*) FROM public.edge_encryption ge
--     JOIN public.edges e ON e.id = ge.edge_id
--    WHERE ge.group_id IS DISTINCT FROM e.owner_group_id;
--
-- No binary depends on 233, so there is no rollout order.
-- Idempotent: a second run changes nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP POLICY IF EXISTS claim_version_encryption_owner_scope_insert ON public.claim_version_encryption;
DROP POLICY IF EXISTS claim_version_encryption_owner_scope_update ON public.claim_version_encryption;
DROP POLICY IF EXISTS evidence_encryption_owner_scope_insert ON public.evidence_encryption;
DROP POLICY IF EXISTS evidence_encryption_owner_scope_update ON public.evidence_encryption;
DROP POLICY IF EXISTS edge_encryption_owner_scope_insert ON public.edge_encryption;
DROP POLICY IF EXISTS edge_encryption_owner_scope_update ON public.edge_encryption;

COMMIT;
