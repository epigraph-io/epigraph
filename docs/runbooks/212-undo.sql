-- ===================================================================
-- 212-undo.sql: take migration 212 (the sealed-row vector guard) back out,
-- in ONE transaction, on the migration (superuser) DSN.
--
-- WHAT IT DOES: drops the two triggers (`claims_refuse_sealed_vector`,
-- `evidence_refuse_sealed_vector`) and their two functions.
--
-- WHAT IT LEAVES: every row as it stands, and 212's `_sqlx_migrations` row.
-- No binary depends on 212: every in-tree vector writer carries its own
-- `NOT EXISTS (… _encryption …)` predicate, so after this undo the invariant
-- is enforced statement by statement again, exactly as before 212, and a
-- writer added without the predicate is caught only by CLAUDE.md's
-- `sealed_with_embedding` audit. Re-introducing the guard is a NEW migration,
-- never a re-run of 212.
-- Idempotent: a second run changes nothing.
-- ===================================================================
BEGIN;
SET LOCAL lock_timeout = '3s';

DROP TRIGGER IF EXISTS claims_refuse_sealed_vector ON public.claims;
DROP TRIGGER IF EXISTS evidence_refuse_sealed_vector ON public.evidence;
DROP FUNCTION IF EXISTS public.epigraph_refuse_sealed_claim_vector();
DROP FUNCTION IF EXISTS public.epigraph_refuse_sealed_evidence_vector();

COMMIT;
