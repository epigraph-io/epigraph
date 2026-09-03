-- docs/runbooks/070-undo.sql
--
-- UNDO for migration 070_tenancy_triggers.sql (and 071_ownership_compat_shim.sql).
--
-- WHY A RUNBOOK AND NOT A .down.sql. `migrations/` contains ZERO `.down.sql`
-- files — `sqlx migrate revert` is not available in this tree. Plan §3.0 names
-- three one-way doors that must therefore ship a checked-in undo script; 070 is
-- one of them.
--
-- FILENAME RECONCILIATION. Plan §3.0 calls this file `docs/runbooks/070-undo.sql`
-- and §3.1's amendment note renames it `071-undo.sql`. Both were written against
-- the PRE-SHIFT numbering, where PR-12's trigger migration was "066". Under
-- migrations/README.md's authoritative post-shift table the trigger migration is
-- **070**, so this file takes 070 and covers 071 as well — the two ship together
-- and undoing the triggers without the shim would leave `ownership` writes
-- raising 42501 with nothing to transcribe them.
--
-- WHAT THIS DOES AND DOES NOT UNDO.
--   * It DROPs the triggers and their functions. Fully reversible: re-running
--     migrations 070 and 071 restores them (both are CREATE OR REPLACE +
--     DROP TRIGGER IF EXISTS throughout).
--   * It does NOT un-stamp data. Rows already given an explicit
--     (visibility, owner_group_id) keep it. That is deliberate: the stamped
--     values are CORRECT, the backfill is idempotent, and reverting them would
--     re-open the declassification bug arm (a) exists to close.
--   * It does NOT drop the bookkeeping tables. `tenancy_backfill_progress`,
--     `tenancy_undeclared_writes` and `tenancy_transcription_log` belong to
--     migration 062, not to this one, and `schema_contract.rs` pins their shape.
--   * It does NOT revoke the grants to `epigraph_maintenance`. They are
--     prerequisites of 074/077 as well.
--
-- AFTER RUNNING THIS, migration 074 (PR-16) MUST NOT BE APPLIED. 074
-- CREATE OR REPLACEs functions this script has dropped and drops the transition
-- DEFAULTs that arm (a) keys on. Re-apply 070 and 071 first.
--
-- Usage:
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f docs/runbooks/070-undo.sql

BEGIN;
SET LOCAL lock_timeout = '3s';

-- 071 first: the shim's UPDATEs fire 070 arm (d), so dropping it first means
-- the window in between has no half-wired cascade.
DROP TRIGGER IF EXISTS ownership_transcribe ON public.ownership;
DROP FUNCTION IF EXISTS public.epigraph_ownership_transcribe();

-- 070 arm (d)
DROP TRIGGER IF EXISTS claims_propagate_tenancy ON public.claims;
DROP FUNCTION IF EXISTS public.epigraph_propagate_tenancy();

-- 070 arm (c) — one trigger per claim-derived tier-A table.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
      'evidence','triples','entity_mentions','claim_versions','mass_functions',
      'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
      'harvester_claim_provenance','challenges','reasoning_traces',
      'experiment_triples','experiment_entity_mentions','claim_clusters',
      'claim_cluster_membership','claim_neighborhood_membership',
      'claim_signature_revocations'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON public.%I',
                       t || '_inherit_tenancy', t);
    END LOOP;
END $$;
DROP FUNCTION IF EXISTS public.epigraph_inherit_tenancy_stmt();

-- 070 arm (b)
DROP TRIGGER IF EXISTS edges_tenancy ON public.edges;
DROP FUNCTION IF EXISTS public.epigraph_edges_tenancy();
DROP FUNCTION IF EXISTS public.epigraph_node_tenancy(uuid, text);

-- 070 arm (a)
DROP TRIGGER IF EXISTS claims_require_tenancy ON public.claims;
DROP FUNCTION IF EXISTS public.epigraph_claims_require_tenancy();

COMMIT;

-- Confirm: this must return zero rows.
SELECT tgname, relname
  FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE NOT t.tgisinternal
   AND (tgname LIKE '%_tenancy' OR tgname LIKE '%_inherit_tenancy'
        OR tgname = 'ownership_transcribe');
