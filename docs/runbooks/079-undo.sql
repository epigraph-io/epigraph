-- docs/runbooks/079-undo.sql
--
-- UNDO for migration 079_rls_force.sql — the FORCE ROW LEVEL SECURITY kill
-- switch named in plan §9.2 step 11d and §0.6.
--
-- WHY A RUNBOOK AND NOT A .down.sql. `migrations/` contains ZERO `.down.sql`
-- files — `sqlx migrate revert` is not available in this tree. Plan §3.0 names
-- FORCE as one of the three one-way doors that must ship a checked-in undo
-- script; `070-undo.sql` and `074-undo.sql` are the other two, and the file
-- naming convention there is the ACTUAL migration number. The plan calls this
-- file "075-undo.sql" (and "076-undo.sql" in its renumbering note); under
-- `migrations/README.md`, which is authoritative, it is 079.
--
-- ===================================================================
-- WHAT THIS DOES, AND WHAT IT DELIBERATELY DOES NOT.
--
-- It drops FORCE and leaves 077's policies ENABLEd. That is the whole design of
-- the kill switch: FORCE only ADDITIONALLY subjects the TABLE OWNER, so
-- dropping it restores the owner's unfiltered access — which, paired with
-- reverting `DATABASE_URL` to the owner role `epigraph`, is a complete,
-- sub-minute, no-data-change rollback.
--
-- IT DOES NOT DROP THE POLICIES, and you should not reach for that. With
-- `DATABASE_URL` back on the owner role the policies are inert, and dropping
-- them would additionally disarm every non-owner role — including the
-- maintenance fleet's refusal in `epigraph-db/src/pool.rs::maintenance_verdict`,
-- which keys on `(relrowsecurity OR relforcerowsecurity)` precisely so that
-- pulling THIS lever does not silently disarm it. If you genuinely need the
-- policies gone, that is a forward migration, reviewed, not a runbook.
--
-- ===================================================================
-- THE ARRAY MUST MATCH 079's, EXACTLY.
--
-- `AppState::assert_rls_posture` refuses to boot on a PARTIALLY FORCEd
-- protected set — zero FORCEd is a pre-079 database and is inert, all FORCEd is
-- the armed state, and a subset is a half-applied migration with no legitimate
-- cause. An undo that missed a table would land the cluster in exactly that
-- state and the API would not come back up.
--
-- THE ARRAY IS NO LONGER 079's ARRAY, AND THAT IS THE POINT (PR-18a). The boot
-- assertion counts what the CATALOG reports FORCEd, not what 079 wrote, so this
-- script has to cover every FORCEd relation whatever installed it. 079 is an
-- applied file and cannot be edited — `migrations/README.md` states the rule and
-- the checksum failure it causes — so a table added from 080 onward FORCEs
-- itself at creation, exactly as 078 did for `rls_canary`. The list below is
-- therefore 079's thirty-five PLUS the four privatization tables 080/082/083
-- FORCE, and `crates/epigraph-db/tests/locked_decisions.rs::FORCE_PROTECTED_SET`
-- pins this file, `epigraph_api::state::FORCE_PROTECTED_SET` and the catalog
-- together.
--
-- `rls_canary` is deliberately absent, exactly as in 079: migration 078 FORCEs
-- it at creation and it must STAY FORCEd. Un-FORCing it would make the canary
-- row visible to the owner and the boot probe would then report a false alarm
-- during the very rollback this script is performing. It is the ONE relation
-- the catalog reports FORCEd that this script must not touch, and
-- `d4_the_kill_switch_covers_the_same_relations_as_the_flip` asserts its
-- absence.
--
-- ===================================================================
-- WHO RUNS THIS. The table owner — `epigraph` — or a superuser. `ALTER TABLE`
-- is owner-only, so `epigraph_app` cannot pull its own kill switch, which is
-- the intended property.
--
-- Run it as one transaction: a half-applied undo is the state the boot
-- assertion refuses on.
-- ===================================================================

BEGIN;

SET LOCAL lock_timeout = '3s';

DO $$
DECLARE t text;
        protected text[] := ARRAY[
          -- ---- 062 tier_a, verbatim -------------------------------------
          'claims','evidence','edges',
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance',
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations',
          'harvester_fragments',
          'frames','contexts','perspectives','communities',
          'recall_events',
          -- ---- group / identity control tables ---------------------------
          'groups','group_memberships','group_key_epochs',
          'agents','jobs','security_events',
          -- ---- the four encryption tables --------------------------------
          'claim_encryption','claim_version_encryption',
          'evidence_encryption','edge_encryption',
          -- ---- the four privatization tables (PR-18a) --------------------
          -- NOT FORCEd by 079. 080, 082 and 083 FORCE the table they create,
          -- for the reason 078 established for `rls_canary`. They are undone
          -- HERE because the boot assertion counts the CATALOG, not 079's
          -- array: leaving four of thirty-nine FORCEd is the partial state
          -- `AppState::rls_verdict` refuses on, so an undo that skipped them
          -- would be the outage this script exists to prevent. The `IF EXISTS`
          -- guard below is what makes that safe on a database that has not run
          -- 080-083 — and it is why this script does not need to know whether
          -- they ran.
          'privatization_plans','privatization_plan_items',
          'privatization_audit','instance_admins',
          -- ---- the operator-link record (107) ----------------------------
          -- FORCEd by 107 at creation, on the same precedent and for the same
          -- boot-assertion reason as the four above.
          'operator_links'];
BEGIN
    FOREACH t IN ARRAY protected LOOP
        IF EXISTS (SELECT 1 FROM pg_class c
                     JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relname = t
                      AND c.relkind IN ('r', 'p')) THEN
            EXECUTE format('ALTER TABLE public.%I NO FORCE ROW LEVEL SECURITY', t);
        END IF;
    END LOOP;
END $$;

COMMIT;

-- ===================================================================
-- VERIFY. Expect 0 rows from the first query and 1 from the second.
--
--   SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
--    WHERE n.nspname = 'public' AND c.relforcerowsecurity AND c.relname <> 'rls_canary';
--
--   SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
--    WHERE n.nspname = 'public' AND c.relname = 'rls_canary' AND c.relforcerowsecurity;
--
-- THEN revert `DATABASE_URL` to the owner role and restart. Reverting the DSN
-- without running this script also works and is faster; this script is for the
-- case where you cannot change the DSN, or where you want the owner role
-- unfiltered while you investigate.
-- ===================================================================
