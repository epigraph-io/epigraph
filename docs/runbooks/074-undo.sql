-- docs/runbooks/074-undo.sql
--
-- UNDO for migration 074_tenancy_required.sql.
--
-- WHY A RUNBOOK AND NOT A .down.sql. `migrations/` contains ZERO `.down.sql`
-- files — `sqlx migrate revert` is not available in this tree. Plan §3.0 names
-- the tenancy-required migration as a one-way door that must ship a checked-in
-- undo script. `docs/runbooks/070-undo.sql` covers 070 and 071 only; this is
-- 074's.
--
-- READ THIS BEFORE YOU RUN IT.
--
-- 074 is a one-way door in ONE direction only, and it is not the direction the
-- name suggests. Restoring the DEFAULTs and the transition trigger is
-- mechanical and this script does it. What CANNOT be undone is any write that
-- happened while the defaults were gone:
--
--   * Rows written with an explicit declaration keep it. That is correct — the
--     values are what their writers chose — and this script deliberately does
--     not touch row data.
--   * Rows written by a member of `epigraph_seed` while 074 was applied carry
--     `owner_group_id = '00000000-0000-0000-0000-00000000dead'` (the seed
--     group) where, before 074, they would have carried the world group. That
--     difference is durable. It is also detectable and repairable:
--
--       SELECT count(*) FROM claims
--        WHERE owner_group_id = '00000000-0000-0000-0000-00000000dead'::uuid;
--
--     If you need those rows back on the world group, do it as an explicit,
--     audited UPDATE — not by re-running a migration.
--
-- WHAT THIS DOES NOT UNDO, DELIBERATELY:
--   * 075 / 076's `VALIDATE CONSTRAINT`. Validation is a property of the
--     constraint, not of this file, and un-validating is not an operation
--     PostgreSQL offers. It is also harmless to leave: a validated constraint
--     is a strictly stronger statement about data that already satisfies it.
--     If a constraint genuinely must be relaxed, DROP and re-ADD it NOT VALID
--     as its own migration.
--   * The re-ownership of the trigger functions to `epigraph_maintenance`.
--     070 and 077 need it too.
--   * `claims_block_widening` is dropped here because 074 created it. If you
--     are undoing 074 to recover a write path, note that this removes the
--     sealed-claim declassification guard (sec F11) as a side effect. Prefer
--     fixing the write path.
--
-- AFTER RUNNING THIS, the tree is back at the 070/071/072/073 state: the
-- defaults are present, arm (a) WARNS and COUNTS instead of raising, and
-- `tenancy_undeclared_writes` starts moving again. Re-applying 074 is safe and
-- idempotent — but re-run the week-11b gate (counter flat at zero for 24 hours)
-- first, because the whole reason you are here is that it was not flat.
--
-- Usage:
--   psql "$MIGRATION_DATABASE_URL" -v ON_ERROR_STOP=1 -f docs/runbooks/074-undo.sql
--
-- Run it as the table OWNER. The application role (`epigraph_app`) cannot:
-- `ALTER TABLE ... SET DEFAULT` requires ownership, which is the same property
-- `tenancy_required.rs` asserts the app role does not have.

BEGIN;
SET LOCAL lock_timeout = '3s';

-- 1. The 23 BEFORE ROW triggers 074 added, and their two generic bodies.
--    `claims_require_tenancy` is NOT dropped here — it predates 074 (migration
--    070 created it) and step 3 puts its transition body back.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
      'evidence','triples','entity_mentions','claim_versions','mass_functions',
      'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
      'harvester_claim_provenance','challenges','reasoning_traces',
      'experiment_triples','experiment_entity_mentions','claim_clusters',
      'claim_cluster_membership','claim_neighborhood_membership',
      'claim_signature_revocations',
      'frames','contexts','perspectives','communities',
      'harvester_fragments','recall_events'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON public.%I',
                       t || '_require_tenancy', t);
    END LOOP;
END $$;
DROP FUNCTION IF EXISTS public.epigraph_derived_require_tenancy();
DROP FUNCTION IF EXISTS public.epigraph_root_require_tenancy();

-- 2. The widening guard.
DROP TRIGGER IF EXISTS claims_block_widening ON public.claims;
DROP FUNCTION IF EXISTS public.epigraph_claims_block_widening();

-- 3. Restore 062's DEFAULTs on all 25 tier-A tables.
--    This must happen BEFORE step 4 replaces the trigger body: the transition
--    form keys on "owner_group_id still equals the world default", so a window
--    with the transition body and no default would make every undeclared
--    insert raise a bare NOT NULL violation with no diagnosis.
DO $$
DECLARE t text;
        tier_a text[] := ARRAY[
          'claims','evidence','edges',
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance',
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations',
          'harvester_fragments',
          'frames','contexts','perspectives','communities',
          'recall_events'
        ];
BEGIN
    FOREACH t IN ARRAY tier_a LOOP
        IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relname = t AND c.relkind = 'r')
        THEN
            EXECUTE format(
              'ALTER TABLE public.%I ALTER COLUMN visibility SET DEFAULT ''public''', t);
            EXECUTE format(
              'ALTER TABLE public.%I ALTER COLUMN owner_group_id SET DEFAULT '
              '''00000000-0000-0000-0000-000000000000''::uuid', t);
        END IF;
    END LOOP;
END $$;

COMMIT;

-- 4. Put migration 070's TRANSITION body back.
--
--    NOT inlined here. Copying a 40-line plpgsql body into a runbook is how the
--    two drift: the next edit to 070 would not reach this file, and the
--    difference would only surface as a behavioural change on the day someone
--    ran the undo. Re-run the migration file itself — it is idempotent
--    (CREATE OR REPLACE FUNCTION throughout) and it is the single source of
--    truth for that body:
--
--      psql "$MIGRATION_DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/070_tenancy_triggers.sql
--      psql "$MIGRATION_DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/072_edge_co_ownership.sql
--
--    072 second, because it CREATE OR REPLACEs two of the bodies 070 defines
--    and re-running 070 alone would revert them to the pre-co-ownership form.
--
--    Do NOT delete 074's `_sqlx_migrations` row afterwards. sqlx tolerates a
--    gap (`set_ignore_missing(true)`) but not a checksum mismatch, and a
--    deleted row means the next deploy re-applies 074 silently — which is
--    exactly the state you just backed out of. Leave the row; re-apply 074
--    deliberately when the gate is green.

-- Confirm: this must return zero rows.
SELECT tgname, relname
  FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
 WHERE NOT t.tgisinternal
   AND (tgname LIKE '%\_require\_tenancy' AND tgname <> 'claims_require_tenancy'
        OR tgname = 'claims_block_widening');

-- And this must return 25 rows (every tier-A table with its default restored).
SELECT table_name, column_name, column_default
  FROM information_schema.columns
 WHERE table_schema = 'public'
   AND column_name = 'owner_group_id'
   AND column_default IS NOT NULL
 ORDER BY table_name;
