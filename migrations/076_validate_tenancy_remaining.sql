-- 076_validate_tenancy_remaining.sql -- VALIDATE the tenancy constraints on
-- every remaining tier-A table, plus `agents`, plus PR-13's edge co-ownership
-- shape, plus the two `ownership` constraints 068 left NOT VALID.
-- PR-16 of the multi-user tenancy series. Number per migrations/README.md.
--
-- Split from 075 for the lock-duration reason stated in 075's header. Run it
-- as a separate deploy step.
--
-- `claims` is deliberately absent from the array: 075 owns it. Re-listing it
-- here would be harmless (VALIDATE is idempotent) but would blur which file
-- holds which lock, which is the whole reason for the split.
--
-- Idempotent, and guarded per constraint on the catalog so a partially
-- provisioned database skips rather than aborts.
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE t text; c text;
        tier_a text[] := ARRAY[
          'evidence','edges',
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
        IF NOT EXISTS (SELECT 1 FROM pg_class k JOIN pg_namespace n ON n.oid = k.relnamespace
                        WHERE n.nspname = 'public' AND k.relname = t AND k.relkind = 'r')
        THEN CONTINUE; END IF;
        FOREACH c IN ARRAY ARRAY[
            t || '_visibility_check',
            t || '_owner_group_fkey',
            t || '_group_needs_real_group'] LOOP
            IF EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conrelid = format('public.%I', t)::regclass
                          AND conname = c
                          AND NOT convalidated) THEN
                EXECUTE format('ALTER TABLE public.%I VALIDATE CONSTRAINT %I', t, c);
            END IF;
        END LOOP;
    END LOOP;
END $$;

-- Tier B and the two-parent relation's shape. `agents_profile_visibility_check`
-- is NOT covered by §8.2 A1's `column_name IN ('visibility','owner_group_id')`
-- filter, so A1 passing does not prove this ran -- which is why it is named
-- here explicitly rather than folded into the loop above.
-- `edges_co_owner_shape` / `edges_co_owner_fkey` are PR-13's (migration 072).
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('agents',    'agents_profile_visibility_check'),
        ('edges',     'edges_co_owner_shape'),
        ('edges',     'edges_co_owner_fkey'),
        ('ownership', 'ownership_community_fkey'),
        ('ownership', 'ownership_key_id_is_uuid'),
        ('ownership', 'ownership_community_needs_community_partition')
    ) AS v(tbl, con) LOOP
        IF EXISTS (SELECT 1 FROM pg_class k JOIN pg_namespace n ON n.oid = k.relnamespace
                    WHERE n.nspname = 'public' AND k.relname = r.tbl AND k.relkind = 'r')
           AND EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conrelid = format('public.%I', r.tbl)::regclass
                          AND conname = r.con
                          AND NOT convalidated) THEN
            EXECUTE format('ALTER TABLE public.%I VALIDATE CONSTRAINT %I', r.tbl, r.con);
        END IF;
    END LOOP;
END $$;
