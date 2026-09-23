-- ===================================================================
-- 079 — FORCE ROW LEVEL SECURITY. The flip.
--
-- Version 079 per `migrations/README.md`; the plan calls this file
-- "075_rls_force.sql". See 077's header for the numbering correction.
--
-- ENABLE does not apply to the table OWNER; only FORCE does. Every table below
-- is owned by the superuser `epigraph`, so 077's policies are already filtering
-- `epigraph_app`, `epigraph_admin` and `epigraph_maintenance` — this file
-- closes the remaining owner hole and nothing else. That is why PR-15's
-- maintenance probe keys on `(relrowsecurity OR relforcerowsecurity)` and why
-- PR-17's boot assertion does too.
--
-- KILL SWITCH: `ALTER TABLE … NO FORCE ROW LEVEL SECURITY`. Instant, no
-- rewrite, no data change. Paired with reverting `DATABASE_URL` to the owner
-- role this is a sub-minute rollback. Scripted at
-- `docs/runbooks/079-undo.sql`, which loops THE SAME ARRAY as this file — a
-- partial undo would leave the cluster in the half-FORCEd state
-- `AppState::assert_rls_posture` refuses on, so the two arrays must not drift.
--
-- PRECONDITIONS, checked by the deploy runbook BEFORE this runs (§9.2 step 11d):
--   * §0.5's session-GUC probe passes on the target cluster.
--   * PR-15 has landed: the job pool, the 14 DATABASE_URL CLI binaries, and
--     scripts/{theme_lib,fuzzy_dedup_claims}.py all use MAINTENANCE_DATABASE_URL.
--   * `current_user` on the API pool is exactly `epigraph_app`, which requires
--     the out-of-band `ALTER ROLE epigraph_app LOGIN PASSWORD …` (never in this
--     repository — it is public).
--   * THE REQUEST PATH STAMPS ITS SESSION GUCs. This is the open precondition
--     that PR-17 does NOT discharge; see the PR body and `bin/server.rs`'s own
--     note that handlers still read `state.db_pool` and that migrating them
--     onto `ScopedPool::acquire_as` is "PR-07/PR-17".
--
-- ===================================================================
-- THE ARRAY IS GUARDED ON CATALOG PRESENCE, AND THAT IS NOT DEFENSIVE PADDING.
--
-- The plan's 079 array names `privatization_plans`, `privatization_plan_items`,
-- `privatization_audit` and `instance_admins`. NONE OF THEM EXIST: under
-- `migrations/README.md` they are PR-18's 080–083. Unguarded, this file would
-- abort on the first of them and take the whole flip with it. They are omitted
-- rather than guarded-for, because a guard would silently pass on the day PR-18
-- lands them and forget to FORCE them — PR-18 owns adding them to this array
-- and to `locked_decisions.rs` in the same commit.
--
-- The `relkind IN ('r','p')` guard IS load-bearing: `alternative_set` and
-- `alt_set_decisions` are VIEWs in the §2.4 generated protected set, and
-- `ALTER TABLE … FORCE ROW LEVEL SECURITY` errors on a view. 077 closes those
-- two with `security_invoker = true` instead, which is the correct instrument
-- for a view.
--
-- `rls_canary` is deliberately ABSENT: 078 FORCEs it itself, at creation.
-- ===================================================================

SET LOCAL lock_timeout = '3s';

DO $$
DECLARE t text;
        -- 062's `tier_a` (25) ∪ the 10 control/encryption tables. Transcribed
        -- rather than derived, so a table added to 062 and not here fails
        -- `locked_decisions.rs` instead of silently going unFORCEd.
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
          -- ---- the FOUR encryption tables (the plan's prose says three) ---
          'claim_encryption','claim_version_encryption',
          'evidence_encryption','edge_encryption'];
BEGIN
    FOREACH t IN ARRAY protected LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_class c
                         JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public' AND c.relname = t
                          AND c.relkind IN ('r', 'p')) THEN
            RAISE EXCEPTION 'epigraph rls: protected table public.% is missing or is '
                            'not an ordinary/partitioned table; refusing to FORCE a '
                            'partial set', t
                USING ERRCODE = '42P01';
        END IF;
        -- A table that reached here without 077's ENABLE would be FORCEd with
        -- NO policy at all, which denies every row to every non-owner — the
        -- `force_without_enable_is_not_satisfied` trap `repos/entity_type.rs`
        -- already pins. Refuse rather than create it.
        IF NOT EXISTS (SELECT 1 FROM pg_class c
                         JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public' AND c.relname = t
                          AND c.relrowsecurity) THEN
            RAISE EXCEPTION 'epigraph rls: public.% has no ENABLE ROW LEVEL SECURITY; '
                            'migration 077 must run first, or FORCE would deny every '
                            'row to every non-owner', t
                USING ERRCODE = '42P17';
        END IF;
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END $$;
