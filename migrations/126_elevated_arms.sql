-- no-transaction
--
-- Migration 126: the ELEVATED READ ARMS and the elevated WRITE REFUSAL on
-- every policy class (elevation plan EL-7, DESIGN 6.3).
--
-- ===================================================================
-- 1. WHAT IT ADDS, PER TABLE (no existing policy body changes)
--
--   <t>_elevated_read       PERMISSIVE  FOR SELECT  TO epigraph_app
--                           USING ((SELECT public.epigraph_is_elevated()))
--   <t>_elevated_no_insert  RESTRICTIVE FOR INSERT  TO epigraph_app
--                           WITH CHECK (NOT (SELECT public.epigraph_is_elevated()))
--   <t>_elevated_no_update  RESTRICTIVE FOR UPDATE  TO epigraph_app
--                           USING (NOT (SELECT public.epigraph_is_elevated()))
--   <t>_elevated_no_delete  RESTRICTIVE FOR DELETE  TO epigraph_app
--                           USING (NOT (SELECT public.epigraph_is_elevated()))
--
-- Permissive policies are OR'ed, so the read arm WIDENS a table's existing
-- tenancy policy without touching it; restrictive policies are AND'ed, so the
-- refusals narrow every write without touching it either. The scalar subquery
-- is an initplan: `epigraph_is_elevated()` (migration 125) runs once per
-- statement, not once per row, and its fast path answers false without a
-- table read whenever `epigraph.elevation_id` is empty, which it is for every
-- viewer that is not Elevated (the pool stamps '' and the release scrub clears
-- it). So for every session that is not elevated, this migration changes no
-- answer: the arm is false and every refusal is true.
--
-- An ELEVATED session (a live elevation session row of the stamped principal
-- and family, re-checked against a live assignment of an `elevates` role on
-- every statement) reads every row of an armed table and writes none: an
-- UPDATE or DELETE sees no row to change, and an INSERT fails its WITH CHECK
-- (SQLSTATE 42501). Rust refuses the elevated write transaction first
-- (`ScopedPool::begin_as`, `DbError::ElevatedReadOnly`) and gives elevated
-- transaction-mode reads `BEGIN READ ONLY`; these policies are what close the
-- remaining path, a session-mode autocommit connection stamped Elevated.
--
-- WHY `TO epigraph_app` AND NOT `TO public` (the existing tenancy policies are
-- TO public). Every SECURITY DEFINER runs as `epigraph_maintenance`, which is
-- neither BYPASSRLS nor a member of `epigraph_app`, so:
--   * the refusals do not apply to definers. The audited admin paths (the
--     elevated-access recorder, the pending-act proposal and confirmation of
--     later migrations, and every audit insert a definer makes) write while
--     the CALLER is elevated, and must;
--   * `epigraph_is_elevated()` itself reads `elevation_sessions`,
--     `role_assignments`, `platform_roles`, `operator_links` and the
--     human-operator registry as a definer, so no arm can recurse into it.
--     Those tables are excluded below anyway.
-- Every application login (`epigraph_app` member) gets both the arm and the
-- refusals.
--
-- ===================================================================
-- 2. THE CENSUS: every table with row security, in exactly one list
--    (pinned by crates/epigraph-db/tests/elevation_arms_census.rs; a new
--    row-security table fails that test until it is placed here)
--
-- 3a. READ ARM + WRITE REFUSAL, the classes DESIGN 6.3 arms (T-OWN, T-OWN-PRIV,
--     T-DER, T-EDGE, T-AGENT, T-GROUP): agents, challenges,
--     claim_cluster_membership, claim_clusters, claim_frames,
--     claim_neighborhood_membership, claim_signature_revocations,
--     claim_versions, claims, contexts, ds_bayesian_divergence,
--     ds_combined_beliefs, edges, entity_mentions, evidence, frames,
--     group_memberships, groups, harvester_claim_provenance,
--     harvester_fragments, mass_functions, perspectives, reasoning_traces,
--     recall_events, triples.
--
-- 3b. READ ARM ONLY (T-AUDIT): privatization_audit, security_events. Their
--     rows are appended by definers and an allowlisted append policy while
--     the caller may be elevated (an elevation's own audit rows included);
--     refusing the insert would break the trail. They carry no UPDATE or
--     DELETE grant or policy to refuse.
--
-- 3c. WRITE REFUSAL ONLY (T-DROP, retired machinery still carrying tenancy
--     policies): claim_encryption, claim_version_encryption, communities,
--     edge_encryption, evidence_encryption, experiment_entity_mentions,
--     experiment_triples, group_key_epochs. The application can still write
--     them, so an elevated session must not; but they are not a class DESIGN
--     6.3 widens, and four of them hold ciphertext and one wrapped key
--     material. An elevated read of them adds nothing a custodian needs.
--
-- EXCLUDED (no elevated policy), each for a reason:
--   * elevation_sessions, elevation_tickets: the elevation record itself
--     (125); read by `epigraph_is_elevated()`.
--   * person_authenticators, passkey_enrollments: passkey material (124).
--   * role_assignments, platform_roles, operator_links: read by
--     `epigraph_is_elevated()`; definer-written governance (122/123).
--   * instance_admins: frozen legacy registry (123).
--   * evidence_visibility_pins: definer-read, maintenance-written (110).
--   * privatization_plans, privatization_plan_items: their standing admin
--     read arm becomes an elevated arm behind the admin-scope arming switch
--     (a later migration), not here.
--   * jobs, rls_canary: bypass-only; the application reads and writes no
--     row of either.
-- None of the excluded tables grants the application a write.
--
-- ===================================================================
-- 3. THE LOCK PLAN (why this file has no transaction, and what that buys)
--
-- `CREATE POLICY` takes ACCESS EXCLUSIVE on its table. In one transaction,
-- about 120 of them would hold every armed table's lock until the last one
-- committed. So:
--   * `-- no-transaction`. sqlx-postgres 0.8.6 then sends the whole file as
--     ONE simple-query message, and PostgreSQL runs a multi-statement simple
--     query as one IMPLICIT transaction block: without more, this file would
--     still be one transaction. Each table's block is therefore followed by
--     `COMMIT;`, which ends the implicit block there (measured: a later
--     table's lock timeout leaves the earlier tables' policies in place; with
--     no COMMIT it rolls all of them back). PostgreSQL answers each such
--     COMMIT with `WARNING: there is no transaction in progress`. That
--     warning is expected; the COMMIT still commits.
--     (`-- no-transaction` files 063-066 and 073 are one statement each for a
--     different reason: CREATE INDEX CONCURRENTLY refuses ANY transaction
--     block, implicit or not. A DO block has no such refusal.)
--   * ONE table per DO block, all of that table's policies in it, so a table
--     is armed completely or not at all.
--   * `set_config('lock_timeout', '3s', true)`: transaction-local, so it
--     bounds each table's wait and ends with that table's COMMIT. A plain
--     SET would outlive this file on the migrator's connection.
--   * Every CREATE is preceded by its `DROP POLICY IF EXISTS`, so a rerun is
--     a no-op on an armed table and resumes at the first unarmed one.
-- A lock timeout fails the migration with NO `_sqlx_migrations` row (sqlx
-- records a no-transaction migration only after the whole file ran); the
-- tables before it stay armed, and rerunning the migration finishes the
-- rest. Production applies DESIGN 9.1's lock plan (timers stopped, no
-- transaction older than a few seconds, outside the backup windows).
--
-- ROLLBACK: docs/runbooks/126-undo.sql drops every policy this file creates,
-- by name, in the same per-table form. It must run BEFORE 125-undo, which
-- refuses while any policy reads `epigraph_is_elevated()`.
--
-- N-1: binaries older than the elevated viewer stamp no elevation pair (the
-- two settings read empty, so `epigraph_is_elevated()` is false): to them
-- this migration changes nothing. Deploy the elevated viewer's binaries
-- before any elevation session exists, so that the arms can matter.
-- ===================================================================

-- -------------------------------------------------------------------
-- 3a. READ ARM + WRITE REFUSAL (T-OWN, T-OWN-PRIV, T-DER, T-EDGE, T-AGENT, T-GROUP)
-- -------------------------------------------------------------------

-- agents (T-AGENT: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS agents_elevated_read ON public.agents;
    CREATE POLICY agents_elevated_read ON public.agents
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS agents_elevated_no_insert ON public.agents;
    CREATE POLICY agents_elevated_no_insert ON public.agents
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS agents_elevated_no_update ON public.agents;
    CREATE POLICY agents_elevated_no_update ON public.agents
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS agents_elevated_no_delete ON public.agents;
    CREATE POLICY agents_elevated_no_delete ON public.agents
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- challenges (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS challenges_elevated_read ON public.challenges;
    CREATE POLICY challenges_elevated_read ON public.challenges
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS challenges_elevated_no_insert ON public.challenges;
    CREATE POLICY challenges_elevated_no_insert ON public.challenges
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS challenges_elevated_no_update ON public.challenges;
    CREATE POLICY challenges_elevated_no_update ON public.challenges
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS challenges_elevated_no_delete ON public.challenges;
    CREATE POLICY challenges_elevated_no_delete ON public.challenges
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- claim_cluster_membership (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_cluster_membership_elevated_read ON public.claim_cluster_membership;
    CREATE POLICY claim_cluster_membership_elevated_read ON public.claim_cluster_membership
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_cluster_membership_elevated_no_insert ON public.claim_cluster_membership;
    CREATE POLICY claim_cluster_membership_elevated_no_insert ON public.claim_cluster_membership
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_cluster_membership_elevated_no_update ON public.claim_cluster_membership;
    CREATE POLICY claim_cluster_membership_elevated_no_update ON public.claim_cluster_membership
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_cluster_membership_elevated_no_delete ON public.claim_cluster_membership;
    CREATE POLICY claim_cluster_membership_elevated_no_delete ON public.claim_cluster_membership
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- claim_clusters (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_clusters_elevated_read ON public.claim_clusters;
    CREATE POLICY claim_clusters_elevated_read ON public.claim_clusters
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_clusters_elevated_no_insert ON public.claim_clusters;
    CREATE POLICY claim_clusters_elevated_no_insert ON public.claim_clusters
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_clusters_elevated_no_update ON public.claim_clusters;
    CREATE POLICY claim_clusters_elevated_no_update ON public.claim_clusters
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_clusters_elevated_no_delete ON public.claim_clusters;
    CREATE POLICY claim_clusters_elevated_no_delete ON public.claim_clusters
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- claim_frames (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_frames_elevated_read ON public.claim_frames;
    CREATE POLICY claim_frames_elevated_read ON public.claim_frames
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_frames_elevated_no_insert ON public.claim_frames;
    CREATE POLICY claim_frames_elevated_no_insert ON public.claim_frames
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_frames_elevated_no_update ON public.claim_frames;
    CREATE POLICY claim_frames_elevated_no_update ON public.claim_frames
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_frames_elevated_no_delete ON public.claim_frames;
    CREATE POLICY claim_frames_elevated_no_delete ON public.claim_frames
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- claim_neighborhood_membership (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_neighborhood_membership_elevated_read ON public.claim_neighborhood_membership;
    CREATE POLICY claim_neighborhood_membership_elevated_read ON public.claim_neighborhood_membership
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_neighborhood_membership_elevated_no_insert ON public.claim_neighborhood_membership;
    CREATE POLICY claim_neighborhood_membership_elevated_no_insert ON public.claim_neighborhood_membership
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_neighborhood_membership_elevated_no_update ON public.claim_neighborhood_membership;
    CREATE POLICY claim_neighborhood_membership_elevated_no_update ON public.claim_neighborhood_membership
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_neighborhood_membership_elevated_no_delete ON public.claim_neighborhood_membership;
    CREATE POLICY claim_neighborhood_membership_elevated_no_delete ON public.claim_neighborhood_membership
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- claim_signature_revocations (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_signature_revocations_elevated_read ON public.claim_signature_revocations;
    CREATE POLICY claim_signature_revocations_elevated_read ON public.claim_signature_revocations
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_signature_revocations_elevated_no_insert ON public.claim_signature_revocations;
    CREATE POLICY claim_signature_revocations_elevated_no_insert ON public.claim_signature_revocations
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_signature_revocations_elevated_no_update ON public.claim_signature_revocations;
    CREATE POLICY claim_signature_revocations_elevated_no_update ON public.claim_signature_revocations
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_signature_revocations_elevated_no_delete ON public.claim_signature_revocations;
    CREATE POLICY claim_signature_revocations_elevated_no_delete ON public.claim_signature_revocations
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- claim_versions (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_versions_elevated_read ON public.claim_versions;
    CREATE POLICY claim_versions_elevated_read ON public.claim_versions
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_versions_elevated_no_insert ON public.claim_versions;
    CREATE POLICY claim_versions_elevated_no_insert ON public.claim_versions
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_versions_elevated_no_update ON public.claim_versions;
    CREATE POLICY claim_versions_elevated_no_update ON public.claim_versions
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_versions_elevated_no_delete ON public.claim_versions;
    CREATE POLICY claim_versions_elevated_no_delete ON public.claim_versions
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- claims (T-OWN: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claims_elevated_read ON public.claims;
    CREATE POLICY claims_elevated_read ON public.claims
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claims_elevated_no_insert ON public.claims;
    CREATE POLICY claims_elevated_no_insert ON public.claims
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claims_elevated_no_update ON public.claims;
    CREATE POLICY claims_elevated_no_update ON public.claims
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claims_elevated_no_delete ON public.claims;
    CREATE POLICY claims_elevated_no_delete ON public.claims
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- contexts (T-OWN: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS contexts_elevated_read ON public.contexts;
    CREATE POLICY contexts_elevated_read ON public.contexts
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS contexts_elevated_no_insert ON public.contexts;
    CREATE POLICY contexts_elevated_no_insert ON public.contexts
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS contexts_elevated_no_update ON public.contexts;
    CREATE POLICY contexts_elevated_no_update ON public.contexts
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS contexts_elevated_no_delete ON public.contexts;
    CREATE POLICY contexts_elevated_no_delete ON public.contexts
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- ds_bayesian_divergence (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS ds_bayesian_divergence_elevated_read ON public.ds_bayesian_divergence;
    CREATE POLICY ds_bayesian_divergence_elevated_read ON public.ds_bayesian_divergence
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS ds_bayesian_divergence_elevated_no_insert ON public.ds_bayesian_divergence;
    CREATE POLICY ds_bayesian_divergence_elevated_no_insert ON public.ds_bayesian_divergence
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS ds_bayesian_divergence_elevated_no_update ON public.ds_bayesian_divergence;
    CREATE POLICY ds_bayesian_divergence_elevated_no_update ON public.ds_bayesian_divergence
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS ds_bayesian_divergence_elevated_no_delete ON public.ds_bayesian_divergence;
    CREATE POLICY ds_bayesian_divergence_elevated_no_delete ON public.ds_bayesian_divergence
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- ds_combined_beliefs (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS ds_combined_beliefs_elevated_read ON public.ds_combined_beliefs;
    CREATE POLICY ds_combined_beliefs_elevated_read ON public.ds_combined_beliefs
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS ds_combined_beliefs_elevated_no_insert ON public.ds_combined_beliefs;
    CREATE POLICY ds_combined_beliefs_elevated_no_insert ON public.ds_combined_beliefs
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS ds_combined_beliefs_elevated_no_update ON public.ds_combined_beliefs;
    CREATE POLICY ds_combined_beliefs_elevated_no_update ON public.ds_combined_beliefs
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS ds_combined_beliefs_elevated_no_delete ON public.ds_combined_beliefs;
    CREATE POLICY ds_combined_beliefs_elevated_no_delete ON public.ds_combined_beliefs
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- edges (T-EDGE: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS edges_elevated_read ON public.edges;
    CREATE POLICY edges_elevated_read ON public.edges
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS edges_elevated_no_insert ON public.edges;
    CREATE POLICY edges_elevated_no_insert ON public.edges
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS edges_elevated_no_update ON public.edges;
    CREATE POLICY edges_elevated_no_update ON public.edges
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS edges_elevated_no_delete ON public.edges;
    CREATE POLICY edges_elevated_no_delete ON public.edges
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- entity_mentions (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS entity_mentions_elevated_read ON public.entity_mentions;
    CREATE POLICY entity_mentions_elevated_read ON public.entity_mentions
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS entity_mentions_elevated_no_insert ON public.entity_mentions;
    CREATE POLICY entity_mentions_elevated_no_insert ON public.entity_mentions
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS entity_mentions_elevated_no_update ON public.entity_mentions;
    CREATE POLICY entity_mentions_elevated_no_update ON public.entity_mentions
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS entity_mentions_elevated_no_delete ON public.entity_mentions;
    CREATE POLICY entity_mentions_elevated_no_delete ON public.entity_mentions
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- evidence (T-OWN: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS evidence_elevated_read ON public.evidence;
    CREATE POLICY evidence_elevated_read ON public.evidence
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS evidence_elevated_no_insert ON public.evidence;
    CREATE POLICY evidence_elevated_no_insert ON public.evidence
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS evidence_elevated_no_update ON public.evidence;
    CREATE POLICY evidence_elevated_no_update ON public.evidence
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS evidence_elevated_no_delete ON public.evidence;
    CREATE POLICY evidence_elevated_no_delete ON public.evidence
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- frames (T-OWN: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS frames_elevated_read ON public.frames;
    CREATE POLICY frames_elevated_read ON public.frames
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS frames_elevated_no_insert ON public.frames;
    CREATE POLICY frames_elevated_no_insert ON public.frames
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS frames_elevated_no_update ON public.frames;
    CREATE POLICY frames_elevated_no_update ON public.frames
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS frames_elevated_no_delete ON public.frames;
    CREATE POLICY frames_elevated_no_delete ON public.frames
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- group_memberships (T-GROUP: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS group_memberships_elevated_read ON public.group_memberships;
    CREATE POLICY group_memberships_elevated_read ON public.group_memberships
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS group_memberships_elevated_no_insert ON public.group_memberships;
    CREATE POLICY group_memberships_elevated_no_insert ON public.group_memberships
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS group_memberships_elevated_no_update ON public.group_memberships;
    CREATE POLICY group_memberships_elevated_no_update ON public.group_memberships
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS group_memberships_elevated_no_delete ON public.group_memberships;
    CREATE POLICY group_memberships_elevated_no_delete ON public.group_memberships
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- groups (T-GROUP: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS groups_elevated_read ON public.groups;
    CREATE POLICY groups_elevated_read ON public.groups
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS groups_elevated_no_insert ON public.groups;
    CREATE POLICY groups_elevated_no_insert ON public.groups
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS groups_elevated_no_update ON public.groups;
    CREATE POLICY groups_elevated_no_update ON public.groups
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS groups_elevated_no_delete ON public.groups;
    CREATE POLICY groups_elevated_no_delete ON public.groups
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- harvester_claim_provenance (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS harvester_claim_provenance_elevated_read ON public.harvester_claim_provenance;
    CREATE POLICY harvester_claim_provenance_elevated_read ON public.harvester_claim_provenance
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS harvester_claim_provenance_elevated_no_insert ON public.harvester_claim_provenance;
    CREATE POLICY harvester_claim_provenance_elevated_no_insert ON public.harvester_claim_provenance
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS harvester_claim_provenance_elevated_no_update ON public.harvester_claim_provenance;
    CREATE POLICY harvester_claim_provenance_elevated_no_update ON public.harvester_claim_provenance
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS harvester_claim_provenance_elevated_no_delete ON public.harvester_claim_provenance;
    CREATE POLICY harvester_claim_provenance_elevated_no_delete ON public.harvester_claim_provenance
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- harvester_fragments (T-OWN: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS harvester_fragments_elevated_read ON public.harvester_fragments;
    CREATE POLICY harvester_fragments_elevated_read ON public.harvester_fragments
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS harvester_fragments_elevated_no_insert ON public.harvester_fragments;
    CREATE POLICY harvester_fragments_elevated_no_insert ON public.harvester_fragments
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS harvester_fragments_elevated_no_update ON public.harvester_fragments;
    CREATE POLICY harvester_fragments_elevated_no_update ON public.harvester_fragments
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS harvester_fragments_elevated_no_delete ON public.harvester_fragments;
    CREATE POLICY harvester_fragments_elevated_no_delete ON public.harvester_fragments
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- mass_functions (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS mass_functions_elevated_read ON public.mass_functions;
    CREATE POLICY mass_functions_elevated_read ON public.mass_functions
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS mass_functions_elevated_no_insert ON public.mass_functions;
    CREATE POLICY mass_functions_elevated_no_insert ON public.mass_functions
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS mass_functions_elevated_no_update ON public.mass_functions;
    CREATE POLICY mass_functions_elevated_no_update ON public.mass_functions
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS mass_functions_elevated_no_delete ON public.mass_functions;
    CREATE POLICY mass_functions_elevated_no_delete ON public.mass_functions
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- perspectives (T-OWN: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS perspectives_elevated_read ON public.perspectives;
    CREATE POLICY perspectives_elevated_read ON public.perspectives
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS perspectives_elevated_no_insert ON public.perspectives;
    CREATE POLICY perspectives_elevated_no_insert ON public.perspectives
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS perspectives_elevated_no_update ON public.perspectives;
    CREATE POLICY perspectives_elevated_no_update ON public.perspectives
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS perspectives_elevated_no_delete ON public.perspectives;
    CREATE POLICY perspectives_elevated_no_delete ON public.perspectives
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- reasoning_traces (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS reasoning_traces_elevated_read ON public.reasoning_traces;
    CREATE POLICY reasoning_traces_elevated_read ON public.reasoning_traces
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS reasoning_traces_elevated_no_insert ON public.reasoning_traces;
    CREATE POLICY reasoning_traces_elevated_no_insert ON public.reasoning_traces
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS reasoning_traces_elevated_no_update ON public.reasoning_traces;
    CREATE POLICY reasoning_traces_elevated_no_update ON public.reasoning_traces
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS reasoning_traces_elevated_no_delete ON public.reasoning_traces;
    CREATE POLICY reasoning_traces_elevated_no_delete ON public.reasoning_traces
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- recall_events (T-OWN-PRIV: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS recall_events_elevated_read ON public.recall_events;
    CREATE POLICY recall_events_elevated_read ON public.recall_events
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS recall_events_elevated_no_insert ON public.recall_events;
    CREATE POLICY recall_events_elevated_no_insert ON public.recall_events
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS recall_events_elevated_no_update ON public.recall_events;
    CREATE POLICY recall_events_elevated_no_update ON public.recall_events
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS recall_events_elevated_no_delete ON public.recall_events;
    CREATE POLICY recall_events_elevated_no_delete ON public.recall_events
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- triples (T-DER: read arm + write refusal)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS triples_elevated_read ON public.triples;
    CREATE POLICY triples_elevated_read ON public.triples
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS triples_elevated_no_insert ON public.triples;
    CREATE POLICY triples_elevated_no_insert ON public.triples
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS triples_elevated_no_update ON public.triples;
    CREATE POLICY triples_elevated_no_update ON public.triples
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS triples_elevated_no_delete ON public.triples;
    CREATE POLICY triples_elevated_no_delete ON public.triples
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- -------------------------------------------------------------------
-- 3b. READ ARM ONLY (T-AUDIT)
-- -------------------------------------------------------------------

-- privatization_audit (T-AUDIT: read arm only)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS privatization_audit_elevated_read ON public.privatization_audit;
    CREATE POLICY privatization_audit_elevated_read ON public.privatization_audit
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- security_events (T-AUDIT: read arm only)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS security_events_elevated_read ON public.security_events;
    CREATE POLICY security_events_elevated_read ON public.security_events
        AS PERMISSIVE FOR SELECT TO epigraph_app
        USING ((SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- -------------------------------------------------------------------
-- 3c. WRITE REFUSAL ONLY (T-DROP)
-- -------------------------------------------------------------------

-- claim_encryption (T-DROP: write refusal only)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_encryption_elevated_no_insert ON public.claim_encryption;
    CREATE POLICY claim_encryption_elevated_no_insert ON public.claim_encryption
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_encryption_elevated_no_update ON public.claim_encryption;
    CREATE POLICY claim_encryption_elevated_no_update ON public.claim_encryption
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_encryption_elevated_no_delete ON public.claim_encryption;
    CREATE POLICY claim_encryption_elevated_no_delete ON public.claim_encryption
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- claim_version_encryption (T-DROP: write refusal only)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_version_encryption_elevated_no_insert ON public.claim_version_encryption;
    CREATE POLICY claim_version_encryption_elevated_no_insert ON public.claim_version_encryption
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_version_encryption_elevated_no_update ON public.claim_version_encryption;
    CREATE POLICY claim_version_encryption_elevated_no_update ON public.claim_version_encryption
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS claim_version_encryption_elevated_no_delete ON public.claim_version_encryption;
    CREATE POLICY claim_version_encryption_elevated_no_delete ON public.claim_version_encryption
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- communities (T-DROP: write refusal only)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS communities_elevated_no_insert ON public.communities;
    CREATE POLICY communities_elevated_no_insert ON public.communities
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS communities_elevated_no_update ON public.communities;
    CREATE POLICY communities_elevated_no_update ON public.communities
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS communities_elevated_no_delete ON public.communities;
    CREATE POLICY communities_elevated_no_delete ON public.communities
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- edge_encryption (T-DROP: write refusal only)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS edge_encryption_elevated_no_insert ON public.edge_encryption;
    CREATE POLICY edge_encryption_elevated_no_insert ON public.edge_encryption
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS edge_encryption_elevated_no_update ON public.edge_encryption;
    CREATE POLICY edge_encryption_elevated_no_update ON public.edge_encryption
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS edge_encryption_elevated_no_delete ON public.edge_encryption;
    CREATE POLICY edge_encryption_elevated_no_delete ON public.edge_encryption
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- evidence_encryption (T-DROP: write refusal only)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS evidence_encryption_elevated_no_insert ON public.evidence_encryption;
    CREATE POLICY evidence_encryption_elevated_no_insert ON public.evidence_encryption
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS evidence_encryption_elevated_no_update ON public.evidence_encryption;
    CREATE POLICY evidence_encryption_elevated_no_update ON public.evidence_encryption
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS evidence_encryption_elevated_no_delete ON public.evidence_encryption;
    CREATE POLICY evidence_encryption_elevated_no_delete ON public.evidence_encryption
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- experiment_entity_mentions (T-DROP: write refusal only)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS experiment_entity_mentions_elevated_no_insert ON public.experiment_entity_mentions;
    CREATE POLICY experiment_entity_mentions_elevated_no_insert ON public.experiment_entity_mentions
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS experiment_entity_mentions_elevated_no_update ON public.experiment_entity_mentions;
    CREATE POLICY experiment_entity_mentions_elevated_no_update ON public.experiment_entity_mentions
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS experiment_entity_mentions_elevated_no_delete ON public.experiment_entity_mentions;
    CREATE POLICY experiment_entity_mentions_elevated_no_delete ON public.experiment_entity_mentions
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- experiment_triples (T-DROP: write refusal only)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS experiment_triples_elevated_no_insert ON public.experiment_triples;
    CREATE POLICY experiment_triples_elevated_no_insert ON public.experiment_triples
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS experiment_triples_elevated_no_update ON public.experiment_triples;
    CREATE POLICY experiment_triples_elevated_no_update ON public.experiment_triples
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS experiment_triples_elevated_no_delete ON public.experiment_triples;
    CREATE POLICY experiment_triples_elevated_no_delete ON public.experiment_triples
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;

-- group_key_epochs (T-DROP: write refusal only)
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS group_key_epochs_elevated_no_insert ON public.group_key_epochs;
    CREATE POLICY group_key_epochs_elevated_no_insert ON public.group_key_epochs
        AS RESTRICTIVE FOR INSERT TO epigraph_app
        WITH CHECK (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS group_key_epochs_elevated_no_update ON public.group_key_epochs;
    CREATE POLICY group_key_epochs_elevated_no_update ON public.group_key_epochs
        AS RESTRICTIVE FOR UPDATE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
    DROP POLICY IF EXISTS group_key_epochs_elevated_no_delete ON public.group_key_epochs;
    CREATE POLICY group_key_epochs_elevated_no_delete ON public.group_key_epochs
        AS RESTRICTIVE FOR DELETE TO epigraph_app
        USING (NOT (SELECT public.epigraph_is_elevated()));
END $$;
COMMIT;
