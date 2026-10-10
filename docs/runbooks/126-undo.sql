-- ===================================================================
-- 126-undo.sql: take migration 126 (the elevated read arms and the elevated
-- write refusal) back out, on the migration (superuser) DSN.
--
-- READ FIRST. Nothing in any binary names these policies, so no binary has to
-- roll back first. Run this BEFORE 125-undo, which refuses while any policy
-- reads `epigraph_is_elevated()`. While an elevation session is live, undoing
-- this ends what that session can READ (back to its own groups) and lifts its
-- write refusal to Rust's alone (`ScopedPool::begin_as`); end live sessions
-- first if that matters.
--
-- FORM: the same as 126 itself. One table per DO block, each followed by its
-- own COMMIT, each with a transaction-local 3 s lock timeout, each policy
-- dropped IF EXISTS. A lock timeout stops the script at one table with the
-- tables before it disarmed; rerun it to finish. Run it either as one
-- simple-query batch or with `psql -v ON_ERROR_STOP=1 -f` (in autocommit,
-- each COMMIT answers `WARNING: there is no transaction in progress`, which
-- is expected).
--
-- WHAT IT LEAVES: 126's `_sqlx_migrations` row. Re-arming is a NEW migration,
-- never a re-run of 126.
-- ===================================================================


-- agents
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS agents_elevated_read ON public.agents;
    DROP POLICY IF EXISTS agents_elevated_no_insert ON public.agents;
    DROP POLICY IF EXISTS agents_elevated_no_update ON public.agents;
    DROP POLICY IF EXISTS agents_elevated_no_delete ON public.agents;
END $$;
COMMIT;

-- challenges
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS challenges_elevated_read ON public.challenges;
    DROP POLICY IF EXISTS challenges_elevated_no_insert ON public.challenges;
    DROP POLICY IF EXISTS challenges_elevated_no_update ON public.challenges;
    DROP POLICY IF EXISTS challenges_elevated_no_delete ON public.challenges;
END $$;
COMMIT;

-- claim_cluster_membership
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_cluster_membership_elevated_read ON public.claim_cluster_membership;
    DROP POLICY IF EXISTS claim_cluster_membership_elevated_no_insert ON public.claim_cluster_membership;
    DROP POLICY IF EXISTS claim_cluster_membership_elevated_no_update ON public.claim_cluster_membership;
    DROP POLICY IF EXISTS claim_cluster_membership_elevated_no_delete ON public.claim_cluster_membership;
END $$;
COMMIT;

-- claim_clusters
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_clusters_elevated_read ON public.claim_clusters;
    DROP POLICY IF EXISTS claim_clusters_elevated_no_insert ON public.claim_clusters;
    DROP POLICY IF EXISTS claim_clusters_elevated_no_update ON public.claim_clusters;
    DROP POLICY IF EXISTS claim_clusters_elevated_no_delete ON public.claim_clusters;
END $$;
COMMIT;

-- claim_frames
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_frames_elevated_read ON public.claim_frames;
    DROP POLICY IF EXISTS claim_frames_elevated_no_insert ON public.claim_frames;
    DROP POLICY IF EXISTS claim_frames_elevated_no_update ON public.claim_frames;
    DROP POLICY IF EXISTS claim_frames_elevated_no_delete ON public.claim_frames;
END $$;
COMMIT;

-- claim_neighborhood_membership
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_neighborhood_membership_elevated_read ON public.claim_neighborhood_membership;
    DROP POLICY IF EXISTS claim_neighborhood_membership_elevated_no_insert ON public.claim_neighborhood_membership;
    DROP POLICY IF EXISTS claim_neighborhood_membership_elevated_no_update ON public.claim_neighborhood_membership;
    DROP POLICY IF EXISTS claim_neighborhood_membership_elevated_no_delete ON public.claim_neighborhood_membership;
END $$;
COMMIT;

-- claim_signature_revocations
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_signature_revocations_elevated_read ON public.claim_signature_revocations;
    DROP POLICY IF EXISTS claim_signature_revocations_elevated_no_insert ON public.claim_signature_revocations;
    DROP POLICY IF EXISTS claim_signature_revocations_elevated_no_update ON public.claim_signature_revocations;
    DROP POLICY IF EXISTS claim_signature_revocations_elevated_no_delete ON public.claim_signature_revocations;
END $$;
COMMIT;

-- claim_versions
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_versions_elevated_read ON public.claim_versions;
    DROP POLICY IF EXISTS claim_versions_elevated_no_insert ON public.claim_versions;
    DROP POLICY IF EXISTS claim_versions_elevated_no_update ON public.claim_versions;
    DROP POLICY IF EXISTS claim_versions_elevated_no_delete ON public.claim_versions;
END $$;
COMMIT;

-- claims
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claims_elevated_read ON public.claims;
    DROP POLICY IF EXISTS claims_elevated_no_insert ON public.claims;
    DROP POLICY IF EXISTS claims_elevated_no_update ON public.claims;
    DROP POLICY IF EXISTS claims_elevated_no_delete ON public.claims;
END $$;
COMMIT;

-- contexts
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS contexts_elevated_read ON public.contexts;
    DROP POLICY IF EXISTS contexts_elevated_no_insert ON public.contexts;
    DROP POLICY IF EXISTS contexts_elevated_no_update ON public.contexts;
    DROP POLICY IF EXISTS contexts_elevated_no_delete ON public.contexts;
END $$;
COMMIT;

-- ds_bayesian_divergence
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS ds_bayesian_divergence_elevated_read ON public.ds_bayesian_divergence;
    DROP POLICY IF EXISTS ds_bayesian_divergence_elevated_no_insert ON public.ds_bayesian_divergence;
    DROP POLICY IF EXISTS ds_bayesian_divergence_elevated_no_update ON public.ds_bayesian_divergence;
    DROP POLICY IF EXISTS ds_bayesian_divergence_elevated_no_delete ON public.ds_bayesian_divergence;
END $$;
COMMIT;

-- ds_combined_beliefs
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS ds_combined_beliefs_elevated_read ON public.ds_combined_beliefs;
    DROP POLICY IF EXISTS ds_combined_beliefs_elevated_no_insert ON public.ds_combined_beliefs;
    DROP POLICY IF EXISTS ds_combined_beliefs_elevated_no_update ON public.ds_combined_beliefs;
    DROP POLICY IF EXISTS ds_combined_beliefs_elevated_no_delete ON public.ds_combined_beliefs;
END $$;
COMMIT;

-- edges
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS edges_elevated_read ON public.edges;
    DROP POLICY IF EXISTS edges_elevated_no_insert ON public.edges;
    DROP POLICY IF EXISTS edges_elevated_no_update ON public.edges;
    DROP POLICY IF EXISTS edges_elevated_no_delete ON public.edges;
END $$;
COMMIT;

-- entity_mentions
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS entity_mentions_elevated_read ON public.entity_mentions;
    DROP POLICY IF EXISTS entity_mentions_elevated_no_insert ON public.entity_mentions;
    DROP POLICY IF EXISTS entity_mentions_elevated_no_update ON public.entity_mentions;
    DROP POLICY IF EXISTS entity_mentions_elevated_no_delete ON public.entity_mentions;
END $$;
COMMIT;

-- evidence
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS evidence_elevated_read ON public.evidence;
    DROP POLICY IF EXISTS evidence_elevated_no_insert ON public.evidence;
    DROP POLICY IF EXISTS evidence_elevated_no_update ON public.evidence;
    DROP POLICY IF EXISTS evidence_elevated_no_delete ON public.evidence;
END $$;
COMMIT;

-- frames
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS frames_elevated_read ON public.frames;
    DROP POLICY IF EXISTS frames_elevated_no_insert ON public.frames;
    DROP POLICY IF EXISTS frames_elevated_no_update ON public.frames;
    DROP POLICY IF EXISTS frames_elevated_no_delete ON public.frames;
END $$;
COMMIT;

-- group_memberships
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS group_memberships_elevated_read ON public.group_memberships;
    DROP POLICY IF EXISTS group_memberships_elevated_no_insert ON public.group_memberships;
    DROP POLICY IF EXISTS group_memberships_elevated_no_update ON public.group_memberships;
    DROP POLICY IF EXISTS group_memberships_elevated_no_delete ON public.group_memberships;
END $$;
COMMIT;

-- groups
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS groups_elevated_read ON public.groups;
    DROP POLICY IF EXISTS groups_elevated_no_insert ON public.groups;
    DROP POLICY IF EXISTS groups_elevated_no_update ON public.groups;
    DROP POLICY IF EXISTS groups_elevated_no_delete ON public.groups;
END $$;
COMMIT;

-- harvester_claim_provenance
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS harvester_claim_provenance_elevated_read ON public.harvester_claim_provenance;
    DROP POLICY IF EXISTS harvester_claim_provenance_elevated_no_insert ON public.harvester_claim_provenance;
    DROP POLICY IF EXISTS harvester_claim_provenance_elevated_no_update ON public.harvester_claim_provenance;
    DROP POLICY IF EXISTS harvester_claim_provenance_elevated_no_delete ON public.harvester_claim_provenance;
END $$;
COMMIT;

-- harvester_fragments
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS harvester_fragments_elevated_read ON public.harvester_fragments;
    DROP POLICY IF EXISTS harvester_fragments_elevated_no_insert ON public.harvester_fragments;
    DROP POLICY IF EXISTS harvester_fragments_elevated_no_update ON public.harvester_fragments;
    DROP POLICY IF EXISTS harvester_fragments_elevated_no_delete ON public.harvester_fragments;
END $$;
COMMIT;

-- mass_functions
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS mass_functions_elevated_read ON public.mass_functions;
    DROP POLICY IF EXISTS mass_functions_elevated_no_insert ON public.mass_functions;
    DROP POLICY IF EXISTS mass_functions_elevated_no_update ON public.mass_functions;
    DROP POLICY IF EXISTS mass_functions_elevated_no_delete ON public.mass_functions;
END $$;
COMMIT;

-- perspectives
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS perspectives_elevated_read ON public.perspectives;
    DROP POLICY IF EXISTS perspectives_elevated_no_insert ON public.perspectives;
    DROP POLICY IF EXISTS perspectives_elevated_no_update ON public.perspectives;
    DROP POLICY IF EXISTS perspectives_elevated_no_delete ON public.perspectives;
END $$;
COMMIT;

-- reasoning_traces
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS reasoning_traces_elevated_read ON public.reasoning_traces;
    DROP POLICY IF EXISTS reasoning_traces_elevated_no_insert ON public.reasoning_traces;
    DROP POLICY IF EXISTS reasoning_traces_elevated_no_update ON public.reasoning_traces;
    DROP POLICY IF EXISTS reasoning_traces_elevated_no_delete ON public.reasoning_traces;
END $$;
COMMIT;

-- recall_events
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS recall_events_elevated_read ON public.recall_events;
    DROP POLICY IF EXISTS recall_events_elevated_no_insert ON public.recall_events;
    DROP POLICY IF EXISTS recall_events_elevated_no_update ON public.recall_events;
    DROP POLICY IF EXISTS recall_events_elevated_no_delete ON public.recall_events;
END $$;
COMMIT;

-- triples
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS triples_elevated_read ON public.triples;
    DROP POLICY IF EXISTS triples_elevated_no_insert ON public.triples;
    DROP POLICY IF EXISTS triples_elevated_no_update ON public.triples;
    DROP POLICY IF EXISTS triples_elevated_no_delete ON public.triples;
END $$;
COMMIT;

-- privatization_audit
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS privatization_audit_elevated_read ON public.privatization_audit;
END $$;
COMMIT;

-- security_events
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS security_events_elevated_read ON public.security_events;
END $$;
COMMIT;

-- claim_encryption
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_encryption_elevated_no_insert ON public.claim_encryption;
    DROP POLICY IF EXISTS claim_encryption_elevated_no_update ON public.claim_encryption;
    DROP POLICY IF EXISTS claim_encryption_elevated_no_delete ON public.claim_encryption;
END $$;
COMMIT;

-- claim_version_encryption
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS claim_version_encryption_elevated_no_insert ON public.claim_version_encryption;
    DROP POLICY IF EXISTS claim_version_encryption_elevated_no_update ON public.claim_version_encryption;
    DROP POLICY IF EXISTS claim_version_encryption_elevated_no_delete ON public.claim_version_encryption;
END $$;
COMMIT;

-- communities
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS communities_elevated_no_insert ON public.communities;
    DROP POLICY IF EXISTS communities_elevated_no_update ON public.communities;
    DROP POLICY IF EXISTS communities_elevated_no_delete ON public.communities;
END $$;
COMMIT;

-- edge_encryption
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS edge_encryption_elevated_no_insert ON public.edge_encryption;
    DROP POLICY IF EXISTS edge_encryption_elevated_no_update ON public.edge_encryption;
    DROP POLICY IF EXISTS edge_encryption_elevated_no_delete ON public.edge_encryption;
END $$;
COMMIT;

-- evidence_encryption
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS evidence_encryption_elevated_no_insert ON public.evidence_encryption;
    DROP POLICY IF EXISTS evidence_encryption_elevated_no_update ON public.evidence_encryption;
    DROP POLICY IF EXISTS evidence_encryption_elevated_no_delete ON public.evidence_encryption;
END $$;
COMMIT;

-- experiment_entity_mentions
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS experiment_entity_mentions_elevated_no_insert ON public.experiment_entity_mentions;
    DROP POLICY IF EXISTS experiment_entity_mentions_elevated_no_update ON public.experiment_entity_mentions;
    DROP POLICY IF EXISTS experiment_entity_mentions_elevated_no_delete ON public.experiment_entity_mentions;
END $$;
COMMIT;

-- experiment_triples
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS experiment_triples_elevated_no_insert ON public.experiment_triples;
    DROP POLICY IF EXISTS experiment_triples_elevated_no_update ON public.experiment_triples;
    DROP POLICY IF EXISTS experiment_triples_elevated_no_delete ON public.experiment_triples;
END $$;
COMMIT;

-- group_key_epochs
DO $$
BEGIN
    PERFORM set_config('lock_timeout', '3s', true);
    DROP POLICY IF EXISTS group_key_epochs_elevated_no_insert ON public.group_key_epochs;
    DROP POLICY IF EXISTS group_key_epochs_elevated_no_update ON public.group_key_epochs;
    DROP POLICY IF EXISTS group_key_epochs_elevated_no_delete ON public.group_key_epochs;
END $$;
COMMIT;
