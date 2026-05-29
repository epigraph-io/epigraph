-- CDST claim classification: 'supported' | 'contradicted' | 'not_enough_info'.
-- NULL = unclassified (no BBAs yet, or not recomputed since this column was added).
--
-- Computed by the deterministic BetP 7-rule cascade
-- (epigraph_engine::classifier::classify) inside recompute_combined_belief —
-- a verdict on the claim's *combined* belief, parallel to the cached
-- pignistic_prob. Populated / refreshed in bulk via the `recompute_beliefs`
-- MCP tool (recompute_beliefs → recompute_claim_belief_on_frame →
-- recompute_combined_belief).
--
-- Replaces the deprecated EpigraphV2 scripts/classify_mass_functions.py, which
-- stored the label in claims.properties->>'cdst_label' (no current Rust reader).
ALTER TABLE claims ADD COLUMN classification TEXT;

-- Partial index: the common query is "show me contradicted / NEI claims".
CREATE INDEX idx_claims_classification ON claims (classification) WHERE classification IS NOT NULL;
