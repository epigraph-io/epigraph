-- Migration 032: Counterfactual scenarios (G4, G5)
--
-- When two claims contradict, the system generates counterfactual scenarios
-- to identify discriminating tests that could resolve the conflict.

CREATE TABLE counterfactual_scenarios (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conflict_event_id UUID,
    claim_a_id UUID REFERENCES claims(id),
    claim_b_id UUID REFERENCES claims(id),
    scenario_a JSONB NOT NULL,
    scenario_b JSONB NOT NULL,
    discriminating_tests JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_counterfactual_claims ON counterfactual_scenarios (claim_a_id, claim_b_id);
