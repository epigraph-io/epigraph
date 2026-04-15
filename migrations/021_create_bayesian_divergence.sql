-- DS vs Bayesian divergence tracking (dekg-planning-doc §2.2)
--
-- Stores pignistic probability (DS decision transform) alongside
-- the Bayesian posterior (truth_value) so we can detect when the
-- two frameworks disagree significantly.

CREATE TABLE ds_bayesian_divergence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    frame_id UUID NOT NULL REFERENCES frames(id) ON DELETE CASCADE,
    pignistic_prob DOUBLE PRECISION NOT NULL,
    bayesian_posterior DOUBLE PRECISION NOT NULL,
    kl_divergence DOUBLE PRECISION NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(claim_id, frame_id, computed_at)
);

CREATE INDEX idx_divergence_claim ON ds_bayesian_divergence(claim_id);
CREATE INDEX idx_divergence_kl ON ds_bayesian_divergence(kl_divergence DESC);
