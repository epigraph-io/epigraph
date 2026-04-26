-- Migration 101: Add validity constraints and staleness index to divergence cache
--
-- Rationale: On 2026-03-16, a -0.0 pignistic_prob was written to
-- ds_bayesian_divergence for claim 70d289c5-7a0c-4e08-98cf-d21d0ea988f3.
-- This inflated the KL divergence to 1.491 and caused it to appear as the
-- top divergence outlier.  The root cause (floating-point underflow in BetP
-- when non_classical_mass ≈ 1.0) is fixed in the application layer; this
-- migration adds defence-in-depth at the database level.
--
-- Note: IEEE 754 -0.0 satisfies BETWEEN 0.0 AND 1.0, so the CHECK constraint
-- does NOT catch the exact bug — but it blocks obviously-invalid values
-- (< -1e-9 or > 1 + 1e-9).  Application-layer clamping is the primary guard.

ALTER TABLE ds_bayesian_divergence
    ADD CONSTRAINT divergence_pignistic_prob_valid
    CHECK (pignistic_prob >= -1e-9 AND pignistic_prob <= 1.0 + 1e-9);

ALTER TABLE ds_bayesian_divergence
    ADD CONSTRAINT divergence_bayesian_posterior_valid
    CHECK (bayesian_posterior >= 0.0 AND bayesian_posterior <= 1.0);

ALTER TABLE ds_bayesian_divergence
    ADD CONSTRAINT divergence_kl_divergence_non_negative
    CHECK (kl_divergence >= 0.0);

-- Index to support the 7-day TTL filter in get_latest and top_divergent queries
CREATE INDEX IF NOT EXISTS idx_divergence_computed_at
    ON ds_bayesian_divergence (computed_at DESC);
