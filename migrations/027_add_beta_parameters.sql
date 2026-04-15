-- Migration: 027_add_beta_parameters
-- Description: Add Beta-Bernoulli parameters for parallel Bayesian tracking
--
-- Evidence:
-- - DEKG planning doc §2.2 requires running DS and Bayesian side-by-side
-- - Current KL divergence compares pignistic against static truth_value
-- - Proper Beta-Bernoulli provides live posterior that responds to evidence
--
-- Reasoning:
-- - Default (1.0, 1.0) = uniform Beta prior (maximum ignorance)
-- - Posterior = alpha / (alpha + beta) converges with evidence
-- - Enables true DS-vs-Bayesian comparison instead of static proxy
--
-- Verification:
-- - cargo test --lib passes
-- - Existing queries unaffected (new columns have defaults)

ALTER TABLE claims ADD COLUMN IF NOT EXISTS beta_alpha DOUBLE PRECISION DEFAULT 1.0;
ALTER TABLE claims ADD COLUMN IF NOT EXISTS beta_beta DOUBLE PRECISION DEFAULT 1.0;
