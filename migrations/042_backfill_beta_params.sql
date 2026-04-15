-- Backfill Beta-Bernoulli parameters for existing claims.
--
-- Derives α/β from existing DS belief/plausibility columns.
-- Uses effective sample size ~10 for claims with DS data,
-- weak prior (n≈2) for claims with only truth_value.
-- Leaves claims already at (1.0, 1.0) that have no data as uniform priors.

-- Claims with DS belief/plausibility: effective sample size ~10
UPDATE claims SET
  beta_alpha = 1.0 + COALESCE(belief, 0.5) * 10.0,
  beta_beta  = 1.0 + (1.0 - COALESCE(plausibility, 0.5)) * 10.0
WHERE belief IS NOT NULL
  AND beta_alpha = 1.0
  AND beta_beta = 1.0;

-- Claims with only truth_value (no DS): weak prior centered on truth_value
UPDATE claims SET
  beta_alpha = 1.0 + truth_value,
  beta_beta  = 1.0 + (1.0 - truth_value)
WHERE belief IS NULL
  AND beta_alpha = 1.0
  AND beta_beta = 1.0
  AND truth_value IS NOT NULL
  AND truth_value != 0.5;
