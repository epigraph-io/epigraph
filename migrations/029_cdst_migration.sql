-- CDST Migration: Complementary Dempster-Shafer Theory support
-- Separates genuine conflict from frame incompleteness (missing propositions)

-- Frame versioning: track frame extensions
ALTER TABLE frames ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1;

-- Conflict/missing decomposition on claims
-- Existing mass_on_empty = genuine conflict in CDST
-- New mass_on_missing = m((Omega, true)) = frame may be incomplete
ALTER TABLE claims ADD COLUMN IF NOT EXISTS mass_on_missing DOUBLE PRECISION DEFAULT 0.0;

-- Conflict/missing on scoped belief cache
ALTER TABLE ds_combined_beliefs ADD COLUMN IF NOT EXISTS mass_on_missing DOUBLE PRECISION DEFAULT 0.0;

-- Frame version tracking on divergence records
ALTER TABLE ds_bayesian_divergence ADD COLUMN IF NOT EXISTS frame_version INTEGER DEFAULT 1;
