-- Add open-world mass column for CDST complement focal element tracking.
-- Represents frame incompleteness: "these hypotheses might not cover reality."
ALTER TABLE claims
    ADD COLUMN IF NOT EXISTS open_world_mass DOUBLE PRECISION DEFAULT NULL;

-- Backfill from mass_on_missing (migration 029): CDST complement mass.
UPDATE claims
    SET open_world_mass = COALESCE(mass_on_missing, 0.0)
    WHERE mass_on_missing IS NOT NULL AND mass_on_missing > 0;

-- For claims without mass function data: conservative default = half of ignorance width.
UPDATE claims
    SET open_world_mass = GREATEST(0.0, (COALESCE(plausibility, 1.0) - COALESCE(belief, 0.0)) * 0.5)
    WHERE open_world_mass IS NULL;

-- Set NOT NULL after backfill.
ALTER TABLE claims
    ALTER COLUMN open_world_mass SET DEFAULT 0.0,
    ALTER COLUMN open_world_mass SET NOT NULL;

-- Index for frame_validates edge queries.
CREATE INDEX IF NOT EXISTS idx_edges_frame_validates
    ON edges (source_id, target_id)
    WHERE relationship = 'frame_validates';
