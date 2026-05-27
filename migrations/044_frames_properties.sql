-- 044_frames_properties.sql
--
-- Add a JSONB properties column to `frames` so operators can configure
-- per-frame epistemic parameters at runtime without code releases. The
-- canonical use case is locality-aware discounting: different frames
-- (binary_truth, textbook_veracity_*, research_validity, ...) carry
-- different epistemological commitments about what intra-source evidence
-- means for independence.
--
-- Conventional keys (consumed by `crates/epigraph-engine`):
--   * `intra_evidence_locality_factor` :: float -- multiplier applied
--     to per-BBA source_strength when the supporting evidence is
--     intra-source within this frame. Overrides the global default
--     in calibration.toml::evidence_locality.intra_evidence_locality_factor.
--     Range conventionally (0.0, 1.0]; 1.0 means "no locality discount
--     for this frame" (e.g. textbook frames where same-source is the
--     point, not a correlation concern); 0.3 is the global default.
--
-- Operators set per-frame overrides via:
--   UPDATE frames SET properties = properties ||
--     jsonb_build_object('intra_evidence_locality_factor', 0.5)
--   WHERE name = 'research_validity';

ALTER TABLE frames
    ADD COLUMN properties JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN frames.properties IS
'Per-frame configuration overrides consumed by epigraph-engine. '
'Conventional keys: intra_evidence_locality_factor (float, locality-discount '
'multiplier; falls back to calibration.toml when absent). See migration 044.';
