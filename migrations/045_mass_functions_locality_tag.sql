-- Migration 045: add mass_functions.locality_tag for explicit BBA typing.
--
-- See issue #197 and docs/superpowers/plans/2026-05-28-locality-tag-schema.md.
--
-- Phase 1a of the locality-tag work: additive column + index + default.
-- Forward write paths populate this column in the same PR; backfill of the
-- existing 279 894 rows is a separate one-shot SQL (Phase 1b) AFTER deploy.

ALTER TABLE mass_functions
    ADD COLUMN locality_tag varchar(20) NOT NULL DEFAULT 'unknown';

CREATE INDEX idx_mass_functions_locality_tag ON mass_functions(locality_tag);

COMMENT ON COLUMN mass_functions.locality_tag IS
    'Locality classification of this BBA''s underlying evidence relative '
    'to its claim''s asserting paper. Values: intra (evidence cites the '
    'same paper that asserts the claim), cross (evidence is from a '
    'different paper), unknown (no evidence row attached, or pre-locality '
    'classification). Read at combine-time with evidence_type to compute '
    'effective source_strength dynamically. See issue #197.';
