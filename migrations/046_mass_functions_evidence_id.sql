-- Migration 046: add mass_functions.evidence_id FK for per-BBA evidence provenance.
--
-- See issue #197 and docs/superpowers/plans/2026-05-28-locality-tag-schema.md.
--
-- Phase 3 of the locality work: rather than denormalize locality into
-- `locality_tag` (Phase 1a/1b), the long-term ground truth is the evidence
-- row that produced the BBA. When `evidence_id` is set, locality is derivable
-- directly: compare `evidence.properties->>'doi'` to the DOI of the paper
-- asserting `mass_functions.claim_id`. `locality_tag` stays in place as the
-- cache for legacy rows where the evidence link is not recoverable.
--
-- ON DELETE SET NULL: when an evidence row is removed (e.g. retracted),
-- the BBA stays but loses its evidence pointer. The combine path falls back
-- to `locality_tag` and `source_strength` for the orphaned BBA. We do NOT
-- cascade-delete the BBA because callers may want to mark it stale rather
-- than vanish a row that historical recompute output depends on.

ALTER TABLE mass_functions
    ADD COLUMN evidence_id uuid NULL
    REFERENCES evidence(id) ON DELETE SET NULL;

CREATE INDEX idx_mass_functions_evidence_id
    ON mass_functions(evidence_id)
    WHERE evidence_id IS NOT NULL;

COMMENT ON COLUMN mass_functions.evidence_id IS
    'FK to the specific evidence row that produced this BBA. NULL for '
    'BBAs from non-evidence sources (edge_factor, agent-only conversational, '
    'pre-Phase-3 legacy rows that the linking heuristic could not resolve). '
    'When set, locality is derivable from primary data: compare '
    'evidence.properties->>''doi'' to the doi of the paper that asserts '
    'mass_functions.claim_id. See issue #197 Phase 3.';
