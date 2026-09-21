-- Record WHICH frame the cached belief scalars on `claims` summarize.
--
-- `claim_frames` is keyed PRIMARY KEY (claim_id, frame_id): a claim carrying
-- different beliefs in different contexts is intended. But `claims` holds six
-- belief columns — belief, plausibility, mass_on_empty, pignistic_prob,
-- mass_on_missing, open_world_mass — with no frame reference at all. A reader of
-- `claims.pignistic_prob` therefore cannot tell which of N contexts the number
-- describes, which makes it unfalsifiable: it looks authoritative and silently
-- means one particular thing.
--
-- Backlog 696d3a1c was the sharp end of this. Every frame's recompute wrote those
-- same six columns and the alphabetically last frame won, silently reverting
-- edge-derived belief. `recompute_claim_cached_belief` now designates one frame;
-- this column records which, so the cache is self-describing rather than an
-- anonymous one-of-N.
--
-- Additive and nullable on purpose. NULL means "written before this column
-- existed, provenance unknown" — which is the honest value for every pre-existing
-- row and must not be backfilled with a guess.

ALTER TABLE claims
    ADD COLUMN IF NOT EXISTS belief_frame_id uuid REFERENCES frames(id);

COMMENT ON COLUMN claims.belief_frame_id IS
    'Frame whose combined belief the cached belief/plausibility/pignistic_prob/'
    'mass_on_empty/mass_on_missing/open_world_mass columns summarize. NULL means '
    'the cache predates this column and its frame is unknown. Per-frame belief is '
    'NOT stored here — it is recomputed from mass_functions by the framed '
    'get_belief path, which is the source of truth for any specific context.';

-- Partial: the overwhelming majority of rows are NULL until recomputed, and the
-- index exists to answer "which claims are cached under frame X", not to scan NULLs.
CREATE INDEX IF NOT EXISTS idx_claims_belief_frame
    ON claims (belief_frame_id) WHERE belief_frame_id IS NOT NULL;
