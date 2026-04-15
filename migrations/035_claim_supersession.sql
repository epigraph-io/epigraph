-- Claim supersession: version chains for correcting erroneous claims
--
-- Rather than mutating claims in-place (which breaks cryptographic integrity),
-- a new claim is created that explicitly supersedes the old one. The old claim
-- is marked is_current = false. This preserves the full epistemic history.

ALTER TABLE claims ADD COLUMN supersedes UUID REFERENCES claims(id);
ALTER TABLE claims ADD COLUMN is_current BOOLEAN NOT NULL DEFAULT true;

-- Walk version chains: find what supersedes a given claim
CREATE INDEX idx_claims_supersedes ON claims(supersedes) WHERE supersedes IS NOT NULL;

-- Most queries should filter to current claims only
CREATE INDEX idx_claims_is_current ON claims(is_current) WHERE is_current = true;
