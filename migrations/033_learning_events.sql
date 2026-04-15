-- Migration 033: Learning events (G15)
--
-- Captures lessons learned when challenges are resolved.
-- Links back to the challenge and conflicting claims for provenance.
--
-- Note: challenge_id is a plain UUID (no FK) because the challenges table
-- does not yet exist in the migration sequence. A future migration should
-- add: ALTER TABLE learning_events ADD CONSTRAINT fk_learning_events_challenge
--       FOREIGN KEY (challenge_id) REFERENCES challenges(id);

CREATE TABLE learning_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_id UUID NOT NULL,
    conflict_claim_a UUID REFERENCES claims(id),
    conflict_claim_b UUID REFERENCES claims(id),
    resolution TEXT NOT NULL,
    lesson TEXT NOT NULL,
    extraction_adjustments JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_learning_events_challenge ON learning_events (challenge_id);
CREATE INDEX idx_learning_events_claims ON learning_events (conflict_claim_a, conflict_claim_b);
