-- Migration 036: Challenges table + learning_events FK + event sequencing
--
-- Creates the challenges table for the conflict resolution lifecycle,
-- adds the deferred FK from learning_events to challenges, and creates
-- a sequence for race-safe event ordering.

CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id UUID NOT NULL REFERENCES claims(id),
    challenger_id UUID REFERENCES agents(id),
    challenge_type VARCHAR(50) NOT NULL,
    explanation TEXT NOT NULL,
    state VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES agents(id),
    resolution_details JSONB
);

CREATE INDEX idx_challenges_claim ON challenges (claim_id);
CREATE INDEX idx_challenges_state ON challenges (state);

-- Add the deferred FK from migration 033
ALTER TABLE learning_events
    ADD CONSTRAINT fk_learning_events_challenge
    FOREIGN KEY (challenge_id) REFERENCES challenges(id);

-- Race-safe event ordering sequence
CREATE SEQUENCE IF NOT EXISTS events_graph_version_seq;
