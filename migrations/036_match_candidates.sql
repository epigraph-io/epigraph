-- match_candidates: durable store for cross-source claim matches.
CREATE TABLE match_candidates (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_a            UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    claim_b            UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    score              REAL NOT NULL,
    features           JSONB NOT NULL,
    verifier_verdict   TEXT,
    verifier_rationale TEXT,
    status             TEXT NOT NULL,
    matcher_run_id     UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at         TIMESTAMPTZ,
    decided_by         UUID,
    CONSTRAINT match_candidates_canonical_order CHECK (claim_a < claim_b),
    CONSTRAINT match_candidates_unique_pair UNIQUE (claim_a, claim_b),
    CONSTRAINT match_candidates_status_valid CHECK (
        status IN ('pending', 'promoted', 'rejected', 'stale')
    ),
    CONSTRAINT match_candidates_verdict_valid CHECK (
        verifier_verdict IS NULL OR verifier_verdict IN
        ('same', 'paraphrase', 'overlapping', 'distinct', 'contradicts')
    )
);

CREATE INDEX idx_match_candidates_status ON match_candidates(status);
CREATE INDEX idx_match_candidates_claim_a ON match_candidates(claim_a);
CREATE INDEX idx_match_candidates_claim_b ON match_candidates(claim_b);
CREATE INDEX idx_match_candidates_run ON match_candidates(matcher_run_id) WHERE matcher_run_id IS NOT NULL;
