-- MPC embedding shares for privacy-preserving similarity search
--
-- Evidence: Design spec §5 — embedding_shares table
-- Reasoning: Shamir secret shares stored per-party, enabling MPC inner product computation

CREATE TABLE embedding_shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    party_index SMALLINT NOT NULL,
    share_data BYTEA NOT NULL,
    epoch INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(claim_id, party_index)
);

CREATE INDEX idx_embedding_shares_claim ON embedding_shares(claim_id);
CREATE INDEX idx_embedding_shares_group ON embedding_shares(group_id);
