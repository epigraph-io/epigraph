-- Encryption metadata for claims, edges, and evidence
--
-- Evidence: Design spec §4 — claim_encryption, edge_encryption, evidence_encryption tables
-- Reasoning: Separate encryption metadata from core tables to avoid schema changes to existing tables
-- Verification: FK constraints, CHECK constraints on privacy_tier

CREATE TABLE claim_encryption (
    claim_id UUID PRIMARY KEY REFERENCES claims(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL,
    privacy_tier VARCHAR(20) NOT NULL
        CHECK (privacy_tier IN ('encrypted_content', 'fully_private')),
    encrypted_content BYTEA NOT NULL,
    encrypted_labels BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE edge_encryption (
    edge_id UUID PRIMARY KEY REFERENCES edges(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL,
    privacy_tier VARCHAR(20) NOT NULL
        CHECK (privacy_tier IN ('encrypted_content', 'fully_private')),
    encrypted_labels BYTEA,
    encrypted_properties BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE evidence_encryption (
    evidence_id UUID PRIMARY KEY REFERENCES evidence(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL,
    privacy_tier VARCHAR(20) NOT NULL
        CHECK (privacy_tier IN ('encrypted_content', 'fully_private')),
    encrypted_content BYTEA NOT NULL,
    encrypted_labels BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_claim_encryption_group ON claim_encryption(group_id);
CREATE INDEX idx_edge_encryption_group ON edge_encryption(group_id);
CREATE INDEX idx_evidence_encryption_group ON evidence_encryption(group_id);
