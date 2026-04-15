-- Migration: 004_create_evidence
-- Description: Create evidence table for supporting materials
--
-- Evidence backs claims with verifiable sources.
-- Types: document, observation, testimony, computation, reference
--
-- Evidence:
-- - IMPLEMENTATION_PLAN.md §1.4 specifies Evidence model
-- - Ed25519 signatures are exactly 64 bytes
--
-- Reasoning:
-- - content_hash (BLAKE3, 32 bytes) for content integrity
-- - evidence_type as VARCHAR for flexibility (enum in Rust)
-- - signature (64 bytes) for Ed25519 cryptographic verification
-- - signer_id references agents (nullable for unsigned evidence)
-- - raw_content stored for archival and verification
-- - labels/properties support LPG extensions
--
-- Verification:
-- - CHECK constraint validates evidence_type enum values
-- - CHECK constraint ensures signature is exactly 64 bytes if present
-- - Foreign keys maintain referential integrity

CREATE TABLE evidence (
    -- Primary identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- BLAKE3 hash of content (32 bytes)
    content_hash BYTEA NOT NULL,

    -- Evidence type (enum values)
    evidence_type VARCHAR(50) NOT NULL,

    -- Source URL or location reference
    source_url TEXT,

    -- Raw content (for documents, text, etc.)
    raw_content TEXT,

    -- Reference to claim this evidence supports
    claim_id UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,

    -- Ed25519 signature (64 bytes, nullable)
    signature BYTEA,

    -- Agent who signed this evidence (nullable)
    signer_id UUID REFERENCES agents(id) ON DELETE SET NULL,

    -- LPG: Labels for categorization (e.g., ['peer-reviewed', 'primary-source'])
    labels TEXT[] NOT NULL DEFAULT '{}',

    -- LPG: Flexible properties as JSONB
    -- Example: {"doi": "10.1000/xyz", "page_range": [1, 5], "extraction_confidence": 0.95}
    properties JSONB NOT NULL DEFAULT '{}',

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT evidence_type_valid CHECK (
        evidence_type IN ('document', 'observation', 'testimony', 'computation', 'reference')
    ),
    CONSTRAINT evidence_content_hash_length CHECK (
        octet_length(content_hash) = 32
    ),
    CONSTRAINT evidence_signature_length CHECK (
        signature IS NULL OR octet_length(signature) = 64
    ),
    CONSTRAINT evidence_signature_requires_signer CHECK (
        (signature IS NULL AND signer_id IS NULL) OR
        (signature IS NOT NULL AND signer_id IS NOT NULL)
    )
);

-- Index for claim lookups
CREATE INDEX idx_evidence_claim_id ON evidence(claim_id);

-- Index for evidence type filtering
CREATE INDEX idx_evidence_type ON evidence(evidence_type);

-- Index for content hash lookups
CREATE INDEX idx_evidence_content_hash ON evidence(content_hash);

-- Index for signer lookups
CREATE INDEX idx_evidence_signer_id ON evidence(signer_id) WHERE signer_id IS NOT NULL;

-- GIN index for label queries
CREATE INDEX idx_evidence_labels ON evidence USING GIN(labels);

-- GIN index for property queries
CREATE INDEX idx_evidence_properties ON evidence USING GIN(properties);

-- Index for time-based queries
CREATE INDEX idx_evidence_created_at ON evidence(created_at DESC);

-- Composite index for claim + type queries
CREATE INDEX idx_evidence_claim_type ON evidence(claim_id, evidence_type);
