-- Add Ed25519 signature and signer columns to claims and edges.
--
-- Evidence: claims and edges had content_hash but no cryptographic signatures.
--   Evidence table already has signature+signer_id (migration 004) — this
--   extends the same pattern to claims and edges.
-- Reasoning: All graph nodes should be cryptographically signed for tamper
--   detection. The signer_id tracks who signed (may differ from agent_id
--   during migration attestation).

-- Claims: add signature + signer_id
ALTER TABLE claims ADD COLUMN IF NOT EXISTS signature BYTEA;
ALTER TABLE claims ADD COLUMN IF NOT EXISTS signer_id UUID REFERENCES agents(id) ON DELETE SET NULL;

ALTER TABLE claims ADD CONSTRAINT claims_signature_length
    CHECK (signature IS NULL OR octet_length(signature) = 64);
ALTER TABLE claims ADD CONSTRAINT claims_signature_requires_signer
    CHECK ((signature IS NULL AND signer_id IS NULL) OR (signature IS NOT NULL AND signer_id IS NOT NULL));

CREATE INDEX IF NOT EXISTS idx_claims_signer_id ON claims(signer_id) WHERE signer_id IS NOT NULL;

-- Edges: add signature + signer_id
ALTER TABLE edges ADD COLUMN IF NOT EXISTS signature BYTEA;
ALTER TABLE edges ADD COLUMN IF NOT EXISTS signer_id UUID REFERENCES agents(id) ON DELETE SET NULL;

ALTER TABLE edges ADD CONSTRAINT edges_signature_length
    CHECK (signature IS NULL OR octet_length(signature) = 64);
ALTER TABLE edges ADD CONSTRAINT edges_signature_requires_signer
    CHECK ((signature IS NULL AND signer_id IS NULL) OR (signature IS NOT NULL AND signer_id IS NOT NULL));

CREATE INDEX IF NOT EXISTS idx_edges_signer_id ON edges(signer_id) WHERE signer_id IS NOT NULL;

-- Edges: add content_hash (claims already have it, edges don't)
ALTER TABLE edges ADD COLUMN IF NOT EXISTS content_hash BYTEA;
ALTER TABLE edges ADD CONSTRAINT edges_content_hash_length
    CHECK (content_hash IS NULL OR octet_length(content_hash) = 32);
