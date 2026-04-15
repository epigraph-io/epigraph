-- Migration: 002_create_agents
-- Description: Create agents table for EpiGraph participants
--
-- Agents are cryptographic identities that submit claims.
-- Each agent has an Ed25519 keypair (only public key stored).
--
-- Evidence:
-- - IMPLEMENTATION_PLAN.md §1.4 specifies Agent model structure
-- - Ed25519 public keys are exactly 32 bytes
--
-- Reasoning:
-- - UUID primary keys match Rust Uuid type
-- - public_key stored as BYTEA (32 bytes) for Ed25519
-- - display_name max 255 chars prevents abuse
-- - labels/properties support LPG extensions
-- - created_at/updated_at for audit trail
--
-- Verification:
-- - CHECK constraint ensures public_key is exactly 32 bytes
-- - UNIQUE constraint on public_key prevents duplicate registrations

CREATE TABLE agents (
    -- Primary identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Ed25519 public key (32 bytes)
    public_key BYTEA NOT NULL,

    -- Human-readable name
    display_name VARCHAR(255),

    -- LPG: Labels for categorization (e.g., ['human', 'verified'])
    labels TEXT[] NOT NULL DEFAULT '{}',

    -- LPG: Flexible properties as JSONB
    -- Example: {"organization": "MIT", "expertise": ["physics", "math"]}
    properties JSONB NOT NULL DEFAULT '{}',

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT agents_public_key_length CHECK (octet_length(public_key) = 32),
    CONSTRAINT agents_public_key_unique UNIQUE (public_key),
    CONSTRAINT agents_display_name_not_empty CHECK (
        display_name IS NULL OR length(trim(display_name)) > 0
    )
);

-- Index for public key lookups (signature verification)
CREATE UNIQUE INDEX idx_agents_public_key ON agents(public_key);

-- GIN index for label queries
CREATE INDEX idx_agents_labels ON agents USING GIN(labels);

-- GIN index for property queries
CREATE INDEX idx_agents_properties ON agents USING GIN(properties);

-- Index for display name searches
CREATE INDEX idx_agents_display_name ON agents(display_name) WHERE display_name IS NOT NULL;

-- Index for sorting by creation time
CREATE INDEX idx_agents_created_at ON agents(created_at DESC);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER agents_updated_at
    BEFORE UPDATE ON agents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
