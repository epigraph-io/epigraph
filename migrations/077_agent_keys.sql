CREATE TABLE IF NOT EXISTS agent_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    key_type VARCHAR(50) NOT NULL DEFAULT 'signing',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMPTZ,
    revocation_reason TEXT,
    revoked_by UUID REFERENCES agents(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_keys_active
    ON agent_keys(agent_id, key_type) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_agent_keys_agent ON agent_keys(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_keys_status ON agent_keys(status);
CREATE INDEX IF NOT EXISTS idx_agent_keys_public_key ON agent_keys(public_key);

-- Seed: migrate existing agent public keys into agent_keys table
INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from, created_at)
SELECT id, public_key, 'signing', 'active', created_at, created_at
FROM agents
ON CONFLICT DO NOTHING;
