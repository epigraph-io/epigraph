-- Add agentic framework identity columns to agents table
ALTER TABLE agents ADD COLUMN IF NOT EXISTS role VARCHAR(50) NOT NULL DEFAULT 'custom';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS state VARCHAR(50) NOT NULL DEFAULT 'active';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS state_reason JSONB;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS parent_agent_id UUID REFERENCES agents(id);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS rate_limit_rpm INTEGER NOT NULL DEFAULT 60;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS concurrency_limit INTEGER NOT NULL DEFAULT 10;

CREATE INDEX IF NOT EXISTS idx_agent_role ON agents(role);
CREATE INDEX IF NOT EXISTS idx_agent_state ON agents(state);
CREATE INDEX IF NOT EXISTS idx_agent_parent ON agents(parent_agent_id);
