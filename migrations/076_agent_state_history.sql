CREATE TABLE IF NOT EXISTS agent_state_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    previous_state VARCHAR(50) NOT NULL,
    new_state VARCHAR(50) NOT NULL,
    reason JSONB,
    changed_by UUID REFERENCES agents(id),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_state_history_agent ON agent_state_history(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_state_history_time ON agent_state_history(changed_at);
