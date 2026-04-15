CREATE TABLE IF NOT EXISTS agent_capabilities (
    agent_id UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    can_submit_claims BOOLEAN NOT NULL DEFAULT true,
    can_provide_evidence BOOLEAN NOT NULL DEFAULT true,
    can_challenge_claims BOOLEAN NOT NULL DEFAULT false,
    can_invoke_tools BOOLEAN NOT NULL DEFAULT false,
    can_spawn_agents BOOLEAN NOT NULL DEFAULT false,
    can_modify_policies BOOLEAN NOT NULL DEFAULT false,
    privileged_access BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO agent_capabilities (agent_id)
SELECT id FROM agents
ON CONFLICT (agent_id) DO NOTHING;
