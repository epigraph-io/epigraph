-- Privacy-Preserving Encrypted Subgraphs — Groups and Key Management
--
-- Evidence: Design spec docs/superpowers/specs/2026-03-19-encrypted-subgraphs-design.md §4
-- Reasoning: Groups are the unit of encryption — each group has its own key hierarchy
-- Verification: Tables created, constraints enforced, indexes added

CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name VARCHAR(255),
    did_key TEXT NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    pre_public_key BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE group_key_epochs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL,
    wrapped_key BYTEA,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'rotating', 'retired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at TIMESTAMPTZ,
    UNIQUE(group_id, epoch)
);

CREATE TABLE group_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    wrapped_key_share BYTEA NOT NULL,
    epoch INTEGER NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'writer'
        CHECK (role IN ('admin', 'writer', 'reader')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE(group_id, agent_id, epoch)
);

CREATE INDEX idx_group_key_epochs_group_status ON group_key_epochs(group_id, status);
CREATE INDEX idx_group_memberships_agent ON group_memberships(agent_id);
CREATE INDEX idx_group_memberships_group ON group_memberships(group_id);
