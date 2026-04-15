-- OAuth2 client registration for agents, humans, and services.
--
-- Evidence: docs/superpowers/specs/2026-03-20-oauth2-authz-design.md §2
-- Reasoning: Three client types with ownership chain and legal identity for services.
--   allowed_scopes = max requestable; granted_scopes = admin-approved (starts empty for pending).

CREATE TABLE oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(64) NOT NULL UNIQUE,
    client_secret_hash BYTEA,
    client_name VARCHAR(255) NOT NULL,
    client_type VARCHAR(20) NOT NULL CHECK (client_type IN ('agent', 'human', 'service')),
    redirect_uris TEXT[],
    allowed_scopes TEXT[] NOT NULL,
    granted_scopes TEXT[] NOT NULL DEFAULT '{}',
    status VARCHAR(20) NOT NULL CHECK (status IN ('active', 'pending', 'suspended', 'revoked'))
        DEFAULT 'pending',
    agent_id UUID REFERENCES agents(id),
    owner_id UUID REFERENCES oauth_clients(id),

    -- Legal identity (required for 'service' type)
    legal_entity_name VARCHAR(255),
    legal_entity_id VARCHAR(100),
    legal_contact_email VARCHAR(255),
    legal_accepted_tos_at TIMESTAMPTZ,

    created_by UUID REFERENCES oauth_clients(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- NOTE: agents_must_have_owner constraint deferred to Phase 2.
    -- Backfill migration inserts agents with owner_id = NULL initially.
    CONSTRAINT services_must_have_legal_entity CHECK (
        client_type != 'service' OR (legal_entity_name IS NOT NULL AND legal_contact_email IS NOT NULL)
    )
);

CREATE INDEX idx_oauth_clients_agent_id ON oauth_clients(agent_id);
CREATE INDEX idx_oauth_clients_owner_id ON oauth_clients(owner_id);
CREATE INDEX idx_oauth_clients_status ON oauth_clients(status);
CREATE INDEX idx_oauth_clients_type ON oauth_clients(client_type);
