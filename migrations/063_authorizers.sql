-- Authorization entities: individuals, councils, automated policies.
--
-- Evidence: docs/superpowers/specs/2026-03-20-oauth2-authz-design.md §6

CREATE TABLE authorizers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    authorizer_type VARCHAR(30) NOT NULL CHECK (authorizer_type IN (
        'individual', 'council', 'policy'
    )),
    display_name VARCHAR(255) NOT NULL,
    client_id UUID REFERENCES oauth_clients(id),
    quorum_threshold INTEGER,
    policy_rule JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE authorization_votes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provenance_log_id UUID,  -- FK added after provenance_log table exists
    authorizer_id UUID NOT NULL REFERENCES authorizers(id),
    voter_client_id UUID NOT NULL REFERENCES oauth_clients(id),
    vote VARCHAR(10) NOT NULL CHECK (vote IN ('approve', 'reject', 'abstain')),
    signature BYTEA NOT NULL,
    voted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed auto-policy authorizer (used for scope-sufficient writes)
INSERT INTO authorizers (id, authorizer_type, display_name, policy_rule)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'policy',
    'auto_scope_policy',
    '{"rule": "scopes_sufficient", "description": "Auto-approved when client has required scopes"}'
);
