-- Backfill existing agents as OAuth clients.
--
-- Evidence: docs/superpowers/specs/2026-03-20-oauth2-authz-design.md §7
-- Reasoning: Existing agents need OAuth clients for bearer token auth.
--   owner_id = NULL initially (admin must assign before Phase 2 enforcement).
--   Scopes = Harvester-level (existing agents were unrestricted).

INSERT INTO oauth_clients (
    client_id, client_name, client_type,
    allowed_scopes, granted_scopes, status, agent_id
)
SELECT
    encode(a.public_key, 'hex'),
    COALESCE(a.display_name, 'agent-' || a.id::text),
    'agent',
    ARRAY[
        'claims:read', 'claims:write', 'evidence:read', 'evidence:submit',
        'edges:read', 'edges:write', 'agents:read', 'groups:read',
        'analysis:belief', 'analysis:propagation', 'analysis:reasoning',
        'analysis:gaps', 'analysis:structural', 'analysis:hypothesis',
        'analysis:political'
    ],
    ARRAY[
        'claims:read', 'claims:write', 'evidence:read', 'evidence:submit',
        'edges:read', 'edges:write', 'agents:read', 'groups:read',
        'analysis:belief', 'analysis:propagation', 'analysis:reasoning',
        'analysis:gaps', 'analysis:structural', 'analysis:hypothesis',
        'analysis:political'
    ],
    'active',
    a.id
FROM agents a
WHERE NOT EXISTS (
    SELECT 1 FROM oauth_clients oc WHERE oc.agent_id = a.id
);
