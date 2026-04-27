-- Grant `claims:revoke-signature` to active human OAuth clients that can write
-- claims, so the POST /api/v1/claims/:id/revoke-signature endpoint introduced
-- in PR #6 is actually reachable.
--
-- The scope is referenced only in code (revoke_signature.rs); no client row
-- carries it in `allowed_scopes` or `granted_scopes`, so every call returns
-- 403 Missing required scope. This migration backfills the scope on
-- already-provisioned admin clients (idempotent: array_append-via-NOT-IN
-- guards against duplicate entries).
--
-- Scope: limited to human clients that already hold `claims:write`. Service
-- clients and read-only clients are intentionally excluded; revoking another
-- agent's signature is a high-trust write and should require the same
-- baseline as creating claims.

UPDATE oauth_clients
SET allowed_scopes = array_append(allowed_scopes, 'claims:revoke-signature')
WHERE client_type = 'human'
  AND status      = 'active'
  AND 'claims:write' = ANY(allowed_scopes)
  AND NOT ('claims:revoke-signature' = ANY(allowed_scopes));

UPDATE oauth_clients
SET granted_scopes = array_append(granted_scopes, 'claims:revoke-signature')
WHERE client_type = 'human'
  AND status      = 'active'
  AND 'claims:write' = ANY(granted_scopes)
  AND NOT ('claims:revoke-signature' = ANY(granted_scopes));
