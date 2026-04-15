-- Refresh token storage for OAuth2 token rotation.
--
-- Evidence: docs/superpowers/specs/2026-03-20-oauth2-authz-design.md §4
-- Reasoning: Refresh tokens require server-side state for rotation (old token invalidated).
--   Store BLAKE3 hash, never plaintext. Partial index on non-revoked for fast lookup.

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash BYTEA NOT NULL UNIQUE,
    client_id UUID NOT NULL REFERENCES oauth_clients(id),
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_tokens_client ON refresh_tokens(client_id);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at) WHERE revoked_at IS NULL;
