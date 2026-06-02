-- OAuth 2.1 authorization-code flow support for the claude.ai MCP connector.
-- Single-use authorization codes and the pending-authorize session that bridges
-- the /oauth/authorize request across the Google login round-trip.

CREATE TABLE public.oauth_authorization_codes (
    code_hash bytea PRIMARY KEY,                 -- BLAKE3 of the raw code; raw never stored
    client_id character varying(64) NOT NULL,    -- the registered "Claude" client
    oauth_client_id uuid NOT NULL,               -- the per-user human client (oauth_clients.id)
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    code_challenge_method character varying(10) NOT NULL DEFAULT 'S256',
    scopes text[] NOT NULL,
    resource text,                               -- RFC 8707 resource (accepted, not enforced)
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,            -- single-use marker
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX idx_oauth_authz_codes_expires ON public.oauth_authorization_codes (expires_at);

CREATE TABLE public.oauth_authorize_sessions (
    state character varying(128) PRIMARY KEY,    -- the state we send to Google (CSRF nonce)
    client_id character varying(64) NOT NULL,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    code_challenge_method character varying(10) NOT NULL DEFAULT 'S256',
    scope text,
    claude_state text,                           -- the state claude.ai gave us, echoed back
    google_code_verifier text NOT NULL,          -- EpiGraph<->Google PKCE verifier
    resolved_oauth_client_id uuid,               -- set during the Google callback transition (per-user client)
    granted_scopes text[],                       -- set during the Google callback transition (requested ∩ grantable)
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX idx_oauth_authz_sessions_expires ON public.oauth_authorize_sessions (expires_at);
