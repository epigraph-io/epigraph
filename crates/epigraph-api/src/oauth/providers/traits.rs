//! Core traits and types for external identity providers.

use async_trait::async_trait;
use thiserror::Error;

/// Identity extracted from a validated external assertion.
#[derive(Debug, Clone)]
pub struct ExternalIdentity {
    /// Becomes the suffix in `client_id = "{provider}:{subject}"`.
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    /// Full claims for audit/debug. Never log this directly — it may contain PII.
    pub raw_claims: serde_json::Value,
}

#[derive(Debug, Error)]
pub enum ProviderError {
    /// Bad signature, expired, wrong issuer, wrong audience, malformed JWT.
    #[error("invalid assertion: {0}")]
    InvalidAssertion(String),
    /// Upstream JWKS unreachable and stale-grace exhausted.
    #[error("JWKS fetch failed: {0}")]
    JwksFetch(String),
    /// Misconfigured at startup.
    #[error("provider config error: {0}")]
    Config(String),
    /// Upstream IdP returned an error during redirect-flow exchange.
    #[error("upstream IdP error: {0}")]
    Upstream(String),
}

#[async_trait]
pub trait ExternalIdentityProvider: Send + Sync {
    /// Stable identifier — used as the prefix in `client_id` and the path
    /// segment in `/oauth/{name}/...`. Must match `[a-z0-9-]+` and be unique
    /// in the registry.
    fn name(&self) -> &str;

    /// The `grant_type` string this provider responds to in `POST /oauth/token`.
    /// Unique within the registry.
    fn grant_type(&self) -> &str;

    /// Validate the inbound assertion (a JWT) and extract identity.
    async fn validate(&self, assertion: &str) -> Result<ExternalIdentity, ProviderError>;

    fn auto_provision(&self) -> bool;
    fn default_scopes(&self) -> &[String];
}

#[async_trait]
pub trait OidcRedirectFlow: Send + Sync {
    fn build_auth_url(&self, state: &str, pkce_challenge: &str, redirect_uri: &str) -> String;

    /// Exchange the IdP-returned code for an `id_token` JWT (still IdP-signed).
    /// The caller passes the resulting JWT to `ExternalIdentityProvider::validate`.
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        pkce_verifier: &str,
    ) -> Result<String, ProviderError>;

    /// Provider-configured default redirect URI, used when the caller doesn't supply one.
    /// Returns `None` when no provider-level default is configured (callers fall back
    /// to environment-variable defaults at the route layer).
    fn default_redirect_uri(&self) -> Option<&str> {
        None
    }
}
