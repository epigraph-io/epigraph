//! `AuthProvider` — pluggable authentication providers for the EpiGraph kernel.
//!
//! The kernel chains a `Vec<Arc<dyn AuthProvider>>` ahead of bearer-JWT verification.
//! Each provider inspects request headers and either authenticates (returning
//! `Ok(Some(identity))`), declines (`Ok(None)`), or rejects (`Err(_)`).
//!
//! Identity is *not* a kernel JWT — it's verified claims that the kernel's
//! `IdentityResolver` then maps to an `oauth_clients` row via find-or-create.
//!
//! See the AuthProvider design at:
//! `docs/superpowers/specs/2026-04-27-cf-access-auth-seam-design.md`.

use async_trait::async_trait;

use crate::InterfaceError;

/// Type of OAuth client backing this identity. Canonical home for the enum
/// (previously duplicated in `epigraph-api::middleware::bearer`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientType {
    Agent,
    Human,
    Service,
}

/// Verified claims returned by an `AuthProvider` to the kernel chain runner.
///
/// `default_scopes` is applied **only on first sight** (auto-provision); the
/// resolver ignores it on cache hits, so a provider can never accidentally
/// expand existing-user scopes.
#[derive(Debug, Clone)]
pub struct ProviderIdentity {
    /// Stable prefix used to namespace `oauth_clients.client_id` (e.g., `"cf-access"`).
    /// Must be `'static` — providers must use a compile-time constant, not a
    /// runtime-derived string, to ensure prefix stability across restarts.
    pub client_id_prefix: &'static str,
    pub external_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub default_scopes: Vec<String>,
    pub client_type: ClientType,
}

/// Errors returned by an `AuthProvider`.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Credential present in the request but invalid (bad sig, wrong aud, …).
    /// Causes the chain to short-circuit with HTTP 401.
    #[error("invalid credential: {0}")]
    InvalidCredential(String),
    /// Provider's external dependency was unreachable (e.g., JWKS fetch failed).
    /// Per review B3, the kernel chain runner currently maps this to 401 alongside
    /// `InvalidCredential` for v1 simplicity, but the variant is retained for
    /// future routing to 503.
    #[error("provider unavailable: {0}")]
    ProviderUnavailable(String),
    /// Wrap an arbitrary backend error.
    #[error(transparent)]
    Other(#[from] InterfaceError),
}

/// Pluggable authentication provider.
///
/// Implementations live outside the kernel (e.g., `wrhq-epigraph-cf-access`).
/// Providers receive only `request::Parts` — they don't see the body.
#[async_trait]
pub trait AuthProvider: Send + Sync + 'static {
    /// Stable name for logging, telemetry, error messages.
    fn name(&self) -> &'static str;

    /// Inspect the request and either authenticate, decline, or reject.
    ///
    /// - `Ok(Some(identity))` — credential present and valid.
    /// - `Ok(None)` — this provider doesn't apply to this request.
    /// - `Err(_)` — credential present but invalid; chain → 401.
    async fn try_authenticate(
        &self,
        parts: &http::request::Parts,
    ) -> Result<Option<ProviderIdentity>, AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubProvider;

    #[async_trait]
    impl AuthProvider for StubProvider {
        fn name(&self) -> &'static str { "stub" }
        async fn try_authenticate(
            &self,
            _parts: &http::request::Parts,
        ) -> Result<Option<ProviderIdentity>, AuthError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn provider_can_decline() {
        let p = StubProvider;
        let req = http::Request::builder().body(()).unwrap();
        let (parts, _) = req.into_parts();
        assert!(matches!(p.try_authenticate(&parts).await, Ok(None)));
    }

    #[test]
    fn auth_error_invalid_credential_displays() {
        let e = AuthError::InvalidCredential("expired".into());
        assert!(format!("{e}").contains("expired"));
    }

    #[test]
    fn auth_error_provider_unavailable_displays() {
        let e = AuthError::ProviderUnavailable("jwks down".into());
        assert!(format!("{e}").contains("jwks down"));
    }

    #[test]
    fn provider_identity_constructable() {
        let id = ProviderIdentity {
            client_id_prefix: "test",
            external_id: "xyz".into(),
            email: Some("a@b.com".into()),
            display_name: Some("A".into()),
            default_scopes: vec!["claims:read".into()],
            client_type: ClientType::Human,
        };
        assert_eq!(id.client_type, ClientType::Human);
        assert_eq!(id.client_id_prefix, "test");
    }
}
