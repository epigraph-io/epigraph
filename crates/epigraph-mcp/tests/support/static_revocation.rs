//! An in-memory [`AccessTokenRevocation`] for MCP HTTP tests.
//!
//! Lives under `tests/`, never in the crate: a public "never revoked" store in
//! `src/` could be wired into a production listener and silently disable
//! revocation, which `auth.rs`'s module doc forbids.
//!
//! Tests whose subject is NOT revocation (scope gating, session status codes,
//! the operated-signer guard) serve on a deliberately dead pool. The
//! production `DbAccessTokenRevocation` would fail CLOSED there and turn every
//! valid token into a 401, so they use [`StaticRevocation::none`] and say so.

#![allow(dead_code)]

use epigraph_mcp::auth::{AccessTokenRevocation, RevocationUnavailable};
use uuid::Uuid;

pub enum StaticRevocation {
    /// No token is revoked.
    None,
    /// Every lookup fails, as a store whose database is down does.
    Unavailable,
}

impl StaticRevocation {
    pub fn none() -> std::sync::Arc<dyn AccessTokenRevocation> {
        std::sync::Arc::new(Self::None)
    }

    pub fn unavailable() -> std::sync::Arc<dyn AccessTokenRevocation> {
        std::sync::Arc::new(Self::Unavailable)
    }
}

#[async_trait::async_trait]
impl AccessTokenRevocation for StaticRevocation {
    async fn is_revoked(&self, _jti: Uuid) -> Result<bool, RevocationUnavailable> {
        match self {
            Self::None => Ok(false),
            Self::Unavailable => Err(RevocationUnavailable(
                "test store: revocation lookup unavailable".to_string(),
            )),
        }
    }
}
