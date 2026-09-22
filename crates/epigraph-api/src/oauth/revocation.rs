//! Access-token revocation: which verified JWTs `POST /oauth/revoke` has
//! withdrawn.
//!
//! # Two lists, one of them shared
//!
//! * **The shared list** — `revoked_access_tokens`, keyed by `jti`, read
//!   through [`epigraph_db::RevokedAccessTokenRepository`]. It is the one the
//!   MCP server's bearer middleware also reads, it survives a restart, and
//!   every API replica sees it. Enabled by
//!   [`AccessTokenRevocation::with_shared_store`], which `bin/server.rs` calls
//!   only when the boot probe finds the table `Ready`.
//! * **The process-local list** — `jti -> exp`, always kept. With the shared
//!   list enabled it is a fast path for this process's own revocations; without
//!   it (the table's migration has not run, or a `db`-less build) it is the
//!   whole of revocation, which is exactly the pre-existing behaviour. Unlike
//!   the `HashSet<String>` it replaces it holds no bearer secrets, and it is
//!   pruned: entries leave once their token has expired.
//!
//! # Only verified tokens are recorded
//!
//! The revoke endpoint is anonymous (RFC 7009 authenticates the token, not a
//! session), so both [`AccessTokenRevocation::revoke`] and
//! [`AccessTokenRevocation::is_revoked`] take the [`EpiGraphClaims`] of a token
//! whose signature has already verified. The old set took the raw string
//! before any validation, so anyone could grow it without bound with junk.
//!
//! # Fail closed
//!
//! A shared-list error is [`RevocationUnavailable`], which maps to a 503. It is
//! never read as "not revoked".
//!
//! # Why this holds its own pool handle
//!
//! The handle is the application pool, handed over once at boot. It is not
//! `AppState.db_pool`, and so it is outside what
//! `crates/epigraph-db/tests/no_unscoped_pool.rs` counts. That is deliberate,
//! not an evasion of that ratchet: the table has no tenancy columns and row
//! security is off by design, and the lookup runs in the bearer middleware
//! BEFORE any principal exists. That is the same structural argument as the
//! ratchet's `middleware/bearer.rs` entry. There is no viewer that could stamp
//! this connection, and none that would change what it may read.

use std::collections::HashMap;
use std::sync::Arc;

use uuid::Uuid;

use crate::errors::ApiError;
use crate::oauth::EpiGraphClaims;

/// The shared revocation list could not be read or written.
#[derive(Debug, thiserror::Error)]
#[error("access-token revocation store unavailable: {0}")]
pub struct RevocationUnavailable(String);

impl From<RevocationUnavailable> for ApiError {
    fn from(_: RevocationUnavailable) -> Self {
        // The cause was logged where it happened; the wire says only "retry".
        ApiError::ServiceUnavailable {
            service: "access-token revocation".to_string(),
        }
    }
}

/// See the module doc.
#[derive(Clone, Default)]
pub struct AccessTokenRevocation {
    /// `jti -> exp` (unix seconds) for tokens this process revoked.
    local: Arc<std::sync::RwLock<HashMap<Uuid, i64>>>,
    /// The shared list's pool, when the boot probe found it ready.
    #[cfg(feature = "db")]
    shared: Option<epigraph_db::PgPool>,
}

impl AccessTokenRevocation {
    /// Process-local only. Every `AppState` constructor starts here.
    pub fn new() -> Self {
        Self::default()
    }

    /// Also record to, and consult, the shared `revoked_access_tokens` list.
    ///
    /// Call only after [`epigraph_db::RevokedAccessTokenRepository::probe`]
    /// returned `Ready` on `pool`. With the table absent every lookup would
    /// fail, and failing closed would 503 every authenticated request.
    #[cfg(feature = "db")]
    #[must_use]
    pub fn with_shared_store(mut self, pool: epigraph_db::PgPool) -> Self {
        self.shared = Some(pool);
        self
    }

    /// Whether revocations reach, and are read from, the shared list.
    pub fn is_shared(&self) -> bool {
        #[cfg(feature = "db")]
        {
            self.shared.is_some()
        }
        #[cfg(not(feature = "db"))]
        {
            false
        }
    }

    /// Record a VERIFIED token as revoked until its `exp`.
    ///
    /// # Errors
    /// [`RevocationUnavailable`] when the shared list is enabled and the write
    /// fails. The local record is made first either way, so this process
    /// rejects the token regardless. The caller must still report the failure,
    /// because no other process has seen the revocation.
    pub async fn revoke(&self, claims: &EpiGraphClaims) -> Result<(), RevocationUnavailable> {
        {
            let now = chrono::Utc::now().timestamp();
            // A poisoned lock still holds a usable map. Recovering it keeps
            // revocation from being silently dropped.
            let mut local = self.local.write().unwrap_or_else(|p| p.into_inner());
            local.retain(|_, exp| *exp > now);
            local.insert(claims.jti, claims.exp);
        }

        #[cfg(feature = "db")]
        if let Some(pool) = &self.shared {
            use chrono::TimeZone;
            use epigraph_db::RevokedAccessTokenRepository;

            let expires_at = chrono::Utc
                .timestamp_opt(claims.exp, 0)
                .single()
                .ok_or_else(|| {
                    RevocationUnavailable(format!("unrepresentable exp {}", claims.exp))
                })?;
            RevokedAccessTokenRepository::revoke(pool, claims.jti, expires_at)
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "could not record an access-token revocation");
                    RevocationUnavailable(e.to_string())
                })?;
            // Housekeeping rides on the (rare) revoke path. A failure here costs
            // only table size, so it is logged and not reported.
            if let Err(e) = RevokedAccessTokenRepository::prune_expired(pool).await {
                tracing::warn!(error = %e, "pruning expired access-token revocations failed");
            }
        }
        Ok(())
    }

    /// Whether a VERIFIED token has been revoked.
    ///
    /// # Errors
    /// [`RevocationUnavailable`] when the shared list is enabled and the
    /// lookup fails. Callers must refuse the request. They must never admit it.
    pub async fn is_revoked(&self, claims: &EpiGraphClaims) -> Result<bool, RevocationUnavailable> {
        let local_hit = self
            .local
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(&claims.jti);
        if local_hit {
            return Ok(true);
        }

        #[cfg(feature = "db")]
        if let Some(pool) = &self.shared {
            return epigraph_db::RevokedAccessTokenRepository::is_revoked(pool, claims.jti)
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "access-token revocation lookup failed; refusing");
                    RevocationUnavailable(e.to_string())
                });
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(exp_offset_secs: i64) -> EpiGraphClaims {
        let now = chrono::Utc::now().timestamp();
        EpiGraphClaims {
            sub: Uuid::new_v4(),
            iss: "epigraph".into(),
            aud: "epigraph-api".into(),
            exp: now + exp_offset_secs,
            iat: now,
            nbf: now,
            jti: Uuid::new_v4(),
            scopes: vec![],
            client_type: "service".into(),
            owner_id: None,
            agent_id: None,
        }
    }

    #[tokio::test]
    async fn a_locally_revoked_jti_is_revoked_and_another_is_not() {
        let r = AccessTokenRevocation::new();
        let revoked = claims(900);
        let other = claims(900);
        r.revoke(&revoked).await.unwrap();
        assert!(r.is_revoked(&revoked).await.unwrap());
        assert!(!r.is_revoked(&other).await.unwrap());
        assert!(!r.is_shared());
    }

    /// The set this replaces grew forever. Expired entries now leave on the
    /// next revocation, because an expired token is already rejected on `exp`.
    #[tokio::test]
    async fn expired_local_entries_are_pruned_on_the_next_revoke() {
        let r = AccessTokenRevocation::new();
        let expired = claims(-10);
        r.revoke(&expired).await.unwrap();
        assert_eq!(r.local.read().unwrap().len(), 1);

        let live = claims(900);
        r.revoke(&live).await.unwrap();
        let local = r.local.read().unwrap();
        assert_eq!(local.len(), 1, "the expired entry must be gone");
        assert!(local.contains_key(&live.jti));
    }

    /// Clones share one list. `AppState` is cloned per request, so a list
    /// that did not share would forget every revocation at once.
    #[tokio::test]
    async fn clones_share_the_local_list() {
        let r = AccessTokenRevocation::new();
        let c = claims(900);
        r.clone().revoke(&c).await.unwrap();
        assert!(r.is_revoked(&c).await.unwrap());
    }
}
