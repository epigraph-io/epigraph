//! The shared, durable list of revoked OAuth access tokens, keyed by JWT `jti`.
//!
//! # Why this exists
//!
//! Access tokens are self-contained JWTs: a validator that only checks the
//! signature and `exp` cannot know that a token was revoked. The list used to
//! be a per-process `HashSet` inside `epigraph-api`, so MCP (a separate
//! process validating the same tokens) never saw a revocation, an API restart
//! forgot every revocation, and a second API replica did not share them. This
//! table is the one list every validating process reads.
//!
//! # The table is created by a PENDING migration
//!
//! Its DDL is in
//! `crates/epigraph-db/tests/fixtures/pending_migration_revoked_access_tokens.sql`,
//! not in `migrations/`, because the branch that wrote this module could not
//! allocate a migration number. That is why the statements below are runtime
//! `sqlx::query` calls rather than `query!` macros — the macros need the table
//! in the schema `cargo sqlx prepare` sees — and why [`probe`] distinguishes an
//! ABSENT table (log and keep the pre-existing behaviour) from a present but
//! UNUSABLE one (refuse to boot).
//!
//! # Posture
//!
//! * Keyed on `jti`, never on the token: nothing replayable is stored at rest.
//! * No tenancy and row security OFF, deliberately — the lookup runs before a
//!   principal exists, on a connection with no tenancy GUCs. [`probe`] refuses
//!   a table with `relrowsecurity` set, because under ENABLE-with-no-policy
//!   every lookup would answer "not revoked": a check that fails open.
//! * [`is_revoked`] does NOT filter on `expires_at`. A row is authoritative
//!   until [`prune_expired`] removes it, and the prune waits
//!   [`PRUNE_GRACE_SECONDS`] past `expires_at` so a database clock running
//!   ahead of the validating process cannot un-revoke a token the process
//!   still considers unexpired.
//!
//! [`probe`]: RevokedAccessTokenRepository::probe
//! [`is_revoked`]: RevokedAccessTokenRepository::is_revoked
//! [`prune_expired`]: RevokedAccessTokenRepository::prune_expired

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

/// How long past its token's `exp` a revocation row is kept before
/// [`RevokedAccessTokenRepository::prune_expired`] may delete it.
///
/// The JWT is rejected on `exp` by the validating process's clock (leeway 0,
/// `epigraph_auth::JwtConfig::validate_token`); the prune runs on the
/// database's clock. Without a margin, a database clock ahead of the process
/// clock deletes the row while the process still accepts the token.
pub const PRUNE_GRACE_SECONDS: i64 = 300;

/// What [`RevokedAccessTokenRepository::probe`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStoreStatus {
    /// The table exists, row security is off on it, and this pool can read it.
    Ready,
    /// The table does not exist: the migration that creates it has not run on
    /// this database.
    Absent,
}

pub struct RevokedAccessTokenRepository;

impl RevokedAccessTokenRepository {
    /// Decide at boot whether the shared revocation list can be used.
    ///
    /// * `Ok(Absent)` — no table. The caller keeps its pre-existing behaviour
    ///   and must say so loudly; it is a deployment that has not run the
    ///   migration, not a transient fault.
    /// * `Ok(Ready)` — table present, row security off, and a lookup on THIS
    ///   pool succeeded, so a missing grant surfaces here rather than as a 503
    ///   on the first authenticated request.
    /// * `Err` — present but unusable: a failed lookup (permissions), or row
    ///   security enabled. The caller should refuse to serve rather than run a
    ///   revocation check that errors on every request or silently admits.
    ///
    /// # Errors
    /// `DbError::QueryFailed` on the catalog read or the lookup;
    /// `DbError::InvalidData` when row security is enabled on the table.
    #[instrument(skip(pool))]
    pub async fn probe(pool: &PgPool) -> Result<RevocationStoreStatus, DbError> {
        let rls: Option<bool> = sqlx::query_scalar(
            "SELECT (SELECT c.relrowsecurity FROM pg_class c \
                      WHERE c.oid = to_regclass('public.revoked_access_tokens'))",
        )
        .fetch_one(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;

        match rls {
            None => Ok(RevocationStoreStatus::Absent),
            Some(true) => Err(DbError::InvalidData {
                reason: "row level security is ENABLED on public.revoked_access_tokens. The \
                         table carries no tenancy and is read before any principal exists, so \
                         a policy can only filter revocations out of view: a revocation check \
                         that fails open. Disable row security on it (it is deliberately \
                         unprotected, like oauth_clients)."
                    .to_string(),
            }),
            Some(false) => {
                // Prove THIS pool's role can read it. The nil jti is never minted.
                Self::is_revoked(pool, Uuid::nil()).await?;
                Ok(RevocationStoreStatus::Ready)
            }
        }
    }

    /// Record `jti` as revoked. `expires_at` is the token's own `exp`.
    ///
    /// Idempotent: a second revocation of the same token is a no-op. Callers
    /// must pass a `jti`/`exp` taken from a token whose SIGNATURE VERIFIED —
    /// the revoke endpoint is anonymous, and an unverified token would let
    /// anyone grow this table with far-future rows.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the insert fails.
    #[instrument(skip(pool))]
    pub async fn revoke(
        pool: &PgPool,
        jti: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO revoked_access_tokens (jti, expires_at) VALUES ($1, $2) \
             ON CONFLICT (jti) DO NOTHING",
        )
        .bind(jti)
        .bind(expires_at)
        .execute(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(())
    }

    /// Whether `jti` has been revoked.
    ///
    /// Deliberately not filtered on `expires_at`; see the module doc.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the lookup fails. Callers must treat an error
    /// as "cannot admit", never as "not revoked".
    #[instrument(skip(pool))]
    pub async fn is_revoked(pool: &PgPool, jti: Uuid) -> Result<bool, DbError> {
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM revoked_access_tokens WHERE jti = $1)")
            .bind(jti)
            .fetch_one(pool)
            .await
            .map_err(|e| DbError::QueryFailed { source: e })
    }

    /// Delete rows whose token expired more than [`PRUNE_GRACE_SECONDS`] ago.
    /// Returns the number removed.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the delete fails.
    #[instrument(skip(pool))]
    pub async fn prune_expired(pool: &PgPool) -> Result<u64, DbError> {
        let done = sqlx::query(
            "DELETE FROM revoked_access_tokens \
              WHERE expires_at < now() - make_interval(secs => $1)",
        )
        .bind(PRUNE_GRACE_SECONDS as f64)
        .execute(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(done.rows_affected())
    }
}
