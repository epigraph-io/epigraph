//! Single use of agent `client_credentials` assertions (migration 213).
//!
//! An agent authenticates on `/oauth/token` with
//! `timestamp || nonce || Ed25519(timestamp || nonce)`, accepted while the
//! timestamp is fresh. The nonce of every accepted assertion is recorded here
//! until that window (plus a skew margin) has passed, and a second
//! presentation of the same `(client, nonce)` is refused, so a captured
//! assertion mints nothing.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

pub struct AssertionNonceRepository;

impl AssertionNonceRepository {
    /// Record that `client` (an `oauth_clients.id`) presented an assertion
    /// carrying `nonce`, kept until `expires_at`, through migration 213's
    /// definer: the application role holds no write on the table. Returns
    /// `true` when this call recorded it (the first presentation) and `false`
    /// when the pair was already recorded (a replay) or `expires_at` has
    /// already passed on the database clock. The decision is one
    /// `INSERT .. ON CONFLICT DO NOTHING`, so of two concurrent presentations
    /// exactly one gets `true`.
    ///
    /// The caller must pass a nonce read from an assertion whose SIGNATURE AND
    /// FRESHNESS it has already verified: the token endpoint is anonymous, and
    /// an unverified nonce would let anyone fill the table.
    ///
    /// An `Err` means the answer is UNKNOWN; the token endpoint must refuse
    /// the assertion, never admit it.
    #[instrument(skip(pool, nonce))]
    pub async fn consume(
        pool: &PgPool,
        client: Uuid,
        nonce: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<bool, DbError> {
        sqlx::query_scalar("SELECT public.epigraph_oauth_assertion_nonce_consume($1, $2, $3)")
            .bind(client)
            .bind(nonce)
            .bind(expires_at)
            .fetch_one(pool)
            .await
            .map_err(|e| DbError::QueryFailed { source: e })
    }
}
