//! Single use of agent `client_credentials` assertions (migration 213).
//!
//! An agent authenticates on `/oauth/token` with
//! `timestamp || nonce || Ed25519(timestamp || nonce)`, accepted while the
//! timestamp is fresh. The nonce of every accepted assertion is recorded here
//! until that window (plus a skew margin) has passed, and a second
//! presentation of the same `(public key, nonce)` is refused, so a captured
//! assertion mints nothing. The record is keyed by the Ed25519 public key the
//! signature verified under, not by the `oauth_clients` row: two rows that
//! spell one key differently (hex case) share one nonce space.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::instrument;

use crate::errors::DbError;

pub struct AssertionNonceRepository;

/// What migration 213's definer did with one presented nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceConsumption {
    /// This call recorded the nonce: the assertion's first presentation.
    Recorded,
    /// The `(public key, nonce)` pair was already recorded: a replay.
    Replay,
    /// The expiry the caller computed has already passed on the DATABASE
    /// clock, so nothing was recorded. The caller accepted the assertion as
    /// fresh on its own clock, so this means the two clocks disagree by more
    /// than the retention margin. It is a refusal, but not a replay.
    Expired,
}

impl AssertionNonceRepository {
    /// Record that the agent holding `public_key` (the 32-byte Ed25519 key its
    /// assertion's signature verified under) presented an assertion carrying
    /// `nonce`, kept until `expires_at`, through migration 213's
    /// definer: the application role holds no write on the table. The
    /// decision is one `INSERT .. ON CONFLICT DO NOTHING`, so of two
    /// concurrent presentations exactly one gets
    /// [`NonceConsumption::Recorded`]. Only `Recorded` admits the assertion.
    ///
    /// The caller must pass a nonce read from an assertion whose SIGNATURE AND
    /// FRESHNESS it has already verified: the token endpoint is anonymous, and
    /// an unverified nonce would let anyone fill the table.
    ///
    /// An `Err` means the answer is UNKNOWN (including an answer this build
    /// does not recognise); the token endpoint must refuse the assertion,
    /// never admit it.
    #[instrument(skip(pool, public_key, nonce))]
    pub async fn consume(
        pool: &PgPool,
        public_key: &[u8],
        nonce: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<NonceConsumption, DbError> {
        let answer: String =
            sqlx::query_scalar("SELECT public.epigraph_oauth_assertion_nonce_consume($1, $2, $3)")
                .bind(public_key)
                .bind(nonce)
                .bind(expires_at)
                .fetch_one(pool)
                .await
                .map_err(|e| DbError::QueryFailed { source: e })?;
        match answer.as_str() {
            "recorded" => Ok(NonceConsumption::Recorded),
            "replay" => Ok(NonceConsumption::Replay),
            "expired" => Ok(NonceConsumption::Expired),
            other => Err(DbError::InvalidData {
                reason: format!("unrecognised assertion nonce answer {other:?}"),
            }),
        }
    }
}
