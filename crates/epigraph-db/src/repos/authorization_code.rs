use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::DbError;

pub struct AuthorizationCodeRepository;

pub struct AuthorizationCodeRow {
    pub client_id: String,
    pub oauth_client_id: Uuid,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scopes: Vec<String>,
    pub used_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

impl AuthorizationCodeRepository {
    /// Insert a single-use code (caller passes BLAKE3(raw code)).
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        pool: &PgPool,
        code_hash: &[u8],
        client_id: &str,
        oauth_client_id: Uuid,
        redirect_uri: &str,
        code_challenge: &str,
        scopes: &[String],
        resource: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"INSERT INTO oauth_authorization_codes
               (code_hash, client_id, oauth_client_id, redirect_uri, code_challenge,
                scopes, resource, expires_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"#,
        )
        .bind(code_hash)
        .bind(client_id)
        .bind(oauth_client_id)
        .bind(redirect_uri)
        .bind(code_challenge)
        .bind(scopes)
        .bind(resource)
        .bind(expires_at)
        .execute(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(())
    }

    /// Atomically mark a code used and return it iff it was unused and unexpired.
    /// Returns None if the code is missing, already used, or expired.
    pub async fn consume(
        pool: &PgPool,
        code_hash: &[u8],
    ) -> Result<Option<AuthorizationCodeRow>, DbError> {
        let row = sqlx::query_as::<
            _,
            (
                String,
                Uuid,
                String,
                String,
                Vec<String>,
                Option<DateTime<Utc>>,
                DateTime<Utc>,
            ),
        >(
            r#"UPDATE oauth_authorization_codes
               SET used_at = now()
               WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()
               RETURNING client_id, oauth_client_id, redirect_uri, code_challenge,
                         scopes, used_at, expires_at"#,
        )
        .bind(code_hash)
        .fetch_optional(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row.map(|r| AuthorizationCodeRow {
            client_id: r.0,
            oauth_client_id: r.1,
            redirect_uri: r.2,
            code_challenge: r.3,
            scopes: r.4,
            used_at: r.5,
            expires_at: r.6,
        }))
    }
}
