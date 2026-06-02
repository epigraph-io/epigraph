use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::DbError;

pub struct AuthorizeSessionRepository;

#[derive(Clone)]
pub struct AuthorizeSessionRow {
    pub state: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scope: Option<String>,
    pub claude_state: Option<String>,
    pub google_code_verifier: String,
    pub resolved_oauth_client_id: Option<Uuid>,
    pub granted_scopes: Option<Vec<String>>,
    pub expires_at: DateTime<Utc>,
}

// Column order shared by every SELECT/UPDATE/DELETE ... RETURNING below.
type SessionTuple = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<Uuid>,
    Option<Vec<String>>,
    DateTime<Utc>,
);

const SESSION_COLS: &str = "state, client_id, redirect_uri, code_challenge, scope, \
    claude_state, google_code_verifier, resolved_oauth_client_id, granted_scopes, expires_at";

fn to_row(r: SessionTuple) -> AuthorizeSessionRow {
    AuthorizeSessionRow {
        state: r.0,
        client_id: r.1,
        redirect_uri: r.2,
        code_challenge: r.3,
        scope: r.4,
        claude_state: r.5,
        google_code_verifier: r.6,
        resolved_oauth_client_id: r.7,
        granted_scopes: r.8,
        expires_at: r.9,
    }
}

impl AuthorizeSessionRepository {
    /// Create the pending-authorize session, keyed by the Google CSRF state.
    /// resolved_oauth_client_id / granted_scopes are NULL until the Google callback.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        pool: &PgPool,
        state: &str,
        client_id: &str,
        redirect_uri: &str,
        code_challenge: &str,
        scope: Option<&str>,
        claude_state: Option<&str>,
        google_code_verifier: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"INSERT INTO oauth_authorize_sessions
               (state, client_id, redirect_uri, code_challenge, scope, claude_state,
                google_code_verifier, expires_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"#,
        )
        .bind(state)
        .bind(client_id)
        .bind(redirect_uri)
        .bind(code_challenge)
        .bind(scope)
        .bind(claude_state)
        .bind(google_code_verifier)
        .bind(expires_at)
        .execute(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(())
    }

    /// Read-only lookup by state (NO delete). The Google callback uses this to recover
    /// google_code_verifier + the original request before exchanging the Google code.
    pub async fn find_by_state(
        pool: &PgPool,
        state: &str,
    ) -> Result<Option<AuthorizeSessionRow>, DbError> {
        let row = sqlx::query_as::<_, SessionTuple>(&format!(
            "SELECT {SESSION_COLS} FROM oauth_authorize_sessions WHERE state = $1 AND expires_at > now()"
        ))
        .bind(state)
        .fetch_optional(pool).await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row.map(to_row))
    }

    /// Atomically rotate a session from its Google-CSRF state to a fresh consent nonce,
    /// recording the resolved per-user client + granted scopes. Returns the updated row
    /// (with the new state) or None if from_state was unknown/expired. This is the ONLY
    /// way the user/scopes get bound — never from browser-supplied fields.
    pub async fn transition_to_consent(
        pool: &PgPool,
        from_state: &str,
        to_state: &str,
        resolved_oauth_client_id: Uuid,
        granted_scopes: &[String],
    ) -> Result<Option<AuthorizeSessionRow>, DbError> {
        let row = sqlx::query_as::<_, SessionTuple>(&format!(
            "UPDATE oauth_authorize_sessions \
             SET state = $2, resolved_oauth_client_id = $3, granted_scopes = $4 \
             WHERE state = $1 AND expires_at > now() RETURNING {SESSION_COLS}"
        ))
        .bind(from_state)
        .bind(to_state)
        .bind(resolved_oauth_client_id)
        .bind(granted_scopes)
        .fetch_optional(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row.map(to_row))
    }

    /// Fetch + delete (single-use) by state, only if unexpired. The consent POST handler
    /// uses this to consume the consent ticket atomically before minting a code.
    pub async fn take(pool: &PgPool, state: &str) -> Result<Option<AuthorizeSessionRow>, DbError> {
        let row = sqlx::query_as::<_, SessionTuple>(&format!(
            "DELETE FROM oauth_authorize_sessions WHERE state = $1 AND expires_at > now() RETURNING {SESSION_COLS}"
        ))
        .bind(state)
        .fetch_optional(pool).await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row.map(to_row))
    }
}
