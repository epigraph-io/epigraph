//! OAuth2 client CRUD repository.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

#[derive(Debug, Clone, FromRow)]
pub struct OAuthClientRow {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<Vec<u8>>,
    pub client_name: String,
    pub client_type: String,
    pub redirect_uris: Option<Vec<String>>,
    pub allowed_scopes: Vec<String>,
    pub granted_scopes: Vec<String>,
    pub status: String,
    pub agent_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub legal_entity_name: Option<String>,
    pub legal_entity_id: Option<String>,
    pub legal_contact_email: Option<String>,
    pub legal_accepted_tos_at: Option<DateTime<Utc>>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct OAuthClientRepository;

impl OAuthClientRepository {
    #[instrument(skip(pool))]
    pub async fn get_by_client_id(
        pool: &PgPool,
        client_id: &str,
    ) -> Result<Option<OAuthClientRow>, DbError> {
        let row = sqlx::query_as::<_, OAuthClientRow>(
            "SELECT * FROM oauth_clients WHERE client_id = $1 AND status = 'active'",
        )
        .bind(client_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row)
    }

    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<OAuthClientRow>, DbError> {
        let row = sqlx::query_as::<_, OAuthClientRow>("SELECT * FROM oauth_clients WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row)
    }

    #[instrument(skip(pool, client_secret_hash))]
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        pool: &PgPool,
        client_id: &str,
        client_secret_hash: Option<&[u8]>,
        client_name: &str,
        client_type: &str,
        allowed_scopes: &[String],
        granted_scopes: &[String],
        status: &str,
        agent_id: Option<Uuid>,
        owner_id: Option<Uuid>,
        legal_entity_name: Option<&str>,
        legal_contact_email: Option<&str>,
        redirect_uris: Option<&[String]>,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"INSERT INTO oauth_clients
                (client_id, client_secret_hash, client_name, client_type,
                 allowed_scopes, granted_scopes, status, agent_id, owner_id,
                 legal_entity_name, legal_contact_email, redirect_uris)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id"#,
        )
        .bind(client_id)
        .bind(client_secret_hash)
        .bind(client_name)
        .bind(client_type)
        .bind(allowed_scopes)
        .bind(granted_scopes)
        .bind(status)
        .bind(agent_id)
        .bind(owner_id)
        .bind(legal_entity_name)
        .bind(legal_contact_email)
        .bind(redirect_uris)
        .fetch_one(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row.0)
    }

    /// Link an OAuth client to its `agents` principal. **Write-once.**
    ///
    /// The `AND agent_id IS NULL` guard is the whole point: a re-mint, a raced
    /// concurrent first-mint, or a future re-registration can never rebind an
    /// existing client to a different agent, which would silently transfer
    /// every ownership and membership decision made under the old identity.
    ///
    /// Takes a `&mut PgConnection` so `AgentRepository::ensure_for_client` can
    /// run it inside the same transaction as the `agents` insert.
    ///
    /// Returns `true` when this call performed the link, `false` when the row
    /// was already linked (or does not exist) — both are success.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the update fails.
    #[instrument(skip(conn))]
    pub async fn set_agent_id(
        conn: &mut sqlx::PgConnection,
        id: Uuid,
        agent_id: Uuid,
    ) -> Result<bool, DbError> {
        let result = sqlx::query(
            "UPDATE oauth_clients SET agent_id = $2, updated_at = now() \
             WHERE id = $1 AND agent_id IS NULL",
        )
        .bind(id)
        .bind(agent_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(result.rows_affected() > 0)
    }

    /// Look up a client by `client_name` (status-agnostic), oldest first.
    ///
    /// `bootstrap_canonical_clients` identifies the three canonical service
    /// clients by name, not by `client_id`, because their ids are generated
    /// randomly at first bootstrap.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_client_name(
        pool: &PgPool,
        client_name: &str,
    ) -> Result<Option<OAuthClientRow>, DbError> {
        let row = sqlx::query_as::<_, OAuthClientRow>(
            "SELECT * FROM oauth_clients WHERE client_name = $1 ORDER BY created_at LIMIT 1",
        )
        .bind(client_name)
        .fetch_optional(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row)
    }

    /// Look up a client by `client_id` REGARDLESS of status.
    ///
    /// [`Self::get_by_client_id`] filters `status = 'active'` because it backs
    /// authentication. Registration needs the status-agnostic view: since PR-02
    /// an agent client registers `pending`, so an active-only lookup cannot see
    /// it, and `POST /oauth/register` would fall through to `create` and raise a
    /// duplicate-`client_id` 500 instead of the documented idempotent 200.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_client_id_any_status(
        pool: &PgPool,
        client_id: &str,
    ) -> Result<Option<OAuthClientRow>, DbError> {
        let row =
            sqlx::query_as::<_, OAuthClientRow>("SELECT * FROM oauth_clients WHERE client_id = $1")
                .bind(client_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row)
    }

    /// Converge a canonical client's scope arrays onto the definition its name
    /// implies, returning `true` when the row actually changed.
    ///
    /// `bootstrap_canonical_clients` was create-or-skip: it looked a canonical
    /// client up by name and `continue`d on a hit, never reconciling scopes. So
    /// when a release adds a scope to a canonical role — PR-02 adds `groups:write`
    /// and `groups:admin`, which `POST /api/v1/groups` and both member routes now
    /// REQUIRE — every already-bootstrapped instance keeps its old arrays and
    /// 403s, including on the admin client, with no migration or backfill to fix
    /// it. Re-running bootstrap is the operator-facing repair, so bootstrap has
    /// to be convergent rather than merely idempotent.
    ///
    /// Assignment, not union: the canonical names ARE their scope definition
    /// (`epigraph_core::canonical_scopes::scopes_for`), so a drifted row is
    /// drift, not local policy. A deployment that wants a differently-scoped
    /// client should create one under its own name.
    ///
    /// `WHERE ... IS DISTINCT FROM` keeps the no-op case a no-op, so `updated_at`
    /// is not churned on every bootstrap run.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the update fails.
    #[instrument(skip(pool))]
    pub async fn reconcile_scopes_by_client_name(
        pool: &PgPool,
        client_name: &str,
        scopes: &[String],
    ) -> Result<bool, DbError> {
        let result = sqlx::query(
            "UPDATE oauth_clients SET allowed_scopes = $2, granted_scopes = $2, \
             updated_at = now() \
             WHERE client_name = $1 \
               AND (allowed_scopes IS DISTINCT FROM $2 OR granted_scopes IS DISTINCT FROM $2)",
        )
        .bind(client_name)
        .bind(scopes)
        .execute(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(result.rows_affected() > 0)
    }

    /// `get_by_id` over a borrowed connection, for callers already inside a
    /// transaction (`ensure_for_client`'s callers read the client row back
    /// after linking it).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn get_by_id_conn(
        conn: &mut sqlx::PgConnection,
        id: Uuid,
    ) -> Result<Option<OAuthClientRow>, DbError> {
        let row = sqlx::query_as::<_, OAuthClientRow>("SELECT * FROM oauth_clients WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(row)
    }

    #[instrument(skip(pool))]
    pub async fn update_status(pool: &PgPool, id: Uuid, status: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE oauth_clients SET status = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(status)
            .execute(pool)
            .await
            .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(())
    }

    #[instrument(skip(pool))]
    pub async fn approve(
        pool: &PgPool,
        id: Uuid,
        granted_scopes: &[String],
        approved_by: Uuid,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"UPDATE oauth_clients SET granted_scopes = $2, status = 'active', created_by = $3, updated_at = now() WHERE id = $1"#,
        )
        .bind(id)
        .bind(granted_scopes)
        .bind(approved_by)
        .execute(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(())
    }

    #[instrument(skip(pool))]
    pub async fn get_by_owner(
        pool: &PgPool,
        owner_id: Uuid,
    ) -> Result<Vec<OAuthClientRow>, DbError> {
        let rows =
            sqlx::query_as::<_, OAuthClientRow>("SELECT * FROM oauth_clients WHERE owner_id = $1")
                .bind(owner_id)
                .fetch_all(pool)
                .await
                .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(rows)
    }

    #[instrument(skip(pool))]
    pub async fn suspend_by_owner(pool: &PgPool, owner_id: Uuid) -> Result<u64, DbError> {
        let result = sqlx::query(
            "UPDATE oauth_clients SET status = 'suspended', updated_at = now() WHERE owner_id = $1 AND status = 'active'",
        )
        .bind(owner_id)
        .execute(pool)
        .await
        .map_err(|e| DbError::QueryFailed { source: e })?;
        Ok(result.rows_affected())
    }
}
