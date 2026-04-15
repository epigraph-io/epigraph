//! Provenance recording for write operations.
//!
//! Called by handlers after a successful write to record
//! the chain of custody in the provenance log.

use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::AuthContext;

/// Records provenance for a mutation. Pass `Some(&diff)` for PATCH operations.
#[cfg(feature = "db")]
#[allow(clippy::too_many_arguments)]
pub async fn record_provenance(
    pool: &sqlx::PgPool,
    auth: &AuthContext,
    record_type: &str,
    record_id: Uuid,
    action: &str,
    content_hash: &[u8],
    provenance_sig: &[u8],
    patch_payload: Option<&serde_json::Value>,
) -> Result<Uuid, ApiError> {
    use epigraph_db::repos::provenance::{ProvenanceRepository, AUTO_POLICY_AUTHORIZER_ID};

    let principal_id = auth.owner_id.unwrap_or(auth.client_id);
    let scopes_used: Vec<String> = auth.scopes.clone();

    let id = ProvenanceRepository::append(
        pool,
        record_type,
        record_id,
        action,
        auth.client_id,
        principal_id,
        &[AUTO_POLICY_AUTHORIZER_ID],
        "auto_policy",
        content_hash,
        provenance_sig,
        auth.jti,
        &scopes_used,
        patch_payload,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Failed to record provenance: {e}"),
    })?;

    Ok(id)
}
