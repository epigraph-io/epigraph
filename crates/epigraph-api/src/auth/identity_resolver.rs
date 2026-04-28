//! `IdentityResolver` — find-or-create on `oauth_clients` from a `ProviderIdentity`.

#[cfg(feature = "db")]
use epigraph_db::{repos::oauth_client::{OAuthClientRepository, OAuthClientRow}, PgPool};
use epigraph_interfaces::{ClientType as InterfaceClientType, ProviderIdentity};
use uuid::Uuid;

use crate::errors::ApiError;
#[allow(deprecated)]
use crate::middleware::bearer::{AuthContext, ClientType};

/// Resolve `ProviderIdentity` to `AuthContext`, find-or-creating an `oauth_clients` row.
///
/// Three callers: chain runner (`auth_chain_middleware`), the refactored Google
/// device flow, and the wrhq overlay's `/oauth/cf/exchange` endpoint.
#[cfg(feature = "db")]
#[derive(Clone)]
pub struct IdentityResolver {
    pool: PgPool,
}

#[cfg(feature = "db")]
impl IdentityResolver {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Find or create an `oauth_clients` row keyed on `<prefix>:<external_id>`.
    ///
    /// On hit: returns the existing row's claims unchanged (does NOT expand scopes).
    /// On miss: inserts with `identity.default_scopes` for both `allowed_scopes` and
    /// `granted_scopes`, then returns claims for the freshly-created row.
    pub async fn resolve_or_provision(
        &self,
        identity: &ProviderIdentity,
    ) -> Result<AuthContext, ApiError> {
        let client_id = format!("{}:{}", identity.client_id_prefix, identity.external_id);

        // Defensive length check for VARCHAR(64) constraint.
        if client_id.len() > 64 {
            return Err(ApiError::InternalError {
                message: format!(
                    "client_id length {} exceeds VARCHAR(64); prefix={} external_id_len={}",
                    client_id.len(),
                    identity.client_id_prefix,
                    identity.external_id.len()
                ),
            });
        }

        if let Some(row) = OAuthClientRepository::get_by_client_id(&self.pool, &client_id)
            .await
            .map_err(|e| ApiError::InternalError { message: e.to_string() })?
        {
            return Ok(build_auth_context(&row));
        }

        let kernel_client_type = match identity.client_type {
            InterfaceClientType::Human => "human",
            InterfaceClientType::Agent => "agent",
            InterfaceClientType::Service => "service",
        };

        let display = identity.display_name.clone().unwrap_or_else(|| client_id.clone());

        let id = OAuthClientRepository::create(
            &self.pool,
            &client_id,
            None, // no client secret — external assertion is the credential
            &display,
            kernel_client_type,
            &identity.default_scopes,
            &identity.default_scopes,
            "active",
            None, // no agent_id
            None, // no owner_id
            None, // no legal entity name
            identity.email.as_deref(),
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Failed to create client {}: {e}", client_id),
        })?;

        let row = OAuthClientRepository::get_by_id(&self.pool, id)
            .await
            .map_err(|e| ApiError::InternalError { message: e.to_string() })?
            .ok_or(ApiError::InternalError {
                message: "Failed to read newly created client".to_string(),
            })?;

        tracing::info!(
            client_id = %client_id,
            email = ?identity.email,
            "Auto-provisioned client via AuthProvider"
        );

        Ok(build_auth_context(&row))
    }
}

#[cfg(feature = "db")]
#[allow(deprecated)]
fn build_auth_context(row: &OAuthClientRow) -> AuthContext {
    let client_type = match row.client_type.as_str() {
        "agent" => ClientType::Agent,
        "human" => ClientType::Human,
        "service" => ClientType::Service,
        _ => ClientType::Service,
    };
    AuthContext {
        client_id: row.id,
        agent_id: row.agent_id,
        owner_id: row.owner_id,
        client_type,
        scopes: row.granted_scopes.clone(),
        jti: Uuid::new_v4(), // No real JWT involved — synthetic correlation id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cf_access_uuid_sub_fits_constraint() {
        // "cf-access:" (10) + UUID (36) = 46 < 64.
        let uuid_sub = "f128c985-ede8-4150-9d3f-ff2ee8263484";
        let formatted = format!("cf-access:{}", uuid_sub);
        assert_eq!(formatted.len(), 46);
        assert!(formatted.len() <= 64);
    }

    #[test]
    fn over_long_client_id_is_recognized() {
        // 64-char limit on `oauth_clients.client_id`. Prefix + ':' + external_id.
        let long_external_id = "x".repeat(60);
        let identity = ProviderIdentity {
            client_id_prefix: "very-long-prefix",
            external_id: long_external_id,
            email: None,
            display_name: None,
            default_scopes: vec![],
            client_type: InterfaceClientType::Human,
        };
        let formatted = format!("{}:{}", identity.client_id_prefix, identity.external_id);
        assert!(formatted.len() > 64);
    }
}
