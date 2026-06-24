//! Idempotent provisioning of canonical service clients.
//!
//! Used by the `bootstrap_clients` binary and exercised by integration tests.
//! See `bin/bootstrap_clients.rs` for the operator-facing entry point.

use anyhow::{Context, Result};
use blake3::Hash;
use epigraph_core::canonical_scopes::{scopes_for, CANONICAL_CLIENT_NAMES};
use epigraph_db::repos::oauth_client::OAuthClientRepository;
use rand::Rng;
use sqlx::PgPool;

/// Outcome of provisioning a single client.
#[derive(Debug, Clone)]
pub enum ClientOutcome {
    /// A row with this `client_name` already existed; not modified.
    Existing {
        name: &'static str,
        client_id: String,
    },
    /// New row created. `client_secret` is the plaintext to capture once.
    Created {
        name: &'static str,
        client_id: String,
        client_secret: String,
    },
}

/// Idempotently create the three canonical service-type OAuth clients
/// (`epigraph-admin`, `epigraph-ro`, `epigraph-wo`).
///
/// For each canonical name, looks up an existing row by `client_name` and
/// skips if found. Otherwise generates a fresh `client_id` (`epigraph_<32 hex>`)
/// and a 32-byte random secret (hex), blake3-hashes the secret, and inserts
/// a row with the role's scope set granted+allowed and `status='active'`.
///
/// Returns one `ClientOutcome` per canonical name in declaration order.
pub async fn bootstrap_canonical_clients(
    pool: &PgPool,
    legal_entity_name: &str,
    legal_contact_email: &str,
    owner_client_id: Option<uuid::Uuid>,
) -> Result<Vec<ClientOutcome>> {
    let mut outcomes = Vec::with_capacity(CANONICAL_CLIENT_NAMES.len());

    for name in CANONICAL_CLIENT_NAMES {
        let scopes = scopes_for(name).expect("canonical name resolves");

        let existing: Option<(String,)> = sqlx::query_as(
            "SELECT client_id FROM oauth_clients WHERE client_name = $1 ORDER BY created_at LIMIT 1",
        )
        .bind(name)
        .fetch_optional(pool)
        .await
        .with_context(|| format!("query existing client {name}"))?;

        if let Some((client_id,)) = existing {
            outcomes.push(ClientOutcome::Existing { name, client_id });
            continue;
        }

        let mut rng = rand::thread_rng();
        let cid = format!("epigraph_{}", hex::encode(rng.gen::<[u8; 16]>()));
        let secret_bytes: [u8; 32] = rng.gen();
        let cs = hex::encode(secret_bytes);
        let hash: Hash = blake3::hash(&secret_bytes);

        OAuthClientRepository::create(
            pool,
            &cid,
            Some(hash.as_bytes() as &[u8]),
            name,
            "service",
            &scopes,
            &scopes,
            "active",
            None,
            owner_client_id,
            Some(legal_entity_name),
            Some(legal_contact_email),
            None, // redirect_uris: service clients use client_credentials, no redirect
        )
        .await
        .with_context(|| format!("create client {name}"))?;

        outcomes.push(ClientOutcome::Created {
            name,
            client_id: cid,
            client_secret: cs,
        });
    }

    Ok(outcomes)
}
