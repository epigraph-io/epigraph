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
    /// A row with this `client_name` already existed.
    ///
    /// `scopes_reconciled` is true when the row's `allowed_scopes` /
    /// `granted_scopes` had drifted from `scopes_for(name)` and were rewritten
    /// by this run. That is the operator-facing repair for a release that adds a
    /// scope to a canonical role — see
    /// `OAuthClientRepository::reconcile_scopes_by_client_name`.
    Existing {
        name: &'static str,
        client_id: String,
        scopes_reconciled: bool,
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
/// For each canonical name, looks up an existing row by `client_name`. If found,
/// its scope arrays are RECONCILED onto `scopes_for(name)` and the row is
/// reported as `Existing`. Otherwise generates a fresh `client_id`
/// (`epigraph_<32 hex>`) and a 32-byte random secret (hex), blake3-hashes the
/// secret, and inserts a row with the role's scope set granted+allowed and
/// `status='active'`.
///
/// **Convergent, not merely idempotent (PR-02).** This used to `continue` on a
/// hit and never touch scopes. `epigraph_core::canonical_scopes` is the single
/// definition of what each canonical role holds, and when a release widens one —
/// PR-02 adds `groups:write` to the write roles and `groups:admin` to admin,
/// which `POST /api/v1/groups` and both member routes now REQUIRE — a
/// create-or-skip bootstrap leaves every already-bootstrapped instance 403ing on
/// those routes with nothing in the release able to fix it. Re-running this
/// binary is that fix, so it has to converge.
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

        // SQL lives in the repo layer (CLAUDE.md); this used to be an inline
        // SELECT here.
        let existing = OAuthClientRepository::get_by_client_name(pool, name)
            .await
            .with_context(|| format!("query existing client {name}"))?;

        if let Some(row) = existing {
            let scopes_reconciled =
                OAuthClientRepository::reconcile_scopes_by_client_name(pool, name, &scopes)
                    .await
                    .with_context(|| format!("reconcile scopes for {name}"))?;
            outcomes.push(ClientOutcome::Existing {
                name,
                client_id: row.client_id,
                scopes_reconciled,
            });
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
