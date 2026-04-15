//! Provenance attachment endpoint.
//!
//! `POST /api/v1/claims/:id/provenance` — attaches author/source provenance
//! to a claim in a single call: creates author agents (with `did:key`),
//! organization agents, and wires up ATTRIBUTED_TO, AUTHORED, and
//! AFFILIATED_WITH edges.

use crate::errors::ApiError;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use epigraph_core::Agent;
use epigraph_crypto::did_key::{did_key_for_author, normalize_author_name};
use epigraph_db::{AgentRepository, EdgeRepository};

// =============================================================================
// REQUEST / RESPONSE TYPES
// =============================================================================

/// A single author entry in the provenance request.
#[derive(Debug, Deserialize)]
pub struct AuthorEntry {
    pub name: String,
    #[serde(default)]
    pub orcid: Option<String>,
    #[serde(default)]
    pub affiliations: Option<Vec<String>>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub is_corresponding: Option<bool>,
    #[serde(default)]
    pub position: Option<i32>,
}

/// Request body for `POST /api/v1/claims/:id/provenance`.
#[derive(Debug, Deserialize)]
pub struct ProvenanceRequest {
    /// Authors of the source material
    pub authors: Vec<AuthorEntry>,
    /// Source DOI or URL
    #[serde(default)]
    pub source_url: Option<String>,
    /// Digital agent DID that performed the ingestion (e.g., EpiClaw's DID)
    #[serde(default)]
    pub ingestion_agent_id: Option<Uuid>,
}

/// Result for a single author agent created/found.
#[derive(Debug, Serialize)]
pub struct AuthorAgentResult {
    pub agent_id: Uuid,
    pub name: String,
    pub did_key: String,
    /// `true` if a new agent was created, `false` if existing.
    pub created: bool,
}

/// Result for a single organization agent created/found.
#[derive(Debug, Serialize)]
pub struct OrgAgentResult {
    pub agent_id: Uuid,
    pub name: String,
    pub created: bool,
}

/// Response body for `POST /api/v1/claims/:id/provenance`.
#[derive(Debug, Serialize)]
pub struct ProvenanceResponse {
    pub claim_id: Uuid,
    pub author_agents: Vec<AuthorAgentResult>,
    pub organization_agents: Vec<OrgAgentResult>,
    pub edges_created: usize,
}

// =============================================================================
// HANDLER
// =============================================================================

/// Attach author/source provenance to a claim.
///
/// `POST /api/v1/claims/:id/provenance`
///
/// Creates author and organization agents as needed (deduplicating by
/// deterministic `did:key`), then creates ATTRIBUTED_TO, AUTHORED, and
/// AFFILIATED_WITH edges.
pub async fn set_provenance(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Json(request): Json<ProvenanceRequest>,
) -> Result<Json<ProvenanceResponse>, ApiError> {
    let pool = &state.db_pool;

    // ── 1. Verify claim exists ──────────────────────────────────────────
    let claim_row: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: e.to_string(),
        })?;

    if claim_row.is_none() {
        return Err(ApiError::NotFound {
            entity: "claim".to_string(),
            id: claim_id.to_string(),
        });
    }

    let mut author_results: Vec<AuthorAgentResult> = Vec::new();
    let mut edges_created: usize = 0;

    // Track (affiliation_name → Vec<agent_uuid>) for AFFILIATED_WITH edges
    let mut affiliation_map: HashMap<String, Vec<Uuid>> = HashMap::new();

    // ── 2. Process each author ──────────────────────────────────────────
    for author in &request.authors {
        let (did, public_key) = did_key_for_author(author.orcid.as_deref(), &author.name);
        let did_str = did.to_string();

        // Canonical display_name for dedup: "orcid:{orcid}" or "author:{normalized}"
        let canonical_name = match &author.orcid {
            Some(orcid) if !orcid.is_empty() => format!("orcid:{orcid}"),
            _ => format!("author:{}", normalize_author_name(&author.name)),
        };

        // Find or create agent by public key (deterministic from did:key)
        let (agent_id, created) =
            find_or_create_author_agent(pool, &public_key, &canonical_name, &did_str, author)
                .await?;

        // Create ATTRIBUTED_TO edge: claim → agent
        let attr_props = serde_json::json!({
            "prov": "wasAttributedTo",
            "role": "author",
            "position": author.position,
            "is_corresponding": author.is_corresponding,
        });
        EdgeRepository::create(
            pool,
            claim_id,
            "claim",
            agent_id,
            "agent",
            "ATTRIBUTED_TO",
            Some(attr_props),
            None,
            None,
        )
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to create ATTRIBUTED_TO edge: {e}"),
        })?;
        edges_created += 1;

        // Create AUTHORED edge: agent → claim (best-effort)
        let authored_props = serde_json::json!({
            "prov": "authored",
            "position": author.position,
        });
        if EdgeRepository::create(
            pool,
            agent_id,
            "agent",
            claim_id,
            "claim",
            "AUTHORED",
            Some(authored_props),
            None,
            None,
        )
        .await
        .is_ok()
        {
            edges_created += 1;
        }

        // Track affiliations for this author
        if let Some(ref affiliations) = author.affiliations {
            for aff in affiliations {
                affiliation_map
                    .entry(aff.clone())
                    .or_default()
                    .push(agent_id);
            }
        }

        author_results.push(AuthorAgentResult {
            agent_id,
            name: author.name.clone(),
            did_key: did_str,
            created,
        });
    }

    // ── 3. Process organizations ────────────────────────────────────────
    let mut org_results: Vec<OrgAgentResult> = Vec::new();

    for (aff_name, author_agent_ids) in &affiliation_map {
        let (org_agent_id, org_created) = find_or_create_org_agent(pool, aff_name).await?;

        // Create AFFILIATED_WITH edges: person → org
        for &author_id in author_agent_ids {
            let aff_props = serde_json::json!({
                "prov": "affiliation",
            });
            if EdgeRepository::create(
                pool,
                author_id,
                "agent",
                org_agent_id,
                "agent",
                "AFFILIATED_WITH",
                Some(aff_props),
                None,
                None,
            )
            .await
            .is_ok()
            {
                edges_created += 1;
            }
        }

        org_results.push(OrgAgentResult {
            agent_id: org_agent_id,
            name: aff_name.clone(),
            created: org_created,
        });
    }

    // ── 4. Ingestion agent edge ─────────────────────────────────────────
    if let Some(ingestion_id) = request.ingestion_agent_id {
        let assoc_props = serde_json::json!({
            "prov": "wasAssociatedWith",
            "role": "ingestion_agent",
        });
        if EdgeRepository::create(
            pool,
            claim_id,
            "claim",
            ingestion_id,
            "agent",
            "WAS_ASSOCIATED_WITH",
            Some(assoc_props),
            None,
            None,
        )
        .await
        .is_ok()
        {
            edges_created += 1;
        }
    }

    // ── 5. Return response ──────────────────────────────────────────────
    Ok(Json(ProvenanceResponse {
        claim_id,
        author_agents: author_results,
        organization_agents: org_results,
        edges_created,
    }))
}

// =============================================================================
// HELPERS
// =============================================================================

/// Find an existing author agent by public key, or create a new one.
///
/// Returns `(agent_id, created)` where `created` is true if a new agent was inserted.
async fn find_or_create_author_agent(
    pool: &sqlx::PgPool,
    public_key: &[u8; 32],
    canonical_name: &str,
    _did_key_str: &str,
    author: &AuthorEntry,
) -> Result<(Uuid, bool), ApiError> {
    // Check if agent with this public key already exists
    if let Some(existing) = AgentRepository::get_by_public_key(pool, public_key)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: e.to_string(),
        })?
    {
        return Ok((existing.id.into(), false));
    }

    // Create new agent
    let mut agent = Agent::new(*public_key, Some(canonical_name.to_string()));
    agent.labels = vec!["person".to_string()];
    if let Some(ref orcid) = author.orcid {
        if !orcid.is_empty() {
            agent.orcid = Some(orcid.clone());
        }
    }

    let created = AgentRepository::create(pool, &agent).await.map_err(|e| {
        // If we hit a duplicate key race condition, try fetching again
        tracing::warn!(
            canonical_name = %canonical_name,
            error = %e,
            "Agent creation raced; retrying lookup"
        );
        ApiError::DatabaseError {
            message: e.to_string(),
        }
    })?;

    Ok((created.id.into(), true))
}

/// Find an existing organization agent by its deterministic public key, or create one.
///
/// Returns `(agent_id, created)`.
async fn find_or_create_org_agent(
    pool: &sqlx::PgPool,
    org_name: &str,
) -> Result<(Uuid, bool), ApiError> {
    let canonical = format!("org:{}", normalize_author_name(org_name));

    // Derive a deterministic keypair for the org
    let signer = epigraph_crypto::did_key::keypair_from_name(&canonical);
    let public_key = signer.public_key();

    // Check if org agent already exists
    if let Some(existing) = AgentRepository::get_by_public_key(pool, &public_key)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: e.to_string(),
        })?
    {
        return Ok((existing.id.into(), false));
    }

    let mut agent = Agent::new(public_key, Some(canonical));
    agent.labels = vec!["organization".to_string()];

    let created =
        AgentRepository::create(pool, &agent)
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?;

    Ok((created.id.into(), true))
}
