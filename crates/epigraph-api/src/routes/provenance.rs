//! Provenance attachment endpoint.
//!
//! `POST /api/v1/claims/:id/provenance` attaches author/source provenance to a
//! claim in a single call: it wires up ATTRIBUTED_TO, AUTHORED and
//! AFFILIATED_WITH edges (creating organization agents as needed) and the
//! ingestion agent's WAS_ASSOCIATED_WITH.
//!
//! # Who may write it
//!
//! Every one of these edges has an agent endpoint, so migration 120 makes it
//! world-owned: neither the claim's owner nor the writer could take it back.
//! An ATTRIBUTED_TO / AUTHORED pair puts the claim in the author's mouth. So,
//! on ONE transaction stamped with the caller's viewer, and before anything
//! is written:
//!
//! * the caller needs `claims:write` and `edges:write`, and must be the
//!   claim's filer or the human operating it through a live binding
//!   (`AgentRepository::speaks_for`);
//! * each author must resolve to an agent the caller is or operates. A third
//!   party's authorship is not written here: there is no document to hang
//!   it on, so it cannot be recorded the way the document ingest records a
//!   named person (`authored -> paper`, pending their countersignature).
//!   The request is refused (403) naming the author, and points there;
//! * the ingestion agent must be the caller or an agent it operates.
//!
//! An author that names a system identity is refused (400) before either.

use crate::errors::ApiError;
use crate::middleware::bearer::{AuthContext, ViewerExtractor};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use epigraph_core::{Agent, ClaimId};
use epigraph_crypto::did_key::{did_key_for_author, normalize_author_name};
use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository};

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

/// The refusal for an author the caller does not speak for.
pub const THIRD_PARTY_AUTHOR_REFUSAL: &str =
    "may name as an author only itself or an agent it operates through a live binding: \
     this route has no document to record a third party's authorship on. Ingest the \
     document (ingest_document / ingest_document_spine), which records a named person's \
     authorship of the paper as pending their countersignature; nothing was written";

fn db_error(e: impl std::fmt::Display) -> ApiError {
    ApiError::DatabaseError {
        message: e.to_string(),
    }
}

/// Attach author/source provenance to a claim.
///
/// `POST /api/v1/claims/:id/provenance`
///
/// Refuses (403, nothing written) a caller that is not the claim's filer or
/// its operator, an author the caller is not and does not operate, and an
/// ingestion agent the caller does not speak for; see the module doc. On
/// success writes ATTRIBUTED_TO and AUTHORED for each author, AFFILIATED_WITH
/// for each author's affiliation (creating the organization agent when it is
/// absent) and the ingestion agent's WAS_ASSOCIATED_WITH, all or nothing.
pub async fn set_provenance(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<AuthContext>>,
    Path(claim_id): Path<Uuid>,
    Json(request): Json<ProvenanceRequest>,
) -> Result<Json<ProvenanceResponse>, ApiError> {
    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".into(),
        });
    };
    crate::middleware::scopes::check_scopes(auth, &["claims:write", "edges:write"])?;
    let Some(caller) = auth.agent_id else {
        return Err(ApiError::Forbidden {
            reason: "attaching provenance needs an agent principal; nothing was written".into(),
        });
    };

    // ONE transaction stamped with the caller's viewer: the claim read, every
    // authority check, the agent lookups and every write.
    let mut tx = state.write_as(&viewer, "set_provenance").await?;

    // ── 1. The claim, as the caller sees it, and its filer ───────────────
    let Some(claim) =
        ClaimRepository::get_by_id_conn(&mut tx, &viewer, ClaimId::from_uuid(claim_id))
            .await
            .map_err(db_error)?
    else {
        return Err(ApiError::NotFound {
            entity: "claim".to_string(),
            id: claim_id.to_string(),
        });
    };
    let filer: Uuid = claim.agent_id.into();

    // ── 1b. A system identity is never an author (migration 148) ─────────
    // Refused: the legacy public-constant key of a system role, and any
    // author that resolves to a REGISTERED system agent under another key.
    // The key is derived with the loop's exact arguments, so an empty ORCID
    // falls back to the name exactly as it does there.
    let registered_system_agents = if request.authors.is_empty() {
        Vec::new()
    } else {
        epigraph_db::SystemAgentRepository::registered_agent_ids(&mut tx)
            .await
            .map_err(db_error)?
    };
    let mut resolved: Vec<(Option<Uuid>, String)> = Vec::new();
    for author in &request.authors {
        let (did, public_key) = did_key_for_author(author.orcid.as_deref(), &author.name);
        let existing = AgentRepository::get_by_public_key(&mut *tx, &public_key)
            .await
            .map_err(db_error)?
            .map(|a| Uuid::from(a.id));
        let refused = epigraph_db::is_reserved_author_key(&public_key)
            || existing.is_some_and(|id| registered_system_agents.contains(&id));
        if refused {
            return Err(ApiError::ValidationError {
                field: "authors".to_string(),
                reason: format!(
                    "author {:?} names a system agent's identity; a claim cannot be attributed \
                     to a system identity. Nothing was written",
                    author.name
                ),
            });
        }
        resolved.push((existing, did.to_string()));
    }

    // ── 1c. Who the caller may speak for ─────────────────────────────────
    let mut asked: Vec<Uuid> = vec![filer];
    asked.extend(resolved.iter().filter_map(|(id, _)| *id));
    asked.extend(request.ingestion_agent_id);
    let speaks = AgentRepository::speaks_for(&mut *tx, caller, &asked)
        .await
        .map_err(db_error)?;
    if !speaks.contains_key(&filer) {
        return Err(ApiError::Forbidden {
            reason: "only the claim's filer, or the human operating it through a live \
                     binding, may attach its provenance; nothing was written"
                .into(),
        });
    }
    for (author, (id, _)) in request.authors.iter().zip(&resolved) {
        if !id.is_some_and(|id| speaks.contains_key(&id)) {
            return Err(ApiError::Forbidden {
                reason: format!(
                    "author {:?}: the caller {THIRD_PARTY_AUTHOR_REFUSAL}",
                    author.name
                ),
            });
        }
    }
    if let Some(ingestion) = request.ingestion_agent_id {
        if !speaks.contains_key(&ingestion) {
            return Err(ApiError::Forbidden {
                reason: "the ingestion agent must be the caller or an agent it operates \
                         through a live binding; nothing was written"
                    .into(),
            });
        }
    }

    let refused = |e: epigraph_db::DbError| {
        if crate::errors::db_is_insufficient_privilege(&e) {
            crate::errors::write_refused("provenance edge")
        } else {
            db_error(e)
        }
    };
    let mut author_results: Vec<AuthorAgentResult> = Vec::new();
    let mut edges_created: usize = 0;
    // Track (affiliation_name → Vec<agent_uuid>) for AFFILIATED_WITH edges
    let mut affiliation_map: HashMap<String, Vec<Uuid>> = HashMap::new();

    // ── 2. Each author: ATTRIBUTED_TO and AUTHORED ───────────────────────
    for (author, (id, did_str)) in request.authors.iter().zip(resolved) {
        // Every author was checked above, so it exists.
        let Some(agent_id) = id else {
            continue;
        };
        let attr_props = serde_json::json!({
            "prov": "wasAttributedTo",
            "role": "author",
            "position": author.position,
            "is_corresponding": author.is_corresponding,
        });
        EdgeRepository::create_signed_conn(
            &mut tx,
            state.edge_signing_key(),
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
        .map_err(refused)?;
        edges_created += 1;

        let authored_props = serde_json::json!({
            "prov": "authored",
            "position": author.position,
        });
        EdgeRepository::create_signed_conn(
            &mut tx,
            state.edge_signing_key(),
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
        .map_err(refused)?;
        edges_created += 1;

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
            created: false,
        });
    }

    // ── 3. Organizations: AFFILIATED_WITH from each (spoken-for) author ──
    let mut org_results: Vec<OrgAgentResult> = Vec::new();
    for (aff_name, author_agent_ids) in &affiliation_map {
        let (org_agent_id, org_created) = find_or_create_org_agent(&mut tx, aff_name).await?;
        for &author_id in author_agent_ids {
            EdgeRepository::create_signed_conn(
                &mut tx,
                state.edge_signing_key(),
                author_id,
                "agent",
                org_agent_id,
                "agent",
                "AFFILIATED_WITH",
                Some(serde_json::json!({ "prov": "affiliation" })),
                None,
                None,
            )
            .await
            .map_err(refused)?;
            edges_created += 1;
        }
        org_results.push(OrgAgentResult {
            agent_id: org_agent_id,
            name: aff_name.clone(),
            created: org_created,
        });
    }

    // ── 4. Ingestion agent edge ─────────────────────────────────────────
    if let Some(ingestion_id) = request.ingestion_agent_id {
        EdgeRepository::create_signed_conn(
            &mut tx,
            state.edge_signing_key(),
            claim_id,
            "claim",
            ingestion_id,
            "agent",
            "WAS_ASSOCIATED_WITH",
            Some(serde_json::json!({
                "prov": "wasAssociatedWith",
                "role": "ingestion_agent",
            })),
            None,
            None,
        )
        .await
        .map_err(refused)?;
        edges_created += 1;
    }

    tx.commit().await.map_err(db_error)?;

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

/// Find an existing organization agent by its deterministic public key, or
/// create one, on the handler's stamped transaction.
///
/// Returns `(agent_id, created)`.
async fn find_or_create_org_agent(
    conn: &mut sqlx::PgConnection,
    org_name: &str,
) -> Result<(Uuid, bool), ApiError> {
    let canonical = format!("org:{}", normalize_author_name(org_name));

    // Derive a deterministic keypair for the org
    let signer = epigraph_crypto::did_key::keypair_from_name(&canonical);
    let public_key = signer.public_key();

    if let Some(existing) = AgentRepository::get_by_public_key(&mut *conn, &public_key)
        .await
        .map_err(db_error)?
    {
        return Ok((existing.id.into(), false));
    }

    let mut agent = Agent::new(public_key, Some(canonical));
    agent.labels = vec!["organization".to_string()];
    let created = AgentRepository::create_conn(conn, &agent)
        .await
        .map_err(db_error)?;
    Ok((created.id.into(), true))
}
