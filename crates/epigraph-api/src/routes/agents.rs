//! Agent endpoints.
//!
//! # Tenancy: 6 of this file's 15 raw-pool sites are converted
//!
//! Conversion shard 6. `get_agent_reputation` (2 sites) and `agent_claims`
//! (3 sites) each serve their whole request on one viewer-stamped connection
//! from [`AppState::read_as`].
//!
//! **Only 3 of those 5 sites change what a caller can see, and the split is
//! stated rather than averaged.** The `AgentRepository::get_by_id` site in each
//! handler narrows nothing: `agents` carries RLS, but migration 077 section 9
//! creates `agents_identity FOR SELECT TO PUBLIC USING (true)` on it and says
//! why. The `ClaimRepository::get_by_agent` and the two
//! `EdgeRepository::*_claims_attributed_to` sites read `claims` and `edges`,
//! both FORCEd and both viewer-spliced, and those are the reads the stamp bears
//! on. An earlier classification filed this whole file as convertible-and-inert;
//! that is right about `get_agent`/`list_agents` and wrong about these five.
//!
//! NOT converted, with the blocker named per handler:
//! * `create_agent`, `update_agent` — WRITE. [`AppState::read_as`] is read-only,
//!   and a write routed through a `ScopedRead` type-checks and is then rolled
//!   back on drop under `SessionGucMode::Transaction`. Owner is
//!   `ScopedPool::begin_as` plus `Viewer::splice_write`.
//! * `list_agents` (4 sites) — `AgentRepository::list*` / `count*` take a
//!   `&PgPool` and read only `agents`, which is `USING (true)`, so stamping
//!   them would narrow nothing. Since backlog 761c2b05 both `get_agent` and
//!   `list_agents` take a `Viewer` and null `orcid` / `ror_id` for a profile
//!   the caller may not see and, since the human-identity rule (migration
//!   309), `display_name` for a human the caller may not see named, through
//!   `epigraph_db::AgentDisclosureRepository::disclosure` on a
//!   [`AppState::read_as`] connection (the decision reads the stamp);
//!   `get_agent`'s one row read moved onto that connection too.
//!   `list_agents`' `?public_key=` lookup (backlog 8946be59) reads its one row
//!   on that connection as well and applies the same profile redaction.
//!
//! `viewer_route_table_lint.rs`'s `FAIL_OPEN_SCOPE_SITES`,
//! `AUTH_OPTIONAL_PROVENANCE_SITES` and `AUTH_OPTIONAL_WRITE_SITES` rows for
//! this file all sit in the write handlers above and are unchanged.
//!
//! [`AppState::read_as`]: crate::AppState::read_as

use axum::{
    extract::{Path, Query, State},
    Json,
};
use epigraph_core::{Agent, AgentId};
#[cfg(feature = "db")]
use epigraph_db::{
    AgentDisclosureRepository, AgentRepository, ClaimRepository, EdgeRepository,
    OAuthClientRepository,
};
#[cfg(feature = "db")]
use epigraph_engine::reputation::{ClaimOutcome, ReputationCalculator};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::middleware::bearer::ViewerExtractor;
use crate::routes::claims::{ClaimResponse, PaginatedResponse};
use crate::services::ValidationService;
use crate::{errors::ApiError, state::AppState};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Truth value below which a claim is considered refuted by strong counter-evidence.
/// Used when converting claims to `ClaimOutcome` for reputation calculation.
const REFUTATION_THRESHOLD: f64 = 0.2;

// =============================================================================
// PUBLIC KEY CONSTANTS
// =============================================================================

/// Length of a hex-encoded Ed25519 public key (32 bytes = 64 hex characters)
#[cfg(test)]
const ED25519_PUBLIC_KEY_HEX_LENGTH: usize = 64;

/// Length of an Ed25519 public key in bytes
const ED25519_PUBLIC_KEY_BYTE_LENGTH: usize = 32;

/// Request to create a new agent
#[derive(Deserialize)]
pub struct CreateAgentRequest {
    /// Ed25519 public key (hex-encoded, 64 chars for 32 bytes)
    pub public_key: String,
    /// Optional display name
    pub display_name: Option<String>,
    /// PROV-O labels (e.g., "person", "organization", "software_agent")
    #[serde(default)]
    pub labels: Option<Vec<String>>,
    /// ORCID identifier for person-type agents
    #[serde(default)]
    pub orcid: Option<String>,
    /// ROR identifier for organization-type agents
    #[serde(default)]
    pub ror_id: Option<String>,
    /// Arbitrary JSONB properties (methodology, affiliation metadata, etc.)
    #[serde(default)]
    pub properties: Option<serde_json::Value>,
    /// Ask for an OAuth login for the new agent (backlog 2f87eb08). Default
    /// `false`: registering an agent records an identity and provisions NO
    /// client. With `true`, the new agent gets an `agent` client whose
    /// `client_id` is its public key: ACTIVE with the agent provision scopes
    /// when the caller holds `claims:admin`, otherwise PENDING with none
    /// granted, as `/oauth/register`'s agent arm registers it.
    #[serde(default)]
    pub login: bool,
    /// What `public_key` is: `ed25519` (the default, a real signature
    /// verifier) or `seed-derived`, a key derived from a PUBLIC seed (an
    /// author's name, a DOI) whose private half anyone can compute. A
    /// `seed-derived` agent only NAMES someone: it is stored so that no
    /// verifier accepts its key (migration 230, backlog 57943a39), and it gets
    /// no OAuth client. Declaring it on an existing key changes nothing.
    #[serde(default)]
    pub key_kind: Option<String>,
    /// Required with `key_kind: "seed-derived"`: the hex Ed25519 signature,
    /// under `public_key`, of
    /// `epigraph_crypto::key_kind_declaration_message("seed-derived", key)`.
    /// The declaration is permanent, so the caller must prove it holds the
    /// key: otherwise anyone with `agents:write` could declare another
    /// party's not yet registered key and lock its holder out.
    #[serde(default)]
    pub key_kind_proof: Option<String>,
}

/// Agent response structure
#[derive(Serialize, Debug)]
pub struct AgentResponse {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub public_key: String, // hex-encoded Ed25519 public key
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub labels: Vec<String>,
    pub orcid: Option<String>,
    pub ror_id: Option<String>,
}

/// Agent reputation response
#[derive(Serialize, Debug)]
pub struct AgentReputationResponse {
    pub agent_id: Uuid,
    pub display_name: Option<String>,
    pub reputation_score: f64,
    pub total_claims: usize,
    pub verified_claims: usize,
    pub claim_age_days_avg: f64,
}

impl From<Agent> for AgentResponse {
    fn from(agent: Agent) -> Self {
        Self {
            id: agent.id.into(),
            display_name: agent.display_name,
            public_key: hex::encode(agent.public_key),
            created_at: agent.created_at,
            labels: agent.labels,
            orcid: agent.orcid,
            ror_id: agent.ror_id,
        }
    }
}

/// Query parameters for agent listing with optional label filter
#[derive(Deserialize, Debug)]
pub struct AgentListParams {
    #[serde(default = "default_agent_list_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Filter agents by PROV-O label (person, organization, software_agent, instrument)
    pub label: Option<String>,
    /// Exact Ed25519 public key (64 hex characters, either case). When set,
    /// the response holds the one agent with that key, or none: `total` is 0
    /// or 1. ANDed with `label` when both are given. A malformed key is a 400.
    pub public_key: Option<String>,
}

fn default_agent_list_limit() -> i64 {
    20
}

/// Parse and validate a hex-encoded Ed25519 public key.
///
/// Delegates to `ValidationService::parse_public_key` for centralized validation.
///
/// # Arguments
/// * `hex_key` - The hex-encoded public key string (must be 64 characters)
///
/// # Returns
/// * `Ok([u8; 32])` - The decoded 32-byte public key
/// * `Err(ApiError::ValidationError)` - If the key is invalid
///
/// # Example
/// ```rust,ignore
/// let key = parse_public_key("0".repeat(64).as_str())?;
/// assert_eq!(key.len(), 32);
/// ```
fn parse_public_key(hex_key: &str) -> Result<[u8; ED25519_PUBLIC_KEY_BYTE_LENGTH], ApiError> {
    ValidationService::parse_public_key(hex_key)
}

/// Standard harvester-level scopes for an agent OAuth client provisioned on an
/// explicit login request. These allow the agent to read/write claims, edges,
/// and evidence.
///
/// Re-exported from `epigraph_core::canonical_scopes` (identical contents) so
/// this is no longer one of three divergent private grant lists. It is
/// deliberately NOT `read_write_scopes()` — see the constant's doc comment.
#[cfg(feature = "db")]
const AGENT_DEFAULT_SCOPES: &[&str] = epigraph_core::canonical_scopes::AGENT_PROVISION_SCOPES;

/// Refuse a `key_kind` declaration whose proof of possession is missing or
/// does not verify under `public_key` (backlog 57943a39). See
/// [`CreateAgentRequest::key_kind_proof`].
#[cfg(feature = "db")]
fn check_key_kind_proof(
    public_key: &[u8; 32],
    kind: &str,
    proof_hex: Option<&str>,
) -> Result<(), ApiError> {
    let refuse = |reason: &str| ApiError::ValidationError {
        field: "key_kind_proof".to_string(),
        reason: format!(
            "{reason}: declaring key_kind {kind:?} requires the hex Ed25519 signature, under \
             public_key, of key_kind_declaration_message({kind:?}, public_key)"
        ),
    };
    let Some(proof_hex) = proof_hex else {
        return Err(refuse("missing proof of possession"));
    };
    let proof: [u8; 64] = hex::decode(proof_hex)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| refuse("the proof is not a hex-encoded 64-byte signature"))?;
    let message = epigraph_crypto::key_kind_declaration_message(kind, public_key);
    if epigraph_crypto::SignatureVerifier::verify(public_key, &message, &proof).unwrap_or(false) {
        Ok(())
    } else {
        Err(refuse("the proof does not verify under public_key"))
    }
}

/// Create a new agent
///
/// POST /agents
///
/// Creates a new agent with the given public key and optional display name.
///
/// Registering an agent is an IDENTITY act and provisions no login (backlog
/// 2f87eb08). It used to give every new agent an ACTIVE `agent` client with
/// `claims:write`, treating the caller's `agents:write` as the approval, so any
/// `agents:write` holder (a bulk ingester registering one agent per author)
/// minted a live login for every key it registered. Now a client is created
/// only when the request sets `login: true`, and it is ACTIVE only when the
/// caller also holds `claims:admin`; otherwise it is PENDING with no scope
/// granted, awaiting the same approval as a `/oauth/register` agent client.
#[cfg(feature = "db")]
pub async fn create_agent(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    ViewerExtractor(viewer): ViewerExtractor,
    Json(request): Json<CreateAgentRequest>,
) -> Result<Json<AgentResponse>, ApiError> {
    // Enforce scope unconditionally: a request with no AuthContext is refused
    let Some(axum::Extension(ref auth)) = &auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };
    crate::middleware::scopes::check_scopes(auth, &["agents:write"])?;
    let login = request.login;

    let public_key = parse_public_key(&request.public_key)?;
    // Migration 148: the legacy public-constant key of a system role names a
    // system identity. Creating it would mint a second holder of that identity
    // (or, while the system agent still holds it, hand that agent back as a
    // find-hit and provision a client for it), so it is refused before any
    // insert and before any client provisioning.
    if epigraph_db::is_reserved_author_key(&public_key) {
        return Err(ApiError::ValidationError {
            field: "public_key".to_string(),
            reason: "this public key is a system agent's legacy public-constant key, \
                     derivable by anyone; it cannot be registered as an agent"
                .to_string(),
        });
    }

    let seed_derived = match request.key_kind.as_deref() {
        None | Some("ed25519") => false,
        Some(k) if k == epigraph_db::KEY_KIND_SEED_DERIVED => true,
        Some(other) => {
            return Err(ApiError::ValidationError {
                field: "key_kind".to_string(),
                reason: format!(
                    "unknown key_kind {other:?}: expected `ed25519` (the default) or \
                     `seed-derived`"
                ),
            });
        }
    };

    if seed_derived {
        check_key_kind_proof(
            &public_key,
            epigraph_db::KEY_KIND_SEED_DERIVED,
            request.key_kind_proof.as_deref(),
        )?;
    }

    let mut agent = Agent::new(public_key, request.display_name);
    if let Some(labels) = request.labels {
        agent.labels = labels;
    }
    if let Some(orcid) = request.orcid {
        agent.orcid = Some(orcid);
    }
    if let Some(ror_id) = request.ror_id {
        agent.ror_id = Some(ror_id);
    }
    // Note: properties stored via AgentRepository if column exists; currently
    // the Agent struct doesn't carry a properties field, so we rely on the
    // update path or direct DB write for properties. The field is accepted
    // here for forward-compatibility but not persisted until core model is extended.
    let _ = request.properties; // acknowledged but unused until core model supports it
    let (created_agent, was_created) =
        AgentRepository::create_or_get_declaring(&state.db_pool, &agent, seed_derived).await?;
    let new_agent_id = Uuid::from(created_agent.id);

    // A login is provisioned only on an explicit request (backlog 2f87eb08),
    // and only for a *newly created* agent: on a find-hit the agent already
    // exists, and re-creating its client would hit the `oauth_clients` unique
    // constraint on `client_id`.
    //
    // Never for a `seed-derived` key: its private half is public, so an
    // active client for it is a credential anyone can use (backlog 57943a39).
    if was_created && login && !seed_derived {
        let client_id_str = hex::encode(public_key);
        let client_name = created_agent.display_name.as_deref().unwrap_or("Agent");
        let scopes: Vec<String> = AGENT_DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect();

        // `agents:write` is NOT the approval of a login: it is held by bulk
        // ingesters that register an agent per author, for identities that
        // never asked to log in. Only `claims:admin` approves one here; any
        // other caller gets a PENDING client with nothing granted, exactly
        // what `/oauth/register`'s agent arm writes, for an admin to approve.
        let admin = auth.has_scope(epigraph_core::canonical_scopes::CLAIMS_ADMIN);
        let (status, granted): (&str, Vec<String>) = if admin {
            ("active", scopes.clone())
        } else {
            ("pending", Vec::new())
        };

        // This path passes a REAL agent_id at creation time, so it is not
        // part of the "oauth_clients.agent_id is never populated" bug that
        // `AgentRepository::ensure_for_client` fixes for the other three
        // creation paths (`oauth/register.rs`, external provisioning,
        // `bootstrap_clients`). `ensure_for_client` is a no-op for a client
        // created here — it early-returns on the existing link.
        //
        // Do NOT "unify" the two: this one has a real Ed25519 agent whose
        // public_key IS a signature verifier (key_kind='ed25519'), whereas
        // ensure_for_client materialises a `derived` placeholder for a
        // keyless OAuth principal. Collapsing them would either lose the
        // real key or mark it derived.
        if let Err(e) = OAuthClientRepository::create(
            &state.db_pool,
            &client_id_str,
            None, // no client_secret_hash for agent clients
            client_name,
            "agent",
            &scopes,  // allowed_scopes: what an approval may grant
            &granted, // granted_scopes: all of them for an admin, else none
            status,
            Some(new_agent_id),   // agent_id
            Some(auth.client_id), // owner_id = the creating user/service
            None,                 // legal_entity_name
            None,                 // legal_contact_email
            None,                 // redirect_uris: agents use Ed25519 assertion auth, no redirect
        )
        .await
        {
            // Log but don't fail agent creation — the agent row already exists
            tracing::warn!(
                agent_id = %new_agent_id,
                error = %e,
                "Failed to provision the requested OAuth client for new agent"
            );
        }
    }

    // On a find-hit the response is an EXISTING agent's row, and `orcid` /
    // `ror_id` are its profile DETAILS (backlog 761c2b05): posting someone
    // else's public key (which `GET /api/v1/agents` serves) must not read back
    // a private profile's ORCID. This handler has no viewer, so it applies
    // the strict arms of the profile rule only: the agent itself or
    // `claims:admin` sees them; everyone else gets null, even for a public
    // profile, whose detail `GET /api/v1/agents/:id` still serves. A newly
    // created row echoes what this caller just supplied.
    //
    // The NAME of an existing human principal is gated the same way the agent
    // routes gate it (migration 309's disclosure, on a connection stamped from
    // the caller's viewer): a find-hit must not read back a name
    // `GET /api/v1/agents/:id` would null.
    let mut created_agent = created_agent;
    if !was_created {
        let mut read = scoped_read(&state, &viewer, "create_agent").await?;
        let d = AgentDisclosureRepository::disclosure(&mut read, &[new_agent_id])
            .await?
            .remove(&new_agent_id)
            .unwrap_or_default();
        if !d.named {
            // Shown as a nameless service principal is (operator ruling C7).
            created_agent.display_name = d.unnamed_as;
        }
    }
    let mut response: AgentResponse = created_agent.into();
    if !was_created
        && auth.agent_id != Some(new_agent_id)
        && !auth.has_scope(epigraph_core::canonical_scopes::CLAIMS_ADMIN)
    {
        response.orcid = None;
        response.ror_id = None;
    }

    Ok(Json(response))
}

/// Create a new agent (placeholder - no database)
///
/// POST /agents
///
/// Returns a placeholder response when DB is not enabled.
#[cfg(not(feature = "db"))]
pub async fn create_agent(
    State(_state): State<AppState>,
    Json(request): Json<CreateAgentRequest>,
) -> Result<Json<AgentResponse>, ApiError> {
    let public_key = parse_public_key(&request.public_key)?;

    let response = AgentResponse {
        id: Uuid::new_v4(),
        display_name: request.display_name,
        public_key: hex::encode(public_key),
        created_at: chrono::Utc::now(),
        labels: vec![],
        orcid: None,
        ror_id: None,
    };

    Ok(Json(response))
}

/// Get an agent by ID
///
/// GET /agents/:id
///
/// Returns agent information including their public key. `display_name` is,
/// for a human principal the caller may not see named, the `oauth:<client
/// row id>` placeholder a nameless service principal carries (operator
/// ruling C7), and `orcid` /
/// `ror_id` are profile DETAILS, null unless the caller may see the agent's
/// profile: both decided by migration 309's `epigraph_agent_disclosure` on the
/// caller's stamped connection (`epigraph_db::AgentDisclosureRepository`, the
/// rule `get_public_profile` and `find_agent` apply). An unnamed human
/// answers 200 like any agent; its id is never withheld.
#[cfg(feature = "db")]
pub async fn get_agent(
    State(state): State<AppState>,
    ViewerExtractor(viewer): ViewerExtractor,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentResponse>, ApiError> {
    let agent_id = AgentId::from_uuid(id);
    let mut read = scoped_read(&state, &viewer, "get_agent").await?;

    // `agents` is `USING (true)` (migration 077 section 9): the stamp narrows
    // no row here; it is what the profile-visibility read below needs.
    let agent = AgentRepository::get_by_id(&mut *read, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Agent".to_string(),
            id: id.to_string(),
        })?;
    let d = AgentDisclosureRepository::disclosure(&mut read, &[id]).await?;

    Ok(Json(redact_profile(agent, &d)))
}

/// A viewer-stamped connection for `handler`, or the 500 every scoped read in
/// this file answers when none can be had.
#[cfg(feature = "db")]
async fn scoped_read<'s>(
    state: &'s AppState,
    viewer: &epigraph_db::Viewer,
    handler: &'static str,
) -> Result<epigraph_db::ScopedRead<'s>, ApiError> {
    state.read_as(viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler,
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })
}

/// The agent as the caller may see it: `display_name` replaced by the
/// placeholder a nameless service principal carries when not `named`
/// (operator ruling C7), `orcid` / `ror_id` nulled when not `details`. An id
/// missing from `d` (never true for a row just read) is treated as fully
/// hidden: the fail direction is closed.
#[cfg(feature = "db")]
fn redact_profile(
    mut agent: Agent,
    d: &std::collections::HashMap<Uuid, epigraph_db::Disclosure>,
) -> AgentResponse {
    let disclosure = d.get(&Uuid::from(agent.id)).cloned().unwrap_or_default();
    epigraph_db::redact_agent(&mut agent, disclosure);
    agent.into()
}

/// Get an agent by ID (placeholder - no database)
///
/// GET /agents/:id
///
/// Returns placeholder data until DB integration is complete.
#[cfg(not(feature = "db"))]
pub async fn get_agent(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentResponse>, ApiError> {
    let response = AgentResponse {
        id,
        display_name: Some("Placeholder Agent".to_string()),
        public_key: "0".repeat(64), // Placeholder hex-encoded key
        created_at: chrono::Utc::now(),
        labels: vec![],
        orcid: None,
        ror_id: None,
    };

    Ok(Json(response))
}

/// List agents with pagination and optional label / public-key filters
///
/// GET /agents?limit=20&offset=0&label=person
/// GET /api/v1/agents?public_key=<64 hex>
///
/// Returns a paginated list of agents ordered by creation date (newest first).
/// When `label` is provided, only agents with that PROV-O label are returned.
/// `orcid` and `ror_id` are null for every agent whose profile the caller may
/// not see, as in [`get_agent`].
///
/// When `public_key` is provided, the answer is the one agent holding that
/// exact key (`total` 0 or 1), still filtered by `label` if that is given, so
/// a caller resolves an agent by key in ONE request instead of paging the
/// whole list. That lookup reads on the caller's viewer-stamped connection
/// ([`AppState::read_as`]). `agents_identity` (migration 077 section 9) is
/// `USING (true)`, so the stamp narrows nothing today and the row is the one
/// the unfiltered list would page to: the filter exposes nothing the list
/// does not, and its `orcid` / `ror_id` are nulled by the same
/// profile-visibility rule (backlog 761c2b05).
///
/// The handler takes a [`ViewerExtractor`], so a token that names no
/// principal is refused 401 on every arm, as `search_agents` and
/// `get_agent_reputation` in this file already refuse it. The label and
/// unfiltered arms still read through `state.db_pool`: their repository
/// functions take a `&PgPool`, and moving them is a repository-signature
/// change this filter does not make.
///
/// [`AppState::read_as`]: crate::AppState::read_as
#[cfg(feature = "db")]
pub async fn list_agents(
    State(state): State<AppState>,
    ViewerExtractor(viewer): ViewerExtractor,
    Query(params): Query<AgentListParams>,
) -> Result<Json<PaginatedResponse<AgentResponse>>, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    if let Some(ref hex_key) = params.public_key {
        let key = parse_public_key(hex_key.trim())?;
        let mut read = state.read_as(&viewer).await.map_err(|e| {
            tracing::error!(
                target: "tenancy.scoped_read",
                error = %e,
                handler = "list_agents",
                "could not acquire a viewer-stamped connection"
            );
            ApiError::InternalError {
                message: "Failed to acquire a scoped connection".to_string(),
            }
        })?;
        let found = AgentRepository::get_by_public_key(&mut *read, &key)
            .await?
            .filter(|a| match params.label.as_ref() {
                None => true,
                Some(label) => a.labels.contains(label),
            });
        let total = i64::from(found.is_some());
        // The same profile redaction as the list arms below (backlog
        // 761c2b05): a key lookup must not disclose an ORCID / ROR id the
        // list would null.
        let ids: Vec<Uuid> = found.iter().map(|a| Uuid::from(a.id)).collect();
        let d = AgentDisclosureRepository::disclosure(&mut read, &ids).await?;
        // One match at most, so `offset` past it pages to nothing.
        let items: Vec<AgentResponse> = found
            .into_iter()
            .skip(usize::try_from(offset).unwrap_or(usize::MAX))
            .map(|a| redact_profile(a, &d))
            .collect();
        return Ok(Json(PaginatedResponse {
            items,
            total,
            limit,
            offset,
        }));
    }

    let (agents, total) = if let Some(ref label) = params.label {
        let agents = AgentRepository::list_by_label(&state.db_pool, label, limit, offset).await?;
        let total = AgentRepository::count_by_label(&state.db_pool, label).await?;
        (agents, total)
    } else {
        let agents = AgentRepository::list(&state.db_pool, limit, offset).await?;
        let total = AgentRepository::count(&state.db_pool).await?;
        (agents, total)
    };

    // The rows come from the raw pool (`agents` is `USING (true)`, so a stamp
    // narrows none of them); the profile-visibility read needs the stamp, for
    // the shared-group arm. Applied after both branches, so a label filter
    // cannot skip it.
    let ids: Vec<Uuid> = agents.iter().map(|a| Uuid::from(a.id)).collect();
    let mut read = scoped_read(&state, &viewer, "list_agents").await?;
    let d = AgentDisclosureRepository::disclosure(&mut read, &ids).await?;
    let items: Vec<AgentResponse> = agents.into_iter().map(|a| redact_profile(a, &d)).collect();

    Ok(Json(PaginatedResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// List agents with pagination (placeholder - no database)
///
/// GET /agents?limit=20&offset=0
///
/// Returns an empty list when DB is not enabled.
#[cfg(not(feature = "db"))]
pub async fn list_agents(
    State(_state): State<AppState>,
    Query(params): Query<AgentListParams>,
) -> Result<Json<PaginatedResponse<AgentResponse>>, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    Ok(Json(PaginatedResponse {
        items: vec![],
        total: 0,
        limit,
        offset,
    }))
}

/// Query parameters of `GET /api/v1/agents/search`.
#[derive(Deserialize, Debug)]
pub struct AgentSearchParams {
    /// The name (or an ORCID / ROR id) to look up. Required.
    pub name: String,
    /// Keep only agents of this kind: `human`, `llm_agent`, `system`, `role`,
    /// `ingest_author` or `unknown`.
    pub kind: Option<String>,
    /// Keep only agents holding this role (`role:<key>` or `<key>`).
    pub role: Option<String>,
    /// At most this many results (default 10, at most 25).
    pub limit: Option<i64>,
}

/// The scope `GET /api/v1/agents/search` requires: the card counts claims
/// and names agents, both claim-reading facts (the MCP `find_agent` /
/// `get_agent` tools are mapped to the same scope).
#[cfg(feature = "db")]
pub const AGENT_SEARCH_SCOPE: &str = "claims:read";

/// Find agents by name
///
/// GET /api/v1/agents/search?name=&kind=&role=&limit=
///
/// Case-insensitive, accent-folded name match (plus exact ORCID / ROR id
/// where the caller may see it), ranked exact > prefix > similar, each result
/// carrying the card that tells near-duplicates apart: kind (derived from
/// evidence the caller may see), the roles it may see, the human the agent
/// is currently bound to (shown to every reader; none once its link is
/// retired), created_at, and counts of authored papers (not awaiting
/// countersignature, and pending apart) and asserted claims computed under
/// the caller's viewer.
/// The same code and viewer rules serve MCP `find_agent`
/// (`epigraph_db::AgentLookupRepository::find`). Requires authentication.
#[cfg(feature = "db")]
pub async fn search_agents(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    ViewerExtractor(viewer): ViewerExtractor,
    Query(params): Query<AgentSearchParams>,
) -> Result<Json<epigraph_db::FindAgentResult>, ApiError> {
    // Fail closed: no AuthContext is a 401, never a skipped scope check.
    let Some(axum::Extension(auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "agent search requires authentication".into(),
        });
    };
    crate::middleware::scopes::check_scopes(&auth, &[AGENT_SEARCH_SCOPE])?;
    let query = epigraph_db::FindAgentQuery::new(
        &params.name,
        params.kind.as_deref(),
        params.role.as_deref(),
        params.limit,
    )
    .map_err(|e| match e {
        epigraph_db::DbError::InvalidData { reason } => ApiError::ValidationError {
            field: "name/kind/role".to_string(),
            reason,
        },
        other => other.into(),
    })?;
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "search_agents",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;
    let result = epigraph_db::AgentLookupRepository::find(&mut read, &viewer, &query).await?;
    Ok(Json(result))
}

/// Get an agent's reputation score
///
/// GET /agents/:id/reputation
///
/// Computes a reputation score from the agent's claim history.
/// Reputation is derived FROM claim outcomes, never used AS INPUT to truth calculation.
/// This prevents the "Appeal to Authority" fallacy.
#[cfg(feature = "db")]
pub async fn get_agent_reputation(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentReputationResponse>, ApiError> {
    let agent_id = AgentId::from_uuid(id);

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "get_agent_reputation",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // 1. Look up the agent (404 if not found).
    //
    // Stamping this statement narrows NOTHING and is not claimed to: migration
    // 077 section 9 gives `agents` the policy `agents_identity FOR SELECT TO
    // PUBLIC USING (true)`. It shares the connection so that the reputation this
    // handler returns is computed under ONE tenancy stamp rather than two
    // checkouts'. That is the property the shared connection delivers; it is NOT
    // a shared snapshot, because a `ScopedRead` is a bare connection under
    // `SessionGucMode::Session` and READ COMMITTED under `Transaction`.
    let agent = AgentRepository::get_by_id(&mut *read, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Agent".to_string(),
            id: id.to_string(),
        })?;

    // 2. Fetch all claims by this agent. THIS is the read the stamp bears on:
    // `claims` is FORCEd and `get_by_agent` splices the viewer.
    let claims = ClaimRepository::get_by_agent(&mut *read, &viewer, agent_id).await?;

    // The name as the caller may see it (migration 309, on this stamped
    // connection): an unnamed human's reputation reads as a nameless service
    // principal's (its `oauth:<client row id>` placeholder, ruling C7).
    let mut agent = agent;
    let d = AgentDisclosureRepository::disclosure(&mut read, &[id]).await?;
    epigraph_db::redact_agent(&mut agent, d.get(&id).cloned().unwrap_or_default());

    // 3. Convert claims into ClaimOutcome structs
    let now = chrono::Utc::now();
    let outcomes: Vec<ClaimOutcome> = claims
        .iter()
        .map(|claim| {
            let age = now.signed_duration_since(claim.created_at);
            #[allow(clippy::cast_precision_loss)]
            let age_days = (age.num_hours() as f64 / 24.0).max(0.0);
            ClaimOutcome {
                truth_value: claim.truth_value.value(),
                age_days,
                was_refuted: claim.truth_value.value() < REFUTATION_THRESHOLD,
            }
        })
        .collect();

    // 4. Calculate reputation score
    let calculator = ReputationCalculator::new();
    let reputation_score =
        calculator
            .calculate(&outcomes)
            .map_err(|e| ApiError::InternalError {
                message: format!("Reputation calculation failed: {}", e),
            })?;

    // 5. Compute response statistics
    let total_claims = claims.len();
    let verified_claims = claims
        .iter()
        .filter(|c| c.truth_value.is_verified_true())
        .count();
    let claim_age_days_avg = if outcomes.is_empty() {
        0.0
    } else {
        outcomes.iter().map(|o| o.age_days).sum::<f64>() / outcomes.len() as f64
    };

    Ok(Json(AgentReputationResponse {
        agent_id: id,
        display_name: agent.display_name,
        reputation_score,
        total_claims,
        verified_claims,
        claim_age_days_avg,
    }))
}

/// Get an agent's reputation score (placeholder - no database)
///
/// GET /agents/:id/reputation
///
/// Returns a placeholder response with initial reputation when DB is not enabled.
#[cfg(not(feature = "db"))]
pub async fn get_agent_reputation(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AgentReputationResponse>, ApiError> {
    let calculator = ReputationCalculator::new();
    let reputation_score = calculator
        .calculate(&[])
        .map_err(|e| ApiError::InternalError {
            message: format!("Reputation calculation failed: {}", e),
        })?;

    Ok(Json(AgentReputationResponse {
        agent_id: id,
        display_name: Some("Placeholder Agent".to_string()),
        reputation_score,
        total_claims: 0,
        verified_claims: 0,
        claim_age_days_avg: 0.0,
    }))
}

// =============================================================================
// AGENT CLAIMS (via ATTRIBUTED_TO edges)
// =============================================================================

/// Query parameters for the agent claims endpoint
#[derive(Deserialize, Debug)]
pub struct AgentClaimsParams {
    /// Maximum number of items to return (default: 20, max: 100)
    #[serde(default = "default_agent_claims_limit")]
    pub limit: i64,
    /// Number of items to skip (default: 0)
    #[serde(default)]
    pub offset: i64,
    /// Minimum truth value filter (default: 0.0)
    #[serde(default)]
    pub min_truth: f64,
}

fn default_agent_claims_limit() -> i64 {
    20
}

/// Response for agent claims endpoint, includes attribution metadata
#[derive(Serialize, Debug)]
pub struct AttributedClaimResponse {
    #[serde(flatten)]
    pub claim: ClaimResponse,
    /// PROV-O edge properties (role, position, contributions)
    pub attribution: serde_json::Value,
}

/// List claims attributed to an agent via ATTRIBUTED_TO edges
///
/// GET /api/v1/agents/:id/claims?limit=50&offset=0&min_truth=0.0
///
/// Traverses `prov:wasAttributedTo` edges to return all claims attributed to
/// the given agent. Works for both human author agents and digital ingestion agents.
///
/// Returns claims linked via ATTRIBUTED_TO edges (claim → agent), with pagination
/// and optional minimum truth value filtering.
#[cfg(feature = "db")]
pub async fn agent_claims(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<AgentClaimsParams>,
) -> Result<Json<PaginatedResponse<AttributedClaimResponse>>, ApiError> {
    let agent_id = AgentId::from_uuid(id);

    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "agent_claims",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    // Verify agent exists. As in `get_agent_reputation`, `agents_identity`
    // does not narrow, so this site shares the connection for coherence with
    // the two `edges`/`claims` reads below rather than for suppression.
    AgentRepository::get_by_id(&mut *read, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Agent".to_string(),
            id: id.to_string(),
        })?;

    // Clamp pagination
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);
    let min_truth = params.min_truth.clamp(0.0, 1.0);

    // Query claims via ATTRIBUTED_TO edges.
    //
    // The page and its total now come off the SAME connection, which is what
    // makes `total` describe the set `rows` was drawn from. On two checkouts
    // they could disagree — and a total larger than the viewer's visible set is
    // itself a cardinality disclosure.
    let rows =
        EdgeRepository::get_claims_attributed_to(&mut *read, &viewer, id, min_truth, limit, offset)
            .await?;

    let total =
        EdgeRepository::count_claims_attributed_to(&mut *read, &viewer, id, min_truth).await?;

    // The page's labels, in one read on the same viewer-stamped connection
    // (backlog a8b785a7: every item used to carry `labels: []`). A failed read
    // is an error, not an empty label list: `[]` would claim the claims are
    // unlabelled. The page has one row per attribution EDGE, so a claim with
    // two edges to this agent appears twice; each row reads the map without
    // consuming it, so both copies carry the labels.
    let ids: Vec<Uuid> = rows.iter().map(|row| row.id).collect();
    let labels = ClaimRepository::labels_by_ids(&mut *read, &viewer, &ids)
        .await
        .map_err(|e| ApiError::DatabaseError {
            message: format!("agent_claims: failed to read the claims' labels: {e}"),
        })?;

    let items: Vec<AttributedClaimResponse> = rows
        .into_iter()
        .map(|row| {
            let claim = ClaimResponse {
                id: row.id,
                content: row.content,
                truth_value: row.truth_value,
                agent_id: row.agent_id,
                trace_id: row.trace_id,
                created_at: row.created_at,
                updated_at: row.updated_at,
                privacy_tier: None,
                encrypted_content: None,
                encryption_epoch: None,
                group_id: None,
                labels: labels.get(&row.id).cloned().unwrap_or_default(),
                was_created: false,
                authored_by: None,
                visibility: None,
                owner_group_id: None,
                visibility_note: None,
            };
            AttributedClaimResponse {
                claim,
                attribution: row.edge_properties,
            }
        })
        .collect();

    Ok(Json(PaginatedResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// List claims attributed to an agent (placeholder - no database)
///
/// GET /api/v1/agents/:id/claims
#[cfg(not(feature = "db"))]
pub async fn agent_claims(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Query(params): Query<AgentClaimsParams>,
) -> Result<Json<PaginatedResponse<AttributedClaimResponse>>, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    Ok(Json(PaginatedResponse {
        items: vec![],
        total: 0,
        limit,
        offset,
    }))
}

// =============================================================================
// UPDATE AGENT
// =============================================================================

/// Request to update an existing agent
#[derive(Deserialize)]
pub struct UpdateAgentRequest {
    pub display_name: Option<String>,
    pub labels: Option<Vec<String>>,
    pub orcid: Option<String>,
    pub ror_id: Option<String>,
    /// Reserved for future use
    pub properties: Option<serde_json::Value>,
    /// Whether the caller's OWN name is shown to everyone: `"public"` or
    /// `"group"` (migration 310, human-identity visibility spec section 8).
    /// Accepted only on the caller's own record, `claims:admin` included, and
    /// only from a person (a human principal); written through the audited
    /// self-service definer on a viewer-stamped transaction.
    #[serde(default)]
    pub profile_visibility: Option<String>,
}

/// Update an existing agent
///
/// PUT /api/v1/agents/:id
///
/// Updates mutable fields on an agent. The public key is immutable.
/// Caller must be the target agent (auth.agent_id == :id) or have `claims:admin`.
///
/// # Errors
///
/// - 401 Unauthorized: Missing or invalid Bearer token
/// - 403 Forbidden: Missing scope or caller is not the target agent
/// - 404 Not Found: Agent does not exist
///
/// `profile_visibility` (`"public"` | `"group"`) is self only: 403 when `:id`
/// is not the caller, even for `claims:admin`, and 403 (PVS05) when the caller
/// is not a person; 400 for another value. A request carrying only that field
/// writes nothing else.
#[cfg(feature = "db")]
pub async fn update_agent(
    State(state): State<AppState>,
    ViewerExtractor(viewer): ViewerExtractor,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateAgentRequest>,
) -> Result<Json<AgentResponse>, ApiError> {
    // Enforce scope unconditionally: a request with no AuthContext is refused
    let Some(axum::Extension(ref auth)) = auth_ctx else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required".to_string(),
        });
    };
    crate::middleware::scopes::check_scopes(auth, &["agents:write"])?;
    // Caller must be the target agent OR have claims:admin
    if !auth.has_scope("claims:admin") && auth.agent_id != Some(id) {
        return Err(ApiError::Forbidden {
            reason: "can only mutate your own agent record".into(),
        });
    }

    // The profile opt-in is the person's own act ("set BY H"): no admin arm.
    // Checked before anything is written.
    let profile = match request.profile_visibility.as_deref() {
        None => None,
        Some(_) if auth.agent_id != Some(id) => {
            return Err(ApiError::Forbidden {
                reason: "profile_visibility is set only on your own record, by you".into(),
            });
        }
        Some(raw) => Some(epigraph_db::ProfileVisibility::parse(raw).ok_or_else(|| {
            ApiError::ValidationError {
                field: "profile_visibility".to_string(),
                reason: format!("{raw:?} is neither 'public' nor 'group'"),
            }
        })?),
    };

    // The opt-in is its own act, never mixed with a profile edit: the edit
    // and the opt-in run on different connections (the edit on the request
    // pool, the opt-in through 310's definer on a stamped transaction), so a
    // mixed body could commit the edit and then have the opt-in refused
    // (review finding correctness#7). Refused before anything is written.
    let profile_only = profile.is_some();
    if profile_only
        && (request.display_name.is_some()
            || request.labels.is_some()
            || request.orcid.is_some()
            || request.ror_id.is_some())
    {
        return Err(ApiError::ValidationError {
            field: "profile_visibility".to_string(),
            reason: "set profile_visibility in a request of its own, with no other field".into(),
        });
    }

    let agent_id = AgentId::from_uuid(id);

    // Fetch existing agent (404 if not found)
    let mut agent = AgentRepository::get_by_id(&state.db_pool, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Agent".to_string(),
            id: id.to_string(),
        })?;

    // Apply partial updates
    if let Some(display_name) = request.display_name {
        agent.display_name = Some(display_name);
    }
    if let Some(labels) = request.labels {
        agent.labels = labels;
    }
    if let Some(orcid) = request.orcid {
        agent.orcid = Some(orcid);
    }
    if let Some(ror_id) = request.ror_id {
        agent.ror_id = Some(ror_id);
    }

    let updated = if profile_only {
        agent
    } else {
        AgentRepository::update(&state.db_pool, &agent).await?
    };

    // Migration 310's definer, on a transaction stamped from the caller: the
    // target is the stamped principal, which is `id` (checked above).
    if let Some(visibility) = profile {
        let mut tx = state.write_as(&viewer, "update_agent").await?;
        AgentRepository::set_profile_visibility_conn(&mut tx, visibility).await?;
        tx.commit().await.map_err(|e| ApiError::InternalError {
            message: format!("Failed to commit the profile visibility: {e}"),
        })?;
    }

    // Record provenance when OAuth2-authenticated
    if let Some(axum::Extension(ref auth)) = auth_ctx {
        let content_hash = blake3::hash(id.as_bytes());
        if let Err(e) = crate::middleware::provenance::record_provenance(
            &state.db_pool,
            auth,
            "agent",
            id,
            "update",
            content_hash.as_bytes(),
            &[],
            None,
        )
        .await
        {
            tracing::warn!(agent_id = %id, error = %e, "Failed to record agent update provenance");
        }
    }

    // The response is redacted by the rule on the caller's stamped read, as
    // `get_agent` is (review findings correctness#7, leaks#4a, tests#2): a
    // `claims:admin` caller editing ANOTHER agent must not be handed a name
    // the rule withholds from it, whatever the edit's own connection admits.
    let mut read = scoped_read(&state, &viewer, "update_agent").await?;
    let d = AgentDisclosureRepository::disclosure(&mut read, &[id]).await?;
    Ok(Json(redact_profile(updated, &d)))
}

/// Update an existing agent (placeholder - no database)
#[cfg(not(feature = "db"))]
pub async fn update_agent(
    State(_state): State<AppState>,
    Path(_id): Path<Uuid>,
    Json(_request): Json<UpdateAgentRequest>,
) -> Result<Json<AgentResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Agent updates require database".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_response_from_agent() {
        let public_key = [42u8; ED25519_PUBLIC_KEY_BYTE_LENGTH];
        let agent = Agent::new(public_key, Some("Alice".to_string()));

        // Consume agent directly - no need to clone since we don't use it after
        let response: AgentResponse = agent.into();

        assert_eq!(response.display_name, Some("Alice".to_string()));
        assert_eq!(response.public_key.len(), ED25519_PUBLIC_KEY_HEX_LENGTH);
        assert!(response.public_key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_parse_public_key_valid() {
        let valid_hex = "0".repeat(ED25519_PUBLIC_KEY_HEX_LENGTH);
        let result = parse_public_key(&valid_hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0u8; ED25519_PUBLIC_KEY_BYTE_LENGTH]);
    }

    #[test]
    fn test_parse_public_key_invalid_length() {
        let short_hex = "0".repeat(ED25519_PUBLIC_KEY_BYTE_LENGTH); // Half the required length
        let result = parse_public_key(&short_hex);
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::ValidationError { field, .. } => {
                assert_eq!(field, "public_key");
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_parse_public_key_invalid_hex() {
        let invalid_hex = "g".repeat(ED25519_PUBLIC_KEY_HEX_LENGTH);
        let result = parse_public_key(&invalid_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_reputation_response_serialization() {
        let response = AgentReputationResponse {
            agent_id: Uuid::nil(),
            display_name: Some("Test Agent".to_string()),
            reputation_score: 0.75,
            total_claims: 10,
            verified_claims: 7,
            claim_age_days_avg: 15.5,
        };

        let json = serde_json::to_value(&response).unwrap();

        assert_eq!(json["agent_id"], Uuid::nil().to_string());
        assert_eq!(json["display_name"], "Test Agent");
        assert_eq!(json["reputation_score"], 0.75);
        assert_eq!(json["total_claims"], 10);
        assert_eq!(json["verified_claims"], 7);
        assert_eq!(json["claim_age_days_avg"], 15.5);
    }

    #[test]
    fn test_new_agent_no_claims_gets_initial_reputation() {
        let calculator = ReputationCalculator::new();
        let reputation = calculator.calculate(&[]).unwrap();

        // New agents with no claims should get initial reputation of 0.5
        assert!(
            (reputation - 0.5).abs() < f64::EPSILON,
            "Expected initial reputation 0.5, got {}",
            reputation
        );
    }

    #[test]
    fn test_agent_response_includes_labels() {
        let mut agent = Agent::new([42u8; 32], Some("Dr. Smith".to_string()));
        agent.labels = vec!["person".to_string()];
        agent.orcid = Some("0000-0001-2345-6789".to_string());

        let response: AgentResponse = agent.into();
        assert_eq!(response.labels, vec!["person"]);
        assert_eq!(response.orcid, Some("0000-0001-2345-6789".to_string()));
        assert!(response.ror_id.is_none());
    }

    #[test]
    fn test_agent_list_params_defaults() {
        let json = "{}";
        let params: AgentListParams = serde_json::from_str(json).unwrap();

        assert_eq!(params.limit, 20);
        assert_eq!(params.offset, 0);
        assert!(params.label.is_none());
    }

    #[test]
    fn test_agent_claims_params_defaults() {
        let json = "{}";
        let params: AgentClaimsParams = serde_json::from_str(json).unwrap();

        assert_eq!(params.limit, 20);
        assert_eq!(params.offset, 0);
        assert!((params.min_truth - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_agent_claims_params_custom() {
        let json = r#"{"limit": 50, "offset": 10, "min_truth": 0.7}"#;
        let params: AgentClaimsParams = serde_json::from_str(json).unwrap();

        assert_eq!(params.limit, 50);
        assert_eq!(params.offset, 10);
        assert!((params.min_truth - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_attributed_claim_response_serialization() {
        let now = chrono::Utc::now();
        let response = AttributedClaimResponse {
            claim: ClaimResponse {
                id: Uuid::nil(),
                content: "Test claim".to_string(),
                truth_value: 0.85,
                agent_id: Uuid::nil(),
                trace_id: None,
                created_at: now,
                updated_at: now,
                privacy_tier: None,
                encrypted_content: None,
                encryption_epoch: None,
                group_id: None,
                labels: Vec::new(),
                was_created: false,
                authored_by: None,
                visibility: None,
                owner_group_id: None,
                visibility_note: None,
            },
            attribution: serde_json::json!({
                "prov": "wasAttributedTo",
                "role": "author",
                "position": 0
            }),
        };

        let json = serde_json::to_value(&response).unwrap();

        // #[serde(flatten)] means claim fields are at top level
        assert_eq!(json["content"], "Test claim");
        assert_eq!(json["truth_value"], 0.85);
        assert_eq!(json["attribution"]["prov"], "wasAttributedTo");
        assert_eq!(json["attribution"]["role"], "author");
        assert_eq!(json["attribution"]["position"], 0);
    }
}
