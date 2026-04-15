//! Political network monitoring API endpoints (Items 3–12)
//!
//! Provides REST endpoints for narrative propagation analysis:
//! - `GET  /api/v1/agents/:id/epistemic-profile`      — Item 4: Epistemic Profile
//! - `GET  /api/v1/agents/compare`                     — Item 4: Multi-agent comparison
//! - `GET  /api/v1/agents/:id/position-timeline`       — Item 5: Temporal Position Drift
//! - `GET  /api/v1/claims/:id/genealogy`               — Item 8: Talking Point Genealogy
//! - `GET  /api/v1/agents/:id/originated-claims`       — Item 8: Reverse genealogy
//! - `GET  /api/v1/agents/:id/inflation-index`         — Item 9: Monster Inflation Index
//! - `GET  /api/v1/inflation-index/leaderboard`        — Item 9: Cross-figure comparison
//! - `GET  /api/v1/claims/:id/techniques`              — Item 3: USES_TECHNIQUE edges
//! - `GET  /api/v1/propaganda-techniques`              — Item 3: List techniques
//! - `POST /api/v1/propaganda-techniques`              — Item 3: Create technique
//! - `GET  /api/v1/coalitions`                         — Item 7: List coalitions
//! - `POST /api/v1/coalitions`                         — Item 7: Create coalition
//! - `GET  /api/v1/counter-narrative-gaps`             — Item 11: Gap scanner stub
//! - `GET  /api/v1/mirror-narratives`                  — Item 12: Mirror detection stub

use crate::errors::ApiError;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use epigraph_core::AgentId;
#[cfg(feature = "db")]
use epigraph_db::{AgentRepository, PoliticalRepository};

// =============================================================================
// RESPONSE TYPES
// =============================================================================

/// Epistemic profile for a political agent (Item 4)
#[derive(Debug, Serialize)]
pub struct EpistemicProfileResponse {
    pub agent_id: Uuid,
    pub display_name: Option<String>,
    pub claim_count: usize,
    pub evidence_distribution: HashMap<String, f64>,
    pub epistemic_status_distribution: HashMap<String, f64>,
    pub mean_truth_value: f64,
    pub refutation_rate: f64,
    pub topics: Vec<String>,
    pub time_range: Option<TimeRange>,
}

#[derive(Debug, Serialize)]
pub struct TimeRange {
    pub first: chrono::DateTime<chrono::Utc>,
    pub last: chrono::DateTime<chrono::Utc>,
}

/// Position timeline for temporal drift analysis (Item 5)
#[derive(Debug, Serialize)]
pub struct PositionTimelineResponse {
    pub agent_id: Uuid,
    pub topic: Option<String>,
    pub timeline: Vec<TimelineEntry>,
    pub consistency_score: f64,
    pub flip_events: Vec<FlipEvent>,
}

#[derive(Debug, Serialize)]
pub struct TimelineEntry {
    pub date: chrono::DateTime<chrono::Utc>,
    pub claim_id: Uuid,
    pub content_summary: String,
    pub truth_value: f64,
    pub supersedes: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct FlipEvent {
    pub date: chrono::DateTime<chrono::Utc>,
    pub from_claim_id: Uuid,
    pub to_claim_id: Uuid,
}

/// Genealogy response for talking point propagation (Item 8)
#[derive(Debug, Serialize)]
pub struct GenealogyResponse {
    pub claim_id: Uuid,
    pub origin: Option<GenealogyOrigin>,
    pub propagation_tree: Vec<PropagationEntry>,
    pub total_amplifiers: usize,
    pub institutional_path: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct GenealogyOrigin {
    pub agent_id: Uuid,
    pub agent_name: Option<String>,
    pub date: Option<String>,
    pub venue: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PropagationEntry {
    pub agent_id: Uuid,
    pub agent_name: Option<String>,
    pub relationship: String,
    pub date: Option<String>,
    pub venue: Option<String>,
    pub reach_estimate: Option<i64>,
    pub delta_from_original: Option<f64>,
    pub amplification_type: Option<String>,
}

/// Inflation index response (Item 9)
#[derive(Debug, Serialize)]
pub struct InflationIndexResponse {
    pub agent_id: Uuid,
    pub overall_inflation_index: Option<f64>,
    pub claim_count: usize,
    pub sample_claims: Vec<InflationClaimEntry>,
}

#[derive(Debug, Serialize)]
pub struct InflationClaimEntry {
    pub claim_id: Uuid,
    pub content_summary: String,
    pub inflation_factor: f64,
    pub asserted_value: Option<String>,
    pub evidenced_value: Option<String>,
}

/// Propaganda technique response
#[derive(Debug, Serialize)]
pub struct TechniqueResponse {
    pub id: Uuid,
    pub name: String,
    pub category: Option<String>,
    pub description: Option<String>,
    pub detection_guidance: Option<String>,
    pub properties: serde_json::Value,
}

/// Coalition response (Item 7)
#[derive(Debug, Serialize)]
pub struct CoalitionResponse {
    pub id: Uuid,
    pub name: Option<String>,
    pub archetype: Option<String>,
    pub dominant_antagonist: Option<String>,
    pub cognitive_shape: Option<String>,
    pub member_count: i32,
    pub start_date: Option<chrono::DateTime<chrono::Utc>>,
    pub peak_date: Option<chrono::DateTime<chrono::Utc>>,
    pub is_active: bool,
    pub reach_estimate: Option<i64>,
    pub detection_method: String,
}

/// Claim technique usage response
#[derive(Debug, Serialize)]
pub struct ClaimTechniqueResponse {
    pub technique: TechniqueResponse,
    pub confidence: Option<f64>,
    pub detected_by: Option<String>,
    pub evidence_text: Option<String>,
}

/// Originated claims response (reverse genealogy)
#[derive(Debug, Serialize)]
pub struct OriginatedClaimResponse {
    pub claim_id: Uuid,
    pub content: String,
    pub amplifier_count: i64,
}

// =============================================================================
// REQUEST TYPES
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct EpistemicProfileParams {
    // Future: topic filter, date range
}

#[derive(Debug, Deserialize)]
pub struct CompareAgentsParams {
    pub ids: String, // comma-separated UUIDs
}

#[derive(Debug, Deserialize)]
pub struct PositionTimelineParams {
    pub topic: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OriginatedClaimsParams {
    #[serde(default = "default_min_amplifiers")]
    pub amplified_by_min: i64,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_min_amplifiers() -> i64 {
    1
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Deserialize)]
pub struct InflationIndexParams {
    pub topic: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TechniqueListParams {
    pub category: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreateTechniqueRequest {
    pub name: String,
    pub category: Option<String>,
    pub description: Option<String>,
    pub detection_guidance: Option<String>,
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct CoalitionListParams {
    #[serde(default)]
    pub active: Option<bool>,
    pub archetype: Option<String>,
    #[serde(default)]
    pub min_members: Option<i32>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreateCoalitionRequest {
    pub name: Option<String>,
    pub archetype: Option<String>,
    pub dominant_antagonist: Option<String>,
    pub cognitive_shape: Option<String>,
    #[serde(default = "default_detection_method")]
    pub detection_method: String,
    pub properties: Option<serde_json::Value>,
}

fn default_detection_method() -> String {
    "embedding+time".to_string()
}

#[derive(Debug, Deserialize)]
pub struct CounterNarrativeGapParams {
    #[serde(default = "default_min_coalition_size")]
    pub min_coalition_size: i32,
    #[serde(default = "default_max_readiness")]
    pub max_readiness: i32,
}

fn default_min_coalition_size() -> i32 {
    3
}

fn default_max_readiness() -> i32 {
    2
}

#[derive(Debug, Deserialize)]
pub struct MirrorNarrativeParams {
    #[serde(default)]
    pub active: Option<bool>,
}

// =============================================================================
// HANDLERS
// =============================================================================

// ── Item 4: Epistemic Profile ───────────────────────────────────────────

/// GET /api/v1/agents/:id/epistemic-profile
///
/// Aggregates an agent's claim history into an epistemic profile showing
/// evidence type distribution, truth value statistics, and refutation rate.
#[cfg(feature = "db")]
pub async fn epistemic_profile(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(_params): Query<EpistemicProfileParams>,
) -> Result<Json<EpistemicProfileResponse>, ApiError> {
    let agent_id = AgentId::from_uuid(id);
    let pool = &state.db_pool;

    // Verify agent exists
    let agent = AgentRepository::get_by_id(pool, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Agent".to_string(),
            id: id.to_string(),
        })?;

    // Fetch claims
    let claims = PoliticalRepository::get_agent_profile_claims(pool, id).await?;
    let claim_count = claims.len();

    if claim_count == 0 {
        return Ok(Json(EpistemicProfileResponse {
            agent_id: id,
            display_name: agent.display_name,
            claim_count: 0,
            evidence_distribution: HashMap::new(),
            epistemic_status_distribution: HashMap::new(),
            mean_truth_value: 0.0,
            refutation_rate: 0.0,
            topics: vec![],
            time_range: None,
        }));
    }

    // Compute truth value stats
    let sum_truth: f64 = claims.iter().map(|c| c.truth_value).sum();
    let mean_truth = sum_truth / claim_count as f64;

    // Refutation rate (truth < 0.2)
    let refuted = claims.iter().filter(|c| c.truth_value < 0.2).count();
    let refutation_rate = refuted as f64 / claim_count as f64;

    // Epistemic status distribution
    let mut status_dist: HashMap<String, usize> = HashMap::new();
    for claim in &claims {
        let status = if claim.truth_value < 0.2 {
            "refuted"
        } else if claim.truth_value < 0.4 {
            "contested"
        } else if claim.truth_value >= 0.8 {
            "verified"
        } else {
            "active"
        };
        *status_dist.entry(status.to_string()).or_insert(0) += 1;
    }
    let status_distribution: HashMap<String, f64> = status_dist
        .into_iter()
        .map(|(k, v)| (k, v as f64 / claim_count as f64))
        .collect();

    // Evidence distribution
    let ev_rows = PoliticalRepository::get_agent_evidence_distribution(pool, id).await?;
    let ev_total: i64 = ev_rows.iter().map(|r| r.count).sum();
    let evidence_distribution: HashMap<String, f64> = if ev_total > 0 {
        ev_rows
            .into_iter()
            .filter_map(|r| {
                r.evidence_type
                    .map(|t| (t, r.count as f64 / ev_total as f64))
            })
            .collect()
    } else {
        HashMap::new()
    };

    // Extract topics from claim labels
    let mut topics: Vec<String> = claims
        .iter()
        .flat_map(|c| c.labels.iter().cloned())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    topics.sort();

    // Time range
    let first = claims.iter().map(|c| c.created_at).min();
    let last = claims.iter().map(|c| c.created_at).max();
    let time_range = first
        .zip(last)
        .map(|(f, l)| TimeRange { first: f, last: l });

    Ok(Json(EpistemicProfileResponse {
        agent_id: id,
        display_name: agent.display_name,
        claim_count,
        evidence_distribution,
        epistemic_status_distribution: status_distribution,
        mean_truth_value: mean_truth,
        refutation_rate,
        topics,
        time_range,
    }))
}

/// GET /api/v1/agents/compare?ids=uuid1,uuid2,uuid3
///
/// Returns epistemic profiles for multiple agents for side-by-side comparison.
#[cfg(feature = "db")]
pub async fn compare_agents(
    State(state): State<AppState>,
    Query(params): Query<CompareAgentsParams>,
) -> Result<Json<Vec<EpistemicProfileResponse>>, ApiError> {
    let ids: Vec<Uuid> = params
        .ids
        .split(',')
        .filter_map(|s| Uuid::parse_str(s.trim()).ok())
        .collect();

    if ids.is_empty() {
        return Err(ApiError::ValidationError {
            field: "ids".to_string(),
            reason: "At least one valid UUID required".to_string(),
        });
    }

    if ids.len() > 10 {
        return Err(ApiError::ValidationError {
            field: "ids".to_string(),
            reason: "Maximum 10 agents for comparison".to_string(),
        });
    }

    let mut profiles = Vec::with_capacity(ids.len());
    for id in ids {
        let agent_id = AgentId::from_uuid(id);
        let pool = &state.db_pool;

        let agent = match AgentRepository::get_by_id(pool, agent_id).await? {
            Some(a) => a,
            None => continue, // Skip missing agents
        };

        let claims = PoliticalRepository::get_agent_profile_claims(pool, id).await?;
        let claim_count = claims.len();

        let (mean_truth, refutation_rate) = if claim_count > 0 {
            let sum: f64 = claims.iter().map(|c| c.truth_value).sum();
            let refuted = claims.iter().filter(|c| c.truth_value < 0.2).count();
            (
                sum / claim_count as f64,
                refuted as f64 / claim_count as f64,
            )
        } else {
            (0.0, 0.0)
        };

        profiles.push(EpistemicProfileResponse {
            agent_id: id,
            display_name: agent.display_name,
            claim_count,
            evidence_distribution: HashMap::new(), // Simplified for comparison
            epistemic_status_distribution: HashMap::new(),
            mean_truth_value: mean_truth,
            refutation_rate,
            topics: vec![],
            time_range: None,
        });
    }

    Ok(Json(profiles))
}

// ── Item 5: Position Timeline ────────────────────────────────────────────

/// GET /api/v1/agents/:id/position-timeline
///
/// Returns a chronological timeline of an agent's positions on a topic,
/// including supersession events and consistency metrics.
#[cfg(feature = "db")]
pub async fn position_timeline(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<PositionTimelineParams>,
) -> Result<Json<PositionTimelineResponse>, ApiError> {
    let agent_id = AgentId::from_uuid(id);
    let pool = &state.db_pool;

    // Verify agent exists
    AgentRepository::get_by_id(pool, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Agent".to_string(),
            id: id.to_string(),
        })?;

    let since = params
        .since
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    let until = params
        .until
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));

    let claims = PoliticalRepository::get_agent_position_timeline(pool, id, since, until).await?;

    // Build timeline entries
    let mut timeline: Vec<TimelineEntry> = claims
        .iter()
        .map(|c| {
            let summary = if c.content.len() > 120 {
                format!("{}...", &c.content[..120])
            } else {
                c.content.clone()
            };
            TimelineEntry {
                date: c.created_at,
                claim_id: c.claim_id,
                content_summary: summary,
                truth_value: c.truth_value,
                supersedes: c.supersedes_id,
            }
        })
        .collect();

    // Identify flip events (where a claim supersedes a prior one)
    let flip_events: Vec<FlipEvent> = timeline
        .iter()
        .filter_map(|entry| {
            entry.supersedes.map(|prior_id| FlipEvent {
                date: entry.date,
                from_claim_id: prior_id,
                to_claim_id: entry.claim_id,
            })
        })
        .collect();

    // Consistency score: fraction of claims that don't supersede anything
    let total = timeline.len();
    let stable = timeline.iter().filter(|e| e.supersedes.is_none()).count();
    let consistency_score = if total > 0 {
        stable as f64 / total as f64
    } else {
        1.0
    };

    // Sort by date
    timeline.sort_by_key(|e| e.date);

    Ok(Json(PositionTimelineResponse {
        agent_id: id,
        topic: params.topic,
        timeline,
        consistency_score,
        flip_events,
    }))
}

// ── Item 8: Talking Point Genealogy ──────────────────────────────────────

/// GET /api/v1/claims/:id/genealogy
///
/// Walks ORIGINATED_BY and AMPLIFIED_BY edges to construct the propagation tree
/// for a claim, identifying the originator and all amplifiers.
#[cfg(feature = "db")]
pub async fn claim_genealogy(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<GenealogyResponse>, ApiError> {
    let pool = &state.db_pool;

    // Verify claim exists
    let claim_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM claims WHERE id = $1)")
            .bind(claim_id)
            .fetch_one(pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("DB check failed: {e}"),
            })?;
    if !claim_exists {
        return Err(ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        });
    }

    let steps = PoliticalRepository::get_claim_genealogy(pool, claim_id).await?;

    // Find origin (ORIGINATED_BY) and amplifiers (AMPLIFIED_BY)
    let origin = steps
        .iter()
        .find(|s| s.relationship == "ORIGINATED_BY")
        .map(|s| {
            let props = &s.properties;
            GenealogyOrigin {
                agent_id: s.agent_id,
                agent_name: s.agent_name.clone(),
                date: props
                    .get("date_asserted")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                venue: props
                    .get("venue")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            }
        });

    let propagation_tree: Vec<PropagationEntry> = steps
        .iter()
        .map(|s| {
            let props = &s.properties;
            PropagationEntry {
                agent_id: s.agent_id,
                agent_name: s.agent_name.clone(),
                relationship: s.relationship.clone(),
                date: props
                    .get("date_asserted")
                    .or_else(|| props.get("date_amplified"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
                venue: props
                    .get("venue")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                reach_estimate: props.get("reach_estimate").and_then(|v| v.as_i64()),
                delta_from_original: props.get("delta_from_original").and_then(|v| v.as_f64()),
                amplification_type: props
                    .get("amplification_type")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            }
        })
        .collect();

    let total_amplifiers = steps
        .iter()
        .filter(|s| s.relationship == "AMPLIFIED_BY")
        .count();

    // Build institutional path from venue types
    let mut institutional_path: Vec<String> = Vec::new();
    for entry in &propagation_tree {
        if let Some(venue) = &entry.venue {
            if !institutional_path.contains(venue) {
                institutional_path.push(venue.clone());
            }
        }
    }

    Ok(Json(GenealogyResponse {
        claim_id,
        origin,
        propagation_tree,
        total_amplifiers,
        institutional_path,
    }))
}

/// GET /api/v1/agents/:id/originated-claims
///
/// Returns claims originated by an agent that were amplified by N+ others.
#[cfg(feature = "db")]
pub async fn originated_claims(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<OriginatedClaimsParams>,
) -> Result<Json<Vec<OriginatedClaimResponse>>, ApiError> {
    let agent_id = AgentId::from_uuid(id);
    let pool = &state.db_pool;

    AgentRepository::get_by_id(pool, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Agent".to_string(),
            id: id.to_string(),
        })?;

    let limit = params.limit.clamp(1, 100);
    let min_amp = params.amplified_by_min.max(0);

    let rows =
        PoliticalRepository::get_originated_claims_with_amplification(pool, id, min_amp, limit)
            .await?;

    let items: Vec<OriginatedClaimResponse> = rows
        .into_iter()
        .map(|(claim_id, content, count)| OriginatedClaimResponse {
            claim_id,
            content,
            amplifier_count: count,
        })
        .collect();

    Ok(Json(items))
}

// ── Item 9: Inflation Index ──────────────────────────────────────────────

/// GET /api/v1/agents/:id/inflation-index
///
/// Returns the monster inflation index for an agent — quantifies systematic
/// exaggeration of threat magnitudes by comparing asserted vs evidenced quantities.
#[cfg(feature = "db")]
pub async fn inflation_index(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(_params): Query<InflationIndexParams>,
) -> Result<Json<InflationIndexResponse>, ApiError> {
    let agent_id = AgentId::from_uuid(id);
    let pool = &state.db_pool;

    AgentRepository::get_by_id(pool, agent_id)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            entity: "Agent".to_string(),
            id: id.to_string(),
        })?;

    let rows = PoliticalRepository::get_agent_inflation_claims(pool, id).await?;

    let sample_claims: Vec<InflationClaimEntry> = rows
        .iter()
        .map(|(claim_id, content, _truth_value, props)| {
            let factor = props
                .get("inflation_factor")
                .and_then(|v| v.as_f64())
                .unwrap_or(1.0);
            let summary = if content.len() > 120 {
                format!("{}...", &content[..120])
            } else {
                content.clone()
            };
            InflationClaimEntry {
                claim_id: *claim_id,
                content_summary: summary,
                inflation_factor: factor,
                asserted_value: props
                    .get("asserted_value")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                evidenced_value: props
                    .get("evidenced_value")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            }
        })
        .collect();

    let overall: Option<f64> = if sample_claims.is_empty() {
        None
    } else {
        let sum: f64 = sample_claims.iter().map(|c| c.inflation_factor).sum();
        Some(sum / sample_claims.len() as f64)
    };

    Ok(Json(InflationIndexResponse {
        agent_id: id,
        overall_inflation_index: overall,
        claim_count: sample_claims.len(),
        sample_claims,
    }))
}

/// GET /api/v1/inflation-index/leaderboard
///
/// Ranked list of agents by mean inflation index (non-partisan metric).
#[cfg(feature = "db")]
pub async fn inflation_leaderboard(
    State(state): State<AppState>,
    Query(_params): Query<InflationIndexParams>,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let pool = &state.db_pool;

    // Query agents who have claims with inflation_factor
    let rows: Vec<(Uuid, Option<String>, f64, i64)> = sqlx::query_as(
        r#"
        SELECT c.agent_id, a.display_name,
               AVG((c.properties->>'inflation_factor')::FLOAT) AS mean_inflation,
               COUNT(*) AS claim_count
        FROM claims c
        JOIN agents a ON a.id = c.agent_id
        WHERE c.properties ? 'inflation_factor'
        GROUP BY c.agent_id, a.display_name
        HAVING COUNT(*) >= 2
        ORDER BY mean_inflation DESC
        LIMIT 20
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("Leaderboard query failed: {e}"),
    })?;

    let items: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(agent_id, name, mean_inflation, count)| {
            serde_json::json!({
                "agent_id": agent_id,
                "display_name": name,
                "mean_inflation_index": mean_inflation,
                "claim_count": count
            })
        })
        .collect();

    Ok(Json(items))
}

// ── Item 3: Propaganda Techniques ────────────────────────────────────────

/// GET /api/v1/propaganda-techniques
#[cfg(feature = "db")]
pub async fn list_techniques(
    State(state): State<AppState>,
    Query(params): Query<TechniqueListParams>,
) -> Result<Json<Vec<TechniqueResponse>>, ApiError> {
    let limit = params.limit.clamp(1, 200);
    let rows =
        PoliticalRepository::list_techniques(&state.db_pool, params.category.as_deref(), limit)
            .await?;

    let items: Vec<TechniqueResponse> = rows
        .into_iter()
        .map(|r| TechniqueResponse {
            id: r.id,
            name: r.name,
            category: r.category,
            description: r.description,
            detection_guidance: r.detection_guidance,
            properties: r.properties,
        })
        .collect();

    Ok(Json(items))
}

/// POST /api/v1/propaganda-techniques
#[cfg(feature = "db")]
pub async fn create_technique(
    State(state): State<AppState>,
    Json(req): Json<CreateTechniqueRequest>,
) -> Result<(StatusCode, Json<TechniqueResponse>), ApiError> {
    if req.name.is_empty() {
        return Err(ApiError::ValidationError {
            field: "name".to_string(),
            reason: "Technique name cannot be empty".to_string(),
        });
    }

    let row = PoliticalRepository::create_technique(
        &state.db_pool,
        &req.name,
        req.category.as_deref(),
        req.description.as_deref(),
        req.detection_guidance.as_deref(),
        req.properties,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(TechniqueResponse {
            id: row.id,
            name: row.name,
            category: row.category,
            description: row.description,
            detection_guidance: row.detection_guidance,
            properties: row.properties,
        }),
    ))
}

/// GET /api/v1/claims/:id/techniques
///
/// Returns propaganda techniques detected on a claim via USES_TECHNIQUE edges.
#[cfg(feature = "db")]
pub async fn claim_techniques(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<Vec<ClaimTechniqueResponse>>, ApiError> {
    let pool = &state.db_pool;

    let rows = PoliticalRepository::get_claim_techniques(pool, claim_id).await?;

    let items: Vec<ClaimTechniqueResponse> = rows
        .into_iter()
        .map(|(tech, edge_props)| ClaimTechniqueResponse {
            technique: TechniqueResponse {
                id: tech.id,
                name: tech.name,
                category: tech.category,
                description: tech.description,
                detection_guidance: tech.detection_guidance,
                properties: tech.properties,
            },
            confidence: edge_props.get("confidence").and_then(|v| v.as_f64()),
            detected_by: edge_props
                .get("detected_by")
                .and_then(|v| v.as_str())
                .map(String::from),
            evidence_text: edge_props
                .get("evidence_text")
                .and_then(|v| v.as_str())
                .map(String::from),
        })
        .collect();

    Ok(Json(items))
}

// ── Item 7: Coalitions ──────────────────────────────────────────────────

/// GET /api/v1/coalitions
#[cfg(feature = "db")]
pub async fn list_coalitions(
    State(state): State<AppState>,
    Query(params): Query<CoalitionListParams>,
) -> Result<Json<Vec<CoalitionResponse>>, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let active = params.active.unwrap_or(false);
    let min_members = params.min_members.unwrap_or(0);

    let rows = PoliticalRepository::list_coalitions(
        &state.db_pool,
        active,
        params.archetype.as_deref(),
        min_members,
        limit,
    )
    .await?;

    let items: Vec<CoalitionResponse> = rows
        .into_iter()
        .map(|r| CoalitionResponse {
            id: r.id,
            name: r.name,
            archetype: r.archetype,
            dominant_antagonist: r.dominant_antagonist,
            cognitive_shape: r.cognitive_shape,
            member_count: r.member_count,
            start_date: r.start_date,
            peak_date: r.peak_date,
            is_active: r.is_active,
            reach_estimate: r.reach_estimate,
            detection_method: r.detection_method,
        })
        .collect();

    Ok(Json(items))
}

/// POST /api/v1/coalitions
#[cfg(feature = "db")]
pub async fn create_coalition(
    State(state): State<AppState>,
    Json(req): Json<CreateCoalitionRequest>,
) -> Result<(StatusCode, Json<CoalitionResponse>), ApiError> {
    let row = PoliticalRepository::create_coalition(
        &state.db_pool,
        req.name.as_deref(),
        req.archetype.as_deref(),
        req.dominant_antagonist.as_deref(),
        req.cognitive_shape.as_deref(),
        &req.detection_method,
        req.properties,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CoalitionResponse {
            id: row.id,
            name: row.name,
            archetype: row.archetype,
            dominant_antagonist: row.dominant_antagonist,
            cognitive_shape: row.cognitive_shape,
            member_count: row.member_count,
            start_date: row.start_date,
            peak_date: row.peak_date,
            is_active: row.is_active,
            reach_estimate: row.reach_estimate,
            detection_method: row.detection_method,
        }),
    ))
}

// ── Item 11: Counter-Narrative Gap Scanner (Stub) ────────────────────────

/// GET /api/v1/counter-narrative-gaps
///
/// Stub endpoint — returns narrative clusters with insufficient counter-narratives.
/// Full implementation requires LLM integration for archetype classification.
#[cfg(feature = "db")]
pub async fn counter_narrative_gaps(
    State(_state): State<AppState>,
    Query(params): Query<CounterNarrativeGapParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({
        "status": "stub",
        "description": "Counter-narrative gap scanner — requires LLM archetype classification (Item 11)",
        "filter": {
            "min_coalition_size": params.min_coalition_size,
            "max_readiness": params.max_readiness
        },
        "gaps": []
    })))
}

// ── Item 12: Mirror Narrative Detection (Stub) ───────────────────────────

/// GET /api/v1/mirror-narratives
///
/// Stub endpoint — returns pairs of narrative coalitions that are structural mirrors.
/// Full implementation requires archetype similarity + semantic opposition scoring.
#[cfg(feature = "db")]
pub async fn mirror_narratives(
    State(_state): State<AppState>,
    Query(params): Query<MirrorNarrativeParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({
        "status": "stub",
        "description": "Mirror narrative detection — requires archetype similarity + antagonist opposition scoring (Item 12)",
        "filter": {
            "active": params.active.unwrap_or(false)
        },
        "mirrors": []
    })))
}

// =============================================================================
// NON-DB STUBS
// =============================================================================

#[cfg(not(feature = "db"))]
pub async fn epistemic_profile(
    Path(_id): Path<Uuid>,
    Query(_params): Query<EpistemicProfileParams>,
) -> Result<Json<EpistemicProfileResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Epistemic profile requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn compare_agents(
    Query(_params): Query<CompareAgentsParams>,
) -> Result<Json<Vec<EpistemicProfileResponse>>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Agent comparison requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn position_timeline(
    Path(_id): Path<Uuid>,
    Query(_params): Query<PositionTimelineParams>,
) -> Result<Json<PositionTimelineResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Position timeline requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn claim_genealogy(
    Path(_claim_id): Path<Uuid>,
) -> Result<Json<GenealogyResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Genealogy requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn originated_claims(
    Path(_id): Path<Uuid>,
    Query(_params): Query<OriginatedClaimsParams>,
) -> Result<Json<Vec<OriginatedClaimResponse>>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Originated claims requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn inflation_index(
    Path(_id): Path<Uuid>,
    Query(_params): Query<InflationIndexParams>,
) -> Result<Json<InflationIndexResponse>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Inflation index requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn inflation_leaderboard(
    Query(_params): Query<InflationIndexParams>,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Inflation leaderboard requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn list_techniques(
    Query(_params): Query<TechniqueListParams>,
) -> Result<Json<Vec<TechniqueResponse>>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Propaganda techniques requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn create_technique(
    Json(_req): Json<CreateTechniqueRequest>,
) -> Result<(StatusCode, Json<TechniqueResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Propaganda techniques requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn claim_techniques(
    Path(_claim_id): Path<Uuid>,
) -> Result<Json<Vec<ClaimTechniqueResponse>>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Claim techniques requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn list_coalitions(
    Query(_params): Query<CoalitionListParams>,
) -> Result<Json<Vec<CoalitionResponse>>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Coalitions requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn create_coalition(
    Json(_req): Json<CreateCoalitionRequest>,
) -> Result<(StatusCode, Json<CoalitionResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Coalitions requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn counter_narrative_gaps(
    Query(_params): Query<CounterNarrativeGapParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Counter-narrative gaps requires database".to_string(),
    })
}

#[cfg(not(feature = "db"))]
pub async fn mirror_narratives(
    Query(_params): Query<MirrorNarrativeParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Err(ApiError::ServiceUnavailable {
        service: "Mirror narratives requires database".to_string(),
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn technique_response_serializes() {
        let resp = TechniqueResponse {
            id: Uuid::nil(),
            name: "Appeal to Fear".to_string(),
            category: Some("emotional_appeal".to_string()),
            description: Some("Uses fear to persuade".to_string()),
            detection_guidance: None,
            properties: serde_json::json!({}),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "Appeal to Fear");
        assert_eq!(json["category"], "emotional_appeal");
    }

    #[test]
    fn coalition_response_serializes() {
        let resp = CoalitionResponse {
            id: Uuid::nil(),
            name: Some("Test Coalition".to_string()),
            archetype: Some("overcoming_the_monster".to_string()),
            dominant_antagonist: Some("immigration".to_string()),
            cognitive_shape: Some("man_in_hole".to_string()),
            member_count: 5,
            start_date: None,
            peak_date: None,
            is_active: true,
            reach_estimate: Some(100_000),
            detection_method: "embedding+time".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["archetype"], "overcoming_the_monster");
        assert_eq!(json["member_count"], 5);
    }

    #[test]
    fn genealogy_response_serializes() {
        let resp = GenealogyResponse {
            claim_id: Uuid::nil(),
            origin: Some(GenealogyOrigin {
                agent_id: Uuid::nil(),
                agent_name: Some("Heritage Foundation".to_string()),
                date: Some("2025-01-15".to_string()),
                venue: Some("policy_paper".to_string()),
            }),
            propagation_tree: vec![PropagationEntry {
                agent_id: Uuid::nil(),
                agent_name: Some("Heritage Foundation".to_string()),
                relationship: "ORIGINATED_BY".to_string(),
                date: Some("2025-01-15".to_string()),
                venue: Some("policy_paper".to_string()),
                reach_estimate: Some(15000),
                delta_from_original: None,
                amplification_type: None,
            }],
            total_amplifiers: 0,
            institutional_path: vec!["policy_paper".to_string()],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["origin"]["agent_name"]
            .as_str()
            .unwrap()
            .contains("Heritage"));
        assert_eq!(json["total_amplifiers"], 0);
    }

    #[test]
    fn inflation_index_response_serializes() {
        let resp = InflationIndexResponse {
            agent_id: Uuid::nil(),
            overall_inflation_index: Some(7.4),
            claim_count: 3,
            sample_claims: vec![InflationClaimEntry {
                claim_id: Uuid::nil(),
                content_summary: "32,000 protesters".to_string(),
                inflation_factor: 8.2,
                asserted_value: Some("32000".to_string()),
                evidenced_value: Some("3117-7000".to_string()),
            }],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["overall_inflation_index"], 7.4);
        assert_eq!(json["sample_claims"][0]["inflation_factor"], 8.2);
    }

    #[test]
    fn epistemic_profile_response_serializes() {
        let mut evidence_dist = HashMap::new();
        evidence_dist.insert("testimonial".to_string(), 1.0);

        let resp = EpistemicProfileResponse {
            agent_id: Uuid::nil(),
            display_name: Some("Test Agent".to_string()),
            claim_count: 6,
            evidence_distribution: evidence_dist,
            epistemic_status_distribution: HashMap::new(),
            mean_truth_value: 0.226,
            refutation_rate: 0.833,
            topics: vec!["Iran".to_string()],
            time_range: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["claim_count"], 6);
        assert_eq!(json["evidence_distribution"]["testimonial"], 1.0);
    }

    #[test]
    fn position_timeline_response_serializes() {
        let resp = PositionTimelineResponse {
            agent_id: Uuid::nil(),
            topic: Some("immigration".to_string()),
            timeline: vec![],
            consistency_score: 0.42,
            flip_events: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["consistency_score"], 0.42);
        assert_eq!(json["topic"], "immigration");
    }
}
