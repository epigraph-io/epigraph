//! `GET /api/v1/claims/:id/ego` — the hydrated, degree-capped depth-1
//! neighbourhood of a claim (plan §2.2).
//!
//! The claim page's outlink list and the graph canvas both read this one
//! route. It replaces `GET /claims/:id/neighborhood` + one `GET /claims/:id`
//! per neighbour for that job: the N+1 runs against a 10-connection pool with
//! no statement timeout, and `claim_neighborhood`'s 500-edge cut collects
//! outgoing rows first, so a claim with many outlinks loses every backlink.
//!
//! Redaction follows `claim_neighborhood`: an edge touching a redacted
//! *neighbour* claim is dropped along with that neighbour, because a raw
//! `claim_id` plus a relationship name already says more than a redacted node
//! should. A redacted *centre* answers with the centre alone.
//!
//! All SQL lives in `epigraph_db::EgoRepository`.

use std::collections::{HashMap, HashSet};

use axum::{
    extract::{Path, Query, State},
    Json,
};
use epigraph_db::{EgoEntity, EgoRepository};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::access_control::{batch_content_access, ContentAccess};
use crate::errors::ApiError;
use crate::state::AppState;

const DEFAULT_MAX_DEGREE: u32 = 40;
const MIN_MAX_DEGREE: u32 = 1;
const MAX_MAX_DEGREE: u32 = 200;

/// Longest `label` this route emits. Counted in characters and cut on a char
/// boundary — the same rule `load_subgraph` uses, at the length the graph
/// canvas renders.
const MAX_LABEL_CHARS: usize = 160;

#[derive(Debug, Deserialize)]
pub struct EgoQuery {
    /// `u32` rather than `u8`/`u16` so an out-of-range value is clamped here
    /// instead of rejected by axum as a plain-text 400.
    #[serde(default)]
    pub max_degree: Option<u32>,
    /// Comma-separated relationship names, matched case-insensitively. Absent
    /// or empty means every relationship.
    #[serde(default)]
    pub relationships: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EgoNode {
    pub id: Uuid,
    pub entity_type: String,
    pub label: String,
    pub redacted: bool,
    // Claim-only fields. Omitted, not null, for other entity types — the
    // convention every other read route here follows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truth_value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pignistic_prob: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_current: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct EgoEdge {
    pub id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub source_type: String,
    pub target_type: String,
    pub relationship: String,
    /// Relative to the centre: `"out"` when the centre is the edge's source.
    pub direction: &'static str,
}

#[derive(Debug, Serialize)]
pub struct EgoResponse {
    pub center: EgoNode,
    pub nodes: Vec<EgoNode>,
    pub edges: Vec<EgoEdge>,
    /// Every depth-1 edge matching the relationship filter, before the degree
    /// cap. This is the claim's degree, not the size of `edges`.
    pub total_edges: i64,
    /// `true` when the degree cap cut the edge set.
    pub truncated: bool,
}

/// Cut `label` to [`MAX_LABEL_CHARS`] characters, never mid-character.
fn clip_label(label: &str) -> String {
    if label.chars().count() <= MAX_LABEL_CHARS {
        return label.to_string();
    }
    let head: String = label.chars().take(MAX_LABEL_CHARS - 3).collect();
    format!("{head}...")
}

fn parse_relationships(raw: Option<&str>) -> Option<Vec<String>> {
    let names: Vec<String> = raw?
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

/// Build the wire node for a hydrated entity, applying redaction.
fn to_node(entity: EgoEntity, redacted: bool) -> EgoNode {
    let is_claim = entity.entity_type == "claim";
    let content = entity.content.map(|c| {
        if redacted {
            let mut c = c;
            crate::access_control::redact_claim_content(&mut c);
            c
        } else {
            c
        }
    });
    // A claim's label IS its content, so it has to be rebuilt from the
    // redacted text rather than the row's.
    let label = match (is_claim, content.as_deref()) {
        (true, Some(text)) => clip_label(text),
        _ => clip_label(&entity.label),
    };
    EgoNode {
        id: entity.id,
        entity_type: entity.entity_type,
        label,
        redacted,
        content,
        truth_value: entity.truth_value,
        pignistic_prob: entity.pignistic_prob,
        labels: entity.labels,
        is_current: entity.is_current,
    }
}

/// A neighbour that no entity table knows about: the edge still declares its
/// type, so it is rendered as a bare typed node rather than dropped.
fn unhydrated_node(id: Uuid, entity_type: &str) -> EgoNode {
    EgoNode {
        id,
        entity_type: entity_type.to_string(),
        label: entity_type.to_string(),
        redacted: false,
        content: None,
        truth_value: None,
        pignistic_prob: None,
        labels: None,
        is_current: None,
    }
}

/// `GET /api/v1/claims/:id/ego`
pub async fn claim_ego(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<EgoQuery>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
) -> Result<Json<EgoResponse>, ApiError> {
    let pool = &state.db_pool;

    // SECURITY: requester from the validated bearer only; no `agent_id`
    // parameter exists on this route because it would be spoofable.
    let requester = auth_ctx
        .as_ref()
        .and_then(|axum::Extension(ctx)| ctx.agent_id.or(Some(ctx.client_id)));

    let max_degree = params
        .max_degree
        .unwrap_or(DEFAULT_MAX_DEGREE)
        .clamp(MIN_MAX_DEGREE, MAX_MAX_DEGREE) as usize;
    let relationships = parse_relationships(params.relationships.as_deref());

    let center_rows = EgoRepository::hydrate(pool, &[claim_id]).await?;
    let center_entity = center_rows
        .into_iter()
        .find(|e| e.entity_type == "claim")
        .ok_or_else(|| ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        })?;

    let center_redacted = batch_content_access(pool, &[claim_id], requester)
        .await
        .get(&claim_id)
        .copied()
        .unwrap_or(ContentAccess::Redacted)
        == ContentAccess::Redacted;

    if center_redacted {
        // Not even the degree is reported: `total_edges` would leak how much
        // of the graph hangs off a claim the caller cannot read.
        return Ok(Json(EgoResponse {
            center: to_node(center_entity, true),
            nodes: Vec::new(),
            edges: Vec::new(),
            total_edges: 0,
            truncated: false,
        }));
    }

    let fetched =
        EgoRepository::edges(pool, claim_id, max_degree, relationships.as_deref()).await?;

    // Neighbour id → the entity type the edge declares for it.
    let mut declared_type: HashMap<Uuid, String> = HashMap::new();
    let mut edges: Vec<EgoEdge> = Vec::new();
    for row in &fetched.outbound {
        declared_type.insert(row.target_id, row.target_type.clone());
        edges.push(EgoEdge {
            id: row.id,
            source_id: row.source_id,
            target_id: row.target_id,
            source_type: row.source_type.clone(),
            target_type: row.target_type.clone(),
            relationship: row.relationship.clone(),
            direction: "out",
        });
    }
    for row in &fetched.inbound {
        declared_type.insert(row.source_id, row.source_type.clone());
        edges.push(EgoEdge {
            id: row.id,
            source_id: row.source_id,
            target_id: row.target_id,
            source_type: row.source_type.clone(),
            target_type: row.target_type.clone(),
            relationship: row.relationship.clone(),
            direction: "in",
        });
    }
    declared_type.remove(&claim_id);

    let neighbour_ids: Vec<Uuid> = declared_type.keys().copied().collect();
    let hydrated = EgoRepository::hydrate(pool, &neighbour_ids).await?;

    // Only claim neighbours can be redacted; the batch check is scoped to them
    // so a large agent/evidence fan-out costs nothing extra.
    let claim_neighbour_ids: Vec<Uuid> = hydrated
        .iter()
        .filter(|e| e.entity_type == "claim")
        .map(|e| e.id)
        .collect();
    let access = batch_content_access(pool, &claim_neighbour_ids, requester).await;

    let mut nodes: Vec<EgoNode> = Vec::new();
    let mut hidden: HashSet<Uuid> = HashSet::new();
    let mut seen: HashSet<Uuid> = HashSet::new();
    for entity in hydrated {
        if entity.entity_type == "claim"
            && access
                .get(&entity.id)
                .copied()
                .unwrap_or(ContentAccess::Redacted)
                == ContentAccess::Redacted
        {
            hidden.insert(entity.id);
            continue;
        }
        // An id can exist in more than one table (a uuid collision across
        // entity tables); keep the first hydration, matching the edge's
        // declared type where they agree.
        if seen.insert(entity.id) {
            nodes.push(to_node(entity, false));
        }
    }
    for (id, entity_type) in &declared_type {
        if !seen.contains(id) && !hidden.contains(id) {
            nodes.push(unhydrated_node(*id, entity_type));
        }
    }

    edges.retain(|e| !hidden.contains(&e.source_id) && !hidden.contains(&e.target_id));

    Ok(Json(EgoResponse {
        center: to_node(center_entity, false),
        nodes,
        edges,
        total_edges: fetched.total_edges,
        truncated: fetched.truncated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_labels_are_untouched() {
        assert_eq!(clip_label("a short claim"), "a short claim");
        let exact = "x".repeat(MAX_LABEL_CHARS);
        assert_eq!(clip_label(&exact), exact);
    }

    #[test]
    fn long_labels_are_cut_on_a_char_boundary() {
        // Multi-byte throughout: a byte-slice at 157 would land mid-character
        // and panic.
        let long = "é".repeat(MAX_LABEL_CHARS + 10);
        let clipped = clip_label(&long);
        assert_eq!(clipped.chars().count(), MAX_LABEL_CHARS);
        assert!(clipped.ends_with("..."));
    }

    #[test]
    fn relationship_filter_is_none_when_blank() {
        assert_eq!(parse_relationships(None), None);
        assert_eq!(parse_relationships(Some("")), None);
        assert_eq!(
            parse_relationships(Some("supports, REFUTES")),
            Some(vec!["supports".to_string(), "REFUTES".to_string()])
        );
    }
}
