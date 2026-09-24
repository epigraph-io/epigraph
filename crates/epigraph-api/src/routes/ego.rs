//! `GET /api/v1/claims/:id/ego` — the hydrated, degree-capped depth-1
//! neighbourhood of a claim (plan §2.2).
//!
//! The claim page's outlink list and the graph canvas both read this one
//! route. It replaces `GET /claims/:id/neighborhood` + one `GET /claims/:id`
//! per neighbour for that job: the N+1 runs against a 10-connection pool with
//! no statement timeout, and `claim_neighborhood`'s 500-edge cut collects
//! outgoing rows first, so a claim with many outlinks loses every backlink.
//!
//! Visibility follows `claim_neighborhood`: an edge touching a neighbour claim
//! this viewer may not read is dropped along with that neighbour, because a raw
//! `claim_id` plus a relationship name already says more than a hidden node
//! should. An unreadable *centre* is reported as absent (404), identically to a
//! claim that does not exist — it is not answered with a blanked centre, which
//! would confirm the claim is there. The filtering happens in
//! `EgoRepository::hydrate`'s SQL, not in a post-pass over rows already read.
//!
//! `total_edges` is redaction-aware: `EgoRepository` counts the degree in the
//! database, and this route subtracts the edges it then dropped for redaction
//! before serialising. `truncated` stays cap-only, so the pair says "the cap
//! cut the list, and this is how much of it you are allowed to know about"
//! rather than handing a stranger the exact size of the part they cannot see.
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

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
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
    /// Every depth-1 edge matching the relationship filter that this requester
    /// may see, before the degree cap: the database count minus the edges
    /// redaction dropped. Not the size of `edges` — that is additionally cut
    /// by the cap — and deliberately not the raw degree, which would disclose
    /// the number of hidden neighbours.
    pub total_edges: i64,
    /// `true` when the degree cap cut the edge set — never when redaction did.
    /// A client may therefore read this as "there is more to see", which is
    /// what the Explorer's "connection limit cut the list" notice does.
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

/// Build the wire node for a hydrated entity.
///
/// No redaction arm: every entity reaching here came back from a viewer-filtered
/// `EgoRepository::hydrate`, so its content is content this viewer may read. The
/// `redacted` field stays on the wire, always `false`, so the response shape does
/// not change for existing clients.
fn to_node(entity: EgoEntity) -> EgoNode {
    let is_claim = entity.entity_type == "claim";
    let content = entity.content;
    // A claim's label IS its content, so prefer the hydrated text over the row's
    // provisional label.
    let label = match (is_claim, content.as_deref()) {
        (true, Some(text)) => clip_label(text),
        _ => clip_label(&entity.label),
    };
    EgoNode {
        id: entity.id,
        entity_type: entity.entity_type,
        label,
        redacted: false,
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
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
    Query(params): Query<EgoQuery>,
) -> Result<Json<EgoResponse>, ApiError> {
    let pool = &state.db_pool;

    let max_degree = params
        .max_degree
        .unwrap_or(DEFAULT_MAX_DEGREE)
        .clamp(MIN_MAX_DEGREE, MAX_MAX_DEGREE) as usize;
    let relationships = parse_relationships(params.relationships.as_deref());

    let center_rows = EgoRepository::hydrate(pool, &viewer, &[claim_id]).await?;
    let center_entity = center_rows
        .into_iter()
        .find(|e| e.entity_type == "claim")
        .ok_or_else(|| ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        })?;

    // No explicit centre check any more: `hydrate` is read through the viewer,
    // so a claim this caller may not read produced no row above and the
    // `NotFound` already fired — absent, not blanked. The old spelling answered
    // with a redacted centre and an empty graph, which still confirmed the claim
    // existed.

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
    let hydrated = EgoRepository::hydrate(pool, &viewer, &neighbour_ids).await?;

    // A neighbour the viewer may not read is now missing from `hydrated`
    // entirely, because the filtering moved into `hydrate`'s SQL. Its id is still
    // in `declared_type` though — the edge walk put it there — so without this it
    // would fall through to `unhydrated_node` below and be rendered as a bare
    // typed node, which discloses both that the claim exists and how it relates
    // to the centre. Only ids the EDGE declares as claims are treated this way;
    // an evidence or frame id legitimately has no hydration and must still
    // render.
    let hydrated_ids: HashSet<Uuid> = hydrated.iter().map(|e| e.id).collect();
    let hidden: HashSet<Uuid> = declared_type
        .iter()
        .filter(|(id, ty)| ty.as_str() == "claim" && !hydrated_ids.contains(id))
        .map(|(id, _)| *id)
        .collect();

    let mut nodes: Vec<EgoNode> = Vec::new();
    let mut seen: HashSet<Uuid> = HashSet::new();
    for entity in hydrated {
        // An id can exist in more than one table (a uuid collision across
        // entity tables); keep the first hydration, matching the edge's
        // declared type where they agree.
        if seen.insert(entity.id) {
            nodes.push(to_node(entity));
        }
    }
    for (id, entity_type) in &declared_type {
        if !seen.contains(id) && !hidden.contains(id) {
            nodes.push(unhydrated_node(*id, entity_type));
        }
    }

    let before_redaction = edges.len();
    edges.retain(|e| !hidden.contains(&e.source_id) && !hidden.contains(&e.target_id));
    let dropped_for_redaction = (before_redaction - edges.len()) as i64;

    // The repo counts the degree in the database, before redaction. Serialising
    // that raw would tell the viewer exactly how many neighbours they may not
    // see — the metadata leak this handler already refuses to make for a
    // redacted *centre*. Subtracting what redaction dropped makes the two
    // consistent: with no cap in play the count is exactly `edges.len()`, and
    // `truncated` is left alone so it still means the degree cap and only the
    // degree cap. `saturating_sub` cannot fire (dropped ≤ kept ≤ total) and is
    // there so a future counting change degrades to 0 rather than a negative
    // degree.
    let total_edges = fetched.total_edges.saturating_sub(dropped_for_redaction);

    Ok(Json(EgoResponse {
        center: to_node(center_entity),
        nodes,
        edges,
        total_edges,
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
