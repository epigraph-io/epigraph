//! `GET /api/v1/claims/:id/ego` — the hydrated, degree-capped depth-1
//! neighbourhood of a claim (plan §2.2).
//!
//! The claim page's outlink list and the graph canvas both read this one
//! route. It replaces `GET /claims/:id/neighborhood` + one `GET /claims/:id`
//! per neighbour for that job: the N+1 runs against a 10-connection pool with
//! no statement timeout, and `claim_neighborhood`'s 500-edge cut collects
//! outgoing rows first, so a claim with many outlinks loses every backlink.
//!
//! # What a viewer cannot see is absent
//!
//! A centre claim the viewer may not read is a 404, byte-identical to the 404
//! for a uuid that names nothing — not a centre-only body with a zeroed degree,
//! which confirmed the claim existed.
//!
//! A *neighbour* the viewer may not read is simply not in `nodes`, and the edge
//! that pointed at it is dropped with it. That rule is unchanged from the
//! redaction era; only its trigger is. A raw `claim_id` plus a relationship
//! name already says more than an absent node should — it says a claim exists,
//! that it stands in this relation to the centre, and which relation. The
//! trigger is now "not in the hydrated set" rather than "redacted", which also
//! covers the id that matches no row in any entity table.
//!
//! `total_edges` needs no correction here. `EgoRepository::edges` counts the
//! degree inside the same viewer predicate that produces the edge rows, so the
//! number is the visible degree by construction rather than the true degree
//! minus whatever this handler happened to drop. `truncated` stays cap-only, so
//! the pair says "the cap cut the list" and never "there is more you cannot
//! see".
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
    /// Every depth-1 edge matching the relationship filter that this viewer
    /// may see, before the degree cap. Counted in the database inside the
    /// viewer predicate, so it is not the claim's raw degree — that number
    /// would state exactly how many neighbours the viewer is not allowed to
    /// know about. Not the size of `edges` either: that is additionally cut by
    /// the cap.
    pub total_edges: i64,
    /// `true` when the degree cap cut the edge set — never when tenancy did.
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
/// Every entity reaching this function came back from a viewer-filtered read,
/// so there is no second, blanked spelling of a node to build — a claim's
/// `label` is simply its content, clipped.
fn to_node(entity: EgoEntity) -> EgoNode {
    let is_claim = entity.entity_type == "claim";
    let label = match (is_claim, entity.content.as_deref()) {
        (true, Some(text)) => clip_label(text),
        _ => clip_label(&entity.label),
    };
    EgoNode {
        id: entity.id,
        entity_type: entity.entity_type,
        label,
        content: entity.content,
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
    let max_degree = params
        .max_degree
        .unwrap_or(DEFAULT_MAX_DEGREE)
        .clamp(MIN_MAX_DEGREE, MAX_MAX_DEGREE) as usize;
    let relationships = parse_relationships(params.relationships.as_deref());

    // One viewer-stamped connection for all four statements, so the centre
    // check, the degree count and the neighbour hydration describe the same
    // corpus.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "claim_ego",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let Some(center_entity) = EgoRepository::center(&mut read, &viewer, claim_id).await? else {
        return Err(ApiError::NotFound {
            entity: "Claim".to_string(),
            id: claim_id.to_string(),
        });
    };

    let fetched = EgoRepository::edges(
        &mut read,
        &viewer,
        claim_id,
        max_degree,
        relationships.as_deref(),
    )
    .await?;

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
    let hydrated = EgoRepository::hydrate(&mut read, &viewer, &neighbour_ids).await?;

    crate::routes::finish_scoped_read(read, "claim_ego").await?;

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
    // A declared neighbour that hydration did not return is either an id no
    // entity table knows about or a claim this viewer may not read, and this
    // handler cannot tell the two apart — by design, since telling them apart
    // IS the existence oracle. Only ids whose declared type is not `claim` are
    // emitted as bare typed nodes; a `claim` that did not hydrate is dropped,
    // and the loop below drops its edges with it.
    for (id, entity_type) in &declared_type {
        if !seen.contains(id) && entity_type != "claim" {
            nodes.push(unhydrated_node(*id, entity_type));
            seen.insert(*id);
        }
    }

    // An edge to a node that is not in `nodes` is dropped. `total_edges` is
    // untouched: the repo already counted only the edges whose far endpoint
    // this viewer may see, so it needs no correction here, and correcting it
    // twice would under-report.
    let kept_ids: HashSet<Uuid> = nodes
        .iter()
        .map(|n| n.id)
        .chain(std::iter::once(claim_id))
        .collect();
    edges.retain(|e| kept_ids.contains(&e.source_id) && kept_ids.contains(&e.target_id));

    Ok(Json(EgoResponse {
        center: to_node(center_entity),
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
