//! GET /api/v1/claims/:id/cross_source_matches (T20).
//!
//! Returns two arrays for the given claim:
//! - `corroborates`: claim→claim edges with relationship `CORROBORATES`, either
//!   direction.
//! - `pending`: `match_candidates` rows in `status = 'pending'`. Promoted /
//!   rejected rows are intentionally omitted — the UI surface for those is
//!   either the CORROBORATES edge itself or admin tooling.
//!
//! POST /api/v1/match_candidates/:id/decide takes `promote`, `reject` and
//! `retire`. `retire` is the undo of a promotion — the only verdict that
//! accepts an already-decided row (see `decide_candidate`).
//!
//! KNOWN GAP: `corroborates` is the only edge array, so a pair promoted as a
//! *contradiction* (see `decide_candidate`) leaves `pending` without appearing
//! anywhere in this response. Surfacing contradictions needs a response-shape
//! change; tracked separately.
//!
//! 404 when the claim doesn't exist. 200 with empty arrays when it exists
//! but has no matches.

use axum::extract::Query;
use axum::{
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use std::collections::HashMap;
use uuid::Uuid;

use crate::{errors::ApiError, state::AppState};

// Cross-source matches reads two tables (edges, match_candidates) via raw
// sqlx. Local helpers fold sqlx errors into ApiError::DatabaseError so the
// existing DbError → ApiError bridge isn't bypassed silently.
fn map_sqlx<T>(r: Result<T, sqlx::Error>) -> Result<T, ApiError> {
    r.map_err(|e| ApiError::DatabaseError {
        message: e.to_string(),
    })
}

#[derive(Serialize)]
pub struct CorroboratesEdge {
    pub edge_id: String,
    pub source_id: String,
    pub target_id: String,
    pub properties: serde_json::Value,
}

#[derive(Serialize)]
pub struct PendingCandidate {
    pub id: String,
    pub claim_a: String,
    pub claim_b: String,
    pub score: f32,
    pub features: serde_json::Value,
    pub verifier_verdict: Option<String>,
    pub verifier_rationale: Option<String>,
    pub matcher_run_id: Option<String>,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct CrossSourceMatchesResponse {
    pub claim_id: String,
    pub corroborates: Vec<CorroboratesEdge>,
    pub pending: Vec<PendingCandidate>,
}

#[cfg(feature = "db")]
pub async fn get_cross_source_matches(
    State(state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<CrossSourceMatchesResponse>, ApiError> {
    // 404 if the claim doesn't exist. Using count(*) so we don't pay for the
    // full row hydration we'd get from ClaimRepository::get_by_id.
    let exists: (i64,) = map_sqlx(
        sqlx::query_as("SELECT COUNT(*)::bigint FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&state.db_pool)
            .await,
    )?;
    if exists.0 == 0 {
        return Err(ApiError::NotFound {
            entity: "claim".to_string(),
            id: claim_id.to_string(),
        });
    }

    let edge_rows: Vec<(Uuid, Uuid, Uuid, serde_json::Value)> = map_sqlx(
        sqlx::query_as(
            "SELECT id, source_id, target_id, properties FROM edges
             WHERE relationship = 'CORROBORATES'
               AND (source_id = $1 OR target_id = $1)",
        )
        .bind(claim_id)
        .fetch_all(&state.db_pool)
        .await,
    )?;
    let corroborates: Vec<CorroboratesEdge> = edge_rows
        .into_iter()
        .map(|(id, src, tgt, properties)| CorroboratesEdge {
            edge_id: id.to_string(),
            source_id: src.to_string(),
            target_id: tgt.to_string(),
            properties,
        })
        .collect();

    let repo = epigraph_db::MatchCandidateRepo::new(state.db_pool.clone());
    let candidate_rows = map_sqlx(repo.list_for_claim(claim_id).await)?;
    let pending: Vec<PendingCandidate> = candidate_rows
        .into_iter()
        .filter(|r| r.status == "pending")
        .map(|r| PendingCandidate {
            id: r.id.to_string(),
            claim_a: r.claim_a.to_string(),
            claim_b: r.claim_b.to_string(),
            score: r.score,
            features: r.features,
            verifier_verdict: r.verifier_verdict,
            verifier_rationale: r.verifier_rationale,
            matcher_run_id: r.matcher_run_id.map(|u| u.to_string()),
            created_at: r.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(CrossSourceMatchesResponse {
        claim_id: claim_id.to_string(),
        corroborates,
        pending,
    }))
}

#[cfg(not(feature = "db"))]
pub async fn get_cross_source_matches(
    State(_state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<CrossSourceMatchesResponse>, ApiError> {
    Ok(Json(CrossSourceMatchesResponse {
        claim_id: claim_id.to_string(),
        corroborates: Vec::new(),
        pending: Vec::new(),
    }))
}

#[derive(serde::Deserialize)]
pub struct ListCandidatesQuery {
    pub status: Option<String>,
    pub limit: i64,
}

#[derive(Serialize)]
pub struct PendingCandidateOut {
    pub id: String,
    pub claim_a: String,
    pub claim_a_excerpt: String,
    pub claim_b: String,
    pub claim_b_excerpt: String,
    pub score: f32,
    pub verifier_verdict: Option<String>,
    pub verifier_rationale: Option<String>,
    pub created_at: String,
}

fn excerpt(content: Option<&String>) -> String {
    match content {
        Some(c) => {
            let trimmed: String = c.chars().take(200).collect();
            if c.chars().count() > 200 {
                format!("{trimmed}…")
            } else {
                trimmed
            }
        }
        None => "(claim not found)".to_string(),
    }
}

/// Lists cross-source match candidates, including verbatim content excerpts of
/// both claims in each pair.
///
/// Fails closed on its own rather than trusting router placement: the
/// `#[cfg(feature = "db")]` router puts this path in the protected chain, but
/// the `#[cfg(not(feature = "db"))]` router registers the same path under
/// `public`. Guarding here means the handler cannot leak claim content if it is
/// ever re-placed in a public chain. `claims:read` matches the MCP twin of this
/// operation (`list_match_candidates` in `epigraph-mcp/src/scope_map.rs`);
/// the sibling `decide_candidate` requires `claims:write`, as does its MCP twin.
#[cfg(feature = "db")]
pub async fn list_candidates(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Query(q): Query<ListCandidatesQuery>,
) -> Result<Json<Vec<PendingCandidateOut>>, ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "list_candidates requires authentication".into(),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:read"])?;

    let status_ref = match q.status.as_deref() {
        Some(s @ ("pending" | "promoted" | "rejected" | "stale")) => Some(s),
        Some(other) => {
            return Err(ApiError::BadRequest {
                message: format!(
                    "status must be one of pending|promoted|rejected|stale, got {other}"
                ),
            });
        }
        None => None,
    };

    let repo = epigraph_db::MatchCandidateRepo::new(state.db_pool.clone());
    let rows = map_sqlx(repo.list(status_ref, q.limit).await)?;

    let mut claim_ids: Vec<Uuid> = Vec::with_capacity(rows.len() * 2);
    for r in &rows {
        claim_ids.push(r.claim_a);
        claim_ids.push(r.claim_b);
    }
    claim_ids.sort_unstable();
    claim_ids.dedup();

    let content_rows: Vec<(Uuid, String)> = map_sqlx(
        sqlx::query_as("SELECT id, content FROM claims WHERE id = ANY($1)")
            .bind(&claim_ids)
            .fetch_all(&state.db_pool)
            .await,
    )?;
    let content_by_id: HashMap<Uuid, String> = content_rows.into_iter().collect();

    let out = rows
        .into_iter()
        .map(|r| PendingCandidateOut {
            id: r.id.to_string(),
            claim_a_excerpt: excerpt(content_by_id.get(&r.claim_a)),
            claim_a: r.claim_a.to_string(),
            claim_b_excerpt: excerpt(content_by_id.get(&r.claim_b)),
            claim_b: r.claim_b.to_string(),
            score: r.score,
            verifier_verdict: r.verifier_verdict,
            verifier_rationale: r.verifier_rationale,
            created_at: r.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(out))
}

#[cfg(not(feature = "db"))]
pub async fn list_candidates(
    State(_state): State<AppState>,
    Query(_q): Query<ListCandidatesQuery>,
) -> Result<Json<Vec<PendingCandidateOut>>, ApiError> {
    Ok(Json(Vec::new()))
}

#[derive(serde::Deserialize)]
pub struct DecideCandidateRequest {
    pub verdict: String,
}

#[cfg(feature = "db")]
pub async fn decide_candidate(
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Path(id): Path<Uuid>,
    Json(req): Json<DecideCandidateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth_ctx
        .ok_or(ApiError::Unauthorized {
            reason: "decide_candidate requires authentication".into(),
        })?
        .0;
    // Scope is per-VERDICT, not per-route, because this one entry point covers
    // two different kinds of act:
    //   promote / reject  — ADDITIVE. They record a decision and, for promote,
    //                       create an edge. `claims:write`, same as filing a
    //                       challenge.
    //   retire            — AUTHORITATIVE. It withdraws an assertion someone
    //                       else made: it retracts the edge and deletes the
    //                       derived factors, bp_messages and BBAs. That is the
    //                       same class of act as supersession, so it takes
    //                       `claims:admin`, matching the peer routes
    //                       (crud::promote_staged_edges, versioning::
    //                       mark_duplicate, conflicts, policies).
    // A single route-wide `claims:write` would let any writer withdraw another
    // principal's assertion, and 50 of 825 production oauth_clients hold
    // `claims:write`.
    let required: &[&str] = if req.verdict.eq_ignore_ascii_case("retire") {
        &["claims:admin"]
    } else {
        &["claims:write"]
    };
    crate::middleware::scopes::check_scopes(&auth, required)?;

    // Decision provenance: prefer agent_id, fall back to client_id (sub).
    //
    // OAuth *service* clients — notably the Telegram approval bridge — are
    // created with `agent_id = NULL` (see `oauth/register.rs`) and nothing ever
    // links one, so `auth.agent_id` is `None` for every decision they make.
    // Writing that through unchanged recorded `decided_by = NULL`, silently
    // dropping the identity behind a promotion that creates a real CORROBORATES
    // edge. Falling back to the authenticated client keeps every decision
    // attributable to *something* without rejecting these callers.
    //
    // `agents.id` and `oauth_clients.id` are disjoint UUID spaces, so a reader
    // can tell which kind of principal a `decided_by` names by looking it up;
    // `match_candidates.decided_by` has no foreign key, so a client UUID here
    // violates no constraint. Same `agent_id.or(client_id)` idiom already used
    // for authenticated identity in `routes/claims.rs`.
    let decided_by = auth.agent_id.or(Some(auth.client_id));

    let repo = epigraph_db::MatchCandidateRepo::new(state.db_pool.clone());
    let row = map_sqlx(repo.get(id).await)?;

    // Undecided-only guard. This lives *inside* the `promote` / `reject` arms
    // rather than above the match, because those two are the verdicts that
    // must not be replayed: a second `promote` overwrites `decided_by` and
    // re-creates an edge a retirement just removed, and a re-`reject` rewrites
    // the provenance of a ruling already made.
    //
    // `retire` is the deliberate exception — it is the *undo* of a decision,
    // so a decided row is precisely its input. Hoisting the guard above the
    // match (its original position) is what made a promoted candidate
    // unretractable over HTTP at all, leaving the `retire_match_candidates`
    // operator binary on the host as the only route.
    let reject_if_decided = || -> Result<(), ApiError> {
        if row.status == "pending" {
            return Ok(());
        }
        Err(ApiError::Conflict {
            reason: format!("candidate {id} already decided (status={})", row.status),
        })
    };

    match req.verdict.as_str() {
        "retire" => {
            let outcome =
                repo.retire(id, decided_by)
                    .await
                    .map_err(|e| ApiError::DatabaseError {
                        message: e.to_string(),
                    })?;

            // Deliberately NOT followed by `recompute_claim_belief_binary`.
            // That entry point recombines `mass_functions`, and a matcher
            // promotion writes none (it calls
            // `EdgeRepository::create_symmetric_if_absent`, never
            // `auto_wire_edge_if_epistemic`), so it would provably return
            // bit-identical scalars. What a retirement invalidates is the
            // factor graph, whose consumer —
            // `routes/computation.rs::propagate_beliefs`, i.e.
            // `POST /api/v1/bp/propagate` with `apply_updates: true` — reloads
            // `factors` from the database on every run and is the only writer
            // of the `claims.pignistic_prob` a deleted factor could have
            // biased. The affected endpoints are returned so a caller that
            // cares can drive that pass itself.
            return Ok(Json(serde_json::json!({
                "id": id.to_string(),
                "status": "stale",
                "previous_status": outcome.previous_status,
                "edges_retracted": outcome.edges_retracted,
                "factors_deleted": outcome.factors_deleted,
                "bp_messages_deleted": outcome.bp_messages_deleted,
                "bbas_invalidated": outcome.bbas_invalidated,
                "affected_claims": outcome.affected_claims
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                // The undo record. The delete is irreversible and the edge
                // properties carry the promotion's whole provenance, so the
                // online path returns what the `retire_match_candidates`
                // binary writes to its `--dump` file.
                "retracted_edges": outcome.retracted_edges,
            })));
        }
        "promote" => {
            reject_if_decided()?;
            // Resolve the polarity FIRST — before the current-ness guard and
            // before `set_status`. "promote" is the operator saying "act on
            // this pair", not "these claims agree": the relationship comes
            // from the row's own `verifier_verdict`. Writing CORROBORATES
            // unconditionally recorded the exact inverse of the verifier's
            // finding for contradicting pairs. Resolving up front also means a
            // refused promote cannot leave the row `promoted` with no edge.
            let disposition =
                epigraph_engine::matching::verifier::promotion_disposition_for_column(
                    row.verifier_verdict.as_deref(),
                )
                .map_err(|e| ApiError::BadRequest {
                    message: format!("cannot promote candidate {id}: {e}"),
                })?;
            let Some(relationship) = disposition.edge_relationship() else {
                return Err(ApiError::BadRequest {
                    message: format!(
                        "cannot promote candidate {id}: verifier_verdict '{}' means the claims \
                         are unrelated, so there is no edge to record. Reject it instead.",
                        row.verifier_verdict.as_deref().unwrap_or("distinct")
                    ),
                });
            };

            let all_current = epigraph_db::ClaimRepository::are_all_current(
                &state.db_pool,
                &[row.claim_a, row.claim_b],
            )
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?;
            if !all_current {
                return Err(ApiError::BadRequest {
                    message: format!(
                        "cannot promote candidate {id}: both claims must be current \
                         (is_current=true)"
                    ),
                });
            }

            repo.set_status(id, "promoted", decided_by)
                .await
                .map_err(|e| ApiError::DatabaseError {
                    message: e.to_string(),
                })?;

            let props = serde_json::json!({
                "candidate_id": id,
                "score": row.score,
                "features": row.features,
                "verifier_verdict": row.verifier_verdict,
                "decided_by": decided_by,
                "source": "cross_source_matcher",
            });
            epigraph_db::EdgeRepository::create_symmetric_if_absent(
                &state.db_pool,
                row.claim_a,
                row.claim_b,
                relationship,
                props,
            )
            .await
            .map_err(|e| ApiError::DatabaseError {
                message: e.to_string(),
            })?;
        }
        "reject" => {
            reject_if_decided()?;
            repo.set_status(id, "rejected", decided_by)
                .await
                .map_err(|e| ApiError::DatabaseError {
                    message: e.to_string(),
                })?;
        }
        other => {
            return Err(ApiError::BadRequest {
                message: format!("verdict must be 'promote', 'reject' or 'retire', got {other}"),
            });
        }
    }

    let updated = map_sqlx(repo.get(id).await)?;
    Ok(Json(serde_json::json!({
        "id": updated.id.to_string(),
        "status": updated.status,
    })))
}
