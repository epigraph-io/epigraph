//! CDST maintenance tools.
//!
//! [`recompute_beliefs`] is the in-server, queryable sibling of the
//! `epigraph-recompute-belief` operator binary: it refreshes the cached
//! `claims.{belief, plausibility, pignistic_prob, conflict_k, missing_mass}`
//! scalars from current `mass_functions` state, per-frame, in deterministic
//! frame-name order.
//!
//! Why it exists: several write paths populate or discount BBAs without
//! refreshing the cached belief — e.g. initial `ingest_document` writes the
//! cache from the raw built BBA (no `effective_source_strength` discount,
//! backlog 50ea636e), and operator edits to `calibration.toml` /
//! per-frame overrides change combined belief only on the next recompute.
//! This tool re-runs the canonical `recompute_claim_belief_on_frame` cascade
//! so the cache catches up, targeted (`claim_ids` / `labels`) or in bulk.

#![allow(clippy::wildcard_imports)]

use rmcp::model::*;
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::RecomputeBeliefsParams;

use epigraph_db::{ClaimRepository, MassFunctionRepository};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

#[derive(serde::Serialize)]
struct RecomputeError {
    claim_id: String,
    frame_id: String,
    error: String,
}

#[derive(serde::Serialize)]
struct RecomputeBeliefsResult {
    /// How the target claim set was selected: `claim_ids` | `labels` | `all_with_bbas`.
    target: &'static str,
    /// Number of candidate claims considered.
    claims_considered: usize,
    /// Claims that had at least one (claim, frame) belief recomputed.
    claims_recomputed: usize,
    /// Candidate claims that carried no BBAs, so nothing was recomputed.
    claims_skipped_no_bba: usize,
    /// Total (claim, frame) belief writes performed.
    frame_writes: usize,
    /// Per-(claim, frame) errors; recompute continues past failures.
    errors: Vec<RecomputeError>,
    /// True when the bulk enumeration hit `limit` and more claims remain
    /// (page with `offset` or use the `epigraph-recompute-belief` CLI).
    truncated: bool,
}

/// Bulk-recompute cached claim beliefs from current `mass_functions` state.
///
/// Target precedence: `claim_ids` (explicit) > `labels` (current claims with
/// all labels) > bulk enumeration of every claim that has a BBA. Each target
/// claim's cache is written from ONE owner frame (`binary_truth` when present),
/// see `recompute_claim_cached_belief`.
///
/// # Every statement runs on the maintenance session's connection
///
/// Enumeration, per-claim frame listing and the recompute itself all run on
/// `session`'s connection, which `maintenance::maintenance_viewer` has checked
/// can bypass RLS. The server's application pool is never named here
/// (`tests/maintenance_tools_spend_only_the_session.rs`), so the bypass viewer
/// cannot be spent on a connection that would filter it into zero rows.
///
/// Each claim's recompute is its OWN transaction on that connection. The frame
/// get-or-create and the cached-belief UPDATE land together or not at all, and a
/// failure on one claim is rolled back alone and reported in `errors`.
/// `claims_recomputed` / `frame_writes` count only claims whose transaction
/// COMMITTED a cache write, so the response cannot claim a write that was
/// rolled back (#395).
pub async fn recompute_beliefs(
    _server: &EpiGraphMcpFull,
    session: &mut epigraph_db::MaintenanceSession<'_>,
    params: RecomputeBeliefsParams,
) -> Result<CallToolResult, McpError> {
    use sqlx::Acquire as _;
    let (conn, viewer) = session.split();
    let limit = params.limit.unwrap_or(500).clamp(1, 2000);
    let offset = params.offset.unwrap_or(0).max(0);

    let claim_ids_param = params.claim_ids.unwrap_or_default();
    let labels_param = params.labels.unwrap_or_default();

    let (target, claim_ids, truncated): (&'static str, Vec<Uuid>, bool) = if !claim_ids_param
        .is_empty()
    {
        let mut ids = Vec::with_capacity(claim_ids_param.len());
        for s in &claim_ids_param {
            ids.push(
                Uuid::parse_str(s.trim())
                    .map_err(|e| invalid_params(format!("invalid claim_id {s:?}: {e}")))?,
            );
        }
        ("claim_ids", ids, false)
    } else if !labels_param.is_empty() {
        // Fetch limit+1 to distinguish "exactly limit, none remain" from
        // "limit reached, more remain" (same trick as the bulk path).
        let mut rows = ClaimRepository::list_by_labels(
            &mut *conn,
            viewer,
            epigraph_db::LabelQuery {
                labels: &labels_param,
                current_only: true,
                limit: limit + 1,
                offset,
                ..Default::default()
            },
        )
        .await
        .map_err(internal_error)?;
        let truncated = rows.len() as i64 > limit;
        rows.truncate(limit as usize);
        let ids: Vec<Uuid> = rows.into_iter().map(|(c, _)| c.id.into()).collect();
        ("labels", ids, truncated)
    } else {
        // Fetch limit+1 to detect truncation, then trim back to limit.
        let mut ids = MassFunctionRepository::list_claim_ids(&mut *conn, viewer, limit + 1, offset)
            .await
            .map_err(internal_error)?;
        let truncated = ids.len() as i64 > limit;
        ids.truncate(limit as usize);
        ("all_with_bbas", ids, truncated)
    };

    let claims_considered = claim_ids.len();
    let mut claims_recomputed = 0usize;
    let mut claims_skipped_no_bba = 0usize;
    let mut frame_writes = 0usize;
    let mut errors: Vec<RecomputeError> = Vec::new();

    for claim_id in claim_ids {
        let frames = MassFunctionRepository::list_frames_for_claim(&mut *conn, viewer, claim_id)
            .await
            .map_err(internal_error)?;
        if frames.is_empty() {
            claims_skipped_no_bba += 1;
            continue;
        }
        // Exactly ONE frame owns the shared claims.* cache (backlog 696d3a1c).
        // Looping over every frame here wrote that cache once per frame and let
        // the alphabetically last one win, silently reverting edge-derived
        // belief. `frame_writes` is consequently now at most 1 per claim.
        let owner_frame = frames
            .iter()
            .map(|(id, _)| *id)
            .next()
            .expect("frames is non-empty: checked above");
        let mut wrote_any = false;
        // ONE TRANSACTION PER CLAIM, on the maintenance connection. A bulk
        // recompute is authored by nobody, so it is not stamped from anyone's
        // viewer; its authority is the connection's bypass, checked by
        // `maintenance_viewer`. The transaction makes the claim's frame
        // get-or-create and its cached-belief UPDATE one unit, and a failure is
        // rolled back alone (it is reported, and the sweep continues).
        let mut tx = match conn.begin().await {
            Ok(tx) => tx,
            Err(e) => {
                errors.push(RecomputeError {
                    claim_id: claim_id.to_string(),
                    frame_id: owner_frame.to_string(),
                    error: format!("could not begin the per-claim transaction: {e}"),
                });
                continue;
            }
        };
        match epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut tx, viewer, claim_id)
            .await
        {
            Ok(true) => match tx.commit().await {
                Ok(()) => {
                    frame_writes += 1;
                    wrote_any = true;
                }
                Err(e) => errors.push(RecomputeError {
                    claim_id: claim_id.to_string(),
                    frame_id: owner_frame.to_string(),
                    error: format!("recomputed but could not commit: {e}"),
                }),
            },
            // No BBA on the owner frame: nothing was written. Dropping `tx`
            // rolls back the (empty) transaction.
            Ok(false) => {}
            Err(e) => errors.push(RecomputeError {
                claim_id: claim_id.to_string(),
                frame_id: owner_frame.to_string(),
                error: e,
            }),
        }
        if wrote_any {
            claims_recomputed += 1;
        }
    }

    success_json(&RecomputeBeliefsResult {
        target,
        claims_considered,
        claims_recomputed,
        claims_skipped_no_bba,
        frame_writes,
        errors,
        truncated,
    })
}
