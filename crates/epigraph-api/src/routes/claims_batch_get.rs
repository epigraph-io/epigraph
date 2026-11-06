//! `POST /api/v1/claims/batch-get`: many claims by id, in one round trip.
//!
//! The Atlas theme page and timeline read a list of claim ids (from a search
//! with a theme filter) and need each claim's body. This route answers that
//! with three viewer-spliced statements on one viewer-stamped connection,
//! instead of one `GET /api/v1/claims/:id` per id.
//!
//! # What a viewer cannot see is absent
//!
//! There is no redaction pass. The claim read splices the viewer predicate
//! into its SQL, so a claim the caller may not read is never fetched, and its
//! id lands in `not_found` next to ids that name nothing. `not_found` means
//! "absent or not readable by you", as one answer.
//!
//! # No counts
//!
//! The body is exactly `{ claims, not_found, remaining }`. There is no `total`,
//! `found` or `hidden` field; the only number a client can work out is
//! `claims.length`, the count of readable claims among the ids it sent.
//!
//! # `remaining` is a size-cap cursor
//!
//! The serialised `claims` array (brackets and commas included) is held to
//! [`MAX_BATCH_GET_BYTES`]. Ids the server did not classify once the budget is
//! spent go to `remaining`, in request order; resubmitting them continues. The
//! first readable claim is always returned, so a resubmission always makes
//! progress. The cut is worked out from request position alone, and hidden and
//! absent ids both weigh zero bytes, so `remaining` never separates them
//! either.
//!
//! # Each item is the `GET /claims/:id` body plus `is_current`
//!
//! The body is built by [`claims::claim_response_for_read`], the builder
//! `GET /api/v1/claims/:id` uses, so the two cannot drift. `is_current` is the
//! row's real retirement state. There is no belief field: `truth_value` is
//! projected, never compared, ordered or folded, and no `belief`,
//! `plausibility` or `pignistic_prob` is served (`epigraph-db`'s
//! `tests/no_role_blind_belief_reads.rs`).
//!
//! # `trace_id` is checked against the viewer
//!
//! `reasoning_traces` carries its own `(visibility, owner_group_id)`, and a
//! claim's `trace_id` is a bare pointer: a trace private to another group can
//! hang off a public claim. So an item names its `trace_id` only when the same
//! viewer can read that trace (`ReasoningTraceRepository::readable_ids`), and
//! is `null` otherwise, the same answer as a claim with no trace.
//!
//! All SQL lives in `epigraph_db` (`ClaimRepository::get_by_ids_with_labels`,
//! `ReasoningTraceRepository::readable_ids`,
//! `ClaimEncryptionRepository::get_by_claim_ids_conn`).

use std::collections::{HashMap, HashSet};

use axum::{extract::rejection::JsonRejection, extract::State, Json};
use epigraph_core::Claim;
use epigraph_db::{ClaimEncryptionRepository, ClaimRepository, ReasoningTraceRepository};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::bearer::ViewerExtractor;
use crate::routes::claims;
use crate::state::AppState;

/// Most ids one request may name, counted before de-duplication. Same number
/// as `POST /api/v1/claims/batch`.
pub const MAX_BATCH_GET_IDS: usize = 100;

/// Byte budget for the serialised `claims` array, brackets and commas included
/// (about 2 MB, the Atlas spec's response cap).
pub const MAX_BATCH_GET_BYTES: usize = 2 * 1024 * 1024;

/// Request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchGetRequest {
    /// Strings, not `Uuid`, so a bad entry is refused with its index instead of
    /// serde's column-offset message.
    pub ids: Vec<String>,
}

/// One readable claim: the `GET /api/v1/claims/:id` body plus `is_current`.
#[derive(Debug, Serialize)]
pub struct BatchGetClaim {
    #[serde(flatten)]
    pub claim: claims::ClaimResponse,
    /// The row's real retirement state, not a placeholder.
    pub is_current: bool,
}

/// Response body. Every distinct requested id appears exactly once across the
/// three arrays, each in request order of first occurrence.
#[derive(Debug, Serialize)]
pub struct BatchGetResponse {
    pub claims: Vec<BatchGetClaim>,
    /// Absent or not readable by the caller, as one answer.
    pub not_found: Vec<Uuid>,
    /// Not classified because the byte budget was spent; resubmit as `ids`.
    pub remaining: Vec<Uuid>,
}

/// Parse, cap and de-duplicate the request ids, keeping first-occurrence order.
fn ordered_ids(raw: &[String]) -> Result<Vec<Uuid>, ApiError> {
    if raw.len() > MAX_BATCH_GET_IDS {
        return Err(ApiError::ValidationError {
            field: "ids".to_string(),
            reason: format!(
                "at most {MAX_BATCH_GET_IDS} ids per request, got {}",
                raw.len()
            ),
        });
    }
    let mut seen: HashSet<Uuid> = HashSet::with_capacity(raw.len());
    let mut ordered: Vec<Uuid> = Vec::with_capacity(raw.len());
    for (i, s) in raw.iter().enumerate() {
        let id = Uuid::parse_str(s).map_err(|_| ApiError::ValidationError {
            field: format!("ids[{i}]"),
            reason: "not a UUID".to_string(),
        })?;
        if seen.insert(id) {
            ordered.push(id);
        }
    }
    Ok(ordered)
}

/// `POST /api/v1/claims/batch-get`
///
/// Returns each readable claim among `ids` with the body `GET
/// /api/v1/claims/:id` gives the caller, plus `is_current`, and with
/// `trace_id` null unless the caller can read that trace. Every other id is in
/// `not_found`; ids past the byte budget are in `remaining`.
pub async fn batch_get_claims(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    payload: Result<Json<BatchGetRequest>, JsonRejection>,
) -> Result<Json<BatchGetResponse>, ApiError> {
    let Json(req) = payload.map_err(|r| ApiError::BadRequest {
        message: format!("invalid request body: {}", r.body_text()),
    })?;
    let ordered = ordered_ids(&req.ids)?;

    if ordered.is_empty() {
        return Ok(Json(BatchGetResponse {
            claims: Vec::new(),
            not_found: Vec::new(),
            remaining: Vec::new(),
        }));
    }

    // One viewer-stamped connection for all three statements, so the claim
    // rows, the trace check and the seal records are read under the session
    // GUCs migration 077's policies read, the same as `get_claim`.
    let mut read = state.read_as(&viewer).await.map_err(|e| {
        tracing::error!(
            target: "tenancy.scoped_read",
            error = %e,
            handler = "batch_get_claims",
            "could not acquire a viewer-stamped connection"
        );
        ApiError::InternalError {
            message: "Failed to acquire a scoped connection".to_string(),
        }
    })?;

    let rows = ClaimRepository::get_by_ids_with_labels(&mut *read, &viewer, &ordered).await?;

    // The traces these rows name, checked against the same viewer. A trace the
    // viewer cannot read and a trace that does not exist both come back absent.
    let mut trace_ids: Vec<Uuid> = rows
        .iter()
        .filter_map(|(c, _)| c.trace_id.map(Uuid::from))
        .collect();
    trace_ids.sort_unstable();
    trace_ids.dedup();
    let readable_traces =
        ReasoningTraceRepository::readable_ids(&mut *read, &viewer, &trace_ids).await?;

    let found: Vec<Uuid> = rows.iter().map(|(c, _)| Uuid::from(c.id)).collect();
    let mut enc =
        ClaimEncryptionRepository::get_by_claim_ids_conn(&mut read, &viewer, &found).await?;

    crate::routes::finish_scoped_read(read, "batch_get_claims").await?;

    let mut by_id: HashMap<Uuid, (Claim, Vec<String>)> = rows
        .into_iter()
        .map(|(c, labels)| (Uuid::from(c.id), (c, labels)))
        .collect();

    let mut claims_out: Vec<BatchGetClaim> = Vec::new();
    let mut not_found: Vec<Uuid> = Vec::new();
    let mut remaining: Vec<Uuid> = Vec::new();
    // The two brackets of the `claims` array.
    let mut used: usize = 2;
    let mut spent = false;

    for id in ordered {
        if spent {
            remaining.push(id);
            continue;
        }
        let Some((claim, labels)) = by_id.remove(&id) else {
            not_found.push(id);
            continue;
        };
        let is_current = claim.is_current;
        // No trace is trivially "readable": there is nothing to withhold.
        let trace_readable = match claim.trace_id {
            Some(t) => readable_traces.contains(&Uuid::from(t)),
            None => true,
        };
        let item = BatchGetClaim {
            claim: claims::claim_response_for_read(claim, labels, enc.remove(&id), trace_readable),
            is_current,
        };
        // Each item after the first also costs the comma before it.
        let cost = serde_json::to_vec(&item)
            .map_err(|e| ApiError::InternalError {
                message: format!("failed to serialise a batch-get item: {e}"),
            })?
            .len()
            + usize::from(!claims_out.is_empty());
        if used + cost > MAX_BATCH_GET_BYTES && !claims_out.is_empty() {
            spent = true;
            remaining.push(id);
            continue;
        }
        used += cost;
        claims_out.push(item);
    }

    Ok(Json(BatchGetResponse {
        claims: claims_out,
        not_found,
        remaining,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_parsed_deduplicated_and_kept_in_order() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let raw = [
            b.to_string(),
            a.to_string(),
            b.to_string().to_uppercase(),
            b.simple().to_string(),
        ];
        assert_eq!(ordered_ids(&raw).unwrap(), vec![b, a]);
    }

    #[test]
    fn the_first_bad_index_is_named() {
        let raw = [Uuid::new_v4().to_string(), "x".into(), "y".into()];
        match ordered_ids(&raw) {
            Err(ApiError::ValidationError { field, .. }) => assert_eq!(field, "ids[1]"),
            other => panic!("expected a ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn the_cap_is_counted_before_deduplication() {
        let one = Uuid::new_v4().to_string();
        assert!(ordered_ids(&vec![one.clone(); MAX_BATCH_GET_IDS]).is_ok());
        match ordered_ids(&vec![one; MAX_BATCH_GET_IDS + 1]) {
            Err(ApiError::ValidationError { field, .. }) => assert_eq!(field, "ids"),
            other => panic!("expected a ValidationError, got {other:?}"),
        }
    }
}
