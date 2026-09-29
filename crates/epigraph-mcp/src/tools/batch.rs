#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

/// Batch submit multiple claims (max 100).
///
/// Each entry is converted with `From<BatchClaimEntry> for SubmitClaimParams`
/// (every `submit_claim` field passes through; see that impl for the drift
/// guard) and submitted through the SAME pipeline as `submit_claim`, one entry
/// at a time, each on its own transaction. A refused entry — an unknown
/// methodology or evidence_type, a bad label, a refused write — is refused
/// before or inside its own transaction, so it writes nothing and the other
/// entries still land.
///
/// # Response (additive only)
///
/// `submitted`, `errors` and `error_details` are unchanged. `results` is new:
/// one object per entry, in input order, `{index, status: "ok", ...the full
/// submit_claim response}` or `{index, status: "error", error}`.
pub async fn batch_submit_claims(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: BatchSubmitClaimsParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    if params.claims.is_empty() {
        return Err(invalid_params("claims array cannot be empty"));
    }
    if params.claims.len() > 100 {
        return Err(invalid_params("Maximum 100 claims per batch"));
    }

    // Refuse up front, before any entry is attempted, when the request has no
    // author (see `EpiGraphMcpFull::write_identity`); each entry resolves the
    // same identity again inside `submit_claim_response`.
    let _author = server.write_identity(auth, viewer).await?;
    let mut submitted = 0_usize;
    let mut errors = Vec::new();
    let mut results = Vec::with_capacity(params.claims.len());

    for (i, entry) in params.claims.into_iter().enumerate() {
        // Read BEFORE the conversion fills the batch defaults: once converted,
        // a defaulted methodology or confidence is indistinguishable from a
        // supplied one.
        let supplied = SuppliedByEntry {
            methodology: entry.methodology.is_some(),
            confidence: entry.confidence.is_some(),
        };
        let claim_params = SubmitClaimParams::from(entry);

        match crate::tools::claims::submit_claim_response(server, viewer, claim_params, auth).await
        {
            Ok(mut response) => {
                submitted += 1;
                if let Some(d) = response.deduplicated.as_mut() {
                    supplied.unlist_defaulted_inputs(d);
                }
                let mut row = serde_json::to_value(&response).map_err(internal_error)?;
                if let Some(obj) = row.as_object_mut() {
                    obj.insert("index".into(), serde_json::json!(i));
                    obj.insert("status".into(), serde_json::json!("ok"));
                }
                results.push(row);
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "index": i,
                    "status": "error",
                    "error": e.message,
                }));
                errors.push(serde_json::json!({
                    "index": i,
                    "error": format!("{e:?}"),
                }));
            }
        }
    }

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({
            "submitted": submitted,
            "errors": errors.len(),
            "error_details": errors,
            "results": results,
        })
        .to_string(),
    )]))
}

/// Which of the inputs that `From<BatchClaimEntry> for SubmitClaimParams`
/// defaults the entry actually carried.
#[derive(Debug, Clone, Copy)]
struct SuppliedByEntry {
    methodology: bool,
    confidence: bool,
}

impl SuppliedByEntry {
    /// Drop a defaulted `methodology` / `confidence` from both lists of a
    /// `deduplicated` block.
    ///
    /// `tools::claims::dedup_block` lists both unconditionally, because they
    /// are required on `submit_claim` and so always caller-supplied there. A
    /// batch entry may omit them and get `BATCH_DEFAULT_METHODOLOGY` /
    /// `BATCH_DEFAULT_CONFIDENCE` instead, and `Deduplicated` promises to list
    /// only inputs the caller supplied (G11/G15 review: an entry that omitted
    /// both was told its `methodology` and `confidence` had been applied). The
    /// default is still what the content-hash path records on the new
    /// reasoning trace; it is simply not an input of this call.
    fn unlist_defaulted_inputs(self, d: &mut Deduplicated) {
        let defaulted = |name: &&str| {
            (*name == "methodology" && !self.methodology)
                || (*name == "confidence" && !self.confidence)
        };
        d.inputs_applied.retain(|n| !defaulted(n));
        d.inputs_discarded.retain(|n| !defaulted(n));
    }
}

/// Stage claims for validation without persisting.
pub async fn stage_claims(
    _server: &EpiGraphMcpFull,
    params: StageClaimsParams,
) -> Result<CallToolResult, McpError> {
    if params.claims.is_empty() {
        return Err(invalid_params("claims array cannot be empty"));
    }

    let mut results = Vec::new();

    for (i, content) in params.claims.iter().enumerate() {
        let trimmed = content.trim();
        let valid = !trimmed.is_empty() && trimmed.len() >= 10;
        let warnings: Vec<String> = if trimmed.len() < 20 {
            vec!["Claim is very short — consider adding more detail".into()]
        } else {
            vec![]
        };

        results.push(serde_json::json!({
            "index": i,
            "valid": valid,
            "content_length": trimmed.len(),
            "warnings": warnings,
        }));
    }

    let valid_count = results
        .iter()
        .filter(|r| r["valid"].as_bool().unwrap_or(false))
        .count();

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({
            "total": params.claims.len(),
            "valid": valid_count,
            "invalid": params.claims.len() - valid_count,
            "results": results,
        })
        .to_string(),
    )]))
}

/// Get system statistics.
///
/// # Tenancy (PR-09)
///
/// Every cardinality except `agents` is now **viewer-scoped**: the numbers are
/// "rows this viewer can read", not "rows that exist". Before PR-09 this
/// function took a `&Viewer` and spent it on exactly one call
/// (`TripleRepository::index_counts`) while issuing eight raw `SELECT COUNT(*)`
/// statements of its own, so any principal — including the nil principal of an
/// unauthenticated HTTP call — learned the exact global corpus size. That is a
/// membership oracle, and it was invisible to a lint keyed on the presence of
/// the parameter.
///
/// `agents` and the triple/entity index counts stay corpus-wide and are
/// annotated `VISIBILITY-EXEMPT:` at their repo functions
/// (`corpus_stats.rs::agent_count`, `triple.rs::index_counts`): neither table
/// carries migration 062's tenancy columns, and both numbers exist to tell
/// "the index is empty" apart from "your query matched nothing".
pub async fn system_stats(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: SystemStatsParams,
) -> Result<CallToolResult, McpError> {
    let detailed = params.detailed.unwrap_or(false);

    let counts = epigraph_db::CorpusStatsRepository::tenant_counts(&server.pool, viewer, detailed)
        .await
        .map_err(internal_error)?;
    let agent_count = epigraph_db::CorpusStatsRepository::agent_count(&server.pool, viewer)
        .await
        .map_err(internal_error)?;

    let mut stats = serde_json::json!({
        "claims": counts.claims,
        "evidence": counts.evidence,
        "edges": counts.edges,
        "agents": agent_count,
        "frames": counts.frames,
    });

    if detailed {
        // Structured triple/entity index health. Surfaced here so an empty /
        // unpopulated RDF layer is observable, rather than silently reported as
        // count=0 / entity-not-found by query_triples/search_triples/
        // entity_neighborhood (backlog ae2784a9).
        let index = epigraph_db::TripleRepository::index_counts(&server.pool, viewer)
            .await
            .map_err(internal_error)?;

        stats["workflows"] = serde_json::json!(counts.workflow_claims.unwrap_or(0));
        stats["challenges"] = serde_json::json!(counts.challenges.unwrap_or(0));
        stats["embeddings"] = serde_json::json!(counts.embedded_claims.unwrap_or(0));
        stats["triples"] = serde_json::json!(index.triples);
        stats["entities"] = serde_json::json!(index.entities);
        stats["entity_mentions"] = serde_json::json!(index.entity_mentions);
    }

    Ok(CallToolResult::success(vec![Content::text(
        stats.to_string(),
    )]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(by: DedupBy, applied: &[&'static str], discarded: &[&'static str]) -> Deduplicated {
        Deduplicated {
            by,
            existing_claim_id: uuid::Uuid::nil().to_string(),
            inputs_applied: applied.to_vec(),
            inputs_discarded: discarded.to_vec(),
        }
    }

    /// The novelty-gate arm lists `methodology` and `confidence` as DISCARDED
    /// unconditionally; a batch entry that omitted them must see neither.
    #[test]
    fn a_defaulted_input_leaves_both_lists_and_a_supplied_one_stays() {
        let omitted = SuppliedByEntry {
            methodology: false,
            confidence: false,
        };
        let mut gate = block(
            DedupBy::NoveltyGate,
            &[],
            &[
                "content",
                "methodology",
                "evidence_data",
                "evidence_type",
                "confidence",
            ],
        );
        omitted.unlist_defaulted_inputs(&mut gate);
        assert_eq!(
            gate.inputs_discarded,
            vec!["content", "evidence_data", "evidence_type"]
        );

        let only_methodology = SuppliedByEntry {
            methodology: true,
            confidence: false,
        };
        let mut hash = block(
            DedupBy::ContentHash,
            &[
                "methodology",
                "evidence_data",
                "evidence_type",
                "confidence",
                "labels",
            ],
            &[],
        );
        only_methodology.unlist_defaulted_inputs(&mut hash);
        assert_eq!(
            hash.inputs_applied,
            vec!["methodology", "evidence_data", "evidence_type", "labels"]
        );
    }
}
