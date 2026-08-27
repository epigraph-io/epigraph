//! MCP tools for the cross-source matcher (T19).
//!
//! Four tools: three read-or-decide, plus one that invokes the *verifier-free*
//! half of the pipeline.
//!
//! The matcher runs in three stages — blocking, scoring, LLM verification — and
//! they are split across two processes on purpose:
//!
//! - **MCP runs blocking + scoring.** `stage_cross_source_matches` calls
//!   `epigraph_engine::matching::pipeline::stage_candidates`, which writes
//!   `status='pending'` candidates with `verifier_verdict IS NULL` and no edges.
//! - **The `cross_source_sweep` CLI runs verification.** It cannot move here:
//!   the only production `VerifierClient` is
//!   `epigraph_cli::matching_client::RerankBridgesClient`, and `epigraph-cli`
//!   depends on `epigraph-mcp` (`epigraph-cli/Cargo.toml:160`), so the reverse
//!   dependency is impossible. Wiring an MCP tool to `run_pipeline` with a stub
//!   verifier would be a guaranteed no-op — `run_pipeline` routes every
//!   at-or-above-mid pair through the verifier, and a `None` slot writes
//!   nothing.
//!
//! The tools:
//!
//! - `find_cross_source_matches`: return existing match_candidates + CORROBORATES
//!   edges for a claim. Read-only.
//! - `list_match_candidates`: list the queue, sorted by score desc, optionally
//!   filtered by status.
//! - `decide_match_candidate`: promote or reject a row. Promotion writes the
//!   edge the row's `verifier_verdict` calls for — `CORROBORATES` for
//!   same/paraphrase/overlapping, `contradicts` for contradicts — and refuses
//!   outright for `distinct`. Honours `reject_if_read_only` like other write
//!   tools.
//! - `stage_cross_source_matches`: block + score seed claims and stage the
//!   survivors as `pending`. Spends no LLM tokens, writes no edges, and does
//!   not stamp `claims.last_match_scan_at`, so the nightly sweep still
//!   re-scans and verifies those seeds. `dry_run` defaults to true.

#![allow(clippy::wildcard_imports)]

use rmcp::model::*;
use serde::Serialize;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::{ClaimRepository, EdgeRepository, MatchCandidateRepo};
use epigraph_engine::matching::calibration::MatcherConfig;
use epigraph_engine::matching::pipeline::{stage_candidates, StageInputs, StageReport};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

#[derive(Serialize)]
struct CandidateOut {
    id: String,
    claim_a: String,
    claim_b: String,
    score: f32,
    status: String,
    verifier_verdict: Option<String>,
    verifier_rationale: Option<String>,
    matcher_run_id: Option<String>,
    features: serde_json::Value,
    created_at: String,
}

fn row_to_out(r: epigraph_db::MatchCandidateRow) -> CandidateOut {
    CandidateOut {
        id: r.id.to_string(),
        claim_a: r.claim_a.to_string(),
        claim_b: r.claim_b.to_string(),
        score: r.score,
        status: r.status,
        verifier_verdict: r.verifier_verdict,
        verifier_rationale: r.verifier_rationale,
        matcher_run_id: r.matcher_run_id.map(|u| u.to_string()),
        features: r.features,
        created_at: r.created_at.to_rfc3339(),
    }
}

pub async fn find_cross_source_matches(
    server: &EpiGraphMcpFull,
    params: FindCrossSourceMatchesParams,
) -> Result<CallToolResult, McpError> {
    let claim_id = parse_uuid(&params.claim_id)?;
    let repo = MatchCandidateRepo::new(server.pool.clone());

    let candidates = repo
        .list_for_claim(claim_id)
        .await
        .map_err(internal_error)?;
    let candidates_out: Vec<CandidateOut> = candidates.into_iter().map(row_to_out).collect();

    // Pull CORROBORATES edges incident on the claim — already-promoted matches.
    let edges: Vec<(uuid::Uuid, uuid::Uuid, uuid::Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT id, source_id, target_id, properties FROM edges
         WHERE relationship = 'CORROBORATES'
           AND (source_id = $1 OR target_id = $1)",
    )
    .bind(claim_id)
    .fetch_all(&server.pool)
    .await
    .map_err(internal_error)?;

    let corroborates: Vec<serde_json::Value> = edges
        .into_iter()
        .map(|(id, source_id, target_id, properties)| {
            serde_json::json!({
                "edge_id":    id.to_string(),
                "source_id":  source_id.to_string(),
                "target_id":  target_id.to_string(),
                "properties": properties,
            })
        })
        .collect();

    success_json(&serde_json::json!({
        "claim_id":     claim_id.to_string(),
        "candidates":   candidates_out,
        "corroborates": corroborates,
    }))
}

pub async fn list_match_candidates(
    server: &EpiGraphMcpFull,
    params: ListMatchCandidatesParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 500);

    let status_owned = params.status.as_deref().map(|s| s.to_lowercase());
    let status_ref = match status_owned.as_deref() {
        Some(s @ ("pending" | "promoted" | "rejected" | "stale")) => Some(s),
        Some(other) => {
            return Err(invalid_params(format!(
                "status must be one of pending|promoted|rejected|stale, got {other}"
            )));
        }
        None => None,
    };

    let repo = MatchCandidateRepo::new(server.pool.clone());
    let rows = repo.list(status_ref, limit).await.map_err(internal_error)?;
    let out: Vec<CandidateOut> = rows.into_iter().map(row_to_out).collect();
    success_json(&out)
}

pub async fn decide_match_candidate(
    server: &EpiGraphMcpFull,
    params: DecideMatchCandidateParams,
) -> Result<CallToolResult, McpError> {
    server.reject_if_read_only()?;
    let candidate_id = parse_uuid(&params.candidate_id)?;
    let decision = params.verdict.to_lowercase();

    let repo = MatchCandidateRepo::new(server.pool.clone());
    let row = repo.get(candidate_id).await.map_err(internal_error)?;

    let acting_agent = server.agent_id().await?;

    match decision.as_str() {
        "promote" => {
            // Resolve the polarity FIRST — before the current-ness guard and
            // before `set_status`. "promote" is the operator saying "act on
            // this pair", not "these claims agree": the relationship comes from
            // the row's own `verifier_verdict`. Writing CORROBORATES
            // unconditionally recorded the exact inverse of the verifier's
            // finding for contradicting pairs. Resolving up front also means a
            // refused promote cannot leave the row `promoted` with no edge.
            // Refuse to promote a row the write-time contradiction scan
            // staged but no verifier has scored (backlog 6ed02d04).
            // `promotion_disposition_for_column(None)` resolves a NULL verdict
            // to Corroborate on purpose, so unverified MATCHER rows stay
            // promotable — but a scan row exists precisely because a detector
            // suspects the pair CONFLICTS, so that default would record the
            // exact inverse. Rejecting is deliberately still one call away.
            if epigraph_engine::matching::verifier::is_unverified_write_time_scan(
                row.verifier_verdict.as_deref(),
                &row.features,
            ) {
                return Err(invalid_params(format!(
                    "cannot promote candidate {candidate_id}: it was staged by the write-time \
                     contradiction scan and carries no verifier verdict. Promoting a NULL verdict \
                     records CORROBORATES, which is the inverse of what this row was staged for. \
                     Run the verifier (cross_source_sweep) to set verifier_verdict, or reject it."
                )));
            }

            let disposition =
                epigraph_engine::matching::verifier::promotion_disposition_for_column(
                    row.verifier_verdict.as_deref(),
                )
                .map_err(|e| {
                    invalid_params(format!("cannot promote candidate {candidate_id}: {e}"))
                })?;
            let Some(relationship) = disposition.edge_relationship() else {
                return Err(invalid_params(format!(
                    "cannot promote candidate {candidate_id}: verifier_verdict '{}' means the \
                     claims are unrelated, so there is no edge to record. Reject it instead.",
                    row.verifier_verdict.as_deref().unwrap_or("distinct")
                )));
            };

            // Guard: the edge must connect two live claims. If
            // either endpoint was superseded or marked duplicate (is_current =
            // false) since the candidate was generated, promoting would create
            // a structural inconsistency — an edge incident on a retired claim
            // (backlog bug 5c7fc645). Refuse rather than write it.
            if !ClaimRepository::are_all_current(&server.pool, &[row.claim_a, row.claim_b])
                .await
                .map_err(internal_error)?
            {
                return Err(invalid_params(format!(
                    "cannot promote candidate {candidate_id}: a '{relationship}' edge requires \
                     both claims to be current (is_current=true). One of {} / {} is superseded, a \
                     duplicate, or missing.",
                    row.claim_a, row.claim_b
                )));
            }

            repo.set_status(candidate_id, "promoted", Some(acting_agent))
                .await
                .map_err(internal_error)?;

            // Write the edge if it doesn't already exist (either
            // direction). The unique-triple index was dropped in migrations
            // 017/018, so this explicit existence check — now centralized in
            // `EdgeRepository::create_symmetric_if_absent` — is the only guard
            // against duplicates from repeated `decide` calls. The
            // are_all_current guard above stays here at the call site.
            let props = serde_json::json!({
                "candidate_id":     candidate_id,
                "score":            row.score,
                "features":         row.features,
                "verifier_verdict": row.verifier_verdict,
                "decided_by":       acting_agent,
                "source":           "cross_source_matcher",
            });
            EdgeRepository::create_symmetric_if_absent(
                &server.pool,
                row.claim_a,
                row.claim_b,
                relationship,
                props,
            )
            .await
            .map_err(internal_error)?;
        }
        "reject" => {
            repo.set_status(candidate_id, "rejected", Some(acting_agent))
                .await
                .map_err(internal_error)?;
        }
        other => {
            return Err(invalid_params(format!(
                "verdict must be 'promote' or 'reject', got {other}"
            )));
        }
    }

    let updated = repo.get(candidate_id).await.map_err(internal_error)?;
    success_json(&row_to_out(updated))
}

/// Resolve which `calibration.toml` to load: explicit param wins, then
/// `EPIGRAPH_CALIBRATION_PATH`, then a bare `calibration.toml` relative to the
/// server process's working directory.
///
/// Pure so the precedence is testable without touching the environment.
fn resolve_calibration_path(param: Option<&str>, env: Option<&str>) -> std::path::PathBuf {
    match (param, env) {
        (Some(p), _) => std::path::PathBuf::from(p),
        (None, Some(e)) => std::path::PathBuf::from(e),
        (None, None) => std::path::PathBuf::from("calibration.toml"),
    }
}

/// Response body for [`stage_cross_source_matches`]. Pure so the "these rows
/// are NOT verified" signal is unit-testable.
fn stage_report_json(report: &StageReport, seeds: usize, dry_run: bool) -> serde_json::Value {
    serde_json::json!({
        "run_id":          report.run_id.to_string(),
        "seeds":           seeds,
        "blocked_pairs":   report.blocked_pairs,
        "scanned_pairs":   report.scanned_pairs,
        "truncated_pairs": report.truncated_pairs,
        "staged":          report.staged,
        "below_band":      report.below_band,
        "already_decided": report.already_decided,
        "dry_run":         dry_run,
        // Load-bearing, not decoration: staged rows carry
        // `verifier_verdict = NULL`, and `promotion_disposition_for_column(None)`
        // resolves NULL to Corroborate — so an operator who promotes one of
        // these writes a CORROBORATES edge nothing verified.
        "verified":        false,
        "note":            "Staged rows carry verifier_verdict = NULL — blocking and scoring only, \
                            no LLM verification and no edges. Run the cross_source_sweep CLI to \
                            verify them, or review them with list_match_candidates. \
                            last_match_scan_at is deliberately NOT stamped, so the nightly sweep \
                            still re-scans these seeds.",
    })
}

pub async fn stage_cross_source_matches(
    server: &EpiGraphMcpFull,
    params: StageCrossSourceMatchesParams,
) -> Result<CallToolResult, McpError> {
    // Writes match_candidates rows (unless dry_run) — gate before any work.
    server.reject_if_read_only()?;

    let limit = params.limit.unwrap_or(25).clamp(1, 200);
    let max_pairs = params.max_pairs.unwrap_or(300).clamp(1, 2000);
    // Default TRUE, matching `sweep_semantic_duplicates`: a tool that fills a
    // human review queue should have to be asked twice.
    let dry_run = params.dry_run.unwrap_or(true);

    let seeds: Vec<uuid::Uuid> = match params.claim_ids.as_deref() {
        Some(ids) if !ids.is_empty() => ids
            .iter()
            .map(|s| parse_uuid(s))
            .collect::<Result<Vec<_>, _>>()?,
        _ => ClaimRepository::select_match_seeds(&server.pool, limit)
            .await
            .map_err(internal_error)?,
    };
    if seeds.is_empty() {
        return Err(invalid_params(
            "no seed claims to scan: `claim_ids` was empty and the 7-day seed window returned \
             nothing (every current claim has been scanned within the last 7 days)"
                .to_string(),
        ));
    }

    // Fail loudly rather than falling back to `MatcherConfig::default()`. The
    // in-code `EligibilityConfig` default excludes only 2 labels, while the
    // deployed calibration.toml excludes 17 — a prod dry-run found 31 of 44
    // staged candidates were operational self-logs before that list grew. A
    // silent built-in default would reproduce exactly that.
    let cal_path = resolve_calibration_path(
        params.calibration_path.as_deref(),
        std::env::var("EPIGRAPH_CALIBRATION_PATH").ok().as_deref(),
    );
    let cfg = MatcherConfig::load_from(&cal_path).map_err(|e| {
        invalid_params(format!(
            "could not load matcher calibration from {}: {e}. Pass `calibration_path`, or set \
             EPIGRAPH_CALIBRATION_PATH on the server. There is no built-in fallback: the default \
             eligibility list excludes far fewer labels than the deployed one and would flood the \
             review queue with operational self-logs.",
            cal_path.display()
        ))
    })?;

    let seed_count = seeds.len();
    let report = stage_candidates(
        &server.pool,
        StageInputs {
            seeds,
            cfg,
            max_pairs: usize::try_from(max_pairs).unwrap_or(300),
            write: !dry_run,
        },
    )
    .await
    .map_err(internal_error)?;

    success_json(&stage_report_json(&report, seed_count, dry_run))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_path_param_wins_over_env() {
        assert_eq!(
            resolve_calibration_path(Some("/a/cal.toml"), Some("/b/cal.toml")),
            std::path::PathBuf::from("/a/cal.toml")
        );
    }

    #[test]
    fn calibration_path_falls_back_to_env_then_cwd() {
        assert_eq!(
            resolve_calibration_path(None, Some("/b/cal.toml")),
            std::path::PathBuf::from("/b/cal.toml")
        );
        assert_eq!(
            resolve_calibration_path(None, None),
            std::path::PathBuf::from("calibration.toml")
        );
    }

    /// An agent reading the response must not be able to mistake staged rows
    /// for verified ones, and a partial scan must not read as a full one.
    #[test]
    fn stage_report_json_marks_staged_rows_unverified() {
        let report = StageReport {
            run_id: uuid::Uuid::nil(),
            blocked_pairs: 40,
            scanned_pairs: 25,
            truncated_pairs: 10,
            staged: 7,
            below_band: 18,
            already_decided: 5,
            wrote_rows: true,
        };
        let v = stage_report_json(&report, 3, false);
        assert_eq!(v["verified"], serde_json::json!(false));
        assert_eq!(v["truncated_pairs"], serde_json::json!(10));
        assert_eq!(v["already_decided"], serde_json::json!(5));
        assert_eq!(v["staged"], serde_json::json!(7));
        assert_eq!(v["seeds"], serde_json::json!(3));
        assert_eq!(v["dry_run"], serde_json::json!(false));
        assert!(v["note"]
            .as_str()
            .expect("note must be a string")
            .contains("verifier_verdict = NULL"));
    }
}
