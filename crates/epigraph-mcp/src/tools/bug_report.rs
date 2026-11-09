//! `submit_bug_report` and `list_my_bug_reports`: the write-only bug-report
//! intake (migration 207).
//!
//! An agent that is not a member of the group operations triages bugs in can
//! still report one. The report is written as ONE claim authored by the
//! caller, owned by the intake group the instance configured, visible only to
//! that group. The caller gets a receipt (the claim id and `submitted_at`) and
//! nothing about what else the group holds: no novelty gate, no dedup, no
//! similarity hint, and the same answer shape every time. The caller can list
//! its own reports and their current labels, which is how it sees triage.
//!
//! The database does the deciding (`BugReportRepository`, the two definers):
//! which group, whether the caller is bound, the limits. This module checks the
//! sizes first so an oversized report is refused before the embedding provider
//! is called, resolves the caller's write identity, and maps the definers'
//! `BUGnn:` refusals to the caller's error.

use rmcp::model::{CallToolResult, ContentBlock, ErrorCode};
use std::borrow::Cow;

use crate::errors::{db_caller_error, internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{ListMyBugReportsParams, SubmitBugReportParams};
use epigraph_db::repos::bug_report::{
    MAX_DESCRIPTION_BYTES, MAX_EVIDENCE_BYTES, MAX_TITLE_CHARS, SEVERITIES,
};
use epigraph_db::{BugReportInput, BugReportRepository};

/// The tool name a write is stamped and logged under.
const SUBMIT: &str = "submit_bug_report";

/// The dimension of `claims.embedding`; a vector of any other length is not
/// passed to the definer.
const EMBEDDING_DIM: usize = 1536;

/// A definer refusal (`DbError::Refused`, every `BUGnn:`) as the caller's
/// error with the database's text; everything else as [`db_caller_error`].
fn intake_error(e: epigraph_db::DbError) -> McpError {
    match e {
        epigraph_db::DbError::Refused { message, .. } => McpError {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::from(message),
            data: None,
        },
        other => db_caller_error(other),
    }
}

fn blank(s: &str) -> bool {
    s.trim().is_empty()
}

/// Whether `s` is the slug the definer accepts: `^[a-z0-9][a-z0-9-]{0,47}$`.
fn is_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 48
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// The definer's input checks, run before anything is resolved or embedded.
/// The definer repeats every one of them (it is the authority); these exist so
/// a report that will be refused costs no provider call.
fn check(p: &SubmitBugReportParams) -> Result<(), McpError> {
    let refuse = |m: String| Err(invalid_params(format!("BUG04: {m}; nothing was written")));
    if blank(&p.title) {
        return refuse("a bug report needs a non-empty title".into());
    }
    let chars = p.title.chars().count();
    if chars > MAX_TITLE_CHARS {
        return refuse(format!(
            "the title is {chars} characters; the maximum is {MAX_TITLE_CHARS}"
        ));
    }
    if blank(&p.description) {
        return refuse("a bug report needs a non-empty description".into());
    }
    for (what, text, max) in [
        ("description", Some(&p.description), MAX_DESCRIPTION_BYTES),
        ("repro", p.repro.as_ref(), MAX_DESCRIPTION_BYTES),
        ("evidence", p.evidence.as_ref(), MAX_EVIDENCE_BYTES),
    ] {
        if let Some(t) = text {
            if t.len() > max {
                return refuse(format!(
                    "the {what} is {} bytes; the maximum is {max}",
                    t.len()
                ));
            }
        }
    }
    if let Some(s) = &p.severity {
        if !SEVERITIES.contains(&s.as_str()) {
            return refuse("severity must be blocker, major or minor".into());
        }
    }
    if let Some(c) = &p.component {
        if !is_slug(c) {
            return refuse(
                "component must be a short lower-case slug (letters, digits and hyphens, at \
                 most 48)"
                    .into(),
            );
        }
    }
    Ok(())
}

fn success_json(value: &serde_json::Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

/// File one bug report as the caller. The answer is
/// `{claim_id, submitted_at}` and nothing else, whatever the intake group
/// already holds.
///
/// # Errors
/// `INVALID_PARAMS` for input the intake refuses (BUG04); `INVALID_REQUEST`
/// for every other refusal: no write identity (an elevated or principal-less
/// request), the intake not configured (BUG03), an unbound or system caller
/// (BUG06, BUG07, OPL01), the rate limit (BUG08). Nothing is written on any
/// of them.
pub async fn submit_bug_report(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: SubmitBugReportParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    check(&params)?;
    let author = server.write_identity(auth, viewer).await?;

    let mut input = BugReportInput {
        title: params.title,
        description: params.description,
        severity: params.severity,
        component: params.component,
        repro: params.repro,
        evidence: params.evidence,
        embedding: None,
    };
    // Before the transaction, so a provider round trip never holds one open;
    // best-effort, so a provider outage never refuses a report (the
    // maintenance backfill embeds a row that has no vector).
    input.embedding = match server.embedder.generate(&input.content()).await {
        Ok(v) if v.len() == EMBEDDING_DIM => Some(crate::embed::format_pgvector(&v)),
        Ok(v) => {
            tracing::warn!(
                tool = SUBMIT,
                dim = v.len(),
                "embedding has the wrong dimension; the report is filed without one"
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                tool = SUBMIT,
                "embedding failed; the report is filed without one: {e}"
            );
            None
        }
    };

    let mut tx = crate::claim_helper::begin_author_stamped_tx(server, author, SUBMIT).await?;
    let receipt = BugReportRepository::submit_conn(&mut tx, &input)
        .await
        .map_err(intake_error)?;
    tx.commit().await.map_err(internal_error)?;

    success_json(&serde_json::json!({
        "claim_id": receipt.claim_id.to_string(),
        "submitted_at": receipt.submitted_at.to_rfc3339(),
    }))
}

/// The caller's own intake reports, newest first: claim id, title,
/// submitted_at, the claim's current labels (triage's status), whether it is
/// resolved, and whether it is current.
///
/// # Errors
/// `INVALID_REQUEST` when the intake is not configured (BUG03) or the request
/// has no principal (BUG01); `INTERNAL_ERROR` when this process has no
/// tenancy-aware pool.
pub async fn list_my_bug_reports(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ListMyBugReportsParams,
) -> Result<CallToolResult, McpError> {
    let limit = i32::try_from(params.limit.unwrap_or(50).clamp(1, 200)).unwrap_or(50);
    let scoped = server.scoped.as_ref().ok_or_else(|| {
        crate::errors::internal_error_text(
            "list_my_bug_reports: this process was not built from a ScopedPool, so the read \
             cannot be stamped with the caller's viewer",
        )
    })?;
    let mut tx = scoped.begin_as(viewer).await.map_err(db_caller_error)?;
    let rows = BugReportRepository::list_mine_conn(&mut tx, limit)
        .await
        .map_err(intake_error)?;
    tx.rollback().await.map_err(internal_error)?;

    let reports: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "claim_id": r.claim_id.to_string(),
                "title": r.title,
                "submitted_at": r.submitted_at.to_rfc3339(),
                "labels": r.labels,
                "resolved": r.resolved,
                "is_current": r.is_current,
            })
        })
        .collect();
    success_json(&serde_json::json!({
        "count": reports.len(),
        "reports": reports,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> SubmitBugReportParams {
        SubmitBugReportParams {
            title: "t".into(),
            description: "d".into(),
            severity: None,
            component: None,
            repro: None,
            evidence: None,
        }
    }

    #[test]
    fn the_pre_checks_match_the_definers_limits() {
        assert!(check(&params()).is_ok());
        let mut p = params();
        p.title = "\t\n".into();
        assert!(check(&p).is_err(), "blank title");
        let mut p = params();
        p.title = "é".repeat(MAX_TITLE_CHARS);
        assert!(
            check(&p).is_ok(),
            "the title cap counts characters, not bytes"
        );
        p.title.push('x');
        assert!(check(&p).is_err());
        let mut p = params();
        p.description = "d".repeat(MAX_DESCRIPTION_BYTES);
        assert!(check(&p).is_ok());
        p.description.push('d');
        assert!(check(&p).is_err());
        let mut p = params();
        p.evidence = Some("e".repeat(MAX_EVIDENCE_BYTES + 1));
        assert!(check(&p).is_err());
        let mut p = params();
        p.severity = Some("critical".into());
        assert!(check(&p).is_err());
        let mut p = params();
        p.component = Some("mcp-server".into());
        assert!(check(&p).is_ok());
        p.component = Some("MCP".into());
        assert!(check(&p).is_err());
        p.component = Some("-x".into());
        assert!(check(&p).is_err());
        p.component = Some("a".repeat(49));
        assert!(check(&p).is_err());
    }
}
