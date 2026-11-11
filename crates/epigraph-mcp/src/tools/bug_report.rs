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
//! The database does the deciding (`BugReportRepository`, migration 207's
//! definers): which group, whether the caller is bound, the limits. This
//! module checks the input first, then asks the database's preflight whether
//! the write would refuse the caller (not configured, system agent, unbound,
//! a role's agent its holder does not cover, over its limit), so a report
//! that will be refused for those reasons costs no embedding provider call;
//! then it embeds and writes. It maps the definers' `BUGnn:` refusals to the
//! caller's error.

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

/// Nothing visible: whitespace, format, control and blank filler characters
/// only (the definer's `c_invisible`; see
/// [`epigraph_db::repos::bug_report::is_blank`]).
fn blank(s: &str) -> bool {
    epigraph_db::repos::bug_report::is_blank(s)
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
/// (BUG06, BUG07, OPL01), a role's agent whose role its own human does not
/// hold now (ROL01), the rate limit (BUG08). Nothing is written on any of
/// them. The input checks and the preflight (BUG01-03, BUG06-08, ROL01) run
/// before the embedding provider is called; what reaches the provider and is
/// then refused is a caller whose state changed between the preflight and
/// the write (a race), or a refusal the preflight does not repeat (the
/// staged insert's writer-scope checks, OPL01 and OPL02, which the gate's
/// choice of home group is built to satisfy).
pub async fn submit_bug_report(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: SubmitBugReportParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    check(&params)?;
    let author = server.write_identity(auth, viewer).await?;

    // The write's own refusals that do not depend on the report (BUG01-03,
    // BUG06-08 and 166's ROL01), BEFORE the provider call: otherwise a caller
    // the write refuses (and one over its limit) costs an embedding per
    // attempt, and the limit would not cap provider spend. Its own short transaction, rolled back: the provider
    // round trip below must not hold one open. Advisory and racy, so the
    // write repeats every check.
    let mut pre = crate::claim_helper::begin_author_stamped_tx(server, author, SUBMIT).await?;
    BugReportRepository::preflight_conn(&mut pre)
        .await
        .map_err(intake_error)?;
    pre.rollback().await.map_err(internal_error)?;

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
/// A principal-less HTTP context (`--allow-unauthenticated-http`) is refused:
/// it reads as the listener's own agent, and a shared listener credential is
/// not a reporter. The labels triage puts on a report are the intake group's
/// information, shown only to the agent that filed it.
///
/// # Errors
/// `INVALID_REQUEST` for a principal-less context, when the intake is not
/// configured (BUG03) or the request has no principal (BUG01);
/// `INTERNAL_ERROR` when this process has no tenancy-aware pool.
pub async fn list_my_bug_reports(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ListMyBugReportsParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    if auth.is_some_and(crate::auth::is_principal_less) {
        return Err(McpError {
            code: ErrorCode::INVALID_REQUEST,
            message: Cow::Borrowed(
                "list_my_bug_reports needs an authenticated principal; a principal-less \
                 listener lists no reports",
            ),
            data: None,
        });
    }
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

    /// Both ends of every invisible range, by value (the DB test
    /// `malformed_input_is_refused_with_nothing_written` sends the same list
    /// through the definer).
    const INVISIBLE_ENDPOINTS: &[u32] = &[
        0x01, 0x1F, 0x20, 0x7F, 0x85, 0x9F, 0xA0, 0xAD, 0x34F, 0x600, 0x605, 0x61C, 0x6DD, 0x70F,
        0x890, 0x891, 0x8E2, 0x115F, 0x1160, 0x1680, 0x17B4, 0x17B5, 0x180B, 0x180E, 0x180F,
        0x2000, 0x200A, 0x200B, 0x200F, 0x2028, 0x2029, 0x202A, 0x202E, 0x202F, 0x205F, 0x2060,
        0x2064, 0x2066, 0x206F, 0x2800, 0x3000, 0x3164, 0xFE00, 0xFE0F, 0xFEFF, 0xFFA0, 0xFFF9,
        0xFFFB, 0x110BD, 0x110CD, 0x13430, 0x1343F, 0x1BCA0, 0x1BCA3, 0x1D173, 0x1D17A, 0xE0001,
        0xE0020, 0xE007F, 0xE0100, 0xE01EF,
    ];

    #[test]
    fn a_title_or_description_with_nothing_visible_is_refused() {
        let endpoints: String = INVISIBLE_ENDPOINTS
            .iter()
            .map(|&c| char::from_u32(c).expect("a scalar value"))
            .collect();
        for text in [
            "\u{200B}".to_string(),
            "\u{200B}\u{200C}\u{200D}".to_string(),
            "\u{2060}\u{FEFF}".to_string(),
            "\u{1C}".to_string(),
            "\u{202E}\u{2066}\u{200F}".to_string(),
            "\u{E0001}\u{E0020}\u{E007F}".to_string(),
            " \u{AD}\t\u{3000}".to_string(),
            "\u{3164}\u{115F}\u{1160}\u{FFA0}".to_string(),
            "\u{2800}\u{34F}\u{FE0F}\u{E0100}".to_string(),
            endpoints,
        ] {
            let mut p = params();
            p.title.clone_from(&text);
            assert!(check(&p).is_err(), "title {text:?} admitted");
            let mut p = params();
            p.description = text.clone();
            assert!(check(&p).is_err(), "description {text:?} admitted");
        }
        // CALIBRATION: one visible character among invisible ones is text.
        let mut p = params();
        p.title = "a\u{200B}".into();
        p.description = "\u{FEFF}x".into();
        assert!(check(&p).is_ok());
        for c in [
            '!',
            'é',
            '\u{2065}',
            '\u{E0080}',
            '\u{34E}',
            '\u{350}',
            '\u{115E}',
            '\u{1161}',
            '\u{17B3}',
            '\u{17B6}',
            '\u{180A}',
            '\u{1810}',
            '\u{27FF}',
            '\u{2801}',
            '\u{3163}',
            '\u{3165}',
            '\u{FDFF}',
            '\u{FE10}',
            '\u{FF9F}',
            '\u{FFA1}',
            '\u{E00FF}',
            '\u{E01F0}',
        ] {
            let mut p = params();
            p.title = c.to_string();
            assert!(check(&p).is_ok(), "{c:?} is not in an invisible range");
        }
    }
}
