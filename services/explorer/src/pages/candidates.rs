//! `/candidates?status=`: cross-source match candidates as side-by-side
//! pairs of claim excerpts (J6), read-only.
//!
//! Upstream (`GET /api/v1/match_candidates`) filters by status, keeps only
//! candidates whose two claims the viewer may read, and orders them by
//! score, highest first; this page renders them in that order. Statuses are
//! the kernel's own four; anything else is refused here with a notice and
//! no upstream call. Upstream has no total and no paging, so a list that
//! fills the page is marked as possibly cut.
//!
//! Deciding a candidate (promote, reject, retire) stays on MCP / the CLI:
//! this page has no form or button that writes.

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use crate::auth::{PageCtx, SignedIn};
use crate::error::AppError;
use crate::links::Links;
use crate::pages::core::vocab::one_line;
use crate::state::AppState;
use crate::upstream::candidates::{
    Candidate, CANDIDATES_LIMIT, CANDIDATE_STATUSES, DEFAULT_STATUS,
};
use crate::upstream::{degrade, truncate_chars, Degraded};
use crate::view::render;

/// Longest verifier rationale shown (characters).
const RATIONALE_CHARS: usize = 600;

pub fn routes() -> Router<AppState> {
    Router::new().route("/candidates", get(candidates))
}

/// The raw query string; a string so a malformed value renders a notice,
/// not a 400.
#[derive(Debug, Default, Deserialize)]
pub struct RawCandidatesQuery {
    pub status: Option<String>,
}

/// The status asked for: unset or blank is [`DEFAULT_STATUS`]; otherwise it
/// must be exactly one of [`CANDIDATE_STATUSES`] (after trimming), as the
/// kernel requires.
pub fn parse_status(raw: Option<&str>) -> Result<&'static str, &'static str> {
    let s = raw.unwrap_or("").trim();
    if s.is_empty() {
        return Ok(DEFAULT_STATUS);
    }
    CANDIDATE_STATUSES
        .iter()
        .copied()
        .find(|known| *known == s)
        .ok_or("Status must be one of pending, promoted, rejected or stale.")
}

/// One entry of the status switcher.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusLink {
    pub name: &'static str,
    pub url: String,
    pub current: bool,
}

/// One claim of a pair.
#[derive(Debug, Clone, PartialEq)]
pub struct PairSide {
    pub url: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CandidateRow {
    pub id: String,
    pub a: PairSide,
    pub b: PairSide,
    /// Two decimal places.
    pub score: String,
    pub verdict: Option<String>,
    pub rationale: Option<String>,
    pub created: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CandidateList {
    pub rows: Vec<CandidateRow>,
    /// The list filled the page: upstream may hold more.
    pub capped: bool,
}

fn row(c: Candidate, links: &Links) -> CandidateRow {
    CandidateRow {
        id: c.id.to_string(),
        a: PairSide {
            url: links.claim(c.claim_a),
            text: one_line(&c.claim_a_excerpt),
        },
        b: PairSide {
            url: links.claim(c.claim_b),
            text: one_line(&c.claim_b_excerpt),
        },
        score: format!("{:.2}", c.score),
        verdict: c.verifier_verdict.filter(|v| !v.trim().is_empty()),
        rationale: c
            .verifier_rationale
            .map(|r| truncate_chars(&one_line(&r), RATIONALE_CHARS))
            .filter(|r| !r.is_empty()),
        created: c.created_at.format("%Y-%m-%d").to_string(),
    }
}

/// Rows in upstream's order; `capped` when the list is as long as asked for.
pub fn candidate_list(rows: Vec<Candidate>, limit: u32, links: &Links) -> CandidateList {
    let capped = rows.len() >= limit as usize;
    CandidateList {
        rows: rows.into_iter().map(|c| row(c, links)).collect(),
        capped,
    }
}

#[derive(Template)]
#[template(path = "candidates.html")]
struct CandidatesPage {
    ctx: PageCtx,
    switcher: Vec<StatusLink>,
    /// The status listed; `None` when the one asked for was refused.
    status: Option<&'static str>,
    problem: Option<String>,
    list: Option<Degraded<CandidateList>>,
    limit: u32,
}

async fn candidates(
    State(state): State<AppState>,
    user: SignedIn,
    Query(raw): Query<RawCandidatesQuery>,
) -> Result<Html<String>, AppError> {
    let parsed = parse_status(raw.status.as_deref());
    let current = parsed.ok();
    let switcher = CANDIDATE_STATUSES
        .iter()
        .map(|&name| StatusLink {
            name,
            url: state.links.candidates_page(name),
            current: current == Some(name),
        })
        .collect();
    let (mut problem, mut list) = (None, None);
    match parsed {
        Err(why) => problem = Some(why.to_string()),
        Ok(status) => {
            let api = user.api(&state);
            list = Some(
                degrade(api.match_candidates(status, CANDIDATES_LIMIT).await)?
                    .map(|rows| candidate_list(rows, CANDIDATES_LIMIT, &state.links)),
            );
        }
    }
    render(&CandidatesPage {
        ctx: user.ctx,
        switcher,
        status: current,
        problem,
        list,
        limit: CANDIDATES_LIMIT,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_is_one_of_the_kernels_four_and_blank_is_pending() {
        assert_eq!(parse_status(None), Ok("pending"));
        assert_eq!(parse_status(Some("  ")), Ok("pending"));
        for s in ["pending", "promoted", "rejected", "stale"] {
            assert_eq!(parse_status(Some(s)), Ok(s));
        }
        assert_eq!(parse_status(Some(" stale ")), Ok("stale"));
        for bad in ["Pending", "STALE", "accepted", "pending,stale"] {
            assert!(parse_status(Some(bad)).is_err(), "{bad}");
        }
    }

    fn cand(n: u128) -> Candidate {
        Candidate {
            id: uuid::Uuid::from_u128(n),
            claim_a: uuid::Uuid::from_u128(n << 8),
            claim_a_excerpt: "a  b\n c".into(),
            claim_b: uuid::Uuid::from_u128((n << 8) + 1),
            claim_b_excerpt: "d".into(),
            score: 0.12345,
            verifier_verdict: Some(" ".into()),
            verifier_rationale: None,
            created_at: chrono::DateTime::parse_from_rfc3339("2026-09-30T23:59:59.5+00:00")
                .unwrap()
                .with_timezone(&chrono::Utc),
        }
    }

    #[test]
    fn a_list_is_capped_only_when_it_fills_the_page() {
        let links = Links::new("https://explorer.example.com", "/explorer");
        let short = candidate_list(vec![cand(1), cand(2)], 3, &links);
        assert!(!short.capped);
        assert_eq!(short.rows.len(), 2);
        let full = candidate_list(vec![cand(1), cand(2), cand(3)], 3, &links);
        assert!(full.capped);
        let r = &full.rows[0];
        assert_eq!(r.id, uuid::Uuid::from_u128(1).to_string());
        assert_eq!(r.a.url, links.claim(uuid::Uuid::from_u128(1 << 8)));
        assert_eq!(r.a.text, "a b c", "whitespace collapsed");
        assert_eq!(r.score, "0.12");
        assert_eq!(r.verdict, None, "a blank verdict is no verdict");
        assert_eq!(r.created, "2026-09-30");
    }
}
