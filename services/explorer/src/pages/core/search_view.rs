//! `/search` and `/bff/search` (plan §3.4): three modes over three upstream
//! routes with three response shapes, normalised into one hit list.
//!
//! | mode | upstream | paging |
//! |---|---|---|
//! | `semantic` | `POST /search/semantic` | none (no offset upstream) |
//! | `label` | `GET /claims/by-labels` | offset; "next" when a page is full |
//! | `evidence` | `GET /search/evidence` | none (no offset upstream) |

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::vocab::{evidence_type_label, fmt_date, fmt_percent, fmt_prob, one_line};
use crate::error::AppError;
use crate::links::Links;
use crate::upstream::core::{EvidenceHit, LabelHit, SemanticHit, MAX_SEARCH_LIMIT};
use crate::upstream::{degrade, truncate_chars, Api, Degraded, REDACTED};

/// Results per page in the paged (label) mode.
pub const PAGE_SIZE: u32 = 20;
/// Results asked for in the unpaged modes (the BFF-wide cap, plan §3.5).
pub const UNPAGED_LIMIT: u32 = MAX_SEARCH_LIMIT;
/// Longest query accepted (upstream rejects > 10240 bytes).
pub const MAX_QUERY_CHARS: usize = 1000;
/// Highest page number accepted, to keep offsets sane.
pub const MAX_PAGE: u32 = 500;
/// Snippet length in a result list.
const SNIPPET_CHARS: usize = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Semantic,
    Label,
    Evidence,
}

impl Mode {
    pub const ALL: [Mode; 3] = [Mode::Semantic, Mode::Label, Mode::Evidence];

    /// Unknown or missing modes fall back to semantic.
    pub fn parse(raw: Option<&str>) -> Mode {
        match raw.map(|m| m.trim().to_ascii_lowercase()).as_deref() {
            Some("label") | Some("labels") => Mode::Label,
            Some("evidence") => Mode::Evidence,
            _ => Mode::Semantic,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Semantic => "semantic",
            Mode::Label => "label",
            Mode::Evidence => "evidence",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Mode::Semantic => "Meaning (semantic)",
            Mode::Label => "Labels",
            Mode::Evidence => "Evidence text",
        }
    }

    /// Whether upstream can return a page after the first.
    pub fn pages(&self) -> bool {
        matches!(self, Mode::Label)
    }

    fn limit(&self) -> u32 {
        if self.pages() {
            PAGE_SIZE
        } else {
            UNPAGED_LIMIT
        }
    }
}

/// The raw query string. Every field is a string so a malformed `page`
/// cannot turn into a 400 before the page renders.
#[derive(Debug, Default, Deserialize)]
pub struct RawSearchQuery {
    pub q: Option<String>,
    pub mode: Option<String>,
    pub page: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchParams {
    pub q: String,
    pub mode: Mode,
    pub page: u32,
}

impl SearchParams {
    pub fn from_raw(raw: &RawSearchQuery) -> Self {
        let mode = Mode::parse(raw.mode.as_deref());
        let page = if mode.pages() {
            raw.page
                .as_deref()
                .and_then(|p| p.trim().parse::<u32>().ok())
                .unwrap_or(1)
                .clamp(1, MAX_PAGE)
        } else {
            1
        };
        SearchParams {
            q: raw.q.as_deref().unwrap_or("").trim().to_string(),
            mode,
            page,
        }
    }
}

/// One result, whichever mode produced it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SearchHit {
    /// `claim` or `evidence`.
    pub kind: &'static str,
    pub claim_id: Uuid,
    pub claim_url: String,
    pub evidence_id: Option<Uuid>,
    pub evidence_url: Option<String>,
    /// Snippet (whitespace collapsed, char-boundary cut).
    pub text: String,
    /// Upstream sent `"[REDACTED]"`; `text` is a placeholder.
    pub redacted: bool,
    pub similarity: Option<f64>,
    pub truth_value: Option<f64>,
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub labels: Vec<String>,
    /// `Some(false)` for a superseded claim.
    pub is_current: Option<bool>,
    pub evidence_type: Option<String>,
    pub created: Option<String>,
}

impl SearchHit {
    pub fn similarity_display(&self) -> String {
        fmt_percent(self.similarity)
    }

    pub fn truth_display(&self) -> String {
        fmt_prob(self.truth_value)
    }

    /// `[0.60, 0.90]` when both bounds are known.
    pub fn interval_display(&self) -> Option<String> {
        match (self.belief, self.plausibility) {
            (Some(b), Some(p)) => Some(format!("[{}, {}]", fmt_prob(Some(b)), fmt_prob(Some(p)))),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchOutcome {
    pub query: String,
    pub mode: Mode,
    pub page: u32,
    /// Results asked of upstream for this page.
    pub limit: u32,
    /// Whether this mode can page at all.
    pub paging_supported: bool,
    /// `None` when there was nothing to search for, or the query was invalid.
    pub results: Option<Degraded<Vec<SearchHit>>>,
    /// Why the query was not sent (too long, no labels, …).
    pub problem: Option<String>,
    pub prev_url: Option<String>,
    pub next_url: Option<String>,
}

/// Validate, call the mode's upstream route, and normalise. Upstream
/// failures degrade the result list; only `SessionExpired` is an error.
pub async fn run(
    api: &Api<'_>,
    links: &Links,
    p: &SearchParams,
) -> Result<SearchOutcome, AppError> {
    let mut out = SearchOutcome {
        query: p.q.clone(),
        mode: p.mode,
        page: p.page,
        limit: p.mode.limit(),
        paging_supported: p.mode.pages(),
        results: None,
        problem: None,
        prev_url: None,
        next_url: None,
    };
    if p.q.is_empty() {
        return Ok(out);
    }
    if p.q.chars().count() > MAX_QUERY_CHARS {
        out.problem = Some(format!(
            "That search is too long. Use at most {MAX_QUERY_CHARS} characters."
        ));
        return Ok(out);
    }

    let hits = match p.mode {
        Mode::Semantic => degrade(api.search_semantic(&p.q, out.limit).await)?.map(|r| {
            r.results
                .into_iter()
                .map(|h| semantic_hit(h, links))
                .collect()
        }),
        Mode::Evidence => degrade(api.search_evidence(&p.q, out.limit).await)?.map(|r| {
            r.results
                .into_iter()
                .map(|h| evidence_hit(h, links))
                .collect()
        }),
        Mode::Label => {
            let labels = label_list(&p.q);
            if labels.is_empty() {
                out.problem = Some("Enter one or more labels, separated by commas.".into());
                return Ok(out);
            }
            let offset = u64::from(p.page - 1) * u64::from(PAGE_SIZE);
            degrade(api.search_by_labels(&labels, PAGE_SIZE, offset).await)?.map(|v| {
                v.into_iter()
                    .map(|h| label_hit(h, links))
                    .collect::<Vec<_>>()
            })
        }
    };

    if p.mode.pages() {
        if p.page > 1 {
            out.prev_url = Some(links.search(&p.q, Some(p.mode.as_str()), Some(p.page - 1)));
        }
        // Offset paging has no total: offer the next page when this one is
        // full ("next page if full").
        if hits.get().is_some_and(|h| h.len() as u32 >= PAGE_SIZE) && p.page < MAX_PAGE {
            out.next_url = Some(links.search(&p.q, Some(p.mode.as_str()), Some(p.page + 1)));
        }
    }
    out.results = Some(hits);
    Ok(out)
}

/// `"a, b,,c "` → `"a,b,c"`.
pub fn label_list(q: &str) -> String {
    q.split(',')
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

fn snippet(raw: &str) -> (String, bool) {
    if raw.trim() == REDACTED {
        ("Content hidden".to_string(), true)
    } else {
        (truncate_chars(&one_line(raw), SNIPPET_CHARS), false)
    }
}

fn semantic_hit(h: SemanticHit, links: &Links) -> SearchHit {
    let (text, redacted) = snippet(&h.statement);
    SearchHit {
        kind: "claim",
        claim_url: links.claim(h.claim_id),
        claim_id: h.claim_id,
        evidence_id: None,
        evidence_url: None,
        text,
        redacted,
        similarity: h.similarity,
        truth_value: h.epistemic.truth_value,
        belief: h.epistemic.belief,
        plausibility: h.epistemic.plausibility,
        labels: h.claim_type.into_iter().collect(),
        is_current: None,
        evidence_type: None,
        created: h.created_at.map(|d| d.format("%Y-%m-%d").to_string()),
    }
}

fn label_hit(h: LabelHit, links: &Links) -> SearchHit {
    let (text, redacted) = snippet(&h.content);
    SearchHit {
        kind: "claim",
        claim_url: links.claim(h.id),
        claim_id: h.id,
        evidence_id: None,
        evidence_url: None,
        text,
        redacted,
        similarity: None,
        truth_value: h.truth_value,
        belief: None,
        plausibility: None,
        labels: h.labels,
        is_current: h.is_current,
        evidence_type: None,
        created: Some(fmt_date(&h.created_at)).filter(|d| !d.is_empty()),
    }
}

fn evidence_hit(h: EvidenceHit, links: &Links) -> SearchHit {
    let (text, redacted) = match h.raw_content.as_deref().map(str::trim) {
        Some(c) if !c.is_empty() => snippet(c),
        _ => ("(no text)".to_string(), false),
    };
    SearchHit {
        kind: "evidence",
        claim_url: links.claim(h.claim_id),
        claim_id: h.claim_id,
        evidence_url: Some(links.evidence(h.evidence_id)),
        evidence_id: Some(h.evidence_id),
        text,
        redacted,
        similarity: h.similarity,
        truth_value: None,
        belief: None,
        plausibility: None,
        labels: Vec::new(),
        is_current: None,
        evidence_type: Some(evidence_type_label(&h.evidence_type)),
        created: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(q: &str, mode: Option<&str>, page: Option<&str>) -> RawSearchQuery {
        RawSearchQuery {
            q: Some(q.into()),
            mode: mode.map(str::to_string),
            page: page.map(str::to_string),
        }
    }

    #[test]
    fn params_are_forgiving() {
        let p = SearchParams::from_raw(&raw("  water  ", None, Some("x")));
        assert_eq!((p.q.as_str(), p.mode, p.page), ("water", Mode::Semantic, 1));
        let p = SearchParams::from_raw(&raw("a", Some("LABEL"), Some("3")));
        assert_eq!((p.mode, p.page), (Mode::Label, 3));
        let p = SearchParams::from_raw(&raw("a", Some("label"), Some("0")));
        assert_eq!(p.page, 1);
        let p = SearchParams::from_raw(&raw("a", Some("label"), Some("999999")));
        assert_eq!(p.page, MAX_PAGE);
        let p = SearchParams::from_raw(&raw("a", Some("evidence"), Some("4")));
        assert_eq!(p.page, 1, "unpaged modes ignore page");
        let p = SearchParams::from_raw(&raw("a", Some("bogus"), None));
        assert_eq!(p.mode, Mode::Semantic);
    }

    #[test]
    fn labels_are_trimmed_and_joined() {
        assert_eq!(label_list(" a, b,,c "), "a,b,c");
        assert_eq!(label_list(" , "), "");
    }

    #[test]
    fn redacted_snippets_are_placeholders() {
        assert_eq!(snippet("[REDACTED]"), ("Content hidden".into(), true));
        let (t, r) = snippet(&"é".repeat(400));
        assert!(!r);
        assert_eq!(t.chars().count(), SNIPPET_CHARS + 1);
    }
}
