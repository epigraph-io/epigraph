//! Abbreviated claim ids (backlog `30d8b667`).
//!
//! * `resolve_claim_id_prefix`: the claims an 8-or-more hex prefix (the
//!   `30d8b667` form prose and backlog items cite) names, every match when it
//!   is ambiguous.
//! * `lint_claim_id_citations`: the claim ids a claim's text cites, each
//!   classified by whether the citation is wired as an edge to the claim.
//!
//! Both are reads on the caller's viewer-stamped connection. A claim the
//! caller cannot read is not a match, so a prefix naming only hidden claims
//! reads exactly like one naming nothing; a hidden edge is not wiring.

use std::collections::{HashMap, HashSet};

use rmcp::model::*;
use serde::Serialize;
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{LintClaimIdCitationsParams, ResolveClaimIdPrefixParams};

use epigraph_core::ClaimId;
use epigraph_db::{id_prefix_bounds, ClaimIdPrefixMatch, ClaimIdPrefixRepository, ClaimRepository};

const DEFAULT_MATCH_LIMIT: i64 = 10;
const MAX_MATCH_LIMIT: i64 = 50;
/// Matches looked up per cited token by the lint. A citation with more
/// readable matches than this is ambiguous whatever they are.
const LINT_MATCHES_PER_TOKEN: i64 = 10;
/// Distinct cited tokens the lint examines, first appearance first. Bounds
/// the statements one call issues; `tokens_truncated` says when it bit.
const MAX_LINT_TOKENS: usize = 100;

fn success_json(value: &impl Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

#[derive(Debug, Serialize)]
struct PrefixMatch {
    id: Uuid,
    content: String,
    content_truncated: bool,
    is_current: bool,
}

impl From<ClaimIdPrefixMatch> for PrefixMatch {
    fn from(m: ClaimIdPrefixMatch) -> Self {
        Self {
            id: m.id,
            content: m.content,
            content_truncated: m.content_truncated,
            is_current: m.is_current,
        }
    }
}

#[derive(Debug, Serialize)]
struct PrefixResolution {
    prefix: String,
    matches: Vec<PrefixMatch>,
    /// More than one readable claim carries the prefix.
    ambiguous: bool,
    /// More matches exist than `limit` returned.
    truncated: bool,
}

pub async fn resolve_claim_id_prefix(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ResolveClaimIdPrefixParams,
) -> Result<CallToolResult, McpError> {
    let (lo, hi) = id_prefix_bounds(&params.prefix).ok_or_else(|| {
        invalid_params(
            "prefix must be 8 to 32 hex digits of a claim id (hyphens ignored), e.g. 30d8b667",
        )
    })?;
    let limit = params
        .limit
        .unwrap_or(DEFAULT_MATCH_LIMIT)
        .clamp(1, MAX_MATCH_LIMIT);

    let mut read = server.read_as(viewer, "resolve_claim_id_prefix").await?;
    let mut rows = ClaimIdPrefixRepository::matches(&mut *read, viewer, lo, hi, limit + 1)
        .await
        .map_err(internal_error)?;
    read.commit().await.map_err(internal_error)?;

    let truncated = i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit;
    rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    success_json(&PrefixResolution {
        prefix: params.prefix.trim().to_ascii_lowercase(),
        ambiguous: rows.len() > 1,
        truncated,
        matches: rows.into_iter().map(PrefixMatch::from).collect(),
    })
}

/// The claim-id citations in `text`, distinct, lower-cased, in order of first
/// appearance: every full hyphenated uuid, and every standalone run of exactly
/// eight hex digits (the abbreviated form). A token is a maximal run of ASCII
/// letters, digits, `-` and `_`, so `a1b2c3d4` inside `xa1b2c3d4` or a longer
/// hex string (a 9-digit commit sha, a content hash) is not a citation; the
/// first eight digits of a hyphenated uuid are cited once, as the uuid.
#[must_use]
pub fn cited_id_tokens(text: &str) -> Vec<String> {
    fn is_uuid(tok: &str) -> bool {
        tok.len() == 36
            && tok.char_indices().all(|(i, c)| match i {
                8 | 13 | 18 | 23 => c == '-',
                _ => c.is_ascii_hexdigit(),
            })
    }
    let mut out: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let bytes_ok = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    for raw in text.split(|c: char| !bytes_ok(c)) {
        let tok = raw.trim_matches('-');
        let cited = if is_uuid(tok) {
            Some(tok.to_ascii_lowercase())
        } else if tok.len() == 8 && tok.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(tok.to_ascii_lowercase())
        } else {
            // A hyphenated run that starts with an 8-hex segment followed by
            // a non-uuid tail (`30d8b667-fixed`) still cites the prefix.
            tok.split_once('-').and_then(|(head, _)| {
                (head.len() == 8 && head.chars().all(|c| c.is_ascii_hexdigit()))
                    .then(|| head.to_ascii_lowercase())
            })
        };
        if let Some(t) = cited {
            if seen.insert(t.clone()) {
                out.push(t);
            }
        }
    }
    out
}

#[derive(Debug, Serialize)]
struct Citation {
    token: String,
    /// `wired`: a readable claim it names shares an edge with this claim.
    /// `unwired`: it names exactly one readable claim and no edge joins them.
    /// `ambiguous`: it names several readable claims and none is wired.
    /// `unresolved`: it names no claim you can read (not an id, or hidden).
    /// `self`: it names only this claim.
    status: &'static str,
    matches: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
struct CitationLint {
    claim_id: Uuid,
    citations: Vec<Citation>,
    /// The `unwired` citations' tokens: the ones to wire or to remove.
    unwired: Vec<String>,
    tokens_truncated: bool,
}

pub async fn lint_claim_id_citations(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: LintClaimIdCitationsParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.claim_id)?;
    let mut read = server.read_as(viewer, "lint_claim_id_citations").await?;
    let claim = ClaimRepository::get_by_id(&mut *read, viewer, ClaimId::from_uuid(id))
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("claim {id} not found")))?;

    let mut tokens = cited_id_tokens(&claim.content);
    let tokens_truncated = tokens.len() > MAX_LINT_TOKENS;
    tokens.truncate(MAX_LINT_TOKENS);

    let mut matches: HashMap<String, Vec<Uuid>> = HashMap::new();
    let mut all: Vec<Uuid> = Vec::new();
    for tok in &tokens {
        let Some((lo, hi)) = id_prefix_bounds(tok) else {
            continue;
        };
        let rows =
            ClaimIdPrefixRepository::matches(&mut *read, viewer, lo, hi, LINT_MATCHES_PER_TOKEN)
                .await
                .map_err(internal_error)?;
        let ids: Vec<Uuid> = rows.into_iter().map(|r| r.id).collect();
        all.extend(ids.iter().copied().filter(|m| *m != id));
        matches.insert(tok.clone(), ids);
    }
    all.sort_unstable();
    all.dedup();
    let wired: HashSet<Uuid> = ClaimIdPrefixRepository::wired_to(&mut *read, viewer, id, &all)
        .await
        .map_err(internal_error)?
        .into_iter()
        .collect();
    read.commit().await.map_err(internal_error)?;

    let citations: Vec<Citation> = tokens
        .into_iter()
        .map(|token| {
            let ids = matches.remove(&token).unwrap_or_default();
            let others: Vec<Uuid> = ids.iter().copied().filter(|m| *m != id).collect();
            let status = if ids.is_empty() {
                "unresolved"
            } else if others.is_empty() {
                "self"
            } else if others.iter().any(|m| wired.contains(m)) {
                "wired"
            } else if others.len() == 1 {
                "unwired"
            } else {
                "ambiguous"
            };
            Citation {
                token,
                status,
                matches: ids,
            }
        })
        .collect();
    let unwired = citations
        .iter()
        .filter(|c| c.status == "unwired")
        .map(|c| c.token.clone())
        .collect();
    success_json(&CitationLint {
        claim_id: id,
        citations,
        unwired,
        tokens_truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cites_abbreviated_and_full_ids_once_each_in_order() {
        let text = "Resolves 30d8b667 (see 1A2B3C4D-0ca4-4b7f-aa85-000000000001, and \
                    30d8b667 again; follow-up 0720d208-fix).";
        assert_eq!(
            cited_id_tokens(text),
            vec![
                "30d8b667",
                "1a2b3c4d-0ca4-4b7f-aa85-000000000001",
                "0720d208"
            ]
        );
    }

    #[test]
    fn longer_hex_and_embedded_runs_are_not_citations() {
        // A 9-digit commit sha, a 7-digit run, an embedded run, a hash.
        let text = "commit 4c91bc717, short abcdef1, x30d8b667, hash 30d8b6670ca44b7f";
        assert!(
            cited_id_tokens(text).is_empty(),
            "{:?}",
            cited_id_tokens(text)
        );
    }

    #[test]
    fn a_bare_eight_digit_date_is_still_a_candidate() {
        // An 8-digit date is hex too; the lint reports it as unresolved
        // rather than guessing, since a real id prefix can be all digits.
        assert_eq!(cited_id_tokens("on 20261114"), vec!["20261114"]);
    }
}
