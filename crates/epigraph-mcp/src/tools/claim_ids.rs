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

use std::collections::HashSet;

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
/// the statements one call issues (at most four prefix lookups per token, see
/// [`lint_prefixes`]); `tokens_truncated` says when it bit.
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
/// appearance. A token is a maximal run of ASCII letters, digits, `-` and `_`;
/// it cites the longest run of leading uuid-shaped groups it starts with (an
/// 8-hex group, then whole 4-, 4-, 4- and 12-hex groups, hyphen-separated), so
/// a full uuid is cited whole, a partial one such as `30d8b667-0ca4` keeps the
/// more specific prefix the text gave, and `30d8b667-fixed` cites `30d8b667`.
/// `a1b2c3d4` inside `xa1b2c3d4` or a longer hex string (a 9-digit commit sha,
/// a content hash) is not a citation.
///
/// A hyphenated 4-letter hex WORD after an id (`30d8b667-face`) is read as a
/// group and narrows the prefix here; the lint falls back past it when the
/// longer prefix names no readable claim (see [`lint_prefixes`]). Partial
/// groups (`30d8b667-0c`) are never kept.
#[must_use]
pub fn cited_id_tokens(text: &str) -> Vec<String> {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    fn uuid_prefix(tok: &str) -> Option<String> {
        let mut kept: Vec<&str> = Vec::new();
        for (seg, want) in tok.split('-').zip(GROUPS) {
            if seg.len() == want && seg.chars().all(|c| c.is_ascii_hexdigit()) {
                kept.push(seg);
            } else {
                break;
            }
        }
        (!kept.is_empty()).then(|| kept.join("-").to_ascii_lowercase())
    }
    let mut out: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let bytes_ok = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    for raw in text.split(|c: char| !bytes_ok(c)) {
        if let Some(t) = uuid_prefix(raw.trim_matches('-')) {
            if seen.insert(t.clone()) {
                out.push(t);
            }
        }
    }
    out
}

/// The prefixes the lint looks a cited token up at, longest first: the token
/// itself, then, while its last group is a 4-letter hex WORD (only `a`-`f`,
/// as in `face`, `beef`, `cafe`), the token without that group. The first
/// that names a readable claim is the citation's precision, so
/// `30d8b667-face` in prose resolves at `30d8b667` unless a claim really
/// starts `30d8b667-face`.
///
/// Only all-letter 4-hex groups are dropped. A group with a digit
/// (`30d8b667-0ca4`) and a full uuid (its last group is 12 hex) are what the
/// author wrote as an id; falling back past them could re-point the citation
/// at a sibling claim under the same head, so they resolve at full precision
/// or not at all.
#[must_use]
pub fn lint_prefixes(token: &str) -> Vec<String> {
    let mut groups: Vec<&str> = token.split('-').collect();
    let mut out = vec![token.to_string()];
    while groups.len() > 1 {
        let last = groups[groups.len() - 1];
        if last.len() != 4 || !last.chars().all(|c| matches!(c, 'a'..='f' | 'A'..='F')) {
            break;
        }
        groups.pop();
        out.push(groups.join("-"));
    }
    out
}

#[derive(Debug, Serialize)]
struct Citation {
    /// The prefix the citation resolved at; the token as written when it
    /// resolved at none.
    token: String,
    /// The token as written, present only when the lint fell back to a
    /// shorter prefix ([`lint_prefixes`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    cited_as: Option<String>,
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

    // (token resolved at, token as written, readable matches), deduplicated
    // on the resolved token: `30d8b667-face` falling back to `30d8b667` is
    // the same citation as a later bare `30d8b667`.
    let mut resolved: Vec<(String, String, Vec<Uuid>)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut all: Vec<Uuid> = Vec::new();
    for written in tokens {
        let mut at = written.clone();
        let mut ids: Vec<Uuid> = Vec::new();
        for prefix in lint_prefixes(&written) {
            let Some((lo, hi)) = id_prefix_bounds(&prefix) else {
                break;
            };
            let rows = ClaimIdPrefixRepository::matches(
                &mut *read,
                viewer,
                lo,
                hi,
                LINT_MATCHES_PER_TOKEN,
            )
            .await
            .map_err(internal_error)?;
            if !rows.is_empty() {
                at = prefix;
                ids = rows.into_iter().map(|r| r.id).collect();
                break;
            }
        }
        if !seen.insert(at.clone()) {
            continue;
        }
        all.extend(ids.iter().copied().filter(|m| *m != id));
        resolved.push((at, written, ids));
    }
    all.sort_unstable();
    all.dedup();
    let wired: HashSet<Uuid> = ClaimIdPrefixRepository::wired_to(&mut *read, viewer, id, &all)
        .await
        .map_err(internal_error)?
        .into_iter()
        .collect();
    read.commit().await.map_err(internal_error)?;

    let citations: Vec<Citation> = resolved
        .into_iter()
        .map(|(token, written, ids)| {
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
                cited_as: (written != token).then_some(written),
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
    fn a_partial_hyphenated_uuid_keeps_its_whole_groups() {
        // Review finding: `30d8b667-0ca4` names more than `30d8b667`; cutting
        // it to the 8-hex head turned a unique citation into an ambiguous one.
        assert_eq!(
            cited_id_tokens("see 30d8b667-0CA4, 30d8b667-0ca4-4b7f and 30d8b667-0c"),
            vec!["30d8b667-0ca4", "30d8b667-0ca4-4b7f", "30d8b667"]
        );
        // A full uuid with a trailing word is cited as the uuid.
        assert_eq!(
            cited_id_tokens("1a2b3c4d-0ca4-4b7f-aa85-000000000001-old"),
            vec!["1a2b3c4d-0ca4-4b7f-aa85-000000000001"]
        );
    }

    #[test]
    fn the_lint_falls_back_only_past_trailing_hex_words() {
        // Backlog `5120795e`: `30d8b667-face` must also be looked up as
        // `30d8b667`, longest first.
        assert_eq!(
            lint_prefixes("30d8b667-face"),
            vec!["30d8b667-face", "30d8b667"]
        );
        assert_eq!(
            lint_prefixes("30d8b667-cafe-babe"),
            vec!["30d8b667-cafe-babe", "30d8b667-cafe", "30d8b667"]
        );
        // The fallback stops at a group with a digit...
        assert_eq!(
            lint_prefixes("30d8b667-0ca4-beef"),
            vec!["30d8b667-0ca4-beef", "30d8b667-0ca4"]
        );
        assert_eq!(lint_prefixes("30d8b667-0ca4"), vec!["30d8b667-0ca4"]);
        // ...never drops the head, even an all-letter one...
        assert_eq!(lint_prefixes("abcdefab"), vec!["abcdefab"]);
        assert_eq!(
            lint_prefixes("abcdefab-face"),
            vec!["abcdefab-face", "abcdefab"]
        );
        // ...and never shortens a full uuid.
        assert_eq!(
            lint_prefixes("30d8b667-aaaa-bbbb-cccc-dddddddddddd"),
            vec!["30d8b667-aaaa-bbbb-cccc-dddddddddddd"]
        );
    }

    #[test]
    fn a_bare_eight_digit_date_is_still_a_candidate() {
        // An 8-digit date is hex too; the lint reports it as unresolved
        // rather than guessing, since a real id prefix can be all digits.
        assert_eq!(cited_id_tokens("on 20261114"), vec!["20261114"]);
    }
}
