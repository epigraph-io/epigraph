//! Pure presentation for the entities pages: formatting, query parsing,
//! evidence-type normalisation, safe outbound links, duplicate detection in
//! version histories, and the provenance-chain layout. No I/O.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};
use url::{form_urlencoded, Url};
use uuid::Uuid;

use crate::links::Links;
use crate::upstream::entities::ClaimVersion;
use crate::upstream::{truncate_chars, ChainNode, ProvenanceChainResponse, REDACTED};

/// What a redacted claim reads as on these pages.
pub const HIDDEN_TEXT: &str = "Content hidden. You do not have access to this claim's text.";
/// Highest `?page=` honoured; keeps upstream offsets small and finite.
pub const MAX_PAGE: u32 = 10_000;
/// `?max_depth=` on the provenance page when absent or unparseable
/// (the MCP tool's default, plan §2.1).
pub const DEFAULT_PROVENANCE_DEPTH: u32 = 4;

// ---- formatting ----------------------------------------------------------------

/// A probability-like number to two places, or an em dash.
pub fn fmt_prob(v: Option<f64>) -> String {
    match v {
        Some(x) if x.is_finite() => format!("{x:.2}"),
        _ => "—".into(),
    }
}

/// A fraction as a whole percentage; tiny non-zero shares read `<1%`.
pub fn fmt_pct(v: f64) -> String {
    if !v.is_finite() {
        return "—".into();
    }
    let pct = v * 100.0;
    if pct > 0.0 && pct < 0.5 {
        "<1%".into()
    } else {
        format!("{pct:.0}%")
    }
}

/// An upstream timestamp as `YYYY-MM-DD HH:MM UTC`. Upstream mixes `Z` and
/// `+00:00`; anything unparseable is shown as sent (cut to 40 chars).
pub fn fmt_time(raw: Option<&str>) -> String {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return "—".into();
    };
    match DateTime::parse_from_rfc3339(raw) {
        Ok(t) => t
            .with_timezone(&Utc)
            .format("%Y-%m-%d %H:%M UTC")
            .to_string(),
        Err(_) => truncate_chars(raw, 40),
    }
}

/// First 8 hex digits of a UUID, for compact references.
pub fn short_id(id: Uuid) -> String {
    let s = id.simple().to_string();
    s[..8].to_string()
}

/// Claim text ready for a template: cut on a char boundary, with redaction
/// made explicit so templates can style it (`.claim-text--redacted`).
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimText {
    pub text: String,
    pub redacted: bool,
    /// True when the text was cut to fit.
    pub cut: bool,
}

pub fn claim_text(content: &str, max_chars: usize) -> ClaimText {
    let trimmed = content.trim();
    if trimmed == REDACTED {
        return ClaimText {
            text: HIDDEN_TEXT.into(),
            redacted: true,
            cut: false,
        };
    }
    if trimmed.is_empty() {
        return ClaimText {
            text: "(no text recorded)".into(),
            redacted: false,
            cut: false,
        };
    }
    let text = truncate_chars(trimmed, max_chars);
    let cut = text.len() != trimmed.len();
    ClaimText {
        text,
        redacted: false,
        cut,
    }
}

// ---- query parsing ---------------------------------------------------------------

/// The last value of `key` in a raw query string. Hand-parsed rather than
/// `Query<T>` so a repeated or odd parameter can never turn into a 400.
pub fn query_param(raw: Option<&str>, key: &str) -> Option<String> {
    form_urlencoded::parse(raw.unwrap_or("").as_bytes())
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .last()
}

/// `?page=` → `1..=MAX_PAGE`; anything unparseable is page 1.
pub fn parse_page(raw: Option<&str>) -> u32 {
    raw.and_then(|s| s.trim().parse::<u64>().ok())
        .map(|p| p.clamp(1, u64::from(MAX_PAGE)) as u32)
        .unwrap_or(1)
}

/// `?max_depth=` → `lo..=hi`; anything unparseable is `default`. A wide
/// integer is parsed first so `-3` and `300` clamp instead of failing.
pub fn parse_depth(raw: Option<&str>, default: u32, (lo, hi): (u32, u32)) -> u32 {
    match raw.and_then(|s| s.trim().parse::<i64>().ok()) {
        Some(d) => d.clamp(i64::from(lo), i64::from(hi)) as u32,
        None => default.clamp(lo, hi),
    }
}

/// `value` if it is one of `allowed`, else the first allowed value.
pub fn one_of(value: Option<&str>, allowed: &[&'static str]) -> &'static str {
    value
        .and_then(|v| allowed.iter().find(|a| a.eq_ignore_ascii_case(v.trim())))
        .copied()
        .unwrap_or(allowed[0])
}

// ---- evidence ----------------------------------------------------------------------

/// A display evidence type. Upstream has three vocabularies for one row
/// (`/claims/:id/evidence`, `/evidence/:id`, `/search/evidence`; plan §3.4),
/// so every page shows this normalised label, plus the recorded value when
/// it differs.
#[derive(Debug, Clone, PartialEq)]
pub struct EvidenceKind {
    pub label: String,
    pub recorded_as: Option<String>,
}

pub fn evidence_kind(raw: Option<&str>) -> EvidenceKind {
    let raw = raw.map(str::trim).unwrap_or("");
    let key = raw.to_ascii_lowercase().replace(['-', ' '], "_");
    let label = match key.as_str() {
        "" | "unknown" | "none" | "null" | "unspecified" => "Unspecified",
        "document" | "documentary" | "doc" => "Document",
        "literature" | "paper" | "publication" | "reference" | "citation" | "article" => {
            "Literature"
        }
        "figure" | "image" | "table" | "chart" => "Figure",
        "observation" | "observational" | "empirical" | "measurement" | "experiment"
        | "experimental" => "Observation",
        "testimony" | "testimonial" => "Testimony",
        "computation" | "computational" | "analytical" | "analysis" | "simulation" => "Analysis",
        "statistical" | "statistics" => "Statistical",
        "conversational" | "conversation" => "Conversation",
        "consensus" => "Consensus",
        _ => {
            return EvidenceKind {
                label: sentence_case(&truncate_chars(&key.replace('_', " "), 40)),
                recorded_as: None,
            }
        }
    };
    EvidenceKind {
        label: label.into(),
        recorded_as: (!raw.is_empty() && !raw.eq_ignore_ascii_case(label))
            .then(|| truncate_chars(raw, 40)),
    }
}

fn sentence_case(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// An outbound link. `href` is `None` when the value is not a safe
/// http(s) URL or DOI: the template then renders plain text, so a hostile
/// `javascript:` value can never become a link.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtLink {
    pub kind: &'static str,
    pub href: Option<String>,
    pub text: String,
}

/// A DOI in any of its usual spellings (`10.x/y`, `doi:10.x/y`,
/// `https://doi.org/10.x/y`, `dx.doi.org`), normalised to `10.x/y`.
pub fn doi_from(raw: &str) -> Option<String> {
    let s = raw.trim();
    let lower = s.to_ascii_lowercase();
    let rest = [
        "https://doi.org/",
        "http://doi.org/",
        "https://dx.doi.org/",
        "http://dx.doi.org/",
        "doi:",
    ]
    .iter()
    .find(|p| lower.starts_with(*p))
    .map_or(s, |p| s[p.len()..].trim_start());
    let (prefix, suffix) = rest.split_once('/')?;
    let valid = prefix.starts_with("10.")
        && prefix.len() > 3
        && prefix[3..].chars().all(|c| c.is_ascii_digit() || c == '.')
        && !suffix.is_empty()
        && !rest.chars().any(|c| c.is_whitespace() || c.is_control());
    valid.then(|| rest.to_string())
}

/// `https://doi.org/<doi>` with the DOI percent-encoded as a path, so `#`,
/// `?` and friends inside a DOI cannot change the link's meaning.
pub fn doi_url(doi: &str) -> Option<String> {
    let doi = doi_from(doi)?;
    let mut u = Url::parse("https://doi.org/").ok()?;
    u.set_path(&doi);
    Some(u.into())
}

/// An absolute http(s) URL with a host, normalised; everything else `None`.
pub fn web_url(raw: &str) -> Option<String> {
    let u = Url::parse(raw.trim()).ok()?;
    (matches!(u.scheme(), "http" | "https") && u.host_str().is_some_and(|h| !h.is_empty()))
        .then(|| u.into())
}

/// Links for an evidence row's `source_url` and `doi`. A DOI in
/// `source_url` becomes `https://doi.org/<doi>` (plan §3.4); a DOI given in
/// both fields is shown once.
pub fn source_links(source_url: Option<&str>, doi: Option<&str>) -> Vec<ExtLink> {
    let mut out = Vec::new();
    let mut shown_doi: Option<String> = None;
    if let Some(s) = source_url.map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(d) = doi_from(s) {
            out.push(ExtLink {
                kind: "DOI",
                href: doi_url(&d),
                text: format!("doi:{}", truncate_chars(&d, 120)),
            });
            shown_doi = Some(d.to_ascii_lowercase());
        } else {
            out.push(ExtLink {
                kind: "Source",
                href: web_url(s),
                text: truncate_chars(s, 120),
            });
        }
    }
    if let Some(d) = doi.map(str::trim).filter(|d| !d.is_empty()) {
        match doi_from(d) {
            Some(n) if shown_doi.as_deref() == Some(n.to_ascii_lowercase().as_str()) => {}
            Some(n) => out.push(ExtLink {
                kind: "DOI",
                href: doi_url(&n),
                text: format!("doi:{}", truncate_chars(&n, 120)),
            }),
            None => out.push(ExtLink {
                kind: "DOI",
                href: None,
                text: truncate_chars(d, 120),
            }),
        }
    }
    out
}

// ---- agents ------------------------------------------------------------------------

/// `https://orcid.org/<id>` for a well-formed ORCID iD (bare or as a URL).
pub fn orcid_url(raw: &str) -> Option<String> {
    let s = raw.trim();
    let id = ["https://orcid.org/", "http://orcid.org/"]
        .iter()
        .find_map(|p| s.strip_prefix(p))
        .unwrap_or(s);
    let groups: Vec<&str> = id.split('-').collect();
    let valid = groups.len() == 4
        && groups.iter().enumerate().all(|(i, g)| {
            g.len() == 4
                && g.chars().enumerate().all(|(j, c)| {
                    c.is_ascii_digit() || (i == 3 && j == 3 && (c == 'X' || c == 'x'))
                })
        });
    valid.then(|| format!("https://orcid.org/{}", id.to_ascii_uppercase()))
}

/// `https://ror.org/<id>` for a well-formed ROR id (bare or as a URL).
pub fn ror_url(raw: &str) -> Option<String> {
    let s = raw.trim();
    let id = ["https://ror.org/", "http://ror.org/"]
        .iter()
        .find_map(|p| s.strip_prefix(p))
        .unwrap_or(s);
    let valid = id.len() == 9 && id.chars().all(|c| c.is_ascii_alphanumeric());
    valid.then(|| format!("https://ror.org/{}", id.to_ascii_lowercase()))
}

/// One row of a share table (`<meter>` value plus a percentage label).
#[derive(Debug, Clone, PartialEq)]
pub struct ShareRow {
    pub label: String,
    /// `0..=1`, three places, for `<meter value>`.
    pub value: String,
    pub pct: String,
}

/// Largest shares first, at most `cap` rows; `label` maps each key.
pub fn share_rows(
    map: &BTreeMap<String, f64>,
    cap: usize,
    label: impl Fn(&str) -> String,
) -> Vec<ShareRow> {
    let mut rows: Vec<(&String, f64)> = map
        .iter()
        .map(|(k, v)| (k, if v.is_finite() { *v } else { 0.0 }))
        .collect();
    rows.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    rows.into_iter()
        .take(cap)
        .map(|(k, v)| ShareRow {
            label: label(k),
            value: format!("{:.3}", v.clamp(0.0, 1.0)),
            pct: fmt_pct(v),
        })
        .collect()
}

/// `refuted` → `Refuted`, `meta_analysis` → `Meta analysis`.
pub fn humanise_key(key: &str) -> String {
    sentence_case(&truncate_chars(key.trim(), 60).replace('_', " "))
}

// ---- history -----------------------------------------------------------------------

/// For each version, the index of the version it is a duplicate of, when it
/// was (by inference) reached through `mark_duplicate` rather than a real
/// supersession.
///
/// `mark_duplicate` writes `dup.supersedes = canonical` and retires the
/// duplicate, so `/history` lists the duplicate as a *later* version that is
/// not current (claims-endpoints §7). A real supersession always leaves a
/// newer version behind. So a later version is a duplicate of its
/// predecessor when it is not current and either the predecessor is still
/// current, or nothing supersedes it (it is the last version and has no
/// `superseded_by`).
pub fn duplicate_of(versions: &[ClaimVersion]) -> Vec<Option<usize>> {
    versions
        .iter()
        .enumerate()
        .map(|(i, v)| {
            if i == 0 || v.is_current {
                return None;
            }
            let prev_current = versions[i - 1].is_current;
            let dead_end = i + 1 == versions.len() && v.superseded_by.is_none();
            (prev_current || dead_end).then_some(i - 1)
        })
        .collect()
}

// ---- provenance chain --------------------------------------------------------------

/// A compact, linked mention of a claim in the chain.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeRef {
    pub url: String,
    pub label: String,
    pub redacted: bool,
}

/// One edge, read from the node it is listed under.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainLink {
    /// "supports", "superseded by", … (`{node} {phrase} {other}`).
    pub phrase: String,
    pub other: NodeRef,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainNodeView {
    pub id: Uuid,
    pub url: String,
    pub text: ClaimText,
    /// `is_current == false`: a superseded ancestor.
    pub superseded: bool,
    pub truth: String,
    pub labels: Vec<String>,
    pub in_cycle: bool,
    pub links: Vec<ChainLink>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainLevel {
    pub depth: u32,
    pub title: String,
    pub nodes: Vec<ChainNodeView>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainLayout {
    /// Depth 0 (the root) first.
    pub levels: Vec<ChainLevel>,
    /// Each cycle as a closed walk (the first node repeated at the end).
    pub cycles: Vec<Vec<NodeRef>>,
    /// Nodes other than the root.
    pub ancestor_count: usize,
}

/// Longest claim text shown per chain node.
const CHAIN_TEXT_CHARS: usize = 400;
/// Longest claim text in a [`NodeRef`].
const REF_TEXT_CHARS: usize = 90;
/// Labels shown per chain node.
const CHAIN_LABELS: usize = 6;

fn is_hidden(n: &ChainNode) -> bool {
    n.redacted || n.content.trim() == REDACTED
}

/// Group the chain by depth and attach every edge to exactly one node.
///
/// Upstream stores evidence relationships ancestor → descendant and
/// `supersedes` new → old, and sends edges in arbitrary order. Each edge is
/// listed under its *upstream* end — the deeper endpoint (ties go to the
/// source) — and phrased from that node: "A supports B", "O superseded by
/// N". So the root (depth 0) shows no edges of its own and every ancestor
/// says how it feeds the claims below it.
pub fn layout_chain(chain: &ProvenanceChainResponse, links: &Links) -> ChainLayout {
    let by_id: HashMap<Uuid, &ChainNode> = chain.nodes.iter().map(|n| (n.id, n)).collect();
    let in_cycle: HashSet<Uuid> = chain.cycles.iter().flatten().copied().collect();

    let node_ref = |id: Uuid| -> NodeRef {
        match by_id.get(&id) {
            Some(n) if is_hidden(n) => NodeRef {
                url: links.claim(id),
                label: format!("Hidden claim {}", short_id(id)),
                redacted: true,
            },
            Some(n) if !n.content.trim().is_empty() => NodeRef {
                url: links.claim(id),
                label: truncate_chars(n.content.trim(), REF_TEXT_CHARS),
                redacted: false,
            },
            _ => NodeRef {
                url: links.claim(id),
                label: format!("Claim {}", short_id(id)),
                redacted: false,
            },
        }
    };

    let mut edge_links: HashMap<Uuid, Vec<ChainLink>> = HashMap::new();
    for e in &chain.edges {
        let depth = |id: Uuid| by_id.get(&id).map(|n| n.depth);
        let holder_is_source = match (depth(e.source), depth(e.target)) {
            (Some(s), Some(t)) => s >= t,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => continue,
        };
        let (holder, other) = if holder_is_source {
            (e.source, e.target)
        } else {
            (e.target, e.source)
        };
        edge_links.entry(holder).or_default().push(ChainLink {
            phrase: relationship_phrase(&e.relationship, holder_is_source),
            other: node_ref(other),
        });
    }
    for v in edge_links.values_mut() {
        v.sort_by(|a, b| {
            (a.phrase.as_str(), a.other.label.as_str())
                .cmp(&(b.phrase.as_str(), b.other.label.as_str()))
        });
        v.dedup();
    }

    // Upstream order is topological with the root last; reversed, each level
    // reads from the claims nearest the root outwards.
    let mut levels: BTreeMap<u32, Vec<ChainNodeView>> = BTreeMap::new();
    for n in chain.nodes.iter().rev() {
        let depth = if n.id == chain.root { 0 } else { n.depth };
        let text = if is_hidden(n) {
            claim_text(REDACTED, CHAIN_TEXT_CHARS)
        } else {
            claim_text(&n.content, CHAIN_TEXT_CHARS)
        };
        levels.entry(depth).or_default().push(ChainNodeView {
            id: n.id,
            url: links.claim(n.id),
            text,
            superseded: n.is_current == Some(false),
            truth: fmt_prob(n.truth_value),
            labels: n
                .labels
                .iter()
                .take(CHAIN_LABELS)
                .map(|l| truncate_chars(l, 60))
                .collect(),
            in_cycle: in_cycle.contains(&n.id),
            links: edge_links.remove(&n.id).unwrap_or_default(),
        });
    }

    let cycles = chain
        .cycles
        .iter()
        .filter(|c| !c.is_empty())
        .map(|c| {
            let mut walk: Vec<NodeRef> = c.iter().map(|id| node_ref(*id)).collect();
            if c.len() > 1 && c.first() != c.last() {
                walk.push(node_ref(c[0]));
            }
            walk
        })
        .collect();

    ChainLayout {
        levels: levels
            .into_iter()
            .map(|(depth, nodes)| ChainLevel {
                depth,
                title: match depth {
                    0 => "This claim".to_string(),
                    1 => "Direct sources · depth 1".to_string(),
                    d => format!("Depth {d}"),
                },
                nodes,
            })
            .collect(),
        cycles,
        ancestor_count: chain.nodes.iter().filter(|n| n.id != chain.root).count(),
    }
}

/// How an edge reads from the node it is listed under. `from_source`: that
/// node is the edge's stored source ("A supports B"); otherwise it is the
/// target and the phrase is passive ("O superseded by N").
pub fn relationship_phrase(relationship: &str, from_source: bool) -> String {
    let key = relationship.trim().to_ascii_lowercase();
    let human = truncate_chars(&key.replace('_', " "), 40);
    if from_source {
        return if human.is_empty() {
            "linked to".into()
        } else {
            human
        };
    }
    match key.as_str() {
        "supersedes" => "superseded by".into(),
        "supports" => "supported by".into(),
        "corroborates" => "corroborated by".into(),
        "elaborates" => "elaborated by".into(),
        "decomposes_to" => "part of".into(),
        "" => "linked from".into(),
        _ => format!("target of {human} from"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::{ChainEdge, ChainNode};

    fn uid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn links() -> Links {
        Links::new("https://explorer.example.com", "/explorer")
    }

    #[test]
    fn numbers_and_times() {
        assert_eq!(fmt_prob(Some(0.456)), "0.46");
        assert_eq!(fmt_prob(None), "—");
        assert_eq!(fmt_prob(Some(f64::NAN)), "—");
        assert_eq!(fmt_pct(0.421), "42%");
        assert_eq!(fmt_pct(0.001), "<1%");
        assert_eq!(fmt_pct(0.0), "0%");
        assert_eq!(
            fmt_time(Some("2026-01-02T03:04:05Z")),
            "2026-01-02 03:04 UTC"
        );
        assert_eq!(
            fmt_time(Some("2026-01-02T05:04:05+02:00")),
            "2026-01-02 03:04 UTC"
        );
        assert_eq!(fmt_time(Some("yesterday")), "yesterday");
        assert_eq!(fmt_time(None), "—");
        assert_eq!(
            short_id(uid(0xabcdef12_0000_0000_0000_000000000000)),
            "abcdef12"
        );
    }

    #[test]
    fn claim_text_redacts_and_cuts_on_chars() {
        let t = claim_text("[REDACTED]", 10);
        assert!(t.redacted && t.text == HIDDEN_TEXT);
        let t = claim_text("μμμμμ", 3);
        assert_eq!(t.text, "μμμ…");
        assert!(t.cut);
        let t = claim_text("  short ", 10);
        assert_eq!(t.text, "short");
        assert!(!t.cut);
    }

    #[test]
    fn query_params_clamp_and_never_fail() {
        assert_eq!(
            query_param(Some("page=2&page=3"), "page").as_deref(),
            Some("3")
        );
        assert_eq!(query_param(None, "page"), None);
        assert_eq!(parse_page(Some("0")), 1);
        assert_eq!(parse_page(Some("abc")), 1);
        assert_eq!(parse_page(Some("99999999999")), MAX_PAGE);
        assert_eq!(parse_page(Some(" 7 ")), 7);
        assert_eq!(parse_depth(Some("300"), 4, (1, 8)), 8);
        assert_eq!(parse_depth(Some("-3"), 4, (1, 8)), 1);
        assert_eq!(parse_depth(Some("x"), 4, (1, 8)), 4);
        assert_eq!(parse_depth(None, 4, (1, 8)), 4);
        assert_eq!(
            one_of(Some("PLAUSIBILITY"), &["belief", "plausibility"]),
            "plausibility"
        );
        assert_eq!(
            one_of(Some("drop table"), &["belief", "plausibility"]),
            "belief"
        );
    }

    #[test]
    fn evidence_types_normalise_across_vocabularies() {
        for (raw, label) in [
            ("empirical", "Observation"),
            ("observation", "Observation"),
            ("testimonial", "Testimony"),
            ("testimony", "Testimony"),
            ("analytical", "Analysis"),
            ("computation", "Analysis"),
            ("statistical", "Statistical"),
            ("figure", "Figure"),
            ("document", "Document"),
            ("reference", "Literature"),
            ("conversational", "Conversation"),
            ("unknown", "Unspecified"),
        ] {
            assert_eq!(evidence_kind(Some(raw)).label, label, "{raw}");
        }
        assert_eq!(evidence_kind(Some("Document")).recorded_as, None);
        assert_eq!(
            evidence_kind(Some("empirical")).recorded_as.as_deref(),
            Some("empirical")
        );
        assert_eq!(evidence_kind(None).label, "Unspecified");
        assert_eq!(evidence_kind(None).recorded_as, None);
        assert_eq!(evidence_kind(Some("meta_analysis")).label, "Meta analysis");
    }

    #[test]
    fn dois_become_doi_org_links() {
        assert_eq!(doi_from("10.1000/xyz").as_deref(), Some("10.1000/xyz"));
        assert_eq!(doi_from("doi: 10.1000/xyz").as_deref(), Some("10.1000/xyz"));
        assert_eq!(
            doi_from("https://doi.org/10.1000/xyz").as_deref(),
            Some("10.1000/xyz")
        );
        assert_eq!(
            doi_from("DOI:10.1000/a(b)c").as_deref(),
            Some("10.1000/a(b)c")
        );
        assert_eq!(doi_from("10.1000"), None);
        assert_eq!(doi_from("11.1000/x"), None);
        assert_eq!(doi_from("10.10 00/x"), None);
        assert_eq!(doi_from("https://example.com/10.1/x"), None);
        assert_eq!(
            doi_url("10.1000/a#b?c").as_deref(),
            Some("https://doi.org/10.1000/a%23b%3Fc")
        );
    }

    #[test]
    fn only_http_urls_become_links() {
        assert_eq!(
            web_url("https://api.example.com/paper.pdf").as_deref(),
            Some("https://api.example.com/paper.pdf")
        );
        assert_eq!(web_url("javascript:alert(1)"), None);
        assert_eq!(web_url("data:text/html,x"), None);
        assert_eq!(web_url("/relative/path"), None);
        assert_eq!(web_url("mailto:a@example.com"), None);

        let l = source_links(Some("javascript:alert(1)"), None);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].href, None);
        assert_eq!(l[0].text, "javascript:alert(1)");

        // A DOI in source_url becomes a doi.org link; the same DOI in `doi` is not repeated.
        let l = source_links(Some("10.1000/XYZ"), Some("https://doi.org/10.1000/xyz"));
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].href.as_deref(), Some("https://doi.org/10.1000/XYZ"));

        let l = source_links(Some("https://api.example.com/a"), Some("10.1/b"));
        assert_eq!(l.len(), 2);
        assert_eq!(l[1].href.as_deref(), Some("https://doi.org/10.1/b"));

        let l = source_links(None, Some("not a doi"));
        assert_eq!(l[0].href, None);
        assert!(source_links(Some("  "), None).is_empty());
    }

    #[test]
    fn orcid_and_ror() {
        assert_eq!(
            orcid_url("0000-0002-1825-009x").as_deref(),
            Some("https://orcid.org/0000-0002-1825-009X")
        );
        assert_eq!(
            orcid_url("https://orcid.org/0000-0002-1825-0097").as_deref(),
            Some("https://orcid.org/0000-0002-1825-0097")
        );
        assert_eq!(orcid_url("0000-0002-1825"), None);
        assert_eq!(orcid_url("javascript:alert(1)"), None);
        assert_eq!(
            ror_url("05dxps055").as_deref(),
            Some("https://ror.org/05dxps055")
        );
        assert_eq!(
            ror_url("https://ror.org/05dxps055").as_deref(),
            Some("https://ror.org/05dxps055")
        );
        assert_eq!(ror_url("05dx/ps05"), None);
    }

    #[test]
    fn share_rows_sort_and_cap() {
        let m = BTreeMap::from([
            ("a".to_string(), 0.2),
            ("b".to_string(), 0.7),
            ("c".to_string(), 0.1),
        ]);
        let rows = share_rows(&m, 2, humanise_key);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].label, "B");
        assert_eq!(rows[0].value, "0.700");
        assert_eq!(rows[0].pct, "70%");
    }

    fn version(n: u32, current: bool, superseded_by: Option<Uuid>) -> ClaimVersion {
        ClaimVersion {
            claim_id: uid(u128::from(n)),
            content: format!("v{n}"),
            truth_value: None,
            version: n,
            is_current: current,
            created_at: None,
            superseded_by,
        }
    }

    #[test]
    fn duplicates_are_inferred_from_retirement_shape() {
        // Plain supersession: v1 → v2 (current).
        let v = [version(1, false, Some(uid(2))), version(2, true, None)];
        assert_eq!(duplicate_of(&v), [None, None]);

        // mark_duplicate: the canonical stays current, the dup follows it.
        let v = [version(1, true, None), version(2, false, None)];
        assert_eq!(duplicate_of(&v), [None, Some(0)]);

        // Canonical later superseded elsewhere; the walk picked the dup.
        let v = [version(1, false, Some(uid(2))), version(2, false, None)];
        assert_eq!(duplicate_of(&v), [None, Some(0)]);

        // Middle version retired by a real supersession is not a duplicate.
        let v = [
            version(1, false, Some(uid(2))),
            version(2, false, Some(uid(3))),
            version(3, true, None),
        ];
        assert_eq!(duplicate_of(&v), [None, None, None]);
        assert!(duplicate_of(&[]).is_empty());
    }

    fn node(n: u128, depth: u32, content: &str) -> ChainNode {
        ChainNode {
            id: uid(n),
            content: content.into(),
            truth_value: Some(0.5),
            labels: vec![],
            is_current: Some(true),
            depth,
            redacted: false,
        }
    }

    fn edge(s: u128, t: u128, rel: &str) -> ChainEdge {
        ChainEdge {
            source: uid(s),
            target: uid(t),
            relationship: rel.into(),
        }
    }

    #[test]
    fn chain_levels_edges_cycles_and_redaction() {
        let mut old = node(3, 1, "old version");
        old.is_current = Some(false);
        let mut hidden = node(4, 2, "[REDACTED]");
        hidden.redacted = true;
        let chain = ProvenanceChainResponse {
            root: uid(1),
            // Evidence first, root last.
            nodes: vec![
                hidden,
                node(2, 1, "evidence claim"),
                old,
                node(1, 0, "root"),
            ],
            edges: vec![
                edge(2, 1, "supports"),
                edge(1, 3, "SUPERSEDES"),
                edge(4, 2, "decomposes_to"),
                edge(2, 4, "corroborates"),
            ],
            truncated: false,
            cycles: vec![vec![uid(2), uid(4)]],
        };
        let l = layout_chain(&chain, &links());
        assert_eq!(l.ancestor_count, 3);
        assert_eq!(
            l.levels.iter().map(|x| x.depth).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(l.levels[0].nodes.len(), 1);
        assert!(l.levels[0].nodes[0].links.is_empty(), "root lists no edges");

        let lvl1 = &l.levels[1].nodes;
        let ev = lvl1.iter().find(|n| n.id == uid(2)).unwrap();
        assert_eq!(ev.links.len(), 1);
        assert_eq!(ev.links[0].phrase, "supports");
        assert_eq!(ev.links[0].other.label, "root");
        assert!(ev.in_cycle);

        let old = lvl1.iter().find(|n| n.id == uid(3)).unwrap();
        assert!(old.superseded);
        assert_eq!(old.links[0].phrase, "superseded by");

        let hidden = &l.levels[2].nodes[0];
        assert!(hidden.text.redacted);
        assert!(!hidden.text.text.contains("REDACTED"));
        // The deeper end holds both edges between 2 and 4.
        let phrases: Vec<_> = hidden.links.iter().map(|x| x.phrase.as_str()).collect();
        assert_eq!(phrases, ["corroborated by", "decomposes to"]);

        assert_eq!(l.cycles.len(), 1);
        let walk: Vec<_> = l.cycles[0].iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            walk,
            ["evidence claim", "Hidden claim 00000000", "evidence claim"]
        );
        assert!(l.cycles[0][1].redacted);
    }

    #[test]
    fn chain_edges_to_unknown_nodes_still_link() {
        let chain = ProvenanceChainResponse {
            root: uid(1),
            nodes: vec![node(1, 0, "root")],
            edges: vec![edge(9, 1, "supports"), edge(8, 7, "supports")],
            truncated: true,
            cycles: vec![],
        };
        let l = layout_chain(&chain, &links());
        // Edge 9 → 1: only the target is known, so it is listed on the root.
        let root = &l.levels[0].nodes[0];
        assert_eq!(root.links.len(), 1);
        assert_eq!(root.links[0].phrase, "supported by");
        assert!(root.links[0].other.label.starts_with("Claim "));
        assert_eq!(l.ancestor_count, 0);
        assert_eq!(
            relationship_phrase("RELATES_TO", false),
            "target of relates to from"
        );
        assert_eq!(relationship_phrase("", true), "linked to");
    }
}
