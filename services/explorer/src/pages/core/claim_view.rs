//! The composed claim view behind `/claim/:id` and `/bff/claim/:id`
//! (plan §3.4).
//!
//! `GET /claims/:id` is required (404 page / 502 page / login redirect).
//! Everything else is an optional section fetched concurrently under the
//! global upstream semaphore and degraded independently. When the claim
//! comes back `"[REDACTED]"` no other sub-call is made at all: several of
//! them (`/evidence`, `/challenges`, …) do not redact upstream.

use serde::Serialize;
use uuid::Uuid;

use super::relationships::{group_outlinks, Outlinks};
use super::vocab::{
    evidence_type_label, fmt_date, fmt_datetime, fmt_prob, one_line, short_id, source_link,
    SourceLink,
};
use crate::error::{not_found_as, AppError};
use crate::links::Links;
use crate::upstream::core::{ChallengeList, ClaimEvidence, ClaimProvenance, EvidenceEdgeList};
use crate::upstream::{
    degrade, truncate_chars, Api, BeliefResponse, ClaimResponse, Degraded, PlacementResponse,
    DEFAULT_EGO_DEGREE, REDACTED,
};

/// Longest evidence / challenge text rendered inline; the entity page has
/// the rest.
const INLINE_TEXT_CHARS: usize = 600;
/// `og:title` length (char-boundary cut).
pub const OG_TITLE_CHARS: usize = 100;
/// Labels quoted in `og:description`.
const OG_LABELS: usize = 3;

/// Reason given for every section of a redacted claim.
pub const HIDDEN: &str = "Hidden: you cannot see this claim's content.";

/// Links from the claim to its other views.
#[derive(Debug, Clone, Serialize)]
pub struct ClaimUrls {
    pub page: String,
    pub history: String,
    pub provenance: String,
    pub graph: String,
    pub agent: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClaimView {
    pub id: Uuid,
    /// Upstream withheld the content from this viewer.
    pub redacted: bool,
    pub claim: ClaimResponse,
    pub urls: ClaimUrls,
    pub belief: Degraded<BeliefResponse>,
    pub outlinks: Degraded<Outlinks>,
    /// Column-based `/claims/:id/evidence`: the complete list.
    pub evidence: Degraded<Vec<EvidenceRow>>,
    /// `evidence → claim` `SUPPORTS` edges (packet-submitted evidence).
    pub supporting: Degraded<Vec<EdgeEvidenceRow>>,
    /// `evidence → claim` `CONTRADICTS` edges.
    pub contradicting: Degraded<Vec<EdgeEvidenceRow>>,
    pub challenges: Degraded<Vec<ChallengeRow>>,
    /// `/claims/:id/provenance`: claim → trace → evidence.
    pub provenance: Degraded<Vec<ProvenanceRow>>,
    pub placement: Degraded<PlacementView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceRow {
    pub id: String,
    pub href: Option<String>,
    pub evidence_type: String,
    pub type_label: String,
    pub content: String,
    pub source: Option<SourceLink>,
    pub created: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EdgeEvidenceRow {
    pub evidence_id: Uuid,
    pub href: String,
    pub content: Option<String>,
    pub strength: Option<f64>,
    pub created: String,
}

impl EdgeEvidenceRow {
    pub fn strength_display(&self) -> String {
        fmt_prob(self.strength)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChallengeRow {
    pub id: Uuid,
    pub challenge_type: String,
    pub type_label: String,
    pub explanation: String,
    pub state: String,
    pub challenger: String,
    pub challenger_href: Option<String>,
    pub created: Option<String>,
    pub resolved: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceRow {
    pub steps: Vec<ProvenanceStepView>,
    pub source: Option<SourceLink>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceStepView {
    pub id: Uuid,
    pub entity_type: String,
    pub text: String,
    pub href: Option<String>,
}

/// Where the claim sits in the latest clustering run. None of these are
/// permalinks: ids are regenerated whenever clustering re-runs.
#[derive(Debug, Clone, Serialize)]
pub struct PlacementView {
    pub theme_href: Option<String>,
    pub community_href: Option<String>,
    pub neighborhood_href: Option<String>,
    pub run_completed: Option<String>,
}

impl PlacementView {
    pub fn is_empty(&self) -> bool {
        self.theme_href.is_none()
            && self.community_href.is_none()
            && self.neighborhood_href.is_none()
    }
}

impl ClaimView {
    /// The claim text for display (never called for a redacted claim).
    pub fn content(&self) -> &str {
        &self.claim.content
    }

    pub fn short_id(&self) -> String {
        short_id(self.id)
    }

    pub fn truth_display(&self) -> String {
        fmt_prob(self.claim.truth_value)
    }

    pub fn created_display(&self) -> String {
        self.claim
            .created_at
            .as_ref()
            .map(fmt_datetime)
            .unwrap_or_default()
    }

    pub fn updated_display(&self) -> String {
        self.claim
            .updated_at
            .as_ref()
            .map(fmt_datetime)
            .unwrap_or_default()
    }

    /// `(label, value)` rows for the DS belief panel.
    pub fn belief_rows(b: &BeliefResponse) -> Vec<(&'static str, String)> {
        vec![
            ("Belief", fmt_prob(b.belief)),
            ("Plausibility", fmt_prob(b.plausibility)),
            ("Ignorance", fmt_prob(b.ignorance)),
            ("Conflict mass", fmt_prob(b.mass_on_conflict)),
            ("Missing mass", fmt_prob(b.mass_on_missing)),
            ("Mass functions", b.mass_function_count.to_string()),
        ]
    }
}

/// Fetch and compose the claim view for this viewer.
pub async fn compose(api: &Api<'_>, links: &Links, id: Uuid) -> Result<ClaimView, AppError> {
    let claim = api.claim(id).await.map_err(not_found_as("claim"))?;
    let urls = ClaimUrls {
        page: links.claim(id),
        history: links.claim_history(id),
        provenance: links.claim_provenance(id),
        graph: links.claim_graph(id),
        agent: claim.agent_id.map(|a| links.agent(a)),
    };

    if claim.is_redacted() {
        return Ok(ClaimView {
            id,
            redacted: true,
            claim,
            urls,
            belief: Degraded::unavailable(HIDDEN),
            outlinks: Degraded::unavailable(HIDDEN),
            evidence: Degraded::unavailable(HIDDEN),
            supporting: Degraded::unavailable(HIDDEN),
            contradicting: Degraded::unavailable(HIDDEN),
            challenges: Degraded::unavailable(HIDDEN),
            provenance: Degraded::unavailable(HIDDEN),
            placement: Degraded::unavailable(HIDDEN),
        });
    }

    let (belief, ego, evidence, supporting, contradicting, challenges, provenance, placement) = tokio::join!(
        api.belief(id),
        api.ego(id, DEFAULT_EGO_DEGREE, None),
        api.claim_evidence_list(id),
        api.claim_supporting_evidence(id),
        api.claim_contradicting_evidence(id),
        api.claim_challenges(id),
        api.claim_provenance_summary(id),
        api.placement(id),
    );

    Ok(ClaimView {
        id,
        redacted: false,
        claim,
        urls,
        belief: degrade(belief)?,
        outlinks: degrade(ego)?.map(|e| group_outlinks(&e, links)),
        evidence: degrade(evidence)?.map(|v| evidence_rows(v, links)),
        supporting: degrade(supporting)?.map(|v| edge_evidence_rows(v, links)),
        contradicting: degrade(contradicting)?.map(|v| edge_evidence_rows(v, links)),
        challenges: degrade(challenges)?.map(|v| challenge_rows(v, links)),
        provenance: degrade(provenance)?.map(|v| provenance_rows(v, links)),
        placement: degrade(placement)?.map(|p| placement_view(p, links)),
    })
}

fn evidence_rows(list: Vec<ClaimEvidence>, links: &Links) -> Vec<EvidenceRow> {
    list.into_iter()
        .map(|e| EvidenceRow {
            href: Uuid::parse_str(&e.id).ok().map(|i| links.evidence(i)),
            type_label: evidence_type_label(&e.evidence_type),
            content: truncate_chars(e.content.trim(), INLINE_TEXT_CHARS),
            source: e.source_url.as_deref().and_then(source_link),
            created: fmt_date(&e.created_at),
            evidence_type: e.evidence_type,
            id: e.id,
        })
        .collect()
}

fn edge_evidence_rows(list: EvidenceEdgeList, links: &Links) -> Vec<EdgeEvidenceRow> {
    list.evidence
        .into_iter()
        .map(|e| EdgeEvidenceRow {
            href: links.evidence(e.evidence_id),
            evidence_id: e.evidence_id,
            content: e
                .evidence_content
                .as_deref()
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(|c| truncate_chars(c, INLINE_TEXT_CHARS)),
            strength: e.strength,
            created: fmt_date(&e.created_at),
        })
        .collect()
}

fn challenge_rows(list: ChallengeList, links: &Links) -> Vec<ChallengeRow> {
    list.challenges
        .into_iter()
        .map(|c| {
            // The nil UUID stands for a NULL challenger upstream.
            let challenger = c.challenger_id.filter(|a| !a.is_nil());
            ChallengeRow {
                id: c.id,
                type_label: c.challenge_type.replace('_', " "),
                challenge_type: c.challenge_type,
                explanation: truncate_chars(c.explanation.trim(), INLINE_TEXT_CHARS),
                state: if c.state.is_empty() {
                    "unknown".into()
                } else {
                    c.state
                },
                challenger: challenger
                    .map(|a| format!("Agent {}", short_id(a)))
                    .unwrap_or_else(|| "Unknown challenger".into()),
                challenger_href: challenger.map(|a| links.agent(a)),
                created: c.created_at.as_ref().map(fmt_datetime),
                resolved: c.resolved_at.as_ref().map(fmt_datetime),
            }
        })
        .collect()
}

fn provenance_rows(p: ClaimProvenance, links: &Links) -> Vec<ProvenanceRow> {
    p.chains
        .into_iter()
        .map(|chain| ProvenanceRow {
            steps: chain
                .path
                .into_iter()
                .map(|s| {
                    let entity_type = s.entity_type.to_ascii_lowercase();
                    let text = if s.label == REDACTED {
                        "Content hidden".to_string()
                    } else if s.label.trim().is_empty() {
                        format!("{entity_type} {}", short_id(s.id))
                    } else {
                        one_line(&s.label)
                    };
                    ProvenanceStepView {
                        href: links.entity(&entity_type, s.id),
                        id: s.id,
                        entity_type,
                        text,
                    }
                })
                .collect(),
            source: chain
                .source_url
                .as_deref()
                .or(chain.source_doi.as_deref())
                .and_then(source_link),
        })
        .collect()
}

fn placement_view(p: PlacementResponse, links: &Links) -> PlacementView {
    PlacementView {
        theme_href: p.theme_id.map(|i| links.theme(i)),
        community_href: p.cluster_id.map(|i| links.community(i)),
        neighborhood_href: p.neighborhood_id.map(|i| links.neighborhood(i, None)),
        run_completed: p.run_completed_at.as_ref().map(fmt_datetime),
    }
}

/// OpenGraph / Twitter card fields. Built only from content the viewer (or,
/// for an unfurl, an anonymous caller) is allowed to see.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Og {
    pub title: String,
    pub description: String,
    /// Absolute canonical claim URL (from `PUBLIC_BASE_URL`).
    pub url: String,
}

/// A card that says nothing about the claim: for anonymous viewers without
/// `PUBLIC_UNFURL`, and for redacted claims.
pub fn og_generic(url: String) -> Og {
    Og {
        title: "A claim in EpiGraph".into(),
        description: "Sign in to EpiGraph Explorer to read this claim and its evidence.".into(),
        url,
    }
}

/// A card for a readable claim. Never call it with a redacted claim.
pub fn og_for_claim(claim: &ClaimResponse, belief: Option<&BeliefResponse>, url: String) -> Og {
    debug_assert!(!claim.is_redacted());
    let text = one_line(&claim.content);
    let title = if text.is_empty() {
        "A claim in EpiGraph".to_string()
    } else {
        truncate_chars(&text, OG_TITLE_CHARS)
    };
    let mut parts = Vec::new();
    if let Some(t) = claim.truth_value.filter(|t| t.is_finite()) {
        parts.push(format!("Truth value {t:.2}"));
    }
    if let Some(p) = belief
        .and_then(|b| b.pignistic_prob)
        .filter(|p| p.is_finite())
    {
        parts.push(format!("Belief (BetP) {p:.2}"));
    }
    let labels: Vec<String> = claim
        .labels
        .iter()
        .map(|l| one_line(l))
        .filter(|l| !l.is_empty())
        .take(OG_LABELS)
        .map(|l| truncate_chars(&l, 40))
        .collect();
    if !labels.is_empty() {
        parts.push(format!("Labels: {}", labels.join(", ")));
    }
    let description = if parts.is_empty() {
        "A claim in the EpiGraph knowledge graph.".to_string()
    } else {
        parts.join(" · ")
    };
    Og {
        title,
        description,
        url,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claim(content: &str, labels: &[&str]) -> ClaimResponse {
        serde_json::from_value(json!({
            "id": "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10",
            "content": content, "truth_value": 0.8, "labels": labels
        }))
        .unwrap()
    }

    #[test]
    fn og_cuts_on_char_boundaries_and_quotes_first_labels() {
        let long = "μ".repeat(150);
        let og = og_for_claim(&claim(&long, &["a", "b", "c", "d"]), None, "u".into());
        assert_eq!(
            og.title.chars().count(),
            OG_TITLE_CHARS + 1,
            "100 chars + …"
        );
        assert!(og.title.ends_with('…'));
        assert_eq!(og.description, "Truth value 0.80 · Labels: a, b, c");
    }

    #[test]
    fn og_includes_betp_when_known() {
        let b: BeliefResponse = serde_json::from_value(json!({
            "claim_id": "0b9a5a4e-5f43-4c4b-9a52-3f0d1e2c7a10", "belief": 0.6,
            "plausibility": 0.9, "ignorance": 0.3, "mass_on_conflict": null,
            "mass_on_missing": null, "pignistic_prob": 0.75, "mass_function_count": 1
        }))
        .unwrap();
        let og = og_for_claim(&claim("x\ny", &[]), Some(&b), "u".into());
        assert_eq!(og.title, "x y");
        assert_eq!(og.description, "Truth value 0.80 · Belief (BetP) 0.75");
    }

    #[test]
    fn generic_card_has_no_claim_text() {
        let og = og_generic("https://explorer.example.com/explorer/claim/x".into());
        assert_eq!(og.title, "A claim in EpiGraph");
    }
}
