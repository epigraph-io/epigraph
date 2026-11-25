//! The provenance section of `/bff/atlas/claim/{id}` (phase P3b): who filed
//! a claim and, for a claim a document's ingest created, the document with
//! its authors and the ingestion note ("ingested by *human* using *model* on
//! *date*"). OWNED BY THE ATLAS AREA.
//!
//! Built from the kernel's `authored_by` block on `GET /claims/:id`
//! ([`crate::upstream::atlas_provenance`]), read with the viewer's own
//! bearer, so every part the viewer may not see is already `null` upstream.
//! The rules added here:
//!
//! - Primary authors are the kernel's `authors` only. Pending (awaiting
//!   countersignature) and later-added authors are carried in their own
//!   lists and never merged into `authors`.
//! - A document key is linked only when it parses as a DOI (`doi_href`); any
//!   other key (`urn:epigraph:doc:…`) is shown as text with no link.
//! - `model` and `prompt_snapshot_id` come from the kernel's
//!   `prompt_snapshot` alone, which is `null` unless the viewer passes the
//!   kernel's prompt-history gate. Nothing here looks a model up or guesses
//!   one, and the prompt hash is never carried.
//! - Every agent or author links only to the Explorer's own `/agent/{id}`.
//! - Text is clipped to one line; lists are capped. The creating document
//!   carries at most [`PROVENANCE_AUTHORS_CAP`] names across its three lists
//!   (primary authors first), as the kernel does; a corroborating document
//!   carries its title and key only, since the panel shows no more of it.
//! - The whole section is held under [`PROVENANCE_BYTES_CAP`] encoded bytes;
//!   a section over it is unavailable, so the claim panel stays under the
//!   atlas body cap whatever the names hold.
//! - A kernel without the block, or with a `source` this build does not
//!   know, gives an unavailable section, never an error for the panel.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::bff::atlas::{clip, PAPER_DOI_CHARS, PAPER_TITLE_CHARS};
use crate::bff::graph::{one_line, LABEL_CHARS};
use crate::links::Links;
use crate::pages::core::vocab::doi_url;
use crate::upstream::atlas_provenance::{
    AuthorRef, AuthoredBy, Filer, Ingester, PaperAuthor, PaperAuthorship, PromptSnapshot,
};
use crate::upstream::Degraded;

/// Most names carried for the creating document, across its primary,
/// pending and added lists together (the kernel lists at most 50 in all).
pub const PROVENANCE_AUTHORS_CAP: usize = 50;
/// Most affiliations carried per author.
pub const PROVENANCE_AFFILIATIONS_CAP: usize = 3;
/// Most corroborating documents carried (the kernel lists at most 10).
pub const PROVENANCE_DOCUMENTS_CAP: usize = 10;
/// Largest encoded provenance section. Every list at its cap and every text
/// at its clip length, all of control characters (escaped to six bytes
/// each), comes to about 250 KB, so the caps above keep a section under
/// this; it is a tripwire that degrades this section alone rather than
/// pushing the claim panel over `ATLAS_BODY_CAP`.
pub const PROVENANCE_BYTES_CAP: usize = 320 * 1024;
const MODEL_CHARS: usize = 80;
const ROLE_CHARS: usize = 40;

/// Shown when the API's claim read carries no `authored_by` block.
pub const PROVENANCE_UNSUPPORTED: &str =
    "Who filed this claim is not available from this EpiGraph API yet.";
/// Shown when the section would be over [`PROVENANCE_BYTES_CAP`].
pub const PROVENANCE_TOO_LARGE: &str = "Who filed this claim is too long to show here.";
/// Shown when the block has a shape this build cannot show.
pub const PROVENANCE_UNKNOWN: &str =
    "This EpiGraph API describes who filed this claim in a way this Explorer cannot show yet.";

/// An agent or a person, linked to the Explorer's agent page.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PersonOut {
    pub id: Uuid,
    pub name: Option<String>,
    pub href: String,
}

/// Who filed (or ingested) the claim.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FilerOut {
    pub agent: PersonOut,
    /// The human the agent was bound to then; `null` when none.
    pub human: Option<PersonOut>,
    /// From the prompt snapshot only; `null` when the viewer may not see it.
    pub model: Option<String>,
    pub prompt_snapshot_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AuthorOut {
    pub id: Uuid,
    pub name: Option<String>,
    pub href: String,
    /// Only a role other than `author`.
    pub role: Option<String>,
    pub affiliations: Vec<String>,
}

/// A document with its authors, each list kept apart.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DocumentOut {
    pub id: Uuid,
    pub doi: Option<String>,
    pub doi_href: Option<String>,
    pub title: Option<String>,
    pub authors: Vec<AuthorOut>,
    pub pending_authors: Vec<AuthorOut>,
    pub added_authors: Vec<AuthorOut>,
    pub authors_truncated: bool,
}

/// A document that also records the claim: its key and title only (the
/// panel names it and links a DOI; its authors are not shown).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CorroboratingOut {
    pub id: Uuid,
    pub doi: Option<String>,
    pub doi_href: Option<String>,
    pub title: Option<String>,
}

/// The provenance section, tagged by `source` as the kernel tags it.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum ProvenanceOut {
    /// The filer stated the claim.
    Agent {
        filed_at: Option<DateTime<Utc>>,
        filed_by: FilerOut,
        corroborated_by: Vec<CorroboratingOut>,
        corroborated_by_truncated: bool,
    },
    /// A document's ingest created the claim: its authors are the claim's
    /// authors and the filer is shown apart as the ingester.
    Literature {
        filed_at: Option<DateTime<Utc>>,
        paper: DocumentOut,
        ingested_by: FilerOut,
        /// When the creating ingest recorded the claim.
        ingested_at: Option<DateTime<Utc>>,
        corroborated_by: Vec<CorroboratingOut>,
        corroborated_by_truncated: bool,
    },
}

fn name_of(raw: Option<&str>) -> Option<String> {
    raw.map(|n| one_line(n, LABEL_CHARS))
        .filter(|n| !n.is_empty())
}

fn person_out(a: &AuthorRef, links: &Links) -> PersonOut {
    PersonOut {
        id: a.id,
        name: name_of(a.display_name.as_deref()),
        href: links.agent(a.id),
    }
}

fn snapshot_parts(s: Option<&PromptSnapshot>) -> (Option<String>, Option<Uuid>) {
    match s {
        None => (None, None),
        Some(s) => (
            s.model
                .as_deref()
                .map(|m| one_line(m, MODEL_CHARS))
                .filter(|m| !m.is_empty()),
            Some(s.snapshot_id),
        ),
    }
}

fn filer_out(
    agent: &AuthorRef,
    human: Option<&AuthorRef>,
    snapshot: Option<&PromptSnapshot>,
    links: &Links,
) -> FilerOut {
    let (model, prompt_snapshot_id) = snapshot_parts(snapshot);
    FilerOut {
        agent: person_out(agent, links),
        human: human.map(|h| person_out(h, links)),
        model,
        prompt_snapshot_id,
    }
}

fn author_out(a: &PaperAuthor, links: &Links) -> AuthorOut {
    AuthorOut {
        id: a.id,
        name: name_of(a.display_name.as_deref()),
        href: links.agent(a.id),
        role: a
            .role
            .as_deref()
            .map(|r| one_line(r, ROLE_CHARS))
            .filter(|r| !r.is_empty() && !r.eq_ignore_ascii_case("author")),
        affiliations: a
            .affiliations
            .iter()
            .map(|s| one_line(s, LABEL_CHARS))
            .filter(|s| !s.is_empty())
            .take(PROVENANCE_AFFILIATIONS_CAP)
            .collect(),
    }
}

/// At most `*left` of `list`, taking them from `left`; true when cut.
fn authors_out(list: &[PaperAuthor], left: &mut usize, links: &Links) -> (Vec<AuthorOut>, bool) {
    let take = list.len().min(*left);
    *left -= take;
    (
        list.iter()
            .take(take)
            .map(|a| author_out(a, links))
            .collect(),
        take < list.len(),
    )
}

/// A document's clipped key, its DOI link (only when the key parses as a
/// DOI) and its one-line title.
fn key_and_title(d: &PaperAuthorship) -> (Option<String>, Option<String>, Option<String>) {
    let doi = d
        .paper
        .doi
        .as_deref()
        .map(|k| clip(k.trim(), PAPER_DOI_CHARS).0)
        .filter(|k| !k.is_empty());
    let title = d
        .paper
        .title
        .as_deref()
        .map(|t| one_line(t, PAPER_TITLE_CHARS))
        .filter(|t| !t.is_empty());
    (doi.as_deref().and_then(doi_url), doi, title)
}

/// The creating document, with at most [`PROVENANCE_AUTHORS_CAP`] names
/// across its three lists, primary authors first.
pub fn document_out(d: &PaperAuthorship, links: &Links) -> DocumentOut {
    let (doi_href, doi, title) = key_and_title(d);
    let mut left = PROVENANCE_AUTHORS_CAP;
    let (authors, a_cut) = authors_out(&d.authors, &mut left, links);
    let (pending_authors, p_cut) = authors_out(&d.pending_authors, &mut left, links);
    let (added_authors, d_cut) = authors_out(&d.added_authors, &mut left, links);
    DocumentOut {
        id: d.paper.id,
        doi_href,
        doi,
        title,
        authors,
        pending_authors,
        added_authors,
        authors_truncated: d.authors_truncated || a_cut || p_cut || d_cut,
    }
}

fn documents_out(list: &[PaperAuthorship], truncated: bool) -> (Vec<CorroboratingOut>, bool) {
    (
        list.iter()
            .take(PROVENANCE_DOCUMENTS_CAP)
            .map(|d| {
                let (doi_href, doi, title) = key_and_title(d);
                CorroboratingOut {
                    id: d.paper.id,
                    doi,
                    doi_href,
                    title,
                }
            })
            .collect(),
        truncated || list.len() > PROVENANCE_DOCUMENTS_CAP,
    )
}

/// The section, or unavailable when it would encode over
/// [`PROVENANCE_BYTES_CAP`].
fn within_budget(out: ProvenanceOut) -> Degraded<ProvenanceOut> {
    match serde_json::to_vec(&out) {
        Ok(b) if b.len() <= PROVENANCE_BYTES_CAP => Degraded::ok(out),
        Ok(b) => {
            tracing::warn!(bytes = b.len(), "provenance section over its byte budget");
            Degraded::unavailable(PROVENANCE_TOO_LARGE)
        }
        Err(e) => {
            tracing::warn!(error = %e, "provenance section not encodable");
            Degraded::unavailable(PROVENANCE_UNKNOWN)
        }
    }
}

/// When the ingest that created the claim recorded it: the creating ingest
/// of the creating document, else none (never another ingest's date).
pub fn creating_ingest_at(ingesters: &[Ingester], paper: Uuid) -> Option<DateTime<Utc>> {
    ingesters
        .iter()
        .find(|i| i.created_claim && i.paper_id == paper)
        .and_then(|i| i.recorded_at)
}

/// The section from the raw block of `GET /claims/:id` and the claim's
/// `created_at`.
pub fn provenance_out(
    raw: Option<&Value>,
    filed_at: Option<DateTime<Utc>>,
    links: &Links,
) -> Degraded<ProvenanceOut> {
    let Some(raw) = raw.filter(|v| !v.is_null()) else {
        return Degraded::unavailable(PROVENANCE_UNSUPPORTED);
    };
    let block: AuthoredBy = match serde_json::from_value(raw.clone()) {
        Ok(b) => b,
        Err(e) => {
            tracing::info!(error = %e, "authored_by block not decodable");
            return Degraded::unavailable(PROVENANCE_UNKNOWN);
        }
    };
    match block {
        AuthoredBy::Agent {
            agent,
            human,
            prompt_snapshot,
            corroborated_by,
            corroborated_by_truncated,
            ingesters: _,
        } => {
            let (corroborated_by, corroborated_by_truncated) =
                documents_out(&corroborated_by, corroborated_by_truncated);
            within_budget(ProvenanceOut::Agent {
                filed_at,
                filed_by: filer_out(&agent, human.as_ref(), prompt_snapshot.as_ref(), links),
                corroborated_by,
                corroborated_by_truncated,
            })
        }
        AuthoredBy::Literature {
            paper,
            ingested_by,
            corroborated_by,
            corroborated_by_truncated,
            ingesters,
        } => {
            let Filer {
                agent,
                human,
                prompt_snapshot,
            } = &ingested_by;
            let (corroborated_by, corroborated_by_truncated) =
                documents_out(&corroborated_by, corroborated_by_truncated);
            within_budget(ProvenanceOut::Literature {
                filed_at,
                ingested_at: creating_ingest_at(&ingesters, paper.paper.id),
                paper: document_out(&paper, links),
                ingested_by: filer_out(agent, human.as_ref(), prompt_snapshot.as_ref(), links),
                corroborated_by,
                corroborated_by_truncated,
            })
        }
        AuthoredBy::Unknown => Degraded::unavailable(PROVENANCE_UNKNOWN),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const A: &str = "00000000-0000-0000-0000-00000000000a";
    const H: &str = "00000000-0000-0000-0000-00000000000b";
    const P: &str = "00000000-0000-0000-0000-00000000000d";
    const P2: &str = "00000000-0000-0000-0000-0000000000d2";
    const S: &str = "00000000-0000-0000-0000-00000000000e";
    const X: &str = "00000000-0000-0000-0000-00000000000f";

    fn links() -> Links {
        Links::new("https://explorer.example.com", "/explorer")
    }

    fn author(id: &str, name: &str) -> Value {
        json!({"id": id, "display_name": name, "position": 0, "role": "author",
               "affiliations": [], "pending_countersign": false,
               "named_by": null, "added_by": null})
    }

    fn literature(paper_key: &str, snapshot: Value, ingesters: Value) -> Value {
        json!({
            "source": "literature",
            "paper": {"paper": {"id": P, "doi": paper_key, "title": "A  paper\ntitle"},
                      "authors": [author(H, "Ada Lovelace")],
                      "pending_authors": [author(X, "Pending Person")],
                      "added_authors": [author(S, "Added Person")],
                      "authors_truncated": false},
            "ingested_by": {"agent": {"id": A, "display_name": "ingest-bot"},
                            "human": {"id": H, "display_name": "Ada Lovelace"},
                            "prompt_snapshot": snapshot},
            "corroborated_by": [], "corroborated_by_truncated": false,
            "ingesters": ingesters, "ingesters_truncated": false
        })
    }

    fn ok(d: Degraded<ProvenanceOut>) -> ProvenanceOut {
        d.into_option().expect("available")
    }

    #[test]
    fn literature_keeps_pending_and_added_authors_out_of_the_primary_list() {
        let raw = literature("10.1234/abc", Value::Null, json!([]));
        let ProvenanceOut::Literature { paper, .. } =
            ok(provenance_out(Some(&raw), None, &links()))
        else {
            panic!("literature")
        };
        let primary: Vec<_> = paper.authors.iter().map(|a| a.id.to_string()).collect();
        assert_eq!(primary, vec![H.to_string()]);
        assert_eq!(paper.pending_authors.len(), 1);
        assert_eq!(paper.pending_authors[0].id.to_string(), X);
        assert_eq!(paper.added_authors[0].id.to_string(), S);
        assert_eq!(paper.title.as_deref(), Some("A paper title"));
        assert_eq!(
            paper.doi_href.as_deref(),
            Some("https://doi.org/10.1234/abc")
        );
        assert_eq!(paper.authors[0].href, format!("/explorer/agent/{H}"));
        assert_eq!(
            paper.authors[0].role, None,
            "the default role is not repeated"
        );
    }

    #[test]
    fn a_document_key_that_is_not_a_doi_is_never_linked() {
        for key in [
            "urn:epigraph:doc:abc",
            "javascript:alert(1)",
            "https://evil.example/10.1234/x",
            "//evil.example",
        ] {
            let raw = literature(key, Value::Null, json!([]));
            let ProvenanceOut::Literature { paper, .. } =
                ok(provenance_out(Some(&raw), None, &links()))
            else {
                panic!("literature")
            };
            assert_eq!(paper.doi_href, None, "{key}");
            assert_eq!(paper.doi.as_deref(), Some(key), "the key is still shown");
        }
    }

    #[test]
    fn model_and_snapshot_come_only_from_a_visible_snapshot() {
        let raw = literature("10.1/x", Value::Null, json!([]));
        let ProvenanceOut::Literature { ingested_by, .. } =
            ok(provenance_out(Some(&raw), None, &links()))
        else {
            panic!("literature")
        };
        assert_eq!(ingested_by.model, None);
        assert_eq!(ingested_by.prompt_snapshot_id, None);
        assert_eq!(ingested_by.human.as_ref().unwrap().id.to_string(), H);

        let raw = literature(
            "10.1/x",
            json!({"snapshot_id": S, "model": "model-x", "prompt_hash": "f00d",
                   "started_at": "2026-10-01T00:00:00Z"}),
            json!([]),
        );
        let out = ok(provenance_out(Some(&raw), None, &links()));
        let body = serde_json::to_string(&out).unwrap();
        assert!(!body.contains("f00d"), "the prompt hash is never carried");
        let ProvenanceOut::Literature { ingested_by, .. } = out else {
            panic!("literature")
        };
        assert_eq!(ingested_by.model.as_deref(), Some("model-x"));
        assert_eq!(ingested_by.prompt_snapshot_id.unwrap().to_string(), S);
    }

    #[test]
    fn the_ingestion_date_is_the_creating_ingest_of_the_creating_document() {
        let ingesters = json!([
            {"agent": {"id": S, "display_name": null}, "human": null, "paper_id": P2,
             "created_claim": false, "recorded_at": "2026-01-01T00:00:00Z"},
            {"agent": {"id": A, "display_name": null}, "human": null, "paper_id": P,
             "created_claim": false, "recorded_at": "2026-02-01T00:00:00Z"},
            {"agent": {"id": A, "display_name": null}, "human": null, "paper_id": P,
             "created_claim": true, "recorded_at": "2026-03-01T00:00:00Z"}
        ]);
        let raw = literature("10.1/x", Value::Null, ingesters);
        let ProvenanceOut::Literature { ingested_at, .. } =
            ok(provenance_out(Some(&raw), None, &links()))
        else {
            panic!("literature")
        };
        assert_eq!(
            ingested_at.map(|d| d.to_rfc3339()),
            Some("2026-03-01T00:00:00+00:00".into())
        );

        // No creating ingest of that document: no date, never another's.
        let ingesters = json!([
            {"agent": {"id": S, "display_name": null}, "human": null, "paper_id": P2,
             "created_claim": true, "recorded_at": "2026-01-01T00:00:00Z"}
        ]);
        let raw = literature("10.1/x", Value::Null, ingesters);
        let ProvenanceOut::Literature { ingested_at, .. } =
            ok(provenance_out(Some(&raw), None, &links()))
        else {
            panic!("literature")
        };
        assert_eq!(ingested_at, None);
    }

    #[test]
    fn an_agent_claim_names_the_filer_and_lists_corroborating_documents_apart() {
        let docs: Vec<Value> = (0..12)
            .map(|i| {
                json!({"paper": {"id": format!("00000000-0000-0000-0000-0000000001{i:02}"),
                                 "doi": "10.1/y", "title": null},
                       "authors": [], "pending_authors": [], "added_authors": [],
                       "authors_truncated": false})
            })
            .collect();
        let raw = json!({
            "source": "agent",
            "agent": {"id": A, "display_name": "bot  one"},
            "human": null,
            "prompt_snapshot": null,
            "corroborated_by": docs, "corroborated_by_truncated": false,
            "ingesters": [], "ingesters_truncated": false
        });
        let filed: DateTime<Utc> = "2026-11-01T00:00:00Z".parse().unwrap();
        let ProvenanceOut::Agent {
            filed_at,
            filed_by,
            corroborated_by,
            corroborated_by_truncated,
        } = ok(provenance_out(Some(&raw), Some(filed), &links()))
        else {
            panic!("agent")
        };
        assert_eq!(filed_at, Some(filed));
        assert_eq!(filed_by.agent.name.as_deref(), Some("bot one"));
        assert_eq!(filed_by.agent.href, format!("/explorer/agent/{A}"));
        assert_eq!(filed_by.human, None);
        assert_eq!(filed_by.model, None);
        assert_eq!(corroborated_by.len(), PROVENANCE_DOCUMENTS_CAP);
        assert!(corroborated_by_truncated, "a cut list says so");
    }

    #[test]
    fn a_missing_or_unknown_block_is_an_unavailable_section() {
        assert_eq!(
            provenance_out(None, None, &links()).reason(),
            Some(PROVENANCE_UNSUPPORTED)
        );
        assert_eq!(
            provenance_out(Some(&Value::Null), None, &links()).reason(),
            Some(PROVENANCE_UNSUPPORTED)
        );
        for raw in [
            json!({"source": "dataset"}),
            json!({"source": "agent"}),
            json!("agent"),
        ] {
            assert_eq!(
                provenance_out(Some(&raw), None, &links()).reason(),
                Some(PROVENANCE_UNKNOWN),
                "{raw}"
            );
        }
    }

    #[test]
    fn author_lists_and_affiliations_are_capped() {
        let many: Vec<Value> = (0..60)
            .map(|i| {
                json!({"id": format!("00000000-0000-0000-0000-0000000002{i:02}"),
                       "display_name": "N", "role": "editor",
                       "affiliations": ["a", "b", "c", "d", "  "]})
            })
            .collect();
        let raw = json!({
            "source": "literature",
            "paper": {"paper": {"id": P, "doi": "10.1/x", "title": null},
                      "authors": many, "authors_truncated": false},
            "ingested_by": {"agent": {"id": A}}
        });
        let ProvenanceOut::Literature { paper, .. } =
            ok(provenance_out(Some(&raw), None, &links()))
        else {
            panic!("literature")
        };
        assert_eq!(paper.authors.len(), PROVENANCE_AUTHORS_CAP);
        assert!(paper.authors_truncated);
        assert_eq!(paper.authors[0].affiliations, vec!["a", "b", "c"]);
        assert_eq!(paper.authors[0].role.as_deref(), Some("editor"));
    }

    fn named(i: usize, name: &str) -> Value {
        json!({"id": format!("00000000-0000-0000-0000-{i:012}"), "display_name": name})
    }

    #[test]
    fn the_creating_document_carries_at_most_the_cap_across_its_lists() {
        let list = |from: usize, n: usize| -> Vec<Value> {
            (from..from + n).map(|i| named(i, "N")).collect()
        };
        let raw = json!({
            "source": "literature",
            "paper": {"paper": {"id": P, "doi": "10.1/x", "title": null},
                      "authors": list(1000, 40), "pending_authors": list(2000, 20),
                      "added_authors": list(3000, 5), "authors_truncated": false},
            "ingested_by": {"agent": {"id": A}}
        });
        let ProvenanceOut::Literature { paper, .. } =
            ok(provenance_out(Some(&raw), None, &links()))
        else {
            panic!("literature")
        };
        assert_eq!(paper.authors.len(), 40, "primary authors are kept first");
        assert_eq!(paper.pending_authors.len(), PROVENANCE_AUTHORS_CAP - 40);
        assert!(paper.added_authors.is_empty());
        assert!(paper.authors_truncated);
    }

    /// An author whose every field is at its clip length and made of control
    /// characters, which JSON escapes to six bytes each.
    fn heavy(i: usize) -> Value {
        let junk = "\u{1}".repeat(1000);
        json!({"id": format!("00000000-0000-0000-0000-{i:012}"), "display_name": junk,
               "role": junk, "affiliations": [junk, junk, junk, junk]})
    }

    fn heavy_document(i: usize) -> Value {
        let authors: Vec<Value> = (0..PROVENANCE_AUTHORS_CAP)
            .map(|j| heavy(i * 100 + j))
            .collect();
        json!({"paper": {"id": format!("00000000-0000-0000-0000-{:012}", 900_000 + i),
                         "doi": "\u{1}".repeat(1000), "title": "\u{1}".repeat(1000)},
               "authors": authors.clone(), "pending_authors": authors.clone(),
               "added_authors": authors, "authors_truncated": false})
    }

    #[test]
    fn a_worst_case_section_stays_within_its_budget() {
        let docs: Vec<Value> = (1..=12).map(heavy_document).collect();
        let raw = json!({
            "source": "literature",
            "paper": heavy_document(0),
            "ingested_by": {"agent": heavy(99), "human": heavy(98),
                            "prompt_snapshot": {"snapshot_id": S, "model": "\u{1}".repeat(1000)}},
            "corroborated_by": docs, "corroborated_by_truncated": false
        });
        let out = ok(provenance_out(Some(&raw), None, &links()));
        let bytes = serde_json::to_vec(&out).unwrap().len();
        assert!(bytes <= PROVENANCE_BYTES_CAP, "{bytes}");
        let body: Value = serde_json::to_value(&out).unwrap();
        let docs = body["corroborated_by"].as_array().unwrap();
        assert_eq!(docs.len(), PROVENANCE_DOCUMENTS_CAP);
        for d in docs {
            assert!(
                d.get("authors").is_none(),
                "a corroborating document names no authors"
            );
        }
        let names = ["authors", "pending_authors", "added_authors"]
            .iter()
            .map(|k| body["paper"][k].as_array().unwrap().len())
            .sum::<usize>();
        assert_eq!(names, PROVENANCE_AUTHORS_CAP);
    }

    #[test]
    fn a_section_over_its_budget_is_unavailable() {
        let big = AuthorOut {
            id: Uuid::nil(),
            name: Some("\u{1}".repeat(1000)),
            href: String::new(),
            role: None,
            affiliations: vec![],
        };
        let paper = DocumentOut {
            id: Uuid::nil(),
            doi: None,
            doi_href: None,
            title: None,
            authors: vec![big; 100],
            pending_authors: vec![],
            added_authors: vec![],
            authors_truncated: false,
        };
        let filer = FilerOut {
            agent: PersonOut {
                id: Uuid::nil(),
                name: None,
                href: String::new(),
            },
            human: None,
            model: None,
            prompt_snapshot_id: None,
        };
        let out = ProvenanceOut::Literature {
            filed_at: None,
            paper,
            ingested_by: filer,
            ingested_at: None,
            corroborated_by: vec![],
            corroborated_by_truncated: false,
        };
        assert!(serde_json::to_vec(&out).unwrap().len() > PROVENANCE_BYTES_CAP);
        assert_eq!(within_budget(out).reason(), Some(PROVENANCE_TOO_LARGE));
    }
}
