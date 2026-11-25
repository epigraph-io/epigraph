//! Upstream DTOs and the typed call for the Atlas claim panel's provenance
//! (phase P3b). OWNED BY THE ATLAS AREA.
//!
//! `GET /api/v1/claims/:id` carries an `authored_by` block (backlog
//! `48421526`, `b7354adc`), tagged by `source`:
//!
//! - `agent`: the filer stated the claim. `agent`, its bound `human` and the
//!   `prompt_snapshot` it ran at the claim's `created_at` (`null` unless the
//!   caller passes the kernel's prompt-history gate).
//! - `literature`: a document's ingest created the claim. `paper` with its
//!   primary `authors` (pending and later-added authors listed apart, never
//!   primary) and `ingested_by`, the filer, shown apart from the authors.
//!
//! Both carry `corroborated_by` (other readable documents whose ingest
//! recorded the claim) and `ingesters` (every readable ingest, oldest first).
//!
//! The block is kept raw on [`ClaimRead`] and decoded on its own, so a shape
//! this build does not know degrades the panel's provenance section only and
//! never the claim read (the fallback path of the claim panel reads the same
//! body). Discipline as `upstream/types.rs`: every field that is not
//! guaranteed is `Option` or `#[serde(default)]`, unknown fields are ignored,
//! and an unknown `source` decodes as [`AuthoredBy::Unknown`]. The kernel's
//! `prompt_hash` is not read: the panel names the snapshot and its model only.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::{Api, ClaimResponse, UpstreamError};

/// `GET /api/v1/claims/:id`, with `authored_by` kept as raw JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct ClaimRead {
    #[serde(flatten)]
    pub claim: ClaimResponse,
    /// Absent on a kernel that predates the block.
    #[serde(default)]
    pub authored_by: Option<Value>,
}

/// An agent (a person is an agent too): the two fields `GET /agents/:id`
/// names.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AuthorRef {
    pub id: Uuid,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// The prompt snapshot an agent was running when it filed the claim.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PromptSnapshot {
    pub snapshot_id: Uuid,
    #[serde(default)]
    pub model: Option<String>,
}

/// A document node.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PaperRef {
    pub id: Uuid,
    /// The document key: a DOI, or another key (`urn:epigraph:doc:…`).
    #[serde(default)]
    pub doi: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
}

/// One author of a document, from its `authored` edge.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PaperAuthor {
    pub id: Uuid,
    #[serde(default)]
    pub display_name: Option<String>,
    /// `author` when absent.
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub affiliations: Vec<String>,
}

/// A document and its authors.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PaperAuthorship {
    pub paper: PaperRef,
    /// On the creating document, the claim's primary authors.
    #[serde(default)]
    pub authors: Vec<PaperAuthor>,
    /// Named by an ingester, awaiting the person's countersignature. Never
    /// primary.
    #[serde(default)]
    pub pending_authors: Vec<PaperAuthor>,
    /// Added by a later ingest of the same document. Never primary.
    #[serde(default)]
    pub added_authors: Vec<PaperAuthor>,
    #[serde(default)]
    pub authors_truncated: bool,
}

/// The agent that filed a claim row, with its human and prompt snapshot.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Filer {
    pub agent: AuthorRef,
    #[serde(default)]
    pub human: Option<AuthorRef>,
    #[serde(default)]
    pub prompt_snapshot: Option<PromptSnapshot>,
}

/// One ingest of the claim.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Ingester {
    pub agent: AuthorRef,
    #[serde(default)]
    pub human: Option<AuthorRef>,
    pub paper_id: Uuid,
    /// This ingest created the claim.
    #[serde(default)]
    pub created_claim: bool,
    #[serde(default)]
    pub recorded_at: Option<DateTime<Utc>>,
}

/// The `authored_by` block, tagged by `source`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum AuthoredBy {
    Agent {
        agent: AuthorRef,
        #[serde(default)]
        human: Option<AuthorRef>,
        #[serde(default)]
        prompt_snapshot: Option<PromptSnapshot>,
        #[serde(default)]
        corroborated_by: Vec<PaperAuthorship>,
        #[serde(default)]
        corroborated_by_truncated: bool,
        #[serde(default)]
        ingesters: Vec<Ingester>,
    },
    Literature {
        paper: PaperAuthorship,
        ingested_by: Filer,
        #[serde(default)]
        corroborated_by: Vec<PaperAuthorship>,
        #[serde(default)]
        corroborated_by_truncated: bool,
        #[serde(default)]
        ingesters: Vec<Ingester>,
    },
    /// A source added after this build: decoded, then shown as unavailable.
    #[serde(other)]
    Unknown,
}

impl Api<'_> {
    /// `GET /api/v1/claims/:id`, keeping the `authored_by` block.
    pub async fn claim_read(&self, id: Uuid) -> Result<ClaimRead, UpstreamError> {
        self.get(&format!("/api/v1/claims/{id}")).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const C: &str = "00000000-0000-0000-0000-00000000000c";
    const A: &str = "00000000-0000-0000-0000-00000000000a";
    const H: &str = "00000000-0000-0000-0000-00000000000b";
    const P: &str = "00000000-0000-0000-0000-00000000000d";
    const S: &str = "00000000-0000-0000-0000-00000000000e";

    /// The kernel's `literature` block (crates/epigraph-api/src/routes/
    /// claims.rs, `AuthoredByView`) decodes with every list apart.
    #[test]
    fn the_kernel_literature_block_decodes() {
        let read: ClaimRead = serde_json::from_value(json!({
            "id": C, "content": "x", "truth_value": 0.5, "agent_id": A,
            "created_at": "2026-11-01T00:00:00Z", "labels": [],
            "authored_by": {
                "source": "literature",
                "paper": {"paper": {"id": P, "doi": "10.1/x", "title": "T"},
                          "authors": [{"id": H, "display_name": "Ada", "position": 0,
                                       "role": "author", "affiliations": ["U"],
                                       "pending_countersign": false, "named_by": null,
                                       "added_by": null}],
                          "pending_authors": [{"id": S, "display_name": "Bo", "position": 1,
                                               "role": "author", "affiliations": [],
                                               "pending_countersign": true,
                                               "named_by": {"id": A, "display_name": null},
                                               "added_by": null}],
                          "added_authors": [], "authors_truncated": false},
                "ingested_by": {"agent": {"id": A, "display_name": "ingest-bot"},
                                "human": {"id": H, "display_name": "Ada"},
                                "prompt_snapshot": {"snapshot_id": S, "model": "m-1",
                                                    "prompt_hash": "ab", "started_at": "2026-10-01T00:00:00Z"}},
                "corroborated_by": [], "corroborated_by_truncated": false,
                "ingesters": [{"agent": {"id": A, "display_name": "ingest-bot"},
                               "human": null, "paper_id": P, "created_claim": true,
                               "recorded_at": "2026-11-01T00:00:00Z"}],
                "ingesters_truncated": false
            }
        }))
        .unwrap();
        assert_eq!(read.claim.content, "x");
        let a: AuthoredBy = serde_json::from_value(read.authored_by.unwrap()).unwrap();
        match a {
            AuthoredBy::Literature {
                paper,
                ingested_by,
                ingesters,
                ..
            } => {
                assert_eq!(paper.authors.len(), 1);
                assert_eq!(paper.pending_authors[0].display_name.as_deref(), Some("Bo"));
                assert_eq!(
                    ingested_by.prompt_snapshot.unwrap().model.as_deref(),
                    Some("m-1")
                );
                assert!(ingesters[0].created_claim);
            }
            other => panic!("{other:?}"),
        }
    }

    /// A source this build does not know is kept apart, and a kernel
    /// without the block still reads the claim.
    #[test]
    fn unknown_sources_and_missing_blocks_stay_apart() {
        let a: AuthoredBy = serde_json::from_value(json!({"source": "dataset", "id": P})).unwrap();
        assert_eq!(a, AuthoredBy::Unknown);
        let read: ClaimRead = serde_json::from_value(json!({"id": C, "content": "x"})).unwrap();
        assert!(read.authored_by.is_none());
    }
}
