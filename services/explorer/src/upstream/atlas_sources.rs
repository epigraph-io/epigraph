//! Upstream DTOs and the typed call for the Atlas Sources view (phase P3b).
//! OWNED BY THE ATLAS AREA.
//!
//! `GET /api/v1/sources/overview?theme_id=&kind=&after=&limit=` (backlog
//! da4a8bc1), read with the viewer's own bearer: who said what across the
//! corpus or one theme, grouped by kind (`paper`, then `agent`, then `web`)
//! and within a kind by `claim_count` descending. Every count is the number
//! of current claims the viewer could list one at a time; a source with no
//! such claim is absent. There is no total.
//!
//! Discipline (as `upstream/types.rs`): every field that is not guaranteed
//! present is `Option` or `#[serde(default)]`, unknown fields are ignored, a
//! source of a kind this build does not know decodes as
//! [`SourceEntry::Unknown`] (and is dropped by the BFF), and every field is
//! `pub` so that no unread field trips `dead_code`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Api, UpstreamError};

/// Page-size range of the sources overview (the kernel's `1..=200`).
pub const SOURCES_PAGE_RANGE: (u32, u32) = (1, 200);

/// The source kinds the overview filters by.
pub const SOURCE_KINDS: [&str; 3] = ["paper", "agent", "web"];

/// Query of `GET /sources/overview`. `limit` is clamped to `1..=200`.
#[derive(Debug, Serialize, Clone, Copy, PartialEq)]
pub struct SourcesQuery<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<&'a str>,
    pub limit: u32,
}

/// One listed author of a paper source.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SourceAuthor {
    pub id: Uuid,
    #[serde(default)]
    pub display_name: Option<String>,
    /// An ingester's word awaiting the person's countersignature.
    #[serde(default)]
    pub pending_countersign: bool,
}

/// One source, tagged by `kind`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceEntry {
    Paper {
        id: Uuid,
        #[serde(default)]
        doi: Option<String>,
        #[serde(default)]
        title: Option<String>,
        #[serde(default)]
        authors: Vec<SourceAuthor>,
        #[serde(default)]
        authors_truncated: bool,
        #[serde(default)]
        claim_count: i64,
    },
    Agent {
        id: Uuid,
        #[serde(default)]
        display_name: Option<String>,
        #[serde(default)]
        claim_count: i64,
    },
    Web {
        domain: String,
        #[serde(default)]
        claim_count: i64,
    },
    /// A kind added after this build: decoded, then dropped.
    #[serde(other)]
    Unknown,
}

/// `GET /sources/overview` body.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct SourcesOverview {
    #[serde(default)]
    pub sources: Vec<SourceEntry>,
    /// `null` on the last page; otherwise passed back as `after`.
    #[serde(default)]
    pub next_cursor: Option<String>,
}

impl Api<'_> {
    /// `GET /api/v1/sources/overview`.
    pub async fn sources_overview(
        &self,
        q: &SourcesQuery<'_>,
    ) -> Result<SourcesOverview, UpstreamError> {
        let q = SourcesQuery {
            limit: q.limit.clamp(SOURCES_PAGE_RANGE.0, SOURCES_PAGE_RANGE.1),
            ..*q
        };
        self.get_query("/api/v1/sources/overview", &q).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const A: &str = "00000000-0000-0000-0000-00000000000a";
    const B: &str = "00000000-0000-0000-0000-00000000000b";

    /// The kernel's documented body (crates/epigraph-api/src/routes/sources.rs)
    /// decodes, and a kind this build does not know is kept apart.
    #[test]
    fn the_kernel_body_decodes_and_unknown_kinds_stay_apart() {
        let b: SourcesOverview = serde_json::from_value(json!({
            "sources": [
                {"kind": "paper", "id": A, "doi": "10.1234/x", "title": "T",
                 "authors": [{"id": B, "display_name": "Ada", "pending_countersign": true}],
                 "authors_truncated": false, "claim_count": 12},
                {"kind": "agent", "id": B, "display_name": null, "claim_count": 4},
                {"kind": "web", "domain": "example.org", "claim_count": 2},
                {"kind": "dataset", "id": A, "claim_count": 1}
            ],
            "next_cursor": "abc"
        }))
        .unwrap();
        assert_eq!(b.sources.len(), 4);
        match &b.sources[0] {
            SourceEntry::Paper { authors, .. } => assert!(authors[0].pending_countersign),
            other => panic!("{other:?}"),
        }
        assert_eq!(b.sources[3], SourceEntry::Unknown);
        assert_eq!(b.next_cursor.as_deref(), Some("abc"));
    }

    #[test]
    fn the_query_omits_what_is_not_asked() {
        let q = SourcesQuery {
            theme_id: None,
            kind: None,
            after: None,
            limit: 50,
        };
        assert_eq!(serde_json::to_value(q).unwrap(), json!({"limit": 50}));
    }
}
