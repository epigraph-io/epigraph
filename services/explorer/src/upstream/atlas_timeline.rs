//! Upstream DTOs and the typed call for the Atlas Timeline view (phase P3c).
//! OWNED BY THE ATLAS AREA.
//!
//! `GET /api/v1/claims?theme_id=&created_after=&created_before=&sort_by=created_at&sort_order=asc&is_current=true&include_links=true&after=&limit=`
//! (backlog ea26d7aa), read with the viewer's own bearer: one theme's current
//! claims in filing order, keyset-paged on `(created_at, id)`, with the
//! in-force epistemic links whose two ends are both on the page.
//!
//! An API from before those filters either refuses `theme_id` (400) or, on
//! an older build that drops unknown keys, answers without `links` although
//! they were asked for. [`ClaimsPage::links`] stays `None` in that case so
//! the BFF can tell the two answers apart and never draw an unfiltered page
//! as the theme's.
//!
//! Discipline (as `upstream/types.rs`): every field that is not guaranteed
//! present is `Option` or `#[serde(default)]`, unknown fields are ignored,
//! and every field is `pub` so that no unread field trips `dead_code`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Api, UpstreamError};

/// Page-size range of `GET /claims` (the kernel's `1..=100`).
pub const CLAIMS_PAGE_RANGE: (u32, u32) = (1, 100);

/// Query of the timeline read. The order, the current-only filter and the
/// links are fixed; `limit` is clamped to `1..=100`.
#[derive(Debug, Serialize, Clone, Copy, PartialEq)]
pub struct TimelineQuery<'a> {
    pub theme_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_after: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<&'a str>,
    pub limit: u32,
}

/// The wire form: [`TimelineQuery`] plus the fixed parameters.
#[derive(Serialize)]
struct Wire<'a> {
    theme_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_after: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_before: Option<DateTime<Utc>>,
    sort_by: &'static str,
    sort_order: &'static str,
    is_current: bool,
    include_links: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<&'a str>,
    limit: u32,
}

/// One claim of a page (the kernel's `ClaimSummary`; `statement` is an alias
/// of `content` and is not read).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct PageClaim {
    pub id: Uuid,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub truth_value: Option<f64>,
    #[serde(default)]
    pub agent_id: Option<Uuid>,
    #[serde(default)]
    pub is_current: Option<bool>,
    pub created_at: DateTime<Utc>,
}

/// One claim-to-claim link among the claims of a page.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct PageLink {
    pub id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    /// Lower-cased relationship name.
    pub relationship: String,
}

/// `GET /claims` body, as far as the timeline reads it.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct ClaimsPage {
    #[serde(default)]
    pub claims: Vec<PageClaim>,
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// `None`: the API did not honour `include_links` (see the module doc).
    #[serde(default)]
    pub links: Option<Vec<PageLink>>,
    #[serde(default)]
    pub links_truncated: Option<bool>,
}

impl Api<'_> {
    /// `GET /api/v1/claims` for one theme's timeline page.
    pub async fn claims_timeline(
        &self,
        q: &TimelineQuery<'_>,
    ) -> Result<ClaimsPage, UpstreamError> {
        let wire = Wire {
            theme_id: q.theme_id,
            created_after: q.created_after,
            created_before: q.created_before,
            sort_by: "created_at",
            sort_order: "asc",
            is_current: true,
            include_links: true,
            after: q.after,
            limit: q.limit.clamp(CLAIMS_PAGE_RANGE.0, CLAIMS_PAGE_RANGE.1),
        };
        self.get_query("/api/v1/claims", &wire).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const A: &str = "00000000-0000-0000-0000-00000000000a";
    const B: &str = "00000000-0000-0000-0000-00000000000b";
    const E: &str = "00000000-0000-0000-0000-00000000000e";

    /// The kernel's `ClaimListResponse` decodes; a body without `links` keeps
    /// `links: None`, which is how an API that ignored the filters is told
    /// apart from a page with no links.
    #[test]
    fn the_kernel_body_decodes_and_missing_links_stay_none() {
        let b: ClaimsPage = serde_json::from_value(json!({
            "claims": [{"id": A, "content": "x", "statement": "x", "truth_value": 0.5,
                        "agent_id": B, "is_current": true,
                        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}],
            "total": 1, "limit": 100, "offset": 0, "next_cursor": null,
            "links": [{"id": E, "source_id": A, "target_id": B, "relationship": "supports"}],
            "links_truncated": false
        }))
        .unwrap();
        assert_eq!(b.links.as_ref().unwrap()[0].relationship, "supports");
        let old: ClaimsPage = serde_json::from_value(json!({
            "claims": [], "total": 0, "limit": 100, "offset": 0
        }))
        .unwrap();
        assert_eq!(old.links, None);
        let none: ClaimsPage = serde_json::from_value(json!({
            "claims": [], "links": [], "links_truncated": false
        }))
        .unwrap();
        assert_eq!(none.links, Some(vec![]));
    }
}
