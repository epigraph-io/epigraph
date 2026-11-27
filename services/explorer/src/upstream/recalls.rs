//! Upstream DTOs and the typed call for the caller's own recall history:
//! `GET /api/v1/recall-events` (backlog 39aad446).
//!
//! The route answers for the bearer's own rows only; there is no agent
//! parameter to send, so the Explorer cannot ask for anyone else's history.
//! It pages by keyset: `after` is the previous page's `next_cursor`, passed
//! back unchanged, and `next_cursor` is `null` on the last page.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Api, UpstreamError};

/// The route's `limit` ceiling; a larger value is clamped upstream anyway.
pub const MAX_RECALL_EVENTS_LIMIT: u32 = 200;
/// Longest cursor forwarded upstream. The route's own tokens are
/// `k1.<micros>.<32 hex>`, well under this.
pub const MAX_CURSOR_LEN: usize = 128;

/// One page: `{"items": [...], "next_cursor": ...}`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct RecallEventsPage {
    #[serde(default)]
    pub items: Vec<RecallEvent>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// One recall the caller ran, as the MCP `get_recall_events` tool reports it.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct RecallEvent {
    pub id: Uuid,
    /// The tool that ran it (`recall`, `recall_with_context`, ...).
    #[serde(default)]
    pub tool: String,
    #[serde(default)]
    pub query_text: String,
    /// The claims it returned, in the order it returned them.
    #[serde(default)]
    pub returned_claim_ids: Vec<Uuid>,
    #[serde(default)]
    pub created_at: Option<String>,
}

/// A cursor safe to forward: the route's own token alphabet, bounded. Anything
/// else is dropped (the page starts from the newest row) rather than sent.
#[must_use]
pub fn sane_cursor(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|c| {
        !c.is_empty()
            && c.len() <= MAX_CURSOR_LEN
            && c.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
    })
}

impl Api<'_> {
    /// `GET /api/v1/recall-events?limit=&after=`: one page of the signed-in
    /// caller's own recall history, newest first.
    pub async fn own_recall_events(
        &self,
        after: Option<&str>,
        limit: u32,
    ) -> Result<RecallEventsPage, UpstreamError> {
        #[derive(Serialize)]
        struct Q<'a> {
            limit: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            after: Option<&'a str>,
        }
        let q = Q {
            limit: limit.clamp(1, MAX_RECALL_EVENTS_LIMIT),
            after: sane_cursor(after),
        };
        self.get_query("/api/v1/recall-events", &q).await
    }
}

#[cfg(test)]
mod tests {
    use super::sane_cursor;

    #[test]
    fn only_the_routes_token_alphabet_is_forwarded() {
        let token = "k1.1790000000000000.0f1e2d3c4b5a69788796a5b4c3d2e1f0";
        assert_eq!(sane_cursor(Some(token)), Some(token));
        assert_eq!(sane_cursor(Some("  ")), None);
        assert_eq!(sane_cursor(None), None);
        assert_eq!(sane_cursor(Some("k1.1&agent_id=x")), None);
        assert_eq!(sane_cursor(Some(&"a".repeat(129))), None);
    }
}
