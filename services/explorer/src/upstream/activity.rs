//! Typed calls behind the agent-activity page: each watched agent's newest
//! claims since a time, and the events tail.
//!
//! `GET /api/v1/claims` (`routes/claims_query.rs::list_claims_query`) reads
//! on the viewer's stamped connection, so an agent's claims the viewer may
//! not read are not here. It filters `created_at >= created_after`, sorts as
//! asked, clamps `limit` to 100, and reports a real `COUNT(*)` over the same
//! filter in `total`, so `total` above the rows returned means the list was
//! cut, not that rows are missing.
//!
//! `GET /api/v1/events` (`routes/events.rs::list_events`) has no agent
//! filter (`actor_id` is not part of its public query), so the tail asks for
//! every agent's events and the page keeps the watched ones. What it answers
//! is not "the newest N": it takes the newest `2 × (limit + offset)` rows of
//! the persisted log plus the API process's in-memory events, keeps those at
//! or after `since`, sorts them OLDEST first, and returns the first `limit`,
//! with `total` counted before that cut. So `since` is always sent (without
//! it the in-memory events since the API started sort to the front), and
//! `total` above the events returned means the newest ones were cut.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::audit::rfc3339;
use super::{Api, UpstreamError};

/// Claims asked for per agent (upstream clamps `limit` to 100).
pub const AGENT_CLAIMS_LIMIT: u32 = 20;
/// Events asked for in the tail: upstream's own maximum.
pub const EVENTS_TAIL_LIMIT: u32 = 1000;

/// One row of `GET /api/v1/claims` (`ClaimSummary`), the fields the page
/// shows.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AgentClaim {
    pub id: Uuid,
    pub content: String,
    /// `None` when upstream did not say; only `Some(false)` is shown as
    /// superseded.
    #[serde(default)]
    pub is_current: Option<bool>,
    pub created_at: DateTime<Utc>,
}

/// `ClaimListResponse`: one page, and how many rows match in all.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AgentClaims {
    pub claims: Vec<AgentClaim>,
    pub total: u64,
}

/// One row of `GET /api/v1/events` (`GraphEvent`). The payload is not
/// read: it names claims, and the tail shows only who did what when.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct GraphEvent {
    pub id: Uuid,
    pub event_type: String,
    #[serde(default)]
    pub actor_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// `EventListResponse`: the events returned, and how many upstream counted
/// before cutting to `limit`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct EventList {
    pub events: Vec<GraphEvent>,
    pub total: u64,
}

impl Api<'_> {
    /// `GET /api/v1/events?since=&limit=`: every agent's events at or after
    /// `since` that upstream's window holds, oldest first, at most `limit`
    /// (see the module doc for what that window is).
    pub async fn events_since(
        &self,
        since: &DateTime<Utc>,
        limit: u32,
    ) -> Result<EventList, UpstreamError> {
        #[derive(Serialize)]
        struct Q {
            since: String,
            limit: u32,
        }
        let q = Q {
            since: rfc3339(since),
            limit,
        };
        self.get_query("/api/v1/events", &q).await
    }

    /// `GET /api/v1/claims?agent_id=&created_after=&sort_by=created_at&
    /// sort_order=desc&limit=`: `agent`'s newest claims created at or after
    /// `since`, at most `limit`.
    pub async fn agent_claims_since(
        &self,
        agent: Uuid,
        since: &DateTime<Utc>,
        limit: u32,
    ) -> Result<AgentClaims, UpstreamError> {
        #[derive(Serialize)]
        struct Q {
            agent_id: Uuid,
            created_after: String,
            sort_by: &'static str,
            sort_order: &'static str,
            limit: u32,
        }
        let q = Q {
            agent_id: agent,
            created_after: rfc3339(since),
            sort_by: "created_at",
            sort_order: "desc",
            limit,
        };
        self.get_query("/api/v1/claims", &q).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claim_list_decodes_the_kernels_summary() {
        let body = serde_json::json!({
            "claims": [{
                "id": "00000000-0000-4000-8000-000000000001",
                "content": "c", "statement": "c", "truth_value": 0.5,
                "agent_id": "00000000-0000-4000-a000-000000000001",
                "is_current": false,
                "created_at": "2026-10-02T10:00:00.250000Z",
                "updated_at": "2026-10-02T10:00:00.250000Z"
            }],
            "total": 7, "limit": 20, "offset": 0
        });
        let list: AgentClaims = serde_json::from_value(body).unwrap();
        assert_eq!(list.total, 7);
        assert_eq!(list.claims[0].is_current, Some(false));
        assert_eq!(
            rfc3339(&list.claims[0].created_at),
            "2026-10-02T10:00:00.250Z"
        );
    }

    #[test]
    fn an_event_list_decodes_without_its_payload() {
        let body = serde_json::json!({
            "events": [{
                "id": "00000000-0000-4000-9000-000000000001",
                "event_type": "claim.created",
                "actor_id": null,
                "payload": {"claim_id": "00000000-0000-4000-8000-000000000001"},
                "graph_version": 3,
                "created_at": "2026-10-01T01:00:00Z"
            }],
            "total": 1500
        });
        let list: EventList = serde_json::from_value(body).unwrap();
        assert_eq!(list.total, 1500);
        assert_eq!(list.events[0].actor_id, None);
        assert_eq!(list.events[0].event_type, "claim.created");
    }
}
