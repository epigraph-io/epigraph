//! Typed calls behind the agent-activity page: each watched agent's newest
//! claims since a time.
//!
//! `GET /api/v1/claims` (`routes/claims_query.rs::list_claims_query`) reads
//! on the viewer's stamped connection, so an agent's claims the viewer may
//! not read are not here. It filters `created_at >= created_after`, sorts as
//! asked, clamps `limit` to 100, and reports a real `COUNT(*)` over the same
//! filter in `total`, so `total` above the rows returned means the list was
//! cut, not that rows are missing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::audit::rfc3339;
use super::{Api, UpstreamError};

/// Claims asked for per agent (upstream clamps `limit` to 100).
pub const AGENT_CLAIMS_LIMIT: u32 = 20;

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

impl Api<'_> {
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
}
