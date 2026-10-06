//! Typed calls behind the admin-acts page: the viewer's own acts.
//!
//! `GET /api/v1/admin/acts?mine&limit=` (`routes/admin_acts.rs::list_acts`
//! on the elevation stack, read at `feat/mt-c-elevation` `3387413f`)
//! answers `{"acts": [...]}`, each a `ProposedAct` flattened with the
//! confirmation page's `path`. Only the fields the page shows are decoded;
//! `args`, `args_digest` and `elevation_id` are ignored.
//!
//! `ProposedAct` has no status field: [`ListedAct::status`] derives one.
//! The kernel attaches a `path` to every act although the page is live only
//! while the act is unasserted and unexpired, so only a pending act is ever
//! linked ([`ListedAct::confirm_url`]).

use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use super::{Api, UpstreamError};

/// Acts asked for per page (the kernel's default; it allows 1..=200).
pub const ACTS_LIMIT: u32 = 50;

/// The confirmation page's path prefix, served by the API.
const CONFIRM_PREFIX: &str = "/elevate/act/";

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ActsResponse {
    pub acts: Vec<ListedAct>,
}

/// One of the viewer's own acts.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ListedAct {
    pub id: Uuid,
    /// `role.grant`, `role.end`, `claim.custodial_supersede`, …
    pub kind: String,
    /// `agent`, `role_assignment` or `claim`.
    pub target_type: String,
    pub target_id: Uuid,
    pub reason: String,
    pub proposed_at: DateTime<Utc>,
    /// When an unconfirmed act stops being confirmable, and a confirmed one
    /// executable.
    pub expires_at: DateTime<Utc>,
    /// When the passkey answered, if it has.
    #[serde(default)]
    pub asserted_at: Option<DateTime<Utc>>,
    /// `confirmed` or `refused`, once asserted.
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub refusal: Option<String>,
    /// When the maintenance CLI executed it, if it has.
    #[serde(default)]
    pub consumed_at: Option<DateTime<Utc>>,
    /// The confirmation page's path, as the API states it.
    pub path: String,
}

/// Where an act stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActStatus {
    /// Unasserted, unconsumed and unexpired: it can still be confirmed.
    Pending,
    Confirmed,
    Refused,
    Executed,
    /// Expired before anything happened, or confirmed but never executed.
    Expired,
}

impl ActStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ActStatus::Pending => "pending",
            ActStatus::Confirmed => "confirmed",
            ActStatus::Refused => "refused",
            ActStatus::Executed => "executed",
            ActStatus::Expired => "expired",
        }
    }
}

impl ListedAct {
    /// Pending iff `asserted_at` and `consumed_at` are both unset and
    /// `expires_at` is still ahead.
    pub fn is_pending(&self, now: DateTime<Utc>) -> bool {
        self.asserted_at.is_none() && self.consumed_at.is_none() && self.expires_at > now
    }

    pub fn status(&self, now: DateTime<Utc>) -> ActStatus {
        if self.consumed_at.is_some() {
            ActStatus::Executed
        } else if self.outcome.as_deref() == Some("refused") {
            ActStatus::Refused
        } else if self.expires_at <= now {
            ActStatus::Expired
        } else if self.asserted_at.is_some() {
            ActStatus::Confirmed
        } else {
            ActStatus::Pending
        }
    }

    /// The link to confirm this act: `api_origin` joined with the
    /// response's own `path`, only while the act is pending and only when
    /// that path is exactly this act's confirmation page. The Explorer never
    /// builds the path; a path naming another origin, page or act, or
    /// carrying anything more, gets no link.
    pub fn confirm_url(&self, api_origin: &str, now: DateTime<Utc>) -> Option<String> {
        let own_page = self
            .path
            .strip_prefix(CONFIRM_PREFIX)
            .is_some_and(|rest| rest == self.id.to_string());
        (self.is_pending(now) && own_page)
            .then(|| format!("{}{}", api_origin.trim_end_matches('/'), self.path))
    }
}

impl Api<'_> {
    /// `GET /api/v1/admin/acts?mine&limit=<limit>`: the viewer's own acts,
    /// newest first.
    pub async fn admin_acts(&self, limit: u32) -> Result<ActsResponse, UpstreamError> {
        self.get(&format!("/api/v1/admin/acts?mine&limit={limit}"))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;

    const ID: &str = "00000000-0000-4000-8000-0000000000a1";
    const OTHER: &str = "00000000-0000-4000-8000-0000000000a2";

    fn act(now: DateTime<Utc>) -> ListedAct {
        ListedAct {
            id: ID.parse().unwrap(),
            kind: "role.grant".into(),
            target_type: "agent".into(),
            target_id: OTHER.parse().unwrap(),
            reason: "r".into(),
            proposed_at: now - Duration::minutes(5),
            expires_at: now + Duration::minutes(5),
            asserted_at: None,
            outcome: None,
            refusal: None,
            consumed_at: None,
            path: format!("/elevate/act/{ID}"),
        }
    }

    #[test]
    fn decodes_the_kernels_listing() {
        let body = json!({"acts": [{
            "id": ID, "kind": "role.grant",
            "args": {"agent_id": OTHER}, "args_digest": "ab".repeat(32),
            "target_type": "agent", "target_id": OTHER, "reason": "why",
            "elevation_id": OTHER,
            "proposed_at": "2026-10-01T00:00:00Z", "expires_at": "2026-10-01T00:10:00Z",
            "asserted_at": null, "outcome": null, "refusal": null, "consumed_at": null,
            "path": format!("/elevate/act/{ID}")
        }]});
        let r: ActsResponse = serde_json::from_value(body).unwrap();
        assert_eq!(r.acts.len(), 1);
        assert_eq!(r.acts[0].id.to_string(), ID);
        assert_eq!(r.acts[0].kind, "role.grant");
        assert_eq!(r.acts[0].asserted_at, None);
    }

    #[test]
    fn status_and_pending_follow_the_timestamps() {
        let now = Utc::now();
        let a = act(now);
        assert!(a.is_pending(now));
        assert_eq!(a.status(now), ActStatus::Pending);

        let expired = ListedAct {
            expires_at: now,
            ..act(now)
        };
        assert!(!expired.is_pending(now), "expires_at must be in the future");
        assert_eq!(expired.status(now), ActStatus::Expired);

        let confirmed = ListedAct {
            asserted_at: Some(now),
            outcome: Some("confirmed".into()),
            ..act(now)
        };
        assert!(!confirmed.is_pending(now));
        assert_eq!(confirmed.status(now), ActStatus::Confirmed);

        let refused = ListedAct {
            asserted_at: Some(now),
            outcome: Some("refused".into()),
            ..act(now)
        };
        assert_eq!(refused.status(now), ActStatus::Refused);

        let executed = ListedAct {
            asserted_at: Some(now),
            outcome: Some("confirmed".into()),
            consumed_at: Some(now),
            ..act(now)
        };
        assert!(!executed.is_pending(now));
        assert_eq!(executed.status(now), ActStatus::Executed);

        let consumed_only = ListedAct {
            consumed_at: Some(now),
            ..act(now)
        };
        assert!(!consumed_only.is_pending(now), "consumed is never pending");
    }

    #[test]
    fn confirm_url_is_the_api_origin_and_the_acts_own_path_only() {
        let now = Utc::now();
        assert_eq!(
            act(now).confirm_url("https://api.example.com/", now),
            Some(format!("https://api.example.com/elevate/act/{ID}"))
        );
        for path in [
            "//evil.example/x".to_string(),
            "/elsewhere".to_string(),
            format!("/elevate/act/{OTHER}"),
            format!("/elevate/act/{ID}?x=1"),
            format!("/elevate/act/{ID}#x"),
            format!("/elevate/act/{ID}/"),
            format!("/elevate/act/../{ID}"),
            format!("/elevate/act//{ID}"),
            format!("/elevate/act/{}", ID.to_uppercase()),
            format!("https://evil.example/elevate/act/{ID}"),
            format!("\\elevate/act/{ID}"),
            String::new(),
        ] {
            let a = ListedAct {
                path: path.clone(),
                ..act(now)
            };
            assert_eq!(
                a.confirm_url("https://api.example.com", now),
                None,
                "{path:?}"
            );
        }
        let done = ListedAct {
            asserted_at: Some(now),
            ..act(now)
        };
        assert_eq!(done.confirm_url("https://api.example.com", now), None);
    }
}
