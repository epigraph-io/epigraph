//! Typed calls behind the audit page: the security events the viewer may
//! read (`GET /api/v1/audit/security`,
//! `routes/audit.rs::query_security_events`).
//!
//! Which rows come back is the kernel's decision, not this module's: the
//! route needs `audit:read` and reads on the viewer's stamped connection,
//! where the `security_events_read` policy narrows the rows. Its query
//! parameters only filter within that set.
//!
//! A window is pulled in pages of [`AUDIT_PAGE_ROWS`], never as one request
//! for the whole ceiling: each row carries a JSONB `details`, so a large page
//! could exceed [`super::MAX_UPSTREAM_BODY`]. The route orders by
//! `created_at DESC` and filters `created_at >= since AND created_at <=
//! until`, so each later page is asked for with `until` = the previous
//! page's oldest `created_at`. That bound is inclusive: the next page starts
//! with the rows at that instant again, and [`Pager`] counts each id once.

use std::collections::HashSet;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Api, UpstreamError};

/// Rows asked for per upstream request.
pub const AUDIT_PAGE_ROWS: usize = 1000;
/// The scope the audit route requires.
pub const AUDIT_READ_SCOPE: &str = "audit:read";

/// One row of `GET /api/v1/audit/security` (`SecurityEventResponse`).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub event_type: String,
    #[serde(default)]
    pub agent_id: Option<Uuid>,
    /// `None` for events with no success concept; only `Some(false)` is a
    /// failure (the route's own `failures_only` meaning).
    #[serde(default)]
    pub success: Option<bool>,
    #[serde(default)]
    pub details: serde_json::Value,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// What window, and which events in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFilter {
    pub since: DateTime<Utc>,
    pub until: Option<DateTime<Utc>>,
    pub event_type: Option<String>,
    pub failures_only: bool,
}

/// A timestamp as the route parses it: RFC 3339, `Z`, and every sub-second
/// digit it has. A cursor rounded to the second would skip the rows between
/// the rounded instant and the real one.
pub fn rfc3339(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

/// Why a pull stopped.
#[derive(Debug, Clone, PartialEq)]
pub enum PullStop {
    /// A short page: the window holds no more rows.
    Complete,
    /// The row ceiling was reached; the window may hold more.
    Capped,
    /// A full page brought no row not already counted: more than a page of
    /// events share one timestamp, and an inclusive `until` cannot page past
    /// them.
    Stalled,
    /// A later page failed; the rows before it are counted.
    Failed(UpstreamError),
}

/// The rows of one window, newest first, each id once.
#[derive(Debug)]
pub struct AuditPull {
    pub rows: Vec<SecurityEvent>,
    pub stop: PullStop,
}

/// The paging state of one pull: the cursor, the ids already counted, and
/// the rows kept so far (at most `ceiling`).
#[derive(Debug)]
pub struct Pager {
    cursor: Option<DateTime<Utc>>,
    ceiling: usize,
    seen: HashSet<Uuid>,
    rows: Vec<SecurityEvent>,
    pages: usize,
}

impl Pager {
    /// Start at `until` (the window's own end, if it has one).
    pub fn new(until: Option<DateTime<Utc>>, ceiling: usize) -> Self {
        Self {
            cursor: until,
            ceiling,
            seen: HashSet::new(),
            rows: Vec::new(),
            pages: 0,
        }
    }

    /// The `until` to ask the next page for.
    pub fn cursor(&self) -> Option<DateTime<Utc>> {
        self.cursor
    }

    /// No page has been taken yet.
    pub fn is_first(&self) -> bool {
        self.pages == 0
    }

    /// Take one page (asked for with `limit` = [`AUDIT_PAGE_ROWS`]). `None`
    /// means ask for the next one; `Some(stop)` ends the pull.
    pub fn take(&mut self, page: Vec<SecurityEvent>) -> Option<PullStop> {
        self.pages += 1;
        let full = page.len() >= AUDIT_PAGE_ROWS;
        let oldest = page.iter().map(|e| e.created_at).min();
        let mut fresh = 0usize;
        for event in page {
            if !self.seen.insert(event.id) {
                continue;
            }
            fresh += 1;
            if self.rows.len() >= self.ceiling {
                return Some(PullStop::Capped);
            }
            self.rows.push(event);
        }
        if !full {
            return Some(PullStop::Complete);
        }
        if self.rows.len() >= self.ceiling {
            return Some(PullStop::Capped);
        }
        if fresh == 0 {
            return Some(PullStop::Stalled);
        }
        self.cursor = oldest;
        None
    }

    pub fn finish(self, stop: PullStop) -> AuditPull {
        AuditPull {
            rows: self.rows,
            stop,
        }
    }
}

impl Api<'_> {
    /// One page of `GET /api/v1/audit/security`, newest first.
    pub async fn security_events_page(
        &self,
        filter: &AuditFilter,
        until: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<SecurityEvent>, UpstreamError> {
        #[derive(Serialize)]
        struct Q<'a> {
            since: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            until: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            event_type: Option<&'a str>,
            #[serde(skip_serializing_if = "std::ops::Not::not")]
            failures_only: bool,
            limit: usize,
        }
        let q = Q {
            since: rfc3339(&filter.since),
            until: until.as_ref().map(rfc3339),
            event_type: filter.event_type.as_deref(),
            failures_only: filter.failures_only,
            limit,
        };
        self.get_query("/api/v1/audit/security", &q).await
    }

    /// The whole window, newest first, each id once, up to `ceiling` rows.
    ///
    /// `Err` only when the first page fails (there is nothing to count) or
    /// the session ends. A later page that fails ends the pull with
    /// [`PullStop::Failed`] and the rows read before it.
    pub async fn security_events_window(
        &self,
        filter: &AuditFilter,
        ceiling: usize,
    ) -> Result<AuditPull, UpstreamError> {
        let mut pager = Pager::new(filter.until, ceiling);
        loop {
            let page = match self
                .security_events_page(filter, pager.cursor(), AUDIT_PAGE_ROWS)
                .await
            {
                Ok(page) => page,
                Err(UpstreamError::SessionExpired) => return Err(UpstreamError::SessionExpired),
                Err(e) if pager.is_first() => return Err(e),
                Err(e) => {
                    tracing::info!(error = %e, "a later page of security events failed; counting what was read");
                    return Ok(pager.finish(PullStop::Failed(e)));
                }
            };
            if let Some(stop) = pager.take(page) {
                return Ok(pager.finish(stop));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_790_000_000 - secs, 123_456_000)
            .unwrap()
    }

    fn ev(n: u128, secs: i64) -> SecurityEvent {
        SecurityEvent {
            id: Uuid::from_u128(n),
            event_type: "auth_attempt".into(),
            agent_id: None,
            success: Some(true),
            details: serde_json::Value::Null,
            ip_address: None,
            correlation_id: None,
            created_at: at(secs),
        }
    }

    #[test]
    fn the_cursor_keeps_every_sub_second_digit() {
        assert_eq!(rfc3339(&at(0)), "2026-09-21T14:13:20.123456Z");
        let whole = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
        assert_eq!(rfc3339(&whole), "2026-10-01T00:00:00Z");
    }

    #[test]
    fn a_repeated_boundary_row_is_counted_once_and_the_cursor_moves() {
        let mut p = Pager::new(None, 10_000);
        let first: Vec<_> = (0..AUDIT_PAGE_ROWS as u128)
            .map(|n| ev(n, n as i64))
            .collect();
        assert_eq!(p.take(first), None, "a full page asks for more");
        assert_eq!(p.cursor(), Some(at(AUDIT_PAGE_ROWS as i64 - 1)));
        // The next page starts with the previous oldest row again.
        let last = AUDIT_PAGE_ROWS as u128 - 1;
        let second = vec![ev(last, last as i64), ev(last + 1, last as i64 + 1)];
        assert_eq!(p.take(second), Some(PullStop::Complete));
        let pull = p.finish(PullStop::Complete);
        assert_eq!(pull.rows.len(), AUDIT_PAGE_ROWS + 1);
    }

    #[test]
    fn a_full_page_of_seen_rows_is_a_stall_not_a_loop() {
        let mut p = Pager::new(None, 10_000);
        let same: Vec<_> = (0..AUDIT_PAGE_ROWS as u128).map(|n| ev(n, 0)).collect();
        assert_eq!(p.take(same.clone()), None);
        assert_eq!(p.take(same), Some(PullStop::Stalled));
    }

    #[test]
    fn the_ceiling_caps_the_rows_kept() {
        let mut p = Pager::new(None, 1500);
        let page = |from: u128| -> Vec<SecurityEvent> {
            (from..from + AUDIT_PAGE_ROWS as u128)
                .map(|n| ev(n, n as i64))
                .collect()
        };
        assert_eq!(p.take(page(0)), None);
        assert_eq!(p.take(page(1000)), Some(PullStop::Capped));
        assert_eq!(p.finish(PullStop::Capped).rows.len(), 1500);

        // Exactly the ceiling in a full page: there may be more.
        let mut p = Pager::new(None, 1000);
        assert_eq!(p.take(page(0)), Some(PullStop::Capped));
        // Exactly the ceiling in a short page: the window is done.
        let mut p = Pager::new(None, 1000);
        let short: Vec<_> = (0..999u128).map(|n| ev(n, n as i64)).collect();
        assert_eq!(p.take(short), Some(PullStop::Complete));
    }
}
