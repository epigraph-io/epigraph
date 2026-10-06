//! `/audit?since=&until=&type=&failures=`: the security events the viewer
//! may read since a time, counted by type (J4), read-only.
//!
//! The window is pulled page by page ([`crate::upstream::audit`]) up to the
//! configured row ceiling and grouped here by `event_type`, with each type's
//! failures (`success = false`). `type=` drills down to that type's raw rows;
//! `failures=1` asks upstream for failures only.
//!
//! What can go wrong is shown, never a 500:
//! - a token whose granted scope lacks `audit:read` gets an explanation and
//!   upstream is not asked (an upstream 403 gets the same answer);
//! - a first page that fails leaves the section "unavailable";
//! - a later page that fails, or a window that cannot be paged past, keeps
//!   the counts read so far under an "incomplete" banner;
//! - a window holding more than the ceiling is marked "capped".
//!
//! Which rows the viewer may read is the kernel's decision. The page compares
//! the rows it read with the viewer's own agent id (the `agent_id` its access
//! token names, [`crate::upstream::identity::token_agent_id`]), which is the
//! id the kernel writes on the viewer's own events:
//! - every row is the viewer's own: "every event in this window is one of
//!   your own security events", stated as a fact about the window only. A
//!   window of the viewer's own rows does not show what the ACCOUNT may read
//!   (an instance admin's quiet, failures-only or drilled window holds only
//!   their own rows too), so the note says that it does not;
//! - a row has no agent, or another agent's id: this account reads more than
//!   its own events;
//! - no row, or the viewer's own id is not known (a token that names no
//!   agent): the window cannot say, and the page says that rather than guess.
//!   Without the viewer's id, rows of two agents or an unattributed row still
//!   show the account reads beyond one agent's trail.

use std::collections::{BTreeMap, HashSet};

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, NaiveDate, NaiveDateTime, SubsecRound, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{PageCtx, SignedIn};
use crate::error::AppError;
use crate::links::Links;
use crate::pages::core::vocab::{fmt_count, short_id};
use crate::state::AppState;
use crate::upstream::audit::{
    rfc3339, AuditFilter, AuditPull, PullStop, SecurityEvent, AUDIT_PAGE_ROWS, AUDIT_READ_SCOPE,
};
use crate::upstream::identity::token_agent_id;
use crate::upstream::{truncate_chars, UpstreamError};
use crate::view::render;

/// The window when the viewer names no `since`.
pub const DEFAULT_WINDOW_HOURS: i64 = 24;
/// Raw rows a drill-down shows (newest first).
pub const DRILL_ROWS: usize = 200;
/// Longest `type=` accepted.
pub const MAX_TYPE_CHARS: usize = 100;
/// `details` is shown as one line of JSON, cut at this many characters.
const DETAILS_CHARS: usize = 300;
/// Characters of a rejected input echoed back in the notice.
const ECHO_CHARS: usize = 64;

pub fn routes() -> Router<AppState> {
    Router::new().route("/audit", get(audit))
}

/// The raw query string. Every field is a string, so a malformed value is
/// explained on the page rather than turned into a 400.
#[derive(Debug, Default, Deserialize)]
pub struct RawAuditQuery {
    pub since: Option<String>,
    pub until: Option<String>,
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    pub failures: Option<String>,
}

/// A UTC time: RFC 3339 (any offset), or `YYYY-MM-DDTHH:MM[:SS[.f]]` /
/// `YYYY-MM-DD HH:MM[:SS]` read as UTC, or a bare date (its midnight UTC).
pub fn parse_time(raw: &str) -> Option<DateTime<Utc>> {
    let raw = raw.trim();
    if let Ok(t) = DateTime::parse_from_rfc3339(raw) {
        return Some(t.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
    ] {
        if let Ok(t) = NaiveDateTime::parse_from_str(raw, fmt) {
            return Some(t.and_utc());
        }
    }
    NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|t| t.and_utc())
}

fn blank_to_none(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|v| !v.is_empty())
}

fn not_a_time(raw: &str) -> String {
    format!(
        "“{}” is not a time. Use a UTC time such as 2026-10-05T12:00:00Z.",
        truncate_chars(raw, ECHO_CHARS)
    )
}

/// The window and filters the query asks for, or why it will not be sent.
/// Without a `since`, the last [`DEFAULT_WINDOW_HOURS`] up to `now`.
pub fn parse_window(raw: &RawAuditQuery, now: DateTime<Utc>) -> Result<AuditFilter, String> {
    let since = match blank_to_none(raw.since.as_deref()) {
        Some(s) => parse_time(s).ok_or_else(|| not_a_time(s))?,
        None => (now - chrono::Duration::hours(DEFAULT_WINDOW_HOURS)).trunc_subsecs(0),
    };
    let until = match blank_to_none(raw.until.as_deref()) {
        Some(u) => Some(parse_time(u).ok_or_else(|| not_a_time(u))?),
        None => None,
    };
    if until.is_some_and(|u| u < since) {
        return Err("The window ends before it starts: “until” is earlier than “since”.".into());
    }
    let event_type = match blank_to_none(raw.event_type.as_deref()) {
        Some(t) if t.chars().count() > MAX_TYPE_CHARS || t.chars().any(char::is_control) => {
            return Err("That event type is not valid.".into())
        }
        other => other.map(str::to_string),
    };
    let failures_only = matches!(
        raw.failures
            .as_deref()
            .map(|f| f.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1" | "true" | "on" | "yes")
    );
    Ok(AuditFilter {
        since,
        until,
        event_type,
        failures_only,
    })
}

/// Whether a token's granted scope (as its token response listed it)
/// includes `wanted`; `None` when the scope is not known.
pub fn token_grants(scope: Option<&str>, wanted: &str) -> Option<bool> {
    scope.map(|s| s.split_whitespace().any(|g| g == wanted))
}

/// One `event_type`'s row of counts.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TypeCount {
    pub event_type: String,
    pub total: u64,
    /// Events with `success = false`; a NULL outcome is not a failure.
    pub failures: u64,
    /// This window, drilled down to this type.
    #[serde(skip)]
    pub drill_url: String,
}

/// One raw event in a drill-down.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EventRow {
    pub id: Uuid,
    pub created_at: String,
    /// `success`, `failure`, or `none`.
    pub outcome: &'static str,
    pub agent_id: Option<Uuid>,
    pub ip_address: Option<String>,
    pub correlation_id: Option<String>,
    /// `details` as one line of JSON, cut to a few hundred characters.
    pub details: String,
    #[serde(skip)]
    pub created: String,
    #[serde(skip)]
    pub agent_short: Option<String>,
    #[serde(skip)]
    pub agent_url: Option<String>,
}

/// Whose events a window shows, judged against the viewer's own agent id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventScope {
    /// Every row is the viewer's own. A fact about the window only: it does
    /// not show that the account may read no one else's events.
    Own,
    /// A row has no agent, or names an agent that is not the viewer.
    BeyondOwn,
    /// No row, or the viewer's own agent id is not known.
    Unknown,
}

/// Judge `rows` against `viewer` (see the module doc).
pub fn event_scope(rows: &[SecurityEvent], viewer: Option<Uuid>) -> EventScope {
    let unattributed = rows.iter().any(|e| e.agent_id.is_none());
    let agents: HashSet<Uuid> = rows.iter().filter_map(|e| e.agent_id).collect();
    match viewer {
        _ if unattributed => EventScope::BeyondOwn,
        Some(v) if agents.iter().any(|a| *a != v) => EventScope::BeyondOwn,
        None if agents.len() > 1 => EventScope::BeyondOwn,
        Some(_) if !agents.is_empty() => EventScope::Own,
        _ => EventScope::Unknown,
    }
}

/// What was counted in a window.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuditCounts {
    /// Busiest type first.
    pub types: Vec<TypeCount>,
    pub events_read: usize,
    /// The ceiling, when the window holds more rows than it.
    pub capped_at: Option<usize>,
    /// Why the counts stop short of the window, when they do.
    pub partial: Option<String>,
    /// Whose events the rows show.
    pub scope: EventScope,
    /// `scope` is [`EventScope::BeyondOwn`].
    pub reads_beyond_own: bool,
    /// Drill-down only: the newest [`DRILL_ROWS`] rows.
    pub rows: Vec<EventRow>,
}

impl AuditCounts {
    pub fn is_own(&self) -> bool {
        self.scope == EventScope::Own
    }
}

/// The audit section's state.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuditResult {
    /// The token does not carry `audit:read`.
    NotGranted,
    /// Nothing could be read.
    Unavailable {
        reason: String,
    },
    Counted(AuditCounts),
}

impl AuditResult {
    pub fn counts(&self) -> Option<&AuditCounts> {
        match self {
            AuditResult::Counted(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_not_granted(&self) -> bool {
        matches!(self, AuditResult::NotGranted)
    }

    pub fn unavailable(&self) -> Option<&str> {
        match self {
            AuditResult::Unavailable { reason } => Some(reason),
            _ => None,
        }
    }
}

/// The page's data, also served as JSON by `/bff/audit`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuditView {
    pub since: String,
    pub until: Option<String>,
    pub event_type: Option<String>,
    pub failures_only: bool,
    pub result: AuditResult,
}

fn outcome(success: Option<bool>) -> &'static str {
    match success {
        Some(true) => "success",
        Some(false) => "failure",
        None => "none",
    }
}

fn event_row(e: SecurityEvent, links: &Links) -> EventRow {
    let details = match &e.details {
        serde_json::Value::Null => String::new(),
        v => truncate_chars(&v.to_string(), DETAILS_CHARS),
    };
    EventRow {
        id: e.id,
        created_at: rfc3339(&e.created_at),
        outcome: outcome(e.success),
        agent_id: e.agent_id,
        ip_address: e.ip_address,
        correlation_id: e.correlation_id,
        details,
        created: e.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        agent_short: e.agent_id.map(short_id),
        agent_url: e.agent_id.map(|id| links.agent(id)),
    }
}

/// Count a pull by type. `drill` keeps the newest [`DRILL_ROWS`] rows;
/// `drill_url` builds a type's drill-down link; `viewer` is the viewer's own
/// agent id, if known.
pub fn tally(
    pull: AuditPull,
    ceiling: usize,
    drill: bool,
    viewer: Option<Uuid>,
    links: &Links,
    drill_url: impl Fn(&str) -> String,
) -> AuditCounts {
    let mut by_type: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for e in &pull.rows {
        let entry = by_type.entry(e.event_type.clone()).or_default();
        entry.0 += 1;
        if e.success == Some(false) {
            entry.1 += 1;
        }
    }
    let scope = event_scope(&pull.rows, viewer);
    let mut types: Vec<TypeCount> = by_type
        .into_iter()
        .map(|(event_type, (total, failures))| TypeCount {
            drill_url: drill_url(&event_type),
            event_type,
            total,
            failures,
        })
        .collect();
    types.sort_by(|a, b| {
        b.total
            .cmp(&a.total)
            .then_with(|| a.event_type.cmp(&b.event_type))
    });
    let (capped_at, partial) = match &pull.stop {
        PullStop::Complete => (None, None),
        PullStop::Capped => (Some(ceiling), None),
        PullStop::Stalled => (
            None,
            Some(format!(
                "more than {} events share one timestamp, so the window cannot be paged past them.",
                fmt_count(AUDIT_PAGE_ROWS as i64)
            )),
        ),
        PullStop::Failed(e) => (
            None,
            Some(format!(
                "a later page of events could not be read. {}",
                e.user_message()
            )),
        ),
    };
    let events_read = pull.rows.len();
    let rows = if drill {
        pull.rows
            .into_iter()
            .take(DRILL_ROWS)
            .map(|e| event_row(e, links))
            .collect()
    } else {
        Vec::new()
    };
    AuditCounts {
        types,
        events_read,
        capped_at,
        partial,
        scope,
        reads_beyond_own: scope == EventScope::BeyondOwn,
        rows,
    }
}

/// Read and count the window for this viewer. Only a session that ended
/// escapes as an error; every other failure is a state of the view.
pub async fn compose(
    state: &AppState,
    user: &SignedIn,
    filter: &AuditFilter,
) -> Result<AuditView, AppError> {
    let since = rfc3339(&filter.since);
    let until = filter.until.as_ref().map(rfc3339);
    let scope = user
        .auth
        .session_id()
        .and_then(|id| state.sessions.get(id))
        .and_then(|s| s.scope);
    let result = if token_grants(scope.as_deref(), AUDIT_READ_SCOPE) == Some(false) {
        // The token response said what it granted, and `audit:read` is not
        // in it: upstream would refuse. Do not ask.
        AuditResult::NotGranted
    } else {
        let api = user.api(state);
        let ceiling = state.config.audit_row_ceiling;
        match api.security_events_window(filter, ceiling).await {
            Ok(pull) => {
                let drill_url = |t: &str| {
                    state.links.audit_page(
                        Some(&since),
                        until.as_deref(),
                        Some(t),
                        filter.failures_only,
                    )
                };
                // The viewer's own agent, read from its own token for
                // display (the request's current token: a refresh mid-pull
                // keeps the agent).
                let viewer = user.auth.bearer().and_then(token_agent_id);
                AuditResult::Counted(tally(
                    pull,
                    ceiling,
                    filter.event_type.is_some(),
                    viewer,
                    &state.links,
                    drill_url,
                ))
            }
            Err(UpstreamError::SessionExpired) => return Err(AppError::SessionExpired),
            Err(UpstreamError::Forbidden { .. }) => AuditResult::NotGranted,
            Err(e) => {
                tracing::info!(error = %e, "security events unavailable");
                AuditResult::Unavailable {
                    reason: e.user_message().to_string(),
                }
            }
        }
    };
    Ok(AuditView {
        since,
        until,
        event_type: filter.event_type.clone(),
        failures_only: filter.failures_only,
        result,
    })
}

/// The form's values as the viewer will see them again.
struct FormValues {
    since: String,
    until: String,
    event_type: String,
    failures_only: bool,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditPage {
    ctx: PageCtx,
    action_url: String,
    form: FormValues,
    /// Why nothing was asked of upstream (a bad window).
    problem: Option<String>,
    /// `None` when nothing was asked.
    view: Option<AuditView>,
    since_text: String,
    until_text: Option<String>,
    events_read_text: String,
    capped_text: String,
    drill_note: String,
    /// The same window with "failures only" flipped.
    failures_toggle_url: String,
    /// The same window, every type.
    all_types_url: String,
}

fn display_time(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

async fn audit(
    State(state): State<AppState>,
    user: SignedIn,
    Query(raw): Query<RawAuditQuery>,
) -> Result<Html<String>, AppError> {
    let links = &state.links;
    let mut page = AuditPage {
        ctx: user.ctx.clone(),
        action_url: links.audit(),
        form: FormValues {
            since: raw.since.clone().unwrap_or_default(),
            until: raw.until.clone().unwrap_or_default(),
            event_type: raw.event_type.clone().unwrap_or_default(),
            failures_only: false,
        },
        problem: None,
        view: None,
        since_text: String::new(),
        until_text: None,
        events_read_text: String::new(),
        capped_text: String::new(),
        drill_note: String::new(),
        failures_toggle_url: String::new(),
        all_types_url: String::new(),
    };
    match parse_window(&raw, Utc::now()) {
        Err(why) => page.problem = Some(why),
        Ok(filter) => {
            let view = compose(&state, &user, &filter).await?;
            page.form = FormValues {
                since: view.since.clone(),
                until: view.until.clone().unwrap_or_default(),
                event_type: view.event_type.clone().unwrap_or_default(),
                failures_only: view.failures_only,
            };
            page.since_text = display_time(&filter.since);
            page.until_text = filter.until.as_ref().map(display_time);
            page.failures_toggle_url = links.audit_page(
                Some(&view.since),
                view.until.as_deref(),
                view.event_type.as_deref(),
                !view.failures_only,
            );
            page.all_types_url = links.audit_page(
                Some(&view.since),
                view.until.as_deref(),
                None,
                view.failures_only,
            );
            if let Some(c) = view.result.counts() {
                page.events_read_text = fmt_count(c.events_read as i64);
                page.capped_text = fmt_count(c.capped_at.unwrap_or_default() as i64);
                page.drill_note = if c.rows.len() < c.events_read {
                    format!(
                        "Showing the newest {} of {} events.",
                        fmt_count(c.rows.len() as i64),
                        fmt_count(c.events_read as i64)
                    )
                } else {
                    "Every event, newest first.".to_string()
                };
            }
            page.view = Some(view);
        }
    }
    render(&page)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn raw(since: Option<&str>, until: Option<&str>) -> RawAuditQuery {
        RawAuditQuery {
            since: since.map(str::to_string),
            until: until.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn the_window_defaults_to_the_last_day_and_reads_utc_times() {
        let now = Utc.with_ymd_and_hms(2026, 10, 5, 12, 0, 0).unwrap()
            + chrono::Duration::milliseconds(750);
        let f = parse_window(&raw(None, None), now).unwrap();
        assert_eq!(
            f.since,
            Utc.with_ymd_and_hms(2026, 10, 4, 12, 0, 0).unwrap(),
            "24 h back, whole seconds"
        );
        assert_eq!(f.until, None);
        assert!(!f.failures_only && f.event_type.is_none());
        assert_eq!(
            parse_window(&raw(Some("  "), Some("")), now).unwrap().since,
            f.since,
            "blank is unset"
        );

        let want = Utc.with_ymd_and_hms(2026, 10, 1, 6, 30, 0).unwrap();
        for s in [
            "2026-10-01T06:30:00Z",
            "2026-10-01T08:30:00+02:00",
            "2026-10-01T06:30",
            "2026-10-01T06:30:00",
            "2026-10-01 06:30",
        ] {
            assert_eq!(parse_time(s), Some(want), "{s}");
        }
        assert_eq!(
            parse_time("2026-10-01"),
            Some(Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap())
        );
        for bad in ["yesterday", "2026-13-01", "1696000000", ""] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_bad_window_is_refused_with_a_reason() {
        let now = Utc::now();
        let e = parse_window(&raw(Some("soon"), None), now).unwrap_err();
        assert!(e.contains("“soon” is not a time"), "{e}");
        let e = parse_window(&raw(None, Some("x")), now).unwrap_err();
        assert!(e.contains("is not a time"), "{e}");
        let e = parse_window(
            &raw(Some("2026-10-02T00:00:00Z"), Some("2026-10-01T00:00:00Z")),
            now,
        )
        .unwrap_err();
        assert!(e.contains("ends before it starts"), "{e}");
        assert!(parse_window(
            &raw(Some("2026-10-01T00:00:00Z"), Some("2026-10-01T00:00:00Z")),
            now
        )
        .is_ok());
        let long = RawAuditQuery {
            event_type: Some("x".repeat(MAX_TYPE_CHARS + 1)),
            ..Default::default()
        };
        assert!(parse_window(&long, now).is_err());
        let flags = |v: &str| {
            parse_window(
                &RawAuditQuery {
                    failures: Some(v.into()),
                    ..Default::default()
                },
                now,
            )
            .unwrap()
            .failures_only
        };
        assert!(flags("1") && flags("true") && flags(" ON "));
        assert!(!flags("0") && !flags("") && !flags("no"));
    }

    fn row(n: u128, agent: Option<u128>) -> SecurityEvent {
        SecurityEvent {
            id: Uuid::from_u128(n),
            event_type: "auth_attempt".into(),
            agent_id: agent.map(Uuid::from_u128),
            success: Some(false),
            details: serde_json::Value::Null,
            ip_address: None,
            correlation_id: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn whose_events_is_judged_against_the_viewers_own_agent() {
        use EventScope::*;
        let me = Some(Uuid::from_u128(7));
        for (label, rows, viewer, want) in [
            ("all mine", vec![row(1, Some(7)), row(2, Some(7))], me, Own),
            // One agent that is not the viewer: an admin's window filled by
            // one client's failures is not "your own".
            ("one other agent", vec![row(1, Some(42))], me, BeyondOwn),
            (
                "mine and another",
                vec![row(1, Some(7)), row(2, Some(42))],
                me,
                BeyondOwn,
            ),
            (
                "unattributed",
                vec![row(1, Some(7)), row(2, None)],
                me,
                BeyondOwn,
            ),
            ("empty window", vec![], me, Unknown),
            // The viewer's id is not known: one agent cannot be called own.
            (
                "one agent, viewer unknown",
                vec![row(1, Some(7))],
                None,
                Unknown,
            ),
            (
                "two agents, viewer unknown",
                vec![row(1, Some(7)), row(2, Some(42))],
                None,
                BeyondOwn,
            ),
            (
                "unattributed, viewer unknown",
                vec![row(1, None)],
                None,
                BeyondOwn,
            ),
            ("empty, viewer unknown", vec![], None, Unknown),
        ] {
            assert_eq!(event_scope(&rows, viewer), want, "{label}");
        }
    }

    #[test]
    fn a_scope_is_granted_only_as_a_whole_word() {
        assert_eq!(token_grants(None, AUDIT_READ_SCOPE), None, "unknown");
        assert_eq!(
            token_grants(Some("claims:read audit:read"), AUDIT_READ_SCOPE),
            Some(true)
        );
        assert_eq!(
            token_grants(Some("claims:read"), AUDIT_READ_SCOPE),
            Some(false)
        );
        assert_eq!(
            token_grants(Some("audit:readonly"), AUDIT_READ_SCOPE),
            Some(false)
        );
        assert_eq!(token_grants(Some(""), AUDIT_READ_SCOPE), Some(false));
    }
}
