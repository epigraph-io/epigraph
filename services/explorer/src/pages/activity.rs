//! `/activity?since=`: what the watched agents did since a time (J5),
//! read-only.
//!
//! The agents are the configured watch list
//! (`EPIGRAPH_EXPLORER_WATCH_AGENTS`); there is no "my agents" route to ask.
//! For each one the page shows its newest claims created since `since`
//! ([`crate::upstream::activity`]), and marks a list the API counted more
//! rows for than it returned.
//!
//! The per-agent calls are started no more than [`fan_out_width`] at a time.
//! Every call's deadline runs from the moment it starts, queueing for the
//! viewer's in-flight cap included, so starting them all at once would let
//! the last ones of a long list spend their deadline waiting.
//!
//! Below the agents, an events tail: one call for every agent's recent
//! events since `since` ([`EVENTS_TAIL_LIMIT`] at most), kept here only when
//! a watched agent is the actor, newest first. The API's event list cannot
//! be filtered by agent and holds only a window of its newest events, so the
//! tail is labelled as corpus-wide and filtered, and makes no claim to be
//! every event of the watched agents since `since`. When the API counted
//! more events than it returned, it cut the newest end, and the tail says so.
//!
//! One agent's failed call leaves that agent's section "unavailable", and a
//! failed events call leaves only the tail "unavailable"; only a session
//! that ended escapes. With no watch list the page explains how to set one
//! and asks upstream nothing.

use std::collections::HashSet;

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, SubsecRound, Utc};
use futures::stream::{self, StreamExt};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{PageCtx, SignedIn};
use crate::config::{Config, ENV_WATCH_AGENTS};
use crate::error::AppError;
use crate::links::Links;
use crate::pages::audit::parse_time;
use crate::pages::core::vocab::{fmt_count, one_line, short_id};
use crate::state::AppState;
use crate::upstream::activity::{
    AgentClaim, AgentClaims, EventList, AGENT_CLAIMS_LIMIT, EVENTS_TAIL_LIMIT,
};
use crate::upstream::{degrade, truncate_chars, Degraded, UpstreamError};
use crate::view::render;

/// The window when the viewer names no `since`.
pub const DEFAULT_WINDOW_HOURS: i64 = 24;
/// Snippet length of a claim row.
const SNIPPET_CHARS: usize = 200;
/// Characters of a rejected input echoed back in the notice.
const ECHO_CHARS: usize = 64;
/// Watched agents' events the tail shows at most (newest first).
pub const TAIL_ROWS: usize = 100;

pub fn routes() -> Router<AppState> {
    Router::new().route("/activity", get(activity))
}

/// The raw query string; a malformed `since` is explained on the page
/// rather than turned into a 400.
#[derive(Debug, Default, Deserialize)]
pub struct RawActivityQuery {
    pub since: Option<String>,
}

/// The `since` asked for, or why it will not be sent. Without one, the last
/// [`DEFAULT_WINDOW_HOURS`] up to `now`. Accepts what the audit page
/// accepts ([`parse_time`]).
pub fn parse_since(raw: Option<&str>, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => parse_time(s).ok_or_else(|| {
            format!(
                "“{}” is not a time. Use a UTC time such as 2026-10-05T12:00:00Z.",
                truncate_chars(s, ECHO_CHARS)
            )
        }),
        None => Ok((now - chrono::Duration::hours(DEFAULT_WINDOW_HOURS)).trunc_subsecs(0)),
    }
}

/// How many per-agent calls run at once: the viewer's in-flight cap, and
/// never more than the global semaphore.
pub fn fan_out_width(config: &Config) -> usize {
    config
        .session_concurrency
        .min(config.upstream_concurrency)
        .max(1)
}

/// One claim in an agent's list.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimRow {
    pub id: Uuid,
    pub claim_url: String,
    pub text: String,
    pub created: String,
    pub superseded: bool,
}

/// One agent's claims since the window's start.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentClaimsView {
    pub rows: Vec<ClaimRow>,
    /// How many claims upstream counted for the filter.
    pub total: u64,
    /// `total` is more than the rows returned.
    pub capped: bool,
    /// `total`, thousands-separated.
    pub total_text: String,
}

/// One watched agent's section.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentSection {
    pub id: Uuid,
    pub short: String,
    pub agent_url: String,
    pub claims: Degraded<AgentClaimsView>,
}

/// One event in the tail.
#[derive(Debug, Clone, PartialEq)]
pub struct TailRow {
    pub id: Uuid,
    pub event_type: String,
    pub created: String,
    pub actor_id: Uuid,
    pub actor_short: String,
    pub actor_url: String,
}

/// The events tail: the watched agents' events among those upstream
/// returned.
#[derive(Debug, Clone, PartialEq)]
pub struct EventsTail {
    /// Newest first, at most [`TAIL_ROWS`].
    pub rows: Vec<TailRow>,
    /// The watched agents' events among those returned.
    pub watched: usize,
    /// Every agent's events upstream returned.
    pub returned: usize,
    /// Every agent's events upstream counted since `since` in its window.
    pub counted: u64,
    /// `counted` is more than `returned`: upstream cut its newest events.
    pub cut: bool,
    /// `counted` and `returned`, thousands-separated.
    pub counted_text: String,
    pub returned_text: String,
}

fn display_time(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn claim_row(c: AgentClaim, links: &Links) -> ClaimRow {
    ClaimRow {
        id: c.id,
        claim_url: links.claim(c.id),
        text: truncate_chars(&one_line(&c.content), SNIPPET_CHARS),
        created: display_time(&c.created_at),
        superseded: c.is_current == Some(false),
    }
}

/// An agent's list as the page shows it: rows in upstream's order
/// (newest first), capped when upstream counted more than it returned.
pub fn claims_view(list: AgentClaims, links: &Links) -> AgentClaimsView {
    let shown = list.claims.len() as u64;
    AgentClaimsView {
        capped: list.total > shown,
        total: list.total,
        total_text: fmt_count(list.total as i64),
        rows: list
            .claims
            .into_iter()
            .map(|c| claim_row(c, links))
            .collect(),
    }
}

/// Keep the watched agents' events, newest first, at most [`TAIL_ROWS`].
pub fn events_tail(list: EventList, watch: &[Uuid], links: &Links) -> EventsTail {
    let watch: HashSet<Uuid> = watch.iter().copied().collect();
    let returned = list.events.len();
    let mut kept: Vec<_> = list
        .events
        .into_iter()
        .filter_map(|e| match e.actor_id {
            Some(actor) if watch.contains(&actor) => Some((actor, e)),
            _ => None,
        })
        .collect();
    // Upstream sends the oldest first.
    kept.sort_by_key(|(_, e)| std::cmp::Reverse(e.created_at));
    let watched = kept.len();
    EventsTail {
        rows: kept
            .into_iter()
            .take(TAIL_ROWS)
            .map(|(actor, e)| TailRow {
                id: e.id,
                event_type: e.event_type,
                created: display_time(&e.created_at),
                actor_id: actor,
                actor_short: short_id(actor),
                actor_url: links.agent(actor),
            })
            .collect(),
        watched,
        returned,
        counted: list.total,
        cut: list.total > returned as u64,
        counted_text: fmt_count(list.total as i64),
        returned_text: fmt_count(returned as i64),
    }
}

/// One upstream call the page makes.
enum Job {
    Events,
    Agent(Uuid),
}

/// Its answer.
enum Answer {
    Events(Result<EventList, UpstreamError>),
    Agent(Uuid, Result<AgentClaims, UpstreamError>),
}

#[derive(Template)]
#[template(path = "activity.html")]
struct ActivityPage {
    ctx: PageCtx,
    action_url: String,
    /// The form's `since` as the viewer typed it.
    since_input: String,
    /// The watch list is empty.
    no_watch_list: bool,
    watch_var: &'static str,
    /// Why nothing was asked of upstream (a bad `since`).
    problem: Option<String>,
    since_text: String,
    agents: Vec<AgentSection>,
    /// `None` when nothing was asked of upstream.
    tail: Option<Degraded<EventsTail>>,
    tail_limit_text: String,
}

async fn activity(
    State(state): State<AppState>,
    user: SignedIn,
    Query(raw): Query<RawActivityQuery>,
) -> Result<Html<String>, AppError> {
    let links = &state.links;
    let watch = &state.config.watch_agents;
    let mut page = ActivityPage {
        ctx: user.ctx.clone(),
        action_url: links.activity(),
        since_input: raw.since.clone().unwrap_or_default(),
        no_watch_list: watch.is_empty(),
        watch_var: ENV_WATCH_AGENTS,
        problem: None,
        since_text: String::new(),
        agents: Vec::new(),
        tail: None,
        tail_limit_text: fmt_count(i64::from(EVENTS_TAIL_LIMIT)),
    };
    if watch.is_empty() {
        return render(&page);
    }
    let since = match parse_since(raw.since.as_deref(), Utc::now()) {
        Ok(t) => t,
        Err(why) => {
            page.problem = Some(why);
            return render(&page);
        }
    };
    page.since_text = display_time(&since);

    let api = user.api(&state);
    let api = &api;
    // The events call is one of the bounded calls, not an extra one beside
    // them.
    let jobs = std::iter::once(Job::Events).chain(watch.iter().copied().map(Job::Agent));
    let answers: Vec<Answer> = stream::iter(jobs)
        .map(|job| async move {
            match job {
                Job::Events => Answer::Events(api.events_since(&since, EVENTS_TAIL_LIMIT).await),
                Job::Agent(agent) => Answer::Agent(
                    agent,
                    api.agent_claims_since(agent, &since, AGENT_CLAIMS_LIMIT)
                        .await,
                ),
            }
        })
        .buffered(fan_out_width(&state.config))
        .collect()
        .await;
    for answer in answers {
        match answer {
            Answer::Events(result) => {
                page.tail = Some(degrade(result)?.map(|l| events_tail(l, watch, links)));
            }
            Answer::Agent(agent, result) => page.agents.push(AgentSection {
                id: agent,
                short: short_id(agent),
                agent_url: links.agent(agent),
                claims: degrade(result)?.map(|l| claims_view(l, links)),
            }),
        }
    }
    render(&page)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn since_defaults_to_the_last_day_and_reads_utc_times() {
        let now = Utc.with_ymd_and_hms(2026, 10, 5, 12, 30, 45).unwrap()
            + chrono::Duration::milliseconds(250);
        assert_eq!(
            parse_since(None, now),
            Ok(Utc.with_ymd_and_hms(2026, 10, 4, 12, 30, 45).unwrap())
        );
        assert_eq!(parse_since(Some("  "), now), parse_since(None, now));
        assert_eq!(
            parse_since(Some("2026-10-01T02:00:00+02:00"), now),
            Ok(Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap())
        );
        assert_eq!(
            parse_since(Some("2026-10-01"), now),
            Ok(Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap())
        );
        let err = parse_since(Some("yesterday"), now).unwrap_err();
        assert!(err.contains("is not a time"), "{err}");
    }

    #[test]
    fn the_tail_keeps_watched_actors_newest_first_and_marks_a_cut() {
        use crate::upstream::activity::GraphEvent;
        let links = Links::new("https://explorer.example.com", "");
        let (a, b, other) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let ev = |n: u128, actor: Option<Uuid>, hour: u32| GraphEvent {
            id: Uuid::from_u128(100 + n),
            event_type: "claim.created".into(),
            actor_id: actor,
            created_at: Utc.with_ymd_and_hms(2026, 10, 1, hour, 0, 0).unwrap(),
        };
        let list = EventList {
            events: vec![
                ev(1, Some(a), 1),
                ev(2, Some(other), 2),
                ev(3, None, 3),
                ev(4, Some(b), 4),
            ],
            total: 4,
        };
        let tail = events_tail(list, &[a, b], &links);
        let ids: Vec<Uuid> = tail.rows.iter().map(|r| r.id).collect();
        assert_eq!(ids, [Uuid::from_u128(104), Uuid::from_u128(101)]);
        assert_eq!((tail.watched, tail.returned, tail.cut), (2, 4, false));

        let many = EventList {
            events: (0..(TAIL_ROWS as u128 + 5))
                .map(|n| ev(n, Some(a), 1))
                .collect(),
            total: 2000,
        };
        let tail = events_tail(many, &[a], &links);
        assert_eq!(tail.rows.len(), TAIL_ROWS);
        assert_eq!(tail.watched, TAIL_ROWS + 5);
        assert!(tail.cut);
    }

    #[test]
    fn a_list_is_capped_only_when_upstream_counted_more() {
        let links = Links::new("https://explorer.example.com", "");
        let claim = |n: u128| AgentClaim {
            id: Uuid::from_u128(n),
            content: "a\n claim".into(),
            is_current: None,
            created_at: Utc.with_ymd_and_hms(2026, 10, 2, 0, 0, 0).unwrap(),
        };
        let whole = claims_view(
            AgentClaims {
                claims: vec![claim(1), claim(2)],
                total: 2,
            },
            &links,
        );
        assert!(!whole.capped);
        assert_eq!(whole.rows[0].text, "a claim");
        assert!(
            !whole.rows[0].superseded,
            "unknown currency is not shown as superseded"
        );
        let cut = claims_view(
            AgentClaims {
                claims: vec![claim(1)],
                total: 9,
            },
            &links,
        );
        assert!(cut.capped);
        assert_eq!(cut.total, 9);
    }
}
