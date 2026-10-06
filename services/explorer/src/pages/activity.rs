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
//! One agent's failed call leaves that agent's section "unavailable"; only a
//! session that ended escapes. With no watch list the page explains how to
//! set one and asks upstream nothing.

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
use crate::upstream::activity::{AgentClaim, AgentClaims, AGENT_CLAIMS_LIMIT};
use crate::upstream::{degrade, truncate_chars, Degraded};
use crate::view::render;

/// The window when the viewer names no `since`.
pub const DEFAULT_WINDOW_HOURS: i64 = 24;
/// Snippet length of a claim row.
const SNIPPET_CHARS: usize = 200;
/// Characters of a rejected input echoed back in the notice.
const ECHO_CHARS: usize = 64;

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
    let results: Vec<_> = stream::iter(watch.iter().copied())
        .map(|agent| async move {
            (
                agent,
                api.agent_claims_since(agent, &since, AGENT_CLAIMS_LIMIT)
                    .await,
            )
        })
        .buffered(fan_out_width(&state.config))
        .collect()
        .await;
    for (agent, result) in results {
        page.agents.push(AgentSection {
            id: agent,
            short: short_id(agent),
            agent_url: links.agent(agent),
            claims: degrade(result)?.map(|l| claims_view(l, links)),
        });
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
