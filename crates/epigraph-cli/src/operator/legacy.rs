//! `link-legacy-authors`: tie every legacy author to a human operator with a
//! RETIRED link (migration 122's `epigraph_link_legacy_authors`).
//!
//! The definer decides everything (who is a candidate, who is skipped and why,
//! the audit row); this module passes the operator, the exclusion list and the
//! quiet-window cutoff, runs the call in ONE transaction, and commits it under
//! `--apply` or rolls it back otherwise, so a dry run prints exactly what the
//! definer did.
//!
//! # Registered system agents are always excluded
//!
//! Migration 148 refuses a RETIRED link of a registered system agent (it would
//! never be bindable again), and the definer's insert is inside one call, so
//! one such agent among the candidates would abort the whole tie. The command
//! therefore adds every `system_agents` agent to the exclusion list
//! ([`registered_system_agents`]) and names each one; the definer then reports
//! it `skipped:excluded`. A database below 148 has none.
//!
//! # The quiet window
//!
//! A retired link is permanent and never promoted, and once operator binding is
//! armed a retired identity can never write again. So by default an agent that
//! authored a claim within `--quiet-days` (30) is SKIPPED as `recent_writer`:
//! it may still be running, and wants a LIVE link (`epigraph-operator link`)
//! instead. `--no-quiet-window` ties every candidate, recent or not.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use std::collections::BTreeMap;
use uuid::Uuid;

/// Everything the command was told.
#[derive(Clone, Debug)]
pub struct Options {
    pub operator: Uuid,
    pub exclude: Vec<Uuid>,
    /// Claims authored at or after this instant make their author a
    /// `recent_writer` (skipped). `None` disables the window.
    pub quiet_since: Option<DateTime<Utc>>,
    pub apply: bool,
}

/// Every registered system agent (migration 148), or none on a database
/// without the registry.
///
/// # Errors
/// A statement failed.
pub async fn registered_system_agents(conn: &mut PgConnection) -> anyhow::Result<Vec<Uuid>> {
    let present: bool =
        sqlx::query_scalar("SELECT to_regclass('public.system_agents') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?;
    if !present {
        return Ok(Vec::new());
    }
    Ok(epigraph_db::SystemAgentRepository::registered_agent_ids(&mut *conn).await?)
}

/// Add `system_agents` to `exclude` (deduplicated); returns the ids it added
/// that were not already excluded.
#[must_use]
pub fn exclude_system_agents(exclude: &mut Vec<Uuid>, system_agents: &[Uuid]) -> Vec<Uuid> {
    let mut added = Vec::new();
    for id in system_agents {
        if !exclude.contains(id) {
            exclude.push(*id);
            added.push(*id);
        }
    }
    added
}

/// One `(agent, outcome)` per candidate, as the definer returned them.
///
/// # Errors
/// The definer refused (a non-human operator, an operated operator, RVK01 /
/// RVK02, ...), or a statement failed. Nothing is written in either case.
pub async fn run(conn: &mut PgConnection, opts: &Options) -> anyhow::Result<Vec<(Uuid, String)>> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT agent_id, outcome FROM public.epigraph_link_legacy_authors($1, $2, $3)",
    )
    .bind(opts.operator)
    .bind(&opts.exclude)
    .bind(opts.quiet_since)
    .fetch_all(&mut *tx)
    .await?;
    if opts.apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(rows)
}

/// Count per outcome.
#[must_use]
pub fn summarize(rows: &[(Uuid, String)]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for (_, o) in rows {
        *out.entry(o.clone()).or_default() += 1;
    }
    out
}

/// The lines to print: every agent with its outcome, then the totals.
#[must_use]
pub fn describe(rows: &[(Uuid, String)], opts: &Options) -> Vec<String> {
    let mut out = vec![format!(
        "link-legacy-authors: operator={} excluded={} quiet_since={} mode={}",
        opts.operator,
        opts.exclude.len(),
        opts.quiet_since
            .map_or_else(|| "none".to_string(), |t| t.to_rfc3339()),
        if opts.apply { "APPLY" } else { "DRY-RUN" }
    )];
    for (agent, outcome) in rows {
        let tag = if outcome == "linked" {
            "LINKED-RETIRED".to_string()
        } else {
            format!("SKIPPED:{}", outcome.trim_start_matches("skipped:"))
        };
        out.push(format!("{tag}\t{agent}"));
    }
    out.push(format!("CANDIDATES\t{}", rows.len()));
    for (outcome, n) in summarize(rows) {
        out.push(format!("OUTCOME\t{outcome}\t{n}"));
    }
    if !opts.apply {
        out.push(
            "DRY RUN: the call above ran and was rolled back (its audit row with it)".to_string(),
        );
    }
    out
}
