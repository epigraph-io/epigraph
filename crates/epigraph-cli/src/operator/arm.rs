//! `arm-operator-binding`: turn operator-binding enforcement ON for this
//! database (migration 122's `epigraph_arm_operator_binding`), ONCE.
//!
//! Arming is one-way (no disarm function; the maintenance role holds no UPDATE
//! or DELETE on the arming record), so this command first reports who would be
//! refused: every agent that authored a claim in the last `--recent-days` days
//! and is NOT bound (neither a human operator nor the holder of a live link).
//! Any such agent is a live writer the moment enforcement starts refusing, so
//! `--apply` REFUSES while the list is non-empty, unless
//! `--allow-unbound-writers` says the operator has decided those writers stop.
//!
//! A dry run (the default) prints the report and arms nothing.
//!
//! The census also names every system role with no `system_agents` row
//! (migration 148). Once armed, a binary at or above 148 refuses every write
//! through an unregistered system agent (workflow ingest, policy challenges),
//! so `register-system-agent` belongs BEFORE arming. The line is a report
//! only: it does not change what `--apply` refuses.

use anyhow::bail;
use sqlx::PgConnection;
use uuid::Uuid;

/// What the pre-arm census found, and what arming did.
#[derive(Debug, Default)]
pub struct ArmReport {
    /// Already armed before this run: `(armed_at, armed_by)`.
    pub already: Option<(chrono::DateTime<chrono::Utc>, String)>,
    /// `(agent, claims in the window)` for every unbound recent writer.
    pub unbound_writers: Vec<(Uuid, i64)>,
    /// This run armed the database.
    pub armed_now: bool,
    /// `--apply` was refused because of `unbound_writers` (nothing armed).
    pub refused: bool,
    /// System roles with no `system_agents` row (migration 148).
    pub unregistered_system_roles: Vec<&'static str>,
    /// The database has no `system_agents` table (below migration 148).
    pub system_agent_registry_absent: bool,
}

/// The system roles with no `system_agents` row, or `None` when the table does
/// not exist (a database below migration 148: the census still runs).
///
/// # Errors
/// A statement failed.
pub async fn unregistered_system_roles(
    conn: &mut PgConnection,
) -> anyhow::Result<Option<Vec<&'static str>>> {
    let present: bool =
        sqlx::query_scalar("SELECT to_regclass('public.system_agents') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?;
    if !present {
        return Ok(None);
    }
    let roles: Vec<&'static str> = epigraph_db::SystemAgentRole::ALL
        .iter()
        .map(|r| r.as_str())
        .collect();
    let missing: Vec<String> = sqlx::query_scalar(
        "SELECT r.role FROM unnest($1::text[]) AS r(role) \
          WHERE NOT EXISTS (SELECT 1 FROM public.system_agents s WHERE s.role = r.role) \
          ORDER BY r.role",
    )
    .bind(&roles)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Some(
        roles
            .into_iter()
            .filter(|r| missing.iter().any(|m| m == r))
            .collect(),
    ))
}

/// The census: unbound agents that authored claims in the last `days` days.
///
/// # Errors
/// The read fails (e.g. migration 122 is not applied).
pub async fn unbound_recent_writers(
    conn: &mut PgConnection,
    days: i32,
) -> anyhow::Result<Vec<(Uuid, i64)>> {
    Ok(sqlx::query_as(
        "SELECT c.agent_id, count(*)::bigint \
           FROM claims c \
          WHERE c.created_at > now() - make_interval(days => $1) \
          GROUP BY c.agent_id \
         HAVING public.epigraph_author_binding(c.agent_id) IS NULL \
          ORDER BY 2 DESC, 1",
    )
    .bind(days)
    .fetch_all(&mut *conn)
    .await?)
}

/// Report, and under `apply` arm. With unbound recent writers and no
/// `allow_unbound`, `apply` arms nothing and sets [`ArmReport::refused`].
///
/// # Errors
/// A non-positive window, or a failed statement.
pub async fn run(
    conn: &mut PgConnection,
    days: i32,
    apply: bool,
    allow_unbound: bool,
) -> anyhow::Result<ArmReport> {
    if days <= 0 {
        bail!("--recent-days must be at least 1");
    }
    let already: Option<(chrono::DateTime<chrono::Utc>, String)> =
        sqlx::query_as("SELECT armed_at, armed_by FROM public.operator_binding_arming")
            .fetch_optional(&mut *conn)
            .await?;
    let unbound_writers = unbound_recent_writers(conn, days).await?;
    let system_roles = unregistered_system_roles(conn).await?;
    let mut report = ArmReport {
        already,
        unbound_writers,
        system_agent_registry_absent: system_roles.is_none(),
        unregistered_system_roles: system_roles.unwrap_or_default(),
        ..Default::default()
    };
    if !apply || report.already.is_some() {
        return Ok(report);
    }
    if !report.unbound_writers.is_empty() && !allow_unbound {
        report.refused = true;
        return Ok(report);
    }
    report.armed_now =
        sqlx::query_scalar("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
            .fetch_one(&mut *conn)
            .await?;
    Ok(report)
}

/// The report's lines.
#[must_use]
pub fn describe(r: &ArmReport, days: i32, apply: bool) -> Vec<String> {
    let mut out = Vec::new();
    if let Some((at, by)) = &r.already {
        out.push(format!("ALREADY-ARMED\tat={at}\tby={by}"));
    }
    out.push(format!(
        "UNBOUND-RECENT-WRITERS\t{}\t(window: {days} day(s))",
        r.unbound_writers.len()
    ));
    for (agent, n) in &r.unbound_writers {
        out.push(format!("UNBOUND\t{agent}\t{n} claim(s)"));
    }
    if r.system_agent_registry_absent {
        out.push(
            "SYSTEM-AGENT-REGISTRY-ABSENT\t(migration 148 not applied; once armed, workflow \
             writes are refused by a >=148 binary)"
                .to_string(),
        );
    }
    for role in &r.unregistered_system_roles {
        out.push(format!(
            "SYSTEM-AGENT-UNREGISTERED\t{role}\t(once armed, every write through this system \
             agent is refused until it is registered: epigraph-operator register-system-agent)"
        ));
    }
    if r.refused {
        out.push(format!(
            "REFUSED\t{} agent(s) above authored claims in the last {days} day(s) and are NOT \
             bound to a human operator; arming would refuse every one of their writes from now \
             on. Link them (epigraph-operator link), or pass --allow-unbound-writers if stopping \
             them is the decision. Nothing was armed.",
            r.unbound_writers.len()
        ));
    } else if r.armed_now {
        out.push("ARMED\toperator binding is now enforced on this database".to_string());
    } else if !apply && r.already.is_none() {
        out.push("DRY RUN: nothing was armed; re-run with --apply".to_string());
    }
    out
}
