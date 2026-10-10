//! `arm-operator-binding`: turn operator-binding enforcement ON for this
//! database (migration 122's `epigraph_arm_operator_binding`), ONCE.
//!
//! Arming is one-way (no disarm function; the maintenance role holds no UPDATE
//! or DELETE on the arming record), so this command first reports who would be
//! refused: every agent that authored a claim in the last `--recent-days` days
//! and is NOT bound (a human operator, a live link, or an allowlisted client's
//! agent, migration 149). Any such agent is a live writer the moment
//! enforcement starts refusing, so `--apply` REFUSES while the list is
//! non-empty, unless `--allow-unbound-writers` says the operator has decided
//! those writers stop.
//!
//! A second list covers the allowlist (migration 149): an allowlisted agent is
//! bound, but only into groups its operator writes, so its recent claims in
//! any OTHER group (its own personal group, typically) would be refused OPL02
//! once armed. Those are listed OUT-OF-SCOPE, and `--apply` refuses on them
//! under the same override. The list is restricted to `client_allowlist`
//! authors, so with an empty allowlist the report is exactly what it was
//! before 149.
//!
//! LIMIT: `claims` records the AUTHOR and the owner group, not the writing
//! principal, so the census sees writer scope only where the author was also
//! the writer. A row authored by an allowlisted agent but written by another
//! principal can be listed although it was admitted (conservative; the
//! override exists), and a write BY an allowlisted agent under another author
//! is invisible to both lists.
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
    /// `(agent, owner group, claims in the window)` for every allowlisted
    /// (migration 149) recent author whose claims sit in a group its operator
    /// does not write.
    pub out_of_scope_writers: Vec<(Uuid, Option<Uuid>, i64)>,
    /// This run armed the database.
    pub armed_now: bool,
    /// `--apply` was refused because of `unbound_writers` or
    /// `out_of_scope_writers` (nothing armed).
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

/// The allowlist census (migration 149): allowlisted agents that authored
/// claims in the last `days` days in a group their operator does not write,
/// per group.
///
/// # Errors
/// The read fails (e.g. migration 149 is not applied, which leaves the label
/// unknown and the list empty, or 122 is not).
pub async fn out_of_scope_allowlisted_writers(
    conn: &mut PgConnection,
    days: i32,
) -> anyhow::Result<Vec<(Uuid, Option<Uuid>, i64)>> {
    Ok(sqlx::query_as(
        "SELECT c.agent_id, c.owner_group_id, count(*)::bigint \
           FROM claims c \
          WHERE c.created_at > now() - make_interval(days => $1) \
          GROUP BY c.agent_id, c.owner_group_id \
         HAVING public.epigraph_author_binding(c.agent_id) = $2 \
            AND NOT COALESCE(public.epigraph_operator_writes_group( \
                      public.epigraph_human_of(c.agent_id, false), c.owner_group_id), false) \
          ORDER BY 3 DESC, 1, 2",
    )
    .bind(days)
    .bind(epigraph_db::CLIENT_ALLOWLIST_BINDING)
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
    let out_of_scope_writers = out_of_scope_allowlisted_writers(conn, days).await?;
    let system_roles = unregistered_system_roles(conn).await?;
    let mut report = ArmReport {
        already,
        unbound_writers,
        out_of_scope_writers,
        system_agent_registry_absent: system_roles.is_none(),
        unregistered_system_roles: system_roles.unwrap_or_default(),
        ..Default::default()
    };
    if !apply || report.already.is_some() {
        return Ok(report);
    }
    if (!report.unbound_writers.is_empty() || !report.out_of_scope_writers.is_empty())
        && !allow_unbound
    {
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
    // Printed only when non-empty: with an empty allowlist the report is
    // byte-identical to the one before migration 149.
    if !r.out_of_scope_writers.is_empty() {
        out.push(format!(
            "OUT-OF-SCOPE-RECENT-WRITERS\t{}\t(window: {days} day(s))",
            r.out_of_scope_writers.len()
        ));
        for (agent, group, n) in &r.out_of_scope_writers {
            let group = group.map_or_else(|| "-".to_string(), |g| g.to_string());
            out.push(format!("OUT-OF-SCOPE\t{agent}\t{group}\t{n} claim(s)"));
        }
    }
    if r.refused && !r.out_of_scope_writers.is_empty() {
        out.push(format!(
            "REFUSED-OUT-OF-SCOPE\t{} allowlisted agent/group pair(s) above authored claims in \
             the last {days} day(s) in a group their operator does not write; arming would \
             refuse every such write (OPL02). Write into a group the operator writes, revoke the \
             allowance (epigraph-operator revoke-author-binding-client), or pass \
             --allow-unbound-writers if stopping them is the decision. Nothing was armed.",
            r.out_of_scope_writers.len()
        ));
    }
    if r.refused {
        // Today's line, unchanged, and only for the unbound list; a refusal on
        // the out-of-scope list alone has its own line above.
        if !r.unbound_writers.is_empty() {
            out.push(format!(
                "REFUSED\t{} agent(s) above authored claims in the last {days} day(s) and are NOT \
             bound to a human operator; arming would refuse every one of their writes from now \
             on. Link them (epigraph-operator link), or pass --allow-unbound-writers if stopping \
             them is the decision. Nothing was armed.",
                r.unbound_writers.len()
            ));
        }
    } else if r.armed_now {
        out.push("ARMED\toperator binding is now enforced on this database".to_string());
    } else if !apply && r.already.is_none() {
        out.push("DRY RUN: nothing was armed; re-run with --apply".to_string());
    }
    out
}
