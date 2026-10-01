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
    let mut report = ArmReport {
        already,
        unbound_writers,
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
