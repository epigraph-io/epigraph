//! `restore-role-successor`: give a role's running successor the group back
//! after its root identity was detached (backlog 9073f0a5; migration 264's
//! `epigraph_restore_role_successor`).
//!
//! Re-attaching a detached root identity by name does not bring back a
//! successor whose old succession copy (chained to the root's detached row)
//! still covers the window. The definer does the documented pair (detach that
//! copy, attach the successor by name) in one audited act, after re-attaching
//! the root by name if it is not, and only where a copy written fresh from the
//! root's row would admit the successor; otherwise it refuses `ROL04` and
//! writes nothing. Every attach and detach is audited by `role_agents`' own
//! trigger, and the act by one `platform.role_successor_restored` row.
//!
//! This module runs the call in ONE transaction, committed under `--apply` and
//! rolled back otherwise, so a dry run prints exactly what the definer did.

use anyhow::Context;
use sqlx::PgConnection;
use std::fmt::Write as _;
use uuid::Uuid;

/// One step the definer reported, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// `root_attached`, `root_already_attached`, `successor_already_attached`,
    /// `successor_unchanged`, `copy_detached`, `successor_attached` or
    /// `descendant_still_out`.
    pub step: String,
    pub agent: Uuid,
    pub attachment: Option<Uuid>,
}

/// Whether the call restored the successor (its new row made by name).
#[must_use]
pub fn restored(steps: &[Step]) -> bool {
    steps.iter().any(|s| s.step == "successor_attached")
}

/// One stable, grep-able line per step.
#[must_use]
pub fn describe(steps: &[Step], apply: bool) -> String {
    let mut out = String::new();
    for s in steps {
        let attachment = s
            .attachment
            .map_or_else(|| "-".to_string(), |a| a.to_string());
        let note = match s.step.as_str() {
            "descendant_still_out" => {
                "\tnot changed: restore it with --root <the successor above> if it runs"
            }
            "successor_unchanged" => "\tits copies already chain through live rows",
            _ => "",
        };
        let _ = writeln!(
            out,
            "{}{}\tagent={}\tattachment={attachment}{note}",
            if apply || matches!(s.step.as_str(), "descendant_still_out") {
                ""
            } else {
                "WOULD "
            },
            s.step.to_uppercase().replace('_', "-"),
            s.agent
        );
    }
    out.truncate(out.trim_end().len());
    out
}

/// The text of a refused call, with the definer's HINT (which `Display`
/// drops).
fn refusal(successor: Uuid, e: &sqlx::Error) -> String {
    let mut text = format!("restoring {successor}: {e}");
    if let Some(hint) = e
        .as_database_error()
        .and_then(|d| d.try_downcast_ref::<sqlx::postgres::PgDatabaseError>())
        .and_then(sqlx::postgres::PgDatabaseError::hint)
    {
        let _ = write!(text, " HINT: {hint}");
    }
    text
}

/// Restore `successor` under `role` through `root`.
///
/// # Errors
/// The definer refused (not a maintenance session, a missing reason, a
/// successor a fresh copy would not admit: `ROL04`), or a statement failed.
/// Nothing is written in either case.
pub async fn run(
    conn: &mut PgConnection,
    role: &str,
    root: Uuid,
    successor: Uuid,
    valid_to: Option<chrono::DateTime<chrono::Utc>>,
    reason: &str,
    apply: bool,
) -> anyhow::Result<Vec<Step>> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let rows: Vec<(String, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT out_step, out_agent_id, out_attachment_id \
           FROM public.epigraph_restore_role_successor($1, $2, $3, $4, $5)",
    )
    .bind(role)
    .bind(root)
    .bind(successor)
    .bind(valid_to)
    .bind(reason)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| anyhow::anyhow!(refusal(successor, &e)))?;
    let steps = rows
        .into_iter()
        .map(|(step, agent, attachment)| Step {
            step,
            agent,
            attachment,
        })
        .collect();
    if apply {
        tx.commit().await.context("committing the restore")?;
    } else {
        tx.rollback().await?;
    }
    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(s: &str, agent: Uuid, attachment: Option<Uuid>) -> Step {
        Step {
            step: s.to_string(),
            agent,
            attachment,
        }
    }

    #[test]
    fn a_dry_run_says_would_and_a_descendant_is_reported_as_is() {
        let (root, succ, desc, a) = (
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            Uuid::from_u128(4),
        );
        let steps = [
            step("root_attached", root, Some(a)),
            step("successor_attached", succ, Some(a)),
            step("descendant_still_out", desc, None),
        ];
        let dry = describe(&steps, false);
        let lines: Vec<&str> = dry.lines().collect();
        assert_eq!(lines.len(), 3, "{dry}");
        assert!(lines[0].starts_with("WOULD ROOT-ATTACHED\tagent="), "{dry}");
        assert!(lines[1].starts_with("WOULD SUCCESSOR-ATTACHED\t"), "{dry}");
        assert!(lines[2].starts_with("DESCENDANT-STILL-OUT\t"), "{dry}");
        assert!(lines[2].contains("attachment=-"), "{dry}");
        let applied = describe(&steps, true);
        assert!(applied.starts_with("ROOT-ATTACHED\t"), "{applied}");
        assert!(restored(&steps));
        assert!(!restored(&steps[..1]));
    }
}
