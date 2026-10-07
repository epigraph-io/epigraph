//! `arm-admin-scopes` / `disarm-admin-scopes`: turn migration 128's
//! admin-scope switch on or off (elevation plan EL-9), with a reason.
//!
//! ARMED, the token endpoint strips every admin-only scope at every mint,
//! client approval and registration refuse to hand one out, and
//! `grant-client-scope` refuses: a standing admin scope is replaced by an
//! elevation. DISARMED (the shipped state), they behave as before and every
//! mint that kept an admin-only scope records an `oauth.admin_scope_would_strip`
//! event. Arm only once those events have read zero for a soak window (the
//! runbook); disarm is the rollback.
//!
//! Both directions are maintenance acts on [`super::connect`]'s DSN, through
//! the switch's definer (`epigraph_set_admin_scope_enforcement`), which the
//! table's own trigger audits (`platform.admin_scopes_armed` /
//! `platform.admin_scopes_disarmed`, naming the reason and the database
//! login). Asking for the state the switch is already in changes and records
//! nothing. Without `--apply` the change runs in a transaction that is rolled
//! back, its audit row included, and the report says what would change.

use anyhow::{bail, Context};
use epigraph_db::{AdminScopeChange, AdminScopeEnforcement, AdminScopeState};
use sqlx::{Acquire, PgConnection};

/// What a run found and did.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// `true` for `arm-admin-scopes`.
    pub arm: bool,
    /// The switch before the run.
    pub before: AdminScopeState,
    /// The setter's answer (rolled back on a dry run).
    pub change: AdminScopeChange,
    /// `false` for a dry run: nothing was committed.
    pub applied: bool,
}

/// Refuse a blank reason before any connection is used.
///
/// # Errors
/// `reason` is empty or whitespace.
pub fn validate_reason(reason: &str) -> anyhow::Result<()> {
    if reason.trim().is_empty() {
        bail!("--reason must say why (it is recorded in the audit event); nothing was changed");
    }
    Ok(())
}

/// Arm (`arm = true`) or disarm the switch with `reason`, in one transaction
/// on `conn`, committed only under `apply`.
///
/// # Errors
/// A blank reason; the database has no switch (migration 128 not applied);
/// the setter refuses (not a maintenance session); a statement fails.
pub async fn run(
    conn: &mut PgConnection,
    arm: bool,
    reason: &str,
    apply: bool,
) -> anyhow::Result<Outcome> {
    validate_reason(reason)?;
    let mut tx = conn.begin().await.context("beginning the transaction")?;
    let before = AdminScopeEnforcement::state(&mut tx)
        .await
        .context("reading the admin-scope switch (is migration 128 applied?)")?;
    let change = AdminScopeEnforcement::set(&mut tx, arm, reason)
        .await
        .context("setting the admin-scope switch")?;
    if apply {
        tx.commit().await.context("committing")?;
    } else {
        tx.rollback().await.context("rolling back the dry run")?;
    }
    Ok(Outcome {
        arm,
        before,
        change,
        applied: apply,
    })
}

/// The report's lines.
#[must_use]
pub fn describe(o: &Outcome) -> Vec<String> {
    let b = &o.before;
    let mut out = vec![format!(
        "BEFORE\tarmed={}\tchanged_at={}\tchanged_by={}\treason={:?}",
        b.armed, b.changed_at, b.changed_by, b.reason
    )];
    let verb = if o.arm { "ARMED" } else { "DISARMED" };
    if !o.change.changed {
        out.push(format!(
            "UNCHANGED\tadmin-scope enforcement is already {}; nothing was recorded",
            if o.change.armed { "armed" } else { "disarmed" }
        ));
    } else if o.applied {
        out.push(format!(
            "{verb}\tadmin-scope enforcement is now {} on this database (audited as \
             platform.admin_scopes_{})",
            if o.change.armed { "ARMED" } else { "disarmed" },
            if o.change.armed { "armed" } else { "disarmed" }
        ));
    } else {
        out.push(format!(
            "WOULD BE {verb}\tDRY RUN: the change and its audit event were rolled back; re-run \
             with --apply"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blank_reason_is_refused() {
        assert!(validate_reason("").is_err());
        assert!(validate_reason("  \t").is_err());
        assert!(validate_reason("would-strip read zero for 14 days").is_ok());
    }
}
