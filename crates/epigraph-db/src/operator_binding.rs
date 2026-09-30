//! The operator-binding valve (migration 122).
//!
//! Once a database is ARMED, a claim may be authored only by an agent bound to
//! a human operator; `claims_require_tenancy_then_operator_binding` refuses anything else
//! with `OPL01`. This module is the one emergency relief, and it is per
//! PROCESS:
//!
//! * [`ENFORCEMENT_ENV`] (`EPIGRAPH_OPERATOR_LINK_ENFORCEMENT`) is read ONCE, the
//!   first time [`enforcement`] is called. Only the exact value `off`
//!   (case-insensitive, trimmed) turns enforcement off; unset, empty, `on` and
//!   any typo leave it ON, so a misspelt valve fails closed.
//! * While off, [`enforcement`] logs [`VALVE_OFF_WARNING`] at WARN once per
//!   process, i.e. on every boot. Request binaries call [`enforcement`] at boot
//!   so the line lands with the boot log rather than at the first query.
//! * [`crate::ScopedPool`] stamps [`VALVE_GUC`] = `off` on every connection it
//!   opens while the valve is off ([`apply_valve`]), and
//!   `epigraph_operator_binding_enforced()` honours it. Every request unit and
//!   every operator CLI builds its pools through `ScopedPool`, so that is the
//!   whole transport. A pool built any other way stays ENFORCED, and so does a
//!   deployment behind a transaction-mode pooler (a session setting does not
//!   survive there): both fail closed.
//!
//! # Not an authority boundary
//!
//! Any database session can set a custom setting, so [`VALVE_GUC`] is the
//! valve's transport, not a privilege: a raw session that sets it writes as an
//! unbound agent. What the setting guards against is a CODE PATH writing as an
//! unbound agent, and no code path sets it but the valve.
//!
//! # `OPL01` only
//!
//! The valve relieves the BINDING (`OPL01`). The cross-human scope (`OPL02`,
//! migration 122 section 1b) keys on the database's arming alone, so no valve
//! lets one human's agent write into another human's group.

use std::sync::OnceLock;

/// The environment variable a process reads once at boot.
pub const ENFORCEMENT_ENV: &str = "EPIGRAPH_OPERATOR_LINK_ENFORCEMENT";

/// The session setting the valve travels as; migration 122's
/// `epigraph_operator_binding_enforced()` reads it.
pub const VALVE_GUC: &str = "epigraph.operator_link_enforcement";

/// The boot WARN while the valve is off.
pub const VALVE_OFF_WARNING: &str = "EPIGRAPH_OPERATOR_LINK_ENFORCEMENT=off: operator binding is \
     NOT enforced for this process. Claims by agents that are not bound to a human operator \
     (OPL01) are ACCEPTED on every connection it opens. This is an emergency valve: link the \
     agent (epigraph-operator link) and remove the variable.";

/// Whether this process enforces operator binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enforcement {
    /// Default: the database's arming decides.
    On,
    /// The valve is open: this process's connections carry [`VALVE_GUC`] = `off`.
    Off,
}

impl Enforcement {
    /// Parse the variable's value. Only `off` (case-insensitive, trimmed) is
    /// [`Enforcement::Off`]; everything else, absence included, is
    /// [`Enforcement::On`].
    #[must_use]
    pub fn from_env_value(raw: Option<&str>) -> Self {
        match raw {
            Some(v) if v.trim().eq_ignore_ascii_case("off") => Self::Off,
            _ => Self::On,
        }
    }
}

static ENFORCEMENT: OnceLock<Enforcement> = OnceLock::new();

/// This process's enforcement, read from [`ENFORCEMENT_ENV`] on the first call
/// and fixed for the life of the process. Logs [`VALVE_OFF_WARNING`] on that
/// first call when the valve is off.
pub fn enforcement() -> Enforcement {
    *ENFORCEMENT.get_or_init(|| {
        let e = Enforcement::from_env_value(std::env::var(ENFORCEMENT_ENV).ok().as_deref());
        if e == Enforcement::Off {
            tracing::warn!(target: "tenancy.operator_binding", "{VALVE_OFF_WARNING}");
        }
        e
    })
}

/// Stamp the valve on a freshly opened connection when this process's valve is
/// off; a no-op otherwise. Session scope: it must outlive every checkout.
///
/// # Errors
/// The `set_config` fails.
pub async fn apply_valve(conn: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    if enforcement() == Enforcement::Off {
        sqlx::query("SELECT set_config($1, 'off', false)")
            .bind(VALVE_GUC)
            .execute(conn)
            .await?;
    }
    Ok(())
}

/// Log, once at boot, what this process will enforce: the valve state and
/// whether the database is armed. Non-fatal: a read failure is logged, not
/// returned, because the trigger enforces whatever this says.
pub async fn log_boot_state(pool: &sqlx::PgPool, unit: &str) {
    let valve = enforcement();
    match crate::AgentRepository::operator_binding_armed(pool).await {
        Ok(Some(true)) if valve == Enforcement::On => tracing::info!(
            target: "tenancy.operator_binding",
            unit,
            "operator binding ENFORCED: the database is armed; a claim by an agent not bound to \
             a human operator is refused (OPL01)"
        ),
        Ok(Some(true)) => tracing::warn!(
            target: "tenancy.operator_binding",
            unit,
            "the database is armed for operator binding, but this process's valve is OFF"
        ),
        Ok(Some(false)) => tracing::warn!(
            target: "tenancy.operator_binding",
            unit,
            "operator binding is NOT ARMED on this database: claims by agents not bound to a \
             human operator are accepted. Arm it with `epigraph-operator arm-operator-binding \
             --apply` once every live writer is bound (docs/deploy.md)"
        ),
        Ok(None) => tracing::warn!(
            target: "tenancy.operator_binding",
            unit,
            "migration 122 (operator binding) is not applied to this database; claim writes \
             through default declarations fail closed until it is"
        ),
        Err(e) => tracing::warn!(
            target: "tenancy.operator_binding",
            unit,
            error = %e,
            "could not read the operator-binding arming state"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::Enforcement;

    #[test]
    fn only_the_exact_word_off_opens_the_valve() {
        for raw in ["off", "OFF", " Off\n"] {
            assert_eq!(
                Enforcement::from_env_value(Some(raw)),
                Enforcement::Off,
                "{raw:?}"
            );
        }
        for raw in [
            None,
            Some(""),
            Some("on"),
            Some("0"),
            Some("false"),
            Some("of"),
            Some("offf"),
        ] {
            assert_eq!(
                Enforcement::from_env_value(raw),
                Enforcement::On,
                "{raw:?} must leave enforcement ON (fail closed)"
            );
        }
    }
}
