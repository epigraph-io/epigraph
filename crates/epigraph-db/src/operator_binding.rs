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

/// The boot INFO line of a process that enforces on an armed database.
///
/// It names the refusal's code in parentheses, never as `OPL01:`: a refusal's
/// own message is `OPL01: ...` / `OPL02: ...` (migration 122), and the deploy
/// runbook counts refusals in the logs by exactly that `OPL0[12]:` prefix, so a
/// boot line (or [`VALVE_OFF_WARNING`]) carrying it would read as a refusal on
/// every restart.
pub const ARMED_BOOT_INFO: &str = "operator binding ENFORCED: the database is armed; a claim by \
     an agent not bound to a human operator is refused (OPL01)";

/// The boot ERROR of a process on an armed database whose connection is
/// PRIVILEGED (`epigraph_bypass()` is true: a superuser or maintenance login).
///
/// Migration 122's trigger binds the session's stamped PRINCIPAL only on a
/// non-privileged session; on a privileged one it checks the claim's author
/// column alone (that is the platform corpus's custodial edit path), and since
/// migration 123 a privileged session is the only one relieved of the
/// cross-human scope (`OPL02`). So a request unit on such a DSN would let any
/// caller its request body names as author write as that author, across
/// humans (delta review round 4 SEC-R4-3). A request unit therefore REFUSES TO
/// START in this state ([`request_unit_may_serve`], operator ruling OQ-7 (b)).
/// Same rule as [`ARMED_BOOT_INFO`]: the code appears only in parentheses,
/// never as a refusal's `OPL0x:` prefix.
pub const PRIVILEGED_DSN_ERROR: &str = "operator binding NOT ENFORCED for the writer on this \
     privileged DSN: the database is armed, but this process connects as a privileged role \
     (epigraph_bypass() is true), so the claims trigger checks the author column only and \
     ignores the stamped principal (the writer binding, OPL01, does not apply). A request unit \
     must connect as epigraph_app (docs/deploy.md, \"Operator binding\").";

/// The refusal a request unit (the API `server`, `epigraph-mcp` on every
/// transport) prints to stderr before exiting non-zero when its DSN is
/// privileged on an armed database (operator ruling OQ-7 (b)). Followed by
/// [`PRIVILEGED_DSN_ERROR`], which says why.
pub const PRIVILEGED_DSN_REFUSAL: &str = "refusing to start: a request unit never serves an \
     armed database on a privileged DSN (operator ruling OQ-7 (b)); connect it as epigraph_app";

/// What [`check_request_unit_boot`] reports, as a value a test can compare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootState {
    /// Armed, valve closed, a non-privileged connection: [`ARMED_BOOT_INFO`].
    Enforced,
    /// Armed, a PRIVILEGED connection, whatever the valve says (a privileged
    /// session is not bound on its principal either way):
    /// [`PRIVILEGED_DSN_ERROR`]. A request unit refuses to start.
    PrivilegedDsn,
    /// Armed, a non-privileged connection, but this process's valve is open.
    ValveOff,
    /// Migration 122 applied, not armed.
    NotArmed,
    /// Migration 122 not applied.
    NotMigrated,
}

/// Read what this process will enforce on `pool`'s database: the arming,
/// whether the connection is privileged (`epigraph_bypass()`), and the valve.
/// Privilege is read BEFORE the valve: an open valve on a privileged DSN is
/// still a privileged DSN.
///
/// # Errors
/// A read failed.
pub async fn boot_state(pool: &sqlx::PgPool) -> Result<BootState, crate::DbError> {
    let valve = enforcement();
    Ok(
        match crate::AgentRepository::operator_binding_armed(pool).await? {
            None => BootState::NotMigrated,
            Some(false) => BootState::NotArmed,
            Some(true) => {
                let privileged: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
                    .fetch_one(pool)
                    .await?;
                if privileged {
                    BootState::PrivilegedDsn
                } else if valve == Enforcement::Off {
                    BootState::ValveOff
                } else {
                    BootState::Enforced
                }
            }
        },
    )
}

/// Whether a REQUEST UNIT may serve in `state`: every state but
/// [`BootState::PrivilegedDsn`] (operator ruling OQ-7 (b)). A pure mapping, so
/// the rule is unit-tested apart from the database.
///
/// # Errors
/// [`PRIVILEGED_DSN_REFUSAL`] for a privileged DSN on an armed database.
pub fn request_unit_may_serve(state: BootState) -> Result<(), &'static str> {
    match state {
        BootState::PrivilegedDsn => Err(PRIVILEGED_DSN_REFUSAL),
        BootState::Enforced
        | BootState::ValveOff
        | BootState::NotArmed
        | BootState::NotMigrated => Ok(()),
    }
}

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

/// The boot WARN of an armed database whose process has the valve open.
pub const VALVE_OFF_BOOT_WARNING: &str =
    "the database is armed for operator binding, but this process's valve is OFF";

/// The boot WARN of a migrated database that is not armed.
pub const NOT_ARMED_BOOT_WARNING: &str = "operator binding is NOT ARMED on this database: claims \
     by agents not bound to a human operator are accepted. Arm it with `epigraph-operator \
     arm-operator-binding --apply` once every live writer is bound (docs/deploy.md)";

/// The boot WARN of a database without migration 122.
pub const NOT_MIGRATED_BOOT_WARNING: &str = "migration 122 (operator binding) is not applied to \
     this database; claim writes through default declarations fail closed until it is";

/// The level and the line [`check_request_unit_boot`] logs for `state`: a pure
/// mapping, so a test pins that a privileged DSN is an ERROR naming
/// [`PRIVILEGED_DSN_ERROR`] (the SEC-R4-3 signal), not an INFO saying
/// ENFORCED.
#[must_use]
pub fn boot_line(state: BootState) -> (tracing::Level, &'static str) {
    match state {
        BootState::Enforced => (tracing::Level::INFO, ARMED_BOOT_INFO),
        BootState::PrivilegedDsn => (tracing::Level::ERROR, PRIVILEGED_DSN_ERROR),
        BootState::ValveOff => (tracing::Level::WARN, VALVE_OFF_BOOT_WARNING),
        BootState::NotArmed => (tracing::Level::WARN, NOT_ARMED_BOOT_WARNING),
        BootState::NotMigrated => (tracing::Level::WARN, NOT_MIGRATED_BOOT_WARNING),
    }
}

/// A request unit's boot check, once, before it serves: log what this process
/// will enforce (the valve state, whether the database is armed, and whether
/// this connection is privileged: [`boot_state`], mapped by [`boot_line`]),
/// and refuse to serve a privileged DSN on an armed database
/// ([`request_unit_may_serve`], operator ruling OQ-7 (b)). Fails CLOSED: a
/// read failure is a refusal too, since without the read the unit cannot
/// show that its DSN is not privileged.
///
/// The caller (a request binary's `main`) prints the `Err` to stderr and exits
/// non-zero. Only request units call this: the maintenance timers and the
/// operator CLIs run on the maintenance DSN by design.
///
/// # Errors
/// The refusal text: [`PRIVILEGED_DSN_REFUSAL`] followed by
/// [`PRIVILEGED_DSN_ERROR`], or the read failure.
pub async fn check_request_unit_boot(pool: &sqlx::PgPool, unit: &str) -> Result<BootState, String> {
    let state = boot_state(pool).await.map_err(|e| {
        format!(
            "refusing to start: could not read the operator-binding arming state or whether \
             this DSN is privileged ({e})"
        )
    })?;
    match boot_line(state) {
        (level, line) if level == tracing::Level::ERROR => {
            tracing::error!(target: "tenancy.operator_binding", unit, "{line}");
        }
        (level, line) if level == tracing::Level::WARN => {
            tracing::warn!(target: "tenancy.operator_binding", unit, "{line}");
        }
        (_, line) => tracing::info!(target: "tenancy.operator_binding", unit, "{line}"),
    }
    request_unit_may_serve(state)
        .map_err(|refusal| format!("{refusal}. {PRIVILEGED_DSN_ERROR}"))?;
    Ok(state)
}

/// The environment variable a request unit reads once for the interval, in
/// seconds, between its posture re-reads ([`watch_request_unit`]).
pub const RECHECK_ENV: &str = "EPIGRAPH_REQUEST_UNIT_RECHECK_SECS";

/// The re-read interval when [`RECHECK_ENV`] is unset or not a number.
pub const RECHECK_DEFAULT_SECS: u64 = 30;

/// The longest re-read interval [`RECHECK_ENV`] can set: the variable tunes
/// the check, it never turns it off.
pub const RECHECK_MAX_SECS: u64 = 300;

/// What a RUNNING request unit prints to stderr before exiting non-zero when
/// a re-read finds it serving a privileged DSN of an armed database (operator
/// ruling OQ-7 (b)): the database was armed, or the login gained privilege,
/// after the boot check passed. Followed by [`PRIVILEGED_DSN_ERROR`].
pub const PRIVILEGED_DSN_STOP: &str = "stopping: a request unit never serves an armed database \
     on a privileged DSN (operator ruling OQ-7 (b)), and this one's database was armed, or its \
     login made privileged, after it started; connect it as epigraph_app";

/// The re-read interval for `raw` (the value of [`RECHECK_ENV`]): a whole
/// number of seconds clamped to `1..=`[`RECHECK_MAX_SECS`], or
/// [`RECHECK_DEFAULT_SECS`] when absent or not a number. A pure mapping, so
/// the clamp is unit-tested.
#[must_use]
pub fn recheck_interval_from_env_value(raw: Option<&str>) -> std::time::Duration {
    let secs = raw
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(RECHECK_DEFAULT_SECS, |s| s.clamp(1, RECHECK_MAX_SECS));
    std::time::Duration::from_secs(secs)
}

/// The stop text of a RUNNING request unit under operator ruling OQ-7 (b) for
/// `state`, or `None` while it may serve ([`request_unit_may_serve`]). Logs
/// the state's ERROR line ([`boot_line`]) when it stops. The rule
/// [`watch_request_unit`] applies, public so a request unit with a further
/// rule of its own can compose it into one [`watch_posture`] (two watches on
/// one posture would race to name the reason).
#[must_use]
pub fn request_unit_stop(unit: &str, state: BootState) -> Option<String> {
    if request_unit_may_serve(state).is_ok() {
        return None;
    }
    let (_, line) = boot_line(state);
    tracing::error!(target: "tenancy.operator_binding", unit, "{line}");
    Some(format!("{PRIVILEGED_DSN_STOP}. {PRIVILEGED_DSN_ERROR}"))
}

/// Re-read this process's posture on `pool` every `interval`, for as long as
/// it serves, and return the stop text once `stop_for` names one for the
/// state read.
///
/// A failed re-read is logged at WARN and the unit keeps serving: it already
/// passed its fail-closed boot check, and a transient database error must not
/// take every request unit down at once. Only a positive read of a refused
/// state stops it.
pub async fn watch_posture<F>(
    pool: sqlx::PgPool,
    unit: &str,
    interval: std::time::Duration,
    stop_for: F,
) -> String
where
    F: Fn(&str, BootState) -> Option<String>,
{
    loop {
        tokio::time::sleep(interval).await;
        match boot_state(&pool).await {
            Ok(state) => {
                if let Some(stop) = stop_for(unit, state) {
                    return stop;
                }
            }
            Err(e) => tracing::warn!(
                target: "tenancy.operator_binding",
                unit,
                "could not re-read the operator-binding arming state or whether this DSN is \
                 privileged ({e}); still serving, re-reading in {}s",
                interval.as_secs()
            ),
        }
    }
}

/// Re-read this process's posture on `pool` every `interval`, for as long as
/// it serves, and return the stop text once it is a state a request unit may
/// not serve ([`request_unit_may_serve`]). The boot check
/// ([`check_request_unit_boot`]) runs once, and the deploy order starts the
/// request units BEFORE the database is armed (docs/deploy.md, "Operator
/// binding"), so without this a unit started on a privileged DSN of an
/// unarmed database kept serving once the database was armed (review
/// R2-OQ-COR-1). [`watch_posture`] with [`request_unit_stop`].
pub async fn watch_request_unit(
    pool: sqlx::PgPool,
    unit: &str,
    interval: std::time::Duration,
) -> String {
    watch_posture(pool, unit, interval, request_unit_stop).await
}

/// Spawn [`watch_posture`] with `stop_for` for a request unit's `main`, at the
/// interval [`RECHECK_ENV`] sets, and EXIT the process (status 1, the stop
/// text on stderr) when it returns. Call it right after the unit's boot
/// checks pass, on the same pool, on every transport, and only once: one
/// watch per process, so the stop names one reason.
pub fn spawn_posture_watch<F>(pool: sqlx::PgPool, unit: &'static str, stop_for: F)
where
    F: Fn(&str, BootState) -> Option<String> + Send + Sync + 'static,
{
    let interval = recheck_interval_from_env_value(std::env::var(RECHECK_ENV).ok().as_deref());
    tokio::spawn(async move {
        let stop = watch_posture(pool, unit, interval, stop_for).await;
        eprintln!("ERROR: {stop}");
        std::process::exit(1);
    });
}

/// Spawn [`watch_request_unit`] for a request unit's `main`, at the interval
/// [`RECHECK_ENV`] sets, and EXIT the process (status 1, the stop text on
/// stderr) when it returns. Call it right after [`check_request_unit_boot`]
/// passes, on the same pool, on every transport.
pub fn spawn_request_unit_watch(pool: sqlx::PgPool, unit: &'static str) {
    spawn_posture_watch(pool, unit, request_unit_stop);
}

#[cfg(test)]
mod tests {
    use super::{
        boot_line, recheck_interval_from_env_value, request_unit_may_serve, request_unit_stop,
        BootState, Enforcement, ARMED_BOOT_INFO, PRIVILEGED_DSN_ERROR, PRIVILEGED_DSN_REFUSAL,
        PRIVILEGED_DSN_STOP, VALVE_OFF_WARNING,
    };

    /// The re-read interval is tunable but never disabled: clamped to
    /// 1..=300 s, 30 s when unset or not a number (review R2-OQ-COR-1).
    #[test]
    fn the_recheck_interval_is_clamped_never_disabled() {
        let secs = |raw: Option<&str>| recheck_interval_from_env_value(raw).as_secs();
        assert_eq!(secs(None), 30);
        assert_eq!(secs(Some("")), 30);
        assert_eq!(secs(Some("off")), 30);
        assert_eq!(secs(Some("-5")), 30);
        assert_eq!(secs(Some("0")), 1);
        assert_eq!(secs(Some(" 7 ")), 7);
        assert_eq!(secs(Some("999999")), 300);
        assert!(PRIVILEGED_DSN_STOP.starts_with("stopping:"));
        assert!(PRIVILEGED_DSN_STOP.contains("OQ-7 (b)"));
        assert!(!PRIVILEGED_DSN_STOP.contains("  "));
    }

    /// SEC-R4-3's signal is the ERROR line, so its level, its text and the
    /// prefix the deploy runbook greps are pinned here (review TST-MTC-11 and
    /// COR-MTC-4: the literal once carried runs of spaces, so "on this
    /// privileged DSN" matched nothing). Only `operator binding ENFORCED:`
    /// marks the enforced state; the ERROR line starts `operator binding NOT
    /// ENFORCED`.
    #[test]
    fn a_privileged_dsn_is_an_error_line_the_runbook_can_grep() {
        assert_eq!(
            boot_line(BootState::PrivilegedDsn),
            (tracing::Level::ERROR, PRIVILEGED_DSN_ERROR)
        );
        assert_eq!(
            boot_line(BootState::Enforced),
            (tracing::Level::INFO, ARMED_BOOT_INFO)
        );
        for state in [
            BootState::ValveOff,
            BootState::NotArmed,
            BootState::NotMigrated,
        ] {
            assert_eq!(boot_line(state).0, tracing::Level::WARN, "{state:?}");
        }
        assert!(PRIVILEGED_DSN_ERROR
            .starts_with("operator binding NOT ENFORCED for the writer on this privileged DSN:"));
        assert!(ARMED_BOOT_INFO.starts_with("operator binding ENFORCED:"));
        assert!(!PRIVILEGED_DSN_ERROR.starts_with("operator binding ENFORCED:"));
        for state in [
            BootState::Enforced,
            BootState::PrivilegedDsn,
            BootState::ValveOff,
            BootState::NotArmed,
            BootState::NotMigrated,
        ] {
            let line = boot_line(state).1;
            assert!(
                !line.contains("  "),
                "a boot line carries a run of spaces: {line:?}"
            );
        }
    }

    /// Operator ruling OQ-7 (b): a request unit refuses exactly one state, a
    /// privileged DSN on an armed database, and the refusal names the ruling
    /// and the role to connect as.
    #[test]
    fn a_request_unit_refuses_only_a_privileged_dsn() {
        assert_eq!(
            request_unit_may_serve(BootState::PrivilegedDsn),
            Err(PRIVILEGED_DSN_REFUSAL)
        );
        for state in [
            BootState::Enforced,
            BootState::ValveOff,
            BootState::NotArmed,
            BootState::NotMigrated,
        ] {
            assert_eq!(request_unit_may_serve(state), Ok(()), "{state:?}");
        }
        assert!(PRIVILEGED_DSN_REFUSAL.starts_with("refusing to start:"));
        assert!(PRIVILEGED_DSN_REFUSAL.contains("OQ-7 (b)"));
        assert!(PRIVILEGED_DSN_REFUSAL.contains("epigraph_app"));
        assert!(!PRIVILEGED_DSN_REFUSAL.contains("  "));
    }

    /// The running rule [`request_unit_stop`] stops on exactly the state the
    /// boot refuses, with the stop text (not the boot refusal) followed by the
    /// reason. Mutation: a `Some` for `Enforced` (an armed application DSN)
    /// -> the loop below fails.
    #[test]
    fn the_running_rule_stops_only_a_privileged_dsn() {
        assert_eq!(
            request_unit_stop("t", BootState::PrivilegedDsn),
            Some(format!("{PRIVILEGED_DSN_STOP}. {PRIVILEGED_DSN_ERROR}"))
        );
        for state in [
            BootState::Enforced,
            BootState::ValveOff,
            BootState::NotArmed,
            BootState::NotMigrated,
        ] {
            assert_eq!(request_unit_stop("t", state), None, "{state:?}");
        }
    }

    /// The boot lines name the code but never in a refusal's `OPL0x:` form,
    /// which is what the deploy runbook counts as a refusal in the logs.
    #[test]
    fn boot_lines_never_read_as_a_refusal() {
        for line in [ARMED_BOOT_INFO, VALVE_OFF_WARNING, PRIVILEGED_DSN_ERROR] {
            assert!(line.contains("OPL01"), "the line names the code: {line}");
            for refusal in ["OPL01:", "OPL02:"] {
                assert!(
                    !line.contains(refusal),
                    "a boot line must not carry a refusal's prefix {refusal:?}: {line}"
                );
            }
        }
    }

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
