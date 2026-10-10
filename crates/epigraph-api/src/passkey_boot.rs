//! The software-attestation flag is never served on an armed database
//! (elevation plan EL-3, operator question EQ-1 (a)).
//!
//! `EPIGRAPH_WEBAUTHN_ALLOW_SOFTWARE_ATTESTATION` replaces the attestation
//! allowlist with a policy that accepts `none` and self attestation, i.e. a
//! passkey from a SOFTWARE authenticator. It exists for tests and local
//! development. While operator ruling D3 is not in effect, whoever holds the
//! maintenance DSN can open an enrollment ticket, so on a production database
//! the flag would let that holder complete one with a software key and own a
//! "passkey" of the operator's.
//!
//! "A production database" is read the way operator ruling OQ-7 (b) reads it:
//! armed for operator binding (migration 122), whatever the connection's
//! privilege or the valve. So the `server` refuses to START with the flag on
//! an armed database ([`check_software_attestation_boot`], run BEFORE OQ-7's
//! own check so its reason is the one printed), and a server SERVING with it
//! stops once its database is armed under it ([`running_stop`], composed
//! ahead of OQ-7's rule into the one posture watch, because the deploy order
//! starts request units before arming).
//!
//! Only the API `server` is concerned: `epigraph-passkey` is never a
//! dependency of `epigraph-mcp`.

use epigraph_db::operator_binding::{boot_state, request_unit_stop, BootState};

/// The variable named in the refusals (spelled once; the source of truth is
/// `epigraph_passkey::config::ENV_ALLOW_SOFTWARE_ATTESTATION`).
const FLAG: &str = epigraph_passkey::config::ENV_ALLOW_SOFTWARE_ATTESTATION;

/// What `server` prints to stderr before exiting non-zero when it is started
/// with the flag on an armed database.
pub const SOFTWARE_ATTESTATION_REFUSAL: &str = "refusing to start: \
     EPIGRAPH_WEBAUTHN_ALLOW_SOFTWARE_ATTESTATION accepts passkeys from a software authenticator \
     (tests and development only), and this database is armed for operator binding; unset it \
     and configure the attestation allowlist (EPIGRAPH_WEBAUTHN_AAGUIDS, \
     EPIGRAPH_WEBAUTHN_ATTESTATION_CA_FILE)";

/// What a SERVING `server` with the flag prints before exiting non-zero once
/// a re-read finds its database armed.
pub const SOFTWARE_ATTESTATION_STOP: &str = "stopping: \
     EPIGRAPH_WEBAUTHN_ALLOW_SOFTWARE_ATTESTATION accepts passkeys from a software authenticator \
     (tests and development only), and this database was armed for operator binding after the \
     unit started; unset it and configure the attestation allowlist";

/// Whether a server with the software-attestation flag may serve in `state`:
/// only on a database that is not armed ([`BootState::NotArmed`],
/// [`BootState::NotMigrated`]). Every armed state is refused, the
/// application DSN ([`BootState::Enforced`]) and an open valve included: the
/// flag's hazard is the enrollment, not the connection. A pure mapping, so
/// the rule is unit-tested apart from the database.
///
/// # Errors
/// [`SOFTWARE_ATTESTATION_REFUSAL`] on an armed database.
pub fn software_attestation_may_serve(state: BootState) -> Result<(), &'static str> {
    match state {
        BootState::Enforced | BootState::PrivilegedDsn | BootState::ValveOff => {
            Err(SOFTWARE_ATTESTATION_REFUSAL)
        }
        BootState::NotArmed | BootState::NotMigrated => Ok(()),
    }
}

/// The boot verdict for a server with the flag, from the posture read: the
/// mapping above, and a read FAILURE refuses too (without the read the unit
/// cannot show the database is not armed). A pure mapping.
///
/// # Errors
/// The refusal text, or the read failure.
pub fn software_attestation_boot_verdict<E: std::fmt::Display>(
    read: Result<BootState, E>,
) -> Result<(), String> {
    let state = read.map_err(|e| {
        format!(
            "refusing to start: {FLAG} is set and the operator-binding arming state could not be \
             read ({e})"
        )
    })?;
    software_attestation_may_serve(state).map_err(str::to_string)
}

/// The boot check: a no-op unless `allows_software` (the configured relying
/// party took the software policy); otherwise read the posture on `pool` and
/// refuse an armed database. Call it BEFORE
/// `epigraph_db::operator_binding::check_request_unit_boot`.
///
/// # Errors
/// See [`software_attestation_boot_verdict`].
pub async fn check_software_attestation_boot(
    pool: &sqlx::PgPool,
    allows_software: bool,
) -> Result<(), String> {
    if !allows_software {
        return Ok(());
    }
    let verdict = software_attestation_boot_verdict(boot_state(pool).await);
    if let Err(refusal) = &verdict {
        tracing::error!(target: "elevate", "{refusal}");
    }
    verdict
}

/// The running rule of the `server`'s posture watch
/// (`epigraph_db::operator_binding::spawn_posture_watch`): with the flag on,
/// an armed database stops it with [`SOFTWARE_ATTESTATION_STOP`] FIRST;
/// otherwise OQ-7's rule (`request_unit_stop`). One composed rule rather than
/// a second watch, so the order, not timing, names the reason.
pub fn running_stop(allows_software: bool) -> impl Fn(&str, BootState) -> Option<String> {
    move |unit, state| {
        if allows_software && software_attestation_may_serve(state).is_err() {
            tracing::error!(target: "elevate", unit, "{SOFTWARE_ATTESTATION_STOP}");
            return Some(SOFTWARE_ATTESTATION_STOP.to_string());
        }
        request_unit_stop(unit, state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARMED: [BootState; 3] = [
        BootState::Enforced,
        BootState::PrivilegedDsn,
        BootState::ValveOff,
    ];
    const UNARMED: [BootState; 2] = [BootState::NotArmed, BootState::NotMigrated];

    /// Every armed state is refused, the application DSN included; only an
    /// unarmed database serves. Mutation: OQ-7's mapping copied (refuse only
    /// `PrivilegedDsn`) -> `Enforced` and `ValveOff` serve.
    #[test]
    fn the_flag_is_refused_on_every_armed_state() {
        for state in ARMED {
            assert_eq!(
                software_attestation_may_serve(state),
                Err(SOFTWARE_ATTESTATION_REFUSAL),
                "{state:?}"
            );
        }
        for state in UNARMED {
            assert_eq!(software_attestation_may_serve(state), Ok(()), "{state:?}");
        }
        assert!(SOFTWARE_ATTESTATION_REFUSAL.starts_with("refusing to start:"));
        assert!(SOFTWARE_ATTESTATION_REFUSAL.contains(FLAG));
        assert!(SOFTWARE_ATTESTATION_STOP.starts_with("stopping:"));
        assert!(SOFTWARE_ATTESTATION_STOP.contains(FLAG));
        for text in [SOFTWARE_ATTESTATION_REFUSAL, SOFTWARE_ATTESTATION_STOP] {
            assert!(!text.contains("  "), "a run of spaces: {text:?}");
        }
    }

    /// A read failure refuses (fails closed). Mutation: the error mapped to
    /// `Ok(())` -> served.
    #[test]
    fn a_failed_read_refuses() {
        let refused = software_attestation_boot_verdict::<&str>(Err("connection refused"));
        let text = refused.expect_err("a failed read must refuse");
        assert!(text.starts_with("refusing to start:"), "{text}");
        assert!(
            text.contains(FLAG) && text.contains("connection refused"),
            "{text}"
        );
        assert_eq!(
            software_attestation_boot_verdict::<&str>(Ok(BootState::NotArmed)),
            Ok(())
        );
        assert_eq!(
            software_attestation_boot_verdict::<&str>(Ok(BootState::Enforced)),
            Err(SOFTWARE_ATTESTATION_REFUSAL.to_string())
        );
    }

    /// The composed running rule: with the flag, every armed state stops with
    /// the flag's text (ahead of OQ-7's on a privileged DSN); without it, OQ-7's
    /// rule alone. Mutation: the flag's arm dropped (OQ-7's rule only) ->
    /// `Enforced` serves and `PrivilegedDsn` prints OQ-7's stop.
    #[test]
    fn the_running_rule_puts_the_flag_ahead_of_oq7() {
        let with = running_stop(true);
        let without = running_stop(false);
        for state in ARMED {
            assert_eq!(
                with("t", state),
                Some(SOFTWARE_ATTESTATION_STOP.to_string()),
                "{state:?}"
            );
            assert_eq!(
                without("t", state),
                request_unit_stop("t", state),
                "{state:?}"
            );
        }
        for state in UNARMED {
            assert_eq!(with("t", state), None, "{state:?}");
            assert_eq!(without("t", state), None, "{state:?}");
        }
        assert!(without("t", BootState::PrivilegedDsn).is_some());
        assert_eq!(without("t", BootState::Enforced), None);
    }
}
