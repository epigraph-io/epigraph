//! A RUNNING signer's watch over its own key's admission, shared by every
//! process that signs: the API's edge signing key (backlog `07ed8d4d`) and the
//! MCP server's claim and edge signer (backlog `ac52fcb0`).
//!
//! A signing process checks its key at boot. A key revoked, rotated out or
//! past its window while the process runs would otherwise go on signing rows
//! the verifier refuses until the next restart. [`watch_signer_admission`]
//! keeps asking, on the DATABASE clock (which dates the rows the verifier
//! judges), whether and until when the verifier admits the key for the signer
//! agent ([`AgentKeyRepository::signer_key_admission`], the verifier's own
//! admission rule), and returns once it does not, or once its recorded window
//! ends within [`STOP_LEAD_SECS`]. A known end is not left to the interval:
//! the watch sleeps until the lead before it, so a planned cut-over stops the
//! signer before it. A REVOCATION is only seen at the next check, so rows
//! signed in the (at most one interval) between the revocation and that check
//! carry a signature the verifier refuses; a shorter interval narrows that
//! gap.
//!
//! A failed re-read is logged (WARN, ERROR after
//! [`FAILED_RECHECKS_BEFORE_ERROR`] in a row) and the watch goes on: only a
//! positive read of an inadmissible key returns. What the caller does then
//! (the API and the MCP server exit the process) is its own.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::repos::agent_key::{KeyAdmissionEnd, SignerKeyAdmission};
use crate::{AgentKeyRepository, AgentRepository, DbError};

/// How long before its key's recorded admission ends (a known cut-over, a
/// `valid_until`) a signer stops signing with it. The signer stops BEFORE the
/// end, not an interval after it, so a row it signed is dated inside the
/// window; the lead covers the re-check's latency, the exit, and a
/// transaction that began just before the stop.
pub const STOP_LEAD_SECS: i64 = 5;

/// Consecutive failed re-reads after which the watch logs at ERROR, not WARN.
pub const FAILED_RECHECKS_BEFORE_ERROR: u32 = 5;

/// What a signer does with its key after an admission read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionVerdict {
    /// Keep signing, re-reading within at most this long (`None`: no recorded
    /// end; the watch interval alone decides).
    Keep(Option<Duration>),
    /// Stop: not admitted (`None`), or its admission ends at this instant,
    /// within [`STOP_LEAD_SECS`] of the read.
    Stop(Option<DateTime<Utc>>),
}

/// The verdict on one admission read: stop when the key is not admitted or
/// its admission ends within [`STOP_LEAD_SECS`] of the read (both on the
/// database clock), otherwise keep signing until at most the lead before the
/// end.
#[must_use]
pub fn admission_verdict(read: &SignerKeyAdmission) -> AdmissionVerdict {
    match read.end {
        KeyAdmissionEnd::NotAdmitted => AdmissionVerdict::Stop(None),
        KeyAdmissionEnd::Open => AdmissionVerdict::Keep(None),
        KeyAdmissionEnd::At(end) => {
            let left = end - read.checked_at - chrono::Duration::seconds(STOP_LEAD_SECS);
            match left.to_std() {
                Ok(left) if !left.is_zero() => AdmissionVerdict::Keep(Some(left)),
                _ => AdmissionVerdict::Stop(Some(end)),
            }
        }
    }
}

/// The agent a watched key is admitted (or not) for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchedSigner {
    /// A known signer agent (the API resolves or registers its signer agent
    /// at boot).
    Agent(Uuid),
    /// The agent whose `agents.public_key` is this identity key, looked up
    /// READ-ONLY on each check until it exists. The MCP server creates its
    /// own agent row lazily, on its first tool call, and signs nothing
    /// before: while no agent carries the identity key there is no row
    /// signed as it for the verifier to refuse, so that is not a stop.
    IdentityKey([u8; 32]),
}

/// One admission read for `signer`'s `public_key`: the signer agent and its
/// read, or `None` while a [`WatchedSigner::IdentityKey`] names no agent yet.
///
/// # Errors
/// Returns `DbError` if a read fails.
pub async fn read_signer_admission(
    pool: &PgPool,
    signer: WatchedSigner,
    public_key: &[u8; 32],
) -> Result<Option<(Uuid, SignerKeyAdmission)>, DbError> {
    let signer_id = match signer {
        WatchedSigner::Agent(id) => id,
        WatchedSigner::IdentityKey(key) => {
            match AgentRepository::get_by_public_key(pool, &key).await? {
                Some(agent) => agent.id.as_uuid(),
                None => return Ok(None),
            }
        }
    };
    let read = AgentKeyRepository::signer_key_admission(pool, signer_id, public_key).await?;
    Ok(Some((signer_id, read)))
}

/// Why [`watch_signer_admission`] returned: the signer agent, and the instant
/// its key's admission ends (`None`: it is not admitted now).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionStop {
    pub signer_id: Uuid,
    pub end: Option<DateTime<Utc>>,
}

/// When a watch starts stopping on an inadmissible read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arming {
    /// From the first read: the signer refused an inadmissible key at boot
    /// (the API's edge signer, the MCP server's separate-signing-key mode),
    /// so any later read that says stop is a change since the boot check.
    FromBoot,
    /// From the first read that ADMITS the key. For a signer that never
    /// checked its key at boot (the MCP server's legacy key rungs): stopping
    /// on the first read would be a new boot refusal, which is not this
    /// watch's decision. A key that is not admitted while unarmed is logged
    /// (WARN, once) and the watch goes on; once it has been admitted, losing
    /// admission stops the signer like [`Arming::FromBoot`].
    AfterFirstAdmission,
}

/// Check whether the verifier still admits `public_key` for `signer`, now and
/// then every `interval` (sooner when a recorded window ends first), and
/// return once [`admission_verdict`] says stop while the watch is armed
/// ([`Arming`]). `what` names the signer in the log lines (e.g. the variable
/// that configures its key).
///
/// A failed re-read is logged (WARN, then ERROR after
/// [`FAILED_RECHECKS_BEFORE_ERROR`] in a row) and the watch goes on: a
/// transient database error must not stop the signer. Only a positive read of
/// an inadmissible key returns.
pub async fn watch_signer_admission(
    pool: PgPool,
    signer: WatchedSigner,
    public_key: [u8; 32],
    interval: Duration,
    what: &str,
    arming: Arming,
) -> AdmissionStop {
    let mut signer = signer;
    let mut armed = arming == Arming::FromBoot;
    let mut warned_unadmitted = false;
    let mut failures: u32 = 0;
    loop {
        let next = match read_signer_admission(&pool, signer, &public_key).await {
            Ok(None) => {
                failures = 0;
                interval
            }
            Ok(Some((signer_id, read))) => {
                // Found once, kept: the process caches its agent the same way.
                signer = WatchedSigner::Agent(signer_id);
                failures = 0;
                match admission_verdict(&read) {
                    AdmissionVerdict::Keep(cap) => {
                        armed = true;
                        cap.map_or(interval, |c| c.min(interval))
                    }
                    AdmissionVerdict::Stop(end) if armed => {
                        return AdmissionStop { signer_id, end };
                    }
                    AdmissionVerdict::Stop(_) => {
                        if !warned_unadmitted {
                            warned_unadmitted = true;
                            tracing::warn!(
                                signer_id = %signer_id,
                                public_key = %hex::encode(public_key),
                                "{what}: the edge and claim verifiers do not admit this signing \
                                 key for its agent, so what it signs will not verify; it was not \
                                 checked at boot, so the process keeps serving, and stops only \
                                 once the key, after being admitted, loses admission"
                            );
                        }
                        interval
                    }
                }
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                log_failed_recheck(what, failures, &e, interval);
                interval
            }
        };
        tokio::time::sleep(next).await;
    }
}

fn log_failed_recheck(what: &str, failures: u32, e: &DbError, interval: Duration) {
    let secs = interval.as_secs();
    if failures >= FAILED_RECHECKS_BEFORE_ERROR {
        tracing::error!(
            "{what}: could not re-check the signing key's admission {failures} times in a row \
             ({e}); still signing with a key whose admission it cannot confirm, re-checking in \
             {secs}s"
        );
    } else {
        tracing::warn!(
            "{what}: could not re-check the signing key's admission ({e}); still signing, \
             re-checking in {secs}s"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(end: KeyAdmissionEnd) -> SignerKeyAdmission {
        SignerKeyAdmission {
            checked_at: DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            end,
        }
    }

    #[test]
    fn a_key_not_admitted_stops_at_once() {
        assert_eq!(
            admission_verdict(&read(KeyAdmissionEnd::NotAdmitted)),
            AdmissionVerdict::Stop(None)
        );
    }

    #[test]
    fn an_open_key_keeps_signing_on_the_interval() {
        assert_eq!(
            admission_verdict(&read(KeyAdmissionEnd::Open)),
            AdmissionVerdict::Keep(None)
        );
    }

    #[test]
    fn a_known_end_is_slept_to_the_lead_before_it_and_stops_inside_the_lead() {
        let r = read(KeyAdmissionEnd::Open);
        let far = r.checked_at + chrono::Duration::seconds(STOP_LEAD_SECS + 60);
        assert_eq!(
            admission_verdict(&read(KeyAdmissionEnd::At(far))),
            AdmissionVerdict::Keep(Some(Duration::from_secs(60)))
        );
        let near = r.checked_at + chrono::Duration::seconds(STOP_LEAD_SECS);
        assert_eq!(
            admission_verdict(&read(KeyAdmissionEnd::At(near))),
            AdmissionVerdict::Stop(Some(near))
        );
    }
}
