//! `verify-confirmations`: the offline confirmation verifier (elevation plan
//! EL-13), from the maintenance DSN.
//!
//! # Why it exists
//!
//! The database cannot verify a WebAuthn signature. The ceremony definers
//! that confirm an elevation ticket (migration 125) and an admin act (130)
//! take the API's word for the assertion, and store its evidence (the
//! challenge and the client's response, verbatim) so that something can check
//! it later. A holder of the APPLICATION DSN can therefore call those definers
//! with fabricated evidence and open a person's elevation, or confirm a
//! person's act; a holder of the MAINTENANCE DSN can write the rows directly.
//! That forgery is not preventable here (it closes with the later
//! authentication batches); this verb makes it DETECTABLE.
//!
//! # What it checks
//!
//! For every CONFIRMED elevation ticket and admin act (asserted at or after
//! `--since`, when given), against the relying party the ceremonies ran
//! under (`EPIGRAPH_WEBAUTHN_RP_ID` / `EPIGRAPH_WEBAUTHN_ORIGIN`):
//!
//! 1. the evidence parses and names the challenge it was made over;
//! 2. that challenge is the one the row's stored ceremony was started with;
//! 3. for an act, it is ALSO the act's own challenge, recomputed from the act
//!    id, the stored args digest and the stored nonce
//!    (`epigraph_passkey::act_challenge`): a valid signature over another
//!    act's challenge confirms nothing;
//! 4. the passkey the row names exists and belongs to the row's person (the
//!    ticket's person, the act's proposer), revoked or not: a later
//!    revocation does not make an earlier confirmation false;
//! 5. the evidence RE-VERIFIES against that passkey's stored public key, the
//!    rp id and the origin (`epigraph_passkey::Verifier::reverify`); the
//!    signature counter is not re-checked (the database's has moved on);
//! 6. the asserted credential is that passkey;
//! 7. the asserted backup-eligible flag does not exceed the stored one.
//!
//! Then, across rows: a challenge asserted MORE THAN ONCE (over every
//! asserted ticket and act, confirmed or refused, whatever `--since` says):
//! every confirmed occurrence after the first is flagged. A ticket's
//! challenge is random, so a genuine evidence object copied, with its
//! ceremony state, onto a later ticket passes every per-row check; only its
//! repetition gives it away.
//!
//! REFUSED assertions are not verified: a refusal granted nothing, and the
//! audited refusal of an unknown credential stores evidence that by design
//! does not verify. They are counted, and they take part in the repetition
//! check.
//!
//! # What it records
//!
//! Each finding becomes ONE `platform.confirmation_unverified` row in
//! `security_events`, attributed to the person (so the person reads it in
//! their own trail), naming the row, the reason and the detail. A finding
//! already recorded (same subject, row and reason) is not recorded again, so
//! a timer that reruns the verb does not grow the table; the verb still
//! reports it and still exits 2 until the row is dealt with. The rows commit
//! whether or not the run found anything else; nothing else is written, and
//! no ceremony row is changed.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use epigraph_passkey::{
    act_challenge, evidence_challenge, AuthenticationState, StoredPasskey, Verifier, ACT_NONCE_LEN,
};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

/// The `security_events.event_type` of a finding.
pub const EVENT_TYPE: &str = "platform.confirmation_unverified";

/// What a finding is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Subject {
    /// A confirmed `elevation_tickets` row (migration 125).
    ElevationTicket,
    /// A confirmed `pending_admin_acts` row (migration 130).
    AdminAct,
}

impl Subject {
    /// The name recorded in the audit row and printed.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ElevationTicket => "elevation_ticket",
            Self::AdminAct => "admin_act",
        }
    }
}

/// A confirmation that does not verify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// What kind of row.
    pub subject: Subject,
    /// The row's id.
    pub id: Uuid,
    /// The person it elevated, or whose act it confirmed.
    pub person: Uuid,
    /// The passkey the row names, when it names one.
    pub authenticator_id: Option<Uuid>,
    /// When the assertion was recorded.
    pub at: DateTime<Utc>,
    /// A stable code: `evidence_malformed`, `challenge_state_malformed`,
    /// `challenge_not_stored`, `challenge_not_bound`, `credential_unknown`,
    /// `credential_not_the_persons`, `assertion_does_not_verify`,
    /// `credential_mismatch`, `backup_eligibility_changed`,
    /// `challenge_reused`.
    pub reason: &'static str,
    /// What exactly, for the operator.
    pub detail: String,
}

/// What a run checked and found.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    /// The `--since` bound, when given.
    pub since: Option<DateTime<Utc>>,
    /// Confirmed elevation tickets verified.
    pub elevations_checked: usize,
    /// Confirmed admin acts verified (0 on a database without migration
    /// 130).
    pub acts_checked: usize,
    /// Refused assertions seen (not verified; part of the repetition check).
    pub refused_seen: usize,
    /// Everything that did not verify.
    pub findings: Vec<Finding>,
    /// How many audit rows this run added (a finding recorded by an earlier
    /// run is not recorded again).
    pub recorded: usize,
}

/// One asserted ticket or act, with the passkey it names.
#[derive(Debug, sqlx::FromRow)]
struct Asserted {
    subject: String,
    id: Uuid,
    person: Uuid,
    outcome: String,
    asserted_at: DateTime<Utc>,
    challenge_state: Option<Value>,
    assertion_evidence: Value,
    authenticator_id: Option<Uuid>,
    args_digest: Option<Vec<u8>>,
    key_person: Option<Uuid>,
    credential_id: Option<Vec<u8>>,
    passkey: Option<Value>,
    backup_eligible: Option<bool>,
}

impl Asserted {
    fn subject(&self) -> Subject {
        if self.subject == "admin_act" {
            Subject::AdminAct
        } else {
            Subject::ElevationTicket
        }
    }
}

const TICKETS: &str = "\
    SELECT 'elevation_ticket'::text AS subject, t.id, t.person_agent_id AS person, t.outcome, \
           t.asserted_at, t.challenge_state, t.assertion_evidence, t.authenticator_id, \
           NULL::bytea AS args_digest, a.person_agent_id AS key_person, a.credential_id, \
           a.passkey, a.backup_eligible \
      FROM public.elevation_tickets t \
      LEFT JOIN public.person_authenticators a ON a.id = t.authenticator_id \
     WHERE t.outcome IS NOT NULL";

const ACTS: &str = "\
    SELECT 'admin_act'::text AS subject, x.id, x.proposed_by AS person, x.outcome, \
           x.asserted_at, x.challenge_state, x.assertion_evidence, x.authenticator_id, \
           x.args_digest, a.person_agent_id AS key_person, a.credential_id, a.passkey, \
           a.backup_eligible \
      FROM public.pending_admin_acts x \
      LEFT JOIN public.person_authenticators a ON a.id = x.authenticator_id \
     WHERE x.outcome IS NOT NULL";

/// Why a confirmation does not verify: `(reason, detail)`.
type Failure = (&'static str, String);

fn fail(reason: &'static str, detail: impl Into<String>) -> Failure {
    (reason, detail.into())
}

/// The challenge a stored ceremony state was started with: a ticket stores
/// the library's authentication state itself; an act wraps it as
/// `{"ceremony": <state>, "nonce": <b64url>}` (EL-12b).
fn stored_challenge(row: &Asserted) -> Result<Vec<u8>, Failure> {
    let state = row
        .challenge_state
        .as_ref()
        .ok_or_else(|| fail("challenge_state_malformed", "no stored ceremony state"))?;
    let ceremony = match row.subject() {
        Subject::AdminAct => state
            .get("ceremony")
            .cloned()
            .ok_or_else(|| fail("challenge_state_malformed", "no stored act ceremony"))?,
        Subject::ElevationTicket => state.clone(),
    };
    AuthenticationState::from_json(ceremony)
        .challenge()
        .map_err(|e| fail("challenge_state_malformed", e.to_string()))
}

/// The act's own challenge, recomputed from its id, its stored args digest
/// and its stored nonce.
fn act_bound_challenge(row: &Asserted) -> Result<[u8; 32], Failure> {
    let digest: [u8; 32] = row
        .args_digest
        .as_deref()
        .and_then(|d| d.try_into().ok())
        .ok_or_else(|| fail("challenge_state_malformed", "no 32-byte args digest"))?;
    let nonce: [u8; ACT_NONCE_LEN] = row
        .challenge_state
        .as_ref()
        .and_then(|s| s.get("nonce"))
        .and_then(Value::as_str)
        .and_then(|n| URL_SAFE_NO_PAD.decode(n).ok())
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| fail("challenge_state_malformed", "no stored act nonce"))?;
    Ok(act_challenge(row.id, &digest, &nonce))
}

/// The per-row checks (module docs, 1-7), in order; the first failure wins.
fn check(verifier: &Verifier, row: &Asserted) -> Result<(), Failure> {
    let challenge = evidence_challenge(&row.assertion_evidence)
        .map_err(|e| fail("evidence_malformed", e.to_string()))?;
    if stored_challenge(row)? != challenge {
        return Err(fail(
            "challenge_not_stored",
            "the evidence was made over a challenge this row's ceremony was not started with",
        ));
    }
    if row.subject() == Subject::AdminAct && act_bound_challenge(row)?.as_slice() != challenge {
        return Err(fail(
            "challenge_not_bound",
            "the evidence's challenge is not this act's (id, args digest, nonce)",
        ));
    }
    let (Some(key_person), Some(credential_id), Some(passkey), Some(backup_eligible)) = (
        row.key_person,
        row.credential_id.as_deref(),
        row.passkey.as_ref(),
        row.backup_eligible,
    ) else {
        return Err(fail(
            "credential_unknown",
            "the row names no stored passkey to verify it with",
        ));
    };
    if key_person != row.person {
        return Err(fail(
            "credential_not_the_persons",
            format!("the passkey belongs to {key_person}"),
        ));
    }
    let snapshot = StoredPasskey {
        passkey: passkey.clone(),
        sign_count: 0,
    };
    let asserted = verifier
        .reverify(&row.assertion_evidence, &snapshot)
        .map_err(|e| fail("assertion_does_not_verify", e.to_string()))?;
    if asserted.credential_id != credential_id {
        return Err(fail(
            "credential_mismatch",
            "the evidence asserts another credential than the passkey the row names",
        ));
    }
    if asserted.backup_eligible && !backup_eligible {
        return Err(fail(
            "backup_eligibility_changed",
            "a passkey registered device-bound asserted as backup-eligible",
        ));
    }
    Ok(())
}

/// Read every asserted ticket and act, verify the confirmed ones asserted
/// at or after `since`, look for repeated challenges, and report. Reads
/// only; [`record`] writes the findings.
///
/// # Errors
/// A read fails.
pub async fn verify(
    conn: &mut PgConnection,
    verifier: &Verifier,
    since: Option<DateTime<Utc>>,
) -> anyhow::Result<Report> {
    let acts_exist: bool =
        sqlx::query_scalar("SELECT to_regclass('public.pending_admin_acts') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?;
    let sql = if acts_exist {
        format!("{TICKETS} UNION ALL {ACTS} ORDER BY asserted_at, subject, id")
    } else {
        format!("{TICKETS} ORDER BY asserted_at, subject, id")
    };
    let rows: Vec<Asserted> = sqlx::query_as(&sql).fetch_all(&mut *conn).await?;

    let mut report = Report {
        since,
        ..Report::default()
    };
    let in_window = |at: DateTime<Utc>| since.is_none_or(|s| at >= s);
    // The first assertion (in `asserted_at` order) of every challenge, over
    // ALL asserted rows: a replay of an old evidence object is as old as its
    // original, whatever the window.
    let mut first: HashMap<Vec<u8>, (Subject, Uuid)> = HashMap::new();
    for row in &rows {
        let original = match evidence_challenge(&row.assertion_evidence) {
            Ok(c) => match first.get(&c) {
                Some(o) => Some(*o),
                None => {
                    first.insert(c, (row.subject(), row.id));
                    None
                }
            },
            Err(_) => None,
        };
        if row.outcome != "confirmed" {
            if in_window(row.asserted_at) {
                report.refused_seen += 1;
            }
            continue;
        }
        if !in_window(row.asserted_at) {
            continue;
        }
        match row.subject() {
            Subject::AdminAct => report.acts_checked += 1,
            Subject::ElevationTicket => report.elevations_checked += 1,
        }
        let failure = check(verifier, row).err().or_else(|| {
            original.map(|(subject, id)| {
                fail(
                    "challenge_reused",
                    format!(
                        "the same challenge was asserted earlier, by {} {id}",
                        subject.as_str()
                    ),
                )
            })
        });
        if let Some((reason, detail)) = failure {
            report.findings.push(Finding {
                subject: row.subject(),
                id: row.id,
                person: row.person,
                authenticator_id: row.authenticator_id,
                at: row.asserted_at,
                reason,
                detail,
            });
        }
    }
    Ok(report)
}

/// Record each of `findings` as one `platform.confirmation_unverified` row,
/// unless the same finding (subject, row, reason) is already recorded, in
/// one committed transaction. Returns how many rows were added.
///
/// `created_at` is the database's own `now()`: 123's
/// `security_events_platform_privileged` admits a `platform.` row only with
/// it, and only from a privileged session.
///
/// # Errors
/// A statement fails.
pub async fn record(conn: &mut PgConnection, findings: &[Finding]) -> anyhow::Result<usize> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let mut added = 0;
    for f in findings {
        let details = serde_json::json!({
            "tool": "epigraph-operator",
            "command": "verify-confirmations",
            "subject": f.subject.as_str(),
            "id": f.id,
            "person": f.person,
            "authenticator_id": f.authenticator_id,
            "at": f.at,
            "reason": f.reason,
            "detail": f.detail,
        });
        let n = sqlx::query(
            "INSERT INTO public.security_events (event_type, agent_id, success, details) \
             SELECT $1, $2, false, $3 \
              WHERE NOT EXISTS (SELECT 1 FROM public.security_events e \
                                 WHERE e.event_type = $1 \
                                   AND e.details->>'subject' = $4 \
                                   AND e.details->>'id' = $5 \
                                   AND e.details->>'reason' = $6)",
        )
        .bind(EVENT_TYPE)
        .bind(f.person)
        .bind(&details)
        .bind(f.subject.as_str())
        .bind(f.id.to_string())
        .bind(f.reason)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        added += usize::try_from(n).unwrap_or(0);
    }
    tx.commit().await?;
    Ok(added)
}

/// One tab-separated line per finding.
#[must_use]
pub fn describe(f: &Finding) -> String {
    format!(
        "UNVERIFIED\t{}\t{}\tperson={}\tpasskey={}\tat={}\treason={}\tdetail={:?}",
        f.subject.as_str(),
        f.id,
        f.person,
        f.authenticator_id
            .map_or_else(|| "-".to_string(), |a| a.to_string()),
        f.at.to_rfc3339(),
        f.reason,
        f.detail,
    )
}

/// The run's one summary line.
#[must_use]
pub fn summary(r: &Report) -> String {
    format!(
        "SUMMARY\televations_checked={}\tacts_checked={}\trefused_seen={}\tunverified={}\t\
         recorded={}",
        r.elevations_checked,
        r.acts_checked,
        r.refused_seen,
        r.findings.len(),
        r.recorded,
    )
}
