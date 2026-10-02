//! `passkey-enroll` / `list-passkeys` / `revoke-passkey`: a registered human's
//! passkeys (migration 124), the confirmation an elevation will require
//! (operator ruling D5: WebAuthn with user verification).
//!
//! `passkey-enroll` opens a maintenance ENROLLMENT TICKET through 124's
//! maintenance-only definer and prints the ceremony PATH,
//! `/elevate/enroll/<id>`. The operator opens it under the deployment's
//! public base URL, on the device that holds the authenticator, within the
//! ticket's 15 minutes; the API runs the WebAuthn ceremony and records the
//! passkey. Nothing here talks WebAuthn, and nothing here prints a host: the
//! public base URL is deployment configuration.
//!
//! `revoke-passkey` is the break-glass revoke: audited
//! (`platform.passkey_revoked`), final, and the way back to the bootstrap
//! path if a passkey is lost.
//!
//! Every write goes through a 124 definer, whose table triggers enforce the
//! rules (ELV01 a passkey belongs only to a registered human that is no
//! other human's agent, ELV03 append-only) and write one `platform.` audit
//! row. Each call runs in one transaction, committed under `--apply` and
//! rolled back otherwise (its audit row with it), so a dry run prints exactly
//! what the definer did and leaves nothing.

use chrono::{DateTime, Utc};
use epigraph_db::{PasskeyEnrollmentRow, PasskeyRepository, PasskeyRow};
use sqlx::PgConnection;
use uuid::Uuid;

/// The ceremony path of an enrollment ticket, relative to the public base URL.
#[must_use]
pub fn ceremony_path(enrollment: Uuid) -> String {
    format!("/elevate/enroll/{enrollment}")
}

/// Open an enrollment ticket for `person` in one transaction (committed under
/// `apply`). Returns the ticket as written.
///
/// # Errors
/// The table's guard refused it (ELV01 a subject that is not a registered
/// human, or is another human's agent), the reason is empty, or a statement
/// failed.
pub async fn enroll(
    conn: &mut PgConnection,
    person: Uuid,
    reason: &str,
    label: Option<&str>,
    apply: bool,
) -> anyhow::Result<PasskeyEnrollmentRow> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let id = PasskeyRepository::create_enrollment(&mut tx, person, reason, label).await?;
    let row = PasskeyRepository::get_enrollment(&mut tx, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("enrollment {id} not readable after it was opened"))?;
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(row)
}

/// Revoke `passkey` now, in one transaction (committed under `apply`).
/// Returns whether this call revoked it and the row as it stands.
///
/// # Errors
/// The passkey does not exist, or a statement failed.
pub async fn revoke(
    conn: &mut PgConnection,
    passkey: Uuid,
    reason: &str,
    apply: bool,
) -> anyhow::Result<(bool, PasskeyRow)> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    if PasskeyRepository::get(&mut tx, passkey).await?.is_none() {
        anyhow::bail!("no passkey {passkey}; nothing was changed");
    }
    let revoked = PasskeyRepository::revoke(&mut tx, passkey, reason).await?;
    let row = PasskeyRepository::get(&mut tx, passkey)
        .await?
        .ok_or_else(|| anyhow::anyhow!("passkey {passkey} vanished"))?;
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok((revoked, row))
}

fn fmt_time(t: Option<DateTime<Utc>>) -> String {
    t.map_or_else(|| "-".to_string(), |t| t.to_rfc3339())
}

/// One tab-separated line per enrollment ticket, ending with its ceremony
/// path.
#[must_use]
pub fn describe_enrollment(row: &PasskeyEnrollmentRow) -> String {
    format!(
        "{}\tperson={}\texpires_at={}\tcreated_by={}\tlabel={:?}\treason={:?}\tceremony={}",
        row.id,
        row.person_agent_id,
        row.expires_at.to_rfc3339(),
        row.created_by,
        row.label.as_deref().unwrap_or(""),
        row.reason,
        ceremony_path(row.id),
    )
}

/// One tab-separated line per passkey. The credential id is printed in hex
/// (it is an identifier, not a secret; the public key is not printed).
#[must_use]
pub fn describe(row: &PasskeyRow) -> String {
    format!(
        "{}\tperson={}\tcredential_id={}\taaguid={}\tformat={}\tuser_verified={}\t\
         backup_eligible={}\tsign_count={}\tcreated_at={}\tlast_used_at={}\trevoked_at={}\t\
         label={:?}",
        row.id,
        row.person_agent_id,
        hex::encode(&row.credential_id),
        row.aaguid,
        row.attestation_format,
        row.user_verified,
        row.backup_eligible,
        row.sign_count,
        row.created_at.to_rfc3339(),
        fmt_time(row.last_used_at),
        fmt_time(row.revoked_at),
        row.label.as_deref().unwrap_or(""),
    )
}
