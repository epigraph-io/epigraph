//! Pending admin acts (migration 130): the canonical form of an act's args,
//! their digest, and the maintenance read of one act.
//!
//! # Two implementations of one canonical form, on purpose
//!
//! The database canonicalizes an act's args when it is proposed
//! (`epigraph_admin_act_args`, `epigraph_canonical_json`) and recomputes them
//! from the write that consumes it. The maintenance CLI recomputes them from
//! ITS OWN FLAGS with the functions here and refuses before writing when the
//! digest differs from the confirmed act's: the operator learns at once that
//! the verb was run with other args than the ones the passkey confirmed,
//! instead of from an ELV09 after the fact. The two are tested against each
//! other (`pending_admin_acts.rs::the_rust_and_database_canonical_forms_agree`).
//!
//! The form: a JSON object with keys in byte order and no whitespace; ids as
//! lower-case hyphenated uuids; times UTC with microseconds and a `Z`; a truth
//! value as a decimal string with exactly six places; no JSON numbers at all
//! (a float's text is not canonical). Strings are escaped as `serde_json`
//! escapes them, which is how PostgreSQL's jsonb prints them (`\"`, `\\`,
//! `\b`, `\f`, `\n`, `\r`, `\t`, `\u00xx` in lower-case hex for the other
//! control characters, everything else verbatim). The canonicalizer sorts
//! keys itself and never relies on `serde_json`'s map ordering (a
//! `preserve_order` feature unified in from any dependency would change it).
//!
//! # Connections
//!
//! [`AdminActRepository::get`] is a MAINTENANCE read: an application
//! connection sees no act (130's row policies).
//!
//! # Why nothing here takes a `Viewer`
//!
//! An act is an authority record about a principal, not a corpus row; a
//! viewer filter has nothing to narrow (`visibility_lint.rs` registers the
//! function with its reason).

use crate::errors::DbError;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use tracing::instrument;
use uuid::Uuid;

/// The act kinds migration 130 knows.
pub const ROLE_GRANT: &str = "role.grant";
pub const ROLE_END: &str = "role.end";
pub const CUSTODIAL_SUPERSEDE: &str = "claim.custodial_supersede";
pub const PASSKEY_REGISTER: &str = "passkey.register";

/// `value` printed canonically (module docs).
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                write_canonical(&map[k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// SHA-256 of `args`' canonical text: an act's `args_digest`.
#[must_use]
pub fn args_digest(args: &Value) -> [u8; 32] {
    Sha256::digest(canonical_json(args).as_bytes()).into()
}

/// A time in the one form every act uses: UTC, microseconds, a `Z`.
#[must_use]
pub fn canonical_timestamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// The args of a `role.grant` act. `valid_from` `None` is "from the
/// execution" (the grant definer's default); `valid_to` `None` is
/// open-ended.
#[must_use]
pub fn role_grant_args(
    role: &str,
    holder: Uuid,
    valid_from: Option<DateTime<Utc>>,
    valid_to: Option<DateTime<Utc>>,
    reason: &str,
) -> Value {
    json!({
        "role": role,
        "holder": holder.to_string(),
        "valid_from": valid_from.map(canonical_timestamp),
        "valid_to": valid_to.map(canonical_timestamp),
        "reason": reason,
    })
}

/// The args of a `role.end` act.
#[must_use]
pub fn role_end_args(assignment: Uuid, reason: &str) -> Value {
    json!({ "assignment": assignment.to_string(), "reason": reason })
}

/// A truth value in the act's form: a decimal string with exactly six places.
///
/// # Errors
/// The value is outside `[0, 1]`, or has more than six decimal places (the
/// act could not state it exactly).
pub fn canonical_truth(truth: f64) -> Result<String, String> {
    if !(0.0..=1.0).contains(&truth) {
        return Err(format!("truth {truth} is not in [0, 1]"));
    }
    let text = format!("{truth:.6}");
    if text.parse::<f64>().ok() != Some(truth) {
        return Err(format!(
            "truth {truth} has more than six decimal places; an act states a truth value to \
             six places"
        ));
    }
    Ok(text)
}

/// The args of a `claim.custodial_supersede` act: the claim, the SHA-256 of
/// the revised content's UTF-8 bytes (exactly what the supersede stores), the
/// truth value, the reason, and the allow-owned override.
///
/// # Errors
/// [`canonical_truth`]'s.
pub fn custodial_supersede_args(
    claim: Uuid,
    content: &str,
    truth: f64,
    reason: &str,
    allow_owned: bool,
) -> Result<Value, String> {
    Ok(json!({
        "claim": claim.to_string(),
        "content_sha256": hex::encode(Sha256::digest(content.as_bytes())),
        "truth": canonical_truth(truth)?,
        "reason": reason,
        "allow_owned": allow_owned,
    }))
}

/// The args of a `passkey.register` act (a later passkey of the proposer).
#[must_use]
pub fn passkey_register_args(person: Uuid, label: Option<&str>, reason: &str) -> Value {
    json!({ "person": person.to_string(), "label": label, "reason": reason })
}

/// A row of `pending_admin_acts` (its ceremony state and evidence omitted).
#[derive(Debug, Clone, FromRow)]
pub struct AdminActRow {
    pub id: Uuid,
    pub kind: String,
    pub args: Value,
    pub args_digest: Vec<u8>,
    pub reason: String,
    pub proposed_by: Uuid,
    pub elevation_id: Uuid,
    pub assignment_id: Uuid,
    pub proposed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub outcome: Option<String>,
    pub refusal: Option<String>,
    pub authenticator_id: Option<Uuid>,
    pub consumed_at: Option<DateTime<Utc>>,
}

impl AdminActRow {
    /// Why this act cannot authorize a write of `kind` with `args` on the
    /// authority of `actor` (`None`: the write names no actor) at `now`, or
    /// `None` when it can as far as the row shows. The database decides
    /// again inside the write (it also re-checks the proposer's assignment
    /// and the confirming passkey); this is the CLI's early, explained
    /// refusal.
    #[must_use]
    pub fn refusal_for(
        &self,
        kind: &str,
        args: &Value,
        actor: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Option<String> {
        if self.kind != kind {
            return Some(format!(
                "act {} is a {} act, not {kind}",
                self.id, self.kind
            ));
        }
        if self.outcome.as_deref() != Some("confirmed") {
            return Some(format!(
                "act {} is not confirmed ({}); confirm it with the proposer's passkey at \
                 /elevate/act/{} first",
                self.id,
                self.refusal.as_deref().unwrap_or("no assertion yet"),
                self.id
            ));
        }
        if let Some(at) = self.consumed_at {
            return Some(format!("act {} was already executed at {at}", self.id));
        }
        if now >= self.expires_at {
            return Some(format!(
                "act {} expired at {}; propose it again",
                self.id, self.expires_at
            ));
        }
        if self.args_digest.as_slice() != args_digest(args) {
            return Some(format!(
                "these flags are not the args act {} confirmed: the act says {}, the flags say {}",
                self.id,
                canonical_json(&self.args),
                canonical_json(args)
            ));
        }
        if let Some(actor) = actor {
            if actor != self.proposed_by {
                return Some(format!(
                    "act {} was proposed and confirmed by {}, not by {actor}",
                    self.id, self.proposed_by
                ));
            }
        }
        None
    }
}

/// Repository for pending admin acts.
pub struct AdminActRepository;

impl AdminActRepository {
    /// One act by id (a maintenance read; an application connection sees
    /// none).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn get(
        conn: &mut sqlx::PgConnection,
        act: Uuid,
    ) -> Result<Option<AdminActRow>, DbError> {
        let row = sqlx::query_as::<_, AdminActRow>(
            "SELECT id, kind, args, args_digest, reason, proposed_by, elevation_id, \
                    assignment_id, proposed_at, expires_at, outcome, refusal, \
                    authenticator_id, consumed_at \
               FROM pending_admin_acts WHERE id = $1",
        )
        .bind(act)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_sort_by_bytes_and_nothing_is_spaced() {
        let v = json!({"b": 1, "aa": [true, null, {"z": "x", "y": "é"}], "a": "q\"\\\n\u{1}"});
        assert_eq!(
            canonical_json(&v),
            "{\"a\":\"q\\\"\\\\\\n\\u0001\",\"aa\":[true,null,{\"y\":\"é\",\"z\":\"x\"}],\"b\":1}"
        );
    }

    #[test]
    fn a_truth_value_is_stated_to_six_places_or_refused() {
        assert_eq!(canonical_truth(0.7).as_deref(), Ok("0.700000"));
        assert_eq!(canonical_truth(1.0).as_deref(), Ok("1.000000"));
        assert_eq!(canonical_truth(0.0).as_deref(), Ok("0.000000"));
        assert!(canonical_truth(0.123_456_7).is_err());
        assert!(canonical_truth(1.5).is_err());
    }

    #[test]
    fn a_time_is_utc_with_microseconds() {
        let t = DateTime::parse_from_rfc3339("2030-01-01T00:00:00.5+02:00")
            .expect("time")
            .with_timezone(&Utc);
        assert_eq!(canonical_timestamp(t), "2029-12-31T22:00:00.500000Z");
    }
}
