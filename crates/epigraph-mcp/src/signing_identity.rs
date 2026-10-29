//! The separate-signing-key mode (agent identity lineage design D1, D2): the
//! boot check, and the key binding `verify_claim` reports.
//!
//! # The two keys
//!
//! * The IDENTITY key names the agent (`agents.public_key`). The host derives
//!   it from a secret it never shares, registers the agent under it, and gives
//!   the container only its PUBLIC half (`EPIGRAPH_AGENT_IDENTITY_PUBKEY`). It
//!   signs nothing.
//! * The SIGNING key is random. The host registers its public half for the
//!   agent in `agent_keys` (`key_type 'signing'`, through migration 161's
//!   attestor-only registration) and gives the container the private half
//!   (`EPIGRAPH_AGENT_SIGNING_KEY`). Every signature this process makes is
//!   by it.
//!
//! # Why the boot check
//!
//! A container cannot register a signing key itself (migration 161 section
//! 7a refuses an attested key type to the application role). A signing key the
//! host did not register would produce signatures that verify against nothing
//! the database knows, and `verify_claim` would report them unbound forever.
//! So [`check_signing_key`] refuses to start unless the signing key is an
//! ACTIVE `signing` key of the identity's agent whose validity window is open
//! now (the window `verify_claim` binds by). It only reads: a refused boot
//! leaves no agent row behind.

use chrono::{DateTime, Utc};
use epigraph_db::{AgentKeyRepository, AgentKeyRow, AgentRepository, AttestedKeyRow};
use sqlx::PgPool;
use uuid::Uuid;

/// The attested key type the separate-signing-key mode signs with.
pub const KEY_KIND_SIGNING: &str = "signing";
/// Migration 161's backfilled key type for an agent's pre-existing identity
/// key. Under the unkeyed scheme its private half is computable from public
/// inputs, so a signature under it is forgeable.
pub const KEY_KIND_IDENTITY_LEGACY: &str = "identity-legacy";
/// A signature that verifies only under the signer's `agents.public_key`,
/// which no attested `agent_keys` row carries.
pub const KEY_KIND_UNATTESTED: &str = "unattested";

/// Refuse to serve unless `signing_public_key` is an ACTIVE `signing` key of
/// the agent whose identity key is `identity_public_key`. Returns that agent's
/// id. Read-only: nothing is created, so a refused boot leaves no row.
///
/// # Errors
///
/// The operator-facing refusal (it names public keys only; the private key is
/// never in scope here), or a failed read.
pub async fn check_signing_key(
    pool: &PgPool,
    identity_public_key: &[u8; 32],
    signing_public_key: &[u8; 32],
) -> Result<Uuid, String> {
    let identity_hex = hex::encode(identity_public_key);
    let agent = AgentRepository::get_by_public_key(pool, identity_public_key)
        .await
        .map_err(|e| format!("could not look up the identity public key {identity_hex}: {e}"))?
        .ok_or_else(|| {
            format!(
                "no agent has the identity public key {identity_hex} \
                 (EPIGRAPH_AGENT_IDENTITY_PUBKEY). The host registers an identity, with its \
                 signing key, before the container starts; refusing to start rather than create \
                 an unregistered identity."
            )
        })?
        .id
        .as_uuid();
    let rows = AgentKeyRepository::rows_with_public_key(pool, signing_public_key)
        .await
        .map_err(|e| format!("could not read the signing key's agent_keys rows: {e}"))?;
    // This process's clock, not the database's: it is the clock that stamps
    // `created_at` on every claim this process will sign, so the question is
    // exactly "would a claim signed now bind?".
    signing_key_verdict(agent, signing_public_key, &rows, Utc::now())?;
    Ok(agent)
}

/// The pure half of [`check_signing_key`]: admit iff some row of `rows` (all
/// of them carry the signing public key) is an active `signing` key of
/// `agent` whose window admits `at` ([`window_admits`], as `verify_claim`
/// binds); otherwise say what the rows show instead.
///
/// `rows` come from `AgentKeyRepository::rows_with_public_key`, which spells
/// `key_type` and `status` as migration 161's guard does (`lower(btrim(..))`),
/// so they are compared here as exact literals: normalising again in Rust
/// would be a second, different spelling.
fn signing_key_verdict(
    agent: Uuid,
    signing_public_key: &[u8; 32],
    rows: &[AgentKeyRow],
    at: DateTime<Utc>,
) -> Result<(), String> {
    if rows.iter().any(|r| {
        r.agent_id == agent
            && r.key_type == KEY_KIND_SIGNING
            && r.status == "active"
            && window_admits(&r.status, r.valid_from, r.valid_until, at)
    }) {
        return Ok(());
    }
    let signing_hex = hex::encode(signing_public_key);
    let found = if rows.is_empty() {
        "it is registered for no agent".to_string()
    } else {
        rows.iter()
            .map(|r| {
                let whose = if r.agent_id == agent {
                    "this agent".to_string()
                } else {
                    format!("agent {}", r.agent_id)
                };
                let until = r
                    .valid_until
                    .map_or_else(|| "open".to_string(), |u| u.to_rfc3339());
                format!(
                    "a {} key of {whose} with status {}, valid from {} until {until}",
                    r.key_type,
                    r.status,
                    r.valid_from.to_rfc3339()
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    Err(format!(
        "the signing key {signing_hex} (public half of EPIGRAPH_AGENT_SIGNING_KEY) is not an \
         active signing key of agent {agent}: {found}. The host registers the signing key \
         (epigraph_register_agent_identity) before the container starts; refusing to start."
    ))
}

/// What `verify_claim` reports about which key signed a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBinding {
    /// The stored signature verifies under the signer's `agents.public_key` or
    /// under an attested key (`signing` / `identity-legacy`) of the claim's
    /// signer or author.
    pub signature_valid: bool,
    /// The verifying key is an attested key of the claim's AUTHOR that was
    /// valid when the claim was created.
    pub key_bound: bool,
    /// The kind of the verifying key: the bound key's kind when bound, else
    /// the kind of an attested key that verifies, else [`KEY_KIND_UNATTESTED`]
    /// when only the signer's `agents.public_key` verifies; `None` when nothing
    /// verifies.
    pub key_kind: Option<&'static str>,
    /// The message the verifying key's signature was made over (ruling R-34):
    /// `v1` (claim-tagged) or `legacy` (the bare digest), for the same key
    /// `key_kind` names; `None` when nothing verifies.
    pub signature_scheme: Option<epigraph_crypto::SignatureScheme>,
}

/// How far before a key's `valid_from` a claim may be dated and still bind:
/// the shared window rule's skew ([`epigraph_db::repos::agent_key::KEY_VALID_FROM_SKEW_SECS`]).
///
/// `claims.created_at` is stamped by the writer's clock (`Claim::new`) and
/// `valid_from` by the database's (`now()` at registration), so a writer a
/// little behind the database dates its first claims before the window
/// opens. This is clock skew, not a security boundary: `created_at` is set by
/// the writer and is not covered by the signature, so the lower bound never
/// stopped a determined backdater. Only the LOWER bound is relaxed; a window's
/// END (rotation, the legacy cut-over) stays exact.
pub const VALID_FROM_SKEW_SECS: i64 = epigraph_db::repos::agent_key::KEY_VALID_FROM_SKEW_SECS;

/// Whether an attested key row was valid at `at`: inside `[valid_from -
/// VALID_FROM_SKEW_SECS, valid_until)`, and ACTIVE, or ROTATED / EXPIRED with a
/// recorded `valid_until` (a rotated key with an open window records no end,
/// so it binds nothing). A REVOKED or PENDING key binds nothing: a revoked key
/// is treated as compromised from the start.
fn valid_at(row: &AttestedKeyRow, at: DateTime<Utc>) -> bool {
    window_admits(&row.status, row.valid_from, row.valid_until, at)
}

/// [`valid_at`] over the fields alone, shared with the boot verdict so the
/// boot check and `verify_claim` cannot disagree about a window. It IS the
/// repository's [`epigraph_db::repos::agent_key::key_window_admits`], which
/// the edge verifier calls too.
fn window_admits(
    status: &str,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
    at: DateTime<Utc>,
) -> bool {
    epigraph_db::repos::agent_key::key_window_admits(status, valid_from, valid_until, at)
}

fn kind_of(row: &AttestedKeyRow) -> Option<&'static str> {
    match row.key_type.as_str() {
        KEY_KIND_SIGNING => Some(KEY_KIND_SIGNING),
        KEY_KIND_IDENTITY_LEGACY => Some(KEY_KIND_IDENTITY_LEGACY),
        _ => None,
    }
}

/// The first `signing` row, else the first row: a `signing` key is preferred
/// over a legacy one when both qualify.
fn prefer_signing<'a>(
    rows: impl Iterator<Item = &'a AttestedKeyRow>,
) -> Option<&'a AttestedKeyRow> {
    let mut first = None;
    for row in rows {
        if row.key_type == KEY_KIND_SIGNING {
            return Some(row);
        }
        first = first.or(Some(row));
    }
    first
}

/// Bind a claim's signature to a key (design D2).
///
/// `signer_key` is the signer agent's `agents.public_key` (what
/// `verify_claim` checked before D2); `keys` are the attested keys of the
/// claim's author and signer. In the separate-signing-key mode the signer's
/// `agents.public_key` is its identity key, which signs nothing, so the
/// signature verifies only under a `signing` row: that is why `keys` widen
/// `signature_valid`. Only attested types are ever passed in (see
/// `AgentKeyRepository::attested_keys_for_claim`), so no
/// application-insertable row can make a signature valid.
#[must_use]
pub fn bind_signature(
    digest: &[u8; 32],
    signature: Option<&[u8; 64]>,
    signer_key: &[u8; 32],
    author: Uuid,
    created_at: DateTime<Utc>,
    keys: &[AttestedKeyRow],
) -> KeyBinding {
    let Some(signature) = signature else {
        return KeyBinding {
            signature_valid: false,
            key_bound: false,
            key_kind: None,
            signature_scheme: None,
        };
    };
    // Versioned (ruling R-34): the claim-tagged v1 message first, then the
    // legacy bare digest. A signature tagged for another kind verifies neither.
    let scheme_under = |key: &[u8]| {
        <[u8; 32]>::try_from(key).ok().and_then(|key| {
            epigraph_crypto::SignatureVerifier::verify_entity(
                &key,
                epigraph_crypto::SignedEntity::Claim,
                digest,
                signature,
            )
            .ok()
            .flatten()
        })
    };
    let verifying: Vec<&AttestedKeyRow> = keys
        .iter()
        .filter(|k| kind_of(k).is_some() && scheme_under(&k.public_key).is_some())
        .collect();
    let signer_key_scheme = scheme_under(signer_key);

    let bound = prefer_signing(
        verifying
            .iter()
            .copied()
            .filter(|k| k.agent_id == author && valid_at(k, created_at)),
    );
    let named = bound.or_else(|| prefer_signing(verifying.iter().copied()));
    let key_kind = named
        .and_then(kind_of)
        .or(signer_key_scheme.map(|_| KEY_KIND_UNATTESTED));
    let signature_scheme = named
        .and_then(|k| scheme_under(&k.public_key))
        .or(signer_key_scheme);
    KeyBinding {
        signature_valid: signer_key_scheme.is_some() || !verifying.is_empty(),
        key_bound: bound.is_some(),
        key_kind,
        signature_scheme,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use epigraph_crypto::AgentSigner;

    fn key_row(agent: Uuid, key_type: &str, status: &str) -> AgentKeyRow {
        let now = Utc::now();
        AgentKeyRow {
            id: Uuid::new_v4(),
            agent_id: agent,
            public_key: vec![7; 32],
            key_type: key_type.to_string(),
            status: status.to_string(),
            valid_from: now,
            valid_until: None,
            revocation_reason: None,
            revoked_by: None,
            created_at: now,
        }
    }

    /// Exactly an active signing row of the agent admits; every near miss
    /// (other agent, legacy type, rotated, revoked, no row) refuses.
    #[test]
    fn the_verdict_admits_only_an_active_signing_row_of_the_agent() {
        let agent = Uuid::new_v4();
        let other = Uuid::new_v4();
        let pk = [7u8; 32];
        assert!(signing_key_verdict(
            agent,
            &pk,
            &[key_row(agent, "signing", "active")],
            Utc::now()
        )
        .is_ok());
        for rows in [
            // Normalising is the read's job (SQL `lower(btrim(..))`), so a
            // spelling the read would not produce is not admitted here.
            vec![key_row(agent, "signing\t", "active")],
            vec![],
            vec![key_row(other, "signing", "active")],
            vec![key_row(agent, "identity-legacy", "active")],
            vec![key_row(agent, "signing", "rotated")],
            vec![key_row(agent, "signing", "revoked")],
            vec![key_row(agent, "encryption", "active")],
        ] {
            let err = signing_key_verdict(agent, &pk, &rows, Utc::now()).expect_err("refused");
            assert!(err.contains("is not an active signing key of"), "{err}");
        }
    }

    /// The verdict's window is `verify_claim`'s: an active signing row of the
    /// agent admits only while `[valid_from - skew, valid_until)` holds `at`.
    #[test]
    fn the_verdict_admits_only_inside_the_window() {
        let agent = Uuid::new_v4();
        let pk = [7u8; 32];
        let now = Utc::now();
        let with = |from: DateTime<Utc>, until: Option<DateTime<Utc>>| {
            let mut row = key_row(agent, "signing", "active");
            row.valid_from = from;
            row.valid_until = until;
            vec![row]
        };
        let ok = |rows: Vec<AgentKeyRow>| signing_key_verdict(agent, &pk, &rows, now).is_ok();
        assert!(ok(with(now - Duration::days(1), None)), "open window");
        assert!(ok(with(
            now - Duration::days(1),
            Some(now + Duration::days(1))
        )));
        assert!(
            ok(with(now + Duration::seconds(1), None)),
            "within the skew"
        );
        assert!(
            !ok(with(now - Duration::days(2), Some(now - Duration::days(1)))),
            "closed"
        );
        assert!(
            !ok(with(now - Duration::days(1), Some(now))),
            "ends exactly now"
        );
        assert!(!ok(with(now + Duration::days(1), None)), "not yet open");
    }

    fn attested(
        agent: Uuid,
        key: &AgentSigner,
        key_type: &str,
        status: &str,
        from: DateTime<Utc>,
        until: Option<DateTime<Utc>>,
    ) -> AttestedKeyRow {
        AttestedKeyRow {
            agent_id: agent,
            public_key: key.public_key().to_vec(),
            key_type: key_type.to_string(),
            status: status.to_string(),
            valid_from: from,
            valid_until: until,
        }
    }

    /// A rotated key binds only inside a recorded window; with an open
    /// window it binds nothing, because rotation records no time.
    #[test]
    fn a_rotated_key_binds_only_inside_a_recorded_window() {
        let author = Uuid::new_v4();
        let key = AgentSigner::from_bytes(&[3; 32]).expect("key");
        let digest = [9u8; 32];
        let sig = key.sign(&digest);
        let t0 = Utc::now() - Duration::days(10);
        let at = t0 + Duration::days(2);
        let closed = attested(
            author,
            &key,
            "signing",
            "rotated",
            t0,
            Some(t0 + Duration::days(5)),
        );
        let open = attested(author, &key, "signing", "rotated", t0, None);
        let b = bind_signature(&digest, Some(&sig), &[0; 32], author, at, &[closed]);
        assert!(b.signature_valid && b.key_bound, "{b:?}");
        let b = bind_signature(&digest, Some(&sig), &[0; 32], author, at, &[open]);
        assert!(b.signature_valid && !b.key_bound, "{b:?}");
    }

    /// `claims.created_at` is stamped by the WRITER's clock (`Claim::new`)
    /// and `valid_from` by the DATABASE's (`now()` at registration), so the
    /// first claims after registration can read a little earlier than the
    /// window opens. A small skew still binds; a claim dated well before the
    /// key existed does not.
    #[test]
    fn a_claim_a_moment_before_valid_from_still_binds() {
        let author = Uuid::new_v4();
        let key = AgentSigner::from_bytes(&[5; 32]).expect("key");
        let digest = [2u8; 32];
        let sig = key.sign(&digest);
        let from = Utc::now() - Duration::hours(1);
        let row = attested(author, &key, "signing", "active", from, None);
        for skew in [Duration::milliseconds(1), Duration::seconds(1)] {
            let b = bind_signature(
                &digest,
                Some(&sig),
                &[0; 32],
                author,
                from - skew,
                std::slice::from_ref(&row),
            );
            assert!(b.key_bound, "{skew:?} before valid_from must bind: {b:?}");
        }
        let b = bind_signature(
            &digest,
            Some(&sig),
            &[0; 32],
            author,
            from - Duration::minutes(10),
            std::slice::from_ref(&row),
        );
        assert!(
            b.signature_valid && !b.key_bound,
            "ten minutes early is not skew: {b:?}"
        );
    }

    /// The skew allowance's exact edge: `valid_from - VALID_FROM_SKEW_SECS`
    /// binds, one millisecond earlier does not.
    #[test]
    fn the_skew_allowance_ends_exactly_at_its_bound() {
        let author = Uuid::new_v4();
        let key = AgentSigner::from_bytes(&[6; 32]).expect("key");
        let digest = [3u8; 32];
        let sig = key.sign(&digest);
        let from = Utc::now() - Duration::hours(1);
        let row = attested(author, &key, "signing", "active", from, None);
        let edge = from - Duration::seconds(VALID_FROM_SKEW_SECS);
        let bound = |at| {
            bind_signature(
                &digest,
                Some(&sig),
                &[0; 32],
                author,
                at,
                std::slice::from_ref(&row),
            )
            .key_bound
        };
        assert!(bound(edge), "the edge itself binds");
        assert!(
            !bound(edge - Duration::milliseconds(1)),
            "past the edge does not"
        );
    }

    /// A signature only the signer's `agents.public_key` verifies is valid,
    /// unbound and `unattested`; with no signature at all, nothing is.
    #[test]
    fn a_signature_under_the_bare_agent_key_is_unattested() {
        let author = Uuid::new_v4();
        let key = AgentSigner::from_bytes(&[4; 32]).expect("key");
        let digest = [1u8; 32];
        let sig = key.sign(&digest);
        let b = bind_signature(
            &digest,
            Some(&sig),
            &key.public_key(),
            author,
            Utc::now(),
            &[],
        );
        assert_eq!(
            b,
            KeyBinding {
                signature_valid: true,
                key_bound: false,
                key_kind: Some(KEY_KIND_UNATTESTED),
                signature_scheme: Some(epigraph_crypto::SignatureScheme::Legacy),
            }
        );
        let b = bind_signature(&digest, None, &key.public_key(), author, Utc::now(), &[]);
        assert_eq!(
            b,
            KeyBinding {
                signature_valid: false,
                key_bound: false,
                key_kind: None,
                signature_scheme: None,
            }
        );
    }
    /// Ruling R-34 at the claim verifier: a claim-tagged v1 signature verifies
    /// and says `v1`; the SAME key's evidence-tagged signature over the same
    /// digest is not a claim signature, under the bare agent key or an
    /// attested one.
    #[test]
    fn only_a_claim_tagged_or_legacy_signature_verifies_a_claim() {
        use epigraph_crypto::{SignatureScheme, SignedEntity};
        let author = Uuid::new_v4();
        let key = AgentSigner::from_bytes(&[8; 32]).expect("key");
        let digest = [4u8; 32];
        let row = attested(
            author,
            &key,
            "signing",
            "active",
            Utc::now() - Duration::hours(1),
            None,
        );

        let v1 = key.sign_entity(SignedEntity::Claim, &digest);
        let b = bind_signature(
            &digest,
            Some(&v1),
            &key.public_key(),
            author,
            Utc::now(),
            std::slice::from_ref(&row),
        );
        assert!(b.signature_valid && b.key_bound, "{b:?}");
        assert_eq!(b.signature_scheme, Some(SignatureScheme::V1), "{b:?}");

        let as_evidence = key.sign_entity(SignedEntity::Evidence, &digest);
        for keys in [&[][..], std::slice::from_ref(&row)] {
            let b = bind_signature(
                &digest,
                Some(&as_evidence),
                &key.public_key(),
                author,
                Utc::now(),
                keys,
            );
            assert_eq!(
                b,
                KeyBinding {
                    signature_valid: false,
                    key_bound: false,
                    key_kind: None,
                    signature_scheme: None,
                },
                "an evidence-tagged signature verified a claim"
            );
        }
    }
}
