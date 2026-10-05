//! WebAuthn passkey ceremonies for EpiGraph.
//!
//! A thin, opinionated wrapper over `webauthn-rs` 0.5: the relying-party
//! configuration ([`config`]), registration and authentication ceremonies
//! whose in-flight state is a JSON value a database row can hold, and an
//! evidence re-verifier ([`Passkeys::reverify`]) that re-checks a stored
//! assertion against a stored credential long after the ceremony ended.
//!
//! # What the database never decides
//!
//! The ceremony state between a ceremony's two HTTP requests lives in a row
//! the request DSN can write. Nothing security-relevant is taken from it on
//! the way back in:
//!
//! * the attestation roots and AAGUID allowlist come from THIS process's
//!   configuration at finish time, never from the stored state
//!   ([`Passkeys::finish_registration`]);
//! * user verification is checked on the registered credential and on every
//!   assertion here, whatever policy the stored state names (operator ruling
//!   D5: a passkey with user verification);
//! * the stored state must have been started under the policy this process
//!   runs now.
//!
//! # Where this crate is linked
//!
//! `epigraph-api` (feature `db`) and, later, the maintenance CLI's verifier.
//! NEVER `epigraph-mcp`: `webauthn-rs-core` links OpenSSL, and the fleet MCP
//! image and the stdio server stay free of it
//! (`tests/dependency_boundary.rs`).

pub mod config;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationCaList, AttestationCaListBuilder, AttestedPasskeyRegistration, Passkey,
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    Webauthn, WebauthnBuilder, WebauthnError,
};

pub use config::{AttestationPolicy, ConfigError, PasskeyConfig};

/// The shortest challenge [`Passkeys::start_authentication`] accepts as an
/// override (WebAuthn recommends at least 16 random bytes).
pub const MIN_CHALLENGE_LEN: usize = 16;
/// The longest challenge override accepted.
pub const MAX_CHALLENGE_LEN: usize = 64;

/// The relying-party name shown by authenticators.
const RP_NAME: &str = "EpiGraph";

/// Why a ceremony step failed.
#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    /// The configuration could not build a relying party.
    #[error("passkey configuration: {0}")]
    Config(String),
    /// The library refused the ceremony (origin, rp id, signature,
    /// attestation, ...). The text is the library's.
    #[error("the authenticator's response was refused: {0}")]
    Refused(String),
    /// The authenticator did not verify its user (D5).
    #[error("the authenticator did not verify its user; a passkey needs user verification")]
    UserNotVerified,
    /// The assertion's signature counter did not advance past the stored one:
    /// a possibly cloned authenticator.
    #[error("the signature counter did not advance; the credential may be cloned")]
    CounterRegressed,
    /// The stored ceremony state is not one this process can finish.
    #[error("ceremony state: {0}")]
    State(String),
    /// A request or stored value is malformed.
    #[error("malformed {what}: {detail}")]
    Malformed {
        /// Which value.
        what: &'static str,
        /// Why.
        detail: String,
    },
}

fn malformed(what: &'static str, e: impl std::fmt::Display) -> PasskeyError {
    PasskeyError::Malformed {
        what,
        detail: e.to_string(),
    }
}

fn refused(e: &WebauthnError) -> PasskeyError {
    match e {
        WebauthnError::UserNotVerified => PasskeyError::UserNotVerified,
        WebauthnError::CredentialPossibleCompromise => PasskeyError::CounterRegressed,
        other => PasskeyError::Refused(other.to_string()),
    }
}

/// The opaque, serializable state of a registration in flight.
#[derive(Clone, Debug, PartialEq)]
pub struct RegistrationState(Value);

impl RegistrationState {
    /// The JSON object a database row stores.
    #[must_use]
    pub fn to_json(&self) -> Value {
        self.0.clone()
    }

    /// Back from the stored JSON. Checked when it is used, not here.
    #[must_use]
    pub fn from_json(v: Value) -> Self {
        Self(v)
    }
}

/// The opaque, serializable state of an authentication in flight.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticationState(Value);

impl AuthenticationState {
    /// The JSON object a database row stores.
    #[must_use]
    pub fn to_json(&self) -> Value {
        self.0.clone()
    }

    /// Back from the stored JSON. Checked when it is used, not here.
    #[must_use]
    pub fn from_json(v: Value) -> Self {
        Self(v)
    }

    /// The challenge this authentication was started with.
    ///
    /// # Errors
    /// The state is malformed.
    pub fn challenge(&self) -> Result<Vec<u8>, PasskeyError> {
        let raw = self
            .0
            .pointer("/library/ast/challenge")
            .and_then(Value::as_str)
            .ok_or_else(|| PasskeyError::State("no challenge".into()))?;
        URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|e| malformed("challenge", e))
    }
}

/// What a verified registration yields: the columns of a
/// `person_authenticators` row (migration 124).
#[derive(Clone, Debug, PartialEq)]
pub struct RegisteredPasskey {
    /// The credential id (16..=1023 bytes).
    pub credential_id: Vec<u8>,
    /// The library's serialized credential, public key and counter included
    /// (`{"cred": {...}}`).
    pub passkey: Value,
    /// The authenticator model, from a verified attestation; the nil UUID for
    /// `none` and self attestation.
    pub aaguid: Uuid,
    /// The attestation statement format (`packed`, `tpm`, `none`, ...).
    pub attestation_format: String,
    /// Whether the authenticator verified its user. Always true: a
    /// registration that did not is refused.
    pub user_verified: bool,
    /// Whether the credential may be synced between devices.
    pub backup_eligible: bool,
}

/// A stored passkey, as a ceremony needs it: the serialized credential and the
/// signature counter the database holds (which supersedes the one inside the
/// serialized credential: the database's column is the one that advances).
#[derive(Clone, Debug, PartialEq)]
pub struct StoredPasskey {
    /// [`RegisteredPasskey::passkey`] as stored.
    pub passkey: Value,
    /// The stored signature counter.
    pub sign_count: u32,
}

/// A verified assertion.
#[derive(Clone, Debug, PartialEq)]
pub struct Assertion {
    /// The asserting credential.
    pub credential_id: Vec<u8>,
    /// The authenticator's signature counter in this assertion.
    pub counter: u32,
    /// Always true: an assertion without user verification is refused.
    pub user_verified: bool,
    /// The backup-eligible flag the authenticator ASSERTED. The library's
    /// passkey path accepts a credential registered device-bound that now
    /// asserts as syncable; a caller that must refuse that change (an
    /// elevation: `backup_eligibility_changed`) compares this with the flag
    /// it stored at registration.
    pub backup_eligible: bool,
    /// What [`Passkeys::reverify`] needs to check this assertion again later:
    /// the challenge and the client's response, verbatim.
    pub evidence: Value,
}

/// A relying party: one configuration, ready to run ceremonies.
pub struct Passkeys {
    config: PasskeyConfig,
    webauthn: Webauthn,
    /// Built from [`AttestationPolicy::Allowlist`]; `None` for
    /// [`AttestationPolicy::SoftwareAllowed`].
    ca_list: Option<AttestationCaList>,
}

impl std::fmt::Debug for Passkeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Passkeys")
            .field("rp_id", &self.config.rp_id)
            .field("origin", &self.config.origin.as_str())
            .field(
                "software_attestation",
                &self.config.allows_software_attestation(),
            )
            .finish_non_exhaustive()
    }
}

const STATE_VERSION: u64 = 1;
const KIND_ATTESTED: &str = "attested";
const KIND_SOFTWARE: &str = "software";

impl Passkeys {
    /// Build the relying party for `config`.
    ///
    /// # Errors
    /// [`PasskeyError::Config`]: the origin does not belong to the rp id, or a
    /// root certificate does not parse.
    pub fn new(config: PasskeyConfig) -> Result<Self, PasskeyError> {
        // Exact origin only: neither `allow_subdomains` nor `allow_any_port`.
        let webauthn = WebauthnBuilder::new(&config.rp_id, &config.origin)
            .map_err(|e| PasskeyError::Config(e.to_string()))?
            .rp_name(RP_NAME)
            .build()
            .map_err(|e| PasskeyError::Config(e.to_string()))?;
        let ca_list = match &config.policy {
            AttestationPolicy::SoftwareAllowed => None,
            AttestationPolicy::Allowlist { ca_pem, aaguids } => {
                let certs = config::pem_certificates(ca_pem);
                if certs.is_empty() || aaguids.is_empty() {
                    return Err(PasskeyError::Config(
                        "the attestation allowlist needs a root and an AAGUID".into(),
                    ));
                }
                // Every (root, AAGUID) pair: a root admits ONLY the listed
                // models, never a blanket allow.
                let mut builder = AttestationCaListBuilder::new();
                for cert in &certs {
                    for aaguid in aaguids {
                        builder
                            .insert_device_pem(
                                cert,
                                *aaguid,
                                format!("allowlisted authenticator {aaguid}"),
                                std::collections::BTreeMap::new(),
                            )
                            .map_err(|e| PasskeyError::Config(format!("attestation root: {e}")))?;
                    }
                }
                Some(builder.build())
            }
        };
        Ok(Self {
            config,
            webauthn,
            ca_list,
        })
    }

    /// The configuration this relying party runs.
    #[must_use]
    pub fn config(&self) -> &PasskeyConfig {
        &self.config
    }

    /// Start registering a passkey for the human whose principal is `user_id`.
    /// Returns the options to hand to `navigator.credentials.create` (JSON,
    /// `{"publicKey": ...}`) and the state to store until the response comes
    /// back.
    ///
    /// Under the allowlist policy this is an ATTESTED registration (direct
    /// attestation, packed or TPM, a hardware-bound key); under the software
    /// policy a plain passkey registration. Both require user verification.
    ///
    /// # Errors
    /// The library refused to build the challenge.
    pub fn start_registration(
        &self,
        user_id: Uuid,
        user_name: &str,
        display_name: &str,
    ) -> Result<(Value, RegistrationState), PasskeyError> {
        let (options, kind, library) = match &self.ca_list {
            Some(ca_list) => {
                let (ccr, state) = self
                    .webauthn
                    .start_attested_passkey_registration(
                        user_id,
                        user_name,
                        display_name,
                        None,
                        ca_list.clone(),
                        None,
                    )
                    .map_err(|e| refused(&e))?;
                (
                    serde_json::to_value(&ccr).map_err(|e| malformed("options", e))?,
                    KIND_ATTESTED,
                    serde_json::to_value(&state).map_err(|e| malformed("state", e))?,
                )
            }
            None => {
                let (ccr, state) = self
                    .webauthn
                    .start_passkey_registration(user_id, user_name, display_name, None)
                    .map_err(|e| refused(&e))?;
                (
                    serde_json::to_value(&ccr).map_err(|e| malformed("options", e))?,
                    KIND_SOFTWARE,
                    serde_json::to_value(&state).map_err(|e| malformed("state", e))?,
                )
            }
        };
        let state = serde_json::json!({
            "v": STATE_VERSION,
            "kind": kind,
            "library": library,
        });
        Ok((options, RegistrationState(state)))
    }

    fn library_state<'a>(&self, state: &'a Value, kind: &str) -> Result<&'a Value, PasskeyError> {
        if state.get("v").and_then(Value::as_u64) != Some(STATE_VERSION) {
            return Err(PasskeyError::State("unknown state version".into()));
        }
        let stored = state.get("kind").and_then(Value::as_str);
        if stored != Some(kind) {
            return Err(PasskeyError::State(format!(
                "started under the {} policy, finishing under the {kind} policy",
                stored.unwrap_or("unknown")
            )));
        }
        state
            .get("library")
            .ok_or_else(|| PasskeyError::State("no library state".into()))
    }

    /// Finish a registration: verify the authenticator's response (`response`,
    /// the JSON of a `PublicKeyCredential` from `navigator.credentials.create`)
    /// against `state`.
    ///
    /// The attestation roots and AAGUID allowlist are THIS process's, spliced
    /// over whatever the stored state carries; user verification is checked on
    /// the credential whatever policy the stored state names.
    ///
    /// # Errors
    /// [`PasskeyError::Refused`] / [`PasskeyError::UserNotVerified`]: the
    /// response does not verify (wrong origin or rp id, bad signature, an
    /// attestation that is not allowlisted, no user verification, ...).
    /// [`PasskeyError::State`]: the state was not started under this policy.
    pub fn finish_registration(
        &self,
        response: &Value,
        state: &RegistrationState,
    ) -> Result<RegisteredPasskey, PasskeyError> {
        let reg: RegisterPublicKeyCredential =
            serde_json::from_value(response.clone()).map_err(|e| malformed("response", e))?;
        let passkey_json = match &self.ca_list {
            Some(ca_list) => {
                let mut library = self.library_state(&state.0, KIND_ATTESTED)?.clone();
                // The roots are ours, not the row's.
                let ours = serde_json::to_value(ca_list).map_err(|e| malformed("roots", e))?;
                match library.as_object_mut() {
                    Some(obj) => {
                        obj.insert("ca_list".into(), ours);
                    }
                    None => return Err(PasskeyError::State("not an object".into())),
                }
                let st: AttestedPasskeyRegistration =
                    serde_json::from_value(library).map_err(|e| malformed("state", e))?;
                let pk = self
                    .webauthn
                    .finish_attested_passkey_registration(&reg, &st)
                    .map_err(|e| refused(&e))?;
                serde_json::to_value(&pk).map_err(|e| malformed("credential", e))?
            }
            None => {
                let library = self.library_state(&state.0, KIND_SOFTWARE)?.clone();
                let st: PasskeyRegistration =
                    serde_json::from_value(library).map_err(|e| malformed("state", e))?;
                let pk = self
                    .webauthn
                    .finish_passkey_registration(&reg, &st)
                    .map_err(|e| refused(&e))?;
                serde_json::to_value(&pk).map_err(|e| malformed("credential", e))?
            }
        };
        registered_from(passkey_json)
    }

    fn passkey_of(stored: &StoredPasskey, counter: u32) -> Result<Passkey, PasskeyError> {
        let mut json = stored.passkey.clone();
        let cred = json
            .get_mut("cred")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| malformed("stored passkey", "no credential"))?;
        cred.insert("counter".into(), Value::from(counter));
        serde_json::from_value(json).map_err(|e| malformed("stored passkey", e))
    }

    /// Start an assertion by any of `passkeys` (each with its stored counter),
    /// with user verification required. Returns the options for
    /// `navigator.credentials.get` and the state to store.
    ///
    /// `challenge` OVERRIDES the library's random challenge: an act
    /// confirmation commits to the act by asserting over a challenge computed
    /// from it, which the verifier can recompute later. It must be
    /// [`MIN_CHALLENGE_LEN`]..=[`MAX_CHALLENGE_LEN`] bytes.
    ///
    /// # Errors
    /// No passkey, a malformed stored passkey, or a challenge of the wrong
    /// length.
    pub fn start_authentication(
        &self,
        passkeys: &[StoredPasskey],
        challenge: Option<&[u8]>,
    ) -> Result<(Value, AuthenticationState), PasskeyError> {
        self.start_authentication_inner(passkeys, challenge, false)
    }

    /// [`Self::start_authentication`], with the signature counter left to the
    /// CALLER: every credential's counter is taken as 0, so
    /// [`Self::finish_authentication`] never refuses on it, and the caller
    /// compares [`Assertion::counter`] with its stored counter itself.
    ///
    /// For a caller whose database is the counter's authority: it compares
    /// under the row lock it updates the counter with (two concurrent
    /// ceremonies cannot both pass), and it can audit a regression, which a
    /// refusal here could not (the asserting credential and counter would
    /// never reach it). Elevation's confirm definer is that caller (ELV05).
    ///
    /// # Errors
    /// As [`Self::start_authentication`].
    pub fn start_authentication_deferring_counter(
        &self,
        passkeys: &[StoredPasskey],
        challenge: Option<&[u8]>,
    ) -> Result<(Value, AuthenticationState), PasskeyError> {
        self.start_authentication_inner(passkeys, challenge, true)
    }

    fn start_authentication_inner(
        &self,
        passkeys: &[StoredPasskey],
        challenge: Option<&[u8]>,
        ignore_counters: bool,
    ) -> Result<(Value, AuthenticationState), PasskeyError> {
        if passkeys.is_empty() {
            return Err(PasskeyError::State("no passkey to assert with".into()));
        }
        let creds = passkeys
            .iter()
            .map(|p| Self::passkey_of(p, if ignore_counters { 0 } else { p.sign_count }))
            .collect::<Result<Vec<_>, _>>()?;
        let (rcr, st) = self
            .webauthn
            .start_passkey_authentication(&creds)
            .map_err(|e| refused(&e))?;
        let mut options = serde_json::to_value(&rcr).map_err(|e| malformed("options", e))?;
        let mut library = serde_json::to_value(&st).map_err(|e| malformed("state", e))?;
        if let Some(c) = challenge {
            if !(MIN_CHALLENGE_LEN..=MAX_CHALLENGE_LEN).contains(&c.len()) {
                return Err(malformed(
                    "challenge",
                    format!(
                        "{} bytes; {MIN_CHALLENGE_LEN}..={MAX_CHALLENGE_LEN} required",
                        c.len()
                    ),
                ));
            }
            let enc = Value::from(URL_SAFE_NO_PAD.encode(c));
            match (
                options.pointer_mut("/publicKey/challenge"),
                library.pointer_mut("/ast/challenge"),
            ) {
                (Some(o), Some(s)) => {
                    *o = enc.clone();
                    *s = enc;
                }
                _ => return Err(PasskeyError::State("no challenge to override".into())),
            }
        }
        let state = serde_json::json!({ "v": STATE_VERSION, "library": library });
        Ok((options, AuthenticationState(state)))
    }

    /// Finish an assertion: verify `response` (the JSON of a
    /// `PublicKeyCredential` from `navigator.credentials.get`) against
    /// `state`. User verification is required.
    ///
    /// # Errors
    /// [`PasskeyError::Refused`], [`PasskeyError::UserNotVerified`] or
    /// [`PasskeyError::CounterRegressed`].
    pub fn finish_authentication(
        &self,
        response: &Value,
        state: &AuthenticationState,
    ) -> Result<Assertion, PasskeyError> {
        if state.0.get("v").and_then(Value::as_u64) != Some(STATE_VERSION) {
            return Err(PasskeyError::State("unknown state version".into()));
        }
        let library = state
            .0
            .get("library")
            .cloned()
            .ok_or_else(|| PasskeyError::State("no library state".into()))?;
        let st: PasskeyAuthentication =
            serde_json::from_value(library).map_err(|e| malformed("state", e))?;
        let cred: PublicKeyCredential =
            serde_json::from_value(response.clone()).map_err(|e| malformed("response", e))?;
        let res = self
            .webauthn
            .finish_passkey_authentication(&cred, &st)
            .map_err(|e| refused(&e))?;
        if !res.user_verified() {
            return Err(PasskeyError::UserNotVerified);
        }
        let challenge = state.challenge()?;
        Ok(Assertion {
            credential_id: res.cred_id().as_slice().to_vec(),
            counter: res.counter(),
            user_verified: true,
            backup_eligible: res.backup_eligible(),
            evidence: serde_json::json!({
                "v": STATE_VERSION,
                "challenge": URL_SAFE_NO_PAD.encode(&challenge),
                "response": response,
            }),
        })
    }

    /// Re-verify a stored assertion (`evidence`, [`Assertion::evidence`]) by
    /// the credential it names (`snapshot`), against this relying party's rp
    /// id and origin and the challenge recorded in the evidence. The signature
    /// counter is NOT re-checked (it is the database's, and it has moved on);
    /// everything else is, as at the ceremony.
    ///
    /// A caller that knows what the challenge MUST have been (an act
    /// confirmation's, recomputed from the act) compares it with
    /// [`evidence_challenge`] as well: a valid signature over another
    /// challenge verifies here.
    ///
    /// # Errors
    /// The evidence does not verify, or is malformed.
    pub fn reverify(
        &self,
        evidence: &Value,
        snapshot: &StoredPasskey,
    ) -> Result<Assertion, PasskeyError> {
        let challenge = evidence_challenge(evidence)?;
        let response = evidence
            .get("response")
            .ok_or_else(|| malformed("evidence", "no response"))?;
        let (_, state) = self.start_authentication_inner(
            std::slice::from_ref(snapshot),
            Some(&challenge),
            true,
        )?;
        self.finish_authentication(response, &state)
    }
}

/// The length of the server nonce an admin act's confirmation challenge is
/// computed with ([`act_challenge`]).
pub const ACT_NONCE_LEN: usize = 32;

/// The challenge an ADMIN ACT's confirmation asserts over (elevation plan
/// §1.6): SHA-256 of the act id's 16 bytes, the act's args digest (SHA-256 of
/// its canonical args, 32 bytes) and a server nonce, concatenated in that
/// order. Every part has a fixed length, so the concatenation is unambiguous.
///
/// It is given to [`Passkeys::start_authentication_deferring_counter`] as the
/// challenge override, and the nonce is stored with the ceremony state. The
/// page that runs the ceremony can therefore not show act A while the
/// passkey confirms act B: whoever holds the act row (the API at the
/// assertion, the offline verifier long after) recomputes the challenge from
/// the act id and the STORED digest and refuses a stored state, or a recorded
/// assertion, whose challenge is anything else.
#[must_use]
pub fn act_challenge(act: Uuid, args_digest: &[u8; 32], nonce: &[u8; ACT_NONCE_LEN]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(act.as_bytes());
    h.update(args_digest);
    h.update(nonce);
    h.finalize().into()
}

/// The challenge recorded in an assertion's evidence.
///
/// # Errors
/// The evidence is malformed.
pub fn evidence_challenge(evidence: &Value) -> Result<Vec<u8>, PasskeyError> {
    if evidence.get("v").and_then(Value::as_u64) != Some(STATE_VERSION) {
        return Err(malformed("evidence", "unknown version"));
    }
    let raw = evidence
        .get("challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("evidence", "no challenge"))?;
    URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|e| malformed("evidence challenge", e))
}

/// The row columns of a library-serialized credential (`{"cred": {...}}`).
fn registered_from(passkey: Value) -> Result<RegisteredPasskey, PasskeyError> {
    let cred = passkey
        .get("cred")
        .ok_or_else(|| malformed("credential", "no cred"))?;
    let credential_id = URL_SAFE_NO_PAD
        .decode(
            cred.get("cred_id")
                .and_then(Value::as_str)
                .ok_or_else(|| malformed("credential", "no cred_id"))?,
        )
        .map_err(|e| malformed("credential id", e))?;
    let user_verified = cred
        .get("user_verified")
        .and_then(Value::as_bool)
        .ok_or_else(|| malformed("credential", "no user_verified"))?;
    // D5, whatever the stored state's policy said.
    if !user_verified {
        return Err(PasskeyError::UserNotVerified);
    }
    let backup_eligible = cred
        .get("backup_eligible")
        .and_then(Value::as_bool)
        .ok_or_else(|| malformed("credential", "no backup_eligible"))?;
    let attestation_format = cred
        .get("attestation_format")
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("credential", "no attestation_format"))?
        .to_string();
    let format_ok = attestation_format
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase())
        && attestation_format
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !format_ok {
        return Err(malformed("attestation format", &attestation_format));
    }
    // A verified attestation names its model; `none` and self attestation do
    // not, and are recorded with the nil AAGUID.
    let metadata = cred.pointer("/attestation/metadata");
    let aaguid = match metadata.and_then(|m| {
        m.pointer("/Packed/aaguid")
            .or_else(|| m.pointer("/Tpm/aaguid"))
    }) {
        Some(v) => v
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| malformed("credential", "aaguid"))?,
        None => Uuid::nil(),
    };
    Ok(RegisteredPasskey {
        credential_id,
        passkey,
        aaguid,
        attestation_format,
        user_verified,
        backup_eligible,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The act challenge is SHA-256 over the act id's 16 bytes, the args
    /// digest and the nonce, in that order (a fixed vector computed outside
    /// Rust). Mutations: the id hashed as its text; the nonce omitted; the
    /// digest and nonce swapped; any part replaced by a random value -> the
    /// vector differs.
    #[test]
    fn the_act_challenge_is_sha256_of_id_digest_and_nonce() {
        let act = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let digest = [0x11u8; 32];
        let nonce = [0x22u8; ACT_NONCE_LEN];
        let c = act_challenge(act, &digest, &nonce);
        assert_eq!(
            c.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "fefcb32873e8b15e1f6c8aec0c094474d04f6a8e3beec576ac9d684fc01640bf"
        );
        // One bit of the digest changes the challenge.
        let mut other = digest;
        other[0] = 0x12;
        assert_eq!(
            act_challenge(act, &other, &nonce)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "4cd9a8b75d8f9af7862a312958f2c8b47ff47c6912ee8ed085a7ef32b332730a"
        );
        // A challenge override accepts it.
        assert!((MIN_CHALLENGE_LEN..=MAX_CHALLENGE_LEN).contains(&c.len()));
    }
}
