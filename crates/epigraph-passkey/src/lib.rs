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
//! * the Android key rules (the `android-key` format, a device-bound
//!   credential) are checked here on the registered credential, whatever
//!   the stored state allowed;
//! * whether a registration may carry no attestation (the anchored path) is
//!   decided here ([`Passkeys::check_anchor`]) from the caller's
//!   [`ActAnchor`]: rows written by the API's ceremony, by a holder of the
//!   request DSN with a live enrollment id (who can call 124's
//!   `epigraph_complete_passkey_enrollment` directly, and so can already
//!   plant any key on that enrollment), or by the maintenance DSN. The
//!   confirmation is re-verified against the anchor's key, and the anchor's
//!   own attestation (its stored certificate chain, and for an Android key
//!   that the leaf certifies the credential's key) is re-verified against
//!   the roots THIS process trusts now, as is every passkey on its lineage.
//!   What is not re-verified: that a stored `packed` / `tpm` chain was the
//!   one that attested the stored key (its attestation signature is not
//!   kept), so a row planted through that completion function with a
//!   genuine, public model chain beside the planter's own key passes
//!   ([`Passkeys::hardware_attested`] says what that allows). The stored
//!   state only has to agree;
//! * user verification is checked on the registered credential and on every
//!   assertion here, whatever policy the stored state names (operator ruling
//!   D5: a passkey with user verification);
//! * the stored state must have been started under the policy this process
//!   runs now.
//!
//! # Where this crate is linked
//!
//! `epigraph-api` (feature `db`) and the maintenance CLI's offline confirmation
//! verifier ([`Verifier`]).
//! NEVER `epigraph-mcp`: `webauthn-rs-core` links OpenSSL, and the fleet MCP
//! image and the stdio server stay free of it
//! (`tests/dependency_boundary.rs`).

pub mod android;
pub mod config;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationCa, AttestationCaList, AttestationCaListBuilder, AttestationMetadata,
    AttestedPasskeyRegistration, COSEKey, ParsedAttestation, ParsedAttestationData, Passkey,
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    Webauthn, WebauthnBuilder, WebauthnError,
};
use webauthn_rs_core::attestation::verify_attestation_ca_chain;

pub use config::{
    AaguidAllowlist, AttestationPolicy, AttestedPolicy, ConfigError, PasskeyConfig, RelyingParty,
};

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
    /// The library verified the attestation, and this crate's policy refused
    /// it (an attestation under an Android root that is not a device-bound
    /// `android-key` one; an attestation statement on the anchored path).
    #[error("the attestation was refused: {0}")]
    AttestationRefused(String),
    /// The anchored path's anchor does not admit this registration.
    #[error("the passkey.register act does not anchor this passkey: {0}")]
    Anchor(AnchorRefusal),
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
    /// The attestation statement format (`packed`, `tpm`, `android-key`,
    /// `none`, ...).
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
    /// The per-model allowlist's roots, each admitting only the listed
    /// AAGUIDs; `None` without an allowlist.
    allowlist_cas: Option<AttestationCaList>,
    /// The Android key roots, each a BLANKET allow; `None` without them. A
    /// separate list, never merged into `allowlist_cas`: the library's union
    /// of a blanket and a restricted entry for one root is a blanket allow.
    android_cas: Option<AttestationCaList>,
    /// [`config::ENV_ANDROID_KEY_STATUS_FILE`]: `Some` exactly when
    /// `android_cas` is.
    android_status_file: Option<PathBuf>,
    /// [`config::ENV_ALLOW_SYNCED_ANCHORED_PASSKEY`].
    allow_synced_anchored: bool,
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
const KIND_ANCHORED: &str = "anchored";

/// The allowlist's roots: every (root, AAGUID) pair, so a root admits ONLY
/// the listed models, never a blanket allow.
fn allowlist_cas(
    ca_pem: &[u8],
    aaguids: &BTreeSet<Uuid>,
) -> Result<AttestationCaList, PasskeyError> {
    let certs = config::pem_certificates(ca_pem);
    if certs.is_empty() || aaguids.is_empty() {
        return Err(PasskeyError::Config(
            "the attestation allowlist needs a root and an AAGUID".into(),
        ));
    }
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
    Ok(builder.build())
}

/// The Android key roots: each certificate of the bundle on its own (the
/// library's PEM constructor reads only the first) as a BLANKET allow.
fn android_key_cas(ca_pem: &[u8]) -> Result<AttestationCaList, PasskeyError> {
    let certs = config::pem_certificates(ca_pem);
    if certs.is_empty() {
        return Err(PasskeyError::Config(
            "the Android key roots need a certificate".into(),
        ));
    }
    let mut list = AttestationCaList::default();
    for cert in &certs {
        let one = AttestationCaList::try_from(cert.as_slice())
            .map_err(|e| PasskeyError::Config(format!("Android key attestation root: {e}")))?;
        list.union(&one);
    }
    Ok(list)
}

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
        let (allowlist, android, android_status_file, allow_synced_anchored) = match &config.policy
        {
            AttestationPolicy::SoftwareAllowed => (None, None, None, false),
            AttestationPolicy::Allowlist { ca_pem, aaguids } => {
                (Some(allowlist_cas(ca_pem, aaguids)?), None, None, false)
            }
            AttestationPolicy::Attested(p) => {
                let allowlist = p
                    .allowlist
                    .as_ref()
                    .map(|a| allowlist_cas(&a.ca_pem, &a.aaguids))
                    .transpose()?;
                let android = p
                    .android_key_ca_pem
                    .as_deref()
                    .map(android_key_cas)
                    .transpose()?;
                if allowlist.is_none() && android.is_none() {
                    return Err(PasskeyError::Config(
                        "the attested policy needs the allowlist or the Android key roots".into(),
                    ));
                }
                // No Android root without the revocation input (P779-2).
                let status = match (&android, &p.android_key_status_file) {
                    (Some(_), Some(path)) => Some(path.clone()),
                    (Some(_), None) => {
                        return Err(PasskeyError::Config(format!(
                            "the Android key roots need {}",
                            config::ENV_ANDROID_KEY_STATUS_FILE
                        )))
                    }
                    (None, _) => None,
                };
                (allowlist, android, status, p.allow_synced_anchored)
            }
        };
        if let (Some(a), Some(b)) = (&allowlist, &android) {
            // One root in both files would be trusted for every key it
            // attests in one list and for some models in the other: refuse
            // the ambiguity rather than pick.
            if a.cas().keys().any(|kid| b.cas().contains_key(kid)) {
                return Err(PasskeyError::Config(format!(
                    "a root is in both {} and {}; an Android key root is trusted for every \
                     key it attests, so it cannot also be a per-model allowlist root",
                    config::ENV_ATTESTATION_CA_FILE,
                    config::ENV_ANDROID_KEY_CA_FILE
                )));
            }
        }
        Ok(Self {
            config,
            webauthn,
            allowlist_cas: allowlist,
            android_cas: android,
            android_status_file,
            allow_synced_anchored,
        })
    }

    /// The Android attestation status list as THIS process sees it at `now`,
    /// for the boot log: `None` without the Android roots. It never refuses
    /// anything (a stale list refuses Android enrollments and anchors at use;
    /// boot already refused an unreadable or malformed one). A caller logs a
    /// WARN unless it is [`android::StatusFreshness::Fresh`].
    #[must_use]
    pub fn android_status_report(
        &self,
        now: SystemTime,
    ) -> Option<Result<AndroidStatusReport, String>> {
        let path = self.android_status_file.as_deref()?;
        Some((|| {
            let age = android::age_of(path, now)?;
            let bytes = std::fs::read(path).map_err(|e| {
                format!(
                    "the attestation status list {} cannot be read: {e}",
                    path.display()
                )
            })?;
            let list = android::StatusList::parse(&bytes)
                .map_err(|e| format!("the attestation status list {}: {e}", path.display()))?;
            Ok(AndroidStatusReport {
                path: path.to_path_buf(),
                age,
                entries: list.len(),
                freshness: android::freshness(age),
            })
        })())
    }

    /// Whether this relying party runs the anchored path
    /// ([`Self::start_anchored_registration`]).
    #[must_use]
    pub fn allows_synced_anchored(&self) -> bool {
        self.allow_synced_anchored
    }

    /// The roots a registration is started with: either list (the finish
    /// splices in its own, whatever the state holds). `None`: the software
    /// policy.
    fn start_cas(&self) -> Option<&AttestationCaList> {
        self.allowlist_cas.as_ref().or(self.android_cas.as_ref())
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
    /// attestation, packed or TPM, a hardware-bound key; with the Android key
    /// roots configured, `android-key` is offered too); under the software
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
        let (options, kind, library) = match self.start_cas() {
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
                let mut options =
                    serde_json::to_value(&ccr).map_err(|e| malformed("options", e))?;
                if self.android_cas.is_some() {
                    // A hint to the client (WebAuthn L3 `attestationFormats`):
                    // the library offers packed and TPM only.
                    if let Some(formats) = options
                        .pointer_mut("/publicKey/attestationFormats")
                        .and_then(Value::as_array_mut)
                    {
                        formats.push(Value::from("android-key"));
                    }
                }
                (
                    options,
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
    /// With both the allowlist and the Android key roots, the response is
    /// verified against the allowlist first (today's path, unchanged) and,
    /// only when that refuses it, against the Android roots ALONE. A
    /// registration verified that way is accepted only as a device-bound
    /// `android-key` attestation of a key the attestation places in a TEE or
    /// StrongBox, none of whose certificates is on the attestation status
    /// list (`android_key_rules`): a `packed` or `tpm` certificate chaining
    /// to an Android root is refused, as are a backup-eligible credential and
    /// a software-level key, whatever the stored state allowed.
    ///
    /// # Errors
    /// [`PasskeyError::Refused`] / [`PasskeyError::UserNotVerified`]: the
    /// response does not verify (wrong origin or rp id, bad signature, an
    /// attestation that is not allowlisted, no user verification, ...).
    /// [`PasskeyError::AttestationRefused`]: it verified under an Android
    /// root, and is not a device-bound, hardware-level `android-key`
    /// attestation in good standing.
    /// [`PasskeyError::State`]: the state was not started under this policy.
    pub fn finish_registration(
        &self,
        response: &Value,
        state: &RegistrationState,
    ) -> Result<RegisteredPasskey, PasskeyError> {
        let reg: RegisterPublicKeyCredential =
            serde_json::from_value(response.clone()).map_err(|e| malformed("response", e))?;
        let passkey_json = match self.start_cas() {
            Some(_) => {
                let library = self.library_state(&state.0, KIND_ATTESTED)?;
                let allowlisted = self
                    .allowlist_cas
                    .as_ref()
                    .map(|cas| self.finish_attested_under(&reg, library, cas));
                match (allowlisted, &self.android_cas) {
                    (Some(Ok(pk)), _) => pk,
                    (first, Some(android)) => {
                        match self.finish_attested_under(&reg, library, android) {
                            Ok(pk) => {
                                self.android_key_rules(&pk)?;
                                pk
                            }
                            Err(second) => {
                                return Err(match first {
                                    None => second,
                                    Some(Err(first)) => both_refused(first, second),
                                    Some(Ok(_)) => unreachable!("matched above"),
                                })
                            }
                        }
                    }
                    (Some(Err(e)), None) => return Err(e),
                    (None, None) => unreachable!("start_cas is Some"),
                }
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

    /// Finish an attested registration of `library` (the stored library
    /// state) under `cas`, spliced over the state's own roots.
    fn finish_attested_under(
        &self,
        reg: &RegisterPublicKeyCredential,
        library: &Value,
        cas: &AttestationCaList,
    ) -> Result<Value, PasskeyError> {
        let mut library = library.clone();
        // The roots are ours, not the row's.
        let ours = serde_json::to_value(cas).map_err(|e| malformed("roots", e))?;
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
            .finish_attested_passkey_registration(reg, &st)
            .map_err(|e| refused(&e))?;
        serde_json::to_value(&pk).map_err(|e| malformed("credential", e))
    }

    /// Start registering a LATER passkey on the anchored path: a passkey
    /// registration that ASKS for attestation (`direct`) but needs none (a
    /// synced credential allowed, user verification required), stored as an
    /// `anchored` state. Asking matters: a browser strips the attestation of
    /// a hardware key to `none` when the relying party asks for none, and a
    /// hardware key whose attestation is trusted is recorded attested
    /// ([`Self::finish_anchored_registration`]), so it stands on its own and
    /// is not revoked with its anchor. Synced passkeys answer `none` either
    /// way. No `attestationFormats` hint is given (the attested ceremony's
    /// options carry one).
    ///
    /// The caller takes the anchored path only when [`Self::check_anchor`]
    /// admits the enrollment's [`ActAnchor`] (re-verified there: see
    /// [`ActAnchor`] for who can write those rows);
    /// [`Self::finish_anchored_registration`] checks it again.
    ///
    /// # Errors
    /// [`PasskeyError::Config`]: the anchored path is not enabled; or the
    /// library refused to build the challenge.
    pub fn start_anchored_registration(
        &self,
        user_id: Uuid,
        user_name: &str,
        display_name: &str,
    ) -> Result<(Value, RegistrationState), PasskeyError> {
        if !self.allow_synced_anchored {
            return Err(PasskeyError::Config(format!(
                "the anchored registration is off ({})",
                config::ENV_ALLOW_SYNCED_ANCHORED_PASSKEY
            )));
        }
        let (ccr, state) = self
            .webauthn
            .start_passkey_registration(user_id, user_name, display_name, None)
            .map_err(|e| refused(&e))?;
        let state = serde_json::json!({
            "v": STATE_VERSION,
            "kind": KIND_ANCHORED,
            "library": serde_json::to_value(&state).map_err(|e| malformed("state", e))?,
        });
        let mut options = serde_json::to_value(&ccr).map_err(|e| malformed("options", e))?;
        // The library's passkey options ask for `none`; the finish never
        // reads the preference, so asking for more changes only what the
        // browser passes through.
        match options.pointer_mut("/publicKey/attestation") {
            Some(preference) => *preference = Value::from("direct"),
            None => return Err(PasskeyError::State("no attestation preference".into())),
        }
        Ok((options, RegistrationState(state)))
    }

    /// Finish a registration on the anchored path: `anchor` must admit it
    /// ([`Self::check_anchor`], re-run here) and the state must have been
    /// started as an anchored one. What is recorded depends on the response's
    /// attestation (the library has verified its signature over this
    /// credential, and chained it to nothing):
    ///
    /// * `none` (a synced passkey; a hardware key whose user declined to share
    ///   its model): recorded `none` with the nil AAGUID. It holds only
    ///   through its anchor: [`Self::hardware_attested`] never admits it as an
    ///   anchor, [`Self::check_anchor`] refuses any anchor whose lineage holds
    ///   it, and migration 200's cascade revokes it with its anchor.
    /// * a statement that is hardware-attested under THIS configuration now
    ///   ([`Self::hardware_attested`]: an allowlisted model's chain, or an
    ///   Android key under the Android roots, rules and status list; device
    ///   bound): recorded as attested (its format and model), exactly as the
    ///   attested ceremony would record it. It stands on its own: it is not
    ///   revoked with its anchor, and it may anchor in turn (P779R-3: a backup
    ///   hardware key enrolled with the setting on).
    /// * any other statement (self attestation, an unlisted model, an
    ///   unconfigured root, a synced credential with a statement): its
    ///   attestation is DROPPED and the passkey recorded `none`, as a browser
    ///   would have recorded it had the relying party asked for none (WebAuthn
    ///   lets a relying party treat an untrusted attestation as none). It is
    ///   then the first case. A statement is never recorded unless it is
    ///   trusted here, so it cannot anchor unverified.
    ///
    /// # Errors
    /// [`PasskeyError::Config`] (the path is off), [`PasskeyError::Anchor`],
    /// [`PasskeyError::State`], or the library's refusal (which comes before
    /// any of the above: a statement the library cannot verify at all is
    /// refused, not dropped).
    pub fn finish_anchored_registration(
        &self,
        response: &Value,
        state: &RegistrationState,
        anchor: &ActAnchor,
    ) -> Result<RegisteredPasskey, PasskeyError> {
        if !self.allow_synced_anchored {
            return Err(PasskeyError::Config(format!(
                "the anchored registration is off ({})",
                config::ENV_ALLOW_SYNCED_ANCHORED_PASSKEY
            )));
        }
        self.check_anchor(anchor).map_err(PasskeyError::Anchor)?;
        let library = self.library_state(&state.0, KIND_ANCHORED)?.clone();
        let reg: RegisterPublicKeyCredential =
            serde_json::from_value(response.clone()).map_err(|e| malformed("response", e))?;
        let st: PasskeyRegistration =
            serde_json::from_value(library).map_err(|e| malformed("state", e))?;
        let pk = self
            .webauthn
            .finish_passkey_registration(&reg, &st)
            .map_err(|e| refused(&e))?;
        let registered =
            registered_from(serde_json::to_value(&pk).map_err(|e| malformed("credential", e))?)?;
        if registered.attestation_format == "none" {
            return Ok(registered);
        }
        match self.hardware_attested(
            &registered.passkey,
            &registered.attestation_format,
            registered.aaguid,
            registered.backup_eligible,
        ) {
            Ok(()) => {
                tracing::info!(
                    target: "passkey.anchor",
                    act = %anchor.act_id,
                    format = %registered.attestation_format,
                    aaguid = %registered.aaguid,
                    "an anchored enrollment registered a hardware-attested passkey; it is \
                     recorded attested and stands on its own"
                );
                Ok(registered)
            }
            Err(why) => {
                tracing::info!(
                    target: "passkey.anchor",
                    act = %anchor.act_id,
                    format = %registered.attestation_format,
                    reason = %why,
                    "an anchored enrollment's attestation is not trusted here; it is dropped and \
                     the passkey recorded `none`"
                );
                registered_from(without_attestation(registered.passkey)?)
            }
        }
    }

    /// Whether `anchor` admits an anchored registration: its act is a
    /// CONFIRMED `passkey.register` act of the enrollment's person; its
    /// confirming passkey is that person's, live, and HARDWARE-ATTESTED UNDER
    /// THIS PROCESS'S CONFIGURATION NOW ([`Self::hardware_attested`]: its
    /// stored certificate chain re-verified against today's roots, AAGUID
    /// allowlist, Android security-level rules and status list, never the
    /// columns its registration wrote alone); so is every passkey on its
    /// LINEAGE back to the person's first, maintenance-enrolled passkey
    /// ([`ActAnchor::anchor_lineage`]), so a synced passkey anchors nothing
    /// through any chain of acts; and the confirmation's stored assertion
    /// RE-VERIFIES: made over the act's own challenge
    /// ([`act_challenge`] of the act id, its stored args digest and its
    /// stored nonce, which is also the stored ceremony's), by that passkey's
    /// key, for this relying party, asserting that credential, and not as
    /// backup-eligible. The database cannot verify a signature, so an
    /// application-DSN holder can record a confirmation with fabricated
    /// evidence; that confirmation anchors nothing here.
    ///
    /// # Errors
    /// The first [`AnchorRefusal`] that applies.
    pub fn check_anchor(&self, anchor: &ActAnchor) -> Result<(), AnchorRefusal> {
        if anchor.act_kind != "passkey.register" {
            return Err(AnchorRefusal::NotARegisterAct);
        }
        if anchor.act_outcome.as_deref() != Some("confirmed") {
            return Err(AnchorRefusal::NotConfirmed);
        }
        if anchor.anchor_person != anchor.enrollment_person {
            return Err(AnchorRefusal::PersonMismatch);
        }
        if anchor.anchor_revoked {
            return Err(AnchorRefusal::AnchorRevoked);
        }
        if let Err(why) = self.hardware_attested(
            &anchor.anchor_passkey,
            &anchor.anchor_attestation_format,
            anchor.anchor_aaguid,
            anchor.anchor_backup_eligible,
        ) {
            tracing::warn!(
                target: "passkey.anchor",
                act = %anchor.act_id,
                reason = %why,
                "the act's confirming passkey is not hardware-attested under this configuration"
            );
            return Err(AnchorRefusal::AnchorNotAttested);
        }
        if !anchor.anchor_lineage_complete {
            tracing::warn!(
                target: "passkey.anchor",
                act = %anchor.act_id,
                "the confirming passkey's lineage does not reach a maintenance-enrolled passkey"
            );
            return Err(AnchorRefusal::LineageNotAttested);
        }
        for ancestor in &anchor.anchor_lineage {
            // An ancestor is held to today's roots, allowlist, hardware rules
            // and status list, and to its certificates' validity WHEN IT
            // CONFIRMED the act its successor was enrolled on (P779R-1).
            if let Err(why) = self.hardware_attested_at(
                &ancestor.passkey,
                &ancestor.attestation_format,
                ancestor.aaguid,
                ancestor.backup_eligible,
                CertificateTime::At(ancestor.confirmed_at),
            ) {
                tracing::warn!(
                    target: "passkey.anchor",
                    act = %anchor.act_id,
                    ancestor = %ancestor.passkey_id,
                    reason = %why,
                    "a passkey on the confirming passkey's lineage is not hardware-attested \
                     under this configuration"
                );
                return Err(AnchorRefusal::LineageNotAttested);
            }
        }
        let evidence = anchor
            .assertion_evidence
            .as_ref()
            .ok_or(AnchorRefusal::ChallengeNotBound)?;
        let asserted_over =
            evidence_challenge(evidence).map_err(|_| AnchorRefusal::ChallengeNotBound)?;
        let digest: [u8; 32] = anchor
            .args_digest
            .as_slice()
            .try_into()
            .map_err(|_| AnchorRefusal::ChallengeNotBound)?;
        let stored = anchor
            .act_challenge_state
            .as_ref()
            .ok_or(AnchorRefusal::ChallengeNotBound)?;
        let nonce: [u8; ACT_NONCE_LEN] = stored
            .get("nonce")
            .and_then(Value::as_str)
            .and_then(|n| URL_SAFE_NO_PAD.decode(n).ok())
            .and_then(|n| n.try_into().ok())
            .ok_or(AnchorRefusal::ChallengeNotBound)?;
        let started_with = stored
            .get("ceremony")
            .cloned()
            .map(AuthenticationState::from_json)
            .and_then(|c| c.challenge().ok())
            .ok_or(AnchorRefusal::ChallengeNotBound)?;
        let bound = act_challenge(anchor.act_id, &digest, &nonce);
        if asserted_over != bound.as_slice() || started_with != bound.as_slice() {
            return Err(AnchorRefusal::ChallengeNotBound);
        }
        let snapshot = StoredPasskey {
            passkey: anchor.anchor_passkey.clone(),
            sign_count: 0,
        };
        let asserted = self
            .reverify(evidence, &snapshot)
            .map_err(|_| AnchorRefusal::AssertionDoesNotVerify)?;
        if asserted.credential_id != anchor.anchor_credential_id {
            return Err(AnchorRefusal::CredentialMismatch);
        }
        if asserted.backup_eligible {
            return Err(AnchorRefusal::BackupEligibilityChanged);
        }
        Ok(())
    }

    /// Whether a STORED passkey is hardware-attested under THIS process's
    /// configuration, NOW: device-bound, and its stored attestation (the
    /// certificate chain the library verified at registration, kept in the
    /// credential at `/cred/attestation`) still verifies against the roots
    /// configured today:
    ///
    /// * `packed` / `tpm`: chains to an allowlist root that admits the
    ///   credential's AAGUID (a non-nil one, recorded in the row);
    /// * `android-key`: chains to an Android key root, its KeyDescription
    ///   (the leaf's, and only the leaf's) places the attestation and the key
    ///   in a TEE or StrongBox with `purpose` and `origin` hardware-enforced,
    ///   and no certificate of the chain, root included, is on the status list
    ///   (which must be no older than
    ///   [`android::ANDROID_KEY_STATUS_MAX_AGE`]);
    /// * any other format (`none`, self attestation, ...): never.
    ///
    /// The row's columns (`attestation_format`, `aaguid`, `backup_eligible`)
    /// must agree with the credential they were written from. Certificate
    /// validity periods are checked NOW, as at registration, so an anchor
    /// whose chain has expired anchors nothing ([`Self::hardware_attested_at`]
    /// checks them at another time, for a lineage ancestor).
    ///
    /// For `android-key` the leaf certificate is issued FOR the credential's
    /// key, so the two must be the same key. For `packed` / `tpm` the
    /// certificate is the authenticator model's, and what bound it to this
    /// credential (the attestation signature) is not stored, so that binding
    /// is NOT re-checked here. The API's ceremony checked it when it wrote
    /// the row, but the row has two other writers: the maintenance DSN, and a
    /// holder of the request DSN with a live enrollment id, who can call
    /// 124's `epigraph_complete_passkey_enrollment` directly with a key, a
    /// stored credential and columns of their choosing. Such a holder can
    /// store a genuine, public `packed` / `tpm` model chain beside their own
    /// key, and this check passes it. What that allows, beyond what the
    /// holder can already do (plant any key on that enrollment, which then
    /// elevates as the person): the row anchors later passkeys (on acts it
    /// confirms, each opened by the operator's `passkey-enroll --act`),
    /// counts as hardware on a lineage (its genuine chain also passes the
    /// validity window), and, recorded as non-`none`, is not revoked with its
    /// anchor by migration 200's cascade. An `android-key` row cannot be
    /// planted this way: its leaf must certify the credential's key, which
    /// must then assert. Re-deriving the columns in the database would not
    /// close it (the stored credential is as freely chosen as the columns,
    /// and this check already demands they agree); storing the attestation
    /// statement and re-verifying its signature here would, and is not done.
    ///
    /// # Errors
    /// Why not, in words, for the log.
    pub fn hardware_attested(
        &self,
        passkey: &Value,
        attestation_format: &str,
        aaguid: Uuid,
        backup_eligible: bool,
    ) -> Result<(), String> {
        self.hardware_attested_at(
            passkey,
            attestation_format,
            aaguid,
            backup_eligible,
            CertificateTime::Now,
        )
    }

    /// [`Self::hardware_attested`], with the certificates' validity periods
    /// checked at `at` instead of now. Everything else is checked as of NOW
    /// whatever `at` says: the chain must reach a root configured today (its
    /// signatures verified with the library's own verifier), the AAGUID must
    /// be allowlisted today, the Android hardware rules must hold, and no
    /// certificate may be on today's status list (which must be fresh today).
    ///
    /// [`CertificateTime::At`] is what a LINEAGE ancestor is held to
    /// ([`Passkeys::check_anchor`]): its certificates must have been valid
    /// when it confirmed the act its successor was enrolled on
    /// ([`LineagePasskey::confirmed_at`]). An ancestor whose chain expired
    /// afterwards therefore still counts, and one whose chain had already
    /// expired, or was not yet valid, when it confirmed does not (nor does
    /// anything enrolled on that act). The anchor itself is checked
    /// [`CertificateTime::Now`].
    ///
    /// # Errors
    /// Why not, in words, for the log.
    pub fn hardware_attested_at(
        &self,
        passkey: &Value,
        attestation_format: &str,
        aaguid: Uuid,
        backup_eligible: bool,
        at: CertificateTime,
    ) -> Result<(), String> {
        let cred = passkey
            .get("cred")
            .ok_or_else(|| "the stored credential has no `cred`".to_string())?;
        if backup_eligible || cred.get("backup_eligible").and_then(Value::as_bool) != Some(false) {
            return Err("a backup-eligible (syncable) credential".into());
        }
        let stored_format = cred.get("attestation_format").and_then(Value::as_str);
        if stored_format != Some(attestation_format) {
            return Err(format!(
                "the row's attestation format `{attestation_format}` is not the credential's \
                 ({stored_format:?})"
            ));
        }
        let attestation: ParsedAttestation = cred
            .get("attestation")
            .cloned()
            .ok_or_else(|| "the stored credential holds no attestation".to_string())
            .and_then(|a| {
                serde_json::from_value(a)
                    .map_err(|e| format!("the stored attestation does not parse: {e}"))
            })?;
        match attestation_format {
            "packed" | "tpm" => {
                let model = match &attestation.metadata {
                    AttestationMetadata::Packed { aaguid: m }
                    | AttestationMetadata::Tpm { aaguid: m, .. } => *m,
                    _ => return Err("the stored attestation names no model".into()),
                };
                if aaguid.is_nil() || model != aaguid {
                    return Err(format!(
                        "the row's AAGUID {aaguid} is not the attested model {model}"
                    ));
                }
                let cas = self
                    .allowlist_cas
                    .as_ref()
                    .ok_or_else(|| "no attestation allowlist is configured".to_string())?;
                let ca = verify_attestation_ca_chain(&attestation.data, cas, at.is_past())
                    .map_err(|e| format!("its chain no longer verifies to an allowlist root: {e}"))?
                    .ok_or_else(|| "it carries no certificate chain".to_string())?;
                if !ca.blanket_allow() && !ca.aaguids().contains_key(&aaguid) {
                    return Err(format!("its model {aaguid} is no longer on the allowlist"));
                }
                chain_valid_at(&attestation.data, ca, at)
            }
            "android-key" => self.android_key_trusted(cred, &attestation, at),
            other => Err(format!("a `{other}` attestation is not hardware-attested")),
        }
    }

    /// The Android half of [`Self::hardware_attested`], over a credential
    /// (`cred`, the `{"cred": ...}` object's inside) and its stored
    /// attestation: the leaf certificate's key is the credential's, the chain
    /// reaches an Android key root, the KeyDescription's hardware rules
    /// ([`android::hardware_rules`]) hold, no certificate is on the status
    /// list, and every certificate was valid at `at`.
    fn android_key_trusted(
        &self,
        cred: &Value,
        attestation: &ParsedAttestation,
        at: CertificateTime,
    ) -> Result<(), String> {
        let cas = self
            .android_cas
            .as_ref()
            .ok_or_else(|| "no Android key roots are configured".to_string())?;
        let chain = match &attestation.data {
            ParsedAttestationData::Basic(chain) if !chain.is_empty() => chain,
            _ => {
                return Err("the stored Android key attestation holds no certificate chain".into())
            }
        };
        let key: COSEKey = cred
            .get("cred")
            .cloned()
            .ok_or_else(|| "the stored credential holds no public key".to_string())
            .and_then(|k| {
                serde_json::from_value(k)
                    .map_err(|e| format!("the stored public key does not parse: {e}"))
            })?;
        let certified = COSEKey::try_from((key.type_, &chain[0]))
            .map_err(|e| format!("the leaf certificate's key does not read: {e}"))?;
        if certified != key {
            return Err("the leaf certificate does not attest this credential's key".into());
        }
        let ca = verify_attestation_ca_chain(&attestation.data, cas, at.is_past())
            .map_err(|e| format!("its chain does not verify to an Android key root: {e}"))?
            .ok_or_else(|| "it carries no certificate chain".to_string())?;
        chain_valid_at(&attestation.data, ca, at)?;
        let der = chain
            .iter()
            .map(|c| c.to_der())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("a certificate does not encode: {e}"))?;
        let (mut serials, description) = android::inspect_chain(&der)?;
        android::hardware_rules(&description)?;
        let root = ca
            .ca()
            .to_der()
            .map_err(|e| format!("the root does not encode: {e}"))?;
        let (_, root) = x509_parser::parse_x509_certificate(&root)
            .map_err(|e| format!("the root does not parse: {e}"))?;
        serials.push(root.raw_serial().to_vec());
        let path = self
            .android_status_file
            .as_deref()
            .ok_or_else(|| format!("no {} is configured", config::ENV_ANDROID_KEY_STATUS_FILE))?;
        let list = android::StatusList::load(path, std::time::SystemTime::now())?;
        for serial in &serials {
            if let Some((listed, status)) = list.status_of_serial(serial) {
                return Err(format!(
                    "attestation certificate {listed} is {status} on the attestation status list"
                ));
            }
        }
        Ok(())
    }

    /// The rules for a registration that verified under the Android key
    /// roots (a blanket allow): the `android-key` format with Android key
    /// metadata, a device-bound credential, and [`Self::android_key_trusted`]
    /// (hardware level, status list). User verification is
    /// [`registered_from`]'s, as for every registration.
    fn android_key_rules(&self, passkey: &Value) -> Result<(), PasskeyError> {
        let cred = passkey
            .get("cred")
            .ok_or_else(|| malformed("credential", "no cred"))?;
        let format = cred.get("attestation_format").and_then(Value::as_str);
        let android_metadata = cred
            .pointer("/attestation/metadata/AndroidKey")
            .is_some_and(Value::is_object);
        if format != Some("android-key") || !android_metadata {
            return Err(PasskeyError::AttestationRefused(format!(
                "an Android key root vouches only for the android-key attestation format, and \
                 this is `{}`",
                format.unwrap_or("unknown")
            )));
        }
        if cred.get("backup_eligible").and_then(Value::as_bool) != Some(false) {
            return Err(PasskeyError::AttestationRefused(
                "an Android key attestation is accepted only for a device-bound credential, and \
                 this one is backup-eligible"
                    .into(),
            ));
        }
        let attestation: ParsedAttestation = cred
            .get("attestation")
            .cloned()
            .ok_or_else(|| malformed("credential", "no attestation"))
            .and_then(|a| serde_json::from_value(a).map_err(|e| malformed("attestation", e)))?;
        self.android_key_trusted(cred, &attestation, CertificateTime::Now)
            .map_err(PasskeyError::AttestationRefused)
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

/// A relying party that only RE-VERIFIES stored assertions: the offline
/// confirmation verifier's (`epigraph-operator verify-confirmations`). It is
/// built from the rp id and the origin alone and offers
/// [`Verifier::reverify`] and nothing else, so it can start no ceremony and
/// register nothing (the attestation policy, which only registration reads,
/// is therefore never configured for it).
#[derive(Debug)]
pub struct Verifier(Passkeys);

impl Verifier {
    /// A verifier for `rp`.
    ///
    /// # Errors
    /// [`PasskeyError::Config`]: the origin does not belong to the rp id.
    pub fn new(rp: RelyingParty) -> Result<Self, PasskeyError> {
        Passkeys::new(PasskeyConfig {
            rp_id: rp.rp_id,
            origin: rp.origin,
            // Read only by a registration, which this type cannot start.
            policy: AttestationPolicy::SoftwareAllowed,
        })
        .map(Self)
    }

    /// [`Passkeys::reverify`]: `evidence` against the credential `snapshot`,
    /// this relying party's rp id and origin, and the challenge recorded in
    /// the evidence (the signature counter is not re-checked).
    ///
    /// # Errors
    /// The evidence does not verify, or is malformed.
    pub fn reverify(
        &self,
        evidence: &Value,
        snapshot: &StoredPasskey,
    ) -> Result<Assertion, PasskeyError> {
        self.0.reverify(evidence, snapshot)
    }
}

/// What the anchored path knows of an enrollment's `passkey.register` act and
/// the passkey that confirmed it (migration 200's
/// `epigraph_enrollment_anchor`). Rows written by the API's ceremony, the
/// maintenance DSN, or a request-DSN holder with a live enrollment id, who
/// can call 124's `epigraph_complete_passkey_enrollment` with values of its
/// choosing.
/// So [`Passkeys::check_anchor`] re-verifies the confirmation, and the
/// anchor's and every ancestor's stored attestation against the CURRENT
/// configuration ([`Passkeys::hardware_attested`], which says what it does
/// not re-check).
#[derive(Clone, Debug, PartialEq)]
pub struct ActAnchor {
    /// The act the enrollment was opened on.
    pub act_id: Uuid,
    /// Its kind.
    pub act_kind: String,
    /// Its outcome (`confirmed`, `refused`, or none yet).
    pub act_outcome: Option<String>,
    /// Its stored canonical args digest (32 bytes).
    pub args_digest: Vec<u8>,
    /// Its stored confirmation ceremony (`{"ceremony": ..., "nonce": ...}`).
    pub act_challenge_state: Option<Value>,
    /// Its stored assertion ([`Assertion::evidence`]).
    pub assertion_evidence: Option<Value>,
    /// The person the enrollment registers a passkey for.
    pub enrollment_person: Uuid,
    /// The person whose passkey confirmed the act.
    pub anchor_person: Uuid,
    /// The confirming passkey's credential id.
    pub anchor_credential_id: Vec<u8>,
    /// The confirming passkey's stored credential.
    pub anchor_passkey: Value,
    /// What its registration recorded: the AAGUID, ...
    pub anchor_aaguid: Uuid,
    /// ... the attestation format, ...
    pub anchor_attestation_format: String,
    /// ... and whether it may be synced.
    pub anchor_backup_eligible: bool,
    /// Whether it has been revoked since.
    pub anchor_revoked: bool,
    /// The passkeys that authorized the anchor, nearest first: the passkey
    /// that confirmed the act its own enrollment was opened on, then the one
    /// that confirmed THAT passkey's act, and so on, up to a passkey enrolled
    /// by the maintenance DSN (the person's first). Empty for an anchor that
    /// is itself the first.
    pub anchor_lineage: Vec<LineagePasskey>,
    /// Whether [`Self::anchor_lineage`] reaches a maintenance-enrolled
    /// passkey (the reader stops at a depth bound and reports `false`).
    pub anchor_lineage_complete: bool,
}

/// One passkey on an anchor's lineage ([`ActAnchor::anchor_lineage`]): its
/// stored credential, the columns its registration wrote, and when it
/// confirmed the act its successor was enrolled on.
///
/// A REVOKED passkey stays on the lineage and does not break it by being
/// revoked: it authorized its successor once, and is held to
/// [`Passkeys::hardware_attested_at`] whatever became of it (so a backup key
/// enrolled on an act a lost phone confirmed still anchors after the phone is
/// revoked). What does break the lineage: a root, model or Android rule no
/// longer trusted today, a certificate on today's status list (a REVOKED
/// CERTIFICATE), or a certificate that was not valid at
/// [`Self::confirmed_at`].
#[derive(Clone, Debug, PartialEq)]
pub struct LineagePasskey {
    /// Its id.
    pub passkey_id: Uuid,
    /// Its stored credential.
    pub passkey: Value,
    /// Its recorded AAGUID.
    pub aaguid: Uuid,
    /// Its recorded attestation format.
    pub attestation_format: String,
    /// Its recorded backup-eligible flag.
    pub backup_eligible: bool,
    /// When it confirmed the act its successor on the lineage (the anchor,
    /// for the first entry) was enrolled on: that act's `asserted_at`, which
    /// migration 130's guard sets to the database's `now()` at the assertion.
    /// Its certificates must have been valid then.
    pub confirmed_at: SystemTime,
}

impl LineagePasskey {
    /// The lineage as migration 200's reader returns it (a JSON array of
    /// `{passkey_id, passkey, aaguid, attestation_format, backup_eligible,
    /// confirmed_at_unix}`, the last in whole Unix seconds). `None` when it is
    /// not that shape (the caller then treats the lineage as incomplete).
    #[must_use]
    pub fn list_from_json(v: &Value) -> Option<Vec<Self>> {
        v.as_array()?
            .iter()
            .map(|e| {
                Some(Self {
                    passkey_id: e.get("passkey_id")?.as_str()?.parse().ok()?,
                    passkey: e.get("passkey")?.clone(),
                    aaguid: e.get("aaguid")?.as_str()?.parse().ok()?,
                    attestation_format: e.get("attestation_format")?.as_str()?.to_string(),
                    backup_eligible: e.get("backup_eligible")?.as_bool()?,
                    confirmed_at: UNIX_EPOCH
                        + Duration::from_secs(e.get("confirmed_at_unix")?.as_u64()?),
                })
            })
            .collect()
    }
}

/// Why an [`ActAnchor`] does not admit an anchored registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AnchorRefusal {
    /// The act is not a `passkey.register` act.
    #[error("the enrollment's act is not a passkey.register act")]
    NotARegisterAct,
    /// The act was not confirmed.
    #[error("the enrollment's act was not confirmed")]
    NotConfirmed,
    /// The confirming passkey is another person's.
    #[error("the act was confirmed by another person's passkey")]
    PersonMismatch,
    /// The confirming passkey has been revoked.
    #[error("the passkey that confirmed the act has been revoked")]
    AnchorRevoked,
    /// The confirming passkey is not hardware-attested under the current
    /// configuration.
    #[error(
        "the passkey that confirmed the act is not hardware-attested under the current \
         configuration (a synced or unattested passkey anchors nothing)"
    )]
    AnchorNotAttested,
    /// A passkey that authorized the confirming passkey is not
    /// hardware-attested under the current configuration, or the lineage does
    /// not reach the person's first passkey.
    #[error(
        "a passkey on the confirming passkey's lineage is not hardware-attested under the \
         current configuration (a synced passkey anchors nothing, through any chain of acts)"
    )]
    LineageNotAttested,
    /// The stored assertion was not made over the act's own challenge.
    #[error("the act's recorded confirmation is not over the act's own challenge")]
    ChallengeNotBound,
    /// The stored assertion does not verify against the confirming passkey.
    #[error("the act's recorded confirmation does not verify against the confirming passkey")]
    AssertionDoesNotVerify,
    /// The stored assertion is by another credential.
    #[error("the act's recorded confirmation asserts another credential")]
    CredentialMismatch,
    /// The stored assertion is backup-eligible, by a device-bound passkey.
    #[error("the act's recorded confirmation asserted a backup-eligible credential")]
    BackupEligibilityChanged,
}

impl AnchorRefusal {
    /// A stable snake_case code for logs and responses.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotARegisterAct => "not_a_register_act",
            Self::NotConfirmed => "act_not_confirmed",
            Self::PersonMismatch => "person_mismatch",
            Self::AnchorRevoked => "anchor_revoked",
            Self::AnchorNotAttested => "anchor_not_attested",
            Self::LineageNotAttested => "lineage_not_attested",
            Self::ChallengeNotBound => "challenge_not_bound",
            Self::AssertionDoesNotVerify => "assertion_does_not_verify",
            Self::CredentialMismatch => "credential_mismatch",
            Self::BackupEligibilityChanged => "backup_eligibility_changed",
        }
    }
}

/// Both attested attempts refused: the allowlist's reason and the Android
/// roots'. A reason that is not the library's (user verification, the
/// state) is reported alone, as it would be without the Android roots.
fn both_refused(allowlist: PasskeyError, android: PasskeyError) -> PasskeyError {
    match (allowlist, android) {
        (PasskeyError::Refused(a), PasskeyError::Refused(b)) => PasskeyError::Refused(format!(
            "attestation allowlist: {a}; Android key roots: {b}"
        )),
        (PasskeyError::Refused(_), other) | (other, _) => other,
    }
}

/// The Android attestation status list at boot
/// ([`Passkeys::android_status_report`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AndroidStatusReport {
    /// [`config::ENV_ANDROID_KEY_STATUS_FILE`].
    pub path: PathBuf,
    /// Its age, by modification time.
    pub age: Duration,
    /// How many serials it lists.
    pub entries: usize,
    /// How that age stands: past 24 hours AGING (log a WARN), past 48 STALE
    /// (Android enrollments and anchors are refused).
    pub freshness: android::StatusFreshness,
}

/// When a stored attestation's certificates must have been valid
/// ([`Passkeys::hardware_attested_at`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateTime {
    /// Now: an anchor, and a registration.
    Now,
    /// At this time: a lineage ancestor, at the moment it confirmed the act
    /// its successor was enrolled on ([`LineagePasskey::confirmed_at`]).
    At(SystemTime),
}

impl CertificateTime {
    /// Whether the time is not now, so the library's own time check (which
    /// knows only now) is off and [`chain_valid_at`] is the window check.
    fn is_past(self) -> bool {
        matches!(self, Self::At(_))
    }
}

/// Every certificate of a stored chain (`data`, leaf first) and the root it
/// verified to (`root`) was valid at `at`: notBefore <= `at` <= notAfter, to
/// the second. For [`CertificateTime::Now`] the library has checked this
/// already, and it is checked again here.
fn chain_valid_at(
    data: &ParsedAttestationData,
    root: &AttestationCa,
    at: CertificateTime,
) -> Result<(), String> {
    let when = match at {
        CertificateTime::Now => SystemTime::now(),
        CertificateTime::At(t) => t,
    };
    let secs = when
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .ok_or_else(|| "the validity time is before 1970".to_string())?;
    let chain = match data {
        ParsedAttestationData::Basic(c)
        | ParsedAttestationData::AttCa(c)
        | ParsedAttestationData::AnonCa(c) => c,
        _ => return Err("it carries no certificate chain".into()),
    };
    let mut der = chain
        .iter()
        .map(|c| c.to_der())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("a certificate does not encode: {e}"))?;
    der.push(
        root.ca()
            .to_der()
            .map_err(|e| format!("the root does not encode: {e}"))?,
    );
    let last = der.len() - 1;
    for (index, cert) in der.iter().enumerate() {
        let (_, cert) = x509_parser::parse_x509_certificate(cert)
            .map_err(|e| format!("attestation certificate {index} does not parse: {e}"))?;
        let validity = cert.validity();
        let (from, to) = (
            validity.not_before.timestamp(),
            validity.not_after.timestamp(),
        );
        if secs < from || secs > to {
            let which = if index == last {
                "the root".to_string()
            } else {
                format!("attestation certificate {index}")
            };
            return Err(format!(
                "{which} was not valid at {secs} (Unix seconds; valid {from}..={to}){}",
                if at.is_past() {
                    ", when this passkey confirmed its successor's act"
                } else {
                    ""
                }
            ));
        }
    }
    Ok(())
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

/// A library-serialized credential (`{"cred": {...}}`) with its attestation
/// dropped: the attestation, its metadata and its format replaced by what the
/// library records for a `none` registration. The key, credential id,
/// counter, flags and everything else are untouched.
fn without_attestation(mut passkey: Value) -> Result<Value, PasskeyError> {
    let cred = passkey
        .get_mut("cred")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| malformed("credential", "no cred"))?;
    cred.insert(
        "attestation".into(),
        serde_json::json!({"data": "None", "metadata": "None"}),
    );
    cred.insert("attestation_format".into(), Value::from("none"));
    // Still a credential the library reads (it is asserted with later).
    serde_json::from_value::<Passkey>(passkey.clone())
        .map_err(|e| malformed("credential without its attestation", e))?;
    Ok(passkey)
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
