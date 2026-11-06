//! A software WebAuthn client and authenticator for tests, written from the
//! WebAuthn Level 3 and CTAP 2.1 specifications, and the attestation
//! statements an allowlist relying party needs.
//!
//! # Why hand-written, not a library
//!
//! It is INDEPENDENT of the code under test: nothing here shares a type or an
//! encoder with `webauthn-rs`, so a test that registers or asserts with it
//! checks the relying party against the specification rather than the library
//! agreeing with itself (a happy path through `webauthn-rs` is what proves this
//! file's encodings right).
//!
//! The elevation plan named 1Password's `passkey-client` /
//! `passkey-authenticator` for this. They cannot be a dependency of this
//! workspace at all, not even a dev-dependency: every `passkey-types` release
//! (0.3 to 0.6, measured) enables `serde_json/preserve_order`, and resolver 2
//! unifies dev-dependency features into the library whenever tests or
//! `--all-targets` are built. Every `cargo test` and `clippy --all-targets`
//! would then compile the server with insertion-ordered JSON maps while the
//! deployed binary sorts them, a test/production divergence in exactly the
//! serialization later batches hash and sign.
//!
//! # What it emits (WebAuthn §6.1, §6.5, §8.2, §8.7; CTAP2 §6.5.1)
//!
//! * An ES256 credential: a P-256 key, its COSE form
//!   `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.
//! * `authenticatorData` = SHA-256(rp id) ‖ flags (UP 0x01, UV 0x04, BE 0x08,
//!   BS 0x10, AT 0x40) ‖ signCount (u32 BE) ‖ [aaguid ‖ credIdLen (u16 BE) ‖
//!   credId ‖ COSE key].
//! * `clientDataJSON` `{"type", "challenge", "origin", "crossOrigin"}`, the
//!   challenge copied verbatim from the options.
//! * Attestation `none`, `packed` self attestation (signed by the credential
//!   key), `packed` with an `x5c` from a [`TestAttestation`] root, or
//!   `android-key` (WebAuthn §8.4): a certificate FOR THE CREDENTIAL KEY,
//!   issued by a [`TestAttestation`] root and carrying the Android key
//!   attestation extension, the statement signed by the credential key.
//! * Assertions: a DER ECDSA signature over `authenticatorData ‖
//!   SHA-256(clientDataJSON)`.
//!
//! By default it models a SYNCED passkey (BE and BS set, no signature counter),
//! as platform passkeys are; [`SoftAuthenticator::hardware`] models a hardware
//! key (BE and BS clear), [`SoftAuthenticator::counting`] one that keeps a
//! signature counter.
//!
//! Shared by `epigraph-passkey`'s and `epigraph-api`'s tests through
//! `#[path]`, so it is never part of a normal build.

#![allow(dead_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ciborium::Value as Cbor;
use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::{BigNum, BigNumContext, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder, X509};
use serde_json::{json, Value};
use uuid::Uuid;

/// The relying party every test configures: a reserved example domain
/// (RFC 2606), so no real host is named.
pub const RP_ID: &str = "auth.example.com";
/// The origin every test configures.
pub const ORIGIN: &str = "https://auth.example.com";

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;

/// Which user-verification request the CLIENT forwards to the authenticator.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ClientUv {
    /// As the relying party asked (an honest client).
    AsRequested,
    /// Not performed, whatever the relying party asked: a client (or a
    /// hostile page script) that skips user verification. The authenticator
    /// reports UV = 0.
    Skip,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(v: &Value, what: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(
            v.as_str()
                .unwrap_or_else(|| panic!("{what} is not a string: {v}")),
        )
        .unwrap_or_else(|e| panic!("{what}: {e}"))
}

fn sha256(data: &[u8]) -> Vec<u8> {
    openssl::sha::sha256(data).to_vec()
}

fn sign(key: &PKey<Private>, data: &[u8]) -> Vec<u8> {
    let mut signer = Signer::new(MessageDigest::sha256(), key).expect("signer");
    signer.update(data).expect("update");
    signer.sign_to_vec().expect("sign")
}

fn p256() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256");
    PKey::from_ec_key(EcKey::generate(&group).expect("key")).expect("pkey")
}

/// A CREDENTIAL key: P-256 with both affine coordinates a full 32 bytes (no
/// leading zero byte). `webauthn-rs-core` 0.5.5 reads the public key out of an
/// `android-key` attestation certificate with `COSEKey::try_from((alg,
/// &X509))`, which refuses a coordinate whose `num_bytes()` is not 32
/// ("The COSEKey contains invalid ECDSA X/Y coordinate data"): about one
/// genuine key in 64. That is the library's behaviour (a real device that hits
/// it registers on a retry, with a new key); a test that drew such a key would
/// fail at random, so the test authenticator never does.
fn credential_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256");
    loop {
        let key = EcKey::generate(&group).expect("key");
        let mut ctx = BigNumContext::new().expect("ctx");
        let mut x = BigNum::new().expect("x");
        let mut y = BigNum::new().expect("y");
        key.public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
            .expect("coordinates");
        if x.num_bytes() == 32 && y.num_bytes() == 32 {
            return PKey::from_ec_key(key).expect("pkey");
        }
    }
}

fn cbor(v: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).expect("CBOR");
    out
}

fn text(s: &str) -> Cbor {
    Cbor::Text(s.into())
}

/// The COSE_Key (RFC 9053 §7.1.1) of `key`'s public half: EC2, ES256, P-256.
fn cose_key(key: &PKey<Private>) -> Vec<u8> {
    let ec = key.ec_key().expect("ec");
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256");
    let mut ctx = BigNumContext::new().expect("ctx");
    let mut x = BigNum::new().expect("x");
    let mut y = BigNum::new().expect("y");
    ec.public_key()
        .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
        .expect("coordinates");
    cbor(&Cbor::Map(vec![
        (Cbor::Integer(1.into()), Cbor::Integer(2.into())),
        (Cbor::Integer(3.into()), Cbor::Integer((-7).into())),
        (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),
        (
            Cbor::Integer((-2).into()),
            Cbor::Bytes(x.to_vec_padded(32).expect("x")),
        ),
        (
            Cbor::Integer((-3).into()),
            Cbor::Bytes(y.to_vec_padded(32).expect("y")),
        ),
    ]))
}

/// The authenticator data of `attestationObject` (base64url), decoded.
fn auth_data_of(registration: &Value) -> Vec<u8> {
    let att_obj = unb64(
        &registration["response"]["attestationObject"],
        "attestationObject",
    );
    let parsed: Cbor = ciborium::de::from_reader(att_obj.as_slice()).expect("attestation CBOR");
    parsed
        .as_map()
        .and_then(|m| {
            m.iter()
                .find_map(|(k, v)| (k.as_text() == Some("authData")).then(|| v.as_bytes().cloned()))
        })
        .flatten()
        .expect("authData")
}

/// `registration` with its attestation object replaced by
/// `{fmt, attStmt, authData}`.
fn with_attestation(registration: &Value, fmt: &str, att_stmt: Cbor, auth_data: Vec<u8>) -> Value {
    let obj = Cbor::Map(vec![
        (text("fmt"), text(fmt)),
        (text("attStmt"), att_stmt),
        (text("authData"), Cbor::Bytes(auth_data)),
    ]);
    let mut out = registration.clone();
    out["response"]["attestationObject"] = Value::from(b64(&cbor(&obj)));
    out
}

/// The flags byte of authenticator data follows the 32-byte rp id hash.
const FLAGS_AT: usize = 32;

struct Credential {
    id: Vec<u8>,
    key: PKey<Private>,
    rp_id: String,
    user_handle: Vec<u8>,
    synced: bool,
}

/// A software authenticator behind a minimal WebAuthn client.
pub struct SoftAuthenticator {
    aaguid: Uuid,
    synced: bool,
    not_backed_up: bool,
    counting: bool,
    counter: u32,
    credentials: Vec<Credential>,
}

/// Whether `rp_id` may be asserted from `host` (WebAuthn §5.1.3 step 8: the rp
/// id is the origin's effective domain or a registrable suffix of it).
fn rp_id_allowed(host: &str, rp_id: &str) -> bool {
    host == rp_id || host.ends_with(&format!(".{rp_id}"))
}

fn host_of(origin: &str) -> String {
    url::Url::parse(origin)
        .expect("origin")
        .host_str()
        .expect("host")
        .to_string()
}

/// `origin` as it appears in client data: scheme://host[:port], no slash.
fn serialized_origin(origin: &str) -> String {
    url::Url::parse(origin)
        .expect("origin")
        .origin()
        .ascii_serialization()
}

impl SoftAuthenticator {
    /// A synced passkey provider of model `aaguid`: BE and BS set, no
    /// signature counter.
    #[must_use]
    pub fn new(aaguid: Uuid) -> Self {
        Self {
            aaguid,
            synced: true,
            not_backed_up: false,
            counting: false,
            counter: 0,
            credentials: Vec::new(),
        }
    }

    /// A hardware key instead: BE and BS clear.
    #[must_use]
    pub fn hardware(mut self) -> Self {
        self.synced = false;
        self
    }

    /// Backup-ELIGIBLE but not (yet) backed up: BE set, BS clear. The one
    /// flag combination that lets a credential registered device-bound
    /// "upgrade" to backup-eligible past webauthn-rs's passkey path (BS on a
    /// non-eligible credential it refuses itself).
    #[must_use]
    pub fn eligible_not_backed_up(mut self) -> Self {
        self.not_backed_up = true;
        self
    }

    /// Keep a signature counter, incremented by every assertion.
    #[must_use]
    pub fn counting(mut self) -> Self {
        self.counting = true;
        self
    }

    /// Set the signature counter (a cloned authenticator replays an old one).
    pub fn set_counter(&mut self, counter: u32) {
        self.counter = counter;
    }

    /// `options` (a relying party's `{"publicKey": ...}` creation options)
    /// with `rp.id` replaced, as a hostile page would hand the client.
    #[must_use]
    pub fn with_rp_id(mut options: Value, rp_id: &str) -> Value {
        options["publicKey"]["rp"]["id"] = Value::from(rp_id);
        options
    }

    fn flags(&self, synced: bool, uv: bool) -> u8 {
        let mut f = UP;
        if uv {
            f |= UV;
        }
        if synced {
            f |= BE;
            if !self.not_backed_up {
                f |= BS;
            }
        }
        f
    }

    /// Create a credential from `origin` for `options`, with `none`
    /// attestation. Returns the `PublicKeyCredential` JSON a browser page
    /// posts back.
    pub async fn register(&mut self, origin: &str, options: Value, uv: ClientUv) -> Value {
        let pk = &options["publicKey"];
        let host = host_of(origin);
        let rp_id = pk["rp"]["id"].as_str().map_or(host.clone(), str::to_string);
        assert!(
            rp_id_allowed(&host, &rp_id),
            "a client refuses rp id {rp_id} from {origin}"
        );
        assert!(
            pk["pubKeyCredParams"]
                .as_array()
                .is_some_and(|p| p.iter().any(|a| a["alg"] == -7)),
            "the relying party does not offer ES256: {pk}"
        );
        let uv = match uv {
            ClientUv::Skip => false,
            ClientUv::AsRequested => matches!(
                pk["authenticatorSelection"]["userVerification"].as_str(),
                Some("required" | "preferred") | None
            ),
        };
        let challenge = pk["challenge"].as_str().expect("challenge").to_string();
        let user_handle = unb64(&pk["user"]["id"], "user.id");
        let client_data = serde_json::to_vec(&json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": serialized_origin(origin),
            "crossOrigin": false,
        }))
        .expect("client data");

        let key = credential_key();
        let mut id = vec![0_u8; 32];
        openssl::rand::rand_bytes(&mut id).expect("rand");
        let mut auth_data = sha256(rp_id.as_bytes());
        auth_data.push(self.flags(self.synced, uv) | AT);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        auth_data.extend_from_slice(self.aaguid.as_bytes());
        auth_data.extend_from_slice(&u16::try_from(id.len()).expect("len").to_be_bytes());
        auth_data.extend_from_slice(&id);
        auth_data.extend_from_slice(&cose_key(&key));

        self.credentials.push(Credential {
            id: id.clone(),
            key,
            rp_id,
            user_handle,
            synced: self.synced,
        });
        let registration = json!({
            "id": b64(&id),
            "rawId": b64(&id),
            "type": "public-key",
            "response": {
                "attestationObject": "",
                "clientDataJSON": b64(&client_data),
            },
            "extensions": {},
        });
        with_attestation(&registration, "none", Cbor::Map(vec![]), auth_data)
    }

    /// `registration` (made by this authenticator) re-made with `packed` SELF
    /// attestation: no certificate, signed by the credential key itself.
    #[must_use]
    pub fn self_attest(&self, registration: &Value) -> Value {
        let id = unb64(&registration["rawId"], "rawId");
        let cred = self
            .credentials
            .iter()
            .find(|c| c.id == id)
            .expect("a credential of this authenticator");
        let auth_data = auth_data_of(registration);
        let cdj = unb64(
            &registration["response"]["clientDataJSON"],
            "clientDataJSON",
        );
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&sha256(&cdj));
        let stmt = Cbor::Map(vec![
            (text("alg"), Cbor::Integer((-7).into())),
            (text("sig"), Cbor::Bytes(sign(&cred.key, &signed))),
        ]);
        with_attestation(registration, "packed", stmt, auth_data)
    }

    /// The private key of the credential `registration` (made by this
    /// authenticator) registered.
    fn key_of(&self, registration: &Value) -> &PKey<Private> {
        let id = unb64(&registration["rawId"], "rawId");
        &self
            .credentials
            .iter()
            .find(|c| c.id == id)
            .expect("a credential of this authenticator")
            .key
    }

    /// Assert with a credential of this authenticator from `origin`, for
    /// `options` (`{"publicKey": ...}` request options; user verification as
    /// the options ask).
    pub async fn authenticate(&mut self, origin: &str, options: Value) -> Value {
        let pk = &options["publicKey"];
        let host = host_of(origin);
        let rp_id = pk["rpId"].as_str().map_or(host.clone(), str::to_string);
        assert!(
            rp_id_allowed(&host, &rp_id),
            "a client refuses rp id {rp_id} from {origin}"
        );
        let allowed: Vec<Vec<u8>> = pk["allowCredentials"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|c| unb64(&c["id"], "allowCredentials.id"))
                    .collect()
            })
            .unwrap_or_default();
        let uv = matches!(
            pk["userVerification"].as_str(),
            Some("required" | "preferred") | None
        );
        if self.counting {
            self.counter += 1;
        }
        let counter = self.counter;
        let cred = self
            .credentials
            .iter()
            .find(|c| c.rp_id == rp_id && (allowed.is_empty() || allowed.contains(&c.id)))
            .expect("no credential of this authenticator is allowed");
        let client_data = serde_json::to_vec(&json!({
            "type": "webauthn.get",
            "challenge": pk["challenge"].as_str().expect("challenge"),
            "origin": serialized_origin(origin),
            "crossOrigin": false,
        }))
        .expect("client data");
        let mut auth_data = sha256(rp_id.as_bytes());
        auth_data.push(self.flags(cred.synced, uv));
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&sha256(&client_data));
        json!({
            "id": b64(&cred.id),
            "rawId": b64(&cred.id),
            "type": "public-key",
            "response": {
                "authenticatorData": b64(&auth_data),
                "clientDataJSON": b64(&client_data),
                "signature": b64(&sign(&cred.key, &signed)),
                "userHandle": b64(&cred.user_handle),
            },
            "extensions": {},
        })
    }
}

/// `registration` (a `none`-attestation response) as a HARDWARE-bound key
/// would make it: the backup-eligible and backed-up flags cleared. A `none`
/// attestation signs nothing at registration, so the flags can change without
/// re-signing. Used where a test must show a refusal is about the attestation,
/// not about a synced credential (which the allowlist refuses as well).
#[must_use]
pub fn hardware_bound(registration: &Value) -> Value {
    let mut auth_data = auth_data_of(registration);
    auth_data[FLAGS_AT] &= !(BE | BS);
    with_attestation(registration, "none", Cbor::Map(vec![]), auth_data)
}

/// A test attestation root and an attestation certificate it issued.
pub struct TestAttestation {
    root: X509,
    root_key: PKey<Private>,
    leaf: X509,
    leaf_key: PKey<Private>,
}

/// One DER TLV: `tag` (its identifier octets, already encoded) and `content`,
/// with a definite length (X.690 §8.1.3).
fn der(tag: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).expect("short length"));
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).expect("length of length"));
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

/// What an `android-key` statement's certificates say ([`TestAttestation::android_key_with`]).
/// The default is a genuine TEE key: both security levels 1 (TEE), `purpose`
/// and `origin` in the TEE-enforced list, the leaf issued by the root
/// directly, random serials.
#[derive(Clone, Debug)]
pub struct AndroidKeyOpts {
    /// `attestationSecurityLevel`: 0 Software, 1 TrustedEnvironment,
    /// 2 StrongBox.
    pub attestation_level: u8,
    /// `keyMintSecurityLevel` (`keymasterSecurityLevel`), same values.
    pub keymaster_level: u8,
    /// `purpose` and `origin` in the SOFTWARE-enforced list instead of the
    /// TEE-enforced one.
    pub in_software_list: bool,
    /// The leaf issued by an intermediate (a batch certificate) that the root
    /// issued, with both in `x5c`, as a real device's chain is.
    pub intermediate: bool,
    /// The intermediate carries a KeyDescription too (an attacker extending a
    /// genuine chain with a certificate of their own; only the first
    /// occurrence counts, and this crate refuses a second one).
    pub key_description_on_intermediate: bool,
    /// The leaf's serial number (big-endian magnitude); random when `None`.
    pub leaf_serial: Option<Vec<u8>>,
    /// The intermediate's serial number; random when `None`.
    pub intermediate_serial: Option<Vec<u8>>,
    /// The leaf's validity, (notBefore, notAfter) in Unix seconds; from
    /// yesterday for a year when `None`.
    pub leaf_validity: Option<(i64, i64)>,
}

impl Default for AndroidKeyOpts {
    fn default() -> Self {
        Self {
            attestation_level: 1,
            keymaster_level: 1,
            in_software_list: false,
            intermediate: false,
            key_description_on_intermediate: false,
            leaf_serial: None,
            intermediate_serial: None,
            leaf_validity: None,
        }
    }
}

/// The Android key attestation extension's value (`KeyDescription`, Android
/// Keystore schema), as `webauthn-rs-core` 0.5.5 parses it: version 3, the
/// attestation and keymaster security levels of `opts`, the attestation
/// challenge, an empty unique id, and the two authorization lists, one empty
/// and one holding `purpose` [1] = {SIGN (2)} and `origin` [702] =
/// GENERATED (0) (the TEE-enforced one unless `opts.in_software_list`), with
/// no `allApplications` [600] (WebAuthn §8.4.1: the key is scoped to the RP
/// id).
fn android_key_description(challenge: &[u8], opts: &AndroidKeyOpts) -> Vec<u8> {
    let enforced = [
        // [1] EXPLICIT SET OF INTEGER { 2 }
        der(&[0xA1], &der(&[0x31], &der(&[0x02], &[0x02]))),
        // [702] EXPLICIT INTEGER 0: high tag number form, 702 = 5 * 128 + 62.
        der(&[0xBF, 0x85, 0x3E], &der(&[0x02], &[0x00])),
    ]
    .concat();
    let (software, tee) = if opts.in_software_list {
        (der(&[0x30], &enforced), der(&[0x30], &[]))
    } else {
        (der(&[0x30], &[]), der(&[0x30], &enforced))
    };
    der(
        &[0x30],
        &[
            der(&[0x02], &[0x03]),
            der(&[0x0A], &[opts.attestation_level]),
            der(&[0x02], &[0x04]),
            der(&[0x0A], &[opts.keymaster_level]),
            der(&[0x04], challenge),
            der(&[0x04], &[]),
            software,
            tee,
        ]
        .concat(),
    )
}

/// A serial number: `fixed` (big-endian magnitude), or 64 random bits.
fn serial_of(fixed: Option<&[u8]>) -> openssl::asn1::Asn1Integer {
    match fixed {
        Some(bytes) => BigNum::from_slice(bytes)
            .expect("bn")
            .to_asn1_integer()
            .expect("serial"),
        None => serial(),
    }
}

fn serial() -> openssl::asn1::Asn1Integer {
    let mut bn = BigNum::new().expect("bn");
    bn.rand(64, MsbOption::MAYBE_ZERO, false).expect("rand");
    bn.to_asn1_integer().expect("serial")
}

impl TestAttestation {
    /// A fresh root and attestation certificate (§8.2.1: version 3; subject C,
    /// O, OU = "Authenticator Attestation", CN; `CA:FALSE`), valid from
    /// yesterday for a year: the library checks the window.
    #[must_use]
    pub fn new(vendor: &str) -> Self {
        let root_key = p256();
        let mut name = X509NameBuilder::new().expect("name");
        name.append_entry_by_text("CN", &format!("{vendor} Test Attestation Root"))
            .expect("cn");
        let root_name = name.build();
        let mut b = X509Builder::new().expect("builder");
        b.set_version(2).expect("v3");
        b.set_serial_number(&serial()).expect("serial");
        b.set_subject_name(&root_name).expect("subject");
        b.set_issuer_name(&root_name).expect("issuer");
        b.set_pubkey(&root_key).expect("pubkey");
        // Valid from a year ago: a test may hold a lineage passkey's chain to
        // its validity at a past confirmation time, which the root must cover.
        b.set_not_before(&Asn1Time::from_unix(now_unix() - ROOT_AGE).expect("t"))
            .expect("nb");
        b.set_not_after(&Asn1Time::days_from_now(365).expect("t"))
            .expect("na");
        b.append_extension(BasicConstraints::new().critical().ca().build().expect("bc"))
            .expect("bc");
        b.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .expect("ku"),
        )
        .expect("ku");
        b.sign(&root_key, MessageDigest::sha256())
            .expect("sign root");
        let root = b.build();

        let leaf_key = p256();
        let mut name = X509NameBuilder::new().expect("name");
        name.append_entry_by_text("C", "US").expect("c");
        name.append_entry_by_text("O", vendor).expect("o");
        name.append_entry_by_text("OU", "Authenticator Attestation")
            .expect("ou");
        name.append_entry_by_text("CN", &format!("{vendor} Test Authenticator"))
            .expect("cn");
        let leaf_name = name.build();
        let mut b = X509Builder::new().expect("builder");
        b.set_version(2).expect("v3");
        b.set_serial_number(&serial()).expect("serial");
        b.set_subject_name(&leaf_name).expect("subject");
        b.set_issuer_name(root.subject_name()).expect("issuer");
        b.set_pubkey(&leaf_key).expect("pubkey");
        b.set_not_before(&Asn1Time::from_unix(now_unix() - 86_400).expect("t"))
            .expect("nb");
        b.set_not_after(&Asn1Time::days_from_now(365).expect("t"))
            .expect("na");
        b.append_extension(BasicConstraints::new().critical().build().expect("bc"))
            .expect("bc");
        b.sign(&root_key, MessageDigest::sha256())
            .expect("sign leaf");
        Self {
            root,
            root_key,
            leaf: b.build(),
            leaf_key,
        }
    }

    /// `registration` (made by `auth`) re-made as an `android-key`
    /// attestation chained to THIS root (WebAuthn §8.4): the certificate in
    /// `x5c` is issued for the CREDENTIAL's public key and carries the
    /// Android key attestation extension (OID 1.3.6.1.4.1.11129.2.1.17)
    /// whose challenge is SHA-256(clientDataJSON); the statement is signed by
    /// the credential key. `device_bound` clears BE and BS before signing (a
    /// hardware-backed Android key); otherwise the flags stay as `auth` set
    /// them (a backup-eligible credential, which the relying party must
    /// refuse). A genuine TEE key: [`Self::android_key_with`] with the
    /// default [`AndroidKeyOpts`].
    #[must_use]
    pub fn android_key(
        &self,
        auth: &SoftAuthenticator,
        registration: &Value,
        device_bound: bool,
    ) -> Value {
        self.android_key_with(auth, registration, device_bound, &AndroidKeyOpts::default())
    }

    /// [`Self::android_key`], with the certificates `opts` describes.
    #[must_use]
    pub fn android_key_with(
        &self,
        auth: &SoftAuthenticator,
        registration: &Value,
        device_bound: bool,
        opts: &AndroidKeyOpts,
    ) -> Value {
        let cred_key = auth.key_of(registration);
        let mut auth_data = auth_data_of(registration);
        if device_bound {
            auth_data[FLAGS_AT] &= !(BE | BS);
        }
        let cdj = unb64(
            &registration["response"]["clientDataJSON"],
            "clientDataJSON",
        );
        let client_data_hash = sha256(&cdj);
        let x5c = self
            .android_chain(cred_key, &client_data_hash, opts)
            .iter()
            .map(|c| Cbor::Bytes(c.to_der().expect("der")))
            .collect();
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_data_hash);
        let stmt = Cbor::Map(vec![
            (text("alg"), Cbor::Integer((-7).into())),
            (text("sig"), Cbor::Bytes(sign(cred_key, &signed))),
            (text("x5c"), Cbor::Array(x5c)),
        ]);
        with_attestation(registration, "android-key", stmt, auth_data)
    }

    /// The `x5c` chain [`Self::android_key_with`] builds (leaf first, then
    /// the intermediate when `opts` asks for one) for the credential key
    /// `cred_key`, its KeyDescription's challenge `client_data_hash`.
    fn android_chain(
        &self,
        cred_key: &PKey<Private>,
        client_data_hash: &[u8],
        opts: &AndroidKeyOpts,
    ) -> Vec<X509> {
        let key_description = android_key_description(client_data_hash, opts);
        let oid = Asn1Object::from_str("1.3.6.1.4.1.11129.2.1.17").expect("oid");

        // The issuer of the leaf: the root, or an intermediate the root
        // issued (a batch attestation certificate).
        let intermediate = opts.intermediate.then(|| {
            let key = p256();
            let mut name = X509NameBuilder::new().expect("name");
            name.append_entry_by_text("CN", "Android Keystore Batch")
                .expect("cn");
            let name = name.build();
            let mut b = X509Builder::new().expect("builder");
            b.set_version(2).expect("v3");
            b.set_serial_number(&serial_of(opts.intermediate_serial.as_deref()))
                .expect("serial");
            b.set_subject_name(&name).expect("subject");
            b.set_issuer_name(self.root.subject_name()).expect("issuer");
            b.set_pubkey(&key).expect("pubkey");
            b.set_not_before(&Asn1Time::from_unix(now_unix() - 86_400).expect("t"))
                .expect("nb");
            b.set_not_after(&Asn1Time::days_from_now(365).expect("t"))
                .expect("na");
            b.append_extension(BasicConstraints::new().critical().ca().build().expect("bc"))
                .expect("bc");
            b.append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .build()
                    .expect("ku"),
            )
            .expect("ku");
            if opts.key_description_on_intermediate {
                let value = Asn1OctetString::new_from_bytes(&key_description).expect("octets");
                b.append_extension(X509Extension::new_from_der(&oid, false, &value).expect("ext"))
                    .expect("android key extension");
            }
            b.sign(&self.root_key, MessageDigest::sha256())
                .expect("sign intermediate");
            (b.build(), key)
        });

        let mut name = X509NameBuilder::new().expect("name");
        name.append_entry_by_text("CN", "Android Keystore Key")
            .expect("cn");
        let leaf_name = name.build();
        let mut b = X509Builder::new().expect("builder");
        b.set_version(2).expect("v3");
        b.set_serial_number(&serial_of(opts.leaf_serial.as_deref()))
            .expect("serial");
        b.set_subject_name(&leaf_name).expect("subject");
        match &intermediate {
            Some((cert, _)) => b.set_issuer_name(cert.subject_name()).expect("issuer"),
            None => b.set_issuer_name(self.root.subject_name()).expect("issuer"),
        }
        b.set_pubkey(cred_key).expect("pubkey");
        let (not_before, not_after) = opts
            .leaf_validity
            .unwrap_or((now_unix() - 86_400, now_unix() + 365 * 86_400));
        b.set_not_before(&Asn1Time::from_unix(not_before).expect("t"))
            .expect("nb");
        b.set_not_after(&Asn1Time::from_unix(not_after).expect("t"))
            .expect("na");
        let value = Asn1OctetString::new_from_bytes(&key_description).expect("octets");
        b.append_extension(X509Extension::new_from_der(&oid, false, &value).expect("ext"))
            .expect("android key extension");
        match &intermediate {
            Some((_, key)) => b.sign(key, MessageDigest::sha256()),
            None => b.sign(&self.root_key, MessageDigest::sha256()),
        }
        .expect("sign android leaf");
        let leaf = b.build();

        let mut chain = vec![leaf];
        if let Some((cert, _)) = intermediate {
            chain.push(cert);
        }
        chain
    }

    /// The DER chain [`Self::android_key_with`] would put in `x5c` for
    /// `registration` (made by `auth`) under `opts`, on its own: a test splices
    /// it into a STORED credential to give that credential a chain it could
    /// not register with (an expired one, say).
    #[must_use]
    pub fn android_chain_der(
        &self,
        auth: &SoftAuthenticator,
        registration: &Value,
        opts: &AndroidKeyOpts,
    ) -> Vec<Vec<u8>> {
        let cdj = unb64(
            &registration["response"]["clientDataJSON"],
            "clientDataJSON",
        );
        self.android_chain(auth.key_of(registration), &sha256(&cdj), opts)
            .iter()
            .map(|c| c.to_der().expect("der"))
            .collect()
    }

    /// This attestation's `packed` leaf certificate re-issued by its root with
    /// the validity `not_before..=not_after` (Unix seconds), same key and
    /// subject, as DER: spliced into a stored credential like
    /// [`Self::android_chain_der`].
    #[must_use]
    pub fn leaf_der_valid(&self, not_before: i64, not_after: i64) -> Vec<u8> {
        let mut b = X509Builder::new().expect("builder");
        b.set_version(2).expect("v3");
        b.set_serial_number(&serial()).expect("serial");
        b.set_subject_name(self.leaf.subject_name())
            .expect("subject");
        b.set_issuer_name(self.root.subject_name()).expect("issuer");
        b.set_pubkey(&self.leaf_key).expect("pubkey");
        b.set_not_before(&Asn1Time::from_unix(not_before).expect("t"))
            .expect("nb");
        b.set_not_after(&Asn1Time::from_unix(not_after).expect("t"))
            .expect("na");
        b.append_extension(BasicConstraints::new().critical().build().expect("bc"))
            .expect("bc");
        b.sign(&self.root_key, MessageDigest::sha256())
            .expect("sign leaf");
        b.build().to_der().expect("der")
    }

    /// The root's serial number, as lowercase hex without leading zeros (the
    /// form of a status-list entry's key).
    #[must_use]
    pub fn root_serial_hex(&self) -> String {
        let hex = self
            .root
            .serial_number()
            .to_bn()
            .expect("bn")
            .to_hex_str()
            .expect("hex")
            .to_ascii_lowercase();
        let trimmed = hex.trim_start_matches('0');
        if trimmed.is_empty() {
            "0".into()
        } else {
            trimmed.to_string()
        }
    }

    /// The root, PEM, as a relying party's CA file holds it.
    #[must_use]
    pub fn root_pem(&self) -> Vec<u8> {
        self.root.to_pem().expect("pem")
    }

    /// `registration` re-made as a `packed` attestation with this
    /// certificate in `x5c`, over the same client data, by a HARDWARE key of
    /// the same model: BE and BS are cleared before signing, since an attested
    /// hardware key sets neither (and the allowlist relying party refuses a
    /// backup-eligible credential).
    #[must_use]
    pub fn rewrap(&self, registration: &Value) -> Value {
        let mut auth_data = auth_data_of(registration);
        auth_data[FLAGS_AT] &= !(BE | BS);
        let cdj = unb64(
            &registration["response"]["clientDataJSON"],
            "clientDataJSON",
        );
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&sha256(&cdj));
        let stmt = Cbor::Map(vec![
            (text("alg"), Cbor::Integer((-7).into())),
            (text("sig"), Cbor::Bytes(sign(&self.leaf_key, &signed))),
            (
                text("x5c"),
                Cbor::Array(vec![Cbor::Bytes(self.leaf.to_der().expect("der"))]),
            ),
        ]);
        with_attestation(registration, "packed", stmt, auth_data)
    }
}

/// How long before now a test root's validity starts.
const ROOT_AGE: i64 = 365 * 86_400;

fn now_unix() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("time")
}

/// Google's attestation status lists the tests use (`tests/fixtures/
/// android-key-status/`, embedded so this file works from any crate's tests).
pub mod android_status {
    /// The example list of Google's key attestation documentation: serial
    /// `2c8cdddfd5e03bfc` REVOKED, `c8966fcb2fbb0d7a` SUSPENDED.
    pub const GOOGLE_EXAMPLE: &str =
        include_str!("../fixtures/android-key-status/google-example.json");
    /// No entry.
    pub const EMPTY: &str = include_str!("../fixtures/android-key-status/empty.json");
    /// Serial `0a1b2c3d4e5f6071` REVOKED, keyed `a1b2c3d4e5f6071`.
    pub const LEADING_ZERO: &str = include_str!("../fixtures/android-key-status/leading-zero.json");
    /// The REVOKED serial of [`GOOGLE_EXAMPLE`], as certificate bytes.
    pub const REVOKED_SERIAL: [u8; 8] = [0x2c, 0x8c, 0xdd, 0xdf, 0xd5, 0xe0, 0x3b, 0xfc];
    /// The SUSPENDED serial of [`GOOGLE_EXAMPLE`], as certificate bytes.
    pub const SUSPENDED_SERIAL: [u8; 8] = [0xc8, 0x96, 0x6f, 0xcb, 0x2f, 0xbb, 0x0d, 0x7a];
    /// Serial `8b1a2c3d4e5f6071` REVOKED, keyed in decimal.
    pub const DECIMAL_SERIAL_LIST: &str =
        include_str!("../fixtures/android-key-status/decimal-serial.json");
    /// The REVOKED serial of [`DECIMAL_SERIAL_LIST`], as certificate bytes.
    pub const DECIMAL_SERIAL: [u8; 8] = [0x8b, 0x1a, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71];
    /// The REVOKED serial of [`LEADING_ZERO`], as certificate bytes.
    pub const LEADING_ZERO_SERIAL: [u8; 8] = [0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71];

    /// `list` written to a fresh file in the temporary directory, last
    /// modified `age` ago: what the operator's refresh job leaves for
    /// `EPIGRAPH_WEBAUTHN_ANDROID_KEY_STATUS_FILE`.
    #[must_use]
    pub fn file(list: &str, age: std::time::Duration) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("epigraph-android-status-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("status dir");
        let path = dir.join("status.json");
        std::fs::write(&path, list).expect("status file");
        std::fs::File::options()
            .write(true)
            .open(&path)
            .expect("open status file")
            .set_modified(std::time::SystemTime::now() - age)
            .expect("set its modification time");
        path
    }

    /// A list with no entry, written just now.
    #[must_use]
    pub fn fresh_empty() -> std::path::PathBuf {
        file(EMPTY, std::time::Duration::ZERO)
    }
}
