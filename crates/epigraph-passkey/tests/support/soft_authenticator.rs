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
//!   key), or `packed` with an `x5c` from a [`TestAttestation`] root.
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
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, BigNumContext, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
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

        let key = p256();
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
    leaf: X509,
    leaf_key: PKey<Private>,
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
            leaf: b.build(),
            leaf_key,
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

fn now_unix() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("time")
}
