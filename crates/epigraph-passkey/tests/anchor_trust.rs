//! What may ANCHOR a later unattested passkey, and what may register as an
//! Android hardware key: the rule of the anchored path on an armed database.
//!
//! * the first passkey is always hardware-attested (`ceremony.rs`);
//! * an anchor is hardware-attested AND still trusted under the CURRENT
//!   configuration when it anchors: its stored certificate chain re-verified
//!   against today's roots and allowlist, the Android security-level rules
//!   and today's status list, never the columns its registration wrote;
//! * a synced passkey never anchors, directly or through any chain of acts.
//!
//! These began as the adversarial review's probes of PR #779 (each passed on
//! the PR head, i.e. each property was violated; recorded in the commit that
//! fixed it) and are kept as the red lines of those fixes. Every test names
//! the mutation of `src/` it was run against.

#[path = "support/soft_authenticator.rs"]
mod support;

use std::path::PathBuf;
use std::time::Duration;

use epigraph_passkey::{
    act_challenge, AaguidAllowlist, ActAnchor, AnchorRefusal, AttestationPolicy, AttestedPolicy,
    LineagePasskey, PasskeyConfig, PasskeyError, Passkeys, RegisteredPasskey, StoredPasskey,
    ACT_NONCE_LEN,
};
use support::{
    android_status, AndroidKeyOpts, ClientUv, SoftAuthenticator, TestAttestation, ORIGIN, RP_ID,
};
use uuid::Uuid;

const MODEL: Uuid = Uuid::from_u128(0x2fc0_579f_8113_47ea_b116_bb5a_8db9_202a);
const OTHER_MODEL: Uuid = Uuid::from_u128(0xcb69_481e_8ff7_4039_93ec_0a27_29a1_54a8);

/// The attested policy: `allow` the per-model allowlist, `android` the
/// Android key roots with the status list `status` (a fresh empty one when
/// `None`), `anchored` the anchored path.
fn attested_with(
    allow: Option<(&TestAttestation, &[Uuid])>,
    android: Option<&TestAttestation>,
    status: Option<PathBuf>,
    anchored: bool,
) -> Passkeys {
    let status = android.map(|_| status.unwrap_or_else(android_status::fresh_empty));
    Passkeys::new(PasskeyConfig {
        rp_id: RP_ID.into(),
        origin: ORIGIN.parse().unwrap(),
        policy: AttestationPolicy::Attested(AttestedPolicy {
            allowlist: allow.map(|(att, models)| AaguidAllowlist {
                ca_pem: att.root_pem(),
                aaguids: models.iter().copied().collect(),
            }),
            android_key_ca_pem: android.map(TestAttestation::root_pem),
            android_key_status_file: status,
            allow_synced_anchored: anchored,
        }),
    })
    .expect("relying party")
}

fn attested(
    allow: Option<(&TestAttestation, &[Uuid])>,
    android: Option<&TestAttestation>,
    anchored: bool,
) -> Passkeys {
    attested_with(allow, android, None, anchored)
}

fn software() -> Passkeys {
    Passkeys::new(PasskeyConfig {
        rp_id: RP_ID.into(),
        origin: ORIGIN.parse().unwrap(),
        policy: AttestationPolicy::SoftwareAllowed,
    })
    .expect("relying party")
}

/// An android-key registration by a fresh hardware authenticator under `rp`,
/// its certificates as `opts` describes and chained to `root`.
async fn android_registration(
    rp: &Passkeys,
    root: &TestAttestation,
    opts: &AndroidKeyOpts,
) -> (SoftAuthenticator, Result<RegisteredPasskey, PasskeyError>) {
    let (options, state) = rp.start_registration(Uuid::new_v4(), "op", "Op").unwrap();
    let mut auth = SoftAuthenticator::new(MODEL).hardware();
    let created = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let response = root.android_key_with(&auth, &created, true, opts);
    let reg = rp.finish_registration(&response, &state);
    (auth, reg)
}

fn policy_refusal(r: Result<RegisteredPasskey, PasskeyError>) -> String {
    match r {
        Err(PasskeyError::AttestationRefused(why)) => why,
        other => panic!("expected a policy refusal, got {other:?}"),
    }
}

/// An act confirmed by `auth`'s passkey `reg` exactly as the act ceremony
/// confirms one, for an enrollment of `person`; the anchor is a first
/// (maintenance-enrolled) passkey: an empty, complete lineage.
async fn confirmed_anchor(
    rp: &Passkeys,
    auth: &mut SoftAuthenticator,
    reg: &RegisteredPasskey,
    person: Uuid,
) -> ActAnchor {
    let act = Uuid::new_v4();
    let digest = [0x5A_u8; 32];
    let nonce = [0xC3_u8; ACT_NONCE_LEN];
    let challenge = act_challenge(act, &digest, &nonce);
    let stored = StoredPasskey {
        passkey: reg.passkey.clone(),
        sign_count: 0,
    };
    let (options, state) = rp
        .start_authentication_deferring_counter(std::slice::from_ref(&stored), Some(&challenge))
        .unwrap();
    let assertion = rp
        .finish_authentication(&auth.authenticate(ORIGIN, options).await, &state)
        .expect("the confirmation verifies");
    ActAnchor {
        act_id: act,
        act_kind: "passkey.register".into(),
        act_outcome: Some("confirmed".into()),
        args_digest: digest.to_vec(),
        act_challenge_state: Some(serde_json::json!({
            "v": 1,
            "ceremony": state.to_json(),
            "nonce": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, nonce),
        })),
        assertion_evidence: Some(assertion.evidence),
        enrollment_person: person,
        anchor_person: person,
        anchor_credential_id: reg.credential_id.clone(),
        anchor_passkey: reg.passkey.clone(),
        anchor_aaguid: reg.aaguid,
        anchor_attestation_format: reg.attestation_format.clone(),
        anchor_backup_eligible: reg.backup_eligible,
        anchor_revoked: false,
        anchor_lineage: vec![],
        anchor_lineage_complete: true,
    }
}

fn lineage_entry(reg: &RegisteredPasskey) -> LineagePasskey {
    LineagePasskey {
        passkey_id: Uuid::new_v4(),
        passkey: reg.passkey.clone(),
        aaguid: reg.aaguid,
        attestation_format: reg.attestation_format.clone(),
        backup_eligible: reg.backup_eligible,
    }
}

// =====================================================================
// P779-1: an Android key is hardware only when its attestation says so
// =====================================================================

/// A KeyDescription that places the key in SOFTWARE is refused at
/// registration under a genuine Android root: both security levels 0 with
/// `purpose`/`origin` in the software list (the review's probe A, which the
/// PR head accepted and recorded as hardware), either level alone 0, and
/// TEE levels with `purpose`/`origin` only in the software list. The same
/// software-level key registered under the software policy (an unarmed
/// database) anchors nothing once the Android root is configured.
/// CALIBRATION: the default TEE key registers and anchors.
/// Mutations: `android::hardware_rules` returning Ok -> every case
/// registers; its level check accepting 0 -> the first three register; its
/// hardware-list check reading the software list -> the last registers.
#[tokio::test]
async fn an_android_key_registers_only_when_the_attestation_puts_it_in_hardware() {
    let google = TestAttestation::new("Android");
    let rp = attested(None, Some(&google), true);
    let (mut auth, good) = android_registration(&rp, &google, &AndroidKeyOpts::default()).await;
    let good = good.expect("CALIBRATION: a TEE key registers");
    let anchor = confirmed_anchor(&rp, &mut auth, &good, Uuid::new_v4()).await;
    assert_eq!(rp.check_anchor(&anchor), Ok(()), "CALIBRATION: it anchors");

    for (label, opts) in [
        (
            "software levels, software list (probe A)",
            AndroidKeyOpts {
                attestation_level: 0,
                keymaster_level: 0,
                in_software_list: true,
                ..AndroidKeyOpts::default()
            },
        ),
        (
            "software attestation level",
            AndroidKeyOpts {
                attestation_level: 0,
                ..AndroidKeyOpts::default()
            },
        ),
        (
            "software key level",
            AndroidKeyOpts {
                keymaster_level: 0,
                ..AndroidKeyOpts::default()
            },
        ),
        (
            "TEE levels, purpose and origin software-enforced",
            AndroidKeyOpts {
                in_software_list: true,
                ..AndroidKeyOpts::default()
            },
        ),
    ] {
        let (_, reg) = android_registration(&rp, &google, &opts).await;
        let why = policy_refusal(reg);
        assert!(
            why.contains("hardware-backed") || why.contains("hardware-enforced"),
            "{label}: {why}"
        );
    }

    // The probe-A key registered where nothing checks it (the software
    // policy), then offered as an anchor under the Android root.
    let soft = software();
    let (mut auth, reg) = android_registration(
        &soft,
        &google,
        &AndroidKeyOpts {
            attestation_level: 0,
            keymaster_level: 0,
            in_software_list: true,
            ..AndroidKeyOpts::default()
        },
    )
    .await;
    let reg = reg.expect("the software policy records it");
    assert_eq!(reg.attestation_format, "android-key");
    let anchor = confirmed_anchor(&rp, &mut auth, &reg, Uuid::new_v4()).await;
    assert_eq!(
        rp.check_anchor(&anchor),
        Err(AnchorRefusal::AnchorNotAttested)
    );
}

/// StrongBox (security level 2) is refused by `webauthn-rs-core` 0.5.5's
/// own parser before this crate sees it (`InvalidTag`): pinned, so a library
/// that starts parsing it shows up here (this crate's rules admit level 2).
#[tokio::test]
async fn a_strongbox_key_is_refused_by_the_pinned_parser() {
    let google = TestAttestation::new("Android");
    let rp = attested(None, Some(&google), false);
    let (_, reg) = android_registration(
        &rp,
        &google,
        &AndroidKeyOpts {
            attestation_level: 2,
            keymaster_level: 2,
            ..AndroidKeyOpts::default()
        },
    )
    .await;
    match reg {
        Err(PasskeyError::Refused(why)) => assert!(!why.is_empty()),
        other => panic!("the 0.5.5 parser refuses level 2: {other:?}"),
    }
}

/// Only the leaf's KeyDescription counts: a chain whose intermediate
/// carries one as well (a certificate extending a genuine chain) is refused.
/// CALIBRATION: the same chain without the second one registers.
/// Mutation: `android::inspect_chain` ignoring non-leaf extensions -> it
/// registers.
#[tokio::test]
async fn a_key_description_outside_the_leaf_is_refused() {
    let google = TestAttestation::new("Android");
    let rp = attested(None, Some(&google), false);
    let chain = AndroidKeyOpts {
        intermediate: true,
        ..AndroidKeyOpts::default()
    };
    let (_, reg) = android_registration(&rp, &google, &chain).await;
    reg.expect("CALIBRATION: leaf, batch intermediate, root");
    let (_, reg) = android_registration(
        &rp,
        &google,
        &AndroidKeyOpts {
            key_description_on_intermediate: true,
            ..chain
        },
    )
    .await;
    let why = policy_refusal(reg);
    assert!(why.contains("only the leaf"), "{why}");
}

// =====================================================================
// P779-2: the attestation status list, local, fail closed
// =====================================================================

/// Every certificate of the chain is checked against the status list at
/// registration: a REVOKED leaf, a SUSPENDED intermediate (Google's
/// example list, verbatim), a leaf whose serial starts with a zero nibble
/// (keyed without it), and the root itself are each refused. CALIBRATION:
/// the same chains under the empty list register.
/// Mutations: the status loop skipped -> all register; the root's serial
/// not added -> the root case registers; `serial_hex` keeping byte padding
/// -> the leading-zero case registers.
#[tokio::test]
async fn a_listed_certificate_anywhere_in_the_chain_refuses_the_registration() {
    let google = TestAttestation::new("Android");
    let cases = [
        (
            "revoked leaf",
            android_status::GOOGLE_EXAMPLE,
            AndroidKeyOpts {
                leaf_serial: Some(android_status::REVOKED_SERIAL.to_vec()),
                ..AndroidKeyOpts::default()
            },
            "2c8cdddfd5e03bfc is REVOKED",
        ),
        (
            "suspended intermediate",
            android_status::GOOGLE_EXAMPLE,
            AndroidKeyOpts {
                intermediate: true,
                intermediate_serial: Some(android_status::SUSPENDED_SERIAL.to_vec()),
                ..AndroidKeyOpts::default()
            },
            "c8966fcb2fbb0d7a is SUSPENDED",
        ),
        (
            "leading-zero leaf",
            android_status::LEADING_ZERO,
            AndroidKeyOpts {
                leaf_serial: Some(android_status::LEADING_ZERO_SERIAL.to_vec()),
                ..AndroidKeyOpts::default()
            },
            "a1b2c3d4e5f6071 is REVOKED",
        ),
    ];
    for (label, list, opts, expected) in cases {
        let calm = attested(None, Some(&google), false);
        let (_, reg) = android_registration(&calm, &google, &opts).await;
        reg.unwrap_or_else(|e| panic!("CALIBRATION {label}: {e}"));
        let listed = attested_with(
            None,
            Some(&google),
            Some(android_status::file(list, Duration::ZERO)),
            false,
        );
        let (_, reg) = android_registration(&listed, &google, &opts).await;
        let why = policy_refusal(reg);
        assert!(why.contains(expected), "{label}: {why}");
    }

    let root_listed = format!(
        r#"{{"entries": {{"{}": {{"status": "REVOKED", "reason": "CA_COMPROMISE"}}}}}}"#,
        google.root_serial_hex()
    );
    let rp = attested_with(
        None,
        Some(&google),
        Some(android_status::file(&root_listed, Duration::ZERO)),
        false,
    );
    let (_, reg) = android_registration(&rp, &google, &AndroidKeyOpts::default()).await;
    let why = policy_refusal(reg);
    assert!(why.contains("REVOKED"), "root: {why}");
}

/// A status list older than 48 hours (by its file's modification time)
/// refuses every Android enrollment and every Android anchor: fail closed.
/// 47 hours is accepted; a file dated far in the future is refused (it
/// would stay "fresh" forever); a file deleted after boot is refused.
/// Mutations: the age check removed -> the 49h registration passes; the
/// future check removed -> the future-dated case passes.
#[tokio::test]
async fn a_stale_status_list_refuses_android_enrollments_and_anchors() {
    let google = TestAttestation::new("Android");
    let hour = Duration::from_secs(3600);
    let fresh = attested_with(
        None,
        Some(&google),
        Some(android_status::file(android_status::EMPTY, 47 * hour)),
        true,
    );
    let (mut auth, reg) = android_registration(&fresh, &google, &AndroidKeyOpts::default()).await;
    let reg = reg.expect("CALIBRATION: a 47h-old list is accepted");
    let anchor = confirmed_anchor(&fresh, &mut auth, &reg, Uuid::new_v4()).await;
    assert_eq!(fresh.check_anchor(&anchor), Ok(()), "CALIBRATION: anchors");

    let stale = attested_with(
        None,
        Some(&google),
        Some(android_status::file(android_status::EMPTY, 49 * hour)),
        true,
    );
    let (_, r) = android_registration(&stale, &google, &AndroidKeyOpts::default()).await;
    let why = policy_refusal(r);
    assert!(why.contains("older than the 48h maximum"), "{why}");
    assert_eq!(
        stale.check_anchor(&anchor),
        Err(AnchorRefusal::AnchorNotAttested),
        "a stale list anchors nothing"
    );

    let future = android_status::file(android_status::EMPTY, Duration::ZERO);
    std::fs::File::options()
        .write(true)
        .open(&future)
        .unwrap()
        .set_modified(std::time::SystemTime::now() + 2 * hour)
        .unwrap();
    let ahead = attested_with(None, Some(&google), Some(future), false);
    let (_, r) = android_registration(&ahead, &google, &AndroidKeyOpts::default()).await;
    assert!(policy_refusal(r).contains("in the future"));

    let gone = android_status::fresh_empty();
    let vanished = attested_with(None, Some(&google), Some(gone.clone()), false);
    std::fs::remove_file(&gone).unwrap();
    let (_, r) = android_registration(&vanished, &google, &AndroidKeyOpts::default()).await;
    assert!(policy_refusal(r).contains("cannot be read"));
}

/// A certificate listed AFTER the passkey registered stops it anchoring:
/// the list is read at every anchor use. CALIBRATION: under the empty list
/// the same anchor admits. Mutation: the status check run at registration
/// only -> the listed anchor admits.
#[tokio::test]
async fn a_certificate_listed_after_registration_stops_the_anchor() {
    let google = TestAttestation::new("Android");
    let before = attested(None, Some(&google), true);
    let (mut auth, reg) = android_registration(
        &before,
        &google,
        &AndroidKeyOpts {
            leaf_serial: Some(android_status::REVOKED_SERIAL.to_vec()),
            ..AndroidKeyOpts::default()
        },
    )
    .await;
    let reg = reg.expect("not listed yet");
    let anchor = confirmed_anchor(&before, &mut auth, &reg, Uuid::new_v4()).await;
    assert_eq!(before.check_anchor(&anchor), Ok(()), "CALIBRATION");
    let after = attested_with(
        None,
        Some(&google),
        Some(android_status::file(
            android_status::GOOGLE_EXAMPLE,
            Duration::ZERO,
        )),
        true,
    );
    assert_eq!(
        after.check_anchor(&anchor),
        Err(AnchorRefusal::AnchorNotAttested)
    );
}

// =====================================================================
// P779-3: an anchor is re-verified against the CURRENT configuration
// =====================================================================

/// The operator removes the Android roots (distrusts them): an android-key
/// passkey registered under them no longer anchors (the review's probe C).
/// A model removed from the allowlist stops its packed passkey anchoring the
/// same way. CALIBRATION: under the configuration they registered with, both
/// anchor. Mutation: `check_anchor` deciding from the row columns alone (the
/// PR head's `is_hardware_attested`) -> both anchor after the change.
#[tokio::test]
async fn an_anchor_whose_trust_was_withdrawn_anchors_nothing() {
    let google = TestAttestation::new("Android");
    let vendor = TestAttestation::new("Allowlisted");
    let before = attested(Some((&vendor, &[MODEL])), Some(&google), true);
    let (mut auth, reg) = android_registration(&before, &google, &AndroidKeyOpts::default()).await;
    let reg = reg.unwrap();
    let anchor = confirmed_anchor(&before, &mut auth, &reg, Uuid::new_v4()).await;
    assert_eq!(before.check_anchor(&anchor), Ok(()), "CALIBRATION");
    let without_android = attested(Some((&vendor, &[MODEL])), None, true);
    assert_eq!(
        without_android.check_anchor(&anchor),
        Err(AnchorRefusal::AnchorNotAttested),
        "probe C"
    );

    let (options, state) = before
        .start_registration(Uuid::new_v4(), "op", "Op")
        .unwrap();
    let mut key = SoftAuthenticator::new(MODEL).hardware();
    let created = key.register(ORIGIN, options, ClientUv::AsRequested).await;
    let packed = before
        .finish_registration(&vendor.rewrap(&created), &state)
        .unwrap();
    let anchor = confirmed_anchor(&before, &mut key, &packed, Uuid::new_v4()).await;
    assert_eq!(before.check_anchor(&anchor), Ok(()), "CALIBRATION");
    let other_models = attested(Some((&vendor, &[OTHER_MODEL])), None, true);
    assert_eq!(
        other_models.check_anchor(&anchor),
        Err(AnchorRefusal::AnchorNotAttested),
        "the model left the allowlist"
    );
    let other_root = attested(Some((&TestAttestation::new("Other"), &[MODEL])), None, true);
    assert_eq!(
        other_root.check_anchor(&anchor),
        Err(AnchorRefusal::AnchorNotAttested),
        "the root was replaced"
    );
}

/// A passkey registered while the database served the SOFTWARE policy
/// (unarmed) with a certificate chain from a root nobody configured is
/// recorded `packed` with a real model AAGUID (or `android-key`),
/// device-bound; once the database runs the attested policy it anchors
/// nothing: the review's probes B1 (packed) and B2 (android-key, with no
/// Android roots, and with Android roots that are not its root).
/// Mutation: as above -> all three anchor.
#[tokio::test]
async fn a_software_era_passkey_with_a_self_made_chain_anchors_nothing() {
    let nobody = TestAttestation::new("Nobody");
    let soft = software();
    let (options, state) = soft.start_registration(Uuid::new_v4(), "op", "Op").unwrap();
    let mut auth = SoftAuthenticator::new(MODEL).hardware();
    let created = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let b1 = soft
        .finish_registration(&nobody.rewrap(&created), &state)
        .expect("the software policy records it");
    assert_eq!(
        (
            b1.attestation_format.as_str(),
            b1.aaguid,
            b1.backup_eligible
        ),
        ("packed", MODEL, false),
        "CALIBRATION: the row looks hardware-attested"
    );
    let vendor = TestAttestation::new("Allowlisted");
    let prod = attested(Some((&vendor, &[MODEL])), None, true);
    let anchor = confirmed_anchor(&prod, &mut auth, &b1, Uuid::new_v4()).await;
    assert_eq!(
        prod.check_anchor(&anchor),
        Err(AnchorRefusal::AnchorNotAttested),
        "B1"
    );

    let fake_google = TestAttestation::new("FakeGoogle");
    let (mut auth, b2) =
        android_registration(&soft, &fake_google, &AndroidKeyOpts::default()).await;
    let b2 = b2.expect("the software policy records it");
    assert_eq!(
        (b2.attestation_format.as_str(), b2.backup_eligible),
        ("android-key", false)
    );
    let anchor = confirmed_anchor(&prod, &mut auth, &b2, Uuid::new_v4()).await;
    assert_eq!(
        prod.check_anchor(&anchor),
        Err(AnchorRefusal::AnchorNotAttested),
        "B2, no Android roots"
    );
    let google = TestAttestation::new("Android");
    let with_android = attested(Some((&vendor, &[MODEL])), Some(&google), true);
    assert_eq!(
        with_android.check_anchor(&anchor),
        Err(AnchorRefusal::AnchorNotAttested),
        "B2, other Android roots"
    );
}

/// The row's columns must agree with the stored credential they were
/// written from: a genuine allowlisted packed anchor whose row says `tpm`,
/// backup-eligible, or another model anchors nothing, and so does a
/// credential with no stored attestation. CALIBRATION: the true columns
/// anchor. Mutations: the format comparison removed -> `tpm` anchors; the
/// AAGUID comparison removed -> the other model anchors (OTHER_MODEL is on
/// the allowlist here).
#[tokio::test]
async fn the_rows_columns_must_agree_with_the_stored_credential() {
    let vendor = TestAttestation::new("Allowlisted");
    let rp = attested(Some((&vendor, &[MODEL, OTHER_MODEL])), None, true);
    let (options, state) = rp.start_registration(Uuid::new_v4(), "op", "Op").unwrap();
    let mut key = SoftAuthenticator::new(MODEL).hardware();
    let created = key.register(ORIGIN, options, ClientUv::AsRequested).await;
    let reg = rp
        .finish_registration(&vendor.rewrap(&created), &state)
        .unwrap();
    let good = confirmed_anchor(&rp, &mut key, &reg, Uuid::new_v4()).await;
    assert_eq!(rp.check_anchor(&good), Ok(()), "CALIBRATION");
    let mut tpm = good.clone();
    tpm.anchor_attestation_format = "tpm".into();
    let mut synced = good.clone();
    synced.anchor_backup_eligible = true;
    let mut model = good.clone();
    model.anchor_aaguid = OTHER_MODEL;
    let mut bare = good.clone();
    bare.anchor_passkey["cred"]
        .as_object_mut()
        .unwrap()
        .remove("attestation");
    for (label, a) in [
        ("tpm", tpm),
        ("backup-eligible", synced),
        ("other model", model),
        ("no attestation", bare),
    ] {
        assert_eq!(
            rp.check_anchor(&a),
            Err(AnchorRefusal::AnchorNotAttested),
            "{label}"
        );
    }
}

// =====================================================================
// P779-7: a synced passkey anchors nothing through any chain of acts
// =====================================================================

/// An anchor that is itself hardware-attested anchors nothing when a passkey
/// on its LINEAGE (one that authorized it) is not: a synced passkey that
/// confirmed the act the phone was enrolled on, whatever its position, and
/// so does an incomplete lineage (it does not reach a first passkey).
/// CALIBRATION: an all-hardware lineage anchors.
/// Mutations: the lineage loop removed -> the synced ancestor anchors; the
/// completeness check removed -> the incomplete lineage anchors.
#[tokio::test]
async fn a_synced_passkey_on_the_lineage_anchors_nothing() {
    let vendor = TestAttestation::new("Allowlisted");
    let google = TestAttestation::new("Android");
    let rp = attested(Some((&vendor, &[MODEL])), Some(&google), true);
    let person = Uuid::new_v4();

    // The person's first passkey (hardware, packed) ...
    let (options, state) = rp.start_registration(person, "op", "Op").unwrap();
    let mut first_key = SoftAuthenticator::new(MODEL).hardware();
    let created = first_key
        .register(ORIGIN, options, ClientUv::AsRequested)
        .await;
    let first = rp
        .finish_registration(&vendor.rewrap(&created), &state)
        .unwrap();
    // ... anchored a synced passkey ...
    let anchor = confirmed_anchor(&rp, &mut first_key, &first, person).await;
    let (options, state) = rp.start_anchored_registration(person, "op", "Op").unwrap();
    let mut manager = SoftAuthenticator::new(OTHER_MODEL);
    let response = manager
        .register(ORIGIN, options, ClientUv::AsRequested)
        .await;
    let synced = rp
        .finish_anchored_registration(&response, &state, &anchor)
        .unwrap();
    // ... which confirmed the act a phone was then enrolled on (attested).
    let (mut phone_key, phone) =
        android_registration(&rp, &google, &AndroidKeyOpts::default()).await;
    let phone = phone.expect("a genuine phone registers");

    let mut via_synced = confirmed_anchor(&rp, &mut phone_key, &phone, person).await;
    via_synced.anchor_lineage = vec![lineage_entry(&synced), lineage_entry(&first)];
    assert_eq!(
        rp.check_anchor(&via_synced),
        Err(AnchorRefusal::LineageNotAttested),
        "the phone was authorized by the synced passkey"
    );
    let mut deeper = via_synced.clone();
    deeper.anchor_lineage = vec![lineage_entry(&first), lineage_entry(&synced)];
    assert_eq!(
        rp.check_anchor(&deeper),
        Err(AnchorRefusal::LineageNotAttested),
        "anywhere on the lineage"
    );
    let mut incomplete = via_synced.clone();
    incomplete.anchor_lineage = vec![lineage_entry(&first)];
    incomplete.anchor_lineage_complete = false;
    assert_eq!(
        rp.check_anchor(&incomplete),
        Err(AnchorRefusal::LineageNotAttested),
        "incomplete"
    );
    let mut hardware = via_synced;
    hardware.anchor_lineage = vec![lineage_entry(&first)];
    assert_eq!(
        rp.check_anchor(&hardware),
        Ok(()),
        "CALIBRATION: authorized by the first passkey"
    );
}

/// The lineage JSON migration 200's reader returns parses, and anything else
/// is `None` (the API then reports the lineage incomplete). Mutation:
/// `list_from_json` skipping malformed entries -> the second case parses.
#[test]
fn the_lineage_reads_from_the_readers_json() {
    let id = Uuid::new_v4();
    let v = serde_json::json!([{
        "passkey_id": id.to_string(), "passkey": {"cred": {}},
        "aaguid": MODEL.to_string(), "attestation_format": "packed", "backup_eligible": false,
    }]);
    let list = LineagePasskey::list_from_json(&v).expect("parses");
    assert_eq!(list.len(), 1);
    assert_eq!(
        (
            list[0].passkey_id,
            list[0].aaguid,
            list[0].attestation_format.as_str()
        ),
        (id, MODEL, "packed")
    );
    let bad = serde_json::json!([{"passkey_id": "x"}]);
    assert!(LineagePasskey::list_from_json(&bad).is_none());
    assert_eq!(
        LineagePasskey::list_from_json(&serde_json::json!([])),
        Some(vec![])
    );
}
