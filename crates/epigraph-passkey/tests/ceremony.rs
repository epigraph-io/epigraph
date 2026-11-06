//! Registration, assertion and re-verification against an INDEPENDENT client
//! and authenticator written from the WebAuthn and CTAP specifications
//! (`support/soft_authenticator.rs`; why not a library is explained there),
//! with the attestation statements an allowlist relying party needs.
//!
//! Every test names the mutation of `src/` it was run against.

#[path = "support/soft_authenticator.rs"]
mod support;

use std::collections::BTreeSet;

use epigraph_passkey::{
    act_challenge, AaguidAllowlist, ActAnchor, AnchorRefusal, AttestationPolicy, AttestedPolicy,
    PasskeyConfig, PasskeyError, Passkeys, RegistrationState, RelyingParty, StoredPasskey,
    Verifier, ACT_NONCE_LEN,
};
use serde_json::Value;
use support::{
    android_status, hardware_bound, ClientUv, SoftAuthenticator, TestAttestation, ORIGIN, RP_ID,
};
use uuid::Uuid;

/// The authenticator model every allowlist test admits.
const MODEL: Uuid = Uuid::from_u128(0x2fc0_579f_8113_47ea_b116_bb5a_8db9_202a);
/// A model no test allowlists.
const OTHER_MODEL: Uuid = Uuid::from_u128(0xcb69_481e_8ff7_4039_93ec_0a27_29a1_54a8);

fn allowlist(att: &TestAttestation, models: &[Uuid]) -> Passkeys {
    Passkeys::new(PasskeyConfig {
        rp_id: RP_ID.into(),
        origin: ORIGIN.parse().unwrap(),
        policy: AttestationPolicy::Allowlist {
            ca_pem: att.root_pem(),
            aaguids: models.iter().copied().collect::<BTreeSet<_>>(),
        },
    })
    .expect("relying party")
}

fn software() -> Passkeys {
    Passkeys::new(PasskeyConfig {
        rp_id: RP_ID.into(),
        origin: ORIGIN.parse().unwrap(),
        policy: AttestationPolicy::SoftwareAllowed,
    })
    .expect("relying party")
}

/// The library's refusal text, or a panic naming what came back instead.
fn refusal(err: PasskeyError) -> String {
    match err {
        PasskeyError::Refused(why) => why,
        other => panic!("expected a library refusal, got {other:?}"),
    }
}

fn start(rp: &Passkeys) -> (Value, RegistrationState) {
    rp.start_registration(Uuid::new_v4(), "operator", "Operator")
        .expect("start")
}

/// The interop pin everything else rests on: a packed attestation by an
/// allowlisted model, chained to the configured root, over an independent
/// authenticator's credential, verifies, and yields the row columns.
#[tokio::test]
async fn an_attested_registration_by_an_allowlisted_model_verifies() {
    let att = TestAttestation::new("Allowlisted");
    let rp = allowlist(&att, &[MODEL]);
    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = att.rewrap(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    let reg = rp
        .finish_registration(&response, &state)
        .expect("an allowlisted packed attestation verifies");
    assert_eq!(reg.aaguid, MODEL);
    assert_eq!(reg.attestation_format, "packed");
    assert!(reg.user_verified);
    assert!(!reg.backup_eligible);
    let raw_id = response["rawId"].as_str().unwrap().to_string();
    assert_eq!(
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &reg.credential_id
        ),
        raw_id
    );
    assert!(
        reg.passkey.pointer("/cred/cred").is_some(),
        "{}",
        reg.passkey
    );
}

/// EQ-1 (a): `none` attestation is refused under the allowlist, which is what
/// keeps a software authenticator (the one this very test uses) from
/// enrolling. Mutation: the allowlist policy starts a plain
/// `start_passkey_registration` (finishing it as one too) -> accepted.
#[tokio::test]
async fn none_attestation_is_refused_under_the_allowlist() {
    let att = TestAttestation::new("Allowlisted");
    let rp = allowlist(&att, &[MODEL]);
    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(MODEL);
    // Hardware-bound, so the refusal below is the ATTESTATION's and not the
    // allowlist's separate refusal of a synced credential.
    let response = hardware_bound(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    let why = refusal(rp.finish_registration(&response, &state).unwrap_err());
    assert!(
        why.contains("not a format valid for CA chain validation"),
        "{why}"
    );
}

/// EQ-1 (a): `packed` SELF attestation (signed by the credential's own key,
/// no certificate) is refused under the allowlist just as `none` is: it proves
/// nothing about the authenticator's make. Mutation: as above.
#[tokio::test]
async fn self_attestation_is_refused_under_the_allowlist() {
    let att = TestAttestation::new("Allowlisted");
    let rp = allowlist(&att, &[MODEL]);
    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(MODEL).hardware();
    let created = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let response = auth.self_attest(&created);
    let why = refusal(rp.finish_registration(&response, &state).unwrap_err());
    assert!(
        why.contains("not a format valid for CA chain validation"),
        "{why}"
    );
    // CALIBRATION: the same self-attested response is well-formed; the
    // software policy accepts it.
    let soft = software();
    let (options, state) = start(&soft);
    let mut auth = SoftAuthenticator::new(MODEL);
    let created = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let reg = soft
        .finish_registration(&auth.self_attest(&created), &state)
        .expect("self attestation verifies as a signature");
    assert_eq!(reg.attestation_format, "packed");
    assert_eq!(reg.aaguid, Uuid::nil());
}

/// A model the root vouches for but the allowlist does not name is refused.
/// Mutation: the root inserted as a blanket allow (no AAGUID restriction) ->
/// accepted.
#[tokio::test]
async fn a_model_not_on_the_allowlist_is_refused() {
    let att = TestAttestation::new("Allowlisted");
    let rp = allowlist(&att, &[MODEL]);
    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(OTHER_MODEL);
    let response = att.rewrap(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    let why = refusal(rp.finish_registration(&response, &state).unwrap_err());
    assert!(why.contains("limits the aaguids allowed"), "{why}");
}

/// An attestation by a root the relying party was not given is refused, even
/// for an allowlisted model.
#[tokio::test]
async fn an_attestation_from_an_unconfigured_root_is_refused() {
    let ours = TestAttestation::new("Allowlisted");
    let theirs = TestAttestation::new("Impostor");
    let rp = allowlist(&ours, &[MODEL]);
    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = theirs.rewrap(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    let why = refusal(rp.finish_registration(&response, &state).unwrap_err());
    assert!(
        why.contains("not trusted by one of the selected CA"),
        "{why}"
    );
}

/// The stored ceremony state sits in a row the request DSN can write. A state
/// that carries its OWN roots (here: an impostor's root admitting the
/// impostor's model) does not bring them in: the finish uses this process's.
/// Mutation: the `ca_list` splice removed from `finish_registration` ->
/// the impostor's attestation is accepted.
#[tokio::test]
async fn a_stored_state_cannot_bring_its_own_roots() {
    let ours = TestAttestation::new("Allowlisted");
    let theirs = TestAttestation::new("Impostor");
    let rp = allowlist(&ours, &[MODEL]);
    let impostor_rp = allowlist(&theirs, &[OTHER_MODEL]);
    let (options, state) = start(&rp);
    let (_, impostor_state) = start(&impostor_rp);
    let mut tampered = state.to_json();
    tampered["library"]["ca_list"] = impostor_state.to_json()["library"]["ca_list"].clone();
    let tampered = RegistrationState::from_json(tampered);
    let mut auth = SoftAuthenticator::new(OTHER_MODEL);
    let response = theirs.rewrap(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    // CALIBRATION: the impostor's own relying party would accept it.
    assert!(impostor_rp
        .finish_registration(
            &response,
            &RegistrationState::from_json({
                let mut s = impostor_state.to_json();
                s["library"]["rs"]["challenge"] =
                    state.to_json()["library"]["rs"]["challenge"].clone();
                s
            })
        )
        .is_ok());
    let why = refusal(rp.finish_registration(&response, &tampered).unwrap_err());
    assert!(
        why.contains("not trusted by one of the selected CA"),
        "{why}"
    );
}

/// D5: a registration without user verification is refused, both when the
/// stored state asks for it (the library refuses) and when a tampered state
/// downgrades the policy (this crate's own check on the credential refuses).
/// Mutation: the `user_verified` check in `registered_from` removed -> the
/// downgraded state's registration is accepted.
#[tokio::test]
async fn a_registration_without_user_verification_is_refused() {
    let att = TestAttestation::new("Allowlisted");
    let rp = allowlist(&att, &[MODEL]);

    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = att.rewrap(&auth.register(ORIGIN, options, ClientUv::Skip).await);
    let err = rp.finish_registration(&response, &state).unwrap_err();
    assert!(
        matches!(
            err,
            PasskeyError::UserNotVerified | PasskeyError::Refused(_)
        ),
        "{err:?}"
    );

    let (options, state) = start(&rp);
    let mut downgraded = state.to_json();
    downgraded["library"]["rs"]["policy"] = Value::from("discouraged");
    let downgraded = RegistrationState::from_json(downgraded);
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = att.rewrap(&auth.register(ORIGIN, options, ClientUv::Skip).await);
    let err = rp.finish_registration(&response, &downgraded).unwrap_err();
    assert!(matches!(err, PasskeyError::UserNotVerified), "{err:?}");
}

/// The origin is exact. Mutations: `allow_any_port(true)` on the builder ->
/// the port variant is accepted; `allow_subdomains(true)` -> the subdomain
/// variant is accepted.
#[tokio::test]
async fn a_response_from_another_origin_is_refused() {
    let att = TestAttestation::new("Allowlisted");
    let rp = allowlist(&att, &[MODEL]);
    for origin in [
        "https://auth.example.com:8443",
        "https://x.auth.example.com",
    ] {
        let (options, state) = start(&rp);
        let mut auth = SoftAuthenticator::new(MODEL);
        let response = att.rewrap(&auth.register(origin, options, ClientUv::AsRequested).await);
        let why = refusal(rp.finish_registration(&response, &state).unwrap_err());
        assert!(why.contains("origin does not match"), "{origin}: {why}");
    }
}

/// A credential scoped to another rp id (here the parent domain, which a
/// browser on the configured origin would allow a page to ask for) is
/// refused, though the origin is right.
#[tokio::test]
async fn a_credential_for_another_rp_id_is_refused() {
    let att = TestAttestation::new("Allowlisted");
    let rp = allowlist(&att, &[MODEL]);
    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(MODEL);
    let options = SoftAuthenticator::with_rp_id(options, "example.com");
    let response = att.rewrap(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    let why = refusal(rp.finish_registration(&response, &state).unwrap_err());
    assert!(
        why.contains("relying party id hash does not match"),
        "{why}"
    );
}

/// The test-only software policy accepts `none` attestation, recorded with
/// the nil AAGUID (the calibration that the flag is what the refusals above
/// depend on).
#[tokio::test]
async fn the_software_policy_accepts_none_attestation() {
    let rp = software();
    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let reg = rp.finish_registration(&response, &state).expect("accepted");
    assert_eq!(reg.attestation_format, "none");
    assert_eq!(reg.aaguid, Uuid::nil());
    assert!(reg.user_verified);
}

/// A state started under one policy is not finished under the other.
/// Mutation: the `kind` comparison in `library_state` removed -> the software
/// state is finished by the allowlist relying party (and fails later, for
/// another reason: the error is no longer `State`).
#[tokio::test]
async fn a_state_started_under_another_policy_is_refused() {
    let att = TestAttestation::new("Allowlisted");
    let rp = allowlist(&att, &[MODEL]);
    let (options, state) = start(&software());
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = att.rewrap(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    let err = rp.finish_registration(&response, &state).unwrap_err();
    assert!(matches!(err, PasskeyError::State(_)), "{err:?}");
}

/// A state survives the trip through a database `jsonb` column (text).
#[tokio::test]
async fn a_ceremony_state_survives_storage() {
    let rp = software();
    let (options, state) = start(&rp);
    let stored = serde_json::to_string(&state.to_json()).unwrap();
    let state = RegistrationState::from_json(serde_json::from_str(&stored).unwrap());
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    rp.finish_registration(&response, &state).expect("finishes");
}

/// Register with the software policy and return the authenticator and the
/// stored passkey.
async fn registered(rp: &Passkeys) -> (SoftAuthenticator, StoredPasskey) {
    let (options, state) = start(rp);
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let reg = rp
        .finish_registration(&response, &state)
        .expect("registered");
    (
        auth,
        StoredPasskey {
            passkey: reg.passkey,
            sign_count: 0,
        },
    )
}

/// An assertion verifies, with user verification, and its evidence carries
/// the challenge it was made over.
#[tokio::test]
async fn an_assertion_verifies() {
    let rp = software();
    let (mut auth, stored) = registered(&rp).await;
    let (options, state) = rp
        .start_authentication(std::slice::from_ref(&stored), None)
        .unwrap();
    let response = auth.authenticate(ORIGIN, options).await;
    let a = rp
        .finish_authentication(&response, &state)
        .expect("verifies");
    assert!(a.user_verified);
    assert_eq!(
        epigraph_passkey::evidence_challenge(&a.evidence).unwrap(),
        state.challenge().unwrap()
    );
}

/// An assertion without user verification is refused.
#[tokio::test]
async fn an_assertion_without_user_verification_is_refused() {
    let rp = software();
    let (mut auth, stored) = registered(&rp).await;
    let (mut options, state) = rp
        .start_authentication(std::slice::from_ref(&stored), None)
        .unwrap();
    options["publicKey"]["userVerification"] = Value::from("discouraged");
    let response = auth.authenticate(ORIGIN, options).await;
    let err = rp.finish_authentication(&response, &state).unwrap_err();
    assert!(
        matches!(
            err,
            PasskeyError::UserNotVerified | PasskeyError::Refused(_)
        ),
        "{err:?}"
    );
}

/// The challenge override is what the authenticator signs and what the
/// verifier checks: a response over override A does not verify against a
/// state carrying override B. Mutations: the override applied to the options
/// only -> the A response fails against its own state; to the state only ->
/// likewise.
#[tokio::test]
async fn the_challenge_override_is_what_the_assertion_signs() {
    let rp = software();
    let (mut auth, stored) = registered(&rp).await;
    let a = [0xA1_u8; 32];
    let b = [0xB2_u8; 32];
    let (options_a, state_a) = rp
        .start_authentication(std::slice::from_ref(&stored), Some(&a))
        .unwrap();
    let (_, state_b) = rp
        .start_authentication(std::slice::from_ref(&stored), Some(&b))
        .unwrap();
    assert_eq!(state_a.challenge().unwrap(), a);
    let response = auth.authenticate(ORIGIN, options_a).await;
    let err = rp.finish_authentication(&response, &state_b).unwrap_err();
    assert!(matches!(err, PasskeyError::Refused(_)), "{err:?}");
    let ok = rp
        .finish_authentication(&response, &state_a)
        .expect("A verifies");
    assert_eq!(
        epigraph_passkey::evidence_challenge(&ok.evidence).unwrap(),
        a
    );
    assert!(rp
        .start_authentication(std::slice::from_ref(&stored), Some(&[1_u8; 8]))
        .is_err());
}

/// A non-advancing signature counter is refused as a possible clone, keyed on
/// the counter the DATABASE holds (`StoredPasskey::sign_count`), not the one
/// frozen inside the serialized credential. Mutation: `passkey_of` ignores
/// `sign_count` -> accepted.
#[tokio::test]
async fn a_counter_that_does_not_advance_is_refused() {
    let rp = software();
    let (mut auth, mut stored) = registered(&rp).await;
    let (options, state) = rp
        .start_authentication(std::slice::from_ref(&stored), None)
        .unwrap();
    let response = auth.authenticate(ORIGIN, options).await;
    let first = rp.finish_authentication(&response, &state).expect("first");
    // The test authenticator keeps no counter (0), so a stored counter above
    // it is exactly a regression.
    assert_eq!(first.counter, 0);
    stored.sign_count = 5;
    let (options, state) = rp
        .start_authentication(std::slice::from_ref(&stored), None)
        .unwrap();
    let response = auth.authenticate(ORIGIN, options).await;
    let err = rp.finish_authentication(&response, &state).unwrap_err();
    assert!(matches!(err, PasskeyError::CounterRegressed), "{err:?}");
}

/// An authenticator that keeps a counter and REPLAYS an old value (a cloned
/// key) is refused once the database holds the newer one. Mutation: as above.
#[tokio::test]
async fn a_replayed_counter_is_refused() {
    let rp = software();
    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(MODEL).counting();
    let response = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let reg = rp
        .finish_registration(&response, &state)
        .expect("registered");
    let mut stored = StoredPasskey {
        passkey: reg.passkey,
        sign_count: 0,
    };
    for expected in [1_u32, 2] {
        let (options, state) = rp
            .start_authentication(std::slice::from_ref(&stored), None)
            .unwrap();
        let a = rp
            .finish_authentication(&auth.authenticate(ORIGIN, options).await, &state)
            .expect("an advancing counter verifies");
        assert_eq!(a.counter, expected);
        stored.sign_count = a.counter;
    }
    auth.set_counter(0);
    let (options, state) = rp
        .start_authentication(std::slice::from_ref(&stored), None)
        .unwrap();
    let err = rp
        .finish_authentication(&auth.authenticate(ORIGIN, options).await, &state)
        .unwrap_err();
    assert!(matches!(err, PasskeyError::CounterRegressed), "{err:?}");
}

/// Stored evidence re-verifies against the stored credential, and only
/// against it: a tampered signature, a challenge swapped in the evidence, or
/// another credential's snapshot are each refused. The counter is not
/// re-checked (the database's has moved on). Mutation: `reverify` returns Ok
/// without finishing -> each refusal is accepted.
#[tokio::test]
async fn evidence_reverifies_against_its_credential_only() {
    let rp = software();
    let (mut auth, mut stored) = registered(&rp).await;
    let (_, other) = registered(&rp).await;
    let (options, state) = rp
        .start_authentication(std::slice::from_ref(&stored), Some(&[7_u8; 32]))
        .unwrap();
    let response = auth.authenticate(ORIGIN, options).await;
    let a = rp
        .finish_authentication(&response, &state)
        .expect("verifies");
    stored.sign_count = 9;
    rp.reverify(&a.evidence, &stored)
        .expect("genuine evidence re-verifies");

    let mut sig = a.evidence.clone();
    let s = sig["response"]["response"]["signature"]
        .as_str()
        .unwrap()
        .to_string();
    let mut bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &s).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    sig["response"]["response"]["signature"] = Value::from(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &bytes,
    ));
    assert!(rp.reverify(&sig, &stored).is_err(), "a tampered signature");

    let mut chal = a.evidence.clone();
    chal["challenge"] = Value::from(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        [8_u8; 32],
    ));
    assert!(rp.reverify(&chal, &stored).is_err(), "a swapped challenge");

    assert!(
        rp.reverify(&a.evidence, &other).is_err(),
        "another credential"
    );
}

/// The offline verifier, built from the relying party alone (no attestation
/// policy: it registers nothing), re-verifies what the ceremony's relying
/// party verified, and refuses it under another origin or rp id and with a
/// tampered signature. Mutations: `Verifier::reverify` answers Ok without
/// verifying (the tampered case is accepted); `Verifier::new` ignores the
/// configured origin (the other-origin verifier accepts).
#[tokio::test]
async fn a_verifier_reverifies_what_the_ceremony_verified() {
    let rp = software();
    let (mut auth, stored) = registered(&rp).await;
    let (options, state) = rp
        .start_authentication(std::slice::from_ref(&stored), None)
        .unwrap();
    let a = rp
        .finish_authentication(&auth.authenticate(ORIGIN, options).await, &state)
        .expect("verifies");
    let verifier = |rp_id: &str, origin: &str| {
        Verifier::new(RelyingParty {
            rp_id: rp_id.into(),
            origin: origin.parse().unwrap(),
        })
        .expect("verifier")
    };
    let v = verifier(RP_ID, ORIGIN);
    let again = v.reverify(&a.evidence, &stored).expect("genuine evidence");
    assert_eq!(again.credential_id, a.credential_id);
    assert!(
        verifier(RP_ID, "https://auth.example.com:8443")
            .reverify(&a.evidence, &stored)
            .is_err(),
        "another origin"
    );
    assert!(
        verifier("example.com", "https://auth.example.com")
            .reverify(&a.evidence, &stored)
            .is_err(),
        "another rp id"
    );
    let mut sig = a.evidence.clone();
    let s = sig["response"]["response"]["signature"]
        .as_str()
        .unwrap()
        .to_string();
    let mut bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &s).unwrap();
    bytes[0] ^= 0x01;
    sig["response"]["response"]["signature"] = Value::from(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &bytes,
    ));
    assert!(v.reverify(&sig, &stored).is_err(), "a tampered signature");
}

/// The assertion reports the backup-eligible flag the AUTHENTICATOR asserted,
/// so a caller can refuse a device-bound credential that now asserts as
/// syncable (webauthn-rs's passkey path accepts that upgrade; elevation's
/// confirm definer refuses it, `backup_eligibility_changed`). Mutations:
/// `backup_eligible: false` hardcoded -> the synced case is red; `true`
/// hardcoded -> the hardware case is red.
#[tokio::test]
async fn an_assertion_reports_the_asserted_backup_eligible_flag() {
    let rp = software();
    for (auth, expected) in [
        (SoftAuthenticator::new(MODEL), true),
        (SoftAuthenticator::new(MODEL).hardware(), false),
    ] {
        let mut auth = auth;
        let (options, state) = start(&rp);
        let response = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
        let reg = rp
            .finish_registration(&response, &state)
            .expect("registered");
        assert_eq!(
            reg.backup_eligible, expected,
            "CALIBRATION: registered flag"
        );
        let stored = StoredPasskey {
            passkey: reg.passkey,
            sign_count: 0,
        };
        let (options, state) = rp
            .start_authentication(std::slice::from_ref(&stored), None)
            .unwrap();
        let a = rp
            .finish_authentication(&auth.authenticate(ORIGIN, options).await, &state)
            .expect("verifies");
        assert_eq!(a.backup_eligible, expected, "asserted flag");
    }
}

/// The counter-deferring start leaves the signature counter to the CALLER:
/// a stored counter the assertion does not advance past is NOT refused by the
/// library, and the assertion's own counter is reported for the caller's
/// database to compare under its row lock (elevation's confirm definer, ELV05,
/// which also writes the audit row a library refusal could not). The counted
/// start refuses the same assertion (the calibration). Mutation: the
/// deferring start overlays the stored counter -> refused here.
#[tokio::test]
async fn the_counter_deferring_start_leaves_the_counter_to_the_caller() {
    let rp = software();
    let (mut auth, mut stored) = registered(&rp).await;
    stored.sign_count = 5;
    let (options, state) = rp
        .start_authentication(std::slice::from_ref(&stored), None)
        .unwrap();
    let err = rp
        .finish_authentication(&auth.authenticate(ORIGIN, options).await, &state)
        .unwrap_err();
    assert!(
        matches!(err, PasskeyError::CounterRegressed),
        "CALIBRATION: the counted start refuses: {err:?}"
    );
    let (options, state) = rp
        .start_authentication_deferring_counter(std::slice::from_ref(&stored), None)
        .unwrap();
    let a = rp
        .finish_authentication(&auth.authenticate(ORIGIN, options).await, &state)
        .expect("the counter is the caller's to check");
    assert_eq!(a.counter, 0, "the asserted counter is reported");
}

// =====================================================================
// Android key roots (a blanket root, `android-key` only, device-bound)
// =====================================================================

/// The attested policy: `allow` the per-model allowlist (root and models),
/// `android` the Android key roots, `anchored` the anchored path.
fn attested(
    allow: Option<(&TestAttestation, &[Uuid])>,
    android: Option<&TestAttestation>,
    anchored: bool,
) -> Passkeys {
    Passkeys::new(PasskeyConfig {
        rp_id: RP_ID.into(),
        origin: ORIGIN.parse().unwrap(),
        policy: AttestationPolicy::Attested(AttestedPolicy {
            allowlist: allow.map(|(att, models)| AaguidAllowlist {
                ca_pem: att.root_pem(),
                aaguids: models.iter().copied().collect(),
            }),
            android_key_ca_pem: android.map(TestAttestation::root_pem),
            android_key_status_file: android.map(|_| android_status::fresh_empty()),
            allow_synced_anchored: anchored,
        }),
    })
    .expect("relying party")
}

/// The policy refusal text, or a panic naming what came back instead.
fn policy_refusal(err: PasskeyError) -> String {
    match err {
        PasskeyError::AttestationRefused(why) => why,
        other => panic!("expected a policy refusal, got {other:?}"),
    }
}

/// THE MEASURED FAILURE, fixed: a device-bound `android-key` attestation
/// chaining to a configured Android root verifies and is recorded as
/// `android-key`, device-bound and user-verified, with the nil AAGUID (an
/// Android key names no model), whatever model the authenticator data
/// claims. The challenge offers `android-key` to the client. CALIBRATION:
/// the SAME response under the same root inserted as a per-model allowlist
/// root (today's only option) is refused exactly as production refused it.
///
/// Mutation: the Android roots built with `allowlist_cas` (per-model) ->
/// red with "does not have an aaguid".
#[tokio::test]
async fn an_android_key_attestation_verifies_under_a_blanket_android_root() {
    let google = TestAttestation::new("Android");
    let rp = attested(None, Some(&google), false);
    let (options, state) = start(&rp);
    let formats = options["publicKey"]["attestationFormats"].clone();
    assert!(
        formats
            .as_array()
            .is_some_and(|f| f.iter().any(|v| v == "android-key")),
        "the challenge offers android-key: {formats}"
    );
    let mut auth = SoftAuthenticator::new(OTHER_MODEL).hardware();
    let created = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let response = google.android_key(&auth, &created, true);
    let reg = rp
        .finish_registration(&response, &state)
        .expect("a device-bound android-key attestation verifies");
    assert_eq!(reg.attestation_format, "android-key");
    assert_eq!(reg.aaguid, Uuid::nil());
    assert!(reg.user_verified);
    assert!(!reg.backup_eligible);
    rp.hardware_attested(
        &reg.passkey,
        &reg.attestation_format,
        reg.aaguid,
        reg.backup_eligible,
    )
    .expect("and is hardware-attested under this configuration");

    let per_model = allowlist(&google, &[OTHER_MODEL]);
    let (options, state) = start(&per_model);
    let mut auth = SoftAuthenticator::new(OTHER_MODEL).hardware();
    let created = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let why = refusal(
        per_model
            .finish_registration(&google.android_key(&auth, &created, true), &state)
            .unwrap_err(),
    );
    assert!(why.contains("does not have an aaguid"), "{why}");
}

/// A `packed` attestation whose certificate chains to an ANDROID root is
/// refused: the blanket root vouches for the `android-key` format only. With
/// the allowlist configured beside it (another root), the packed statement
/// by an ALLOWLISTED model still does not pass through the Android root.
/// Mutation: the format check in `android_key_rules` removed -> accepted.
#[tokio::test]
async fn a_packed_attestation_chaining_to_an_android_root_is_refused() {
    let google = TestAttestation::new("Android");
    let vendor = TestAttestation::new("Allowlisted");
    for rp in [
        attested(None, Some(&google), false),
        attested(Some((&vendor, &[MODEL])), Some(&google), false),
    ] {
        let (options, state) = start(&rp);
        let mut auth = SoftAuthenticator::new(MODEL).hardware();
        let response = google.rewrap(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
        let why = policy_refusal(rp.finish_registration(&response, &state).unwrap_err());
        assert!(why.contains("android-key attestation format"), "{why}");
    }
}

/// A BACKUP-ELIGIBLE `android-key` credential is refused. The library's
/// attested state refuses it already; a stored state rewritten to allow
/// synced credentials (the request DSN can write it) is refused by this
/// crate's own rule. Mutation: the `backup_eligible` check in
/// `android_key_rules` removed -> the tampered case is accepted.
#[tokio::test]
async fn a_backup_eligible_android_key_credential_is_refused() {
    let google = TestAttestation::new("Android");
    let rp = attested(None, Some(&google), false);

    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(MODEL);
    let created = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let why = refusal(
        rp.finish_registration(&google.android_key(&auth, &created, false), &state)
            .unwrap_err(),
    );
    assert!(
        why.contains("hardware"),
        "CALIBRATION: the library's refusal: {why}"
    );

    let (options, state) = start(&rp);
    let mut tampered = state.to_json();
    tampered["library"]["rs"]["allow_synchronised_authenticators"] = Value::from(true);
    let tampered = RegistrationState::from_json(tampered);
    let mut auth = SoftAuthenticator::new(MODEL);
    let created = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let why = policy_refusal(
        rp.finish_registration(&google.android_key(&auth, &created, false), &tampered)
            .unwrap_err(),
    );
    assert!(why.contains("backup-eligible"), "{why}");
}

/// With the Android roots beside it, the per-model allowlist is unchanged:
/// a packed attestation by an allowlisted model verifies through it
/// (recorded `packed` with its model), a model it does not name is still
/// refused with the allowlist's reason, and an android-key attestation
/// verifies through the Android root. Mutation: the allowlist attempt
/// skipped when the Android roots are set -> the packed case is refused.
#[tokio::test]
async fn the_allowlist_is_unchanged_beside_the_android_roots() {
    let google = TestAttestation::new("Android");
    let vendor = TestAttestation::new("Allowlisted");
    let rp = attested(Some((&vendor, &[MODEL])), Some(&google), false);

    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = vendor.rewrap(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    let reg = rp
        .finish_registration(&response, &state)
        .expect("an allowlisted packed attestation verifies");
    assert_eq!(
        (reg.attestation_format.as_str(), reg.aaguid),
        ("packed", MODEL)
    );

    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(OTHER_MODEL);
    let response = vendor.rewrap(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    let why = refusal(rp.finish_registration(&response, &state).unwrap_err());
    assert!(why.contains("limits the aaguids allowed"), "{why}");

    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(MODEL).hardware();
    let created = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let reg = rp
        .finish_registration(&google.android_key(&auth, &created, true), &state)
        .expect("an android-key attestation verifies beside the allowlist");
    assert_eq!(reg.attestation_format, "android-key");
}

/// `none` attestation is refused under the Android roots too (the blanket is
/// for attested keys only), and a root in BOTH files is a configuration
/// error, never a silent widening of the per-model root. Mutation: the
/// overlap check removed -> the relying party builds.
#[tokio::test]
async fn none_is_refused_under_the_android_roots_and_a_shared_root_is_refused() {
    let google = TestAttestation::new("Android");
    let rp = attested(None, Some(&google), false);
    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = hardware_bound(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    let why = refusal(rp.finish_registration(&response, &state).unwrap_err());
    assert!(
        why.contains("not a format valid for CA chain validation"),
        "{why}"
    );

    let shared = Passkeys::new(PasskeyConfig {
        rp_id: RP_ID.into(),
        origin: ORIGIN.parse().unwrap(),
        policy: AttestationPolicy::Attested(AttestedPolicy {
            allowlist: Some(AaguidAllowlist {
                ca_pem: google.root_pem(),
                aaguids: [MODEL].into_iter().collect::<BTreeSet<_>>(),
            }),
            android_key_ca_pem: Some(google.root_pem()),
            android_key_status_file: Some(android_status::fresh_empty()),
            allow_synced_anchored: false,
        }),
    });
    match shared {
        Err(PasskeyError::Config(why)) => assert!(why.contains("in both"), "{why}"),
        other => panic!("a shared root must be refused: {other:?}"),
    }
}

// =====================================================================
// The anchored path: a later, unattested passkey anchored by an attested one
// =====================================================================

/// A hardware-attested passkey registered under `rp` (packed, allowlisted
/// MODEL by `vendor`), and its authenticator.
async fn attested_passkey(
    rp: &Passkeys,
    vendor: &TestAttestation,
) -> (SoftAuthenticator, epigraph_passkey::RegisteredPasskey) {
    let (options, state) = start(rp);
    let mut auth = SoftAuthenticator::new(MODEL).hardware();
    let response = vendor.rewrap(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    let reg = rp.finish_registration(&response, &state).expect("attested");
    (auth, reg)
}

/// An act confirmed by `auth`'s passkey `reg` exactly as the act ceremony
/// confirms one: its challenge is `act_challenge(act, digest, nonce)`, the
/// stored state wraps the library's state with the nonce, and the evidence is
/// the verified assertion's. Returns the anchor an enrollment of `person`
/// on that act would read.
async fn confirmed_anchor(
    rp: &Passkeys,
    auth: &mut SoftAuthenticator,
    reg: &epigraph_passkey::RegisteredPasskey,
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

/// The anchored path end to end: a later passkey from a SYNCED provider,
/// with `none` attestation, registers when its act was confirmed by the same
/// person's hardware-attested passkey, and is recorded as `none`,
/// backup-eligible, with the nil AAGUID, so it can never anchor in turn.
/// The anchored challenge asks for no attestation and allows a synced
/// credential. Mutation: `finish_anchored_registration` finishing as an
/// attested registration -> refused (the CALIBRATION that the path is what
/// admits it).
#[tokio::test]
async fn a_later_unattested_passkey_anchored_by_an_attested_one_registers() {
    let vendor = TestAttestation::new("Allowlisted");
    let rp = attested(Some((&vendor, &[MODEL])), None, true);
    let person = Uuid::new_v4();
    let (mut first, reg) = attested_passkey(&rp, &vendor).await;
    let anchor = confirmed_anchor(&rp, &mut first, &reg, person).await;
    rp.check_anchor(&anchor).expect("the anchor admits it");

    let (options, state) = rp
        .start_anchored_registration(person, "operator", "Operator")
        .expect("anchored start");
    assert_eq!(options["publicKey"]["attestation"], "none", "{options}");
    let mut synced = SoftAuthenticator::new(OTHER_MODEL);
    let response = synced
        .register(ORIGIN, options, ClientUv::AsRequested)
        .await;
    let later = rp
        .finish_anchored_registration(&response, &state, &anchor)
        .expect("the anchored passkey registers");
    assert_eq!(later.attestation_format, "none");
    assert_eq!(later.aaguid, Uuid::nil());
    assert!(later.backup_eligible && later.user_verified);
    assert!(rp
        .hardware_attested(
            &later.passkey,
            &later.attestation_format,
            later.aaguid,
            later.backup_eligible
        )
        .is_err());

    // CALIBRATION: the same kind of response on the attested path is refused.
    let (options, state) = start(&rp);
    let mut synced = SoftAuthenticator::new(OTHER_MODEL);
    let response = synced
        .register(ORIGIN, options, ClientUv::AsRequested)
        .await;
    assert!(rp.finish_registration(&response, &state).is_err());
}

/// A FIRST passkey is attested whatever the anchored setting says: with it
/// on, `none` is refused on the attested path, and an attested state
/// relabelled `anchored` (the request DSN can write the state) is refused by
/// both finishes: the attested one by its kind, the anchored one without an
/// anchor that admits it. Mutation: `finish_registration` accepting a state
/// of kind `anchored` -> the relabelled state finishes.
#[tokio::test]
async fn a_first_passkey_with_none_is_refused_with_the_anchored_setting_on() {
    let vendor = TestAttestation::new("Allowlisted");
    let rp = attested(Some((&vendor, &[MODEL])), None, true);
    let (options, state) = start(&rp);
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = hardware_bound(&auth.register(ORIGIN, options, ClientUv::AsRequested).await);
    let why = refusal(rp.finish_registration(&response, &state).unwrap_err());
    assert!(
        why.contains("not a format valid for CA chain validation"),
        "{why}"
    );

    let (options, state) = rp
        .start_anchored_registration(Uuid::new_v4(), "operator", "Operator")
        .unwrap();
    let mut auth = SoftAuthenticator::new(MODEL);
    let response = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let err = rp.finish_registration(&response, &state).unwrap_err();
    assert!(matches!(err, PasskeyError::State(_)), "{err:?}");
}

/// A confirmation by a passkey that is NOT hardware-attested anchors
/// nothing: a synced passkey (BE set) and an unattested device-bound one
/// (`none`, BE clear) are both refused `anchor_not_attested`, and so is a
/// self-attested `packed` one (the nil AAGUID). Their confirmations are
/// genuine. Mutation: `Passkeys::hardware_attested` answering Ok -> the
/// device-bound `none` anchor admits it. (A software-era `packed` passkey
/// WITH a certificate chain is `anchor_trust.rs`'s
/// `a_software_era_passkey_with_a_self_made_chain_anchors_nothing`.)
#[tokio::test]
async fn a_confirmation_by_an_unattested_passkey_anchors_nothing() {
    let vendor = TestAttestation::new("Allowlisted");
    let rp = attested(Some((&vendor, &[MODEL])), None, true);
    let soft = software();
    let person = Uuid::new_v4();
    for (label, shape) in [
        ("synced none", 0_u8),
        ("device-bound none", 1),
        ("self-attested packed", 2),
    ] {
        let (options, state) = start(&soft);
        let mut auth = if shape == 0 {
            SoftAuthenticator::new(MODEL)
        } else {
            SoftAuthenticator::new(MODEL).hardware()
        };
        let created = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
        let response = if shape == 2 {
            auth.self_attest(&created)
        } else {
            created
        };
        let reg = soft.finish_registration(&response, &state).expect(label);
        let anchor = confirmed_anchor(&rp, &mut auth, &reg, person).await;
        assert_eq!(
            rp.check_anchor(&anchor),
            Err(AnchorRefusal::AnchorNotAttested),
            "{label}"
        );
        let (options, state) = rp
            .start_anchored_registration(person, "operator", "Operator")
            .unwrap();
        let mut later = SoftAuthenticator::new(OTHER_MODEL);
        let response = later.register(ORIGIN, options, ClientUv::AsRequested).await;
        assert!(
            matches!(
                rp.finish_anchored_registration(&response, &state, &anchor),
                Err(PasskeyError::Anchor(AnchorRefusal::AnchorNotAttested))
            ),
            "{label}"
        );
    }
}

/// The act's recorded confirmation is RE-VERIFIED: a confirmation whose
/// signature was tampered with, one recorded over another act's challenge,
/// one by another credential, an anchor of another person, a revoked
/// anchor, an act that is not confirmed or not a `passkey.register` act are
/// each refused with its reason. Mutations: `reverify` skipped in
/// `check_anchor` -> the tampered signature admits; the challenge binding
/// skipped -> the other act's challenge admits; the person check removed ->
/// the other person's anchor admits; the revoked check removed -> admits.
#[tokio::test]
async fn the_recorded_confirmation_is_reverified() {
    let vendor = TestAttestation::new("Allowlisted");
    let rp = attested(Some((&vendor, &[MODEL])), None, true);
    let person = Uuid::new_v4();
    let (mut auth, reg) = attested_passkey(&rp, &vendor).await;
    let good = confirmed_anchor(&rp, &mut auth, &reg, person).await;
    assert_eq!(rp.check_anchor(&good), Ok(()), "CALIBRATION");

    let mut sig = good.clone();
    let evidence = sig.assertion_evidence.as_mut().unwrap();
    let raw = evidence["response"]["response"]["signature"]
        .as_str()
        .unwrap()
        .to_string();
    let mut bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, raw).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    evidence["response"]["response"]["signature"] = Value::from(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &bytes,
    ));
    assert_eq!(
        rp.check_anchor(&sig),
        Err(AnchorRefusal::AssertionDoesNotVerify)
    );

    // A genuine confirmation of ANOTHER act, stored on this one.
    let other = confirmed_anchor(&rp, &mut auth, &reg, person).await;
    let mut moved = good.clone();
    moved.assertion_evidence = other.assertion_evidence.clone();
    moved.act_challenge_state = other.act_challenge_state.clone();
    assert_eq!(
        rp.check_anchor(&moved),
        Err(AnchorRefusal::ChallengeNotBound)
    );

    let (_, second) = attested_passkey(&rp, &vendor).await;
    let mut cred = good.clone();
    cred.anchor_credential_id = second.credential_id;
    assert_eq!(
        rp.check_anchor(&cred),
        Err(AnchorRefusal::CredentialMismatch)
    );

    let mut someone = good.clone();
    someone.enrollment_person = Uuid::new_v4();
    assert_eq!(
        rp.check_anchor(&someone),
        Err(AnchorRefusal::PersonMismatch)
    );
    let mut revoked = good.clone();
    revoked.anchor_revoked = true;
    assert_eq!(rp.check_anchor(&revoked), Err(AnchorRefusal::AnchorRevoked));
    let mut refused = good.clone();
    refused.act_outcome = Some("refused".into());
    assert_eq!(rp.check_anchor(&refused), Err(AnchorRefusal::NotConfirmed));
    let mut grant = good;
    grant.act_kind = "role.grant".into();
    assert_eq!(rp.check_anchor(&grant), Err(AnchorRefusal::NotARegisterAct));
}

/// The anchored path verifies NO attestation, so it accepts none: a
/// response carrying a statement (a packed one with a certificate, or self
/// attestation) is refused rather than recorded as if it were verified, which
/// would let it anchor a further passkey. Mutation: the `none`-only check
/// removed -> the packed response is recorded `packed` with its model.
#[tokio::test]
async fn the_anchored_path_refuses_an_attestation_statement() {
    let vendor = TestAttestation::new("Allowlisted");
    let rp = attested(Some((&vendor, &[MODEL])), None, true);
    let person = Uuid::new_v4();
    let (mut first, reg) = attested_passkey(&rp, &vendor).await;
    let anchor = confirmed_anchor(&rp, &mut first, &reg, person).await;
    for statement in ["x5c", "self"] {
        let (options, state) = rp
            .start_anchored_registration(person, "operator", "Operator")
            .unwrap();
        let mut auth = SoftAuthenticator::new(MODEL).hardware();
        let created = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
        let response = if statement == "x5c" {
            vendor.rewrap(&created)
        } else {
            auth.self_attest(&created)
        };
        let why = policy_refusal(
            rp.finish_anchored_registration(&response, &state, &anchor)
                .unwrap_err(),
        );
        assert!(why.contains("without attestation"), "{statement}: {why}");
    }
}

/// With the setting OFF the anchored path does not exist: neither its start
/// nor its finish runs, even with an anchor that would admit it, and a
/// registration starts attested as before. Mutation: the setting check in
/// `start_anchored_registration` removed -> it starts.
#[tokio::test]
async fn the_anchored_path_is_off_unless_configured() {
    let vendor = TestAttestation::new("Allowlisted");
    let off = attested(Some((&vendor, &[MODEL])), None, false);
    let on = attested(Some((&vendor, &[MODEL])), None, true);
    let person = Uuid::new_v4();
    let (mut first, reg) = attested_passkey(&on, &vendor).await;
    let anchor = confirmed_anchor(&on, &mut first, &reg, person).await;
    assert!(!off.allows_synced_anchored() && on.allows_synced_anchored());
    assert!(matches!(
        off.start_anchored_registration(person, "operator", "Operator"),
        Err(PasskeyError::Config(_))
    ));
    let (options, state) = on
        .start_anchored_registration(person, "operator", "Operator")
        .unwrap();
    let mut auth = SoftAuthenticator::new(OTHER_MODEL);
    let response = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    assert!(matches!(
        off.finish_anchored_registration(&response, &state, &anchor),
        Err(PasskeyError::Config(_))
    ));
    assert!(!allowlist(&vendor, &[MODEL]).allows_synced_anchored());
    let (_, state) = start(&off);
    assert_eq!(state.to_json()["kind"], "attested");
}

/// What counts as hardware-attested is decided from the STORED credential
/// under the configuration running now, never from the columns alone: the
/// columns that read "hardware" for every shape (`packed` + a model, `tpm`
/// + a model, `android-key`, device-bound) are refused when the credential
/// behind them is a software one, and a genuine attested credential is
/// refused under the software policy (which configures no roots). The
/// genuine cases are `anchor_trust.rs`'s. Mutation: `hardware_attested`
/// deciding from its three column arguments (the PR head's
/// `is_hardware_attested`) -> every columns-only case passes.
#[tokio::test]
async fn hardware_attested_is_decided_from_the_credential_not_the_columns() {
    let vendor = TestAttestation::new("Allowlisted");
    let google = TestAttestation::new("Android");
    let rp = attested(Some((&vendor, &[MODEL])), Some(&google), true);
    let soft = software();
    let (options, state) = start(&soft);
    let mut auth = SoftAuthenticator::new(MODEL).hardware();
    let created = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let unattested = soft
        .finish_registration(&created, &state)
        .expect("a device-bound none passkey");
    for (format, aaguid) in [
        ("packed", MODEL),
        ("tpm", MODEL),
        ("android-key", Uuid::nil()),
        ("none", Uuid::nil()),
    ] {
        assert!(
            rp.hardware_attested(&unattested.passkey, format, aaguid, false)
                .is_err(),
            "{format}"
        );
    }
    let (_, genuine) = attested_passkey(&rp, &vendor).await;
    rp.hardware_attested(&genuine.passkey, "packed", MODEL, false)
        .expect("CALIBRATION: genuine");
    assert!(soft
        .hardware_attested(&genuine.passkey, "packed", MODEL, false)
        .is_err());
}
