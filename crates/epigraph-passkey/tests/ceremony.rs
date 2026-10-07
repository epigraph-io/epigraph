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
    AttestationPolicy, PasskeyConfig, PasskeyError, Passkeys, RegistrationState, RelyingParty,
    StoredPasskey, Verifier,
};
use serde_json::Value;
use support::{hardware_bound, ClientUv, SoftAuthenticator, TestAttestation, ORIGIN, RP_ID};
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
