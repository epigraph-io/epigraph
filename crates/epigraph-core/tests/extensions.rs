//! Integration tests for the extension point traits — verifies the kernel
//! defaults compile and behave correctly with no downstream crates present.
//!
//! # What PR-11 changed here, and why it is a near-total rewrite
//!
//! The plan's *Tests* line says "updated `epigraph-core/tests/extensions.rs`",
//! which understates it. Of the five tests this file used to hold:
//!
//! * `encryption_noop_passthrough`, `orchestration_noop_submits_silently` and
//!   `orchestration_noop_status_is_unknown` tested `EncryptionProvider` and
//!   `OrchestrationBackend`, both **deleted** by PR-11. They are gone with
//!   their traits.
//! * `policy_noop_allows_all` asserted the kernel default permits every action.
//!   That is the property PR-11 inverts, so it is now
//!   [`the_kernel_default_denies_every_action`].
//! * `all_noop_impls_are_send_sync` loses two of its three assertions.
//!
//! # Why this file cannot see `AllowAllPolicyGate`
//!
//! `AllowAllPolicyGate` is behind `#[cfg(any(test, feature = "insecure-allow-all"))]`.
//! `cfg(test)` is set for the crate **being tested**, not for its dependencies,
//! so an integration test in `epigraph-core` does not see an item that
//! `epigraph-interfaces` compiles only under its own `cfg(test)` — and no
//! manifest in this workspace turns the feature on. That is the intended
//! outcome and it is asserted negatively where it can be: this file can only
//! reach the deny-all default. The allow-all gate's own coverage lives in
//! `epigraph-interfaces`' inline unit tests, which is the only place it is
//! compiled.

use epigraph_core::extensions::{
    Action, DenyAllPolicyGate, PolicyGate, Principal, ResourceKind, ResourceRef,
};
use uuid::Uuid;

fn every_action() -> Vec<Action> {
    vec![
        Action::Create,
        Action::Update,
        Action::Delete,
        Action::Declassify,
        Action::Custom("publish".into()),
    ]
}

/// The inverse of the pre-PR-11 `policy_noop_allows_all`.
///
/// A kernel with no policy installed must not let anyone write. Every
/// `AppState` constructor installs `epigraph_authz::GroupPolicyGate` over the
/// top of this; what this pins is that the *floor* is refusal, so a deployment
/// that forgets to install a gate fails closed rather than open.
#[tokio::test]
async fn the_kernel_default_denies_every_action() {
    let gate = DenyAllPolicyGate::new();
    let principal = Principal::without_groups(Uuid::new_v4());
    let resource = ResourceRef::new(ResourceKind::Claim, Uuid::new_v4());

    for action in every_action() {
        let decision = gate.authorize(&principal, &action, &resource).await;
        assert!(
            !decision.is_allowed(),
            "kernel default must deny {action:?}, got {decision:?}"
        );
    }
}

/// Membership in a group does not by itself buy anything from the kernel
/// default. Only `epigraph_authz::GroupPolicyGate` reads `writable_groups`.
#[tokio::test]
async fn the_kernel_default_denies_even_a_group_writer_on_their_own_group() {
    let group = Uuid::new_v4();
    let gate = DenyAllPolicyGate::new();
    let principal = Principal::new(Uuid::new_v4(), vec![group]);
    let resource = ResourceRef::new(ResourceKind::Claim, Uuid::new_v4()).owned_by_group(group);

    let decision = gate.authorize(&principal, &Action::Create, &resource).await;
    assert!(!decision.is_allowed(), "got {decision:?}");
}

/// A denial always carries a loggable reason.
///
/// A 403 with no recorded cause is indistinguishable in an incident from a
/// crash, and "the gate denied and nobody knows why" is how a fail-closed
/// control gets switched off in production.
#[tokio::test]
async fn a_denial_is_explained() {
    let decision = DenyAllPolicyGate::new()
        .authorize(
            &Principal::without_groups(Uuid::new_v4()),
            &Action::Declassify,
            &ResourceRef::new(ResourceKind::Ownership, Uuid::new_v4()),
        )
        .await;

    let reason = decision.denial_reason().expect("a denial carries a reason");
    assert!(
        reason.contains("no policy is installed"),
        "unhelpful denial reason: {reason}"
    );
}

/// `is_active()` is `true` for the deny-all gate.
///
/// The old no-op returned `false` so callers could skip policy *logging*. A
/// `false` on a gate that refuses everything would invite a caller to skip the
/// check itself, which is the failure this whole PR exists to prevent.
#[test]
fn the_kernel_default_reports_itself_active() {
    assert!(DenyAllPolicyGate::new().is_active());
}

#[test]
fn kernel_default_impls_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DenyAllPolicyGate>();
    assert_send_sync::<Principal>();
    assert_send_sync::<ResourceRef>();
}
