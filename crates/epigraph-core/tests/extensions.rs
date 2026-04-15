//! Integration tests for extension point traits — verifies no-op defaults compile
//! and behave correctly without any enterprise crates present.

use epigraph_core::extensions::{
    EncryptionProvider, NoOpEncryption, NoOpOrchestration, NoOpPolicyGate, OrchestrationBackend,
    PolicyGate,
};
use uuid::Uuid;

#[tokio::test]
async fn encryption_noop_passthrough() {
    let enc = NoOpEncryption;
    let group_id = Uuid::new_v4();
    let plaintext = b"hello epistemic world";

    let ciphertext = enc.encrypt(plaintext, group_id).await.unwrap();
    assert_eq!(&ciphertext, plaintext, "no-op encrypt must be identity");

    let recovered = enc.decrypt(&ciphertext, group_id).await.unwrap();
    assert_eq!(&recovered, plaintext, "no-op decrypt must be identity");

    assert!(!enc.is_enabled(), "no-op encryption must report disabled");
}

#[tokio::test]
async fn policy_noop_allows_all() {
    let gate = NoOpPolicyGate;
    let agent = Uuid::new_v4();
    let resource = Uuid::new_v4();

    assert!(gate.check_read(agent, resource).await.unwrap());
    assert!(gate.check_write(agent, resource).await.unwrap());
}

#[tokio::test]
async fn orchestration_noop_returns_error() {
    let orch = NoOpOrchestration;
    let result = orch.schedule_task("some_task", serde_json::json!({})).await;
    assert!(result.is_err(), "no-op orchestration must return Err");
}

#[test]
fn all_noop_impls_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NoOpEncryption>();
    assert_send_sync::<NoOpPolicyGate>();
    assert_send_sync::<NoOpOrchestration>();
}
