//! Integration tests for extension point traits — verifies no-op defaults compile
//! and behave correctly without any enterprise crates present.

use epigraph_core::extensions::{
    Action, EncryptionProvider, NoOpEncryption, NoOpOrchestration, NoOpOrchestrationBackend,
    NoOpPolicyGate, OrchestrationBackend, PolicyGate, TaskStatus,
};
use uuid::Uuid;

#[tokio::test]
async fn encryption_noop_passthrough() {
    let enc = NoOpEncryption::new();
    let plaintext = b"hello epistemic world";

    let ciphertext = enc.encrypt(plaintext, "group-key-1").await.unwrap();
    assert_eq!(&ciphertext, plaintext, "no-op encrypt must be identity");

    let recovered = enc.decrypt(&ciphertext, "group-key-1").await.unwrap();
    assert_eq!(&recovered, plaintext, "no-op decrypt must be identity");

    assert!(!enc.is_active(), "no-op encryption must report inactive");
}

#[tokio::test]
async fn policy_noop_allows_all() {
    let gate = NoOpPolicyGate::new();
    let agent = Uuid::new_v4();
    let resource = Uuid::new_v4();

    for action in [Action::Create, Action::Read, Action::Update, Action::Delete] {
        assert!(
            gate.check(agent, &action, resource).await.unwrap(),
            "no-op policy gate must allow {action:?}"
        );
    }
}

#[tokio::test]
async fn orchestration_noop_submits_silently() {
    let orch = NoOpOrchestration::new();
    let task_id = Uuid::new_v4();
    let result = orch
        .submit(task_id, serde_json::json!({"type": "test"}))
        .await;
    assert!(result.is_ok(), "no-op orchestration must return Ok(())");
    assert!(
        !orch.is_active(),
        "no-op orchestration must report inactive"
    );
}

#[tokio::test]
async fn orchestration_noop_status_is_unknown() {
    let orch = NoOpOrchestrationBackend::new();
    let status = orch.status(Uuid::new_v4()).await.unwrap();
    assert_eq!(status, TaskStatus::Unknown);
}

#[test]
fn all_noop_impls_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NoOpEncryption>();
    assert_send_sync::<NoOpPolicyGate>();
    assert_send_sync::<NoOpOrchestration>();
}
