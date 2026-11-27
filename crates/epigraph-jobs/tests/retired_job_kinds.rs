//! The four RETIRED job kinds (`TruthPropagation`, `ReputationUpdate`,
//! `WebhookNotification`, `DataCleanup`) have no handler, but a `jobs` row
//! already stored with one must stay readable: removing the variant would turn
//! that row into a payload no code can parse. This pins that the stored JSON
//! still deserializes, that each keeps its `job_type` string (the value in the
//! row's `job_type` column, which `drain_jobs --cancel-pending` matches on),
//! and that exactly these four are retired.

use epigraph_jobs::EpiGraphJob;

const ID: &str = "00000000-0000-0000-0000-000000000001";

fn stored(kind: &str, body: &serde_json::Value) -> EpiGraphJob {
    let payload = serde_json::json!({ kind: body });
    serde_json::from_value(payload)
        .unwrap_or_else(|e| panic!("a stored {kind} row must still deserialize: {e}"))
}

#[test]
fn a_stored_row_of_a_retired_kind_still_deserializes_with_its_type() {
    for (kind, body, job_type) in [
        (
            "TruthPropagation",
            serde_json::json!({ "source_claim_id": ID }),
            "truth_propagation",
        ),
        (
            "ReputationUpdate",
            serde_json::json!({ "agent_id": ID }),
            "reputation_update",
        ),
        (
            "WebhookNotification",
            serde_json::json!({ "webhook_id": ID, "payload": { "event": "claim.created" } }),
            "webhook_notification",
        ),
        (
            "DataCleanup",
            serde_json::json!({ "retention_days": 30 }),
            "data_cleanup",
        ),
    ] {
        let job = stored(kind, &body);
        assert_eq!(job.job_type(), job_type, "{kind}");
        assert!(job.is_retired(), "{kind} must be marked retired");
    }
}

#[test]
fn only_the_four_kinds_without_a_handler_are_retired() {
    let live = [
        stored(
            "ClusterGraph",
            &serde_json::json!({ "resolution": 1.0, "retain_runs": 3 }),
        ),
        stored(
            "EmbeddingGeneration",
            &serde_json::json!({ "claim_id": ID }),
        ),
        stored(
            "PrivatizationApply",
            &serde_json::json!({ "plan_id": ID, "dispatched_by": ID, "correlation_id": "c" }),
        ),
        stored(
            "PrivatizationRevert",
            &serde_json::json!({ "plan_id": ID, "dispatched_by": ID, "correlation_id": "c" }),
        ),
        stored(
            "PrivatizationReseal",
            &serde_json::json!({ "group_id": ID, "dispatched_by": ID, "correlation_id": "c" }),
        ),
    ];
    for job in live {
        assert!(
            !job.is_retired(),
            "{} has a registered handler and must not be retired",
            job.job_type()
        );
    }
}
