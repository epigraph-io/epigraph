//! Verify auto_wire_ds_update stores source_strength = evidence-type weight
//! (not the agent confidence). The SciFact discount path uses source_strength
//! as Shafer's reliability multiplier; conflating it with agent confidence
//! double-discounts the BBA (the mass shape already encodes confidence).
//!
//! Sheaf cohomology stagnation (h1 frozen at the obstruction-rich extreme)
//! is the visible symptom of the prior conflation.

#[macro_use]
mod common;

use epigraph_mcp::tools;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent_and_claim(pool: &PgPool) -> (Uuid, Uuid) {
    let agent_id = Uuid::new_v4();
    let claim_id = Uuid::new_v4();
    // Derive unique public_key + content_hash from the UUIDs so re-runs
    // against a persistent test DB don't collide on previous fixtures.
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind(agent_id.as_bytes().repeat(2))
        .execute(pool)
        .await
        .expect("seed agent");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(claim_id)
    .bind(format!("source-strength regression {claim_id}"))
    .bind(claim_id.as_bytes().repeat(2))
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    (agent_id, claim_id)
}

#[tokio::test]
async fn auto_wire_ds_update_stores_weight_as_source_strength() {
    let pool = test_pool_or_skip!();
    let (agent_id, claim_id) = seed_agent_and_claim(&pool).await;

    // Confidence and weight differ so we can tell which one was stored.
    let confidence = 0.95;
    let weight = 0.6;
    let evidence_id = Uuid::new_v4();

    tools::ds_auto::auto_wire_ds_update(
        &pool,
        claim_id,
        agent_id,
        confidence,
        weight,
        true, // supports
        Some("testimony"),
        Some(evidence_id),
    )
    .await
    .expect("auto_wire_ds_update");

    let stored: (Option<f64>, Option<String>, Option<Uuid>) = sqlx::query_as(
        "SELECT source_strength, evidence_type, evidence_id \
           FROM mass_functions \
          WHERE claim_id = $1 AND perspective_id = $2",
    )
    .bind(claim_id)
    .bind(evidence_id)
    .fetch_one(&pool)
    .await
    .expect("fetch BBA");

    let stored_strength = stored.0.expect("source_strength must be set");
    assert!(
        (stored_strength - weight).abs() < f64::EPSILON,
        "source_strength should be the evidence-type weight ({weight}), got {stored_strength}"
    );
    assert!(
        (stored_strength - confidence).abs() > 0.01,
        "source_strength must NOT equal confidence ({confidence}); confidence is encoded in BBA shape"
    );
    assert_eq!(stored.1.as_deref(), Some("testimony"));
    // Phase 3 (issue #197): auto_wire_ds_update must pipe its evidence_id
    // parameter through to mass_functions.evidence_id as the FK to the
    // evidence row that produced this BBA. Without this, the linking
    // script (scripts/link_mass_function_evidence.py) is the only path to
    // recover per-BBA provenance — and only on a best-effort basis.
    assert_eq!(
        stored.2,
        Some(evidence_id),
        "Phase 3: evidence_id parameter must round-trip into mass_functions.evidence_id"
    );
}
