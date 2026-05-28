//! Round-trip test for `mass_functions.evidence_id` (Phase 3 of issue #197).
//!
//! Asserts that the column persists end-to-end:
//!   * `store_with_perspective(..., evidence_id=Some(id))` → row reads back
//!     `evidence_id = Some(id)`
//!   * A raw INSERT that omits the column lets the column default to NULL
//!     (it is NULL-able, no DEFAULT in migration 046)
//!   * Deleting the evidence row triggers `ON DELETE SET NULL` semantics:
//!     the mass_functions row stays, `evidence_id` flips to NULL.
//!
//! Layered against `source_strength_tests.rs` in `epigraph-mcp`, which
//! exercises the forward-write plumbing through `auto_wire_ds_update`.
//! This test pins the repo-layer signature and the migration's FK semantics.

use epigraph_db::{MassFunctionRepository, MassFunctionRow};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

fn distinct_hash(tag: u32) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[0] = (tag & 0xff) as u8;
    h[1] = ((tag >> 8) & 0xff) as u8;
    h[2] = ((tag >> 16) & 0xff) as u8;
    h
}

async fn seed_agent(pool: &PgPool, tag: u32) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind(distinct_hash(tag))
        .execute(pool)
        .await
        .expect("seed agent");
    agent_id
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid, tag: u32) -> Uuid {
    let claim_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current) \
         VALUES ($1, $2, $3, $4, 0.5, true)",
    )
    .bind(claim_id)
    .bind(format!("evidence-id-roundtrip-claim-{tag:x}"))
    .bind(distinct_hash(tag))
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    claim_id
}

async fn seed_frame(pool: &PgPool, tag: u32) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, '{\"TRUE\",\"FALSE\"}') RETURNING id",
    )
    .bind(format!("evidence-id-roundtrip-frame-{tag:x}"))
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

/// Insert an evidence row attached to the given claim. The `evidence_type`
/// is constrained by `evidence_type_valid` in migration 001 to one of:
/// document, observation, testimony, computation, reference, figure,
/// conversational. `signer_id` is nullable when `signature` is also NULL
/// (`evidence_signature_requires_signer` constraint), so we leave both
/// off — agent attribution is not part of the FK contract under test.
async fn seed_evidence(pool: &PgPool, claim_id: Uuid, tag: u32) -> Uuid {
    let evidence_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence (id, content_hash, evidence_type, claim_id) \
         VALUES ($1, $2, 'observation', $3)",
    )
    .bind(evidence_id)
    .bind(distinct_hash(tag))
    .bind(claim_id)
    .execute(pool)
    .await
    .expect("seed evidence");
    evidence_id
}

async fn fetch_row(pool: &PgPool, claim_id: Uuid, frame_id: Uuid) -> MassFunctionRow {
    let rows = MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id)
        .await
        .expect("get_for_claim_frame");
    assert_eq!(
        rows.len(),
        1,
        "expected exactly one BBA after a single store call, got {}",
        rows.len()
    );
    rows.into_iter().next().unwrap()
}

/// Happy path: store_with_perspective(..., evidence_id=Some(id)) persists
/// and reads back exactly. `perspective_id` is None here to keep the test
/// focused on the evidence_id round-trip; the production caller
/// (`auto_wire_ds_update` in ds_auto.rs) sets perspective_id to the same
/// evidence_id, but materializes the perspectives row via
/// `ensure_evidence_perspective` first. That FK plumbing is exercised by
/// `perspective_evidence_fk_tests.rs`; here we keep one variable.
#[sqlx::test(migrations = "../../migrations")]
async fn store_persists_evidence_id_with_null_perspective(pool: PgPool) {
    let agent = seed_agent(&pool, 0xF2_0001).await;
    let claim = seed_claim(&pool, agent, 0xF2_0002).await;
    let frame = seed_frame(&pool, 0xF2_0003).await;
    let evidence = seed_evidence(&pool, claim, 0xF2_0004).await;
    let masses = json!({"0": 0.6, "0,1": 0.4});

    MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        frame,
        Some(agent),
        None, // skip perspectives FK
        &masses,
        None,
        Some("auto_wire"),
        Some(1.0),
        Some("observation"),
        "intra",
        Some(evidence),
    )
    .await
    .expect("store evidence_id");

    let row = fetch_row(&pool, claim, frame).await;
    assert_eq!(
        row.evidence_id,
        Some(evidence),
        "evidence_id must round-trip on the BBA row"
    );
    assert_eq!(row.locality_tag, "intra");
}

/// `store()` wrapper also persists evidence_id (a `None` here, but proves
/// the wrapper threads through correctly).
#[sqlx::test(migrations = "../../migrations")]
async fn store_wrapper_threads_evidence_id_none(pool: PgPool) {
    let agent = seed_agent(&pool, 0xF3_0001).await;
    let claim = seed_claim(&pool, agent, 0xF3_0002).await;
    let frame = seed_frame(&pool, 0xF3_0003).await;
    let masses = json!({"0": 0.6, "0,1": 0.4});

    MassFunctionRepository::store(
        &pool,
        claim,
        frame,
        Some(agent),
        &masses,
        None,
        Some("test"),
        "unknown",
        None,
    )
    .await
    .expect("store wrapper");

    let row = fetch_row(&pool, claim, frame).await;
    assert!(
        row.evidence_id.is_none(),
        "evidence_id should be NULL when caller passes None"
    );
}

/// Verifies migration 046's nullability: a raw INSERT that omits
/// `evidence_id` from the column list lands NULL (column is nullable, no
/// DEFAULT). Every pre-Phase-3 legacy row will land here at deploy time.
#[sqlx::test(migrations = "../../migrations")]
async fn raw_insert_without_evidence_id_defaults_to_null(pool: PgPool) {
    let agent = seed_agent(&pool, 0xF4_0001).await;
    let claim = seed_claim(&pool, agent, 0xF4_0002).await;
    let frame = seed_frame(&pool, 0xF4_0003).await;
    let masses = json!({"0": 0.6, "0,1": 0.4});

    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(&masses)
    .execute(&pool)
    .await
    .expect("raw INSERT without evidence_id");

    let row = fetch_row(&pool, claim, frame).await;
    assert!(
        row.evidence_id.is_none(),
        "evidence_id must default to NULL when INSERT omits it"
    );
}

/// Verifies the FK behaviour: `ON DELETE SET NULL` flips the BBA row's
/// `evidence_id` to NULL when the evidence row is deleted, leaving the
/// BBA row intact. This is the Phase 3 retraction-safety semantic: the
/// BBA stays but loses its provenance pointer, so the combine path falls
/// back to `locality_tag` / `source_strength`.
#[sqlx::test(migrations = "../../migrations")]
async fn evidence_delete_sets_evidence_id_to_null(pool: PgPool) {
    let agent = seed_agent(&pool, 0xF5_0001).await;
    let claim = seed_claim(&pool, agent, 0xF5_0002).await;
    let frame = seed_frame(&pool, 0xF5_0003).await;
    let evidence = seed_evidence(&pool, claim, 0xF5_0004).await;
    let masses = json!({"0": 0.6, "0,1": 0.4});

    MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        frame,
        Some(agent),
        None,
        &masses,
        None,
        Some("auto_wire"),
        Some(1.0),
        Some("observation"),
        "intra",
        Some(evidence),
    )
    .await
    .expect("store evidence_id");

    // Pre-condition: evidence_id is set.
    let before = fetch_row(&pool, claim, frame).await;
    assert_eq!(before.evidence_id, Some(evidence));

    // Delete the evidence row. The `evidence_cascade_edges` trigger
    // (migration 001) cleans up edges; the FK on mass_functions is
    // `ON DELETE SET NULL`, so the BBA stays.
    //
    // Note: production deletes of evidence may go through a service layer
    // that does additional cleanup. This test verifies the SQL-level FK
    // contract independent of that — if a future migration changes the
    // ON DELETE clause to CASCADE, the assert below will fail and surface
    // the change in PR review rather than silently shrinking BBA counts.
    sqlx::query("DELETE FROM evidence WHERE id = $1")
        .bind(evidence)
        .execute(&pool)
        .await
        .expect("delete evidence row");

    let after = fetch_row(&pool, claim, frame).await;
    assert!(
        after.evidence_id.is_none(),
        "ON DELETE SET NULL must null evidence_id after evidence delete (got {:?})",
        after.evidence_id
    );
    // The locality_tag stays — it's the cached classification, not the FK.
    assert_eq!(
        after.locality_tag, "intra",
        "locality_tag is NOT cleared by evidence delete; it's the cache"
    );
}
