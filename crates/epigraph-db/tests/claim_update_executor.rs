//! `ClaimRepository::update_truth_value` and `update_trace_id` run on ANY
//! executor (backlog 2dbf45f2).
//!
//! Each was two copies of one `UPDATE`: a `&PgPool` fn using `sqlx::query!`
//! and a `_conn` twin repeating it with runtime `sqlx::query` and a panicking
//! `Row::get` decode. Each pair is now ONE generic-executor fn, and the `_conn`
//! forms are thin wrappers over it. These tests pin both halves of that:
//!
//! * the base fn takes a transaction's connection, and its write lands INSIDE
//!   that transaction (the returned row carries the new value; a rollback
//!   leaves the stored row untouched). A `&PgPool`-only signature cannot be
//!   called this way at all;
//! * `NotFound` for a missing id is still reported on that executor;
//! * the `_conn` wrappers still accept `&mut tx` by deref coercion, which is
//!   the contract their callers in the MCP tools rely on.
//!
//! The pool path stays covered by `lineage_tests.rs`, which calls
//! `update_trace_id(&pool, ..)`.

mod helpers;

use epigraph_core::domain::reasoning_trace::Methodology;
use epigraph_core::{ClaimId, TenancyDecl, TruthValue};
use epigraph_db::{AgentRepository, ClaimRepository, DbError, PgPool, ReasoningTraceRepository};
use helpers::{make_agent, make_claim, make_trace};
use uuid::Uuid;

async fn stored_truth(pool: &PgPool, id: Uuid) -> f64 {
    sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read stored truth_value")
}

async fn stored_trace(pool: &PgPool, id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT trace_id FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read stored trace_id")
}

#[sqlx::test(migrations = "../../migrations")]
async fn update_truth_value_runs_on_a_transaction_and_rolls_back_with_it(pool: PgPool) {
    let agent = AgentRepository::create(&pool, &make_agent(Some("truth executor")))
        .await
        .unwrap();
    let claim = ClaimRepository::create(
        &pool,
        &make_claim(agent.id, "truth executor claim", 0.4),
        TenancyDecl::Inherited,
    )
    .await
    .unwrap();
    let id = claim.id.as_uuid();

    let mut tx = pool.begin().await.unwrap();
    let updated =
        ClaimRepository::update_truth_value(&mut *tx, claim.id, TruthValue::new(0.9).unwrap())
            .await
            .expect("update_truth_value on a transaction's connection");
    assert_eq!(updated.id, claim.id);
    assert_eq!(updated.content, "truth executor claim");
    assert_eq!(updated.agent_id, agent.id);
    assert!((updated.truth_value.value() - 0.9).abs() < 1e-12);
    tx.rollback().await.unwrap();

    assert!(
        (stored_truth(&pool, id).await - 0.4).abs() < 1e-12,
        "the UPDATE must have run inside the rolled-back transaction, not on another connection"
    );

    // The same fn on the pool (the `conventions.rs` caller's shape) commits.
    ClaimRepository::update_truth_value(&pool, claim.id, TruthValue::new(0.7).unwrap())
        .await
        .unwrap();
    assert!((stored_truth(&pool, id).await - 0.7).abs() < 1e-12);
}

#[sqlx::test(migrations = "../../migrations")]
async fn update_trace_id_runs_on_a_transaction_and_rolls_back_with_it(pool: PgPool) {
    let agent = AgentRepository::create(&pool, &make_agent(Some("trace executor")))
        .await
        .unwrap();
    let claim = ClaimRepository::create(
        &pool,
        &make_claim(agent.id, "trace executor claim", 0.6),
        TenancyDecl::Inherited,
    )
    .await
    .unwrap();
    let id = claim.id.as_uuid();
    let trace = ReasoningTraceRepository::create(
        &pool,
        &make_trace(agent.id, Methodology::Deductive, 0.8, "trace executor"),
        claim.id,
    )
    .await
    .unwrap();
    let before = stored_trace(&pool, id).await;
    assert_ne!(before, Some(trace.id.as_uuid()));

    let mut tx = pool.begin().await.unwrap();
    let updated = ClaimRepository::update_trace_id(&mut *tx, claim.id, trace.id)
        .await
        .expect("update_trace_id on a transaction's connection");
    assert_eq!(updated.id, claim.id);
    assert_eq!(updated.trace_id, Some(trace.id));
    assert!((updated.truth_value.value() - 0.6).abs() < 1e-12);
    tx.rollback().await.unwrap();

    assert_eq!(
        stored_trace(&pool, id).await,
        before,
        "the UPDATE must have run inside the rolled-back transaction, not on another connection"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_missing_claim_is_not_found_on_any_executor(pool: PgPool) {
    let missing = ClaimId::new();
    let agent = AgentRepository::create(&pool, &make_agent(Some("missing executor")))
        .await
        .unwrap();
    let owner = ClaimRepository::create(
        &pool,
        &make_claim(agent.id, "trace owner claim", 0.5),
        TenancyDecl::Inherited,
    )
    .await
    .unwrap();
    let trace = ReasoningTraceRepository::create(
        &pool,
        &make_trace(agent.id, Methodology::Deductive, 0.8, "missing executor"),
        owner.id,
    )
    .await
    .unwrap();

    let mut tx = pool.begin().await.unwrap();
    let err = ClaimRepository::update_truth_value(&mut *tx, missing, TruthValue::new(0.5).unwrap())
        .await
        .expect_err("no such claim");
    assert!(
        matches!(err, DbError::NotFound { id, .. } if id == missing.as_uuid()),
        "{err:?}"
    );
    let err = ClaimRepository::update_trace_id(&mut *tx, missing, trace.id)
        .await
        .expect_err("no such claim");
    assert!(
        matches!(err, DbError::NotFound { id, .. } if id == missing.as_uuid()),
        "{err:?}"
    );
    tx.rollback().await.unwrap();
}

/// The `_conn` wrappers keep their concrete `&mut PgConnection` parameter so
/// `&mut tx` still coerces; a generic `E` would not accept a `&mut Transaction`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_conn_wrappers_still_take_a_transaction_by_deref(pool: PgPool) {
    let agent = AgentRepository::create(&pool, &make_agent(Some("conn wrapper")))
        .await
        .unwrap();
    let claim = ClaimRepository::create(
        &pool,
        &make_claim(agent.id, "conn wrapper claim", 0.3),
        TenancyDecl::Inherited,
    )
    .await
    .unwrap();
    let trace = ReasoningTraceRepository::create(
        &pool,
        &make_trace(agent.id, Methodology::Inductive, 0.7, "conn wrapper"),
        claim.id,
    )
    .await
    .unwrap();

    let mut tx = pool.begin().await.unwrap();
    let a =
        ClaimRepository::update_truth_value_conn(&mut tx, claim.id, TruthValue::new(0.8).unwrap())
            .await
            .unwrap();
    assert!((a.truth_value.value() - 0.8).abs() < 1e-12);
    let b = ClaimRepository::update_trace_id_conn(&mut tx, claim.id, trace.id)
        .await
        .unwrap();
    assert_eq!(b.trace_id, Some(trace.id));
    assert!((b.truth_value.value() - 0.8).abs() < 1e-12);
    tx.commit().await.unwrap();

    assert!((stored_truth(&pool, claim.id.as_uuid()).await - 0.8).abs() < 1e-12);
    assert_eq!(
        stored_trace(&pool, claim.id.as_uuid()).await,
        Some(trace.id.as_uuid())
    );
}
