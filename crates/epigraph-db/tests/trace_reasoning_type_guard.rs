//! `ReasoningTraceRepository::create_with_reasoning_type` refuses a
//! `reasoning_type` outside `REASONING_TYPES` in Rust, BEFORE the INSERT
//! (backlog e207bb6d).
//!
//! Postgres's `reasoning_type_valid` CHECK would refuse the same value, so the
//! pure unit test on the private validation helper cannot tell whether the
//! writer actually calls it. What the Rust-side guard buys is visible only
//! through the writer itself, inside a transaction (which is how
//! `write_submission` calls it): the refusal is the documented
//! `DbError::InvalidData`, nothing is written, and the transaction is still
//! usable afterwards. A CHECK violation instead aborts the transaction, so the
//! follow-up write in the same transaction fails with 25P02.

mod helpers;

use epigraph_core::domain::reasoning_trace::Methodology;
use epigraph_db::{AgentRepository, ClaimRepository, DbError, PgPool, ReasoningTraceRepository};
use helpers::{make_agent, make_claim, make_trace};
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_reasoning_type_is_refused_before_the_insert_and_leaves_the_transaction_usable(
    pool: PgPool,
) {
    let agent = AgentRepository::create(&pool, &make_agent(Some("u034 guard")))
        .await
        .expect("seed agent");
    let claim = ClaimRepository::create(
        &pool,
        &make_claim(agent.id, "u034: guard target claim", 0.7),
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("seed claim");

    let refused = make_trace(agent.id, Methodology::Instrumental, 0.8, "refused");
    let refused_id: Uuid = refused.id.into();
    let accepted = make_trace(agent.id, Methodology::Instrumental, 0.8, "accepted");
    let accepted_id: Uuid = accepted.id.into();

    let mut tx = pool.begin().await.expect("begin");

    match ReasoningTraceRepository::create_with_reasoning_type(
        &mut *tx,
        &refused,
        claim.id,
        "vibes",
        Some("direct_observation"),
    )
    .await
    {
        Err(DbError::InvalidData { reason }) => assert!(
            reason.contains("vibes"),
            "the refusal must name the rejected value: {reason}"
        ),
        other => panic!(
            "an out-of-CHECK reasoning_type must be refused as InvalidData before the \
             INSERT, got {other:?}"
        ),
    }

    // Same transaction: a CHECK-violating INSERT would have aborted it.
    ReasoningTraceRepository::create_with_reasoning_type(
        &mut *tx,
        &accepted,
        claim.id,
        "observational",
        Some("direct_observation"),
    )
    .await
    .expect("the transaction must still accept a valid write after the refusal");
    tx.commit().await.expect("commit");

    let rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, reasoning_type, properties->>'submitted_methodology' \
         FROM reasoning_traces WHERE claim_id = $1",
    )
    .bind(claim.id.as_uuid())
    .fetch_all(&pool)
    .await
    .expect("read traces");
    assert!(
        rows.iter().all(|(id, _, _)| *id != refused_id),
        "the refused trace must not have been written: {rows:?}"
    );
    assert_eq!(
        rows,
        vec![(
            accepted_id,
            "observational".to_string(),
            Some("direct_observation".to_string())
        )],
        "exactly the accepted trace is stored, with the chosen reasoning_type and the \
         submitted methodology"
    );
}
