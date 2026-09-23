//! `publish_or_log_conn`'s "or log" contract, tested where it is hardest to
//! honour: inside a caller's transaction.
//!
//! # The defect these arms pin
//!
//! The durable event INSERT is fire-and-forget by design — `create_strict` and
//! `supersede` both call it as `let _ = …` and a failure is a warn, never a
//! refused write. That contract is free on an autocommit pool checkout, where a
//! failed statement costs exactly that statement. It is NOT free inside a
//! transaction: PostgreSQL aborts the whole transaction on the first failed
//! statement, so a swallowed event failure turns the caller's NEXT statement into
//! `25P02 current transaction is aborted, commands ignored until end of
//! transaction block` — with the real cause only in a log line the caller never
//! sees. The write is lost AND the diagnostic is gone, which is strictly worse
//! than either honest alternative.
//!
//! It became reachable when the MCP submission path put a real transaction around
//! `create_strict`. Today it is otherwise LATENT: `events` is not RLS-enabled by
//! migration 077 and not in 079's FORCE set, so the INSERT is governed by GRANTs
//! alone. These arms are what keep it latent when `events` grows a policy or a
//! constraint — the failure is injected with a trigger for exactly that reason,
//! rather than waiting for a policy to supply one.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_db::{ClaimRepository, EventRepository};
use sqlx::PgPool;
use uuid::Uuid;

/// Make every `events` INSERT fail, deterministically.
///
/// A trigger and not a policy: the harness role owns the table and bypasses RLS,
/// so no policy could refuse it and an arm relying on one would assert nothing.
/// Never cleaned up — `#[sqlx::test]` throws the database away.
async fn refuse_every_event_insert(pool: &PgPool) {
    sqlx::query(
        "CREATE OR REPLACE FUNCTION refuse_event_for_test() RETURNS trigger
         LANGUAGE plpgsql AS $$
         BEGIN
             RAISE EXCEPTION 'refused events insert (test trigger)' USING ERRCODE = '42501';
         END $$",
    )
    .execute(pool)
    .await
    .expect("create the refusing trigger function");
    sqlx::query(
        "CREATE TRIGGER refuse_event_for_test BEFORE INSERT ON events
         FOR EACH ROW EXECUTE FUNCTION refuse_event_for_test()",
    )
    .execute(pool)
    .await
    .expect("install the refusing trigger");
}

/// A refused event INSERT must report `None` and leave the caller's transaction
/// USABLE.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_event_leaves_the_callers_transaction_usable(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "eventbesteffort").await;
    refuse_every_event_insert(&pool).await;

    let mut tx = pool.begin().await.expect("begin the caller's transaction");
    let published = EventRepository::publish_or_log_conn(
        &mut tx,
        "test.refused",
        Some(agent),
        &serde_json::json!({"probe": true}),
    )
    .await;
    assert!(
        published.is_none(),
        "CALIBRATION: the trigger must really have refused the INSERT, or the assertion below \
         passes for the wrong reason"
    );

    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&mut *tx)
        .await
        .expect(
            "the caller's transaction must still be usable. A `25P02 current transaction is \
             aborted` here is the defect: the swallowed event failure aborted a transaction the \
             caller believes is fine, and the caller's own write is now lost with no diagnostic.",
        );
    assert_eq!(one, 1);
    tx.commit().await.expect("the transaction must commit");
}

/// THE CALL SITE THAT MATTERS: `create_strict` publishes `claim.created` with
/// `let _ = …`, so a refused event must not take the claim with it.
#[sqlx::test(migrations = "../../migrations")]
async fn create_strict_still_lands_its_claim_when_the_event_is_refused(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "eventbesteffort2").await;
    refuse_every_event_insert(&pool).await;

    let content = format!("claim whose event was refused {}", Uuid::new_v4());
    let claim = Claim::new(
        content.clone(),
        AgentId::from_uuid(agent),
        [0u8; 32],
        TruthValue::new(0.5).expect("truth value"),
    );

    let mut tx = pool.begin().await.expect("begin");
    let stored = ClaimRepository::create_strict(
        &mut tx,
        &claim,
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect(
        "the claim INSERT succeeded and only its observability failed, so create_strict must \
             return Ok",
    );
    // One more statement on the same transaction: this is what fails with 25P02
    // when the event failure is not contained.
    sqlx::query("UPDATE claims SET labels = ARRAY['event-refused'] WHERE id = $1")
        .bind(Uuid::from(stored.id))
        .execute(&mut *tx)
        .await
        .expect("the transaction must still accept the statements that follow the event INSERT");
    tx.commit().await.expect("commit");

    let labels: Vec<String> = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(Uuid::from(stored.id))
        .fetch_one(&pool)
        .await
        .expect("read the committed claim back");
    assert_eq!(
        labels,
        vec!["event-refused".to_string()],
        "the whole transaction must have committed"
    );
    let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(&pool)
        .await
        .expect("count events");
    assert_eq!(
        events, 0,
        "CALIBRATION: no event landed, so the arm above really did exercise the failure path"
    );
}
