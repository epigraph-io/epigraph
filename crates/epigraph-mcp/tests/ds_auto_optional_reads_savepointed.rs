//! `ds_auto`'s optional calibration reads must not abort the transaction they
//! run in.
//!
//! Since the new-claim DS wiring moved inside the submission transaction, a
//! read written `.await.ok()` hid its error while PostgreSQL marked the whole
//! transaction aborted, so the NEXT statement failed with `current transaction
//! is aborted` (SQLSTATE 25P02), naming the wrong statement. The batch H-a
//! review found this in `ds_auto.rs`'s intra-locality, evidence-type-weight and
//! prior-BetP reads. They now run through
//! `ds_auto::optional_read_under_savepoint`, and this test pins its contract on
//! a read that is guaranteed to fail (`SELECT 1/0`) inside a real transaction:
//! the read is reported as absent AND the transaction is still usable.

use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_optional_read_leaves_the_transaction_usable(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");

    let value: Option<i32> = epigraph_mcp::tools::ds_auto::optional_read_under_savepoint(
        &mut tx,
        "division by zero probe",
        |c| {
            Box::pin(async move {
                sqlx::query_scalar::<_, i32>("SELECT 1/0")
                    .fetch_optional(c)
                    .await
            })
        },
    )
    .await
    .expect("only a savepoint failure is an Err");
    assert_eq!(value, None, "a failed optional read reads as absent");

    // The discriminating half: before the savepoint, this statement failed with
    // 25P02 because the division by zero had aborted the transaction.
    let after: i32 = sqlx::query_scalar("SELECT 41 + 1")
        .fetch_one(&mut *tx)
        .await
        .expect(
            "the enclosing transaction must still accept statements after a failed optional read",
        );
    assert_eq!(after, 42);

    // And a successful read still returns its value.
    let ok: Option<i32> = epigraph_mcp::tools::ds_auto::optional_read_under_savepoint(
        &mut tx,
        "constant probe",
        |c| {
            Box::pin(async move {
                sqlx::query_scalar::<_, i32>("SELECT 7")
                    .fetch_optional(c)
                    .await
            })
        },
    )
    .await
    .expect("savepoint");
    assert_eq!(ok, Some(7));

    tx.commit().await.expect("the transaction commits");
}
