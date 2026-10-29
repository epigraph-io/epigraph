#![cfg(feature = "db")]
//! GET /api/v1/claims/:id/history walks `claims.supersedes` backward to a root
//! and then forward. This file used to build the two loop shapes that walk
//! could follow — a self-supersede, and an X<->Y pair via `mark_duplicate` —
//! and assert it terminated on them.
//!
//! # Both shapes are now refused at the write path, so both arms are inverted
//!
//! - A self-supersede raises `OPL02` from the claims-path trigger added by
//!   migration 123 (`custodian_role.sql:1058-1063`), on INSERT and on any
//!   UPDATE that sets `supersedes` to the row's own id.
//! - An X<->Y dedup loop is refused by `mark_duplicate` itself: the first call
//!   retires X, and the second is rejected with "canonical <id> is not current;
//!   refusing to build a dedup chain onto a retired claim".
//!
//! So the arms assert the REFUSALS, and the walk's own protection —
//! `ClaimRepository::version_history`'s single viewer-filtered recursive CTE
//! with `depth < 100` on both recursive terms — is now defence for LEGACY rows
//! written before those guards rather than for anything a caller can create.
//! If either guard is ever removed, these arms fail and the cycle question
//! reopens explicitly instead of silently.
//!
//! `history_of_a_linear_chain_is_unchanged` is kept VERBATIM: it is a genuine
//! non-regression over main's CTE, which derives `superseded_by` from
//! `claims.supersedes` rather than positionally.
mod common;

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn pool_and_app() -> (
    sqlx::PgPool,
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    reqwest::Client,
) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    // This suite runs on the shared $DATABASE_URL database rather than on a
    // per-test one, so it must state its precondition instead of self-healing.
    // The tenancy series deleted `ensure_claim_encryption_table` precisely so
    // an unmigrated database fails loudly here rather than silently passing a
    // suite that tests nothing.
    let migrated: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.claim_encryption')::text")
            .fetch_one(&pool)
            .await
            .expect("probe the schema");
    assert!(
        migrated.is_some(),
        "$DATABASE_URL is not migrated. Run: \
         cargo run -p epigraph-api --bin epigraph-migrate"
    );
    let (addr, shutdown) = common::spawn_app(&url).await;
    // A looping handler never answers; the timeout turns that into a failure
    // instead of a hung test.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap();
    (pool, addr, shutdown, client)
}

async fn history(
    client: &reqwest::Client,
    addr: std::net::SocketAddr,
    claim_id: Uuid,
) -> serde_json::Value {
    // A bearer is not optional any more: the tenancy series moved 105
    // registrations from the public router to the protected one, and the
    // anonymous allowlist is `/health` and `/api/v1/openapi.json`. Without
    // this every arm below fails on a 401 that has nothing to do with cycles.
    let resp = client
        .get(format!("http://{addr}/api/v1/claims/{claim_id}/history"))
        .bearer_auth(common::mint_token_with_agent(
            &["claims:read"],
            Uuid::new_v4(),
        ))
        .send()
        .await
        .unwrap_or_else(|e| panic!("history for {claim_id} did not answer (cycle?): {e}"));
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

/// The test DB is shared, so leave no supersedes loop behind for other
/// suites' walks to trip over.
async fn unlink(pool: &sqlx::PgPool, ids: &[Uuid]) {
    sqlx::query("UPDATE claims SET supersedes = NULL WHERE id = ANY($1)")
        .bind(ids)
        .execute(pool)
        .await
        .unwrap();
}

fn version_ids(body: &serde_json::Value) -> Vec<Uuid> {
    body["versions"]
        .as_array()
        .expect("versions array")
        .iter()
        .map(|v| v["claim_id"].as_str().unwrap().parse().unwrap())
        .collect()
}

/// The `mark_duplicate` arm of this file, inverted — for the same reason as the
/// self-supersedes arm below.
///
/// This test used to build X -> Y then Y -> X and assert the walk survived the
/// loop. Main's `mark_duplicate` now refuses the second call outright:
/// "canonical <id> is not current; refusing to build a dedup chain onto a
/// retired claim". The first call retires X, so the call that would close the
/// loop can no longer be made, and the comment this arm used to carry — "both
/// calls pass mark_duplicate's own checks" — is no longer true of the tree.
///
/// With BOTH loop shapes refused at the write path, `version_history`'s
/// `depth < 100` cap is now defence for LEGACY rows written before these
/// guards, not for anything a caller can still create. That is worth stating
/// rather than deleting, because a future reader finding the cap with no
/// reachable cycle would reasonably wonder whether it is dead code.
#[tokio::test(flavor = "multi_thread")]
async fn a_mark_duplicate_cycle_cannot_be_created() {
    let (pool, addr, _shutdown, client) = pool_and_app().await;
    let x = common::seed_claim(&pool, "history cycle X").await;
    let y = common::seed_claim(&pool, "history cycle Y").await;

    // X -> Y retires X. This one still succeeds.
    ClaimRepository::mark_duplicate(&pool, ClaimId::from_uuid(x), ClaimId::from_uuid(y))
        .await
        .expect("the first dedup is legitimate");

    // Y -> X would close the loop onto the now-retired X, and is refused.
    let err = ClaimRepository::mark_duplicate(&pool, ClaimId::from_uuid(y), ClaimId::from_uuid(x))
        .await
        .expect_err("a dedup chain onto a retired claim must be refused");
    let text = err.to_string();
    assert!(
        text.contains("not current") && text.contains("mark_duplicate"),
        "expected mark_duplicate's retired-canonical refusal, got {text}"
    );

    // And the history of the one legitimate dedup still answers, bounded.
    let body = history(&client, addr, y).await;
    let ids = version_ids(&body);
    assert!(
        !ids.is_empty() && ids.len() <= 101,
        "the surviving chain must still answer within the cap, got {ids:?}"
    );

    unlink(&pool, &[x, y]).await;
}

/// The self-supersedes arm of this file, inverted.
///
/// This test used to build `supersedes = id` and assert the walk survived it.
/// Migration 123 (`custodian_role.sql:1058-1063`) made that state
/// unconstructible: the claims-path trigger raises `OPL02` on any INSERT or
/// any UPDATE that sets `supersedes` to the row's own id. So the walk no
/// longer needs to survive a self-loop — there cannot be one — and the honest
/// assertion is that the database refuses to make one. The multi-claim cycle
/// `mark_duplicate` can still build is covered above, and that arm is what now
/// exercises the depth cap.
#[tokio::test(flavor = "multi_thread")]
async fn a_self_supersedes_loop_cannot_be_created() {
    let (pool, _addr, _shutdown, _client) = pool_and_app().await;
    let z = common::seed_claim(&pool, "history self-loop Z").await;

    let err = sqlx::query("UPDATE claims SET supersedes = id WHERE id = $1")
        .bind(z)
        .execute(&pool)
        .await
        .expect_err("the claims-path trigger must refuse a self-supersedes write");

    let db = err.as_database_error().expect("a database error");
    assert_eq!(
        db.code().as_deref(),
        Some("OPL02"),
        "expected the operator-binding trigger's OPL02, got {err}"
    );
    assert!(
        db.message().contains("never supersedes"),
        "expected the self-supersedes message, got {}",
        db.message()
    );

    unlink(&pool, &[z]).await;
}

/// Non-regression: an ordinary A ← B chain still lists oldest first, links
/// forward, and reports the current version.
#[tokio::test(flavor = "multi_thread")]
async fn history_of_a_linear_chain_is_unchanged() {
    let (pool, addr, _shutdown, client) = pool_and_app().await;
    let a = common::seed_claim(&pool, "history chain A").await;
    let b = common::seed_claim(&pool, "history chain B").await;
    sqlx::query("UPDATE claims SET is_current = false, embedding = NULL WHERE id = $1")
        .bind(a)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE claims SET supersedes = $1 WHERE id = $2")
        .bind(a)
        .bind(b)
        .execute(&pool)
        .await
        .unwrap();

    for start in [a, b] {
        let body = history(&client, addr, start).await;
        assert_eq!(version_ids(&body), vec![a, b], "start {start}");
        assert_eq!(body["versions"][0]["superseded_by"], b.to_string());
        assert_eq!(
            body["versions"][1]["superseded_by"],
            serde_json::Value::Null
        );
        assert_eq!(body["current_version"], 2);
    }
}
