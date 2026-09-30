//! `epigraph-tenancy-backfill` under operator binding (migration 122): the
//! claims arm stamps a LINKED author's world-owned claims to the OPERATOR's
//! group (derived rows follow through 070's arm (d)), an unlinked author's to
//! its own personal group as before, and `verify` REPORTS (never fails on)
//! claims still owned by a linked author's own personal group.
//!
//! Driven through the real binary, as `backfill_idempotence.rs` is.
//!
//! Verified to fail:
//! * `owner_group_sql` reduced to `personal_group_sql` -> the linked author's
//!   claim (and its evidence) land in the author's own group;
//! * the REPORT loop removed from `verify` -> the stderr assertion fails.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-tenancy-backfill");

async fn run_backfill(pool: &PgPool, args: &[&str]) -> (i32, String) {
    let url = fixture::database_url_for(pool).await;
    let out = Command::new(BIN)
        .args(args)
        .env("DATABASE_URL", &url)
        .env("MAINTENANCE_DATABASE_URL", &url)
        .env("RUST_LOG", "warn")
        .output()
        .expect("spawn epigraph-tenancy-backfill");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

async fn owner_of(pool: &PgPool, table: &str, id: Uuid) -> Uuid {
    sqlx::query_scalar(&format!("SELECT owner_group_id FROM {table} WHERE id = $1"))
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("owner")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_backfill_stamps_a_linked_authors_claims_to_the_operators_group(pool: PgPool) {
    let (operator, operator_group) = fixture::seed_human_operator(&pool, "operator").await;
    let (linked, linked_group) = fixture::seed_agent_with_group(&pool, "linked").await;
    let (unlinked, unlinked_group) = fixture::seed_agent_with_group(&pool, "unlinked").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_retired_agent(&mut conn, linked, operator)
            .await
            .expect("retired link");
    }
    let c_linked = fixture::seed_public_claim(&pool, linked, "legacy by a linked author").await;
    let ev = fixture::seed_evidence(&pool, c_linked, "testimony").await;
    let c_unlinked = fixture::seed_public_claim(&pool, unlinked, "legacy by an unlinked one").await;

    let (code, stderr) = run_backfill(&pool, &["run"]).await;
    assert_eq!(code, 0, "run must complete:\n{stderr}");
    assert_eq!(
        owner_of(&pool, "claims", c_linked).await,
        operator_group,
        "a linked author's legacy claim belongs to its operator"
    );
    assert_eq!(
        owner_of(&pool, "evidence", ev).await,
        operator_group,
        "its derived row follows (070 arm (d))"
    );
    assert_eq!(
        owner_of(&pool, "claims", c_unlinked).await,
        unlinked_group,
        "an unlinked author keeps the personal-group fallback"
    );
    assert_ne!(operator_group, linked_group);

    // A claim the linked author's OWN group owns is declared, so verify passes,
    // and REPORTS it for `reown-linked`.
    let hash = Uuid::new_v4().as_bytes().repeat(2);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, 'written before the link', $2, 0.5, $3, true, 'public', $4)",
    )
    .bind(Uuid::new_v4())
    .bind(hash)
    .bind(linked)
    .bind(linked_group)
    .execute(&pool)
    .await
    .expect("personal-group claim");
    let (code, stderr) = run_backfill(&pool, &["verify"]).await;
    assert_eq!(code, 0, "the residue is a REPORT, not a failure:\n{stderr}");
    assert!(
        stderr.contains("REPORT: 1 row(s) in claims"),
        "verify must report the linked author's personal-group claim:\n{stderr}"
    );
}
