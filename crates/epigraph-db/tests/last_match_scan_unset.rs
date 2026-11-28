//! Every claim create path leaves `claims.last_match_scan_at` NULL (backlog
//! 42613caa).
//!
//! The column (migration 037) records when the cross-source sweep last
//! scanned a claim; the sweep picks seeds with `last_match_scan_at IS NULL OR
//! last_match_scan_at < now() - 7 days` and is the ONLY writer that may stamp
//! it. A create path that stamped it (a column copy, a `DEFAULT now()`, a
//! carried-over predecessor value) would make a new claim look already
//! scanned, and the post-write match scan would silently skip it for a week.
//!
//! One test per create path, each reading the column straight after the
//! write:
//! * `create_with_tx` (the legacy content-hash create, `create_conn`'s INSERT);
//! * `create_signed_reporting_conn` and `create_with_id_if_absent_signed_conn`,
//!   the two writes the document ingest's persist step
//!   (`persist_planned_claim` in epigraph-mcp, private to that crate) makes;
//! * `create_with_id_if_absent` (the pool entry point of the same INSERT);
//! * `create_strict` (the INSERT `create_or_get` reaches);
//! * the two INSERTs that write a successor naming `supersedes` (the
//!   register in `inherited_successor_insert_lint.rs`): the supersede act's
//!   and `evolve_step`'s, each with the PREDECESSOR stamped first, so a
//!   successor that copied its predecessor's column would be caught.
//!
//! Uses the non-macro `sqlx::query*` forms so the offline `.sqlx/` cache is
//! not extended.

use epigraph_core::{AgentId, Claim, ClaimId, TenancyDecl, TruthValue};
use epigraph_crypto::ContentHasher;
use epigraph_db::{ClaimRepository, SupersedeActor, SupersedeTool};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, sha256($1::text::bytea))")
        .bind(id)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

/// A claim with content no other row holds, so a legacy create INSERTS
/// rather than answering with an existing row.
fn fresh_claim(agent: Uuid) -> Claim {
    Claim::new(
        format!("last_match_scan_at subject {}", Uuid::new_v4()),
        AgentId::from_uuid(agent),
        [0u8; 32],
        TruthValue::clamped(0.5),
    )
}

async fn assert_unscanned(pool: &PgPool, id: Uuid, path: &str) {
    let stamp: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_match_scan_at FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap_or_else(|e| panic!("{path}: read the new row {id}: {e}"));
    assert_eq!(
        stamp, None,
        "{path} stamped last_match_scan_at on a new claim; only the \
         cross-source sweep may stamp it, or the post-write scan skips the claim"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_with_tx_leaves_last_match_scan_at_null(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let claim = fresh_claim(agent);
    let mut conn = pool.acquire().await.unwrap();
    let row = ClaimRepository::create_with_tx(&mut conn, &claim, TenancyDecl::Inherited)
        .await
        .expect("create_with_tx");
    let id: Uuid = row.id.into();
    assert_eq!(
        id,
        Uuid::from(claim.id),
        "a fresh content INSERTS its own row"
    );
    assert_unscanned(&pool, id, "create_with_tx").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_reporting_create_leaves_last_match_scan_at_null(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let claim = fresh_claim(agent);
    let mut conn = pool.acquire().await.unwrap();
    let (row, inserted) = ClaimRepository::create_signed_reporting_conn(
        &mut conn,
        &claim,
        TenancyDecl::Inherited,
        None,
    )
    .await
    .expect("create_signed_reporting_conn");
    assert!(inserted, "a fresh content INSERTS");
    assert_unscanned(&pool, row.id.into(), "create_signed_reporting_conn").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_with_id_if_absent_leaves_last_match_scan_at_null(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let id = Uuid::new_v4();
    let content = format!("if-absent subject {id}");
    let inserted = ClaimRepository::create_with_id_if_absent(
        &pool,
        id,
        &content,
        &ContentHasher::hash(content.as_bytes()),
        agent,
        TruthValue::clamped(0.5),
        &["claim".to_string()],
        TenancyDecl::Inherited,
    )
    .await
    .expect("create_with_id_if_absent");
    assert!(inserted, "a fresh id INSERTS");
    assert_unscanned(&pool, id, "create_with_id_if_absent").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn ingest_create_with_id_if_absent_signed_leaves_last_match_scan_at_null(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let id = Uuid::new_v4();
    let content = format!("ingest node subject {id}");
    let mut conn = pool.acquire().await.unwrap();
    let inserted = ClaimRepository::create_with_id_if_absent_signed_conn(
        &mut conn,
        id,
        &content,
        &ContentHasher::hash(content.as_bytes()),
        agent,
        TruthValue::clamped(0.5),
        &["claim".to_string()],
        TenancyDecl::Inherited,
        None,
    )
    .await
    .expect("create_with_id_if_absent_signed_conn");
    assert!(inserted, "a fresh id INSERTS");
    assert_unscanned(&pool, id, "create_with_id_if_absent_signed_conn").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_strict_leaves_last_match_scan_at_null(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let claim = fresh_claim(agent);
    let mut conn = pool.acquire().await.unwrap();
    let row = ClaimRepository::create_strict(&mut conn, &claim, TenancyDecl::Inherited)
        .await
        .expect("create_strict");
    assert_unscanned(&pool, row.id.into(), "create_strict").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn supersede_successor_leaves_last_match_scan_at_null(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let old: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, $2, 0.5, $3, true) RETURNING id",
    )
    .bind("supersede scan subject, old")
    .bind(ContentHasher::hash(b"supersede scan subject, old").as_slice())
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("seed the predecessor");
    // The sweep has scanned the predecessor: a successor that carried the
    // column over would look scanned too.
    sqlx::query("UPDATE claims SET last_match_scan_at = now() WHERE id = $1")
        .bind(old)
        .execute(&pool)
        .await
        .expect("stamp the predecessor");

    let (new_id, _) = ClaimRepository::supersede(
        &pool,
        ClaimId::from_uuid(old),
        "supersede scan subject, new",
        TruthValue::clamped(0.7),
        "last_match_scan_at successor test",
        SupersedeActor::new(agent, SupersedeTool::SupersedeClaim),
    )
    .await
    .expect("supersede");
    assert_ne!(new_id, old);
    assert_unscanned(&pool, new_id, "the supersede successor INSERT").await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_successor_leaves_last_match_scan_at_null(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             last_match_scan_at) \
         VALUES ($1, $2, 0.5, $3, true, now()) RETURNING id",
    )
    .bind("evolve scan subject, parent step")
    .bind(ContentHasher::hash(b"evolve scan subject, parent step").as_slice())
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("seed the scanned parent step");

    let res = ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(parent),
        "evolve scan subject, child step",
        "supersedes",
        Some("last_match_scan_at successor test"),
        2,
        agent,
    )
    .await
    .expect("evolve_step");
    assert_ne!(res.new_claim_id, parent);
    assert_unscanned(&pool, res.new_claim_id, "the evolve_step successor INSERT").await;
}
