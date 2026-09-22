//! Repo-layer regression tests for backlog f6310444 — a label carrying
//! unexpanded shell syntax (`group:$EPICLAW_GROUP_ID`, claim 2a0125e2) must be
//! refused at the write, and the refusal must write NOTHING.
//!
//! WHY THIS FILE EXISTS AT ALL, rather than the `label_tests` module inside
//! `crates/epigraph-db/src/repos/claim.rs`: every test in that module is
//! `#[tokio::test] #[ignore]` (it connects to whatever `DATABASE_URL` names and
//! mutates it), so `cargo test -p epigraph-db` — the command the gate runs —
//! SKIPS them. The headline regression test for this backlog item was therefore
//! not CI-protected: a future edit could delete
//! `reject_unexpanded_labels(add)?` from the repo layer and the suite would stay
//! green. `#[sqlx::test]` gets a throwaway migrated database per test, needs no
//! `--ignored`, and is the convention already used by the sibling
//! `method_entity_type_edge.rs`.
//!
//! Direction proof (measured, see the branch report): with the
//! `reject_unexpanded_labels` calls removed from `ClaimRepository`, the two
//! `refuses_*` tests fail with the corrupted array actually stored; with the
//! guard also applied to the `remove` side — the plausible over-broad fix —
//! `still_removes_an_already_corrupted_label` fails instead.

use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::{ClaimRepository, DbError};
use sqlx::PgPool;
use uuid::Uuid;

/// The exact value observed on claim 2a0125e2.
const BAD_LABEL: &str = "group:$EPICLAW_GROUP_ID";

/// Seed an agent + claim on the throwaway database and return the claim id.
async fn seed_claim(pool: &PgPool) -> Uuid {
    let agent_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'label-test', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent");

    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ('label test claim', sha256('label-test'::bytea), 0.5, $1) \
         RETURNING id",
    )
    .bind(agent_id)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn stored_labels(pool: &PgPool, claim_id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("read labels")
}

/// An unexpanded shell variable in `add` must be refused AND must leave the
/// stored label array untouched — not even the well-formed sibling from the
/// same array may land.
#[sqlx::test(migrations = "../../migrations")]
async fn update_labels_refuses_unexpanded_shell_variable_and_writes_nothing(pool: PgPool) {
    let claim_id = seed_claim(&pool).await;
    ClaimRepository::update_labels(&pool, claim_id, &["keeper".into()], &[])
        .await
        .expect("seed a well-formed label");

    let result = ClaimRepository::update_labels(
        &pool,
        claim_id,
        &["good-label".into(), BAD_LABEL.into()],
        &[],
    )
    .await;

    assert!(
        matches!(result, Err(DbError::InvalidData { .. })),
        "expected InvalidData, got: {result:?}"
    );
    assert_eq!(
        stored_labels(&pool, claim_id).await,
        vec!["keeper".to_string()],
        "a refused label array must leave claims.labels byte-for-byte unchanged"
    );
}

/// The labels-at-creation path (`create_with_id_if_absent`, used by the ingest
/// executors) must refuse before the INSERT, so no claim row exists afterwards.
#[sqlx::test(migrations = "../../migrations")]
async fn create_with_id_if_absent_refuses_unexpanded_label_and_inserts_no_row(pool: PgPool) {
    let agent_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'label-create-test', 'system') \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed agent");

    let id = Uuid::new_v4();
    let content = "labels-at-creation guard subject";
    let result = ClaimRepository::create_with_id_if_absent(
        &pool,
        id,
        content,
        &[0x11u8; 32],
        agent_id,
        TruthValue::clamped(0.5),
        &["claim".into(), BAD_LABEL.into()],
        // `Inherited`, not a declared group: the guard under test runs BEFORE
        // the INSERT, so the row's tenancy is never reached — and a declared
        // group would make this test also depend on group seeding.
        epigraph_core::TenancyDecl::Inherited,
    )
    .await;

    assert!(
        matches!(result, Err(DbError::InvalidData { .. })),
        "expected InvalidData, got: {result:?}"
    );

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        rows, 0,
        "the guard must run before the INSERT, leaving no row behind"
    );
}

/// The `remove` side must NOT be validated: removal is the only remediation
/// path for the rows already carrying `group:$EPICLAW_GROUP_ID`.
///
/// Load-bearing in the other direction: this fails against the plausible
/// over-broad fix that validates `add` and `remove` alike, which would make the
/// existing corruption permanently unfixable through the API.
#[sqlx::test(migrations = "../../migrations")]
async fn update_labels_still_removes_an_already_corrupted_label(pool: PgPool) {
    let claim_id = seed_claim(&pool).await;

    // Seed the corruption the way it actually got there — a direct write,
    // bypassing the guard (the guard is what stops NEW ones).
    sqlx::query("UPDATE claims SET labels = ARRAY['backlog', $2] WHERE id = $1")
        .bind(claim_id)
        .bind(BAD_LABEL)
        .execute(&pool)
        .await
        .expect("seed the corruption");

    let after = ClaimRepository::update_labels(&pool, claim_id, &[], &[BAD_LABEL.into()])
        .await
        .expect("removing an already-corrupted label must remain possible");

    assert_eq!(after, vec!["backlog".to_string()]);
    assert_eq!(
        stored_labels(&pool, claim_id).await,
        vec!["backlog".to_string()]
    );
}

/// `patch_claim_atomic_conn` is the third caller-supplied label surface (MCP
/// `patch_claim`, HTTP PATCH `/claims/:id`). It must refuse inside the
/// transaction, so the properties/trace half of the same patch does not land
/// either.
#[sqlx::test(migrations = "../../migrations")]
async fn patch_claim_atomic_refuses_unexpanded_label_and_commits_nothing(pool: PgPool) {
    let claim_id = seed_claim(&pool).await;
    ClaimRepository::update_labels(&pool, claim_id, &["keeper".into()], &[])
        .await
        .expect("seed a well-formed label");

    let mut tx = pool.begin().await.expect("begin");
    let result = ClaimRepository::patch_claim_atomic_conn(
        &mut tx,
        ClaimId::from_uuid(claim_id),
        &epigraph_db::PatchClaimInput {
            trace_id: None,
            properties: Some(serde_json::json!({"patched": true})),
            add_labels: vec![BAD_LABEL.into()],
            remove_labels: vec![],
        },
    )
    .await;
    assert!(
        matches!(result, Err(DbError::InvalidData { .. })),
        "expected InvalidData, got: {result:?}"
    );
    drop(tx);

    assert_eq!(
        stored_labels(&pool, claim_id).await,
        vec!["keeper".to_string()]
    );
    let props: serde_json::Value =
        sqlx::query_scalar("SELECT COALESCE(properties, '{}'::jsonb) FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("read properties");
    assert_eq!(
        props.get("patched"),
        None,
        "the properties half of a refused patch must not commit; got {props}"
    );
}
