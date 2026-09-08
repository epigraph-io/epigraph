//! Integration tests for `ClaimRepository::get_by_id_with_labels`.
//!
//! Regression coverage for the `get_claim` TOCTOU race: the old MCP handler
//! fetched a claim's core fields and its labels via two separate,
//! unsynchronized queries (`get_by_id` then `get_labels`), so a concurrent
//! `update_labels` between the two round trips could return labels
//! inconsistent with the claim row already read. `get_by_id_with_labels`
//! reads both from a single SQL statement, which is inherently consistent
//! under Postgres MVCC.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn insert_test_agent(pool: &PgPool, agent_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO agents (id, public_key, created_at, updated_at)
           VALUES ($1, sha256($1::text::bytea), NOW(), NOW())
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("upsert agent");
}

fn make_claim(content: &str, agent_id: Uuid) -> Claim {
    Claim::new(
        content.to_string(),
        AgentId::from_uuid(agent_id),
        [0u8; 32],
        TruthValue::new(0.5).unwrap(),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_by_id_with_labels_returns_none_when_no_row(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;

    // Seed a DECOY that must NOT be returned. On the shared database this arm
    // used to run against, some sibling arm's rows happened to supply this
    // role; that discrimination was an accident of execution order, not a
    // property of the test. `#[sqlx::test]` hands us an empty table, so without
    // an explicit decoy `is_none()` would be satisfied by there being nothing
    // to return at all — deleting the `WHERE id = $1` predicate from
    // `get_by_id_with_labels` would still pass. The decoy makes the predicate
    // the only reason the result is None.
    let decoy_agent = Uuid::new_v4();
    insert_test_agent(&pool, decoy_agent).await;
    let decoy = ClaimRepository::create(
        &pool,
        &make_claim(&format!("decoy {}", Uuid::new_v4()), decoy_agent),
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("create decoy");

    let found =
        ClaimRepository::get_by_id_with_labels(&pool, &viewer, epigraph_core::ClaimId::new())
            .await
            .expect("query call");

    assert!(found.is_none(), "expected None, got {:?}", found.is_some());

    // The decoy is real, visible to this viewer, and would have been returned
    // by an unfiltered query — otherwise the assertion above proves nothing.
    assert!(
        ClaimRepository::get_by_id_with_labels(&pool, &viewer, decoy.id)
            .await
            .expect("query call")
            .is_some(),
        "decoy must be retrievable by its own id, or it cannot discriminate"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_by_id_with_labels_matches_separate_calls(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let claim = make_claim(&format!("atomic read {}", Uuid::new_v4()), agent_id);
    let created = ClaimRepository::create(&pool, &claim, epigraph_core::TenancyDecl::Inherited)
        .await
        .expect("create");

    ClaimRepository::update_labels(
        &pool,
        created.id.as_uuid(),
        &["backlog".to_string(), "atomic".to_string()],
        &[],
    )
    .await
    .expect("seed labels");

    // Seed a second LABELLED claim under a different agent. Without it the
    // per-test database holds exactly one labelled claim, so dropping the
    // claim_id predicate from `get_labels` would return that same row's labels
    // and the `new_sorted == ["atomic", "backlog"]` assertion would still pass.
    // The decoy's labels are disjoint, so any leak changes the result.
    let decoy_agent = Uuid::new_v4();
    insert_test_agent(&pool, decoy_agent).await;
    let decoy = ClaimRepository::create(
        &pool,
        &make_claim(&format!("decoy labels {}", Uuid::new_v4()), decoy_agent),
        epigraph_core::TenancyDecl::Inherited,
    )
    .await
    .expect("create decoy");
    ClaimRepository::update_labels(&pool, decoy.id.as_uuid(), &["decoy-label".to_string()], &[])
        .await
        .expect("seed decoy labels");

    let (via_new, labels_via_new) =
        ClaimRepository::get_by_id_with_labels(&pool, &viewer, created.id)
            .await
            .expect("get_by_id_with_labels")
            .expect("claim exists");

    let via_old = ClaimRepository::get_by_id(&pool, &viewer, created.id)
        .await
        .expect("get_by_id")
        .expect("claim exists");
    let labels_via_old = ClaimRepository::get_labels(&pool, &viewer, created.id)
        .await
        .expect("get_labels");

    assert_eq!(via_new.id, via_old.id);
    assert_eq!(via_new.content, via_old.content);
    assert_eq!(via_new.agent_id, via_old.agent_id);
    assert_eq!(via_new.is_current, via_old.is_current);
    assert_eq!(via_new.supersedes, via_old.supersedes);

    let mut new_sorted = labels_via_new.clone();
    new_sorted.sort();
    let mut old_sorted = labels_via_old.clone();
    old_sorted.sort();
    assert_eq!(new_sorted, old_sorted);
    assert_eq!(
        new_sorted,
        vec!["atomic".to_string(), "backlog".to_string()]
    );
}
