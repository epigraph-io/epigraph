//! `compound_write_guard::decide`, the `EPIGRAPH_COMPOUND_WRITE_GUARD`
//! decision behind the textless BBA writers (backlog 7435772c), on the
//! caller's stamped APPLICATION transaction, as the request path runs it.
//!
//! - The role is structure: a compound whose whole decomposition is private
//!   to another group is still a compound for a caller that can see none of
//!   it, so `refuse` refuses it (with no atoms listed). The inline role
//!   predicate read on this session finds no compound there.
//! - The listed atoms are the caller's: a hidden atom is not listed, and a
//!   visible leaf that is itself a compound (its decomposition hidden from
//!   the caller) is not listed either.
//! - An atom and a standalone claim are not compounds, in either mode.
//! - `warn` logs the caller and the writer, never the claim's content.
//!
//! Fixtures are seeded on the harness superuser pool.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_engine::belief_modes::CompoundWriteGuard;
use epigraph_engine::compound_write_guard::{decide, GuardDecision};
use sqlx::PgPool;
use uuid::Uuid;

async fn claim(pool: &PgPool, author: Uuid, group: Uuid, visibility: &str, what: &str) -> Uuid {
    let content = format!("7435772c guard {what} {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, $3, $4) RETURNING id",
    )
    .bind(&content)
    .bind(author)
    .bind(visibility)
    .bind(group)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// `parent -decomposes_to-> child`, in force, its tenancy forced to
/// `(visibility, group)`.
async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid, visibility: &str, group: Uuid) {
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, \
                            valid_from) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to', \
                 now() - interval '1 day') RETURNING id",
    )
    .bind(parent)
    .bind(child)
    .fetch_one(pool)
    .await
    .expect("seed decomposes_to");
    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(edge)
    .bind(visibility)
    .bind(group)
    .execute(pool)
    .await
    .expect("force edge tenancy");
}

#[tracing_test::traced_test]
#[sqlx::test(migrations = "../../migrations")]
async fn the_guard_decides_role_on_the_whole_graph_and_lists_only_the_callers_atoms(pool: PgPool) {
    let (caller, mine) = fixture::seed_agent_with_group(&pool, "7435772c-guard-caller").await;
    let (other, theirs) = fixture::seed_agent_with_group(&pool, "7435772c-guard-other").await;

    // A public compound whose only child, and the edge to it, are private to
    // another group.
    let hidden = claim(&pool, caller, mine, "public", "hidden compound").await;
    let hidden_child = claim(&pool, other, theirs, "group", "private only child").await;
    decomposes_to(&pool, hidden, hidden_child, "group", theirs).await;

    // A public compound with a visible atom, a hidden atom, and a visible
    // mid node whose own decomposition is hidden (a leaf for this caller,
    // a compound by structure).
    let mixed = claim(&pool, caller, mine, "public", "mixed compound").await;
    let seen = claim(&pool, caller, mine, "public", "visible atom").await;
    let unseen = claim(&pool, other, theirs, "group", "hidden atom").await;
    let mid = claim(&pool, caller, mine, "public", "mid node").await;
    let mid_child = claim(&pool, other, theirs, "group", "mid node's hidden child").await;
    decomposes_to(&pool, mixed, seen, "public", mine).await;
    decomposes_to(&pool, mixed, unseen, "public", mine).await;
    decomposes_to(&pool, mixed, mid, "public", mine).await;
    decomposes_to(&pool, mid, mid_child, "group", theirs).await;

    let standalone = claim(&pool, caller, mine, "public", "standalone").await;

    let viewer = Viewer::resolve(&pool, caller)
        .await
        .expect("resolve caller");
    let url = fixture::database_url_for(&pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let mut tx = scoped.begin_as(&viewer).await.expect("stamped transaction");
    let who: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(&mut *tx)
        .await
        .expect("session_user");
    assert_eq!(who, "epigraph_app");

    // The hidden compound: refused under `refuse`, accepted under `warn`,
    // with no atom listed either way.
    let refused = decide(
        &mut tx,
        &viewer,
        hidden,
        CompoundWriteGuard::Refuse,
        "test_writer",
        Some(caller),
    )
    .await
    .expect("decide hidden, refuse");
    let GuardDecision::Refuse(target) = refused else {
        panic!(
            "a compound whose decomposition the caller cannot see must still be refused under \
             refuse (role is structure): {refused:?}"
        );
    };
    assert_eq!(target.claim_id, hidden);
    assert!(target.visible_atoms.is_empty(), "{target:?}");
    assert_eq!(target.visible_atom_count, 0);

    let warned = decide(
        &mut tx,
        &viewer,
        hidden,
        CompoundWriteGuard::Warn,
        "test_writer",
        Some(caller),
    )
    .await
    .expect("decide hidden, warn");
    assert!(
        matches!(&warned, GuardDecision::Accept(t) if t.visible_atoms.is_empty()),
        "warn accepts the hidden compound and lists nothing: {warned:?}"
    );

    // The mixed compound: only the visible atom is listed.
    let mixed_decision = decide(
        &mut tx,
        &viewer,
        mixed,
        CompoundWriteGuard::Refuse,
        "test_writer",
        Some(caller),
    )
    .await
    .expect("decide mixed");
    let GuardDecision::Refuse(target) = mixed_decision else {
        panic!("the mixed compound is a compound: {mixed_decision:?}");
    };
    let listed: Vec<Uuid> = target.visible_atoms.iter().map(|a| a.id).collect();
    assert_eq!(
        listed,
        vec![seen],
        "only the caller's visible atom is listed: not the hidden atom {unseen}, and not the \
         visible mid node {mid}, which is itself a compound"
    );
    assert_eq!(target.visible_atom_count, 1);
    assert!(
        target.visible_atoms[0].content.contains("visible atom"),
        "{target:?}"
    );

    // Not compounds: an atom and a standalone claim, in either mode.
    for (id, what) in [(seen, "atom"), (standalone, "standalone")] {
        for mode in [CompoundWriteGuard::Warn, CompoundWriteGuard::Refuse] {
            let d = decide(&mut tx, &viewer, id, mode, "test_writer", Some(caller))
                .await
                .expect("decide non-compound");
            assert_eq!(d, GuardDecision::NotCompound, "{what} under {mode}");
        }
    }
    tx.commit().await.expect("commit");

    // The warn path logged the writer and the caller, and no content.
    assert!(logs_contain("textless BBA write on a compound accepted"));
    assert!(logs_contain("test_writer"));
    assert!(logs_contain(&caller.to_string()));
    assert!(
        !logs_contain("7435772c guard"),
        "the log must not carry claim content"
    );
}
