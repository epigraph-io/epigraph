//! `Viewer::resolve` against a real schema.
//!
//! # Why this file exists
//!
//! `GroupMembershipRepository::list_live_for_agent` — the one query PR-03 adds
//! — uses runtime `sqlx::query_as` rather than the `query_as!` macro (it
//! returns an untyped tuple, matching every other query in that file), so
//! **nothing checks it at compile time**. `ViewerExtractor` is now attached to
//! the read handlers (PR-06/PR-07), but its two unit tests in
//! `epigraph-api/src/middleware/bearer.rs` both return before `resolve` is
//! reached. Without this file the query is executed by no *unit* test, and a column
//! rename in PR-04/05 would land as a runtime 500 on every authenticated
//! request with no test failing first.
//!
//! # What it pins
//!
//! * the query runs at all against the migrated schema (column names, types);
//! * `revoked_at IS NOT NULL` rows are excluded — the whole point of "live";
//! * the `writable` split is `admin`/`writer` and excludes `reader`, matching
//!   `group_memberships_role_check` (migration 060:245);
//! * an agent with no memberships resolves to a `Scoped` viewer over zero
//!   groups rather than an error — an empty group set is a correct answer.

use epigraph_db::{repos::GroupMembershipRepository, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

/// Insert an agent. `public_key` is unique, so derive it from the id.
async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

/// Insert a `team` group. `groups_public_key_shape` requires exactly 32 bytes
/// for `kind = 'team'`, and `did_key` is UNIQUE.
async fn seed_group(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, did_key, public_key, kind, display_name) \
         VALUES ($1, $2, $3, 'team', 'viewer-resolve-test')",
    )
    .bind(id)
    .bind(format!("did:key:viewer-resolve-{id}"))
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed group");
    id
}

/// One membership row. `revoked` writes `revoked_at = now()`, which is what
/// takes the row out of `idx_group_memberships_agent_live`'s partial predicate.
async fn seed_membership(pool: &PgPool, group_id: Uuid, agent_id: Uuid, role: &str, revoked: bool) {
    sqlx::query(
        "INSERT INTO group_memberships \
             (group_id, agent_id, wrapped_key_share, epoch, role, revoked_at) \
         VALUES ($1, $2, $3, 0, $4, CASE WHEN $5 THEN now() ELSE NULL END)",
    )
    .bind(group_id)
    .bind(agent_id)
    .bind(vec![0u8; 48])
    .bind(role)
    .bind(revoked)
    .execute(pool)
    .await
    .expect("seed membership");
}

#[sqlx::test(migrations = "../../migrations")]
async fn resolve_returns_live_groups_only_and_splits_writable(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let writer_group = seed_group(&pool).await;
    let reader_group = seed_group(&pool).await;
    let admin_group = seed_group(&pool).await;
    let revoked_group = seed_group(&pool).await;

    seed_membership(&pool, writer_group, agent, "writer", false).await;
    seed_membership(&pool, reader_group, agent, "reader", false).await;
    seed_membership(&pool, admin_group, agent, "admin", false).await;
    seed_membership(&pool, revoked_group, agent, "writer", true).await;

    // A second agent in the same groups must not bleed into the first's set.
    let other = seed_agent(&pool).await;
    let other_group = seed_group(&pool).await;
    seed_membership(&pool, other_group, other, "admin", false).await;

    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");

    assert_eq!(viewer.principal(), Some(agent));
    assert!(
        !viewer.is_bypass(),
        "resolve never produces a bypass viewer"
    );

    let mut bind = viewer
        .group_bind()
        .expect("a scoped viewer binds its groups")
        .to_vec();
    bind.sort_unstable();
    let mut want = vec![writer_group, reader_group, admin_group];
    want.sort_unstable();
    assert_eq!(
        bind, want,
        "the revoked membership must not appear, and another agent's \
         membership must not either"
    );

    let mut writable = viewer.writable_groups().to_vec();
    writable.sort_unstable();
    let mut want_writable = vec![writer_group, admin_group];
    want_writable.sort_unstable();
    assert_eq!(
        writable, want_writable,
        "`admin` and `writer` are write-capable; `reader` is not"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn resolve_of_an_agent_with_no_memberships_is_an_empty_scoped_viewer(pool: PgPool) {
    let agent = seed_agent(&pool).await;

    let viewer = Viewer::resolve(&pool, agent).await.expect("resolve");

    assert_eq!(viewer.principal(), Some(agent));
    assert!(!viewer.is_bypass());
    assert_eq!(
        viewer.group_bind(),
        Some(&[][..]),
        "no memberships is a correct answer, not an error and not a bypass"
    );
    assert!(viewer.writable_groups().is_empty());
}

/// The repository query itself, one layer below `resolve`: the projection and
/// the `revoked_at IS NULL` predicate. Pinned separately so a failure says
/// which of the two layers broke.
#[sqlx::test(migrations = "../../migrations")]
async fn list_live_for_agent_projects_group_id_and_role(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let live = seed_group(&pool).await;
    let dead = seed_group(&pool).await;
    seed_membership(&pool, live, agent, "reader", false).await;
    seed_membership(&pool, dead, agent, "admin", true).await;

    let rows = GroupMembershipRepository::list_live_for_agent(&pool, agent)
        .await
        .expect("list_live_for_agent");

    assert_eq!(rows, vec![(live, "reader".to_string())]);
}
