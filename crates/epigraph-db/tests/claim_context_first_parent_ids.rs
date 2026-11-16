//! `ClaimContextRepository::first_parent_ids` is viewer-filtered on both
//! ends (backlog 4e856a99).
//!
//! `recall_with_context(group_by_parent=true)` puts the returned parent id on
//! the wire as `parent_claim_id`, so a filter bug here discloses the id of a
//! claim the caller cannot read, not merely an ordering. Every edge in this
//! fixture is FORCED public (`seed_edge_owned_by`), so the edge predicate
//! passes everywhere and only the claim predicates can hide a row: a test
//! whose edges tracked their endpoints' tenancy would stay green with the
//! claim predicate deleted.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimContextRepository;
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

/// A public `decomposes_to` edge `parent -> child`.
async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid) {
    let world = fixture::world_group(pool).await;
    let id = fixture::seed_edge_owned_by(pool, parent, child, "public", world).await;
    sqlx::query("UPDATE edges SET relationship = 'decomposes_to' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("make the edge decomposes_to");
}

async fn created_days_ago(pool: &PgPool, claim: Uuid, days: i32) {
    sqlx::query("UPDATE claims SET created_at = now() - make_interval(days => $2) WHERE id = $1")
        .bind(claim)
        .bind(days)
        .execute(pool)
        .await
        .expect("age claim");
}

#[sqlx::test(migrations = "../../migrations")]
async fn first_parent_ids_never_names_or_follows_a_hidden_claim(pool: PgPool) {
    let (me, mine) = fixture::seed_agent_with_group(&pool, "first-parent-viewer").await;
    let (them, theirs) = fixture::seed_agent_with_group(&pool, "first-parent-foreign").await;
    let viewer = Viewer::resolve(&pool, me).await.expect("resolve viewer");

    // 1. A visible child with two parents: a FOREIGN one created first and a
    //    visible one created later. The first visible parent is the answer;
    //    `DISTINCT ON` must pick over the filtered rows, not before them.
    let child = fixture::seed_group_claim(&pool, me, mine, "fp child").await;
    let foreign_parent = fixture::seed_group_claim(&pool, them, theirs, "fp foreign parent").await;
    let visible_parent = fixture::seed_group_claim(&pool, me, mine, "fp visible parent").await;
    created_days_ago(&pool, foreign_parent, 2).await;
    created_days_ago(&pool, visible_parent, 1).await;
    decomposes_to(&pool, foreign_parent, child).await;
    decomposes_to(&pool, visible_parent, child).await;

    // 2. A visible child whose ONLY parent is foreign: absent from the map.
    let orphaned = fixture::seed_group_claim(&pool, me, mine, "fp orphaned child").await;
    let only_parent = fixture::seed_group_claim(&pool, them, theirs, "fp only parent").await;
    decomposes_to(&pool, only_parent, orphaned).await;

    // 3. A FOREIGN child with a visible parent: absent, so the caller cannot
    //    learn that a hidden claim decomposes from one of its own.
    let foreign_child = fixture::seed_group_claim(&pool, them, theirs, "fp foreign child").await;
    decomposes_to(&pool, visible_parent, foreign_child).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let got = ClaimContextRepository::first_parent_ids(
        &mut conn,
        &viewer,
        &[child, orphaned, foreign_child],
    )
    .await
    .expect("first_parent_ids");

    assert_eq!(
        got,
        HashMap::from([(child, visible_parent)]),
        "expected only child -> visible_parent. A foreign parent id here ({foreign_parent} or \
         {only_parent}) means the parent-claim predicate is missing; {foreign_child} as a key \
         means the child-claim predicate is"
    );

    // Calibration: once the viewer is also a member of the foreign group the
    // earliest parent wins and every child has one, so the absences above are
    // the filter, not the fixture.
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(theirs)
    .bind(me)
    .execute(&pool)
    .await
    .expect("join the foreign group");
    let everyone = Viewer::resolve(&pool, me).await.expect("re-resolve viewer");
    let all = ClaimContextRepository::first_parent_ids(
        &mut conn,
        &everyone,
        &[child, orphaned, foreign_child],
    )
    .await
    .expect("first_parent_ids as a member of both groups");
    assert_eq!(
        all,
        HashMap::from([
            (child, foreign_parent),
            (orphaned, only_parent),
            (foreign_child, visible_parent),
        ]),
        "calibration: unfiltered, every child has its earliest parent"
    );
}
