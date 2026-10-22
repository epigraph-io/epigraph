//! `ClaimRepository::marked_duplicates_of`: the label-dedup `index_view` read.
//!
//! A marked duplicate leaves the index (it is not current) and keeps what it
//! knew. This read returns, for each canonical, every claim marked a duplicate
//! of it down a chain (a duplicate of a duplicate included), through in-force
//! dedup identity edges only, filtered by the viewer.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimRepository, DuplicateProvenance};
use sqlx::PgPool;
use uuid::Uuid;

async fn mark(pool: &PgPool, dup: Uuid, canonical: Uuid) -> epigraph_db::DedupRepair {
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::mark_duplicate_with_repair_attributed_conn(
        &mut conn,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
        &DuplicateProvenance::new("test", "shared_id"),
    )
    .await
    .expect("mark")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_index_view_reads_every_marked_duplicate_down_the_chain_and_nothing_else(pool: PgPool) {
    let (a, _) = fixture::seed_agent_with_group(&pool, "author").await;
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let c = fixture::seed_public_claim(&pool, a, "canonical").await;
    let d1 = fixture::seed_public_claim(&pool, a, "first duplicate").await;
    let d2 = fixture::seed_public_claim(&pool, a, "second duplicate").await;
    let plain = fixture::seed_public_claim(&pool, a, "a plain same_as neighbour").await;
    let undone = fixture::seed_public_claim(&pool, a, "a duplicate un-marked since").await;
    mark(&pool, d2, d1).await;
    mark(&pool, d1, c).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'same_as')",
    )
    .bind(plain)
    .bind(c)
    .execute(&pool)
    .await
    .expect("plain same_as");
    let r = mark(&pool, undone, c).await;
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::unmark_duplicate_with_reversal_conn(
        &mut conn,
        &bypass,
        ClaimId::from_uuid(undone),
        &r.revert,
    )
    .await
    .expect("unmark");

    let rows = ClaimRepository::marked_duplicates_of(&pool, &bypass, &[c], 100)
        .await
        .expect("index view");
    let got: Vec<(Uuid, Uuid)> = rows.iter().map(|r| (r.canonical, r.id)).collect();
    let mut want = vec![(c, d1), (c, d2)];
    want.sort();
    assert_eq!(
        got, want,
        "both levels, under the top canonical; nothing else"
    );
    assert!(rows.iter().all(|r| !r.content.is_empty()));

    // The read of a mid-chain claim starts there.
    let mid = ClaimRepository::marked_duplicates_of(&pool, &bypass, &[d1], 100)
        .await
        .expect("index view");
    assert_eq!(
        mid.iter().map(|r| (r.canonical, r.id)).collect::<Vec<_>>(),
        vec![(d1, d2)]
    );

    // The cap reports itself: cap + 1 rows come back when more exist.
    let capped = ClaimRepository::marked_duplicates_of(&pool, &bypass, &[c], 1)
        .await
        .expect("capped");
    assert_eq!(capped.len(), 2, "cap + 1 rows signal truncation");
}

/// A duplicate private to another group is not read by a stranger's viewer
/// (and is by a member's).
#[sqlx::test(migrations = "../../migrations")]
async fn the_index_view_is_filtered_by_the_viewer(pool: PgPool) {
    let (w, g) = fixture::seed_agent_with_group(&pool, "writer").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let c = fixture::seed_group_claim(&pool, w, g, "group canonical").await;
    let d = fixture::seed_group_claim(&pool, w, g, "group duplicate").await;
    mark(&pool, d, c).await;
    let member = Viewer::resolve(&pool, w).await.expect("viewer");
    let outsider = Viewer::resolve(&pool, stranger).await.expect("viewer");
    let seen = |v: Viewer| {
        let pool = pool.clone();
        async move {
            ClaimRepository::marked_duplicates_of(&pool, &v, &[c], 100)
                .await
                .expect("read")
                .len()
        }
    };
    assert_eq!(seen(member).await, 1);
    assert_eq!(seen(outsider).await, 0);
}
