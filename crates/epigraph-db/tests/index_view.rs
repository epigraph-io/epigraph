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
    let elsewhere = fixture::seed_public_claim(&pool, a, "another canonical").await;
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
    // Retired by another act, so only the edge filter can keep it out.
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(plain)
        .execute(&pool)
        .await
        .expect("retire the plain neighbour");
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
    drop(conn);
    // Re-marked onto another claim: non-current, with a RETRACTED dedup
    // identity edge to `c`, so only the in-force filter keeps it out of `c`.
    mark(&pool, undone, elsewhere).await;

    let rows = ClaimRepository::marked_duplicates_of(&pool, &bypass, &[c], 100)
        .await
        .expect("index view")
        .rows;
    let got: Vec<(Uuid, Uuid)> = rows.iter().map(|r| (r.canonical, r.id)).collect();
    let mut want = vec![(c, d1), (c, d2)];
    want.sort();
    assert_eq!(
        got, want,
        "both levels, under the top canonical; nothing else"
    );
    for row in &rows {
        let want = if row.id == d1 {
            "first duplicate"
        } else {
            "second duplicate"
        };
        assert_eq!(row.content, want);
    }
    let moved = ClaimRepository::marked_duplicates_of(&pool, &bypass, &[elsewhere], 100)
        .await
        .expect("index view")
        .rows;
    assert_eq!(
        moved.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![undone],
        "the re-marked duplicate is read under its current canonical only"
    );

    // The read of a mid-chain claim starts there.
    let mid = ClaimRepository::marked_duplicates_of(&pool, &bypass, &[d1], 100)
        .await
        .expect("index view")
        .rows;
    assert_eq!(
        mid.iter().map(|r| (r.canonical, r.id)).collect::<Vec<_>>(),
        vec![(d1, d2)]
    );

    // The cap reports itself: cap + 1 rows come back when more exist.
    let capped = ClaimRepository::marked_duplicates_of(&pool, &bypass, &[c], 1)
        .await
        .expect("capped")
        .rows;
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
                .rows
                .len()
        }
    };
    assert_eq!(seen(member).await, 1);
    assert_eq!(seen(outsider).await, 0);
}

/// The realistic leak: a PUBLIC canonical with a duplicate private to a group.
/// A stranger reads the canonical but not the duplicate; a member reads both.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_duplicate_of_a_public_canonical_is_read_only_by_its_group(pool: PgPool) {
    let (w, g) = fixture::seed_agent_with_group(&pool, "writer").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let c = fixture::seed_public_claim(&pool, w, "public canonical").await;
    let d = fixture::seed_group_claim(&pool, w, g, "private duplicate").await;
    mark(&pool, d, c).await;
    let member = Viewer::resolve(&pool, w).await.expect("viewer");
    let outsider = Viewer::resolve(&pool, stranger).await.expect("viewer");
    let member_rows = ClaimRepository::marked_duplicates_of(&pool, &member, &[c], 100)
        .await
        .expect("read")
        .rows;
    assert_eq!(
        member_rows.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![d]
    );
    let outsider_rows = ClaimRepository::marked_duplicates_of(&pool, &outsider, &[c], 100)
        .await
        .expect("read")
        .rows;
    assert!(outsider_rows.is_empty(), "{outsider_rows:?}");
}

/// The walk bound reports itself at the repository, and only for what the
/// viewer reads. A chain one longer than the bound (c <- d1 <- ... <- d17,
/// the deepest link private to a group): read from `c` by a viewer that
/// reads everything it is `chain_truncated`, with the bound's worth of rows
/// and never the link past it; read from `d1` it fits the bound and is not
/// truncated; read from `c` by a stranger, who cannot read the deepest link,
/// it is not truncated either, so the flag does not betray a row the viewer
/// may not see. A group member reads the flag as the bypass viewer does.
#[sqlx::test(migrations = "../../migrations")]
async fn a_chain_past_the_walk_bound_is_flagged_only_for_a_viewer_who_reads_it(pool: PgPool) {
    let (w, g) = fixture::seed_agent_with_group(&pool, "writer").await;
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "stranger").await;
    let (_scoped, bypass) = fixture::bypass(&pool).await;
    let bound =
        usize::try_from(epigraph_db::repos::claim::MAX_DUPLICATE_CHAIN_DEPTH).expect("bound");
    let c = fixture::seed_public_claim(&pool, w, "canonical").await;
    // chain[0] = d1 .. chain[bound] = the link past the bound (private).
    let mut chain = Vec::with_capacity(bound + 1);
    for i in 1..=bound {
        chain.push(fixture::seed_public_claim(&pool, w, &format!("link {i}")).await);
    }
    let past = fixture::seed_group_claim(&pool, w, g, "the link past the bound").await;
    chain.push(past);
    // Deepest first, so each canonical is current when marked onto.
    for k in (1..=bound).rev() {
        mark(&pool, chain[k], chain[k - 1]).await;
    }
    mark(&pool, chain[0], c).await;

    let whole = ClaimRepository::marked_duplicates_of(&pool, &bypass, &[c], 100)
        .await
        .expect("read");
    assert!(whole.chain_truncated, "one past the bound is reported");
    assert_eq!(whole.rows.len(), bound, "{:?}", whole.rows);
    assert!(
        whole.rows.iter().all(|r| r.id != past),
        "the link past the bound is never returned"
    );

    let from_d1 = ClaimRepository::marked_duplicates_of(&pool, &bypass, &[chain[0]], 100)
        .await
        .expect("read");
    assert!(
        !from_d1.chain_truncated,
        "a chain that fits is not truncated"
    );
    assert_eq!(from_d1.rows.len(), bound);
    assert!(from_d1.rows.iter().any(|r| r.id == past));

    let outsider = Viewer::resolve(&pool, stranger).await.expect("viewer");
    let seen = ClaimRepository::marked_duplicates_of(&pool, &outsider, &[c], 100)
        .await
        .expect("read");
    assert!(
        !seen.chain_truncated,
        "a link the viewer cannot read does not set the flag"
    );
    assert_eq!(seen.rows.len(), bound, "every public link is still read");

    let member = Viewer::resolve(&pool, w).await.expect("viewer");
    assert!(
        ClaimRepository::marked_duplicates_of(&pool, &member, &[c], 100)
            .await
            .expect("read")
            .chain_truncated
    );
}
