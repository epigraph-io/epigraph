//! `DerivationScopeRepository::cache_admissible` branch by branch (ruling
//! R-22, generalised to every claim in R-71).
//!
//! The recompute tests cannot separate the edge branch from the source-claim
//! branch: the edges trigger makes an edge from a private claim private, so
//! either check alone passes them. Here the edge's own visibility is set
//! against its source's after the trigger (the harness is a privileged
//! writer), so each branch is exercised alone. An orphan edge-factor row
//! (its edge deleted) is pinned as not admissible, as documented.
//!
//! The agreement test runs one recompute of a GROUP claim on the harness
//! (superuser) pool and one on an `epigraph_app` session stamped as a member,
//! where row security applies, and requires the same cached interval.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::derivation_scope::DerivationScopeRepository;
use epigraph_db::visibility::Viewer;
use epigraph_db::PgPool;
use epigraph_engine::edge_factor::{auto_wire_ds_for_edge, ensure_binary_frame, EdgeFactorOutcome};
use uuid::Uuid;

async fn with_interval(pool: &PgPool, claim: Uuid, bel: f64, pl: f64) {
    sqlx::query("UPDATE claims SET belief = $2, plausibility = $3 WHERE id = $1")
        .bind(claim)
        .bind(bel)
        .bind(pl)
        .execute(pool)
        .await
        .expect("set the source interval");
}

/// Wire `edge` as `viewer` and return the edge-factor row it wrote.
async fn wire(
    pool: &PgPool,
    viewer: &Viewer,
    signer: Uuid,
    edge: Uuid,
    from: Uuid,
    to: Uuid,
) -> Uuid {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = auto_wire_ds_for_edge(&mut conn, viewer, edge, signer, from, to, "supports")
        .await
        .expect("wire the edge factor");
    assert_eq!(out, EdgeFactorOutcome::Wired, "PREMISE: the edge wires");
    sqlx::query_scalar(
        "SELECT id FROM mass_functions \
          WHERE claim_id = $1 AND perspective_id = $2 AND combination_method = 'edge_factor'",
    )
    .bind(to)
    .bind(edge)
    .fetch_one(pool)
    .await
    .expect("the edge-factor row")
}

async fn set_edge_tenancy(pool: &PgPool, edge: Uuid, visibility: &str, owner: Uuid) {
    sqlx::query(
        "UPDATE edges SET visibility = $2, owner_group_id = $3, \
                co_owner_group_id = NULL \
          WHERE id = $1",
    )
    .bind(edge)
    .bind(visibility)
    .bind(owner)
    .execute(pool)
    .await
    .expect("set the edge's tenancy");
}

#[sqlx::test(migrations = "../../migrations")]
async fn each_derivation_source_is_checked_on_its_own(pool: PgPool) {
    let public = fixture::public_viewer(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "r22-adm-member").await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "r22-adm-author").await;
    let member_viewer = Viewer::resolve(&pool, member).await.expect("member viewer");
    ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary_truth");
    let world = fixture::world_group(&pool).await;

    let target = fixture::seed_public_claim(&pool, author, "r22 adm target").await;
    let public_a = fixture::seed_public_claim(&pool, author, "r22 adm public source a").await;
    let public_b = fixture::seed_public_claim(&pool, author, "r22 adm public source b").await;
    let private_src = fixture::seed_group_claim(&pool, member, group, "r22 adm private").await;
    for c in [public_a, public_b, private_src] {
        with_interval(&pool, c, 0.6, 0.8).await;
    }

    // Admissible: a public edge from a public claim.
    let ok_edge = fixture::seed_edge(&pool, public_a, target).await;
    let ok_row = wire(&pool, &public, author, ok_edge, public_a, target).await;

    // The EDGE branch alone: a public source, but the edge narrowed to a group.
    let narrow_edge = fixture::seed_edge(&pool, public_b, target).await;
    let narrow_edge_row = wire(&pool, &public, author, narrow_edge, public_b, target).await;
    set_edge_tenancy(&pool, narrow_edge, "group", group).await;

    // The SOURCE-CLAIM branch alone: the edge made public, its source private.
    let leaky_edge = fixture::seed_edge(&pool, private_src, target).await;
    let private_source_row = wire(
        &pool,
        &member_viewer,
        member,
        leaky_edge,
        private_src,
        target,
    )
    .await;
    set_edge_tenancy(&pool, leaky_edge, "public", world).await;

    // An orphan: the edge row is gone, nothing visible vouches for the BBA.
    let gone_source = fixture::seed_public_claim(&pool, author, "r22 adm gone source").await;
    with_interval(&pool, gone_source, 0.6, 0.8).await;
    let gone_edge = fixture::seed_edge(&pool, gone_source, target).await;
    let orphan_row = wire(&pool, &public, author, gone_edge, gone_source, target).await;
    sqlx::query("DELETE FROM edges WHERE id = $1")
        .bind(gone_edge)
        .execute(&pool)
        .await
        .expect("delete the edge");
    let orphan_left: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mass_functions WHERE id = $1)")
            .bind(orphan_row)
            .fetch_one(&pool)
            .await
            .expect("orphan row");
    assert!(orphan_left, "PREMISE: deleting the edge row leaves its BBA");

    let admitted = DerivationScopeRepository::cache_admissible(
        &pool,
        &[ok_row, narrow_edge_row, private_source_row, orphan_row],
    )
    .await
    .expect("cache_admissible");
    assert!(admitted.contains(&ok_row), "the all-public row is admitted");
    assert!(
        !admitted.contains(&narrow_edge_row),
        "a BBA through an edge narrower than the claim was admitted (edge branch)"
    );
    assert!(
        !admitted.contains(&private_source_row),
        "a BBA carrying a private source claim's belief through a public edge was admitted \
         (source-claim branch)"
    );
    assert!(
        !admitted.contains(&orphan_row),
        "an orphan edge-factor BBA was admitted"
    );
}
