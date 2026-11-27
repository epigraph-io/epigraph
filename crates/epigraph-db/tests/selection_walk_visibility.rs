//! `EdgeRepository::claim_neighbors_for_selection` (backlog 02d9e9a1: one
//! step of a share / publicize selection walk) neither follows an edge nor
//! names a claim the viewer cannot read, by its OWN spliced predicates.
//!
//! It runs here on the superuser pool, where row security does not apply,
//! so the `{VISIBILITY:c}` and `{EDGE_VISIBILITY:e}` fragments are the only
//! filter. The app-role tests in `epigraph-mcp`
//! (`visibility_selection_app_role.rs`) cannot tell a dropped fragment from
//! row security doing the same job. Each edge's tenancy is forced
//! (`seed_edge_owned_by`), so the claim predicate and the edge predicate are
//! tested apart: an edge the viewer reads to a claim it does not, and an
//! edge it does not read to a claim it does.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::BTreeSet;

use epigraph_db::visibility::Viewer;
use epigraph_db::EdgeRepository;
use sqlx::PgPool;
use uuid::Uuid;

/// Alice's root R has three outgoing `supports` edges and one incoming:
///
/// * R -> M, her own claim, over an edge of her group: followed;
/// * R -> H, Carol's private claim, over an edge forced into Alice's group:
///   the edge reads, the claim does not, so H is not named;
/// * R -> P, Carol's public claim, over an edge forced into Carol's group:
///   the claim reads, the edge does not, so P is not reached;
/// * I -> R, Alice's own claim, over an edge of her group: followed only
///   when incoming edges are.
///
/// Verified to fail with the claim fragment removed (H is named) and with
/// the edge fragments removed (P is reached).
#[sqlx::test(migrations = "../../migrations")]
async fn a_selection_step_follows_and_names_only_what_the_viewer_reads(pool: PgPool) {
    let (alice, home) = fixture::seed_agent_with_group(&pool, "walk-alice").await;
    let (carol, carols) = fixture::seed_agent_with_group(&pool, "walk-carol").await;
    let r = fixture::seed_group_claim(&pool, alice, home, "the root").await;
    let m = fixture::seed_group_claim(&pool, alice, home, "her own step").await;
    let i = fixture::seed_group_claim(&pool, alice, home, "her own support").await;
    let h = fixture::seed_group_claim(&pool, carol, carols, "carol's private step").await;
    let p = fixture::seed_public_claim(&pool, carol, "carol's public step").await;
    fixture::seed_edge_owned_by(&pool, r, m, "group", home).await;
    fixture::seed_edge_owned_by(&pool, r, h, "group", home).await;
    fixture::seed_edge_owned_by(&pool, r, p, "group", carols).await;
    fixture::seed_edge_owned_by(&pool, i, r, "group", home).await;

    let alice_v = Viewer::resolve(&pool, alice).await.expect("resolve alice");
    let step = |outgoing: bool, incoming: bool| {
        let pool = pool.clone();
        let v = &alice_v;
        async move {
            EdgeRepository::claim_neighbors_for_selection(
                &pool,
                v,
                &[r],
                &["supports"],
                outgoing,
                incoming,
                100,
            )
            .await
            .expect("walk step")
            .into_iter()
            .map(|(from, to, relationship, is_current)| {
                assert_eq!(from, r);
                assert_eq!(relationship, "supports");
                assert!(is_current);
                to
            })
            .collect::<BTreeSet<Uuid>>()
        }
    };
    assert_eq!(step(true, false).await, BTreeSet::from([m]));
    assert_eq!(step(false, true).await, BTreeSet::from([i]));
    assert_eq!(step(true, true).await, BTreeSet::from([m, i]));

    // Calibration: a viewer in Carol's group reads H and P, and the edges
    // forced into her group, so the seeding is not what hides them.
    let carol_v = Viewer::resolve(&pool, carol).await.expect("resolve carol");
    let rows = EdgeRepository::claim_neighbors_for_selection(
        &pool,
        &carol_v,
        &[r],
        &["supports"],
        true,
        false,
        100,
    )
    .await
    .expect("carol's step");
    let reached: BTreeSet<Uuid> = rows.into_iter().map(|row| row.1).collect();
    assert_eq!(
        reached,
        BTreeSet::from([p]),
        "carol reads P and its edge; H's edge is alice's group's, R -> M is alice's"
    );
}
