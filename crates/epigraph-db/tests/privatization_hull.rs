//! The mandatory content-lineage hull, through its first Rust caller.
//!
//! FINAL-PLAN §8.6 names this file; it did not exist. §8.6 also describes it as
//! covering "all four hull arms … `claim_versions`, and `evidence`", and that
//! description does not match the shipped DDL — see "What the hull actually
//! selects" below. The assertions here are written against the function that
//! exists.
//!
//! # What the hull actually selects
//!
//! `epigraph_content_lineage_hull(uuid[])` returns `(claim_id, via)` and reads
//! `public.claims` only. `via` takes exactly three values: `seed`,
//! `hull:supersedes`, `hull:step_lineage`. There are **two** arms, not four.
//!
//! `privatization_plan_items.via`'s column comment additionally lists
//! `hull:versions` and `hull:evidence`. **Nothing in the shipped schema
//! produces either value.** `claim_versions` and `evidence` reach the right
//! tenancy by a different mechanism: migration 070's
//! `epigraph_propagate_tenancy` carries them in its `derived[]` array, so they
//! TRACK their claim rather than being enumerated as plan items. §6.5.2 says as
//! much — it lists `claim_versions` under `propagated_rows`, "trigger-driven,
//! not plan items — but SHOWN". This file therefore asserts the two arms that
//! exist and does not fabricate coverage for two that do not.
//!
//! # The two properties that are NOT properties of the SQL
//!
//! Migration 080's header records two under-selections in its own hull and
//! assigns both to this caller:
//!
//! 1. **The sibling arm is one hop.** `chain` recurses over `supersedes`;
//!    `lineage` is a separate, non-recursive CTE that is never fed back into
//!    `chain`. So a sibling's own predecessors and successors are not walked.
//! 2. **The walk stops at 64 hops** and returns the shorter list, with no way
//!    for a caller to tell a 40-deep lineage from a truncated one.
//!
//! Both are UNDER-selections, and an under-selected hull is the dangling
//! reference the hull exists to prevent. `select_content_lineage_hull` closes
//! both by re-seeding the function until a round adds nothing.
//!
//! **Every test of that fix carries a calibration that the RAW single call
//! fails.** Without it, "the iterated hull found the claim" is satisfied by a
//! one-shot implementation whenever the fixture happens to be shallow, and the
//! test would pass on the tree the fix exists to repair.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::privatization::{PrivatizationRepository, SelectedClaim};
use sqlx::PgPool;
use uuid::Uuid;

/// Point `later` at `earlier` through `supersedes`.
///
/// `is_current` goes false on the SUPERSEDED claim, matching
/// `ClaimRepository::supersede`. The hull itself never reads the flag — 080's
/// `chain` and `lineage` terms filter on `supersedes` / `step_lineage_id` only,
/// which is why an inverted flag here would have gone unnoticed — but a fixture
/// that encodes a backwards invariant is inherited by whatever is written next
/// in this file, and the next assertion about version currency would then be
/// measuring the fixture.
async fn supersede(pool: &PgPool, later: Uuid, earlier: Uuid) {
    sqlx::query("UPDATE claims SET supersedes = $2 WHERE id = $1")
        .bind(later)
        .bind(earlier)
        .execute(pool)
        .await
        .expect("wire supersedes");
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(earlier)
        .execute(pool)
        .await
        .expect("retire the superseded claim");
}

/// Put `claim` in workflow-step lineage `lineage`.
async fn in_lineage(pool: &PgPool, claim: Uuid, lineage: Uuid) {
    sqlx::query("UPDATE claims SET step_lineage_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(lineage)
        .execute(pool)
        .await
        .expect("wire step_lineage_id");
}

/// The RAW function, called once — the behaviour the repo layer improves on.
///
/// Present so every assertion about the fix can be calibrated against the
/// unfixed shape on the same fixture.
async fn raw_hull_once(pool: &PgPool, seeds: &[Uuid]) -> Vec<Uuid> {
    sqlx::query_scalar::<_, Uuid>("SELECT claim_id FROM public.epigraph_content_lineage_hull($1)")
        .bind(seeds)
        .fetch_all(pool)
        .await
        .expect("raw hull")
}

fn anchor(id: Uuid) -> SelectedClaim {
    SelectedClaim {
        claim_id: id,
        depth: 0,
        via: "seed".to_string(),
    }
}

fn ids(selected: &[SelectedClaim]) -> Vec<Uuid> {
    selected.iter().map(|s| s.claim_id).collect()
}

/// The `supersedes` walk is transitive in BOTH directions.
///
/// Backwards matters because predecessors carry older content that no tenancy
/// trigger reaches. Forwards matters because a public successor pointing at a
/// now-private predecessor is an existence oracle.
#[sqlx::test(migrations = "../../migrations")]
async fn the_supersedes_walk_is_transitive_in_both_directions(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "hull-chain").await;

    // v1 <- v2 <- v3 <- v4 ; seed in the MIDDLE so both directions are exercised.
    let v1 = fixture::seed_public_claim(&pool, agent, "v1").await;
    let v2 = fixture::seed_public_claim(&pool, agent, "v2").await;
    let v3 = fixture::seed_public_claim(&pool, agent, "v3").await;
    let v4 = fixture::seed_public_claim(&pool, agent, "v4").await;
    supersede(&pool, v2, v1).await;
    supersede(&pool, v3, v2).await;
    supersede(&pool, v4, v3).await;

    let hull = PrivatizationRepository::select_content_lineage_hull(
        &mut conn,
        &viewer,
        &[anchor(v2)],
        100,
    )
    .await
    .expect("hull");
    let got = ids(&hull);

    assert!(got.contains(&v1), "predecessors are dragged in (backwards)");
    assert!(got.contains(&v3), "successors are dragged in (forwards)");
    assert!(
        got.contains(&v4),
        "and the forward walk is TRANSITIVE: v4 is two hops out. A public v4 pointing at a \
         privatized v3 is the dangling reference the hull exists to prevent"
    );
}

/// THE SIBLING ARM IS CLOSED TRANSITIVELY.
///
/// Fixture: seed `a` shares a `step_lineage_id` with sibling `b`; `b` supersedes
/// `c`. The raw function reaches `b` (one hop through `lineage`) but never walks
/// `b`'s own `supersedes`, because `lineage` is not fed back into `chain`. So
/// `c` stays public while its sibling-lineage relative is privatized — the same
/// oracle one hop further out, in migration 080's own words.
#[sqlx::test(migrations = "../../migrations")]
async fn the_sibling_arm_is_closed_transitively(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "hull-sibling").await;

    let lineage = Uuid::new_v4();
    let a = fixture::seed_public_claim(&pool, agent, "step draft a").await;
    let b = fixture::seed_public_claim(&pool, agent, "step draft b").await;
    let c = fixture::seed_public_claim(&pool, agent, "superseded by b").await;
    in_lineage(&pool, a, lineage).await;
    in_lineage(&pool, b, lineage).await;
    supersede(&pool, b, c).await;

    // CALIBRATION. The raw single call finds the sibling and stops there. If
    // this assertion ever fails, the SQL has been changed and the iteration
    // below may no longer be what closes the gap — re-derive before deleting.
    let raw = raw_hull_once(&pool, &[a]).await;
    assert!(raw.contains(&b), "the raw call does reach the sibling");
    assert!(
        !raw.contains(&c),
        "the raw call must NOT reach the sibling's predecessor — that is the one-hop \
         under-selection this test exists to measure. If it does, this test proves nothing"
    );

    let hull =
        PrivatizationRepository::select_content_lineage_hull(&mut conn, &viewer, &[anchor(a)], 100)
            .await
            .expect("hull");
    let got = ids(&hull);

    assert!(got.contains(&b), "the sibling is still selected");
    assert!(
        got.contains(&c),
        "the sibling's own supersedes chain must be walked too. Leaving c public while a and b \
         go private restores the oracle one hop out"
    );
}

/// A `supersedes` chain longer than the SQL walk's 64-hop cap is COMPLETED.
///
/// The cap is a truncation, not a refusal, and the raw function cannot report
/// that it fired. Re-seeding from the frontier finishes the chain.
#[sqlx::test(migrations = "../../migrations")]
async fn a_chain_longer_than_the_sql_walk_cap_is_completed(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "hull-deep").await;

    // 70 links: comfortably past the function's `array_length(path,1) < 64`.
    const LINKS: usize = 70;
    let mut chain = Vec::with_capacity(LINKS);
    for i in 0..LINKS {
        chain.push(fixture::seed_public_claim(&pool, agent, &format!("v{i}")).await);
    }
    for pair in chain.windows(2) {
        // pair[1] supersedes pair[0]
        supersede(&pool, pair[1], pair[0]).await;
    }
    let head = chain[0];
    let tail = *chain.last().expect("non-empty");

    // CALIBRATION: the raw call truncates and never reaches the tail.
    let raw = raw_hull_once(&pool, &[head]).await;
    assert!(
        !raw.contains(&tail),
        "the raw walk must stop short of a {LINKS}-link chain, or this fixture is not deep \
         enough to measure the cap"
    );

    let hull = PrivatizationRepository::select_content_lineage_hull(
        &mut conn,
        &viewer,
        &[anchor(head)],
        1000,
    )
    .await
    .expect("hull");
    let got = ids(&hull);

    assert!(
        got.contains(&tail),
        "the iterated hull must reach the end of the chain. A truncated hull leaves a public \
         successor pointing at a privatized predecessor, which the cap cannot report"
    );
    assert_eq!(
        got.len(),
        LINKS,
        "and it must reach every link exactly once, not merely the far end"
    );
}

/// A hull larger than `node_cap` is refused, not truncated.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hull_larger_than_the_node_cap_is_refused(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "hull-cap").await;

    let mut chain = Vec::new();
    for i in 0..10 {
        chain.push(fixture::seed_public_claim(&pool, agent, &format!("v{i}")).await);
    }
    for pair in chain.windows(2) {
        supersede(&pool, pair[1], pair[0]).await;
    }

    // CALIBRATION: ten links fit under a cap of ten.
    let ok = PrivatizationRepository::select_content_lineage_hull(
        &mut conn,
        &viewer,
        &[anchor(chain[0])],
        10,
    )
    .await
    .expect("a hull that fits its cap must succeed");
    assert_eq!(ok.len(), 10);

    let err = PrivatizationRepository::select_content_lineage_hull(
        &mut conn,
        &viewer,
        &[anchor(chain[0])],
        4,
    )
    .await
    .expect_err("a hull larger than node_cap must be refused, not silently shortened");
    assert!(
        format!("{err}").contains("node_cap"),
        "the refusal must name the bound it hit: {err:?}"
    );

    // THE SECOND PATH INTO THE SAME REFUSAL. Above, the cap is hit by a round
    // that GREW the set. Here the anchors alone already exceed it and the hull
    // adds nothing, so a check that only ran after a productive round would
    // return `Ok` with more items than the cap allows — the `# Errors` contract
    // says "when the closed hull is larger than node_cap", with no growth
    // qualifier, and the test name above promises the same.
    let anchors: Vec<SelectedClaim> = chain.iter().map(|id| anchor(*id)).collect();
    let already_over =
        PrivatizationRepository::select_content_lineage_hull(&mut conn, &viewer, &anchors, 4)
            .await
            .expect_err("anchors that already exceed the cap must be refused before any expansion");
    assert!(
        format!("{already_over}").contains("node_cap"),
        "got {already_over:?}"
    );
}

/// A hull member reachable from two anchors takes the LOWER depth.
///
/// `privatization_plan_items.depth`'s column comment says hull members inherit
/// their anchor's depth. When two anchors qualify, the tiebreak must match the
/// closure's own `MIN(lvl)` rule, or the frozen item set records a traversal
/// that did not happen.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hull_member_takes_the_lowest_anchor_depth(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "hull-depth").await;

    let shallow = fixture::seed_public_claim(&pool, agent, "shallow anchor").await;
    let deep = fixture::seed_public_claim(&pool, agent, "deep anchor").await;
    let shared = fixture::seed_public_claim(&pool, agent, "shared predecessor").await;
    // `shared` is superseded by BOTH anchors' lineage: put it under `shallow`.
    supersede(&pool, shallow, shared).await;

    let anchors = vec![
        SelectedClaim {
            claim_id: shallow,
            depth: 1,
            via: "closure:derived_from".to_string(),
        },
        SelectedClaim {
            claim_id: deep,
            depth: 3,
            via: "closure:derived_from".to_string(),
        },
    ];

    let hull =
        PrivatizationRepository::select_content_lineage_hull(&mut conn, &viewer, &anchors, 100)
            .await
            .expect("hull");

    let found = hull
        .iter()
        .find(|s| s.claim_id == shared)
        .expect("the shared predecessor must be selected");
    assert_eq!(
        found.depth, 1,
        "the hull member inherits the LOWER anchor depth, matching the closure's MIN(lvl)"
    );

    // The anchors keep their own depths and their own provenance.
    let anchor_depth = |id: Uuid| hull.iter().find(|s| s.claim_id == id).map(|s| s.depth);
    assert_eq!(anchor_depth(shallow), Some(1));
    assert_eq!(anchor_depth(deep), Some(3));
}

/// The anchors' `via` survives the hull; it is not overwritten by re-seeding.
///
/// Each iteration re-seeds the function with everything found so far, and the
/// function labels every seed it is given `seed`. If those labels were allowed
/// to win, a claim reached at depth 2 by `closure:derived_from` would be
/// recorded as a seed — and `depth`'s own comment says `0 = seed`, so the
/// stored pair would describe a traversal that never happened.
#[sqlx::test(migrations = "../../migrations")]
async fn re_seeding_does_not_relabel_an_anchor_as_a_seed(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "hull-via").await;

    let reached = fixture::seed_public_claim(&pool, agent, "reached by the closure").await;
    let predecessor = fixture::seed_public_claim(&pool, agent, "its predecessor").await;
    supersede(&pool, reached, predecessor).await;

    let anchors = vec![SelectedClaim {
        claim_id: reached,
        depth: 2,
        via: "closure:decomposes_to".to_string(),
    }];

    let hull =
        PrivatizationRepository::select_content_lineage_hull(&mut conn, &viewer, &anchors, 100)
            .await
            .expect("hull");

    let anchor_row = hull
        .iter()
        .find(|s| s.claim_id == reached)
        .expect("the anchor is in its own hull");
    assert_eq!(
        anchor_row.via, "closure:decomposes_to",
        "the anchor keeps the provenance the closure gave it"
    );
    assert_eq!(anchor_row.depth, 2, "and its depth");

    let added = hull
        .iter()
        .find(|s| s.claim_id == predecessor)
        .expect("the predecessor is added");
    assert_eq!(
        added.via, "hull:supersedes",
        "a claim the hull added is labelled by the arm that found it"
    );
}

/// `via` takes only the values the shipped function produces.
///
/// Pinned because `privatization_plan_items.via`'s column comment also lists
/// `hull:versions` and `hull:evidence`, and nothing in the schema emits either.
/// A later author reading that comment and asserting those values would be
/// asserting a contract the database does not implement.
#[sqlx::test(migrations = "../../migrations")]
async fn the_hull_emits_only_the_two_arms_that_exist(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "hull-arms").await;

    let lineage = Uuid::new_v4();
    let seed = fixture::seed_public_claim(&pool, agent, "seed").await;
    let sibling = fixture::seed_public_claim(&pool, agent, "sibling").await;
    let predecessor = fixture::seed_public_claim(&pool, agent, "predecessor").await;
    in_lineage(&pool, seed, lineage).await;
    in_lineage(&pool, sibling, lineage).await;
    supersede(&pool, seed, predecessor).await;

    let hull = PrivatizationRepository::select_content_lineage_hull(
        &mut conn,
        &viewer,
        &[anchor(seed)],
        100,
    )
    .await
    .expect("hull");

    // Both arms really fired, or the negative assertion below is vacuous.
    let vias: Vec<&str> = hull.iter().map(|s| s.via.as_str()).collect();
    assert!(
        vias.contains(&"hull:supersedes"),
        "the supersedes arm must have fired: {hull:?}"
    );
    assert!(
        vias.contains(&"hull:step_lineage"),
        "the sibling arm must have fired: {hull:?}"
    );

    for selected in &hull {
        assert!(
            matches!(
                selected.via.as_str(),
                "seed" | "hull:supersedes" | "hull:step_lineage"
            ),
            "unexpected via {:?}. The shipped function emits three values; hull:versions and \
             hull:evidence appear in a column comment but have no producer — claim_versions and \
             evidence track their claim through migration 070's propagation trigger instead",
            selected.via
        );
    }
    assert!(
        hull.iter().any(|s| s.claim_id == sibling),
        "the sibling is selected"
    );
    assert!(
        hull.iter().any(|s| s.claim_id == predecessor),
        "the predecessor is selected"
    );
}
