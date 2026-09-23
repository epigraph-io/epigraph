//! `epigraph_privatization_closure`, through its first Rust caller.
//!
//! FINAL-PLAN §8.6 names this file. It did not exist: a `find` over
//! `crates/epigraph-db/tests` returned `privatization_authz.rs` (PR-18a) and
//! `privatization_boundary.rs` (PR-13) and nothing else, so this is a new file.
//!
//! # What is under test is the CALLER, not the SQL
//!
//! Migration 080 ships the traversal and defers two decisions upward by name:
//! the edge-type tiers, and overflow detection. Both are refusals, and a
//! refusal cannot live in a `LANGUAGE sql` function that has no way to report
//! one. So the properties this file pins are properties of
//! `repos/privatization.rs`, exercised end-to-end against the real function.
//!
//! # The node-cap case is the one that would pass vacuously
//!
//! `epigraph_privatization_closure`'s final `LIMIT p_node_cap` carries **no
//! `ORDER BY`**. A test that asserted "at most `node_cap` rows come back" would
//! therefore pass against the truncating implementation and against the
//! refusing one, and would be satisfied by the very behaviour §3.1 forbids. The
//! assertion here is that the call **fails**, and the calibration immediately
//! above it is that the same corpus succeeds under a cap one larger — without
//! that pair, "it refused" is indistinguishable from "it was broken".

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::repos::privatization::{
    ClosureDirection, ClosureRequest, PrivatizationRepository, SelectionError, SelectionRefusal,
    MAX_TRAVERSAL_DEPTH, STRUCTURAL_EDGE_TYPES,
};
use sqlx::PgPool;
use uuid::Uuid;

/// An edge carrying a caller-chosen `relationship`, left for migration 070's
/// trigger to stamp.
async fn seed_rel(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, $2, 'claim', $3, 'claim', $4)",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
    id
}

fn types(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_string()).collect()
}

/// A structural edge type is refused, and the refusal is reachable for every
/// member of the list rather than for a representative one.
#[sqlx::test(migrations = "../../migrations")]
async fn a_structural_edge_type_is_refused(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "closure-structural").await;
    let seed = fixture::seed_public_claim(&pool, agent, "seed").await;

    for structural in STRUCTURAL_EDGE_TYPES {
        let edge_types = types(&[structural]);
        let err = PrivatizationRepository::select_closure(
            &mut conn,
            &viewer,
            ClosureRequest {
                seeds: &[seed],
                edge_types: &edge_types,
                direction: ClosureDirection::Both,
                max_depth: 3,
                node_cap: 100,
            },
        )
        .await
        .expect_err("a structural edge type must be refused");

        assert!(
            matches!(
                err,
                SelectionError::Refused(SelectionRefusal::StructuralEdgeType { .. })
            ),
            "'{structural}' points at a container; traversing it privatizes everything that \
             shares the container. Got {err:?}"
        );
    }
}

/// The refusal is case-insensitive.
///
/// Migration 011 documents live rows carrying `DERIVED_FROM` alongside
/// `derived_from`. A tier gate matching one spelling would let a request
/// spelled the other way through to the traversal it exists to refuse.
#[sqlx::test(migrations = "../../migrations")]
async fn the_structural_refusal_is_case_insensitive(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "closure-case").await;
    let seed = fixture::seed_public_claim(&pool, agent, "seed").await;

    let shouty = types(&["WITHIN_FRAME"]);
    let err = PrivatizationRepository::select_closure(
        &mut conn,
        &viewer,
        ClosureRequest {
            seeds: &[seed],
            edge_types: &shouty,
            direction: ClosureDirection::Both,
            max_depth: 3,
            node_cap: 100,
        },
    )
    .await
    .expect_err("an uppercase structural type must be refused too");
    assert!(matches!(
        err,
        SelectionError::Refused(SelectionRefusal::StructuralEdgeType { .. })
    ));
}

/// The traversal matches `DERIVED_FROM` and `derived_from` alike.
///
/// Both directions are asserted from ONE request, so this cannot pass by the
/// closure happening to match nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn the_traversal_matches_both_case_spellings(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "closure-spelling").await;

    let seed = fixture::seed_public_claim(&pool, agent, "seed").await;
    let lower = fixture::seed_public_claim(&pool, agent, "reached via lowercase").await;
    let upper = fixture::seed_public_claim(&pool, agent, "reached via uppercase").await;
    seed_rel(&pool, seed, lower, "derived_from").await;
    seed_rel(&pool, seed, upper, "DERIVED_FROM").await;

    let edge_types = types(&["derived_from"]);
    let selected = PrivatizationRepository::select_closure(
        &mut conn,
        &viewer,
        ClosureRequest {
            seeds: &[seed],
            edge_types: &edge_types,
            direction: ClosureDirection::Out,
            max_depth: 3,
            node_cap: 100,
        },
    )
    .await
    .expect("closure");

    let ids: Vec<Uuid> = selected.iter().map(|s| s.claim_id).collect();
    assert!(ids.contains(&lower), "the lowercase edge must be followed");
    assert!(
        ids.contains(&upper),
        "the uppercase edge must be followed too: migration 011 records tens of thousands of \
         rows in that spelling, so matching one case under-selects silently"
    );
}

/// A cycle terminates and reports each claim exactly once.
///
/// `max_depth` is `MAX_TRAVERSAL_DEPTH` — the largest value the system will
/// accept — rather than the arbitrary `10` an earlier revision used. The point
/// of the arm is that path-array cycle control, not the depth bound, is what
/// stops the walk, so the depth must be comfortably larger than the 3-claim
/// cycle; 6 is, and 10 is now refused by FINAL-PLAN §3.1's ceiling. Written as
/// the constant so a future change to the ceiling moves this arm with it instead
/// of turning it into a test of the ceiling.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cycle_terminates_and_reports_each_claim_once(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "closure-cycle").await;

    let a = fixture::seed_public_claim(&pool, agent, "a").await;
    let b = fixture::seed_public_claim(&pool, agent, "b").await;
    let c = fixture::seed_public_claim(&pool, agent, "c").await;
    seed_rel(&pool, a, b, "derived_from").await;
    seed_rel(&pool, b, c, "derived_from").await;
    seed_rel(&pool, c, a, "derived_from").await;

    let edge_types = types(&["derived_from"]);
    let selected = PrivatizationRepository::select_closure(
        &mut conn,
        &viewer,
        ClosureRequest {
            seeds: &[a],
            edge_types: &edge_types,
            direction: ClosureDirection::Out,
            max_depth: MAX_TRAVERSAL_DEPTH,
            node_cap: 100,
        },
    )
    .await
    .expect("a cycle must terminate, not exhaust the node cap");

    let mut ids: Vec<Uuid> = selected.iter().map(|s| s.claim_id).collect();
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(before, ids.len(), "each claim appears once: {selected:?}");
    assert_eq!(ids.len(), 3, "the whole cycle is selected");
}

/// `max_depth` bounds the walk, and the bound is the documented one: a claim
/// exactly `max_depth` hops out is IN, one further is OUT.
#[sqlx::test(migrations = "../../migrations")]
async fn max_depth_bounds_the_walk_inclusively(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "closure-depth").await;

    // A chain: c0 -> c1 -> c2 -> c3.
    let mut chain = Vec::new();
    for i in 0..4 {
        chain.push(fixture::seed_public_claim(&pool, agent, &format!("c{i}")).await);
    }
    for pair in chain.windows(2) {
        seed_rel(&pool, pair[0], pair[1], "derived_from").await;
    }

    let edge_types = types(&["derived_from"]);
    let selected = PrivatizationRepository::select_closure(
        &mut conn,
        &viewer,
        ClosureRequest {
            seeds: &[chain[0]],
            edge_types: &edge_types,
            direction: ClosureDirection::Out,
            max_depth: 2,
            node_cap: 100,
        },
    )
    .await
    .expect("closure");

    let ids: Vec<Uuid> = selected.iter().map(|s| s.claim_id).collect();
    assert!(ids.contains(&chain[2]), "depth 2 is inside max_depth = 2");
    assert!(
        !ids.contains(&chain[3]),
        "depth 3 is outside max_depth = 2; the bound is on hops taken, not on hops attempted"
    );

    // `depth` must be the real distance, not a constant.
    let depth_of = |id: Uuid| selected.iter().find(|s| s.claim_id == id).map(|s| s.depth);
    assert_eq!(depth_of(chain[0]), Some(0), "a seed is depth 0");
    assert_eq!(depth_of(chain[1]), Some(1));
    assert_eq!(depth_of(chain[2]), Some(2));
}

/// Exceeding `node_cap` REFUSES. It does not return a truncated selection.
///
/// The calibration is the first half: the same corpus and the same request
/// succeed under a cap that fits. Without it a refusal proves only that
/// something went wrong.
#[sqlx::test(migrations = "../../migrations")]
async fn exceeding_the_node_cap_refuses_rather_than_truncating(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "closure-cap").await;

    // A star: one seed with five children. Six claims in total.
    let seed = fixture::seed_public_claim(&pool, agent, "seed").await;
    for i in 0..5 {
        let child = fixture::seed_public_claim(&pool, agent, &format!("child {i}")).await;
        seed_rel(&pool, seed, child, "derived_from").await;
    }
    let edge_types = types(&["derived_from"]);
    let request = |node_cap: i32| ClosureRequest {
        seeds: std::slice::from_ref(&seed),
        edge_types: &edge_types,
        direction: ClosureDirection::Out,
        max_depth: 3,
        node_cap,
    };

    // CALIBRATION: six nodes fit under a cap of six.
    let ok = PrivatizationRepository::select_closure(&mut conn, &viewer, request(6))
        .await
        .expect("a selection that fits its cap must succeed");
    assert_eq!(ok.len(), 6, "seed plus five children");

    // THE PROPERTY: five is not enough, and the answer is a refusal.
    let err = PrivatizationRepository::select_closure(&mut conn, &viewer, request(5))
        .await
        .expect_err(
            "a selection larger than node_cap must be refused. The SQL function's LIMIT has no \
             ORDER BY, so a truncated result is an ARBITRARY subset — silently privatizing five \
             of six entities is worse than refusing",
        );
    assert!(
        matches!(
            err,
            SelectionError::Refused(SelectionRefusal::NodeCapExceeded { node_cap: 5 })
        ),
        "got {err:?}"
    );
}

/// The overflow refusal survives ids that resolve to no live claim row.
///
/// # Why this needs its own test
///
/// `exceeding_the_node_cap_refuses_rather_than_truncating` and
/// `a_seed_that_names_no_claim_is_dropped` each exercise one mechanism, and the
/// defect lives only where they meet. Every id the SQL function emits consumes
/// one `LIMIT p_node_cap` slot whether or not it names a live claim, so a probe
/// window can come back FULL — meaning the function may have discarded real
/// rows — while the surviving rows number fewer than the cap. An overflow probe
/// measured after the rows are filtered reads that as "it fits" and hands the
/// caller an arbitrary subset labelled complete.
///
/// # The corpus is built so the discrimination is deterministic
///
/// Five live claims and three ids that name nothing, with `node_cap = 5`. The
/// function is therefore asked for 6 rows out of 8 and must return 6. At most 5
/// of those resolve, so a probe taken after filtering can never exceed 5 and
/// can never refuse; a probe taken on the function's own output is always 6 and
/// always refuses. Neither direction depends on WHICH 6 rows the un-`ORDER BY`ed
/// `LIMIT` chose, which is what makes this an assertion rather than a coin flip.
#[sqlx::test(migrations = "../../migrations")]
async fn the_node_cap_refusal_is_not_defeated_by_ids_that_resolve_to_nothing(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "closure-ghost-cap").await;

    // Five live claims: one seed with four children.
    let live_seed = fixture::seed_public_claim(&pool, agent, "seed").await;
    for i in 0..4 {
        let child = fixture::seed_public_claim(&pool, agent, &format!("child {i}")).await;
        seed_rel(&pool, live_seed, child, "derived_from").await;
    }
    let ghosts: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
    let mut seeds = vec![live_seed];
    seeds.extend(ghosts.iter().copied());

    let edge_types = types(&["derived_from"]);
    let live_only = [live_seed];

    // CALIBRATION: without the ghosts the same five claims fit a cap of five
    // and succeed, so the refusal below is attributable to the padding and not
    // to the corpus being too large on its own.
    let ok = PrivatizationRepository::select_closure(
        &mut conn,
        &viewer,
        ClosureRequest {
            seeds: &live_only,
            edge_types: &edge_types,
            direction: ClosureDirection::Out,
            max_depth: 3,
            node_cap: 5,
        },
    )
    .await
    .expect("five live claims must fit a cap of five");
    assert_eq!(ok.len(), 5, "seed plus four children");

    // THE PROPERTY.
    let err = PrivatizationRepository::select_closure(
        &mut conn,
        &viewer,
        ClosureRequest {
            seeds: &seeds,
            edge_types: &edge_types,
            direction: ClosureDirection::Out,
            max_depth: 3,
            node_cap: 5,
        },
    )
    .await
    .expect_err(
        "the closure emitted more rows than the cap allows, so the honest selection may \
             have been truncated. Counting only the rows that resolved would report a plan of \
             five as complete when the function was never asked to prove it was",
    );
    assert!(
        matches!(
            err,
            SelectionError::Refused(SelectionRefusal::NodeCapExceeded { node_cap: 5 })
        ),
        "got {err:?}"
    );
}

/// A seed naming no live claim contributes no item.
///
/// The SQL function's non-recursive term echoes `unnest(p_seeds)` back
/// unfiltered, so without the caller's join to `claims` a mistyped seed would
/// become a plan item for an entity that does not exist — and an apply would
/// then carry a row it can never resolve.
#[sqlx::test(migrations = "../../migrations")]
async fn a_seed_that_names_no_claim_is_dropped(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "closure-ghost").await;
    let real = fixture::seed_public_claim(&pool, agent, "real").await;
    let ghost = Uuid::new_v4();

    let edge_types = types(&["derived_from"]);
    let selected = PrivatizationRepository::select_closure(
        &mut conn,
        &viewer,
        ClosureRequest {
            seeds: &[real, ghost],
            edge_types: &edge_types,
            direction: ClosureDirection::Both,
            max_depth: 2,
            node_cap: 100,
        },
    )
    .await
    .expect("closure");

    let ids: Vec<Uuid> = selected.iter().map(|s| s.claim_id).collect();
    assert!(ids.contains(&real));
    assert!(
        !ids.contains(&ghost),
        "a seed that resolves to no claim row must not become a plan item"
    );
}

/// Direction is honoured: `Out` and `In` select opposite sides of the same edge.
#[sqlx::test(migrations = "../../migrations")]
async fn direction_selects_the_side_it_names(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "closure-direction").await;

    let parent = fixture::seed_public_claim(&pool, agent, "parent").await;
    let child = fixture::seed_public_claim(&pool, agent, "child").await;
    seed_rel(&pool, parent, child, "decomposes_to").await;

    let edge_types = types(&["decomposes_to"]);
    let seeds = [parent];
    let run = |direction: ClosureDirection| ClosureRequest {
        seeds: &seeds,
        edge_types: &edge_types,
        direction,
        max_depth: 3,
        node_cap: 100,
    };

    let outward =
        PrivatizationRepository::select_closure(&mut conn, &viewer, run(ClosureDirection::Out))
            .await
            .expect("out");
    assert!(
        outward.iter().any(|s| s.claim_id == child),
        "source -> target is the 'out' direction"
    );

    let inward =
        PrivatizationRepository::select_closure(&mut conn, &viewer, run(ClosureDirection::In))
            .await
            .expect("in");
    assert!(
        !inward.iter().any(|s| s.claim_id == child),
        "'in' must not follow source -> target, or direction is decorative"
    );
}

/// Degenerate requests are refused rather than silently normalised.
#[sqlx::test(migrations = "../../migrations")]
async fn degenerate_bounds_are_refused(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "closure-degenerate").await;
    let seed = fixture::seed_public_claim(&pool, agent, "seed").await;
    let edge_types = types(&["derived_from"]);

    let no_seeds = PrivatizationRepository::select_closure(
        &mut conn,
        &viewer,
        ClosureRequest {
            seeds: &[],
            edge_types: &edge_types,
            direction: ClosureDirection::Both,
            max_depth: 2,
            node_cap: 10,
        },
    )
    .await
    .expect_err("an empty seed set is a client error, not an empty plan");
    assert!(matches!(
        no_seeds,
        SelectionError::Refused(SelectionRefusal::NoSeeds)
    ));

    for (parameter, max_depth, node_cap) in [("max_depth", 0, 10), ("node_cap", 2, 0)] {
        let err = PrivatizationRepository::select_closure(
            &mut conn,
            &viewer,
            ClosureRequest {
                seeds: &[seed],
                edge_types: &edge_types,
                direction: ClosureDirection::Both,
                max_depth,
                node_cap,
            },
        )
        .await
        .expect_err("a non-positive bound is a client error");
        assert!(
            matches!(
                err,
                SelectionError::Refused(SelectionRefusal::NonPositiveBound { parameter: p, .. })
                    if p == parameter
            ),
            "expected a refusal naming {parameter}, got {err:?}"
        );
    }
}
