//! `POST /api/v1/reasoning/analyze` auto-loads only the edges the caller may
//! read.
//!
//! Deferred-commitment screen key `f-fah-a1-reasoning-analyze`, recorded on
//! register entry `F-FAH-A1`. Before the fix the handler took no `Viewer`.
//! When the caller sent no edges, it loaded them with two inline statements on
//! the raw pool, with no viewer predicate and no retraction filter. With no
//! `claim_ids`, that load scanned every tenant's claim-to-claim edges.
//!
//! # What this file pins, and what it does not
//!
//! The arms here build their state with `AppState::with_scoped_pool` on the
//! `#[sqlx::test]` superuser pool, where no RLS policy filters anything. So
//! what they observe is the in-query predicate on the converted path.
//!
//! [`over_http_the_analysis_follows_the_bearer`] goes through the real router,
//! so it runs against the handler whatever its signature. It was run against
//! the pre-fix `routes/reasoning.rs` and FAILED: the stranger's analysis loaded
//! all three of the owner's edges, including the private one. The
//! direct-invocation arms do not compile against the pre-fix handler, which
//! took no `Viewer`. Each pins a property that handler lacked:
//!
//! * a stranger's analysis must not contain the owner's private edges;
//! * a retracted edge must not be analysed as live;
//! * with no `ScopedPool`, the handler must refuse rather than read the raw
//!   pool.
//!
//! The claim-side arms, in the last section, were run against the handler as
//! it stood after the edge conversion and before the claim conversion. They
//! FAILED there, because the claims still came from the in-memory store.
//!
//! The EXECUTOR half is pinned elsewhere. On this fixture `db_pool` and the
//! scoped pool are the same superuser pool, so reverting the read to
//! `state.db_pool` changes no row here. That reversion is caught by
//! `belief_computation_scoped_read.rs`'s `reasoning_analyze` arm, whose raw
//! pool is downgraded to `epigraph_app` and unstamped. The policy half of the
//! repo read is `epigraph-db/tests/reasoning_edges_scoped_policy.rs`.
//!
//! These tests were moved here from a `#[cfg(all(test, feature = "db"))]`
//! module inside `routes/reasoning.rs`. That module connected to `DATABASE_URL`
//! directly, seeded claims with no tenancy, cleaned up with inline `DELETE`s,
//! and read through an `AppState` with no `ScopedPool`. The converted handler
//! refuses such a state. Its two cases survive below as
//! [`the_owner_auto_loads_its_own_edge_when_none_are_sent`] and
//! [`explicit_edges_skip_the_database_load`].

#![cfg(feature = "db")]

mod common;
mod viewer_fixture;

use axum::extract::State;
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::reasoning::{analyze, AnalyzeRequest, AnalyzeResponse, EdgeInput};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::EdgeRepository;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    database_url_for, scoped_pool, seed_agent_with_group, seed_edge, seed_edge_owned_by,
    seed_group_claim, seed_public_claim, world_group,
};

// ── Fixture ──

fn request(claim_ids: Option<Vec<Uuid>>, edges: Vec<EdgeInput>) -> AnalyzeRequest {
    AnalyzeRequest {
        claim_ids,
        edges,
        min_similarity: None,
        link_threshold: None,
        decay_factor: None,
        propagation_depth: None,
        transitive_support_threshold: None,
        contradiction_threshold: None,
    }
}

async fn scoped_state(pool: &PgPool) -> AppState {
    AppState::with_scoped_pool(scoped_pool(pool).await, ApiConfig::default())
}

async fn viewer_for(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve")
}

async fn run(state: &AppState, viewer: Viewer, req: AnalyzeRequest) -> AnalyzeResponse {
    analyze(ViewerExtractor(viewer), State(state.clone()), Json(req))
        .await
        .expect("analyze must succeed")
        .0
}

/// `(source, target)` of every transitive support, restricted to `keep`. The
/// restriction matters only for requests with no `claim_ids`, which also see
/// whatever the migrations seeded.
fn supports(resp: &AnalyzeResponse, keep: &[Uuid]) -> Vec<(Uuid, Uuid)> {
    let keep: Vec<String> = keep.iter().map(Uuid::to_string).collect();
    let mut out: Vec<(Uuid, Uuid)> = resp
        .transitive_supports
        .iter()
        .filter(|ts| keep.contains(&ts.source_id) && keep.contains(&ts.target_id))
        .map(|ts| {
            (
                ts.source_id.parse().expect("uuid"),
                ts.target_id.parse().expect("uuid"),
            )
        })
        .collect();
    out.sort();
    out
}

async fn set_strength(pool: &PgPool, edge: Uuid, strength: f64) {
    sqlx::query(
        "UPDATE edges SET properties = jsonb_build_object('strength', $2::float8) WHERE id = $1",
    )
    .bind(edge)
    .bind(strength)
    .execute(pool)
    .await
    .expect("set edge strength");
}

/// The owner's graph, one hazard per edge:
///
/// ```text
///   p0 --public edge--> h (private claim)     only the claim predicate drops it
///   p0 --private edge-> p2 (public claim)     only the edge predicate drops it
///   p0 --public edge--> p3 (public claim)     the control a stranger must see
/// ```
///
/// Returns `(owner, stranger, [p0, h, p2, p3])`.
async fn seed_hazard_graph(pool: &PgPool) -> (Uuid, Uuid, [Uuid; 4]) {
    let (owner, group) = seed_agent_with_group(pool, "reasoning-api-owner").await;
    let (stranger, _) = seed_agent_with_group(pool, "reasoning-api-stranger").await;
    let world = world_group(pool).await;
    let tag = Uuid::new_v4();

    let p0 = seed_public_claim(pool, owner, &format!("reasoning api p0 {tag}")).await;
    let h = seed_group_claim(pool, owner, group, &format!("reasoning api h {tag}")).await;
    let p2 = seed_public_claim(pool, owner, &format!("reasoning api p2 {tag}")).await;
    let p3 = seed_public_claim(pool, owner, &format!("reasoning api p3 {tag}")).await;

    // Forced PUBLIC, so only the claim predicate can drop it.
    seed_edge_owned_by(pool, p0, h, "public", world).await;
    // Forced PRIVATE between two public claims, so only the edge predicate can.
    seed_edge_owned_by(pool, p0, p2, "group", group).await;
    // Left to the trigger: public/public stays public.
    seed_edge(pool, p0, p3).await;

    (owner, stranger, [p0, h, p2, p3])
}

// ── The arms ──

/// The case the in-module `test_db_auto_loads_edges_when_empty` covered, now
/// on a group-private pair: the owner sends no edges, and its own private edge
/// is loaded with its stored strength.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_auto_loads_its_own_edge_when_none_are_sent(pool: PgPool) {
    let (owner, group) = seed_agent_with_group(&pool, "reasoning-api-self").await;
    let x = seed_group_claim(&pool, owner, group, "reasoning api: private x").await;
    let y = seed_group_claim(&pool, owner, group, "reasoning api: private y").await;
    let edge = seed_edge(&pool, x, y).await;
    set_strength(&pool, edge, 0.9).await;
    let state = scoped_state(&pool).await;

    let resp = run(
        &state,
        viewer_for(&pool, owner).await,
        request(Some(vec![x, y]), vec![]),
    )
    .await;

    assert_eq!(resp.stats.edges_loaded, 1, "one edge loaded from the DB");
    let ts = resp
        .transitive_supports
        .iter()
        .find(|ts| ts.source_id == x.to_string() && ts.target_id == y.to_string())
        .expect("the auto-loaded edge must produce a transitive support x -> y");
    assert!(
        (ts.cumulative_strength - 0.9).abs() < 1e-6,
        "the stored strength must be preserved; got {}",
        ts.cumulative_strength
    );
}

/// A stranger's analysis loads none of the owner's private graph, with or
/// without `claim_ids`. The owner's analysis over the same rows loads all of
/// it, which is what makes the stranger's result a filter and not an empty
/// fixture.
#[sqlx::test(migrations = "../../migrations")]
async fn a_strangers_analysis_loads_none_of_the_owners_private_edges(pool: PgPool) {
    let (owner, stranger, ids) = seed_hazard_graph(&pool).await;
    let [p0, h, p2, p3] = ids;
    let state = scoped_state(&pool).await;

    let mine = run(
        &state,
        viewer_for(&pool, owner).await,
        request(Some(ids.to_vec()), vec![]),
    )
    .await;
    assert_eq!(
        (mine.stats.edges_loaded, supports(&mine, &ids)),
        (3, {
            let mut v = vec![(p0, h), (p0, p2), (p0, p3)];
            v.sort();
            v
        }),
        "CALIBRATION: the owner loads the edge to its own private claim and its own \
         private edge"
    );

    let theirs = run(
        &state,
        viewer_for(&pool, stranger).await,
        request(Some(ids.to_vec()), vec![]),
    )
    .await;
    assert_eq!(
        (theirs.stats.edges_loaded, supports(&theirs, &ids)),
        (1, vec![(p0, p3)]),
        "a stranger naming the owner's claims must load neither the edge to the \
         private claim h nor the private edge p0->p2, and must still load the public \
         control p0->p3"
    );

    // No `claim_ids`: the branch that scanned every tenant's edges.
    let theirs_all = run(
        &state,
        viewer_for(&pool, stranger).await,
        request(None, vec![]),
    )
    .await;
    assert_eq!(
        supports(&theirs_all, &ids),
        vec![(p0, p3)],
        "with no claim_ids, a stranger must still load only the public control"
    );
    let named: Vec<String> = [h, p2].iter().map(Uuid::to_string).collect();
    let body = serde_json::to_string(&theirs_all.transitive_supports).expect("serialize");
    assert!(
        !named.iter().any(|id| body.contains(id.as_str())),
        "no transitive support may name the owner's private claim or the far end of \
         its private edge; got {body}"
    );
}

/// A retracted edge is not analysed. Before the fix the load had no
/// retraction filter, so a retracted edge produced a transitive support.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retracted_edge_is_not_analysed(pool: PgPool) {
    let (owner, _) = seed_agent_with_group(&pool, "reasoning-api-retract").await;
    let a = seed_public_claim(&pool, owner, "reasoning api: a").await;
    let b = seed_public_claim(&pool, owner, "reasoning api: b").await;
    let edge = seed_edge(&pool, a, b).await;
    let state = scoped_state(&pool).await;

    let before = run(
        &state,
        viewer_for(&pool, owner).await,
        request(Some(vec![a, b]), vec![]),
    )
    .await;
    assert_eq!(
        (before.stats.edges_loaded, supports(&before, &[a, b])),
        (1, vec![(a, b)]),
        "CALIBRATION: the edge is analysed while it is in force"
    );

    let closed = EdgeRepository::retract(&pool, &[edge])
        .await
        .expect("retract");
    assert_eq!(closed, vec![edge], "CALIBRATION: the retraction landed");

    let after = run(
        &state,
        viewer_for(&pool, owner).await,
        request(Some(vec![a, b]), vec![]),
    )
    .await;
    assert_eq!(
        (after.stats.edges_loaded, supports(&after, &[a, b])),
        (0, vec![]),
        "a retracted edge must not be loaded or analysed"
    );
}

/// The case the in-module `test_db_explicit_edges_skip_db_load` covered:
/// explicit edges replace the database load entirely, even when the database
/// holds an edge between the same claims.
#[sqlx::test(migrations = "../../migrations")]
async fn explicit_edges_skip_the_database_load(pool: PgPool) {
    let (owner, _) = seed_agent_with_group(&pool, "reasoning-api-explicit").await;
    let src = seed_public_claim(&pool, owner, "reasoning api: src").await;
    let tgt = seed_public_claim(&pool, owner, "reasoning api: tgt").await;
    let other = seed_public_claim(&pool, owner, "reasoning api: other").await;
    seed_edge(&pool, src, other).await;
    let state = scoped_state(&pool).await;

    let resp = run(
        &state,
        viewer_for(&pool, owner).await,
        request(
            Some(vec![src, tgt, other]),
            vec![EdgeInput {
                source_id: src,
                target_id: tgt,
                relationship: "supports".to_string(),
                strength: 0.5,
            }],
        ),
    )
    .await;

    assert_eq!(resp.stats.edges_loaded, 1, "only the explicit edge is used");
    assert_eq!(
        supports(&resp, &[src, tgt, other]),
        vec![(src, tgt)],
        "the database edge src -> other must not be loaded when edges are sent"
    );
}

/// With no `ScopedPool`, the auto-load refuses with a fixed 500 rather than
/// falling back to the raw pool. The pre-fix handler read `state.db_pool`, so
/// it answered 200 here.
#[sqlx::test(migrations = "../../migrations")]
async fn the_auto_load_refuses_without_a_scoped_pool(pool: PgPool) {
    let (owner, _) = seed_agent_with_group(&pool, "reasoning-api-refuse").await;
    let a = seed_public_claim(&pool, owner, "reasoning api: refuse a").await;
    let b = seed_public_claim(&pool, owner, "reasoning api: refuse b").await;
    seed_edge(&pool, a, b).await;
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    assert!(
        state.scoped.is_none(),
        "CALIBRATION: this state has no ScopedPool"
    );

    let got = analyze(
        ViewerExtractor(viewer_for(&pool, owner).await),
        State(state),
        Json(request(Some(vec![a, b]), vec![])),
    )
    .await;
    match got {
        Err(ApiError::InternalError { message }) => assert_eq!(
            message, "Failed to acquire a scoped connection",
            "the 500 must carry a fixed message, never the database error text"
        ),
        Err(other) => panic!("expected the fixed InternalError, got {other:?}"),
        Ok(Json(resp)) => panic!(
            "the handler must refuse without a ScopedPool, not read the raw pool; \
             it loaded {} edge(s)",
            resp.stats.edges_loaded
        ),
    }
}

/// Through the real router: the route takes a bearer token, and the owner's
/// and a stranger's analyses of the same claims differ by the owner's private
/// edge.
#[sqlx::test(migrations = "../../migrations")]
async fn over_http_the_analysis_follows_the_bearer(pool: PgPool) {
    let (owner, stranger, ids) = seed_hazard_graph(&pool).await;
    let [p0, h, _p2, _p3] = ids;
    let url = database_url_for(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let body = json!({ "claim_ids": ids });

    let post = |token: Option<String>| {
        let mut req = reqwest::Client::new()
            .post(format!("http://{addr}/api/v1/reasoning/analyze"))
            .json(&body);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        req.send()
    };

    let resp = post(None).await.expect("POST without a token");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "the route needs a bearer token"
    );

    let names_private = |v: &Value| {
        v["transitive_supports"]
            .as_array()
            .expect("transitive_supports")
            .iter()
            .any(|ts| ts["source_id"] == p0.to_string() && ts["target_id"] == h.to_string())
    };

    let resp = post(Some(common::test_bearer_token_for_principal(owner, &[])))
        .await
        .expect("POST as the owner");
    assert_eq!(resp.status().as_u16(), 200);
    let mine: Value = resp.json().await.expect("json");
    assert!(
        names_private(&mine),
        "CALIBRATION: the owner's analysis includes p0 -> h, the edge to its own \
         private claim; got {mine}"
    );

    let resp = post(Some(common::test_bearer_token_for_principal(stranger, &[])))
        .await
        .expect("POST as the stranger");
    assert_eq!(resp.status().as_u16(), 200);
    let theirs: Value = resp.json().await.expect("json");
    assert!(
        !names_private(&theirs),
        "a stranger's analysis must not include the edge to the owner's private \
         claim; got {theirs}"
    );
    assert_eq!(
        theirs["stats"]["edges_loaded"], 1,
        "a stranger loads only the public control; got {theirs}"
    );
}

// ── The claim side ──
//
// The claims used to come from `AppState::claim_store`, a process-wide
// in-memory map with no tenancy. In the `db` build they now come from
// `ClaimRepository::truth_values_for` on the same stamped connection as the
// edges.

/// Every claim id in the response's claim-derived fields:
/// `unsupported_claims` and `connected_components`.
fn claim_ids_in(resp: &AnalyzeResponse) -> Vec<String> {
    let mut out: Vec<String> = resp.unsupported_claims.clone();
    for c in &resp.connected_components {
        out.extend(c.claim_ids.iter().cloned());
    }
    out
}

/// A stranger's analysis names none of the owner's private claims, with or
/// without `claim_ids`. The owner's analysis over the same rows does, which is
/// what makes the stranger's result a filter and not an empty fixture.
#[sqlx::test(migrations = "../../migrations")]
async fn a_strangers_analysis_names_none_of_the_owners_private_claims(pool: PgPool) {
    let (owner, stranger, ids) = seed_hazard_graph(&pool).await;
    let [p0, h, p2, p3] = ids;
    let state = scoped_state(&pool).await;

    let mine = run(
        &state,
        viewer_for(&pool, owner).await,
        request(Some(ids.to_vec()), vec![]),
    )
    .await;
    assert_eq!(
        mine.stats.claims_loaded, 4,
        "CALIBRATION: the owner loads all four of its claims"
    );
    assert!(
        claim_ids_in(&mine).contains(&h.to_string()),
        "CALIBRATION: the owner's analysis names its own private claim h"
    );

    let theirs = run(
        &state,
        viewer_for(&pool, stranger).await,
        request(Some(ids.to_vec()), vec![]),
    )
    .await;
    assert_eq!(
        theirs.stats.claims_loaded, 3,
        "a stranger naming the owner's claims must load only the three public ones"
    );
    assert!(
        !claim_ids_in(&theirs).contains(&h.to_string()),
        "a stranger's analysis must not name the owner's private claim h; got {:?}",
        claim_ids_in(&theirs)
    );

    // No `claim_ids`: the claims are the readable endpoints of the readable
    // edges, which for the stranger is the public control alone.
    let theirs_all = run(
        &state,
        viewer_for(&pool, stranger).await,
        request(None, vec![]),
    )
    .await;
    let named = claim_ids_in(&theirs_all);
    assert!(
        named.contains(&p0.to_string()) && named.contains(&p3.to_string()),
        "CALIBRATION: with no claim_ids the stranger analyses the public control's \
         endpoints; got {named:?}"
    );
    assert!(
        !named.contains(&h.to_string()) && !named.contains(&p2.to_string()),
        "with no claim_ids, a stranger must analyse neither the owner's private claim \
         nor the far end of its private edge; got {named:?}"
    );
}

/// The process-wide in-memory store is not analysed in the `db` build. Before
/// the fix, with no `claim_ids`, every claim in it reached every caller's
/// analysis, whoever had batch-imported it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_in_memory_claim_store_is_not_analysed(pool: PgPool) {
    let (caller, _) = seed_agent_with_group(&pool, "reasoning-api-store").await;
    let state = scoped_state(&pool).await;

    // What `POST /api/v1/claims/batch` leaves behind: a claim in the map and
    // in no table.
    let now = chrono::Utc::now();
    let in_memory = epigraph_core::Claim::with_id(
        epigraph_core::ClaimId::from_uuid(Uuid::new_v4()),
        "another caller's batch-imported claim".to_string(),
        epigraph_core::AgentId::new(),
        [0u8; 32],
        [0u8; 32],
        None,
        None,
        epigraph_core::TruthValue::new(0.42).unwrap(),
        now,
        now,
    );
    let in_memory_id = in_memory.id.as_uuid();
    state
        .claim_store
        .write()
        .await
        .insert(in_memory_id, in_memory);

    let all = run(
        &state,
        viewer_for(&pool, caller).await,
        request(None, vec![]),
    )
    .await;
    assert!(
        !claim_ids_in(&all).contains(&in_memory_id.to_string()),
        "with no claim_ids, a claim that exists only in the in-memory store must not \
         be analysed; got {:?}",
        claim_ids_in(&all)
    );

    let named = run(
        &state,
        viewer_for(&pool, caller).await,
        request(Some(vec![in_memory_id]), vec![]),
    )
    .await;
    assert_eq!(
        named.stats.claims_loaded, 0,
        "naming an id that exists only in the in-memory store loads nothing"
    );
}

/// With caller-supplied edges and no `claim_ids`, only the endpoints the
/// caller may read are loaded as claims.
#[sqlx::test(migrations = "../../migrations")]
async fn explicit_edges_load_only_the_endpoints_the_caller_may_read(pool: PgPool) {
    let (_owner, stranger, [p0, h, _p2, p3]) = seed_hazard_graph(&pool).await;
    let state = scoped_state(&pool).await;
    let edge = |s: Uuid, t: Uuid| EdgeInput {
        source_id: s,
        target_id: t,
        relationship: "supports".to_string(),
        strength: 0.5,
    };

    let theirs = run(
        &state,
        viewer_for(&pool, stranger).await,
        request(None, vec![edge(p0, h), edge(p0, p3)]),
    )
    .await;
    assert_eq!(
        theirs.stats.claims_loaded, 2,
        "only p0 and p3 are readable endpoints of the stranger's own edges"
    );
    assert!(
        !claim_ids_in(&theirs).contains(&h.to_string()),
        "the owner's private claim h must not be loaded as a claim, even when the \
         caller names it in an edge; got {:?}",
        claim_ids_in(&theirs)
    );
}
