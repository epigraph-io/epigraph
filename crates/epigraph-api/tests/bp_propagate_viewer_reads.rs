//! Tenancy finding F-SHARD4-A2 (backlog 073d24a3): every read
//! `POST /api/v1/bp/propagate` makes spends the caller's viewer.
//!
//! The handler held a viewer and ran three reads that did not spend it:
//!
//! * the factor load. `factors` has no tenancy and no row security, and
//!   `variable_ids` has no foreign key, so a factor naming another group's
//!   private claim was loaded and that claim's id, with a BP value computed
//!   for it, came back in `updated_beliefs` and `variables_count`;
//! * the scalar priors (`SELECT id, pignistic_prob FROM claims`), on the raw
//!   pool: on the application role, unstamped, it saw public claims only, so a
//!   member's own group's priors were dropped; on a pool past row security it
//!   saw every claim, another group's included;
//! * the `alternative_set` view, on the raw pool and over the whole corpus,
//!   with the same two failure directions for CDST's alternative-set classes.
//!
//! Each test below pins one of them on the pool where its old shape was wrong.
//! One pins the R-22 consequence of reading the caller's own alternative sets
//! on an apply run: a class is a coupling like a factor, so a public claim
//! whose class reaches a group claim is not written from it. The last pins a
//! factor the edge trigger minted from a group-private edge between two
//! public claims: its variables are readable by anyone, its coupling is not.
#![cfg(feature = "db")]

mod viewer_fixture;

use std::collections::BTreeMap;

use axum::extract::State;
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::computation::{propagate_beliefs, PropagateRequest};
use epigraph_api::state::{ApiConfig, AppState, BpApply};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    database_url_for, downgraded_pool, scoped_pool, seed_agent_with_group, seed_group_claim,
    seed_public_claim,
};

fn bearer(agent: Uuid) -> axum::Extension<epigraph_api::middleware::bearer::AuthContext> {
    axum::Extension(epigraph_api::middleware::bearer::AuthContext {
        client_id: agent,
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: epigraph_api::middleware::ClientType::Service,
        scopes: vec!["claims:read".to_string(), "claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    })
}

async fn run(pool: &PgPool, state: &AppState, agent: Uuid, body: Value) -> Value {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    let request: PropagateRequest = serde_json::from_value(body.clone()).expect("request");
    let res: Result<Json<Value>, ApiError> = propagate_beliefs(
        ViewerExtractor(viewer),
        bearer(agent),
        State(state.clone()),
        Json(request),
    )
    .await;
    match res {
        Ok(Json(v)) => v,
        Err(e) => panic!("{body} must answer 200, got {e:?}"),
    }
}

fn betps(body: &Value) -> BTreeMap<Uuid, f64> {
    body["updated_beliefs"]
        .as_array()
        .expect("updated_beliefs is a list")
        .iter()
        .map(|u| {
            (
                u["claim_id"].as_str().unwrap().parse().unwrap(),
                u["betp"].as_f64().unwrap(),
            )
        })
        .collect()
}

async fn set_betp(pool: &PgPool, claim: Uuid, p: f64) {
    sqlx::query("UPDATE claims SET pignistic_prob = $2 WHERE id = $1")
        .bind(claim)
        .bind(p)
        .execute(pool)
        .await
        .expect("set BetP");
}

async fn stored(pool: &PgPool, claim: Uuid) -> (Option<f64>, Option<f64>, Option<f64>) {
    sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the stored belief")
}

async fn factor(pool: &PgPool, a: Uuid, b: Uuid) {
    sqlx::query(
        "INSERT INTO factors (factor_type, variable_ids, potential) \
         VALUES ('evidential_support', $1, '{\"strength\": 0.8}')",
    )
    .bind(vec![a, b])
    .execute(pool)
    .await
    .expect("seed a factor");
}

async fn binary_frame(pool: &PgPool) -> Uuid {
    sqlx::query(
        "INSERT INTO frames (name, hypotheses) \
         VALUES ('binary_truth', ARRAY['TRUE','FALSE']::text[]) \
         ON CONFLICT (name) DO NOTHING",
    )
    .execute(pool)
    .await
    .expect("seed the binary_truth frame");
    sqlx::query_scalar("SELECT id FROM frames WHERE name = 'binary_truth'")
        .fetch_one(pool)
        .await
        .expect("read the binary_truth frame")
}

async fn bba(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, support: f64) {
    sqlx::query(
        "INSERT INTO mass_functions \
           (claim_id, frame_id, source_agent_id, masses, source_strength, evidence_type) \
         VALUES ($1, $2, $3, $4, 1.0, 'empirical')",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(json!({"0": support, "0,1": 1.0 - support}))
    .execute(pool)
    .await
    .expect("seed a BBA");
}

/// An `alternative_of` edge `a - b`, with the tenancy the edge trigger
/// derives from its ends; returns that visibility.
async fn alternative_of(pool: &PgPool, a: Uuid, b: Uuid) -> String {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'alternative_of') RETURNING visibility::text",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .expect("seed an alternative_of edge")
}

/// The superuser pools: the raw `db_pool` and the stamped reads both pass
/// row security, so only an in-query viewer predicate filters anything.
async fn bypass_state(pool: &PgPool, apply: bool) -> AppState {
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(scoped_pool(pool).await);
    if apply {
        state.bp_apply = BpApply::On;
    }
    state
}

/// Both pools on the application role, as in production.
async fn app_role_state(pool: &PgPool) -> AppState {
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    let url = database_url_for(pool).await;
    state.scoped = Some(
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("an app-role ScopedPool"),
    );
    state
}

/// The priors read: a member's run uses the BetP of its own group's claim.
/// On the application role the raw-pool read saw public claims only, so the
/// group claim ran from the engine default whatever its stored value.
#[sqlx::test(migrations = "../../migrations")]
async fn a_members_scalar_run_reads_its_own_groups_priors(pool: PgPool) {
    let (member, group) = seed_agent_with_group(&pool, "a2-priors-member").await;
    let v = seed_public_claim(&pool, member, "a2 priors public").await;
    let w = seed_group_claim(&pool, member, group, "a2 priors group").await;
    set_betp(&pool, v, 0.5).await;
    factor(&pool, v, w).await;
    let state = app_role_state(&pool).await;
    let body = json!({"claim_ids": [v], "max_hops": 1, "mode": "scalar", "max_iterations": 30});

    set_betp(&pool, w, 0.95).await;
    let high = betps(&run(&pool, &state, member, body.clone()).await);
    set_betp(&pool, w, 0.05).await;
    let low = betps(&run(&pool, &state, member, body).await);

    assert!(
        high.contains_key(&w) && low.contains_key(&w),
        "CALIBRATION: the member's own group claim is a variable of its run"
    );
    assert!(
        (high[&v] - low[&v]).abs() > 1e-3,
        "the member's own group claim's prior must move its neighbour: {} vs {}",
        high[&v],
        low[&v]
    );
}

/// The factor load and the priors read, past row security: a caller who
/// cannot read a claim gets neither its id nor a value it moved.
#[sqlx::test(migrations = "../../migrations")]
async fn a_strangers_run_never_reaches_a_claim_it_cannot_read(pool: PgPool) {
    let (member, group) = seed_agent_with_group(&pool, "a2-hidden-member").await;
    let (stranger, _) = seed_agent_with_group(&pool, "a2-hidden-stranger").await;
    let v = seed_public_claim(&pool, member, "a2 hidden public").await;
    let w = seed_group_claim(&pool, member, group, "a2 hidden group").await;
    set_betp(&pool, v, 0.5).await;
    factor(&pool, v, w).await;
    let state = bypass_state(&pool, false).await;
    let body = json!({"claim_ids": [v], "max_hops": 1, "mode": "scalar", "max_iterations": 30});

    // Positive control: the member, who can read both, runs the factor.
    let mine = run(&pool, &state, member, body.clone()).await;
    assert_eq!(
        mine["factors_count"].as_u64(),
        Some(1),
        "CONTROL: the member's run loads the factor: {mine}"
    );
    assert!(betps(&mine).contains_key(&w), "CONTROL: {mine}");

    for p in [0.95, 0.05] {
        set_betp(&pool, w, p).await;
        let theirs = run(&pool, &state, stranger, body.clone()).await;
        assert!(
            !betps(&theirs).contains_key(&w),
            "a stranger's run must not list a claim it cannot read: {theirs}"
        );
        assert_eq!(
            theirs["variables_count"].as_u64(),
            Some(0),
            "a stranger's run must not count a claim it cannot read: {theirs}"
        );
        assert_eq!(
            theirs["factors_count"].as_u64(),
            Some(0),
            "a factor naming a claim the caller cannot read is not loaded: {theirs}"
        );
    }
}

/// The alternative-set read. `s1` and `s2` support `v`; they are linked as
/// alternatives only through `y`, a claim private to the member's group, by
/// two group edges. A class groups its members' messages into `v`, so the
/// member's CDST value for `v` differs from a stranger's, who sees no class.
struct AltFixture {
    member: Uuid,
    stranger: Uuid,
    v: Uuid,
    s1: Uuid,
    s2: Uuid,
}

async fn alt_fixture(pool: &PgPool, label: &str, through_group_claim: bool) -> AltFixture {
    let (member, group) = seed_agent_with_group(pool, &format!("a2-alt-{label}")).await;
    let (stranger, _) = seed_agent_with_group(pool, &format!("a2-alt-stranger-{label}")).await;
    let frame = binary_frame(pool).await;
    let v = seed_public_claim(pool, member, &format!("a2 alt {label} target")).await;
    let s1 = seed_public_claim(pool, member, &format!("a2 alt {label} supporter 1")).await;
    let s2 = seed_public_claim(pool, member, &format!("a2 alt {label} supporter 2")).await;
    set_betp(pool, v, 0.5).await;
    bba(pool, s1, frame, member, 0.8).await;
    bba(pool, s2, frame, member, 0.8).await;
    factor(pool, v, s1).await;
    factor(pool, v, s2).await;
    if through_group_claim {
        let y = seed_group_claim(pool, member, group, &format!("a2 alt {label} link")).await;
        assert_eq!(
            alternative_of(pool, s1, y).await,
            "group",
            "CALIBRATION: an edge to a group claim is the group's"
        );
        assert_eq!(alternative_of(pool, y, s2).await, "group");
    } else {
        assert_eq!(alternative_of(pool, s1, s2).await, "public");
    }
    AltFixture {
        member,
        stranger,
        v,
        s1,
        s2,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_cdst_run_reads_the_alternative_sets_its_caller_can_read(pool: PgPool) {
    let f = alt_fixture(&pool, "read", true).await;
    let state = bypass_state(&pool, false).await;
    let body = json!({"claim_ids": [f.v], "max_hops": 1, "mode": "cdst", "max_iterations": 30});

    let mine = run(&pool, &state, f.member, body.clone()).await;
    let theirs = run(&pool, &state, f.stranger, body.clone()).await;
    assert_eq!(
        mine["factors_count"], theirs["factors_count"],
        "CALIBRATION: both runs load the same public factor graph"
    );
    let (m, t) = (betps(&mine)[&f.v], betps(&theirs)[&f.v]);
    assert!(
        (m - t).abs() > 1e-6,
        "the member's group alternative set must group s1 and s2 for it and not for a \
         stranger: member {m}, stranger {t}"
    );

    // Control: with the group link retracted the member sees no class
    // either, and the two runs agree, so the gap above is the class.
    sqlx::query("DELETE FROM edges WHERE relationship = 'alternative_of'")
        .execute(&pool)
        .await
        .expect("drop the alternative_of edges");
    let mine = run(&pool, &state, f.member, body).await;
    assert!(
        (betps(&mine)[&f.v] - t).abs() < 1e-9,
        "CONTROL: without the class the member's run is the stranger's"
    );
    let _ = (f.s1, f.s2);
}

/// Ruling R-22 on an apply: `v` is public and its class reaches `y`, a group
/// claim, so `v`'s cache is not written from this run. Control: the same
/// shape with a PUBLIC alternative link writes `v`.
#[sqlx::test(migrations = "../../migrations")]
async fn bp_apply_never_writes_a_public_claim_whose_class_reaches_a_group_claim(pool: PgPool) {
    let state = bypass_state(&pool, true).await;

    let f = alt_fixture(&pool, "apply", true).await;
    let before = stored(&pool, f.v).await;
    let body = json!({
        "claim_ids": [f.v], "max_hops": 1, "mode": "cdst",
        "apply_updates": true, "max_iterations": 30,
    });
    let out = run(&pool, &state, f.member, body.clone()).await;
    let computed = betps(&out)[&f.v];
    assert!(
        (computed - before.2.unwrap()).abs() > 1e-4,
        "precondition: BP computed a new value for v: {out}"
    );
    assert_eq!(
        stored(&pool, f.v).await,
        before,
        "v's class reaches a group claim, so its public cache is not written: {out}"
    );
    assert_eq!(
        out["skipped_less_readable_inputs"].as_u64(),
        Some(3),
        "v, s1 and s2 are each coupled to the group claim: {out}"
    );

    // Control: a public link, nothing narrower in reach; v is written.
    let g = alt_fixture(&pool, "apply-public", false).await;
    let body = json!({
        "claim_ids": [g.v], "max_hops": 1, "mode": "cdst",
        "apply_updates": true, "max_iterations": 30,
    });
    let out = run(&pool, &state, g.member, body).await;
    let after = stored(&pool, g.v).await.2.expect("v has a BetP");
    assert!(
        (after - betps(&out)[&g.v]).abs() < 1e-12,
        "CONTROL: with a public class v is written with BP's value: {out}"
    );
    let _ = (g.s1, g.s2, g.stranger);
}

/// A factor the edge trigger minted from an edge private to a group, between
/// two PUBLIC claims: every variable is readable by anyone, but the coupling
/// itself is the group's. A stranger's run must not load it; the member's
/// does.
#[sqlx::test(migrations = "../../migrations")]
async fn a_strangers_run_does_not_load_a_factor_minted_from_a_private_edge(pool: PgPool) {
    let (member, group) = seed_agent_with_group(&pool, "a2-edge-member").await;
    let (stranger, _) = seed_agent_with_group(&pool, "a2-edge-stranger").await;
    let a = seed_public_claim(&pool, member, "a2 edge public a").await;
    let b = seed_public_claim(&pool, member, "a2 edge public b").await;
    set_betp(&pool, a, 0.5).await;
    set_betp(&pool, b, 0.9).await;
    let edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                            visibility, owner_group_id) \
         VALUES ($1, 'claim', $2, 'claim', 'supports', 'group', $3) RETURNING id",
    )
    .bind(b)
    .bind(a)
    .bind(group)
    .fetch_one(&pool)
    .await
    .expect("seed a group-private supports edge between two public claims");
    let (visibility, minted): (String, i64) = sqlx::query_as(
        "SELECT (SELECT visibility::text FROM edges WHERE id = $1), \
                (SELECT count(*) FROM factors WHERE properties->>'source_edge_id' = $1::text)",
    )
    .bind(edge)
    .fetch_one(&pool)
    .await
    .expect("read the edge and its factor");
    assert_eq!(
        (visibility.as_str(), minted),
        ("group", 1),
        "CALIBRATION: the edge is the group's, and the trigger minted its factor"
    );

    let state = bypass_state(&pool, false).await;
    let body = json!({"claim_ids": [a], "max_hops": 1, "mode": "scalar", "max_iterations": 30});
    let mine = run(&pool, &state, member, body.clone()).await;
    assert_eq!(
        mine["factors_count"].as_u64(),
        Some(1),
        "CONTROL: the member, who can read the edge, runs its factor: {mine}"
    );
    let theirs = run(&pool, &state, stranger, body).await;
    assert_eq!(
        theirs["factors_count"].as_u64(),
        Some(0),
        "a factor minted from an edge the caller cannot read is not loaded: {theirs}"
    );
    assert_eq!(theirs["variables_count"].as_u64(), Some(0), "{theirs}");
}
