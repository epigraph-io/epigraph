#![cfg(feature = "db")]
//! The REST belief READS a reader is served, on the APPLICATION ROLE:
//! `GET /api/v1/claims/:id/pignistic` (`get_pignistic`, the HTTP twin of the
//! MCP framed `get_belief`) and `GET /api/v1/claims/:id/belief`
//! (`get_claim_belief`, its `mass_function_count`).
//!
//! * Ruling R-22 (backlog fef24216; generalised to every claim, R-71): a
//!   belief shown to a reader is folded only from BBAs whose every source the
//!   reader can read, and a group member still gets its group's sources.
//! * Ruling R-36 (backlog fe3ec493): agents of one human never aggregate on
//!   any BBA-combining path, this compute-on-read fold included.
//!
//! # What was wrong, measured before this file
//!
//! A row on a public claim is public whatever it was derived from, so
//! `mass_function_count` rose for every reader when a BBA derived from a
//! group-private edge or narrowed evidence was written: an existence oracle
//! over the private source (backlog fef24216 names "existence"). The
//! `get_pignistic` changes (derivation scope, owner-aware fold) had no test.
//!
//! # The instrument
//!
//! Both handlers read only on `AppState::read_as` (a viewer-stamped
//! connection), so the stamped `ScopedPool` is `epigraph_app`
//! (`connect_downgraded_for_tests`) and row security applies to every read
//! under test, as on prod. The graph is seeded on the harness pool.

mod viewer_fixture;

use axum::extract::{Path, Query, State};
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::belief::{get_claim_belief, get_pignistic, PignisticQuery};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_engine::edge_factor::{auto_wire_ds_for_edge, ensure_binary_frame, EdgeFactorOutcome};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    database_url_for, public_viewer, seed_agent_with_group, seed_edge, seed_evidence,
    seed_group_claim, seed_human_operator, seed_public_claim,
};

async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(!bypassrls, "PREMISE: epigraph_app is held to row security");
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

async fn frame(pool: &PgPool, name: &str) -> Uuid {
    epigraph_db::FrameRepository::create(pool, name, None, &["h0".to_string(), "h1".to_string()])
        .await
        .expect("frame")
        .id
}

/// A stored `discount` BBA (the rows `get_pignistic` folds): `t` on h0.
async fn discount_bba(
    pool: &PgPool,
    claim: Uuid,
    frame: Uuid,
    agent: Uuid,
    evidence: Option<Uuid>,
    t: f64,
) {
    epigraph_db::MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        evidence,
        &serde_json::json!({"0": t, "0,1": 1.0 - t}),
        None,
        Some("discount"),
        None,
        None,
        "unknown",
        evidence,
    )
    .await
    .expect("store a BBA");
}

/// Evidence on `claim` narrowed to `group` (the shape `hide-evidence` leaves),
/// with its evidence perspective.
async fn narrowed_evidence(pool: &PgPool, claim: Uuid, group: Uuid, owner: Uuid) -> Uuid {
    let ev = seed_evidence(pool, claim, "document").await;
    // Pinned, as `epigraph-operator hide-evidence` pins it (migration 110):
    // without the pin the next evidence INSERT on the claim re-publishes it.
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test: hidden')",
    )
    .bind(ev)
    .bind(owner)
    .execute(pool)
    .await
    .expect("pin the hidden evidence");
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(ev)
        .bind(group)
        .execute(pool)
        .await
        .expect("narrow the evidence");
    epigraph_db::PerspectiveRepository::ensure_evidence_perspective(pool, ev, Some(owner))
        .await
        .expect("evidence perspective");
    ev
}

/// (BetP, Bel, Pl) of h0 as served to `caller` (`None` = the public viewer).
async fn pignistic(
    state: &AppState,
    pool: &PgPool,
    caller: Option<Uuid>,
    claim: Uuid,
    frame: Uuid,
) -> (f64, f64, f64) {
    let viewer = match caller {
        Some(agent) => Viewer::resolve(pool, agent).await.expect("viewer"),
        None => public_viewer(pool).await,
    };
    let Json(out) = get_pignistic(
        ViewerExtractor(viewer),
        State(state.clone()),
        Path(claim),
        Query(PignisticQuery { frame_id: frame }),
    )
    .await
    .unwrap_or_else(|e| panic!("get_pignistic failed: {e:?}"));
    let h0 = out
        .hypotheses
        .iter()
        .find(|h| h.hypothesis_index == 0)
        .expect("h0");
    (h0.pignistic_probability, h0.belief, h0.plausibility)
}

async fn count(state: &AppState, pool: &PgPool, caller: Uuid, claim: Uuid) -> i64 {
    let viewer = Viewer::resolve(pool, caller).await.expect("viewer");
    let Json(out) = get_claim_belief(ViewerExtractor(viewer), State(state.clone()), Path(claim))
        .await
        .unwrap_or_else(|e| panic!("get_claim_belief failed: {e:?}"));
    out.mass_function_count
}

fn close(a: (f64, f64, f64), b: (f64, f64, f64)) -> bool {
    (a.0 - b.0).abs() < 1e-9 && (a.1 - b.1).abs() < 1e-9 && (a.2 - b.2).abs() < 1e-9
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_readers_pignistic_and_bba_count_never_include_sources_it_cannot_read(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let (member, group) = seed_agent_with_group(&pool, "r22-rest-member").await;
    let (stranger, _) = seed_agent_with_group(&pool, "r22-rest-stranger").await;
    let (author, _) = seed_agent_with_group(&pool, "r22-rest-author").await;
    let frame = frame(&pool, "r22_rest_reads").await;
    let target = seed_public_claim(&pool, author, "r22 rest target").await;

    // The public BBA, then the reads every reader must keep getting.
    discount_bba(&pool, target, frame, author, None, 0.6).await;
    let public_only = pignistic(&state, &pool, Some(stranger), target, frame).await;
    let count_before = count(&state, &pool, stranger, target).await;
    assert_eq!(count_before, 1, "PREMISE: one BBA");

    // A BBA citing evidence narrowed to the member's group (its row stays
    // public: it inherits the claim's tenancy).
    let hidden = narrowed_evidence(&pool, target, group, member).await;
    discount_bba(&pool, target, frame, member, Some(hidden), 0.8).await;
    // And an edge-factor BBA carrying a group-private claim's belief through
    // the group's edge.
    let private_source = seed_group_claim(&pool, member, group, "r22 rest private source").await;
    sqlx::query("UPDATE claims SET belief = 0.9, plausibility = 0.95 WHERE id = $1")
        .bind(private_source)
        .execute(&pool)
        .await
        .expect("source interval");
    let edge = seed_edge(&pool, private_source, target).await;
    let member_viewer = Viewer::resolve(&pool, member).await.expect("viewer");
    let mut conn = pool.acquire().await.expect("acquire");
    ensure_binary_frame(&mut conn, &member_viewer)
        .await
        .expect("binary_truth");
    let wired = auto_wire_ds_for_edge(
        &mut conn,
        &member_viewer,
        edge,
        member,
        private_source,
        target,
        "supports",
    )
    .await
    .expect("wire the edge factor");
    assert_eq!(wired, EdgeFactorOutcome::Wired, "PREMISE: the edge wires");
    drop(conn);

    // The member, on its own stamped read, sees everything it can trace.
    let mine = pignistic(&state, &pool, Some(member), target, frame).await;
    assert!(
        mine.0 > public_only.0 + 1e-3 && mine.1 > public_only.1 + 1e-3,
        "the group member's own read must fold its group's evidence: {mine:?} vs {public_only:?}"
    );
    assert_eq!(
        count(&state, &pool, member, target).await,
        3,
        "the member counts every BBA it can trace"
    );

    // A stranger and the public reader: nothing moved.
    for caller in [Some(stranger), None] {
        let theirs = pignistic(&state, &pool, caller, target, frame).await;
        assert!(
            close(theirs, public_only),
            "GET /pignistic served {caller:?} a value moved by evidence narrowed to a group: \
             {public_only:?} -> {theirs:?}"
        );
    }
    assert_eq!(
        count(&state, &pool, stranger, target).await,
        count_before,
        "GET /belief's mass_function_count told a stranger that BBAs derived from sources it \
         cannot read exist"
    );
}

async fn link(pool: &PgPool, agent: Uuid, human: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("link the agent to its human");
    assert!(out.link_live, "{out:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_pignistic_never_aggregates_two_agents_of_one_human(pool: PgPool) {
    let state = app_role_state(&pool).await;
    let frame = frame(&pool, "r36_rest_pignistic").await;
    let (human, _) = seed_human_operator(&pool, "r36-rest-human").await;
    let (one, _) = seed_agent_with_group(&pool, "r36-rest-one").await;
    let (two, _) = seed_agent_with_group(&pool, "r36-rest-two").await;
    link(&pool, one, human).await;
    link(&pool, two, human).await;
    let (stranger, _) = seed_agent_with_group(&pool, "r36-rest-stranger").await;
    let (author, _) = seed_agent_with_group(&pool, "r36-rest-author").await;
    let claim = |label: &'static str| {
        let pool = pool.clone();
        async move { seed_public_claim(&pool, author, label).await }
    };
    let (alone, siblings, owners) = (
        claim("r36 rest stronger alone").await,
        claim("r36 rest siblings").await,
        claim("r36 rest different owners").await,
    );

    discount_bba(&pool, alone, frame, two, None, 0.7).await;
    // The stronger sibling first, so "the latest row wins" cannot pass.
    discount_bba(&pool, siblings, frame, two, None, 0.7).await;
    discount_bba(&pool, siblings, frame, one, None, 0.6).await;
    discount_bba(&pool, owners, frame, two, None, 0.7).await;
    discount_bba(&pool, owners, frame, stranger, None, 0.6).await;

    let baseline = pignistic(&state, &pool, Some(author), alone, frame).await;
    let s = pignistic(&state, &pool, Some(author), siblings, frame).await;
    assert!(
        close(s, baseline),
        "GET /pignistic aggregated two agents of one human: {s:?} vs the stronger alone \
         {baseline:?}"
    );
    let d = pignistic(&state, &pool, Some(author), owners, frame).await;
    assert!(
        d.0 > baseline.0 + 1e-3 && d.1 > baseline.1 + 1e-3,
        "agents of different owners must still reinforce: {d:?} vs {baseline:?}"
    );
}
