//! `POST /api/v1/bp/propagate` builds its factor graph from the scope the
//! request names, never from the whole `factors` table (backlog b02347c6).
//!
//! Every read-only run used to load every BP-readable factor when `frame_id`
//! was absent, so a run's cost grew with the corpus rather than with the
//! request. A request now names a claim set (`claim_ids`, expanded
//! `max_hops` factor hops through the factor graph) or a frame (`frame_id`),
//! and is refused (400) when it names neither. A scope that reaches more
//! factors than the loader's cap is refused, not truncated.
#![cfg(feature = "db")]

mod viewer_fixture;

use std::collections::BTreeSet;

use axum::extract::State;
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::computation::{
    propagate_beliefs, PropagateRequest, BP_MAX_HOPS, BP_MAX_SCOPE_CLAIMS,
};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{scoped_pool, seed_agent_with_group, seed_public_claim};

fn read_bearer(agent: Uuid) -> axum::Extension<epigraph_api::middleware::bearer::AuthContext> {
    axum::Extension(epigraph_api::middleware::bearer::AuthContext {
        client_id: agent,
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: epigraph_api::middleware::ClientType::Service,
        scopes: vec!["claims:read".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    })
}

async fn run(
    pool: &PgPool,
    state: &AppState,
    agent: Uuid,
    body: serde_json::Value,
) -> Result<serde_json::Value, ApiError> {
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    let request: PropagateRequest = serde_json::from_value(body).expect("request");
    propagate_beliefs(
        ViewerExtractor(viewer),
        read_bearer(agent),
        State(state.clone()),
        Json(request),
    )
    .await
    .map(|Json(v)| v)
}

fn refused_on(res: Result<serde_json::Value, ApiError>, field: &str, what: &str) {
    match res {
        Err(ApiError::ValidationError { field: f, .. }) => {
            assert_eq!(f, field, "{what}: refused on the wrong field")
        }
        other => panic!("{what}: must be a 400 on `{field}`, got {other:?}"),
    }
}

async fn factor(pool: &PgPool, a: Uuid, b: Uuid, frame: Option<Uuid>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO factors (factor_type, variable_ids, potential, frame_id) \
         VALUES ('evidential_support', $1, '{\"strength\": 0.8}', $2) RETURNING id",
    )
    .bind(vec![a, b])
    .bind(frame)
    .fetch_one(pool)
    .await
    .expect("seed a factor")
}

async fn frame(pool: &PgPool, name: &str) -> Uuid {
    epigraph_db::FrameRepository::create(
        pool,
        name,
        None,
        &["supported".to_string(), "unsupported".to_string()],
    )
    .await
    .expect("frame")
    .id
}

fn variables(body: &serde_json::Value) -> BTreeSet<Uuid> {
    body["updated_beliefs"]
        .as_array()
        .expect("updated_beliefs is a list")
        .iter()
        .map(|u| u["claim_id"].as_str().unwrap().parse().unwrap())
        .collect()
}

/// A chain `s - x1 - x2 - x3` (one factor per link, no frame) and, apart from
/// it, a pair `u1 - u2` in its own frame. All claims public, so every factor
/// is readable by any caller and only the scope decides what is loaded.
struct Graph {
    agent: Uuid,
    s: Uuid,
    x1: Uuid,
    x2: Uuid,
    x3: Uuid,
    u1: Uuid,
    u2: Uuid,
    frame: Uuid,
}

async fn graph(pool: &PgPool) -> Graph {
    let (agent, _) = seed_agent_with_group(pool, "b02347c6-bp-scope").await;
    let s = seed_public_claim(pool, agent, "bp scope seed").await;
    let x1 = seed_public_claim(pool, agent, "bp scope hop 1").await;
    let x2 = seed_public_claim(pool, agent, "bp scope hop 2").await;
    let x3 = seed_public_claim(pool, agent, "bp scope hop 3").await;
    let u1 = seed_public_claim(pool, agent, "bp scope unrelated 1").await;
    let u2 = seed_public_claim(pool, agent, "bp scope unrelated 2").await;
    let frame = frame(pool, "b02347c6_bp_scope_frame").await;
    factor(pool, s, x1, None).await;
    factor(pool, x1, x2, None).await;
    factor(pool, x2, x3, None).await;
    factor(pool, u1, u2, Some(frame)).await;
    Graph {
        agent,
        s,
        x1,
        x2,
        x3,
        u1,
        u2,
        frame,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_request_must_name_a_claim_set_or_a_frame(pool: PgPool) {
    let g = graph(&pool).await;
    let state = AppState::with_scoped_pool(scoped_pool(&pool).await, ApiConfig::default());

    refused_on(
        run(&pool, &state, g.agent, serde_json::json!({})).await,
        "claim_ids",
        "a request with no scope",
    );
    refused_on(
        run(&pool, &state, g.agent, serde_json::json!({"claim_ids": []})).await,
        "claim_ids",
        "an empty claim set",
    );
    let too_many: Vec<Uuid> = (0..=BP_MAX_SCOPE_CLAIMS).map(|_| Uuid::new_v4()).collect();
    refused_on(
        run(
            &pool,
            &state,
            g.agent,
            serde_json::json!({"claim_ids": too_many}),
        )
        .await,
        "claim_ids",
        "one claim over the cap",
    );
    refused_on(
        run(
            &pool,
            &state,
            g.agent,
            serde_json::json!({"claim_ids": [g.s], "max_hops": BP_MAX_HOPS + 1}),
        )
        .await,
        "max_hops",
        "one hop over the cap",
    );
    refused_on(
        run(
            &pool,
            &state,
            g.agent,
            serde_json::json!({"claim_ids": [g.s], "max_hops": 0}),
        )
        .await,
        "max_hops",
        "zero hops",
    );
    refused_on(
        run(
            &pool,
            &state,
            g.agent,
            serde_json::json!({"frame_id": g.frame, "max_hops": 2}),
        )
        .await,
        "max_hops",
        "hops with no claim set to expand",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_scope_loads_only_the_factors_within_its_hops(pool: PgPool) {
    let g = graph(&pool).await;
    let state = AppState::with_scoped_pool(scoped_pool(&pool).await, ApiConfig::default());

    for (hops, want_factors, want_vars) in [
        (1_usize, 1_u64, vec![g.s, g.x1]),
        (2, 2, vec![g.s, g.x1, g.x2]),
        (3, 3, vec![g.s, g.x1, g.x2, g.x3]),
    ] {
        let body = run(
            &pool,
            &state,
            g.agent,
            serde_json::json!({"claim_ids": [g.s], "max_hops": hops, "mode": "scalar"}),
        )
        .await
        .unwrap_or_else(|e| panic!("{hops} hops: a scoped run answers 200, got {e:?}"));
        assert_eq!(
            body["factors_count"].as_u64(),
            Some(want_factors),
            "{hops} hops from s loads exactly the factors that many links away: {body}"
        );
        assert_eq!(
            variables(&body),
            want_vars.into_iter().collect::<BTreeSet<_>>(),
            "{hops} hops: the run's variables are the scope's: {body}"
        );
    }

    // The default is two hops.
    let body = run(
        &pool,
        &state,
        g.agent,
        serde_json::json!({"claim_ids": [g.s], "mode": "scalar"}),
    )
    .await
    .expect("a default-hop run answers 200");
    assert_eq!(body["factors_count"].as_u64(), Some(2), "{body}");

    // A frame scope loads that frame's factors and nothing else.
    let body = run(
        &pool,
        &state,
        g.agent,
        serde_json::json!({"frame_id": g.frame, "mode": "scalar"}),
    )
    .await
    .expect("a frame-scoped run answers 200");
    assert_eq!(body["factors_count"].as_u64(), Some(1), "{body}");
    assert_eq!(
        variables(&body),
        [g.u1, g.u2].into_iter().collect::<BTreeSet<_>>(),
        "a frame scope: {body}"
    );

    // Both: the claim set is expanded inside the frame only. `s` has no
    // factor in the frame, so nothing is loaded.
    let body = run(
        &pool,
        &state,
        g.agent,
        serde_json::json!({"frame_id": g.frame, "claim_ids": [g.s], "mode": "scalar"}),
    )
    .await
    .expect("a frame + claim scope answers 200");
    assert_eq!(body["factors_count"].as_u64(), Some(0), "{body}");
}

/// The loader refuses a scope that reaches more factors than its cap, and
/// says so instead of returning a truncated graph.
#[sqlx::test(migrations = "../../migrations")]
async fn a_scope_over_the_factor_cap_is_refused_not_truncated(pool: PgPool) {
    use epigraph_db::repos::factor::{BpFactorScope, BpScopeLoad, FactorRepository};
    let g = graph(&pool).await;
    let scoped = scoped_pool(&pool).await;
    let viewer = Viewer::resolve(&pool, g.agent).await.expect("resolve");
    let mut read = scoped.read_as(&viewer).await.expect("a stamped read");
    let seeds = [g.s];
    let scope = BpFactorScope {
        frame_id: None,
        claim_ids: Some(&seeds),
        max_hops: 3,
    };

    match FactorRepository::load_bp_scope(&mut read, &viewer, &scope, 2)
        .await
        .expect("load")
    {
        BpScopeLoad::OverCap { cap } => assert_eq!(cap, 2),
        BpScopeLoad::Loaded(rows) => panic!(
            "three factors are in scope and the cap is two: must refuse, loaded {}",
            rows.len()
        ),
    }
    match FactorRepository::load_bp_scope(&mut read, &viewer, &scope, 3)
        .await
        .expect("load")
    {
        BpScopeLoad::Loaded(rows) => assert_eq!(
            rows.len(),
            3,
            "CALIBRATION: at a cap of exactly the scope's size everything loads"
        ),
        BpScopeLoad::OverCap { .. } => panic!("three factors fit a cap of three"),
    }
    // A frame-only scope is capped the same way.
    let frame_scope = BpFactorScope {
        frame_id: None,
        claim_ids: None,
        max_hops: 0,
    };
    assert!(
        matches!(
            FactorRepository::load_bp_scope(&mut read, &viewer, &frame_scope, 3)
                .await
                .expect("load"),
            BpScopeLoad::OverCap { cap: 3 }
        ),
        "an unfiltered frame scope over four factors refuses at a cap of three"
    );
}

/// A BP run is CPU-bound for up to `BP_MAX_ITERATIONS` sweeps on tokio's
/// blocking pool, whose default ceiling (512 threads) is shared with every
/// other blocking user in the process. Concurrent runs are capped by
/// `AppState::bp_runs`; one beyond the limit is refused (503) at once, and
/// a finished run gives its permit back.
#[sqlx::test(migrations = "../../migrations")]
async fn bp_runs_beyond_the_configured_limit_are_refused(pool: PgPool) {
    let g = graph(&pool).await;
    let state = AppState::with_scoped_pool(scoped_pool(&pool).await, ApiConfig::default())
        .with_bp_max_concurrent(1);
    let body = serde_json::json!({"claim_ids": [g.s], "mode": "scalar"});

    let held = state
        .bp_runs
        .clone()
        .try_acquire_owned()
        .expect("CALIBRATION: the one permit is free");
    match run(&pool, &state, g.agent, body.clone()).await {
        Err(ApiError::ServiceUnavailable { .. }) => {}
        other => panic!("a run beyond the limit must be a 503, got {other:?}"),
    }

    drop(held);
    let ok = run(&pool, &state, g.agent, body)
        .await
        .expect("with the permit free the same run answers 200");
    assert_eq!(ok["factors_count"].as_u64(), Some(2), "{ok}");
    assert_eq!(
        state.bp_runs.available_permits(),
        1,
        "a finished run gives its permit back"
    );
}
