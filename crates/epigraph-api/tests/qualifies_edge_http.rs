//! `POST /api/v1/edges` accepts `qualifies`, a BELIEF-NEUTRAL scope caveat
//! between two claims (backlog 99582af7).
//!
//! `A qualifies B` records that A bounds the conditions under which B applies
//! (a salt regime, a geometry, a population) without saying B is false. Before
//! this relation existed the only way to wire such a caveat was `contradicts` /
//! `refutes`, which pushes B's belief down for a reason that is not about B's
//! truth, so honest scope caveats were either mis-filed as refutations or left
//! unwired.
//!
//! The HTTP twin of MCP
//! `link_epistemic_smoke.rs::qualifies_edge_is_created_but_does_not_move_belief`.
//! The REST path has a belief side effect the MCP tool does not: the legacy BP
//! `factors` row (the `edges_auto_factor` trigger; the route's own INSERT was
//! removed under atom-level belief). Neutrality is pinned on it and on the DS wire, against a target
//! that already HAS a belief the wire could move, each with a positive control
//! on a parallel pair: a `refutes` edge that does move belief, and a
//! `supports` edge that does create a factor. The route's 1-hop dependent
//! propagation runs only when the wire materialized a mass function, so the
//! zero-BBA assertion covers it.

mod viewer_fixture;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Extension;
use axum::Json;
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::edges::{create_edge, CreateEdgeRequest, CreateEdgeResponse};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, seed_agent_with_group, seed_public_claim};

/// Same shape as `symmetric_edge_wiring_http.rs::state`: a session-stamped
/// `ScopedPool`, so the post-commit DS recomputation lands.
async fn state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped = ScopedPool::connect(&url, SessionGucMode::Session)
        .await
        .expect("connect a scoped pool");
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default());
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

fn auth(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: agent,
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Service,
        scopes: vec!["edges:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

fn claim_edge(source: Uuid, target: Uuid, relationship: &str) -> CreateEdgeRequest {
    CreateEdgeRequest {
        source_id: source,
        target_id: target,
        source_type: "claim".to_string(),
        target_type: "claim".to_string(),
        relationship: relationship.to_string(),
        properties: Some(serde_json::json!({"condition": "1 M monovalent NaCl only"})),
        labels: None,
        valid_from: None,
        valid_to: None,
        if_not_exists: true,
    }
}

async fn post(
    pool: &PgPool,
    state: &AppState,
    agent: Uuid,
    req: CreateEdgeRequest,
) -> (StatusCode, CreateEdgeResponse) {
    let relationship = req.relationship.clone();
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let result = create_edge(
        ViewerExtractor(viewer),
        State(state.clone()),
        auth(agent),
        Json(req),
    )
    .await;
    match result {
        Ok((status, Json(body))) => (status, body),
        Err(e) => panic!("POST /api/v1/edges must accept '{relationship}', got {e:?}"),
    }
}

async fn betp(pool: &PgPool, claim: Uuid) -> f64 {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read pignistic_prob")
        .expect("pignistic_prob set")
}

async fn bbas_on(pool: &PgPool, edge: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM mass_functions WHERE perspective_id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("count edge BBAs")
}

/// Legacy BP factors over the pair, whichever writer made them (today only
/// the `edges_auto_factor` trigger).
async fn factors_over(pool: &PgPool, a: Uuid, b: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM factors WHERE variable_ids @> ARRAY[$1, $2]::uuid[]")
        .bind(a)
        .bind(b)
        .fetch_one(pool)
        .await
        .expect("count factors over the pair")
}

async fn give_belief(pool: &PgPool, claims: &[Uuid]) {
    sqlx::query(
        "UPDATE claims SET belief = 0.9, plausibility = 0.9, pignistic_prob = 0.9 \
         WHERE id = ANY($1)",
    )
    .bind(claims.to_vec())
    .execute(pool)
    .await
    .expect("give the claims a belief interval");
}

#[sqlx::test(migrations = "../../migrations")]
async fn qualifies_edge_is_accepted_and_moves_no_belief(pool: PgPool) {
    let state = state(&pool).await;
    let (agent, _) = seed_agent_with_group(&pool, "qualifies-http").await;
    let caveat = seed_public_claim(&pool, agent, "thresholds hold only in 1 M NaCl").await;
    let hub = seed_public_claim(&pool, agent, "anchor density threshold").await;
    let refuter = seed_public_claim(&pool, agent, "control: a refuting claim").await;
    let refuted = seed_public_claim(&pool, agent, "control: the refuted claim").await;
    let supporter = seed_public_claim(&pool, agent, "control: a supporting claim").await;
    let supported = seed_public_claim(&pool, agent, "control: the supported claim").await;
    give_belief(
        &pool,
        &[caveat, hub, refuter, refuted, supporter, supported],
    )
    .await;

    // Control: on this exact fixture a non-neutral relation from a 0.9 source
    // DOES move its target. Without it, "the hub kept 0.9" could just mean
    // nothing was ever going to be wired here.
    let (control_status, control) = post(
        &pool,
        &state,
        agent,
        claim_edge(refuter, refuted, "refutes"),
    )
    .await;
    assert_eq!(control_status, StatusCode::CREATED);
    let refuted_betp = betp(&pool, refuted).await;
    assert!(
        refuted_betp < 0.9 - 1e-6,
        "control: a refutes edge from a 0.9 source must lower its target, got {refuted_betp}"
    );
    assert_eq!(
        bbas_on(&pool, control.edge.id).await,
        1,
        "control wired one BBA"
    );

    // Control: a `supports` edge on this fixture DOES leave a legacy BP factor
    // over its pair, so the zero asserted for `qualifies` below is a measured
    // absence, not a query that never counts anything.
    let (factor_status, _) = post(
        &pool,
        &state,
        agent,
        claim_edge(supporter, supported, "supports"),
    )
    .await;
    assert_eq!(factor_status, StatusCode::CREATED);
    assert!(
        factors_over(&pool, supporter, supported).await >= 1,
        "control: a supports edge must leave a factor over its pair"
    );

    let (status, created) = post(&pool, &state, agent, claim_edge(caveat, hub, "qualifies")).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        created.edge.relationship, "qualifies",
        "stored in the lower-case canonical spelling"
    );
    assert_eq!(
        created.edge.source_id, caveat,
        "qualifies is directional: caveat -> hub"
    );
    assert_eq!(created.edge.target_id, hub);

    let hub_betp = betp(&pool, hub).await;
    assert!(
        (hub_betp - 0.9).abs() < 1e-9,
        "a scope caveat must not move the qualified claim's belief, got {hub_betp}"
    );
    assert_eq!(
        bbas_on(&pool, created.edge.id).await,
        0,
        "no mass function may be materialized for a qualifies edge"
    );
    assert_eq!(
        factors_over(&pool, caveat, hub).await,
        0,
        "no legacy BP factor may be created for a qualifies edge"
    );

    // Directionality, by behaviour: `hub qualifies caveat` is a different fact
    // from `caveat qualifies hub`. A symmetric claim relation dedups the
    // unordered pair whatever `if_not_exists` says and answers 200 with the
    // forward row; `qualifies` must create its own edge.
    let (reverse_status, reverse) =
        post(&pool, &state, agent, claim_edge(hub, caveat, "qualifies")).await;
    assert_eq!(
        reverse_status,
        StatusCode::CREATED,
        "'hub qualifies caveat' must create its own edge, not dedup onto the forward one"
    );
    assert_ne!(
        reverse.edge.id, created.edge.id,
        "the reverse qualifies must be a distinct edge"
    );
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE relationship = 'qualifies' \
         AND ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1))",
    )
    .bind(caveat)
    .bind(hub)
    .fetch_one(&pool)
    .await
    .expect("count qualifies rows over the pair");
    assert_eq!(rows, 2, "one qualifies row in each direction");
}
