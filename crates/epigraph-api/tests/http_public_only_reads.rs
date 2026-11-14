#![cfg(feature = "db")]
//! The HTTP read handlers converted on 2026-11-05 serve a member its OWN
//! group-private rows on the PRODUCTION pool shape, and still withhold a
//! stranger's.
//!
//! # The defect
//!
//! The same day's MCP finding, on the REST surface. `bin/server.rs` builds
//! `AppState.db_pool` as `scoped.inner()`, and in production that pool logs in
//! as `epigraph_app`, which is neither superuser nor `BYPASSRLS`, against
//! tables whose row security is FORCEd. A statement on `state.db_pool` carries
//! no `epigraph.group_ids`, so the policies admit `visibility = 'public'` only.
//! The in-query `$V` predicate names the caller's groups, but the policy runs
//! first and has already removed the rows: a member's own group-private claims
//! were missing from these endpoints, with a 200 and no log line.
//!
//! # The instrument, and how it differs from `split_state`
//!
//! The `*_scoped_read.rs` files give `AppState.db_pool` a downgraded pool and
//! `AppState.scoped` a SUPERUSER one, so their converted arm proves only the
//! in-query predicate. [`production_state`] is the deployment itself:
//! `ScopedPool::connect_downgraded_for_tests(.., "epigraph_app")` handed to
//! `AppState::with_scoped_pool`, so `db_pool` IS `scoped.inner()` and BOTH arms
//! run as `epigraph_app`. A converted read therefore passes the row-level
//! policy and the `$V` predicate together, and a site reverted to
//! `&state.db_pool` loses the member's row. [`the_production_pool_is_public_only_when_unstamped`]
//! measures that mechanism directly; every other arm asserts the member's own
//! private row is served (the positive control) and a stranger's is absent (the
//! widening direction).

mod viewer_fixture;

use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::computation::{propagate_beliefs, PropagateRequest};
use epigraph_api::routes::cross_source::{
    get_cross_source_matches, list_candidates, ListCandidatesQuery,
};
use epigraph_api::routes::experiments::{
    design_experiment, hypothesize, DesignExperimentRequest, HypothesizeRequest,
};
use epigraph_api::routes::graph_query::{execute_graph_query, GraphQueryRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    database_url_for, seed_agent_with_group, seed_group_claim, seed_public_claim,
};

// ── The instrument ──

/// `AppState` exactly as `bin/server.rs` builds it, on the application role.
async fn production_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("epigraph_app ScopedPool");
    let state = AppState::with_scoped_pool(scoped, ApiConfig::default());

    let (user, privileged): (String, bool) = sqlx::query_as(
        "SELECT current_user::text, rolsuper OR rolbypassrls \
           FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&state.db_pool)
    .await
    .expect("role of the production pool");
    assert_eq!(
        user, "epigraph_app",
        "CALIBRATION: db_pool must run as the application role, as production does"
    );
    assert!(
        !privileged,
        "CALIBRATION: epigraph_app must be subject to row security; a superuser or \
         BYPASSRLS role here makes every arm in this file vacuous"
    );
    let scoped_user: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(state.scoped.as_ref().expect("scoped").inner())
        .await
        .expect("role of the scoped pool");
    assert_eq!(
        scoped_user, user,
        "CALIBRATION: db_pool and scoped.inner() must be the same login, which is \
         what with_scoped_pool and bin/server.rs both build"
    );
    state
}

/// Resolved on the superuser pool: `Viewer::resolve` reads memberships through
/// a SECURITY DEFINER helper, so the application role would resolve the same
/// viewer, and no assertion here rests on the difference.
async fn viewer_for(pool: &PgPool, agent: Uuid) -> Viewer {
    Viewer::resolve(pool, agent).await.expect("resolve viewer")
}

fn read_auth(agent: Uuid) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Service,
        scopes: vec!["claims:read".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

/// A member, a stranger, and three claims: one public, one private to the
/// member's group, one private to the stranger's.
struct Plant {
    member: Uuid,
    group: Uuid,
    public: Uuid,
    mine: Uuid,
    theirs: Uuid,
}

async fn plant(pool: &PgPool, tag: &str) -> Plant {
    let (member, group) = seed_agent_with_group(pool, &format!("{tag}-member")).await;
    let (stranger, stranger_group) = seed_agent_with_group(pool, &format!("{tag}-stranger")).await;
    let public = seed_public_claim(pool, member, &format!("{tag} public claim")).await;
    let mine = seed_group_claim(pool, member, group, &format!("{tag} member private claim")).await;
    let theirs = seed_group_claim(
        pool,
        stranger,
        stranger_group,
        &format!("{tag} stranger private claim"),
    )
    .await;
    Plant {
        member,
        group,
        public,
        mine,
        theirs,
    }
}

fn pgvec(v: &[f32]) -> String {
    format!(
        "[{}]",
        v.iter().map(f32::to_string).collect::<Vec<_>>().join(",")
    )
}

// ── The mechanism ──

/// The measurement behind every other arm: on the production pool an
/// unstamped statement cannot see the member's own private claim, and a
/// viewer-stamped one can.
#[sqlx::test(migrations = "../../migrations")]
async fn the_production_pool_is_public_only_when_unstamped(pool: PgPool) {
    let p = plant(&pool, "mechanism").await;
    let state = production_state(&pool).await;
    let viewer = viewer_for(&pool, p.member).await;

    let count = "SELECT count(*) FROM claims WHERE id = ANY($1)";
    let ids = vec![p.public, p.mine, p.theirs];

    let raw: i64 = sqlx::query_scalar(count)
        .bind(&ids)
        .fetch_one(&state.db_pool)
        .await
        .expect("count on the raw pool");
    assert_eq!(
        raw, 1,
        "the unstamped production pool must see the public claim only: this is the \
         defect the converted handlers no longer have"
    );

    let mut read = state.read_as(&viewer).await.expect("read_as");
    let stamped: i64 = sqlx::query_scalar(count)
        .bind(&ids)
        .fetch_one(&mut *read)
        .await
        .expect("count on the stamped read");
    assert_eq!(
        stamped, 2,
        "POSITIVE CONTROL: stamped with the member's viewer, the same session sees \
         the public claim and the member's own private claim, and not the stranger's"
    );
}

// ── routes/graph_query.rs ──

#[sqlx::test(migrations = "../../migrations")]
async fn graph_query_serves_the_members_own_private_claim(pool: PgPool) {
    let p = plant(&pool, "gql").await;
    sqlx::query(
        "UPDATE claims SET properties = properties || '{\"probe\": \"gql-public-only\"}' \
          WHERE id = ANY($1)",
    )
    .bind(vec![p.public, p.mine, p.theirs])
    .execute(&pool)
    .await
    .expect("tag probe claims");
    let state = production_state(&pool).await;

    let Json(body) = execute_graph_query(
        ViewerExtractor(viewer_for(&pool, p.member).await),
        State(state),
        Json(GraphQueryRequest {
            query: "MATCH (n:claim) WHERE n.probe = 'gql-public-only' RETURN *".to_string(),
            agent_id: None,
        }),
    )
    .await
    .expect("execute_graph_query");

    let ids: Vec<Uuid> = body.nodes.iter().map(|n| n.id).collect();
    assert!(
        ids.contains(&p.mine),
        "POSITIVE CONTROL: the member's own private claim must be a node. Got {ids:?}"
    );
    assert!(
        ids.contains(&p.public),
        "the public claim must be a node: {ids:?}"
    );
    assert!(
        !ids.contains(&p.theirs),
        "the stranger's private claim must be absent: {ids:?}"
    );
}

// ── routes/experiments.rs ──

#[sqlx::test(migrations = "../../migrations")]
async fn hypothesize_finds_the_members_own_private_claim(pool: PgPool) {
    let p = plant(&pool, "hyp").await;
    let statement = "hypothesize public-only probe statement";
    let embedder: std::sync::Arc<dyn EmbeddingService> =
        std::sync::Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
    let vector = pgvec(&embedder.generate(statement).await.expect("mock embedding"));
    for c in [p.public, p.mine, p.theirs] {
        viewer_fixture::set_claim_embedding(&pool, c, &vector).await;
    }
    let state = production_state(&pool)
        .await
        .with_embedding_service(embedder);

    let Json(body) = hypothesize(
        ViewerExtractor(viewer_for(&pool, p.member).await),
        State(state),
        Json(HypothesizeRequest {
            statement: statement.to_string(),
            search_radius: Some(0.9),
            cluster_count: Some(1),
        }),
    )
    .await
    .expect("hypothesize");

    let similar: Vec<String> = body["similar_claims"]
        .as_array()
        .expect("similar_claims")
        .iter()
        .map(|c| c["id"].as_str().expect("id").to_string())
        .collect();
    assert_eq!(
        body["similar_count"], 2,
        "the member may read exactly two of the three identical-vector claims: {body}"
    );
    assert!(
        similar.contains(&p.mine.to_string()),
        "POSITIVE CONTROL: the member's own private claim must be among the similar \
         claims: {similar:?}"
    );
    assert!(
        !similar.contains(&p.theirs.to_string()),
        "stranger leaked: {similar:?}"
    );

    // The clustering branch's second read, on the same connection.
    let members: Vec<String> = body["clusters"][0]["claim_ids"]
        .as_array()
        .expect("one cluster")
        .iter()
        .map(|c| c.as_str().expect("id").to_string())
        .collect();
    assert!(
        members.contains(&p.mine.to_string()) && !members.contains(&p.theirs.to_string()),
        "the neighborhood-embeddings read must carry the member's private claim and \
         not the stranger's: {members:?}"
    );
}

/// A method citing `claim`, with a paper asserting that claim. The edge inherits
/// the claim's tenancy (migration 070), so a private claim's grounding edge is
/// private too: only a stamped read can count it.
async fn grounded_method(pool: &PgPool, name: &str, claim: Uuid) -> Uuid {
    let method: Uuid = sqlx::query_scalar(
        "INSERT INTO methods (id, name, canonical_name, technique_type, source_claim_ids) \
         VALUES (gen_random_uuid(), $1, $1, 'measurement', $2) RETURNING id",
    )
    .bind(name)
    .bind(vec![claim])
    .fetch_one(pool)
    .await
    .expect("seed method");
    let paper: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (id, doi, title) \
         VALUES (gen_random_uuid(), '10.public-only/' || gen_random_uuid()::text, $1) \
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("seed paper");
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper)
    .bind(claim)
    .execute(pool)
    .await
    .expect("seed grounding edge");
    method
}

#[sqlx::test(migrations = "../../migrations")]
async fn design_experiment_counts_the_members_own_private_evidence(pool: PgPool) {
    let p = plant(&pool, "design").await;
    let m_mine = grounded_method(&pool, "design_mine_method", p.mine).await;
    let m_theirs = grounded_method(&pool, "design_theirs_method", p.theirs).await;
    let state = production_state(&pool).await;

    let Json(body) = design_experiment(
        ViewerExtractor(viewer_for(&pool, p.member).await),
        State(state),
        Json(DesignExperimentRequest {
            hypothesis_id: p.public,
            method_ids: vec![m_mine, m_theirs],
            constraints: None,
        }),
    )
    .await
    .expect("design_experiment");

    let gaps: Vec<String> = body["critical_gaps"]
        .as_array()
        .expect("critical_gaps")
        .iter()
        .map(|g| g.as_str().expect("gap").to_string())
        .collect();
    assert!(
        !gaps.iter().any(|g| g.starts_with("design_mine_method")),
        "POSITIVE CONTROL: the method grounded in the member's own private claim has \
         published evidence the member can read, so it must not be flagged: {gaps:?}"
    );
    assert!(
        gaps.iter().any(|g| g.starts_with("design_theirs_method")),
        "the method grounded only in a stranger's private claim must still be flagged \
         as having no evidence the member can read: {gaps:?}"
    );
}

// ── routes/cross_source.rs ──

async fn candidate(pool: &PgPool, x: Uuid, y: Uuid, rationale: &str) -> Uuid {
    let (lo, hi) = if x < y { (x, y) } else { (y, x) };
    sqlx::query_scalar(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status, verifier_rationale) \
         VALUES ($1, $2, 0.7, '{}'::jsonb, 'pending', $3) RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .bind(rationale)
    .fetch_one(pool)
    .await
    .expect("seed match candidate")
}

#[sqlx::test(migrations = "../../migrations")]
async fn cross_source_matches_serve_the_members_own_private_claim(pool: PgPool) {
    let p = plant(&pool, "xsrc").await;
    let ours = candidate(&pool, p.mine, p.public, "member pair").await;
    let _strangers = candidate(&pool, p.theirs, p.public, "stranger pair").await;
    let state = production_state(&pool).await;

    let served = get_cross_source_matches(
        State(state.clone()),
        ViewerExtractor(viewer_for(&pool, p.member).await),
        read_auth(p.member),
        Path(p.mine),
    )
    .await;
    let body = match served {
        Ok(Json(b)) => b,
        Err(e) => panic!(
            "POSITIVE CONTROL: the member's own private claim must not 404 (an unstamped \
             existence probe cannot see it): {e:?}"
        ),
    };
    let pending: Vec<String> = body.pending.iter().map(|c| c.id.clone()).collect();
    assert_eq!(
        pending,
        vec![ours.to_string()],
        "the member's pair must be the one pending candidate on its own claim"
    );

    let withheld = get_cross_source_matches(
        State(state.clone()),
        ViewerExtractor(viewer_for(&pool, p.member).await),
        read_auth(p.member),
        Path(p.theirs),
    )
    .await;
    assert!(
        withheld.is_err(),
        "a stranger's private claim must 404 for the member"
    );

    let Json(listed) = list_candidates(
        State(state),
        ViewerExtractor(viewer_for(&pool, p.member).await),
        read_auth(p.member),
        Query(ListCandidatesQuery {
            status: Some("pending".to_string()),
            limit: 100,
        }),
    )
    .await
    .expect("list_candidates");
    let ids: Vec<String> = listed.iter().map(|c| c.id.clone()).collect();
    assert_eq!(
        ids,
        vec![ours.to_string()],
        "the member lists its own pair and not the stranger's"
    );
    let row = &listed[0];
    let mine_excerpt = if row.claim_a == p.mine.to_string() {
        &row.claim_a_excerpt
    } else {
        &row.claim_b_excerpt
    };
    assert!(
        mine_excerpt.contains("member private claim"),
        "POSITIVE CONTROL: the excerpt of the member's own private claim must be its \
         content, not \"(claim not found)\": {mine_excerpt:?}"
    );
}

// ── routes/computation.rs (`bp_seed_rows`) ──

async fn bba(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, t: f64) {
    epigraph_db::MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        None,
        &serde_json::json!({"0": t, "0,1": 1.0 - t}),
        None,
        Some("auto_wire"),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store a BBA");
}

async fn factor(pool: &PgPool, frame: Uuid, a: Uuid, b: Uuid) {
    sqlx::query(
        "INSERT INTO factors (id, factor_type, variable_ids, potential, frame_id) \
         VALUES ($1, 'evidential_support', $2, $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(vec![a, b])
    .bind(serde_json::json!({"strength": 0.8}))
    .bind(frame)
    .execute(pool)
    .await
    .expect("seed factor");
}

/// Two isolated components with the same shape and the same BBA: one on a
/// public claim, one on the member's own private claim. Their BP values must be
/// equal. On the unstamped pool the private claim's BBA is invisible, its seed
/// is empty and the two values differ.
#[sqlx::test(migrations = "../../migrations")]
async fn bp_seeds_the_members_own_private_claim(pool: PgPool) {
    let p = plant(&pool, "bpseed").await;
    // The canonical frame: only its BBAs seed BP.
    let frame = epigraph_db::FrameRepository::create(
        &pool,
        "binary_truth",
        None,
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id;
    let public_partner = seed_public_claim(&pool, p.member, "bpseed public partner").await;
    let private_partner =
        seed_group_claim(&pool, p.member, p.group, "bpseed private partner").await;
    factor(&pool, frame, p.public, public_partner).await;
    factor(&pool, frame, p.mine, private_partner).await;
    bba(&pool, p.public, frame, p.member, 0.8).await;
    bba(&pool, p.mine, frame, p.member, 0.8).await;
    let state = production_state(&pool).await;

    let request: PropagateRequest = serde_json::from_value(serde_json::json!({
        "frame_id": frame,
        "apply_updates": false,
        "mode": "cdst",
        "max_iterations": 10,
    }))
    .expect("request");
    let Json(body) = propagate_beliefs(
        ViewerExtractor(viewer_for(&pool, p.member).await),
        State(state),
        Json(request),
    )
    .await
    .unwrap_or_else(|e| panic!("propagate_beliefs failed: {e:?}"));

    let served = |claim: Uuid| -> f64 {
        body["updated_beliefs"]
            .as_array()
            .expect("updated_beliefs")
            .iter()
            .find(|b| b["claim_id"].as_str() == Some(claim.to_string().as_str()))
            .and_then(|b| b["betp"].as_f64())
            .unwrap_or_else(|| panic!("no BP value for {claim}: {body}"))
    };
    let public_value = served(p.public);
    let private_value = served(p.mine);
    assert!(
        (public_value - 0.5).abs() > 1e-3,
        "PREMISE: the BBA must move the public claim's value off the prior: {public_value}"
    );
    assert!(
        (private_value - public_value).abs() < 1e-9,
        "POSITIVE CONTROL: the member's own private claim carries the same BBA in the \
         same shape, so it must get the same BP value ({private_value} vs \
         {public_value}); a gap means its BBA was not seeded"
    );
}
