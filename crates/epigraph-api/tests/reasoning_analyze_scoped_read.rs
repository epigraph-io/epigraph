#![cfg(feature = "db")]
//! `POST /api/v1/reasoning/analyze` answers from the caller's own view of the
//! graph, and only for a caller holding `analysis:reasoning`.
//!
//! # What the handler exposes
//!
//! With `edges` empty the handler loads claim-to-claim edges itself, then runs
//! the reasoning engine over them. Every derived row — a transitive support, a
//! contradiction, a component — names the two endpoint claim ids of the edges
//! it was derived from, and `stats.edges_loaded` counts them. So the edge read
//! decides which claim ids and which graph structure a response can carry, and
//! it has to be the caller's read, not an unfiltered one.
//!
//! # The corpus, and why each edge is shaped the way it is
//!
//! Three PUBLIC claims `p1 -> p2 -> p3`, chained by two `supports` edges:
//!
//! * `p1 -> p2` is FORCED to `('group', owner_group)` with
//!   `viewer_fixture::seed_edge_owned_by`. Both endpoints are public, so no
//!   claim predicate can be what withholds it from a stranger: only the EDGE
//!   predicate can. An edge left to migration 070's trigger would inherit its
//!   endpoints' visibility, and a stranger assertion over it would stay green
//!   with the edge predicate deleted.
//! * `p2 -> p3` is left to the trigger, so it is public. It is the non-vacuity
//!   control: the stranger's request must still return it, or an empty answer
//!   could be a broken endpoint rather than a working filter.
//!
//! Each arm asserts an EXACT `edges_loaded` and names every derived pair in
//! both directions, so a fail-open regression (stranger sees 2) and a
//! fail-closed one (owner sees 1) are both visible.
//!
//! # Why `#[sqlx::test]` plus `spawn_app`
//!
//! The arms go through the real router — bearer middleware, scope check,
//! `ViewerExtractor`, handler — on a private database
//! (`viewer_fixture::database_url_for`), as `graph_routes_test.rs` does. The
//! private database is what makes the `claim_ids`-less arm meaningful: it reads
//! every claim-to-claim edge in the database, which on a shared database could
//! page the seeded edges out of its row cap and pass for the wrong reason.

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

mod viewer_fixture;

mod common;

/// The three-claim chain described in the module doc, plus tokens.
struct Corpus {
    p1: Uuid,
    p2: Uuid,
    p3: Uuid,
    owner_agent: Uuid,
    stranger_agent: Uuid,
}

async fn corpus(pool: &PgPool) -> Corpus {
    let (owner_agent, owner_group) =
        viewer_fixture::seed_agent_with_group(pool, "reasoning-owner").await;
    let (stranger_agent, _stranger_group) =
        viewer_fixture::seed_agent_with_group(pool, "reasoning-stranger").await;

    let p1 = viewer_fixture::seed_public_claim(pool, owner_agent, "reasoning chain p1").await;
    let p2 = viewer_fixture::seed_public_claim(pool, owner_agent, "reasoning chain p2").await;
    let p3 = viewer_fixture::seed_public_claim(pool, owner_agent, "reasoning chain p3").await;

    viewer_fixture::seed_edge_owned_by(pool, p1, p2, "group", owner_group).await;
    viewer_fixture::seed_edge(pool, p2, p3).await;

    // CALIBRATION: the corpus has exactly the tenancy shape the arms rely on.
    let shapes: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT source_id, target_id, visibility::text FROM edges \
         WHERE source_id = ANY($1) AND target_id = ANY($1) ORDER BY visibility",
    )
    .bind(vec![p1, p2, p3])
    .fetch_all(pool)
    .await
    .expect("read back seeded edges");
    assert_eq!(
        shapes,
        vec![
            (p1, p2, "group".to_string()),
            (p2, p3, "public".to_string()),
        ],
        "CALIBRATION: p1->p2 must be group-private and p2->p3 public, or the \
         stranger arms below cannot tell the edge predicate from anything else"
    );

    Corpus {
        p1,
        p2,
        p3,
        owner_agent,
        stranger_agent,
    }
}

/// POST the analysis request; return `(status, body)`.
async fn analyze(addr: std::net::SocketAddr, token: &str, body: Value) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/reasoning/analyze"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .expect("POST /api/v1/reasoning/analyze");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("response body");
    let json = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, json)
}

/// The `(source_id, target_id)` pairs of `transitive_supports`.
fn support_pairs(body: &Value) -> Vec<(Uuid, Uuid)> {
    let mut pairs: Vec<(Uuid, Uuid)> = body["transitive_supports"]
        .as_array()
        .unwrap_or_else(|| panic!("response has no transitive_supports array: {body}"))
        .iter()
        .map(|ts| {
            let id = |k: &str| {
                Uuid::parse_str(ts[k].as_str().expect("id is a string")).expect("id is a uuid")
            };
            (id("source_id"), id("target_id"))
        })
        .collect();
    pairs.sort();
    pairs
}

fn edges_loaded(body: &Value) -> u64 {
    body["stats"]["edges_loaded"]
        .as_u64()
        .unwrap_or_else(|| panic!("response has no stats.edges_loaded: {body}"))
}

fn sorted(mut v: Vec<(Uuid, Uuid)>) -> Vec<(Uuid, Uuid)> {
    v.sort();
    v
}

/// The scoped arm (`claim_ids` given): the owner gets its own group-private edge
/// and everything derived through it; a stranger gets the public edge only.
#[sqlx::test(migrations = "../../migrations")]
async fn analyze_withholds_a_group_private_edge_from_a_stranger(pool: PgPool) {
    let c = corpus(&pool).await;
    let url = viewer_fixture::database_url_for(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let request = json!({ "claim_ids": [c.p1, c.p2, c.p3] });

    let owner_token = common::mint_token_with_agent(&["analysis:reasoning"], c.owner_agent);
    let (status, owner) = analyze(addr, &owner_token, request.clone()).await;
    assert_eq!(status, 200, "owner analyze must succeed: {owner}");
    assert_eq!(
        edges_loaded(&owner),
        2,
        "the owner must load both edges, including its own group-private one: {owner}"
    );
    assert_eq!(
        support_pairs(&owner),
        sorted(vec![(c.p1, c.p2), (c.p2, c.p3), (c.p1, c.p3)]),
        "the owner's analysis must derive through its own private edge"
    );

    let stranger_token = common::mint_token_with_agent(&["analysis:reasoning"], c.stranger_agent);
    let (status, stranger) = analyze(addr, &stranger_token, request).await;
    assert_eq!(status, 200, "stranger analyze must succeed: {stranger}");
    assert_eq!(
        edges_loaded(&stranger),
        1,
        "a stranger must load only the public edge, not another group's: {stranger}"
    );
    assert_eq!(
        support_pairs(&stranger),
        vec![(c.p2, c.p3)],
        "a stranger must see the public support and nothing derived from \
         another group's private edge ({} -> {})",
        c.p1,
        c.p2
    );
}

/// The unscoped arm (no `claim_ids`): every claim-to-claim edge the CALLER can
/// read, which for a stranger excludes another group's private edge.
#[sqlx::test(migrations = "../../migrations")]
async fn analyze_without_claim_ids_withholds_a_group_private_edge_from_a_stranger(pool: PgPool) {
    let c = corpus(&pool).await;
    let url = viewer_fixture::database_url_for(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let owner_token = common::mint_token_with_agent(&["analysis:reasoning"], c.owner_agent);
    let (status, owner) = analyze(addr, &owner_token, json!({})).await;
    assert_eq!(status, 200, "owner analyze must succeed: {owner}");
    let owner_pairs = support_pairs(&owner);
    for pair in [(c.p1, c.p2), (c.p2, c.p3), (c.p1, c.p3)] {
        assert!(
            owner_pairs.contains(&pair),
            "the owner's unscoped analysis must include {pair:?}; got {owner_pairs:?}"
        );
    }

    let stranger_token = common::mint_token_with_agent(&["analysis:reasoning"], c.stranger_agent);
    let (status, stranger) = analyze(addr, &stranger_token, json!({})).await;
    assert_eq!(status, 200, "stranger analyze must succeed: {stranger}");
    let stranger_pairs = support_pairs(&stranger);
    assert!(
        stranger_pairs.contains(&(c.p2, c.p3)),
        "non-vacuity: the stranger must still see the public support; got {stranger_pairs:?}"
    );
    for pair in [(c.p1, c.p2), (c.p1, c.p3)] {
        assert!(
            !stranger_pairs.contains(&pair),
            "a stranger must not see {pair:?}, derived from another group's \
             private edge; got {stranger_pairs:?}"
        );
    }
}

/// A token without `analysis:reasoning` is refused, even for the owner of the
/// data — and the refusal carries no analysis.
#[sqlx::test(migrations = "../../migrations")]
async fn analyze_requires_the_analysis_reasoning_scope(pool: PgPool) {
    let c = corpus(&pool).await;
    let url = viewer_fixture::database_url_for(&pool).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let request = json!({ "claim_ids": [c.p1, c.p2, c.p3] });

    let unscoped = common::mint_token_with_agent(&["claims:read", "edges:read"], c.owner_agent);
    let (status, body) = analyze(addr, &unscoped, request.clone()).await;
    assert_eq!(
        status, 403,
        "a token without analysis:reasoning must be refused: {body}"
    );
    assert!(
        body.get("transitive_supports").is_none(),
        "a refused request must carry no analysis: {body}"
    );

    // CALIBRATION: the same agent with the scope is served, so the 403 above is
    // the scope and not the principal.
    let scoped = common::mint_token_with_agent(&["analysis:reasoning"], c.owner_agent);
    let (status, body) = analyze(addr, &scoped, request).await;
    assert_eq!(status, 200, "the scoped token must be served: {body}");
}

// ── Direct handler invocation ──
//
// The arms below call the handler as a function. Two need an `AppState` the
// router fixture cannot build: one with entries in the in-memory
// `claim_store`, one whose raw pool is a different session from its scoped
// pool. The third needs a request the router cannot deliver: a resolved
// viewer with no `AuthContext`.

use axum::extract::State;
use axum::{Extension, Json};
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::reasoning::{analyze as analyze_handler, AnalyzeRequest};
use epigraph_api::state::{ApiConfig, AppState};

/// An `AuthContext` holding only `analysis:reasoning`, for `agent`.
fn reasoning_auth(agent: Uuid) -> Extension<AuthContext> {
    Extension(AuthContext {
        client_id: agent,
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Service,
        scopes: vec!["analysis:reasoning".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
    })
}

fn request(claim_ids: Option<Vec<Uuid>>) -> AnalyzeRequest {
    serde_json::from_value(json!({ "claim_ids": claim_ids })).expect("AnalyzeRequest")
}

/// Call the handler as `agent` and return the response as JSON, so the
/// assertions read the same wire shape the HTTP arms do.
async fn analyze_as(state: AppState, pool: &PgPool, agent: Uuid, req: AnalyzeRequest) -> Value {
    let viewer = epigraph_db::Viewer::resolve(pool, agent)
        .await
        .expect("resolve viewer");
    let Json(resp) = analyze_handler(
        ViewerExtractor(viewer),
        State(state),
        Some(reasoning_auth(agent)),
        Json(req),
    )
    .await
    .unwrap_or_else(|e| panic!("analyze as {agent} must succeed: {e:?}"));
    serde_json::to_value(resp).expect("serialize response")
}

/// An in-memory claim with `id` and `truth`.
fn store_claim(id: Uuid, truth: f64) -> epigraph_core::Claim {
    let now = chrono::Utc::now();
    epigraph_core::Claim::with_id(
        epigraph_core::ClaimId::from_uuid(id),
        format!("store claim {id}"),
        epigraph_core::AgentId::new(),
        [0u8; 32],
        [0u8; 32],
        None,
        None,
        epigraph_core::TruthValue::new(truth).expect("truth in range"),
        now,
        now,
    )
}

/// The in-memory claim set is filtered by the caller's viewer too: an entry
/// naming another group's private claim contributes neither its id nor its
/// truth value to a stranger's analysis, whichever request shape asks — with
/// or without `claim_ids`, and with the caller's own `edges`.
#[sqlx::test(migrations = "../../migrations")]
async fn analyze_drops_a_stored_claim_the_caller_cannot_read(pool: PgPool) {
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "store-owner").await;
    let (stranger, _) = viewer_fixture::seed_agent_with_group(&pool, "store-stranger").await;
    let private = viewer_fixture::seed_group_claim(&pool, owner, group, "store private").await;
    let public = viewer_fixture::seed_public_claim(&pool, owner, "store public").await;
    // A stored entry naming no `claims` row: nobody can be shown to read it, so
    // it is dropped for every caller (the fail-closed reading), the owner too.
    let orphan = Uuid::new_v4();

    let state_with_store = || async {
        let mut state = AppState::with_scoped_pool(
            viewer_fixture::scoped_pool(&pool).await,
            ApiConfig::default(),
        );
        let mut store = std::collections::HashMap::new();
        store.insert(private, store_claim(private, 0.9));
        store.insert(public, store_claim(public, 0.4));
        store.insert(orphan, store_claim(orphan, 0.7));
        state.claim_store = std::sync::Arc::new(tokio::sync::RwLock::new(store));
        state
    };

    // The third shape supplies its own edges, so the handler skips the edge
    // auto-load. The stored-claim filter must hold on that path too: a caller
    // who sends one edge of its own is still reading the stored claim set. Both
    // endpoints are fresh ids, neither stored claim, so the caller's own input
    // cannot put `private` in the body and `public` stays unsupported.
    let own_edge = json!([{
        "source_id": Uuid::new_v4(),
        "target_id": Uuid::new_v4(),
        "relationship": "supports",
        "strength": 0.5,
    }]);
    let shapes: [(&str, Value); 3] = [
        ("unscoped", json!({ "claim_ids": null })),
        (
            "claim_ids",
            json!({ "claim_ids": [private, public, orphan] }),
        ),
        ("caller_edges", json!({ "edges": own_edge })),
    ];

    for (arm, shape) in shapes {
        let req =
            || -> AnalyzeRequest { serde_json::from_value(shape.clone()).expect("AnalyzeRequest") };

        // Non-vacuity: the owner's analysis carries both stored claims.
        let mine = analyze_as(state_with_store().await, &pool, owner, req()).await;
        assert_eq!(
            mine["stats"]["claims_loaded"], 2,
            "[{arm}] the owner must load both stored claims, and not the \
             entry that names no claims row: {mine}"
        );
        assert!(
            !mine.to_string().contains(&orphan.to_string()),
            "[{arm}] a stored entry naming no claims row must be dropped: {mine}"
        );

        let theirs = analyze_as(state_with_store().await, &pool, stranger, req()).await;
        assert_eq!(
            theirs["stats"]["claims_loaded"], 1,
            "[{arm}] a stranger must load only the public stored claim: {theirs}"
        );
        assert_eq!(
            theirs["unsupported_claims"],
            json!([public.to_string()]),
            "[{arm}] the stranger's unsupported set must be the public claim alone"
        );
        assert!(
            !theirs.to_string().contains(&private.to_string()),
            "[{arm}] another group's private claim id leaked into a stranger's analysis: {theirs}"
        );
    }
}

/// The edge read runs on the caller's viewer-stamped connection, not the raw
/// pool.
///
/// `#[sqlx::test]` connects as a superuser that bypasses row security, so on
/// the router fixture a read reverted to `state.db_pool` is indistinguishable
/// from one on `read_as`. Here the raw pool is a separate session downgraded
/// to `epigraph_app` and never stamped, the instrument
/// `shard6_routes_scoped_read.rs::split_state` uses (this is another copy of
/// it, the duplication that file registers). On that session the row policies
/// admit only public edges, so a reverted read loses the owner's own
/// group-private edge while the spliced predicate would still have admitted it.
#[sqlx::test(migrations = "../../migrations")]
async fn analyze_serves_the_owners_private_edge_from_the_stamped_connection(pool: PgPool) {
    let c = corpus(&pool).await;

    let raw = viewer_fixture::downgraded_pool(&pool, "epigraph_app").await;
    let raw_is_privileged: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&raw)
    .await
    .expect("role privileges on the raw pool");
    assert!(
        !raw_is_privileged,
        "CALIBRATION: the raw pool must be subject to row security, or a read \
         reverted onto it is invisible and this arm proves nothing"
    );
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(viewer_fixture::scoped_pool(&pool).await);

    let body = analyze_as(
        state,
        &pool,
        c.owner_agent,
        request(Some(vec![c.p1, c.p2, c.p3])),
    )
    .await;
    assert_eq!(
        body["stats"]["edges_loaded"], 2,
        "the owner must load its own group-private edge through the stamped \
         connection: {body}"
    );
    assert_eq!(
        support_pairs(&body),
        sorted(vec![(c.p1, c.p2), (c.p2, c.p3), (c.p1, c.p3)]),
        "the owner's analysis must derive through its own private edge"
    );
}

/// The handler refuses a request that carries no `AuthContext`, on its own
/// terms. Over HTTP `ViewerExtractor` already answers 401 for that request, so
/// this is the handler's second line, and only a direct call can reach it: the
/// viewer below is resolved and the state is a working one, so a handler that
/// checked the scope only when an `AuthContext` happened to be present would
/// serve this request a full analysis instead of refusing it.
#[sqlx::test(migrations = "../../migrations")]
async fn analyze_refuses_a_request_with_no_auth_context(pool: PgPool) {
    let c = corpus(&pool).await;
    let state = || async {
        AppState::with_scoped_pool(
            viewer_fixture::scoped_pool(&pool).await,
            ApiConfig::default(),
        )
    };

    // Non-vacuity: with the owner's AuthContext the same call is served and
    // derives through the corpus, so a refusal below is the missing context.
    let served = analyze_as(
        state().await,
        &pool,
        c.owner_agent,
        request(Some(vec![c.p1, c.p2, c.p3])),
    )
    .await;
    assert_eq!(
        served["stats"]["edges_loaded"], 2,
        "the owner's call must be served: {served}"
    );

    let viewer = epigraph_db::Viewer::resolve(&pool, c.owner_agent)
        .await
        .expect("resolve viewer");
    let refused = analyze_handler(
        ViewerExtractor(viewer),
        State(state().await),
        None,
        Json(request(Some(vec![c.p1, c.p2, c.p3]))),
    )
    .await;
    match refused {
        Err(ApiError::Unauthorized { .. }) => {}
        Err(other) => panic!("a request with no AuthContext must be Unauthorized, got {other:?}"),
        Ok(Json(resp)) => panic!(
            "a request with no AuthContext was served an analysis: {}",
            serde_json::to_value(resp).expect("serialize response")
        ),
    }
}
