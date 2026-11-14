#![cfg(feature = "db")]
//! The guest read surface (backlog `1deb9dbf`): anonymous, read-only,
//! public-only reads under `/api/v1/guest/`.
//!
//! A guest is anyone who sends no bearer: a signed-out visitor, or a link-card
//! fetcher that has no user token. It reads the public graph and nothing else.
//! A non-public id is answered exactly as an absent one (same status, same
//! content type, same body once the echoed id is masked).
//!
//! # The instrument
//!
//! [`production_state`] is the deployment's own shape: a `ScopedPool`
//! downgraded to `epigraph_app` (neither superuser nor `BYPASSRLS`), so every
//! read passes BOTH migration 077's row policies and the in-query `$V`
//! predicate. A superuser pool skips row security and would let a read that
//! lost its predicate pass. Seeding runs on the superuser `pool`.
//!
//! # What makes these tests fail on the old code
//!
//! The old router has no guest route, so every guest request falls through to
//! axum's empty 404. That alone would satisfy a "private body equals absent
//! body" assertion, so every test here carries a POSITIVE control (a public row
//! answers 200 with its content) and checks the 404 is the API's own
//! `NotFound` JSON, not the empty fallback. The security property (a private
//! row stays out) was proven separately by mutation: the scoped read fragment
//! replaced with an always-true one, on a superuser pool that skips row
//! security, fails the card, ego, overview and layout private-row assertions.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use epigraph_api::{create_router, AgentRateLimiter, ApiConfig, AppState, RateLimitConfig};
use epigraph_db::repos::atlas_layout::{
    LayoutBuild, LayoutLinkOut, LayoutRegionOut, LayoutThemeOut,
};
use epigraph_db::{AtlasLayoutRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DIM: usize = 1536;

// ── The instrument ──

/// `AppState` as `bin/server.rs` builds it, on the application role.
async fn production_state(pool: &PgPool) -> AppState {
    let url = fixture::database_url_for(pool).await;
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
    assert_eq!(user, "epigraph_app", "CALIBRATION: the app role");
    assert!(
        !privileged,
        "CALIBRATION: epigraph_app must be subject to row security"
    );
    state
}

async fn router(pool: &PgPool) -> Router {
    create_router(production_state(pool).await)
}

/// A signed-out GET: no `Authorization` header at all.
async fn guest(router: &Router, path: &str) -> (StatusCode, HeaderMap, String) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&bytes).into())
}

async fn guest_json(router: &Router, path: &str) -> (StatusCode, Value, String) {
    let (status, _, text) = guest(router, path).await;
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    )
}

/// The API's `NotFound` body, not axum's empty fallback.
fn assert_api_not_found(status: StatusCode, headers: &HeaderMap, body: &str) {
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(ct.starts_with("application/json"), "content-type {ct:?}");
    let v: Value = serde_json::from_str(body).expect("a JSON error body");
    assert_eq!(v["error"], "NotFound", "{body}");
}

/// The answer for `hidden` must be the answer for `absent`, byte for byte once
/// each echoed id is masked.
async fn assert_same_as_absent(router: &Router, hidden_path: &str, hidden: Uuid) {
    let absent = Uuid::new_v4();
    let absent_path = hidden_path.replace(&hidden.to_string(), &absent.to_string());
    let (hs, hh, hb) = guest(router, hidden_path).await;
    let (as_, ah, ab) = guest(router, &absent_path).await;
    assert_api_not_found(hs, &hh, &hb);
    assert_api_not_found(as_, &ah, &ab);
    assert_eq!(
        hh.get("content-type"),
        ah.get("content-type"),
        "content-type must not discriminate"
    );
    assert_eq!(
        hb.replace(&hidden.to_string(), "<ID>"),
        ab.replace(&absent.to_string(), "<ID>"),
        "a non-public id must be answered exactly as an absent one"
    );
}

// ── Fixtures ──

fn basis(axis: usize) -> String {
    let mut v = vec!["0"; DIM];
    v[axis] = "1";
    format!("[{}]", v.join(","))
}

fn basis_f32(axis: usize) -> Vec<f32> {
    let mut v = vec![0.0_f32; DIM];
    v[axis] = 1.0;
    v
}

async fn seed_theme(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ($1) RETURNING id")
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("seed theme")
}

async fn claim_in(
    pool: &PgPool,
    agent: Uuid,
    group: Option<Uuid>,
    theme: Uuid,
    content: &str,
    axis: usize,
) -> Uuid {
    let id = match group {
        None => fixture::seed_public_claim(pool, agent, content).await,
        Some(g) => fixture::seed_group_claim(pool, agent, g, content).await,
    };
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(id)
        .bind(theme)
        .execute(pool)
        .await
        .expect("assign theme");
    fixture::set_claim_embedding(pool, id, &basis(axis)).await;
    id
}

async fn set_labels(pool: &PgPool, claim: Uuid, labels: &[&str]) {
    sqlx::query("UPDATE claims SET labels = $2 WHERE id = $1")
        .bind(claim)
        .bind(labels.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
        .execute(pool)
        .await
        .expect("set labels");
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
}

/// A document ingest that created `claim` from `paper`, as `ingest_document`
/// records it.
async fn ingest_record(pool: &PgPool, paper: Uuid, claim: Uuid, by: Uuid) {
    let mut conn = pool.acquire().await.expect("conn");
    epigraph_db::create_ingest_written_edge_if_absent_conn(
        &mut conn,
        None,
        "ingest_document",
        by,
        paper,
        "paper",
        claim,
        "claim",
        "asserts",
        None,
    )
    .await
    .expect("asserts");
    epigraph_db::ClaimIngestRepository::record_signed_conn(
        &mut conn,
        None,
        paper,
        claim,
        by,
        true,
        &[],
        "ingest_document",
        "test-pipeline",
    )
    .await
    .expect("record");
}

// ── The claim card ──

/// A signed-out read of a public claim is its card: content, belief, labels
/// and the documents it came from. No other field: no author, trace, group or
/// encryption field, and no `authored_by` block (it names humans and prompt
/// snapshots).
#[sqlx::test(migrations = "../../migrations")]
async fn a_guest_reads_a_public_claim_card_and_nothing_else(pool: PgPool) {
    let (owner, _) = fixture::seed_agent_with_group(&pool, "card-owner").await;
    let claim = fixture::seed_public_claim(&pool, owner, "public card claim").await;
    set_labels(&pool, claim, &["alpha", "beta"]).await;
    let paper: Uuid = sqlx::query_scalar(
        "INSERT INTO papers (doi, title) VALUES ('10.0000/fixture.card', 'Card Paper') \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("paper");
    ingest_record(&pool, paper, claim, owner).await;
    let router = router(&pool).await;

    let (status, body, text) = guest_json(&router, &format!("/api/v1/guest/claims/{claim}")).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(body["id"], claim.to_string());
    assert_eq!(body["content"], "public card claim");
    assert!(body["truth_value"].is_number(), "{body}");
    assert_eq!(body["labels"], serde_json::json!(["alpha", "beta"]));
    assert_eq!(
        body["sources"],
        serde_json::json!([{"doi": "10.0000/fixture.card", "title": "Card Paper"}]),
        "{body}"
    );

    let mut keys: Vec<&str> = body
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "content",
            "created_at",
            "id",
            "labels",
            "sources",
            "truth_value"
        ],
        "the card carries exactly these fields: {body}"
    );
    assert!(
        !text.contains(&owner.to_string()),
        "the card must not name the filer: {text}"
    );
}

/// THE DONE CRITERION: a signed-out read of a group-private claim is the
/// absent 404, with a public claim on the same router answering 200.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_private_claim_is_the_absent_404_to_a_guest(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "private-owner").await;
    let public = fixture::seed_public_claim(&pool, owner, "the public control").await;
    let private = fixture::seed_group_claim(&pool, owner, group, "SECRET private claim text").await;
    let router = router(&pool).await;

    let (status, body, text) = guest_json(&router, &format!("/api/v1/guest/claims/{public}")).await;
    assert_eq!(status, StatusCode::OK, "positive control: {text}");
    assert_eq!(body["content"], "the public control");

    let path = format!("/api/v1/guest/claims/{private}");
    assert_same_as_absent(&router, &path, private).await;
    let (_, _, text) = guest(&router, &path).await;
    assert!(!text.contains("SECRET"), "{text}");
}

// ── Ego ──

/// A guest's ego of a public claim holds its public neighbour and not its
/// private one; a private centre is the absent 404.
#[sqlx::test(migrations = "../../migrations")]
async fn a_guest_ego_holds_public_neighbours_only(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "ego-owner").await;
    let centre = fixture::seed_public_claim(&pool, owner, "ego centre").await;
    let near = fixture::seed_public_claim(&pool, owner, "public neighbour").await;
    let hidden = fixture::seed_group_claim(&pool, owner, group, "SECRET neighbour").await;
    edge(&pool, centre, near, "supports").await;
    edge(&pool, hidden, centre, "contradicts").await;
    let router = router(&pool).await;

    let (status, body, text) =
        guest_json(&router, &format!("/api/v1/guest/claims/{centre}/ego")).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let ids: Vec<&str> = body["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .filter_map(|n| n["id"].as_str())
        .collect();
    assert!(ids.contains(&near.to_string().as_str()), "{body}");
    assert!(!text.contains(&hidden.to_string()), "{text}");
    assert!(!text.contains("SECRET"), "{text}");
    assert_eq!(
        body["total_edges"], 1,
        "only the public edge is counted: {body}"
    );

    assert_same_as_absent(
        &router,
        &format!("/api/v1/guest/claims/{hidden}/ego"),
        hidden,
    )
    .await;
}

/// A guest's ego does not name who filed or asserted the claim: an edge from
/// an agent is left out of the nodes, the edges and the count, though the
/// card already leaves the filer out. A signed-in reader still sees the agent
/// node (the hiding is the guest's only).
#[sqlx::test(migrations = "../../migrations")]
async fn a_guest_ego_does_not_name_the_filer(pool: PgPool) {
    let (owner, _) = fixture::seed_agent_with_group(&pool, "ego-filer").await;
    sqlx::query("UPDATE agents SET display_name = 'Filer Display Name' WHERE id = $1")
        .bind(owner)
        .execute(&pool)
        .await
        .expect("name the filer");
    let centre = fixture::seed_public_claim(&pool, owner, "filed centre").await;
    let near = fixture::seed_public_claim(&pool, owner, "public neighbour").await;
    edge(&pool, centre, near, "supports").await;
    // The edge a claim write leaves (`routes/claims.rs`, `AUTHORED`).
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'agent', $2, 'claim', 'AUTHORED')",
    )
    .bind(owner)
    .bind(centre)
    .execute(&pool)
    .await
    .expect("seed the authorship edge");
    let router = router(&pool).await;
    let path = format!("/api/v1/guest/claims/{centre}/ego");

    let (status, body, text) = guest_json(&router, &path).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(
        text.contains(&near.to_string()),
        "positive control: the public neighbour is served: {text}"
    );
    assert!(
        !text.contains(&owner.to_string()),
        "the guest ego must not carry the filer's id: {text}"
    );
    assert!(
        !text.contains("Filer Display Name"),
        "the guest ego must not carry the filer's name: {text}"
    );
    assert_eq!(
        body["total_edges"], 1,
        "the agent edge is not counted either: {body}"
    );
    assert_eq!(body["edges"].as_array().expect("edges").len(), 1, "{body}");
    assert_eq!(body["truncated"], false, "{body}");

    // Control: the signed-in route still shows the agent.
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/v1/claims/{centre}/ego"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let signed_in: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(signed_in["total_edges"], 2, "{signed_in}");
    assert!(
        signed_in["nodes"]
            .as_array()
            .expect("nodes")
            .iter()
            .any(|n| n["id"] == owner.to_string() && n["label"] == "Filer Display Name"),
        "the signed-in ego keeps the agent node: {signed_in}"
    );
}

// ── Overview ──

/// A guest's theme overview counts public members only, lists no theme whose
/// members are all private, and carries no stored label (a stored label may
/// be derived from private members' text).
#[sqlx::test(migrations = "../../migrations")]
async fn a_guest_overview_counts_public_members_and_withholds_labels(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "overview-owner").await;
    let mixed = seed_theme(&pool, "SECRET-derived mixed label").await;
    let hidden = seed_theme(&pool, "SECRET all-private theme").await;
    claim_in(&pool, owner, None, mixed, "public member", 0).await;
    claim_in(&pool, owner, Some(group), mixed, "private member a", 0).await;
    claim_in(&pool, owner, Some(group), mixed, "private member b", 0).await;
    claim_in(&pool, owner, Some(group), hidden, "private member c", 1).await;
    let router = router(&pool).await;

    let (status, body, text) = guest_json(&router, "/api/v1/guest/graph/themes/overview").await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let themes = body["themes"].as_array().expect("themes");
    assert_eq!(themes.len(), 1, "{body}");
    assert_eq!(themes[0]["id"], mixed.to_string());
    assert_eq!(themes[0]["claim_count"], 1, "public members only: {body}");
    assert!(themes[0].get("label").is_none(), "{body}");
    assert_eq!(body["total"], 1);
    assert!(!text.contains(&hidden.to_string()), "{text}");
    assert!(!text.contains("SECRET"), "{text}");
}

// ── Layout ──

/// A layout run with a public theme T1 (one public, one private member) in
/// region RA and an all-private theme T6 also ranked in RA.
async fn layout_world(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
    let (owner, group) = fixture::seed_agent_with_group(pool, "layout-owner").await;
    let t1 = seed_theme(pool, "SECRET-derived T1 label").await;
    let t6 = seed_theme(pool, "SECRET T6").await;
    claim_in(pool, owner, None, t1, "public t1 member", 0).await;
    claim_in(pool, owner, Some(group), t1, "private t1 member", 0).await;
    claim_in(pool, owner, Some(group), t6, "private t6 member", 0).await;
    let epoch: i64 = sqlx::query_scalar("SELECT n FROM atlas_layout_epoch")
        .fetch_one(pool)
        .await
        .unwrap();
    let ra = Uuid::new_v4();
    let theme = |t: Uuid, k: i32| LayoutThemeOut {
        theme_id: t,
        region_id: ra,
        rank_in_region: k,
        x: -290.5 + f64::from(k),
        y: 20.25,
        public_member_count: 1,
    };
    let build = LayoutBuild {
        algo: "pca2-ward-v1".into(),
        params: serde_json::json!({}),
        cluster_run_id: None,
        visibility_epoch: epoch,
        public_claim_count: 0,
        public_link_count: 0,
        theme_set_digest: "0".repeat(64),
        regions: vec![LayoutRegionOut {
            id: ra,
            ordinal: 0,
            label: "SECRET-derived region label".into(),
            x: -300.0,
            y: 12.5,
            r: 120.0,
            centroid: basis_f32(0),
        }],
        themes: vec![theme(t1, 0), theme(t6, 1)],
        theme_links: Vec::<LayoutLinkOut>::new(),
    };
    let mut conn = pool.acquire().await.unwrap();
    AtlasLayoutRepository::write_run(&mut conn, &build)
        .await
        .expect("write run");
    (ra, t1, t6)
}

/// A guest's layout shows the public slice: the region and T1 with their
/// public counts, never T6, and no theme or region label.
#[sqlx::test(migrations = "../../migrations")]
async fn a_guest_layout_is_the_public_slice_without_labels(pool: PgPool) {
    let (ra, t1, t6) = layout_world(&pool).await;
    let router = router(&pool).await;

    let (status, body, text) = guest_json(&router, "/api/v1/guest/graph/themes/layout").await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let regions = body["regions"].as_array().expect("regions");
    assert_eq!(regions.len(), 1, "{body}");
    assert_eq!(regions[0]["id"], ra.to_string());
    assert_eq!(regions[0]["member_count"], 1, "public members only: {body}");
    assert_eq!(regions[0]["theme_ids"], serde_json::json!([t1.to_string()]));
    assert!(regions[0].get("label").is_none(), "{body}");
    assert!(!text.contains(&t6.to_string()), "{text}");
    assert!(!text.contains("SECRET"), "{text}");

    let (status, body, text) = guest_json(
        &router,
        &format!("/api/v1/guest/graph/themes/layout?region_id={ra}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let themes = body["themes"].as_array().expect("themes");
    assert_eq!(themes.len(), 1, "{body}");
    assert_eq!(themes[0]["id"], t1.to_string());
    assert_eq!(themes[0]["member_count"], 1, "{body}");
    assert!(themes[0].get("label").is_none(), "{body}");
    assert!(body["region"].get("label").is_none(), "{body}");
    assert!(!text.contains(&t6.to_string()), "{text}");
    assert!(!text.contains("SECRET"), "{text}");

    // The unplaced list is ordered by label and its cursor carries the label
    // bytes, so it is not served to guests.
    let (status, _, text) = guest_json(
        &router,
        "/api/v1/guest/graph/themes/layout?region_id=unplaced",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(!text.contains("SECRET"), "{text}");
}

/// A signed-in caller's layout still carries labels: the guest's withholding
/// does not reach the authenticated route.
#[sqlx::test(migrations = "../../migrations")]
async fn the_signed_in_layout_keeps_its_labels(pool: PgPool) {
    let (ra, _, _) = layout_world(&pool).await;
    let router = router(&pool).await;
    let token = common::mint_token_with_agent(&["claims:read"], Uuid::new_v4());
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/graph/themes/layout")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let region = body["regions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == ra.to_string())
        .expect("region");
    assert_eq!(region["label"], "SECRET-derived region label");
}

// ── The anonymous envelope ──

/// Guest routes answer `Cache-Control: no-store`: a claim privatized after a
/// read must not keep answering from a cache.
#[sqlx::test(migrations = "../../migrations")]
async fn guest_responses_are_not_stored(pool: PgPool) {
    let (owner, _) = fixture::seed_agent_with_group(&pool, "cache-owner").await;
    let claim = fixture::seed_public_claim(&pool, owner, "cache claim").await;
    let router = router(&pool).await;
    for path in [
        format!("/api/v1/guest/claims/{claim}"),
        format!("/api/v1/guest/claims/{claim}/ego"),
        "/api/v1/guest/graph/themes/overview".to_string(),
        "/api/v1/guest/graph/themes/layout".to_string(),
    ] {
        let (status, headers, text) = guest(&router, &path).await;
        assert_eq!(status, StatusCode::OK, "{path}: {text}");
        let cc = headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(cc.contains("no-store"), "{path}: cache-control {cc:?}");
    }
}

/// Guest routes are rate-limited per client address like the rest of the
/// anonymous surface. No database: the limiter refuses before any read.
#[tokio::test]
async fn guest_routes_are_rate_limited_per_address() {
    const LIMIT: u32 = 3;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://ratelimit:unused@127.0.0.1:1/unused")
        .expect("lazy pool");
    let limiter = AgentRateLimiter::new(RateLimitConfig {
        default_rpm: LIMIT,
        global_rpm: 1_000_000,
        replenish_interval_secs: 60,
        enable_global_limit: false,
    });
    let router =
        create_router(AppState::with_db(pool, ApiConfig::default()).with_rate_limiter(limiter));
    let path = format!("/api/v1/guest/claims/{}", Uuid::new_v4());
    let send = |peer: &'static str| {
        let router = router.clone();
        let path = path.clone();
        async move {
            let mut req = Request::builder()
                .method(Method::GET)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            let peer: SocketAddr = peer.parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
            router.oneshot(req).await.unwrap().status()
        }
    };
    for _ in 0..LIMIT {
        let status = send("192.0.2.10:4000").await;
        assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
        // The route exists: under quota it reaches the handler, which cannot
        // read on this pool. An unrouted path would be the empty 404.
        assert_ne!(status, StatusCode::NOT_FOUND, "the guest route is routed");
    }
    assert_eq!(
        send("192.0.2.10:4000").await,
        StatusCode::TOO_MANY_REQUESTS,
        "a guest route past its quota"
    );
    assert_ne!(
        send("192.0.2.11:4000").await,
        StatusCode::TOO_MANY_REQUESTS,
        "another address keeps its own bucket"
    );
}

// ── The constructor's call sites ──

/// `Viewer::public_only` is built ONLY in the guest route module. Anywhere
/// else it would hand a signed-in request (or a background job) the public
/// corpus in place of its own viewer, a silent narrowing, or put a public-only
/// viewer behind a route that was never reviewed as anonymous.
#[test]
fn public_only_viewer_is_built_only_by_the_guest_routes() {
    let crates = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let mut offenders = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(crates)];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                if name != "target" && name != "tests" && !name.starts_with('.') {
                    stack.push(path);
                }
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let rel = path.to_string_lossy().replace('\\', "/");
            if !rel.contains("/src/") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            let code: String = src
                .lines()
                .map(|l| l.find("//").map_or(l, |i| &l[..i]))
                .collect::<Vec<_>>()
                .join("\n");
            // The bare token, not `public_only()`: passing the constructor as
            // a function value (`unwrap_or_else(Viewer::public_only)`) builds
            // the same viewer without the parentheses.
            let calls = word_count(&code, "public_only");
            let allowed = if rel.ends_with("epigraph-api/src/routes/guest.rs") {
                calls
            } else if rel.ends_with("epigraph-db/src/visibility.rs") {
                // The definition, and its own unit test.
                2
            } else {
                0
            };
            if calls > allowed {
                offenders.push(format!("{rel}: {calls}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "Viewer::public_only referenced outside the guest routes:\n{}",
        offenders.join("\n")
    );
}

/// Occurrences of `word` in `text` not run into an identifier on either side,
/// so `public_only_viewer_reads_…` and `is_public_only` do not count.
fn word_count(text: &str, word: &str) -> usize {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word)
        .filter(|(i, _)| {
            let before = text[..*i].chars().next_back();
            let after = text[i + word.len()..].chars().next();
            !before.is_some_and(ident) && !after.is_some_and(ident)
        })
        .count()
}

#[test]
fn word_count_matches_the_bare_token_only() {
    let code = "a(Viewer::public_only()); b.unwrap_or_else(Viewer::public_only); \
                fn public_only_viewer_reads() {} let is_public_only = 1;";
    assert_eq!(word_count(code, "public_only"), 2);
}
