//! T20: GET /api/v1/claims/:id/cross_source_matches integration tests.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use epigraph_api::middleware::SignatureVerificationState;
use epigraph_api::{create_router, ApiConfig, AppState};
use http_body_util::BodyExt;
use serde::Deserialize;
use sqlx::types::Json as SqlxJson;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

fn create_test_router(pool: PgPool) -> Router {
    let config = ApiConfig {
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "http://localhost:8080".to_string(),
        ..ApiConfig::default()
    };
    let signature_state = SignatureVerificationState::with_bypass_routes(vec!["/".to_string()]);
    let state = AppState::with_db_and_signature_state(pool, config, signature_state);
    create_router(state)
}

/// Deliberately credential-less, for the cases that assert a 401.
async fn get_anonymous(router: &Router, path: &str) -> axum::http::Response<axum::body::Body> {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn insert_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("t20 {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, true)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[derive(Debug, Deserialize)]
struct CorroboratesEdge {
    edge_id: String,
    source_id: String,
    target_id: String,
    #[serde(default)]
    properties: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct PendingCandidate {
    id: String,
    claim_a: String,
    claim_b: String,
    score: f32,
    status: Option<String>, // not in response but lets us be lax
    #[serde(default)]
    features: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct Response {
    claim_id: String,
    corroborates: Vec<CorroboratesEdge>,
    pending: Vec<PendingCandidate>,
}

/// PR-03: `GET /api/v1/claims/:id/cross_source_matches` moved to the protected
/// router, so these reads need a Bearer token. `decide_bearer_token` (defined
/// below, for the POST cases) already mints exactly the right shape; reuse it
/// with a linked agent so the token is not the principal-less kind the API
/// refuses.
async fn get(router: &Router, path: &str) -> axum::http::Response<axum::body::Body> {
    let token = decide_bearer_token(Uuid::new_v4(), Some(Uuid::new_v4()), "service");
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_404_when_claim_missing(pool: PgPool) {
    let router = create_test_router(pool);
    let bogus = Uuid::new_v4();
    let resp = get(
        &router,
        &format!("/api/v1/claims/{bogus}/cross_source_matches"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_empty_arrays_when_claim_has_no_matches(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let claim = insert_claim(&pool, agent).await;
    let router = create_test_router(pool);

    let resp = get(
        &router,
        &format!("/api/v1/claims/{claim}/cross_source_matches"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: Response = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.claim_id, claim.to_string());
    assert!(parsed.corroborates.is_empty());
    assert!(parsed.pending.is_empty());
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_corroborates_edges_and_pending_candidates(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let c = insert_claim(&pool, agent).await;

    // Pending candidate (a, b).
    let (lo_ab, hi_ab) = if a < b { (a, b) } else { (b, a) };
    sqlx::query(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status)
         VALUES ($1, $2, 0.7, $3, 'pending')",
    )
    .bind(lo_ab)
    .bind(hi_ab)
    .bind(SqlxJson(serde_json::json!({"embed_cosine": 0.7})))
    .execute(&pool)
    .await
    .unwrap();

    // Promoted candidate (a, c) — must NOT appear in `pending`.
    let (lo_ac, hi_ac) = if a < c { (a, c) } else { (c, a) };
    sqlx::query(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status)
         VALUES ($1, $2, 0.95, $3, 'promoted')",
    )
    .bind(lo_ac)
    .bind(hi_ac)
    .bind(SqlxJson(serde_json::json!({"embed_cosine": 0.99})))
    .execute(&pool)
    .await
    .unwrap();

    // The corresponding CORROBORATES edge (a → c).
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
         VALUES ($1, 'claim', $2, 'claim', 'CORROBORATES', $3)",
    )
    .bind(a)
    .bind(c)
    .bind(SqlxJson(serde_json::json!({"score": 0.95, "source": "cross_source_matcher"})))
    .execute(&pool)
    .await
    .unwrap();

    let router = create_test_router(pool);
    let resp = get(&router, &format!("/api/v1/claims/{a}/cross_source_matches")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: Response = serde_json::from_slice(&body).unwrap();

    assert_eq!(parsed.claim_id, a.to_string());
    assert_eq!(
        parsed.corroborates.len(),
        1,
        "expected one CORROBORATES edge"
    );
    let edge = &parsed.corroborates[0];
    assert_eq!(edge.source_id, a.to_string());
    assert_eq!(edge.target_id, c.to_string());
    let _ = (&edge.edge_id, &edge.properties);

    assert_eq!(parsed.pending.len(), 1, "expected one pending candidate");
    let cand = &parsed.pending[0];
    let pair = [cand.claim_a.as_str(), cand.claim_b.as_str()];
    assert!(pair.contains(&a.to_string().as_str()));
    assert!(pair.contains(&b.to_string().as_str()));
    assert!((cand.score - 0.7).abs() < 1e-5);
    let _ = (&cand.id, &cand.status, &cand.features);
}

// ---------------------------------------------------------------------------
// POST /api/v1/match_candidates/:id/decide — decision provenance.
//
// `decided_by` must never be NULL for an authenticated decision. The Telegram
// bridge bot authenticates as an OAuth *service* client whose `agent_id` is
// NULL (service clients are created with `agent_id = NULL` in
// `oauth/register.rs` and nothing ever links one), so a decide made through it
// used to persist `decided_by = NULL` — a silent provenance hole in rows that
// create real CORROBORATES edges.
// ---------------------------------------------------------------------------

/// Mint a Bearer token against the dev JWT secret (the fallback used by
/// `default_jwt_config()` in state.rs when `EPIGRAPH_JWT_SECRET` is unset).
/// Same pattern as `integration/embed_on_create_claim.rs::test_bearer_token`.
fn decide_bearer_token(client_id: Uuid, agent_id: Option<Uuid>, client_type: &str) -> String {
    decide_bearer_token_with_scopes(
        client_id,
        agent_id,
        client_type,
        vec!["claims:read".to_string(), "claims:write".to_string()],
    )
}

/// `retire` requires `claims:admin` — promote/reject only need `claims:write`.
/// The two helpers exist so a test cannot accidentally exercise retirement with
/// a writer token and conclude the gate is open.
fn admin_bearer_token(client_id: Uuid, agent_id: Option<Uuid>, client_type: &str) -> String {
    decide_bearer_token_with_scopes(
        client_id,
        agent_id,
        client_type,
        vec![
            "claims:read".to_string(),
            "claims:write".to_string(),
            "claims:admin".to_string(),
        ],
    )
}

fn decide_bearer_token_with_scopes(
    client_id: Uuid,
    agent_id: Option<Uuid>,
    client_type: &str,
    scopes: Vec<String>,
) -> String {
    use epigraph_api::oauth::JwtConfig;
    let jwt_config = JwtConfig::from_secret(b"epigraph-dev-secret-change-in-production!!");
    let (token, _) = jwt_config
        .issue_access_token(
            client_id,
            scopes,
            client_type,
            None, // owner_id — service clients created by the bridge have none
            agent_id,
            chrono::Duration::seconds(300),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("issue_access_token must succeed for tests");
    token
}

async fn insert_pending_candidate(pool: &PgPool, a: Uuid, b: Uuid) -> Uuid {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    sqlx::query_scalar(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status)
         VALUES ($1, $2, 0.9, $3, 'pending')
         RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .bind(SqlxJson(serde_json::json!({"embed_cosine": 0.9})))
    .fetch_one(pool)
    .await
    .unwrap()
}

/// The URL of the `#[sqlx::test]` pool's own ephemeral database.
fn database_url_of(pool: &PgPool) -> String {
    let db = pool
        .connect_options()
        .get_database()
        .expect("the #[sqlx::test] pool names its database")
        .to_string();
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let (authority, query) = match base.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (base.as_str(), None),
    };
    let prefix = authority
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("DATABASE_URL must carry a database path")
        .0;
    match query {
        Some(q) => format!("{prefix}/{db}?{q}"),
        None => format!("{prefix}/{db}"),
    }
}

/// A state built through a `ScopedPool` (the retire act runs on a
/// viewer-stamped transaction), with the administrative cascade enabled on the
/// harness pool when `admin` is set (migration 117).
async fn decide_state(pool: PgPool, admin: bool) -> AppState {
    let scoped = epigraph_db::ScopedPool::connect(
        &database_url_of(&pool),
        epigraph_db::SessionGucMode::Session,
    )
    .await
    .expect("ScopedPool over the test database");
    let scoped = if admin {
        scoped.with_maintenance_pool(pool)
    } else {
        scoped
    };
    AppState::with_scoped_pool(scoped, ApiConfig::default()).with_admin_cascade(admin)
}

async fn post_decide(
    pool: PgPool,
    candidate: Uuid,
    token: &str,
    verdict: &str,
) -> axum::http::Response<Body> {
    post_decide_on(decide_state(pool, true).await, candidate, token, verdict).await
}

async fn post_decide_on(
    state: AppState,
    candidate: Uuid,
    token: &str,
    verdict: &str,
) -> axum::http::Response<Body> {
    create_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/match_candidates/{candidate}/decide"))
                .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "verdict": verdict }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn decided_by_of(pool: &PgPool, candidate: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT decided_by FROM match_candidates WHERE id = $1")
        .bind(candidate)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Originally: a service client carried `agent_id = None`, the decision landed
/// with `decided_by = NULL`, and `cross_source.rs:296`
/// (`auth.agent_id.or(Some(auth.client_id))`) was added to fall back to the
/// client identity.
///
/// **PR-06 makes that fallback unreachable.** `decide_candidate` takes
/// `ViewerExtractor` as its first extractor, and the extractor rejects an
/// `agent_id`-less token with 401 before the handler body runs — so
/// `auth.agent_id` is always `Some` at line 296 and the `.or(...)` arm is dead
/// code. The `decided_by = NULL` bug class is now prevented structurally rather
/// than handled defensively.
///
/// This test pins both halves: the agentless token is refused, and a service
/// client that *does* carry a principal (which PR-02 guarantees for every real
/// client) decides successfully and records a non-null decider.
#[sqlx::test(migrations = "../../migrations")]
async fn decide_by_service_client_records_a_non_null_decider(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let candidate = insert_pending_candidate(&pool, a, b).await;

    // 1. The pre-PR-02 shape — service client with no linked agent — is now
    //    refused at ViewerExtractor, before the handler can run at all.
    let client_id = Uuid::new_v4();
    let agentless = decide_bearer_token(client_id, None, "service");
    let refused = post_decide(pool.clone(), candidate, &agentless, "promote").await;
    assert_eq!(
        refused.status(),
        StatusCode::UNAUTHORIZED,
        "a service token carrying no agent_id must be refused before the handler"
    );

    // 2. The shape PR-02 guarantees: the service client carries a principal.
    let token = decide_bearer_token(client_id, Some(agent), "service");
    let resp = post_decide(pool.clone(), candidate, &token, "promote").await;
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "decide must succeed for a service client bound to a principal (body: {})",
        String::from_utf8_lossy(&body)
    );

    // Assert on the persisted row, not the response.
    assert_eq!(
        decided_by_of(&pool, candidate).await,
        Some(agent),
        "decided_by must record the authenticated principal"
    );

    // The CORROBORATES edge written by the same handler carries the decision
    // identity in its properties — it must not be null either.
    let edge_decided_by: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT properties -> 'decided_by' FROM edges
         WHERE relationship = 'corroborates' AND properties ->> 'candidate_id' = $1",
    )
    .bind(candidate.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        edge_decided_by,
        Some(serde_json::json!(agent)),
        "CORROBORATES edge properties.decided_by must match the persisted decider"
    );
}

/// Precedence guard: the fallback must not clobber a real agent identity.
/// Without this, `decided_by = client_id` unconditionally would also satisfy
/// the test above while silently destroying agent attribution.
#[sqlx::test(migrations = "../../migrations")]
async fn decide_prefers_agent_id_over_client_id(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let candidate = insert_pending_candidate(&pool, a, b).await;

    let client_id = Uuid::new_v4();
    let token = decide_bearer_token(client_id, Some(agent), "agent");

    let resp = post_decide(pool.clone(), candidate, &token, "reject").await;
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "decide must succeed for an agent client (body: {})",
        String::from_utf8_lossy(&body)
    );

    let decided_by = decided_by_of(&pool, candidate).await;
    assert_eq!(
        decided_by,
        Some(agent),
        "an agent-linked token must attribute the decision to the agent"
    );
    assert_ne!(
        decided_by,
        Some(client_id),
        "the client-id fallback must not override a present agent_id"
    );
}

// ---------------------------------------------------------------------------
// `retire`: undo a promotion over HTTP.
//
// Before this arm existed, the *only* way to retract a promoted candidate was
// the `retire_match_candidates` operator binary on the host: every HTTP verdict
// was refused by the `status != "pending"` gate. The tests below pin both the
// happy path and the transition rules the gate used to enforce for free.
// ---------------------------------------------------------------------------

/// Count the rows a retirement must remove for one claim pair: the matcher
/// edge, the `factors` row the `edges_auto_factor` trigger derives from it, and
/// that factor's `bp_messages`.
async fn matcher_edge_footprint(pool: &PgPool, a: Uuid, b: Uuid) -> (i64, i64, i64) {
    // Counts edges IN FORCE, not edges present. Under retraction semantics the
    // row survives with `valid_to` set, so a bare `count(*)` could no longer
    // distinguish "retired" from "never happened" — which is the whole point of
    // the change and must stay visible to this test.
    let edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges
         WHERE ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1))
           AND properties->>'source' = 'cross_source_matcher'
           AND valid_to IS NULL",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .unwrap();
    let factors: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM factors f
         JOIN edges e ON e.id::text = f.properties->>'source_edge_id'
         WHERE ((e.source_id = $1 AND e.target_id = $2)
             OR (e.source_id = $2 AND e.target_id = $1))
           AND e.properties->>'source' = 'cross_source_matcher'",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .unwrap();
    let bp: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM bp_messages m
         JOIN factors f ON f.id = m.factor_id
         JOIN edges e ON e.id::text = f.properties->>'source_edge_id'
         WHERE ((e.source_id = $1 AND e.target_id = $2)
             OR (e.source_id = $2 AND e.target_id = $1))
           AND e.properties->>'source' = 'cross_source_matcher'",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .unwrap();
    (edges, factors, bp)
}

async fn status_of(pool: &PgPool, candidate: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM match_candidates WHERE id = $1")
        .bind(candidate)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The reported defect: a promoted candidate cannot be retracted over HTTP.
/// `retire` must flip it to `stale` and take the matcher edge — plus the
/// derived `factors` / `bp_messages` the `edges_auto_factor` trigger hung off
/// it — with it. Deleting the edge alone is the failure mode migration
/// `012_cull_low_similarity_corroborates` was written to avoid: an orphan
/// factor keeps corroborating in the belief graph forever.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_undoes_a_promotion_including_its_derived_factors(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let candidate = insert_pending_candidate(&pool, a, b).await;

    let client_id = Uuid::new_v4();
    let token = decide_bearer_token(client_id, Some(agent), "agent");

    let resp = post_decide(pool.clone(), candidate, &token, "promote").await;
    assert_eq!(resp.status(), StatusCode::OK, "promote must succeed");

    let (edges, factors, _) = matcher_edge_footprint(&pool, a, b).await;
    assert_eq!(edges, 1, "promote must have written one matcher edge");
    assert_eq!(
        factors, 1,
        "the edges_auto_factor trigger must have derived a factor from it — \
         without one this test cannot prove the factor is cleaned up"
    );

    // retire needs claims:admin; promote/reject above ran on claims:write,
    // which is exactly the split this route enforces.
    let token = admin_bearer_token(client_id, Some(agent), "agent");
    let resp = post_decide(pool.clone(), candidate, &token, "retire").await;
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "retire must succeed on a promoted candidate (body: {})",
        String::from_utf8_lossy(&body)
    );

    assert_eq!(
        status_of(&pool, candidate).await,
        "stale",
        "a retired candidate must land in 'stale', matching the CLI"
    );
    assert_eq!(
        matcher_edge_footprint(&pool, a, b).await,
        (0, 0, 0),
        "retire must remove the matcher edge AND its derived factor/bp_messages"
    );

    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["cascade"]["status"], "applied",
        "migration 117: the retraction runs as the administrative cascade: {json}"
    );
    assert_eq!(
        json["edges_retracted"].as_i64(),
        Some(1),
        "the response must account for the retracted edge"
    );

    let dumped = json["retracted_edges"]
        .as_array()
        .expect("response must carry the retracted edges");
    assert_eq!(dumped.len(), 1);
    assert_eq!(
        dumped[0]["properties"]["candidate_id"],
        serde_json::json!(candidate),
        "the snapshot must preserve the edge properties, not just its id"
    );
    // Stored in the canonical lower-case spelling (backlog 3ce5e00c).
    assert_eq!(dumped[0]["relationship"], "corroborates");

    // THE POINT OF RETRACTION. Under the old DELETE these three assertions were
    // impossible: the row was gone, so `decided_by` — who made the original
    // promotion — survived only in this response body, which nothing stores.
    // `match_candidates.decided_by` is overwritten with the RETIRER, so a hard
    // delete left no persisted record of the promoter anywhere.
    let (still_present, closed_at, promoter): (
        i64,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT count(*), max(valid_to), max(properties->>'decided_by')
             FROM edges
             WHERE ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1))
               AND properties->>'source' = 'cross_source_matcher'",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(still_present, 1, "the edge row must SURVIVE retraction");
    assert!(
        closed_at.is_some(),
        "the surviving row must be out of force (valid_to set)"
    );
    assert!(
        promoter.is_some(),
        "properties.decided_by must survive so the original promoter stays recoverable"
    );
}

/// Scope guard: retirement is keyed on the matcher's provenance marker, not on
/// the claim pair. An unrelated hand-authored edge between the same two claims
/// must survive — otherwise `retire` is a pair-wide edge nuke wearing a
/// narrower name.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_leaves_non_matcher_edges_between_the_same_pair_alone(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let candidate = insert_pending_candidate(&pool, a, b).await;

    let client_id = Uuid::new_v4();
    let token = decide_bearer_token(client_id, Some(agent), "agent");
    let resp = post_decide(pool.clone(), candidate, &token, "promote").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let manual_edge: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type,
                            relationship, properties)
         VALUES ($1, 'claim', $2, 'claim', 'CORROBORATES', '{\"source\": \"human\"}'::jsonb)
         RETURNING id",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();

    // retire needs claims:admin; promote/reject above ran on claims:write,
    // which is exactly the split this route enforces.
    let token = admin_bearer_token(client_id, Some(agent), "agent");
    let resp = post_decide(pool.clone(), candidate, &token, "retire").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let survives: i64 = sqlx::query_scalar("SELECT count(*) FROM edges WHERE id = $1")
        .bind(manual_edge)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        survives, 1,
        "retire must scope on properties->>'source' = 'cross_source_matcher', \
         not on the claim pair"
    );
}

/// Regression guard on the gate that `retire` relaxes: relaxing it wholesale
/// would let a decided candidate be re-decided, overwriting `decided_by` and
/// (for promote) re-creating the edge a retirement just removed. `promote` and
/// `reject` must still 409 on an already-decided row.
#[sqlx::test(migrations = "../../migrations")]
async fn promote_and_reject_still_refuse_an_already_decided_candidate(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let candidate = insert_pending_candidate(&pool, a, b).await;

    let client_id = Uuid::new_v4();
    let token = decide_bearer_token(client_id, Some(agent), "agent");

    let resp = post_decide(pool.clone(), candidate, &token, "reject").await;
    assert_eq!(resp.status(), StatusCode::OK);

    for verdict in ["promote", "reject"] {
        let resp = post_decide(pool.clone(), candidate, &token, verdict).await;
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "{verdict} must still 409 on a decided candidate"
        );
    }

    // …and the retire arm must not resurrect it as promotable either: a
    // retired row stays 'stale'.
    // retire needs claims:admin; promote/reject above ran on claims:write,
    // which is exactly the split this route enforces.
    let token = admin_bearer_token(client_id, Some(agent), "agent");
    let resp = post_decide(pool.clone(), candidate, &token, "retire").await;
    assert_eq!(resp.status(), StatusCode::OK, "retire tolerates any status");
    assert_eq!(status_of(&pool, candidate).await, "stale");
}

// NOTE: this route is registered in routes/mod.rs (Task 3 of the
// 2026-07-11 xsm-telegram-approval plan) — this test only passes once
// that registration lands.
//
// TODO: despite its name, this test only asserts the auth gate (401 without a
// bearer token) — it never deserializes a response body, so the seeded
// `verifier_verdict` / `verifier_rationale` and the excerpt projection are
// NOT covered. It still needs an authenticated case that reads the body and
// asserts `claim_a_excerpt` / `claim_b_excerpt` / `verifier_verdict` /
// `verifier_rationale`. A `ListedCandidate` response struct naming exactly
// those fields used to sit below this test unused; it was removed as dead
// code (clippy `-D warnings`), so this comment is the surviving marker.
#[sqlx::test(migrations = "../../migrations")]
async fn list_candidates_returns_pending_with_excerpts(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    sqlx::query(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status, verifier_verdict, verifier_rationale)
         VALUES ($1, $2, 0.81, $3, 'pending', 'paraphrase', 'test rationale text')",
    )
    .bind(lo)
    .bind(hi)
    .bind(SqlxJson(serde_json::json!({"embed_cosine": 0.81})))
    .execute(&pool)
    .await
    .unwrap();

    let router = create_test_router(pool);
    let resp = get_anonymous(&router, "/api/v1/match_candidates?status=pending&limit=100").await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "list requires a bearer token"
    );
}

/// The scope split, pinned from the refusing side.
///
/// Making the retire tests pass by handing them an admin token only proves admin
/// WORKS; it cannot catch the gate being widened back to `claims:write`. This is
/// the test that fails if someone does. It matters because retirement withdraws
/// an assertion another principal made — the same class of act as supersession —
/// and 50 of 825 production oauth_clients hold `claims:write`.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_is_refused_to_a_claims_write_caller(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let candidate = insert_pending_candidate(&pool, a, b).await;
    let client_id = Uuid::new_v4();

    // Same writer token that promote/reject accept.
    let writer = decide_bearer_token(client_id, Some(agent), "agent");

    let promote = post_decide(pool.clone(), candidate, &writer, "promote").await;
    assert_eq!(
        promote.status(),
        StatusCode::OK,
        "precondition: claims:write must still be enough to PROMOTE, otherwise this \
         test would pass even if the whole route were locked to admin"
    );

    let retire = post_decide(pool.clone(), candidate, &writer, "retire").await;
    assert_eq!(
        retire.status(),
        StatusCode::FORBIDDEN,
        "claims:write must NOT be able to retire — that scope files challenges; \
         withdrawing another principal's assertion takes claims:admin"
    );

    // And the refusal must be a real refusal: nothing retracted.
    let (edges, _, _) = matcher_edge_footprint(&pool, a, b).await;
    assert_eq!(
        edges, 1,
        "the promoted edge must still be in force after the refused retire"
    );
}

/// Migrations 117 and 118: with NO administrative connection the retire
/// verdict changes nothing about the candidate (it stays `promoted`, the
/// matcher edge in force), says it did not retire, and records the whole
/// retirement as a deferred request with its `security_events` row.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_without_an_admin_connection_defers_the_cascade(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let candidate = insert_pending_candidate(&pool, a, b).await;
    let client_id = Uuid::new_v4();
    let token = decide_bearer_token(client_id, Some(agent), "agent");
    let resp = post_decide(pool.clone(), candidate, &token, "promote").await;
    assert_eq!(resp.status(), StatusCode::OK, "promote must succeed");

    let token = admin_bearer_token(client_id, Some(agent), "agent");
    let state = decide_state(pool.clone(), false).await;
    let resp = post_decide_on(state, candidate, &token, "retire").await;
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::OK,
        "the request is recorded (body: {})",
        String::from_utf8_lossy(&body)
    );
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["cascade"]["status"], "deferred", "{json}");
    assert_eq!(json["retired"], false, "{json}");
    assert_eq!(json["status"], "promoted", "{json}");
    assert_eq!(status_of(&pool, candidate).await, "promoted");
    let (edges, _, _) = matcher_edge_footprint(&pool, a, b).await;
    assert_eq!(edges, 1, "the deferred cascade retracted nothing");
    let event: Uuid = json["cascade"]["audit_event_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("the deferral names its audit row");
    let (et, cause): (String, String) = sqlx::query_as(
        "SELECT event_type::text, details->>'cause' FROM security_events WHERE id = $1",
    )
    .bind(event)
    .fetch_one(&pool)
    .await
    .expect("deferral row");
    assert_eq!(
        (et.as_str(), cause.as_str()),
        ("cascade.deferred", "match_retire")
    );
}

// ---------------------------------------------------------------------------
// Migration 117 on the APPLICATION ROLE (W10 revision). Every other test in
// this file runs its act on the superuser harness pool, which bypasses row
// security, so an administrative cascade that ran on the caller's connection
// (or drew its session from the application pool) would pass them all. Here
// the ScopedPool is downgraded to `epigraph_app` and the maintenance pool to
// `epigraph_maintenance`, the two logins `bin/server.rs` pairs.
// ---------------------------------------------------------------------------

#[path = "../viewer_fixture.rs"]
mod viewer_fixture;

/// A state whose stamped transactions run as `epigraph_app` and whose
/// maintenance pool (when `admin`) runs as `epigraph_maintenance`.
async fn app_role_state(pool: &PgPool, admin: bool) -> AppState {
    let url = database_url_of(pool);
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &url,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let who: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(scoped.inner())
        .await
        .expect("current_user");
    assert_eq!(
        who, "epigraph_app",
        "CALIBRATION: the act runs as the app role"
    );
    let scoped = if admin {
        let maint = viewer_fixture::downgraded_pool(pool, "epigraph_maintenance").await;
        scoped.with_maintenance_pool(maint)
    } else {
        scoped
    };
    AppState::with_scoped_pool(scoped, ApiConfig::default()).with_admin_cascade(admin)
}

/// A public claim owned by `group`, authored by `agent`.
async fn public_claim_owned_by(pool: &PgPool, agent: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("w10 app-role {tag} {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, true, 'public', $4)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed a public claim owned by a group");
    id
}

async fn post_supersede_on(
    state: AppState,
    claim: Uuid,
    token: &str,
) -> (StatusCode, serde_json::Value) {
    let resp = create_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/claims/{claim}/supersede"))
                .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "content": format!("the corrected {claim}"),
                        "truth_value": 0.6,
                        "reason": "w10 app-role supersede",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&body)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&body) }));
    (status, json)
}

/// The supersede route on the application role, by a caller that is NOT an
/// admin (`claims:write`, the claim's own writer). The act lands on the
/// caller's `epigraph_app` session; ANOTHER writer's edge into the retired
/// claim -- which that session cannot update -- is re-pointed onto the
/// replacement by the maintenance pool; the audit row names the caller's agent
/// and OAuth client; the response carries counts, not ids. Without the
/// maintenance pool the act still lands, the edge stays, and the deferral row
/// names the caller.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_route_on_the_app_role_runs_the_cascade_on_the_maintenance_pool(pool: PgPool) {
    let (w, w_group) = viewer_fixture::seed_agent_with_group(&pool, "w10-writer-w").await;
    let (x, x_group) = viewer_fixture::seed_agent_with_group(&pool, "w10-writer-x").await;
    let token = decide_bearer_token(w, Some(w), "agent");

    for admin in [true, false] {
        let old = public_claim_owned_by(&pool, w, w_group, "W's claim").await;
        let xc = public_claim_owned_by(&pool, x, x_group, "X's citing claim").await;
        let into_old = viewer_fixture::seed_edge(&pool, xc, old).await;

        let (status, json) =
            post_supersede_on(app_role_state(&pool, admin).await, old, &token).await;
        assert!(
            status == StatusCode::OK || status == StatusCode::CREATED,
            "the owner's supersede lands on the app role (admin={admin}): {status} {json}"
        );
        let new_id: Uuid = json["new_claim_id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .expect("new id");
        let target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
            .bind(into_old)
            .fetch_one(&pool)
            .await
            .expect("X's edge");
        let event: Uuid = json["cascade"]["audit_event_id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .expect("the cascade names its audit row");
        let (et, who, client): (String, Option<Uuid>, Option<String>) = sqlx::query_as(
            "SELECT event_type::text, agent_id, details#>>'{trigger,oauth,client_id}' \
               FROM security_events WHERE id = $1",
        )
        .bind(event)
        .fetch_one(&pool)
        .await
        .expect("audit row");
        assert_eq!(
            who,
            Some(w),
            "the audit row's agent_id is the caller (admin={admin})"
        );
        assert_eq!(client, Some(w.to_string()), "and its OAuth client");
        if admin {
            assert_eq!(json["cascade"]["status"], "applied", "{json}");
            assert_eq!(et, "cascade.admin_applied");
            assert_eq!(
                target, new_id,
                "X's edge was re-pointed by the maintenance pool"
            );
            assert_eq!(
                json["cascade"]["touched"]["edges_retargeted"],
                serde_json::json!(1),
                "the caller is told a COUNT, not the ids: {json}"
            );
        } else {
            assert_eq!(json["cascade"]["status"], "deferred", "{json}");
            assert_eq!(et, "cascade.deferred");
            assert_eq!(target, old, "the deferred cascade moved nothing");
        }
    }
}

/// Migration 118 (W11, #518) on the APPLICATION ROLE: with its stale guard
/// applied, the retire verdict works through the maintenance pool -- the
/// candidate is `stale`, the matcher edge retracted, and the applied audit row
/// names the caller -- and without one it changes nothing and records the
/// retirement as a deferred request. Before the fix the verdict flipped the
/// candidate on the caller's `epigraph_app` session, which 118 refuses (MC01),
/// so both shapes failed with a database error.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_route_on_the_app_role_under_118_runs_on_the_maintenance_pool_or_defers(
    pool: PgPool,
) {
    let (w, _) = viewer_fixture::seed_agent_with_group(&pool, "w10-retirer").await;
    let token = admin_bearer_token(w, Some(w), "agent");
    let promote = decide_bearer_token(w, Some(w), "agent");

    for admin in [true, false] {
        let a = insert_claim(&pool, w).await;
        let b = insert_claim(&pool, w).await;
        let candidate = insert_pending_candidate(&pool, a, b).await;
        let resp = post_decide(pool.clone(), candidate, &promote, "promote").await;
        assert_eq!(resp.status(), StatusCode::OK, "promote must succeed");
        viewer_fixture::assert_stale_guard_refuses_the_app_role(&pool, candidate).await;

        let resp = post_decide_on(
            app_role_state(&pool, admin).await,
            candidate,
            &token,
            "retire",
        )
        .await;
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body)
            .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&body) }));
        assert_eq!(status, StatusCode::OK, "admin={admin}: {json}");
        let event: Uuid = json["cascade"]["audit_event_id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .expect("the retirement names its audit row");
        let (et, who, cause): (String, Option<Uuid>, String) = sqlx::query_as(
            "SELECT event_type::text, agent_id, details->>'cause' \
               FROM security_events WHERE id = $1",
        )
        .bind(event)
        .fetch_one(&pool)
        .await
        .expect("audit row");
        assert_eq!((who, cause.as_str()), (Some(w), "match_retire"));
        let (edges, _, _) = matcher_edge_footprint(&pool, a, b).await;
        if admin {
            assert_eq!(json["cascade"]["status"], "applied", "{json}");
            assert_eq!(json["retired"], true, "{json}");
            assert_eq!(et, "cascade.admin_applied");
            assert_eq!(status_of(&pool, candidate).await, "stale");
            assert_eq!(edges, 0, "the matcher edge was retracted");
        } else {
            assert_eq!(json["cascade"]["status"], "deferred", "{json}");
            assert_eq!(json["retired"], false, "{json}");
            assert_eq!(et, "cascade.deferred");
            assert_eq!(status_of(&pool, candidate).await, "promoted");
            assert_eq!(edges, 1, "nothing was retracted");
        }
    }
}

/// The `cascade.deferred` rows recorded for `subject`, with their `recorded_by`.
async fn deferrals_for(pool: &PgPool, subject: Uuid) -> Vec<Option<String>> {
    sqlx::query_scalar(
        "SELECT details->>'recorded_by' FROM security_events \
          WHERE event_type = 'cascade.deferred' \
            AND details#>>'{trigger,subject_id}' = $1::text",
    )
    .bind(subject)
    .fetch_all(pool)
    .await
    .expect("read the deferral rows")
}

/// Operator decision D9 (batch W12a), on the APPLICATION ROLE with no
/// maintenance pool -- the only state a request-serving `server` has now. Each
/// of the three cascading routes (supersede, dedup, and the claims:admin
/// match-candidate retire) commits the caller's act (none for a retire, whose
/// whole request is the deferral), answers success with `cascade.status ==
/// "deferred"` and the D9 reason (no ids in it), and records EXACTLY ONE
/// `cascade.deferred` row for its subject, written through 117's verifying
/// definer (`recorded_by`). The replay timer applies them later.
#[sqlx::test(migrations = "../../migrations")]
async fn d9_every_cascading_route_defers_on_the_app_role_without_a_maintenance_pool(pool: PgPool) {
    let (w, w_group) = viewer_fixture::seed_agent_with_group(&pool, "d9-writer").await;
    let write = decide_bearer_token(w, Some(w), "agent");
    let admin = admin_bearer_token(w, Some(w), "agent");
    let reason = epigraph_engine::admin_cascade::REASON_NOT_CONFIGURED;

    // Supersede.
    let old = public_claim_owned_by(&pool, w, w_group, "d9 superseded").await;
    let (status, json) = post_supersede_on(app_role_state(&pool, false).await, old, &write).await;
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED,
        "{status} {json}"
    );
    assert_eq!(json["cascade"]["status"], "deferred", "{json}");
    assert_eq!(json["cascade"]["reason"], reason, "{json}");
    let is_current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(old)
        .fetch_one(&pool)
        .await
        .expect("old claim");
    assert!(!is_current, "the supersede act did not commit");
    assert_eq!(
        deferrals_for(&pool, old).await,
        vec![Some("epigraph_record_cascade_deferral".to_string())]
    );

    // Dedup.
    let dup = public_claim_owned_by(&pool, w, w_group, "d9 duplicate").await;
    let canonical = public_claim_owned_by(&pool, w, w_group, "d9 canonical").await;
    let resp = create_router(app_role_state(&pool, false).await)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/claims/{dup}/dedup"))
                // An admin token. Since batch OA1 claims:write would do too:
                // w writes both the duplicate's and the canonical's group.
                .header(axum::http::header::AUTHORIZATION, format!("Bearer {admin}"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "canonical_id": canonical }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&body) }));
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["cascade"]["status"], "deferred", "{json}");
    assert_eq!(json["cascade"]["reason"], reason, "{json}");
    let supersedes: Option<Uuid> =
        sqlx::query_scalar("SELECT supersedes FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .expect("dup claim");
    assert_eq!(supersedes, Some(canonical), "the dedup act did not commit");
    assert_eq!(
        deferrals_for(&pool, dup).await,
        vec![Some("epigraph_record_cascade_deferral".to_string())]
    );

    // The claims:admin retire.
    let a = insert_claim(&pool, w).await;
    let b = insert_claim(&pool, w).await;
    let candidate = insert_pending_candidate(&pool, a, b).await;
    let resp = post_decide(pool.clone(), candidate, &write, "promote").await;
    assert_eq!(resp.status(), StatusCode::OK, "promote must succeed");
    let resp = post_decide_on(
        app_role_state(&pool, false).await,
        candidate,
        &admin,
        "retire",
    )
    .await;
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&body) }));
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["cascade"]["status"], "deferred", "{json}");
    assert_eq!(
        deferrals_for(&pool, candidate).await,
        vec![Some("epigraph_record_cascade_deferral".to_string())]
    );
}

/// Wait until another backend of this test database is blocked on a lock while
/// running a statement matching `pattern` (an ILIKE pattern): proof that the
/// request under test read its row BEFORE the competing transaction commits.
async fn wait_until_blocked(watcher: &mut sqlx::PgConnection, pattern: &str, what: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity
             WHERE datname = current_database()
               AND pid <> pg_backend_pid()
               AND wait_event_type = 'Lock'
               AND query ILIKE $1",
        )
        .bind(pattern)
        .fetch_one(&mut *watcher)
        .await
        .expect("pg_stat_activity");
        if waiting >= 1 {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "calibration: {what} never blocked on a lock (pattern {pattern})"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// The HTTP twin of the MCP race test, roles swapped: a `promote` that read the
/// candidate as `pending` loses the race to an operator's `reject` that commits
/// first. `promote_and_reject_still_refuse_an_already_decided_candidate` pins
/// the sequential case; this pins the concurrent one, which the read-then-gate
/// check cannot see.
///
/// An unconditional status write waits for the reject's row lock, then
/// overwrites it to `promoted` and writes a matcher edge over a pair an
/// operator just rejected. The promote must be refused with the same 409 and
/// write nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_promote_racing_a_committed_reject_is_refused_with_409(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let candidate = insert_pending_candidate(&pool, a, b).await;
    let token = decide_bearer_token(Uuid::new_v4(), Some(agent), "agent");
    let mut watcher = pool.acquire().await.expect("watcher connection");

    // An operator's reject that has passed its gate and written, NOT committed:
    // it holds the candidate's row lock while the committed version is still
    // `pending`.
    let mut other = pool.begin().await.expect("competing transaction");
    sqlx::query(
        "UPDATE match_candidates SET status = 'rejected', decided_at = now() WHERE id = $1",
    )
    .bind(candidate)
    .execute(&mut *other)
    .await
    .expect("competing reject");

    let promote = post_decide(pool.clone(), candidate, &token, "promote");
    let commit_once_blocked = async {
        wait_until_blocked(&mut watcher, "%UPDATE match_candidates%", "the promote").await;
        other.commit().await.expect("commit the competing reject");
    };
    let (resp, ()) = tokio::join!(promote, commit_once_blocked);

    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a promote that lost the race to a committed reject must 409: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        status_of(&pool, candidate).await,
        "rejected",
        "the operator's reject stands"
    );
    assert_eq!(
        matcher_edge_footprint(&pool, a, b).await.0,
        0,
        "no matcher edge may be written over a rejected pair"
    );
}

/// Interleaving A over HTTP, the direction backlog b3f95bea names: a `reject`
/// that read the candidate as `pending` loses the race to a `promote` that
/// commits first, edge and all.
///
/// An unconditional status write waits for the promote's row lock, then
/// overwrites it to `rejected` and returns 200, leaving the promotion's matcher
/// edge in force under a rejected candidate -- the orphan the backlog item
/// reported. The reject must be refused with the same 409 as a sequential
/// replay and change nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reject_racing_a_committed_promote_is_refused_with_409(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let candidate = insert_pending_candidate(&pool, a, b).await;
    let token = decide_bearer_token(Uuid::new_v4(), Some(agent), "agent");
    let mut watcher = pool.acquire().await.expect("watcher connection");

    // A promote that has passed its gate, mid-flight: status flipped and its
    // matcher edge written (the shape `create_symmetric_if_absent` writes), NOT
    // committed. It holds the candidate's row lock while the committed version
    // is still `pending`.
    let mut other = pool.begin().await.expect("competing transaction");
    sqlx::query(
        "UPDATE match_candidates SET status = 'promoted', decided_at = now() WHERE id = $1",
    )
    .bind(candidate)
    .execute(&mut *other)
    .await
    .expect("competing promote: status");
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
         VALUES ($1, 'claim', $2, 'claim', 'CORROBORATES', $3)",
    )
    .bind(a)
    .bind(b)
    .bind(SqlxJson(serde_json::json!({
        "source": "cross_source_matcher",
        "candidate_id": candidate,
    })))
    .execute(&mut *other)
    .await
    .expect("competing promote: edge");

    let reject = post_decide(pool.clone(), candidate, &token, "reject");
    let commit_once_blocked = async {
        wait_until_blocked(&mut watcher, "%UPDATE match_candidates%", "the reject").await;
        other.commit().await.expect("commit the competing promote");
    };
    let (resp, ()) = tokio::join!(reject, commit_once_blocked);

    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a reject that lost the race to a committed promote must 409: {body}"
    );
    assert!(
        body.contains("already decided (status=promoted)"),
        "the race loser gets the same refusal as a sequential replay: {body}"
    );
    assert_eq!(
        status_of(&pool, candidate).await,
        "promoted",
        "the committed promotion stands; `rejected` here is b3f95bea's orphan state"
    );
    assert_eq!(
        matcher_edge_footprint(&pool, a, b).await.0,
        1,
        "the promotion's matcher edge is still in force"
    );
}

/// A promote resolves its edge's polarity from the `verifier_verdict` it read.
/// A matcher sweep may re-score a still-`pending` row in between
/// (`MatchCandidateRepo::upsert` only freezes the verdict once `decided_at` is
/// set), so by the time the promote's write runs the verdict it acted on is no
/// longer the row's.
///
/// Here the row is read with NO verdict (which promotes as CORROBORATES) and a
/// competing transaction re-scores it to `contradicts` before the promote's
/// write runs. A write conditional only on `status = 'pending'` still matches
/// and records CORROBORATES over a pair the verifier now says contradict: the
/// inverted polarity the promote arm's comment says was fixed. The promote
/// must be refused with a 409 naming the changed verdict and write nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_promote_racing_a_verdict_rescore_is_refused_with_409(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;
    let candidate = insert_pending_candidate(&pool, a, b).await;
    let token = decide_bearer_token(Uuid::new_v4(), Some(agent), "agent");
    let mut watcher = pool.acquire().await.expect("watcher connection");

    // A matcher re-score of the still-pending row, written NOT committed: the
    // verdict changes, the status does not.
    let mut other = pool.begin().await.expect("competing transaction");
    sqlx::query(
        "UPDATE match_candidates
         SET verifier_verdict = 'contradicts', verifier_rationale = 'rescored'
         WHERE id = $1",
    )
    .bind(candidate)
    .execute(&mut *other)
    .await
    .expect("competing re-score");

    let promote = post_decide(pool.clone(), candidate, &token, "promote");
    let commit_once_blocked = async {
        wait_until_blocked(&mut watcher, "%UPDATE match_candidates%", "the promote").await;
        other.commit().await.expect("commit the competing re-score");
    };
    let (resp, ()) = tokio::join!(promote, commit_once_blocked);

    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a promote whose verdict was re-scored under it must 409: {body}"
    );
    assert!(
        body.contains("verifier_verdict changed"),
        "the refusal names the changed verdict, not an already-decided row: {body}"
    );
    assert_eq!(
        status_of(&pool, candidate).await,
        "pending",
        "nothing was decided; the operator re-reads and decides again"
    );
    assert_eq!(
        matcher_edge_footprint(&pool, a, b).await.0,
        0,
        "no edge may be written from a verdict the row no longer carries"
    );
}

// ---------------------------------------------------------------------------
// U043 (backlog 110f666a, gap 3): a retirement re-derives its endpoints' belief.
//
// `apply_match_retire` deletes the edge-keyed BBAs, factors and bp_messages of
// the matcher edge it retracts. Every other cascade that removes belief inputs
// (supersede, dedup, edge_retract) then re-derives the affected claims from
// the `mass_functions` that survive. A retirement did not, so an endpoint kept
// whatever `pignistic_prob` was last written to it. A past
// `POST /api/v1/bp/propagate {"apply_updates": true}` is such a writer, and a
// later propagate cannot repair it: it builds its variables from the surviving
// `factors` only, so an endpoint whose only factor was the matcher edge is no
// longer a variable, and scalar BP seeds its priors from the stored (biased)
// value. A DS re-derivation from `mass_functions` is the only repair.
// ---------------------------------------------------------------------------

/// A stale BP-written value, far from any value the BBA below derives.
const POISONED_BETP: f64 = 0.93;

/// Give `claim` one BBA on the engine's own `binary_truth` frame, NOT keyed on
/// any edge (`perspective_id` NULL, so the retirement's edge-keyed delete
/// leaves it in place), derive its cache from it through the same entry point
/// the cascade uses, and return the derived `pignistic_prob`.
///
/// The frame must be the engine's: the cascade re-derives on `binary_truth`,
/// and a BBA on a test-local frame would leave it nothing to recombine.
async fn seed_surviving_bba_and_derive(pool: &PgPool, claim: Uuid, source_agent: Uuid) -> f64 {
    let scoped = epigraph_db::ScopedPool::connect(
        &database_url_of(pool),
        epigraph_db::SessionGucMode::Session,
    )
    .await
    .expect("ScopedPool over the test database")
    .with_maintenance_pool(pool.clone());
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    let (conn, viewer) = session.split();
    let frame = epigraph_engine::edge_factor::ensure_binary_frame(&mut *conn, viewer)
        .await
        .expect("the engine's binary frame");
    sqlx::query(
        "INSERT INTO mass_functions \
           (claim_id, frame_id, source_agent_id, perspective_id, masses, source_strength, \
            evidence_type) \
         VALUES ($1, $2, $3, NULL, $4, 1.0, 'empirical')",
    )
    .bind(claim)
    .bind(frame)
    .bind(source_agent)
    .bind(serde_json::json!({"0": 0.6, "1": 0.1, "0,1": 0.3}))
    .execute(&mut *conn)
    .await
    .expect("seed a surviving BBA");
    let derived =
        epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut *conn, viewer, claim)
            .await
            .expect("derive the claim's belief from its BBA");
    assert!(
        derived,
        "CALIBRATION: the BBA is on a frame the recompute reads"
    );
    let d: Option<f64> = sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the derived value");
    let d = d.expect("CALIBRATION: the recompute wrote pignistic_prob");
    assert!(
        (d - POISONED_BETP).abs() > 0.1,
        "CALIBRATION: the derived value ({d}) must be distinguishable from the poison"
    );
    d
}

/// Simulate a past `bp/propagate` with `apply_updates: true`: it overwrites the
/// cached `pignistic_prob` with a value the factor graph biased.
async fn poison_betp(pool: &PgPool, claim: Uuid) {
    sqlx::query("UPDATE claims SET pignistic_prob = $2 WHERE id = $1")
        .bind(claim)
        .bind(POISONED_BETP)
        .execute(pool)
        .await
        .expect("simulate a BP-written value");
}

async fn betp_of(pool: &PgPool, claim: Uuid) -> Option<f64> {
    sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read pignistic_prob")
}

/// The `security_events` row type a belief audit id names.
async fn event_type_of(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT event_type::text FROM security_events WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("the audit row exists")
}

/// A promoted candidate between two fresh claims of a grouped agent, and the
/// admin token that may retire it.
async fn promoted_pair(pool: &PgPool, label: &str) -> (Uuid, Uuid, Uuid, Uuid, String) {
    let (w, _) = viewer_fixture::seed_agent_with_group(pool, label).await;
    let a = insert_claim(pool, w).await;
    let b = insert_claim(pool, w).await;
    let candidate = insert_pending_candidate(pool, a, b).await;
    let promote = decide_bearer_token(w, Some(w), "agent");
    let resp = post_decide(pool.clone(), candidate, &promote, "promote").await;
    assert_eq!(resp.status(), StatusCode::OK, "promote must succeed");
    (w, a, b, candidate, admin_bearer_token(w, Some(w), "agent"))
}

async fn retire_on(state: AppState, candidate: Uuid, token: &str) -> serde_json::Value {
    let resp = post_decide_on(state, candidate, token, "retire").await;
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&body) }));
    assert_eq!(status, StatusCode::OK, "{json}");
    json
}

/// The retire request, with a maintenance connection, on the production roles
/// (`epigraph_app` for the request, `epigraph_maintenance` for the cascade):
/// the endpoint's BP-written value is replaced by the DS value its surviving
/// BBA derives, and the re-derivation has its own audit row.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_rederives_endpoint_belief_from_surviving_bbas(pool: PgPool) {
    let (w, _a, b, candidate, admin) = promoted_pair(&pool, "u043-direct").await;
    let d = seed_surviving_bba_and_derive(&pool, b, w).await;
    poison_betp(&pool, b).await;

    let json = retire_on(app_role_state(&pool, true).await, candidate, &admin).await;
    assert_eq!(json["cascade"]["status"], "applied", "{json}");
    assert_eq!(json["retired"], true, "{json}");

    let after = betp_of(&pool, b)
        .await
        .expect("b keeps a cache: a BBA backs it");
    assert!(
        (after - d).abs() < 1e-9,
        "the retirement must re-derive b from its surviving BBA: expected {d}, found {after} \
         (still {POISONED_BETP} means nothing re-derived it)"
    );
    let belief_event: Uuid = json["cascade"]["belief_audit_event_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("the re-derivation names its audit row: {json}"));
    assert_eq!(
        event_type_of(&pool, belief_event).await,
        "cascade.belief_rederived"
    );
    assert_eq!(
        json["belief_cascade"]["recomputed"],
        serde_json::json!([b]),
        "the caller sees which endpoint was re-derived: {json}"
    );
}

/// Default decision (scope Q2): an endpoint with NO BBA on any frame whose
/// cache a retirement leaves unbacked is cleared, the `edge_retract` cascade's
/// semantics. The only writer that can have put a value there without a BBA
/// is the factor graph that just lost an edge.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_clears_an_unbacked_endpoint_cache(pool: PgPool) {
    let (_w, a, _b, candidate, admin) = promoted_pair(&pool, "u043-unbacked").await;
    sqlx::query(
        "UPDATE claims SET belief = 0.5, plausibility = 0.95, pignistic_prob = $2 WHERE id = $1",
    )
    .bind(a)
    .bind(POISONED_BETP)
    .execute(&pool)
    .await
    .expect("a BP-written cache with no BBA behind it");

    let json = retire_on(app_role_state(&pool, true).await, candidate, &admin).await;
    assert_eq!(json["cascade"]["status"], "applied", "{json}");
    assert_eq!(
        betp_of(&pool, a).await,
        None,
        "an endpoint no BBA backs must have its stale cache cleared: {json}"
    );
    assert_eq!(
        json["belief_cascade"]["unbacked"],
        serde_json::json!([a]),
        "{json}"
    );
}

/// Production's path under D9: the request defers, and the replay timer carries
/// the retirement out on the `epigraph_maintenance` role. The re-derivation
/// must happen there too, and its audit row is named on the replay item.
#[sqlx::test(migrations = "../../migrations")]
async fn replayed_match_retire_rederives_endpoint_belief(pool: PgPool) {
    let (w, _a, b, candidate, admin) = promoted_pair(&pool, "u043-replay").await;
    let d = seed_surviving_bba_and_derive(&pool, b, w).await;
    poison_betp(&pool, b).await;

    let json = retire_on(app_role_state(&pool, false).await, candidate, &admin).await;
    assert_eq!(json["cascade"]["status"], "deferred", "{json}");
    assert_eq!(
        betp_of(&pool, b).await,
        Some(POISONED_BETP),
        "CALIBRATION: a deferred retirement changes nothing yet"
    );

    let maintenance = viewer_fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &database_url_of(&pool),
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool")
    .with_maintenance_pool(maintenance);
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    let (conn, admin_viewer) = session.split();
    let report = epigraph_engine::admin_cascade::replay_deferred(
        conn,
        admin_viewer,
        "u043-test",
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay");
    let item = report
        .items
        .iter()
        .find(|i| i.subject_id == Some(candidate))
        .unwrap_or_else(|| panic!("the replay carried out the retirement: {report:?}"));
    assert_eq!(
        status_of(&pool, candidate).await,
        "stale",
        "CALIBRATION: the replay retired the candidate: {report:?}"
    );

    let after = betp_of(&pool, b)
        .await
        .expect("b keeps a cache: a BBA backs it");
    assert!(
        (after - d).abs() < 1e-9,
        "the replayed retirement must re-derive b: expected {d}, found {after}"
    );
    let belief_event = item
        .status
        .belief_audit_event_id
        .unwrap_or_else(|| panic!("the replayed re-derivation names its audit row: {report:?}"));
    assert_eq!(
        event_type_of(&pool, belief_event).await,
        "cascade.belief_rederived"
    );
}

/// The re-derivation is gated on the retirement having withdrawn something. A
/// candidate that was never promoted has no matcher edge, factor or BBA to
/// remove, and retiring it must not rewrite caches it never fed.
#[sqlx::test(migrations = "../../migrations")]
async fn retiring_an_unpromoted_candidate_leaves_endpoint_beliefs_alone(pool: PgPool) {
    let (w, _) = viewer_fixture::seed_agent_with_group(&pool, "u043-unpromoted").await;
    let a = insert_claim(&pool, w).await;
    let b = insert_claim(&pool, w).await;
    let candidate = insert_pending_candidate(&pool, a, b).await;
    seed_surviving_bba_and_derive(&pool, b, w).await;
    poison_betp(&pool, b).await;

    let admin = admin_bearer_token(w, Some(w), "agent");
    let json = retire_on(app_role_state(&pool, true).await, candidate, &admin).await;
    assert_eq!(json["cascade"]["status"], "applied", "{json}");
    assert_eq!(json["edges_retracted"], 0, "{json}");
    assert_eq!(
        betp_of(&pool, b).await,
        Some(POISONED_BETP),
        "nothing this retirement removed fed b's cache: {json}"
    );
    assert!(
        json["cascade"]["belief_audit_event_id"].is_null(),
        "no re-derivation ran, so none is audited: {json}"
    );
}

/// Move `claim` into a fresh team group nobody in the test belongs to, so only
/// a bypass viewer can see it.
async fn privatize_into_fresh_group(pool: &PgPool, claim: Uuid) {
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind) \
         VALUES ('u043 hidden endpoint', 'did:test:u043:' || gen_random_uuid(), \
                 decode(repeat('ab', 32), 'hex'), 'team') RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed a group");
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(group)
        .execute(pool)
        .await
        .expect("privatize the claim");
}

/// The caller's view filters what it is TOLD, never what is REPAIRED. One
/// endpoint of the promoted pair is a claim the retiring admin cannot see: the
/// re-derivation (bypass viewer) must still repair it, and the
/// `belief_cascade` the caller gets back must not name it. This separates
/// `apply_match_retire`'s `admin_viewer` from its `caller`, which are both
/// `&Viewer` and swap without a compile error.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_repairs_a_hidden_endpoint_without_naming_it_to_the_caller(pool: PgPool) {
    let (w, _) = viewer_fixture::seed_agent_with_group(&pool, "u043-hidden").await;
    let other = insert_agent(&pool).await;
    let a = insert_claim(&pool, w).await;
    let b = insert_claim(&pool, other).await;
    let candidate = insert_pending_candidate(&pool, a, b).await;
    let promote = decide_bearer_token(w, Some(w), "agent");
    let resp = post_decide(pool.clone(), candidate, &promote, "promote").await;
    assert_eq!(resp.status(), StatusCode::OK, "promote must succeed");

    let d_a = seed_surviving_bba_and_derive(&pool, a, w).await;
    let d_b = seed_surviving_bba_and_derive(&pool, b, other).await;
    poison_betp(&pool, a).await;
    poison_betp(&pool, b).await;
    privatize_into_fresh_group(&pool, b).await;

    let caller = epigraph_db::visibility::Viewer::resolve(&pool, w)
        .await
        .expect("resolve the caller's viewer");
    let visible = epigraph_db::ClaimRepository::visible_claim_ids(&pool, &caller, &[a, b])
        .await
        .expect("visibility probe");
    assert!(
        visible.contains(&a) && !visible.contains(&b),
        "CALIBRATION: the caller sees a and not b: {visible:?}"
    );

    let admin = admin_bearer_token(w, Some(w), "agent");
    let json = retire_on(app_role_state(&pool, true).await, candidate, &admin).await;
    assert_eq!(json["cascade"]["status"], "applied", "{json}");

    for (claim, d) in [(a, d_a), (b, d_b)] {
        let after = betp_of(&pool, claim)
            .await
            .expect("a BBA backs both endpoints");
        assert!(
            (after - d).abs() < 1e-9,
            "the retirement must re-derive endpoint {claim} whether or not the caller sees it: \
             expected {d}, found {after}: {json}"
        );
    }

    let report = &json["belief_cascade"];
    assert_eq!(
        report["recomputed"],
        serde_json::json!([a]),
        "the caller is told about the endpoint it sees, and only that one: {json}"
    );
    let b_text = b.to_string();
    for key in ["targets", "recomputed", "unbacked", "errors"] {
        let named = report[key]
            .as_array()
            .unwrap_or_else(|| panic!("belief_cascade.{key} is a list: {json}"))
            .iter()
            .any(|v| v.as_str().is_some_and(|s| s.contains(&b_text)));
        assert!(
            !named,
            "belief_cascade.{key} must not name the hidden endpoint {b}: {json}"
        );
    }
}

/// The re-derivation reads the `mass_functions` that SURVIVE the retirement. A
/// BBA keyed on the matcher edge (`perspective_id` = the edge, the shape
/// `auto_wire_ds_for_edge` writes) is deleted by the retirement
/// (`delete_edge_bbas`), and the re-derived value must exclude it: the latent
/// deleted-BBA / no-recompute gap the scope's option B closes. Prod held no
/// such BBA on 2026-08-19, and today's promote path writes none, so the
/// fixture plants one.
#[sqlx::test(migrations = "../../migrations")]
async fn retire_rederives_without_the_edge_keyed_bba_it_deletes(pool: PgPool) {
    let (w, a, b, candidate, admin) = promoted_pair(&pool, "u043-edge-bba").await;
    let edge: Uuid = sqlx::query_scalar(
        "SELECT id FROM edges \
          WHERE ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)) \
            AND properties->>'source' = 'cross_source_matcher' AND valid_to IS NULL \
          ORDER BY created_at LIMIT 1",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .expect("CALIBRATION: the promotion wrote a live matcher edge");
    let d = seed_surviving_bba_and_derive(&pool, b, w).await;

    // A strongly FALSE-leaning BBA keyed on the matcher edge, from a different
    // source agent, folded into b's cache.
    let edge_signer = insert_agent(&pool).await;
    let scoped = epigraph_db::ScopedPool::connect(
        &database_url_of(&pool),
        epigraph_db::SessionGucMode::Session,
    )
    .await
    .expect("ScopedPool over the test database")
    .with_maintenance_pool(pool.clone());
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    let (conn, viewer) = session.split();
    let frame = epigraph_engine::edge_factor::ensure_binary_frame(&mut *conn, viewer)
        .await
        .expect("the engine's binary frame");
    epigraph_db::PerspectiveRepository::ensure_edge_perspective(
        &mut *conn,
        edge,
        Some(edge_signer),
    )
    .await
    .expect("the edge's perspective row (mass_functions.perspective_id FK)");
    sqlx::query(
        "INSERT INTO mass_functions \
           (claim_id, frame_id, source_agent_id, perspective_id, masses, source_strength, \
            evidence_type) \
         VALUES ($1, $2, $3, $4, $5, 1.0, 'empirical')",
    )
    .bind(b)
    .bind(frame)
    .bind(edge_signer)
    .bind(edge)
    .bind(serde_json::json!({"1": 0.8, "0,1": 0.2}))
    .execute(&mut *conn)
    .await
    .expect("seed the edge-keyed BBA");
    epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut *conn, viewer, b)
        .await
        .expect("fold the edge-keyed BBA into b's cache");
    drop(session);
    let combined = betp_of(&pool, b)
        .await
        .expect("CALIBRATION: b has a cache from both BBAs");
    assert!(
        (combined - d).abs() > 0.1,
        "CALIBRATION: the edge-keyed BBA must move b's value measurably \
         (surviving-only {d}, combined {combined})"
    );

    let json = retire_on(app_role_state(&pool, true).await, candidate, &admin).await;
    assert_eq!(json["cascade"]["status"], "applied", "{json}");
    assert!(
        json["bbas_invalidated"].as_u64().unwrap_or(0) >= 1,
        "the retirement deletes the edge-keyed BBA: {json}"
    );
    let left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE perspective_id = $1")
            .bind(edge)
            .fetch_one(&pool)
            .await
            .expect("count the edge-keyed BBAs");
    assert_eq!(left, 0, "no BBA keyed on the retired edge survives: {json}");

    let after = betp_of(&pool, b)
        .await
        .expect("b keeps a cache: a BBA still backs it");
    assert!(
        (after - d).abs() < 1e-9,
        "the re-derivation must run AFTER the edge-keyed BBA is deleted and fold only the \
         surviving one: expected {d}, found {after} (combined value was {combined}): {json}"
    );
}

// ---------------------------------------------------------------------------
// Scope parity: the claim-scoped read and the candidate list
// ---------------------------------------------------------------------------

async fn get_with_token(
    router: &Router,
    path: &str,
    token: &str,
) -> axum::http::Response<axum::body::Body> {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// `GET /api/v1/claims/:id/cross_source_matches` checks `claims:read` itself,
/// as its sibling `list_candidates` does and as its MCP twin
/// (`find_cross_source_matches` in `epigraph-mcp/src/scope_map.rs`) does.
///
/// `claims:write` alone is the wrong scope for a read: `check_scopes` is
/// strictly conjunctive, with no write-implies-read ladder (see
/// `policies_auth_test.rs::list_candidates_with_wrong_scope_returns_403`).
///
/// The four requests pin, in order:
/// - the sibling refuses this token (the parity being asserted);
/// - this route refuses it for a claim that exists and is visible;
/// - this route refuses it for an id that does not exist — 403, not 404, so
///   the scope check runs before the existence probe and the two ids cannot be
///   told apart by a caller without the scope;
/// - a `claims:read` token is admitted on the same claim (the route is not
///   simply locked).
///
/// The two refusals are compared byte for byte, not only by status, matching
/// the 404-parity standard in `tenant_isolation_http.rs`.
///
/// The handler's own 401 arm (no `AuthContext`) is deliberately untested: both
/// registrations of this path sit behind `bearer_auth_middleware`, which
/// answers 401 before the handler runs, so a router-level no-credential test
/// would pass with or without that arm.
#[sqlx::test(migrations = "../../migrations")]
async fn cross_source_matches_requires_claims_read_like_list_candidates(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let claim = insert_claim(&pool, agent).await;
    let absent = Uuid::new_v4();
    let router = create_test_router(pool);

    let write_only = decide_bearer_token_with_scopes(
        Uuid::new_v4(),
        Some(agent),
        "service",
        vec!["claims:write".to_string()],
    );

    let sibling = get_with_token(
        &router,
        "/api/v1/match_candidates?status=pending&limit=10",
        &write_only,
    )
    .await;
    assert_eq!(
        sibling.status(),
        StatusCode::FORBIDDEN,
        "precondition: list_candidates must refuse a token without claims:read"
    );

    let present = get_with_token(
        &router,
        &format!("/api/v1/claims/{claim}/cross_source_matches"),
        &write_only,
    )
    .await;
    assert_eq!(
        present.status(),
        StatusCode::FORBIDDEN,
        "cross_source_matches must refuse a token without claims:read, as list_candidates does"
    );

    let missing = get_with_token(
        &router,
        &format!("/api/v1/claims/{absent}/cross_source_matches"),
        &write_only,
    )
    .await;
    assert_eq!(
        missing.status(),
        StatusCode::FORBIDDEN,
        "the scope check must run before the existence probe: an absent id answers \
         the same as a present one to a caller without claims:read"
    );
    let present_body = present.into_body().collect().await.unwrap().to_bytes();
    let missing_body = missing.into_body().collect().await.unwrap().to_bytes();
    assert!(
        !present_body.is_empty(),
        "the 403 must carry an error body for the comparison to mean anything"
    );
    assert_eq!(
        present_body, missing_body,
        "the 403 for a present id and for an absent id must be byte-identical"
    );

    let reader = decide_bearer_token_with_scopes(
        Uuid::new_v4(),
        Some(agent),
        "service",
        vec!["claims:read".to_string()],
    );
    let admitted = get_with_token(
        &router,
        &format!("/api/v1/claims/{claim}/cross_source_matches"),
        &reader,
    )
    .await;
    assert_eq!(
        admitted.status(),
        StatusCode::OK,
        "a claims:read token must still be admitted"
    );
    let body = admitted.into_body().collect().await.unwrap().to_bytes();
    let parsed: Response = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.claim_id, claim.to_string());
}
