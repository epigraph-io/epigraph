#![cfg(feature = "db")]
//! The REST claim-mutation ownership gate (`middleware::scopes::require_owner_or_admin`,
//! backlog a2d3e945) on a token minted the way production mints one: a client
//! registered in `oauth_clients`, a `client_credentials` grant through the real
//! `/oauth/token` route, and the principal the mint provisions
//! (`AgentRepository::ensure_for_client`). That principal is an `agents.id`
//! distinct from the client's `oauth_clients.id`, and it is the id a claim the
//! token writes is authored as.
//!
//! The three gated routes (`PUT /api/v1/claims/:id`, `PATCH /api/v1/claims/:id`,
//! `PATCH /api/v1/claims/:id/labels`) must admit that author on its own claim,
//! and must not admit a claim whose author id merely equals the token's
//! `oauth_clients.id` (an `agents` row created with that id).
//!
//! # Verified to fail
//!
//! With the gate's pre-a2d3e945 body (`auth.owner_id.unwrap_or(auth.client_id)
//! == target`) the two router tests fail: the author's three edits are 403,
//! and the client-id-authored claim's three edits are 200.
//!
//! The router tests run on the harness pool, which bypasses row security, so
//! they pin the GATE. What the write does after the gate admits is pinned on
//! the application role by
//! `put_by_the_author_lands_on_the_app_role_and_a_reader_author_is_refused`:
//! with the new gate and `update_claim`'s writes still on the unstamped
//! `state.db_pool`, the author's PUT is 404 there (the unstamped read and
//! UPDATE reach no row), measured before the stamping landed.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_db::repos::oauth_client::OAuthClientRepository;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

mod viewer_fixture;

/// The URL of the per-test database `#[sqlx::test]` created.
async fn url_for(pool: &PgPool) -> String {
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("current_database()");
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let prefix = base
        .split_once('?')
        .map_or(base.as_str(), |(a, _)| a)
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("DATABASE_URL must carry a database path")
        .0
        .to_string();
    format!("{prefix}/{db}")
}

async fn call(
    app: &axum::Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: &Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// An active SERVICE client granted `claims:read claims:write`, then a token
/// for it from `/oauth/token`. Returns `(oauth_clients.id, token, the token's
/// agents.id principal)`.
async fn real_service_token(pool: &PgPool, app: &axum::Router) -> (Uuid, String, Uuid) {
    let scopes: Vec<String> = vec!["claims:read".into(), "claims:write".into()];
    let secret: [u8; 32] = rand::random();
    let client_id = format!("a2d3e945_{}", Uuid::new_v4().simple());
    let row = OAuthClientRepository::create(
        pool,
        &client_id,
        Some(blake3::hash(&secret).as_bytes()),
        "a2d3e945 author",
        "service",
        &scopes,
        &scopes,
        "active",
        None,
        None,
        Some("A2D3E945 Test Org"),
        Some("a2d3e945@example.com"),
        None,
    )
    .await
    .expect("service client");
    let (status, body) = call(
        app,
        Method::POST,
        "/oauth/token",
        None,
        &json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": hex::encode(secret),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "client_credentials grant: {body}");
    let token = body["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("access_token in {body}"))
        .to_string();
    let agent: Uuid = sqlx::query_scalar("SELECT agent_id FROM oauth_clients WHERE id = $1")
        .bind(row)
        .fetch_one(pool)
        .await
        .expect("the mint linked the client to an agent");
    // CALIBRATION: the defect only exists because these differ. If a future
    // mint made the principal equal the client row id, the old gate would
    // pass this test and it would prove nothing.
    assert_ne!(
        agent, row,
        "CALIBRATION: the token's principal is an agents.id distinct from its oauth_clients.id"
    );
    (row, token, agent)
}

/// The three edits the gate guards, each with the status it answered.
async fn edit_all(app: &axum::Router, token: &str, claim: Uuid) -> Vec<(&'static str, u16, Value)> {
    let mut out = Vec::new();
    let (s, b) = call(
        app,
        Method::PUT,
        &format!("/api/v1/claims/{claim}"),
        Some(token),
        &json!({"truth_value": 0.7}),
    )
    .await;
    out.push(("PUT /claims/:id", s.as_u16(), b));
    let (s, b) = call(
        app,
        Method::PATCH,
        &format!("/api/v1/claims/{claim}"),
        Some(token),
        &json!({"properties": {"a2d3e945": true}}),
    )
    .await;
    out.push(("PATCH /claims/:id", s.as_u16(), b));
    let (s, b) = call(
        app,
        Method::PATCH,
        &format!("/api/v1/claims/{claim}/labels"),
        Some(token),
        &json!({"add": ["a2d3e945-own"]}),
    )
    .await;
    out.push(("PATCH /claims/:id/labels", s.as_u16(), b));
    out
}

/// A real OAuth agent token writes a claim over REST, then edits it through
/// each gated route: all three are admitted, and the edits land.
#[sqlx::test(migrations = "../../migrations")]
async fn a_real_oauth_token_edits_the_claim_it_authored(pool: PgPool) {
    let app = epigraph_api::build_app_for_tests(&url_for(&pool).await)
        .await
        .expect("app");
    let (_, token, agent) = real_service_token(&pool, &app).await;

    // Authored the way a real author's claim is: by this token, over REST.
    let (status, body) = call(
        &app,
        Method::POST,
        "/api/v1/claims",
        Some(&token),
        &json!({
            "content": format!("a2d3e945: an author edits its own claim {}", Uuid::new_v4()),
            "agent_id": agent,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create: {body}");
    let claim: Uuid = body["id"].as_str().expect("id").parse().expect("uuid");
    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("claim row");
    assert_eq!(
        author, agent,
        "CALIBRATION: the claim is authored by the token's principal"
    );

    for (route, status, body) in edit_all(&app, &token, claim).await {
        assert_eq!(
            status, 200,
            "{route}: the author edits its own claim: {body}"
        );
    }
    let (truth, flagged, labelled): (f64, bool, bool) = sqlx::query_as(
        "SELECT truth_value, \
                COALESCE((properties->>'a2d3e945')::boolean, false), \
                'a2d3e945-own' = ANY(labels) \
           FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("claim after edits");
    assert!((truth - 0.7).abs() < 1e-9, "PUT landed: truth {truth}");
    assert!(flagged, "PATCH landed its property");
    assert!(labelled, "PATCH /labels landed its label");
}

/// A claim whose author id is the token's `oauth_clients.id` is not the
/// token's claim: each gated route refuses it 403 and changes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn an_author_id_equal_to_the_oauth_client_id_owns_nothing(pool: PgPool) {
    let app = epigraph_api::build_app_for_tests(&url_for(&pool).await)
        .await
        .expect("app");
    let (client_row, token, _) = real_service_token(&pool, &app).await;

    // An `agents` row carrying the client row's id, and a public claim it
    // authored (readable by every caller, so the gate, not the read, decides).
    let pk: Vec<u8> = client_row
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(client_row)
    .bind(&pk)
    .execute(&pool)
    .await
    .expect("agent with the client's id");
    let group: Uuid = sqlx::query_scalar("SELECT public.epigraph_ensure_personal_group($1)")
        .bind(client_row)
        .fetch_one(&pool)
        .await
        .expect("its personal group");
    let claim = Uuid::new_v4();
    let hash: Vec<u8> = claim.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             labels, visibility, owner_group_id) \
         VALUES ($1, 'a2d3e945: authored by an id equal to a client row', $2, 0.5, $3, true, \
                 ARRAY[]::text[], 'public', $4)",
    )
    .bind(claim)
    .bind(&hash)
    .bind(client_row)
    .bind(group)
    .execute(&pool)
    .await
    .expect("seed the claim");

    for (route, status, body) in edit_all(&app, &token, claim).await {
        assert_eq!(
            status, 403,
            "{route}: an oauth_clients.id is not an author: {body}"
        );
    }
    let (truth, props, labels): (f64, Value, Vec<String>) = sqlx::query_as(
        "SELECT truth_value, COALESCE(properties, '{}'::jsonb), labels FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(&pool)
    .await
    .expect("claim after refusals");
    assert!((truth - 0.5).abs() < 1e-9, "truth unchanged: {truth}");
    assert!(
        props.get("a2d3e945").is_none(),
        "no property written: {props}"
    );
    assert!(labels.is_empty(), "no label written: {labels:?}");
}

/// The application role, as `claim_routes_bind_the_caller.rs` builds it: row
/// security decides every write.
async fn app_role_state(pool: &PgPool) -> epigraph_api::AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: the arm is vacuous"
    );
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped = epigraph_db::ScopedPool::connect_downgraded_for_tests(
        &url,
        epigraph_db::SessionGucMode::Session,
        "epigraph_app",
    )
    .await
    .expect("app-role ScopedPool");
    let raw = viewer_fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = epigraph_api::AppState::with_db(raw, epigraph_api::ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

fn agent_token(agent: Uuid) -> epigraph_api::middleware::bearer::AuthContext {
    epigraph_api::middleware::bearer::AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: None,
        client_type: epigraph_api::middleware::ClientType::Agent,
        scopes: vec!["claims:read".to_string(), "claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

async fn put_as(
    pool: &PgPool,
    state: &epigraph_api::AppState,
    caller: Uuid,
    claim: Uuid,
    body: Value,
) -> (StatusCode, String) {
    use axum::response::IntoResponse;
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, caller)
        .await
        .expect("viewer");
    let resp = epigraph_api::routes::claims::update_claim(
        epigraph_api::middleware::bearer::ViewerExtractor(viewer),
        axum::extract::State(state.clone()),
        Some(axum::Extension(agent_token(caller))),
        axum::extract::Path(claim),
        axum::Json(serde_json::from_value(body).expect("request")),
    )
    .await
    .into_response();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// On the APPLICATION ROLE (row security live), `PUT /api/v1/claims/:id` by the
/// claim's author lands, and an author whose membership in the owning group was
/// downgraded to `reader` is refused with nothing written: the gate admits by
/// authorship, and the write itself must still be the caller's to make.
#[sqlx::test(migrations = "../../migrations")]
async fn put_by_the_author_lands_on_the_app_role_and_a_reader_author_is_refused(pool: PgPool) {
    let (author, group) = viewer_fixture::seed_agent_with_group(&pool, "a2d3e945-put").await;
    let claim =
        viewer_fixture::seed_group_claim(&pool, author, group, "a2d3e945: PUT on the app role")
            .await;
    let state = app_role_state(&pool).await;
    let read = |claim: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (f64, Value)>(
                "SELECT truth_value, COALESCE(properties, '{}'::jsonb) FROM claims WHERE id = $1",
            )
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("claim")
        }
    };

    let (status, body) = put_as(
        &pool,
        &state,
        author,
        claim,
        json!({"truth_value": 0.8, "properties": {"a2d3e945": "put"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the author's PUT: {body}");
    let (truth, props) = read(claim).await;
    assert!((truth - 0.8).abs() < 1e-9, "truth landed: {truth}");
    assert_eq!(
        props["a2d3e945"],
        json!("put"),
        "properties landed: {props}"
    );

    sqlx::query(
        "UPDATE group_memberships SET role = 'reader' WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(group)
    .bind(author)
    .execute(&pool)
    .await
    .expect("downgrade the author");
    let (status, body) = put_as(
        &pool,
        &state,
        author,
        claim,
        json!({"truth_value": 0.2, "properties": {"a2d3e945": "reader"}}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a reader author's PUT: {body}"
    );
    let (truth, props) = read(claim).await;
    assert!((truth - 0.8).abs() < 1e-9, "truth unchanged: {truth}");
    assert_eq!(
        props["a2d3e945"],
        json!("put"),
        "properties unchanged: {props}"
    );
}

/// The claim's vector as text, `None` when it holds none.
async fn vector_of(pool: &PgPool, claim: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT embedding::text FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the claim's vector")
}

/// A 1536-dimension vector whose every component is `x`.
fn vector(x: f32) -> Value {
    json!(vec![x; 1536])
}

/// On the APPLICATION ROLE, a `PUT /api/v1/claims/:id` carrying an embedding
/// that the store refuses is not answered 200. The store filters to current,
/// unsealed rows the caller may write, so each refusal matches zero rows and
/// raises nothing; the handler must name it: 409 for a superseded or a sealed
/// claim, 403 for an author downgraded to `reader`. Each time nothing is
/// written, including a truth value sent in the same request.
///
/// # Verified to fail
///
/// With the handler discarding the store's `bool` (the review finding this
/// pins), the first refusal, the superseded claim's, answers 200 having
/// committed its truth value without the vector (measured by mutation).
#[sqlx::test(migrations = "../../migrations")]
async fn a_put_embedding_the_store_refuses_is_not_answered_200(pool: PgPool) {
    let (author, group) = viewer_fixture::seed_agent_with_group(&pool, "a2d3e945-emb").await;
    let claim =
        viewer_fixture::seed_group_claim(&pool, author, group, "a2d3e945: PUT embedding").await;
    let state = app_role_state(&pool).await;
    let truth = |claim: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, f64>("SELECT truth_value FROM claims WHERE id = $1")
                .bind(claim)
                .fetch_one(&pool)
                .await
                .expect("truth")
        }
    };

    // CALIBRATION: the author's embedding lands, so the refusals below are the
    // store's filters, not a route that never stores anything.
    let (status, body) = put_as(
        &pool,
        &state,
        author,
        claim,
        json!({"embedding": vector(0.25)}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the author's embedding PUT: {body}");
    let stored = vector_of(&pool, claim).await;
    assert!(stored.is_some(), "CALIBRATION: the author's vector landed");

    // Superseded: the store's `is_current` filter (a fresh, unembedded claim:
    // `chk_deprecated_no_embedding` forbids a vector on a non-current row, so
    // the old store answered this with a constraint error, not a silent 200).
    let superseded =
        viewer_fixture::seed_group_claim(&pool, author, group, "a2d3e945: superseded PUT").await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(superseded)
        .execute(&pool)
        .await
        .expect("supersede");
    let (status, body) = put_as(
        &pool,
        &state,
        author,
        superseded,
        json!({"truth_value": 0.9, "embedding": vector(0.5)}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a superseded claim's embedding: {body}"
    );
    assert!(
        body.contains("superseded"),
        "the answer names the cause: {body}"
    );
    assert_eq!(
        vector_of(&pool, superseded).await,
        None,
        "no vector written"
    );
    assert!(
        (truth(superseded).await - 0.8).abs() < 1e-9,
        "truth not written either"
    );

    // A reader author: the store's write filter.
    sqlx::query(
        "UPDATE group_memberships SET role = 'reader' WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(group)
    .bind(author)
    .execute(&pool)
    .await
    .expect("downgrade the author");
    let (status, body) = put_as(
        &pool,
        &state,
        author,
        claim,
        json!({"embedding": vector(0.75)}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a reader author's embedding: {body}"
    );
    assert_eq!(vector_of(&pool, claim).await, stored, "vector unchanged");
    sqlx::query(
        "UPDATE group_memberships SET role = 'admin' WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(group)
    .bind(author)
    .execute(&pool)
    .await
    .expect("restore the author");

    // Sealed: the store's `claim_encryption` filter (a fresh, unembedded claim).
    let sealed =
        viewer_fixture::seed_group_claim(&pool, author, group, "a2d3e945: sealed PUT embedding")
            .await;
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(group)
    .execute(&pool)
    .await
    .expect("seed the group key epoch the FK requires");
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                       encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', decode('0badc0de', 'hex'))",
    )
    .bind(sealed)
    .bind(group)
    .execute(&pool)
    .await
    .expect("seal the claim");
    let (status, body) = put_as(
        &pool,
        &state,
        author,
        sealed,
        json!({"embedding": vector(0.5)}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a sealed claim's embedding: {body}"
    );
    assert!(
        body.contains("sealed"),
        "the answer names the cause: {body}"
    );
    assert_eq!(
        vector_of(&pool, sealed).await,
        None,
        "no vector on a sealed claim"
    );
}
