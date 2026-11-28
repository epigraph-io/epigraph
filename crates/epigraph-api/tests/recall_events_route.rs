#![cfg(feature = "db")]
//! `GET /api/v1/recall-events` (backlog 2cf7b6a1): the caller's own recall
//! history, and nobody else's.
//!
//! Every request goes through the full router (`create_router`) with a real
//! bearer, so the route registration, the bearer middleware, the scope check
//! and the viewer extractor are all on the path. Both pools of the `AppState`
//! are the APPLICATION ROLE, as in production: on the superuser pool
//! `#[sqlx::test]` hands out, row security never refuses anything, and "B does
//! not see A's rows" would rest on the repo filter alone (the repo test
//! `recall_event_test.rs::list_own_never_returns_another_agents_rows` pins
//! that half on its own).
//!
//! Every refusal is paired with a positive control in the same test: before
//! the route exists the router answers 404 to everything, and a leak test
//! without its control would pass on a tree with no route at all.

#[allow(dead_code)]
mod common;
mod viewer_fixture;

#[path = "../../epigraph-passkey/tests/support/soft_authenticator.rs"]
mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use chrono::Duration;
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_auth::{AccessTokenBinding, JwtConfig};
use epigraph_db::{
    NewRecallEvent, RecallEventRepository, ScopedPool, ScopedPoolOptions, SessionGucMode,
};
use epigraph_passkey::{AttestationPolicy, PasskeyConfig, Passkeys};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use support::{ClientUv, SoftAuthenticator, ORIGIN, RP_ID};
use tokio::sync::oneshot;
use tower::ServiceExt;
use uuid::Uuid;

/// An `AppState` whose scoped and raw pools are both the application role.
async fn app_role_state(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
        .fetch_one(scoped.inner())
        .await
        .expect("epigraph_bypass on the scoped pool");
    assert!(
        !bypass,
        "CALIBRATION: the scoped pool must not be privileged, or row security admits every row"
    );
    let raw = viewer_fixture::downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

/// Log one recall for `agent`, owned by its personal group, as production
/// writes it. Written on the harness (superuser) pool.
async fn log(pool: &PgPool, agent: Uuid, query: &str, ids: Vec<Uuid>) -> Uuid {
    let group = epigraph_db::ClaimRepository::personal_group_of_pool(pool, agent)
        .await
        .expect("resolve the author's personal group");
    RecallEventRepository::log(
        pool,
        NewRecallEvent {
            id: Uuid::new_v4(),
            agent_id: Some(agent),
            tool: "recall".to_string(),
            query_text: query.to_string(),
            query_pgvector: Some("[0.25,0.5]".to_string()),
            params: serde_json::json!({"limit": 10}),
            returned_claim_ids: ids,
            owner_group_id: Some(group),
        },
    )
    .await
    .expect("log a recall")
}

/// `GET uri` through the full router, with `token` as the bearer when given:
/// the status, the response headers and the body.
async fn get_full(
    state: &AppState,
    token: Option<&str>,
    uri: &str,
) -> (StatusCode, HeaderMap, Value) {
    let mut req = Request::builder().method(Method::GET).uri(uri);
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let resp = create_router(state.clone())
        .oneshot(req.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, headers, body)
}

/// `GET uri` through the full router, with `token` as the bearer when given.
async fn get_with(state: &AppState, token: Option<&str>, uri: &str) -> (StatusCode, Value) {
    let (status, _, body) = get_full(state, token, uri).await;
    (status, body)
}

async fn get_as(state: &AppState, caller: Uuid, uri: &str) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(&["claims:read"], caller);
    get_with(state, Some(&token), uri).await
}

fn ids_of(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap_or_else(|| panic!("no items in {page}"))
        .iter()
        .map(|i| i["id"].as_str().expect("item id").to_string())
        .collect()
}

/// Agent B's token never reads agent A's rows, whatever it asks for; A's own
/// read (the positive control) does see them, with the MCP tool's fields.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_never_reads_another_agents_recall_history(pool: PgPool) {
    let (a, _) = viewer_fixture::seed_agent_with_group(&pool, "recall-route-a").await;
    let (b, _) = viewer_fixture::seed_agent_with_group(&pool, "recall-route-b").await;
    let shared = Uuid::new_v4();
    let a_row = log(&pool, a, "A's secret query", vec![shared]).await;
    let b_row = log(&pool, b, "B's own query", vec![shared]).await;
    let state = app_role_state(&pool).await;

    // Positive control: A reads its own row, with every MCP field.
    let (status, page) = get_as(&state, a, "/api/v1/recall-events").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(ids_of(&page), vec![a_row.to_string()]);
    let item = &page["items"][0];
    assert_eq!(item["agent_id"], a.to_string());
    assert_eq!(item["tool"], "recall");
    assert_eq!(item["query_text"], "A's secret query");
    assert_eq!(item["returned_claim_ids"][0], shared.to_string());
    assert_eq!(item["params"]["limit"], 10);
    assert_eq!(
        item["query_embedding_hash"].as_str().map(str::len),
        Some(64),
        "hex BLAKE3 of the query vector: {item}"
    );
    assert!(item["created_at"].as_str().is_some());
    assert!(page["next_cursor"].is_null());

    // B, with every crafted parameter that could aim at A's row.
    let a_micros: i64 = sqlx::query_scalar(
        "SELECT (extract(epoch FROM created_at) * 1000000)::bigint FROM recall_events \
         WHERE id = $1",
    )
    .bind(a_row)
    .fetch_one(&pool)
    .await
    .unwrap();
    let crafted = [
        "/api/v1/recall-events".to_string(),
        format!("/api/v1/recall-events?claim_id={shared}"),
        "/api/v1/recall-events?since=2000-01-01T00:00:00Z&until=2999-01-01T00:00:00Z".to_string(),
        format!(
            "/api/v1/recall-events?after=k1.{}.{}",
            a_micros + 1_000_000,
            Uuid::max().simple()
        ),
        format!("/api/v1/recall-events?limit=200&agent_id={b}"),
        format!("/api/v1/recall-events?owner={a}&agent={a}&principal={a}"),
    ];
    for uri in &crafted {
        let (status, page) = get_as(&state, b, uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {page}");
        assert_eq!(
            ids_of(&page),
            vec![b_row.to_string()],
            "{uri}: B reads exactly its own row"
        );
        assert!(
            !page.to_string().contains("A's secret query"),
            "{uri}: A's query text leaked"
        );
    }

    // Naming A outright is refused, not silently answered with B's rows.
    let (status, body) = get_as(&state, b, &format!("/api/v1/recall-events?agent_id={a}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(!body.to_string().contains("A's secret query"));
}

/// No bearer is a 401; a bearer without `claims:read` is a 403. The positive
/// control is the same caller with the scope.
#[sqlx::test(migrations = "../../migrations")]
async fn the_route_requires_a_bearer_with_claims_read(pool: PgPool) {
    let (a, _) = viewer_fixture::seed_agent_with_group(&pool, "recall-route-auth").await;
    let row = log(&pool, a, "a query", vec![]).await;
    let state = app_role_state(&pool).await;

    let (status, body) = get_with(&state, None, "/api/v1/recall-events").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(!body.to_string().contains("a query"));

    let unscoped = common::mint_token_with_agent(&["edges:write"], a);
    let (status, body) = get_with(&state, Some(&unscoped), "/api/v1/recall-events").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, page) = get_as(&state, a, "/api/v1/recall-events").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(ids_of(&page), vec![row.to_string()]);
}

/// Pages: newest first, `limit` rows each, `next_cursor` passed back as
/// `after` until it is `null`, every row exactly once.
#[sqlx::test(migrations = "../../migrations")]
async fn pages_walk_the_history_newest_first_and_end_with_a_null_cursor(pool: PgPool) {
    let (a, _) = viewer_fixture::seed_agent_with_group(&pool, "recall-route-pages").await;
    let mut logged = Vec::new();
    for i in 0..5 {
        let id = log(&pool, a, &format!("query {i}"), vec![]).await;
        // Distinct, increasing times, so "newest first" is a checkable order.
        sqlx::query(
            "UPDATE recall_events SET created_at = now() - make_interval(mins => $2) \
             WHERE id = $1",
        )
        .bind(id)
        .bind(10 - i)
        .execute(&pool)
        .await
        .unwrap();
        logged.push(id.to_string());
    }
    logged.reverse();
    let state = app_role_state(&pool).await;

    let mut seen = Vec::new();
    let mut uri = "/api/v1/recall-events?limit=2".to_string();
    let mut pages = 0;
    loop {
        let (status, page) = get_as(&state, a, &uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {page}");
        pages += 1;
        let ids = ids_of(&page);
        assert!(ids.len() <= 2, "{uri}: {ids:?}");
        seen.extend(ids);
        match page["next_cursor"].as_str() {
            Some(c) => uri = format!("/api/v1/recall-events?limit=2&after={c}"),
            None => break,
        }
        assert!(pages < 10, "the cursor never ended");
    }
    assert_eq!(seen, logged, "every row once, newest first");
    assert_eq!(
        pages, 3,
        "2 + 2 + 1: the last page is short and ends the walk"
    );

    let (status, body) = get_as(&state, a, "/api/v1/recall-events?after=not-a-cursor").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = get_as(&state, a, "/api/v1/recall-events?since=yesterday").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// The answer is one caller's private query texts: like the other routes
/// whose whole response depends on the caller (semantic search, papers, the
/// sources overview), it is `Cache-Control: private, no-store` and
/// `Vary: Authorization`, so no shared cache stores it or serves it to
/// another bearer.
#[sqlx::test(migrations = "../../migrations")]
async fn the_answer_is_private_and_varies_on_the_bearer(pool: PgPool) {
    let (a, _) = viewer_fixture::seed_agent_with_group(&pool, "recall-route-cache").await;
    let row = log(&pool, a, "a private query", vec![]).await;
    let state = app_role_state(&pool).await;
    let token = common::mint_token_with_agent(&["claims:read"], a);

    let (status, headers, page) = get_full(&state, Some(&token), "/api/v1/recall-events").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        ids_of(&page),
        vec![row.to_string()],
        "CONTROL: the route served"
    );
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("private, no-store"),
        "{headers:?}"
    );
    assert_eq!(
        headers.get(header::VARY).and_then(|v| v.to_str().ok()),
        Some("Authorization"),
        "{headers:?}"
    );
}

// ---------------------------------------------------------------------------
// An ELEVATED caller. The token's elevation claim resolves at the per-access
// recorder layer, so the read is recorded as an elevated access; the handler
// still reads on the caller's plain scoped viewer (`UnelevatedViewer`), and
// the repo still filters on the caller's agent id. Migration 126's
// `recall_events_elevated_read` arm admits EVERY row to an elevated session,
// so this is the one caller for whom both layers matter.
// ---------------------------------------------------------------------------

const MODEL: Uuid = Uuid::from_u128(0x6a1e_7e57_0000_4a11_8c0d_0000_0000_0262);

fn software() -> Passkeys {
    Passkeys::new(PasskeyConfig {
        rp_id: RP_ID.into(),
        origin: ORIGIN.parse().expect("origin"),
        policy: AttestationPolicy::SoftwareAllowed,
    })
    .expect("relying party")
}

fn random32() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

/// The REST router on an application-role pool that declares the per-access
/// recorder (an elevated request on any other pool is refused before it is
/// served), with the passkey relying party, on a real listener.
struct Recording {
    addr: SocketAddr,
    jwt: Arc<JwtConfig>,
    http: reqwest::Client,
    _stop: oneshot::Sender<()>,
}

impl Recording {
    async fn start(pool: &PgPool) -> Self {
        let scoped = ScopedPool::connect_with_access_recorder_for_tests(
            &viewer_fixture::database_url_for(pool).await,
            SessionGucMode::Session,
            ScopedPoolOptions::default(),
            Some("epigraph_app"),
        )
        .await
        .expect("app-role recording pool");
        let state = AppState::with_scoped_pool(scoped, ApiConfig::default())
            .with_passkeys(Some(Arc::new(software())));
        let jwt = state.jwt_config.clone();
        let app = create_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .expect("serve");
        });
        Self {
            addr,
            jwt,
            http: reqwest::Client::new(),
            _stop: tx,
        }
    }

    async fn post(&self, path: &str, token: Option<&str>, body: &Value) -> (u16, Value) {
        let mut req = self
            .http
            .post(format!("http://{}{path}", self.addr))
            .json(body);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.expect("POST");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn get(&self, path: &str, token: &str) -> (u16, Value) {
        let resp = self
            .http
            .get(format!("http://{}{path}", self.addr))
            .bearer_auth(token)
            .send()
            .await
            .expect("GET");
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    /// A `claims:read` token for `principal` on `client` and `family`.
    fn plain_token(&self, principal: Uuid, client: Uuid, family: Uuid) -> String {
        self.jwt
            .issue_access_token(
                client,
                vec!["claims:read".to_string()],
                "human",
                None,
                Some(principal),
                Duration::minutes(30),
                AccessTokenBinding {
                    family_id: Some(family),
                    elevation_id: None,
                    delegated_by: None,
                },
            )
            .expect("mint")
            .0
    }
}

/// A platform custodian: a registered human with its human client (holding
/// `claims:read`), a live refresh family, the custodian role and a passkey
/// on `auth`, enrolled through the real enrollment ceremony.
struct Custodian {
    person: Uuid,
    client: Uuid,
    client_id: String,
    family: Uuid,
}

async fn custodian_with_passkey(
    pool: &PgPool,
    s: &Recording,
    auth: &mut SoftAuthenticator,
) -> Custodian {
    let (person, _group) =
        viewer_fixture::seed_human_operator(pool, "recall-route-custodian").await;
    let (client, client_id): (Uuid, String) = sqlx::query_as(
        "SELECT id, client_id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human'",
    )
    .bind(person)
    .fetch_one(pool)
    .await
    .expect("the human's client");
    sqlx::query(
        "UPDATE oauth_clients SET granted_scopes = ARRAY['claims:read'], \
                allowed_scopes = ARRAY['claims:read'] WHERE id = $1",
    )
    .bind(client)
    .execute(pool)
    .await
    .expect("scopes");
    let family: Uuid = sqlx::query_scalar(
        "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
         VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
    )
    .bind(random32().to_vec())
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("a refresh family");
    viewer_fixture::make_custodian(pool, person).await;

    let enrollment = viewer_fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'recall history', 'key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("open the enrollment");
        (conn, id)
    })
    .await;
    let base = format!("/elevate/enroll/{enrollment}");
    let (status, options) = s.post(&format!("{base}/challenge"), None, &json!({})).await;
    assert_eq!(status, 200, "enrollment challenge: {options}");
    let response = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let (status, body) = s.post(&format!("{base}/finish"), None, &response).await;
    assert_eq!(status, 200, "enrollment finish: {body}");
    Custodian {
        person,
        client,
        client_id,
        family,
    }
}

/// Elevate `c` the CLI way (a grant-mode ticket, the passkey ceremony, the
/// elevate grant): `(the elevation session, the elevated token)`.
async fn sudo(
    pool: &PgPool,
    s: &Recording,
    c: &Custodian,
    auth: &mut SoftAuthenticator,
) -> (Uuid, String) {
    let plain = s.plain_token(c.person, c.client, c.family);
    let (status, body) = s
        .post(
            "/api/v1/elevation/tickets",
            Some(&plain),
            &json!({"reason": "review recall history"}),
        )
        .await;
    assert_eq!(status, 201, "ticket: {body}");
    let ticket: Uuid = body["ticket_id"]
        .as_str()
        .expect("id")
        .parse()
        .expect("uuid");
    let secret = body["redeem_secret"].as_str().expect("secret").to_string();
    let (status, options) = s
        .post(&format!("/elevate/{ticket}/challenge"), None, &json!({}))
        .await;
    assert_eq!(status, 200, "challenge: {options}");
    let response = auth.authenticate(ORIGIN, options).await;
    let (status, body) = s
        .post(&format!("/elevate/{ticket}/assert"), None, &response)
        .await;
    assert_eq!(status, 200, "ceremony: {body}");
    assert_eq!(body["outcome"], "confirmed", "{body}");
    let (status, body) = s
        .post(
            "/oauth/token",
            None,
            &json!({"grant_type": "urn:epigraph:grant:elevate", "ticket_id": ticket,
                    "redeem_secret": secret, "client_id": c.client_id}),
        )
        .await;
    assert_eq!(status, 200, "elevate grant: {body}");
    let session: Uuid =
        sqlx::query_scalar("SELECT session_id FROM elevation_tickets WHERE id = $1")
            .bind(ticket)
            .fetch_one(pool)
            .await
            .expect("the session");
    (
        session,
        body["access_token"].as_str().expect("token").to_string(),
    )
}

/// An ELEVATED custodian reads only its OWN recall rows here, whatever it
/// asks for, although its elevated session's row policy (126) would admit
/// another agent's row; and each such read is recorded as an elevated access
/// against the session (the per-access layer resolves the token's elevation
/// whichever viewer the handler reads on).
#[sqlx::test(migrations = "../../migrations")]
async fn an_elevated_caller_still_reads_only_its_own_rows_and_is_recorded(pool: PgPool) {
    let (a, _) = viewer_fixture::seed_agent_with_group(&pool, "recall-route-elev-a").await;
    let s = Recording::start(&pool).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let c = custodian_with_passkey(&pool, &s, &mut auth).await;
    let shared = Uuid::new_v4();
    let a_row = log(&pool, a, "A's secret query", vec![shared]).await;
    let own = log(&pool, c.person, "the custodian's own query", vec![shared]).await;

    // CONTROL: the custodian's ordinary token reads its own row here.
    let plain = s.plain_token(c.person, c.client, c.family);
    let (status, page) = s.get("/api/v1/recall-events", &plain).await;
    assert_eq!(status, 200, "CONTROL: the plain token reads: {page}");
    assert_eq!(ids_of(&page), vec![own.to_string()]);

    let (session, elevated) = sudo(&pool, &s, &c, &mut auth).await;
    let asks = [
        "/api/v1/recall-events".to_string(),
        format!("/api/v1/recall-events?claim_id={shared}"),
        "/api/v1/recall-events?limit=200&since=2000-01-01T00:00:00Z&until=2999-01-01T00:00:00Z"
            .to_string(),
    ];
    for uri in &asks {
        let (status, page) = s.get(uri, &elevated).await;
        assert_eq!(status, 200, "{uri}: elevated, the custodian reads: {page}");
        assert_eq!(
            ids_of(&page),
            vec![own.to_string()],
            "{uri}: elevated, still exactly the caller's own row"
        );
        let text = page.to_string();
        assert!(
            !text.contains("A's secret query") && !text.contains(&a_row.to_string()),
            "{uri}: A's row leaked to an elevated caller: {page}"
        );
    }

    let surfaces: Vec<String> =
        sqlx::query_scalar("SELECT surface FROM elevated_access WHERE elevation_id = $1")
            .bind(session)
            .fetch_all(&pool)
            .await
            .expect("the access log");
    assert_eq!(
        surfaces,
        vec!["GET /api/v1/recall-events".to_string(); asks.len()],
        "each elevated read is recorded against the session"
    );
}
