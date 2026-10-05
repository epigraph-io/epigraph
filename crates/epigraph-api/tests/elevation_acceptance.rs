#![cfg(feature = "db")]
//! THE ELEVATION ACCEPTANCE SLICE (elevation plan EL-14; DESIGN §10 check 7,
//! the subset this stack builds). One world, driven end to end:
//!
//! * the REAL REST router and the REAL MCP streamable-HTTP transport, each on
//!   an APPLICATION-ROLE pool that declares the per-access recorder (the
//!   recording builds' shape), over a database migrated to HEAD: migration
//!   132 opens the recorder gate, so no test here opens it by hand;
//! * passkeys registered through the real enrollment ceremony and elevations
//!   confirmed through the real ticket ceremony by an INDEPENDENT test
//!   authenticator (`epigraph-passkey/tests/support/soft_authenticator.rs`),
//!   and the elevated token redeemed at `/oauth/token` (the CLI elevate path,
//!   the one served while connector mode is off by default);
//! * every authority probe on the database runs as `epigraph_app`.
//!
//! THE WORLD. P is a platform custodian (a registered human holding an
//! elevating role) with a passkey. C is an ordinary registered human: what C
//! reads is the baseline "P equals C" compares against. B is another person
//! whose private group holds the CANARIES (a claim, its evidence, an edge
//! between two of B's claims); one public claim is the calibration that the
//! read paths serve at all.
//!
//! ONE STATED GAP, PINNED HERE: the MCP read tools read on the server's
//! UNSTAMPED pool, so an elevated MCP request is NOT widened by the elevated
//! read arms (it is recorded, attributed to B when the answer names B's
//! row). "P after sudo reads B's canaries through MCP" therefore does not
//! hold yet; `p_after_sudo_reads_bs_canaries_and_b_reads_every_access`
//! asserts what does (REST widened, MCP recorded and not widened) so the day
//! the MCP reads are stamped this test is the one to flip.
//!
//! Each test names the planted regression or mutation it was run against.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-passkey/tests/support/soft_authenticator.rs"]
mod support;

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use chrono::Duration;
use epigraph_auth::{AccessTokenBinding, JwtConfig};
use epigraph_db::{ScopedPool, ScopedPoolOptions, SessionGucMode, Viewer};
use epigraph_passkey::{AttestationPolicy, PasskeyConfig, Passkeys};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use support::{ClientUv, SoftAuthenticator, ORIGIN, RP_ID};
use tokio::sync::oneshot;
use uuid::Uuid;

/// The authenticator model the test authenticators claim.
const MODEL: Uuid = Uuid::from_u128(0x7a11_c0de_5eed_4a11_8c0d_e5ee_d4a1_1c0d);

/// The read scopes every person's human client holds here.
const READ: &[&str] = &["claims:read", "edges:read", "evidence:read"];

/// A search term only the canaries carry.
const TERM: &str = "quillovant";

fn software() -> Passkeys {
    Passkeys::new(PasskeyConfig {
        rp_id: RP_ID.into(),
        origin: ORIGIN.parse().unwrap(),
        policy: AttestationPolicy::SoftwareAllowed,
    })
    .expect("relying party")
}

// =====================================================================
// The two transports
// =====================================================================

/// The REST router and the MCP transport, sharing one token secret.
struct Server {
    addr: SocketAddr,
    mcp: String,
    jwt: Arc<JwtConfig>,
    http: reqwest::Client,
    _stop: oneshot::Sender<()>,
}

/// The application-role pool a recording build serves on (it declares the
/// per-access recorder; the harness cannot use the production constructor,
/// which takes no role to downgrade to).
async fn recording_pool(pool: &PgPool, max_connections: u32) -> ScopedPool {
    ScopedPool::connect_with_access_recorder_for_tests(
        &fixture::database_url_for(pool).await,
        SessionGucMode::Session,
        ScopedPoolOptions {
            max_connections,
            ..ScopedPoolOptions::default()
        },
        Some("epigraph_app"),
    )
    .await
    .expect("app-role recording pool")
}

async fn spawn(pool: &PgPool) -> Server {
    spawn_with(pool, ScopedPoolOptions::default().max_connections).await
}

/// Both transports; the REST router's pool holds at most `max_connections`.
async fn spawn_with(pool: &PgPool, max_connections: u32) -> Server {
    let scoped = recording_pool(pool, max_connections).await;
    let state =
        epigraph_api::AppState::with_scoped_pool(scoped, epigraph_api::ApiConfig::default())
            .with_passkeys(Some(Arc::new(software())));
    let jwt = state.jwt_config.clone();
    let app = epigraph_api::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    let mcp = mcp_listener(pool, jwt.clone()).await;
    Server {
        addr,
        mcp,
        jwt,
        http: reqwest::Client::new(),
        _stop: tx,
    }
}

/// The router `epigraph-mcp --listen` builds: the streamable-HTTP service
/// behind the bearer middleware, its ScopedPool the recording application
/// pool, its tools' own pool the application role (unstamped, as in
/// production), connector mode OFF (the default), the ceremony page named
/// under the relying party's origin.
async fn mcp_listener(pool: &PgPool, jwt: Arc<JwtConfig>) -> String {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    let scoped = recording_pool(pool, 4).await;
    let tools_pool = fixture::downgraded_pool(pool, "epigraph_app").await;
    let signer = Arc::new(epigraph_crypto::AgentSigner::from_bytes(&[0x5c; 32]).expect("signer"));
    let embedder = Arc::new(
        epigraph_mcp::embed::McpEmbedder::new(tools_pool.clone(), None)
            .with_scoped_pool(scoped.clone()),
    );
    let service = StreamableHttpService::new(
        move || {
            Ok(epigraph_mcp::server::EpiGraphMcpFull::new_shared(
                tools_pool.clone(),
                signer.clone(),
                embedder.clone(),
                false,
            )
            .with_scoped_pool(scoped.clone())
            .with_admin_scope_arming_ttl(std::time::Duration::ZERO)
            .with_public_base_url(Some(ORIGIN.to_string())))
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let state = epigraph_mcp::auth::McpAuthState {
        jwt_config: jwt,
        resource_metadata_url: None,
    };
    let router = axum08::Router::new().nest_service("/mcp", service).layer(
        axum08::middleware::from_fn_with_state(state, epigraph_mcp::auth::bearer_auth_middleware),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum08::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}/mcp")
}

impl Server {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    async fn post(&self, path: &str, token: Option<&str>, body: &Value) -> (StatusCode, Value) {
        let mut req = self.http.post(self.url(path)).json(body);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        let resp = self
            .http
            .get(self.url(path))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    /// A human token for `p` on its family, with `scopes`, naming `elv`.
    fn token(&self, p: &Person, elv: Option<Uuid>, scopes: &[&str]) -> String {
        self.jwt
            .issue_access_token(
                p.client,
                scopes.iter().map(|s| (*s).to_string()).collect(),
                "human",
                None,
                Some(p.person),
                Duration::minutes(30),
                AccessTokenBinding {
                    family_id: Some(p.family),
                    elevation_id: elv,
                },
            )
            .expect("mint")
            .0
    }

    /// `p`'s ordinary token (no elevation claim).
    fn plain(&self, p: &Person) -> String {
        self.token(p, None, READ)
    }

    // ---- MCP over HTTP (JSON-RPC, SSE answers) -------------------------

    async fn mcp_post(&self, token: &str, session: Option<&str>, body: Value) -> reqwest::Response {
        let mut req = self
            .http
            .post(&self.mcp)
            .bearer_auth(token)
            .header("Accept", "application/json, text/event-stream")
            .json(&body);
        if let Some(s) = session {
            req = req.header("Mcp-Session-Id", s);
        }
        req.send().await.expect("POST /mcp")
    }

    /// One JSON-RPC `method(params)` on a fresh MCP session for `token`.
    async fn rpc(&self, token: &str, method: &str, params: Value) -> Value {
        let init = self
            .mcp_post(
                token,
                None,
                json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                  "clientInfo": {"name": "el14-acceptance", "version": "0"}}}),
            )
            .await;
        assert_eq!(init.status().as_u16(), 200, "MCP initialize");
        let session = init
            .headers()
            .get("Mcp-Session-Id")
            .expect("session header")
            .to_str()
            .expect("ascii")
            .to_owned();
        let _ = sse_data(init).await;
        let notified = self
            .mcp_post(
                token,
                Some(&session),
                json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            )
            .await;
        assert_eq!(notified.status().as_u16(), 202, "notifications/initialized");
        let resp = self
            .mcp_post(
                token,
                Some(&session),
                json!({"jsonrpc": "2.0", "id": 2, "method": method, "params": params}),
            )
            .await;
        sse_data(resp).await
    }

    async fn call(&self, token: &str, tool: &str, arguments: Value) -> Value {
        self.rpc(
            token,
            "tools/call",
            json!({"name": tool, "arguments": arguments}),
        )
        .await
    }

    async fn tools(&self, token: &str) -> Vec<String> {
        let answer = self.rpc(token, "tools/list", json!({})).await;
        answer["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("a tool list: {answer}"))
            .iter()
            .map(|t| t["name"].as_str().expect("name").to_string())
            .collect()
    }
}

/// The first COMPLETE SSE `data:` line of `resp` (a long answer spans several
/// chunks), parsed.
async fn sse_data(mut resp: reqwest::Response) -> Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut acc: Vec<u8> = Vec::new();
    while let Ok(Ok(Some(bytes))) = tokio::time::timeout_at(deadline, resp.chunk()).await {
        acc.extend_from_slice(&bytes);
        let text = String::from_utf8_lossy(&acc);
        if let Some(line) = text
            .split_inclusive('\n')
            .filter(|l| l.ends_with('\n'))
            .find(|l| l.starts_with("data:") && l.trim_end().len() > 5)
        {
            return serde_json::from_str(line.trim_start_matches("data:").trim())
                .unwrap_or_else(|e| panic!("SSE data is JSON ({e}): {line}"));
        }
    }
    panic!("no complete SSE data: {}", String::from_utf8_lossy(&acc));
}

/// Whether a tool answer served a result (not a JSON-RPC error, not
/// `isError`).
fn served(answer: &Value) -> bool {
    answer.get("result").is_some() && answer["result"]["isError"].as_bool() != Some(true)
}

fn refused_as_elevated(body: &Value) -> bool {
    body.to_string().contains("ELEVATED READ-ONLY")
}

// =====================================================================
// The world
// =====================================================================

/// A registered human: its human client and a live refresh family.
#[derive(Clone, Debug)]
struct Person {
    person: Uuid,
    group: Uuid,
    client: Uuid,
    client_id: String,
    family: Uuid,
}

async fn person(pool: &PgPool, label: &str) -> Person {
    let (person, group) = fixture::seed_human_operator(pool, label).await;
    let (client, client_id): (Uuid, String) = sqlx::query_as(
        "SELECT id, client_id FROM oauth_clients WHERE agent_id = $1 AND client_type = 'human'",
    )
    .bind(person)
    .fetch_one(pool)
    .await
    .expect("the human's client");
    grant_scopes(pool, client, READ).await;
    let family = family(pool, client).await;
    Person {
        person,
        group,
        client,
        client_id,
        family,
    }
}

/// Give a client these allowed and granted scopes.
async fn grant_scopes(pool: &PgPool, client: Uuid, scopes: &[&str]) {
    sqlx::query("UPDATE oauth_clients SET granted_scopes = $2, allowed_scopes = $2 WHERE id = $1")
        .bind(client)
        .bind(scopes.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
        .execute(pool)
        .await
        .expect("granted scopes");
}

/// A live refresh token of `client`, which is its own family.
async fn family(pool: &PgPool, client: Uuid) -> Uuid {
    let hash: Vec<u8> = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    sqlx::query_scalar(
        "INSERT INTO refresh_tokens (token_hash, client_id, scopes, expires_at) \
         VALUES ($1, $2, ARRAY['claims:read'], now() + interval '1 day') RETURNING id",
    )
    .bind(&hash)
    .bind(client)
    .fetch_one(pool)
    .await
    .expect("a refresh token")
}

/// Register a passkey for `person` as production does: the enrollment opened
/// on a maintenance session (`epigraph-operator passkey-enroll`), the page's
/// challenge and finish over HTTP by `auth`.
async fn enroll(pool: &PgPool, s: &Server, person: Uuid, auth: &mut SoftAuthenticator) {
    let id = fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_create_passkey_enrollment($1, 'acceptance', 'key')",
        )
        .bind(person)
        .fetch_one(&mut *conn)
        .await
        .expect("open the enrollment");
        (conn, id)
    })
    .await;
    let base = format!("/elevate/enroll/{id}");
    let (status, options) = s.post(&format!("{base}/challenge"), None, &json!({})).await;
    assert_eq!(status, StatusCode::OK, "enrollment challenge: {options}");
    let response = auth.register(ORIGIN, options, ClientUv::AsRequested).await;
    let (status, body) = s.post(&format!("{base}/finish"), None, &response).await;
    assert_eq!(status, StatusCode::OK, "enrollment finish: {body}");
}

/// A platform custodian with one passkey on `auth`.
async fn custodian(pool: &PgPool, s: &Server, label: &str, auth: &mut SoftAuthenticator) -> Person {
    let p = person(pool, label).await;
    fixture::make_custodian(pool, p.person).await;
    enroll(pool, s, p.person, auth).await;
    p
}

/// B's canaries and one public calibration row.
struct Canaries {
    b: Person,
    claim: Uuid,
    evidence: Uuid,
    edge: Uuid,
    public: Uuid,
}

async fn canaries(pool: &PgPool) -> Canaries {
    let b = person(pool, "B").await;
    let claim =
        fixture::seed_group_claim(pool, b.person, b.group, &format!("{TERM} B canary")).await;
    let other =
        fixture::seed_group_claim(pool, b.person, b.group, &format!("{TERM} B second")).await;
    let evidence = fixture::seed_evidence(pool, claim, "observation").await;
    let edge = fixture::seed_edge(pool, claim, other).await;
    let public = fixture::seed_public_claim(pool, b.person, &format!("{TERM} public row")).await;
    Canaries {
        b,
        claim,
        evidence,
        edge,
        public,
    }
}

fn ids(v: &Value) -> Vec<String> {
    v.get("items")
        .and_then(Value::as_array)
        .or_else(|| v.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|i| i.get("id").and_then(Value::as_str).map(str::to_string))
        .collect()
}

/// What `token` reads of the canaries, read by read: `(read, seen)`. REST: the
/// claim by id, the claim in a search list, its evidence, the edge; the public
/// row by id (calibration). MCP: `get_claim` of the canary and of the public
/// row.
async fn view(s: &Server, w: &Canaries, token: &str) -> Vec<(&'static str, bool)> {
    let mut out = Vec::new();
    let (status, body) = s.get(&format!("/api/v1/claims/{}", w.claim), token).await;
    out.push((
        "rest claim by id",
        status == StatusCode::OK && body["id"] == json!(w.claim.to_string()),
    ));
    let (_, body) = s
        .get(&format!("/claims?search={TERM}&limit=100"), token)
        .await;
    out.push(("rest claim list", ids(&body).contains(&w.claim.to_string())));
    let (_, body) = s
        .get(&format!("/api/v1/claims/{}/evidence", w.claim), token)
        .await;
    out.push((
        "rest claim evidence",
        ids(&body).contains(&w.evidence.to_string()),
    ));
    let (_, body) = s
        .get(&format!("/api/v1/edges?source_id={}", w.claim), token)
        .await;
    out.push(("rest edge list", ids(&body).contains(&w.edge.to_string())));
    let (status, body) = s.get(&format!("/api/v1/claims/{}", w.public), token).await;
    out.push((
        "rest public claim",
        status == StatusCode::OK && body["id"] == json!(w.public.to_string()),
    ));
    let answer = s
        .call(token, "get_claim", json!({"claim_id": w.claim.to_string()}))
        .await;
    out.push((
        "mcp get_claim",
        served(&answer) && answer.to_string().contains("B canary"),
    ));
    let answer = s
        .call(
            token,
            "get_claim",
            json!({"claim_id": w.public.to_string()}),
        )
        .await;
    out.push((
        "mcp public claim",
        served(&answer) && answer.to_string().contains("public row"),
    ));
    out
}

/// The view of someone who reads none of B's private rows.
fn baseline() -> Vec<(&'static str, bool)> {
    vec![
        ("rest claim by id", false),
        ("rest claim list", false),
        ("rest claim evidence", false),
        ("rest edge list", false),
        ("rest public claim", true),
        ("mcp get_claim", false),
        ("mcp public claim", true),
    ]
}

/// A grant-mode ticket for `p` (id, redeem secret) through the API.
async fn open_ticket(s: &Server, p: &Person, reason: &str) -> (Uuid, String) {
    let (status, body) = s
        .post(
            "/api/v1/elevation/tickets",
            Some(&s.plain(p)),
            &json!({ "reason": reason }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "ticket: {body}");
    (
        body["ticket_id"].as_str().unwrap().parse().unwrap(),
        body["redeem_secret"].as_str().unwrap().to_string(),
    )
}

/// The ticket ceremony by `auth` over a fresh challenge.
async fn ceremony(s: &Server, ticket: Uuid, auth: &mut SoftAuthenticator) -> (StatusCode, Value) {
    let (status, options) = s
        .post(&format!("/elevate/{ticket}/challenge"), None, &json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "challenge: {options}");
    let response = auth.authenticate(ORIGIN, options).await;
    s.post(&format!("/elevate/{ticket}/assert"), None, &response)
        .await
}

/// SUDO, the CLI way: a grant-mode ticket, the passkey ceremony, and the
/// elevate grant at `/oauth/token`. `(session, the elevated token)`.
async fn sudo(
    pool: &PgPool,
    s: &Server,
    p: &Person,
    auth: &mut SoftAuthenticator,
) -> (Uuid, String) {
    let (ticket, secret) = open_ticket(s, p, "acceptance: read B's rows").await;
    let (status, body) = ceremony(s, ticket, auth).await;
    assert_eq!(status, StatusCode::OK, "ceremony: {body}");
    assert_eq!(body["outcome"], "confirmed", "{body}");
    let (status, body) = s
        .post(
            "/oauth/token",
            None,
            &json!({"grant_type": "urn:epigraph:grant:elevate", "ticket_id": ticket,
                    "redeem_secret": secret, "client_id": p.client_id}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "elevate grant: {body}");
    let session: Uuid =
        sqlx::query_scalar("SELECT session_id FROM elevation_tickets WHERE id = $1")
            .bind(ticket)
            .fetch_one(pool)
            .await
            .expect("the session");
    (session, body["access_token"].as_str().unwrap().to_string())
}

/// Run `f` as `epigraph_app` stamped with `principal`, the elevation pair and
/// the recorder declaration (each as given), then clear every setting.
async fn as_app<F, Fut, T>(
    pool: &PgPool,
    principal: Uuid,
    elevation: Option<(Uuid, Uuid)>,
    recorder: bool,
    f: F,
) -> T
where
    F: FnOnce(sqlx::pool::PoolConnection<sqlx::Postgres>) -> Fut,
    Fut: std::future::Future<Output = (sqlx::pool::PoolConnection<sqlx::Postgres>, T)>,
{
    let (elv, fam) = elevation
        .map(|(e, f)| (e.to_string(), f.to_string()))
        .unwrap_or_default();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.elevation_id', $2, false), \
                    set_config('epigraph.family_id', $3, false), \
                    set_config('epigraph.access_recorder', $4, false)",
        )
        .bind(principal.to_string())
        .bind(&elv)
        .bind(&fam)
        .bind(if recorder { "on" } else { "" })
        .execute(&mut *conn)
        .await
        .expect("stamp");
        let role: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(&mut *conn)
            .await
            .expect("current_user");
        assert_eq!(role, "epigraph_app", "CALIBRATION: the application role");
        let (mut conn, out) = f(conn).await;
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.elevation_id', '', false), \
                    set_config('epigraph.family_id', '', false), \
                    set_config('epigraph.access_recorder', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, out)
    })
    .await
}

/// `(is_elevated(), how many of B's canary claims it reads)` on an
/// application connection stamped as given.
async fn probe(
    pool: &PgPool,
    principal: Uuid,
    elevation: Option<(Uuid, Uuid)>,
    recorder: bool,
    claim: Uuid,
) -> (bool, i64) {
    as_app(
        pool,
        principal,
        elevation,
        recorder,
        |mut conn| async move {
            let e: bool = sqlx::query_scalar("SELECT public.epigraph_is_elevated()")
                .fetch_one(&mut *conn)
                .await
                .expect("is_elevated");
            let n: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
                .bind(claim)
                .fetch_one(&mut *conn)
                .await
                .expect("read the canary");
            (conn, (e, n))
        },
    )
    .await
}

/// `(surface, owner_group_ids)` of every access recorded for `session`.
async fn accesses(pool: &PgPool, session: Uuid) -> Vec<(String, Vec<Uuid>)> {
    sqlx::query_as(
        "SELECT surface, owner_group_ids FROM elevated_access WHERE elevation_id = $1 \
          ORDER BY created_at, id",
    )
    .bind(session)
    .fetch_all(pool)
    .await
    .expect("the log")
}

/// How many of `session`'s access rows `who` reads through the log's row
/// policy, as `epigraph_app`.
async fn accesses_seen_by(pool: &PgPool, who: Uuid, session: Uuid) -> i64 {
    as_app(pool, who, None, false, |mut conn| async move {
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM elevated_access WHERE elevation_id = $1")
                .bind(session)
                .fetch_one(&mut *conn)
                .await
                .expect("read the log");
        (conn, n)
    })
    .await
}

/// How many rows of `claims` with id `claim` a checkout for `viewer` counts
/// with a raw statement (row security alone decides; no Rust fragment).
async fn raw_count(scoped: &ScopedPool, viewer: &Viewer, claim: Uuid) -> i64 {
    let mut conn = scoped.acquire_as(viewer).await.expect("checkout");
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&mut *conn)
        .await
        .expect("read")
}

/// Run one statement as the harness superuser with every user trigger off
/// (moving a session's clock, which the append-only guards refuse).
async fn without_triggers(pool: &PgPool, sql: &str, id: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *conn)
        .await
        .expect("replica");
    sqlx::query(sql)
        .bind(id)
        .execute(&mut *conn)
        .await
        .expect("statement");
    sqlx::query("RESET session_replication_role")
        .execute(&mut *conn)
        .await
        .expect("reset");
}

// =====================================================================
// 1. P before sudo equals C
// =====================================================================

/// Before any elevation the custodian P reads exactly what an ordinary person
/// C reads: none of B's canaries on any REST or MCP read, the public row on
/// each. The role confers no standing read of B's rows.
///
/// Also under the routes' own query fragments (which alone would hide B's row
/// whatever the policies said): a raw count on a scoped checkout for P, for
/// C and (calibration) for B.
///
/// Planted regression: 126's `claims_elevated_read` arm USING (true) (a read
/// arm that does not wait for an elevation) -> P's and C's raw counts read
/// B's canary. (The REST and MCP reads alone do NOT catch it: their scoped
/// fragment filters in SQL; measured, the mutant survived them.)
#[sqlx::test(migrations = "../../migrations")]
async fn p_before_sudo_reads_what_c_reads(pool: PgPool) {
    let s = spawn(&pool).await;
    let w = canaries(&pool).await;
    let p = custodian(&pool, &s, "P", &mut SoftAuthenticator::new(MODEL)).await;
    let c = person(&pool, "C").await;
    let p_view = view(&s, &w, &s.plain(&p)).await;
    assert_eq!(p_view, baseline(), "P before sudo reads none of B's rows");
    assert_eq!(view(&s, &w, &s.plain(&c)).await, p_view, "P equals C");
    let b_view = view(&s, &w, &s.plain(&w.b)).await;
    assert!(
        b_view.iter().take(4).all(|(_, seen)| *seen),
        "CALIBRATION: B reads its own canaries through REST: {b_view:?}"
    );

    // Under the routes' own fragments: row security alone, on a checkout for
    // each person's scoped viewer, with a raw statement.
    let scoped = recording_pool(&pool, 2).await;
    let mut counts = Vec::new();
    for who in [p.person, c.person, w.b.person] {
        let v = Viewer::resolve(scoped.inner(), who).await.expect("resolve");
        counts.push(raw_count(&scoped, &v, w.claim).await);
    }
    assert_eq!(
        counts,
        vec![0, 0, 1],
        "row security alone: P and C read none of B's canary (B, calibration, reads it)"
    );
}

// =====================================================================
// 2. The confused deputy
// =====================================================================

/// A ceremony for B's family completed by P's passkey (a hostile client
/// ignoring `allowCredentials`) is REFUSED: no session for anyone, the ticket
/// burned, `platform.elevation_refused` written, and no token redeems.
///
/// Mutation (125): the confirm definer's "the credential is the ticket
/// person's" check dropped -> the refusal is no longer recorded (the session
/// guard raises instead, so the ticket is left unrefused and unaudited).
#[sqlx::test(migrations = "../../migrations")]
async fn a_ceremony_for_bs_family_completed_by_p_is_refused(pool: PgPool) {
    let s = spawn(&pool).await;
    let mut p_auth = SoftAuthenticator::new(MODEL);
    let p = custodian(&pool, &s, "P", &mut p_auth).await;
    let b = custodian(&pool, &s, "B holder", &mut SoftAuthenticator::new(MODEL)).await;
    let (ticket, secret) = open_ticket(&s, &b, "B's own ticket").await;
    let (status, options) = s
        .post(&format!("/elevate/{ticket}/challenge"), None, &json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    // P's authenticator answers B's challenge with P's own credential.
    let mut options = options;
    options["publicKey"]["allowCredentials"] = json!([]);
    let response = p_auth.authenticate(ORIGIN, options).await;
    let _ = s
        .post(&format!("/elevate/{ticket}/assert"), None, &response)
        .await;

    let (outcome, session): (Option<String>, Option<Uuid>) =
        sqlx::query_as("SELECT outcome, session_id FROM elevation_tickets WHERE id = $1")
            .bind(ticket)
            .fetch_one(&pool)
            .await
            .expect("the ticket");
    assert_eq!(outcome.as_deref(), Some("refused"), "refused");
    assert_eq!(session, None, "no session");
    let sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM elevation_sessions WHERE person_agent_id = ANY($1)",
    )
    .bind(vec![p.person, b.person])
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(sessions, 0, "no session for anyone");
    let refused: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type = 'platform.elevation_refused' AND details->>'ticket_id' = $1",
    )
    .bind(ticket.to_string())
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(refused, 1, "the refusal is audited");
    let (status, body) = s
        .post(
            "/oauth/token",
            None,
            &json!({"grant_type": "urn:epigraph:grant:elevate", "ticket_id": ticket,
                    "redeem_secret": secret, "client_id": b.client_id}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no token: {body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");
}

// =====================================================================
// 3. P after sudo reads B's canaries; every access is B's to read
// =====================================================================

/// After the passkey ceremony and the elevate grant, P's elevated token reads
/// every one of B's canaries through REST (by id, in a list, its evidence,
/// the edge); each of those reads is recorded in `elevated_access` attributed
/// to B's group BEFORE the response left, and B (its group's admin) reads
/// every such row through the log's row policy as `epigraph_app`, while C
/// reads none.
///
/// MCP (THE STATED GAP): the same token's `get_claim` of B's canary is NOT
/// widened (the MCP read tools read unstamped), and the call is still
/// recorded, attributed to B's group because the answer names B's row, so the
/// attempt is B's to see. Flip the `mcp get_claim` expectation when the MCP
/// reads are stamped.
///
/// Planted regressions (§10.5): the API recorder layer's record call removed
/// ("a missing elevated_access row") -> the REST reads are served with no row
/// and the per-read attribution assertion fails; the MCP `call_tool` wrapper
/// skipping the recorder -> no `mcp:get_claim` row.
#[sqlx::test(migrations = "../../migrations")]
async fn p_after_sudo_reads_bs_canaries_and_b_reads_every_access(pool: PgPool) {
    let s = spawn(&pool).await;
    let w = canaries(&pool).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = custodian(&pool, &s, "P", &mut auth).await;
    let c = person(&pool, "C").await;
    let (session, elevated) = sudo(&pool, &s, &p, &mut auth).await;

    let claims = s.jwt.validate_token(&elevated).expect("valid");
    assert_eq!(claims.elv, Some(session), "the token names the session");
    assert!(
        claims.scopes.iter().any(|x| x == "platform:admin"),
        "{:?}",
        claims.scopes
    );

    let seen = view(&s, &w, &elevated).await;
    let mut want = baseline();
    for (read, v) in want.iter_mut() {
        if read.starts_with("rest") {
            *v = true;
        }
    }
    assert_eq!(
        seen, want,
        "elevated: every REST read sees B's canary; MCP get_claim is NOT widened (stated gap)"
    );

    let log = accesses(&pool, session).await;
    for surface in [
        "GET /api/v1/claims/:id",
        "GET /claims",
        "GET /api/v1/claims/:id/evidence",
        "GET /api/v1/edges",
    ] {
        assert!(
            log.iter()
                .any(|(s, groups)| s == surface && groups.contains(&w.b.group)),
            "{surface} is recorded against B's group: {log:?}"
        );
    }
    assert!(
        log.iter()
            .any(|(s, groups)| s == "mcp:get_claim" && groups.contains(&w.b.group)),
        "the MCP attempt on B's canary is recorded against B's group: {log:?}"
    );
    let for_b = log
        .iter()
        .filter(|(_, groups)| groups.contains(&w.b.group))
        .count() as i64;
    assert_eq!(
        accesses_seen_by(&pool, w.b.person, session).await,
        for_b,
        "B reads every access attributed to its group"
    );
    assert_eq!(
        accesses_seen_by(&pool, c.person, session).await,
        0,
        "C reads none"
    );
}

// =====================================================================
// 4. Writes are refused while elevated
// =====================================================================

/// While elevated nothing writes: REST refuses a write from the elevated
/// token (and from an elevation-claim token carrying a write scope) 403
/// ELEVATED READ-ONLY; MCP refuses a write tool to the elevated request; and
/// the DATABASE itself refuses an INSERT on an elevated application
/// connection into P's OWN group, which the same connection unelevated may
/// write. Nothing lands.
///
/// Planted regression (§10.5, "a write accepted under an elevated viewer"):
/// 126's `claims_elevated_no_insert` RESTRICTIVE policy dropped -> the
/// elevated INSERT lands (measured: the plant does produce an accepted
/// write) and the last assertion fails.
#[sqlx::test(migrations = "../../migrations")]
async fn writes_are_refused_while_elevated(pool: PgPool) {
    let s = spawn(&pool).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = custodian(&pool, &s, "P", &mut auth).await;
    let (session, elevated) = sudo(&pool, &s, &p, &mut auth).await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM claims")
        .fetch_one(&pool)
        .await
        .expect("count");
    let edge = json!({"source_id": Uuid::new_v4(), "target_id": Uuid::new_v4(),
                      "source_type": "claim", "target_type": "claim",
                      "relationship": "supports"});

    let writer = s.token(
        &p,
        Some(session),
        &["claims:read", "claims:write", "edges:write"],
    );
    for token in [&elevated, &writer] {
        let (status, body) = s.post("/api/v1/edges", Some(token), &edge).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(refused_as_elevated(&body), "REST: {body}");
    }
    let answer = s
        .call(
            &writer,
            "submit_claim",
            json!({"content": "an elevated write", "methodology": "observational",
                   "evidence_data": "seen", "evidence_type": "observation",
                   "confidence": 0.5}),
        )
        .await;
    assert!(!served(&answer), "MCP serves no write: {answer}");
    assert!(
        answer.to_string().contains("ELEVATED READ-ONLY"),
        "MCP refuses it as elevated: {answer}"
    );

    // The DATABASE half, on the recording pool with every session setting
    // stamped from the real viewers (the elevated one, and its scoped copy).
    let scoped = recording_pool(&pool, 2).await;
    let v = Viewer::resolve_elevated(&scoped, p.person, Some(session), p.family)
        .await
        .expect("resolve");
    assert!(v.is_elevated(), "CALIBRATION: elevated");
    let plain_viewer = v.detach_scoped().expect("the scoped copy");
    let insert = |viewer: Viewer| {
        let (scoped, person, group) = (scoped.clone(), p.person, p.group);
        async move {
            let mut conn = scoped.acquire_as(&viewer).await.expect("checkout");
            sqlx::query(
                "INSERT INTO claims (content, content_hash, truth_value, agent_id, \
                                     owner_group_id, visibility) \
                 VALUES ('an elevated db write', sha256(random()::text::bytea), 0.5, $1, \
                         $2, 'group')",
            )
            .bind(person)
            .bind(group)
            .execute(&mut *conn)
            .await
            .map(|_| ())
        }
    };
    let refused = insert(v).await;
    let code = refused
        .as_ref()
        .err()
        .and_then(|e| e.as_database_error())
        .and_then(|d| d.code().map(|c| c.to_string()));
    assert_eq!(
        code.as_deref(),
        Some("42501"),
        "the database refuses the elevated INSERT: {refused:?}"
    );
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM claims")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(after, before, "nothing landed while elevated");
    insert(plain_viewer)
        .await
        .expect("CALIBRATION: P's scoped viewer on the same pool writes P's own group");
}

// =====================================================================
// 5. One act runs only after its confirmation
// =====================================================================

/// One `role.end` act, proposed by P's elevated token over REST, is refused
/// at execution until P's passkey confirms THAT act (over the act's own
/// content-bound challenge); a bare end is refused too (P holds a passkey:
/// ELV10). Once confirmed, the maintenance execution (the repository call
/// `epigraph-operator end-role-assignment --act` makes; the binary itself is
/// driven in the CLI crate's end-to-end test) ends the assignment, and the
/// audit row carries `confirmation = passkey`, the act id and the elevation
/// id.
///
/// Regression pin over the whole path: the confirmation requirement is two
/// layers in migration 130 (the consumer and the table guard), each alone
/// equivalent behind the other and both mutated together in
/// `epigraph-db/tests/pending_admin_acts.rs`.
#[sqlx::test(migrations = "../../migrations")]
async fn one_act_runs_only_after_its_confirmation(pool: PgPool) {
    let s = spawn(&pool).await;
    let p = person(&pool, "P").await;
    fixture::make_custodian(&pool, p.person).await;
    let x = person(&pool, "X").await;
    // A bootstrap grant by P, before P held a passkey.
    let (holder, by) = (x.person, p.person);
    let assignment: Uuid = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let a = sqlx::query_scalar(
            "SELECT public.epigraph_grant_role('role:auditor', $1, NULL, NULL, $2, 'test')",
        )
        .bind(holder)
        .bind(by)
        .fetch_one(&mut *conn)
        .await
        .expect("a test assignment");
        (conn, a)
    })
    .await;
    let mut auth = SoftAuthenticator::new(MODEL);
    enroll(&pool, &s, p.person, &mut auth).await;
    let (session, elevated) = sudo(&pool, &s, &p, &mut auth).await;

    let (status, body) = s
        .post(
            "/api/v1/admin/acts",
            Some(&elevated),
            &json!({"kind": "role.end",
                    "args": {"assignment": assignment.to_string(), "reason": "done"},
                    "reason": "the test assignment is no longer needed"}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let act: Uuid = body["act_id"].as_str().unwrap().parse().unwrap();

    let execute = |with_act: bool| {
        let pool = pool.clone();
        async move {
            fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
                let r = if with_act {
                    epigraph_db::RoleAssignmentRepository::end_on_act(
                        &mut *conn, assignment, "done", act,
                    )
                    .await
                } else {
                    epigraph_db::RoleAssignmentRepository::end(&mut *conn, assignment, "done").await
                };
                (conn, r)
            })
            .await
        }
    };
    let ended = || async {
        sqlx::query_scalar::<_, bool>(
            "SELECT revoked_at IS NOT NULL FROM role_assignments WHERE id = $1",
        )
        .bind(assignment)
        .fetch_one(&pool)
        .await
        .expect("the assignment")
    };
    let early = execute(true).await;
    assert!(early.is_err(), "an unconfirmed act does not run: {early:?}");
    let bare = execute(false).await;
    assert!(
        format!("{bare:?}").contains("ELV10"),
        "without the act, P (holding a passkey) is refused: {bare:?}"
    );
    assert!(!ended().await, "nothing ran");

    let (status, options) = s
        .post(&format!("/elevate/act/{act}/challenge"), None, &json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    let assertion = auth.authenticate(ORIGIN, options).await;
    let (status, body) = s
        .post(&format!("/elevate/act/{act}/assert"), None, &assertion)
        .await;
    assert_eq!(status, StatusCode::OK, "confirmation: {body}");

    let done = execute(true).await;
    assert!(matches!(done, Ok(true)), "the confirmed act runs: {done:?}");
    assert!(ended().await, "ended");
    let (confirmation, act_id, elevation): (Option<String>, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT details->>'confirmation', details->>'act_id', details->>'elevation_id' \
               FROM security_events \
              WHERE event_type = 'platform.role_ended' AND details->>'assignment_id' = $1",
        )
        .bind(assignment.to_string())
        .fetch_one(&pool)
        .await
        .expect("the end's audit row");
    assert_eq!(
        (confirmation.as_deref(), act_id, elevation),
        (
            Some("passkey"),
            Some(act.to_string()),
            Some(session.to_string())
        ),
        "the audit carries the confirmation, the act and the elevation"
    );
}

// =====================================================================
// 6. After unsudo, expiry or de-registration, P equals C again
// =====================================================================

/// Each way an elevation ends returns P's elevated token to exactly C's view:
/// `POST /api/v1/elevation/end` (unsudo), the session's expiry (no one ended
/// it), and the revocation of P's registration as a human operator. Each
/// phase first calibrates that the fresh elevation reads B's canary.
///
/// Mutation (125): the liveness test's expiry comparison dropped -> the aged
/// session still reads B's canary.
#[sqlx::test(migrations = "../../migrations")]
async fn after_unsudo_expiry_or_deregistration_p_reads_what_c_reads(pool: PgPool) {
    let s = spawn(&pool).await;
    let w = canaries(&pool).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = custodian(&pool, &s, "P", &mut auth).await;
    let c = person(&pool, "C").await;
    let c_view = view(&s, &w, &s.plain(&c)).await;
    assert_eq!(c_view, baseline(), "CALIBRATION: C reads none of B's rows");
    let reads_canary = |token: String| {
        let s = &s;
        let claim = w.claim;
        async move { s.get(&format!("/api/v1/claims/{claim}"), &token).await.0 == StatusCode::OK }
    };

    // unsudo
    let (_, elevated) = sudo(&pool, &s, &p, &mut auth).await;
    assert!(
        reads_canary(elevated.clone()).await,
        "CALIBRATION: elevated"
    );
    let resp = s
        .http
        .post(s.url("/api/v1/elevation/end"))
        .bearer_auth(&elevated)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "unsudo");
    assert_eq!(
        view(&s, &w, &elevated).await,
        c_view,
        "after unsudo P equals C"
    );

    // expiry
    let (session, elevated) = sudo(&pool, &s, &p, &mut auth).await;
    assert!(
        reads_canary(elevated.clone()).await,
        "CALIBRATION: elevated"
    );
    without_triggers(
        &pool,
        "UPDATE elevation_sessions SET started_at = started_at - interval '1 hour', \
                                       expires_at = expires_at - interval '1 hour' \
          WHERE id = $1",
        session,
    )
    .await;
    assert_eq!(
        view(&s, &w, &elevated).await,
        c_view,
        "after expiry P equals C"
    );

    // de-registration
    let (_, elevated) = sudo(&pool, &s, &p, &mut auth).await;
    assert!(
        reads_canary(elevated.clone()).await,
        "CALIBRATION: elevated"
    );
    let who = p.person;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_revoke_human_operator($1, 'acceptance')")
            .bind(who)
            .execute(&mut *conn)
            .await
            .expect("revoke P's registration");
        (conn, ())
    })
    .await;
    assert_eq!(
        view(&s, &w, &elevated).await,
        c_view,
        "after de-registration P equals C"
    );
}

// =====================================================================
// 7. Pooled reuse
// =====================================================================

/// A connection reused after an elevated request reads no foreign row. On a
/// REST router whose pool holds ONE connection, an elevated read of B's
/// canary is followed on that same connection by C's read and P's ordinary
/// read: neither reads B's row. Under the REST route's own fragment, the same
/// on the bare pool: a one-connection recording pool checks the connection
/// out for P's elevated viewer, then for P's scoped viewer, and a raw count
/// (row security alone decides) reads B's canary only the first time.
///
/// Mutation (EL-6): the five-setting statement leaving the elevation pair in
/// place when it stamps or scrubs an empty one (both the per-checkout stamp
/// and the release scrub use it) -> P's scoped checkout runs elevated and
/// counts B's canary. (Measured: the REST half alone does not catch it, the
/// route's scoped fragment filters B's row in SQL; the raw count does.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_pooled_connection_reads_no_foreign_row_after_an_elevated_request(pool: PgPool) {
    let s = spawn_with(&pool, 1).await;
    let w = canaries(&pool).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = custodian(&pool, &s, "P", &mut auth).await;
    let c = person(&pool, "C").await;
    let (session, elevated) = sudo(&pool, &s, &p, &mut auth).await;
    let by_id = format!("/api/v1/claims/{}", w.claim);
    for _ in 0..3 {
        let (status, body) = s.get(&by_id, &elevated).await;
        assert_eq!(status, StatusCode::OK, "CALIBRATION: elevated: {body}");
        for (who, token) in [("C", s.plain(&c)), ("P unelevated", s.plain(&p))] {
            let (status, body) = s.get(&by_id, &token).await;
            assert_ne!(
                status,
                StatusCode::OK,
                "{who} on the reused connection reads B's row: {body}"
            );
        }
    }

    let one = recording_pool(&pool, 1).await;
    let v = Viewer::resolve_elevated(&one, p.person, Some(session), p.family)
        .await
        .expect("resolve");
    assert!(v.is_elevated(), "CALIBRATION: elevated");
    let scoped_viewer = v.detach_scoped().expect("the scoped copy");
    for _ in 0..3 {
        assert_eq!(
            raw_count(&one, &v, w.claim).await,
            1,
            "CALIBRATION: the elevated checkout"
        );
        assert_eq!(
            raw_count(&one, &scoped_viewer, w.claim).await,
            0,
            "the same connection, checked out for P's scoped viewer, reads none of B's rows"
        );
    }
}

// =====================================================================
// 8. A detached task runs scoped
// =====================================================================

/// A task detached from an elevated request (`Viewer::detach_scoped`, the
/// only way a spawned task gets a viewer) runs as the principal's SCOPED
/// viewer: it reads none of B's rows on the same recording pool where the
/// elevated viewer reads them.
///
/// Mutation (EL-6): `detach_scoped` carrying the elevation into the copy ->
/// the detached read sees B's canary.
#[sqlx::test(migrations = "../../migrations")]
async fn a_detached_task_runs_scoped(pool: PgPool) {
    let s = spawn(&pool).await;
    let w = canaries(&pool).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = custodian(&pool, &s, "P", &mut auth).await;
    let (session, _) = sudo(&pool, &s, &p, &mut auth).await;
    let scoped = recording_pool(&pool, 2).await;
    let v = Viewer::resolve_elevated(&scoped, p.person, Some(session), p.family)
        .await
        .expect("resolve");
    assert!(
        v.is_elevated(),
        "CALIBRATION: the request viewer is elevated"
    );
    let detached = v.detach_scoped().expect("a scoped copy");
    assert!(!detached.is_elevated(), "the detached viewer is scoped");

    let count = |viewer: Viewer| {
        let (scoped, claim) = (scoped.clone(), w.claim);
        tokio::spawn(async move {
            let mut conn = scoped.acquire_as(&viewer).await.expect("checkout");
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM claims WHERE id = $1")
                .bind(claim)
                .fetch_one(&mut *conn)
                .await
                .expect("read")
        })
    };
    assert_eq!(
        count(detached).await.expect("the detached task"),
        0,
        "the detached task reads none of B's rows"
    );
    assert_eq!(
        count(v).await.expect("CALIBRATION"),
        1,
        "CALIBRATION: the elevated viewer reads B's canary on the same pool"
    );
}

// =====================================================================
// 9. P's agent cannot elevate
// =====================================================================

/// P's AGENT (linked to P as its operator) gets no ticket: over HTTP its
/// token carries no authority at all (operated agents are stdio-only), and
/// under that gate the DATABASE refuses it too (ELV02: an agent holds no
/// role), as the session principal on a live family of its own client. A
/// token of the agent naming P's LIVE session reads none of B's rows over
/// REST or MCP (the session is P's, not the agent's).
///
/// Regression pin: agents never elevate (CUS01, 125's ELV02); no single
/// Rust mutation reaches this.
#[sqlx::test(migrations = "../../migrations")]
async fn ps_agent_cannot_elevate(pool: PgPool) {
    let s = spawn(&pool).await;
    let w = canaries(&pool).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = custodian(&pool, &s, "P", &mut auth).await;
    let (session, _) = sudo(&pool, &s, &p, &mut auth).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "P's agent").await;
    sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id) \
         VALUES ($1, $2, $3)",
    )
    .bind(agent)
    .bind(p.person)
    .bind(p.group)
    .execute(&pool)
    .await
    .expect("link the agent to P");
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id, owner_id) \
         VALUES ($1, 'el14-agent', 'agent', $3, $3, 'active', $2, $4) RETURNING id",
    )
    .bind(format!("el14-agent-{agent}"))
    .bind(agent)
    .bind(READ.iter().map(|x| (*x).to_string()).collect::<Vec<_>>())
    .bind(p.client)
    .fetch_one(&pool)
    .await
    .expect("the agent's client");
    let fam = family(&pool, client).await;
    let agent_token = |fam: Uuid, elv: Option<Uuid>| {
        s.jwt
            .issue_access_token(
                client,
                READ.iter().map(|x| (*x).to_string()).collect(),
                "agent",
                Some(p.client),
                Some(agent),
                Duration::minutes(15),
                AccessTokenBinding {
                    family_id: Some(fam),
                    elevation_id: elv,
                },
            )
            .expect("mint")
            .0
    };
    let (status, body) = s
        .post(
            "/api/v1/elevation/tickets",
            Some(&agent_token(fam, None)),
            &json!({"reason": "an agent asks"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "over HTTP: {body}");
    // Under the HTTP gate, the database itself: the agent as the session
    // principal, on a live family of its own client.
    let refused = as_app(&pool, agent, None, true, |mut conn| async move {
        let r = sqlx::query_scalar::<_, Uuid>(
            "SELECT public.epigraph_create_elevation_ticket($1, $2, 'grant', 'an agent asks', \
                    sha256('an agent secret'::bytea))",
        )
        .bind(client)
        .bind(fam)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    assert!(
        format!("{refused:?}").contains("ELV02"),
        "the database refuses the agent a ticket (ELV02): {refused:?}"
    );
    let tickets: i64 =
        sqlx::query_scalar("SELECT count(*) FROM elevation_tickets WHERE person_agent_id = $1")
            .bind(agent)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(tickets, 0, "no ticket for the agent");

    let riding = agent_token(p.family, Some(session));
    let (status, _) = s.get(&format!("/api/v1/claims/{}", w.claim), &riding).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "the agent riding P's session reads none of B's rows"
    );
    let answer = s
        .call(
            &riding,
            "get_claim",
            json!({"claim_id": w.claim.to_string()}),
        )
        .await;
    assert!(!served(&answer), "nor over MCP: {answer}");
}

// =====================================================================
// 10. A forged elevation setting grants nothing
// =====================================================================

/// The five session settings are a transport, never an authority: on an
/// application connection, a forged elevation id on P's family, P's REAL live
/// session stamped under C's principal, and P's real session on a connection
/// that does not declare the recorder are each not elevated and read none of
/// B's rows. Calibration: P's real stamp is elevated and reads B's canary.
///
/// Mutation (125): `epigraph_is_elevated` dropping its principal clause ->
/// C riding P's session is elevated.
#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_elevation_setting_grants_nothing(pool: PgPool) {
    let s = spawn(&pool).await;
    let w = canaries(&pool).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = custodian(&pool, &s, "P", &mut auth).await;
    let c = person(&pool, "C").await;
    let (session, _) = sudo(&pool, &s, &p, &mut auth).await;
    assert_eq!(
        probe(&pool, p.person, Some((session, p.family)), true, w.claim).await,
        (true, 1),
        "CALIBRATION: P's real stamp"
    );
    for (what, principal, pair, recorder) in [
        (
            "a forged elevation id",
            p.person,
            (Uuid::new_v4(), p.family),
            true,
        ),
        ("P's session under C", c.person, (session, p.family), true),
        (
            "P's session on another family",
            p.person,
            (session, c.family),
            true,
        ),
        (
            "P's session, no recorder",
            p.person,
            (session, p.family),
            false,
        ),
    ] {
        assert_eq!(
            probe(&pool, principal, Some(pair), recorder, w.claim).await,
            (false, 0),
            "{what}"
        );
    }
}

// =====================================================================
// 11. A forged platform event is refused
// =====================================================================

/// The application role writes no `platform.` audit row: a forged
/// `platform.elevation_ended` (which would read as "the session was ended")
/// and a forged `platform.elevated` are refused 42501, whatever the stamp,
/// and nothing lands.
///
/// Regression pin (123's `security_events_platform_privileged`, mutated in
/// the database crate).
#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_platform_event_is_refused(pool: PgPool) {
    let s = spawn(&pool).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = custodian(&pool, &s, "P", &mut auth).await;
    let (session, _) = sudo(&pool, &s, &p, &mut auth).await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events")
        .fetch_one(&pool)
        .await
        .expect("count");
    let who = p.person;
    for event in [
        "platform.elevation_ended",
        "platform.elevated",
        "PLATFORM.elevated",
    ] {
        for elevation in [None, Some((session, p.family))] {
            let r = as_app(&pool, who, elevation, true, |mut conn| async move {
                let r = sqlx::query(
                    "INSERT INTO security_events (event_type, agent_id, success, details) \
                     VALUES ($1, $2, true, jsonb_build_object('session_id', $3::text))",
                )
                .bind(event)
                .bind(who)
                .bind(session.to_string())
                .execute(&mut *conn)
                .await;
                (conn, r.map(|_| ()))
            })
            .await;
            let code = r
                .as_ref()
                .err()
                .and_then(|e| e.as_database_error())
                .and_then(|d| d.code().map(|c| c.to_string()));
            assert_eq!(
                code.as_deref(),
                Some("42501"),
                "{event} (elevated: {}): {r:?}",
                elevation.is_some()
            );
        }
    }
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM security_events")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(after, before, "nothing landed");
}

// =====================================================================
// 12. Armed, no grant mints an admin-only scope
// =====================================================================

const VERIFIER: &str = "el14-acceptance-pkce-code-verifier-of-adequate-length-0123456789";
const REDIRECT_URI: &str = "https://claude.ai/api/mcp/auth_callback";

fn scopes_of(s: &Server, body: &Value) -> Vec<String> {
    let mut scopes = s
        .jwt
        .validate_token(body["access_token"].as_str().expect("access_token"))
        .expect("valid")
        .scopes;
    scopes.sort();
    scopes
}

/// With the admin-scope switch ARMED, clients holding `claims:admin` get a
/// token without it from every grant path a person or a service uses: the
/// authorization-code exchange, the refresh grant, a service's client
/// credentials, and the elevate grant (which adds only `platform:admin`).
///
/// Mutation (EL-9): a handler minting the client's granted scopes without the
/// chokepoint -> `claims:admin` in that token (run here on client
/// credentials; each grant is mutated alone in `admin_scope_mint.rs`).
#[sqlx::test(migrations = "../../migrations")]
async fn armed_no_grant_mints_an_admin_only_scope(pool: PgPool) {
    let s = spawn(&pool).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = custodian(&pool, &s, "P", &mut auth).await;
    let held = ["claims:read", "claims:admin"];
    grant_scopes(&pool, p.client, &held).await;
    sqlx::query("SELECT * FROM public.epigraph_set_admin_scope_enforcement(true, 'acceptance')")
        .execute(&pool)
        .await
        .expect("arm");
    let want = vec!["claims:read".to_string()];

    // authorization_code, then refresh_token.
    let code = format!("code_{}", Uuid::new_v4().simple());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(VERIFIER.as_bytes()));
    epigraph_db::repos::authorization_code::AuthorizationCodeRepository::create(
        &pool,
        blake3::hash(code.as_bytes()).as_bytes(),
        &p.client_id,
        p.client,
        REDIRECT_URI,
        &challenge,
        &held.iter().map(|x| (*x).to_string()).collect::<Vec<_>>(),
        None,
        chrono::Utc::now() + Duration::minutes(5),
    )
    .await
    .expect("an authorization code");
    let (status, body) = s
        .post(
            "/oauth/token",
            None,
            &json!({"grant_type": "authorization_code", "code": code,
                    "code_verifier": VERIFIER, "redirect_uri": REDIRECT_URI,
                    "client_id": p.client_id}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "code exchange: {body}");
    assert_eq!(scopes_of(&s, &body), want, "authorization_code");
    let refresh = body["refresh_token"].as_str().expect("a refresh token");
    let (status, body) = s
        .post(
            "/oauth/token",
            None,
            &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    assert_eq!(scopes_of(&s, &body), want, "refresh_token");

    // A service's client credentials.
    let secret: [u8; 32] = rand::random();
    let service_id = format!("el14_svc_{}", Uuid::new_v4().simple());
    epigraph_db::repos::oauth_client::OAuthClientRepository::create(
        &pool,
        &service_id,
        Some(blake3::hash(&secret).as_bytes()),
        "el14 service",
        "service",
        &held.iter().map(|x| (*x).to_string()).collect::<Vec<_>>(),
        &held.iter().map(|x| (*x).to_string()).collect::<Vec<_>>(),
        "active",
        None,
        None,
        Some("EL14 Test Org"),
        Some("el14@example.com"),
        None,
    )
    .await
    .expect("a service client");
    let (status, body) = s
        .post(
            "/oauth/token",
            None,
            &json!({"grant_type": "client_credentials", "client_id": service_id,
                    "client_secret": hex::encode(secret)}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "client credentials: {body}");
    assert_eq!(scopes_of(&s, &body), want, "client_credentials");

    // The elevate grant.
    let (_, elevated) = sudo(&pool, &s, &p, &mut auth).await;
    let mut scopes = s.jwt.validate_token(&elevated).expect("valid").scopes;
    scopes.sort();
    assert_eq!(
        scopes,
        vec!["claims:read".to_string(), "platform:admin".to_string()],
        "elevate: platform:admin and no admin-only scope"
    );
}

// =====================================================================
// 13. The manifest differs between a normal and an elevated request
// =====================================================================

/// What the tool list shows depends on who asks and whether the request is
/// elevated: the act-proposal tool only to P's ELEVATED request (over MCP and
/// in the REST catalog); `unsudo` to the role holder P and never to C; `sudo`
/// to no one while connector mode is off (the default). The elevated list
/// holds every tool P's normal list holds.
///
/// Mutation (EL-11/EL-12b): the listing rule admitting every HTTP caller ->
/// C's list holds `propose_admin_act`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_manifest_differs_between_a_normal_and_an_elevated_request(pool: PgPool) {
    let s = spawn(&pool).await;
    let mut auth = SoftAuthenticator::new(MODEL);
    let p = custodian(&pool, &s, "P", &mut auth).await;
    let c = person(&pool, "C").await;
    let (_, elevated) = sudo(&pool, &s, &p, &mut auth).await;

    let normal = s.tools(&s.plain(&p)).await;
    let raised = s.tools(&elevated).await;
    let c_list = s.tools(&s.plain(&c)).await;
    let has = |list: &[String], name: &str| list.iter().any(|n| n == name);
    assert!(!has(&normal, "propose_admin_act"), "normal: {normal:?}");
    assert!(has(&raised, "propose_admin_act"), "elevated: {raised:?}");
    assert!(!has(&c_list, "propose_admin_act"), "C: {c_list:?}");
    assert!(
        has(&normal, "unsudo") && has(&raised, "unsudo"),
        "P holds the role"
    );
    assert!(!has(&c_list, "unsudo"), "C holds no role: {c_list:?}");
    for list in [&normal, &raised, &c_list] {
        assert!(!has(list, "sudo"), "connector mode is off: {list:?}");
    }
    let missing: Vec<&String> = normal.iter().filter(|n| !has(&raised, n)).collect();
    assert!(missing.is_empty(), "the elevated list drops {missing:?}");

    let catalog = |token: String| {
        let s = &s;
        async move {
            let (status, body) = s.get("/api/v1/mcp/tools", &token).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body.to_string().contains("\"propose_admin_act\"")
        }
    };
    assert!(!catalog(s.plain(&p)).await, "REST catalog, normal");
    assert!(catalog(elevated.clone()).await, "REST catalog, elevated");
}
