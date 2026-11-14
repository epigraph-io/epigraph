//! Backlog fe514fc3: the READ-ONLY `--allow-unauthenticated-http` listener
//! reads PUBLIC rows only.
//!
//! Operator decision: a dedicated zero-membership principal, public-only reads,
//! fail-closed. Before it the listener injected the server's own agent, so
//! every holder of its shared credential read the server agent's personal
//! group, which holds every claim the server ingests over stdio.
//!
//! Driven through the router `main` builds (the same
//! `unauthenticated_reader::listener_principal`, `inject_unauthenticated_context`
//! and `call_tool`), so the injected principal, `request_viewer` and the tool's
//! viewer-filtered read are all in the path.
//!
//! Superuser harness (BYPASSRLS): what is pinned is the in-query visibility
//! predicate each read splices from its viewer, which is what a superuser
//! session still obeys. The row-policy half follows from the same group set.
//!
//! Load-bearing, verified by mutation:
//! * `listener_principal` handing the read-only listener the server agent
//!   (the pre-fix wiring) fails
//!   `a_group_row_of_the_server_agent_is_invisible_on_the_read_only_listener`
//!   (the group claim is served) and
//!   `the_read_only_listener_injects_the_reader_and_the_opt_in_the_signer`;
//! * deleting `request_viewer`'s grouped-viewer refusal fails
//!   `a_membership_granted_to_the_reader_after_boot_closes_the_listener` (the
//!   group claim is served);
//! * deleting `UnauthenticatedReader::resolve`'s membership check fails
//!   `a_reader_that_holds_a_membership_does_not_resolve`;
//! * deleting `call_tool`'s principal-less filter on `record_auth_lineage`
//!   fails `a_call_on_the_read_only_listener_records_no_auth_lineage` (the
//!   edge `server --OPERATED_BY--> reader` is written).

#[path = "viewer_fixture.rs"]
mod fixture;

use std::sync::Arc;
use std::time::Duration;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::auth::{ServerPrincipalSource, UnauthenticatedWrites};
use epigraph_mcp::unauthenticated_reader::{
    listener_principal, UnauthenticatedReader, READER_PUBLIC_KEY,
};
use sqlx::PgPool;
use uuid::Uuid;

const ACCEPT: &str = "application/json, text/event-stream";
const SESSION_HEADER: &str = "Mcp-Session-Id";
const PUBLIC_ONLY_REFUSAL: &str = "reads public rows only";

struct Listener {
    url: String,
    server: Arc<epigraph_mcp::EpiGraphMcpFull>,
}

/// The router `main` builds for `--listen unix:… --allow-unauthenticated-http`
/// (TCP here only so the test can dial it; the middleware stack is the same).
async fn spawn(pool: PgPool, seed: u8, writes: UnauthenticatedWrites) -> Listener {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    let signer = Arc::new(AgentSigner::from_bytes(&[seed; 32]).expect("signer"));
    let scoped = fixture::scoped_pool(&pool).await;
    let embedder = Arc::new(
        epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone()),
    );
    let server = Arc::new(
        epigraph_mcp::EpiGraphMcpFull::new_shared(
            pool.clone(),
            signer.clone(),
            embedder.clone(),
            false,
        )
        .with_scoped_pool(scoped.clone()),
    );
    let principal = listener_principal(
        writes,
        server.clone() as Arc<dyn ServerPrincipalSource>,
        pool.clone(),
    )
    .await;
    let session_pool = pool.clone();
    let service = StreamableHttpService::new(
        move || {
            Ok(epigraph_mcp::EpiGraphMcpFull::new_shared(
                session_pool.clone(),
                signer.clone(),
                embedder.clone(),
                false,
            )
            .with_scoped_pool(scoped.clone()))
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let router = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn_with_state(
            principal,
            epigraph_mcp::auth::inject_unauthenticated_context,
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    Listener {
        url: format!("http://{addr}/mcp"),
        server,
    }
}

async fn read_sse_data(resp: &mut reqwest::Response) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut acc = String::new();
    loop {
        match tokio::time::timeout_at(deadline, resp.chunk()).await {
            Ok(Ok(Some(bytes))) => {
                acc.push_str(&String::from_utf8_lossy(&bytes));
                if acc
                    .lines()
                    .any(|l| l.starts_with("data:") && l.trim_end().len() > 5)
                {
                    return acc;
                }
            }
            _ => return acc,
        }
    }
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    session: Option<&str>,
    body: serde_json::Value,
) -> reqwest::Response {
    // No Authorization header: this listener validates none.
    let mut req = client
        .post(url)
        .header("Accept", ACCEPT)
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(s) = session {
        req = req.header(SESSION_HEADER, s);
    }
    req.send().await.expect("POST")
}

async fn handshake(client: &reqwest::Client, url: &str) -> String {
    let mut resp = post(
        client,
        url,
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "public-only-test", "version": "0"}}
        }),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "initialize");
    let session = resp
        .headers()
        .get(SESSION_HEADER)
        .expect("session header")
        .to_str()
        .expect("ascii")
        .to_owned();
    let _ = read_sse_data(&mut resp).await;
    let notif = post(
        client,
        url,
        Some(&session),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(notif.status().as_u16(), 202, "notifications/initialized");
    session
}

async fn get_claim(
    client: &reqwest::Client,
    url: &str,
    session: &str,
    id: u32,
    claim: Uuid,
) -> String {
    let mut resp = post(
        client,
        url,
        Some(session),
        serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "get_claim", "arguments": {"claim_id": claim.to_string()}}
        }),
    )
    .await;
    read_sse_data(&mut resp).await
}

/// The server agent's live personal group (created by its resolution).
async fn personal_group_of(pool: &PgPool, agent: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT group_id FROM group_memberships WHERE agent_id = $1 AND revoked_at IS NULL \
         LIMIT 1",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("the server agent's resolution provisions its personal group")
}

async fn reader_agent(pool: &PgPool) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(READER_PUBLIC_KEY.to_vec())
        .fetch_optional(pool)
        .await
        .expect("reader lookup")
}

async fn live_memberships(pool: &PgPool, agent: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("membership count")
}

async fn grant_reader_role(pool: &PgPool, group: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("grant a reader membership");
}

/// The finding's exact shape: a `group` claim owned by the SERVER agent's
/// personal group is not served on the read-only listener; a public claim is
/// (calibration: the listener reads at all, so the absence is the filter's).
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_row_of_the_server_agent_is_invisible_on_the_read_only_listener(pool: PgPool) {
    let l = spawn(pool.clone(), 0x51, UnauthenticatedWrites::Refused).await;
    let server_agent = l.server.server_agent_id().await.expect("server agent");
    let group = personal_group_of(&pool, server_agent).await;
    let public = fixture::seed_public_claim(&pool, server_agent, "fe514fc3 public row").await;
    let private =
        fixture::seed_group_claim(&pool, server_agent, group, "fe514fc3 server-group row").await;

    let client = reqwest::Client::new();
    let session = handshake(&client, &l.url).await;

    let served = get_claim(&client, &l.url, &session, 2, public).await;
    assert!(
        served.contains("fe514fc3 public row"),
        "CALIBRATION: a public claim must be served on the read-only listener:\n{served}"
    );

    let hidden = get_claim(&client, &l.url, &session, 3, private).await;
    assert!(
        !hidden.contains("fe514fc3 server-group row")
            && hidden.contains(&format!("claim {private} not found")),
        "a claim in the server agent's group must read as NOT FOUND to an unauthenticated \
         caller (not as some other error):\n{hidden}"
    );

    // And the reader is still in no group after serving requests: nothing on
    // the request path provisions one for it.
    let reader = reader_agent(&pool).await.expect("the reader was created");
    assert_ne!(reader, server_agent);
    assert_eq!(live_memberships(&pool, reader).await, 0);
}

async fn operated_by_edges_from(pool: &PgPool, agent: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND source_type = 'agent' \
         AND relationship = 'OPERATED_BY'",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("OPERATED_BY edge count")
}

/// Review of fe514fc3: nobody authenticates on this listener, so a tool call
/// on it records no `OPERATED_BY` auth-lineage edge. Before the reader agent
/// the would-be edge was a server-agent self-loop that `edges_no_self_loop`
/// refuses; with the reader it would be a real edge `server --OPERATED_BY-->
/// reader`, a second lineage target that the operator-link functions read as
/// a shared HTTP signer. Driven through the real `call_tool`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_call_on_the_read_only_listener_records_no_auth_lineage(pool: PgPool) {
    let l = spawn(pool.clone(), 0x54, UnauthenticatedWrites::Refused).await;
    let server_agent = l.server.server_agent_id().await.expect("server agent");
    let public = fixture::seed_public_claim(&pool, server_agent, "fe514fc3 lineage row").await;

    let client = reqwest::Client::new();
    let session = handshake(&client, &l.url).await;
    let served = get_claim(&client, &l.url, &session, 2, public).await;
    assert!(
        served.contains("fe514fc3 lineage row"),
        "CALIBRATION: the call reached `call_tool` and was served:\n{served}"
    );

    assert_eq!(
        operated_by_edges_from(&pool, server_agent).await,
        0,
        "a principal-less call must record no OPERATED_BY edge from the server agent"
    );
    let reader = reader_agent(&pool).await.expect("the reader was created");
    let into_reader: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE target_id = $1 AND relationship = 'OPERATED_BY'",
    )
    .bind(reader)
    .fetch_one(&pool)
    .await
    .expect("edges into the reader");
    assert_eq!(into_reader, 0, "nothing acts on behalf of the reader");
}

/// Fail-closed after boot: a membership granted to the reader once the
/// listener is up does not widen it; the listener refuses instead, naming the
/// rule, and still does not serve the group row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_membership_granted_to_the_reader_after_boot_closes_the_listener(pool: PgPool) {
    let l = spawn(pool.clone(), 0x52, UnauthenticatedWrites::Refused).await;
    let server_agent = l.server.server_agent_id().await.expect("server agent");
    let group = personal_group_of(&pool, server_agent).await;
    let public = fixture::seed_public_claim(&pool, server_agent, "fe514fc3 public after").await;
    let private =
        fixture::seed_group_claim(&pool, server_agent, group, "fe514fc3 group after").await;
    let reader = reader_agent(&pool)
        .await
        .expect("the reader was created at boot");

    grant_reader_role(&pool, group, reader).await;

    let client = reqwest::Client::new();
    let session = handshake(&client, &l.url).await;
    let hidden = get_claim(&client, &l.url, &session, 2, private).await;
    assert!(
        !hidden.contains("fe514fc3 group after") && hidden.contains(PUBLIC_ONLY_REFUSAL),
        "a reader that gained a membership must be refused, not read with it:\n{hidden}"
    );
    let public_too = get_claim(&client, &l.url, &session, 3, public).await;
    assert!(
        public_too.contains(PUBLIC_ONLY_REFUSAL),
        "the refusal is the listener's posture, not a per-row filter:\n{public_too}"
    );
}

/// Fail-closed at resolution: a reader row that already holds a membership
/// does not resolve, so the listener injects no principal at all.
#[sqlx::test(migrations = "../../migrations")]
async fn a_reader_that_holds_a_membership_does_not_resolve(pool: PgPool) {
    let reader = UnauthenticatedReader::new(pool.clone());
    let id = reader.resolve().await.expect("a fresh reader resolves");
    assert_eq!(live_memberships(&pool, id).await, 0);

    let (_, group) = fixture::seed_agent_with_group(&pool, "fe514fc3-other").await;
    grant_reader_role(&pool, group, id).await;

    let err = UnauthenticatedReader::new(pool.clone())
        .resolve()
        .await
        .expect_err("a reader with a membership must not resolve");
    assert!(err.contains("must hold none"), "{err}");

}

/// The wiring `main` uses: the read-only listener injects the dedicated
/// reader; the write opt-in injects the listener's signer (its callers'
/// writes are authored by it).
#[sqlx::test(migrations = "../../migrations")]
async fn the_read_only_listener_injects_the_reader_and_the_opt_in_the_signer(pool: PgPool) {
    let signer = Arc::new(AgentSigner::from_bytes(&[0x53; 32]).expect("signer"));
    let scoped = fixture::scoped_pool(&pool).await;
    let embedder = Arc::new(
        epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone()),
    );
    let server = Arc::new(
        epigraph_mcp::EpiGraphMcpFull::new_shared(pool.clone(), signer, embedder, false)
            .with_scoped_pool(scoped),
    );
    let server_agent = server.server_agent_id().await.expect("server agent");

    let read_only = listener_principal(
        UnauthenticatedWrites::Refused,
        server.clone() as Arc<dyn ServerPrincipalSource>,
        pool.clone(),
    )
    .await;
    let injected = read_only.agent_id().await.expect("the reader resolves");
    assert_ne!(
        injected, server_agent,
        "the read-only listener is not the server agent"
    );
    assert_eq!(Some(injected), reader_agent(&pool).await);
    assert_eq!(live_memberships(&pool, injected).await, 0);

    let opt_in = listener_principal(
        UnauthenticatedWrites::AsListenerSigner,
        server.clone() as Arc<dyn ServerPrincipalSource>,
        pool.clone(),
    )
    .await;
    assert_eq!(opt_in.agent_id().await, Some(server_agent));
}
