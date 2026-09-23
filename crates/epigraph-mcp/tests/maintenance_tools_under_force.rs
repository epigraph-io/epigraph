//! FINAL-PLAN §8.4 **P5** for the MCP surface: `backfill_embeddings`,
//! `recompute_beliefs` and `sweep_semantic_duplicates`, driven through the REAL
//! `#[tool_router]` dispatch, MODIFY a group-private row under FORCE.
//!
//! # What makes these tests able to fail
//!
//! `#[sqlx::test]` connects as the superuser, which bypasses every policy, so a
//! maintenance test on that pool passes whichever pool the tool spends its
//! bypass viewer on. Here the server is built the way `epigraph-mcp-full` builds
//! it, with two DIFFERENT roles:
//!
//! * the application pool (`server.pool`) is `epigraph_app` — not a member of
//!   `epigraph_maintenance`, so `epigraph_bypass()` is false and, with no
//!   session GUCs stamped, the policy admits only `visibility = 'public'`;
//! * the attached maintenance pool is `epigraph_maintenance`, for which
//!   `epigraph_bypass()` is true.
//!
//! Both are `fixture::downgraded_pool`s, i.e. `SET SESSION AUTHORIZATION`,
//! which moves `session_user` — the column `epigraph_bypass()` reads. `SET
//! ROLE` would not: it leaves `session_user` at the superuser and every policy
//! arm true.
//!
//! Each of the three MODIFY tests pairs its positive assertion with a
//! COUNTERFACTUAL on the same fixture: the same bypass viewer, spent on the
//! application pool, does not see the private row at all. That is what a tool
//! that queried `server.pool` would have done — reported success and changed
//! nothing — so the positive assertion is not satisfiable by that regression.
//! MEASURED: moving the dedup enumeration, the backfill selection and the
//! belief recompute back onto `server.pool` fails all three, each on a
//! success-shaped body (`pairs_marked: 0`, `candidates: 0`,
//! `claims_recomputed: 0`, no errors).
//!
//! # Why through the router
//!
//! The dispatch body is where the session is minted (`maintenance_viewer`) and
//! the tool function is where it is spent; the defect this file guards against
//! lived in the gap between the two. Driving `call_tool` over an in-process
//! duplex transport exercises both halves and `with_scoped_pool`, with no
//! `RequestContext` to synthesize by hand.
//!
//! That duplex is the STDIO shape: no HTTP `Parts`, so no `AuthContext` and no
//! scope gate. It therefore says nothing about WHO reaches the bypass, which on
//! the HTTP transport is decided by `SCOPE_MAP` alone, because `main.rs`
//! attaches the maintenance pool to every per-session HTTP server.
//! [`over_http_only_a_claims_admin_token_reaches_the_maintenance_bypass`]
//! serves the same router behind `bearer_auth_middleware` and answers that.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::time::Duration;

use epigraph_crypto::AgentSigner;
use epigraph_db::visibility::SystemReason;
use epigraph_db::{ClaimRepository, MassFunctionRepository, ScopedPool};
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::maintenance::{MAINTENANCE_POOL_CONNECTIONS, MAINTENANCE_TOOL_CONCURRENCY};
use epigraph_mcp::{tools, EpiGraphMcpFull};
use rmcp::model::CallToolRequestParams;
use rmcp::service::{RoleClient, RunningService};
use rmcp::ServiceExt;
use sqlx::PgPool;
use uuid::Uuid;

const DIM: usize = 1536;

/// The application pool and the `ScopedPool` carrying the maintenance pool,
/// as `main` wires them.
struct Pools {
    app: PgPool,
    scoped: ScopedPool,
}

async fn pools(pool: &PgPool) -> Pools {
    let app = fixture::downgraded_pool(pool, "epigraph_app").await;
    let maint = fixture::downgraded_pool(pool, "epigraph_maintenance").await;
    let scoped = fixture::scoped_pool(pool)
        .await
        .with_maintenance_pool(maint);
    Pools { app, scoped }
}

fn build_server(
    app: &PgPool,
    scoped: Option<ScopedPool>,
    embedder: McpEmbedder,
) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x5au8; 32]).expect("signer");
    let server = EpiGraphMcpFull::new(app.clone(), signer, embedder, false);
    match scoped {
        Some(s) => server.with_scoped_pool(s),
        None => server,
    }
}

/// An MCP client connected to `server` over an in-process duplex — the stdio
/// transport's shape, so `call_tool` runs with no HTTP `Parts` and no scope
/// gate, exactly as `epigraph-mcp-full` does on stdio.
async fn connect(server: EpiGraphMcpFull) -> RunningService<RoleClient, ()> {
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    ().serve(client_io).await.expect("MCP client handshake")
}

async fn call(
    client: &RunningService<RoleClient, ()>,
    name: &'static str,
    args: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let out = client
        .call_tool(CallToolRequestParams {
            meta: None,
            name: name.into(),
            arguments: args.as_object().cloned(),
            task: None,
        })
        .await
        .map_err(|e| e.to_string())?;
    if out.is_error == Some(true) {
        return Err(format!("{:?}", out.content));
    }
    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    Ok(serde_json::from_str(&text).expect("tool result is JSON"))
}

/// The claim these tests exist for is only meaningful while `claims` is under
/// FORCE (and therefore ENABLE). Fail loudly rather than pass vacuously if a
/// migration ever drops it.
async fn assert_claims_are_forced(pool: &PgPool) {
    let (enabled, forced): (bool, bool) = sqlx::query_as(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class \
         WHERE oid = 'public.claims'::regclass",
    )
    .fetch_one(pool)
    .await
    .expect("read claims' row-security flags");
    assert!(
        enabled && forced,
        "precondition: `claims` must have ROW LEVEL SECURITY enabled AND forced at \
         the migrated head; without it these tests cannot distinguish the pools"
    );
}

/// A local stand-in for the embeddings provider: every request gets the same
/// 1536-d vector. Returns the URL to hand `McpEmbedder::with_endpoint`.
async fn embedding_stub() -> String {
    embedding_stub_with_delay(Duration::ZERO).await
}

/// [`embedding_stub`], answering each request only after `delay`.
async fn embedding_stub_with_delay(delay: Duration) -> String {
    use axum::{routing::post, Json, Router};
    let app = Router::new().route(
        "/v1/embeddings",
        post(move || async move {
            tokio::time::sleep(delay).await;
            Json(serde_json::json!({ "data": [{ "embedding": vec![0.01_f32; DIM] }] }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind slow embedding stub");
    let addr = listener.local_addr().expect("stub addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}/v1/embeddings")
}

fn pgvec(axis: usize, tilt: f32) -> String {
    let mut v = vec![0.0f32; DIM];
    v[axis] = 1.0;
    if tilt != 0.0 {
        v[axis + 1] = tilt;
    }
    let s: Vec<String> = v.iter().map(ToString::to_string).collect();
    format!("[{}]", s.join(","))
}

async fn is_current(pool: &PgPool, ids: &[Uuid]) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE id = ANY($1) AND is_current")
        .bind(ids)
        .fetch_one(pool)
        .await
        .expect("count current")
}

async fn pignistic(pool: &PgPool, claim: Uuid) -> Option<f64> {
    sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read pignistic_prob")
}

/// Give `claim` a real binary-frame BBA and cached belief, written as the
/// superuser with a bypass viewer (the claim is group-private, so a public
/// viewer could not address it).
async fn wire_bba(pool: &PgPool, claim: Uuid, agent: Uuid) {
    let (_scoped, bypass) = fixture::bypass(pool).await;
    tools::ds_auto::auto_wire_ds_update(
        pool,
        &bypass,
        claim,
        agent,
        0.9,
        1.0,
        true,
        Some("empirical"),
        None,
    )
    .await
    .expect("auto_wire_ds_update");
}

// ── backfill_embeddings ─────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn backfill_embeddings_embeds_a_group_private_claim(pool: PgPool) {
    assert_claims_are_forced(&pool).await;
    let (agent, group) = fixture::seed_agent_with_group(&pool, "p5-backfill").await;
    let private = fixture::seed_group_claim(
        &pool,
        agent,
        group,
        "p5 backfill: a group-private claim that has no embedding yet",
    )
    .await;

    // A SEALED group-private claim, which must stay unembedded: its content is
    // ciphertext, and a vector derived from the plaintext would be a
    // confidentiality violation (CLAUDE.md's `sealed_with_embedding` audit).
    let sealed = fixture::seed_group_claim(
        &pool,
        agent,
        group,
        "p5 backfill: a group-private claim that is sealed",
    )
    .await;
    sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active')")
        .bind(group)
        .execute(&pool)
        .await
        .expect("seed key epoch");
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', ''::bytea)",
    )
    .bind(sealed)
    .bind(group)
    .execute(&pool)
    .await
    .expect("seal the claim");

    let p = pools(&pool).await;

    // COUNTERFACTUAL: the bypass viewer on the application pool does not even
    // see the private claim as a candidate. A tool that selected on
    // `server.pool` would report zero candidates and succeed.
    {
        let cf = fixture::scoped_pool(&pool).await;
        let session = cf
            .maintenance_session(SystemReason::EmbeddingBackfill)
            .await
            .expect("counterfactual session");
        let seen = ClaimRepository::find_claims_needing_embeddings(&p.app, session.viewer(), 1000)
            .await
            .expect("counterfactual select");
        assert!(
            !seen.iter().any(|(id, _)| *id == private),
            "counterfactual broken: the application pool sees the group-private claim, \
             so this test cannot tell the two pools apart"
        );
    }

    let embedder = McpEmbedder::new(p.app.clone(), Some("stub-key".into()))
        .with_endpoint(embedding_stub().await);
    let client = connect(build_server(&p.app, Some(p.scoped), embedder)).await;
    let body = call(
        &client,
        "backfill_embeddings",
        serde_json::json!({ "limit": 1000, "dry_run": false }),
    )
    .await
    .expect("backfill_embeddings through the router");

    assert!(
        body["embedded"].as_u64().unwrap_or(0) >= 1,
        "backfill must report at least the private claim embedded: {body}"
    );
    let private_embedded: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(private)
            .fetch_one(&pool)
            .await
            .expect("read private embedding");
    assert!(
        private_embedded,
        "the group-private claim must now carry an embedding — the row was MODIFIED \
         on the maintenance connection: {body}"
    );
    let sealed_embedded: bool = sqlx::query_scalar(
        "SELECT embedding IS NOT NULL OR embedding_3072 IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(sealed)
    .fetch_one(&pool)
    .await
    .expect("read sealed embedding");
    assert!(!sealed_embedded, "a sealed claim must never be embedded");
}

// ── recompute_beliefs ───────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn recompute_beliefs_rewrites_a_group_private_claims_cached_belief(pool: PgPool) {
    assert_claims_are_forced(&pool).await;
    let (agent, group) = fixture::seed_agent_with_group(&pool, "p5-recompute").await;
    let claim = fixture::seed_group_claim(
        &pool,
        agent,
        group,
        "p5 recompute: a group-private claim with a BBA",
    )
    .await;
    wire_bba(&pool, claim, agent).await;
    let correct = pignistic(&pool, claim)
        .await
        .expect("wired claim has a BetP");

    // Corrupt the cache to a value the combine path would never produce.
    sqlx::query("UPDATE claims SET pignistic_prob = 0.123 WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("corrupt cache");
    assert!(
        (correct - 0.123).abs() > 1e-6,
        "fixture: 0.123 must be wrong"
    );

    let p = pools(&pool).await;

    // COUNTERFACTUAL: on the application pool the bypass viewer finds no BBA
    // frame for the claim, so a tool reading there would count it as
    // `claims_skipped_no_bba` and write nothing.
    {
        let cf = fixture::scoped_pool(&pool).await;
        let session = cf
            .maintenance_session(SystemReason::BeliefRecomputation)
            .await
            .expect("counterfactual session");
        let frames = MassFunctionRepository::list_frames_for_claim(&p.app, session.viewer(), claim)
            .await
            .expect("counterfactual frames");
        assert!(
            frames.is_empty(),
            "counterfactual broken: the application pool sees the private claim's BBAs"
        );
    }

    let client = connect(build_server(
        &p.app,
        Some(p.scoped),
        McpEmbedder::new(p.app.clone(), None),
    ))
    .await;
    let body = call(
        &client,
        "recompute_beliefs",
        serde_json::json!({ "claim_ids": [claim.to_string()] }),
    )
    .await
    .expect("recompute_beliefs through the router");

    assert_eq!(body["claims_recomputed"], 1, "{body}");
    assert_eq!(body["claims_skipped_no_bba"], 0, "{body}");
    assert!(
        body["errors"].as_array().is_some_and(Vec::is_empty),
        "recompute must not error: {body}"
    );
    let after = pignistic(&pool, claim).await.expect("BetP after recompute");
    assert!(
        (after - correct).abs() < 1e-9,
        "the group-private claim's cached BetP must be rewritten from 0.123 back to \
         {correct} — the row was MODIFIED on the maintenance pool; got {after}"
    );
}

// ── sweep_semantic_duplicates ───────────────────────────────────────────────

/// The DELETE grants `docs/deploy.md` §1c-bis requires of the role behind
/// `MAINTENANCE_DATABASE_URL`, applied to `epigraph_maintenance` in THIS test
/// database only (table privileges are per-database, so nothing leaks).
///
/// This is a DEPLOY PREREQUISITE the schema does not yet provide, not a fixture
/// convenience, and it is measured rather than assumed: retiring a claim fires
/// `claims_deactivate_factors` (migration 001), whose trigger function
/// `DELETE`s from `factors` as the invoking role, and the dedup cascade
/// `DELETE`s `mass_functions` rows for dropped edges. Migration 070 grants
/// `epigraph_maintenance` SELECT/INSERT/UPDATE only, so with stock grants every
/// collapse fails `42501 permission denied for table factors`.
/// `stock_epigraph_maintenance_cannot_yet_retire_a_claim` pins that gap, so the
/// day a migration closes it that test fails and this helper goes with it.
async fn grant_the_maintenance_deletes_deploy_md_requires(pool: &PgPool) {
    sqlx::query("GRANT DELETE ON factors, mass_functions TO epigraph_maintenance")
        .execute(pool)
        .await
        .expect("grant the documented maintenance DELETEs in this test database");
}

/// Two group-private claims with the same words and near-identical vectors.
async fn seed_private_restatement(pool: &PgPool) -> (Uuid, Uuid) {
    // Identical content needs two authors (uq_claims_content_hash_agent); both
    // claims belong to the same group.
    let (a1, group) = fixture::seed_agent_with_group(pool, "p5-dedup-1").await;
    let (a2, _) = fixture::seed_agent_with_group(pool, "p5-dedup-2").await;
    let first = fixture::seed_group_claim(pool, a1, group, "p5 dedup: the same words").await;
    let second = fixture::seed_group_claim(pool, a2, group, "p5 dedup: the same words").await;
    fixture::set_claim_embedding(pool, first, &pgvec(0, 0.0)).await;
    fixture::set_claim_embedding(pool, second, &pgvec(0, 0.001)).await;
    (first, second)
}

fn sweep_args() -> serde_json::Value {
    serde_json::json!({
        "similarity_threshold": 0.10,
        "dry_run": false,
        "limit": 1000,
        "offset": 0,
    })
}

#[sqlx::test(migrations = "../../migrations")]
async fn sweep_semantic_duplicates_collapses_a_group_private_restatement(pool: PgPool) {
    assert_claims_are_forced(&pool).await;
    grant_the_maintenance_deletes_deploy_md_requires(&pool).await;
    let (first, second) = seed_private_restatement(&pool).await;

    let p = pools(&pool).await;

    // COUNTERFACTUAL: the application pool enumerates neither claim, so a sweep
    // that enumerated there would find no pair and collapse nothing.
    {
        let cf = fixture::scoped_pool(&pool).await;
        let session = cf
            .maintenance_session(SystemReason::DedupSweep)
            .await
            .expect("counterfactual session");
        let seen = ClaimRepository::enumerate_current_embedded(
            &p.app,
            session.viewer(),
            None,
            None,
            0,
            1000,
        )
        .await
        .expect("counterfactual enumerate");
        assert!(
            !seen.iter().any(|c| c.id == first || c.id == second),
            "counterfactual broken: the application pool enumerates the private pair"
        );
    }

    let client = connect(build_server(
        &p.app,
        Some(p.scoped),
        McpEmbedder::new(p.app.clone(), None),
    ))
    .await;
    let body = call(&client, "sweep_semantic_duplicates", sweep_args())
        .await
        .expect("sweep_semantic_duplicates through the router");

    assert_eq!(body["pairs_marked"], 1, "{body}");
    assert!(
        body["failures"].as_array().is_some_and(Vec::is_empty),
        "the collapse and its cascade must not fail: {body}"
    );
    assert_eq!(
        is_current(&pool, &[first, second]).await,
        1,
        "exactly one of the private pair must have been retired — the row was \
         MODIFIED on the maintenance pool: {body}"
    );
}

/// PINS A GRANT GAP; does not bless it. With migration 070's stock grants,
/// `epigraph_maintenance` cannot retire a claim: the `claims_deactivate_factors`
/// trigger `DELETE`s from `factors` as the invoking role, and the role holds no
/// DELETE there. The sweep reports the pair in `failures` and changes nothing
/// — loudly, which is the property worth keeping — rather than collapsing it.
///
/// When a migration grants that DELETE (or makes the trigger function
/// `SECURITY DEFINER`), THIS TEST FAILS. Delete it together with
/// `grant_the_maintenance_deletes_deploy_md_requires`, and drop the grants
/// bullet in `docs/deploy.md` §1c-bis.
#[sqlx::test(migrations = "../../migrations")]
async fn stock_epigraph_maintenance_cannot_yet_retire_a_claim(pool: PgPool) {
    let (first, second) = seed_private_restatement(&pool).await;
    let p = pools(&pool).await;
    let client = connect(build_server(
        &p.app,
        Some(p.scoped),
        McpEmbedder::new(p.app.clone(), None),
    ))
    .await;
    let body = call(&client, "sweep_semantic_duplicates", sweep_args())
        .await
        .expect("the sweep itself succeeds and reports the per-pair failure");

    assert_eq!(body["pairs_marked"], 0, "{body}");
    let failures = body["failures"].to_string();
    assert!(
        failures.contains("permission denied for table factors"),
        "the stock-grant failure must be the factors DELETE; if this changed, \
         re-measure what the maintenance role lacks: {body}"
    );
    assert_eq!(
        is_current(&pool, &[first, second]).await,
        2,
        "a refused collapse must leave both claims current"
    );
}

// ── who reaches the bypass: the HTTP scope gate ─────────────────────────────

const JWT_SECRET: &[u8] = b"maintenance-scope-gate-test-secret-at-least-32-bytes";

/// A Bearer token this file's HTTP server accepts, carrying exactly `scopes`
/// and no agent principal (none of the three maintenance tools resolves one).
fn bearer(scopes: &[&str]) -> String {
    epigraph_auth::JwtConfig::from_secret(JWT_SECRET)
        .issue_access_token(
            Uuid::new_v4(),
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "service",
            None,
            None,
            chrono::Duration::minutes(5),
        )
        .expect("mint bearer token")
        .0
}

/// Serve the real router over streamable HTTP behind `bearer_auth_middleware`,
/// with every per-session server carrying `scoped` as `main.rs`'s
/// `with_maintenance` attaches it. Returns the `/mcp` URL.
async fn serve_http(app: &PgPool, scoped: ScopedPool, embedder: McpEmbedder) -> String {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::sync::Arc;

    let pool = app.clone();
    let signer = Arc::new(AgentSigner::from_bytes(&[0x5au8; 32]).expect("signer"));
    let embedder = Arc::new(embedder);
    let service = StreamableHttpService::new(
        move || {
            Ok(
                EpiGraphMcpFull::new_shared(pool.clone(), signer.clone(), embedder.clone(), false)
                    .with_scoped_pool(scoped.clone()),
            )
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let auth = epigraph_mcp::auth::McpAuthState {
        jwt_config: Arc::new(epigraph_auth::JwtConfig::from_secret(JWT_SECRET)),
        resource_metadata_url: None,
    };
    let router = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn_with_state(auth, epigraph_mcp::auth::bearer_auth_middleware),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind MCP HTTP listener");
    let addr = listener.local_addr().expect("listener addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{addr}/mcp")
}

/// An MCP client presenting `token` as its Bearer on every request.
async fn connect_http(url: &str, token: &str) -> RunningService<RoleClient, ()> {
    use rmcp::transport::streamable_http_client::{
        StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
    };
    let mut config =
        StreamableHttpClientTransportConfig::with_uri(std::sync::Arc::<str>::from(url));
    config.auth_header = Some(token.to_string());
    ().serve(StreamableHttpClientTransport::<reqwest::Client>::from_config(config))
        .await
        .expect("MCP client handshake over HTTP")
}

async fn has_embedding(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read embedding presence")
}

/// WHO REACHES THE BYPASS. `main.rs` attaches the maintenance pool to every
/// per-session HTTP server, so on HTTP a maintenance tool's `SCOPE_MAP` entry is
/// the only thing between a token and every tenant's rows. The tests above use
/// the stdio shape and cannot show which scope gets through; this one serves the
/// real router behind `bearer_auth_middleware`, pool attached as `main.rs`
/// attaches it.
///
/// One server, one fixture, two tokens — the token is the only variable:
///
/// * `claims:read` + `claims:write`: all three tools are refused with the scope
///   error, the refusal names none of the private claims, and every private row
///   is what it was. The fixture is ARMED so a regression is visible rather
///   than inferred: the maintenance DELETE grants are applied and the sweep runs
///   with `dry_run=false`, so a `claims:write` gate would retire one of the
///   pair, rewrite the belief and embed the claim — MEASURED by mapping the
///   three tools back to `claims:write`, which fails this test at the first
///   refusal it expects.
/// * `claims:admin`: the same calls on the same server modify each row, which
///   proves the refusals above are the scope gate and not a server that cannot
///   reach its maintenance pool.
#[sqlx::test(migrations = "../../migrations")]
async fn over_http_only_a_claims_admin_token_reaches_the_maintenance_bypass(pool: PgPool) {
    assert_claims_are_forced(&pool).await;
    grant_the_maintenance_deletes_deploy_md_requires(&pool).await;

    let (agent, group) = fixture::seed_agent_with_group(&pool, "p5-http-scope").await;
    let unembedded = fixture::seed_group_claim(
        &pool,
        agent,
        group,
        "p5 http scope: a group-private claim with no embedding",
    )
    .await;
    let believed = fixture::seed_group_claim(
        &pool,
        agent,
        group,
        "p5 http scope: a group-private claim with a BBA",
    )
    .await;
    wire_bba(&pool, believed, agent).await;
    let correct = pignistic(&pool, believed)
        .await
        .expect("wired claim has a BetP");
    sqlx::query("UPDATE claims SET pignistic_prob = 0.123 WHERE id = $1")
        .bind(believed)
        .execute(&pool)
        .await
        .expect("corrupt cache");
    assert!(
        (correct - 0.123).abs() > 1e-6,
        "fixture: 0.123 must be wrong"
    );
    let (first, second) = seed_private_restatement(&pool).await;
    let private = [unembedded, believed, first, second];

    let p = pools(&pool).await;
    let embedder = McpEmbedder::new(p.app.clone(), Some("stub-key".into()))
        .with_endpoint(embedding_stub().await);
    let url = serve_http(&p.app, p.scoped, embedder).await;

    let calls = [
        ("sweep_semantic_duplicates", sweep_args()),
        (
            "recompute_beliefs",
            serde_json::json!({ "claim_ids": [believed.to_string()] }),
        ),
        (
            "backfill_embeddings",
            serde_json::json!({ "limit": 1000, "dry_run": false }),
        ),
    ];

    // ── claims:write: refused, and nothing moved ──
    let writer = connect_http(&url, &bearer(&["claims:read", "claims:write"])).await;
    for (tool, args) in calls {
        let err = call(&writer, tool, args)
            .await
            .expect_err("a claims:write token must not reach a maintenance bypass");
        assert!(
            err.contains(&format!("tool '{tool}' requires scope 'claims:admin'")),
            "{tool}: the refusal must be the scope gate naming claims:admin; got {err}"
        );
        for id in private {
            assert!(
                !err.contains(&id.to_string()),
                "{tool}: the refusal leaked private claim {id}: {err}"
            );
        }
    }
    assert_eq!(
        is_current(&pool, &[first, second]).await,
        2,
        "a refused sweep must leave the private pair current"
    );
    let still_corrupt = pignistic(&pool, believed).await.expect("BetP");
    assert!(
        (still_corrupt - 0.123).abs() < 1e-9,
        "a refused recompute must not rewrite the private belief; got {still_corrupt}"
    );
    assert!(
        !has_embedding(&pool, unembedded).await,
        "a refused backfill must not embed the private claim"
    );

    // ── claims:admin: the same calls modify every private row ──
    // Sweep first: once the backfill has run, `unembedded` and `believed` share
    // the stub's vector and would join the sweep's candidate set.
    let admin = connect_http(&url, &bearer(&["claims:admin"])).await;
    let swept = call(&admin, "sweep_semantic_duplicates", sweep_args())
        .await
        .expect("claims:admin reaches sweep_semantic_duplicates");
    assert_eq!(swept["pairs_marked"], 1, "{swept}");
    assert_eq!(
        is_current(&pool, &[first, second]).await,
        1,
        "the admin sweep must retire one of the private pair: {swept}"
    );
    let recomputed = call(
        &admin,
        "recompute_beliefs",
        serde_json::json!({ "claim_ids": [believed.to_string()] }),
    )
    .await
    .expect("claims:admin reaches recompute_beliefs");
    assert_eq!(recomputed["claims_recomputed"], 1, "{recomputed}");
    let rewritten = pignistic(&pool, believed).await.expect("BetP");
    assert!(
        (rewritten - correct).abs() < 1e-9,
        "the admin recompute must rewrite the private belief to {correct}; got {rewritten}"
    );
    let backfilled = call(
        &admin,
        "backfill_embeddings",
        serde_json::json!({ "limit": 1000, "dry_run": false }),
    )
    .await
    .expect("claims:admin reaches backfill_embeddings");
    assert!(
        has_embedding(&pool, unembedded).await,
        "the admin backfill must embed the private claim: {backfilled}"
    );
}

// ── fail-closed without a ScopedPool ────────────────────────────────────────

/// A server that was never given a `ScopedPool` cannot mint a maintenance lease,
/// so all three tools refuse — through the router, with the error naming the
/// constructor — rather than running on the application pool.
#[sqlx::test(migrations = "../../migrations")]
async fn without_a_scoped_pool_every_maintenance_tool_fails_closed(pool: PgPool) {
    let p = pools(&pool).await;
    let client = connect(build_server(
        &p.app,
        None,
        McpEmbedder::new(p.app.clone(), None),
    ))
    .await;

    for (tool, args) in [
        (
            "backfill_embeddings",
            serde_json::json!({ "dry_run": true }),
        ),
        ("recompute_beliefs", serde_json::json!({ "limit": 1 })),
        (
            "sweep_semantic_duplicates",
            serde_json::json!({ "dry_run": true }),
        ),
    ] {
        let err = call(&client, tool, args)
            .await
            .expect_err("a server without a ScopedPool must refuse maintenance tools");
        assert!(
            err.contains("ScopedPool"),
            "{tool}: the refusal must name the missing ScopedPool; got {err}"
        );
    }
}

// ── the connection budget ───────────────────────────────────────────────────

/// While MORE maintenance calls are in flight than the gate admits, a pool of
/// exactly `MAINTENANCE_POOL_CONNECTIONS` still has a free connection, and
/// every call completes.
///
/// That free connection is the slot `sweep_semantic_duplicates` and
/// `recompute_beliefs` borrow one statement at a time through
/// `MaintenanceSession::pool` while holding their session. If admitted calls
/// could pin the whole pool, those borrows would wait out the acquire timeout
/// once per claim or pair — hours across a 2000-item page.
///
/// DETERMINISTIC ON PURPOSE. `backfill_embeddings` keeps its session pinned
/// across provider round trips (by design), so against a provider stub that
/// answers slowly each call holds one connection for seconds. Without the gate
/// in `maintenance::maintenance_viewer`, `MAINTENANCE_POOL_CONNECTIONS` of these
/// calls pin the whole pool: the probe below and the next call's session
/// acquire both wait out the 3 s acquire timeout. A first version of this test
/// drove fast `recompute_beliefs` calls and relied on them overlapping; widening
/// the gate to 64 left it green, so it proved nothing and was replaced.
#[sqlx::test(migrations = "../../migrations")]
async fn in_flight_maintenance_calls_never_pin_the_whole_budgeted_pool(pool: PgPool) {
    const CALLS: usize = MAINTENANCE_TOOL_CONCURRENCY + 2;
    const PROVIDER_DELAY: Duration = Duration::from_millis(1500);
    const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(3);

    let (agent, _group) = fixture::seed_agent_with_group(&pool, "p5-budget").await;
    for i in 0..4 {
        fixture::seed_public_claim(&pool, agent, &format!("p5 budget claim {i}")).await;
    }

    // Sized EXACTLY as `main` sizes it, with a short acquire timeout so a
    // starved checkout fails the test in seconds instead of stalling it.
    let url = fixture::database_url_for(&pool).await;
    let maint = sqlx::postgres::PgPoolOptions::new()
        .max_connections(MAINTENANCE_POOL_CONNECTIONS)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect(&url)
        .await
        .expect("budget-sized maintenance pool");
    let scoped = fixture::scoped_pool(&pool)
        .await
        .with_maintenance_pool(maint.clone());
    let embedder = McpEmbedder::new(pool.clone(), Some("stub-key".into()))
        .with_endpoint(embedding_stub_with_delay(PROVIDER_DELAY).await);
    let server = build_server(&pool, Some(scoped), embedder);

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..CALLS {
        let server = server.clone();
        set.spawn(async move {
            let client = connect(server).await;
            call(
                &client,
                "backfill_embeddings",
                serde_json::json!({ "limit": 4, "dry_run": false }),
            )
            .await
        });
    }

    // Let every call reach its session (or the gate), then probe.
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let asked = std::time::Instant::now();
    let probe = maint.acquire().await.expect(
        "with more maintenance calls in flight than the gate admits, a pool of \
         MAINTENANCE_POOL_CONNECTIONS must still have a free connection",
    );
    assert!(
        asked.elapsed() < Duration::from_secs(1),
        "the free slot must be free now, not after a call finishes ({:?})",
        asked.elapsed()
    );
    drop(probe);

    let mut done = 0;
    while let Some(joined) = set.join_next().await {
        let body = joined
            .expect("task")
            .expect("no maintenance call may fail to acquire its session");
        assert_eq!(body["failed"], 0, "{body}");
        done += 1;
    }
    assert_eq!(done, CALLS);
}
