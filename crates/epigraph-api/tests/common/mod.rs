use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn spawn_app(database_url: &str) -> (SocketAddr, oneshot::Sender<()>) {
    let app = epigraph_api::build_app_for_tests(database_url)
        .await
        .expect("app builds for tests");
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
    (addr, tx)
}

/// [`spawn_app`] with a caller-chosen webhook-registration egress guard, for
/// tests that need particular DNS answers (a name that resolves to loopback,
/// one that does not resolve). No real DNS: pass a guard over a `StubResolver`.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: only the webhook policy binary uses it"
)]
pub async fn spawn_app_with_webhook_egress(
    database_url: &str,
    webhook_egress: epigraph_jobs::egress::EgressGuard,
) -> (SocketAddr, oneshot::Sender<()>) {
    let app = epigraph_api::build_app_for_tests_with_webhook_egress(database_url, webhook_egress)
        .await
        .expect("app builds for tests");
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
    (addr, tx)
}

/// Spawn the test app with a `MockProvider` embedding service injected.
///
/// Mirrors `epigraph_api::build_app_for_tests` (lib.rs) but inserts a
/// deterministic embedding provider into `AppState` so handlers that call
/// `state.embedding_service()` get a real provider instead of `None`.
///
/// Use this for tests of routes like `POST /api/v1/embeddings/neighborhood-density`
/// whose handler returns 500 when no embedding service is configured.
///
/// # "Mirrors" is load-bearing, and conversion shard 4 nearly broke it
///
/// That sentence was a plain fact while both fixtures built `PgPoolOptions` +
/// `AppState::with_db`. Shard 4 moved `build_app_for_tests` onto
/// `ScopedPool::connect_with_options` + `AppState::with_scoped_pool`, because a
/// handler converted onto `AppState::read_as` REFUSES when `AppState.scoped` is
/// `None` rather than falling back to the raw pool. Left alone, this helper
/// would have kept `scoped` at `None` and the two fixtures would have differed
/// on the one property that decides whether a converted route answers at all —
/// with this doc still asserting they do not.
///
/// Nothing was failing: its three consumers reach hypothesis, cluster and
/// embedding routes, none of which any shard has converted. That is what makes
/// it a trap rather than a bug — the next shard to convert a route reachable
/// from here would have got a 500 whose cause is three files away, which is the
/// failure the ledger already records verbatim against PR-29's
/// `call_diverse_search`. So the construction is mirrored instead, pinned to
/// the same `SessionGucMode::Session` and the same 4 connections, and the
/// sentence above is true again rather than merely old.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn spawn_app_with_mock_embedding(
    database_url: &str,
) -> (SocketAddr, oneshot::Sender<()>) {
    use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
    use std::sync::Arc;

    let scoped = epigraph_db::ScopedPool::connect_with_options(
        database_url,
        epigraph_db::SessionGucMode::Session,
        epigraph_db::ScopedPoolOptions {
            max_connections: 4,
            ..Default::default()
        },
    )
    .await
    .expect("db connect");
    let provider = MockProvider::new(EmbeddingConfig::openai(1536));
    let svc: Arc<dyn EmbeddingService> = Arc::new(provider);
    let state =
        epigraph_api::AppState::with_scoped_pool(scoped, epigraph_api::ApiConfig::default())
            .with_embedding_service(svc);
    let app = epigraph_api::routes::create_router(state);
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
    (addr, tx)
}

/// Returns a real signed JWT that the production bearer_auth_middleware will accept.
/// Uses the same secret-fallback logic as `AppState::default_jwt_config`.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub fn test_bearer_token() -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    // PR-02 binds every authenticated principal to an `agents.id`; PR-06's
    // `ViewerExtractor` refuses an agentless token with 401 before the handler.
    let principal = uuid::Uuid::new_v4();
    let (token, _jti) = cfg
        .issue_access_token(
            principal,
            vec!["graph:read".into()],
            "service",
            Some(principal),
            Some(principal),
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    token
}

#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
/// Seed exactly one cluster run holding one cluster of `size` members.
///
/// # It no longer truncates, and it must not
///
/// This helper used to open with unfiltered `DELETE`s against
/// `graph_cluster_runs`, `claim_cluster_membership`, `graph_clusters` and
/// `cluster_edges`. That was how its only caller manufactured "exactly one run
/// exists" on a database shared with every other test binary — the root cause
/// of F-tests-depend-on-accumulated-shared-db-fixtures, since it destroyed
/// sibling binaries' fixtures as a side effect of seeding its own.
///
/// Its caller (`graph_routes_test.rs`, the sole one — grep before adding
/// another) now runs under `#[sqlx::test]`, so the database is already empty
/// and the truncation would delete nothing. Re-adding it would reintroduce the
/// finding the moment any caller runs on a shared pool.
pub async fn seed_one_cluster(pool: &PgPool, size: usize) -> uuid::Uuid {
    let test_agent_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000aa").unwrap();
    // public_key is unique across all agents — must differ per test binary.
    // 00...AA distinguishes graph_routes_test from graph_themes_test (00...BB)
    // and graph_neighborhoods_test (00...CC). Retained deliberately: the
    // collision it guards against is impossible on a per-test database, but the
    // constant is load-bearing for any caller still on a shared pool.
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type)
         VALUES ($1, decode(repeat('AA', 32), 'hex'), 'graph-routes-test', 'system')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(test_agent_id)
    .execute(pool)
    .await
    .unwrap();

    let run_id = uuid::Uuid::new_v4();
    let cluster_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO graph_clusters (id, run_id, label, size, mean_betp, dominant_type, dominant_frame_id, degraded) VALUES ($1, $2, 'C', $3, 0.5, 'claim', NULL, FALSE)")
        .bind(cluster_id).bind(run_id).bind(size as i32).execute(pool).await.unwrap();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 1, FALSE)",
    )
    .bind(run_id)
    .execute(pool)
    .await
    .unwrap();
    for _ in 0..size {
        let claim_id = uuid::Uuid::new_v4();
        // Derive content_hash from claim_id so each call produces unique hashes.
        // Tests share a Postgres DB; fixed hashes would hit ON CONFLICT from
        // earlier seedings and orphan the membership row → undercount.
        let hash: Vec<u8> = claim_id
            .as_bytes()
            .iter()
            .chain(claim_id.as_bytes().iter())
            .copied()
            .collect();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, pignistic_prob)
             VALUES ($1, 'x', $2, $3, 0.5)
             ON CONFLICT DO NOTHING",
        )
        .bind(claim_id)
        .bind(hash)
        .bind(test_agent_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) VALUES ($1, $2, $3)")
            .bind(claim_id).bind(cluster_id).bind(run_id)
            .execute(pool).await.unwrap();
    }
    cluster_id
}

/// Issue a JWT with caller-specified scopes. evolve_step / dedup / patch_claim
/// require `claims:write`; the existing test_bearer_token() issues only graph:read.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub fn test_bearer_token_with_scopes(scopes: &[&str]) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    // PR-02 made every authenticated principal carry an `agents.id`, and PR-06's
    // `ViewerExtractor` rejects an agentless token with 401 before any scope gate
    // runs. Minting with `agent_id: None` therefore produced a token shape no real
    // client can hold any more, and every scope test using it asserted 403 while
    // receiving 401. Bind the token to a principal, mirroring what
    // `AgentRepository::ensure_for_client` does in production.
    let principal = Uuid::new_v4();
    let (token, _jti) = cfg
        .issue_access_token(
            principal,
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "service",
            Some(principal),
            Some(principal),
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    token
}

/// Insert a system agent with a unique 32-byte public_key.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn seed_system_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed system agent");
    id
}

/// Insert an edge directly via SQL. Returns the generated edge id.
/// Used by tests that need to seed edge fixtures without going through
/// the HTTP edges route (e.g., tests of unique indexes, view closures,
/// or relationships not yet exposed by the public API).
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn insert_edge(
    pool: &PgPool,
    source_id: Uuid,
    target_id: Uuid,
    source_type: &str,
    target_type: &str,
    relationship: &str,
) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(source_id)
    .bind(target_id)
    .bind(source_type)
    .bind(target_type)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("insert edge");
    id
}

/// Insert a minimal claim with per-call unique content_hash.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn seed_claim(pool: &PgPool, content: &str) -> Uuid {
    let agent = seed_system_agent(pool).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// Insert a claim whose `agent_id` is the given UUID.
/// Also inserts an `agents` row for that UUID so the FK is satisfied.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn seed_claim_with_agent(pool: &PgPool, content: &str, agent_id: Uuid) -> Uuid {
    // Ensure the agent row exists (may already exist from a previous call).
    let pk: Vec<u8> = agent_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent for claim");

    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim with agent");
    id
}

/// Like [`seed_claim_with_agent`], but the claim also carries a unique
/// `properties` key so a Cypher `WHERE` can select exactly this row.
///
/// `POST /api/v1/graph/query` compiles an unknown property in a `WHERE` clause
/// to `properties->>'<name>' = $n` (`routes/graph_query.rs`), and it has no
/// other way to address one specific claim: `n.id` would compile to
/// `properties->>'id'`, and the node-selection SQL is
/// `SELECT id FROM claims <where> LIMIT <n>` with **no `ORDER BY`**. A test that
/// matches all claims and hopes its seeded row lands inside the window is a
/// test that fails once the shared database grows past the limit — which is
/// what happened at 2500+ claims against `LIMIT 1000`.
///
/// Returns `(claim_id, probe_value)`; query with
/// `MATCH (n:claim) WHERE n.probe = '<probe_value>' RETURN *`.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn seed_probe_claim_with_agent(
    pool: &PgPool,
    content: &str,
    agent_id: Uuid,
) -> (Uuid, String) {
    let claim_id = seed_claim_with_agent(pool, content, agent_id).await;
    let probe = Uuid::new_v4().to_string();
    sqlx::query(
        "UPDATE claims SET properties = jsonb_build_object('probe', $1::text) WHERE id = $2",
    )
    .bind(&probe)
    .bind(claim_id)
    .execute(pool)
    .await
    .expect("set probe property");
    (claim_id, probe)
}

/// Insert a claim with explicit labels.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn seed_claim_with_labels(pool: &PgPool, content: &str, labels: &[&str]) -> Uuid {
    let id = seed_claim(pool, content).await;
    let labels_owned: Vec<String> = labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query("UPDATE claims SET labels = $1 WHERE id = $2")
        .bind(&labels_owned)
        .bind(id)
        .execute(pool)
        .await
        .expect("set labels");
    id
}

/// Seed an oauth_clients row matching client_id (provenance_log.submitted_by FK).
/// Real schema: id, client_id varchar(64), client_secret_hash bytea (nullable),
/// client_name, client_type, allowed_scopes text[], granted_scopes text[], status.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn seed_oauth_client(pool: &PgPool, client_id: Uuid) {
    sqlx::query(
        "INSERT INTO oauth_clients (id, client_id, client_name, client_type, legal_entity_name, legal_contact_email, allowed_scopes, granted_scopes, status) \
         VALUES ($1, $2, 'test', 'service', 'Test Entity', 'test@example.com', ARRAY['claims:write','claims:read','graph:read','edges:write']::text[], ARRAY['claims:write','claims:read','graph:read','edges:write']::text[], 'active') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(client_id)
    .bind(client_id.to_string())
    .execute(pool)
    .await
    .expect("seed oauth_client");
}

/// Issue a JWT bound to a real seeded oauth_clients row so provenance writes
/// don't violate the FK. Returns (token, client_id).
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn test_bearer_token_with_seeded_client(
    pool: &PgPool,
    scopes: &[&str],
) -> (String, Uuid) {
    let client_id = Uuid::new_v4();
    seed_oauth_client(pool, client_id).await;
    // PR-02 links every oauth client to an `agents` row, and PR-06's
    // `ViewerExtractor` 401s a token whose `agent_id` is absent. Production mints
    // through `AgentRepository::ensure_for_client`; mirror it here so the fixture
    // reflects a post-PR-02 client rather than a shape no real client can hold.
    let mut conn = pool.acquire().await.expect("acquire conn");
    let agent_id = epigraph_db::AgentRepository::ensure_for_client(&mut conn, client_id)
        .await
        .expect("ensure agent for seeded client");
    drop(conn);
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _jti) = cfg
        .issue_access_token(
            client_id,
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "service",
            Some(client_id),
            Some(agent_id.as_uuid()),
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    (token, client_id)
}

/// Like [`test_bearer_token_with_seeded_client`], but the JWT also carries a
/// non-null `agent_id` claim.
///
/// PR-03 makes this the shape a write path needs. `POST /api/v1/claims` used to
/// resolve the author's public key through a fallback chain that ended in
/// `[0u8; 32]` when the token named no principal; that chain is deleted and a
/// principal-less token is now 401 `invalid_token`. `agent_id` must name a row
/// in `agents` — a token naming a nonexistent agent is also 401, deliberately,
/// rather than the zero key it used to produce.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn test_bearer_token_with_seeded_client_for_agent(
    pool: &PgPool,
    scopes: &[&str],
    agent_id: Uuid,
) -> (String, Uuid) {
    let client_id = Uuid::new_v4();
    seed_oauth_client(pool, client_id).await;
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _jti) = cfg
        .issue_access_token(
            client_id,
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "service",
            None,
            Some(agent_id),
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    (token, client_id)
}

/// Mint a real JWT whose `agent_id` claim equals `agent_id`. Used by A3
/// read-path tests to produce OWNER (agent_id == ownership.owner_id) and
/// STRANGER (random agent_id) tokens. The production
/// optional_bearer_auth_middleware accepts the token and injects it as
/// `AuthContext`; `ViewerExtractor` resolves the `Viewer` from
/// `auth_ctx.agent_id`, NOT from the query-string `agent_id`, so this token —
/// and only this token — drives the OWNER (row visible) vs STRANGER (row
/// absent) distinction. Before PR-14 the same token drove a Full-vs-Redacted
/// distinction in a post-fetch pass; the pass is gone and the decision is now
/// made by the read itself.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub fn mint_token_with_agent(scopes: &[&str], agent_id: Uuid) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "agent",
            None,
            Some(agent_id),
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    token
}

/// Ensure `frames.properties` (JSONB) exists in the test database.
///
/// `migrations/044_frames_properties.sql` adds this column, and
/// `FrameRepository::get_by_id` (called by `frame_claims_sorted` to verify the
/// frame exists) SELECTs it on every read. The shared `epigraph_db_repo_test`
/// DB may predate migration 044, so without the column `get_by_id` errors →
/// HTTP 500 *before* the handler reaches the visibility-filtered read — silently
/// turning the A3 `frame_claims_sorted` regression guard RED. `IF NOT EXISTS`
/// makes it a no-op on a DB where 044 has already run.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn ensure_frame_properties_column(pool: &PgPool) {
    sqlx::query(
        "ALTER TABLE frames ADD COLUMN IF NOT EXISTS properties JSONB NOT NULL DEFAULT '{}'::jsonb",
    )
    .execute(pool)
    .await
    .expect("ensure frames.properties column");
}

/// Create a frame (≥2 hypotheses, per the `frames_not_empty` CHECK) and assign
/// `claim_id` to it via `claim_frames`. Returns the new frame's id. Used by the
/// A3 `frame_claims_sorted` (`GET /api/v1/frames/:id/claims`) tests: that handler
/// 404s on a missing frame and JOINs `claim_frames cf JOIN claims c`, so the
/// claim must be in the frame for it to appear in the page at all. Scoping the
/// query to a fresh per-test frame also makes the seeded claim the only row,
/// avoiding paging flakiness on the shared test DB.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn seed_frame_with_claim(pool: &PgPool, claim_id: Uuid) -> Uuid {
    let frame_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO frames (id, name, hypotheses) \
         VALUES ($1, $2, ARRAY['h0','h1']::text[])",
    )
    .bind(frame_id)
    .bind(format!("a3-test-frame-{frame_id}"))
    .execute(pool)
    .await
    .expect("seed frame");

    sqlx::query("INSERT INTO claim_frames (claim_id, frame_id) VALUES ($1, $2)")
        .bind(claim_id)
        .bind(frame_id)
        .execute(pool)
        .await
        .expect("assign claim to frame");
    frame_id
}

/// Resolve `owner_id`'s personal group, minting it and the owner's membership
/// if it does not exist.
///
/// The `ownership` fixtures below used to reach this shape indirectly: they
/// wrote an `ownership` row and migration 071's `ownership_transcribe` trigger
/// resolved-or-minted the personal group and stamped the claim. PR-22 retires
/// that table, so the fixtures do the two halves themselves and this is the
/// first — copied from 071's fallback arm, including the reasons:
///
/// * **Two ways to identify a personal group, and both are needed.** The
///   canonical one is `ensure_personal_group`'s deterministic
///   `did:epigraph:personal:<agent uuid>` key, but the semantics are
///   `kind = 'personal'` created by this agent, and every copy of
///   `tests/viewer_fixture.rs::seed_agent_with_group` mints one under a
///   `did:epigraph:test:` key instead. Matching only the did_key would mint a
///   SECOND personal group for an agent that already has one.
/// * **The membership is not optional and the conflict target is the
///   composite.** An untargeted `DO NOTHING` silently no-ops against a revoked
///   row, leaving the agent with no live membership in its own personal group,
///   permanently.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn personal_group_of(pool: &PgPool, owner_id: Uuid) -> Uuid {
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM groups \
          WHERE (did_key = 'did:epigraph:personal:' || $1::text) \
             OR (kind = 'personal' AND created_by_agent_id = $1) \
          ORDER BY (did_key = 'did:epigraph:personal:' || $1::text) DESC, created_at ASC \
          LIMIT 1",
    )
    .bind(owner_id)
    .fetch_optional(pool)
    .await
    .expect("resolve personal group");

    let group = match existing {
        Some(g) => g,
        None => sqlx::query_scalar(
            "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
             VALUES ('personal:' || $1::text, 'did:epigraph:personal:' || $1::text, \
                     ''::bytea, 'personal', $1) \
             ON CONFLICT (did_key) DO UPDATE SET updated_at = now() RETURNING id",
        )
        .bind(owner_id)
        .fetch_one(pool)
        .await
        .expect("mint personal group"),
    };

    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin') \
         ON CONFLICT (group_id, agent_id, epoch) \
         DO UPDATE SET revoked_at = NULL, role = 'admin'",
    )
    .bind(group)
    .bind(owner_id)
    .execute(pool)
    .await
    .expect("revive personal group membership");

    group
}

/// Stamp `claim_id` `('group', group_id)` and CHECK that it landed.
///
/// The read-back is the reason this is a function rather than three inlined
/// UPDATEs. `read_path_authz_test.rs` runs sixteen authorization tests through
/// the two fixtures below; a fixture that silently stamped the wrong visibility
/// would leave every one of them green while testing nothing, because they all
/// assert that a stranger sees LESS. Asserting the post-condition here is what
/// makes "the stranger saw nothing" mean "the row was private".
async fn stamp_group_private(pool: &PgPool, claim_id: Uuid, group_id: Uuid) {
    sqlx::query("UPDATE claims SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(claim_id)
        .bind(group_id)
        .execute(pool)
        .await
        .expect("stamp the claim group-private");

    let got: Option<(String, Uuid)> =
        sqlx::query_as("SELECT visibility, owner_group_id FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_optional(pool)
            .await
            .expect("read the stamped claim back");
    assert_eq!(
        got,
        Some(("group".to_string(), group_id)),
        "the fixture must leave claim {claim_id} at ('group', {group_id}); a \
         mis-stamped fixture makes every 'a stranger sees nothing' assertion \
         vacuous"
    );
}

/// Make claim `node_id` readable only by `owner_id`'s personal group.
///
/// **This wrote an `ownership` row until PR-22, and what that row DID changed
/// twice before it was retired.** Until PR-12 it was consulted only by
/// `check_content_access`, which returned Full to `owner_id` and Redacted to
/// everyone else while `claims.visibility` stayed `'public'`. Migration 071 made
/// the write a WRITE-THROUGH: the `ownership_transcribe` trigger stamped the
/// claim's tenancy columns to `('group', <owner's personal group>)` in the same
/// statement, and PR-14 deleted `check_content_access`, so the trigger's effect
/// became the whole mechanism. Migration 084 then retired the table, and this
/// fixture writes the tenancy columns the trigger used to write — the same end
/// state, one indirection fewer.
///
/// Read it as: this seeds a row that `owner_id`'s `Viewer` admits and a
/// stranger's `Viewer` excludes.
///
/// Create the claim first with `seed_claim_with_agent(pool, content, owner_id)`
/// so the owner agent row exists.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn seed_private_ownership(pool: &PgPool, node_id: Uuid, owner_id: Uuid) {
    let group = personal_group_of(pool, owner_id).await;
    stamp_group_private(pool, node_id, group).await;
}

/// Make claim `node_id` readable by `community_id`'s projected group, falling
/// back to `owner_id`'s personal group when no community resolves.
///
/// The counterpart to [`seed_private_ownership`] for the arm that, until PR-05,
/// NO test in this repository exercised — every fixture in the suite wrote
/// `'private'`. Pass `None` for `community_id` to reach the owner-only fallback.
///
/// # The three arms are migration 071's, not new policy
///
/// The `ownership_transcribe` trigger this replaces resolved a
/// `partition_type = 'community'` row in exactly this order, and the ordering is
/// a reviewed decision in each case:
///
/// * a community that resolves AND whose projected group has a live member
///   stamps `('group', community_id)` — the projection is ID-preserving
///   (migration 068), so a community's group id IS its community id;
/// * a community with no projectable member falls back to the owner's personal
///   group rather than stamping a group nobody is in, which would make the node
///   unreadable by everyone including its owner;
/// * a NULL or dangling `community_id` is a legacy shape, not an error path, and
///   also falls back — fail-closed, still `'group'`, still not public.
///
/// **The owner is deliberately NOT added to the community group.** On the
/// community arm, ownership alone does not grant access once a community
/// resolves; membership is the whole test. 071 says so at length and names the
/// assertion that states it.
///
/// # PR-22: ONLY THE FIRST ARM HAS A CALLER, AND THAT IS A KNOWN GAP
///
/// This helper hand-writes 071's resolution because PR-22 retires the trigger
/// that used to perform it. The two FALLBACK arms are therefore newly written
/// code with **no caller in this crate**: the sole call site,
/// `read_path_authz_test.rs::get_claim_community_member_sees_content_and_outsider_does_not`,
/// passes `Some(community)` with a live member and takes arm one.
///
/// The arms were inherited from
/// `tenancy_triggers.rs::an_empty_community_falls_back_to_the_owner_rather_than_a_black_hole`
/// and `::a_dangling_community_reference_falls_back_to_the_owner_not_a_raise`,
/// which were the only executable statements of that behaviour anywhere in the
/// tree and which PR-22 deletes with the shim. Do not read their absence as
/// evidence the fallbacks are covered — they are not, and
/// [`stamp_group_private`]'s read-back cannot discriminate WHICH arm ran,
/// because it asserts against whatever group the resolver just returned. In the
/// one live test the member-sees-200 assertion does discriminate, so nothing is
/// green-but-vacuous today; the discrimination just lives in the caller by luck
/// rather than in this fixture by design. Tracked as a follow-up.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn seed_community_ownership(
    pool: &PgPool,
    node_id: Uuid,
    owner_id: Uuid,
    community_id: Option<Uuid>,
) {
    let resolved: Option<Uuid> = match community_id {
        None => None,
        Some(c) => sqlx::query_scalar(
            "SELECT g.id FROM groups g \
              WHERE g.id = $1 AND g.kind = 'community' \
                AND EXISTS (SELECT 1 FROM group_memberships m \
                             WHERE m.group_id = g.id AND m.revoked_at IS NULL)",
        )
        .bind(c)
        .fetch_optional(pool)
        .await
        .expect("resolve the projected community group"),
    };

    let group = match resolved {
        Some(g) => g,
        None => personal_group_of(pool, owner_id).await,
    };
    stamp_group_private(pool, node_id, group).await;
}

/// Create a community and put `agent` in it the ONLY way the community
/// projection recognises: via a perspective the agent owns.
///
/// The community arm is a two-hop join — `community_members ⋈ perspectives ON
/// p.owner_agent_id` — not a direct agent membership table. This was
/// `check_content_access`'s join until PR-14 deleted it; PR-12's community
/// projection (which feeds `Viewer::resolve`'s group set) uses the same two
/// hops, so the fixture's shape is unchanged and its reason is not. A fixture
/// that
/// inserted a `community_members` row without an owning perspective would
/// produce a community the agent is "in" and still cannot read from.
///
/// Returns the community id, for [`seed_community_ownership`]'s `community_id`.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn seed_community_with_member(pool: &PgPool, agent_id: Uuid) -> Uuid {
    // `agents.public_key` is UNIQUE and length-checked; derive 32 bytes from
    // the id so repeated calls for the same agent are idempotent.
    let pk: Vec<u8> = agent_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) \
         VALUES ($1, $2, 'system') ON CONFLICT (id) DO NOTHING",
    )
    .bind(agent_id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent for community member");

    // `communities.name` is UNIQUE varchar(200), so randomise it.
    let community_id: Uuid =
        sqlx::query_scalar("INSERT INTO communities (name) VALUES ($1) RETURNING id")
            .bind(format!("community-{}", Uuid::new_v4()))
            .fetch_one(pool)
            .await
            .expect("seed community");

    let perspective_id: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("perspective-{}", Uuid::new_v4()))
    .bind(agent_id)
    .fetch_one(pool)
    .await
    .expect("seed perspective");

    sqlx::query("INSERT INTO community_members (community_id, perspective_id) VALUES ($1, $2)")
        .bind(community_id)
        .bind(perspective_id)
        .execute(pool)
        .await
        .expect("seed community membership");

    // THE PROJECTION, which migration 071's shim used to replay on the fixture's
    // behalf and PR-22 retired with it. It is not optional: `Viewer::resolve`
    // reads `group_memberships`, not `community_members`, so a community with no
    // projected group and no projected members produces a claim nobody can read
    // — including the member this helper exists to create.
    //
    // Shapes copied from migration 068 and `CommunityRepository::create`, which
    // copied them from 068 for the same reason: ID-PRESERVING, the
    // `did:epigraph:community:` key, `public_key = ''::bytea` (060's
    // `groups_public_key_shape` requires `octet_length = 0` for every
    // `kind <> 'team'`), and `role = 'reader'` because `community_members`
    // attests read interest and says nothing about write authority.
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_at) \
         SELECT c.id, c.name, 'did:epigraph:community:' || c.id::text, ''::bytea, \
                'community', c.created_at \
           FROM communities c WHERE c.id = $1 \
         ON CONFLICT DO NOTHING",
    )
    .bind(community_id)
    .execute(pool)
    .await
    .expect("project the community onto a group");

    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, wrapped_key, status) \
         VALUES ($1, 0, NULL, 'active') ON CONFLICT DO NOTHING",
    )
    .bind(community_id)
    .execute(pool)
    .await
    .expect("project the community's epoch 0");

    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         SELECT DISTINCT cm.community_id, p.owner_agent_id, ''::bytea, 0, 'reader' \
           FROM community_members cm \
           JOIN perspectives p ON p.id = cm.perspective_id \
          WHERE cm.community_id = $1 AND p.owner_agent_id IS NOT NULL \
         ON CONFLICT (group_id, agent_id, epoch) DO UPDATE SET revoked_at = NULL",
    )
    .bind(community_id)
    .execute(pool)
    .await
    .expect("project the community's memberships");

    community_id
}
