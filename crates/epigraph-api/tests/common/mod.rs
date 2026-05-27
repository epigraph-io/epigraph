use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use uuid::Uuid;

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

/// Spawn the test app with a `MockProvider` embedding service injected.
///
/// Mirrors `epigraph_api::build_app_for_tests` (lib.rs) but inserts a
/// deterministic embedding provider into `AppState` so handlers that call
/// `state.embedding_service()` get a real provider instead of `None`.
///
/// Use this for tests of routes like `POST /api/v1/embeddings/neighborhood-density`
/// whose handler returns 500 when no embedding service is configured.
pub async fn spawn_app_with_mock_embedding(
    database_url: &str,
) -> (SocketAddr, oneshot::Sender<()>) {
    use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
    use std::sync::Arc;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(database_url)
        .await
        .expect("db connect");
    let provider = MockProvider::new(EmbeddingConfig::openai(1536));
    let svc: Arc<dyn EmbeddingService> = Arc::new(provider);
    let state = epigraph_api::AppState::with_db(pool, epigraph_api::ApiConfig::default())
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
pub fn test_bearer_token() -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _jti) = cfg
        .issue_access_token(
            uuid::Uuid::new_v4(),
            vec!["graph:read".into()],
            "service",
            None,
            None,
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    token
}

pub async fn seed_one_cluster(pool: &PgPool, size: usize) -> uuid::Uuid {
    sqlx::query("DELETE FROM graph_cluster_runs")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM claim_cluster_membership")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM graph_clusters")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM cluster_edges")
        .execute(pool)
        .await
        .unwrap();

    let test_agent_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000aa").unwrap();
    // public_key is unique across all agents — must differ per test binary.
    // 00...AA distinguishes graph_routes_test from graph_themes_test (00...BB)
    // and graph_neighborhoods_test (00...CC).
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
pub fn test_bearer_token_with_scopes(scopes: &[&str]) -> String {
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (token, _jti) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "service",
            None,
            None,
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    token
}

/// Insert a system agent with a unique 32-byte public_key.
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

/// Connect to the configured test database. Tests that need just a pool
/// (no spawned HTTP app) use this helper to centralize the connection.
pub async fn test_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to test db")
}

/// Insert an edge directly via SQL. Returns the generated edge id.
/// Used by tests that need to seed edge fixtures without going through
/// the HTTP edges route (e.g., tests of unique indexes, view closures,
/// or relationships not yet exposed by the public API).
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

/// Insert a claim with explicit labels.
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
pub async fn test_bearer_token_with_seeded_client(
    pool: &PgPool,
    scopes: &[&str],
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
            None,
            chrono::Duration::minutes(60),
        )
        .expect("test JWT issued");
    (token, client_id)
}
