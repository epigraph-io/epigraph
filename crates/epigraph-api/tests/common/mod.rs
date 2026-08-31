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

/// Spawn the test app with a `MockProvider` embedding service injected.
///
/// Mirrors `epigraph_api::build_app_for_tests` (lib.rs) but inserts a
/// deterministic embedding provider into `AppState` so handlers that call
/// `state.embedding_service()` get a real provider instead of `None`.
///
/// Use this for tests of routes like `POST /api/v1/embeddings/neighborhood-density`
/// whose handler returns 500 when no embedding service is configured.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
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
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
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

#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
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
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
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
/// `AuthContext`; the redaction handlers (`get_claim`, `list_claims`) derive
/// the requester from `auth_ctx.agent_id` (falling back to `client_id`), NOT
/// the query-string `agent_id`, so this token — and only this token — drives
/// the OWNER (Full) vs STRANGER (Redacted) distinction.
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
/// HTTP 500 *before* the handler reaches the redaction branch — silently
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

/// Mark `node_id` (a claim) as a `private` partition owned by `owner_id`.
/// `check_content_access` returns Full only to a requester equal to
/// `owner_id`; everyone else gets Redacted. `node_type` is NOT NULL with a
/// CHECK constraint, so it must be 'claim'. Create the claim first with
/// `seed_claim_with_agent(pool, content, owner_id)` so the owner agent row
/// exists.
#[allow(
    dead_code,
    reason = "shared integration-test fixture: `tests/common/mod.rs` is compiled into every `epigraph-api` integration-test binary, and each binary uses only the subset of helpers it needs, so `dead_code` fires in the others"
)]
pub async fn seed_private_ownership(pool: &PgPool, node_id: Uuid, owner_id: Uuid) {
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id) \
         VALUES ($1, 'claim', 'private', $2) \
         ON CONFLICT (node_id) DO UPDATE SET partition_type = 'private', owner_id = $2",
    )
    .bind(node_id)
    .bind(owner_id)
    .execute(pool)
    .await
    .expect("seed private ownership");
}

/// Mark `node_id` (a claim) as a `community` partition owned by `owner_id` and
/// gated by `community_id`.
///
/// The counterpart to [`seed_private_ownership`] for the arm that, until PR-05,
/// NO test in this repository exercised — every fixture in the suite wrote
/// `'private'`. `check_content_access` returns Full only to a requester whose
/// agent owns a perspective in `community_id` (a two-hop join through
/// `community_members`), and Redacted to everyone else including an anonymous
/// requester. Pass `None` for `community_id` to reach the owner-only fallback.
///
/// Writes `community_id`, NEVER `encryption_key_id`. Before migration 068 the
/// gating community lived stringified in `encryption_key_id`, a `text` column
/// whose name meant something else entirely; a fixture that still wrote it
/// would keep passing while the production writer had moved on. Migration 068's
/// `ownership_key_id_is_uuid` CHECK also refuses any non-UUID value there now.
///
/// Create the claim, the owner agent, the community, the member's perspective
/// and the `community_members` row first; this helper writes only the
/// `ownership` row.
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
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, community_id) \
         VALUES ($1, 'claim', 'community', $2, $3) \
         ON CONFLICT (node_id) DO UPDATE SET partition_type = 'community', \
             owner_id = $2, community_id = $3, encryption_key_id = NULL",
    )
    .bind(node_id)
    .bind(owner_id)
    .bind(community_id)
    .execute(pool)
    .await
    .expect("seed community ownership");
}

/// Create a community and put `agent` in it the ONLY way
/// `check_content_access` recognises: via a perspective the agent owns.
///
/// The community arm is a two-hop join — `community_members ⋈ perspectives ON
/// p.owner_agent_id` — not a direct agent membership table. A fixture that
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

    community_id
}
