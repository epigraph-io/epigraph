use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::sync::oneshot;

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
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type)
         VALUES ($1, decode(repeat('00', 32), 'hex'), 'graph-routes-test', 'system')
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

pub async fn seed_three_node_chain(pool: &PgPool) -> uuid::Uuid {
    let test_agent_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-0000000000aa").unwrap();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type)
         VALUES ($1, decode(repeat('00', 32), 'hex'), 'graph-routes-test', 'system')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(test_agent_id)
    .execute(pool)
    .await
    .unwrap();

    // Disable user triggers on `edges` because validate_edge_reference depends
    // on tables (propaganda_techniques, coalitions, etc.) that the 001+002
    // migration set doesn't create.
    sqlx::query("ALTER TABLE edges DISABLE TRIGGER USER")
        .execute(pool)
        .await
        .unwrap();

    let a = uuid::Uuid::new_v4();
    let b = uuid::Uuid::new_v4();
    let c = uuid::Uuid::new_v4();
    for &id in &[a, b, c] {
        // Same rationale as seed_one_cluster: derive content_hash from the
        // claim's UUID so it's unique per call and won't collide with prior
        // tests' claim rows on this shared DB.
        let hash: Vec<u8> = id
            .as_bytes()
            .iter()
            .chain(id.as_bytes().iter())
            .copied()
            .collect();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, pignistic_prob)
             VALUES ($1, 'x', $2, $3, 0.5)
             ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(hash)
        .bind(test_agent_id)
        .execute(pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'claim', $2, 'claim', 'SUPPORTS'),
                ($2, 'claim', $3, 'claim', 'SUPPORTS')",
    )
    .bind(a)
    .bind(b)
    .bind(c)
    .execute(pool)
    .await
    .unwrap();
    b
}
