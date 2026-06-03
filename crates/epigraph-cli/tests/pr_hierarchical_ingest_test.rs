//! End-to-end contracts the PR-hierarchical `ingest_git --pr-ingest` path depends on.
//!
//! `run_pr_ingest` talks HTTP to epigraph-api. Rather than spawn a server (or import
//! the bin's private helpers, which are unreachable from an integration test), this
//! exercises the exact JSON bodies the CLI emits against the *real* epigraph-api
//! handlers via `tower::ServiceExt::oneshot`, on `epigraph_db_repo_test`.
//!
//! It asserts the three contracts the CLI relies on:
//!   1. submit-packet idempotency: a stable `idempotency_key` returns the same claim_id;
//!   2. a datestamped `RESOLVED_BY` edge (`backlog -> PR`) is accepted with `valid_from`;
//!   3. `content_contains` search finds a backlog claim citing "PR #<n>".
//!
//! Scaffolding (`ensure_system_agent`, `seed_claim`) is copied verbatim from
//! `epigraph-api`'s `routes::edges` `db_tests`.
#![cfg(feature = "db")]

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
    Router,
};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use epigraph_api::routes;
use epigraph_api::state::{ApiConfig, AppState};

/// Router mirroring the four routes the CLI hits (submit + edges + claim read + query).
fn app(pool: PgPool) -> Router {
    let state = AppState::with_db(pool, ApiConfig::default());
    Router::new()
        .route("/api/v1/submit/packet", post(routes::submit::submit_packet))
        .route("/api/v1/edges", post(routes::edges::create_edge))
        .route("/api/v1/claims/:id", get(routes::claims::get_claim))
        .route(
            "/api/v1/claims",
            get(routes::claims_query::list_claims_query),
        )
        .with_state(state)
}

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&b).unwrap()
}

/// Insert a system agent (mirrors `policies.rs::ensure_system_agent`) and return its
/// id. Each call uses a fresh random pubkey so tests don't collide on the unique
/// constraint. Copied from `epigraph-api` `routes::edges` `db_tests`.
async fn ensure_system_agent(pool: &PgPool) -> Uuid {
    let mut pub_key = vec![0u8; 32];
    for b in pub_key.iter_mut() {
        *b = rand::random();
    }
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id",
    )
    .bind(&pub_key)
    .bind("cli-pr-ingest-test")
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Insert a plain claim and return its id. Copied from `epigraph-api`
/// `routes::edges` `db_tests`.
async fn seed_claim(pool: &PgPool, agent_id: Uuid, content: &str) -> Uuid {
    let content_hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties) \
         VALUES ($1, $2, $3, 0.5, ARRAY[]::text[], '{}'::jsonb) RETURNING id",
    )
    .bind(content)
    .bind(content_hash.as_slice())
    .bind(agent_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn pr_ingest_builds_hierarchy_and_resolution_edge(pool: PgPool) {
    // Seed an agent + a backlog claim whose content cites "PR #999" (the PR-number
    // resolution path the CLI uses to find claims to link), plus a decoy claim that
    // does NOT mention PR #999 so step 4 proves the filter discriminates rather than
    // returning everything.
    let agent = ensure_system_agent(&pool).await;
    let backlog = seed_claim(&pool, agent, "Backlog X. Fixed by PR #999.").await;
    let decoy = seed_claim(&pool, agent, "Unrelated backlog item about PR #123.").await;

    let router = app(pool.clone());

    // 1) submit the PR node (stable idempotency_key pr:org/repo#999).
    let pr_body = serde_json::json!({
        "claim": {
            "content": "[PR #999] fix(api): thing",
            "initial_truth": 0.8,
            "agent_id": agent,
            "idempotency_key": "pr:org/repo#999",
            "properties": { "source": "git-history", "node": "pr", "pr_number": 999 }
        },
        "evidence": [],
        "reasoning_trace": {
            "methodology": "heuristic",
            "inputs": [],
            "confidence": 0.8,
            "explanation": "x"
        },
        "signature": "0".repeat(128)
    });
    let r = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/submit/packet")
                .header("content-type", "application/json")
                .body(Body::from(pr_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "first PR submit accepted (got {})",
        r.status()
    );
    let pr_id: Uuid = json(r).await["claim_id"].as_str().unwrap().parse().unwrap();

    // 2) re-submit the same PR -> same claim_id (idempotent find-or-create).
    let r2 = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/submit/packet")
                .header("content-type", "application/json")
                .body(Body::from(pr_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(r2.status().is_success(), "re-submit accepted");
    let r2_json = json(r2).await;
    let pr_id2: Uuid = r2_json["claim_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        pr_id, pr_id2,
        "stable idempotency_key returns the same claim"
    );
    assert_eq!(
        r2_json["was_duplicate"], true,
        "re-submit flagged as duplicate"
    );

    // 3) datestamped RESOLVED_BY edge backlog -> PR (the resolution link).
    let edge = serde_json::json!({
        "source_id": backlog,
        "target_id": pr_id,
        "source_type": "claim",
        "target_type": "claim",
        "relationship": "RESOLVED_BY",
        "valid_from": "2026-06-02T15:10:01Z",
        "if_not_exists": true,
        "properties": { "source": "git-history" }
    });
    let re = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/edges")
                .header("content-type", "application/json")
                .body(Body::from(edge.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        re.status().is_success(),
        "RESOLVED_BY edge accepted (got {})",
        re.status()
    );
    let edge_json = json(re).await;
    assert_eq!(edge_json["relationship"], "RESOLVED_BY");
    // valid_from round-trips to the same instant (chrono may render +00:00 vs Z).
    let returned_vf = edge_json["valid_from"]
        .as_str()
        .expect("edge carries valid_from");
    let want: chrono::DateTime<chrono::Utc> = "2026-06-02T15:10:01Z".parse().unwrap();
    let got: chrono::DateTime<chrono::Utc> = returned_vf.parse().unwrap();
    assert_eq!(got, want, "edge is datestamped at merge time");

    // 4) content_contains finds the backlog claim citing "PR #999".
    let q = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/claims?content_contains=PR%20%23999&is_current=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(q.status(), StatusCode::OK, "claim query ok");
    let found = json(q).await;
    let ids: Vec<String> = found["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        ids.contains(&backlog.to_string()),
        "PR-number search finds the backlog claim (found ids: {ids:?})"
    );
    assert!(
        !ids.contains(&decoy.to_string()),
        "PR-number search excludes the non-matching decoy (filter discriminates, \
         found ids: {ids:?})"
    );
}
