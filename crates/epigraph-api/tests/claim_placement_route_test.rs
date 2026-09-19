#![cfg(feature = "db")]
//! `GET /api/v1/claims/:id/placement` (plan §2.3).
//!
//! The load-bearing property is not the JSON shape but the promise behind it:
//! an id this route returns is an id `expand` accepts *right now*. So the
//! clustered case feeds the returned ids straight back into
//! `/graph/communities/:id/expand` and `/graph/neighborhoods/:id/expand` and
//! asserts they resolve.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use epigraph_api::{create_router, ApiConfig, AppState};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

fn router(pool: PgPool) -> Router {
    create_router(AppState::with_db(pool, ApiConfig::default()))
}

async fn raw(router: &Router, path: &str, bearer: Option<&str>) -> (StatusCode, axum::body::Bytes) {
    let mut req = Request::builder().method(Method::GET).uri(path);
    if let Some(token) = bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, bytes)
}

async fn get(router: &Router, path: &str, bearer: Option<&str>) -> (StatusCode, Value) {
    let (status, bytes) = raw(router, path, bearer).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A complete clustering run around one claim: theme, cluster and
/// neighbourhood, all in the same (and only) run.
struct Clustered {
    claim_id: Uuid,
    theme_id: Uuid,
    run_id: Uuid,
    cluster_id: Uuid,
    neighborhood_id: Uuid,
}

async fn seed_clustered(pool: &PgPool, content: &str) -> Clustered {
    let claim_id = common::seed_claim(pool, content).await;

    let theme_id = Uuid::new_v4();
    sqlx::query("INSERT INTO claim_themes (id, label) VALUES ($1, 'placement-test-theme')")
        .bind(theme_id)
        .execute(pool)
        .await
        .expect("seed theme");
    sqlx::query("UPDATE claims SET theme_id = $1 WHERE id = $2")
        .bind(theme_id)
        .bind(claim_id)
        .execute(pool)
        .await
        .expect("assign theme");

    let run_id = Uuid::new_v4();
    let cluster_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_clusters (id, run_id, label, size, mean_betp, dominant_type, degraded) \
         VALUES ($1, $2, 'cluster-0', 1, 0.5, 'claim', FALSE)",
    )
    .bind(cluster_id)
    .bind(run_id)
    .execute(pool)
    .await
    .expect("seed cluster");
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 1, FALSE)",
    )
    .bind(run_id)
    .execute(pool)
    .await
    .expect("seed run");
    sqlx::query(
        "INSERT INTO claim_cluster_membership (claim_id, cluster_id, run_id) VALUES ($1, $2, $3)",
    )
    .bind(claim_id)
    .bind(cluster_id)
    .bind(run_id)
    .execute(pool)
    .await
    .expect("seed cluster membership");

    let neighborhood_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO graph_neighborhoods (id, run_id, theme_id, label, size, mean_betp) \
         VALUES ($1, $2, $3, 'neighborhood-0', 1, 0.5)",
    )
    .bind(neighborhood_id)
    .bind(run_id)
    .bind(theme_id)
    .execute(pool)
    .await
    .expect("seed neighborhood");
    sqlx::query(
        "INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) \
         VALUES ($1, $2, $3)",
    )
    .bind(run_id)
    .bind(claim_id)
    .bind(neighborhood_id)
    .execute(pool)
    .await
    .expect("seed neighborhood membership");

    Clustered {
        claim_id,
        theme_id,
        run_id,
        cluster_id,
        neighborhood_id,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unclustered_claim_is_all_null(pool: PgPool) {
    let claim_id = common::seed_claim(&pool, "never clustered").await;
    let app = router(pool);

    let (status, body) = get(&app, &format!("/api/v1/claims/{claim_id}/placement"), None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    // All-null is a normal answer, not an error: clustering is
    // operator-triggered and only leaf claims get neighbourhoods.
    assert_eq!(
        body,
        serde_json::json!({
            "claim_id": claim_id.to_string(),
            "theme_id": null,
            "cluster_run_id": null,
            "cluster_id": null,
            "neighborhood_id": null,
            "run_completed_at": null,
        })
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn missing_claim_is_404(pool: PgPool) {
    let app = router(pool);
    let missing = Uuid::new_v4();
    let (status, body) = get(&app, &format!("/api/v1/claims/{missing}/placement"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
    assert_eq!(body["error"], "NotFound");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_clustered_claim_returns_ids_that_expand_accepts(pool: PgPool) {
    let seeded = seed_clustered(&pool, "a clustered claim").await;
    let claim_id = seeded.claim_id;
    let app = router(pool);

    let (status, body) = get(&app, &format!("/api/v1/claims/{claim_id}/placement"), None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let mut keys: Vec<&str> = body
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "claim_id",
            "cluster_id",
            "cluster_run_id",
            "neighborhood_id",
            "run_completed_at",
            "theme_id",
        ]
    );
    assert_eq!(body["claim_id"], claim_id.to_string());
    assert_eq!(body["theme_id"], seeded.theme_id.to_string());
    assert_eq!(body["cluster_run_id"], seeded.run_id.to_string());
    assert_eq!(body["cluster_id"], seeded.cluster_id.to_string());
    assert_eq!(body["neighborhood_id"], seeded.neighborhood_id.to_string());
    assert!(
        body["run_completed_at"].is_string(),
        "run_completed_at should be an RFC3339 string, got {body}"
    );

    // The promise: feed the ids back to the routes the Explorer links to.
    // Both expand routes are on the protected router, so they need a bearer.
    let token = common::test_bearer_token_with_scopes(&["graph:read"]);
    let cluster_id = body["cluster_id"].as_str().expect("cluster_id");
    let (status, bytes) = raw(
        &app,
        &format!("/api/v1/graph/communities/{cluster_id}/expand"),
        Some(&token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "community expand rejected an id placement handed out: {}",
        String::from_utf8_lossy(&bytes)
    );

    let neighborhood_id = body["neighborhood_id"].as_str().expect("neighborhood_id");
    let (status, bytes) = raw(
        &app,
        &format!("/api/v1/graph/neighborhoods/{neighborhood_id}/expand"),
        Some(&token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "neighborhood expand rejected an id placement handed out: {}",
        String::from_utf8_lossy(&bytes)
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_newer_run_hides_the_previous_runs_ids(pool: PgPool) {
    let seeded = seed_clustered(&pool, "clustered, then re-clustered").await;
    let claim_id = seeded.claim_id;
    // A second run that does not contain this claim. `expand` resolves only
    // against the latest run, so the old ids would 404 there — this route must
    // not keep handing them out.
    sqlx::query("INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded, completed_at) VALUES ($1, 0, FALSE, now() + interval '1 hour')")
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .expect("seed newer run");
    let app = router(pool);

    let (status, body) = get(&app, &format!("/api/v1/claims/{claim_id}/placement"), None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["cluster_id"], Value::Null);
    assert_eq!(body["neighborhood_id"], Value::Null);
    assert_eq!(body["cluster_run_id"], Value::Null);
    assert_eq!(body["run_completed_at"], Value::Null);
    assert_eq!(
        body["theme_id"],
        seeded.theme_id.to_string(),
        "theme_id is a column on the claim and does not depend on a run"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_claims_placement_is_withheld_from_everyone_but_its_owner(pool: PgPool) {
    let owner = Uuid::new_v4();
    let seeded = seed_clustered(&pool, "classified but clustered").await;
    let claim_id = seeded.claim_id;
    // Re-point the claim at the owner so `private` ownership is coherent.
    let pk: Vec<u8> = owner.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(owner)
        .bind(&pk)
        .execute(&pool)
        .await
        .expect("seed owner agent");
    sqlx::query("UPDATE claims SET agent_id = $1 WHERE id = $2")
        .bind(owner)
        .bind(claim_id)
        .execute(&pool)
        .await
        .expect("reassign claim");
    common::seed_private_ownership(&pool, claim_id, owner).await;
    let app = router(pool);

    let path = format!("/api/v1/claims/{claim_id}/placement");

    // A theme or cluster id is a pointer into a view that renders the claim's
    // text, so a caller who may not read the claim gets the all-null answer.
    for (who, token) in [
        ("anonymous", None),
        (
            "stranger",
            Some(common::mint_token_with_agent(
                &["claims:read"],
                Uuid::new_v4(),
            )),
        ),
    ] {
        let (status, body) = get(&app, &path, token.as_deref()).await;
        assert_eq!(status, StatusCode::OK, "{who}: {body}");
        assert_eq!(body["claim_id"], claim_id.to_string(), "{who}");
        assert_eq!(body["theme_id"], Value::Null, "{who}: {body}");
        assert_eq!(body["cluster_id"], Value::Null, "{who}: {body}");
        assert_eq!(body["neighborhood_id"], Value::Null, "{who}: {body}");
        assert_eq!(body["cluster_run_id"], Value::Null, "{who}: {body}");
        assert_eq!(body["run_completed_at"], Value::Null, "{who}: {body}");
    }

    let owner_token = common::mint_token_with_agent(&["claims:read"], owner);
    let (status, body) = get(&app, &path, Some(&owner_token)).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["theme_id"], seeded.theme_id.to_string());
    assert_eq!(body["cluster_id"], seeded.cluster_id.to_string());
    assert_eq!(body["neighborhood_id"], seeded.neighborhood_id.to_string());
    assert_eq!(body["cluster_run_id"], seeded.run_id.to_string());
}
