#![cfg(feature = "db")]
//! `POST /api/v1/themes/build-from-corpus` is retired with the k-means
//! prototype it ran (backlog a0ed0180, operator ruling R-29 as revised
//! 2026-10-26). The UMAP pipeline's routes (`scripts/maintain_themes.py`:
//! split-candidates, distant-claims, create-with-centroid, ...) stay.

mod common;

async fn spawn() -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    common::spawn_app(&url).await
}

/// An admin, who passed the old route's scope gate, gets 404: no route. The
/// UMAP pipeline's routes still answer with success for the same bearer.
#[tokio::test(flavor = "multi_thread")]
async fn build_from_corpus_is_gone_and_the_umap_routes_remain() {
    let (addr, _shutdown) = spawn().await;
    let admin = common::test_bearer_token_with_scopes(&["claims:read", "claims:admin"]);
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/api/v1/themes/build-from-corpus"))
        .bearer_auth(&admin)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(
        status, 404,
        "the k-means bootstrap route must be gone, got {status}: {body}"
    );

    for path in [
        "/api/v1/themes/split-candidates",
        "/api/v1/themes/distant-claims",
    ] {
        let resp = client
            .get(format!("http://{addr}{path}"))
            .bearer_auth(&admin)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let body = resp.text().await.unwrap();
        // Success, not merely "not 404": a kept route that broke during the
        // removal (500) or lost its auth wiring (401/403) must fail here too.
        assert!(
            status.is_success(),
            "{path} (UMAP pipeline) must stay routed and working, got {status}: {body}"
        );
    }
}
