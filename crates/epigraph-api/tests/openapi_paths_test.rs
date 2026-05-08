#![cfg(feature = "db")]
mod common;

#[tokio::test(flavor = "multi_thread")]
async fn openapi_documents_in_scope_paths() {
    let url = std::env::var("DATABASE_URL").unwrap();
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/openapi.json"))
        .send()
        .await
        .unwrap();
    let doc: serde_json::Value = resp.json().await.unwrap();
    let paths = doc["paths"].as_object().expect("paths object");
    for required in [
        "/api/v1/claims/{id}/supersede",
        "/api/v1/claims/{id}/dedup",
        "/api/v1/claims/{id}",
        "/api/v1/claims/{id}/labels",
        "/api/v1/workflows/steps/{id}/evolve",
        "/api/v1/workflows/hierarchical/search",
        "/api/v1/workflows/hierarchical/{id}/outcome",
        "/api/v1/workflows/{id}/improve",
        "/api/v1/workflows/{id}",
        "/api/v1/workflows/ingest",
    ] {
        assert!(
            paths.contains_key(required),
            "OpenAPI doc missing required path: {required}\nGot: {:?}",
            paths.keys().collect::<Vec<_>>()
        );
    }
}
