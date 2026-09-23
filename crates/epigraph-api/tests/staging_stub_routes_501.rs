#![cfg(feature = "db")]

//! `POST /api/v1/staging/ingest/git` and `POST /api/v1/staging/merge` answer
//! `501 Not Implemented`, not a fabricated success.
//!
//! # What these routes used to do
//!
//! Both were stubs from the initial import, mounted on the protected router and
//! answering 200:
//!
//! - `ingest/git` checked that `repo_path` was non-empty and returned a
//!   hard-coded empty `StagingSubgraph`, indistinguishable from "this
//!   repository has no commits".
//! - `merge` returned `{merged_claims: N, merged_edges, merged_connections}`
//!   and wrote nothing. A screening client that trusted the 200 could discard
//!   the reviewed staging subgraph and lose it. `merged_connections` also
//!   counted every proposed connection whose staging claim was in the request,
//!   whether or not anyone had accepted it.
//!
//! Deferred-commitment screen key `staging-ingest-merge-fake`.
//!
//! # Why the 400s are asserted too
//!
//! A handler that 501s everything, malformed bodies included, would also pass
//! the 501 assertions. The 400 cases pin that validation still runs first, so a
//! client with a broken body is told so rather than told to stop retrying a
//! feature.

mod common;

async fn spawn() -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    common::spawn_app(&url).await
}

async fn post(
    addr: std::net::SocketAddr,
    path: &str,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .bearer_auth(common::test_bearer_token_with_scopes(&["claims:write"]))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
    (status, json)
}

fn staging_subgraph() -> serde_json::Value {
    serde_json::json!({
        "claims": [
            {
                "id": "s1",
                "statement": "staging claim one",
                "truth_value": 0.4,
                "confidence": 0.8,
                "methodology": "extraction",
                "source": null,
                "domain": null,
                "evidence": []
            },
            {
                "id": "s2",
                "statement": "staging claim two",
                "truth_value": 0.4,
                "confidence": 0.8,
                "methodology": "extraction",
                "source": null,
                "domain": null,
                "evidence": []
            }
        ],
        "edges": [
            {
                "id": "e1",
                "source_claim_id": "s1",
                "target_claim_id": "s2",
                "edge_type": "supports",
                "strength": 0.9
            }
        ],
        "proposed_connections": [
            {
                "staging_claim_id": "s1",
                "existing_claim_id": "00000000-0000-0000-0000-000000000000",
                "edge_type": "supports",
                "strength": 0.5,
                "method": "embedding"
            }
        ]
    })
}

fn assert_not_implemented(status: reqwest::StatusCode, body: &serde_json::Value, route: &str) {
    assert_eq!(
        status, 501,
        "{route} is a stub and must say so with 501, not report success; got {status} body={body}"
    );
    assert_eq!(
        body["error"], "NotImplemented",
        "{route} must answer with the NotImplemented error shape; body={body}"
    );
    assert!(
        body["details"]["feature"]
            .as_str()
            .is_some_and(|f| !f.is_empty()),
        "{route} must name the unimplemented feature; body={body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn staging_merge_returns_501_instead_of_fake_counts() {
    let (addr, _shutdown) = spawn().await;
    let (status, body) = post(
        addr,
        "/api/v1/staging/merge",
        serde_json::json!({
            "staging": staging_subgraph(),
            "accepted_edge_ids": ["e1"]
        }),
    )
    .await;
    assert!(
        body.get("merged_claims").is_none(),
        "merge must not report merged counts for a merge it never performed; body={body}"
    );
    assert_not_implemented(status, &body, "POST /api/v1/staging/merge");
}

#[tokio::test(flavor = "multi_thread")]
async fn staging_merge_with_no_claims_is_still_400() {
    let (addr, _shutdown) = spawn().await;
    let (status, body) = post(
        addr,
        "/api/v1/staging/merge",
        serde_json::json!({
            "staging": { "claims": [], "edges": [], "proposed_connections": [] },
            "accepted_edge_ids": []
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "an empty merge request is malformed and must be rejected before the 501; body={body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn staging_ingest_git_returns_501_instead_of_empty_subgraph() {
    let (addr, _shutdown) = spawn().await;
    let (status, body) = post(
        addr,
        "/api/v1/staging/ingest/git",
        serde_json::json!({ "repo_path": "/srv/some/repo", "since": null, "limit": 10 }),
    )
    .await;
    assert!(
        body.get("claims").is_none(),
        "ingest/git must not return a subgraph it never computed; body={body}"
    );
    assert_not_implemented(status, &body, "POST /api/v1/staging/ingest/git");
}

#[tokio::test(flavor = "multi_thread")]
async fn staging_ingest_git_with_blank_repo_path_is_still_400() {
    let (addr, _shutdown) = spawn().await;
    let (status, body) = post(
        addr,
        "/api/v1/staging/ingest/git",
        serde_json::json!({ "repo_path": "   " }),
    )
    .await;
    assert_eq!(
        status, 400,
        "a blank repo_path is malformed and must be rejected before the 501; body={body}"
    );
}
