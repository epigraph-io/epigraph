#![cfg(feature = "db")]

//! `GET /api/v1/admin/stats` requires `claims:admin`, and still answers one.
//!
//! # Why this file exists at all
//!
//! `routes/admin.rs` has an extensive test module for this handler, and **none
//! of it is compiled**: it is `#[cfg(all(test, not(feature = "db")))]` and
//! `epigraph-api`'s default features are `["db"]`. The compiled in-`src` module
//! is `#[cfg(all(test, feature = "db"))] mod db_tests`, whose tests are all
//! `register_entity_type_*`. So before this file the only live coverage of this
//! route was `tests/public_router_allowlist.rs` asserting that it 401s without a
//! token — which says nothing about what an authenticated non-admin gets.
//!
//! # The 403 and the 200 are both load-bearing
//!
//! A scope gate is trivially satisfiable by refusing everyone, and refusing
//! everyone is invisible to a test that only checks that the wrong caller is
//! refused. So `system_stats_with_claims_admin_returns_the_full_aggregate`
//! parses the body and asserts on real fields: a handler that 200s an empty
//! object, or one that lost a subsystem on the way through the new extractor,
//! fails it.

mod common;

async fn spawn() -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    common::spawn_app(&url).await
}

const STATS: &str = "/api/v1/admin/stats";

/// The gate. `claims:write` is an ordinary read-write scope and is what an
/// `epigraph-wo` token carries; it is not an administrative one.
#[tokio::test(flavor = "multi_thread")]
async fn system_stats_with_claims_write_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}{STATS}"))
        .bearer_auth(common::test_bearer_token_with_scopes(&["claims:write"]))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "an authenticated non-admin principal must not read the instance-wide \
         aggregate; got {}",
        resp.status()
    );
}

/// `claims:read` is in every role including `epigraph-ro`, and is the scope a
/// DCR-registered public client gets. Asserted separately from `claims:write`
/// because the two reach the route from different registration paths.
#[tokio::test(flavor = "multi_thread")]
async fn system_stats_with_claims_read_returns_403() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}{STATS}"))
        .bearer_auth(common::test_bearer_token_with_scopes(&["claims:read"]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "got {}", resp.status());
}

/// Unchanged by this fix, and asserted so that a regression which removed the
/// extractor entirely could not pass by 401-ing instead of 403-ing above.
#[tokio::test(flavor = "multi_thread")]
async fn system_stats_no_token_returns_401() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}{STATS}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "got {}", resp.status());
}

/// THE POSITIVE CONTROL. An admin token reads the whole aggregate, and the
/// aggregate is still whole.
///
/// The field assertions are the point. "Returns 200" would also be true of a
/// handler that answered `{}`, and an over-suppressing fix is silent and
/// permanent in a way an over-permissive one is not.
#[tokio::test(flavor = "multi_thread")]
async fn system_stats_with_claims_admin_returns_the_full_aggregate() {
    let (addr, _shutdown) = spawn().await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}{STATS}"))
        .bearer_auth(common::test_bearer_token_with_scopes(&["claims:admin"]))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "an administrative principal is a legitimate reader here; got {}",
        resp.status()
    );

    let body: serde_json::Value = resp.json().await.expect("stats body is json");
    for subsystem in [
        "event_bus",
        "propagation",
        "caches",
        "challenges",
        "security",
        "webhooks",
        "config",
    ] {
        assert!(
            body.get(subsystem).is_some(),
            "the aggregate lost `{subsystem}`: {body}"
        );
    }
    assert!(
        body["webhooks"]["webhook_count"].is_u64(),
        "`webhook_count` is the cross-tenant field this gate exists for and must \
         still be reported to an admin: {body}"
    );
    assert!(
        body["config"]["require_signatures"].is_boolean(),
        "the `require_signatures` wire name is pinned by `#[serde(rename)]` and \
         documented in docs/deploy.md: {body}"
    );
    assert!(body["uptime_secs"].is_u64(), "{body}");
}
