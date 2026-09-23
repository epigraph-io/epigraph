//! `epigraph_mcp::maintenance::attach_maintenance_pool` — the one function that
//! decides whether `epigraph-mcp-full` gets a maintenance pool, and therefore
//! whether its three maintenance tools run at all.
//!
//! `main` calls it with its own read of `MAINTENANCE_DATABASE_URL` and, on
//! `Ok`, hands the result to `EpiGraphMcpFull::with_scoped_pool`; on `Err` it
//! logs and leaves every server unscoped. These tests drive the function the
//! way `main` does, minus the environment read (which is why `configured` is a
//! parameter).
//!
//! # What is NOT covered here, and where it is
//!
//! The UNPRIVILEGED-UNDER-ROW-SECURITY refusal. Reaching it needs a DSN that
//! authenticates as a non-member of `epigraph_maintenance`, and every such role
//! in this schema is `NOLOGIN` (migration 060) — a test that minted a LOGIN role
//! would be creating a cluster-global credential from a public repository. The
//! decision itself is `epigraph_db::maintenance_verdict`, a pure function whose
//! refusal arm is unit-tested in `crates/epigraph-db/src/pool.rs`; this function
//! propagates its `Err` with `?`.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_db::SessionGucMode;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::maintenance::attach_maintenance_pool;
use epigraph_mcp::EpiGraphMcpFull;
use rmcp::model::CallToolRequestParams;
use rmcp::ServiceExt;
use sqlx::PgPool;

/// `app_url` with its database name replaced — the copy-pasted-DSN accident the
/// name guard exists for.
fn naming_another_database(app_url: &str) -> String {
    let (authority, query) = match app_url.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (app_url, None),
    };
    let (prefix, _db) = authority.rsplit_once('/').expect("DSN has a database path");
    let mut out = format!("{prefix}/definitely_not_this_database");
    if let Some(q) = query {
        out.push('?');
        out.push_str(q);
    }
    out
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_maintenance_dsn_naming_another_database_is_refused(pool: PgPool) {
    let app_url = fixture::database_url_for(&pool).await;
    let app = fixture::scoped_pool(&pool).await;

    let err = attach_maintenance_pool(
        &app,
        &app_url,
        Some(&naming_another_database(&app_url)),
        SessionGucMode::Session,
    )
    .await
    .expect_err("a maintenance DSN on another database must not be attached");
    assert!(
        err.to_string().contains("MAINTENANCE_DATABASE_URL"),
        "the refusal must name the variable an operator has to fix; got {err}"
    );
}

/// With no configured DSN the application DSN is reused (with a WARN), probed,
/// and attached as a SEPARATE pool — never as the application pool itself.
#[sqlx::test(migrations = "../../migrations")]
async fn a_privileged_dsn_is_attached_as_a_separate_pool(pool: PgPool) {
    let app_url = fixture::database_url_for(&pool).await;
    let app = fixture::scoped_pool(&pool).await;

    let scoped = attach_maintenance_pool(&app, &app_url, None, SessionGucMode::Session)
        .await
        .expect("the superuser test DSN satisfies epigraph_bypass()");

    assert!(scoped.has_maintenance_pool());
    assert!(
        !std::ptr::eq(scoped.maintenance_inner(), scoped.inner()),
        "the maintenance side must be its own pool, not the application pool's \
         fallback"
    );
    assert_eq!(
        scoped.maintenance_inner().options().get_max_connections(),
        epigraph_mcp::maintenance::MAINTENANCE_POOL_CONNECTIONS,
        "the pool must be sized by the budget the concurrency gate assumes"
    );
}

/// The whole `main` chain minus the environment read: attach, `with_scoped_pool`,
/// and a maintenance tool through the router returns a summary instead of the
/// fail-closed refusal.
#[sqlx::test(migrations = "../../migrations")]
async fn an_attached_server_runs_a_maintenance_tool(pool: PgPool) {
    let app_url = fixture::database_url_for(&pool).await;
    let app = fixture::scoped_pool(&pool).await;
    let scoped = attach_maintenance_pool(&app, &app_url, None, SessionGucMode::Session)
        .await
        .expect("attach");

    let signer = AgentSigner::from_bytes(&[0x5bu8; 32]).expect("signer");
    let server = EpiGraphMcpFull::new(
        app.inner().clone(),
        signer,
        McpEmbedder::new(app.inner().clone(), None),
        false,
    )
    .with_scoped_pool(scoped);

    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            let _ = running.waiting().await;
        }
    });
    let client = ().serve(client_io).await.expect("MCP client handshake");
    let out = client
        .call_tool(CallToolRequestParams {
            meta: None,
            name: "recompute_beliefs".into(),
            arguments: serde_json::json!({ "limit": 5 }).as_object().cloned(),
            task: None,
        })
        .await
        .expect("an attached server must run recompute_beliefs, not refuse it");
    assert_ne!(out.is_error, Some(true), "{:?}", out.content);
}
