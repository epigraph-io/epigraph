//! A stdio server waits for the tasks its tool calls left running before it
//! exits (backlog b928ccc1).
//!
//! `ingest_document` / `ingest_document_inline` answer `queued` and run their
//! walk in a detached task, and both document walks embed their new claims in
//! another one. On stdio, `main` returned as soon as the client closed the
//! transport (`service.waiting()`), and the runtime then dropped those tasks:
//! the walk was cancelled with nothing written, or the embedding loop stopped
//! with committed claims left without a vector.
//!
//! Two halves are pinned here:
//!
//! - behaviour: over the real stdio transport (`stdio_server_transport` on an
//!   in-memory duplex pipe), a task spawned on the server's tracker is still
//!   running when the client has gone and `waiting` has returned, and
//!   `BackgroundTasks::drain` returns only after it finished. A drain with a
//!   limit gives up on a task that never ends and says how many were left.
//! - wiring: `main.rs` takes the tracker before `serve` consumes the server
//!   and drains it after `waiting`, without a `?` on `waiting` that would skip
//!   the drain. Source-level for the reason `stdio_transport_wired_into_main.rs`
//!   records: a test process cannot boot the binary into stdio mode.
//!
//! Verified to fail: with `drain` returning without waiting, both drain tests
//! fail (the task is reported left and is not finished); with the drain lines
//! removed from `main.rs`, the wiring test fails.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use epigraph_mcp::stdio_transport::stdio_server_transport;
use rmcp::ServiceExt;

fn server() -> epigraph_mcp::EpiGraphMcpFull {
    // A lazy pool against an unreachable address: nothing below needs the DB.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/invalid")
        .expect("connect_lazy never errors");
    let signer = Arc::new(epigraph_crypto::AgentSigner::generate());
    let embedder = Arc::new(epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None));
    epigraph_mcp::EpiGraphMcpFull::new_shared(pool, signer, embedder, false)
}

#[tokio::test]
async fn a_task_left_running_when_the_client_closes_finishes_before_the_drain_returns() {
    let (server_end, client_end) = tokio::io::duplex(1 << 20);
    let server = server();
    let background = server.background_tasks();

    let served = tokio::spawn(async move {
        let (read, write) = tokio::io::split(server_end);
        let running = server
            .serve(stdio_server_transport(read, write))
            .await
            .expect("server side of the stdio handshake");
        running.waiting().await.expect("the service ends cleanly")
    });
    let client =
        ().serve(tokio::io::split(client_end))
            .await
            .expect("client side of the stdio handshake");

    // What a detached ingest leaves behind: work that outlives the call.
    let finished = Arc::new(AtomicBool::new(false));
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    {
        let finished = Arc::clone(&finished);
        background.spawn(async move {
            let _ = released.await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            finished.store(true, Ordering::SeqCst);
        });
    }

    // The client goes away; the server's `waiting` returns.
    client.cancel().await.expect("client closes the transport");
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("the server notices the closed transport")
        .expect("server task");
    assert!(
        !finished.load(Ordering::SeqCst),
        "fixture: the task must still be running after the transport closed"
    );
    assert_eq!(background.running(), 1, "the task is tracked");

    // Released only now, so the drain below is what waits for it.
    release.send(()).expect("the task is waiting");
    let left = background.drain(Duration::from_secs(10)).await;
    assert_eq!(left, 0, "every task finished inside the limit");
    assert!(
        finished.load(Ordering::SeqCst),
        "the drain returned before the task it was draining finished"
    );
}

#[tokio::test]
async fn a_drain_gives_up_at_its_limit_and_counts_what_is_left() {
    let background = server().background_tasks();
    background.spawn(std::future::pending::<()>());
    let started = std::time::Instant::now();
    let left = background.drain(Duration::from_millis(200)).await;
    assert_eq!(left, 1, "the never-ending task is reported as left");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the drain is bounded by its limit"
    );
}

#[tokio::test]
async fn clones_of_a_server_share_one_tracker() {
    // A detached walk runs on a CLONE of the request's server and spawns its
    // embedding loop from there; the process drains the original's tracker.
    let original = server();
    let clone = original.clone();
    clone.background_tasks().spawn(std::future::pending::<()>());
    assert_eq!(original.background_tasks().running(), 1);
}

// ── main.rs wiring ─────────────────────────────────────────────────────────

/// `source` without its `//` comment lines, with all whitespace removed.
fn normalized(source: &str) -> String {
    source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// Every way `source` fails to drain the tracker around its stdio serve.
fn drain_wiring_violations(source: &str) -> Vec<String> {
    let code = normalized(source);
    let mut violations = Vec::new();
    let Some(serve) = code.find(".serve(transport)") else {
        return vec!["no `.serve(transport)` call".into()];
    };
    // `let <name> = server.background_tasks();` before the serve.
    let taken = code[..serve]
        .rfind("=server.background_tasks();")
        .and_then(|at| {
            let start = code[..at].rfind([';', '{', '}']).map_or(0, |i| i + 1);
            code[start..at].strip_prefix("let").map(str::to_string)
        });
    let Some(name) = taken else {
        return vec![
            "the tracker is not taken (`let <name> = server.background_tasks();`) before \
             `.serve(transport)` consumes the server"
                .into(),
        ];
    };
    let after = &code[serve..];
    let Some(waiting) = after.find(".waiting().await") else {
        return vec!["no `.waiting().await` after the serve".into()];
    };
    if after[waiting..].starts_with(".waiting().await?") {
        violations.push(
            "`.waiting().await?` returns before the drain when `waiting` fails; capture it, \
             drain, then propagate"
                .into(),
        );
    }
    if !after[waiting..].contains(&format!("{name}.drain(")) {
        violations.push(format!("`{name}.drain(` is not called after `.waiting()`"));
    }
    violations
}

#[test]
fn main_drains_background_tasks_after_the_stdio_client_goes() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs");
    let source = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let violations = drain_wiring_violations(&source);
    assert!(
        violations.is_empty(),
        "main.rs must drain the server's background tasks after its stdio client goes: {}",
        violations.join("; ")
    );
}

#[test]
fn the_check_catches_the_pre_fix_shape_and_a_skipping_question_mark() {
    let before = "let service = server.serve(transport).await?; service.waiting().await?; }";
    assert!(!drain_wiring_violations(before).is_empty());
    let skipping = "let background = server.background_tasks(); \
                    let service = server.serve(transport).await?; \
                    service.waiting().await?; background.drain(LIMIT).await;";
    assert!(!drain_wiring_violations(skipping).is_empty());
    let fixed = "let background = server.background_tasks(); \
                 let service = server.serve(transport).await?; \
                 let served = service.waiting().await; \
                 background.drain(LIMIT).await; served?;";
    assert_eq!(drain_wiring_violations(fixed), Vec::<String>::new());
}
