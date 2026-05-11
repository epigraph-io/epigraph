//! Integration test for `--listen unix:/abs/path` support (issue #129).
//!
//! Verifies that `serve_with_listener` binds a Unix-domain socket at the
//! requested path with 0660 permissions and accepts incoming connections.
//! Unix sockets eliminate the 127.0.0.1 localhost-bypass surface — only
//! processes with filesystem access can connect — which is the practical
//! near-term mitigation paired with Caddy `reverse_proxy unix://...`.
//!
//! The full Bearer-auth fix lives in issue #122. This test only exercises
//! the listener-binding logic; the router is intentionally trivial so the
//! test runs without a DB / signer / embedder.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn mcp_listen_on_unix_socket_binds_and_accepts_connection() {
    // Unique-per-process path (PID + nanos guards against parallel-test collisions
    // when this file gains a second test or a re-used PID after rapid restarts).
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let sock_path = format!("/tmp/epigraph-mcp-test-{}-{nanos}.sock", std::process::id());
    let _ = std::fs::remove_file(&sock_path);

    let listen_arg = format!("unix:{sock_path}");
    let router = axum::Router::new();

    // Spawn the helper. It awaits forever (until aborted) once bound.
    let listen_arg_clone = listen_arg.clone();
    let handle =
        tokio::spawn(
            async move { epigraph_mcp::serve_with_listener(&listen_arg_clone, router).await },
        );

    // Poll for the socket file to appear (up to 2s).
    let mut appeared = false;
    for _ in 0..20 {
        if std::fs::metadata(&sock_path).is_ok() {
            appeared = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        appeared,
        "socket file {sock_path} did not appear within 2s — bind failed"
    );

    // Verify permissions are 0660 (rw-rw----).
    let meta = std::fs::metadata(&sock_path).expect("socket should exist");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o660,
        "socket perms should be 0660, got {mode:o} — see issue #129"
    );

    // Verify it actually accepts a connection (not just a stale file).
    let _stream = tokio::net::UnixStream::connect(&sock_path)
        .await
        .expect("can connect to bound unix socket");

    // Cleanup.
    handle.abort();
    let _ = std::fs::remove_file(&sock_path);
}
