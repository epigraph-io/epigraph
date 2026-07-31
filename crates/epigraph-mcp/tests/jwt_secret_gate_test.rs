//! Startup-gate tests driven through the COMPILED BINARY, so they prove `main`
//! actually consults `check_listen_auth_mode` (whose arms are unit-tested in
//! `src/main.rs`) — a pure function nobody calls would pass those unit tests
//! while the binary happily started anyway.
//!
//! Only REJECTING cases can be tested this way: `create_pool` connects eagerly,
//! so any accepted configuration proceeds past the gate into a DB connect. The
//! bogus `--database-url` below is therefore only ever reached if the gate
//! wrongly accepts, which would surface as a *different* failure than the one
//! each test asserts.

use std::process::Command;

fn mcp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_epigraph-mcp-full")
}

#[test]
fn rejects_dev_literal_jwt_secret() {
    let out = Command::new(mcp_bin())
        .args([
            "--database-url",
            "postgres://invalid:invalid@127.0.0.1:1/nope",
            "--listen",
            "127.0.0.1:0",
            "--jwt-secret",
            "epigraph-dev-secret-change-in-production!!",
        ])
        .output()
        .expect("run mcp bin");
    assert!(
        !out.status.success(),
        "mcp must reject the dev literal as a --jwt-secret"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("dev")
            || stderr.contains("EPIGRAPH_JWT_SECRET")
            || stderr.contains("--jwt-secret"),
        "stderr must explain the dev-literal rejection; got: {stderr}"
    );
}

/// `--listen <tcp> --allow-unauthenticated-http` must refuse to start.
///
/// This is the configuration `epigraph-mcp-http.service` was running
/// (`--listen 127.0.0.1:3100 --allow-unauthenticated-http`): a TCP listener that
/// injects a permissive AuthContext, so every write tool was reachable with no
/// credential — by any local process, and by a browser whose DNS rebinds to the
/// loopback port. The flag's own documentation scopes it to "a unix-socket
/// listener behind filesystem permissions"; the gate now enforces that scope.
///
/// The assertion checks the process exits AND that stderr names the unix-socket
/// alternative, so a coincidental non-zero exit (e.g. the DB connect failing on
/// the bogus URL, which is what a *missing* gate would produce) cannot pass.
#[test]
fn rejects_unauthenticated_tcp_listener() {
    let out = Command::new(mcp_bin())
        .args([
            "--database-url",
            "postgres://invalid:invalid@127.0.0.1:1/nope",
            "--listen",
            "127.0.0.1:0",
            "--allow-unauthenticated-http",
        ])
        // `--jwt-secret` also reads EPIGRAPH_JWT_SECRET; if the developer's shell
        // exports one, clap would fill it in and the gate would take the
        // mutually-exclusive arm instead of the one under test.
        .env_remove("EPIGRAPH_JWT_SECRET")
        .output()
        .expect("run mcp bin");
    assert!(
        !out.status.success(),
        "mcp must refuse an unauthenticated TCP listener"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unix-socket") && stderr.contains("--allow-unauthenticated-http"),
        "stderr must explain that the flag is unix-socket-only; got: {stderr}"
    );
}
