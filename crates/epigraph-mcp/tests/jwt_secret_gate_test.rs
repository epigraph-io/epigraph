//! The --jwt-secret gate must reject the committed dev literal even though it
//! is >= 32 bytes. Drives the compiled binary with --listen so the gate runs.

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
