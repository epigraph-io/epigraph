//! Boot-time secret gate: the server binary must refuse to start when
//! EPIGRAPH_JWT_SECRET is unset/dev and EPIGRAPH_ALLOW_INSECURE_SECRET is not
//! set, and must start when the opt-out is present. Drives the compiled
//! `server` binary as a subprocess so it exercises the real `main`.

use std::process::Command;

fn server_bin() -> &'static str {
    env!("CARGO_BIN_EXE_server")
}

#[test]
fn refuses_dev_secret_without_optout() {
    let out = Command::new(server_bin())
        .env_remove("EPIGRAPH_JWT_SECRET")
        .env_remove("EPIGRAPH_ALLOW_INSECURE_SECRET")
        .env("EPIGRAPH_PORT", "0")
        .env(
            "DATABASE_URL",
            "postgres://invalid:invalid@127.0.0.1:1/nope",
        )
        .output()
        .expect("run server bin");
    assert!(
        !out.status.success(),
        "server must exit non-zero with dev secret and no opt-out"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("EPIGRAPH_JWT_SECRET"),
        "stderr must name the secret check; got: {stderr}"
    );
}

#[test]
fn optout_skips_secret_gate() {
    let out = Command::new(server_bin())
        .env_remove("EPIGRAPH_JWT_SECRET")
        .env("EPIGRAPH_ALLOW_INSECURE_SECRET", "1")
        .env("EPIGRAPH_PORT", "0")
        .env(
            "DATABASE_URL",
            "postgres://invalid:invalid@127.0.0.1:1/nope",
        )
        .output()
        .expect("run server bin");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("EPIGRAPH_JWT_SECRET"),
        "with the opt-out set the secret gate must be skipped; got: {stderr}"
    );
}
