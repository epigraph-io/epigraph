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

/// Backlog 7b834860: a malformed Ed25519 signing key refuses boot even under
/// the insecure opt-out, so a typo can never fall back silently to signing
/// with the shared secret, and the refusal does not echo the key.
#[test]
fn a_malformed_signing_key_refuses_boot_even_with_the_optout() {
    let typo = "zz".repeat(32);
    let out = Command::new(server_bin())
        .env("EPIGRAPH_JWT_SIGNING_KEY", &typo)
        .env("EPIGRAPH_ALLOW_INSECURE_SECRET", "1")
        .env_remove("EPIGRAPH_JWT_SECRET")
        .env("EPIGRAPH_PORT", "0")
        .env(
            "DATABASE_URL",
            "postgres://invalid:invalid@127.0.0.1:1/nope",
        )
        .output()
        .expect("run server bin");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("EPIGRAPH_JWT_SIGNING_KEY is not hex"),
        "stderr must name the key check; got: {stderr}"
    );
    assert!(!stderr.contains(&typo), "the refusal echoes the key");
}

/// An Ed25519 signing key with no shared secret is a production
/// configuration: the gate passes (the process then fails on the dummy
/// database, which is not the gate). The old gate demanded the secret.
#[test]
fn a_signing_key_alone_passes_the_gate() {
    let out = Command::new(server_bin())
        .env("EPIGRAPH_JWT_SIGNING_KEY", "11".repeat(32))
        .env_remove("EPIGRAPH_JWT_SECRET")
        .env_remove("EPIGRAPH_ALLOW_INSECURE_SECRET")
        .env("EPIGRAPH_PORT", "0")
        .env(
            "DATABASE_URL",
            "postgres://invalid:invalid@127.0.0.1:1/nope",
        )
        .output()
        .expect("run server bin");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("EPIGRAPH_JWT_SECRET") && !stderr.contains("EPIGRAPH_JWT_SIGNING_KEY"),
        "a signing key alone must pass the key gate; got: {stderr}"
    );
}
