//! Operator decision D9 (batch W12a): `epigraph-mcp-full` is a request-serving
//! process on EVERY transport (`--listen` for the HTTP units, stdio for agent
//! containers and operator configs), so it refuses to start when
//! `MAINTENANCE_DATABASE_URL` is set. Driven through the compiled binary, so it
//! proves `main` consults the predicate before any connection: the DSN points
//! at a port nothing listens on, and the refusal must still be the D9 text.

use std::process::Command;

const D9: &str = "MAINTENANCE_DATABASE_URL is set; a request-serving process never holds the \
                  maintenance DSN (operator decision D9)";

fn mcp(args: &[&str], maintenance: Option<&str>) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("RUST_LOG", "warn")
        .args([
            "--database-url",
            "postgres://nobody:nothing@127.0.0.1:1/unreachable",
        ])
        .args(args)
        .current_dir(std::env::temp_dir());
    if let Some(m) = maintenance {
        cmd.env("MAINTENANCE_DATABASE_URL", m);
    }
    let out = cmd.output().expect("run epigraph-mcp-full");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const LISTEN: &[&str] = &[
    "--listen",
    "127.0.0.1:0",
    "--jwt-secret",
    "a-test-secret-that-is-long-enough-for-the-gate-0123456789",
];

#[test]
fn stdio_and_listen_both_refuse_to_start_holding_the_maintenance_dsn() {
    for (transport, args) in [("stdio", &[][..]), ("--listen", LISTEN)] {
        let (code, stdout, stderr) = mcp(
            args,
            Some("postgres://maint:secret@127.0.0.1:1/unreachable"),
        );
        assert_eq!(code, Some(1), "{transport}: {stderr}");
        assert!(
            stderr.contains(D9),
            "{transport}: not the D9 refusal: {stderr}"
        );
        assert!(
            stdout.is_empty(),
            "{transport}: the refusal wrote to stdout, the JSON-RPC stream on stdio: {stdout}"
        );
        assert!(
            !stderr.contains("secret@"),
            "{transport}: the refusal echoed the DSN: {stderr}"
        );
    }
}

/// The control: without the variable (or exported empty) the binary gets past
/// the D9 check and fails later, on the unreachable database.
#[test]
fn without_the_variable_both_transports_get_past_the_d9_check() {
    for (transport, args) in [("stdio", &[][..]), ("--listen", LISTEN)] {
        for maintenance in [None, Some("")] {
            let (code, _, stderr) = mcp(args, maintenance);
            assert_ne!(
                code,
                Some(0),
                "{transport}: it cannot serve an unreachable database"
            );
            assert!(
                !stderr.contains(D9),
                "{transport}: refused for D9 with MAINTENANCE_DATABASE_URL={maintenance:?}: \
                 {stderr}"
            );
        }
    }
}
