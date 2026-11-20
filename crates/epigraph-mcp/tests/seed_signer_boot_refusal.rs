//! `epigraph-mcp` refuses to start with an LLM-seed identity (backlog
//! bfc2eff8): `--agent-model` with a prompt or prompt hash used to derive the
//! process's SIGNING key as `BLAKE3("llm-agent:{model}:{prompt hash}")`, a
//! function of public inputs, so anyone could recompute it and sign as the
//! agent.
//!
//! Driven through the COMPILED BINARY, so the tests prove `main` wires the
//! flags AND their environment variables into the refusal, before the
//! database connect: the database URL here is unreachable, so a binary that
//! did not refuse would fail later, on the connect, with a different message.
//! No database is needed.

use std::process::{Command, Stdio};

/// Spelled here, not imported from the binary: a test that shares its
/// subject's text cannot detect a change to it.
const REFUSED: &str = "are refused";
const WHY: &str = "public inputs";
const UNREACHABLE: &str = "postgres://invalid:invalid@127.0.0.1:1/nope";

/// Run the binary with these arguments and environment, every identity
/// variable cleared first. Returns (success, stderr).
fn run(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"));
    cmd.args(["--database-url", UNREACHABLE])
        .args(args)
        .env_remove("EPIGRAPH_AGENT_IDENTITY_PUBKEY")
        .env_remove("EPIGRAPH_AGENT_SIGNING_KEY")
        .env_remove("EPIGRAPH_MCP_AGENT_KEY")
        .env_remove("EPIGRAPH_AGENT_MODEL")
        .env_remove("EPIGRAPH_AGENT_SYSTEM_PROMPT")
        .env_remove("EPIGRAPH_AGENT_SYSTEM_PROMPT_HASH")
        .env_remove("EPIGRAPH_OPERATOR_ID")
        .env_remove("EPIGRAPH_MCP_EXTENSIONS")
        .env_remove("OPENAI_API_KEY");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .output()
        .expect("run mcp bin");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The flags, and the epiclaw legacy-mode environment (`EPIGRAPH_AGENT_MODEL`
/// with `EPIGRAPH_AGENT_SYSTEM_PROMPT_HASH`), are each refused with the
/// reason, and the refusal names the host-keyed alternative.
///
/// Calibrated first: without an LLM-seed input the same binary gets PAST the
/// signer selection and fails only on the unreachable database, so the
/// refusal below is the seed rule, not any startup failure.
#[test]
fn an_llm_seed_identity_is_refused_at_startup_by_flag_and_by_env() {
    let key = "01".repeat(32);
    let (ok, stderr) = run(&["--agent-key", &key], &[]);
    assert!(!ok, "calibration: the database is unreachable");
    assert!(
        !stderr.contains(REFUSED),
        "calibration: --agent-key must not be refused as a seed identity; got:\n{stderr}"
    );

    let hash = "ab".repeat(32);
    type Case<'a> = (Vec<&'a str>, Vec<(&'a str, &'a str)>);
    let cases: Vec<Case<'_>> = vec![
        (
            vec![
                "--agent-model",
                "claude-opus-4-8",
                "--agent-system-prompt-hash",
                &hash,
            ],
            vec![],
        ),
        (
            vec!["--agent-model", "claude-opus-4-8"],
            vec![(
                "EPIGRAPH_AGENT_SYSTEM_PROMPT",
                "You are a careful reviewer.",
            )],
        ),
        (
            vec![],
            vec![
                ("EPIGRAPH_AGENT_MODEL", "claude-opus-4-8"),
                ("EPIGRAPH_AGENT_SYSTEM_PROMPT_HASH", &hash),
            ],
        ),
    ];
    for (args, env) in cases {
        let (ok, stderr) = run(&args, &env);
        assert!(!ok, "{args:?} {env:?} must not start");
        assert!(
            stderr.contains(REFUSED) && stderr.contains(WHY),
            "{args:?} {env:?} must be refused for the seed-derived key, before the connect; \
             got:\n{stderr}"
        );
        assert!(
            stderr.contains("EPIGRAPH_AGENT_IDENTITY_PUBKEY"),
            "the refusal must name the host-keyed path; got:\n{stderr}"
        );
    }
}
