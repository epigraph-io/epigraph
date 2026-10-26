//! `epigraph-mcp` in the separate-signing-key mode (agent identity lineage
//! design D1, D2) refuses to start unless its signing key is an ACTIVE
//! `signing` key of the agent its identity key names, and refuses a half or
//! mixed configuration instead of falling back to a generated key.
//!
//! Driven through the COMPILED BINARY, so the tests prove `main` reads the two
//! variables and runs the check, not only that a check function exists. The
//! binary runs on stdio with stdin closed: a server past the check logs
//! "Agent identity ready" and then exits on EOF. With `EPIGRAPH_OPERATOR_ID`
//! set, `self_link` resolves (and could create) the server's agent BEFORE
//! serving, which is the boot path that shows which agent `main` wired the
//! identity key to, and that the check runs before anything creates a row.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use epigraph_crypto::AgentSigner;
use epigraph_db::{AgentIdentityRepository, IdentityRegistration, PromptFile};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Logged on both transports after the boot checks.
const PAST_THE_CHECK: &str = "Agent identity ready";

/// Spelled here, not imported from the binary: a test that shares its
/// subject's text cannot detect a change to it.
const NOT_ACTIVE: &str = "is not an active signing key of";
const NO_IDENTITY: &str = "no agent has the identity public key";
const BOTH_OR_NEITHER: &str =
    "EPIGRAPH_AGENT_IDENTITY_PUBKEY and EPIGRAPH_AGENT_SIGNING_KEY must be set together";

const HTTP_REFUSED: &str = "the separate-signing-key mode is stdio-only";

/// A test-only HMAC secret, long enough for the listener's secret check.
const HTTP_TEST_JWT_SECRET: &str = "signing-key-boot-refusal-test-secret-not-for-any-deployment";

const ATTESTOR: &str = "epigraph_identity_attestor";

enum Outcome {
    Exited { code: Option<i32>, stderr: String },
    PastTheCheck { stderr: String },
}

/// Spawn the binary and wait until its log contains `until` (then kill it) or
/// it exits.
fn run_mcp(db_url: &str, env: &[(&str, String)], extra_args: &[&str], until: &str) -> Outcome {
    let mut args = vec!["--database-url", db_url];
    args.extend_from_slice(extra_args);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"));
    // The separate-signing-key pair may be exported on the runner (by a host
    // in that mode): cleared with the rest, so only what the test sets below
    // reaches the child.
    cmd.args(&args)
        .env_remove("EPIGRAPH_AGENT_IDENTITY_PUBKEY")
        .env_remove("EPIGRAPH_AGENT_SIGNING_KEY")
        .env_remove("EPIGRAPH_MCP_AGENT_KEY")
        .env_remove("EPIGRAPH_AGENT_MODEL")
        .env_remove("EPIGRAPH_AGENT_SYSTEM_PROMPT")
        .env_remove("EPIGRAPH_AGENT_SYSTEM_PROMPT_HASH")
        .env_remove("EPIGRAPH_JWT_SECRET")
        .env_remove("EPIGRAPH_OPERATOR_ID")
        .env_remove("EPIGRAPH_MCP_EXTENSIONS")
        .env_remove("EPIGRAPH_SESSION_GUC_MODE")
        .env_remove("EPIGRAPH_OPERATOR_LINK_ENFORCEMENT")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env_remove("OPENAI_API_KEY")
        .env("RUST_LOG", "info");
    // The caller's variables last, so a test may set one the list above clears
    // (EPIGRAPH_OPERATOR_ID).
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp bin");
    let stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut log = String::new();
    loop {
        while let Ok(line) = rx.try_recv() {
            log.push_str(&line);
            log.push('\n');
        }
        if log.contains(until) {
            let _ = child.kill();
            let _ = child.wait();
            return Outcome::PastTheCheck { stderr: log };
        }
        if let Some(status) = child.try_wait().expect("try_wait") {
            while let Ok(line) = rx.recv_timeout(Duration::from_millis(500)) {
                log.push_str(&line);
                log.push('\n');
            }
            if log.contains(until) {
                return Outcome::PastTheCheck { stderr: log };
            }
            return Outcome::Exited {
                code: status.code(),
                stderr: log,
            };
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("epigraph-mcp neither exited nor passed its boot checks within 90s:\n{log}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

async fn run(
    pool: &PgPool,
    env: Vec<(&'static str, String)>,
    extra_args: &'static [&'static str],
) -> Outcome {
    run_until(pool, env, extra_args, PAST_THE_CHECK).await
}

async fn run_until(
    pool: &PgPool,
    env: Vec<(&'static str, String)>,
    extra_args: &'static [&'static str],
    until: &'static str,
) -> Outcome {
    let url = fixture::database_url_for(pool).await;
    tokio::task::spawn_blocking(move || run_mcp(&url, &env, extra_args, until))
        .await
        .expect("join")
}

fn new_mode_env(identity: &[u8; 32], signing_secret: &[u8; 32]) -> Vec<(&'static str, String)> {
    vec![
        ("EPIGRAPH_AGENT_IDENTITY_PUBKEY", hex::encode(identity)),
        ("EPIGRAPH_AGENT_SIGNING_KEY", hex::encode(signing_secret)),
    ]
}

async fn register(pool: &PgPool, identity: [u8; 32], signing: [u8; 32]) -> Uuid {
    let reg = IdentityRegistration {
        identity_pubkey: identity,
        parent_agent_id: None,
        model: "test-model-s2-boot".to_string(),
        prompt_hash: blake3::hash(&identity).to_hex().to_string(),
        group_folder: "g-s2-boot".to_string(),
        signing_pubkey: Some(signing),
        identity_md: PromptFile::Absent,
        global_claude_md: PromptFile::Absent,
        group_claude_md: PromptFile::Absent,
        learned_md: PromptFile::Stored(b"boot lesson\n".to_vec()),
        in_prompt: json!({"learned_md": true}),
        runner_version: None,
        host_sha: None,
    };
    fixture::as_role(pool, ATTESTOR, |mut conn| async move {
        let r = AgentIdentityRepository::register(&mut conn, &reg).await;
        (conn, r)
    })
    .await
    .expect("register")
    .agent_id
}

async fn agent_count_with_key(pool: &PgPool, key: &[u8; 32]) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_one(pool)
        .await
        .expect("count")
}

/// Positive control and refusal over the same database: the registered pair
/// boots; the same identity with a signing key registered nowhere exits 1
/// naming the key; an identity no agent carries exits 1 and creates no row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_binary_boots_only_on_a_registered_signing_key(pool: PgPool) {
    let identity = AgentSigner::from_bytes(&[0xA1; 32])
        .expect("id")
        .public_key();
    let signing_secret = [0xA2u8; 32];
    let signing = AgentSigner::from_bytes(&signing_secret)
        .expect("sk")
        .public_key();
    register(&pool, identity, signing).await;

    match run(&pool, new_mode_env(&identity, &signing_secret), &[]).await {
        Outcome::PastTheCheck { .. } => {}
        Outcome::Exited { code, stderr } => {
            panic!("the registered pair must boot; exited {code:?}:\n{stderr}")
        }
    }

    let unregistered_secret = [0xA3u8; 32];
    match run(&pool, new_mode_env(&identity, &unregistered_secret), &[]).await {
        Outcome::Exited { code, stderr } => {
            assert_eq!(code, Some(1), "{stderr}");
            assert!(stderr.contains(NOT_ACTIVE), "{stderr}");
            assert!(
                !stderr.contains(&hex::encode(unregistered_secret)),
                "the refusal must never echo the private key:\n{stderr}"
            );
        }
        Outcome::PastTheCheck { stderr } => {
            panic!("an unregistered signing key must not boot:\n{stderr}")
        }
    }

    let unknown_identity = AgentSigner::from_bytes(&[0xA4; 32])
        .expect("id")
        .public_key();
    match run(&pool, new_mode_env(&unknown_identity, &signing_secret), &[]).await {
        Outcome::Exited { code, stderr } => {
            assert_eq!(code, Some(1), "{stderr}");
            assert!(stderr.contains(NO_IDENTITY), "{stderr}");
        }
        Outcome::PastTheCheck { stderr } => {
            panic!("an unregistered identity must not boot:\n{stderr}")
        }
    }
    assert_eq!(
        agent_count_with_key(&pool, &unknown_identity).await,
        0,
        "a refused boot creates no agent for the identity"
    );
}

/// Half a configuration is refused, not completed with a generated key: the
/// signing key without the identity, and the identity without the signing key.
/// So is the new mode combined with a legacy `--agent-key`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_half_or_mixed_configuration_is_refused(pool: PgPool) {
    let identity = AgentSigner::from_bytes(&[0xB1; 32])
        .expect("id")
        .public_key();
    let signing_secret = [0xB2u8; 32];
    let signing = AgentSigner::from_bytes(&signing_secret)
        .expect("sk")
        .public_key();
    register(&pool, identity, signing).await;

    for env in [
        vec![("EPIGRAPH_AGENT_SIGNING_KEY", hex::encode(signing_secret))],
        vec![("EPIGRAPH_AGENT_IDENTITY_PUBKEY", hex::encode(identity))],
    ] {
        match run(&pool, env, &[]).await {
            Outcome::Exited { code, stderr } => {
                assert_ne!(code, Some(0), "{stderr}");
                assert!(stderr.contains(BOTH_OR_NEITHER), "{stderr}");
            }
            Outcome::PastTheCheck { stderr } => {
                panic!("half a configuration must not boot:\n{stderr}")
            }
        }
    }

    const LEGACY_KEY: &[&str] = &[
        "--agent-key",
        "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
    ];
    match run(&pool, new_mode_env(&identity, &signing_secret), LEGACY_KEY).await {
        Outcome::Exited { code, stderr } => assert_ne!(code, Some(0), "{stderr}"),
        Outcome::PastTheCheck { stderr } => {
            panic!("the new mode with --agent-key must not boot:\n{stderr}")
        }
    }
}

/// Logged by `self_link` once the operator link is recorded.
const LINKED: &str = "operator link recorded";

fn with_operator(
    mut env: Vec<(&'static str, String)>,
    operator: Uuid,
) -> Vec<(&'static str, String)> {
    env.push(("EPIGRAPH_OPERATOR_ID", operator.to_string()));
    env
}

async fn operator_of(pool: &PgPool, agent: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT operator_id FROM operator_links WHERE agent_id = $1")
        .bind(agent)
        .fetch_optional(pool)
        .await
        .expect("operator link")
}

/// `main`'s stdio wiring, observed on the path that RESOLVES the agent at
/// boot: with `EPIGRAPH_OPERATOR_ID` set, `self_link` finds (or creates) the
/// server's agent before serving. In the separate-signing-key mode that must
/// be the agent the IDENTITY key names, so the link lands on the registered
/// agent and no agent is ever keyed by the signing key.
#[sqlx::test(migrations = "../../migrations")]
async fn the_stdio_boot_links_the_identity_agent_not_a_signing_key_agent(pool: PgPool) {
    let identity = AgentSigner::from_bytes(&[0xD1; 32])
        .expect("id")
        .public_key();
    let signing_secret = [0xD2u8; 32];
    let signing = AgentSigner::from_bytes(&signing_secret)
        .expect("sk")
        .public_key();
    let agent = register(&pool, identity, signing).await;
    let (operator, _) = fixture::seed_human_operator(&pool, "s2-stdio-operator").await;
    assert_eq!(
        operator_of(&pool, agent).await,
        None,
        "calibration: unlinked"
    );

    let env = with_operator(new_mode_env(&identity, &signing_secret), operator);
    match run_until(&pool, env, &[], LINKED).await {
        Outcome::PastTheCheck { .. } => {}
        Outcome::Exited { code, stderr } => {
            panic!("the registered pair with an operator must link; exited {code:?}:\n{stderr}")
        }
    }
    assert_eq!(
        operator_of(&pool, agent).await,
        Some(operator),
        "the link lands on the agent the identity key names"
    );
    assert_eq!(
        agent_count_with_key(&pool, &signing).await,
        0,
        "no agent is keyed by the signing key"
    );
}

/// The boot check runs BEFORE `self_link`, the stdio step that would create
/// the server's agent row: an identity no agent carries, booted with an
/// operator, exits 1 and leaves no agent for the identity (or the signing
/// key) behind. So does a registered identity with a stray signing key.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_stdio_boot_with_an_operator_creates_no_agent(pool: PgPool) {
    let (operator, _) = fixture::seed_human_operator(&pool, "s2-refused-operator").await;
    let signing_secret = [0xE2u8; 32];
    let signing = AgentSigner::from_bytes(&signing_secret)
        .expect("sk")
        .public_key();

    let unknown = AgentSigner::from_bytes(&[0xE1; 32])
        .expect("id")
        .public_key();
    let env = with_operator(new_mode_env(&unknown, &signing_secret), operator);
    match run_until(&pool, env, &[], LINKED).await {
        Outcome::Exited { code, stderr } => {
            assert_eq!(code, Some(1), "{stderr}");
            assert!(stderr.contains(NO_IDENTITY), "{stderr}");
        }
        Outcome::PastTheCheck { stderr } => {
            panic!("an unregistered identity must not link:\n{stderr}")
        }
    }
    assert_eq!(agent_count_with_key(&pool, &unknown).await, 0);
    assert_eq!(agent_count_with_key(&pool, &signing).await, 0);

    let identity = AgentSigner::from_bytes(&[0xE3; 32])
        .expect("id")
        .public_key();
    let registered_signing = AgentSigner::from_bytes(&[0xE4; 32])
        .expect("sk")
        .public_key();
    let agent = register(&pool, identity, registered_signing).await;
    let env = with_operator(new_mode_env(&identity, &signing_secret), operator);
    match run_until(&pool, env, &[], LINKED).await {
        Outcome::Exited { code, stderr } => {
            assert_eq!(code, Some(1), "{stderr}");
            assert!(stderr.contains(NOT_ACTIVE), "{stderr}");
        }
        Outcome::PastTheCheck { stderr } => {
            panic!("a stray signing key must not link:\n{stderr}")
        }
    }
    assert_eq!(operator_of(&pool, agent).await, None, "nothing was linked");
    assert_eq!(agent_count_with_key(&pool, &signing).await, 0);
}

/// The separate-signing-key mode is stdio-only: on an HTTP listener its
/// attested signing key would sign `blake3(content)` for ANY caller, an oracle
/// for signatures that bind to this agent. Refused before the database is
/// touched (the URL is unreachable, so a missing gate fails on the connect
/// with a different message), on a TCP and on a unix-socket listener.
///
/// The positive control is `the_binary_boots_only_on_a_registered_signing_key`:
/// the same pair on stdio boots.
#[test]
fn the_separate_signing_key_mode_is_refused_on_an_http_listener() {
    let identity = AgentSigner::from_bytes(&[0xC1; 32])
        .expect("id")
        .public_key();
    let signing_secret = [0xC2u8; 32];
    for listen in [
        &[
            "--listen",
            "127.0.0.1:0",
            "--jwt-secret",
            HTTP_TEST_JWT_SECRET,
        ][..],
        &[
            "--listen",
            "unix:/tmp/epigraph-s2-never-bound.sock",
            "--allow-unauthenticated-http",
        ][..],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"))
            .env_remove("EPIGRAPH_JWT_SECRET")
            .env_remove("EPIGRAPH_OPERATOR_ID")
            .env_remove("EPIGRAPH_MCP_AGENT_KEY")
            .env_remove("EPIGRAPH_AGENT_MODEL")
            .env_remove("MAINTENANCE_DATABASE_URL")
            .env("EPIGRAPH_AGENT_IDENTITY_PUBKEY", hex::encode(identity))
            .env("EPIGRAPH_AGENT_SIGNING_KEY", hex::encode(signing_secret))
            .args([
                "--database-url",
                "postgres://invalid:invalid@127.0.0.1:1/nope",
            ])
            .args(listen)
            .stdin(Stdio::null())
            .output()
            .expect("run mcp bin");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{listen:?}: {stderr}");
        assert!(stderr.contains(HTTP_REFUSED), "{listen:?}: {stderr}");
        assert!(
            !stderr.contains(&hex::encode(signing_secret)),
            "the refusal must never echo the private key:\n{stderr}"
        );
    }
}

/// The signing PRIVATE key is read from the environment only: on the command
/// line it would sit in `ps` output and `/proc/<pid>/cmdline`, readable by
/// every process in the container. `--agent-signing-key` is therefore not an
/// argument at all (a usage error, exit 2, before anything else runs), and the
/// error never echoes the value. The positive control is every boot above,
/// which passes the key through `EPIGRAPH_AGENT_SIGNING_KEY`.
#[test]
fn the_signing_key_is_not_accepted_on_the_command_line() {
    let identity = AgentSigner::from_bytes(&[0xF1; 32])
        .expect("id")
        .public_key();
    let signing_secret_hex = hex::encode([0xF2u8; 32]);
    let out = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"))
        .env_remove("EPIGRAPH_AGENT_SIGNING_KEY")
        .env_remove("EPIGRAPH_MCP_AGENT_KEY")
        .env_remove("EPIGRAPH_AGENT_MODEL")
        .env_remove("EPIGRAPH_OPERATOR_ID")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env("EPIGRAPH_AGENT_IDENTITY_PUBKEY", hex::encode(identity))
        .args([
            "--database-url",
            "postgres://invalid:invalid@127.0.0.1:1/nope",
            "--agent-signing-key",
            &signing_secret_hex,
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run mcp bin");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "--agent-signing-key must be a usage error, not a key source"
    );
    assert!(stderr.contains("--agent-signing-key"), "{stderr}");
    assert!(
        !stderr.contains(&signing_secret_hex[..16]),
        "the usage error must never echo the private key"
    );
}
