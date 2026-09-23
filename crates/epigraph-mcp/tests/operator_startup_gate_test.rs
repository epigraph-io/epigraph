//! Brief constraint 2 — an operated signer never serves HTTP — driven through
//! the COMPILED BINARY, so these prove `main` actually consults the gates in
//! `epigraph_mcp::operator` (whose pure arms are unit-tested in that module).
//!
//! An HTTP listener (`epigraph-mcp-auth` / `-http` in production) authors every
//! authenticated caller's claims as ONE signer agent. If that agent were
//! operated, every external caller would write into the operator's personal
//! group with the operator's ownership. Two ways in, two gates:
//!
//! 1. `--operator-id` / `EPIGRAPH_OPERATOR_ID` together with `--listen` —
//!    refused before any database work;
//! 2. a signer that ALREADY has a live operator link (recorded by an earlier
//!    stdio process under the same key) — refused after connecting, before
//!    the listener binds.
//!
//! The already-linked arm is paired with a CALIBRATION: the same configuration
//! with no link must reach "Starting EpiGraph MCP server", so the refusal
//! cannot be passing because the process fails to start for some other reason.
//! A missing gate makes the refusal arm hang in `serve`, so every spawn is
//! bounded by a timeout and killed on expiry.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use epigraph_crypto::AgentSigner;
use sqlx::PgPool;
use uuid::Uuid;

fn mcp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_epigraph-mcp-full")
}

/// A test-only HMAC secret: long enough for `assert_production_secret`, not
/// the committed dev literal, and never used outside this file.
const TEST_JWT_SECRET: &str = "operator-startup-gate-test-secret-not-for-any-deployment";

/// `--listen` + `--operator-id` is refused before the database is touched (the
/// URL below is unreachable; a missing gate would fail on the connect with a
/// different message).
#[test]
fn an_http_listener_refuses_an_operator_flag() {
    let out = Command::new(mcp_bin())
        .args([
            "--database-url",
            "postgres://invalid:invalid@127.0.0.1:1/nope",
            "--listen",
            "127.0.0.1:0",
            "--jwt-secret",
            TEST_JWT_SECRET,
            "--agent-key",
            &"61".repeat(32),
            "--operator-id",
            &Uuid::new_v4().to_string(),
        ])
        .env_remove("EPIGRAPH_JWT_SECRET")
        .env_remove("EPIGRAPH_OPERATOR_ID")
        .output()
        .expect("run mcp bin");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("EPIGRAPH_OPERATOR_ID") && stderr.contains("refused on an HTTP listener"),
        "stderr must name the refused operator declaration; got: {stderr}"
    );
}

/// The same through the environment variable epiclaw-host sets, which is the
/// realistic way it would leak onto a shared listener's unit.
#[test]
fn an_http_listener_refuses_the_operator_env_var() {
    let out = Command::new(mcp_bin())
        .args([
            "--database-url",
            "postgres://invalid:invalid@127.0.0.1:1/nope",
            "--listen",
            "unix:/tmp/epigraph-operator-gate-never-bound.sock",
            "--allow-unauthenticated-http",
            "--agent-key",
            &"62".repeat(32),
        ])
        .env_remove("EPIGRAPH_JWT_SECRET")
        .env("EPIGRAPH_OPERATOR_ID", Uuid::new_v4().to_string())
        .output()
        .expect("run mcp bin");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refused on an HTTP listener"),
        "EPIGRAPH_OPERATOR_ID must be refused on an HTTP listener; got: {stderr}"
    );
}

/// `--operator-id` without a declared identity (rung 4) is refused on stdio
/// too: each start would enrol a fresh throwaway agent as a writer.
#[test]
fn an_operator_without_a_declared_identity_is_refused() {
    let out = Command::new(mcp_bin())
        .args([
            "--database-url",
            "postgres://invalid:invalid@127.0.0.1:1/nope",
            "--operator-id",
            &Uuid::new_v4().to_string(),
        ])
        .env_remove("EPIGRAPH_AGENT_MODEL")
        .env_remove("EPIGRAPH_OPERATOR_ID")
        .stdin(Stdio::null())
        .output()
        .expect("run mcp bin");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("requires a declared signer identity"),
        "got: {stderr}"
    );
}

enum Outcome {
    Exited { code: Option<i32>, stderr: String },
    Serving { stderr: String },
}

/// Spawn an HTTP listener against `db_url` signing as `key_hex`, and wait until
/// it either exits or logs that it is serving. Kills it in the second case.
fn spawn_listener(db_url: &str, key_hex: &str) -> Outcome {
    let mut child = Command::new(mcp_bin())
        .args([
            "--database-url",
            db_url,
            "--listen",
            "127.0.0.1:0",
            "--jwt-secret",
            TEST_JWT_SECRET,
            "--agent-key",
            key_hex,
        ])
        .env_remove("EPIGRAPH_JWT_SECRET")
        .env_remove("EPIGRAPH_OPERATOR_ID")
        .env_remove("EPIGRAPH_MCP_EXTENSIONS")
        .env_remove("EPIGRAPH_SESSION_GUC_MODE")
        .env_remove("OPENAI_API_KEY")
        .env("RUST_LOG", "info")
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
        if log.contains("Starting EpiGraph MCP server") {
            let _ = child.kill();
            let _ = child.wait();
            return Outcome::Serving { stderr: log };
        }
        if let Some(status) = child.try_wait().expect("try_wait") {
            std::thread::sleep(Duration::from_millis(200));
            while let Ok(line) = rx.try_recv() {
                log.push_str(&line);
                log.push('\n');
            }
            return Outcome::Exited {
                code: status.code(),
                stderr: log,
            };
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("listener neither exited nor started serving within 90s; stderr:\n{log}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

async fn register_signer(pool: &PgPool, seed: u8) -> (Uuid, String) {
    let signer = AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let pk = signer.public_key();
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(pk.to_vec())
        .execute(pool)
        .await
        .expect("register the listener's signer agent");
    (agent, format!("{seed:02x}").repeat(32))
}

/// A listener whose signer ALREADY has a live operator link refuses to start;
/// the identical configuration without the link serves.
#[sqlx::test(migrations = "../../migrations")]
async fn an_http_listener_refuses_a_signer_that_already_has_an_operator_link(pool: PgPool) {
    let db_url = fixture::database_url_for(&pool).await;
    let (operator, _) = fixture::seed_agent_with_group(&pool, "operator").await;

    // CALIBRATION: unlinked signer, same everything else -> serves.
    let (_unlinked, unlinked_key) = register_signer(&pool, 0x63).await;
    let url = db_url.clone();
    match tokio::task::spawn_blocking(move || spawn_listener(&url, &unlinked_key))
        .await
        .expect("join")
    {
        Outcome::Serving { .. } => {}
        Outcome::Exited { code, stderr } => panic!(
            "CALIBRATION: an UNLINKED signer's listener must start, or the refusal below proves \
             nothing; exited {code:?}:\n{stderr}"
        ),
    }

    let (linked, linked_key) = register_signer(&pool, 0x64).await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_operator(&mut conn, linked, operator)
        .await
        .expect("link the signer, as an earlier stdio process would have");
    drop(conn);

    let url = db_url.clone();
    match tokio::task::spawn_blocking(move || spawn_listener(&url, &linked_key))
        .await
        .expect("join")
    {
        Outcome::Exited { code, stderr } => {
            assert_ne!(code, Some(0), "the refusal must be a failing exit");
            assert!(
                stderr.contains("has an operator link") && stderr.contains(&operator.to_string()),
                "stderr must name the link that refused the listener; got:\n{stderr}"
            );
        }
        Outcome::Serving { stderr } => panic!(
            "an HTTP listener whose signer is OPERATED started serving: every caller would write \
             into the operator's group.\n{stderr}"
        ),
    }

    // A RETIRED link on the signer refuses too: the gate reads the AUTHOR
    // record, retired included, because the operator would otherwise own every
    // HTTP caller's claims (the signer authors them all).
    let (retired, retired_key) = register_signer(&pool, 0x65).await;
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_db::AgentRepository::link_retired_agent(&mut conn, retired, operator)
        .await
        .expect("record a retired link on the signer");
    drop(conn);
    let url = db_url.clone();
    match tokio::task::spawn_blocking(move || spawn_listener(&url, &retired_key))
        .await
        .expect("join")
    {
        Outcome::Exited { code, stderr } => {
            assert_ne!(code, Some(0), "the refusal must be a failing exit");
            assert!(
                stderr.contains("has an operator link") && stderr.contains("a retired link"),
                "stderr must name the retired link that refused the listener; got:\n{stderr}"
            );
        }
        Outcome::Serving { stderr } => panic!(
            "an HTTP listener whose signer has a RETIRED link started serving: the operator would \
             own every caller's claims.\n{stderr}"
        ),
    }
}

/// Spawn a STDIO process with a derived identity and `--operator-id`, and wait
/// until it logs the link outcome (it then blocks in the MCP handshake, so it is
/// killed). Returns the process's stderr.
fn spawn_stdio_with_operator(
    db_url: &str,
    model: &str,
    prompt_hash: &str,
    operator: Uuid,
) -> String {
    let mut child = Command::new(mcp_bin())
        .args([
            "--database-url",
            db_url,
            "--agent-model",
            model,
            "--agent-system-prompt-hash",
            prompt_hash,
            "--operator-id",
            &operator.to_string(),
        ])
        .env_remove("EPIGRAPH_OPERATOR_ID")
        .env_remove("EPIGRAPH_MCP_EXTENSIONS")
        .env_remove("EPIGRAPH_SESSION_GUC_MODE")
        .env_remove("OPENAI_API_KEY")
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
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
        if log.contains("operator link recorded") || log.contains("operator link is REVOKED") {
            let _ = child.kill();
            let _ = child.wait();
            return log;
        }
        if child.try_wait().expect("try_wait").is_some() || Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            std::thread::sleep(Duration::from_millis(200));
            while let Ok(line) = rx.try_recv() {
                log.push_str(&line);
                log.push('\n');
            }
            return log;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The epiclaw shape end to end: a stdio process with a derived identity and
/// `EPIGRAPH_OPERATOR_ID` records its link at startup; after the operator
/// revokes it, the NEXT start reports the revocation and does NOT restore it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stdio_agent_self_links_at_startup_and_a_restart_does_not_revive_a_revocation(
    pool: PgPool,
) {
    let db_url = fixture::database_url_for(&pool).await;
    let (operator, _) = fixture::seed_agent_with_group(&pool, "operator").await;
    let model = "operator-gate-test-model";
    let prompt_hash = "ab".repeat(32);
    let pk = epigraph_crypto::keypair_from_llm_agent_prehashed(model, &prompt_hash).public_key();

    let (url, h) = (db_url.clone(), prompt_hash.clone());
    let log =
        tokio::task::spawn_blocking(move || spawn_stdio_with_operator(&url, model, &h, operator))
            .await
            .expect("join");
    assert!(
        log.contains("operator link recorded"),
        "first start must record the link:\n{log}"
    );

    let agent: Uuid = sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(pk.to_vec())
        .fetch_one(&pool)
        .await
        .expect("the process registered its derived agent");
    let group: Uuid = sqlx::query_scalar(
        "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text",
    )
    .bind(operator)
    .fetch_one(&pool)
    .await
    .expect("operator group");
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM group_memberships WHERE group_id = $1 AND agent_id = $2 \
                          AND role = 'writer' AND revoked_at IS NULL)",
    )
    .bind(group)
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("membership");
    assert!(
        live,
        "the startup link must give the agent a live writer membership"
    );

    epigraph_db::GroupMembershipRepository::revoke_member_unless_last_admin(&pool, group, agent)
        .await
        .expect("the operator revokes the agent");

    let (url, h) = (db_url.clone(), prompt_hash.clone());
    let log =
        tokio::task::spawn_blocking(move || spawn_stdio_with_operator(&url, model, &h, operator))
            .await
            .expect("join");
    assert!(
        log.contains("operator link is REVOKED"),
        "a restart must REPORT the revocation:\n{log}"
    );
    let live_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships WHERE group_id = $1 AND agent_id = $2 \
            AND revoked_at IS NULL",
    )
    .bind(group)
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("membership after restart");
    assert_eq!(
        live_after, 0,
        "a restart must NOT revive a revoked operator membership"
    );
}
