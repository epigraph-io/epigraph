//! Backlog ac52fcb0: `epigraph-mcp` checked its signing key's admission only
//! at boot (and only in the separate-signing-key mode), so a key revoked,
//! rotated out or past its window while the server ran kept signing every
//! claim and edge its tools wrote, each refused by the verifiers, until a
//! restart. The running server now watches the key
//! (`signing_identity::spawn_admission_watch`, on the shared
//! `epigraph_db::signer_admission` watch the API's edge signer runs) and EXITS
//! once the verifiers stop admitting it.
//!
//! Driven through the COMPILED BINARY on stdio with stdin held OPEN: with
//! stdin closed the server exits on EOF, and "the process stopped" would hold
//! on any build. Every stop is preceded by a positive control: the same
//! process still running after several re-checks of an admitted key. The
//! re-check runs every second here (`EPIGRAPH_MCP_SIGNING_KEY_RECHECK_SECS`);
//! production defaults to 30 s.
//!
//! Proof on the old code: neither binary run below ever exits after the
//! revocation (there was no watch), so both tests fail on the exit deadline.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
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
const NO_LONGER_ADMITTED: &str = "is no longer admitted by the claim and edge verifiers";
const NOT_ADMITTED_WARNING: &str = "do not admit this signing key for its agent";

const ATTESTOR: &str = "epigraph_identity_attestor";

/// A running binary, its stdin held open, its stderr collected.
struct Running {
    child: Child,
    _stdin: std::process::ChildStdin,
    lines: mpsc::Receiver<String>,
    log: String,
}

impl Running {
    fn spawn(db_url: &str, env: &[(&str, String)]) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"));
        cmd.args(["--database-url", db_url])
            .env_remove("EPIGRAPH_AGENT_IDENTITY_PUBKEY")
            .env_remove("EPIGRAPH_AGENT_SIGNING_KEY")
            .env_remove("EPIGRAPH_AGENT_SIGNING_KEY_FILE")
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
            .env("EPIGRAPH_MCP_SIGNING_KEY_RECHECK_SECS", "1")
            .env("RUST_LOG", "info");
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mcp bin");
        let stdin = child.stdin.take().expect("stdin");
        let stderr = child.stderr.take().expect("stderr");
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            _stdin: stdin,
            lines: rx,
            log: String::new(),
        }
    }

    fn drain(&mut self) {
        while let Ok(line) = self.lines.try_recv() {
            self.log.push_str(&line);
            self.log.push('\n');
        }
    }

    /// Wait until the log contains `text`; panics if the process exits first.
    fn wait_for_log(&mut self, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            self.drain();
            if self.log.contains(text) {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                std::thread::sleep(Duration::from_millis(300));
                self.drain();
                panic!("exited ({status}) before logging {text:?}:\n{}", self.log);
            }
            assert!(
                Instant::now() < deadline,
                "no {text:?} within 90s:\n{}",
                self.log
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Positive control: still running after `secs` re-checks.
    fn still_running_after(&mut self, secs: u64, what: &str) {
        std::thread::sleep(Duration::from_secs(secs));
        self.drain();
        if let Some(status) = self.child.try_wait().expect("try_wait") {
            std::thread::sleep(Duration::from_millis(300));
            self.drain();
            panic!("{what}: the server stopped ({status}):\n{}", self.log);
        }
    }

    /// The exit code once the process exits; panics after 30 s still running.
    fn exit_code(mut self, what: &str) -> (Option<i32>, String) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                std::thread::sleep(Duration::from_millis(300));
                self.drain();
                return (status.code(), std::mem::take(&mut self.log));
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                self.drain();
                panic!(
                    "{what}: the server kept running (and signing) for 30s after its key lost \
                     admission:\n{}",
                    self.log
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn register(pool: &PgPool, identity: [u8; 32], signing: [u8; 32]) -> Uuid {
    let reg = IdentityRegistration {
        identity_pubkey: identity,
        parent_agent_id: None,
        model: "test-model-admission-watch".to_string(),
        prompt_hash: blake3::hash(&identity).to_hex().to_string(),
        group_folder: "g-admission-watch".to_string(),
        signing_pubkey: Some(signing),
        identity_md: PromptFile::Absent,
        global_claude_md: PromptFile::Absent,
        group_claude_md: PromptFile::Absent,
        learned_md: PromptFile::Absent,
        in_prompt: json!({}),
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

/// Separate-signing-key mode (the agent containers' mode): the host
/// registered the signing key, the server boots on it and keeps serving while
/// it is admitted; once the row is revoked (as after a suspected exposure)
/// the server exits 1 naming the key, instead of signing every later write
/// with a key the verifiers refuse.
///
/// Mutation: `Arming::FromBoot` read as `AfterFirstAdmission` keeps this
/// passing (the key was admitted first); `signer_key_admission` reading every
/// key as `Open` -> the server never exits and this fails.
#[sqlx::test(migrations = "../../migrations")]
async fn revoking_the_running_servers_signing_key_stops_it(pool: PgPool) {
    let identity = AgentSigner::from_bytes(&[0xB1; 32])
        .expect("id")
        .public_key();
    let signing_secret = [0xB2u8; 32];
    let signing = AgentSigner::from_bytes(&signing_secret)
        .expect("sk")
        .public_key();
    let agent = register(&pool, identity, signing).await;

    let url = fixture::database_url_for(&pool).await;
    let env = vec![
        ("EPIGRAPH_AGENT_IDENTITY_PUBKEY", hex::encode(identity)),
        ("EPIGRAPH_AGENT_SIGNING_KEY", hex::encode(signing_secret)),
    ];
    let mut server = tokio::task::spawn_blocking(move || {
        let mut server = Running::spawn(&url, &env);
        server.wait_for_log(PAST_THE_CHECK);
        server.still_running_after(4, "admitted signing key");
        server
    })
    .await
    .expect("join");

    let revoked = sqlx::query(
        "UPDATE agent_keys SET status = 'revoked', valid_until = now(), \
                revocation_reason = 'suspected exposure' \
          WHERE agent_id = $1 AND public_key = $2 AND key_type = 'signing'",
    )
    .bind(agent)
    .bind(signing.as_slice())
    .execute(&pool)
    .await
    .expect("revoke (test superuser)")
    .rows_affected();
    assert_eq!(revoked, 1, "CALIBRATION: the registered signing row");

    server.drain();
    let (code, log) = tokio::task::spawn_blocking(move || server.exit_code("revoked key"))
        .await
        .expect("join");
    assert_eq!(code, Some(1), "{log}");
    assert!(log.contains(NO_LONGER_ADMITTED), "{log}");
    assert!(log.contains(&hex::encode(signing)), "{log}");
    assert!(log.contains(&agent.to_string()), "{log}");
}

/// A legacy key rung (`EPIGRAPH_MCP_AGENT_KEY`: the signer's key is its
/// agent's own key) was never checked at boot, and the watch does not add a
/// boot refusal: a key the verifiers do not admit when the server starts is
/// WARNED about and the server keeps serving (as it always has). Once the key
/// is admitted the watch is armed, and losing admission then stops the
/// server.
///
/// Mutations: arming from boot on this rung -> the first phase exits and this
/// fails; never arming -> the last phase never exits and this fails.
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_key_rung_stops_once_an_admitted_key_loses_admission(pool: PgPool) {
    let secret = [0xC3u8; 32];
    let key = AgentSigner::from_bytes(&secret).expect("key").public_key();
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(key.as_slice())
        .execute(&pool)
        .await
        .expect("seed the server's agent");
    // The bare key carries a revoked attested row: not admitted at boot.
    sqlx::query(
        "INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from, valid_until) \
         VALUES ($1, $2, 'identity-legacy', 'revoked', now() - interval '1 day', now())",
    )
    .bind(agent)
    .bind(key.as_slice())
    .execute(&pool)
    .await
    .expect("a revoked legacy row (test superuser)");

    let url = fixture::database_url_for(&pool).await;
    let env = vec![("EPIGRAPH_MCP_AGENT_KEY", hex::encode(secret))];
    let mut server = tokio::task::spawn_blocking(move || {
        let mut server = Running::spawn(&url, &env);
        server.wait_for_log(PAST_THE_CHECK);
        server.wait_for_log(NOT_ADMITTED_WARNING);
        server.still_running_after(3, "never-admitted legacy key (no new boot refusal)");
        server
    })
    .await
    .expect("join");

    // Admitted: an active signing row for the same bytes. The watch arms.
    let row = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_keys (id, agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, $3, 'signing', 'active', now() - interval '1 minute')",
    )
    .bind(row)
    .bind(agent)
    .bind(key.as_slice())
    .execute(&pool)
    .await
    .expect("an active signing row (test superuser)");
    let mut server = tokio::task::spawn_blocking(move || {
        server.still_running_after(3, "admitted legacy key");
        server
    })
    .await
    .expect("join");

    sqlx::query("UPDATE agent_keys SET status = 'revoked', valid_until = now() WHERE id = $1")
        .bind(row)
        .execute(&pool)
        .await
        .expect("revoke");
    server.drain();
    let (code, log) = tokio::task::spawn_blocking(move || server.exit_code("revoked legacy key"))
        .await
        .expect("join");
    assert_eq!(code, Some(1), "{log}");
    assert!(log.contains(NO_LONGER_ADMITTED), "{log}");
    assert!(log.contains(&hex::encode(key)), "{log}");
}
