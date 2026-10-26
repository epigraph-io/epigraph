//! `epigraph-mcp` refuses to boot an agent attached to a role (migration 166's
//! `role_agents`) while no human holds that role, or while the agent's linked
//! human is not the holder: a gap fails fast at start, not at the first write.
//!
//! Driven through the COMPILED BINARY, so the tests prove `main` runs the
//! check, not only that a check function exists. The binary runs on stdio
//! with stdin closed: a server past its boot checks logs "Agent identity
//! ready" and then exits on EOF.
//!
//! POSITIVE CONTROLS, over the same database: an unattached agent boots, and
//! the attached agent boots once its linked human holds the role.
//!
//! The binary runs on the harness's SUPERUSER DSN (`epigraph_app` is NOLOGIN),
//! so these tests cannot see a missing application-role EXECUTE on
//! `epigraph_role_agent_may_run` (which would refuse EVERY boot). That grant is
//! pinned elsewhere: `epigraph-db/tests/agent_identity_lineage.rs`'s
//! `has_function_privilege` table, and `role_attached_agents.rs`'s
//! `rol01_is_named_and_the_repository_asks_may_run`, which asks on a pool
//! downgraded to `epigraph_app`.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use epigraph_crypto::AgentSigner;
use epigraph_db::{AgentIdentityRepository, AgentRepository, IdentityRegistration, PromptFile};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Logged on both transports after the boot checks.
const PAST_THE_CHECK: &str = "Agent identity ready";

/// Spelled here, not imported from the binary: a test that shares its
/// subject's text cannot detect a change to it.
const REFUSED: &str = "is attached to role";
const NO_HOLDER: &str = "no human holds it";
const NOT_HOLDER: &str = "is not linked to its holder";

const ATTESTOR: &str = "epigraph_identity_attestor";
const ROLE: &str = "role:test-boot-curator";

enum Outcome {
    Exited { code: Option<i32>, stderr: String },
    PastTheCheck { stderr: String },
}

/// Spawn the binary and wait until its log contains `until` (then kill it) or
/// it exits.
fn run_mcp(db_url: &str, env: &[(&str, String)], until: &str) -> Outcome {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_epigraph-mcp-full"));
    cmd.args(["--database-url", db_url])
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

async fn run(pool: &PgPool, env: Vec<(&'static str, String)>) -> Outcome {
    let url = fixture::database_url_for(pool).await;
    tokio::task::spawn_blocking(move || run_mcp(&url, &env, PAST_THE_CHECK))
        .await
        .expect("join")
}

fn env_for(identity: &[u8; 32], signing_secret: &[u8; 32]) -> Vec<(&'static str, String)> {
    vec![
        ("EPIGRAPH_AGENT_IDENTITY_PUBKEY", hex::encode(identity)),
        ("EPIGRAPH_AGENT_SIGNING_KEY", hex::encode(signing_secret)),
    ]
}

/// A host-registered identity (the separate-signing-key mode, as the host
/// starts a container), live-linked to `operator`. Returns the agent id and
/// the boot environment.
async fn registered_agent(
    pool: &PgPool,
    seed: u8,
    operator: Uuid,
) -> (Uuid, Vec<(&'static str, String)>) {
    let identity = AgentSigner::from_bytes(&[seed; 32])
        .expect("id")
        .public_key();
    let signing_secret = [seed.wrapping_add(1); 32];
    let signing = AgentSigner::from_bytes(&signing_secret)
        .expect("sk")
        .public_key();
    let reg = IdentityRegistration {
        identity_pubkey: identity,
        parent_agent_id: None,
        model: "test-model-166-boot".to_string(),
        prompt_hash: blake3::hash(&identity).to_hex().to_string(),
        group_folder: format!("g-166-boot-{seed}"),
        signing_pubkey: Some(signing),
        identity_md: PromptFile::Absent,
        global_claude_md: PromptFile::Absent,
        group_claude_md: PromptFile::Absent,
        learned_md: PromptFile::Stored(b"boot lesson\n".to_vec()),
        in_prompt: json!({"learned_md": true}),
        runner_version: None,
        host_sha: None,
    };
    let agent = fixture::as_role(pool, ATTESTOR, |mut conn| async move {
        let r = AgentIdentityRepository::register(&mut conn, &reg).await;
        (conn, r)
    })
    .await
    .expect("register")
    .agent_id;
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link");
    (agent, env_for(&identity, &signing_secret))
}

async fn seed_role(pool: &PgPool) {
    let node = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type, role, labels) \
         VALUES ($1, uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()), $2, 'role', \
                 'custom', ARRAY['role'])",
    )
    .bind(node)
    .bind(ROLE)
    .execute(pool)
    .await
    .expect("role node");
    sqlx::query(
        "INSERT INTO platform_roles (key, elevates, reads_audit, role_node_id, description) \
         VALUES ($1, false, false, $2, 'test role')",
    )
    .bind(ROLE)
    .bind(node)
    .execute(pool)
    .await
    .expect("platform role");
}

async fn attach(pool: &PgPool, agent: Uuid) {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query(
            "SELECT public.epigraph_attach_agent_to_role($1, $2, now() - interval '5 seconds', \
                                                         NULL, 'test attach')",
        )
        .bind(ROLE)
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("attach");
        (conn, ())
    })
    .await;
}

async fn grant(pool: &PgPool, holder: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT public.epigraph_grant_role($1, $2, now() - interval '5 seconds', NULL, NULL, \
                                           'test grant')",
    )
    .bind(ROLE)
    .bind(holder)
    .fetch_one(pool)
    .await
    .expect("grant")
}

fn expect_refused(outcome: Outcome, reason: &str, what: &str) {
    match outcome {
        Outcome::Exited { code, stderr } => {
            assert_eq!(code, Some(1), "{what}: {stderr}");
            assert!(stderr.contains(REFUSED), "{what}: {stderr}");
            assert!(
                stderr.contains(ROLE),
                "{what}: the refusal names the role: {stderr}"
            );
            assert!(stderr.contains(reason), "{what}: {stderr}");
        }
        Outcome::PastTheCheck { stderr } => panic!("{what} must not boot:\n{stderr}"),
    }
}

fn expect_booted(outcome: Outcome, what: &str) {
    match outcome {
        Outcome::PastTheCheck { .. } => {}
        Outcome::Exited { code, stderr } => panic!("{what} must boot; exited {code:?}:\n{stderr}"),
    }
}

/// No holder: refused. The linked human takes the role: boots. POSITIVE
/// CONTROL: an unattached agent of the same human boots in the gap.
#[sqlx::test(migrations = "../../migrations")]
async fn an_attached_agent_boots_only_while_its_human_holds_the_role(pool: PgPool) {
    seed_role(&pool).await;
    let (h, _) = fixture::seed_human_operator(&pool, "boot-holder").await;
    let (attached, attached_env) = registered_agent(&pool, 0x61, h).await;
    let (_plain, plain_env) = registered_agent(&pool, 0x71, h).await;
    attach(&pool, attached).await;

    expect_refused(run(&pool, attached_env.clone()).await, NO_HOLDER, "a gap");
    expect_booted(
        run(&pool, plain_env).await,
        "an unattached agent in the gap",
    );

    grant(&pool, h).await;
    expect_booted(
        run(&pool, attached_env).await,
        "the attached agent while its human holds the role",
    );
}

/// After a handover the agent still linked to the previous holder is refused,
/// although the role has a holder.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_of_a_previous_holder_does_not_boot(pool: PgPool) {
    seed_role(&pool).await;
    let (h1, _) = fixture::seed_human_operator(&pool, "boot-holder-1").await;
    let (h2, _) = fixture::seed_human_operator(&pool, "boot-holder-2").await;
    let (attached, env) = registered_agent(&pool, 0x81, h1).await;
    attach(&pool, attached).await;
    let a1 = grant(&pool, h1).await;
    expect_booted(run(&pool, env.clone()).await, "before the handover");

    let ended: bool = sqlx::query_scalar(
        "SELECT public.epigraph_end_role_assignment($1, 'test handover', NULL::uuid)",
    )
    .bind(a1)
    .fetch_one(&pool)
    .await
    .expect("end");
    assert!(ended);
    grant(&pool, h2).await;
    expect_refused(run(&pool, env).await, NOT_HOLDER, "after the handover");
}

/// The LEGACY key mode (`EPIGRAPH_MCP_AGENT_KEY`: the signer's own key is the
/// identity, no host registration) meets the same check: the agent is found
/// by the signer's public key. CONTROL: it boots once its human holds the role.
#[sqlx::test(migrations = "../../migrations")]
async fn a_legacy_keyed_attached_agent_does_not_boot_in_a_gap(pool: PgPool) {
    seed_role(&pool).await;
    let (h, _) = fixture::seed_human_operator(&pool, "boot-holder-legacy").await;
    let secret = [0x91_u8; 32];
    let public = AgentSigner::from_bytes(&secret).expect("key").public_key();
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(public.as_slice())
        .execute(&pool)
        .await
        .expect("a legacy-keyed agent");
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, agent, h)
            .await
            .expect("link");
    }
    attach(&pool, agent).await;
    let env = vec![("EPIGRAPH_MCP_AGENT_KEY", hex::encode(secret))];

    expect_refused(
        run(&pool, env.clone()).await,
        NO_HOLDER,
        "a legacy-keyed agent in a gap",
    );
    grant(&pool, h).await;
    expect_booted(
        run(&pool, env).await,
        "the legacy-keyed agent while its human holds the role",
    );
}
