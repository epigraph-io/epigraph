//! `epigraph-operator link --identity-pubkey` (agent identity lineage design
//! D1): a keyed identity cannot be recomputed from (model, prompt hash) without
//! the host secret, so the host names the agent by its identity PUBLIC key.
//!
//! The identity agent is created by the host's registration, never by this
//! command: a key no agent carries is refused and nothing is written.

mod viewer_fixture;

use sqlx::PgPool;
use std::process::Command;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_epigraph-operator");
const DSN_ENV: &str = "EPIGRAPH_OPERATOR_MAINTENANCE_DSN";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn show(&self) -> String {
        format!(
            "exit={}\n--- stdout\n{}\n--- stderr\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

async fn run_op(pool: &PgPool, args: &[&str]) -> Run {
    let url = fixture::database_url_for(pool).await;
    let out = Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "warn")
        .env_remove("DATABASE_URL")
        .env_remove("MAINTENANCE_DATABASE_URL")
        .env_remove("EPIGRAPH_OPERATOR_LINK_ENFORCEMENT")
        .env(DSN_ENV, url)
        .output()
        .expect("spawn epigraph-operator");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

async fn link_row(pool: &PgPool, agent: Uuid) -> Option<(Uuid, bool)> {
    sqlx::query_as("SELECT operator_id, retired FROM operator_links WHERE agent_id = $1")
        .bind(agent)
        .fetch_optional(pool)
        .await
        .expect("link row")
}

/// An existing agent keyed by `key`, as the host's registration leaves it.
async fn seed_identity_agent(pool: &PgPool, key: &[u8; 32]) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type, properties) \
         VALUES ($1, $2, 'llm', '{\"source\": \"epiclaw\"}'::jsonb)",
    )
    .bind(id)
    .bind(key.as_slice())
    .execute(pool)
    .await
    .expect("seed identity agent");
    id
}

/// The identity agent is found by its public key: the dry run writes nothing,
/// `--apply` records a live link to the named human, and a re-run is
/// idempotent.
#[sqlx::test(migrations = "../../migrations")]
async fn link_names_the_agent_by_its_identity_public_key(pool: PgPool) {
    let (human, _) = fixture::seed_agent_with_group(&pool, "human").await;
    fixture::make_human_operator(&pool, human).await;
    let key = [0x5Du8; 32];
    let agent = seed_identity_agent(&pool, &key).await;
    // A bystander agent the link must not touch.
    let bystander = seed_identity_agent(&pool, &[0x5Eu8; 32]).await;

    let key_hex = hex::encode(key);
    let human_s = human.to_string();
    let args = [
        "link",
        "--identity-pubkey",
        key_hex.as_str(),
        "--operator",
        human_s.as_str(),
    ];

    let dry = run_op(&pool, &args).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout.contains("WOULD BE LINKED-LIVE"),
        "{}",
        dry.show()
    );
    assert!(
        dry.stdout.contains(&agent.to_string()),
        "the dry run names the agent the key resolves to: {}",
        dry.show()
    );
    assert_eq!(link_row(&pool, agent).await, None, "{}", dry.show());

    let mut apply_args = args.to_vec();
    apply_args.push("--apply");
    let applied = run_op(&pool, &apply_args).await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    assert_eq!(link_row(&pool, agent).await, Some((human, false)));
    assert_eq!(link_row(&pool, bystander).await, None);

    let again = run_op(&pool, &apply_args).await;
    assert_eq!(again.code, 0, "a re-run is idempotent: {}", again.show());
}

/// A key no agent carries is refused and creates no agent; so is a malformed
/// key, and naming the agent two ways at once.
#[sqlx::test(migrations = "../../migrations")]
async fn link_refuses_an_unknown_or_ambiguous_identity_public_key(pool: PgPool) {
    let (human, _) = fixture::seed_agent_with_group(&pool, "human").await;
    fixture::make_human_operator(&pool, human).await;
    let human_s = human.to_string();
    let unknown = [0x6Fu8; 32];
    let unknown_hex = hex::encode(unknown);

    let refused = run_op(
        &pool,
        &[
            "link",
            "--identity-pubkey",
            unknown_hex.as_str(),
            "--operator",
            human_s.as_str(),
            "--apply",
        ],
    )
    .await;
    assert_ne!(refused.code, 0, "{}", refused.show());
    let created: i64 = sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = $1")
        .bind(unknown.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(
        created,
        0,
        "an unknown identity key creates nothing: {}",
        refused.show()
    );

    let agent = seed_identity_agent(&pool, &[0x70u8; 32]).await;
    let agent_s = agent.to_string();
    let key_hex = hex::encode([0x70u8; 32]);
    for args in [
        vec![
            "link",
            "--identity-pubkey",
            "zz",
            "--operator",
            human_s.as_str(),
        ],
        vec![
            "link",
            "--identity-pubkey",
            key_hex.as_str(),
            "--agent",
            agent_s.as_str(),
            "--operator",
            human_s.as_str(),
        ],
    ] {
        let r = run_op(&pool, &args).await;
        assert_ne!(r.code, 0, "{args:?}: {}", r.show());
    }
    assert_eq!(link_row(&pool, agent).await, None);
}
