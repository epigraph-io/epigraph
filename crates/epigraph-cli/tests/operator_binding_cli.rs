//! `epigraph-operator` operator-binding commands (migration 122), driven through
//! the real binary against a `#[sqlx::test]` database migrated 001 -> head, on
//! the dedicated maintenance DSN variable only.
//!
//! * `link`: a LIVE link for one agent, by id or by the `(model, prompt hash)`
//!   identity a stdio `epigraph-mcp` derives, refusing a non-human operator and
//!   an agent that is an OAuth principal.
//!
//! Each test names the mutation it was verified against in its doc.

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

/// An ACTIVE human OAuth client whose graph agent is `agent`.
async fn make_human(pool: &PgPool, agent: Uuid) {
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id) \
         VALUES ($1, 'binding cli human', 'human', ARRAY['claims:write'], 'active', $2)",
    )
    .bind(format!("human-{agent}"))
    .bind(agent)
    .execute(pool)
    .await
    .expect("human client");
}

async fn link_row(pool: &PgPool, agent: Uuid) -> Option<(Uuid, bool)> {
    sqlx::query_as("SELECT operator_id, retired FROM operator_links WHERE agent_id = $1")
        .bind(agent)
        .fetch_optional(pool)
        .await
        .expect("link row")
}

// ─────────────────────────────────────────────────────────────────────────────
// link
// ─────────────────────────────────────────────────────────────────────────────

/// A host links a fleet identity BEFORE its first start: the dry run writes
/// nothing (not even the agent row), `--apply` creates the agent exactly as
/// `epigraph-mcp` would (same public key, `mcp-agent`, LLM provenance) and
/// records a live link, and a re-run is an idempotent success.
///
/// Verified to fail: the dry run committing its transaction -> the "nothing
/// written" assertions fail.
#[sqlx::test(migrations = "../../migrations")]
async fn link_binds_an_llm_identity_before_its_first_start(pool: PgPool) {
    let (human, _) = fixture::seed_agent_with_group(&pool, "human").await;
    make_human(&pool, human).await;
    let model = "binding-cli-model";
    let hash = "ef".repeat(32);
    let key = epigraph_crypto::keypair_from_llm_agent_prehashed(model, &hash).public_key();
    let agent_of_key = || {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>("SELECT id FROM agents WHERE public_key = $1")
                .bind(key.to_vec())
                .fetch_optional(&pool)
                .await
                .expect("agent by key")
        }
    };
    let human_s = human.to_string();
    let args = [
        "link",
        "--agent-model",
        model,
        "--agent-system-prompt-hash",
        hash.as_str(),
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
        agent_of_key().await.is_none(),
        "a dry run must not create the agent:\n{}",
        dry.show()
    );

    let mut apply_args = args.to_vec();
    apply_args.push("--apply");
    let applied = run_op(&pool, &apply_args).await;
    assert_eq!(applied.code, 0, "{}", applied.show());
    assert!(applied.stdout.contains("LINKED-LIVE"), "{}", applied.show());
    let agent = agent_of_key()
        .await
        .expect("--apply creates the agent under the derived key");
    assert_eq!(link_row(&pool, agent).await, Some((human, false)));
    let (name, llm_model): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT display_name, properties->>'llm_model' FROM agents WHERE id = $1")
            .bind(agent)
            .fetch_one(&pool)
            .await
            .expect("agent row");
    assert_eq!(name.as_deref(), Some("mcp-agent"));
    assert_eq!(llm_model.as_deref(), Some(model));
    let binding: Option<String> = sqlx::query_scalar("SELECT public.epigraph_author_binding($1)")
        .bind(agent)
        .fetch_one(&pool)
        .await
        .expect("binding");
    assert_eq!(binding.as_deref(), Some("live_link"));

    let again = run_op(&pool, &apply_args).await;
    assert_eq!(again.code, 0, "a re-run is idempotent: {}", again.show());
}

/// The operator must be a HUMAN operator; a live link to anything else binds
/// nobody to a human. Nothing is written.
///
/// Verified to fail: the human-operator refusal removed -> the link is recorded
/// and the command exits 0.
#[sqlx::test(migrations = "../../migrations")]
async fn link_refuses_an_operator_that_is_not_human(pool: PgPool) {
    let (not_human, _) = fixture::seed_agent_with_group(&pool, "not-human").await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "agent").await;
    let r = run_op(
        &pool,
        &[
            "link",
            "--agent",
            &agent.to_string(),
            "--operator",
            &not_human.to_string(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("is not a human operator"), "{}", r.show());
    assert_eq!(link_row(&pool, agent).await, None, "nothing may be linked");
}

/// An agent that is an OAuth principal is refused: any link would cost it its
/// HTTP tokens (operated agents are stdio-only), which is an operator decision.
///
/// Verified to fail: the OAuth-principal refusal removed -> linked, exit 0.
#[sqlx::test(migrations = "../../migrations")]
async fn link_refuses_an_agent_that_is_an_oauth_principal(pool: PgPool) {
    let (human, _) = fixture::seed_agent_with_group(&pool, "human").await;
    make_human(&pool, human).await;
    let (service, _) = fixture::seed_agent_with_group(&pool, "service").await;
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    status, agent_id, legal_entity_name, legal_contact_email) \
         VALUES ($1, 'binding cli service', 'service', ARRAY['claims:write'], 'active', $2, \
                 'Example', 'ops@example.invalid')",
    )
    .bind(format!("service-{service}"))
    .bind(service)
    .execute(&pool)
    .await
    .expect("service client");
    let r = run_op(
        &pool,
        &[
            "link",
            "--agent",
            &service.to_string(),
            "--operator",
            &human.to_string(),
            "--apply",
        ],
    )
    .await;
    assert_eq!(r.code, 1, "{}", r.show());
    assert!(r.stderr.contains("OAuth client"), "{}", r.show());
    assert_eq!(
        link_row(&pool, service).await,
        None,
        "nothing may be linked"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// arm-operator-binding
// ─────────────────────────────────────────────────────────────────────────────

async fn armed(pool: &PgPool) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM operator_binding_arming)")
        .fetch_one(pool)
        .await
        .expect("armed read")
}

/// A `('public', group)` claim by `agent`, straight into the table.
async fn insert_claim(pool: &PgPool, agent: Uuid, group: Uuid) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("binding cli probe {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(agent)
    .bind(group)
    .execute(pool)
    .await?;
    Ok(id)
}

/// Arming is one-way, so the census comes first: a dry run lists the unbound
/// recent writer and arms nothing; `--apply` REFUSES (exit 1, nothing armed)
/// while one exists; `--allow-unbound-writers` arms, after which that writer is
/// refused OPL01; a re-run reports ALREADY-ARMED.
///
/// Verified to fail: the unbound-writer refusal removed from `arm::run` ->
/// the plain `--apply` arms and the test fails.
#[sqlx::test(migrations = "../../migrations")]
async fn arm_refuses_while_an_unbound_agent_wrote_recently(pool: PgPool) {
    let (unbound, group) = fixture::seed_agent_with_group(&pool, "unbound").await;
    insert_claim(&pool, unbound, group)
        .await
        .expect("unarmed: an unbound author still writes");
    let unbound_s = unbound.to_string();

    let dry = run_op(&pool, &["arm-operator-binding"]).await;
    assert_eq!(dry.code, 0, "{}", dry.show());
    assert!(
        dry.stdout
            .contains(&format!("UNBOUND\t{unbound_s}\t1 claim(s)")),
        "{}",
        dry.show()
    );
    assert!(dry.stdout.contains("DRY RUN"), "{}", dry.show());
    assert!(!armed(&pool).await, "a dry run must not arm");

    let refused = run_op(&pool, &["arm-operator-binding", "--apply"]).await;
    assert_eq!(refused.code, 1, "{}", refused.show());
    assert!(refused.stdout.contains("REFUSED"), "{}", refused.show());
    assert!(!armed(&pool).await, "a refused --apply must not arm");

    let forced = run_op(
        &pool,
        &["arm-operator-binding", "--apply", "--allow-unbound-writers"],
    )
    .await;
    assert_eq!(forced.code, 0, "{}", forced.show());
    assert!(forced.stdout.contains("ARMED"), "{}", forced.show());
    assert!(armed(&pool).await);
    let e = insert_claim(&pool, unbound, group)
        .await
        .expect_err("armed: the unbound writer is refused");
    assert_eq!(
        e.as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("OPL01"),
        "{e}"
    );

    let again = run_op(&pool, &["arm-operator-binding", "--apply"]).await;
    assert_eq!(again.code, 0, "{}", again.show());
    assert!(again.stdout.contains("ALREADY-ARMED"), "{}", again.show());
}

/// With every recent writer bound, `--apply` arms without an override.
#[sqlx::test(migrations = "../../migrations")]
async fn arm_arms_when_every_recent_writer_is_bound(pool: PgPool) {
    let (human, group) = fixture::seed_agent_with_group(&pool, "human").await;
    make_human(&pool, human).await;
    insert_claim(&pool, human, group)
        .await
        .expect("the human writes");
    let r = run_op(&pool, &["arm-operator-binding", "--apply"]).await;
    assert_eq!(r.code, 0, "{}", r.show());
    assert!(
        r.stdout.contains("UNBOUND-RECENT-WRITERS\t0"),
        "{}",
        r.show()
    );
    assert!(armed(&pool).await);
    insert_claim(&pool, human, group)
        .await
        .expect("armed: the human still writes");
}
