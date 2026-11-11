//! The operator `ingest-document` CLI writes a paper where the D-V1 default
//! puts its acting agent's claims, never public by default (operator ruling,
//! 2026-11-10: "papers automatically go into the team visibility of the
//! ingester but not public").
//!
//! Driven as the real binary, because the CLI's walk is the only one that runs
//! on `MaintenancePool` (`IngestTx::Privileged`, whose owner group comes from
//! `default_decl_for_author`); every MCP ingest test exercises the stamped arm.
//! The acting agent is the CLI's signer (`--agent-key`), registered here before
//! the run so a team membership can be given to it first.
//!
//! Pinned, each on its own fresh database:
//! * no `--visibility`, the agent writes exactly one team: every claim the
//!   ingest creates is `group` over that team;
//! * no `--visibility`, two writable teams and a default team: the default;
//! * no `--visibility`, an agent in no team, operated by a human with two teams
//!   and a default team: the human's default (the agent's own default unset);
//! * no `--visibility`, the agent writes no team: every claim is `group` over
//!   its own personal group (private), none public;
//! * `--visibility public`: public, so a caller can still ask for it;
//! * `--visibility public --group-id <uuid>`: refused before any connection,
//!   as the MCP tools refuse it.

mod viewer_fixture;

use std::path::PathBuf;
use std::process::Command;

use epigraph_crypto::AgentSigner;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

const BIN: &str = env!("CARGO_BIN_EXE_ingest-document");

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    fn show(&self) -> String {
        format!(
            "exit={:?}\n--- stdout\n{}\n--- stderr\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}

/// A one-section paper whose text is unique to this run.
fn extraction_file() -> PathBuf {
    let tag = Uuid::new_v4();
    let doc = serde_json::json!({
        "source": {
            "title": format!("CLI visibility paper {tag}"),
            "doi": format!("10.1234/cli-visibility-{tag}"),
            "source_type": "Paper",
            "authors": [{"name": "Ada Example", "affiliations": [], "roles": ["author"]}]
        },
        "thesis": format!("Ingested papers default to the ingester's team {tag}"),
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "Intro",
            "paragraphs": [{
                "text": format!("A default ingest is never public {tag}"),
                "atoms": [format!("A default ingest is never public {tag}")],
                "generality": [3],
                "confidence": 0.8
            }]
        }],
        "relationships": []
    });
    let path = std::env::temp_dir().join(format!("cli-visibility-{tag}.json"));
    std::fs::write(&path, doc.to_string()).expect("write the extraction");
    path
}

/// Register the agent the CLI will act as (`--agent-key` = `[seed; 32]`).
async fn cli_agent(pool: &PgPool, seed: u8) -> (Uuid, String) {
    let key = [seed; 32];
    let pk = AgentSigner::from_bytes(&key).expect("signer").public_key();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type) \
         VALUES ($1, 'cli-visibility', 'system') RETURNING id",
    )
    .bind(pk.as_slice())
    .fetch_one(pool)
    .await
    .expect("register the cli agent");
    (id, hex::encode(key))
}

/// A keyed TEAM group with `agent` as a writer.
async fn team_with_writer(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = team(pool).await;
    add_writer(pool, id, agent).await;
    id
}

/// A keyed TEAM group with no members.
async fn team(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let key: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, 'cli team', 'did:epigraph:test-team:' || $1::text, $2, 'team')",
    )
    .bind(id)
    .bind(&key)
    .execute(pool)
    .await
    .expect("seed team");
    id
}

async fn add_writer(pool: &PgPool, group: Uuid, agent: Uuid) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(group)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed membership");
}

async fn set_default_team(pool: &PgPool, agent: Uuid, group: Uuid) {
    sqlx::query("UPDATE agents SET default_group_id = $2 WHERE id = $1")
        .bind(agent)
        .bind(group)
        .execute(pool)
        .await
        .expect("set the default team");
}

/// Every claim `agent` authored is `group` over `team`, and there is one.
async fn assert_all_in(pool: &PgPool, agent: Uuid, team: Uuid, run: &Run, why: &str) {
    let rows = authored(pool, agent).await;
    assert!(
        rows.len() >= 3,
        "claims were created: {rows:?}\n{}",
        run.show()
    );
    for (visibility, owner, _) in &rows {
        assert_eq!(
            (visibility.as_str(), *owner),
            ("group", team),
            "{why}: {rows:?}"
        );
    }
}

async fn ingest(pool: &PgPool, agent_key: &str, extra: &[&str]) -> Run {
    let url = fixture::database_url_for(pool).await;
    let file = extraction_file();
    let out = Command::new(BIN)
        .arg("--file")
        .arg(&file)
        .arg("--agent-key")
        .arg(agent_key)
        .args(extra)
        .env("DATABASE_URL", &url)
        .env("MAINTENANCE_DATABASE_URL", &url)
        .env("RUST_LOG", "warn")
        .env_remove("OPENAI_API_KEY")
        .output()
        .expect("spawn ingest-document");
    let _ = std::fs::remove_file(&file);
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// `(visibility, owner_group_id, owner kind)` of every claim `agent` authored.
async fn authored(pool: &PgPool, agent: Uuid) -> Vec<(String, Uuid, String)> {
    sqlx::query_as(
        "SELECT c.visibility::text, c.owner_group_id, g.kind::text \
         FROM claims c JOIN groups g ON g.id = c.owner_group_id \
         WHERE c.agent_id = $1",
    )
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("read the ingest's claims")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_default_cli_ingest_lands_in_the_acting_agents_only_team(pool: PgPool) {
    let (agent, key) = cli_agent(&pool, 0x31).await;
    let team = team_with_writer(&pool, agent).await;

    let run = ingest(&pool, &key, &[]).await;
    assert_eq!(run.code, Some(0), "{}", run.show());

    let rows = authored(&pool, agent).await;
    assert!(
        rows.len() >= 3,
        "the ingest created its thesis, paragraph and atom claims: {rows:?}\n{}",
        run.show()
    );
    for (visibility, owner, _) in &rows {
        assert_eq!(
            (visibility.as_str(), *owner),
            ("group", team),
            "a default CLI ingest goes to the acting agent's only team, never public: {rows:?}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_default_cli_ingest_with_no_team_lands_private(pool: PgPool) {
    let (agent, key) = cli_agent(&pool, 0x32).await;

    let run = ingest(&pool, &key, &[]).await;
    assert_eq!(run.code, Some(0), "{}", run.show());

    let rows = authored(&pool, agent).await;
    assert!(
        rows.len() >= 3,
        "claims were created: {rows:?}\n{}",
        run.show()
    );
    let personal: Uuid = sqlx::query_scalar(
        "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("the acting agent's personal group");
    for (visibility, owner, kind) in &rows {
        assert_eq!(
            (visibility.as_str(), *owner, kind.as_str()),
            ("group", personal, "personal"),
            "no team: a default CLI ingest is private to the acting agent, never public: {rows:?}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_explicit_public_cli_ingest_lands_public(pool: PgPool) {
    let (agent, key) = cli_agent(&pool, 0x33).await;
    // A team the agent writes, so `public` is not merely the absence of one.
    team_with_writer(&pool, agent).await;

    let run = ingest(&pool, &key, &["--visibility", "public"]).await;
    assert_eq!(run.code, Some(0), "{}", run.show());

    let rows = authored(&pool, agent).await;
    assert!(
        rows.len() >= 3,
        "claims were created: {rows:?}\n{}",
        run.show()
    );
    assert!(
        rows.iter().all(|(v, _, _)| v == "public"),
        "an explicit --visibility public still writes public: {rows:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_group_id_with_public_is_refused_before_any_write(pool: PgPool) {
    let (agent, key) = cli_agent(&pool, 0x34).await;
    let team = team_with_writer(&pool, agent).await;

    let team_arg = team.to_string();
    let run = ingest(
        &pool,
        &key,
        &["--visibility", "public", "--group-id", &team_arg],
    )
    .await;
    assert_ne!(run.code, Some(0), "{}", run.show());
    assert!(
        run.stderr.contains("takes no group_id"),
        "the MCP tools' refusal, verbatim: {}",
        run.show()
    );
    assert!(authored(&pool, agent).await.is_empty(), "nothing written");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_default_cli_ingest_uses_the_acting_agents_default_team(pool: PgPool) {
    let (agent, key) = cli_agent(&pool, 0x35).await;
    team_with_writer(&pool, agent).await;
    let chosen = team_with_writer(&pool, agent).await;
    set_default_team(&pool, agent, chosen).await;

    let run = ingest(&pool, &key, &[]).await;
    assert_eq!(run.code, Some(0), "{}", run.show());
    assert_all_in(
        &pool,
        agent,
        chosen,
        &run,
        "two writable teams: the agent's default team decides",
    )
    .await;
}

/// The post-deploy shape: a human with a default team, and the CLI run with
/// the key of an agent operated by that human, which is in no team itself.
#[sqlx::test(migrations = "../../migrations")]
async fn a_default_cli_ingest_by_an_operated_agent_uses_its_humans_default_team(pool: PgPool) {
    let (agent, key) = cli_agent(&pool, 0x36).await;
    let (human, _) = fixture::seed_human_operator(&pool, "cli-visibility-human").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
            .await
            .expect("live link");
    }
    let other = team(&pool).await;
    add_writer(&pool, other, human).await;
    let chosen = team(&pool).await;
    add_writer(&pool, chosen, human).await;
    set_default_team(&pool, human, chosen).await;

    let run = ingest(&pool, &key, &[]).await;
    assert_eq!(run.code, Some(0), "{}", run.show());
    assert_all_in(
        &pool,
        agent,
        chosen,
        &run,
        "an operated agent with no default of its own takes its human's default team",
    )
    .await;
}
