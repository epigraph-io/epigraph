//! `embed_backfill` must also fill `workflows.goal_embedding` (backlog I063,
//! drain unit U031).
//!
//! Every hierarchical-workflow write path embeds its goal best-effort: an
//! embedder outage at write time logs a warning and leaves the row's
//! `goal_embedding` NULL. All three embedding searches over `workflows`
//! (`find_hierarchical_by_embedding`, `search_by_goal_embedding_since`,
//! `search_hierarchical_by_embedding_scored`) filter `goal_embedding IS NOT
//! NULL`, so such a row is invisible to them until something embeds it. These
//! tests drive the real binary, as `maintenance_timer_bins.rs` does, and check
//! that it is that something.
//!
//! Each run uses `env_clear()` and a temp-dir cwd: `main` calls
//! `dotenvy::dotenv()`, and from a worktree that would load the repo `.env`
//! (a real `OPENAI_API_KEY`, or a `MAINTENANCE_DATABASE_URL` naming another
//! database).

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use std::process::Command;

use epigraph_db::WorkflowRepository;
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use sqlx::PgPool;
use uuid::Uuid;

const BIN: &str = env!("CARGO_BIN_EXE_embed_backfill");

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    fn has_line(&self, line: &str) -> bool {
        self.stdout.lines().any(|l| l == line)
    }
}

async fn run_bin(pool: &PgPool, args: &[&str]) -> Run {
    let url = viewer_fixture::database_url_for(pool).await;
    let out = Command::new(BIN)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", &url)
        .env("RUST_LOG", "warn")
        .current_dir(std::env::temp_dir())
        .args(args)
        .output()
        .expect("run embed_backfill");
    Run {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A root workflow whose goal was never embedded, as every write path leaves
/// one when the embedder is down.
async fn seed_unembedded_workflow(pool: &PgPool, goal: &str) -> Uuid {
    let id = Uuid::new_v4();
    let name = format!("u031-probe-{}", id.simple());
    WorkflowRepository::insert_root(
        pool,
        id,
        &name,
        0,
        goal,
        None,
        serde_json::json!({}),
        epigraph_core::TenancyDecl::inherited(),
    )
    .await
    .expect("insert workflow root");
    id
}

async fn null_goal_embeddings(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflows WHERE goal_embedding IS NULL")
        .fetch_one(pool)
        .await
        .expect("count NULL goal embeddings")
}

async fn goal_embedding_dims(pool: &PgPool, id: Uuid) -> Option<i32> {
    sqlx::query_scalar("SELECT vector_dims(goal_embedding) FROM workflows WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read goal_embedding dims")
}

async fn goal_embedding_text(pool: &PgPool, id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT goal_embedding::text FROM workflows WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read goal_embedding text")
}

#[sqlx::test(migrations = "../../migrations")]
async fn embed_backfill_fills_null_workflow_goal_embeddings(pool: PgPool) {
    let id =
        seed_unembedded_workflow(&pool, "Probe goal for the workflow embedding backfill").await;
    assert_eq!(
        null_goal_embeddings(&pool).await,
        1,
        "premise: exactly the seeded row is unembedded"
    );

    let run = run_bin(&pool, &["--allow-mock", "--limit", "50"]).await;
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);

    assert_eq!(
        goal_embedding_dims(&pool, id).await,
        Some(1536),
        "the workflows leg must embed the NULL row; stdout: {}",
        run.stdout
    );
    assert!(
        run.has_line("embed_backfill: 1 workflows embedded, 0 failed"),
        "stdout: {}",
        run.stdout
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn embed_backfill_dry_run_counts_workflows_and_writes_nothing(pool: PgPool) {
    let id = seed_unembedded_workflow(&pool, "Dry-run probe goal").await;
    // A whitespace-only goal has nothing to embed. It must not be counted, or
    // it would be reported (and, on a real run, fail) on every run forever.
    seed_unembedded_workflow(&pool, "   ").await;
    assert_eq!(null_goal_embeddings(&pool).await, 2, "premise");

    // No --allow-mock and no OPENAI_API_KEY: a dry run must not need a provider.
    let run = run_bin(&pool, &["--dry-run"]).await;
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    assert!(
        run.has_line("embed_backfill: 1 workflows need goal embeddings"),
        "stdout: {}",
        run.stdout
    );
    assert_eq!(
        goal_embedding_dims(&pool, id).await,
        None,
        "a dry run writes nothing"
    );
    assert_eq!(null_goal_embeddings(&pool).await, 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn embed_backfill_workflow_leg_is_idempotent(pool: PgPool) {
    let id = seed_unembedded_workflow(&pool, "Idempotence probe goal").await;

    let first = run_bin(&pool, &["--allow-mock"]).await;
    assert_eq!(first.code, Some(0), "stderr: {}", first.stderr);
    let after_first = goal_embedding_text(&pool, id).await;
    assert!(
        after_first.is_some(),
        "first run embeds; stdout: {}",
        first.stdout
    );

    let second = run_bin(&pool, &["--allow-mock"]).await;
    assert_eq!(second.code, Some(0), "stderr: {}", second.stderr);
    assert!(
        second.has_line("embed_backfill: 0 workflows embedded, 0 failed"),
        "an embedded row is not revisited; stdout: {}",
        second.stdout
    );
    assert_eq!(goal_embedding_text(&pool, id).await, after_first);
}

/// The point of the backfill is search visibility, not a non-NULL column: the
/// row must come back from the embedding search it was invisible to.
#[sqlx::test(migrations = "../../migrations")]
async fn embed_backfilled_workflow_is_found_by_embedding_search(pool: PgPool) {
    let goal = "Synthesize a diamondoid tooltip by stepwise hydrogen abstraction";
    let id = seed_unembedded_workflow(&pool, goal).await;
    let query = MockProvider::new(EmbeddingConfig::openai(1536))
        .generate(goal)
        .await
        .expect("mock embedding");

    let before =
        WorkflowRepository::find_hierarchical_by_embedding(&pool, &query, 0.99, 0.0, 10, false)
            .await
            .expect("search before");
    assert!(
        before.iter().all(|r| r.id != id),
        "premise: a NULL goal_embedding is invisible to embedding search"
    );

    let run = run_bin(&pool, &["--allow-mock"]).await;
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);

    let after =
        WorkflowRepository::find_hierarchical_by_embedding(&pool, &query, 0.99, 0.0, 10, false)
            .await
            .expect("search after");
    assert!(
        after.iter().any(|r| r.id == id),
        "the backfilled goal must embed the same text the write paths embed; stdout: {}",
        run.stdout
    );
}

/// The claims leg keeps running and keeps its output, and the workflows leg
/// runs after it rather than only when there are no claims.
#[sqlx::test(migrations = "../../migrations")]
async fn embed_backfill_runs_both_legs_in_one_run(pool: PgPool) {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'u031-bin', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed agent");
    let claim: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current) \
         VALUES ('u031 claim needing an embedding', sha256(gen_random_uuid()::text::bytea), \
                 0.5, $1, true) RETURNING id",
    )
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("seed claim");
    let wf = seed_unembedded_workflow(&pool, "Both-legs probe goal").await;

    let run = run_bin(&pool, &["--allow-mock"]).await;
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    assert!(
        run.has_line("embed_backfill: 1 claims embedded, 0 failed"),
        "claims line unchanged; stdout: {}",
        run.stdout
    );
    assert!(
        run.has_line("embed_backfill: 1 workflows embedded, 0 failed"),
        "stdout: {}",
        run.stdout
    );
    let claim_embedded: bool =
        sqlx::query_scalar("SELECT embedding IS NOT NULL FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read claim embedding");
    assert!(claim_embedded);
    assert_eq!(goal_embedding_dims(&pool, wf).await, Some(1536));
}

/// One row the provider rejects must not stop the others, must stay NULL for
/// the next run, and must make the run exit 2, the same contract the claims
/// leg has. The mock enforces the real 8191-token input limit, so an
/// over-long goal is a genuine provider refusal, not a test double.
#[sqlx::test(migrations = "../../migrations")]
async fn embed_backfill_workflow_failure_is_counted_and_exits_2(pool: PgPool) {
    let too_long = "token ".repeat(20_000);
    let rejected = seed_unembedded_workflow(&pool, &too_long).await;
    let accepted = seed_unembedded_workflow(&pool, "A goal the provider accepts").await;

    let run = run_bin(&pool, &["--allow-mock"]).await;
    assert_eq!(
        run.code,
        Some(2),
        "a failed workflow row must fail the run; stdout: {} stderr: {}",
        run.stdout,
        run.stderr
    );
    assert!(
        run.has_line("embed_backfill: 1 workflows embedded, 1 failed"),
        "stdout: {}",
        run.stdout
    );
    assert!(
        run.stderr
            .contains(&format!("workflow {rejected}: embedding failed")),
        "the failed row is named; stderr: {}",
        run.stderr
    );
    assert_eq!(goal_embedding_dims(&pool, accepted).await, Some(1536));
    assert_eq!(goal_embedding_dims(&pool, rejected).await, None);
}

/// A row deleted between the select and the update writes nothing; it is a
/// failure, not a success.
#[sqlx::test(migrations = "../../migrations")]
async fn workflow_leg_counts_a_vanished_row_as_failed(pool: PgPool) {
    let provider = MockProvider::new(EmbeddingConfig::openai(1536));
    let summary = epigraph_cli::embed_backfill::backfill_workflow_goal_embeddings(
        &pool,
        &provider,
        vec![(Uuid::new_v4(), "goal of a row that no longer exists".into())],
    )
    .await;
    assert_eq!(
        summary,
        epigraph_cli::embed_backfill::WorkflowBackfillSummary {
            candidates: 1,
            written: 0,
            failed: 1
        }
    );
}
