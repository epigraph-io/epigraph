//! Backfill missing primary claim embeddings (`claims.embedding`, 1536d) and
//! hierarchical workflow goal embeddings (`workflows.goal_embedding`, 1536d).
//!
//! The claims leg targets the active recall column. It is distinct from
//! `reembed`, which fills `embedding_3072` for side-by-side large-model
//! experiments.
//!
//! The workflows leg is the recovery path for the workflow write paths, which
//! embed the goal best-effort and leave `goal_embedding` NULL on an embedder
//! failure; see `epigraph_cli::embed_backfill`. Both legs run on every
//! invocation, each limited to `--limit` rows, and the run exits 2 if either
//! leg had a failure.

use std::sync::Arc;

use anyhow::{anyhow, Context};
use clap::Parser;
use epigraph_cli::embed_backfill::{backfill_workflow_goal_embeddings, WorkflowBackfillSummary};
use epigraph_db::{ClaimRepository, WorkflowRepository};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider, OpenAiProvider};

#[derive(Parser, Debug)]
#[command(
    name = "embed_backfill",
    about = "Backfill missing primary claim embeddings and hierarchical workflow goal embeddings"
)]
struct Cli {
    /// PostgreSQL connection URL.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Maximum rows to process this run, applied to each leg (claims,
    /// workflows) independently. Keep this modest on small VMs.
    #[arg(long, default_value_t = 500)]
    limit: i64,

    /// Do not write embeddings; only report how many rows each leg would
    /// process. Needs no OpenAI key.
    #[arg(long)]
    dry_run: bool,

    /// Permit deterministic mock embeddings when OPENAI_API_KEY is unset.
    /// Useful for local/CI smoke tests, not for production recall quality.
    #[arg(long)]
    allow_mock: bool,

    /// OpenAI API key for 1536d text-embedding-3-small generation.
    #[arg(long, env = "OPENAI_API_KEY", hide_env_values = true)]
    openai_api_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();

    // CLI maintenance bin: the operator is the authority and the work is
    // corpus-wide. See `epigraph_cli::MaintenancePool`.
    //
    // Before PR-15 this bin held a bypass `Viewer` minted from a `ScopedPool`
    // it then discarded, and ran `find_claims_needing_embeddings` and
    // `store_embedding` on a second, ordinary pool from `--database-url`. The
    // viewer suppressed the repo-layer predicate; the connection supplied the
    // RLS-filtered one. Under FORCE that combination silently stops embedding
    // private claims and reports success.
    //
    // `MAINTENANCE_DATABASE_URL` overrides `--database-url` when set; the
    // database-name guard in `maintenance_database_url` refuses the two if they
    // disagree.
    let maint = epigraph_cli::MaintenancePool::connect_to(&cli.database_url, "embed_backfill")
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let session = maint
        .viewer(epigraph_db::visibility::SystemReason::EmbeddingBackfill)
        .await
        .context("mint maintenance viewer")?;
    let viewer = session.viewer();

    run(cli, maint.pool(), viewer).await
}

async fn run(
    cli: Cli,
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> anyhow::Result<()> {
    // Select both legs before deciding anything: a dry run, or a run with
    // nothing to do, must report both legs and must not need a provider.
    let claims = ClaimRepository::find_claims_needing_embeddings(pool, viewer, cli.limit)
        .await
        .context("find claims needing embeddings")?;
    // The maintenance connection reads every `workflows` row (its row
    // security, migration 183, admits the maintenance role), so this leg
    // needs no viewer.
    let workflows = WorkflowRepository::find_needing_goal_embedding(pool, cli.limit)
        .await
        .context("find workflows needing goal embeddings")?;

    if cli.dry_run {
        println!("embed_backfill: {} claims need embeddings", claims.len());
        println!(
            "embed_backfill: {} workflows need goal embeddings",
            workflows.len()
        );
        return Ok(());
    }

    let provider = if claims.is_empty() && workflows.is_empty() {
        None
    } else {
        Some(build_1536d_provider(cli.openai_api_key, cli.allow_mock)?)
    };

    let claims_failed = match (&provider, claims.is_empty()) {
        // An empty claims leg prints exactly the claims-only bin's line, so a
        // log scraper keyed on it is unaffected by the workflows leg.
        (_, true) | (None, _) => {
            println!("embed_backfill: 0 claims embedded");
            0
        }
        (Some(provider), false) => {
            let (written, failed) = backfill_claims(pool, provider.as_ref(), claims).await;
            println!("embed_backfill: {written} claims embedded, {failed} failed");
            failed
        }
    };

    let wf = match &provider {
        Some(provider) if !workflows.is_empty() => {
            backfill_workflow_goal_embeddings(pool, provider.as_ref(), workflows).await
        }
        _ => WorkflowBackfillSummary::default(),
    };
    println!(
        "embed_backfill: {} workflows embedded, {} failed",
        wf.written, wf.failed
    );

    if claims_failed > 0 || wf.failed > 0 {
        std::process::exit(2);
    }
    Ok(())
}

/// The claims leg: embed and store each row. Returns `(written, failed)`.
async fn backfill_claims(
    pool: &sqlx::PgPool,
    provider: &dyn EmbeddingService,
    rows: Vec<(uuid::Uuid, String)>,
) -> (usize, usize) {
    let mut written = 0usize;
    let mut failed = 0usize;

    for (claim_id, content) in rows {
        match provider.generate(&content).await {
            Ok(embedding) => {
                let pgvec = format_pgvector(&embedding);
                match ClaimRepository::store_embedding(pool, claim_id, &pgvec).await {
                    Ok(true) => written += 1,
                    Ok(false) => {
                        failed += 1;
                        eprintln!("{claim_id}: store affected 0 rows");
                    }
                    Err(e) => {
                        failed += 1;
                        eprintln!("{claim_id}: store failed: {e}");
                    }
                }
            }
            Err(e) => {
                failed += 1;
                eprintln!("{claim_id}: embedding failed: {e}");
            }
        }
    }
    (written, failed)
}

fn build_1536d_provider(
    openai_api_key: Option<String>,
    allow_mock: bool,
) -> anyhow::Result<Arc<dyn EmbeddingService>> {
    let config = EmbeddingConfig::openai(1536);
    if let Some(key) = openai_api_key.filter(|k| !k.is_empty()) {
        return Ok(Arc::new(OpenAiProvider::new(config, key)?));
    }
    if allow_mock {
        tracing::warn!("OPENAI_API_KEY unset; using deterministic mock embeddings");
        return Ok(Arc::new(MockProvider::new(config)));
    }
    anyhow::bail!("OPENAI_API_KEY is required unless --allow-mock is set");
}

fn format_pgvector(values: &[f32]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::format_pgvector;

    #[test]
    fn pgvector_format_matches_postgres_vector_literal() {
        assert_eq!(format_pgvector(&[0.1, -0.2, 3.0]), "[0.1,-0.2,3]");
    }
}
