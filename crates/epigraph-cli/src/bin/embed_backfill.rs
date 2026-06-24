//! Backfill missing primary claim embeddings (`claims.embedding`, 1536d).
//!
//! This targets the active recall column. It is distinct from `reembed`, which
//! fills `embedding_3072` for side-by-side large-model experiments.

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use epigraph_db::ClaimRepository;
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider, OpenAiProvider};

#[derive(Parser, Debug)]
#[command(
    name = "embed_backfill",
    about = "Backfill missing primary claim embeddings for semantic recall"
)]
struct Cli {
    /// PostgreSQL connection URL.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Maximum rows to process this run. Keep this modest on small VMs.
    #[arg(long, default_value_t = 500)]
    limit: i64,

    /// Do not write embeddings; only report how many rows would be processed.
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
    run(cli).await
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let pool = epigraph_db::create_pool(&cli.database_url)
        .await
        .context("connect database")?;
    let rows = ClaimRepository::find_claims_needing_embeddings(&pool, cli.limit)
        .await
        .context("find claims needing embeddings")?;

    if cli.dry_run {
        println!("embed_backfill: {} claims need embeddings", rows.len());
        return Ok(());
    }

    if rows.is_empty() {
        println!("embed_backfill: 0 claims embedded");
        return Ok(());
    }

    let provider = build_1536d_provider(cli.openai_api_key, cli.allow_mock)?;
    let mut written = 0usize;
    let mut failed = 0usize;

    for (claim_id, content) in rows {
        match provider.generate(&content).await {
            Ok(embedding) => {
                let pgvec = format_pgvector(&embedding);
                match ClaimRepository::store_embedding(&pool, claim_id, &pgvec).await {
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

    println!("embed_backfill: {written} claims embedded, {failed} failed");
    if failed > 0 {
        std::process::exit(2);
    }
    Ok(())
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
