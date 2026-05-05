//! `epigraph-cli reembed` — Idempotent batch re-embedding of claims/evidence
//! at 3072d (text-embedding-3-large).
//!
//! Usage:
//!   reembed --target claims [--batch 256] [--checkpoint-file PATH]
//!   reembed --target evidence [--batch 256] [--checkpoint-file PATH]
//!
//! Reads `OPENAI_API_KEY`. Falls back to a mock provider when unset (dev
//! convenience — the mock writes deterministic 3072d vectors so the column
//! gets populated, but the vectors are not semantically meaningful).
//!
//! `DATABASE_URL` is required.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use epigraph_cli::reembed::{run, ReembedConfig, ReembedTarget};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider, OpenAiProvider};

#[derive(Parser)]
#[command(
    name = "reembed",
    about = "Re-embed claims or evidence at 3072d (text-embedding-3-large)"
)]
struct Cli {
    /// Target table: claims or evidence
    #[arg(long)]
    target: String,
    /// Rows per batch
    #[arg(long, default_value_t = 256)]
    batch: usize,
    /// Optional checkpoint file for resume
    #[arg(long)]
    checkpoint_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();

    let target = match cli.target.as_str() {
        "claims" => ReembedTarget::Claims,
        "evidence" => ReembedTarget::Evidence,
        other => {
            eprintln!("--target must be 'claims' or 'evidence' (got '{other}')");
            std::process::exit(2);
        }
    };

    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        eprintln!("DATABASE_URL required");
        std::process::exit(2);
    });
    let pool = sqlx::PgPool::connect(&url).await.unwrap_or_else(|e| {
        eprintln!("connect failed: {e}");
        std::process::exit(1);
    });

    let provider = build_3072d_provider();

    let summary = run(
        &pool,
        ReembedConfig {
            target,
            batch_size: cli.batch,
            embedding_provider: provider,
            checkpoint_path: cli.checkpoint_file,
        },
    )
    .await
    .unwrap_or_else(|e| {
        eprintln!("reembed failed: {e}");
        std::process::exit(1);
    });

    println!(
        "reembed: {} rows in {} batches (target={:?})",
        summary.rows_written, summary.batches, target,
    );
}

/// Build the 3072d embedding provider. Prefers OpenAI text-embedding-3-large
/// when `OPENAI_API_KEY` is set; falls back to MockProvider for dev/CI.
fn build_3072d_provider() -> Arc<dyn EmbeddingService> {
    let mut config = EmbeddingConfig::openai(3072);
    // Override the default model (text-embedding-3-small) to text-embedding-3-large.
    if let epigraph_embeddings::config::ProviderConfig::OpenAi {
        ref mut model,
        api_base_url: _,
    } = config.provider
    {
        *model = "text-embedding-3-large".to_string();
    }

    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        if !key.is_empty() {
            match OpenAiProvider::new(config.clone(), key) {
                Ok(p) => {
                    tracing::info!("reembed provider: OpenAI text-embedding-3-large (3072d)");
                    return Arc::new(p);
                }
                Err(e) => tracing::warn!("OpenAI init failed, falling back to mock: {e}"),
            }
        }
    }
    tracing::warn!(
        "OPENAI_API_KEY not set; using MockProvider — embeddings will be deterministic but not semantically meaningful"
    );
    Arc::new(MockProvider::new(config))
}
