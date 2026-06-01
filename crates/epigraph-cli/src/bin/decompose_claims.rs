//! `decompose_claims` — split standalone compound claims into atomic
//! propositions + wire parent -decomposes_to-> atom edges.
//!
//! The decompose primitive the dead `decomposition-cycle` schedule needs.
//! Enumerates via `ClaimRepository::list_undecomposed`, decomposes each batch
//! through the prepaid Claude path (`create_llm_client("epigraph")`, which
//! prefers CLAUDE_CODE_OAUTH_TOKEN — NEVER the Anthropic-SDK pay-per-token
//! variant the V2 `_api.py`/`_openai.py` scripts used), parses with
//! `epigraph_cli::decompose::parse_batch_response`, and persists atoms through
//! the canonical API claim path so embedding + DS auto-wire + signing happen
//! on write.
//!
//! Required: DATABASE_URL, EPIGRAPH_API (e.g. http://127.0.0.1:8080),
//! EPIGRAPH_TOKEN (bearer for the API), and CLAUDE_CODE_OAUTH_TOKEN.
//! Use `--provider mock` for a dry compile/smoke without credentials.

use clap::Parser;
use epigraph_cli::decompose::{build_batch_prompt, parse_batch_response, persist_decomposition};
use epigraph_db::ClaimRepository;

#[derive(Parser)]
#[command(name = "decompose_claims", about = "Decompose undecomposed compound claims into atoms")]
struct Cli {
    /// Max claims to process this run.
    #[arg(long, default_value_t = 200)]
    limit: i64,
    /// Claims per LLM call.
    #[arg(long, default_value_t = 10)]
    batch_size: usize,
    /// LLM provider selector for create_llm_client ("epigraph" auto, or "mock").
    #[arg(long, default_value = "epigraph")]
    provider: String,
    /// Parse/enumerate only — do not call the LLM or write anything.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let pool = epigraph_cli::db_connect().await?;

    let claims = ClaimRepository::list_undecomposed(&pool, cli.limit, 0).await?;
    eprintln!("found {} undecomposed claims", claims.len());
    if cli.dry_run || claims.is_empty() {
        for c in &claims {
            println!("{}\t{}", c.id.as_uuid(), c.content);
        }
        return Ok(());
    }

    // Prepaid Claude path. create_llm_client("epigraph") returns the first
    // active provider (Anthropic-from-env, OAuth-preferred); "mock" for smoke.
    let llm = epigraph_cli::enrichment::llm_client::create_llm_client(&cli.provider)?;
    let embedder = epigraph_cli::embedding_service();

    // API submit closure — canonical claim create (embed + DS + sign on write).
    let api_base = std::env::var("EPIGRAPH_API")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let token = std::env::var("EPIGRAPH_TOKEN").unwrap_or_default();
    let http = reqwest::Client::new();

    let mut total_atoms = 0usize;
    let mut total_edges = 0usize;
    for chunk in claims.chunks(cli.batch_size) {
        let indexed: Vec<(usize, &str)> = chunk
            .iter()
            .enumerate()
            .map(|(i, c)| (i, c.content.as_str()))
            .collect();
        let prompt = build_batch_prompt(&indexed);
        // SCAFFOLD BOUNDARY: this network call cannot run in the CI box.
        let raw = match llm.complete_json(&prompt).await {
            Ok(v) => v.to_string(),
            Err(e) => {
                eprintln!("  LLM call failed for batch: {e}; skipping");
                continue;
            }
        };
        let parsed = parse_batch_response(&raw);
        for (local_idx, decomp) in parsed {
            let Some(parent) = chunk.get(local_idx) else { continue; };
            let parent_id = parent.id.as_uuid();
            let http = http.clone();
            let api_base = api_base.clone();
            let token = token.clone();
            let outcome = persist_decomposition(
                &pool,
                parent_id,
                &decomp,
                embedder.clone(),
                move |atom_text, generality| {
                    let http = http.clone();
                    let api_base = api_base.clone();
                    let token = token.clone();
                    async move {
                        // Canonical create via API: signing + DS + embed-on-write.
                        let resp = http
                            .post(format!("{api_base}/api/v1/claims"))
                            .bearer_auth(&token)
                            .json(&serde_json::json!({
                                "content": atom_text,
                                "methodology": "inductive_generalization",
                                "evidence_type": "logical",
                                "confidence": 0.5,
                                "labels": ["atom", format!("generality:{generality}")],
                            }))
                            .send()
                            .await?;
                        let v: serde_json::Value = resp.error_for_status()?.json().await?;
                        let id = v.get("id").or_else(|| v.get("claim_id"))
                            .and_then(|x| x.as_str())
                            .ok_or("API create returned no claim id")?;
                        Ok(uuid::Uuid::parse_str(id)?)
                    }
                },
            )
            .await?;
            total_atoms += outcome.atom_claim_ids.len();
            total_edges += outcome.edges_created;
        }
    }
    eprintln!("decompose complete: {total_atoms} atoms, {total_edges} decomposes_to edges");
    Ok(())
}
