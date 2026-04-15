//! Embedding-based bridge detection for cross-component relationship discovery.
//!
//! This binary performs a second enrichment pass using vector similarity
//! to find semantically related claims that the sliding-window LLM enricher
//! missed. It queries pgvector for high-similarity cross-component pairs,
//! sends them to the LLM for relationship classification, and submits
//! confirmed edges to the API.
//!
//! Supports multiple LLM providers via `--provider`:
//! - `anthropic` (default) — direct API, requires `ANTHROPIC_API_KEY` or OAuth token
//! - `mock` — returns empty results (for testing)

use epigraph_cli::enrichment::llm_client::{create_llm_client, LlmClient};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// CONFIGURATION
// =============================================================================

/// Minimum cosine similarity to consider a pair as a bridge candidate
const MIN_SIMILARITY: f64 = 0.80;

/// Maximum candidates per claim (top-K nearest cross-component neighbors)
const TOP_K_PER_CLAIM: i32 = 3;

/// Number of candidate pairs to send to the LLM in each batch
const LLM_BATCH_SIZE: usize = 15;

/// API endpoint (default)
const DEFAULT_ENDPOINT: &str = "http://localhost:8080";

// =============================================================================
// DATA TYPES
// =============================================================================

#[derive(Debug, Clone)]
struct CandidatePair {
    source_id: Uuid,
    target_id: Uuid,
    source_content: String,
    target_content: String,
    similarity: f64,
}

#[derive(Debug, Serialize)]
struct CreateEdgeRequest {
    source_id: Uuid,
    target_id: Uuid,
    source_type: String,
    target_type: String,
    relationship: String,
    properties: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct LlmRelationship {
    source_index: usize,
    target_index: usize,
    relationship: String,
    strength: f64,
    rationale: String,
}

const VALID_RELATIONSHIPS: &[&str] = &[
    "supports",
    "refutes",
    "elaborates",
    "specializes",
    "generalizes",
    "challenges",
];

// =============================================================================
// DATABASE QUERIES
// =============================================================================

/// Find cross-component bridge candidates using pgvector cosine similarity.
///
/// Uses iterative label propagation to detect connected components, then
/// finds high-similarity pairs across different components that don't
/// already have edges.
async fn find_bridge_candidates(
    pool: &sqlx::PgPool,
) -> Result<Vec<CandidatePair>, Box<dyn std::error::Error>> {
    // Acquire a single connection so temp tables persist across queries
    let mut conn = pool.acquire().await?;

    // Step 1: Build component labels using iterative propagation
    sqlx::query("DROP TABLE IF EXISTS _eb_edges, _eb_labels")
        .execute(&mut *conn)
        .await?;

    sqlx::query(
        "CREATE TEMP TABLE _eb_edges AS
         SELECT DISTINCT source_id AS a, target_id AS b FROM edges
         WHERE source_type = 'claim' AND target_type = 'claim'
         UNION
         SELECT DISTINCT target_id AS a, source_id AS b FROM edges
         WHERE source_type = 'claim' AND target_type = 'claim'",
    )
    .execute(&mut *conn)
    .await?;

    sqlx::query(
        "CREATE TEMP TABLE _eb_labels AS
         SELECT id AS node_id, id::text AS label FROM claims",
    )
    .execute(&mut *conn)
    .await?;

    // Iterative label propagation (up to 30 rounds)
    for round in 1..=30 {
        let result = sqlx::query(
            "WITH new_labels AS (
                SELECT l.node_id,
                       LEAST(l.label, MIN(nl.label)) AS new_label
                FROM _eb_labels l
                LEFT JOIN _eb_edges e ON e.a = l.node_id
                LEFT JOIN _eb_labels nl ON nl.node_id = e.b
                GROUP BY l.node_id, l.label
            )
            UPDATE _eb_labels
            SET label = new_labels.new_label
            FROM new_labels
            WHERE _eb_labels.node_id = new_labels.node_id
              AND _eb_labels.label <> new_labels.new_label",
        )
        .execute(&mut *conn)
        .await?;

        let changed = result.rows_affected();
        if changed == 0 {
            println!("  Component detection converged after {round} rounds");
            break;
        }
    }

    // Step 2: Find cross-component pairs with high similarity and no existing edge
    let rows: Vec<(Uuid, Uuid, String, String, f64)> =
        sqlx::query_as::<_, (Uuid, Uuid, String, String, f64)>(
            "WITH comp AS (
            SELECT node_id, label FROM _eb_labels
        )
        SELECT
            c1.id,
            c2.id,
            c1.content,
            c2.content,
            (1 - (c1.embedding <=> c2.embedding))::float8 AS similarity
        FROM claims c1
        JOIN comp l1 ON l1.node_id = c1.id
        CROSS JOIN LATERAL (
            SELECT c2x.id, c2x.content, c2x.embedding
            FROM claims c2x
            JOIN comp l2 ON l2.node_id = c2x.id AND l2.label <> l1.label
            WHERE c2x.embedding IS NOT NULL
              AND c2x.id > c1.id
              AND NOT EXISTS (
                  SELECT 1 FROM edges e
                  WHERE (e.source_id = c1.id AND e.target_id = c2x.id)
                     OR (e.source_id = c2x.id AND e.target_id = c1.id)
              )
            ORDER BY c1.embedding <=> c2x.embedding
            LIMIT $1
        ) c2
        WHERE c1.embedding IS NOT NULL
          AND (1 - (c1.embedding <=> c2.embedding)) >= $2
        ORDER BY similarity DESC",
        )
        .bind(TOP_K_PER_CLAIM)
        .bind(MIN_SIMILARITY)
        .fetch_all(&mut *conn)
        .await?;

    // Cleanup
    sqlx::query("DROP TABLE IF EXISTS _eb_edges, _eb_labels")
        .execute(&mut *conn)
        .await?;

    let candidates: Vec<CandidatePair> = rows
        .into_iter()
        .map(
            |(source_id, target_id, source_content, target_content, similarity)| CandidatePair {
                source_id,
                target_id,
                source_content,
                target_content,
                similarity,
            },
        )
        .collect();

    Ok(candidates)
}

// =============================================================================
// LLM INTERACTION
// =============================================================================

/// Build a prompt for the LLM to classify relationships between candidate pairs
fn build_bridge_prompt(pairs: &[CandidatePair]) -> String {
    let mut commits_text = String::new();
    // Present each claim with an index, interleaving source and target
    let mut claim_list: Vec<(usize, &str)> = Vec::new();
    for (i, pair) in pairs.iter().enumerate() {
        let src_idx = i * 2;
        let tgt_idx = i * 2 + 1;
        claim_list.push((src_idx, &pair.source_content));
        claim_list.push((tgt_idx, &pair.target_content));
    }

    for (idx, content) in &claim_list {
        commits_text.push_str(&format!("{idx}. {content}\n\n"));
    }

    // Build candidate pair descriptions
    let mut pairs_text = String::new();
    for (i, pair) in pairs.iter().enumerate() {
        pairs_text.push_str(&format!(
            "- Pair {}: commits {} and {} (cosine similarity: {:.3})\n",
            i,
            i * 2,
            i * 2 + 1,
            pair.similarity
        ));
    }

    format!(
        r#"You are an epistemic graph analyst. These commit pairs were identified as semantically similar by vector embeddings but are NOT currently connected in the knowledge graph.

For each candidate pair, determine if a real semantic relationship exists.

## Commits

{commits_text}
## Candidate Pairs (by embedding similarity)

{pairs_text}
## Relationship Types

- **supports**: A provides evidence or foundation for B
- **refutes**: A contradicts or undermines B
- **elaborates**: A adds detail to B
- **specializes**: A is a specific case of B
- **generalizes**: A is a broader version of B
- **challenges**: A raises questions about B's validity

## Rules

1. Only include relationships with strength >= 0.3
2. High embedding similarity does NOT guarantee a real relationship — only confirm genuine semantic links
3. Prefer fewer, confident relationships over many speculative ones
4. The rationale must explain WHY the relationship exists, not just repeat that they are similar
5. Use the source_index and target_index from the commit list above (0-based)

## Output

Return a JSON array of objects:
- source_index: integer (from the commit list)
- target_index: integer (from the commit list)
- relationship: string (one of: supports, refutes, elaborates, specializes, generalizes, challenges)
- strength: number (0.0 to 1.0)
- rationale: string

Return ONLY the JSON array. If no genuine relationships exist, return []."#
    )
}

/// Call the LLM to classify relationships, using the shared `LlmClient` trait.
async fn call_llm(
    client: &dyn LlmClient,
    prompt: &str,
) -> Result<Vec<LlmRelationship>, Box<dyn std::error::Error>> {
    let json_value = client
        .complete_json(prompt)
        .await
        .map_err(|e| format!("LLM error: {e}"))?;

    let relationships: Vec<LlmRelationship> =
        serde_json::from_value(json_value).map_err(|e| format!("Failed to parse LLM JSON: {e}"))?;

    Ok(relationships)
}

// =============================================================================
// EDGE SUBMISSION
// =============================================================================

/// Submit a confirmed edge to the API
async fn submit_edge(
    client: &reqwest::Client,
    endpoint: &str,
    source_id: Uuid,
    target_id: Uuid,
    relationship: &str,
    strength: f64,
    rationale: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = CreateEdgeRequest {
        source_id,
        target_id,
        source_type: "claim".to_string(),
        target_type: "claim".to_string(),
        relationship: relationship.to_string(),
        properties: Some(serde_json::json!({
            "strength": strength,
            "rationale": rationale,
            "source": "embedding_bridge_pass"
        })),
    };

    let url = format!("{endpoint}/api/v1/edges");
    let response = client
        .post(&url)
        .json(&request)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Edge submission failed (HTTP {status}): {body}").into());
    }

    Ok(())
}

// =============================================================================
// MAIN
// =============================================================================

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let endpoint = std::env::var("API_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let dry_run = std::env::args().any(|a| a == "--dry-run");

    // Parse --provider (default: anthropic)
    let args: Vec<String> = std::env::args().collect();
    let provider = args
        .windows(2)
        .find(|w| w[0] == "--provider")
        .map(|w| w[1].as_str())
        .unwrap_or("anthropic");

    // Create LLM client via shared factory
    let llm: Box<dyn LlmClient> = match create_llm_client(provider) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: Failed to create LLM client: {e}");
            std::process::exit(1);
        }
    };

    println!("=== Embedding Bridge Detection ===");
    println!("Endpoint:   {endpoint}");
    println!("Provider:   {provider}");
    println!("Model:      {}", llm.model_name());
    println!("Min sim:    {MIN_SIMILARITY}");
    println!("Top-K:      {TOP_K_PER_CLAIM}");
    println!("Batch size: {LLM_BATCH_SIZE}");
    println!("Dry run:    {dry_run}");
    println!();

    // Connect to database
    println!("Connecting to PostgreSQL...");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("Failed to connect to PostgreSQL");

    // Step 1: Find bridge candidates
    println!("Finding cross-component bridge candidates...");
    let candidates = find_bridge_candidates(&pool)
        .await
        .expect("Failed to find candidates");

    println!(
        "Found {} candidate pairs (similarity >= {MIN_SIMILARITY})",
        candidates.len()
    );
    if candidates.is_empty() {
        println!("No bridge candidates found. Graph may already be fully connected.");
        return;
    }

    // Show similarity distribution
    let avg_sim: f64 =
        candidates.iter().map(|c| c.similarity).sum::<f64>() / candidates.len() as f64;
    let max_sim = candidates
        .iter()
        .map(|c| c.similarity)
        .fold(0.0_f64, f64::max);
    let min_sim = candidates
        .iter()
        .map(|c| c.similarity)
        .fold(1.0_f64, f64::min);
    println!("Similarity range: {min_sim:.4} — {max_sim:.4} (avg: {avg_sim:.4})");
    println!();

    // Step 2: Process in LLM batches
    let http_client = reqwest::Client::new();
    let num_batches = candidates.len().div_ceil(LLM_BATCH_SIZE);
    let mut total_edges = 0;
    let mut total_submitted = 0;
    let mut total_failed = 0;

    for (batch_idx, batch) in candidates.chunks(LLM_BATCH_SIZE).enumerate() {
        println!(
            "--- Batch {}/{} ({} pairs) ---",
            batch_idx + 1,
            num_batches,
            batch.len()
        );

        // Build prompt
        let prompt = build_bridge_prompt(batch);

        // Call LLM
        print!("  Calling {}... ", llm.model_name());
        let relationships = match call_llm(llm.as_ref(), &prompt).await {
            Ok(rels) => {
                println!("got {} relationships", rels.len());
                rels
            }
            Err(e) => {
                println!("ERROR: {e}");
                continue;
            }
        };

        // Validate and submit edges
        for rel in &relationships {
            // Map LLM indices back to claim IDs
            let pair_idx = rel.source_index / 2;
            let is_source_first = rel.source_index % 2 == 0;

            if pair_idx >= batch.len() || rel.target_index / 2 >= batch.len() {
                eprintln!(
                    "  SKIP: indices out of bounds ({}, {})",
                    rel.source_index, rel.target_index
                );
                continue;
            }

            if !VALID_RELATIONSHIPS.contains(&rel.relationship.as_str()) {
                eprintln!("  SKIP: invalid relationship type '{}'", rel.relationship);
                continue;
            }

            if !(0.0..=1.0).contains(&rel.strength) || rel.strength < 0.3 {
                eprintln!("  SKIP: strength {:.2} out of valid range", rel.strength);
                continue;
            }

            // Resolve the actual claim pair
            let source_pair = &batch[rel.source_index / 2];
            let target_pair = &batch[rel.target_index / 2];

            let (source_id, target_id): (Uuid, Uuid) =
                if rel.source_index / 2 == rel.target_index / 2 {
                    // Same pair — source and target are the two claims in this pair
                    if is_source_first {
                        (source_pair.source_id, source_pair.target_id)
                    } else {
                        (source_pair.target_id, source_pair.source_id)
                    }
                } else {
                    // Cross-pair relationship (less common but possible)
                    let src = if is_source_first {
                        source_pair.source_id
                    } else {
                        source_pair.target_id
                    };
                    let tgt = if rel.target_index % 2 == 0 {
                        target_pair.source_id
                    } else {
                        target_pair.target_id
                    };
                    (src, tgt)
                };

            total_edges += 1;
            let src_str = source_id.to_string();
            let tgt_str = target_id.to_string();
            println!(
                "  EDGE: {} --[{}({:.2})]--> {} | {}",
                &src_str[..8],
                rel.relationship,
                rel.strength,
                &tgt_str[..8],
                rel.rationale.chars().take(60).collect::<String>()
            );

            if !dry_run {
                match submit_edge(
                    &http_client,
                    &endpoint,
                    source_id,
                    target_id,
                    &rel.relationship,
                    rel.strength,
                    &rel.rationale,
                )
                .await
                {
                    Ok(()) => total_submitted += 1,
                    Err(e) => {
                        eprintln!("  FAIL: {e}");
                        total_failed += 1;
                    }
                }
            }
        }
    }

    println!();
    println!("=== Bridge Detection Complete ===");
    println!("Candidates evaluated: {}", candidates.len());
    println!("Edges discovered:     {total_edges}");
    if dry_run {
        println!("Dry run — no edges submitted");
    } else {
        println!("Edges submitted:      {total_submitted}");
        println!("Edges failed:         {total_failed}");
    }
}
