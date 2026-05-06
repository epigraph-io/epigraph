//! End-to-end test of the bridge_component pipeline through `run_pipeline`-equivalent
//! library code. Uses --provider mock so no real LLM call.

#![cfg(feature = "genai")]

use sqlx::PgPool;
use uuid::Uuid;

// Imitate what bridge_component does: detect components, build candidate
// table, call rerank_candidates_table — all in-process.

#[sqlx::test(migrations = "../../migrations")]
async fn pipeline_dry_run_with_isolated_components(pool: PgPool) {
    use epigraph_cli::bridge::candidates::{build_candidate_table, drop_candidate_table};
    use epigraph_cli::bridge::components::compute_components;
    use epigraph_cli::rerank::{rerank_candidates_table, RerankConfig};

    // Seed: agent + 2 disconnected components, each with one level=3 atom
    // that has a 1536d embedding.
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent)
        .bind("aa".repeat(32))
        .execute(&pool)
        .await
        .unwrap();

    async fn seed_atom(pool: &PgPool, agent: Uuid, mag: f64) -> Uuid {
        let id = Uuid::new_v4();
        let hash: Vec<u8> = id
            .as_bytes()
            .iter()
            .copied()
            .chain(std::iter::repeat_n(0, 16))
            .take(32)
            .collect();
        let mut zeros = vec!["0.0".to_string(); 1536];
        zeros[0] = mag.to_string();
        let pgvec = format!("[{}]", zeros.join(","));
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding) \
             VALUES ($1, $2, $3, $4, 0.5, jsonb_build_object('level', 3), $5::vector)",
        )
        .bind(id)
        .bind(format!("a-{id}"))
        .bind(hash)
        .bind(agent)
        .bind(&pgvec)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    let small_atom = seed_atom(&pool, agent, 0.99).await;
    let target_atom = seed_atom(&pool, agent, 0.95).await;

    // No structural edges — they are isolated components.
    let components = compute_components(&pool).await.unwrap();
    assert_eq!(
        components.len(),
        2,
        "expected 2 isolated singleton components"
    );

    let table = format!("test_pipeline_{}", Uuid::new_v4().simple());
    let count = build_candidate_table(&pool, &table, &[small_atom], &[target_atom], 0.5, 10)
        .await
        .unwrap();
    assert_eq!(count, 1, "expected 1 candidate pair");

    let config = RerankConfig {
        min_similarity: 0.5,
        batch_size: 10,
        provider: "mock".to_string(),
        model: None,
        dry_run: true, // dry-run: no edge creation
        limit: None,
        verbose: false,
    };
    let summary = rerank_candidates_table(&pool, &table, &config)
        .await
        .unwrap();
    assert_eq!(summary.candidates_evaluated, 1);
    assert_eq!(summary.edges_created, 0, "dry-run must not create edges");

    drop_candidate_table(&pool, &table).await.unwrap();
}
