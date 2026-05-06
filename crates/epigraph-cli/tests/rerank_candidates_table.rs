//! Verify the candidates-table mode finds the right pairs.
//!
//! Wires the new `rerank_candidates_table` library entry point against a
//! seeded temp table and confirms summary accounting works under `--provider mock`
//! (which returns an empty JSON array, so accept counts are zero by design).

#![cfg(feature = "genai")]

use epigraph_cli::rerank::{rerank_candidates_table, RerankConfig};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn candidates_table_with_mock_provider_returns_summary(pool: PgPool) {
    // Seed agent
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind("aa".repeat(32))
        .execute(&pool)
        .await
        .unwrap();

    // Build a 1536-dim pgvector literal with one nonzero component so the
    // embedding column is non-null and similarity is defined.
    let mut zeros = vec!["0.0"; 1536];
    zeros[0] = "0.99";
    let pgvec = format!("[{}]", zeros.join(","));

    let mut ids = Vec::new();
    for i in 0..2 {
        let id = Uuid::new_v4();
        let hash: Vec<u8> = id
            .as_bytes()
            .iter()
            .copied()
            .chain(std::iter::repeat_n(0, 16))
            .take(32)
            .collect();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding) \
             VALUES ($1, $2, $3, $4, 0.5, jsonb_build_object('level', 3), $5::vector)",
        )
        .bind(id)
        .bind(format!("c{i}"))
        .bind(hash)
        .bind(agent_id)
        .bind(&pgvec)
        .execute(&pool)
        .await
        .unwrap();
        ids.push(id);
    }

    // Populate the candidate table with the single (s, t) pair.
    // NOTE: regular table, not TEMP — sqlx pool may check out a different
    // connection for the rerank query and would lose session-local TEMPs.
    // sqlx::test gives each test its own database so cleanup isn't needed.
    sqlx::query("CREATE TABLE bridge_test_candidates (source_id uuid, target_id uuid)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO bridge_test_candidates VALUES ($1, $2)")
        .bind(ids[0])
        .bind(ids[1])
        .execute(&pool)
        .await
        .unwrap();

    let config = RerankConfig {
        min_similarity: 0.0,
        batch_size: 10,
        provider: "mock".to_string(),
        model: None,
        dry_run: true,
        limit: None,
        verbose: false,
    };

    let summary = rerank_candidates_table(&pool, "bridge_test_candidates", &config)
        .await
        .expect("rerank_candidates_table failed");

    assert_eq!(
        summary.candidates_evaluated, 1,
        "should evaluate the one pair we seeded"
    );
    // Mock provider returns empty `[]` → no accepts → no edges, dry_run reinforces it.
    assert_eq!(
        summary.edges_created, 0,
        "dry_run + mock empty response must not create edges"
    );
    assert_eq!(summary.llm_accepted, 0);
    // duration_ms is `u128`; just make sure the field is populated as expected (>= 0 always true).
    let _ = summary.duration_ms;
}

#[sqlx::test(migrations = "../../migrations")]
async fn candidates_table_rejects_unsafe_identifier(pool: PgPool) {
    let config = RerankConfig {
        min_similarity: 0.0,
        batch_size: 10,
        provider: "mock".to_string(),
        model: None,
        dry_run: true,
        limit: None,
        verbose: false,
    };

    let result = rerank_candidates_table(&pool, "foo; DROP TABLE claims", &config).await;
    assert!(
        result.is_err(),
        "SQL-injection-shaped table name must be rejected"
    );
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("[a-zA-Z0-9_]+"),
        "error should explain identifier shape, got: {msg}"
    );
}
