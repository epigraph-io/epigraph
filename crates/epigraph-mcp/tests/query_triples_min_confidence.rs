//! Regression test: `query_triples` `min_confidence` is caller-controlled.
//!
//! Before PR #303, `query_triples` in `crates/epigraph-mcp/src/tools/rdf.rs`
//! hardcoded the confidence threshold at `0.5`, ignoring whatever the caller
//! passed in `QueryTriplesParams::min_confidence`. The fix changed it to
//! `params.min_confidence.unwrap_or(0.0)`.
//!
//! These tests pin two properties of that fix:
//! 1. When `min_confidence` is `None` or `Some(0.0)`, all triples are returned
//!    (the old 0.5 floor silently dropped triples with confidence < 0.5).
//! 2. When `min_confidence` is `Some(0.8)`, only triples with confidence ≥ 0.8
//!    are returned (proves the threshold is genuinely caller-controlled on the
//!    high side, not just pegged at 0.0).

use epigraph_db::TripleRepository;
use epigraph_mcp::tools::rdf::query_triples;
use epigraph_mcp::types::QueryTriplesParams;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// Insert a minimal agent and return its UUID.
async fn insert_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'rdf-min-conf-test', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("insert agent")
}

/// Insert a current claim and return its UUID.
async fn insert_claim(pool: &PgPool, agent_id: Uuid, tag: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current) \
         VALUES ($1, sha256($1::bytea), 0.7, $2, true) \
         RETURNING id",
    )
    .bind(format!("rdf-min-conf-claim-{tag}-{}", Uuid::new_v4()))
    .bind(agent_id)
    .fetch_one(pool)
    .await
    .expect("insert claim")
}

/// Insert a canonical entity and return its UUID.
async fn insert_entity(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO entities (canonical_name, type_top, is_canonical) \
         VALUES ($1, 'Material', true) \
         RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("insert entity")
}

/// Seed one canonical subject entity, one current claim, and three triples at
/// confidence 0.3, 0.7, 0.9. Returns (entity_id, claim_id).
async fn seed_fixtures(pool: &PgPool) -> (Uuid, Uuid) {
    let agent_id = insert_agent(pool).await;
    let claim_id = insert_claim(pool, agent_id, "seed").await;
    let entity_id = insert_entity(pool, &format!("rdf-test-entity-{}", Uuid::new_v4())).await;

    TripleRepository::batch_create_triples(
        pool,
        vec![
            (
                claim_id,
                entity_id,
                "has_property".to_string(),
                None,
                Some("low-confidence".to_string()),
                0.3,
                "test".to_string(),
                serde_json::json!({}),
            ),
            (
                claim_id,
                entity_id,
                "has_property".to_string(),
                None,
                Some("medium-confidence".to_string()),
                0.7,
                "test".to_string(),
                serde_json::json!({}),
            ),
            (
                claim_id,
                entity_id,
                "has_property".to_string(),
                None,
                Some("high-confidence".to_string()),
                0.9,
                "test".to_string(),
                serde_json::json!({}),
            ),
        ],
    )
    .await
    .expect("batch_create_triples");

    (entity_id, claim_id)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// `min_confidence = None` must default to 0.0 (return all triples), not the
/// old hardcoded 0.5 that silently dropped the 0.3 triple.
///
/// This is the load-bearing regression assertion: under the old code this test
/// returns 2 triples; under the fixed code it returns 3.
#[sqlx::test(migrations = "../../migrations")]
async fn query_triples_none_returns_all_triples(pool: PgPool) {
    let (_entity_id, _claim_id) = seed_fixtures(&pool).await;
    let server = build_test_server(pool.clone());

    let result = query_triples(
        &server,
        QueryTriplesParams {
            subject: None,
            subject_type: None,
            predicate: None,
            object: None,
            object_type: None,
            min_confidence: None, // must unwrap_or(0.0), not hardcode 0.5
            limit: None,
        },
    )
    .await
    .expect("query_triples with min_confidence=None");

    let body = common::first_text(&result);
    let count = body["count"].as_u64().expect("count field");
    // All three triples (0.3, 0.7, 0.9) must be returned.
    // The pre-fix hardcoded 0.5 would return only 2 (0.7 and 0.9).
    assert!(
        count >= 3,
        "min_confidence=None must return all 3 triples (got {count}) — \
         old hardcoded 0.5 would have returned only 2"
    );
}

/// `min_confidence = Some(0.0)` is the explicit equivalent of the None case —
/// confirms the unwrap_or path and the low threshold work together.
#[sqlx::test(migrations = "../../migrations")]
async fn query_triples_zero_returns_all_triples(pool: PgPool) {
    let (_entity_id, _claim_id) = seed_fixtures(&pool).await;
    let server = build_test_server(pool.clone());

    let result = query_triples(
        &server,
        QueryTriplesParams {
            subject: None,
            subject_type: None,
            predicate: None,
            object: None,
            object_type: None,
            min_confidence: Some(0.0),
            limit: None,
        },
    )
    .await
    .expect("query_triples with min_confidence=Some(0.0)");

    let body = common::first_text(&result);
    let count = body["count"].as_u64().expect("count field");
    assert!(
        count >= 3,
        "min_confidence=Some(0.0) must return all 3 triples (got {count})"
    );
}

/// `min_confidence = Some(0.8)` must exclude triples at 0.3 and 0.7, proving
/// the threshold is caller-controlled on the high side, not pegged at 0.0.
/// Only the triple at confidence 0.9 satisfies the filter.
#[sqlx::test(migrations = "../../migrations")]
async fn query_triples_high_threshold_filters_correctly(pool: PgPool) {
    let (_entity_id, claim_id) = seed_fixtures(&pool).await;
    let server = build_test_server(pool.clone());

    let result = query_triples(
        &server,
        QueryTriplesParams {
            subject: None,
            subject_type: None,
            predicate: None,
            object: None,
            object_type: None,
            min_confidence: Some(0.8),
            limit: Some(100),
        },
    )
    .await
    .expect("query_triples with min_confidence=Some(0.8)");

    let body = common::first_text(&result);
    let triples = body["triples"].as_array().expect("triples array");

    // All returned triples must belong to our seeded claim and have confidence >= 0.8.
    let our_triples: Vec<_> = triples
        .iter()
        .filter(|t| t["claim_id"].as_str() == Some(&claim_id.to_string()))
        .collect();

    // We seeded exactly one triple at confidence 0.9 — confirm it's present.
    assert_eq!(
        our_triples.len(),
        1,
        "min_confidence=Some(0.8) must return exactly 1 triple from our seed \
         (got {}: {triples:?})",
        our_triples.len()
    );

    let conf = our_triples[0]["confidence"]
        .as_f64()
        .expect("confidence field");
    assert!(
        conf >= 0.8,
        "returned triple must have confidence >= 0.8 (got {conf})"
    );
}
