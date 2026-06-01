//! Integration tests for `ClaimRepository::search_claims_by_embedding`
//! (backlog 1564bdaf). These assert the LEVEL-AGNOSTIC behavior that the
//! pre-existing `search_by_embedding` (level=2-gated) does NOT provide — which
//! is precisely the gap that made flat `recall`/`find_workflow` return empty.
//!
//! Seeding mirrors `claim_search_by_embedding.rs` (the established harness for
//! this repo): a controlled `agents` row, distinct 32-byte content_hashes, and
//! a 1536d query vector. Direct `sqlx::query` INSERTs here seed a THROWAWAY
//! `#[sqlx::test]` database, not production — the no-raw-SQL invariant governs
//! production claim writes (API/repo/MCP), not disposable test fixtures, and
//! the sibling test file establishes this exact precedent.

use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

fn build_query_vec() -> String {
    let mut v = vec!["0.0"; 1536];
    v[0] = "0.99";
    format!("[{}]", v.join(","))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind("bb".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    agent_id
}

fn distinct_hash(tag: u8) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[0] = tag;
    h
}

/// CORE REGRESSION: a memorized claim (NO `level` property) and an atom
/// (`level=3`) must BOTH be retrievable. The old `search_by_embedding` gates on
/// `(properties->>'level')::int = 2` and would drop both — that gate is the
/// root cause of the empty flat recall.
#[sqlx::test(migrations = "../../migrations")]
async fn returns_level_less_and_non_level_2_claims(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let pgvec = build_query_vec();

    let memorized = Uuid::new_v4(); // properties = '{}' (no level), like memorize()
    let atom = Uuid::new_v4(); // level = 3
    let para = Uuid::new_v4(); // level = 2 (control: present under both methods)

    // memorized: empty properties object — no 'level' key at all.
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding) \
         VALUES ($1, $2, $3, $4, 0.9, '{}'::jsonb, $5::vector)",
    )
    .bind(memorized).bind("memorized claim").bind(distinct_hash(1))
    .bind(agent).bind(&pgvec).execute(&pool).await.expect("insert memorized");

    for (id, level, tag) in [(atom, 3, 2u8), (para, 2, 3u8)] {
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding) \
             VALUES ($1, $2, $3, $4, 0.9, jsonb_build_object('level', $5::int), $6::vector)",
        )
        .bind(id).bind(format!("c-{id}")).bind(distinct_hash(tag))
        .bind(agent).bind(level).bind(&pgvec).execute(&pool).await.expect("insert leveled");
    }

    let hits = ClaimRepository::search_claims_by_embedding(&pool, &pgvec, 1536, 10, None)
        .await
        .expect("search_claims_by_embedding");
    let ids: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();

    assert!(ids.contains(&memorized), "level-less memorized claim must be returned");
    assert!(ids.contains(&atom), "level=3 atom must be returned (no level gate)");
    assert!(ids.contains(&para), "level=2 paragraph must still be returned");
}

/// label_filter=Some scopes results to the overlap set — find_workflow's
/// semantic stage must see only `workflow`-labeled claims.
#[sqlx::test(migrations = "../../migrations")]
async fn label_filter_restricts_to_overlapping_labels(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let pgvec = build_query_vec();

    let wf = Uuid::new_v4();
    let other = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, labels, properties, embedding) \
         VALUES ($1, $2, $3, $4, 0.9, ARRAY['workflow']::text[], '{}'::jsonb, $5::vector)",
    )
    .bind(wf).bind("a workflow").bind(distinct_hash(4))
    .bind(agent).bind(&pgvec).execute(&pool).await.expect("insert workflow claim");

    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, labels, properties, embedding) \
         VALUES ($1, $2, $3, $4, 0.9, ARRAY['note']::text[], '{}'::jsonb, $5::vector)",
    )
    .bind(other).bind("a non-workflow note").bind(distinct_hash(5))
    .bind(agent).bind(&pgvec).execute(&pool).await.expect("insert note claim");

    let labels = ["workflow".to_string()];
    let hits = ClaimRepository::search_claims_by_embedding(&pool, &pgvec, 1536, 10, Some(&labels))
        .await
        .expect("search with label filter");
    let ids: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();

    assert!(ids.contains(&wf), "workflow-labeled claim must be returned under filter");
    assert!(!ids.contains(&other), "non-workflow claim must be excluded by label filter");
}

/// COALESCE(is_current, true) = true must exclude superseded claims, matching
/// the evidence path's semantics callers rely on.
#[sqlx::test(migrations = "../../migrations")]
async fn excludes_non_current_claims(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let pgvec = build_query_vec();

    let live = Uuid::new_v4();
    let stale = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, properties, embedding) \
         VALUES ($1, $2, $3, $4, 0.9, true, '{}'::jsonb, $5::vector)",
    )
    .bind(live).bind("live claim").bind(distinct_hash(6))
    .bind(agent).bind(&pgvec).execute(&pool).await.expect("insert live");

    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, properties, embedding) \
         VALUES ($1, $2, $3, $4, 0.9, false, '{}'::jsonb, $5::vector)",
    )
    .bind(stale).bind("stale claim").bind(distinct_hash(7))
    .bind(agent).bind(&pgvec).execute(&pool).await.expect("insert stale");

    let hits = ClaimRepository::search_claims_by_embedding(&pool, &pgvec, 1536, 10, None)
        .await
        .expect("search");
    let ids: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();

    assert!(ids.contains(&live), "is_current=true claim must be returned");
    assert!(!ids.contains(&stale), "is_current=false claim must be excluded");
}

/// Unsupported dim is an explicit InvalidData error, never a silent wrong-column query.
#[sqlx::test(migrations = "../../migrations")]
async fn rejects_unsupported_dim(pool: PgPool) {
    let pgvec = build_query_vec();
    let result = ClaimRepository::search_claims_by_embedding(&pool, &pgvec, 2048, 5, None).await;
    assert!(
        matches!(result, Err(epigraph_db::DbError::InvalidData { .. })),
        "expected InvalidData for unsupported dim, got {:?}",
        result
    );
}
