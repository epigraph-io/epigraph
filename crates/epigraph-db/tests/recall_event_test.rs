//! `RecallEventRepository` — recall audit log (backlog 8cbffa0e / design F5).
//!
//! The audit property this table exists for is not "a row was written" but
//! "the row discriminates WHY a replayed query returned something different".
//! These tests pin that discrimination, plus the GIN-backed reverse lookup and
//! retention pruning.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{NewRecallEvent, RecallEventRepository};
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-recall-event', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool).await.expect("seed agent")
}

fn event(
    agent: Option<Uuid>,
    tool: &str,
    query: &str,
    pgvec: Option<&str>,
    ids: Vec<Uuid>,
) -> NewRecallEvent {
    NewRecallEvent {
        id: Uuid::new_v4(),
        agent_id: agent,
        tool: tool.to_string(),
        query_text: query.to_string(),
        query_pgvector: pgvec.map(str::to_string),
        params: serde_json::json!({"limit": 10}),
        returned_claim_ids: ids,
    }
}

/// The core audit property. Same query text with the SAME embedding hash but
/// different results means the corpus changed; the same text with a DIFFERENT
/// hash means the embedder changed. If the hash did not depend on the vector,
/// these two cases would be indistinguishable and the table would be useless.
#[sqlx::test(migrations = "../../migrations")]
async fn embedding_hash_discriminates_corpus_change_from_embedder_change(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());

    let e1 = RecallEventRepository::log(
        &pool,
        event(
            Some(agent),
            "recall",
            "same query",
            Some("[0.1,0.2]"),
            vec![a],
        ),
    )
    .await
    .unwrap();
    // Corpus changed: identical embedder output, different result set.
    let e2 = RecallEventRepository::log(
        &pool,
        event(
            Some(agent),
            "recall",
            "same query",
            Some("[0.1,0.2]"),
            vec![a, b],
        ),
    )
    .await
    .unwrap();
    // Embedder changed: same text, different vector.
    let e3 = RecallEventRepository::log(
        &pool,
        event(
            Some(agent),
            "recall",
            "same query",
            Some("[0.9,0.8]"),
            vec![a],
        ),
    )
    .await
    .unwrap();

    let rows = RecallEventRepository::list(&pool, &viewer, Some(agent), None, None, None, 50, 0)
        .await
        .unwrap();
    let get = |id: Uuid| {
        rows.iter()
            .find(|r| r.id == id)
            .expect("row present")
            .clone()
    };

    let (r1, r2, r3) = (get(e1), get(e2), get(e3));
    assert_eq!(
        r1.query_embedding_hash, r2.query_embedding_hash,
        "same vector => same hash, so differing results isolate a CORPUS change"
    );
    assert_ne!(r1.returned_claim_ids, r2.returned_claim_ids);
    assert_ne!(
        r1.query_embedding_hash, r3.query_embedding_hash,
        "different vector => different hash, isolating an EMBEDDER change"
    );
    assert_eq!(r1.returned_claim_ids, r3.returned_claim_ids);
}

/// The raw vector must NOT be recoverable from the log — the design stores a
/// hash precisely to avoid 16x row bloat. A regression that stored the literal
/// would still pass a "row was written" test.
#[sqlx::test(migrations = "../../migrations")]
async fn raw_vector_is_not_stored(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let pgvec = "[0.12345,0.67890]";
    RecallEventRepository::log(
        &pool,
        event(Some(agent), "recall", "q", Some(pgvec), vec![]),
    )
    .await
    .unwrap();

    let rows = RecallEventRepository::list(&pool, &viewer, Some(agent), None, None, None, 10, 0)
        .await
        .unwrap();
    let hash = rows[0].query_embedding_hash.clone().expect("hash present");
    assert_eq!(
        hash.len(),
        32,
        "BLAKE3 digest is 32 bytes, not a serialized vector"
    );
    assert!(
        !String::from_utf8_lossy(&hash).contains("0.12345"),
        "the literal must not survive into the stored bytes"
    );
}

/// A lexical-only recall (embedder down) logs a NULL hash rather than failing
/// — the degraded path is itself audit-relevant.
#[sqlx::test(migrations = "../../migrations")]
async fn absent_embedding_logs_null_hash(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    RecallEventRepository::log(
        &pool,
        event(Some(agent), "recall", "lexical only", None, vec![]),
    )
    .await
    .unwrap();
    let rows = RecallEventRepository::list(&pool, &viewer, Some(agent), None, None, None, 10, 0)
        .await
        .unwrap();
    assert!(rows[0].query_embedding_hash.is_none());
}

/// "Which queries ever surfaced this claim?" — the GIN-backed reverse lookup,
/// the read this table's index layout exists to serve.
#[sqlx::test(migrations = "../../migrations")]
async fn claim_filter_finds_queries_that_returned_a_claim(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let (wanted, other) = (Uuid::new_v4(), Uuid::new_v4());

    RecallEventRepository::log(
        &pool,
        event(
            Some(agent),
            "recall",
            "hit",
            Some("[1]"),
            vec![wanted, other],
        ),
    )
    .await
    .unwrap();
    RecallEventRepository::log(
        &pool,
        event(Some(agent), "recall", "miss", Some("[1]"), vec![other]),
    )
    .await
    .unwrap();

    let found = RecallEventRepository::list(&pool, &viewer, None, Some(wanted), None, None, 50, 0)
        .await
        .unwrap();
    assert_eq!(
        found.len(),
        1,
        "only the query that actually returned the claim"
    );
    assert_eq!(found[0].query_text, "hit");
}

/// An unauthenticated / library-level recall logs with a NULL agent rather
/// than being dropped.
#[sqlx::test(migrations = "../../migrations")]
async fn agentless_event_is_accepted(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let id = RecallEventRepository::log(&pool, event(None, "recall", "anon", Some("[1]"), vec![]))
        .await
        .expect("agentless log must be accepted");
    let rows = RecallEventRepository::list(&pool, &viewer, None, None, None, None, 50, 0)
        .await
        .unwrap();
    assert!(rows.iter().any(|r| r.id == id && r.agent_id.is_none()));
}

/// Retention prunes old rows and spares fresh ones.
#[sqlx::test(migrations = "../../migrations")]
async fn prune_removes_only_rows_past_retention(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let fresh = RecallEventRepository::log(
        &pool,
        event(Some(agent), "recall", "fresh", Some("[1]"), vec![]),
    )
    .await
    .unwrap();
    let stale = RecallEventRepository::log(
        &pool,
        event(Some(agent), "recall", "stale", Some("[1]"), vec![]),
    )
    .await
    .unwrap();

    sqlx::query("UPDATE recall_events SET created_at = NOW() - INTERVAL '120 days' WHERE id = $1")
        .bind(stale)
        .execute(&pool)
        .await
        .unwrap();

    let deleted = RecallEventRepository::prune_older_than(&pool, 90)
        .await
        .unwrap();
    assert_eq!(deleted, 1, "exactly the row past the 90-day window");

    let rows = RecallEventRepository::list(&pool, &viewer, Some(agent), None, None, None, 50, 0)
        .await
        .unwrap();
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    assert!(ids.contains(&fresh));
    assert!(!ids.contains(&stale));
}
