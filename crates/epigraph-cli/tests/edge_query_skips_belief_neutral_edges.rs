//! `backfill_factors::EDGE_QUERY` does not select an edge marked
//! `"moves_belief": false` (backlog 22602dd8).
//!
//! An abstract consolidation links its new abstraction to each source with a
//! `generalizes` edge and marks it this way: the abstraction's default
//! confidence comes from those same sources, so wiring the edge into a source
//! that has no factors yet would feed the sources' own belief back into them.
//!
//! The fixture holds a marked `generalizes` edge and an unmarked one in the
//! same shape (current endpoints, a factorless target). The selection must
//! return the control and skip the marked edge.
#![cfg(feature = "db")]

use epigraph_cli::backfill_factors::EDGE_QUERY;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let pk: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    sqlx::query_scalar("INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id")
        .bind(&pk)
        .bind("moves-belief edge query")
        .fetch_one(pool)
        .await
        .expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, belief, plausibility) \
         VALUES ($1, $2, $3, 0.5, 0.9, 0.95) RETURNING id",
    )
    .bind(content)
    .bind(hash.as_slice())
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn seed_edge(pool: &PgPool, src: Uuid, tgt: Uuid, props: serde_json::Value) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, 'claim', $2, 'claim', 'generalizes', $3) RETURNING id",
    )
    .bind(src)
    .bind(tgt)
    .bind(props)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

#[test]
fn the_edge_query_carries_the_shared_moves_belief_predicate() {
    assert!(
        EDGE_QUERY.contains(epigraph_db::EDGE_MOVES_BELIEF_SQL),
        "EDGE_QUERY must spell the predicate exactly as epigraph_db::EDGE_MOVES_BELIEF_SQL"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_edge_phase_skips_an_edge_that_moves_no_belief(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let abstraction = seed_claim(&pool, agent, "an abstraction").await;
    let source = seed_claim(&pool, agent, "one of its sources").await;
    let general = seed_claim(&pool, agent, "an ordinary generaliser").await;
    let specific = seed_claim(&pool, agent, "an ordinary specific claim").await;
    let marked = seed_edge(
        &pool,
        abstraction,
        source,
        serde_json::json!({"mode": "abstract", "moves_belief": false}),
    )
    .await;
    let control = seed_edge(&pool, general, specific, serde_json::json!({})).await;

    let selected: Vec<(Uuid, Uuid, Uuid, Uuid, String)> = sqlx::query_as(EDGE_QUERY)
        .bind(i64::MAX)
        .bind(0_i64)
        .fetch_all(&pool)
        .await
        .expect("EDGE_QUERY");
    let ids: Vec<Uuid> = selected.iter().map(|r| r.0).collect();

    assert!(
        ids.contains(&control),
        "control: an unmarked generalizes edge onto a factorless current target is selected; \
         got {selected:?}"
    );
    assert!(
        !ids.contains(&marked),
        "the edge phase must not select the edge {marked} marked moves_belief=false; \
         got {selected:?}"
    );
}
