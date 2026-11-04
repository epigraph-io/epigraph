//! `backfill_factors::EDGE_QUERY` does not select `supersedes` edges
//! (supersede SPEC §11 K12(b), delivery council N3).
//!
//! Under K12(b) `supersedes` is a Neutral restriction, so the edge phase's
//! auto-wire would write nothing for such an edge anyway. It is removed from
//! the selection so that the backfill's eligible count, which the X-3 delta
//! and the R-131 pre-count read, does not include edges that cannot carry
//! mass.
//!
//! The fixture holds, for each spelling, a `supersedes` edge between two
//! current claims onto a factorless target (exactly what the selection's other
//! predicates admit), and a `contradicts` edge in the same shape as the
//! control the selection must still return.
#![cfg(feature = "db")]

use epigraph_cli::backfill_factors::EDGE_QUERY;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let pk: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    sqlx::query_scalar("INSERT INTO agents (public_key, display_name) VALUES ($1, $2) RETURNING id")
        .bind(&pk)
        .bind("k12b edge query")
        .fetch_one(pool)
        .await
        .expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, believed: bool) -> Uuid {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    let (bel, pl) = if believed {
        (Some(0.9), Some(0.95))
    } else {
        (None, None)
    };
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, belief, plausibility) \
         VALUES ($1, $2, $3, 0.5, $4, $5) RETURNING id",
    )
    .bind(content)
    .bind(hash.as_slice())
    .bind(agent)
    .bind(bel)
    .bind(pl)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn seed_edge(pool: &PgPool, src: Uuid, tgt: Uuid, rel: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(src)
    .bind(tgt)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_edge_phase_selects_no_supersedes_edge(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let mut lineage = Vec::new();
    for rel in ["supersedes", "SUPERSEDES"] {
        let newer = seed_claim(&pool, agent, &format!("k12b newer {rel}"), true).await;
        let older = seed_claim(&pool, agent, &format!("k12b older {rel}"), false).await;
        lineage.push(seed_edge(&pool, newer, older, rel).await);
    }
    let rival = seed_claim(&pool, agent, "k12b rival", true).await;
    let attacked = seed_claim(&pool, agent, "k12b attacked", false).await;
    let control = seed_edge(&pool, rival, attacked, "contradicts").await;

    let selected: Vec<(Uuid, Uuid, Uuid, Uuid, String)> = sqlx::query_as(EDGE_QUERY)
        .bind(i64::MAX)
        .bind(0_i64)
        .fetch_all(&pool)
        .await
        .expect("EDGE_QUERY");
    let ids: Vec<Uuid> = selected.iter().map(|r| r.0).collect();

    assert!(
        ids.contains(&control),
        "control: a contradicts edge onto a factorless current target is selected; got {selected:?}"
    );
    for (edge, rel) in lineage.iter().zip(["supersedes", "SUPERSEDES"]) {
        assert!(
            !ids.contains(edge),
            "the edge phase must not select the `{rel}` edge {edge}: lineage carries no mass; \
             got {selected:?}"
        );
    }
}
