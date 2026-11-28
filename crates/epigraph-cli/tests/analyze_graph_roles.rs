//! `analyze_graph`'s claim load is role-aware (backlog fe1cdcdf).
//!
//! The report prints a claim's cached `truth_value` as its belief and loads
//! claims belief-ordered. A compound's cache is a fold of its own BBAs, not a
//! belief, so it is loaded with no belief and after every non-compound, while
//! it stays in the claim set the reasoning engine reads for structure.

mod viewer_fixture;

use epigraph_cli::analyze_graph::{belief_label, load_claims};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture as fixture;

async fn claim(pool: &PgPool, agent: Uuid, what: &str, truth: f64) -> Uuid {
    let content = format!("{what} {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, visibility, \
                             owner_group_id) \
         VALUES ($1, sha256($1::bytea), $2, $3, 'public', $4) RETURNING id",
    )
    .bind(&content)
    .bind(truth)
    .bind(agent)
    .bind(fixture::world_group(pool).await)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_compound_is_loaded_with_no_belief_and_after_the_atoms(pool: PgPool) {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'analyze-graph', 'system') \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed agent");
    let compound = claim(&pool, agent, "compound", 0.95).await;
    let leaf = claim(&pool, agent, "leaf", 0.4).await;
    let atom = claim(&pool, agent, "atom", 0.6).await;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(compound)
    .bind(leaf)
    .execute(&pool)
    .await
    .expect("seed decomposes_to");

    let claims = load_claims(&pool).await.expect("load_claims");
    let mine: Vec<(Uuid, Option<f64>)> = claims
        .iter()
        .filter(|c| [compound, leaf, atom].contains(&c.id))
        .map(|c| (c.id, c.belief))
        .collect();
    assert_eq!(
        mine,
        vec![(atom, Some(0.6)), (leaf, Some(0.4)), (compound, None)],
        "non-compounds by truth DESC, then the compound with no belief"
    );
    assert_eq!(belief_label(None), "cmpd");
}
