//! `reembed --target claims` must never write a 3072-d vector onto a RETIRED
//! (`is_current = false`) claim.
//!
//! # Why this is worth a test of its own
//!
//! Every retirement write path (`ClaimRepository::supersede_act_conn`,
//! `evolve_step_conn`, `deprecate_claim`, `consolidate_act_conn`,
//! `mark_duplicate_act`) nulls BOTH `embedding` and `embedding_3072` in the
//! statement that flips `is_current`, so a retired claim leaves the ANN
//! surface. `reembed` selects rows by `embedding_3072 IS NULL` — which is
//! exactly the shape a retirement leaves behind — so without an `is_current`
//! clause a run re-populates every retired claim it meets. Two costs:
//!
//! 1. Recall at `centroid_dim = 3072`
//!    (`ClaimRepository::search_by_embedding_since`) has no `is_current`
//!    filter, so the retired claim becomes retrievable again.
//! 2. `chk_deprecated_no_embedding` covers `embedding_3072` (migration 144),
//!    so the first retired row in a batch makes the UPDATE raise 23514 and
//!    the whole run aborts.
//!
//! The assertion is therefore on persisted column state, with a CURRENT claim
//! beside the retired one as calibration: an exclusion that selected nothing
//! would pass every negative assertion while breaking the tool.

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::reembed::{run, ReembedConfig, ReembedTarget};
use epigraph_embeddings::{EmbeddingConfig, MockProvider};

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'reembed-retired-test', 'system', \
                 ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// A claim with BOTH vector columns NULL — the state every retirement path
/// leaves behind, and the state `reembed` selects on.
async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, is_current: bool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             embedding, embedding_3072) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, $3, NULL, NULL) \
         RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(is_current)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn has_vector(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT embedding_3072 IS NOT NULL FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read embedding_3072")
}

#[sqlx::test(migrations = "../../migrations")]
async fn reembed_never_writes_a_vector_onto_a_retired_claim(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let live = seed_claim(&pool, agent, "reembed-retired-test live claim", true).await;
    let retired = seed_claim(&pool, agent, "reembed-retired-test retired claim", false).await;

    let summary = run(
        &pool,
        ReembedConfig {
            target: ReembedTarget::Claims,
            batch_size: 10,
            embedding_provider: Arc::new(MockProvider::new(EmbeddingConfig::openai(3072))),
            checkpoint_path: None,
        },
    )
    .await
    .expect("reembed run over a corpus holding a retired claim must succeed");

    // POSITIVE ARM FIRST: the current claim IS re-embedded, so the exclusion
    // is not simply "select nothing".
    assert!(
        has_vector(&pool, live).await,
        "calibration: a current claim must still be re-embedded"
    );
    assert!(
        !has_vector(&pool, retired).await,
        "a retired claim must never get a 3072 vector (recall at 3072 has no is_current filter)"
    );
    assert_eq!(
        summary.rows_written, 1,
        "exactly the one current claim is written; the retired one is never selected"
    );
}
