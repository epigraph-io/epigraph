//! `ClaimRepository::search_by_embedding_since_conn` serves CURRENT claims
//! only, by its own predicate (backlog 7720cb7a).
//!
//! Before this, both query shapes (with and without the paper-DOI filter)
//! relied on `chk_deprecated_no_embedding` — "a retired claim carries no
//! vector" — to keep superseded claims out of `recall_with_context`'s seed
//! pool, with no `is_current` predicate of their own. Every other recall leg
//! (`search_by_embedding_scoped`, the hybrid dense and lexical CTEs,
//! `nearest_by_embedding`) states `is_current` in SQL. A constraint is a
//! write-side invariant; a read that is only correct while some unrelated
//! migration's CHECK stays in place is one `DROP CONSTRAINT` (or one
//! `NOT VALID` re-add during a backfill) away from resurfacing retired claims.
//!
//! The test drops the constraint in its throwaway database to make the state
//! the read must defend against representable, then asserts the retired row
//! is absent from every shape: both scopes, both DOI shapes, both columns.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{ClaimRepository, EmbeddingSeedScope};
use sqlx::PgPool;
use uuid::Uuid;

const DOI: &str = "10.1/is-current-shape";

/// A unit vector at `deg` degrees in the dim-0/dim-1 plane of a `dim`-wide
/// space.
fn vec_angle(dim: usize, deg: f64) -> String {
    let (s, c) = deg.to_radians().sin_cos();
    let mut v: Vec<String> = vec!["0.0".to_string(); dim];
    v[0] = format!("{c:.6}");
    v[1] = format!("{s:.6}");
    format!("[{}]", v.join(","))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind("cd".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    agent_id
}

/// A public level-2 claim with a vector in BOTH columns, asserted by `paper`.
async fn seed_claim(
    pool: &PgPool,
    agent: Uuid,
    paper: Uuid,
    tag: u8,
    deg: f64,
    current: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[0] = tag;
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             properties, embedding, embedding_3072) \
         VALUES ($1, $2, $3, $4, 0.8, $5, '{\"level\": 2}'::jsonb, $6::vector, $7::vector)",
    )
    .bind(id)
    .bind(format!("is_current shape claim {tag}"))
    .bind(hash)
    .bind(agent)
    .bind(current)
    .bind(vec_angle(1536, deg))
    .bind(vec_angle(3072, deg))
    .execute(pool)
    .await
    .expect("insert claim");
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper)
    .bind(id)
    .execute(pool)
    .await
    .expect("seed asserts edge");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_claim_with_a_vector_is_not_a_seed_in_any_shape(pool: PgPool) {
    // Make the state representable: the read must not depend on this CHECK.
    sqlx::query("ALTER TABLE claims DROP CONSTRAINT chk_deprecated_no_embedding")
        .execute(&pool)
        .await
        .expect("drop chk_deprecated_no_embedding in the throwaway database");

    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let paper = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, 'is_current paper')")
        .bind(paper)
        .bind(DOI)
        .execute(&pool)
        .await
        .expect("seed paper");

    // The retired claim is the NEAREST of all, so any shape that admits it
    // returns it first.
    let retired = seed_claim(&pool, agent, paper, 1, 0.0, false).await;
    let current = seed_claim(&pool, agent, paper, 2, 5.0, true).await;

    for dim in [1536_u32, 3072] {
        let q = vec_angle(dim as usize, 0.0);
        for scope in [
            EmbeddingSeedScope::AllClaims,
            EmbeddingSeedScope::Paragraphs,
        ] {
            for doi in [None, Some(DOI)] {
                let mut conn = pool.acquire().await.expect("acquire");
                let got: Vec<Uuid> = ClaimRepository::search_by_embedding_since_conn(
                    &mut conn, &viewer, &q, dim, 10, doi, None, scope,
                )
                .await
                .expect("search_by_embedding_since_conn")
                .into_iter()
                .map(|h| h.claim_id)
                .collect();
                assert!(
                    !got.contains(&retired),
                    "dim {dim}, {scope:?}, doi {doi:?}: a retired (is_current = false) claim \
                     came back as a recall seed; the read relied on chk_deprecated_no_embedding \
                     instead of stating is_current. Got {got:?}"
                );
                assert_eq!(
                    got,
                    vec![current],
                    "dim {dim}, {scope:?}, doi {doi:?}: the current claim must still be served"
                );
            }
        }
    }
}
