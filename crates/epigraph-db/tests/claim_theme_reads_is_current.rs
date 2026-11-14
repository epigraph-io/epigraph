//! The diverse-retrieval theme reads serve CURRENT claims only, by their own
//! predicate (backlog 7720cb7a's defect class, on the diverse path).
//!
//! `ClaimThemeRepository::claims_in_themes_at_dim_since` (the diverse
//! candidate pool), `claims_in_theme_exact_at_dim` (the pinned-theme pool) and
//! `nearest_theme_coverage_since` (the coverage guard's probe) ordered by
//! `c.{col} <=> $v` with only `c.{col} IS NOT NULL`, so `diverse=true` recall
//! kept retired claims out only while `chk_deprecated_no_embedding` ("a
//! retired claim carries no vector") held. The flat seed query states
//! `is_current` itself (`claim_search_by_embedding_is_current.rs`); these now
//! do too.
//!
//! The test drops the constraint in its throwaway database so a retired claim
//! WITH a vector is representable, makes it the nearest member of the theme,
//! and asserts no read returns or counts it, at both dimensions.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{ClaimThemeRepository, NeighbourhoodThemeCoverage};
use sqlx::PgPool;
use uuid::Uuid;

fn vec_angle(dim: usize, deg: f64) -> String {
    let (s, c) = deg.to_radians().sin_cos();
    let mut v: Vec<String> = vec!["0.0".to_string(); dim];
    v[0] = format!("{c:.6}");
    v[1] = format!("{s:.6}");
    format!("[{}]", v.join(","))
}

/// A public claim in `theme` with a vector in BOTH columns.
async fn seed_claim(
    pool: &PgPool,
    agent: Uuid,
    theme: Uuid,
    tag: u8,
    deg: f64,
    current: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[0] = tag;
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             theme_id, embedding, embedding_3072) \
         VALUES ($1, $2, $3, $4, 0.8, $5, $6, $7::vector, $8::vector)",
    )
    .bind(id)
    .bind(format!("theme is_current claim {tag}"))
    .bind(hash)
    .bind(agent)
    .bind(current)
    .bind(theme)
    .bind(vec_angle(1536, deg))
    .bind(vec_angle(3072, deg))
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_claim_with_a_vector_is_not_a_diverse_candidate(pool: PgPool) {
    sqlx::query("ALTER TABLE claims DROP CONSTRAINT chk_deprecated_no_embedding")
        .execute(&pool)
        .await
        .expect("drop chk_deprecated_no_embedding in the throwaway database");

    let viewer = fixture::public_viewer(&pool).await;
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent)
        .bind("ce".repeat(32))
        .execute(&pool)
        .await
        .expect("seed agent");
    let theme: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label) VALUES ('is_current theme') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed theme");

    // The retired claim is the NEAREST, so any read that admits it returns it
    // first (or counts it in the probe).
    let retired = seed_claim(&pool, agent, theme, 1, 0.0, false).await;
    let current = seed_claim(&pool, agent, theme, 2, 5.0, true).await;

    for dim in [1536_u32, 3072] {
        let q = vec_angle(dim as usize, 0.0);
        let mut conn = pool.acquire().await.expect("acquire");

        let pooled: Vec<Uuid> = ClaimThemeRepository::claims_in_themes_at_dim_since(
            &mut conn,
            &viewer,
            &[theme],
            &q,
            10,
            dim,
            false,
            None,
        )
        .await
        .expect("claims_in_themes_at_dim_since")
        .into_iter()
        .map(|(id, ..)| id)
        .collect();
        assert_eq!(
            pooled,
            vec![current],
            "claims_in_themes_at_dim_since at {dim}: retired {retired} must not be a candidate"
        );

        let pinned: Vec<Uuid> = ClaimThemeRepository::claims_in_theme_exact_at_dim(
            &mut *conn, &viewer, theme, &q, 10, dim, None, -1.0,
        )
        .await
        .expect("claims_in_theme_exact_at_dim")
        .into_iter()
        .map(|(id, ..)| id)
        .collect();
        assert_eq!(
            pinned,
            vec![current],
            "claims_in_theme_exact_at_dim at {dim}: retired {retired} must not be a candidate"
        );

        let probe = ClaimThemeRepository::nearest_theme_coverage_since(
            &mut conn,
            &viewer,
            &q,
            dim,
            &[theme],
            dim,
            40,
            false,
            None,
        )
        .await
        .expect("nearest_theme_coverage_since");
        assert_eq!(
            probe,
            NeighbourhoodThemeCoverage {
                probed: 1,
                reachable: 1,
            },
            "nearest_theme_coverage_since at {dim}: the retired claim must not be probed"
        );
    }
}
