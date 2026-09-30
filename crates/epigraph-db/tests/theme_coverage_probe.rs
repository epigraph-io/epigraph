//! `ClaimThemeRepository::nearest_theme_coverage_at_dim_since` — the probe the
//! diverse-retrieval coverage guard decides on.
//!
//! The guard is only as good as this count, so each arm pins one way the count
//! could be wrong while still looking plausible:
//!
//! - it counts a claim whose theme has NO centroid at the probed dimension as
//!   themed (diverse mode cannot reach such a theme);
//! - it measures something other than the NEAREST `k` (e.g. joins before
//!   limiting, or ignores the ordering);
//! - it counts rows the viewer cannot see (a tenancy leak into a decision, and
//!   a probe that disagrees with the candidate query it stands in for);
//! - it ignores `paragraph_only`, so the MCP guard would measure a different
//!   candidate space than the one diverse mode then draws from.

use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimThemeRepository, NeighbourhoodThemeCoverage};
use sqlx::PgPool;
use uuid::Uuid;

mod viewer_fixture;
use viewer_fixture as fixture;

const DIM: usize = 1536;

/// `e0 + drift * e_axis`: cosine similarity to `e0` is `1/sqrt(1 + drift²)`,
/// strictly decreasing in `drift`, so the nearest-first order is known.
fn near_e0(axis: usize, drift: f32) -> String {
    let mut v = vec![0.0f32; DIM];
    v[0] = 1.0;
    v[axis] = drift;
    let inner: Vec<String> = v.iter().map(|x| x.to_string()).collect();
    format!("[{}]", inner.join(","))
}

fn query() -> String {
    near_e0(1, 0.0)
}

async fn seed_theme(pool: &PgPool, label: &str, with_centroid: bool) -> Uuid {
    let id: Uuid = sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ($1) RETURNING id")
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("seed theme");
    if with_centroid {
        sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
            .bind(id)
            .bind(query())
            .execute(pool)
            .await
            .expect("set centroid");
    }
    id
}

async fn assign(pool: &PgPool, claim: Uuid, theme: Uuid) {
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .execute(pool)
        .await
        .expect("assign theme");
}

async fn seed_public_at(pool: &PgPool, agent: Uuid, content: &str, drift: f32) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, content).await;
    fixture::set_claim_embedding(pool, id, &near_e0(2, drift)).await;
    id
}

async fn probe(
    pool: &PgPool,
    viewer: &Viewer,
    k: i32,
    paragraph_only: bool,
) -> NeighbourhoodThemeCoverage {
    ClaimThemeRepository::nearest_theme_coverage_at_dim_since(
        pool,
        viewer,
        &query(),
        k,
        1536,
        paragraph_only,
        None,
    )
    .await
    .expect("coverage probe")
}

/// Themed means "in a theme diverse mode can select at this dimension": a
/// theme with no 1536-d centroid is invisible to the 1536-d theme lookup, so
/// its members are counted as unthemed.
#[sqlx::test(migrations = "../../migrations")]
async fn counts_only_members_of_themes_with_a_centroid_at_the_dim(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "cov-count").await;
    let with_centroid = seed_theme(&pool, "has-centroid", true).await;
    let no_centroid = seed_theme(&pool, "no-centroid", false).await;

    for i in 0..3 {
        let c = seed_public_at(&pool, agent, &format!("themed-{i}"), 0.01 * i as f32).await;
        assign(&pool, c, with_centroid).await;
    }
    let orphan = seed_public_at(&pool, agent, "centroidless-theme-member", 0.05).await;
    assign(&pool, orphan, no_centroid).await;
    for i in 0..2 {
        seed_public_at(
            &pool,
            agent,
            &format!("unthemed-{i}"),
            0.1 + 0.01 * i as f32,
        )
        .await;
    }

    let viewer = fixture::public_viewer(&pool).await;
    let got = probe(&pool, &viewer, 10, false).await;
    assert_eq!(
        got,
        NeighbourhoodThemeCoverage {
            probed: 6,
            themed: 3
        },
        "6 visible embedded claims; only the 3 in the centroid-bearing theme are reachable \
         by diverse mode (themed=4 means a centroid-less theme was counted)"
    );
}

/// The probe measures the NEAREST `k`, not any `k`: the three nearest claims
/// are themed and everything further out is not, so `k=3` must report full
/// coverage and a wide `k` must not.
#[sqlx::test(migrations = "../../migrations")]
async fn measures_the_nearest_k_only(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "cov-nearest").await;
    let theme = seed_theme(&pool, "near", true).await;
    for i in 0..3 {
        let c = seed_public_at(&pool, agent, &format!("near-{i}"), 0.01 * i as f32).await;
        assign(&pool, c, theme).await;
    }
    for i in 0..7 {
        seed_public_at(&pool, agent, &format!("far-{i}"), 1.0 + 0.1 * i as f32).await;
    }

    let viewer = fixture::public_viewer(&pool).await;
    assert_eq!(
        probe(&pool, &viewer, 3, false).await,
        NeighbourhoodThemeCoverage {
            probed: 3,
            themed: 3
        },
        "the 3 nearest claims are exactly the themed ones"
    );
    assert_eq!(
        probe(&pool, &viewer, 10, false).await,
        NeighbourhoodThemeCoverage {
            probed: 10,
            themed: 3
        },
        "widening k to the whole corpus brings in the 7 unthemed far claims"
    );
}

/// The probe counts only rows the viewer can see. A group-private themed claim
/// sitting nearest the query must count for its owner and not for a stranger —
/// both directions asserted, so a predicate that refuses everyone fails too.
#[sqlx::test(migrations = "../../migrations")]
async fn counts_only_rows_the_viewer_can_see(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "cov-owner").await;
    let theme = seed_theme(&pool, "private-near", true).await;

    let private = fixture::seed_group_claim(&pool, owner, group, "private themed").await;
    fixture::set_claim_embedding(&pool, private, &near_e0(2, 0.0)).await;
    assign(&pool, private, theme).await;
    for i in 0..2 {
        seed_public_at(
            &pool,
            owner,
            &format!("public-unthemed-{i}"),
            0.1 + 0.01 * i as f32,
        )
        .await;
    }

    let stranger = fixture::public_viewer(&pool).await;
    let owner_viewer = Viewer::resolve(&pool, owner).await.expect("resolve owner");

    assert_eq!(
        probe(&pool, &stranger, 10, false).await,
        NeighbourhoodThemeCoverage {
            probed: 2,
            themed: 0
        },
        "the stranger must not see (or count) the group-private themed claim"
    );
    assert_eq!(
        probe(&pool, &owner_viewer, 10, false).await,
        NeighbourhoodThemeCoverage {
            probed: 3,
            themed: 1
        },
        "the owner sees all three, including the private themed one"
    );
}

/// `paragraph_only` must restrict the probe exactly as it restricts the
/// diverse candidate query (level = 2), or the MCP guard measures a candidate
/// space diverse mode never draws from.
#[sqlx::test(migrations = "../../migrations")]
async fn paragraph_only_restricts_the_probe_to_level_2(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "cov-level").await;
    let theme = seed_theme(&pool, "lvl", true).await;

    // Two themed NON-paragraph claims nearest the query, one unthemed paragraph.
    for i in 0..2 {
        let c = seed_public_at(&pool, agent, &format!("atom-{i}"), 0.01 * i as f32).await;
        assign(&pool, c, theme).await;
    }
    let para = seed_public_at(&pool, agent, "paragraph", 0.1).await;
    sqlx::query("UPDATE claims SET properties = jsonb_build_object('level', 2) WHERE id = $1")
        .bind(para)
        .execute(&pool)
        .await
        .expect("mark paragraph");

    let viewer = fixture::public_viewer(&pool).await;
    assert_eq!(
        probe(&pool, &viewer, 10, true).await,
        NeighbourhoodThemeCoverage {
            probed: 1,
            themed: 0
        },
        "paragraph_only must see only the level-2 claim"
    );
    assert_eq!(
        probe(&pool, &viewer, 10, false).await,
        NeighbourhoodThemeCoverage {
            probed: 3,
            themed: 2
        },
        "without paragraph_only all three claims are probed"
    );
}
