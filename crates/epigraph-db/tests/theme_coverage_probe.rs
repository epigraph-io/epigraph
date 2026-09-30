//! `ClaimThemeRepository::nearest_theme_coverage_since` — the probe the
//! diverse-retrieval coverage guard decides on.
//!
//! The guard is only as good as this count, so each arm pins one way the count
//! could be wrong while still looking plausible:
//!
//! - it counts a member of a theme OUTSIDE the shortlist (or any theme at all)
//!   as reachable, although diverse mode draws only from the shortlist;
//! - it counts a claim with no embedding at the reachability dimension, which
//!   the diverse candidate query cannot return;
//! - it measures something other than the NEAREST `k` (e.g. joins before
//!   limiting, or ignores the ordering);
//! - it counts rows the viewer cannot see (a tenancy leak into a decision, and
//!   a probe that disagrees with the candidate query it stands in for);
//! - it ignores `paragraph_only`, so the MCP guard would measure a different
//!   candidate space than the one diverse mode then draws from;
//! - it ignores `since`, so a windowed MCP request is judged on claims the
//!   window excludes.

use chrono::{Duration, Utc};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ClaimThemeRepository, NeighbourhoodThemeCoverage};
use sqlx::PgPool;
use uuid::Uuid;

mod viewer_fixture;
use viewer_fixture as fixture;

const DIM: usize = 1536;
const DIM_LARGE: usize = 3072;

/// `e0 + drift * e_axis` at `dim`: cosine similarity to `e0` is
/// `1/sqrt(1 + drift²)`, strictly decreasing in `drift`, so the nearest-first
/// order is known.
fn near_e0_at(dim: usize, axis: usize, drift: f32) -> String {
    let mut v = vec![0.0f32; dim];
    v[0] = 1.0;
    v[axis] = drift;
    let inner: Vec<String> = v.iter().map(|x| x.to_string()).collect();
    format!("[{}]", inner.join(","))
}

fn near_e0(axis: usize, drift: f32) -> String {
    near_e0_at(DIM, axis, drift)
}

fn query() -> String {
    near_e0(1, 0.0)
}

async fn seed_theme(pool: &PgPool, label: &str) -> Uuid {
    let id: Uuid = sqlx::query_scalar("INSERT INTO claim_themes (label) VALUES ($1) RETURNING id")
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("seed theme");
    sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
        .bind(id)
        .bind(query())
        .execute(pool)
        .await
        .expect("set centroid");
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

async fn probe_full(
    pool: &PgPool,
    viewer: &Viewer,
    shortlist: &[Uuid],
    reachable_dim: u32,
    k: i32,
    paragraph_only: bool,
    since: Option<chrono::DateTime<Utc>>,
) -> NeighbourhoodThemeCoverage {
    ClaimThemeRepository::nearest_theme_coverage_since(
        pool,
        viewer,
        &query(),
        1536,
        shortlist,
        reachable_dim,
        k,
        paragraph_only,
        since,
    )
    .await
    .expect("coverage probe")
}

async fn probe(
    pool: &PgPool,
    viewer: &Viewer,
    shortlist: &[Uuid],
    k: i32,
    paragraph_only: bool,
) -> NeighbourhoodThemeCoverage {
    probe_full(pool, viewer, shortlist, 1536, k, paragraph_only, None).await
}

/// Reachable means "a member of a SHORTLISTED theme": the diverse candidate
/// query is `theme_id = ANY(shortlist)`, so a member of a theme that exists
/// but was not shortlisted is as invisible to diverse mode as an unthemed
/// claim.
#[sqlx::test(migrations = "../../migrations")]
async fn counts_only_members_of_the_shortlisted_themes(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "cov-count").await;
    let shortlisted = seed_theme(&pool, "shortlisted").await;
    let other = seed_theme(&pool, "not-shortlisted").await;

    for i in 0..3 {
        let c = seed_public_at(&pool, agent, &format!("in-shortlist-{i}"), 0.01 * i as f32).await;
        assign(&pool, c, shortlisted).await;
    }
    for i in 0..2 {
        let c = seed_public_at(
            &pool,
            agent,
            &format!("other-theme-{i}"),
            0.05 + 0.01 * i as f32,
        )
        .await;
        assign(&pool, c, other).await;
    }
    seed_public_at(&pool, agent, "unthemed", 0.1).await;

    let viewer = fixture::public_viewer(&pool).await;
    assert_eq!(
        probe(&pool, &viewer, &[shortlisted], 10, false).await,
        NeighbourhoodThemeCoverage {
            probed: 6,
            reachable: 3
        },
        "6 visible embedded claims; only the 3 in the shortlisted theme are reachable \
         (reachable=5 means membership in ANY theme was counted)"
    );
    assert_eq!(
        probe(&pool, &viewer, &[shortlisted, other], 10, false).await,
        NeighbourhoodThemeCoverage {
            probed: 6,
            reachable: 5
        },
        "shortlisting both themes makes both themes' members reachable"
    );
    assert_eq!(
        probe(&pool, &viewer, &[], 10, false).await,
        NeighbourhoodThemeCoverage {
            probed: 6,
            reachable: 0
        },
        "an empty shortlist reaches nothing"
    );
}

/// The neighbourhood is ordered by one dimension and reachability checked at
/// another (the REST 3072 path): a shortlisted member with no 3072-d
/// embedding cannot be returned by the 3072-d candidate query, so it is
/// probed but not reachable; a claim with no 1536-d embedding is not in the
/// neighbourhood at all.
#[sqlx::test(migrations = "../../migrations")]
async fn reachability_requires_an_embedding_at_the_reachable_dim(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "cov-dim").await;
    let theme = seed_theme(&pool, "dims").await;

    let set_3072 = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query("UPDATE claims SET embedding_3072 = $2::vector WHERE id = $1")
                .bind(id)
                .bind(near_e0_at(DIM_LARGE, 2, 0.0))
                .execute(&pool)
                .await
                .expect("set 3072 embedding");
        }
    };

    for i in 0..2 {
        let c = seed_public_at(&pool, agent, &format!("both-dims-{i}"), 0.01 * i as f32).await;
        assign(&pool, c, theme).await;
        set_3072(c).await;
    }
    let only_1536 = seed_public_at(&pool, agent, "1536-only", 0.05).await;
    assign(&pool, only_1536, theme).await;
    let only_3072 = fixture::seed_public_claim(&pool, agent, "3072-only").await;
    assign(&pool, only_3072, theme).await;
    set_3072(only_3072).await;

    let viewer = fixture::public_viewer(&pool).await;
    assert_eq!(
        probe_full(&pool, &viewer, &[theme], 3072, 10, false, None).await,
        NeighbourhoodThemeCoverage {
            probed: 3,
            reachable: 2
        },
        "3 claims have a 1536-d embedding (the neighbourhood); of those only the 2 that \
         also have a 3072-d embedding are reachable at 3072"
    );
    assert_eq!(
        probe_full(&pool, &viewer, &[theme], 1536, 10, false, None).await,
        NeighbourhoodThemeCoverage {
            probed: 3,
            reachable: 3
        },
        "at 1536 every probed row already has the reachability embedding"
    );
}

/// The probe measures the NEAREST `k`, not any `k`: the three nearest claims
/// are themed and everything further out is not, so `k=3` must report full
/// coverage and a wide `k` must not.
#[sqlx::test(migrations = "../../migrations")]
async fn measures_the_nearest_k_only(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "cov-nearest").await;
    let theme = seed_theme(&pool, "near").await;
    for i in 0..3 {
        let c = seed_public_at(&pool, agent, &format!("near-{i}"), 0.01 * i as f32).await;
        assign(&pool, c, theme).await;
    }
    for i in 0..7 {
        seed_public_at(&pool, agent, &format!("far-{i}"), 1.0 + 0.1 * i as f32).await;
    }

    let viewer = fixture::public_viewer(&pool).await;
    assert_eq!(
        probe(&pool, &viewer, &[theme], 3, false).await,
        NeighbourhoodThemeCoverage {
            probed: 3,
            reachable: 3
        },
        "the 3 nearest claims are exactly the themed ones"
    );
    assert_eq!(
        probe(&pool, &viewer, &[theme], 10, false).await,
        NeighbourhoodThemeCoverage {
            probed: 10,
            reachable: 3
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
    let theme = seed_theme(&pool, "private-near").await;

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
        probe(&pool, &stranger, &[theme], 10, false).await,
        NeighbourhoodThemeCoverage {
            probed: 2,
            reachable: 0
        },
        "the stranger must not see (or count) the group-private themed claim"
    );
    assert_eq!(
        probe(&pool, &owner_viewer, &[theme], 10, false).await,
        NeighbourhoodThemeCoverage {
            probed: 3,
            reachable: 1
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
    let theme = seed_theme(&pool, "lvl").await;

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
        probe(&pool, &viewer, &[theme], 10, true).await,
        NeighbourhoodThemeCoverage {
            probed: 1,
            reachable: 0
        },
        "paragraph_only must see only the level-2 claim"
    );
    assert_eq!(
        probe(&pool, &viewer, &[theme], 10, false).await,
        NeighbourhoodThemeCoverage {
            probed: 3,
            reachable: 2
        },
        "without paragraph_only all three claims are probed"
    );
}

/// `since` must window the probe exactly as it windows the diverse candidate
/// query. Old themed claims sit nearest the query and newer unthemed ones
/// further out: un-windowed, the nearest 4 are fully themed; windowed, the old
/// claims drop out and the neighbourhood is the unthemed newer ones — so a
/// probe that ignores `since` passes a windowed request whose in-window
/// neighbourhood diverse mode cannot see.
#[sqlx::test(migrations = "../../migrations")]
async fn since_windows_the_probe(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "cov-since").await;
    let theme = seed_theme(&pool, "old-themed").await;
    let now = Utc::now();
    let old = now - Duration::days(30);
    let cut = now - Duration::days(7);

    let set_created = |id: Uuid, at: chrono::DateTime<Utc>| {
        let pool = pool.clone();
        async move {
            sqlx::query("UPDATE claims SET created_at = $2 WHERE id = $1")
                .bind(id)
                .bind(at)
                .execute(&pool)
                .await
                .expect("set created_at");
        }
    };

    for i in 0..4 {
        let c = seed_public_at(&pool, agent, &format!("old-themed-{i}"), 0.01 * i as f32).await;
        assign(&pool, c, theme).await;
        set_created(c, old).await;
    }
    for i in 0..3 {
        let c = seed_public_at(
            &pool,
            agent,
            &format!("new-unthemed-{i}"),
            0.5 + 0.01 * i as f32,
        )
        .await;
        set_created(c, now).await;
    }

    let viewer = fixture::public_viewer(&pool).await;
    assert_eq!(
        probe_full(&pool, &viewer, &[theme], 1536, 4, false, None).await,
        NeighbourhoodThemeCoverage {
            probed: 4,
            reachable: 4
        },
        "un-windowed, the 4 nearest are the old themed claims"
    );
    assert_eq!(
        probe_full(&pool, &viewer, &[theme], 1536, 4, false, Some(cut)).await,
        NeighbourhoodThemeCoverage {
            probed: 3,
            reachable: 0
        },
        "windowed, only the 3 newer unthemed claims are in the candidate space"
    );
}
