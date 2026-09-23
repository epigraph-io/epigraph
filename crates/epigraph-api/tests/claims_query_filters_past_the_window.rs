//! `GET /api/v1/claims` finds and counts matches however old they are.
//!
//! Until backlog `2265a67b` was fixed, any filter or non-default sort sent the
//! handler down a "slow path". That path fetched `ClaimRepository::list(10_000,
//! 0)`, the newest 10,000 rows, then filtered, sorted and counted them in
//! memory. Four observable failures followed, each with HTTP 200 and no flag:
//!
//! * a filter matching only claims older than that window returned nothing;
//! * `total` was the number of matches inside the window, never above 10,000;
//! * `sort_by=truth_value` ordered only the newest 10,000 rows;
//! * a page past the window's matches was empty.
//!
//! This file seeds 10,001 filler claims newer than two old ones, which is the
//! smallest corpus that reproduces the window. The filler goes in with one
//! `INSERT … SELECT generate_series` and takes about a second.
//!
//! The handler is called directly, as in `claims_query_scoped_read.rs`, because
//! `spawn_app` builds its `AppState` without the `ScopedPool` that `read_as`
//! requires.

mod viewer_fixture;

use axum::extract::{Query, State};
use chrono::{Duration, Utc};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::claims_query::{list_claims_query, ClaimListResponse, ClaimQueryParams};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    scoped_pool, seed_agent_with_group, seed_evidence, seed_reasoning_trace, world_group,
};

/// One more than the old cap, so the window is full of filler and nothing else.
const FILLER: i64 = 10_001;

fn base_params() -> ClaimQueryParams {
    ClaimQueryParams {
        limit: None,
        offset: None,
        truth_min: None,
        truth_max: None,
        agent_id: None,
        exclude_agent_id: None,
        is_current: None,
        created_after: None,
        created_before: None,
        sort_by: None,
        sort_order: None,
        content_contains: None,
        methodology: None,
        evidence_type: None,
    }
}

async fn list(pool: &PgPool, agent: Uuid, params: ClaimQueryParams) -> ClaimListResponse {
    let state = AppState::with_scoped_pool(scoped_pool(pool).await, ApiConfig::default());
    let viewer = Viewer::resolve(pool, agent).await.expect("resolve");
    list_claims_query(ViewerExtractor(viewer), State(state), Query(params))
        .await
        .expect("the listing must serve")
        .0
}

fn ids(r: &ClaimListResponse) -> Vec<Uuid> {
    r.claims.iter().map(|c| c.id).collect()
}

/// A public claim with explicit truth, currency and age.
async fn seed_old(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    truth: f64,
    is_current: bool,
    age_days: i64,
) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0, 16))
        .take(32)
        .collect();
    let at = Utc::now() - Duration::days(age_days);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'public', $7, $8, $8)",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(truth)
    .bind(agent)
    .bind(is_current)
    .bind(world_group(pool).await)
    .bind(at)
    .execute(pool)
    .await
    .expect("seed old claim");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn filters_sorts_and_totals_reach_past_the_newest_ten_thousand_rows(pool: PgPool) {
    let (old_agent, _) = seed_agent_with_group(&pool, "cq-window-old").await;
    let (filler_agent, _) = seed_agent_with_group(&pool, "cq-window-filler").await;

    // Two claims by `old_agent`, a month old. `old_live` holds the global
    // minimum truth value and `old_retired` the global maximum, so a sort over
    // the whole corpus puts them first; a sort over the newest 10,000 cannot
    // see them at all.
    let old_live = seed_old(&pool, old_agent, "old live claim", 0.05, true, 30).await;
    seed_reasoning_trace(&pool, old_live, "deductive").await;
    let old_retired = seed_old(&pool, old_agent, "old retired claim", 0.95, false, 31).await;
    seed_evidence(&pool, old_retired, "document").await;

    // 10,001 newer public claims by another agent, all truth 0.5, all current,
    // no trace and no evidence: they match none of the filters below except
    // `exclude_agent_id`.
    sqlx::query(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, created_at, updated_at) \
         SELECT 'window filler ' || g, \
                decode(md5('a' || g::text) || md5('b' || g::text), 'hex'), \
                0.5, $1, true, 'public', $2, \
                now() - make_interval(secs => g), now() - make_interval(secs => g) \
         FROM generate_series(1, $3) AS g",
    )
    .bind(filler_agent)
    .bind(world_group(&pool).await)
    .bind(FILLER)
    .execute(&pool)
    .await
    .expect("seed filler");

    let viewer = Viewer::resolve(&pool, old_agent).await.expect("resolve");

    // CALIBRATION: the old handler's working set really does exclude both old
    // claims. Without this, every assertion below could pass on a corpus the
    // window never cut.
    let window = ClaimRepository::list(&pool, &viewer, 10_000, 0, None)
        .await
        .expect("the old working-set read");
    let window_ids: Vec<Uuid> = window.iter().map(|c| c.id.as_uuid()).collect();
    assert_eq!(window_ids.len(), 10_000);
    assert!(
        !window_ids.contains(&old_live) && !window_ids.contains(&old_retired),
        "CALIBRATION: both old claims must fall outside the newest 10,000 rows"
    );

    // ---- An agent filter that matches only old claims ----
    let out = list(
        &pool,
        old_agent,
        ClaimQueryParams {
            agent_id: Some(old_agent),
            ..base_params()
        },
    )
    .await;
    assert_eq!(
        ids(&out),
        vec![old_live, old_retired],
        "?agent_id= must return the agent's claims however old, newest first"
    );
    assert_eq!(out.total, 2);

    // ---- ?is_current=false with no content_contains to narrow the scan ----
    let out = list(
        &pool,
        old_agent,
        ClaimQueryParams {
            is_current: Some(false),
            ..base_params()
        },
    )
    .await;
    assert_eq!(ids(&out), vec![old_retired]);
    assert_eq!(out.total, 1);

    // ---- A date filter that selects only rows older than the window ----
    let out = list(
        &pool,
        old_agent,
        ClaimQueryParams {
            created_before: Some(Utc::now() - Duration::days(7)),
            ..base_params()
        },
    )
    .await;
    assert_eq!(ids(&out), vec![old_live, old_retired]);
    assert_eq!(out.total, 2);

    // ---- Truth range, methodology, evidence type ----
    let out = list(
        &pool,
        old_agent,
        ClaimQueryParams {
            truth_min: Some(0.9),
            ..base_params()
        },
    )
    .await;
    assert_eq!((ids(&out), out.total), (vec![old_retired], 1));

    let out = list(
        &pool,
        old_agent,
        ClaimQueryParams {
            methodology: Some("deductive".to_string()),
            ..base_params()
        },
    )
    .await;
    assert_eq!((ids(&out), out.total), (vec![old_live], 1));

    let out = list(
        &pool,
        old_agent,
        ClaimQueryParams {
            evidence_type: Some("document".to_string()),
            ..base_params()
        },
    )
    .await;
    assert_eq!((ids(&out), out.total), (vec![old_retired], 1));

    // ---- sort_by=truth_value orders the whole corpus, not the window ----
    let total_corpus = (FILLER + 2) as usize;
    let out = list(
        &pool,
        old_agent,
        ClaimQueryParams {
            sort_by: Some("truth_value".to_string()),
            sort_order: Some("asc".to_string()),
            limit: Some(1),
            ..base_params()
        },
    )
    .await;
    assert_eq!(
        ids(&out),
        vec![old_live],
        "ascending truth_value must start at the global minimum"
    );
    assert_eq!(out.total, total_corpus);

    let out = list(
        &pool,
        old_agent,
        ClaimQueryParams {
            sort_by: Some("truth_value".to_string()),
            sort_order: Some("desc".to_string()),
            limit: Some(1),
            ..base_params()
        },
    )
    .await;
    assert_eq!(ids(&out), vec![old_retired]);

    // ---- total above 10,000, and a page past the old window ----
    let out = list(
        &pool,
        old_agent,
        ClaimQueryParams {
            exclude_agent_id: Some(old_agent),
            limit: Some(20),
            ..base_params()
        },
    )
    .await;
    assert_eq!(
        out.total, FILLER as usize,
        "total must count every match, not the matches inside a 10,000-row window"
    );
    assert_eq!(out.claims.len(), 20);

    let out = list(
        &pool,
        old_agent,
        ClaimQueryParams {
            exclude_agent_id: Some(old_agent),
            limit: Some(20),
            offset: Some(10_000),
            ..base_params()
        },
    )
    .await;
    assert_eq!(
        out.claims.len(),
        1,
        "offset 10,000 of 10,001 matches must return the last one, not an empty page"
    );
    assert!(out.claims[0].content.starts_with("window filler "));
}
