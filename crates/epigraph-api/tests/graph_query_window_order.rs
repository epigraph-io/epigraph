//! `POST /api/v1/graph/query` takes its LIMIT window newest-first, and the
//! window is total (backlog `2aacb390`).
//!
//! `routes/graph_query.rs::execute_graph_query` selects node ids at two sites:
//! the plain `SELECT id FROM <table> <where> LIMIT <n>` (no edge in the MATCH)
//! and the anchor of the recursive CTE (an edge in the MATCH). Both used to
//! carry no `ORDER BY`, so which rows filled the window was whatever the plan
//! yielded — heap order on a seq scan, which is roughly oldest-first and moves
//! after VACUUM or an UPDATE. That is nondeterministic for every caller, and it
//! is what made `read_path_authz_test` lose its freshly-seeded claim once the
//! shared database grew past the window.
//!
//! # Why the ids are chosen, not random
//!
//! Each probe row's id is fixed in its FIRST byte so that the OLDEST row has
//! the MIDDLE id. A two-row window is then `{newest, middle}` under
//! `created_at DESC, id` and something else under every plausible wrong order:
//!
//! | order                 | window              |
//! |-----------------------|---------------------|
//! | heap (no `ORDER BY`)  | `{oldest, middle}`  |
//! | `id`                  | `{middle, oldest}`  |
//! | `id DESC`             | `{newest, oldest}`  |
//! | `created_at` (ASC)    | `{oldest, middle}`  |
//! | `created_at DESC, id` | `{newest, middle}`  |
//!
//! Rows are inserted oldest-first, in ONE statement each with `created_at` and
//! `properties` set by the INSERT itself — an UPDATE after the fact would
//! append a new heap tuple and reorder the seq scan, which would make the RED
//! on unmodified code depend on the fixture rather than on the route.
//!
//! The `probe` property scopes every query to this test's rows; `properties`
//! has no index, so the match is a seq scan in insertion order.

mod viewer_fixture;

use std::collections::BTreeSet;

use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::graph_query::{execute_graph_query, GraphQueryRequest};
use epigraph_api::state::{ApiConfig, AppState};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{public_viewer, seed_agent_with_group, seed_edge, world_group};

/// An id whose first byte is `lead` and whose other fifteen are random, so the
/// relative `id` order of the seeded rows is fixed without colliding across
/// runs.
fn id_led_by(lead: u8) -> Uuid {
    let mut bytes = *Uuid::new_v4().as_bytes();
    bytes[0] = lead;
    Uuid::from_bytes(bytes)
}

fn ts(rfc3339: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(rfc3339)
        .expect("valid RFC 3339 literal")
        .with_timezone(&Utc)
}

/// One public claim carrying `properties.probe`, with an explicit `created_at`,
/// written by a single INSERT. Same column set as `viewer_fixture::seed_claim`.
async fn seed_probe_claim_at(
    pool: &PgPool,
    id: Uuid,
    agent: Uuid,
    world: Uuid,
    probe: &str,
    created_at: DateTime<Utc>,
) {
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, properties, created_at) \
         VALUES ($1, $2, sha256(convert_to($2, 'UTF8')), 0.8, $3, true, 'public', $4, \
                 jsonb_build_object('probe', $5::text), $6)",
    )
    .bind(id)
    .bind(format!("graph-query window probe {probe} row {id}"))
    .bind(agent)
    .bind(world)
    .bind(probe)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed probe claim");
}

/// CALIBRATION: the seeded `created_at` values are the ones the assertion
/// reasons about. No trigger on `claims` rewrites `created_at` today; this arm
/// fails loudly if one ever does, instead of letting the window assertion pass
/// or fail for a reason it does not name.
async fn assert_created_at(pool: &PgPool, id: Uuid, expected: DateTime<Utc>) {
    let got: DateTime<Utc> = sqlx::query_scalar("SELECT created_at FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read back created_at");
    assert_eq!(
        got, expected,
        "fixture calibration: created_at of {id} was rewritten"
    );
}

async fn run(pool: &PgPool, query: String) -> BTreeSet<Uuid> {
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    let viewer = public_viewer(pool).await;
    let Json(out) = execute_graph_query(
        ViewerExtractor(viewer),
        State(state),
        Json(GraphQueryRequest {
            query,
            agent_id: None,
        }),
    )
    .await
    .expect("graph query succeeds");
    out.nodes.into_iter().map(|n| n.id).collect()
}

struct Probes {
    probe: String,
    oldest: Uuid,
    middle: Uuid,
    newest: Uuid,
}

/// Three public probe claims, inserted OLDEST-FIRST, with the oldest holding
/// the middle id (see the module doc's table).
async fn seed_three(pool: &PgPool) -> Probes {
    let (agent, _group) = seed_agent_with_group(pool, "gq-window").await;
    let world = world_group(pool).await;
    let probe = Uuid::new_v4().to_string();

    let middle = id_led_by(0x10);
    let oldest = id_led_by(0x50);
    let newest = id_led_by(0x90);

    let (t_oldest, t_middle, t_newest) = (
        ts("2020-01-01T00:00:00Z"),
        ts("2021-01-01T00:00:00Z"),
        ts("2022-01-01T00:00:00Z"),
    );
    seed_probe_claim_at(pool, oldest, agent, world, &probe, t_oldest).await;
    seed_probe_claim_at(pool, middle, agent, world, &probe, t_middle).await;
    seed_probe_claim_at(pool, newest, agent, world, &probe, t_newest).await;

    assert_created_at(pool, oldest, t_oldest).await;
    assert_created_at(pool, middle, t_middle).await;
    assert_created_at(pool, newest, t_newest).await;

    Probes {
        probe,
        oldest,
        middle,
        newest,
    }
}

/// The plain (no-edge) site: `SELECT id FROM claims <where> ... LIMIT 2`.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_query_limit_window_is_newest_first(pool: PgPool) {
    let p = seed_three(&pool).await;

    // CALIBRATION: without a LIMIT that bites, all three probe rows come back,
    // so the window assertion below is about WHICH rows, not whether the probe
    // predicate or the viewer filter matches at all.
    let all = run(
        &pool,
        format!("MATCH (n:claim) WHERE n.probe = '{}' RETURN *", p.probe),
    )
    .await;
    assert_eq!(
        all,
        BTreeSet::from([p.oldest, p.middle, p.newest]),
        "calibration: the probe query must match all three seeded claims"
    );

    let got = run(
        &pool,
        format!(
            "MATCH (n:claim) WHERE n.probe = '{}' RETURN * LIMIT 2",
            p.probe
        ),
    )
    .await;
    assert!(
        !got.contains(&p.oldest),
        "LIMIT window must be newest-first (ORDER BY created_at DESC, id); got the oldest \
         row {} in {got:?}, i.e. heap order with no ORDER BY (backlog 2aacb390)",
        p.oldest
    );
    assert_eq!(
        got,
        BTreeSet::from([p.newest, p.middle]),
        "LIMIT 2 window must be exactly {{newest, middle}} under ORDER BY created_at DESC, id"
    );
}

/// The traversal site: the recursive CTE's anchor
/// `(SELECT id, 0 FROM claims <where> ... LIMIT 2)`. Each probe claim has its
/// own unprobed public `supports` target; the default hop range is 1..=1, so
/// the response holds exactly the targets of the anchors the window kept.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_query_traversal_anchor_window_is_newest_first(pool: PgPool) {
    let p = seed_three(&pool).await;
    let (target_agent, _g) = seed_agent_with_group(&pool, "gq-window-targets").await;

    let t_old = viewer_fixture::seed_public_claim(&pool, target_agent, "gq window: t_old").await;
    let t_mid = viewer_fixture::seed_public_claim(&pool, target_agent, "gq window: t_mid").await;
    let t_new = viewer_fixture::seed_public_claim(&pool, target_agent, "gq window: t_new").await;
    seed_edge(&pool, p.oldest, t_old).await;
    seed_edge(&pool, p.middle, t_mid).await;
    seed_edge(&pool, p.newest, t_new).await;

    // CALIBRATION: with a window that holds every anchor, every target is
    // reached — so a missing target below is the window, not the traversal.
    let all = run(
        &pool,
        format!(
            "MATCH (n:claim)-[:supports]->(m:claim) WHERE n.probe = '{}' RETURN *",
            p.probe
        ),
    )
    .await;
    assert_eq!(
        all,
        BTreeSet::from([t_old, t_mid, t_new]),
        "calibration: an unbitten window must reach all three targets"
    );

    let got = run(
        &pool,
        format!(
            "MATCH (n:claim)-[:supports]->(m:claim) WHERE n.probe = '{}' RETURN * LIMIT 2",
            p.probe
        ),
    )
    .await;
    assert!(
        !got.contains(&t_old),
        "traversal anchor window must be newest-first (ORDER BY created_at DESC, id); got \
         t_old {t_old} in {got:?}, i.e. the anchor kept the oldest probe claim (backlog 2aacb390)"
    );
    assert_eq!(
        got,
        BTreeSet::from([t_new, t_mid]),
        "LIMIT 2 anchor window must reach exactly the newest and middle anchors' targets"
    );
}

/// Ties on `created_at` are broken by `id` ascending, so the window is a TOTAL
/// order. The higher id is inserted first, so heap order returns it.
///
/// This arm pins the tie-breaker's direction; it is not counted as a mutation
/// kill for dropping `, id`, because a sort over equal keys may still return
/// the lower id by chance.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_query_limit_window_breaks_created_at_ties_by_id(pool: PgPool) {
    let (agent, _group) = seed_agent_with_group(&pool, "gq-window-tie").await;
    let world = world_group(&pool).await;
    let probe = Uuid::new_v4().to_string();
    let at = ts("2023-06-01T00:00:00Z");

    let high = id_led_by(0xC0);
    let low = id_led_by(0x20);
    seed_probe_claim_at(&pool, high, agent, world, &probe, at).await;
    seed_probe_claim_at(&pool, low, agent, world, &probe, at).await;
    assert_created_at(&pool, high, at).await;
    assert_created_at(&pool, low, at).await;

    let got = run(
        &pool,
        format!("MATCH (n:claim) WHERE n.probe = '{probe}' RETURN * LIMIT 1"),
    )
    .await;
    assert_eq!(
        got,
        BTreeSet::from([low]),
        "equal created_at must fall back to id ascending (ORDER BY created_at DESC, id)"
    );
}

/// The ORDER BY is spliced into the SQL for every allowlisted node table, not
/// only `claims`: `evidence`, `agents` and `reasoning_traces` get the same
/// `ORDER BY created_at DESC, id`. Postgres resolves the column when it plans
/// the statement, so an empty table is enough. A later migration that drops
/// or renames `created_at` on one of them turns that label into a 500 here
/// instead of in production.
#[sqlx::test(migrations = "../../migrations")]
async fn graph_query_window_order_plans_for_every_node_table(pool: PgPool) {
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    for label in ["claim", "evidence", "agent", "trace"] {
        let viewer = public_viewer(&pool).await;
        let res = execute_graph_query(
            ViewerExtractor(viewer),
            State(state.clone()),
            Json(GraphQueryRequest {
                query: format!("MATCH (n:{label}) RETURN * LIMIT 1"),
                agent_id: None,
            }),
        )
        .await;
        assert!(
            res.is_ok(),
            "MATCH (n:{label}) with the ordered LIMIT window must execute; got {:?}",
            res.err()
        );
    }
}
