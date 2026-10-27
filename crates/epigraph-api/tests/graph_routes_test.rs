#![cfg(feature = "db")]
//! # Why the cluster arms here take an injected `pool`
//!
//! The four community-graph arms assert **whole-table** properties: "no runs
//! exist anywhere", "the latest run has exactly 2 clusters / 1 cluster edge",
//! "this cluster expands to exactly 5 nodes", and "an unknown cluster id is
//! 404". The routes answer from the LATEST run, so those counts are global by
//! design and cannot be narrowed to self-created rows without deleting the
//! run-selection logic from the test.
//!
//! They used to manufacture that global precondition by TRUNCATING
//! `graph_cluster_runs`, `cluster_edges`, `claim_cluster_membership` and
//! `graph_clusters` on a shared database — which made them destructive to every
//! sibling binary and dependent on the order they ran in. This is the recorded
//! finding F-tests-depend-on-accumulated-shared-db-fixtures.
//!
//! `#[sqlx::test]` supplies the empty database directly, so the assertions are
//! UNCHANGED and the truncation is simply unnecessary. One arm was worse than
//! flaky: `expand_returns_404_for_unknown_cluster` can pass FOR THE WRONG
//! REASON on a shared database, because the handler returns 404 both for "no
//! such cluster in the latest run" (the branch under test) and for "no runs at
//! all" (what a sibling's truncation leaves behind). A private database makes
//! the seeded run a guarantee rather than a race, so only the intended branch
//! can produce the 404.
//!
//! `spawn_app` builds its own pool FROM A URL, so each arm hands it
//! `fixture::database_url_for(&pool)` — the per-test database's own URL. Passing
//! the ambient `DATABASE_URL` here would seed the private database and then
//! assert against the shared one, which is the silent-vacuous-pass failure this
//! note exists to prevent.
//!
//! # These arms lost their multi-threaded runtime, deliberately
//!
//! They were `#[tokio::test(flavor = "multi_thread")]`. `#[sqlx::test]` drives
//! the future through sqlx's `rt::test_block_on`, which builds a
//! CURRENT-THREAD Tokio runtime, so the axum server `spawn_app` spawns and the
//! reqwest client that drives it are now cooperatively scheduled on ONE thread.
//! That is fine today -- nothing in the request path blocks: there is no
//! `block_in_place`, `Handle::block_on` or `futures::executor::block_on`
//! anywhere in epigraph-api/db/engine `src/`, and `spawn_app` binds an
//! ephemeral port so there is no fixed-port contention. It is written down
//! because it is a PRECEDENT: the next shard converts the remaining
//! `flavor = "multi_thread"` arms in this package the same way, and the day a
//! handler grows a blocking call it will panic ("can call blocking only when
//! running on the multi-threaded runtime") or deadlock outright, with nothing
//! in that diff to explain why.
//!
//! The two remaining `#[tokio::test]` arms are deliberately left alone:
//! `legacy_neighborhood_endpoint_returns_410_gone` and
//! `graph_endpoints_require_bearer` assert 410/401 unconditionally, read no
//! table and mutate none, so per-test provisioning would cost time and buy no
//! isolation.

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

#[sqlx::test(migrations = "../../migrations")]
async fn overview_with_no_runs_returns_no_clusters_computed(pool: PgPool) {
    // No truncation and no seeding: #[sqlx::test] IS the "no runs exist" state
    // this arm previously tried to create by emptying four shared tables.
    let url = fixture::database_url_for(&pool).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/api/v1/graph/communities/overview"))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "no_clusters_computed");
    assert_eq!(body["supernodes"].as_array().unwrap().len(), 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_returns_seeded_supernodes(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let run_id = uuid::Uuid::new_v4();
    let c1 = uuid::Uuid::new_v4();
    let c2 = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO graph_clusters (id, run_id, label, size, mean_betp, dominant_type, dominant_frame_id, degraded) VALUES ($1, $2, 'A', 5, 0.7, 'claim', NULL, FALSE), ($3, $2, 'B', 3, 0.4, 'claim', NULL, FALSE)")
        .bind(c1).bind(run_id).bind(c2)
        .execute(&pool).await.unwrap();
    let (lo, hi) = if c1 < c2 { (c1, c2) } else { (c2, c1) };
    sqlx::query(
        "INSERT INTO cluster_edges (run_id, cluster_a, cluster_b, weight) VALUES ($1, $2, $3, 4)",
    )
    .bind(run_id)
    .bind(lo)
    .bind(hi)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 2, FALSE)",
    )
    .bind(run_id)
    .execute(&pool)
    .await
    .unwrap();

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/graph/communities/overview"))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["supernodes"].as_array().unwrap().len(), 2);
    assert_eq!(body["cluster_edges"].as_array().unwrap().len(), 1);
    assert_eq!(body["cluster_edges"][0]["weight"], 4);
    assert_eq!(body["degraded"], false);
}

// ---------------------------------------------------------------------------
// Opt-in bound on /graph/communities/overview (backlog cc21d1fe).
//
// The route used to return EVERY supernode and EVERY cluster edge of the latest
// run, and ignored its query string, so a caller with a body cap (the Explorer
// BFF, 8 MB) had no way to ask for less. These arms pin the opt-in params
// `limit`, `min_size`, `include_edges` and `edge_limit` by their EFFECT: which
// rows come back, in which order, and what `total_supernodes` / `truncated`
// report. The no-params arm is the guard that the default body is unchanged.
//
// The seed inserts clusters SMALLEST first and edges LIGHTEST first, so a
// handler that lost its `ORDER BY` cannot pass on heap order.
// ---------------------------------------------------------------------------

struct ThreeClusters {
    a: uuid::Uuid,
    b: uuid::Uuid,
}

/// One run with clusters A (size 5), B (size 3), C (size 1) and the three
/// edges A–B (weight 4), B–C (weight 2), A–C (weight 1).
async fn seed_three_clusters(pool: &PgPool) -> ThreeClusters {
    let run_id = uuid::Uuid::new_v4();
    let (a, b, c) = (
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    for (id, label, size) in [(c, "C", 1_i32), (b, "B", 3), (a, "A", 5)] {
        sqlx::query(
            "INSERT INTO graph_clusters (id, run_id, label, size, mean_betp, dominant_type, dominant_frame_id, degraded) \
             VALUES ($1, $2, $3, $4, 0.5, 'claim', NULL, FALSE)",
        )
        .bind(id)
        .bind(run_id)
        .bind(label)
        .bind(size)
        .execute(pool)
        .await
        .unwrap();
    }
    for (x, y, weight) in [(a, c, 1_i32), (b, c, 2), (a, b, 4)] {
        // CHECK (cluster_a < cluster_b) in migrations/015_graph_clusters.sql.
        let (lo, hi) = if x < y { (x, y) } else { (y, x) };
        sqlx::query(
            "INSERT INTO cluster_edges (run_id, cluster_a, cluster_b, weight) VALUES ($1, $2, $3, $4)",
        )
        .bind(run_id)
        .bind(lo)
        .bind(hi)
        .bind(weight)
        .execute(pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 3, FALSE)",
    )
    .bind(run_id)
    .execute(pool)
    .await
    .unwrap();
    ThreeClusters { a, b }
}

/// GET the overview with `query` (no leading `?`; empty for none) against the
/// per-test database at `url`, assert 200 and return the JSON body.
async fn get_overview(url: &str, query: &str) -> Value {
    let (addr, _shutdown) = common::spawn_app(url).await;
    let target = if query.is_empty() {
        format!("http://{addr}/api/v1/graph/communities/overview")
    } else {
        format!("http://{addr}/api/v1/graph/communities/overview?{query}")
    };
    let resp = reqwest::Client::new()
        .get(target)
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "GET overview?{query}");
    resp.json().await.unwrap()
}

fn supernode_labels(body: &Value) -> Vec<String> {
    body["supernodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["label"].as_str().unwrap().to_string())
        .collect()
}

fn edge_weights(body: &Value) -> Vec<i64> {
    body["cluster_edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["weight"].as_i64().unwrap())
        .collect()
}

fn edge_endpoints(edge: &Value) -> std::collections::BTreeSet<String> {
    [edge["a"].as_str().unwrap(), edge["b"].as_str().unwrap()]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn ids(of: &[uuid::Uuid]) -> std::collections::BTreeSet<String> {
    of.iter().map(uuid::Uuid::to_string).collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_limit_returns_top_n_by_size_with_induced_edges(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let s = seed_three_clusters(&pool).await;

    let body = get_overview(&url, "limit=2").await;

    assert_eq!(supernode_labels(&body), ["A", "B"]);
    // Only the edge whose BOTH ends were returned survives: B–C and A–C point
    // at C, which the bound dropped.
    assert_eq!(edge_weights(&body), [4]);
    assert_eq!(edge_endpoints(&body["cluster_edges"][0]), ids(&[s.a, s.b]));
    assert_eq!(body["total_supernodes"], 3);
    assert_eq!(body["truncated"], true);
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_min_size_drops_small_clusters_and_their_edges(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let s = seed_three_clusters(&pool).await;

    let body = get_overview(&url, "min_size=2").await;

    assert_eq!(supernode_labels(&body), ["A", "B"]);
    assert_eq!(edge_weights(&body), [4]);
    assert_eq!(edge_endpoints(&body["cluster_edges"][0]), ids(&[s.a, s.b]));
    assert_eq!(body["total_supernodes"], 3);
    assert_eq!(body["truncated"], true);
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_include_edges_false_returns_no_edges(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    seed_three_clusters(&pool).await;

    let body = get_overview(&url, "limit=5&include_edges=false").await;

    assert_eq!(supernode_labels(&body), ["A", "B", "C"]);
    assert_eq!(edge_weights(&body), Vec::<i64>::new());
    assert_eq!(body["total_supernodes"], 3);
    // Every supernode came back and the edges were declined, not cut: that is
    // not truncation.
    assert_eq!(body["truncated"], false);
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_edge_limit_keeps_heaviest_edges_and_flags_only_a_real_cut(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    seed_three_clusters(&pool).await;

    // One edge short of the induced set: the lightest is cut and reported.
    let cut = get_overview(&url, "limit=3&edge_limit=2").await;
    assert_eq!(supernode_labels(&cut), ["A", "B", "C"]);
    assert_eq!(edge_weights(&cut), [4, 2]);
    assert_eq!(cut["truncated"], true);

    // Exactly the induced set: nothing is cut, so nothing is reported.
    let exact = get_overview(&url, "limit=3&edge_limit=3").await;
    assert_eq!(edge_weights(&exact), [4, 2, 1]);
    assert_eq!(exact["total_supernodes"], 3);
    assert_eq!(exact["truncated"], false);
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_edge_limit_alone_caps_the_whole_run_edges(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    seed_three_clusters(&pool).await;

    let body = get_overview(&url, "edge_limit=1").await;

    assert_eq!(supernode_labels(&body), ["A", "B", "C"]);
    assert_eq!(edge_weights(&body), [4]);
    assert_eq!(body["total_supernodes"], 3);
    assert_eq!(body["truncated"], true);
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_limit_breaks_size_ties_by_cluster_id(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let run_id = uuid::Uuid::new_v4();
    let (x, y) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let (lo, hi) = if x < y { (x, y) } else { (y, x) };
    // Equal sizes, HIGHER id inserted first: heap order would return `hi`.
    for (id, label) in [(hi, "HI"), (lo, "LO")] {
        sqlx::query(
            "INSERT INTO graph_clusters (id, run_id, label, size, mean_betp, dominant_type, dominant_frame_id, degraded) \
             VALUES ($1, $2, $3, 2, 0.5, 'claim', NULL, FALSE)",
        )
        .bind(id)
        .bind(run_id)
        .bind(label)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded) VALUES ($1, 2, FALSE)",
    )
    .bind(run_id)
    .execute(&pool)
    .await
    .unwrap();

    let body = get_overview(&url, "limit=1").await;

    assert_eq!(supernode_labels(&body), ["LO"]);
    assert_eq!(body["supernodes"][0]["cluster_id"], lo.to_string());
    assert_eq!(body["total_supernodes"], 2);
    assert_eq!(body["truncated"], true);
}

#[sqlx::test(migrations = "../../migrations")]
async fn overview_limit_below_one_is_clamped_to_one(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    seed_three_clusters(&pool).await;

    for query in ["limit=0", "limit=-5"] {
        let body = get_overview(&url, query).await;
        assert_eq!(supernode_labels(&body), ["A"], "{query}");
        assert_eq!(edge_weights(&body), Vec::<i64>::new(), "{query}");
        assert_eq!(body["truncated"], true, "{query}");
    }
}

/// `edge_limit` shares `limit`'s `1..=10_000` clamp. No `limit` is sent, so
/// every supernode comes back and only the edge cap is under test: `0` and
/// `-5` must both mean "the single heaviest edge", never a 500 from a
/// negative `LIMIT` and never an empty edge list.
#[sqlx::test(migrations = "../../migrations")]
async fn overview_edge_limit_below_one_is_clamped_to_one(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let s = seed_three_clusters(&pool).await;

    for query in ["edge_limit=0", "edge_limit=-5"] {
        let body = get_overview(&url, query).await;
        assert_eq!(supernode_labels(&body), ["A", "B", "C"], "{query}");
        assert_eq!(edge_weights(&body), [4], "{query}");
        assert_eq!(
            edge_endpoints(&body["cluster_edges"][0]),
            ids(&[s.a, s.b]),
            "{query}"
        );
        assert_eq!(body["total_supernodes"], 3, "{query}");
        assert_eq!(body["truncated"], true, "{query}");
    }
}

/// `min_size` drops clusters BELOW the size, so a cluster of exactly
/// `min_size` is kept: B (size 3) survives `min_size=3`, C (size 1) does not.
#[sqlx::test(migrations = "../../migrations")]
async fn overview_min_size_keeps_a_cluster_of_exactly_that_size(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let s = seed_three_clusters(&pool).await;

    let body = get_overview(&url, "min_size=3").await;

    assert_eq!(supernode_labels(&body), ["A", "B"]);
    assert_eq!(edge_weights(&body), [4]);
    assert_eq!(edge_endpoints(&body["cluster_edges"][0]), ids(&[s.a, s.b]));
    assert_eq!(body["total_supernodes"], 3);
    assert_eq!(body["truncated"], true);
}

/// `include_edges=false` on its own is an opt-out the handler must honour:
/// no other param makes the request bounded, so this arm alone pins that
/// `include_edges` selects the bounded body.
#[sqlx::test(migrations = "../../migrations")]
async fn overview_include_edges_false_alone_skips_edges(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    seed_three_clusters(&pool).await;

    let body = get_overview(&url, "include_edges=false").await;

    assert_eq!(supernode_labels(&body), ["A", "B", "C"]);
    assert_eq!(edge_weights(&body), Vec::<i64>::new());
    assert_eq!(body["total_supernodes"], 3);
    assert_eq!(body["truncated"], false);
}

/// Guard, and meant to pass on main as well: with no bound in the query string
/// the body is today's body — every supernode, every edge, and no new
/// top-level key. The epigraph-gui reads `cluster_edges` unbounded from this
/// exact shape. `color_by` is a pre-existing param that never changed the
/// body, so it must not opt the caller into the bounded shape either.
#[sqlx::test(migrations = "../../migrations")]
async fn overview_without_params_is_unchanged(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    seed_three_clusters(&pool).await;

    for query in ["", "color_by=type"] {
        let body = get_overview(&url, query).await;

        let keys: std::collections::BTreeSet<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "cluster_edges",
                "degraded",
                "generated_at",
                "run_id",
                "supernodes"
            ]
            .into_iter()
            .collect(),
            "{query:?}"
        );
        assert_eq!(supernode_labels(&body), ["A", "B", "C"], "{query:?}");
        let mut weights = edge_weights(&body);
        weights.sort_unstable();
        assert_eq!(weights, [1, 2, 4], "{query:?}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn expand_returns_cluster_members_with_induced_edges(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let cluster_id = common::seed_one_cluster(&pool, 5).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/graph/communities/{cluster_id}/expand?budget=10"
        ))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["nodes"].as_array().unwrap().len(), 5);
    assert_eq!(body["truncated"], false);
}

/// `?relationships=` on expand matches every stored spelling of a case-folded
/// relationship (backlog 3ce5e00c): a legacy upper-case `SUPPORTS` row and a
/// canonical lower-case `supports` row are both returned whichever spelling the
/// caller names, and only the unrelated edge is counted as filtered out.
#[sqlx::test(migrations = "../../migrations")]
async fn expand_relationship_override_matches_both_spellings(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let cluster_id = common::seed_one_cluster(&pool, 3).await;
    let mut members: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT claim_id FROM claim_cluster_membership WHERE cluster_id = $1")
            .bind(cluster_id)
            .fetch_all(&pool)
            .await
            .unwrap();
    members.sort();
    let (a, b, c) = (members[0], members[1], members[2]);
    for (source, target, rel) in [(a, b, "SUPPORTS"), (b, c, "supports"), (a, c, "elaborates")] {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
                                properties) \
             VALUES ($1, 'claim', $2, 'claim', $3, '{}'::jsonb)",
        )
        .bind(source)
        .bind(target)
        .bind(rel)
        .execute(&pool)
        .await
        .unwrap();
    }

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let expand = |relationships: &'static str| async move {
        let resp = reqwest::Client::new()
            .get(format!(
                "http://{addr}/api/v1/graph/communities/{cluster_id}/expand\
                     ?budget=10&relationships={relationships}"
            ))
            .header(
                "Authorization",
                format!("Bearer {}", common::test_bearer_token()),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "{relationships}");
        let body: Value = resp.json().await.unwrap();
        let mut rels: Vec<String> = body["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["relationship"].as_str().unwrap().to_string())
            .collect();
        rels.sort();
        (rels, body["filtered_edge_count"].as_i64().unwrap())
    };

    // Calibration: with no filter the viewer sees all three seeded edges.
    let (all, filtered) = expand("*").await;
    assert_eq!(all, ["SUPPORTS", "elaborates", "supports"]);
    assert_eq!(filtered, 0);

    for asked in ["supports", "SUPPORTS"] {
        let (rels, filtered) = expand(asked).await;
        assert_eq!(
            rels,
            ["SUPPORTS", "supports"],
            "relationships={asked} must return both spellings"
        );
        assert_eq!(
            filtered, 1,
            "relationships={asked}: only `elaborates` is filtered"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn expand_returns_404_for_unknown_cluster(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    // Need at least one run row so the handler reaches the per-cluster check (404
    // also happens when no run exists, but we want to specifically test the
    // "no such cluster in latest run" branch). seed_one_cluster sets that up.
    //
    // On a shared database that was a HOPE, not a guarantee: any sibling arm
    // truncating graph_cluster_runs between this seed and the request sent the
    // handler down the "no runs at all" branch, which returns the same 404 and
    // made the assertion pass while testing nothing. The per-test database is
    // what makes the seeded run survive to the assertion.
    let _ = common::seed_one_cluster(&pool, 1).await;
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let bogus = uuid::Uuid::new_v4();
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/graph/communities/{bogus}/expand"
        ))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_neighborhood_endpoint_returns_410_gone() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    // We don't need to seed anything — handler returns 410 unconditionally.
    let _ = pool;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/v1/graph/neighborhood?node_id={}&hops=1&budget=20",
            uuid::Uuid::new_v4()
        ))
        .header(
            "Authorization",
            format!("Bearer {}", common::test_bearer_token()),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        410,
        "legacy /graph/neighborhood must return 410 Gone"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn graph_endpoints_require_bearer() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;
    for path in [
        "/api/v1/graph/communities/overview".to_string(),
        format!("/api/v1/graph/communities/{}/expand", uuid::Uuid::new_v4()),
        format!(
            "/api/v1/graph/neighborhood?node_id={}",
            uuid::Uuid::new_v4()
        ),
    ] {
        let resp = reqwest::Client::new()
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401, "missing auth path={path}");
    }
}
