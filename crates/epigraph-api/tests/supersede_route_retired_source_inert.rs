#![cfg(feature = "db")]
//! `POST /api/v1/claims/:id/supersede` leaves the retired claim inert: the
//! edge-keyed BBAs its outgoing edges froze onto current targets are
//! invalidated and the targets re-derived (supersede SPEC §11 K10(2); backlog
//! 174ffd23, its belief half). The HTTP twin of
//! `epigraph-mcp/tests/supersede_cascade_retired_source_inert.rs`.
//!
//! The weakening edge (`refutes`) stays on the retired claim (#398), and the
//! existing cascade walks only the successor's targets, so before K10(2) the
//! target kept the retired refuter's frozen mass.
//!
//! Shares the `DATABASE_URL` database with the other `epigraph-api`
//! integration tests: every assertion is scoped to ids this test created.

#[allow(dead_code)]
mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

async fn wire(pool: &PgPool, source: Uuid, target: Uuid, rel: &str) -> Uuid {
    let viewer = fixture::public_viewer(pool).await;
    let author: Uuid = sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(source)
        .fetch_one(pool)
        .await
        .expect("the source's author");
    let edge = epigraph_db::EdgeRepository::create(
        pool, source, "claim", target, "claim", rel, None, None, None,
    )
    .await
    .expect("create edge");
    let outcome = epigraph_engine::edge_factor::auto_wire_ds_for_edge(
        &mut pool.acquire().await.expect("acquire"),
        &viewer,
        edge,
        author,
        source,
        target,
        rel,
    )
    .await
    .expect("auto-wire");
    assert_eq!(
        outcome,
        epigraph_engine::edge_factor::EdgeFactorOutcome::Wired,
        "PREMISE: {rel} edge {edge} wires a BBA"
    );
    edge
}

async fn plant_interval(pool: &PgPool, claim: Uuid, bel: f64, pl: f64) {
    sqlx::query("UPDATE claims SET belief = $2, plausibility = $3 WHERE id = $1")
        .bind(claim)
        .bind(bel)
        .bind(pl)
        .execute(pool)
        .await
        .expect("plant interval");
}

async fn keyed_on(pool: &PgPool, edge: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE perspective_id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("count edge-keyed rows")
}

async fn betp(pool: &PgPool, claim: Uuid) -> Option<f64> {
    sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read BetP")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_http_supersede_invalidates_the_retired_refuters_edge_bba() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect");
    let (addr, _shutdown) = common::spawn_app_with_admin_cascade(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let tag = Uuid::new_v4();

    let refuter =
        common::seed_claim_writable_by_client(&pool, &format!("k10 http refuter {tag}"), client_id)
            .await;
    plant_interval(&pool, refuter, 0.9, 0.95).await;
    let supporter = common::seed_claim(&pool, &format!("k10 http supporter {tag}")).await;
    plant_interval(&pool, supporter, 0.6, 0.7).await;
    let target = common::seed_claim(&pool, &format!("k10 http target {tag}")).await;
    let refutes = wire(&pool, refuter, target, "refutes").await;
    let supports = wire(&pool, supporter, target, "supports").await;
    let before = betp(&pool, target).await.expect("PREMISE: cached BetP");

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{refuter}/supersede"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "content": format!("k10 http successor {tag}"),
            "truth_value": 0.5,
            "reason": "k10 http inert fixture",
        }))
        .send()
        .await
        .expect("send");
    let status = resp.status();
    let text = resp.text().await.expect("body");
    assert!(status == 200 || status == 201, "{status}: {text}");
    let body: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(body["cascade"]["status"], "applied", "{body}");

    let (src, _): (Uuid, Uuid) =
        sqlx::query_as("SELECT source_id, target_id FROM edges WHERE id = $1")
            .bind(refutes)
            .fetch_one(&pool)
            .await
            .expect("refutes edge");
    assert_eq!(
        src, refuter,
        "PREMISE: the refutes edge stays on the retired claim"
    );
    assert_eq!(
        keyed_on(&pool, refutes).await,
        0,
        "the retired refuter's edge BBA on the current target is invalidated"
    );
    assert_eq!(
        keyed_on(&pool, supports).await,
        1,
        "the supporter's BBA stays"
    );

    let after = betp(&pool, target)
        .await
        .expect("the supporter still backs it");
    assert!(
        (after - before).abs() > 1e-9,
        "the target is re-derived without the refuter: before={before}, after={after}"
    );
    let viewer = fixture::public_viewer(&pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let frame = epigraph_engine::edge_factor::ensure_binary_frame(&mut conn, &viewer)
        .await
        .expect("frame");
    let coherent = epigraph_engine::edge_factor::preview_claim_belief_on_frame(
        &mut conn, &viewer, target, frame,
    )
    .await
    .expect("preview")
    .expect("one BBA left")
    .pignistic_prob;
    assert!(
        (after - coherent).abs() < 1e-12,
        "cache {after} equals the fold of what survives {coherent}"
    );
    let targets: Vec<String> = body["belief_cascade"]["targets"]
        .as_array()
        .expect("targets")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    assert!(
        targets.contains(&target.to_string()),
        "the HTTP report names the re-derived target: {body}"
    );
}

async fn preview_betp(pool: &PgPool, claim: Uuid) -> f64 {
    let viewer = fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let frame = epigraph_engine::edge_factor::ensure_binary_frame(&mut conn, &viewer)
        .await
        .expect("frame");
    epigraph_engine::edge_factor::preview_claim_belief_on_frame(&mut conn, &viewer, claim, frame)
        .await
        .expect("preview")
        .expect("one BBA left")
        .pignistic_prob
}

/// Both walks in one HTTP supersede: the supporting edge moves (factor over
/// the new pair, K3) and the refuting edge stays (BBA invalidated, nothing
/// re-derived, K10(2)); both holders are recomputed in the one repair pass and
/// are coherent with what they still hold. The twin of the MCP
/// `a_supersede_rewires_moved_edges_and_invalidates_stayed_ones`.
#[tokio::test(flavor = "multi_thread")]
async fn an_http_supersede_rewires_moved_edges_and_invalidates_stayed_ones() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect");
    let (addr, _shutdown) = common::spawn_app_with_admin_cascade(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let tag = Uuid::new_v4();

    let p =
        common::seed_claim_writable_by_client(&pool, &format!("k10+k3 http p {tag}"), client_id)
            .await;
    plant_interval(&pool, p, 0.9, 0.95).await;
    let y = common::seed_claim(&pool, &format!("k10+k3 http y {tag}")).await;
    let t = common::seed_claim(&pool, &format!("k10+k3 http t {tag}")).await;
    let y_other = common::seed_claim(&pool, &format!("k10+k3 http y other {tag}")).await;
    plant_interval(&pool, y_other, 0.6, 0.7).await;
    let t_other = common::seed_claim(&pool, &format!("k10+k3 http t other {tag}")).await;
    plant_interval(&pool, t_other, 0.55, 0.75).await;
    let supports = wire(&pool, p, y, "supports").await;
    let refutes = wire(&pool, p, t, "refutes").await;
    wire(&pool, y_other, y, "supports").await;
    wire(&pool, t_other, t, "supports").await;
    let y_before = betp(&pool, y).await.expect("PREMISE: Y cached");
    let t_before = betp(&pool, t).await.expect("PREMISE: T cached");

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{p}/supersede"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "content": format!("k10+k3 http successor {tag}"),
            "truth_value": 0.5,
            "reason": "k10+k3 http fixture",
        }))
        .send()
        .await
        .expect("send");
    let status = resp.status();
    let text = resp.text().await.expect("body");
    assert!(status == 200 || status == 201, "{status}: {text}");
    let body: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(body["cascade"]["status"], "applied", "{body}");
    let report = &body["belief_cascade"];
    assert!(
        report["errors"].as_array().is_some_and(Vec::is_empty),
        "{report}"
    );
    let successor: Uuid = body["new_claim_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("new_claim_id");

    let ends = |e: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (Uuid, Uuid)>(
                "SELECT source_id, target_id FROM edges WHERE id = $1",
            )
            .bind(e)
            .fetch_one(&pool)
            .await
            .expect("edge")
        }
    };
    assert_eq!(
        ends(supports).await,
        (successor, y),
        "PREMISE: supports moved"
    );
    assert_eq!(ends(refutes).await.0, p, "PREMISE: refutes stays (#398)");
    let factor: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM factors WHERE properties->>'source_edge_id' = $1::text \
            AND variable_ids @> ARRAY[$2, $3]::uuid[] AND cardinality(variable_ids) = 2",
    )
    .bind(supports)
    .bind(successor)
    .bind(y)
    .fetch_one(&pool)
    .await
    .expect("count factors");
    assert_eq!(
        factor, 1,
        "the moved edge has its factor over (successor, Y)"
    );
    assert_eq!(keyed_on(&pool, refutes).await, 0, "the stayed BBA is gone");
    assert_eq!(
        keyed_on(&pool, supports).await,
        0,
        "the predecessor's interval no longer rides the moved edge (re-derivation from an \
         interval-less successor is SourceFactorless)"
    );

    for (claim, before) in [(y, y_before), (t, t_before)] {
        let after = betp(&pool, claim)
            .await
            .expect("its other supporter remains");
        assert!(
            (after - before).abs() > 1e-9,
            "{claim}: before={before}, after={after}"
        );
        let coherent = preview_betp(&pool, claim).await;
        assert!(
            (after - coherent).abs() < 1e-12,
            "{claim}: cache {after} is the fold of what survives {coherent}"
        );
    }
    let mut targets: Vec<String> = report["targets"]
        .as_array()
        .expect("targets")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    targets.sort();
    let mut expected = vec![y.to_string(), t.to_string()];
    expected.sort();
    assert_eq!(
        targets, expected,
        "both walks' holders, once each: {report}"
    );
}
