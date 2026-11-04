#![cfg(feature = "db")]
//! `POST /api/v1/claims/:id/supersede` regenerates the BP factors of the edges
//! its cascade migrates (supersede SPEC §11 K3, review D4a): the HTTP twin of
//! `epigraph-mcp/tests/supersede_cascade_regenerates_factors.rs`, applied in
//! the request and replayed from a deferral.
//!
//! Retiring the predecessor deletes every factor naming it
//! (`claims_deactivate_factors`) and the migration moves edges by UPDATE, which
//! the INSERT-only `edges_auto_factor` trigger never sees, so without the
//! regeneration a migrated `corroborates` / `supports` edge ends factorless.
//! The incoming `refutes` stays on the retired claim (#398) and must stay
//! factorless.
//!
//! These fixtures share the `DATABASE_URL` database with the rest of
//! `epigraph-api`'s integration tests, so every assertion is scoped to the ids
//! this test created.

#[allow(dead_code)]
mod common;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

async fn factors_on(pool: &PgPool, edge: Uuid, a: Uuid, b: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM factors \
          WHERE properties->>'source_edge_id' = $1::text \
            AND variable_ids @> ARRAY[$2, $3]::uuid[] AND cardinality(variable_ids) = 2",
    )
    .bind(edge)
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .expect("count factors")
}

async fn ends(pool: &PgPool, edge: Uuid) -> (Uuid, Uuid) {
    sqlx::query_as("SELECT source_id, target_id FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("edge ends")
}

struct World {
    old: Uuid,
    x: Uuid,
    y: Uuid,
    z: Uuid,
    w: Uuid,
    incoming: Uuid,
    outgoing: Uuid,
    supports: Uuid,
    refutes: Uuid,
}

async fn world(pool: &PgPool, client_id: Uuid, tag: Uuid) -> World {
    let old = common::seed_claim_writable_by_client(
        pool,
        &format!("k3 http predecessor {tag}"),
        client_id,
    )
    .await;
    let x = common::seed_claim(pool, &format!("k3 http corroborator {tag}")).await;
    let y = common::seed_claim(pool, &format!("k3 http corroborated {tag}")).await;
    let z = common::seed_claim(pool, &format!("k3 http supported {tag}")).await;
    let w = common::seed_claim(pool, &format!("k3 http refuter {tag}")).await;
    let incoming = common::insert_edge(pool, x, old, "claim", "claim", "corroborates").await;
    let outgoing = common::insert_edge(pool, old, y, "claim", "claim", "corroborates").await;
    let supports = common::insert_edge(pool, old, z, "claim", "claim", "supports").await;
    let refutes = common::insert_edge(pool, w, old, "claim", "claim", "refutes").await;
    for (e, a, b) in [
        (incoming, x, old),
        (outgoing, old, y),
        (supports, old, z),
        (refutes, w, old),
    ] {
        assert_eq!(
            factors_on(pool, e, a, b).await,
            1,
            "PREMISE: edge {e} has its trigger-minted factor"
        );
    }
    World {
        old,
        x,
        y,
        z,
        w,
        incoming,
        outgoing,
        supports,
        refutes,
    }
}

async fn supersede(addr: std::net::SocketAddr, token: &str, old: Uuid) -> serde_json::Value {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims/{old}/supersede"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "content": format!("k3 http successor of {old}"),
            "truth_value": 0.5,
            "reason": "k3 http factor regeneration fixture",
        }))
        .send()
        .await
        .expect("send");
    let status = resp.status();
    let text = resp.text().await.expect("body");
    assert!(
        status == 200 || status == 201,
        "supersede must succeed; got {status}: {text}"
    );
    serde_json::from_str(&text).expect("response json")
}

async fn assert_factors_regenerated(pool: &PgPool, w: &World, new: Uuid) {
    assert_eq!(ends(pool, w.incoming).await, (w.x, new), "incoming moved");
    assert_eq!(ends(pool, w.outgoing).await, (new, w.y), "outgoing moved");
    assert_eq!(ends(pool, w.supports).await, (new, w.z), "supports moved");
    assert_eq!(
        ends(pool, w.refutes).await,
        (w.w, w.old),
        "the weakening edge stays on the retired claim (#398)"
    );
    for (e, a, b, what) in [
        (w.incoming, w.x, new, "incoming corroborates"),
        (w.outgoing, new, w.y, "outgoing corroborates"),
        (w.supports, new, w.z, "outgoing supports"),
    ] {
        assert_eq!(
            factors_on(pool, e, a, b).await,
            1,
            "the migrated {what} edge {e} must have its BP factor over its new endpoints"
        );
    }
    let on_retired: i64 =
        sqlx::query_scalar("SELECT count(*) FROM factors WHERE $1 = ANY(variable_ids)")
            .bind(w.old)
            .fetch_one(pool)
            .await
            .expect("count factors naming the retired claim");
    assert_eq!(on_retired, 0, "no factor may name the retired claim");
}

async fn pool_and_url() -> (PgPool, String) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect");
    (pool, url)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_applied_http_supersede_regenerates_migrated_edge_factors() {
    let (pool, url) = pool_and_url().await;
    let (addr, _shutdown) = common::spawn_app_with_admin_cascade(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let w = world(&pool, client_id, Uuid::new_v4()).await;

    let body = supersede(addr, &token, w.old).await;
    assert_eq!(body["cascade"]["status"], "applied", "{body}");
    let new: Uuid = body["new_claim_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("new_claim_id");

    assert_factors_regenerated(&pool, &w, new).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replayed_http_supersede_regenerates_migrated_edge_factors() {
    let (pool, url) = pool_and_url().await;
    // Plain `spawn_app` holds no maintenance connection: the route defers.
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let (token, client_id) =
        common::test_bearer_token_with_seeded_client(&pool, &["claims:write"]).await;
    let w = world(&pool, client_id, Uuid::new_v4()).await;

    let body = supersede(addr, &token, w.old).await;
    assert_eq!(body["cascade"]["status"], "deferred", "{body}");
    let deferral: Uuid = body["cascade"]["audit_event_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("the deferral names its audit row");
    let new: Uuid = body["new_claim_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("new_claim_id");
    assert_eq!(
        ends(&pool, w.incoming).await,
        (w.x, w.old),
        "PREMISE: nothing moves before the replay"
    );

    let scoped = epigraph_db::ScopedPool::connect(&url, epigraph_db::SessionGucMode::Session)
        .await
        .expect("ScopedPool")
        .with_maintenance_pool(pool.clone());
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    let (conn, admin_viewer) = session.split();
    // The database is shared: other binaries' deferrals may be pending, so the
    // replay's verdict is read off THIS deferral's item.
    let report = epigraph_engine::admin_cascade::replay_deferred(
        conn,
        admin_viewer,
        "k3-http-replay",
        100_000,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay");
    let item = report
        .items
        .iter()
        .find(|i| i.deferred_event_id == deferral)
        .unwrap_or_else(|| panic!("the replay reached deferral {deferral}: {report:?}"));
    assert_eq!(
        serde_json::to_value(&item.status).expect("status")["status"],
        "applied",
        "{item:?}"
    );

    assert_factors_regenerated(&pool, &w, new).await;
}
