//! The supersede cascade regenerates the BP factors of the edges it migrates
//! (supersede SPEC §11 K3, review D4a), driven through the real MCP tool
//! `supersede_claim`, with the cascade applied in the request and replayed
//! from a deferral.
//!
//! Why the factors go missing without it: retiring the predecessor deletes
//! every factor naming it (`claims_deactivate_factors`), and the edge
//! migration re-points edges by UPDATE, which the INSERT-only
//! `edges_auto_factor` trigger never sees. So a migrated `corroborates` /
//! `supports` edge ends with no factor, and BP never sees it.
//!
//! The fixture's predecessor has one edge of each kind the migration treats
//! differently: an incoming `corroborates` (moves), an outgoing
//! `corroborates` and an outgoing `supports` (move), and an incoming
//! `refutes`, which the weakening-edge policy (#398) leaves on the retired
//! claim, so it must stay factorless (its endpoint is retired). Migrated
//! `refutes` edges do not exist under that policy, so `corroborates` and
//! `supports` are the migrated kinds a factor is checked for.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, seed_claim};
use epigraph_mcp::tools::supersede::supersede_claim;
use epigraph_mcp::types::SupersedeClaimParams;
use sqlx::PgPool;
use uuid::Uuid;

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, rel: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("insert edge")
}

/// The factors keyed on `edge` whose variables are exactly `{a, b}`.
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

async fn world(pool: &PgPool) -> World {
    let old = seed_claim(pool, "k3 predecessor", 0.5).await;
    let x = seed_claim(pool, "k3 corroborator", 0.5).await;
    let y = seed_claim(pool, "k3 corroborated", 0.5).await;
    let z = seed_claim(pool, "k3 supported", 0.5).await;
    let w = seed_claim(pool, "k3 refuter", 0.5).await;
    let incoming = edge(pool, x, old, "corroborates").await;
    let outgoing = edge(pool, old, y, "corroborates").await;
    let supports = edge(pool, old, z, "supports").await;
    let refutes = edge(pool, w, old, "refutes").await;
    // PREMISE: the INSERT trigger minted each edge's factor.
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

async fn supersede(
    pool: &PgPool,
    server: &epigraph_mcp::server::EpiGraphMcpFull,
    old: Uuid,
) -> serde_json::Value {
    let (auth, admin_viewer) = common::granted_server_admin(server, pool).await;
    let r = supersede_claim(
        server,
        &admin_viewer,
        SupersedeClaimParams {
            claim_id: old.to_string(),
            content: format!("k3 successor of {old}"),
            truth_value: 0.5,
            reason: "k3 factor regeneration fixture".to_string(),
        },
        Some(&auth),
    )
    .await
    .map_err(|e| e.message.to_string())
    .expect("supersede_claim succeeds");
    common::first_text(&r)
}

/// Every migrated edge carries a factor over its NEW endpoints; the edge that
/// stayed on the retired claim carries none.
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
    assert_eq!(
        on_retired, 0,
        "no factor may name the retired claim (its retirement removed them, and regeneration \
         skips a non-current endpoint)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_applied_supersede_cascade_regenerates_migrated_edge_factors(pool: PgPool) {
    let server = build_scoped_test_server(
        pool.clone(),
        fixture::scoped_pool(&pool)
            .await
            .with_maintenance_pool(pool.clone()),
    );
    let w = world(&pool).await;

    let body = supersede(&pool, &server, w.old).await;
    assert_eq!(body["cascade"]["status"], "applied", "{body}");
    let new = common::parse_uuid_field(&body, "new_claim_id");

    assert_factors_regenerated(&pool, &w, new).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_replayed_supersede_cascade_regenerates_migrated_edge_factors(pool: PgPool) {
    // No maintenance connection: the tool commits the act and defers.
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let w = world(&pool).await;

    let body = supersede(&pool, &server, w.old).await;
    assert_eq!(body["cascade"]["status"], "deferred", "{body}");
    let new = common::parse_uuid_field(&body, "new_claim_id");
    assert_eq!(
        ends(&pool, w.incoming).await,
        (w.x, w.old),
        "PREMISE: nothing moves before the replay"
    );

    let scoped = fixture::scoped_pool(&pool)
        .await
        .with_maintenance_pool(pool.clone());
    let mut session = scoped
        .maintenance_session(epigraph_db::visibility::SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    let (conn, admin_viewer) = session.split();
    let report = epigraph_engine::admin_cascade::replay_deferred(
        conn,
        admin_viewer,
        "k3-replay",
        50,
        epigraph_engine::admin_cascade::DEFAULT_MAX_FAILURES,
    )
    .await
    .expect("replay");
    assert_eq!((report.applied, report.failed), (1, 0), "{report:?}");

    assert_factors_regenerated(&pool, &w, new).await;
}
