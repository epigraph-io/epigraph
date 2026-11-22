//! Backlog 3676c459: the MCP edge-CREATE tools refuse a reserved edge
//! property, as `POST /api/v1/edges` and MCP `patch_edge` already do.
//!
//! `epigraph_db::RESERVED_EDGE_PROPERTIES` are the keys only an act or the
//! document ingest writes: the dedup identity, the supersession act's marker
//! (`supersede_act`, which the supersede cascade keys on to leave an act edge
//! on the claim it records), the ingest's own record keys and the authorship
//! replacement key. `link_epistemic` and `link_hierarchical` passed the
//! caller's `properties` straight to the edge writer, so any MCP writer could
//! forge an act edge. The database guards only some of these keys (`dedup`,
//! `ingest_written`); `supersede_act` and the ingest-record keys had no guard
//! at all.
//!
//! Each tool must answer every reserved key with exactly the HTTP route's
//! refusal text (`epigraph_db::reserved_edge_property_refusal`) and write
//! nothing. CALIBRATION: an ordinary property spelling a supersession `tool`
//! value still lands, so the refusal is about the reserved KEY.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::tools::link_epistemic::do_link_epistemic;
use epigraph_mcp::tools::link_hierarchical::do_link_hierarchical;
use epigraph_mcp::types::{LinkEpistemicParams, LinkHierarchicalParams};
use sqlx::PgPool;
use uuid::Uuid;

/// Every edge between `a` and `b` in either direction, in force or not.
async fn edges_between(pool: &PgPool, a: Uuid, b: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges \
          WHERE (source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await
    .expect("count edges")
}

/// A body carrying `key`, the shape a forger would send.
fn carrying(key: &str) -> serde_json::Value {
    serde_json::json!({ key: "supersede_claim", "note": "forged" })
}

/// The exact refusal the HTTP edges route answers for `properties`.
fn http_refusal(properties: &serde_json::Value) -> &'static str {
    epigraph_db::reserved_edge_property_refusal(properties)
        .unwrap_or_else(|| panic!("CALIBRATION: {properties} carries a reserved key"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn link_epistemic_refuses_every_reserved_edge_property(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let link = |a: Uuid, b: Uuid, properties: serde_json::Value| LinkEpistemicParams {
        source_claim_id: a.to_string(),
        target_claim_id: b.to_string(),
        relationship: "supports".to_string(),
        properties: Some(properties),
    };

    // CALIBRATION: the same body under an ordinary key lands.
    let (a, b) = (
        seed_claim(&pool, "reserved key calibration a", 0.5).await,
        seed_claim(&pool, "reserved key calibration b", 0.5).await,
    );
    do_link_epistemic(
        &server,
        &viewer,
        link(a, b, serde_json::json!({"tool": "supersede_claim"})),
        None,
    )
    .await
    .expect("CALIBRATION: an ordinary property is accepted");
    assert_eq!(edges_between(&pool, a, b).await, 1, "CALIBRATION: written");

    for key in epigraph_db::RESERVED_EDGE_PROPERTIES {
        let a = seed_claim(&pool, &format!("epistemic {key} a"), 0.5).await;
        let b = seed_claim(&pool, &format!("epistemic {key} b"), 0.5).await;
        let properties = carrying(key);
        let err = do_link_epistemic(&server, &viewer, link(a, b, properties.clone()), None)
            .await
            .expect_err(&format!("link_epistemic refuses properties.{key}"));
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INVALID_PARAMS,
            "{key}: {err:?}"
        );
        assert_eq!(
            err.message,
            http_refusal(&properties),
            "{key}: the HTTP route's refusal text"
        );
        assert_eq!(edges_between(&pool, a, b).await, 0, "{key}: nothing written");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn link_hierarchical_refuses_every_reserved_edge_property(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let link = |a: Uuid, b: Uuid, properties: serde_json::Value| LinkHierarchicalParams {
        source_claim_id: a.to_string(),
        target_claim_id: b.to_string(),
        relationship: "decomposes_to".to_string(),
        properties: Some(properties),
        ..Default::default()
    };

    let (a, b) = (
        seed_claim(&pool, "hierarchical calibration a", 0.5).await,
        seed_claim(&pool, "hierarchical calibration b", 0.5).await,
    );
    do_link_hierarchical(
        &server,
        &viewer,
        link(a, b, serde_json::json!({"tool": "supersede_claim"})),
        None,
    )
    .await
    .expect("CALIBRATION: an ordinary property is accepted");
    assert_eq!(edges_between(&pool, a, b).await, 1, "CALIBRATION: written");

    for key in epigraph_db::RESERVED_EDGE_PROPERTIES {
        let a = seed_claim(&pool, &format!("hierarchical {key} a"), 0.5).await;
        let b = seed_claim(&pool, &format!("hierarchical {key} b"), 0.5).await;
        let properties = carrying(key);
        let err = do_link_hierarchical(&server, &viewer, link(a, b, properties.clone()), None)
            .await
            .expect_err(&format!("link_hierarchical refuses properties.{key}"));
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INVALID_PARAMS,
            "{key}: {err:?}"
        );
        assert_eq!(
            err.message,
            http_refusal(&properties),
            "{key}: the HTTP route's refusal text"
        );
        assert_eq!(edges_between(&pool, a, b).await, 0, "{key}: nothing written");
    }
}
