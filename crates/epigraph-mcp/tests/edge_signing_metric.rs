//! Backlog `dae795f8` step 4: the unsigned-edge count is a queryable metric.
//! `system_stats(detailed: true)` reports `edges_signed` / `edges_unsigned`
//! over the edges the caller may read, so the edge-signing gap is visible.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use common::{build_test_server, first_text};
use epigraph_crypto::AgentSigner;
use epigraph_db::repos::edge_signature::EdgeSignatureRepository;
use epigraph_db::visibility::Viewer;
use epigraph_db::EdgeRepository;
use epigraph_mcp::types::SystemStatsParams;
use epigraph_mcp::{tools, EpiGraphMcpFull};
use sqlx::PgPool;

async fn stats(server: &EpiGraphMcpFull, viewer: &Viewer) -> (i64, i64) {
    let v = first_text(
        &tools::batch::system_stats(
            server,
            viewer,
            SystemStatsParams {
                detailed: Some(true),
            },
        )
        .await
        .expect("detailed stats"),
    );
    let n = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_else(|| panic!("system_stats detailed must report `{k}`: {v}"))
    };
    (n("edges_signed"), n("edges_unsigned"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn detailed_stats_count_signed_and_unsigned_edges_for_the_caller(pool: PgPool) {
    let signer = AgentSigner::from_bytes(&[0x81; 32]).expect("signer");
    let (w, w_group) = fixture::seed_agent_with_group(&pool, "metric-writer").await;
    sqlx::query("UPDATE agents SET public_key = $2 WHERE id = $1")
        .bind(w)
        .bind(signer.public_key().as_slice())
        .execute(&pool)
        .await
        .expect("register the signer's key");
    let (stranger, _) = fixture::seed_agent_with_group(&pool, "metric-stranger").await;
    let w_viewer = Viewer::resolve(&pool, w).await.expect("viewer");
    let s_viewer = Viewer::resolve(&pool, stranger).await.expect("viewer");
    let server = build_test_server(pool.clone());

    let (w_signed0, w_unsigned0) = stats(&server, &w_viewer).await;
    let (s_signed0, s_unsigned0) = stats(&server, &s_viewer).await;

    let a = fixture::seed_public_claim(&pool, w, "metric A").await;
    let b = fixture::seed_public_claim(&pool, w, "metric B").await;
    let private = fixture::seed_group_claim(&pool, w, w_group, "metric private").await;
    let signed =
        EdgeRepository::create(&pool, a, "claim", b, "claim", "supports", None, None, None)
            .await
            .expect("edge");
    let mut conn = pool.acquire().await.expect("acquire");
    EdgeSignatureRepository::sign_created_edge_conn(&mut conn, signed, &signer, w)
        .await
        .expect("sign");
    drop(conn);
    // Unsigned, and group-private (the tenancy trigger gives it the meet).
    EdgeRepository::create(
        &pool, a, "claim", private, "claim", "supports", None, None, None,
    )
    .await
    .expect("edge");

    assert_eq!(
        stats(&server, &w_viewer).await,
        (w_signed0 + 1, w_unsigned0 + 1),
        "the writer sees its signed public edge and its unsigned private one"
    );
    assert_eq!(
        stats(&server, &s_viewer).await,
        (s_signed0 + 1, s_unsigned0),
        "a stranger's counts include the public edge and not the private one"
    );
}
