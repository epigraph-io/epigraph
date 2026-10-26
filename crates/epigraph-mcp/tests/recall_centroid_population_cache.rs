//! `recall_with_context`'s `frac_3072` auto-detect is read through a per-scope
//! cache, not re-counted on every call (backlog be28f3d2).
//!
//! The fraction is two full-table aggregates over `claims` (about 1.25 s per
//! call, flagged as a slow statement). These tests change the corpus between
//! two reads and watch whether the second read sees the change: a cache that
//! re-counts sees it, a standing read does not. Each test also takes a fresh
//! read after the change, so a stand cannot be mistaken for a count that would
//! have returned the same value anyway.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::time::Duration;

use epigraph_mcp::tools::recall::CentroidPopulationCache;
use sqlx::PgPool;
use uuid::Uuid;

fn vec_of(dim: usize) -> String {
    format!("[{}]", vec!["0.5"; dim].join(","))
}

async fn set_embedding_3072(pool: &PgPool, claim: Uuid) {
    sqlx::query("UPDATE claims SET embedding_3072 = $2::vector WHERE id = $1")
        .bind(claim)
        .bind(vec_of(3072))
        .execute(pool)
        .await
        .expect("set embedding_3072");
}

/// A public claim with only the 1536-d vector (the `submit_claim` shape).
async fn seed_embedded_public(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, content).await;
    fixture::set_claim_embedding(pool, id, &vec_of(1536)).await;
    id
}

/// A standing read is served without re-counting, and a fresh read sees the
/// change it hid.
#[sqlx::test(migrations = "../../migrations")]
async fn a_standing_read_is_served_without_recounting(pool: PgPool) {
    let (agent, _group) = fixture::seed_agent_with_group(&pool, "pop-cache-stand").await;
    let claim = seed_embedded_public(&pool, agent, "pop cache stand").await;
    let viewer = fixture::public_viewer(&pool).await;

    let cache = CentroidPopulationCache::with_ttl(Duration::from_secs(3600));
    let first = cache.fraction(&pool, &viewer).await.expect("first read");
    assert_eq!(first, 0.0, "precondition: no claim carries a 3072-d vector");

    set_embedding_3072(&pool, claim).await;

    let second = cache.fraction(&pool, &viewer).await.expect("second read");
    assert_eq!(
        second, 0.0,
        "within the TTL the standing read must be served; re-counting here is the \
         full-table aggregate on every recall that backlog be28f3d2 measured at ~1.25 s"
    );

    // The change is real: a fresh read sees it, so the stand above is the
    // cache and not a count that happened to agree.
    let fresh = cache.refresh(&pool, &viewer).await.expect("fresh read");
    assert_eq!(
        fresh, 1.0,
        "the only embedded claim now carries a 3072-d vector"
    );
    assert_eq!(
        cache.fraction(&pool, &viewer).await.expect("after refresh"),
        1.0,
        "a refresh replaces the standing read"
    );

    // A zero TTL never stands.
    let uncached = CentroidPopulationCache::with_ttl(Duration::ZERO);
    assert_eq!(uncached.fraction(&pool, &viewer).await.unwrap(), 1.0);
    assert!(
        uncached.cached(&viewer).is_none(),
        "a zero TTL holds nothing"
    );
}

/// The cache is keyed by the query's scope binds: a read for one scope never
/// answers for another.
///
/// A group member sees a group-private claim the public viewer cannot. If the
/// cache held ONE slot, the member would be served the public viewer's answer.
#[sqlx::test(migrations = "../../migrations")]
async fn a_read_for_one_scope_never_answers_for_another(pool: PgPool) {
    let (agent, group) = fixture::seed_agent_with_group(&pool, "pop-cache-scope").await;
    seed_embedded_public(&pool, agent, "pop cache public").await;
    let private = fixture::seed_group_claim(&pool, agent, group, "pop cache private").await;
    fixture::set_claim_embedding(&pool, private, &vec_of(1536)).await;
    set_embedding_3072(&pool, private).await;

    let public = fixture::public_viewer(&pool).await;
    let member = epigraph_db::Viewer::resolve(&pool, agent)
        .await
        .expect("resolve the member");

    let cache = CentroidPopulationCache::with_ttl(Duration::from_secs(3600));
    assert_eq!(
        cache.fraction(&pool, &public).await.unwrap(),
        0.0,
        "the public viewer sees only the 1536-only public claim"
    );
    assert_eq!(
        cache.fraction(&pool, &member).await.unwrap(),
        0.5,
        "the member sees both claims, one of them at 3072; a cache keyed on anything \
         coarser than the scope binds serves the public answer here"
    );
    assert_eq!(
        cache.cached(&public),
        Some(0.0),
        "both scopes stand side by side"
    );
    assert_eq!(cache.cached(&member), Some(0.5));
}

/// `recall_with_context`'s auto-detect goes through the SERVER's cache.
///
/// The test server has no embedding key, so the call fails at the query
/// embedding (stage 2), after stage 1 has read the fraction. What matters is
/// that the read now stands on the server for this viewer's scope; before the
/// fix the server held no cache and the next recall counted again.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_auto_detect_reads_through_the_server_cache(pool: PgPool) {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::tools::recall::__test_only::cached_centroid_population;
    use epigraph_mcp::tools::recall::{recall_with_context, RecallWithContextParams};
    use epigraph_mcp::EpiGraphMcpFull;

    let (agent, _group) = fixture::seed_agent_with_group(&pool, "pop-cache-server").await;
    let claim = seed_embedded_public(&pool, agent, "pop cache server").await;
    set_embedding_3072(&pool, claim).await;
    let viewer = fixture::public_viewer(&pool).await;

    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let server = EpiGraphMcpFull::new(pool.clone(), signer, embedder, false);
    assert_eq!(
        cached_centroid_population(&server, &viewer),
        None,
        "precondition: a new server holds no read"
    );

    let params: RecallWithContextParams =
        serde_json::from_value(serde_json::json!({ "query": "pop cache server" })).expect("params");
    let err = recall_with_context(&server, &viewer, params)
        .await
        .expect_err("no embedding key: the call stops at the query embedding");
    assert!(
        !err.message.contains("auto-detect"),
        "stage 1 must have succeeded; got {}",
        err.message
    );

    assert_eq!(
        cached_centroid_population(&server, &viewer),
        Some(1.0),
        "the auto-detect read must stand on the server for this scope, so the next \
         recall does not run the full-table count again"
    );
}

/// An explicit `centroid_dim=3072` is never refused on a STALE zero.
///
/// Auto-detect leaves a standing 0.0 for the scope; the operator then
/// re-embeds at 3072. The explicit-3072 guard refuses only an unpopulated
/// column, so it must re-measure a cached zero rather than turn the caller
/// away for the rest of the TTL.
#[sqlx::test(migrations = "../../migrations")]
async fn explicit_3072_re_measures_a_cached_zero_before_refusing(pool: PgPool) {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::tools::recall::__test_only::cached_centroid_population;
    use epigraph_mcp::tools::recall::{recall_with_context, RecallWithContextParams};
    use epigraph_mcp::EpiGraphMcpFull;

    let (agent, _group) = fixture::seed_agent_with_group(&pool, "pop-cache-explicit").await;
    let claim = seed_embedded_public(&pool, agent, "pop cache explicit").await;
    let viewer = fixture::public_viewer(&pool).await;

    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let server = EpiGraphMcpFull::new(pool.clone(), signer, embedder, false);

    let params = |dim: Option<u32>| -> RecallWithContextParams {
        serde_json::from_value(
            serde_json::json!({ "query": "pop cache explicit", "centroid_dim": dim }),
        )
        .expect("params")
    };

    // Unpopulated: the explicit request is refused, on a fresh read.
    let refused = recall_with_context(&server, &viewer, params(Some(3072)))
        .await
        .expect_err("no 3072 vectors yet");
    assert!(
        refused.message.contains("no populated rows"),
        "precondition: an unpopulated column refuses explicit 3072; got {}",
        refused.message
    );
    assert_eq!(cached_centroid_population(&server, &viewer), Some(0.0));

    set_embedding_3072(&pool, claim).await;

    let err = recall_with_context(&server, &viewer, params(Some(3072)))
        .await
        .expect_err("no embedding key: the call stops at the query embedding");
    assert!(
        !err.message.contains("no populated rows"),
        "the column is populated now; refusing on the cached zero turns the caller away \
         for the whole TTL. got {}",
        err.message
    );
    assert_eq!(
        cached_centroid_population(&server, &viewer),
        Some(1.0),
        "the re-measured value replaces the stale zero"
    );
}
