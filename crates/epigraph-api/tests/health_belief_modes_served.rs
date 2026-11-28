//! `/health` and MCP `system_stats` report the compound-belief mode this
//! process SERVES beside the one it was CONFIGURED with (backlog 820c15f1).
//!
//! `EPIGRAPH_COMPOUND_BELIEF=progressive|strict` is parsed and reported, but
//! this build does not wire either mode: `CompoundBeliefMode::serving` maps
//! both to `legacy`. Before this report an operator reading `/health` saw
//! `compound_belief: strict` and had no way to learn from it that every
//! compound was still served its legacy value.
//!
//! - `belief_modes` stays the configured value: the cross-process skew check
//!   (SPEC §10.4, `epigraph-cli`'s `belief_mode_check`) compares it, and its
//!   contract is unchanged;
//! - `belief_modes_served` carries what the process actually serves, and the
//!   two surfaces agree on it;
//! - the two flags this build does not act on are reported as what is served
//!   whatever is configured: `EPIGRAPH_INFERENCE=on` serves `off` (no
//!   inference layer runs) and `EPIGRAPH_ATOM_CACHE_MODE=pure` serves
//!   `display`.
//!
//! The modes are read once per process, so this binary holds one test and
//! sets the environment before anything reads it.

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::{body::Body, http::Request};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test(migrations = "../../migrations")]
async fn a_configured_strict_mode_is_reported_as_served_legacy_on_both_surfaces(pool: PgPool) {
    std::env::set_var("EPIGRAPH_COMPOUND_BELIEF", "strict");
    std::env::set_var("EPIGRAPH_INFERENCE", "on");
    std::env::set_var("EPIGRAPH_ATOM_CACHE_MODE", "pure");

    // REST: /health.
    let router = create_router(AppState::new(ApiConfig {
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "http://localhost:8080".to_string(),
        ..ApiConfig::default()
    }));
    let response = router
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let health: serde_json::Value = serde_json::from_slice(&bytes).expect("/health is JSON");

    assert_eq!(
        health["belief_modes"]["compound_belief"], "strict",
        "belief_modes keeps the CONFIGURED mode (the skew check compares it): {health}"
    );
    assert_eq!(
        health["belief_modes_served"]["compound_belief"], "legacy",
        "strict is not wired in this build, so it is served as legacy: {health}"
    );
    assert_eq!(health["belief_modes"]["inference"], "on", "{health}");
    assert_eq!(
        health["belief_modes_served"]["inference"], "off",
        "inference is not acted on in this build, so none is served: {health}"
    );
    assert_eq!(
        health["belief_modes"]["atom_cache_mode"], "pure",
        "{health}"
    );
    assert_eq!(
        health["belief_modes_served"]["atom_cache_mode"], "display",
        "atom_cache_mode is not acted on in this build: {health}"
    );

    // The configured report is still exactly what the CLI skew check parses.
    let configured: epigraph_engine::belief_modes::BeliefModes =
        serde_json::from_value(health["belief_modes"].clone())
            .expect("belief_modes still parses as BeliefModes");
    assert_eq!(
        configured.compound_belief(),
        epigraph_engine::belief_modes::CompoundBelief::Strict
    );

    // MCP: system_stats, as an anonymous caller would see it.
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x5Bu8; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None);
    let server = epigraph_mcp::EpiGraphMcpFull::new(pool.clone(), signer, embedder, false)
        .with_scoped_pool(fixture::scoped_pool(&pool).await);
    let viewer = fixture::public_viewer(&pool).await;
    let result = epigraph_mcp::tools::batch::system_stats(
        &server,
        &viewer,
        epigraph_mcp::types::SystemStatsParams { detailed: None },
    )
    .await
    .expect("system_stats");
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("system_stats returns a text block");
    let stats: serde_json::Value = serde_json::from_str(&text).expect("system_stats is JSON");

    assert_eq!(
        stats["belief_modes"]["compound_belief"], "strict",
        "{stats}"
    );
    assert_eq!(
        stats.get("belief_modes_served"),
        health.get("belief_modes_served"),
        "/health and system_stats must report the same served modes: {stats}"
    );
}
