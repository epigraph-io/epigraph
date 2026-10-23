//! MCP `system_stats` and REST `/health` report the same belief modes
//! (SPEC §10.2, "Visibility").
//!
//! The pre-flip mode check (SPEC §10.4) reads the modes of every live
//! process, and an operator (or a CLI wave bin) may read either surface. If
//! the two disagreed inside ONE process, that check would compare different
//! things depending on which door it knocked on.
//!
//! The modes are process-global, so this binary holds one test and sets the
//! environment before anything reads it. Every flag is set to a NON-default
//! value, so "both report the defaults" cannot pass for agreement; and the
//! comparison is on the wire JSON of each surface, so a surface that spelled a
//! value differently (or left a flag out) fails.

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::{body::Body, http::Request};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use sqlx::PgPool;
use tower::ServiceExt;

const SET: [(&str, &str); 7] = [
    ("EPIGRAPH_ATOM_FOLD", "aef"),
    ("EPIGRAPH_COMPOUND_BELIEF", "progressive"),
    ("EPIGRAPH_COMPOUND_WRITE_GUARD", "refuse"),
    ("EPIGRAPH_COMPOUND_SOURCE_EDGES", "excluded"),
    ("EPIGRAPH_ATOM_CACHE_MODE", "pure"),
    ("EPIGRAPH_INFERENCE", "on"),
    ("EPIGRAPH_BP_APPLY", "on"),
];

/// The values every flag takes when it is unset (SPEC §10.2: every default is
/// today's behaviour).
fn defaults() -> serde_json::Value {
    serde_json::json!({
        "atom_fold": "legacy",
        "compound_belief": "legacy",
        "compound_write_guard": "warn",
        "compound_source_edges": "frozen",
        "atom_cache_mode": "display",
        "inference": "off",
        "bp_apply": "off",
    })
}

#[sqlx::test(migrations = "../../migrations")]
async fn system_stats_and_health_report_the_same_belief_modes(pool: PgPool) {
    for (env, value) in SET {
        std::env::set_var(env, value);
    }

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

    // MCP: system_stats, as an anonymous caller would see it.
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x5Au8; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None);
    let server = epigraph_mcp::EpiGraphMcpFull::new(pool.clone(), signer, embedder, false);
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

    let from_health = health
        .get("belief_modes")
        .unwrap_or_else(|| panic!("/health has no belief_modes: {health}"));
    let from_stats = stats
        .get("belief_modes")
        .unwrap_or_else(|| panic!("system_stats has no belief_modes: {stats}"));

    assert_eq!(
        from_health, from_stats,
        "/health and system_stats must report the same belief modes"
    );
    // Agreement must be about THIS process's modes. With every flag set to a
    // non-default value, no field may still read its default.
    let defaults = defaults();
    let reported = from_stats.as_object().expect("belief_modes is an object");
    assert_eq!(reported.len(), 7, "seven flags: {from_stats}");
    for (key, default) in defaults.as_object().unwrap() {
        let got = reported
            .get(key)
            .unwrap_or_else(|| panic!("belief_modes.{key} missing: {from_stats}"));
        assert_ne!(
            got, default,
            "belief_modes.{key} reads its default although its flag is set: {from_stats}"
        );
    }
}
