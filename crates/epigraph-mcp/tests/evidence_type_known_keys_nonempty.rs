//! Backlog 7cb71243, through the MCP tool: `submit_ds_evidence` with
//! `evidence_type = "empirical"` warned "is not in the calibration vocabulary
//! ... Known keys: ." (a blank list) whenever the serving process could not
//! read `calibration.toml`, which is every agent container (the host-built
//! binary is bind-mounted without the file). The warning was true: the empty
//! vocabulary combined every typed BBA at the 0.5 unknown-type weight.
//!
//! ONE test in this file, on purpose: the served calibration is a
//! process-wide `LazyLock`, so `CALIBRATION_PATH` must point at a missing file
//! before anything in this process touches it. The sibling
//! `evidence_type_unknown_keys.rs` covers the warning for a genuinely unknown
//! key with the calibration readable.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::tools::ds_auto::ensure_binary_frame;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x7cu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = fixture::scoped_pool(&pool).await;
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

async fn insert_claim(pool: &PgPool, content: &str) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), '7cb71243-agent', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), 0.5, $2, true) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn empirical_is_known_when_calibration_toml_is_unreachable(pool: PgPool) {
    // Before anything reads the served calibration in this process.
    std::env::set_var("CALIBRATION_PATH", "/nonexistent/7cb71243/calibration.toml");

    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.unwrap(), &viewer)
        .await
        .unwrap();

    // A key no calibration knows is still reported (control: the warning path
    // is live), and the warning lists a NON-EMPTY vocabulary (the reported
    // defect was a blank "Known keys: .").
    let c = insert_claim(&pool, "7cb71243 unknown anecdote").await;
    let p = serde_json::from_value(serde_json::json!({
        "claim_id": c.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": {"0": 0.6, "0,1": 0.4},
        "evidence_type": "anecdote",
    }))
    .unwrap();
    let out = first_text(
        &tools::ds::submit_ds_evidence(&server, &viewer, p, None)
            .await
            .expect("submit anecdote"),
    );
    let w = out["warnings"][0].as_str().unwrap_or_default();
    assert!(
        w.contains("\"anecdote\"") && w.contains("0.5 unknown-type"),
        "control: an unknown key is reported; got {out}"
    );
    assert!(
        !w.contains("Known keys: .") && w.contains("empirical"),
        "the known-keys list must carry the shipped vocabulary, not be blank; got {w}"
    );

    // The reported call: empirical must resolve, so no warning at all.
    let c = insert_claim(&pool, "7cb71243 empirical").await;
    let p = serde_json::from_value(serde_json::json!({
        "claim_id": c.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": {"0": 0.6, "0,1": 0.4},
        "evidence_type": "empirical",
    }))
    .unwrap();
    let out = first_text(
        &tools::ds::submit_ds_evidence(&server, &viewer, p, None)
            .await
            .expect("submit empirical"),
    );
    assert!(
        out.get("unknown_keys").is_none() && out.get("warnings").is_none(),
        "evidence_type=\"empirical\" must be in the served vocabulary even when \
         calibration.toml is unreachable; got {out}"
    );
}
