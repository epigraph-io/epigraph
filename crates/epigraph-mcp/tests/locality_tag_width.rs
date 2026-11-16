//! `submit_ds_evidence` and the width of `mass_functions.locality_tag`
//! (backlog 01807a57).
//!
//! The column was `varchar(20)` (migration 045), so a longer tag reached the
//! INSERT and came back as a redacted internal error with nothing written.
//! Migration 228 widens it to `varchar(64)`; the tool refuses a STORED tag
//! longer than that as `invalid_params` before the write, so a caller learns
//! what was wrong instead of getting an internal error.
//!
//! Params are built from JSON so the file compiles against the pre-fix types
//! and the revert run fails on the assertions.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::tools::ds_auto::ensure_binary_frame;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use rmcp::model::{CallToolResult, ErrorCode};
use sqlx::PgPool;
use uuid::Uuid;

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x5fu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = fixture::scoped_pool(&pool).await;
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

async fn insert_claim(pool: &PgPool, content: &str) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'locality-width-agent', 'system',
                 ARRAY['test'])
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

async fn submit(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim: Uuid,
    frame: Uuid,
    evidence_type: Option<&str>,
    locality_tag: &str,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let mut p = serde_json::json!({
        "claim_id": claim.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": {"0": 0.7, "0,1": 0.3},
        "locality_tag": locality_tag,
    });
    if let Some(et) = evidence_type {
        p["evidence_type"] = serde_json::json!(et);
    }
    tools::ds::submit_ds_evidence(server, viewer, serde_json::from_value(p).unwrap(), None).await
}

async fn stored_tags(pool: &PgPool, claim: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT locality_tag::text FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_all(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_28_character_tag_stores_and_an_over_long_one_is_a_parameter_error(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.unwrap(), &viewer)
        .await
        .unwrap();

    // The engine-named tag (28 characters) is stored as given.
    let c = insert_claim(&pool, "locality width 28").await;
    submit(
        &server,
        &viewer,
        c,
        frame,
        Some("empirical"),
        "intra_methodological_overlap",
    )
    .await
    .expect("a 28-character tag is stored");
    assert_eq!(
        stored_tags(&pool, c).await,
        ["intra_methodological_overlap"]
    );

    // 64 characters, multi-byte (more than 64 bytes): still stored, because
    // the limit is counted in characters as varchar counts it.
    let c = insert_claim(&pool, "locality width 64").await;
    let tag64 = "é".repeat(64);
    submit(&server, &viewer, c, frame, Some("empirical"), &tag64)
        .await
        .expect("64 characters is within the column");
    assert_eq!(stored_tags(&pool, c).await, [tag64]);

    // 65 characters: a parameter error naming the limit, and nothing written.
    let c = insert_claim(&pool, "locality width 65").await;
    let err = submit(
        &server,
        &viewer,
        c,
        frame,
        Some("empirical"),
        &"a".repeat(65),
    )
    .await
    .expect_err("a 65-character stored tag is refused");
    assert_eq!(err.code, ErrorCode::INVALID_PARAMS, "{err:?}");
    assert!(
        err.message.contains("65 characters") && err.message.contains("64"),
        "the refusal names the length and the limit: {}",
        err.message
    );
    assert!(
        stored_tags(&pool, c).await.is_empty(),
        "nothing was written"
    );

    // The same tag WITHOUT evidence_type is dropped, not stored, so it is
    // never refused: the BBA lands with "unknown" exactly as before.
    let c = insert_claim(&pool, "locality width dropped").await;
    submit(&server, &viewer, c, frame, None, &"a".repeat(65))
        .await
        .expect("a tag sent without evidence_type is dropped, not refused");
    assert_eq!(stored_tags(&pool, c).await, ["unknown"]);
}
