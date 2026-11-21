//! `submit_ds_evidence` and the width of `mass_functions.evidence_type`
//! (backlog candidate B91-evidence-type-width).
//!
//! The column is `varchar(50)` (migration 001). The tool stores the caller's
//! `evidence_type` canonicalised (trimmed and lowercased, or mapped to its
//! canonical key), and a key the calibration does not know is stored as the
//! caller's own key. A stored key longer than 50 characters reached the INSERT
//! and came back as a redacted internal error (-32603) with nothing written.
//! The tool now refuses it as `invalid_params` (-32602) before any write,
//! counting the STORED form in characters as `varchar` does.
//!
//! Params are built from JSON and the limits are literals, so the file
//! compiles against the pre-fix code and the revert run fails on the
//! assertions.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::tools::ds_auto::ensure_binary_frame;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use rmcp::model::{CallToolResult, ErrorCode};
use sqlx::PgPool;
use uuid::Uuid;

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x6au8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = fixture::scoped_pool(&pool).await;
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

async fn insert_claim(pool: &PgPool, content: &str) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'evidence-type-width-agent', 'system',
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
    evidence_type: &str,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let p = serde_json::json!({
        "claim_id": claim.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": {"0": 0.7, "0,1": 0.3},
        "evidence_type": evidence_type,
    });
    tools::ds::submit_ds_evidence(server, viewer, serde_json::from_value(p).unwrap(), None).await
}

async fn stored_types(pool: &PgPool, claim: Uuid) -> Vec<Option<String>> {
    sqlx::query_scalar("SELECT evidence_type::text FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn frame_assignments(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claim_frames WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A refusal is a parameter error naming the stored length and the limit,
/// and it leaves neither the BBA nor the claim's frame assignment behind.
async fn assert_refused(
    pool: &PgPool,
    claim: Uuid,
    res: Result<CallToolResult, rmcp::ErrorData>,
    stored_len: usize,
) {
    let err = res.expect_err("an over-long stored evidence_type is refused");
    assert_eq!(
        err.code,
        ErrorCode::INVALID_PARAMS,
        "a caller's over-long evidence_type is a parameter error, not an internal one: {err:?}"
    );
    assert!(
        err.message.contains(&format!("{stored_len} characters")) && err.message.contains("50"),
        "the refusal names the stored length and the limit: {}",
        err.message
    );
    assert!(stored_types(pool, claim).await.is_empty(), "no BBA written");
    assert_eq!(
        frame_assignments(pool, claim).await,
        0,
        "no frame assignment written"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_over_long_stored_evidence_type_is_a_parameter_error_with_nothing_written(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.unwrap(), &viewer)
        .await
        .unwrap();

    // 50 characters of an unknown key, multi-byte (100 bytes): stored as
    // given, because the limit is counted in characters as varchar counts it.
    let c = insert_claim(&pool, "evidence type width 50").await;
    let type50 = "é".repeat(50);
    submit(&server, &viewer, c, frame, &type50)
        .await
        .expect("a 50-character evidence_type is within the column");
    assert_eq!(stored_types(&pool, c).await, [Some(type50)]);

    // 51 characters of an unknown key: refused before anything is written.
    // (The old code reached the INSERT: 22001, answered as INTERNAL_ERROR.)
    let c = insert_claim(&pool, "evidence type width 51").await;
    let res = submit(&server, &viewer, c, frame, &"x".repeat(51)).await;
    assert_refused(&pool, c, res, 51).await;

    // A known key padded far past 50 with whitespace and sent mixed-case is
    // stored as its canonical key: the limit applies to what is STORED.
    let c = insert_claim(&pool, "evidence type width padded").await;
    let padded = format!("{}Testimony{}", " ".repeat(40), " ".repeat(40));
    assert!(padded.chars().count() > 50);
    submit(&server, &viewer, c, frame, &padded)
        .await
        .expect("a padded known key canonicalises to a short stored key");
    assert_eq!(
        stored_types(&pool, c).await,
        [Some("testimonial".to_string())]
    );

    // 26 characters as sent, but lowercasing grows each one into two (the
    // dotted capital I lowercases to `i` plus a combining dot), so the STORED
    // key is longer than the column. Counting the raw input would let it
    // through to a 22001.
    let c = insert_claim(&pool, "evidence type width lowercase growth").await;
    let raw = "\u{130}".repeat(26);
    let stored_len = raw.to_lowercase().chars().count();
    assert_eq!(raw.chars().count(), 26);
    assert!(
        stored_len > 50,
        "fixture: the lowercased key must exceed the column ({stored_len})"
    );
    let res = submit(&server, &viewer, c, frame, &raw).await;
    assert_refused(&pool, c, res, stored_len).await;
}
