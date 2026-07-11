//! Regression tests for the write-side semantic novelty gate (backlog
//! `1bcaed94`, Task 6.4) as wired into `submit_claim` / `memorize`.
//!
//! Test-strategy note (documented per the task brief's explicit fallback):
//! every MCP integration test server in this crate is built with
//! `McpEmbedder::new(pool, None)` — mock mode, no OpenAI API key (see
//! `tool_resubmit_tests.rs`, `memorize_persists_labels.rs`,
//! `submit_claim_labels_test.rs`). `McpEmbedder::generate` unconditionally
//! errors in that mode, so `novelty_gate::decide` always returns `None` and
//! the gate never actually fires through `submit_claim`/`memorize` in this
//! test process — there is no way to exercise a REAL embedding end-to-end
//! without either a live OpenAI key or refactoring `EpiGraphMcpFull` to take
//! a trait-object embedder (out of scope for this task; `EpiGraphMcpFull`
//! is concretely typed over `McpEmbedder`, which hardcodes the OpenAI
//! endpoint).
//!
//! So this file proves the two things that ARE testable end-to-end at the
//! MCP layer without a live embedder:
//!   1. `submit_claim`'s new read-only content-hash pre-check (added ahead
//!      of the gate so an exact resubmit skips it entirely — see
//!      `novelty_gate` module docs and claims.rs's `is_exact_resubmit`)
//!      still composes correctly with `create_claim_idempotent`'s existing
//!      dedup: a byte-identical resubmit returns the same claim id and the
//!      claims table never grows past 1 row for that content_hash, at ANY
//!      `novelty_threshold` value. NOTE: because the embedder is mocked
//!      here, the gate never actually fires in this test — so this does
//!      NOT prove the ordering guard is load-bearing (with the gate
//!      permanently inert here, removing the guard would not fail this
//!      test either). It proves the new param is wire-compatible with the
//!      pre-existing dedup path. The embed -> ANN -> classify ordering
//!      itself IS exercised for real in
//!      `novelty_gate.rs`'s `decide_*` tests (see below).
//!   2. When the embedder can't produce a vector (today's universal test
//!      condition, and a real production condition on embedder outage), the
//!      gate degrades to a no-op and every distinct submission inserts
//!      normally, for ANY `novelty_threshold` including the escape hatch —
//!      the feature must never turn a working write path into a blocked one.
//!
//! The gate's actual distance-threshold DECISION logic (dist<0.05 →
//! suppress, dist<0.15 → flag, else insert; 0.0 → never suppress), including
//! the full embed -> ANN -> classify pipeline with a REAL (non-network,
//! deterministic) embedder, is covered by:
//!   - `crates/epigraph-db/tests/claim_nearest_by_embedding.rs` (the ANN
//!     repo-layer query `ClaimRepository::nearest_by_embedding`, hand-inserted
//!     pgvector embeddings)
//!   - `crates/epigraph-mcp/src/tools/novelty_gate.rs`'s `#[cfg(test)]`
//!     module: the pure `classify` function (all boundary conditions), AND
//!     `decide_*` tests that run `decide()` end-to-end against the real DB
//!     using `epigraph_embeddings::MockProvider` (a real deterministic
//!     hash-derived embedder, not a stub of the decision logic).
//!
//! What is NOT covered anywhere: `submit_claim`/`memorize`'s glue code that
//! ACTS on a fired decision — the `ReturnExisting` early-return response
//! shape, the `near-duplicate` label append, and the pending-vector reuse
//! into `store_embedding` — because exercising that requires a decision to
//! actually fire through the concrete `EpiGraphMcpFull` server, which only
//! ever holds a real `McpEmbedder` (hardcoded OpenAI endpoint). That code
//! is verified by inspection only. See the task report for the full
//! coverage boundary.

#[macro_use]
mod common;

use common::*;
use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_mcp::types::{MemorizeParams, SubmitClaimParams};
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

fn build_test_server(pool: PgPool, signer_seed: [u8; 32]) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&signer_seed).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None); // mock — no API key
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

async fn claims_with_content_hash_count(pool: &PgPool, content: &str) -> i64 {
    let hash = ContentHasher::hash(content.as_bytes());
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM claims WHERE content_hash = $1")
        .bind(hash.as_slice())
        .fetch_one(pool)
        .await
        .expect("count claims by content_hash")
}

/// `evidence_data` must be unique per (claim, evidence-text) — the schema's
/// `evidence_content_hash_claim_unique` constraint is `(content_hash,
/// claim_id)` — so callers that resubmit the SAME content (same claim id)
/// must vary `evidence_data` across calls, matching the pattern in
/// `tool_resubmit_tests.rs::submit_claim_resubmit_creates_evidence_trace_via_edges`.
fn submit_params(
    content: &str,
    evidence_data: &str,
    novelty_threshold: Option<f64>,
) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.to_string(),
        methodology: "deductive_logic".to_string(),
        evidence_data: evidence_data.to_string(),
        evidence_type: "logical".to_string(),
        confidence: 0.7,
        source_url: None,
        reasoning: None,
        labels: vec![],
        novelty_threshold,
    }
}

/// `submit_claim` now carries a `novelty_threshold` param and a new
/// read-only content-hash existence check (`is_exact_resubmit` in
/// claims.rs) ahead of `create_claim_idempotent`. This proves that addition
/// doesn't regress the pre-existing exact-content dedup: a byte-identical
/// resubmit still returns the same claim id, and the row count for that
/// content_hash never exceeds 1, for any `novelty_threshold` value.
///
/// Does NOT prove the gate-after-hash-check ordering is load-bearing — the
/// embedder is mocked in every MCP test server in this crate, so the gate
/// never fires here regardless of check order. See the module doc comment.
#[tokio::test]
async fn exact_resubmit_still_dedups_with_novelty_threshold_param_present() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;
    let server = build_test_server(pool.clone(), [0x61u8; 32]);

    let content = format!("novelty-gate exact-resubmit test {}", Uuid::new_v4());

    let first = tools::claims::submit_claim(&server, submit_params(&content, "ev-0", None))
        .await
        .expect("first submit_claim");
    let first_id = first_text_claim_id(&first);

    // Resubmit the SAME content with a variety of novelty_threshold values,
    // including 0.0 (the escape hatch) — none of these should matter,
    // because the exact-hash pre-check must fire before the gate is ever
    // consulted. Evidence text varies per call (schema requires distinct
    // (content_hash, claim_id) on evidence — unrelated to the gate).
    for (i, threshold) in [None, Some(0.05), Some(0.0), Some(1.0)]
        .into_iter()
        .enumerate()
    {
        let evidence = format!("ev-{}", i + 1);
        let again =
            tools::claims::submit_claim(&server, submit_params(&content, &evidence, threshold))
                .await
                .unwrap_or_else(|e| panic!("resubmit with threshold {threshold:?} failed: {e:?}"));
        let again_id = first_text_claim_id(&again);
        assert_eq!(
            again_id, first_id,
            "resubmit (threshold={threshold:?}) must return the SAME claim id as the first submit"
        );
    }

    let row_count = claims_with_content_hash_count(&pool, &content).await;
    assert_eq!(
        row_count, 1,
        "exact-content resubmits must never grow the claims table beyond 1 row for this content_hash"
    );
}

/// When the embedder cannot produce a vector (mock mode — every test server
/// in this crate; also the real production degrade-path on an OpenAI
/// outage), `novelty_gate::decide` returns `None` and submit_claim must
/// fall back to inserting exactly as it did before this feature existed —
/// for genuinely new (non-duplicate) content, at ANY `novelty_threshold`
/// value, including the nominal "always suppress near-dupes" default. The
/// gate must never turn an embedder outage into a blocked write.
#[tokio::test]
async fn distinct_content_inserts_normally_when_embedder_unavailable() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;
    let server = build_test_server(pool.clone(), [0x62u8; 32]);

    for (i, threshold) in [None, Some(0.05), Some(0.0)].into_iter().enumerate() {
        let content = format!("novelty-gate distinct content {i} {}", Uuid::new_v4());
        let result = tools::claims::submit_claim(&server, submit_params(&content, "ev", threshold))
            .await
            .unwrap_or_else(|e| panic!("submit_claim (threshold={threshold:?}) failed: {e:?}"));
        let claim_id = first_text_claim_id(&result);

        let row_count = claims_with_content_hash_count(&pool, &content).await;
        assert_eq!(
            row_count, 1,
            "distinct content must insert exactly one row (threshold={threshold:?})"
        );

        // Confirm the returned id really is a freshly-inserted row, not a
        // stale/foreign one, and it is NOT flagged near-duplicate (nothing
        // in the corpus is close to this random UUID-suffixed content).
        let labels: Vec<String> = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
            .bind(Uuid::parse_str(&claim_id).expect("claim_id is a uuid"))
            .fetch_one(&pool)
            .await
            .expect("fetch labels");
        assert!(
            !labels.iter().any(|l| l == "near-duplicate"),
            "unrelated content must not be flagged near-duplicate, got {labels:?}"
        );
    }
}

/// Same guarantee as above, through `memorize` instead of `submit_claim` —
/// Step 4 of the backlog task ("apply the same gate to memorize").
#[tokio::test]
async fn memorize_distinct_content_inserts_normally_when_embedder_unavailable() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;
    let server = build_test_server(pool.clone(), [0x63u8; 32]);

    let content = format!("novelty-gate memorize distinct {}", Uuid::new_v4());
    let params = MemorizeParams {
        content: content.clone(),
        confidence: Some(0.7),
        tags: None,
        novelty_threshold: Some(0.05),
    };
    tools::memory::memorize(&server, params)
        .await
        .expect("memorize");

    let row_count = claims_with_content_hash_count(&pool, &content).await;
    assert_eq!(
        row_count, 1,
        "memorize of distinct content must insert one row"
    );
}

/// Pull `claim_id` out of a `submit_claim`/`memorize` `CallToolResult`.
/// Mirrors `extract_submit_claim_id` in `src/tools/claims.rs` (not reused
/// directly since that helper is private to the crate's src tree, not
/// exported to integration tests).
fn first_text_claim_id(result: &rmcp::model::CallToolResult) -> String {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .expect("result has text content");
    let parsed: serde_json::Value = serde_json::from_str(text).expect("valid json");
    parsed
        .get("claim_id")
        .and_then(|v| v.as_str())
        .expect("claim_id present")
        .to_string()
}
