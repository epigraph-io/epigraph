//! `submit_ds_evidence` with a whitespace-only `evidence_type` (backlog
//! candidate B101-rest-length-and-whitespace).
//!
//! The tool forks on whether the caller sent an `evidence_type`: with one it
//! stores the RAW masses and leaves the discount to the recompute's
//! calibrated tiers; without one it applies `reliability` to the masses and
//! stores no type. The fork tested the raw string for emptiness BEFORE
//! trimming, but the stored key is trimmed (blank is no key). A
//! whitespace-only type therefore took the calibrated branch (`reliability`
//! ignored) yet stored NULL, so the recompute combined the undiscounted
//! masses at the legacy tier, and the locality tag sent with it was stored.
//! It must behave exactly as if the type were omitted.
//!
//! Params are built from JSON so the file compiles against the pre-fix code
//! and the revert run fails on the assertions.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::tools::ds_auto::ensure_binary_frame;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

const EPS: f64 = 1e-9;

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x6bu8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = fixture::scoped_pool(&pool).await;
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

async fn insert_claim(pool: &PgPool, content: &str) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'evidence-type-blank-agent', 'system',
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

/// Submit with `reliability` 0.5 and a `locality_tag`, so the two branches
/// store different masses and a different tag. Returns the response with its
/// per-call ids removed, for comparison across claims.
async fn submit(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim: Uuid,
    frame: Uuid,
    evidence_type: Option<&str>,
) -> serde_json::Value {
    let mut p = serde_json::json!({
        "claim_id": claim.to_string(),
        "frame_id": frame.to_string(),
        "hypothesis_index": 0,
        "masses": {"0": 0.7, "0,1": 0.3},
        "reliability": 0.5,
        "locality_tag": "intra_self_cite",
    });
    if let Some(et) = evidence_type {
        p["evidence_type"] = serde_json::Value::from(et);
    }
    let mut out = first_text(
        &tools::ds::submit_ds_evidence(server, viewer, serde_json::from_value(p).unwrap(), None)
            .await
            .expect("submit_ds_evidence"),
    );
    let obj = out.as_object_mut().expect("a JSON object response");
    obj.remove("mass_function_id");
    obj.remove("claim_id");
    out
}

/// The stored BBA: m({0}), evidence_type, locality_tag, source_strength.
async fn stored_row(pool: &PgPool, claim: Uuid) -> (f64, Option<String>, String, Option<f64>) {
    sqlx::query_as(
        "SELECT (masses->>'0')::float8, evidence_type::text, locality_tag::text, source_strength \
           FROM mass_functions WHERE claim_id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("exactly one BBA for the claim")
}

async fn cached_belief(pool: &PgPool, claim: Uuid) -> Option<f64> {
    sqlx::query_scalar("SELECT belief FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_whitespace_only_evidence_type_behaves_exactly_like_an_omitted_one(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.unwrap(), &viewer)
        .await
        .unwrap();

    // The omitted baseline, against hand values: reliability 0.5 discounts
    // m({0}) = 0.7 to 0.35, no type is stored, and the tag sent without a
    // type is dropped.
    let omitted = insert_claim(&pool, "evidence type blank: omitted").await;
    let want_resp = submit(&server, &viewer, omitted, frame, None).await;
    let want_row = stored_row(&pool, omitted).await;
    assert!(
        (want_row.0 - 0.35).abs() < EPS,
        "baseline: m({{0}}) is the reliability-discounted 0.35, got {}",
        want_row.0
    );
    assert_eq!(want_row.1, None, "baseline: no evidence_type stored");
    assert_eq!(want_row.2, "unknown", "baseline: the tag is dropped");
    let want_belief = cached_belief(&pool, omitted).await;

    for (tag, et) in [("spaces", "   "), ("tab-newline", "\t\n")] {
        let c = insert_claim(&pool, &format!("evidence type blank: {tag}")).await;
        let resp = submit(&server, &viewer, c, frame, Some(et)).await;
        // Old code: the calibrated branch stored the undiscounted 0.7, the
        // `intra_self_cite` tag, and reported the blank key as unknown.
        assert_eq!(
            stored_row(&pool, c).await,
            want_row,
            "{tag}: the stored BBA is the omitted call's (masses, type, tag, strength)"
        );
        assert_eq!(
            cached_belief(&pool, c).await,
            want_belief,
            "{tag}: the cached belief is the omitted call's"
        );
        assert_eq!(
            resp, want_resp,
            "{tag}: the response (belief, warnings, unknown_keys, unknown_locality_tag) is \
             the omitted call's"
        );
    }
}
