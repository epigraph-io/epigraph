//! `batch_submit_claims` parity with `submit_claim` (backlog 73657204).
//!
//! `BatchClaimEntry` used to carry five of `SubmitClaimParams`'s nine fields and
//! `tools/batch.rs` hard-coded the rest (`methodology:
//! "inductive_generalization"`, `source_url: None`, `reasoning: None`,
//! `novelty_threshold: None`), then kept only `claim_id` out of each entry's
//! `submit_claim` result — and did not even return that, only counts.
//!
//! The behavioural tests build their params from JSON, NOT a struct literal, on
//! purpose: serde ignores unknown fields here, so against the pre-fix types the
//! same payload deserializes, runs, and FAILS on the assertions rather than
//! failing to compile. That is what makes revert -> FAIL a measurement.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use std::collections::BTreeSet;

// ── Schema ratchet ──────────────────────────────────────────────────────────

/// Resolve a local `{"$ref": "#/$defs/X"}` against the schema root.
fn resolve<'a>(root: &'a serde_json::Value, node: &'a serde_json::Value) -> &'a serde_json::Value {
    match node.get("$ref").and_then(serde_json::Value::as_str) {
        Some(r) => {
            let path = r
                .strip_prefix("#/")
                .unwrap_or_else(|| panic!("non-local $ref {r}"));
            path.split('/').fold(root, |n, seg| {
                n.get(seg).unwrap_or_else(|| panic!("dangling $ref {r}"))
            })
        }
        None => node,
    }
}

fn input_schema(tools: &serde_json::Value, tool: &str) -> serde_json::Value {
    tools
        .as_array()
        .expect("all_tools_json is an array")
        .iter()
        .find(|t| t.get("name").and_then(serde_json::Value::as_str) == Some(tool))
        .unwrap_or_else(|| panic!("tool `{tool}` is not registered"))
        .get("inputSchema")
        .expect("inputSchema")
        .clone()
}

fn property_names(schema: &serde_json::Value) -> BTreeSet<String> {
    schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .expect("schema has properties")
        .keys()
        .cloned()
        .collect()
}

/// RATCHET: every property `submit_claim` advertises, a `batch_submit_claims`
/// entry advertises too. Asserted on the router-derived wire schema (what
/// `tools/list` hands a client), not on the Rust types.
#[test]
fn batch_claim_entry_advertises_every_submit_claim_property() {
    let tools = EpiGraphMcpFull::all_tools_json();

    let submit = input_schema(&tools, "submit_claim");
    let submit_props = property_names(&submit);

    let batch = input_schema(&tools, "batch_submit_claims");
    let claims = batch
        .get("properties")
        .and_then(|p| p.get("claims"))
        .expect("batch_submit_claims.claims");
    let items = resolve(&batch, claims.get("items").expect("claims.items"));
    let entry_props = property_names(items);

    let missing: Vec<&String> = submit_props.difference(&entry_props).collect();
    assert!(
        missing.is_empty(),
        "batch_submit_claims entries are missing submit_claim properties {missing:?}; \
         submit_claim = {submit_props:?}, batch entry = {entry_props:?}. Add the field to \
         BatchClaimEntry AND pass it through `From<BatchClaimEntry> for SubmitClaimParams`."
    );
}

// ── Behaviour ───────────────────────────────────────────────────────────────

fn batch_params(v: serde_json::Value) -> epigraph_mcp::types::BatchSubmitClaimsParams {
    serde_json::from_value(v).expect("batch params deserialize")
}

/// Every field an entry carries reaches the stored graph, and each entry's
/// FULL `submit_claim` response comes back.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_entries_pass_every_field_through_and_return_full_responses(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let content = "g15 parity: a batched claim that names its methodology";
    let url = "https://example.org/g15-parity-source";
    let reasoning = "g15 parity: the cited run reproduces the defect deterministically";

    let result = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        &viewer,
        batch_params(serde_json::json!({
            "claims": [{
                "content": content,
                "methodology": "deductive_logic",
                "evidence_data": "g15 parity evidence",
                "evidence_type": "logical",
                "confidence": 0.8,
                "source_url": url,
                "reasoning": reasoning,
                "labels": ["g15-parity"],
                "novelty_threshold": 0.0,
            }]
        })),
        None,
    )
    .await
    .expect("batch call succeeds");
    let json = first_text(&result);
    assert_eq!(json["submitted"], 1, "payload: {json}");
    assert_eq!(json["errors"], 0, "payload: {json}");

    // The stored trace carries the entry's methodology and reasoning, not the
    // hard-coded inductive_generalization / "submitted via MCP" defaults.
    let (reasoning_type, explanation): (String, String) = sqlx::query_as(
        "SELECT t.reasoning_type, t.explanation FROM claims c \
         JOIN reasoning_traces t ON t.id = c.trace_id WHERE c.content = $1",
    )
    .bind(content)
    .fetch_one(&pool)
    .await
    .expect("claim has a canonical trace");
    assert_eq!(
        reasoning_type, "deductive",
        "entry methodology deductive_logic was not passed through"
    );
    assert_eq!(
        explanation, reasoning,
        "entry reasoning was not passed through"
    );

    // source_url lands on the evidence row (serialized into its evidence type).
    let (props,): (String,) = sqlx::query_as(
        "SELECT e.properties::text FROM claims c JOIN evidence e ON e.claim_id = c.id \
         WHERE c.content = $1",
    )
    .bind(content)
    .fetch_one(&pool)
    .await
    .expect("claim has evidence");
    assert!(
        props.contains(url),
        "entry source_url was not passed through; evidence properties = {props}"
    );

    // The full per-entry response: every submit_claim field, plus index/status.
    let row = &json["results"][0];
    assert_eq!(row["index"], 0, "payload: {json}");
    assert_eq!(row["status"], "ok", "payload: {json}");
    for field in ["claim_id", "truth_value", "content_hash", "embedded"] {
        assert!(
            row.get(field).is_some(),
            "results[0] lacks submit_claim's `{field}`; payload: {json}"
        );
    }
    for field in ["belief", "plausibility", "pignistic_prob", "frame_id"] {
        assert!(
            row.get(field).is_some(),
            "results[0] lacks the DS field `{field}` a fresh submit_claim returns; payload: {json}"
        );
    }
    let (id,): (uuid::Uuid,) = sqlx::query_as("SELECT id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row["claim_id"], id.to_string(), "payload: {json}");
}

/// An entry with no methodology is still submitted as inductive_generalization,
/// so existing callers are unchanged.
#[sqlx::test(migrations = "../../migrations")]
async fn a_batch_entry_without_methodology_keeps_the_old_default(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let content = "g15 parity: an entry that names no methodology";

    let result = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        &viewer,
        batch_params(serde_json::json!({
            "claims": [{
                "content": content,
                "evidence_data": "ev",
                "evidence_type": "logical",
            }]
        })),
        None,
    )
    .await
    .expect("batch call succeeds");
    assert_eq!(first_text(&result)["submitted"], 1);

    let (reasoning_type,): (String,) = sqlx::query_as(
        "SELECT t.reasoning_type FROM claims c JOIN reasoning_traces t ON t.id = c.trace_id \
         WHERE c.content = $1",
    )
    .bind(content)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(reasoning_type, "inductive");
}

/// An invalid methodology refuses THAT entry, with a clear error, writes
/// nothing for it, and does not stop its neighbours.
#[sqlx::test(migrations = "../../migrations")]
async fn an_invalid_methodology_refuses_only_its_own_entry(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let good_a = "g15 parity: good entry before the bad one";
    let bad = "g15 parity: entry with a methodology that does not exist";
    let good_b = "g15 parity: good entry after the bad one";

    let result = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        &viewer,
        batch_params(serde_json::json!({
            "claims": [
                {"content": good_a, "evidence_data": "ev", "evidence_type": "logical",
                 "methodology": "direct_observation"},
                {"content": bad, "evidence_data": "ev", "evidence_type": "logical",
                 "methodology": "vibes_based_divination"},
                {"content": good_b, "evidence_data": "ev", "evidence_type": "logical"},
            ]
        })),
        None,
    )
    .await
    .expect("batch call itself succeeds; per-entry failures are reported");
    let json = first_text(&result);

    assert_eq!(json["submitted"], 2, "payload: {json}");
    assert_eq!(json["errors"], 1, "payload: {json}");
    assert_eq!(json["error_details"][0]["index"], 1, "payload: {json}");

    let row = &json["results"][1];
    assert_eq!(row["status"], "error", "payload: {json}");
    let msg = row["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("unknown methodology") && msg.contains("vibes_based_divination"),
        "the refused entry's error must name the bad methodology; got {msg:?}"
    );
    assert_eq!(json["results"][0]["status"], "ok", "payload: {json}");
    assert_eq!(json["results"][2]["status"], "ok", "payload: {json}");

    for (content, want) in [(good_a, 1_i64), (bad, 0), (good_b, 1)] {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM claims WHERE content = $1")
            .bind(content)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, want, "claim count for {content:?}");
    }
    // Nothing partial for the refused entry: no evidence row carries its text.
    let (ev,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM evidence e JOIN claims c ON c.id = e.claim_id WHERE c.content = $1",
    )
    .bind(bad)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(ev, 0, "the refused entry left evidence behind");
}
