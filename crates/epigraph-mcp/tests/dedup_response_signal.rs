//! A dedup hit must SAY it is one (backlog a3e63a12, G11).
//!
//! Before this, `submit_claim` / `memorize` answered an exact-content resubmit
//! with a response byte-for-byte shaped like a fresh insert, so a caller could
//! not tell that its confidence never reached the belief, or which of its
//! inputs had been recorded at all. Every test here also MEASURES the
//! `inputs_applied` claim it asserts against the stored graph, so the lists are
//! pinned to what the write path actually does rather than to the wording.
//!
//! The novelty-gate arm cannot be fired through `EpiGraphMcpFull` in a test
//! process — its `McpEmbedder` hard-codes the OpenAI endpoint (see the header of
//! `novelty_gate_test.rs`). Its `deduplicated` block is pinned by the unit tests
//! beside `tools::claims::dedup_block` and `tools::memory::memorize_dedup_block`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::types::{MemorizeParams, SubmitClaimParams};
use sqlx::PgPool;

fn submit(content: &str, evidence: &str, labels: &[&str]) -> SubmitClaimParams {
    SubmitClaimParams {
        content: content.into(),
        methodology: "direct_observation".into(),
        evidence_data: evidence.into(),
        evidence_type: "logical".into(),
        confidence: 0.8,
        source_url: Some("https://example.org/g11".into()),
        reasoning: Some("g11 reasoning".into()),
        labels: labels.iter().map(|s| (*s).to_string()).collect(),
        novelty_threshold: None,
    }
}

fn strs(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .unwrap_or_else(|| panic!("expected an array, got {v}"))
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_reports_a_content_hash_hit_and_what_it_kept(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let content = "g11: an exact resubmit must be reported as one";

    let first = first_text(
        &epigraph_mcp::tools::claims::submit_claim(
            &server,
            &viewer,
            submit(content, "first evidence", &["g11-a"]),
        )
        .await
        .expect("first submit"),
    );
    assert!(
        first.get("deduplicated").is_none(),
        "a fresh insert must not carry a deduplicated block: {first}"
    );

    let mut again = submit(content, "second, different evidence", &["g11-b"]);
    again.novelty_threshold = Some(0.2);
    let second = first_text(
        &epigraph_mcp::tools::claims::submit_claim(&server, &viewer, again)
            .await
            .expect("resubmit"),
    );

    let d = second
        .get("deduplicated")
        .unwrap_or_else(|| panic!("a content-hash hit returned no deduplicated block: {second}"));
    assert_eq!(d["by"], "content_hash", "{second}");
    assert_eq!(d["existing_claim_id"], first["claim_id"], "{second}");
    assert_eq!(second["claim_id"], first["claim_id"], "{second}");

    let applied = strs(&d["inputs_applied"]);
    for want in [
        "labels",
        "evidence_data",
        "evidence_type",
        "source_url",
        "methodology",
        "reasoning",
        "confidence",
    ] {
        assert!(
            applied.contains(&want.to_string()),
            "{want} not in inputs_applied: {d}"
        );
    }
    assert_eq!(
        strs(&d["inputs_discarded"]),
        vec!["novelty_threshold"],
        "{d}"
    );

    // MEASURED: the labels really were merged, and a second evidence row really
    // was written, so "applied" is true of both.
    let (labels,): (Vec<String>,) = sqlx::query_as("SELECT labels FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        labels.contains(&"g11-a".to_string()) && labels.contains(&"g11-b".to_string()),
        "labels were not merged: {labels:?}"
    );
    let (evidence,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM evidence e JOIN claims c ON c.id = e.claim_id WHERE c.content = $1",
    )
    .bind(content)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(evidence, 2, "the resubmit's evidence row was not recorded");

    // And none of it moved the belief: the DS block is absent on the hit.
    assert!(second.get("belief").is_none(), "{second}");
}

/// `source_url` on `empirical` evidence has no slot in the stored evidence type,
/// so the hit must list it as discarded rather than applied.
#[sqlx::test(migrations = "../../migrations")]
async fn an_empirical_source_url_is_reported_discarded(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let content = "g11: empirical evidence keeps no url";
    let mut p = submit(content, "ev", &[]);
    p.evidence_type = "empirical".into();
    epigraph_mcp::tools::claims::submit_claim(&server, &viewer, p)
        .await
        .unwrap();

    let mut p = submit(content, "ev two", &[]);
    p.evidence_type = "empirical".into();
    let url = p.source_url.clone().unwrap();
    let second = first_text(
        &epigraph_mcp::tools::claims::submit_claim(&server, &viewer, p)
            .await
            .unwrap(),
    );
    let d = &second["deduplicated"];
    assert!(
        strs(&d["inputs_discarded"]).contains(&"source_url".to_string()),
        "{second}"
    );
    assert!(
        !strs(&d["inputs_applied"]).contains(&"source_url".to_string()),
        "{second}"
    );
    // MEASURED: no evidence row for this claim carries the url anywhere.
    let (hits,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM evidence e JOIN claims c ON c.id = e.claim_id \
         WHERE c.content = $1 AND (e.properties::text LIKE '%' || $2 || '%' \
                                   OR e.source_url = $2)",
    )
    .bind(content)
    .bind(&url)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        hits, 0,
        "the url was stored after all; the list would be wrong"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn memorize_reports_a_content_hash_hit(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let content = "g11: a memory stored twice";

    let first = first_text(
        &epigraph_mcp::tools::memory::memorize(
            &server,
            &viewer,
            MemorizeParams {
                content: content.into(),
                confidence: Some(0.7),
                tags: Some(vec!["g11-m1".into()]),
                novelty_threshold: None,
            },
        )
        .await
        .unwrap(),
    );
    assert!(first.get("deduplicated").is_none(), "{first}");

    let second = first_text(
        &epigraph_mcp::tools::memory::memorize(
            &server,
            &viewer,
            MemorizeParams {
                content: content.into(),
                confidence: Some(0.9),
                tags: Some(vec!["g11-m2".into()]),
                novelty_threshold: None,
            },
        )
        .await
        .unwrap(),
    );
    let d = second
        .get("deduplicated")
        .unwrap_or_else(|| panic!("memorize dedup hit carried no block: {second}"));
    assert_eq!(d["by"], "content_hash");
    assert_eq!(d["existing_claim_id"], first["claim_id"]);
    assert_eq!(strs(&d["inputs_applied"]), vec!["tags"], "{d}");
    // The existing memory already had a trace, so this call wrote no
    // Evidence/Trace and its confidence went nowhere.
    assert_eq!(strs(&d["inputs_discarded"]), vec!["confidence"], "{d}");

    // MEASURED: exactly one trace, i.e. nothing recorded the second confidence.
    let (traces,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM reasoning_traces t JOIN claims c ON c.id = t.claim_id \
         WHERE c.content = $1",
    )
    .bind(content)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        traces, 1,
        "a second trace was written; confidence was applied"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn batch_submit_claims_reports_dedup_per_entry(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let content = "g11: the same claim twice in one batch";

    let params: epigraph_mcp::types::BatchSubmitClaimsParams =
        serde_json::from_value(serde_json::json!({
            "claims": [
                {"content": content, "evidence_data": "one", "evidence_type": "logical"},
                {"content": content, "evidence_data": "two", "evidence_type": "logical"},
            ]
        }))
        .unwrap();
    let json = first_text(
        &epigraph_mcp::tools::batch::batch_submit_claims(&server, &viewer, params)
            .await
            .unwrap(),
    );
    assert_eq!(json["submitted"], 2, "{json}");
    assert!(json["results"][0].get("deduplicated").is_none(), "{json}");
    let d = &json["results"][1]["deduplicated"];
    assert_eq!(d["by"], "content_hash", "{json}");
    assert_eq!(
        d["existing_claim_id"], json["results"][0]["claim_id"],
        "{json}"
    );
}

/// G11/G15 review: a batch entry that OMITS methodology and confidence gets the
/// batch defaults, and `Deduplicated` lists only inputs the caller supplied, so
/// neither may appear in either list. The same entry with both supplied must
/// list both as applied (the content-hash path writes a reasoning trace
/// carrying them).
#[sqlx::test(migrations = "../../migrations")]
async fn batch_dedup_lists_only_inputs_the_entry_supplied(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let omitted = "g11 review: defaults are not inputs (omitted)";
    let supplied = "g11 review: defaults are not inputs (supplied)";

    let params: epigraph_mcp::types::BatchSubmitClaimsParams =
        serde_json::from_value(serde_json::json!({
            "claims": [
                {"content": omitted, "evidence_data": "one", "evidence_type": "logical"},
                {"content": omitted, "evidence_data": "two", "evidence_type": "logical",
                 "labels": ["g11-review"]},
                {"content": supplied, "evidence_data": "one", "evidence_type": "logical",
                 "methodology": "deductive_logic", "confidence": 0.7},
                {"content": supplied, "evidence_data": "two", "evidence_type": "logical",
                 "methodology": "deductive_logic", "confidence": 0.7},
            ]
        }))
        .unwrap();
    let json = first_text(
        &epigraph_mcp::tools::batch::batch_submit_claims(&server, &viewer, params)
            .await
            .unwrap(),
    );
    assert_eq!(json["submitted"], 4, "{json}");

    let omitted_block = &json["results"][1]["deduplicated"];
    assert_eq!(omitted_block["by"], "content_hash", "{json}");
    assert_eq!(
        strs(&omitted_block["inputs_applied"]),
        vec!["evidence_data", "evidence_type", "labels"],
        "a defaulted methodology/confidence is not a supplied input: {json}"
    );
    assert!(
        strs(&omitted_block["inputs_discarded"]).is_empty(),
        "{json}"
    );

    let supplied_block = &json["results"][3]["deduplicated"];
    assert_eq!(
        strs(&supplied_block["inputs_applied"]),
        vec![
            "methodology",
            "evidence_data",
            "evidence_type",
            "confidence"
        ],
        "{json}"
    );
}
