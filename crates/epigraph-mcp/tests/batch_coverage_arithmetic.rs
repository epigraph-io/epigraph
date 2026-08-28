//! `batch_submit_claims` is held to a counted coverage contract
//! (backlog 4b48ffb5).
//!
//! The shipping defect these tests pin: the response reports
//! `"submitted": submitted.len()`, but `submit_claim` returns `Ok` carrying a
//! PRE-EXISTING claim id on both the content-hash dedup path
//! (`create_claim_idempotent`) and the novelty-gate path
//! (`GateDecision::ReturnExisting`). A batch of 40 could therefore report
//! `submitted: 40` while producing 12 distinct claims — a live, unverified
//! completeness assertion.
//!
//! These ride the content-hash dedup path, so they are deterministic and need
//! no OpenAI key: the novelty gate is only consulted when an embedder is
//! configured, and byte-identical content collapses either way.

use sqlx::PgPool;
mod common;
use common::*;

use epigraph_mcp::types::{BatchClaimEntry, BatchSubmitClaimsParams, CoverageParams};

fn entry(content: &str) -> BatchClaimEntry {
    entry_with_evidence(content, &format!("evidence for {content}"))
}

/// Same claim content, DIFFERENT evidence — the shape a duplicate really takes
/// in traffic: an agent asserts the same thing twice, backed by two separate
/// pieces of support, and believes it asserted two things.
///
/// The evidence must differ or the second entry dies on
/// `evidence_content_hash_claim_unique (content_hash, claim_id)` — an error,
/// not a dedup — and the batch never reaches the interesting path at all. Do
/// not "simplify" these to identical evidence.
fn entry_with_evidence(content: &str, evidence_data: &str) -> BatchClaimEntry {
    BatchClaimEntry {
        content: content.into(),
        evidence_data: evidence_data.into(),
        evidence_type: "logical".into(),
        confidence: Some(0.6),
        labels: vec![],
    }
}

fn coverage(standard: &str) -> Option<CoverageParams> {
    Some(CoverageParams {
        standard: Some(standard.into()),
        unit: None,
        declared_total: None,
    })
}

/// How many `obligations` rows this batch tool wrote.
async fn obligation_rows(pool: &PgPool) -> Vec<(String, i32, i32, Vec<String>)> {
    sqlx::query_as::<_, (String, i32, i32, Vec<String>)>(
        "SELECT verdict, declared_total, observed_total, missing_contract_fields
         FROM obligations WHERE source_tool = 'batch_submit_claims'
         ORDER BY created_at",
    )
    .fetch_all(pool)
    .await
    .expect("read obligations")
}

/// The checker runs with NO opt-in: `coverage: None`, no config key, no env
/// var. A clean batch of three distinct entries closes its own contract.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_of_distinct_claims_satisfies_the_default_exhaustive_contract(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let result = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        BatchSubmitClaimsParams {
            claims: vec![
                entry("distinct coverage claim alpha"),
                entry("distinct coverage claim beta"),
                entry("distinct coverage claim gamma"),
            ],
            coverage: None,
        },
    )
    .await
    .unwrap();

    let summary = first_text(&result);
    assert_eq!(summary["declared"], 3, "{summary}");
    assert_eq!(summary["distinct_claims"], 3, "{summary}");
    assert_eq!(summary["deduplicated"], 0, "{summary}");
    assert_eq!(summary["coverage_standard"], "exhaustive", "{summary}");
    assert_eq!(summary["coverage_verdict"], "satisfied", "{summary}");
    assert!(
        summary["missing_contract_fields"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "exhaustive owes no self-report when it is decided: {summary}"
    );
    // Backwards compatibility: the pre-existing fields keep their meaning.
    assert_eq!(summary["submitted"], 3, "{summary}");
    assert_eq!(summary["errors"], 0, "{summary}");

    let rows = obligation_rows(&pool).await;
    assert_eq!(rows.len(), 1, "exactly one obligation per batch: {rows:?}");
    assert_eq!(rows[0].0, "satisfied");
    assert_eq!((rows[0].1, rows[0].2), (3, 3));
    assert!(
        summary["obligation_id"].is_string(),
        "the batch must hand back the obligation id so it can be rechecked later: {summary}"
    );
}

/// THE HEADLINE TEST. Two entries asserting the same content dedup onto a
/// single claim via `create_or_get`'s `find_by_content_hash_and_agent`.
/// `submitted` still reads 2 — that is the assertion the tool has always
/// shipped, and the one that could be false. `distinct_claims` reads 1 and the
/// verdict is `breach`: the agent believed it was asserting two distinct
/// things and asserted one.
///
/// Deterministic and embedder-free: it rides the content-hash dedup path, so
/// it does not depend on an OpenAI key being present for the novelty gate.
#[sqlx::test(migrations = "../../migrations")]
async fn duplicate_entries_in_one_batch_breach_the_exhaustive_contract(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let content = "a claim submitted twice in the very same batch";

    let result = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        BatchSubmitClaimsParams {
            claims: vec![
                entry_with_evidence(content, "the first supporting observation"),
                entry_with_evidence(content, "a second, independent observation"),
            ],
            coverage: None,
        },
    )
    .await
    .unwrap();

    let summary = first_text(&result);
    // Unchanged meaning: both entries returned Ok, so `submitted` is 2. This
    // is precisely the number that was never verified.
    assert_eq!(
        summary["submitted"], 2,
        "the pre-existing self-report must be preserved verbatim: {summary}"
    );
    assert_eq!(summary["errors"], 0, "{summary}");

    assert_eq!(summary["declared"], 2, "{summary}");
    assert_eq!(
        summary["distinct_claims"], 1,
        "two identical entries anchor ONE claim: {summary}"
    );
    assert_eq!(summary["deduplicated"], 1, "{summary}");
    assert_eq!(
        summary["coverage_verdict"], "breach",
        "the counted verdict must contradict the self-report: {summary}"
    );

    // Confirm against the graph, not just the response.
    let claims: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(claims, 1, "exactly one claim row exists for that content");

    let rows = obligation_rows(&pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "breach");
    assert_eq!((rows[0].1, rows[0].2), (2, 1));
}

/// The override WEAKENS the contract; it does not switch the recording off.
/// Same duplicate batch, declared `summary`: nothing is owed, but the count is
/// still taken and the obligation is still persisted.
#[sqlx::test(migrations = "../../migrations")]
async fn an_explicit_summary_standard_owes_no_completeness(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let content = "a summarised claim submitted twice";

    let result = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        BatchSubmitClaimsParams {
            claims: vec![
                entry_with_evidence(content, "first support for the summary"),
                entry_with_evidence(content, "second support for the summary"),
            ],
            coverage: coverage("summary"),
        },
    )
    .await
    .unwrap();

    let summary = first_text(&result);
    assert_eq!(summary["coverage_standard"], "summary", "{summary}");
    assert_eq!(summary["coverage_verdict"], "not_applicable", "{summary}");
    assert_eq!(
        summary["distinct_claims"], 1,
        "the count is still taken, it just decides nothing: {summary}"
    );

    let rows = obligation_rows(&pool).await;
    assert_eq!(
        rows.len(),
        1,
        "weakening the standard must not stop the recording: {rows:?}"
    );
    assert_eq!(rows[0].0, "not_applicable");
    assert_eq!(rows[0].2, 1, "observed_total is still persisted");
}

/// THE MVP BOUNDARY, as live behaviour rather than a unit-test constant. No
/// count supplies a materiality judgement, so `material` returns
/// `indeterminate` and names the field it lacks — in the response AND in the
/// persisted row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_material_standard_returns_indeterminate_with_its_missing_field(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let result = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        BatchSubmitClaimsParams {
            claims: vec![entry("a materially relevant claim")],
            coverage: coverage("material"),
        },
    )
    .await
    .unwrap();

    let summary = first_text(&result);
    assert_eq!(summary["coverage_standard"], "material", "{summary}");
    assert_eq!(summary["coverage_verdict"], "indeterminate", "{summary}");
    assert_eq!(
        summary["missing_contract_fields"],
        serde_json::json!(["materiality_criterion"]),
        "{summary}"
    );

    let rows = obligation_rows(&pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "indeterminate");
    assert_eq!(
        rows[0].3,
        vec!["materiality_criterion".to_string()],
        "the self-report must survive to the row, not only the response"
    );
}

/// A hyphenated standard parses (the backlog spec writes it that way, the
/// CHECK constraint stores underscores), and an unknown one is rejected BEFORE
/// any claim is written. A typo must not silently become a batch that owes
/// nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_coverage_standard_is_rejected_before_any_write(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let err = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        BatchSubmitClaimsParams {
            claims: vec![entry("a claim that must never be written")],
            coverage: coverage("vibes"),
        },
    )
    .await
    .expect_err("an unrecognised standard must be a parameter error");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");

    let claims: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM claims WHERE content = 'a claim that must never be written'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(claims, 0, "the batch must be rejected before any write");
    assert!(
        obligation_rows(&pool).await.is_empty(),
        "a rejected batch opens no obligation"
    );

    // The hyphenated spelling of a REAL standard is accepted and normalised.
    let ok = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        BatchSubmitClaimsParams {
            claims: vec![entry("a natively complete claim")],
            coverage: coverage("native-complete"),
        },
    )
    .await
    .unwrap();
    let summary = first_text(&ok);
    assert_eq!(summary["coverage_standard"], "native_complete", "{summary}");
    assert_eq!(summary["coverage_verdict"], "satisfied", "{summary}");
    assert_eq!(
        summary["missing_contract_fields"],
        serde_json::json!(["declared_unit_keys"]),
        "count equality does not prove the units are the same units: {summary}"
    );
}

/// THE ZERO-DENOMINATOR RULE on the live path. An external denominator of 0
/// under a counting standard is never satisfied — this is the shape of
/// epiclaw-host's false TASK_SILENT, and a checker that blessed `0 == 0` would
/// have blessed it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_externally_declared_zero_denominator_is_indeterminate(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let result = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        BatchSubmitClaimsParams {
            claims: vec![entry("the only thing there was to say")],
            coverage: Some(CoverageParams {
                standard: Some("exhaustive".into()),
                unit: Some("emitter".into()),
                declared_total: Some(0),
            }),
        },
    )
    .await
    .unwrap();

    let summary = first_text(&result);
    assert_eq!(summary["declared"], 0, "{summary}");
    assert_eq!(summary["coverage_unit"], "emitter", "{summary}");
    assert_eq!(
        summary["coverage_verdict"], "indeterminate",
        "an empty denominator is not closeable by counting: {summary}"
    );
    assert_eq!(
        summary["missing_contract_fields"],
        serde_json::json!(["population_source"]),
        "{summary}"
    );
    // The claim itself was still written — the verdict is advisory.
    assert_eq!(summary["submitted"], 1, "{summary}");
}

/// A denominator that cannot fit `obligations.declared_total` is REJECTED, not
/// saturated.
///
/// Before this was closed, `coverage.declared_total = 3_000_000_000` was
/// accepted and the stored row contradicted ITSELF, because the column was
/// saturated with `unwrap_or(i32::MAX)` while `verdict_reason` was rendered
/// from the untruncated `u32`:
///
/// ```text
/// declared_total column = 2147483647
/// verdict_reason        = exhaustive shortfall: 1 of 3000000000 emitter
///                         anchored, 2999999999 unaccounted for
/// ```
///
/// `ObligationRepository::recheck` re-renders the reason from the column, so
/// the first `check_obligation` call then overwrote the number the caller had
/// been handed, and `check_obligation` served `2147483647` to a caller
/// `batch_submit_claims` had told `3000000000`.
///
/// The rule is the one
/// `an_unknown_coverage_standard_is_rejected_before_any_write` already pins
/// one parameter over: an uninterpretable contract is refused at the boundary,
/// never silently repaired.
#[sqlx::test(migrations = "../../migrations")]
async fn declared_total_above_i32_max_is_rejected_before_any_write(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let err = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        BatchSubmitClaimsParams {
            claims: vec![entry("a claim whose denominator does not fit")],
            coverage: Some(CoverageParams {
                standard: Some("exhaustive".into()),
                unit: Some("emitter".into()),
                declared_total: Some(3_000_000_000),
            }),
        },
    )
    .await
    .expect_err("a denominator above i32::MAX must be a parameter error");
    assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{err:?}");
    assert!(
        err.message.contains("2147483647") && err.message.contains("3000000000"),
        "the error must name both the cap and what was supplied: {err:?}"
    );

    let claims: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM claims WHERE content = 'a claim whose denominator does not fit'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(claims, 0, "the batch must be rejected before any write");
    assert!(
        obligation_rows(&pool).await.is_empty(),
        "a rejected batch opens no obligation"
    );

    // The boundary itself is ACCEPTED — the fix must reject only what the
    // column cannot hold — and the row it writes agrees with itself: one
    // denominator, in the column, in the prose, and in the response.
    let max = i32::MAX.unsigned_abs();
    let ok = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        BatchSubmitClaimsParams {
            claims: vec![entry("a claim whose denominator just fits")],
            coverage: Some(CoverageParams {
                standard: Some("exhaustive".into()),
                unit: Some("emitter".into()),
                declared_total: Some(max),
            }),
        },
    )
    .await
    .expect("i32::MAX is storable and must not be rejected");
    let summary = first_text(&ok);
    assert_eq!(summary["declared"], max, "{summary}");

    // `::bigint` in the SELECT so this decodes under any future column width.
    let (stored, reason) = sqlx::query_as::<_, (i64, String)>(
        "SELECT declared_total::bigint, verdict_reason
         FROM obligations WHERE source_tool = 'batch_submit_claims'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        stored,
        i64::from(max),
        "the stored denominator must equal the one the response reported"
    );
    assert!(
        reason.contains(&max.to_string()),
        "the row's prose must carry the same denominator as its column: {reason}"
    );
}
