//! Backlog f6310444 on the MCP surface: a label carrying unexpanded shell
//! syntax must be refused BEFORE the claim is written, on every MCP tool that
//! takes caller-supplied labels.
//!
//! The contract these tests pin is the same one the HTTP tests
//! (`crates/epigraph-api/tests/label_shell_variable_rejection.rs`) pin:
//! **an error AND `COUNT(*) = 0` for the submitted content.** The count half is
//! what makes guard PLACEMENT load-bearing rather than mere existence — a guard
//! that runs after `create_claim_idempotent` still returns an error, but leaves
//! an orphan claim behind, and on `memorize` the pre-fix code did not even
//! return the error (it went to `tracing::warn!` and the tool reported success
//! with every tag dropped, which is the *undetectable* version of the
//! corruption).
//!
//! Direction proof, measured (see the branch report): with the two pre-write
//! `reject_unexpanded_labels` calls removed from `tools::claims::submit_claim`
//! and `tools::memory::memorize`, `submit_claim_...` and `memorize_...` below
//! fail on the `COUNT(*) = 0` assertion (`submit_claim`) and on the
//! `expect_err` (`memorize`), and `batch_...` fails on its orphan-count
//! assertion.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
mod common;
use common::*;

/// The exact value from the backlog report.
const BAD_LABEL: &str = "group:$EPICLAW_GROUP_ID";

async fn claim_count_for_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(pool)
        .await
        .expect("count claims by content")
}

/// `submit_claim` must refuse the label and persist NO claim.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_rejects_unexpanded_label_and_writes_no_claim(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone()).await;
    let content = "mcp submit_claim label guard subject";

    let err = epigraph_mcp::tools::claims::submit_claim(
        &server,
        &viewer,
        epigraph_mcp::types::SubmitClaimParams {
            content: content.into(),
            methodology: "deductive_logic".into(),
            evidence_data: "ev".into(),
            evidence_type: "logical".into(),
            confidence: 0.8,
            source_url: None,
            reasoning: None,
            labels: vec!["fine-label".into(), BAD_LABEL.into()],
            novelty_threshold: None,
        },
    )
    .await
    .expect_err("an unexpanded shell variable must be refused, not stored");

    // The load-bearing half FIRST, so the pre-fix failure this test reproduces
    // is the orphan itself and not merely the error code: a guard placed at the
    // `update_labels` call below `create_claim_idempotent` returns an error and
    // still leaves the claim row.
    assert_eq!(
        claim_count_for_content(&pool, content).await,
        0,
        "a refused submission must leave no claim row behind"
    );
    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "a caller-caused label rejection must be INVALID_PARAMS, not \
         INTERNAL_ERROR (which reads as retryable); got {err:?}"
    );
    assert!(
        err.message.contains(BAD_LABEL),
        "the rejection must name the offending label, got: {}",
        err.message
    );
}

/// A well-formed label must still flow through — guards against a fix that
/// rejects on the wrong predicate (e.g. any `:` or `-`).
#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_still_accepts_the_live_label_vocabulary(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone()).await;
    let content = "mcp submit_claim label guard negative control";

    epigraph_mcp::tools::claims::submit_claim(
        &server,
        &viewer,
        epigraph_mcp::types::SubmitClaimParams {
            content: content.into(),
            methodology: "deductive_logic".into(),
            evidence_data: "ev".into(),
            evidence_type: "logical".into(),
            confidence: 0.8,
            source_url: None,
            reasoning: None,
            labels: vec![
                "claude-memory".into(),
                "src:MEMORY.md".into(),
                "group:0f4d3c1e-2b8a-4c6d-9e31-7a5b2c8d4f60".into(),
            ],
            novelty_threshold: None,
        },
    )
    .await
    .expect("real labels must keep flowing through");

    let (labels,): (Vec<String>,) = sqlx::query_as("SELECT labels FROM claims WHERE content = $1")
        .bind(content)
        .fetch_one(&pool)
        .await
        .expect("claim row");
    assert!(
        labels.contains(&"src:MEMORY.md".to_string())
            && labels.contains(&"claude-memory".to_string()),
        "the accepted labels must actually be stored, got {labels:?}"
    );
}

/// `memorize` must refuse the tag rather than store the claim with every tag
/// silently dropped. This is the finding the review called blocking: pre-fix
/// this call returned SUCCESS.
#[sqlx::test(migrations = "../../migrations")]
async fn memorize_rejects_unexpanded_tag_and_writes_no_claim(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone()).await;
    let content = "mcp memorize tag guard subject";

    let err = epigraph_mcp::tools::memory::memorize(
        &server,
        &viewer,
        epigraph_mcp::types::MemorizeParams {
            content: content.into(),
            confidence: Some(0.7),
            tags: Some(vec!["claude-memory".into(), BAD_LABEL.into()]),
            novelty_threshold: None,
        },
    )
    .await
    .expect_err("memorize must not report success while dropping every tag");

    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "got {err:?}"
    );
    assert!(
        err.message.contains(BAD_LABEL),
        "the rejection must name the offending tag, got: {}",
        err.message
    );
    assert_eq!(
        claim_count_for_content(&pool, content).await,
        0,
        "a refused memorize must leave no claim row behind — a stored-but-untagged \
         memory is the silently-ungrouped failure mode the backlog names"
    );
}

/// `batch_submit_claims` reports per-entry errors instead of failing the call,
/// so the contract it must honour is: the bad entry is reported AND leaves no
/// row, while its well-formed neighbours are still ingested.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_submit_claims_rejects_one_entry_without_orphaning_it(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone()).await;
    let good = "mcp batch good entry";
    let bad = "mcp batch bad entry";

    let result = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        &viewer,
        epigraph_mcp::types::BatchSubmitClaimsParams {
            claims: vec![
                epigraph_mcp::types::BatchClaimEntry {
                    content: good.into(),
                    evidence_data: "ev".into(),
                    evidence_type: "logical".into(),
                    confidence: Some(0.6),
                    labels: vec!["backlog".into()],
                },
                epigraph_mcp::types::BatchClaimEntry {
                    content: bad.into(),
                    evidence_data: "ev".into(),
                    evidence_type: "logical".into(),
                    confidence: Some(0.6),
                    labels: vec![BAD_LABEL.into()],
                },
            ],
        },
    )
    .await
    .expect("batch call itself succeeds; per-entry failures are reported in the payload");

    let json = first_text(&result);
    assert_eq!(json["submitted"], 1, "payload: {json}");
    assert_eq!(json["errors"], 1, "payload: {json}");
    assert!(
        json["error_details"][0]["error"]
            .as_str()
            .unwrap_or_default()
            .contains(BAD_LABEL),
        "the per-entry error must name the offending label, payload: {json}"
    );

    assert_eq!(
        claim_count_for_content(&pool, good).await,
        1,
        "one bad entry must not block its well-formed neighbours"
    );
    assert_eq!(
        claim_count_for_content(&pool, bad).await,
        0,
        "the refused entry must leave no orphan claim"
    );
}

/// The `update_labels` tool: the repo layer refuses the value inside the same
/// statement that would have written it, so the write half was already safe —
/// what this pins is that the caller is TOLD it is a caller error
/// (INVALID_PARAMS), and that the well-formed sibling in the same `add` array
/// does not land either.
#[sqlx::test(migrations = "../../migrations")]
async fn update_labels_tool_rejects_unexpanded_add_and_changes_nothing(pool: PgPool) {
    let claim_id =
        seed_claim_with_labels(&pool, "update_labels tool guard subject", &["keeper"]).await;
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone()).await;

    let err = epigraph_mcp::tools::claims::update_labels(
        &server,
        &viewer,
        epigraph_mcp::types::UpdateLabelsParams {
            claim_id: claim_id.to_string(),
            add: vec!["good-label".into(), BAD_LABEL.into()],
            remove: vec![],
        },
        None,
    )
    .await
    .expect_err("an unexpanded shell variable must be refused");

    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "got {err:?}"
    );

    let (labels,): (Vec<String>,) = sqlx::query_as("SELECT labels FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .expect("claim row");
    assert_eq!(
        labels,
        vec!["keeper".to_string()],
        "a refused add array must leave claims.labels byte-for-byte unchanged"
    );
}

/// `update_with_evidence` applies its label merge only AFTER inserting the
/// Evidence row, wiring the DS/BBA state and rewriting `truth_value`. A
/// rejection at that point would move a claim's belief on the strength of a
/// call the caller was told had failed, so the guard must run first: no
/// evidence row may exist for the claim afterwards.
#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_rejects_unexpanded_label_before_writing_evidence(pool: PgPool) {
    let claim_id =
        seed_claim_with_labels(&pool, "update_with_evidence guard subject", &["keeper"]).await;
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone()).await;

    let err = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        &viewer,
        epigraph_mcp::types::UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: "re-confirmed".into(),
            source_url: None,
            supports: true,
            strength: 0.7,
            labels: vec![BAD_LABEL.into()],
        },
    )
    .await
    .expect_err("an unexpanded shell variable must be refused");

    // Ordering half first, so the pre-fix failure this reproduces is the
    // partial write itself rather than the reported error code.
    let evidence_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM evidence WHERE claim_id = $1")
            .bind(claim_id)
            .fetch_one(&pool)
            .await
            .expect("count evidence");
    assert_eq!(
        evidence_rows, 0,
        "a refused update_with_evidence must not have inserted evidence first"
    );
    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "got {err:?}"
    );

    let (labels,): (Vec<String>,) = sqlx::query_as("SELECT labels FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .expect("claim row");
    assert_eq!(labels, vec!["keeper".to_string()]);
}

/// `ingest_document` derives a `doi:<doi>` label from the extraction's source
/// metadata and applies it per claim INSIDE the plan walk. An unexpandable DOI
/// must therefore be refused before the paper node and the first claim are
/// written — otherwise the ingest dies partway through with the paper row and
/// some of its claims already committed.
#[sqlx::test(migrations = "../../migrations")]
async fn ingest_document_rejects_an_unexpanded_doi_before_writing_anything(pool: PgPool) {
    let signer = epigraph_crypto::AgentSigner::generate();
    let embedder = epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None);
    let server = epigraph_mcp::EpiGraphMcpFull::new(pool.clone(), signer, embedder, false);
    let viewer = fixture::public_viewer(&pool).await;

    // Same shape as ingest_document_smoke.rs's fixture, with the DOI carrying an
    // unexpanded variable (how a shell-driven ingest script mangles it).
    let fixture = r#"{
      "source": {
        "title": "Paper With An Unexpanded DOI",
        "doi": "10.1234/$RUN_ID",
        "source_type": "Paper",
        "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
      },
      "thesis": "A shell variable is not a DOI",
      "thesis_derivation": "TopDown",
      "sections": [{
        "title": "Intro",
        "paragraphs": [{
          "text": "Atomization aids cross-source matching, and decomposition is necessary",
          "atoms": ["Atomization aids cross-source matching"],
          "generality": [3],
          "confidence": 0.8
        }]
      }],
      "relationships": []
    }"#;
    let extraction: epigraph_ingest::schema::DocumentExtraction =
        serde_json::from_str(fixture).expect("fixture parses");

    let err = epigraph_mcp::tools::ingestion::do_ingest_document(&server, &viewer, &extraction)
        .await
        .expect_err("an unexpandable DOI must be refused");

    // Nothing may have landed: no paper row, no claims.
    let papers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM papers")
        .fetch_one(&pool)
        .await
        .expect("count papers");
    let claims: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims")
        .fetch_one(&pool)
        .await
        .expect("count claims");
    assert_eq!(
        (papers, claims),
        (0, 0),
        "a refused ingest must write nothing; got {papers} papers and {claims} claims"
    );
    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "got {err:?}"
    );
}
