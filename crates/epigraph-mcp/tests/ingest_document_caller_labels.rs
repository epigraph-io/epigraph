//! Caller-supplied `labels` on a hierarchical `DocumentExtraction` land on every
//! claim the ingest writes or resolves to (backlog b6b5ac28).
//!
//! Before this, `DocumentExtraction` had no `labels` field and no
//! `deny_unknown_fields`, so a caller's `"labels": [...]` was accepted and
//! SILENTLY DROPPED: every thesis/section/paragraph/atom landed with only the
//! writer's own `doi:<doi>` label, and a stage-tagging caller had to follow each
//! ingest with one `update_labels` call per claim.
//!
//! The fixtures are built from JSON on purpose: the unknown field is ignored on
//! a tree without the fix, so these tests COMPILE there and fail on the label
//! assertion, not on a missing struct field.
//!
//! Drives the cores (`do_ingest_document`, `do_ingest_document_spine`) directly
//! for the content assertions — the detached handlers `tokio::spawn` the walk,
//! which would make a label read race the write. The one handler test
//! (`ingest_document_inline`) asserts only what the handler does synchronously.
//!
//! Deliberately does NOT use `tests/common`: that helper DROPs
//! `uq_claims_content_hash_agent` (see `verify_claim_after_document_ingest.rs`).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::{
    do_ingest_document, do_ingest_document_spine, ingest_document_inline,
};
use epigraph_mcp::types::IngestDocumentInlineParams;
use sqlx::PgPool;
use uuid::Uuid;

const TITLE: &str = "U035 Caller Label Study";
const DOI: &str = "10.9999/u035-caller-labels";
const THESIS: &str = "Caller labels travel with the hierarchical ingest that writes them.";
const SECTION: &str = "Labelling";
const PARAGRAPH: &str = "Every claim written by one ingest call carries that call's stage tag.";
const ATOM: &str = "One ingest call tags every claim it writes.";

const STAGE: &str = "stage:u035-ingest";
const DATE: &str = "2026-10-05";

/// Built FROM A `ScopedPool`, as in `verify_claim_after_document_ingest.rs`, so
/// the walk runs the production `begin_author_stamped_tx` path.
async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(&pool).await;
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

/// The shared fixture. `labels: None` omits the key entirely (the pre-U035
/// wire shape); `Some(v)` sends it as a top-level array.
fn extraction_with(
    title: &str,
    doi: &str,
    thesis: &str,
    section: &str,
    paragraph: &str,
    atom: &str,
    labels: Option<&[&str]>,
) -> DocumentExtraction {
    let mut json = serde_json::json!({
        "source": {
            "title": title,
            "doi": doi,
            "source_type": "Paper",
            "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
        },
        "thesis": thesis,
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": section,
            "paragraphs": [{
                "text": paragraph,
                "atoms": [atom],
                "generality": [1],
                "confidence": 0.9
            }]
        }],
        "relationships": []
    });
    if let Some(labels) = labels {
        json["labels"] = serde_json::json!(labels);
    }
    serde_json::from_value(json).expect("fixture parses")
}

fn extraction(labels: Option<&[&str]>) -> DocumentExtraction {
    extraction_with(TITLE, DOI, THESIS, SECTION, PARAGRAPH, ATOM, labels)
}

/// The single row carrying `content`. Exactly one is required: two would mean
/// the fixture is ambiguous (or, for a converged atom, that the second ingest
/// inserted a duplicate instead of resolving to the first row).
async fn only_claim_with_content(pool: &PgPool, content: &str) -> Uuid {
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_all(pool)
        .await
        .expect("query claims by content");
    assert_eq!(
        ids.len(),
        1,
        "expected exactly one claim with content {content:?}, found {ids:?}"
    );
    ids[0]
}

async fn labels_of(pool: &PgPool, id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read claim labels")
}

async fn papers_with_doi(pool: &PgPool, doi: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM papers WHERE doi = $1")
        .bind(doi)
        .fetch_one(pool)
        .await
        .expect("count papers")
}

/// Asserts `content`'s row carries this ingest's `doi:` label (non-vacuity:
/// the label path ran and the row is this ingest's) AND every caller label.
async fn assert_carries_caller_labels(pool: &PgPool, what: &str, content: &str, doi: &str) {
    let id = only_claim_with_content(pool, content).await;
    let labels = labels_of(pool, id).await;
    let doi_label = format!("doi:{doi}");
    assert!(
        labels.contains(&doi_label),
        "{what}: the writer's own {doi_label:?} label is missing, so this row was not \
         labelled by this ingest at all: {labels:?}"
    );
    for want in [STAGE, DATE] {
        assert!(
            labels.iter().any(|l| l == want),
            "{what}: caller label {want:?} was supplied on the extraction but did not land \
             on the claim the ingest wrote: {labels:?}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn caller_labels_land_on_every_claim_the_document_ingest_writes(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    do_ingest_document(&server, &viewer, &extraction(Some(&[STAGE, DATE])), None)
        .await
        .expect("document ingests");

    for (what, content) in [
        ("thesis (level 0)", THESIS),
        ("section (level 1)", SECTION),
        ("paragraph (level 2)", PARAGRAPH),
        ("atom (level 3)", ATOM),
    ] {
        assert_carries_caller_labels(&pool, what, content, DOI).await;
    }
}

/// `do_ingest_document_spine` is a separate core with its own label call sites;
/// a fix through one core only would leave the spine's rows untagged. Spine
/// writes levels 0-2; the atom is skipped by design.
#[sqlx::test(migrations = "../../migrations")]
async fn caller_labels_land_on_every_spine_node(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    do_ingest_document_spine(&server, &viewer, &extraction(Some(&[STAGE, DATE])), None)
        .await
        .expect("spine ingests");

    for (what, content) in [
        ("thesis (level 0)", THESIS),
        ("section (level 1)", SECTION),
        ("paragraph (level 2)", PARAGRAPH),
    ] {
        assert_carries_caller_labels(&pool, what, content, DOI).await;
    }
    let atoms: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(ATOM)
        .fetch_one(&pool)
        .await
        .expect("count atoms");
    assert_eq!(atoms, 0, "the spine core writes no atoms");
}

/// `ingest_document_inline` answers `queued` and hands the walk to a detached
/// task AFTER writing the `papers` row synchronously. A caller label the writer
/// would refuse (an unexpanded shell variable) must therefore be refused by the
/// HANDLER, before that row is written — otherwise the caller is told `queued`,
/// a papers row survives, and the refusal reaches only the server log.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unexpanded_caller_label_is_refused_before_the_paper_node_is_written(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;

    // Positive control on the SAME server and viewer: a well-formed caller label
    // is accepted and queued. Without this, an `Err` below could come from the
    // viewer failing `detach_scoped` / the write preflight rather than from the
    // label check, and the test would pass on a tree without the fix.
    let ok_doi = "10.9999/u035-label-control";
    let ok = ingest_document_inline(
        &server,
        &viewer,
        IngestDocumentInlineParams {
            extraction: extraction_with(
                "U035 Control",
                ok_doi,
                "Control thesis for the label refusal.",
                "Control",
                "A control paragraph whose labels are well formed.",
                "Control labels are well formed.",
                Some(&["stage:ok"]),
            ),
        },
        None,
    )
    .await
    .expect("a well-formed caller label is accepted");
    let ok_json: serde_json::Value = serde_json::from_str(&result_text(&ok)).expect("JSON");
    assert_eq!(
        ok_json["status"], "queued",
        "control must be queued: {ok_json}"
    );
    assert_eq!(
        papers_with_doi(&pool, ok_doi).await,
        1,
        "control wrote its paper row"
    );

    let bad_doi = "10.9999/u035-label-refused";
    let err = ingest_document_inline(
        &server,
        &viewer,
        IngestDocumentInlineParams {
            extraction: extraction_with(
                "U035 Refused",
                bad_doi,
                "Refused thesis.",
                "Refused",
                "A paragraph whose caller label is an unexpanded variable.",
                "Unexpanded variables are not labels.",
                Some(&["stage:$STAGE"]),
            ),
        },
        None,
    )
    .await
    .expect_err("an unexpanded caller label must be refused by the handler, not queued");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("$STAGE"),
        "the refusal must be the label check naming the offending label, got: {msg}"
    );
    assert_eq!(
        papers_with_doi(&pool, bad_doi).await,
        0,
        "a refused ingest must not leave its papers row behind"
    );

    // Let the control's detached walk finish before the test database is torn
    // down (as `ingest_document_smoke.rs::inline_param_ingests_full_hierarchy`).
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
}

/// The spine handler calls its core synchronously, so the in-core check is the
/// only gate: an unexpanded caller label must be refused with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn spine_refuses_an_unexpanded_caller_label_and_writes_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let err = do_ingest_document_spine(
        &server,
        &viewer,
        &extraction(Some(&[STAGE, "stage:$STAGE"])),
        None,
    )
    .await
    .expect_err("an unexpanded caller label must be refused");
    assert!(format!("{err:?}").contains("$STAGE"), "{err:?}");
    let claims: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM claims")
        .fetch_one(&pool)
        .await
        .expect("count claims");
    assert_eq!(
        (papers_with_doi(&pool, DOI).await, claims),
        (0, 0),
        "a refused spine ingest must write nothing"
    );
}

/// The default path: an extraction with no `labels` key labels every claim with
/// exactly the set the writer produced before caller labels existed. Pinned from
/// a measurement on origin/main 798951e8 (this test green there: `[doi:<doi>]` on
/// all four levels), not assumed.
#[sqlx::test(migrations = "../../migrations")]
async fn empty_caller_labels_change_nothing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    do_ingest_document(&server, &viewer, &extraction(None), None)
        .await
        .expect("document ingests");

    let expected = vec![format!("doi:{DOI}")];
    for content in [THESIS, SECTION, PARAGRAPH, ATOM] {
        let id = only_claim_with_content(&pool, content).await;
        assert_eq!(labels_of(&pool, id).await, expected, "{content:?}");
    }
}

/// An atom another paper already wrote is RESOLVED to, not re-created. It picks
/// up the second paper's `doi:` label today; the second caller's stage tag must
/// follow the same rule, or `query_claims_by_label(["stage:b"])` misses the
/// converged part of paper B. Both papers' tags must ACCUMULATE, not overwrite.
///
/// Both ingests run as the same author, so the cross-group 42501 arm of
/// `label_resolved_claim` is not exercised here.
#[sqlx::test(migrations = "../../migrations")]
async fn caller_labels_reach_a_converged_atom(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let doi_a = "10.9999/u035-converge-a";
    let doi_b = "10.9999/u035-converge-b";

    do_ingest_document(
        &server,
        &viewer,
        &extraction_with(
            "U035 Paper A",
            doi_a,
            "Paper A thesis.",
            "A section",
            "Paper A paragraph stating the shared atom.",
            ATOM,
            Some(&["stage:a"]),
        ),
        None,
    )
    .await
    .expect("paper A ingests");
    do_ingest_document(
        &server,
        &viewer,
        &extraction_with(
            "U035 Paper B",
            doi_b,
            "Paper B thesis.",
            "B section",
            "Paper B paragraph stating the shared atom.",
            ATOM,
            Some(&["stage:b"]),
        ),
        None,
    )
    .await
    .expect("paper B ingests");

    // Exactly one row: paper B resolved to A's atom rather than inserting one.
    let atom = only_claim_with_content(&pool, ATOM).await;
    let labels = labels_of(&pool, atom).await;
    for want in [
        format!("doi:{doi_a}"),
        format!("doi:{doi_b}"),
        "stage:a".to_string(),
        "stage:b".to_string(),
    ] {
        assert!(
            labels.contains(&want),
            "converged atom is missing {want:?}: {labels:?}"
        );
    }
}

fn result_text(result: &rmcp::model::CallToolResult) -> String {
    let content = result.content.first().expect("at least one content block");
    content.as_text().expect("text content").text.clone()
}
