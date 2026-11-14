//! Backlog 8709d128: the document ingest writers must not republish verbatim
//! source passages in `evidence.raw_content` unless the source's recorded
//! licence (`papers.licence`, migration 226) permits it.
//!
//! Each test drives the PRODUCTION writer (`do_ingest_document` or
//! `do_ingest_document_spine`) against a freshly migrated database and reads
//! the evidence rows it wrote. Before the fix both writers stored
//! `Source: <title> (DOI: <doi>). Passage: '<paragraph text>'` for every new
//! claim, whatever the source's licence.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_db::PaperRepository;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::{do_ingest_document, do_ingest_document_spine};
use sqlx::PgPool;

const PARAGRAPH: &str =
    "Publisher prose that the evidence table must not republish wholesale, verbatim";

fn extraction(title: &str, doi: &str) -> DocumentExtraction {
    let json = serde_json::json!({
        "source": {
            "title": title,
            "doi": doi,
            "source_type": "Paper",
            "authors": [{"name": "Rita Retention", "affiliations": [], "roles": ["author"]}]
        },
        "thesis": "Evidence keeps a citation, a locator and a hash",
        "thesis_derivation": "TopDown",
        "sections": [{
            "title": "Results",
            "paragraphs": [{
                "text": PARAGRAPH,
                "span": {"start": 40, "end": 118},
                "atoms": ["Evidence rows carry a passage hash"],
                "generality": [2],
                "confidence": 0.7
            }]
        }],
        "relationships": []
    });
    serde_json::from_value(json).expect("fixture parses")
}

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(&pool).await;
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

/// Record a licence on the paper row before ingest, the way an operator would.
async fn set_licence(pool: &PgPool, doi: &str, title: &str, licence: &str) {
    let paper_id = PaperRepository::get_or_create(pool, doi, Some(title), None)
        .await
        .expect("paper row");
    sqlx::query("UPDATE papers SET licence = $2 WHERE id = $1")
        .bind(paper_id)
        .bind(licence)
        .execute(pool)
        .await
        .expect("set licence");
}

/// Every evidence body this paper's ingest wrote, with its stored digest.
async fn evidence_for(pool: &PgPool, title: &str) -> Vec<(String, Vec<u8>)> {
    let rows: Vec<(Option<String>, Vec<u8>)> = sqlx::query_as(
        "SELECT raw_content, content_hash FROM evidence WHERE raw_content LIKE $1 ORDER BY raw_content",
    )
    .bind(format!("Source: {title} (DOI:%"))
    .fetch_all(pool)
    .await
    .expect("evidence rows");
    rows.into_iter()
        .map(|(body, hash)| (body.expect("raw_content"), hash))
        .collect()
}

fn paragraph_hash() -> String {
    ContentHasher::to_hex(&ContentHasher::hash(PARAGRAPH.as_bytes()))
}

/// The shape every body shares: digest = BLAKE3(body), and paragraph-backed
/// rows (the paragraph and its atom) carry the locator and passage hash.
fn assert_citation_locator_hash(rows: &[(String, Vec<u8>)], expect_rows_with_passage: usize) {
    for (body, hash) in rows {
        assert_eq!(
            hash.as_slice(),
            ContentHasher::hash(body.as_bytes()).as_slice(),
            "content_hash must stay the digest of the stored body: {body}"
        );
        assert!(body.contains("Passage BLAKE3: "), "no passage hash: {body}");
    }
    let with_locator: Vec<&String> = rows
        .iter()
        .map(|(b, _)| b)
        .filter(|b| {
            b.contains(r#"Locator: sections[0].paragraphs[0] ("Results"), bytes 40..118."#)
                && b.contains(&format!("Passage BLAKE3: {}.", paragraph_hash()))
        })
        .collect();
    assert_eq!(
        with_locator.len(),
        expect_rows_with_passage,
        "paragraph-backed rows carry the locator and the passage hash: {rows:#?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn document_ingest_drops_passage_when_licence_unknown(pool: PgPool) {
    let (title, doi) = ("Unlicensed Retention Paper", "10.9999/b60-unlicensed");
    let server = make_server(pool.clone()).await;
    let viewer = fixture::public_viewer(&pool).await;
    do_ingest_document(
        &server,
        &viewer,
        &extraction(title, doi),
        None,
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .expect("ingest succeeds");

    let rows = evidence_for(&pool, title).await;
    // thesis + section + paragraph + atom, all new.
    assert_eq!(rows.len(), 4, "{rows:#?}");
    for (body, _) in &rows {
        assert!(
            !body.contains(PARAGRAPH),
            "verbatim passage persisted without a licence: {body}"
        );
        assert!(
            body.ends_with("Passage not retained (licence unknown)."),
            "{body}"
        );
    }
    assert_citation_locator_hash(&rows, 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn document_ingest_drops_passage_under_restrictive_licence(pool: PgPool) {
    let (title, doi) = ("NonCommercial Retention Paper", "10.9999/b60-noncommercial");
    set_licence(&pool, doi, title, "CC-BY-NC-4.0").await;
    let server = make_server(pool.clone()).await;
    let viewer = fixture::public_viewer(&pool).await;
    do_ingest_document(
        &server,
        &viewer,
        &extraction(title, doi),
        None,
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .expect("ingest succeeds");

    let rows = evidence_for(&pool, title).await;
    assert_eq!(rows.len(), 4, "{rows:#?}");
    for (body, _) in &rows {
        assert!(!body.contains(PARAGRAPH), "NC passage retained: {body}");
        assert!(
            body.ends_with("Passage not retained (licence: CC-BY-NC-4.0)."),
            "{body}"
        );
    }
    assert_citation_locator_hash(&rows, 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn document_ingest_retains_passage_under_open_licence(pool: PgPool) {
    let (title, doi) = ("Open Retention Paper", "10.9999/b60-open");
    set_licence(&pool, doi, title, "CC-BY-4.0").await;
    let server = make_server(pool.clone()).await;
    let viewer = fixture::public_viewer(&pool).await;
    do_ingest_document(
        &server,
        &viewer,
        &extraction(title, doi),
        None,
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .expect("ingest succeeds");

    let rows = evidence_for(&pool, title).await;
    assert_eq!(rows.len(), 4, "{rows:#?}");
    let retained = rows
        .iter()
        .filter(|(b, _)| b.ends_with(&format!("Licence: CC-BY-4.0. Passage: '{PARAGRAPH}'")))
        .count();
    assert_eq!(
        retained, 2,
        "paragraph + atom keep the open passage: {rows:#?}"
    );
    assert_citation_locator_hash(&rows, 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn spine_ingest_drops_passage_when_licence_unknown(pool: PgPool) {
    let (title, doi) = ("Unlicensed Spine Paper", "10.9999/b60-spine-unlicensed");
    let server = make_server(pool.clone()).await;
    do_ingest_document_spine(
        &server,
        &fixture::public_viewer(&pool).await,
        &extraction(title, doi),
        None,
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .expect("spine ingest succeeds");

    let rows = evidence_for(&pool, title).await;
    assert!(!rows.is_empty(), "the spine writes evidence for new claims");
    for (body, _) in &rows {
        assert!(
            !body.contains(PARAGRAPH),
            "spine persisted the verbatim passage without a licence: {body}"
        );
    }
    assert_citation_locator_hash(&rows, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn spine_ingest_retains_passage_under_open_licence(pool: PgPool) {
    let (title, doi) = ("Open Spine Paper", "10.9999/b60-spine-open");
    set_licence(&pool, doi, title, "CC0-1.0").await;
    let server = make_server(pool.clone()).await;
    do_ingest_document_spine(
        &server,
        &fixture::public_viewer(&pool).await,
        &extraction(title, doi),
        None,
        epigraph_core::VisibilityChoice::Public,
    )
    .await
    .expect("spine ingest succeeds");

    let rows = evidence_for(&pool, title).await;
    let retained = rows
        .iter()
        .filter(|(b, _)| b.ends_with(&format!("Licence: CC0-1.0. Passage: '{PARAGRAPH}'")))
        .count();
    assert_eq!(
        retained, 1,
        "the paragraph keeps the CC0 passage: {rows:#?}"
    );
    assert_citation_locator_hash(&rows, 1);
}

/// Migration 226's CHECK refuses a licence that names nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn blank_licence_is_refused(pool: PgPool) {
    let paper_id = PaperRepository::get_or_create(&pool, "10.9999/b60-blank", Some("Blank"), None)
        .await
        .expect("paper row");
    for bad in ["", " CC-BY-4.0"] {
        let err = sqlx::query("UPDATE papers SET licence = $2 WHERE id = $1")
            .bind(paper_id)
            .bind(bad)
            .execute(&pool)
            .await
            .expect_err("blank or padded licence must be refused");
        assert!(
            err.to_string().contains("papers_licence_nonblank"),
            "{bad:?}: {err}"
        );
    }
}

#[test]
fn retention_allowlist_admits_only_open_redistributable_licences() {
    use epigraph_mcp::tools::ingestion::passage_retention_permitted as ok;
    for open in [
        "CC-BY-4.0",
        "cc-by-3.0",
        "CC BY 4.0",
        "CC-BY-SA-4.0",
        "CC0-1.0",
        "CC0",
        "public-domain",
        "CC-BY-3.0-IGO",
        "CC-BY-SA-3.0",
        "CC-BY-SA",
    ] {
        assert!(ok(Some(open)), "{open} should permit retention");
    }
    for closed in [
        "CC-BY-NC-4.0",
        "CC-BY-ND-4.0",
        "CC-BY-NC-SA-4.0",
        "all-rights-reserved",
        "Elsevier user license",
        "CC-BYX",
        "",
        // Free-text spellings of restrictive licences (review of B60): each
        // normalises to a string that starts with `CC-BY-` yet is NC/ND or
        // not a licence id at all, so a prefix test would admit it.
        "CC-BY-NonCommercial-4.0",
        "CC BY 4.0 (non-commercial)",
        "CC-BY-NoDerivatives-4.0",
        "CC-BY-PROPRIETARY",
        "CC-BY-4.0-NC",
        "CC-BY-SA-4.0-ND",
        "CC0-1.0-NC",
    ] {
        assert!(!ok(Some(closed)), "{closed} must not permit retention");
    }
    assert!(!ok(None), "an unknown licence must not permit retention");
}
