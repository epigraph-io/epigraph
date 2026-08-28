//! End-to-end essence binding (backlog 7c909c49): after an ingest, every claim
//! the document asserts names the exact bytes it was extracted from, and those
//! bytes are still on disk and still hash to the name.
//!
//! Written against the PRE-CHANGE public API only — `do_ingest_document`,
//! `do_ingest_document_spine`, `with_blob_dir` and raw SQL — so the file
//! compiles on the tree before the fix and can be run red there.

use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::ingestion::{do_ingest_document, do_ingest_document_spine};
use sqlx::PgPool;
use std::path::PathBuf;
use uuid::Uuid;

/// Tier 1: carries `source_text`, so the essence is the document itself.
const TIER1_FIXTURE: &str = r#"{
  "source": {
    "title": "Essence Binding Tier One",
    "doi": "10.1234/essence-tier-one",
    "source_type": "Paper",
    "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
  },
  "thesis": "Claims must name the bytes they came from",
  "thesis_derivation": "TopDown",
  "sections": [{
    "title": "Intro",
    "paragraphs": [{
      "text": "A claim bound only to a DOI is bound to a document identity, not to a payload.",
      "atoms": ["A DOI is a document identity", "A DOI is not a byte payload"],
      "generality": [3, 3],
      "confidence": 0.8
    }]
  }],
  "relationships": [],
  "source_text": "A claim bound only to a DOI is bound to a document identity, not to a payload.\n"
}"#;

/// Tier 2: no `source_text`, so the essence is the extraction envelope.
const TIER2_FIXTURE: &str = r#"{
  "source": {
    "title": "Essence Binding Tier Two",
    "doi": "10.1234/essence-tier-two",
    "source_type": "Paper",
    "authors": [{"name": "Bob Author", "affiliations": [], "roles": ["author"]}]
  },
  "thesis": "An envelope with no upstream text is still an artifact",
  "thesis_derivation": "TopDown",
  "sections": [{
    "title": "Intro",
    "paragraphs": [{
      "text": "The extraction envelope is what the run actually consumed.",
      "atoms": ["The envelope is the consumed artifact"],
      "generality": [3],
      "confidence": 0.8
    }]
  }],
  "relationships": []
}"#;

/// A `TempDir` would be dropped at the end of `make_server`, deleting the very
/// bytes the test is about to verify, so the directory is deliberately kept.
/// It lives under the OS temp root and holds a few hundred bytes per test.
fn make_server(pool: PgPool) -> (EpiGraphMcpFull, PathBuf) {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None);
    let blob_dir = tempfile::tempdir().expect("temp blob dir").keep();
    (
        EpiGraphMcpFull::new(pool, signer, embedder, false).with_blob_dir(blob_dir.clone()),
        blob_dir,
    )
}

fn paper_id_of(result: &rmcp::model::CallToolResult) -> Uuid {
    let text = result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("");
    let json: serde_json::Value = serde_json::from_str(&text).expect("response JSON");
    Uuid::parse_str(json["paper_id"].as_str().expect("paper_id present")).unwrap()
}

/// Every `paper -asserts-> claim` edge's `essence_digest`, or `None` for one
/// that carries none.
async fn asserted_digests(pool: &PgPool, paper_id: Uuid) -> Vec<Option<String>> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT properties ->> 'essence_digest' FROM edges \
         WHERE source_id = $1 AND source_type = 'paper' \
           AND target_type = 'claim' AND relationship = 'asserts'",
    )
    .bind(paper_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The digest of the rendition(s) this paper is joined to by `has_essence`.
async fn rendition_digests(pool: &PgPool, paper_id: Uuid) -> Vec<Vec<u8>> {
    sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT sa.content_hash FROM edges e \
         JOIN source_artifacts sa ON sa.id = e.target_id \
         WHERE e.source_id = $1 AND e.source_type = 'paper' \
           AND e.target_type = 'source_artifact' AND e.relationship = 'has_essence' \
           AND sa.artifact_type = 'essence'",
    )
    .bind(paper_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The whole point: the digest must resolve to bytes that are still there and
/// still hash to it.
async fn assert_bytes_resolve(
    pool: &PgPool,
    blob_dir: &std::path::Path,
    digest_hex: &str,
) -> Vec<u8> {
    let raw = hex::decode(digest_hex).expect("digest is hex");
    let size: i64 = sqlx::query_scalar("SELECT size_bytes FROM blobs WHERE content_hash = $1")
        .bind(&raw)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("no blobs row for digest {digest_hex}: {e}"));
    assert!(size > 0);

    let path = blob_dir
        .join(&digest_hex[0..2])
        .join(&digest_hex[2..4])
        .join(format!("{digest_hex}.blob"));
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("essence bytes missing at {}: {e}", path.display()));
    assert_eq!(
        hex::encode(ContentHasher::hash(&bytes)),
        digest_hex,
        "on-disk essence bytes do not re-hash to the digest the claims name"
    );
    bytes
}

/// Tier 1: the essence IS the document text, and every asserted claim names it.
#[sqlx::test(migrations = "../../migrations")]
async fn every_asserted_claim_names_the_source_text_it_came_from(pool: PgPool) {
    let (server, blob_dir) = make_server(pool.clone());
    let extraction: DocumentExtraction = serde_json::from_str(TIER1_FIXTURE).unwrap();

    let result = do_ingest_document(&server, &extraction).await.unwrap();
    let paper_id = paper_id_of(&result);

    let digests = asserted_digests(&pool, paper_id).await;
    assert!(!digests.is_empty(), "the fixture asserts claims");
    let expected = hex::encode(ContentHasher::hash(
        extraction.source_text.as_ref().unwrap().as_bytes(),
    ));
    for d in &digests {
        assert_eq!(
            d.as_deref(),
            Some(expected.as_str()),
            "an asserts edge does not name the source_text bytes"
        );
    }

    // The rendition node carries the same digest...
    let renditions = rendition_digests(&pool, paper_id).await;
    assert_eq!(renditions.len(), 1, "one rendition per exact byte payload");
    assert_eq!(hex::encode(&renditions[0]), expected);

    // ...and the bytes it names are still readable and still hash to it.
    let bytes = assert_bytes_resolve(&pool, &blob_dir, &expected).await;
    assert_eq!(bytes, extraction.source_text.unwrap().into_bytes());

    // Every level-2 paragraph is a byte-exact slice of the essence — the
    // containment property the verifier will lean on.
    let paragraphs: Vec<String> = sqlx::query_scalar(
        "SELECT c.content FROM edges e JOIN claims c ON c.id = e.target_id \
         WHERE e.source_id = $1 AND e.relationship = 'asserts' \
           AND c.properties ->> 'level' = '2'",
    )
    .bind(paper_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(!paragraphs.is_empty(), "the fixture has paragraph claims");
    let essence = String::from_utf8(bytes).unwrap();
    for p in paragraphs {
        assert!(
            essence.contains(&p),
            "paragraph {p:?} is not in the essence"
        );
    }
}

/// Tier 2: no `source_text`, so the envelope is the artifact. There is no
/// "no bytes" branch — the claims are bound either way.
#[sqlx::test(migrations = "../../migrations")]
async fn a_document_with_no_source_text_binds_its_extraction_envelope(pool: PgPool) {
    let (server, blob_dir) = make_server(pool.clone());
    let extraction: DocumentExtraction = serde_json::from_str(TIER2_FIXTURE).unwrap();

    let result = do_ingest_document(&server, &extraction).await.unwrap();
    let paper_id = paper_id_of(&result);

    let digests = asserted_digests(&pool, paper_id).await;
    assert!(!digests.is_empty());
    let named: Vec<&str> = digests.iter().filter_map(Option::as_deref).collect();
    assert_eq!(named.len(), digests.len(), "an asserts edge names no bytes");
    let digest = named[0].to_string();
    assert!(named.iter().all(|d| *d == digest), "one run, one rendition");

    let bytes = assert_bytes_resolve(&pool, &blob_dir, &digest).await;
    let envelope: serde_json::Value = serde_json::from_slice(&bytes)
        .expect("the tier-2 essence is the serialized extraction envelope");
    assert_eq!(envelope["source"]["doi"], "10.1234/essence-tier-two");

    let kind: String = sqlx::query_scalar(
        "SELECT sa.properties ->> 'essence_kind' FROM source_artifacts sa \
         WHERE sa.artifact_type = 'essence' AND sa.content_hash = $1",
    )
    .bind(hex::decode(&digest).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kind, "extraction_json");
}

/// The rendition key is content, so re-ingesting the same bytes converges on
/// ONE `source_artifacts` row and ONE `has_essence` edge rather than growing a
/// row per run. Also covers the spine entry point.
#[sqlx::test(migrations = "../../migrations")]
async fn re_ingesting_the_same_bytes_converges_on_one_rendition(pool: PgPool) {
    let (server, _blob_dir) = make_server(pool.clone());
    let extraction: DocumentExtraction = serde_json::from_str(TIER1_FIXTURE).unwrap();

    let first = do_ingest_document(&server, &extraction).await.unwrap();
    let paper_id = paper_id_of(&first);
    do_ingest_document(&server, &extraction).await.unwrap();
    do_ingest_document_spine(&server, &extraction)
        .await
        .unwrap();

    let renditions = rendition_digests(&pool, paper_id).await;
    assert_eq!(
        renditions.len(),
        1,
        "three ingests of identical bytes must share one rendition and one edge"
    );

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM source_artifacts WHERE artifact_type = 'essence'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows, 1);

    // And nothing came out of it unbound.
    for d in asserted_digests(&pool, paper_id).await {
        assert!(d.is_some(), "a re-ingest left an asserts edge unbound");
    }
}
