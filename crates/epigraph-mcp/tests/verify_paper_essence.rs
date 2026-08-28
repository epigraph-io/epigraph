//! `verify_paper_essence` — the fail-closed half of essence binding
//! (backlog 7c909c49).
//!
//! The verifier only earns its name if it FAILS on a graph that is actually
//! broken, so every test here breaks the graph in one specific way and requires
//! an error, then re-runs with `strict: false` where the distinction matters.

use epigraph_crypto::AgentSigner;
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::essence::verify_paper_essence;
use epigraph_mcp::tools::ingestion::do_ingest_document;
use epigraph_mcp::types::VerifyPaperEssenceParams;
use sqlx::PgPool;
use std::path::PathBuf;
use uuid::Uuid;

const DOI: &str = "10.1234/essence-verify";

const FIXTURE: &str = r#"{
  "source": {
    "title": "Essence Verification",
    "doi": "10.1234/essence-verify",
    "source_type": "Paper",
    "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
  },
  "thesis": "A verifier that cannot fail is not a verifier",
  "thesis_derivation": "TopDown",
  "sections": [{
    "title": "Intro",
    "paragraphs": [{
      "text": "Bytes that cannot be produced cannot support the claims that name them.",
      "atoms": ["Unproducible bytes support nothing"],
      "generality": [3],
      "confidence": 0.8
    }]
  }],
  "relationships": [],
  "source_text": "Bytes that cannot be produced cannot support the claims that name them.\n"
}"#;

fn make_server(pool: PgPool) -> (EpiGraphMcpFull, PathBuf) {
    let signer = AgentSigner::generate();
    let embedder = McpEmbedder::new(pool.clone(), None);
    let blob_dir = tempfile::tempdir().expect("temp blob dir").keep();
    (
        EpiGraphMcpFull::new(pool, signer, embedder, false).with_blob_dir(blob_dir.clone()),
        blob_dir,
    )
}

fn params(strict: bool) -> VerifyPaperEssenceParams {
    VerifyPaperEssenceParams {
        doi: Some(DOI.to_string()),
        paper_id: None,
        strict: Some(strict),
    }
}

fn report(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("");
    serde_json::from_str(&text).expect("report JSON")
}

fn fault_kinds(report: &serde_json::Value) -> Vec<String> {
    report["faults"]
        .as_array()
        .expect("faults array")
        .iter()
        .map(|f| f["kind"].as_str().unwrap().to_string())
        .collect()
}

async fn ingest(server: &EpiGraphMcpFull) -> Uuid {
    let extraction: DocumentExtraction = serde_json::from_str(FIXTURE).unwrap();
    let result = do_ingest_document(server, &extraction).await.unwrap();
    let text = result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("");
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    Uuid::parse_str(json["paper_id"].as_str().unwrap()).unwrap()
}

/// The control: an untouched ingest verifies, with the bytes re-hashed off
/// disk and every asserted claim naming them.
#[sqlx::test(migrations = "../../migrations")]
async fn a_freshly_ingested_paper_verifies(pool: PgPool) {
    let (server, _dir) = make_server(pool.clone());
    ingest(&server).await;

    let out = verify_paper_essence(&server, params(true))
        .await
        .expect("a healthy paper must verify under strict");
    let r = report(&out);
    assert_eq!(r["verified"], true);
    assert_eq!(fault_kinds(&r), Vec::<String>::new());
    assert_eq!(r["renditions"][0]["bytes_verified"], true);
    assert!(r["asserted_claims"].as_u64().unwrap() >= 4);
}

/// The bytes are gone from disk. This is the multi-replica failure mode, and
/// it must be loud.
#[sqlx::test(migrations = "../../migrations")]
async fn missing_bytes_fail_closed(pool: PgPool) {
    let (server, dir) = make_server(pool.clone());
    ingest(&server).await;

    // Wipe every stored blob file, leaving the metadata rows behind.
    for entry in walk(&dir) {
        std::fs::remove_file(entry).unwrap();
    }

    let err = verify_paper_essence(&server, params(true))
        .await
        .expect_err("missing essence bytes must be an error, not a report");
    assert!(
        err.message.contains("bytes_missing"),
        "expected bytes_missing, got {}",
        err.message
    );

    let r = report(&verify_paper_essence(&server, params(false)).await.unwrap());
    assert_eq!(r["verified"], false);
    assert!(fault_kinds(&r).contains(&"bytes_missing".to_string()));
    assert_eq!(r["renditions"][0]["bytes_verified"], false);
}

/// The bytes are there but were edited. Content addressing exists precisely so
/// this is detectable.
#[sqlx::test(migrations = "../../migrations")]
async fn altered_bytes_are_a_digest_mismatch(pool: PgPool) {
    let (server, dir) = make_server(pool.clone());
    ingest(&server).await;

    for entry in walk(&dir) {
        std::fs::write(&entry, b"tampered").unwrap();
    }

    let err = verify_paper_essence(&server, params(true))
        .await
        .unwrap_err();
    assert!(
        err.message.contains("digest_mismatch"),
        "expected digest_mismatch, got {}",
        err.message
    );
}

/// The legacy corpus. Migration 074's trigger grandfathers pre-essence rows for
/// WRITES; this is where they are surfaced rather than quietly tolerated.
#[sqlx::test(migrations = "../../migrations")]
async fn a_pre_essence_edge_is_reported_not_hidden(pool: PgPool) {
    let (server, _dir) = make_server(pool.clone());
    let paper_id = ingest(&server).await;

    // Strip the digest off one edge the way the pre-essence corpus holds them.
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE edges SET properties = properties - 'essence_digest' \
         WHERE id = (SELECT id FROM edges WHERE source_id = $1 AND relationship = 'asserts' LIMIT 1)",
    )
    .bind(paper_id)
    .execute(&mut *conn)
    .await
    .unwrap();
    sqlx::query("SET session_replication_role = origin")
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);

    let err = verify_paper_essence(&server, params(true))
        .await
        .unwrap_err();
    assert!(
        err.message.contains("unbound_claim"),
        "expected unbound_claim, got {}",
        err.message
    );

    // strict:false is the only way to get a report out of a broken paper.
    let r = report(&verify_paper_essence(&server, params(false)).await.unwrap());
    assert_eq!(r["verified"], false);
    assert!(fault_kinds(&r).contains(&"unbound_claim".to_string()));
}

/// The reported incident shape: an atom that provably belongs to this paper,
/// reachable through `decomposes_to`, that the paper does not assert.
#[sqlx::test(migrations = "../../migrations")]
async fn an_atom_the_paper_never_asserts_is_named(pool: PgPool) {
    let (server, _dir) = make_server(pool.clone());
    let paper_id = ingest(&server).await;

    let deleted = sqlx::query(
        "DELETE FROM edges e USING claims c \
         WHERE e.target_id = c.id AND e.source_id = $1 AND e.relationship = 'asserts' \
           AND c.properties ->> 'level' = '3'",
    )
    .bind(paper_id)
    .execute(&pool)
    .await
    .unwrap()
    .rows_affected();
    assert!(deleted > 0, "the fixture has atoms to orphan");

    let err = verify_paper_essence(&server, params(true))
        .await
        .unwrap_err();
    assert!(
        err.message.contains("atom_unbound"),
        "expected atom_unbound, got {}",
        err.message
    );
}

/// Containment teeth: for a verbatim `source_text` rendition, a paragraph claim
/// that is not a byte substring of the essence did not come from those bytes.
#[sqlx::test(migrations = "../../migrations")]
async fn a_paragraph_absent_from_the_essence_is_a_fault(pool: PgPool) {
    let (server, _dir) = make_server(pool.clone());
    let paper_id = ingest(&server).await;

    sqlx::query(
        "UPDATE claims SET content = 'text that was never in the artifact' \
         WHERE id IN (SELECT e.target_id FROM edges e JOIN claims c ON c.id = e.target_id \
                      WHERE e.source_id = $1 AND e.relationship = 'asserts' \
                        AND c.properties ->> 'level' = '2')",
    )
    .bind(paper_id)
    .execute(&pool)
    .await
    .unwrap();

    let err = verify_paper_essence(&server, params(true))
        .await
        .unwrap_err();
    assert!(
        err.message.contains("paragraph_not_in_essence"),
        "expected paragraph_not_in_essence, got {}",
        err.message
    );
}

/// A paper with asserts edges but no rendition at all — the shape the incident
/// report described, where the paper node resolves to nothing readable.
#[sqlx::test(migrations = "../../migrations")]
async fn a_paper_with_no_rendition_fails_closed(pool: PgPool) {
    let (server, _dir) = make_server(pool.clone());
    let paper_id = ingest(&server).await;

    sqlx::query("DELETE FROM edges WHERE source_id = $1 AND relationship = 'has_essence'")
        .bind(paper_id)
        .execute(&pool)
        .await
        .unwrap();

    let err = verify_paper_essence(&server, params(true))
        .await
        .unwrap_err();
    assert!(
        err.message.contains("no_essence") && err.message.contains("unknown_digest"),
        "expected no_essence + unknown_digest, got {}",
        err.message
    );
}

/// Every `*.blob` file under `root`.
fn walk(root: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "blob") {
                out.push(p);
            }
        }
    }
    assert!(!out.is_empty(), "no blob files were written under {root:?}");
    out
}
