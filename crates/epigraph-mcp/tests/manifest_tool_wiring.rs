//! THE LIVE-CALL-SITE PROOF for `export_subgraph_manifest` / `verify_manifest`.
//!
//! A signed-commitment type nobody calls is inert. These tests drive both tools
//! through the same handlers the MCP router dispatches to, against a real
//! database, and assert that a `manifests` row actually appears — plus that the
//! read-only gate really closes the write path.

use epigraph_mcp::tools::manifest::{export_subgraph_manifest, verify_manifest};
use epigraph_mcp::types::{ExportSubgraphManifestParams, VerifyManifestParams};
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

// ── Fixtures ──────────────────────────────────────────────────────────────

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, 'manifest-mcp')",
    )
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent");
    id
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value)
         VALUES ($1, $2, sha256($1::text::bytea), $3, 0.7)",
    )
    .bind(id)
    .bind(content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
         VALUES ($1, 'claim', $2, 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
}

/// A root claim with one ancestor and one superseded predecessor, so the export
/// emits both claims and edges.
async fn seed_subgraph(pool: &PgPool) -> Uuid {
    let agent = seed_agent(pool).await;
    let root = seed_claim(pool, agent, "mcp manifest root").await;
    let ancestor = seed_claim(pool, agent, "mcp manifest ancestor").await;
    let prior = seed_claim(pool, agent, "mcp manifest prior").await;
    seed_edge(pool, ancestor, root, "derived_from").await;
    seed_edge(pool, root, prior, "supersedes").await;
    root
}

fn body(result: &CallToolResult) -> Value {
    let text = result.content[0]
        .as_text()
        .expect("tool returns text content");
    serde_json::from_str(&text.text).expect("tool returns JSON")
}

async fn manifest_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM manifests")
        .fetch_one(pool)
        .await
        .expect("count manifests")
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn export_subgraph_manifest_writes_a_manifest_row(pool: PgPool) {
    let root = seed_subgraph(&pool).await;
    let server = build_test_server(pool.clone());

    assert_eq!(manifest_count(&pool).await, 0, "precondition: no manifests");

    let result = export_subgraph_manifest(
        &server,
        ExportSubgraphManifestParams {
            root_claim_id: root.to_string(),
            max_depth: Some(5),
        },
    )
    .await
    .expect("export_subgraph_manifest");

    assert_eq!(
        manifest_count(&pool).await,
        1,
        "the tool must actually record the commitment, not just compute one"
    );

    let out = body(&result);
    let root_hex = out["document"]["manifest"]["root"]
        .as_str()
        .expect("the document carries the full self-verifying bundle");
    assert_eq!(root_hex.len(), 64);
    assert!(
        root_hex
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "root must be lowercase hex, got {root_hex}"
    );
    assert_eq!(
        out["manifest"]["root"].as_str().unwrap(),
        root_hex,
        "the top-level summary must agree with the bundle"
    );

    let claims = out["claim_ids"].as_array().expect("claim_ids");
    let edges = out["edge_ids"].as_array().expect("edge_ids");
    assert_eq!(
        out["manifest"]["entry_count"].as_u64().unwrap() as usize,
        claims.len() + edges.len()
    );
    assert!(
        claims.len() >= 3 && edges.len() >= 2,
        "got {claims:?} / {edges:?}"
    );
    assert_eq!(out["manifest"]["subject"]["kind"], "provenance_export");
}

#[sqlx::test(migrations = "../../migrations")]
async fn verify_manifest_reports_valid_for_a_freshly_exported_subgraph(pool: PgPool) {
    let root = seed_subgraph(&pool).await;
    let server = build_test_server(pool.clone());

    let exported = body(
        &export_subgraph_manifest(
            &server,
            ExportSubgraphManifestParams {
                root_claim_id: root.to_string(),
                max_depth: None,
            },
        )
        .await
        .expect("export"),
    );
    let manifest_id = exported["manifest"]["manifest_id"]
        .as_str()
        .expect("manifest_id")
        .to_string();

    let report = body(
        &verify_manifest(
            &server,
            VerifyManifestParams {
                manifest_id: manifest_id.clone(),
                prove_claim_id: Some(root.to_string()),
                prove_edge_id: None,
            },
        )
        .await
        .expect("verify"),
    );

    assert_eq!(report["signature_valid"], true);
    assert_eq!(report["header_consistent"], true);
    assert_eq!(report["stored_root_intact"], true);
    assert_eq!(report["live_root_matches"], true);
    assert_eq!(report["entry_count_matches"], true);
    assert_eq!(
        report["signer_key_current"], true,
        "the MCP server signs with its own resolved agents row, so the key is current"
    );
    for entry in report["entries"].as_array().expect("entries") {
        assert_eq!(entry["status"], "ok", "entry {entry:?}");
    }

    let proof = &report["inclusion_proof"];
    assert_eq!(proof["verified"], true);
    assert_eq!(proof["row_id"].as_str().unwrap(), root.to_string());
    assert_eq!(proof["kind"], "claim");

    // A proof covers one leaf; asking for two is a caller error, not a silent
    // pick-one.
    let err = verify_manifest(
        &server,
        VerifyManifestParams {
            manifest_id,
            prove_claim_id: Some(root.to_string()),
            prove_edge_id: Some(Uuid::new_v4().to_string()),
        },
    )
    .await
    .expect_err("both proof params must be rejected");
    assert!(err.message.contains("at most one"), "got {}", err.message);
}

#[sqlx::test(migrations = "../../migrations")]
async fn export_subgraph_manifest_is_refused_in_read_only_mode(pool: PgPool) {
    let root = seed_subgraph(&pool).await;

    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0xA7; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None);
    let server = epigraph_mcp::EpiGraphMcpFull::new(
        pool.clone(),
        signer,
        embedder,
        /* read_only */ true,
    );

    let err = export_subgraph_manifest(
        &server,
        ExportSubgraphManifestParams {
            root_claim_id: root.to_string(),
            max_depth: None,
        },
    )
    .await
    .expect_err("a read-only server must refuse to anchor");
    assert!(err.message.contains("read-only"), "got {}", err.message);

    assert_eq!(
        manifest_count(&pool).await,
        0,
        "and must write nothing while refusing"
    );
}
