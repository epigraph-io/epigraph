//! `anchor_manifest` / `verify_anchor` driven through the same handlers the
//! MCP router dispatches to, against a real database and the real mock ledger.

use epigraph_mcp::tools::anchors::{anchor_manifest, verify_anchor};
use epigraph_mcp::tools::manifest::export_subgraph_manifest;
use epigraph_mcp::types::{AnchorManifestParams, ExportSubgraphManifestParams, VerifyAnchorParams};
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
        "INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, 'anchor-tools')",
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

/// Returns (root claim id, every claim id in the subgraph).
async fn seed_subgraph(pool: &PgPool) -> (Uuid, Vec<Uuid>) {
    let agent = seed_agent(pool).await;
    let root = seed_claim(pool, agent, "anchor tools root").await;
    let ancestor = seed_claim(pool, agent, "anchor tools ancestor").await;
    let prior = seed_claim(pool, agent, "anchor tools prior").await;
    for (source, target, rel) in [
        (ancestor, root, "derived_from"),
        (root, prior, "supersedes"),
    ] {
        sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship)
             VALUES ($1, 'claim', $2, 'claim', $3)",
        )
        .bind(source)
        .bind(target)
        .bind(rel)
        .execute(pool)
        .await
        .expect("seed edge");
    }
    (root, vec![root, ancestor, prior])
}

fn body(result: &CallToolResult) -> Value {
    let text = result.content[0]
        .as_text()
        .expect("tool returns text content");
    serde_json::from_str(&text.text).expect("tool returns JSON")
}

/// Seal a manifest through the manifest track's tool and return its id.
async fn seal(server: &epigraph_mcp::EpiGraphMcpFull, root: Uuid) -> Uuid {
    let out = body(
        &export_subgraph_manifest(
            server,
            ExportSubgraphManifestParams {
                root_claim_id: root.to_string(),
                max_depth: Some(5),
            },
        )
        .await
        .expect("export"),
    );
    out["manifest"]["manifest_id"]
        .as_str()
        .expect("manifest_id")
        .parse()
        .expect("uuid")
}

async fn mock_chain_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM anchor_mock_chain")
        .fetch_one(pool)
        .await
        .expect("count mock chain")
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn verify_anchor_tool_reports_drift(pool: PgPool) {
    let (root, claims) = seed_subgraph(&pool).await;
    let server = build_test_server(pool.clone());
    let manifest_id = seal(&server, root).await;

    // Fresh out of the seal, everything checks out.
    let report = body(
        &verify_anchor(
            &server,
            VerifyAnchorParams {
                root_id: manifest_id.to_string(),
                root_type: None,
            },
        )
        .await
        .expect("verify"),
    );
    assert_eq!(report["verdict"], "verified", "{report:#}");
    assert_eq!(
        report["trust_basis"], "operator-held",
        "the default ledger is the operator's own and the report must say so"
    );

    // Rewrite a column that is inside the leaf of a covered row.
    sqlx::query("UPDATE claims SET content_hash = decode(repeat('7f', 32), 'hex') WHERE id = $1")
        .bind(claims[0])
        .execute(&pool)
        .await
        .expect("mutate a covered row");

    let report = body(
        &verify_anchor(
            &server,
            VerifyAnchorParams {
                root_id: manifest_id.to_string(),
                root_type: Some("manifest".to_string()),
            },
        )
        .await
        .expect("verify"),
    );

    assert_eq!(report["verdict"], "drift", "{report:#}");
    let anchored = report["anchored_root"].as_str().expect("anchored_root");
    let live = report["live_root"].as_str().expect("live_root");
    assert_eq!(anchored.len(), 64);
    assert_eq!(live.len(), 64);
    assert_ne!(anchored, live);
    assert_eq!(report["trust_basis"], "operator-held");
    assert!(report["tx_id"].is_string());
    assert!(report["block_height"].is_i64());
    assert!(report["block_time"].is_string());
}

#[sqlx::test(migrations = "../../migrations")]
async fn anchor_manifest_tool_is_idempotent(pool: PgPool) {
    let (root, _) = seed_subgraph(&pool).await;
    let server = build_test_server(pool.clone());
    let manifest_id = seal(&server, root).await;

    // The seal already anchored it — that is the whole design — so the tool is
    // being called on an ALREADY anchored root here.
    assert_eq!(mock_chain_count(&pool).await, 1);

    let first = body(
        &anchor_manifest(
            &server,
            AnchorManifestParams {
                manifest_id: manifest_id.to_string(),
            },
        )
        .await
        .expect("anchor"),
    );
    let second = body(
        &anchor_manifest(
            &server,
            AnchorManifestParams {
                manifest_id: manifest_id.to_string(),
            },
        )
        .await
        .expect("anchor again"),
    );

    assert_eq!(first["anchor_id"], second["anchor_id"]);
    assert_eq!(first["tx_id"], second["tx_id"]);
    assert_eq!(first["status"], "confirmed");
    assert_eq!(first["trust_basis"], "operator-held");
    assert_eq!(
        mock_chain_count(&pool).await,
        1,
        "re-anchoring must add no ledger row"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM anchors")
            .fetch_one(&pool)
            .await
            .expect("count"),
        1
    );

    // A root that does not exist is a caller error, not an internal fault.
    let err = anchor_manifest(
        &server,
        AnchorManifestParams {
            manifest_id: Uuid::new_v4().to_string(),
        },
    )
    .await
    .expect_err("no such manifest");
    assert!(
        err.message.contains("does not exist"),
        "got {}",
        err.message
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn anchor_manifest_is_rejected_in_read_only_mode(pool: PgPool) {
    let (root, _) = seed_subgraph(&pool).await;

    // Seal on a writable server first, so there IS something to anchor. The
    // seal anchors it too, so the read-only call below is refused BEFORE it can
    // reach the (idempotent) service — the gate closes first, not last.
    let writable = build_test_server(pool.clone());
    let manifest_id = seal(&writable, root).await;

    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM anchors")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(before, 1, "the seal anchored it");

    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0xA7; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None);
    let read_only = epigraph_mcp::EpiGraphMcpFull::new(
        pool.clone(),
        signer,
        embedder,
        /* read_only */ true,
    );

    let err = anchor_manifest(
        &read_only,
        AnchorManifestParams {
            manifest_id: manifest_id.to_string(),
        },
    )
    .await
    .expect_err("a read-only server must refuse to publish");
    assert!(err.message.contains("read-only"), "got {}", err.message);

    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM anchors")
            .fetch_one(&pool)
            .await
            .expect("count"),
        before,
        "and must write nothing while refusing"
    );

    // Verification is a read and stays open on a read-only server.
    let report = body(
        &verify_anchor(
            &read_only,
            VerifyAnchorParams {
                root_id: manifest_id.to_string(),
                root_type: None,
            },
        )
        .await
        .expect("verify is read-only and must still work"),
    );
    assert_eq!(report["verdict"], "verified");
}

/// A kind the schema reserves but this build does not implement must be a hard
/// error. A silent skip would report "nothing to see" for a root that is not
/// anchored at all.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_anchor_rejects_an_unimplemented_root_type(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let err = verify_anchor(
        &server,
        VerifyAnchorParams {
            root_id: Uuid::new_v4().to_string(),
            root_type: Some("checkpoint".to_string()),
        },
    )
    .await
    .expect_err("checkpoint is reserved, not implemented");
    assert!(
        err.message.contains("unknown anchor root type"),
        "got {}",
        err.message
    );
}
