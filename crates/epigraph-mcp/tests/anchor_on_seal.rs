//! THE ANTI-INERTNESS TEST for external anchoring (backlog 94e62824).
//!
//! An anchoring service nobody calls is worse than no anchoring at all: it
//! looks like the property is delivered while nothing is published. This test
//! seals a manifest through the manifest track's own MCP tool — no anchor API
//! is called anywhere in it — and asserts that an `anchors` row and a matching
//! `anchor_mock_chain` row appear anyway.
//!
//! It fails if the post-commit hook in
//! `epigraph_engine::export::manifest::anchor_manifest` is ever dropped, or if
//! anchoring is put behind a flag that defaults to off. Do not weaken it into a
//! unit test over `AnchorService` — that would test the thing while losing the
//! only property worth testing here.

use epigraph_mcp::tools::manifest::export_subgraph_manifest;
use epigraph_mcp::types::ExportSubgraphManifestParams;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::build_test_server;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, display_name) VALUES ($1, $2, 'anchor-seal')")
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

/// A root claim with an ancestor and a superseded predecessor, so the export
/// emits both claims and edges.
async fn seed_subgraph(pool: &PgPool) -> Uuid {
    let agent = seed_agent(pool).await;
    let root = seed_claim(pool, agent, "anchor-on-seal root").await;
    let ancestor = seed_claim(pool, agent, "anchor-on-seal ancestor").await;
    let prior = seed_claim(pool, agent, "anchor-on-seal prior").await;
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
    root
}

#[sqlx::test(migrations = "../../migrations")]
async fn sealing_a_manifest_writes_an_anchor_row(pool: PgPool) {
    let root = seed_subgraph(&pool).await;
    let server = build_test_server(pool.clone());

    for (table, count) in [
        ("anchors", anchor_count(&pool).await),
        ("anchor_mock_chain", mock_chain_count(&pool).await),
    ] {
        assert_eq!(count, 0, "precondition: {table} starts empty");
    }

    // NOTHING anchor-related is called here. This is the manifest track's seal
    // tool, invoked exactly as the MCP router invokes it.
    export_subgraph_manifest(
        &server,
        ExportSubgraphManifestParams {
            root_claim_id: root.to_string(),
            max_depth: Some(5),
        },
    )
    .await
    .expect("export_subgraph_manifest");

    let manifest_id: Uuid = sqlx::query_scalar("SELECT id FROM manifests")
        .fetch_one(&pool)
        .await
        .expect("exactly one manifest was sealed");

    let (anchor_id, status, backend, tx_id, block_height, commitment): (
        Uuid,
        String,
        String,
        Option<String>,
        Option<i64>,
        Vec<u8>,
    ) = sqlx::query_as(
        "SELECT id, status, backend, tx_id, block_height, commitment_bytes
         FROM anchors WHERE root_type = 'manifest' AND root_id = $1",
    )
    .bind(manifest_id)
    .fetch_one(&pool)
    .await
    .expect("sealing a manifest MUST produce exactly one anchor row with no operator action");

    assert_eq!(anchor_count(&pool).await, 1, "one seal, one anchor");
    assert_eq!(
        status, "confirmed",
        "the default mock backend confirms synchronously; anchor {anchor_id} is {status}"
    );
    assert_eq!(
        backend, "mock",
        "unset EPIGRAPH_ANCHOR_BACKEND must mean mock, not off"
    );
    let tx_id = tx_id.expect("a confirmed anchor carries a transaction id");
    assert!(block_height.is_some());

    // The ledger row must exist, under the reserved metadatum label, holding
    // the exact bytes we recorded.
    let (label, published): (i64, Vec<u8>) = sqlx::query_as(
        "SELECT metadata_label, metadata_cbor FROM anchor_mock_chain WHERE tx_id = $1",
    )
    .bind(&tx_id)
    .fetch_one(&pool)
    .await
    .expect("the seal must have published to the ledger too");
    assert_eq!(label, 40961);
    assert_eq!(
        published, commitment,
        "the ledger's bytes and ours must be byte-identical"
    );
    assert_eq!(mock_chain_count(&pool).await, 1);

    // And the anchored root is the manifest's actual root.
    let manifest_root: Vec<u8> = sqlx::query_scalar("SELECT root FROM manifests WHERE id = $1")
        .bind(manifest_id)
        .fetch_one(&pool)
        .await
        .expect("manifest root");
    let anchored_root: Vec<u8> = sqlx::query_scalar("SELECT root_hash FROM anchors WHERE id = $1")
        .bind(anchor_id)
        .fetch_one(&pool)
        .await
        .expect("anchored root");
    assert_eq!(anchored_root, manifest_root);
}

/// The seal must not be able to fail because of anchoring — and a read-only
/// server must not sneak a write in through the anchor path either.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refused_seal_anchors_nothing(pool: PgPool) {
    let root = seed_subgraph(&pool).await;
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0xA7; 32]).expect("signer");
    let embedder = epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None);
    let server = epigraph_mcp::EpiGraphMcpFull::new(
        pool.clone(),
        signer,
        embedder,
        /* read_only */ true,
    );

    export_subgraph_manifest(
        &server,
        ExportSubgraphManifestParams {
            root_claim_id: root.to_string(),
            max_depth: None,
        },
    )
    .await
    .expect_err("a read-only server refuses to seal");

    assert_eq!(anchor_count(&pool).await, 0);
    assert_eq!(mock_chain_count(&pool).await, 0);
}

async fn anchor_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM anchors")
        .fetch_one(pool)
        .await
        .expect("count anchors")
}

async fn mock_chain_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM anchor_mock_chain")
        .fetch_one(pool)
        .await
        .expect("count mock chain")
}
