//! Regression: `mcp__epigraph__memorize`'s `tags` parameter must populate
//! `claims.labels` so the resulting claim is discoverable via
//! `query_claims_by_label`. Pre-fix, `tags` only appeared in the evidence
//! text + response payload, not on the claim row — `query_claims_by_label`
//! returned empty for memorize'd claims.

#[macro_use]
mod common;

use common::*;
use epigraph_crypto::{AgentSigner, ContentHasher};
use epigraph_mcp::types::MemorizeParams;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

async fn build_test_server(pool: PgPool, signer_seed: [u8; 32]) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&signer_seed).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, false)
}

async fn server_agent_uuid(pool: &PgPool, signer_seed: [u8; 32]) -> Uuid {
    let signer = AgentSigner::from_bytes(&signer_seed).expect("signer");
    let pub_key = signer.public_key();
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM agents WHERE public_key = $1")
        .bind(pub_key.as_slice())
        .fetch_one(pool)
        .await
        .expect("server agent must exist")
}

#[tokio::test]
async fn memorize_with_tags_populates_claims_labels() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    let signer_seed = [0xA1u8; 32];
    let server = build_test_server(pool.clone(), signer_seed).await;

    let content = format!("memorize-labels test {}", Uuid::new_v4());
    let params = MemorizeParams {
        content: content.clone(),
        confidence: Some(0.7),
        tags: Some(vec!["backlog".to_string(), "alt-set-extension".to_string()]),
    };

    tools::memory::memorize(&server, params)
        .await
        .expect("memorize");

    let agent_id = server_agent_uuid(&pool, signer_seed).await;
    let content_hash = ContentHasher::hash(content.as_bytes());

    let row: (Vec<String>,) =
        sqlx::query_as("SELECT labels FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(content_hash.as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .expect("claim row");

    let labels = row.0;
    assert!(
        labels.contains(&"backlog".to_string()),
        "labels must include 'backlog', got {labels:?}"
    );
    assert!(
        labels.contains(&"alt-set-extension".to_string()),
        "labels must include 'alt-set-extension', got {labels:?}"
    );
}

#[tokio::test]
async fn memorize_resubmit_accumulates_labels() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    let signer_seed = [0xA2u8; 32];
    let server = build_test_server(pool.clone(), signer_seed).await;

    let content = format!("memorize-accum test {}", Uuid::new_v4());

    // First call: tags = ["one"]
    tools::memory::memorize(
        &server,
        MemorizeParams {
            content: content.clone(),
            confidence: Some(0.7),
            tags: Some(vec!["one".to_string()]),
        },
    )
    .await
    .expect("first memorize");

    // Second call (dedup hit): tags = ["two"]
    tools::memory::memorize(
        &server,
        MemorizeParams {
            content: content.clone(),
            confidence: Some(0.7),
            tags: Some(vec!["two".to_string()]),
        },
    )
    .await
    .expect("second memorize");

    let agent_id = server_agent_uuid(&pool, signer_seed).await;
    let content_hash = ContentHasher::hash(content.as_bytes());

    let row: (Vec<String>,) =
        sqlx::query_as("SELECT labels FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(content_hash.as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .expect("claim row");

    let labels = row.0;
    assert!(
        labels.contains(&"one".to_string()) && labels.contains(&"two".to_string()),
        "labels must accumulate across memorize calls, got {labels:?}"
    );
}

#[tokio::test]
async fn memorize_without_tags_leaves_labels_empty() {
    let pool = test_pool_or_skip!();
    drop_unique_constraint(&pool).await;

    let signer_seed = [0xA3u8; 32];
    let server = build_test_server(pool.clone(), signer_seed).await;

    let content = format!("memorize-no-tags test {}", Uuid::new_v4());
    tools::memory::memorize(
        &server,
        MemorizeParams {
            content: content.clone(),
            confidence: Some(0.7),
            tags: None,
        },
    )
    .await
    .expect("memorize");

    let agent_id = server_agent_uuid(&pool, signer_seed).await;
    let content_hash = ContentHasher::hash(content.as_bytes());

    let row: (Vec<String>,) =
        sqlx::query_as("SELECT labels FROM claims WHERE content_hash = $1 AND agent_id = $2")
            .bind(content_hash.as_slice())
            .bind(agent_id)
            .fetch_one(&pool)
            .await
            .expect("claim row");

    assert!(
        row.0.is_empty(),
        "no tags → empty labels, got {labels:?}",
        labels = row.0
    );
}
