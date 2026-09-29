//! `submit_ds_evidence`'s `hypothesis_index` and the framed `get_belief` read
//! answer about the same hypothesis, and an index outside the frame is WARNED
//! about rather than silently read as something else (backlog 45cbaef4, G6).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_db::FrameRepository;
use epigraph_mcp::{embed::McpEmbedder, tools, EpiGraphMcpFull};
use sqlx::PgPool;
use uuid::Uuid;

async fn make_server(pool: PgPool) -> EpiGraphMcpFull {
    let signer = AgentSigner::from_bytes(&[0x6au8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = fixture::scoped_pool(&pool).await;
    EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

async fn insert_claim(pool: &PgPool, content: &str) -> Uuid {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, sha256($1::bytea), 0.5, $2, true) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn submitted_and_read_beliefs_agree_and_a_bad_index_is_warned(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = make_server(pool.clone()).await;
    let frame = FrameRepository::create(
        &pool,
        "g6_mcp_three_way",
        None,
        &["low".to_string(), "mid".to_string(), "high".to_string()],
    )
    .await
    .unwrap();

    for (index, want_warning) in [(2, false), (0, false), (5, true), (-1, true)] {
        let claim = insert_claim(&pool, &format!("g6 mcp index {index}")).await;
        let submitted = first_text(
            &tools::ds::submit_ds_evidence(
                &server,
                &viewer,
                serde_json::from_value(serde_json::json!({
                    "claim_id": claim.to_string(),
                    "frame_id": frame.id.to_string(),
                    "hypothesis_index": index,
                    "masses": {"0": 0.5, "2": 0.2, "0,1,2": 0.3},
                    "evidence_type": "empirical",
                }))
                .unwrap(),
                None,
            )
            .await
            .expect("accepted"),
        );
        let warned = submitted["warnings"]
            .as_array()
            .map(|w| {
                w.iter().any(|s| {
                    s.as_str()
                        .unwrap()
                        .contains(&format!("hypothesis_index={index}"))
                })
            })
            .unwrap_or(false);
        assert_eq!(warned, want_warning, "index {index}: {submitted}");

        let read = first_text(
            &tools::ds::get_belief(
                &server,
                &viewer,
                serde_json::from_value(serde_json::json!({
                    "claim_id": claim.to_string(),
                    "frame_id": frame.id.to_string(),
                }))
                .unwrap(),
            )
            .await
            .unwrap(),
        );
        for f in ["belief", "plausibility", "pignistic_prob"] {
            let (a, b) = (submitted[f].as_f64().unwrap(), read[f].as_f64().unwrap());
            assert!(
                (a - b).abs() < 1e-9,
                "index {index}: submit_ds_evidence {f} = {a}, framed get_belief {f} = {b}"
            );
        }
    }
}
