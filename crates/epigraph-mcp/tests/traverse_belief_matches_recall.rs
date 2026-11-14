//! `traverse` reports the same `belief_score` as `recall_with_context` for the
//! same claim and viewer (backlog 1574d9b4).
//!
//! `belief_score` is documented on both surfaces as the claim's effective
//! belief: the DS pignistic probability when the claim carries a DS cache,
//! else `truth_value`. `traverse` resolved it only when `min_truth > 0.0`; on
//! the DEFAULT path (`min_truth = 0.0`) it reported the authored `truth_value`
//! under that name. A claim refuted down to BetP 0.18 therefore read 1.0 in
//! `traverse` and 0.18 in `recall` — the same field, the same claim, the same
//! caller.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools;
use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

fn build_test_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    let scoped = epigraph_db::ScopedPool::connect_lazy_for_tests(
        (*pool.connect_options()).clone(),
        epigraph_db::SessionGucMode::Session,
    );
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false).with_scoped_pool(scoped)
}

fn vec_angle(deg: f64) -> String {
    let (s, c) = deg.to_radians().sin_cos();
    let mut v: Vec<String> = vec!["0.0".to_string(); 1536];
    v[0] = format!("{c:.6}");
    v[1] = format!("{s:.6}");
    format!("[{}]", v.join(","))
}

fn text(out: &rmcp::model::CallToolResult) -> Value {
    let t = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    serde_json::from_str(&t).expect("parse tool JSON")
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'b29-traverse', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, truth: f64, deg: f64) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, embedding) \
         VALUES ($1, sha256($1::bytea), $2, $3, true, $4::vector) RETURNING id",
    )
    .bind(content)
    .bind(truth)
    .bind(agent)
    .bind(vec_angle(deg))
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// A DS cache as the edge-wiring recompute writes it (the read is under test,
/// not the recompute).
async fn set_ds_cache(pool: &PgPool, claim: Uuid, belief: f64, plausibility: f64, betp: f64) {
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4 WHERE id = $1",
    )
    .bind(claim)
    .bind(belief)
    .bind(plausibility)
    .bind(betp)
    .execute(pool)
    .await
    .expect("seed DS cache");
}

fn node<'a>(walk: &'a Value, id: Uuid) -> &'a Value {
    walk["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|n| n["id"] == json!(id.to_string()))
        .unwrap_or_else(|| panic!("node {id} missing from traverse: {walk}"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn traverse_and_recall_report_the_same_belief_score(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // `refuted`: authored 1.0, DS BetP 0.1797. `plain`: no DS state at all.
    let refuted = seed_claim(&pool, agent, "b29 refuted start claim", 1.0, 1.0).await;
    let plain = seed_claim(&pool, agent, "b29 plain neighbour claim", 0.7, 2.0).await;
    set_ds_cache(&pool, refuted, 0.0, 0.3594, 0.1797).await;
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'supports')",
    )
    .bind(refuted)
    .bind(plain)
    .execute(&pool)
    .await
    .expect("seed supports edge");

    let recalled = text(
        &recall_with_context_with_pgvec(
            &server,
            &viewer,
            serde_json::from_value(json!({
                "query": "b29 traverse probe", "limit": 10, "min_truth": 0.0,
                "centroid_dim": 1536,
            }))
            .expect("params"),
            1536,
            &vec_angle(0.0),
        )
        .await
        .expect("recall_with_context"),
    );
    let recall_score = |id: Uuid| -> f64 {
        recalled["results"]
            .as_array()
            .expect("results")
            .iter()
            .find(|h| h["paragraph_id"] == json!(id.to_string()))
            .and_then(|h| h["belief_score"].as_f64())
            .unwrap_or_else(|| panic!("{id} missing from recall: {recalled}"))
    };
    assert!(
        (recall_score(refuted) - 0.1797).abs() < 1e-9,
        "calibration: recall reads the DS cache"
    );

    // The default path (no min_truth) and an explicit gate below every score
    // must agree with recall and with each other.
    for min_truth in [None, Some(0.1)] {
        let mut p = json!({ "start_id": refuted.to_string(), "max_depth": 1, "limit": 100 });
        if let Some(m) = min_truth {
            p["min_truth"] = json!(m);
        }
        let walk = text(
            &tools::graph::traverse(&server, &viewer, serde_json::from_value(p).unwrap())
                .await
                .expect("traverse"),
        );
        for id in [refuted, plain] {
            let n = node(&walk, id);
            assert_eq!(
                n["belief_score"].as_f64(),
                Some(recall_score(id)),
                "min_truth {min_truth:?}: traverse reported belief_score {} for {id} but \
                 recall reports {} for the same claim and viewer (truth_value {}). On the \
                 default path traverse used to copy truth_value into belief_score",
                n["belief_score"],
                recall_score(id),
                n["truth_value"]
            );
        }
        assert_eq!(
            node(&walk, refuted)["truth_value"].as_f64(),
            Some(1.0),
            "truth_value stays the authored value"
        );
    }
}
