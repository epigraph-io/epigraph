//! `find_workflow_hierarchical(resolve_to_latest=true)`: a DEPRECATED lineage
//! head (truth below `min_truth`) sorts AFTER the live rows of its group,
//! still returned and still flagged `lineage_head_deprecated`.
//!
//! #676 made the true lineage head always present and ordered it first in its
//! group. For a deprecated head that put the one row a caller should NOT pick
//! ahead of every live generation. A live head still leads its group.
//!
//! Both search paths are covered: the ILIKE path (mock embedder) and the
//! embedding path (a deterministic in-process generator, so no request leaves
//! the process; `search_path` proves which path answered).

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::tools::workflow_hierarchical::find_workflow_hierarchical;
use epigraph_mcp::types::FindWorkflowHierarchicalParams;
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

const DIM: usize = 1536;

/// A unit vector in the plane of axes 0 and 1 whose cosine similarity to the
/// axis-0 query vector is `cos`.
fn at_similarity(cos: f32) -> Vec<f32> {
    let mut v = vec![0.0_f32; DIM];
    v[0] = cos;
    v[1] = (1.0 - cos * cos).sqrt();
    v
}

fn signer() -> AgentSigner {
    AgentSigner::from_bytes(&[0xA7u8; 32]).expect("signer")
}

/// Mock embedder (no API key): `find_workflow_hierarchical` takes the ILIKE path.
fn ilike_server(pool: PgPool) -> EpiGraphMcpFull {
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer(), embedder, false)
}

/// A non-mock embedder whose `generate` is the axis-0 unit vector for every
/// text: `find_workflow_hierarchical` takes the embedding path.
fn embedding_server(pool: PgPool) -> EpiGraphMcpFull {
    let embedder = McpEmbedder::new(pool.clone(), Some("in-process-generator".to_string()))
        .with_generator(std::sync::Arc::new(|_text: &str| Ok(at_similarity(1.0))));
    EpiGraphMcpFull::new(pool, signer(), embedder, false)
}

async fn seed(
    pool: &PgPool,
    canonical: &str,
    generation: i32,
    goal: &str,
    truth: f64,
    embedding: Option<Vec<f32>>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, parent_id, metadata, created_at, truth_value) \
         VALUES ($1, $2, $3, $4, NULL, '{}', NOW(), $5)",
    )
    .bind(id)
    .bind(canonical)
    .bind(generation)
    .bind(goal)
    .bind(truth)
    .execute(pool)
    .await
    .unwrap();
    if let Some(v) = embedding {
        epigraph_db::WorkflowRepository::set_goal_embedding(pool, id, &v)
            .await
            .expect("set goal embedding");
    }
    id
}

/// Two lineages.
///
/// * `alpha`: gen 0 live (truth 1.0, similarity 0.9), gen 1 live (truth 0.6,
///   similarity 1.0), gen 2 the head, DEPRECATED (truth 0.05, no embedding).
///   The live truths run opposite to generation, so a truth-descending sort
///   would swap gen 0 and gen 1; deprecated-last keeps generation order.
/// * `beta`: gen 0 live and matched (similarity 0.8), gen 1 the LIVE head,
///   never matched (its goal misses the query and it has no embedding): it is
///   injected and must still lead its group.
struct Fixture {
    a0: Uuid,
    a1: Uuid,
    a_dead: Uuid,
    b0: Uuid,
    b_head: Uuid,
}

async fn seed_fixture(pool: &PgPool) -> Fixture {
    let alpha = "alpha-deprecated-head-order";
    let beta = "beta-deprecated-head-order";
    Fixture {
        a0: seed(
            pool,
            alpha,
            0,
            "qqdeporder send the digest",
            1.0,
            Some(at_similarity(0.9)),
        )
        .await,
        a1: seed(
            pool,
            alpha,
            1,
            "qqdeporder send the digest v1",
            0.6,
            Some(at_similarity(1.0)),
        )
        .await,
        a_dead: seed(pool, alpha, 2, "qqdeporder send the digest v2", 0.05, None).await,
        b0: seed(
            pool,
            beta,
            0,
            "qqdeporder triage the inbox",
            1.0,
            Some(at_similarity(0.8)),
        )
        .await,
        b_head: seed(
            pool,
            beta,
            1,
            "rewritten plan with no shared words",
            1.0,
            None,
        )
        .await,
    }
}

async fn search(server: &EpiGraphMcpFull, pool: &PgPool) -> serde_json::Value {
    let viewer = fixture::public_viewer(pool).await;
    let result = find_workflow_hierarchical(
        server,
        &viewer,
        FindWorkflowHierarchicalParams {
            query: "qqdeporder".to_string(),
            limit: Some(10),
            resolve_to_latest: Some(true),
            // Default min_truth (0.3): the 0.05 head is below it.
            min_truth: None,
        },
    )
    .await
    .expect("find_workflow_hierarchical");
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content");
    serde_json::from_str(&text).expect("JSON body")
}

fn assert_deprecated_head_trails(body: &serde_json::Value, f: &Fixture) {
    let workflows = body["workflows"].as_array().expect("workflows array");
    let order: Vec<Uuid> = workflows
        .iter()
        .filter_map(|w| w["workflow_id"].as_str().and_then(|s| s.parse().ok()))
        .collect();
    assert_eq!(
        order,
        vec![f.a1, f.a0, f.a_dead, f.b_head, f.b0],
        "expected [alpha gen1, alpha gen0, alpha DEPRECATED head, beta live head, beta gen0] \
         (a deprecated head trails the live rows of its group; a live head leads its group); \
         got {body}"
    );
    let entry = |id: Uuid| {
        workflows
            .iter()
            .find(|w| w["workflow_id"].as_str() == Some(&id.to_string()))
            .unwrap_or_else(|| panic!("{id} must be returned; got {body}"))
    };
    let dead = entry(f.a_dead);
    assert_eq!(dead["is_lineage_head"], serde_json::json!(true), "{dead}");
    for id in [f.a0, f.a1, f.a_dead] {
        let w = entry(id);
        assert_eq!(w["lineage_head_generation"], serde_json::json!(2), "{w}");
        assert_eq!(
            w["lineage_head_deprecated"],
            serde_json::json!(true),
            "still flagged deprecated: {w}"
        );
    }
    let b_head = entry(f.b_head);
    assert_eq!(
        b_head["is_lineage_head"],
        serde_json::json!(true),
        "{b_head}"
    );
    for id in [f.b0, f.b_head] {
        assert_eq!(
            entry(id)["lineage_head_deprecated"],
            serde_json::json!(false),
            "{body}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn ilike_path_sorts_a_deprecated_head_after_its_groups_live_rows(pool: PgPool) {
    let f = seed_fixture(&pool).await;
    let server = ilike_server(pool.clone());
    let body = search(&server, &pool).await;
    assert_eq!(body["search_path"], serde_json::json!("ilike"), "{body}");
    assert_deprecated_head_trails(&body, &f);
}

#[sqlx::test(migrations = "../../migrations")]
async fn embedding_path_sorts_a_deprecated_head_after_its_groups_live_rows(pool: PgPool) {
    let f = seed_fixture(&pool).await;
    let server = embedding_server(pool.clone());
    let body = search(&server, &pool).await;
    assert_eq!(
        body["search_path"],
        serde_json::json!("embedding"),
        "the embedding path must answer, not the ILIKE fallback: {body}"
    );
    assert_deprecated_head_trails(&body, &f);
}

/// The ordering an agent reads in the tool schema must state it.
#[test]
fn resolve_to_latest_description_states_the_deprecated_head_order() {
    let tools = EpiGraphMcpFull::all_tools_json();
    let d = tools
        .as_array()
        .expect("all_tools_json returns an array")
        .iter()
        .find(|t| t["name"] == "find_workflow_hierarchical")
        .and_then(|t| t["inputSchema"]["properties"]["resolve_to_latest"]["description"].as_str())
        .expect("find_workflow_hierarchical.resolve_to_latest carries a description")
        .to_string();
    for needle in [
        "a live head leads its lineage group",
        "a deprecated head (truth below min_truth) sorts after the live rows of its group",
    ] {
        assert!(
            d.contains(needle),
            "resolve_to_latest must say {needle:?}; got: {d}"
        );
    }
}
