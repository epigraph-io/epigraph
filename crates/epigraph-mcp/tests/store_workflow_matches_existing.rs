//! `store_workflow` matches a reworded goal to the existing hierarchical
//! workflow instead of minting a new generation-0 lineage (backlog 5e54282f).
//!
//! `store_workflow` derives the lineage from `slugify(goal)`, so it was
//! idempotent only on the EXACT goal text: "Deploy the Rust binary to the
//! Windows server" and "Deploy Rust binary to Windows server" became two
//! unrelated lineages, and the variant history `improve_workflow_hierarchy`
//! builds was split between them.
//!
//! # How the paraphrase is made similar in a test process
//!
//! `McpEmbedder::with_generator` replaces the provider. The generator here
//! ([`goal_vector`]) derives the vector from the goal's lower-cased words with
//! a few stop words removed and the rest sorted, so two wordings of one goal
//! embed to the SAME vector (cosine 1.0, the geometry a real embedder gives a
//! close paraphrase), and an unrelated goal to a pseudo-random one (cosine
//! near 0). The similarity itself is computed by pgvector over the stored
//! `workflows.goal_embedding`, through the real `store_workflow`.
//!
//! # Verified to fail
//!
//! On the code before this change the paraphrase arm minted a second
//! generation-0 row (two rows, `matched_existing` absent from the response).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::types::StoreWorkflowParams;
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

const DIM: usize = 1536;
const STOP_WORDS: [&str; 6] = ["the", "a", "an", "to", "on", "of"];

/// A deterministic vector for `text` that depends only on its set of
/// non-stop words (see the module docs). FNV-1a over the sorted words seeds an
/// xorshift64 stream; each component is the stream's top 16 bits, centred.
fn goal_vector(text: &str) -> Vec<f32> {
    let lower = text.to_lowercase();
    let mut words: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty() && !STOP_WORDS.contains(w))
        .collect();
    words.sort_unstable();
    words.dedup();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in words.join(" ").bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    let mut out = Vec::with_capacity(DIM);
    for _ in 0..DIM {
        h ^= h << 13;
        h ^= h >> 7;
        h ^= h << 17;
        let top = u16::try_from(h >> 48).expect("the top 16 bits fit a u16");
        out.push(f32::from(top) - 32_768.0);
    }
    out
}

async fn server_with_goal_embedder(
    pool: &PgPool,
) -> (EpiGraphMcpFull, epigraph_db::visibility::Viewer) {
    let scoped = fixture::scoped_pool(pool).await;
    let embedder = McpEmbedder::new(pool.clone(), None)
        .with_scoped_pool(scoped.clone())
        .with_generator(std::sync::Arc::new(|text: &str| Ok(goal_vector(text))));
    let server = EpiGraphMcpFull::new(
        pool.clone(),
        AgentSigner::from_bytes(&[0x5Eu8; 32]).expect("signer"),
        embedder,
        false,
    )
    .with_scoped_pool(scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    let viewer = epigraph_db::visibility::Viewer::resolve(pool, agent)
        .await
        .expect("viewer");
    (server, viewer)
}

fn params(goal: &str, force_new: Option<bool>) -> StoreWorkflowParams {
    StoreWorkflowParams {
        goal: goal.to_string(),
        steps: vec![format!("step for {goal}")],
        prerequisites: None,
        expected_outcome: None,
        confidence: None,
        tags: None,
        tenancy: None,
        force_new,
    }
}

async fn store(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    goal: &str,
    force_new: Option<bool>,
) -> serde_json::Value {
    let r = epigraph_mcp::tools::workflows::store_workflow(
        server,
        viewer,
        params(goal, force_new),
        None,
    )
    .await
    .expect("store_workflow");
    assert_ne!(r.is_error, Some(true), "{r:?}");
    first_text(&r)
}

async fn row_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflows")
        .fetch_one(pool)
        .await
        .expect("count workflows")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_reworded_goal_matches_the_existing_lineage_unless_forced(pool: PgPool) {
    let (server, viewer) = server_with_goal_embedder(&pool).await;
    let tag = Uuid::new_v4().simple().to_string();
    let original_goal = format!("Deploy the Rust binary to the Windows server {tag}");
    let reworded_goal = format!("Deploy Rust binary to Windows server {tag}");
    let base = row_count(&pool).await;

    let original = store(&server, &viewer, &original_goal, None).await;
    assert_eq!(original["matched_existing"], serde_json::json!(false));
    assert_eq!(row_count(&pool).await, base + 1);

    // The paraphrase stores nothing and names the existing workflow.
    let reworded = store(&server, &viewer, &reworded_goal, None).await;
    assert_eq!(
        reworded["matched_existing"],
        serde_json::json!(true),
        "{reworded}"
    );
    assert_eq!(
        reworded["workflow_id"], original["workflow_id"],
        "{reworded}"
    );
    assert_eq!(reworded["canonical_name"], original["canonical_name"]);
    assert_eq!(reworded["claims_ingested"], serde_json::json!(0));
    assert!(
        reworded["similarity"].as_f64().unwrap_or(0.0) >= 0.9,
        "{reworded}"
    );
    let hint = reworded["hint"].as_str().unwrap_or_default();
    assert!(
        hint.contains("improve_workflow_hierarchy")
            && hint.contains(original["canonical_name"].as_str().unwrap()),
        "{hint}"
    );
    assert_eq!(
        row_count(&pool).await,
        base + 1,
        "no second lineage was minted"
    );

    // The exact goal again is the ingest's own no-op, not a match.
    let again = store(&server, &viewer, &original_goal, None).await;
    assert_eq!(
        again["matched_existing"],
        serde_json::json!(false),
        "{again}"
    );
    assert_eq!(
        again["already_ingested"],
        serde_json::json!(true),
        "{again}"
    );
    assert_eq!(row_count(&pool).await, base + 1);

    // force_new mints the paraphrase as its own lineage.
    let forced = store(&server, &viewer, &reworded_goal, Some(true)).await;
    assert_eq!(
        forced["matched_existing"],
        serde_json::json!(false),
        "{forced}"
    );
    assert_ne!(forced["workflow_id"], original["workflow_id"]);
    assert_eq!(row_count(&pool).await, base + 2);

    // An unrelated goal is a new lineage without force_new.
    let unrelated = store(
        &server,
        &viewer,
        &format!("Rotate the TLS certificates on the proxy {tag}"),
        None,
    )
    .await;
    assert_eq!(
        unrelated["matched_existing"],
        serde_json::json!(false),
        "{unrelated}"
    );
    assert_eq!(row_count(&pool).await, base + 3);
}
