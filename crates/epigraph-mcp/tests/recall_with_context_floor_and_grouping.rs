//! Three `recall_with_context` contracts (backlog batch B29):
//!
//! - **a2991ea6**: `diverse=true` with `paper_doi_filter` is REJECTED. The
//!   diverse pipeline's theme candidate query has no DOI predicate, so the
//!   combination used to succeed and silently ignore the filter whenever the
//!   corpus had themes (and honour it only when it fell back to flat ANN).
//! - **75920ad6**: a page whose candidates ALL fell below `min_truth` says so
//!   (`below_confidence_floor`, `insufficient_confidence`), so "nothing
//!   relevant" and "relevant, but not believed enough" are distinguishable.
//! - **4e856a99**: `group_by_parent=true` returns co-parent hits adjacent,
//!   under the `decomposes_to` parent they share, without changing the set.
//!
//! Driven through `__test_only::recall_with_context_with_pgvec` (no embedder
//! API key in the test environment). Parameters are built from JSON so this
//! file compiles against a params struct with or without the new field.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;
use epigraph_mcp::tools::recall::RecallWithContextParams;
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

/// A unit vector at `deg` degrees in the dim-0/dim-1 plane: distance to the
/// query (`vec_angle(0.0)`) grows strictly with the angle, so the flat order
/// is the angle order.
fn vec_angle(deg: f64) -> String {
    let (s, c) = deg.to_radians().sin_cos();
    let mut v: Vec<String> = vec!["0.0".to_string(); 1536];
    v[0] = format!("{c:.6}");
    v[1] = format!("{s:.6}");
    format!("[{}]", v.join(","))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'b29-recall', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// A current public claim; `deg = None` leaves it unembedded (not a hit).
async fn seed_claim(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    truth: f64,
    deg: Option<f64>,
) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, embedding) \
         VALUES ($1, sha256($1::bytea), $2, $3, true, $4::vector) RETURNING id",
    )
    .bind(content)
    .bind(truth)
    .bind(agent)
    .bind(deg.map(vec_angle))
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(parent)
    .bind(child)
    .execute(pool)
    .await
    .expect("seed decomposes_to edge");
}

fn params(extra: Value) -> RecallWithContextParams {
    let mut base = json!({ "query": "b29 probe", "limit": 10, "centroid_dim": 1536 });
    for (k, v) in extra.as_object().expect("object").iter() {
        base[k] = v.clone();
    }
    serde_json::from_value(base).expect("RecallWithContextParams")
}

async fn recall(pool: &PgPool, extra: Value) -> Result<Value, epigraph_mcp::errors::McpError> {
    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(pool).await;
    let out =
        recall_with_context_with_pgvec(&server, &viewer, params(extra), 1536, &vec_angle(0.0))
            .await?;
    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    Ok(serde_json::from_str(&text).expect("parse recall_with_context envelope"))
}

fn hit_ids(hits: &Value) -> Vec<String> {
    hits.as_array()
        .expect("hit array")
        .iter()
        .map(|h| {
            h["paragraph_id"]
                .as_str()
                .expect("paragraph_id")
                .to_string()
        })
        .collect()
}

// ── a2991ea6 ────────────────────────────────────────────────────────────────

/// The combination is refused with an error naming both parameters, before
/// any retrieval. Pre-fix the call SUCCEEDED (on a theme-less corpus it fell
/// back to flat ANN; on a themed one it returned theme candidates from every
/// paper), so `expect_err` is the failing assertion.
#[sqlx::test(migrations = "../../migrations")]
async fn diverse_with_paper_doi_filter_is_rejected(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    seed_claim(&pool, agent, "b29 doi probe claim", 0.9, Some(1.0)).await;

    let err = recall(
        &pool,
        json!({ "diverse": true, "paper_doi_filter": "10.1/b29-doi" }),
    )
    .await
    .expect_err("diverse=true with paper_doi_filter must be rejected, not silently ignored");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("paper_doi_filter") && msg.contains("diverse"),
        "the refusal must name both parameters; got {msg}"
    );

    // Each alone is still accepted.
    recall(&pool, json!({ "diverse": true }))
        .await
        .expect("diverse alone is accepted");
    recall(&pool, json!({ "paper_doi_filter": "10.1/b29-doi" }))
        .await
        .expect("paper_doi_filter alone is accepted");
    recall(
        &pool,
        json!({ "diverse": false, "paper_doi_filter": "10.1/b29-doi" }),
    )
    .await
    .expect("diverse=false with paper_doi_filter is accepted");
}

// ── 75920ad6 ────────────────────────────────────────────────────────────────

/// Three cases on one corpus, in order:
/// 1. every candidate below the floor → `below_confidence_floor` = 3 and
///    `insufficient_confidence` = true, with an empty page;
/// 2. one candidate above it too → the count still reports the 3 dropped, and
///    the flag is false because something was returned;
/// 3. the flag reads the min_truth gate, not final emptiness: when
///    `exclude_contested` empties the page, the flag stays false.
#[sqlx::test(migrations = "../../migrations")]
async fn a_page_emptied_by_the_belief_floor_says_so(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    for (i, deg) in [1.0, 2.0, 3.0].into_iter().enumerate() {
        seed_claim(
            &pool,
            agent,
            &format!("b29 low-belief claim {i}"),
            0.2,
            Some(deg),
        )
        .await;
    }

    let body = recall(&pool, json!({ "min_truth": 0.3 }))
        .await
        .expect("recall");
    assert_eq!(
        body["results"],
        json!([]),
        "calibration: every candidate is below 0.3"
    );
    assert_eq!(
        body["below_confidence_floor"].as_u64(),
        Some(3),
        "an empty page whose 3 candidates all fell below min_truth must count them; got {body}"
    );
    assert_eq!(
        body["insufficient_confidence"].as_bool(),
        Some(true),
        "an empty page whose candidates all fell below min_truth must flag it; got {body}"
    );

    // The partitioned shape carries the same signal (top level, not per hit).
    let body = recall(
        &pool,
        json!({ "min_truth": 0.3, "epistemic_partition": true }),
    )
    .await
    .expect("recall partitioned");
    assert_eq!(body["below_confidence_floor"].as_u64(), Some(3));
    assert_eq!(body["insufficient_confidence"].as_bool(), Some(true));

    // Case 2.
    let strong = seed_claim(&pool, agent, "b29 well-believed claim", 0.9, Some(4.0)).await;
    let body = recall(&pool, json!({ "min_truth": 0.3 }))
        .await
        .expect("recall");
    assert_eq!(hit_ids(&body["results"]), vec![strong.to_string()]);
    assert_eq!(
        body["below_confidence_floor"].as_u64(),
        Some(3),
        "the dropped count is reported whether or not something survived; got {body}"
    );
    assert_eq!(
        body["insufficient_confidence"].as_bool(),
        Some(false),
        "a page that returned a hit is not insufficient; got {body}"
    );

    // Case 3: contest the only survivor, then exclude contested hits.
    let contester = seed_claim(&pool, agent, "b29 contesting claim", 0.9, None).await;
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'refutes')",
    )
    .bind(contester)
    .bind(strong)
    .execute(&pool)
    .await
    .expect("seed refutes edge");
    let body = recall(
        &pool,
        json!({ "min_truth": 0.3, "exclude_contested": true }),
    )
    .await
    .expect("recall");
    assert_eq!(
        body["results"],
        json!([]),
        "calibration: the survivor is contested"
    );
    assert_eq!(
        body["insufficient_confidence"].as_bool(),
        Some(false),
        "exclude_contested, not the belief floor, emptied this page; got {body}"
    );
}

/// No candidates at all: the floor dropped nothing, so the signal is 0/false
/// and the page is the ordinary empty one.
#[sqlx::test(migrations = "../../migrations")]
async fn an_empty_corpus_is_not_insufficient_confidence(pool: PgPool) {
    let body = recall(&pool, json!({ "min_truth": 0.3 }))
        .await
        .expect("recall");
    assert_eq!(body["results"], json!([]));
    assert_eq!(
        body["below_confidence_floor"].as_u64(),
        Some(0),
        "got {body}"
    );
    assert_eq!(
        body["insufficient_confidence"].as_bool(),
        Some(false),
        "got {body}"
    );
}
