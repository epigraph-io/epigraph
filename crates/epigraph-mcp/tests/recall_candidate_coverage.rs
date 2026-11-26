//! `recall` reports how much of the well-matched candidate pool its response
//! covers (backlog 8c511f13): `n_total_candidates`, `coverage_rate` and
//! `candidate_pool_saturated`.
//!
//! A candidate is well matched when it is in the lexical leg or its dense
//! similarity is at least `RECALL_MATCH_MIN_SIMILARITY` (0.40). The fixtures put
//! rows on both sides of that floor, so a count that ignored it would differ.
//!
//! Every params struct is built with `serde_json::from_value`, so this file
//! compiles on the code before the change; there the fields are simply absent
//! and the tests fail on an assertion.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::memory::__test_only::recall_with_pgvec;
use epigraph_mcp::types::RecallParams;
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

async fn seed_agent(pool: &PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind("aa".repeat(32))
        .execute(pool)
        .await
        .expect("seed agent");
    agent_id
}

/// A unit vector at `deg` degrees in the dim-0/dim-1 plane. The query is the
/// 0-degree vector, so a row's dense similarity is `cos(deg)`.
fn vec_angle(deg: f64) -> String {
    let (s, c) = deg.to_radians().sin_cos();
    let mut v: Vec<String> = vec!["0.0".to_string(); 1536];
    v[0] = format!("{c:.6}");
    v[1] = format!("{s:.6}");
    format!("[{}]", v.join(","))
}

/// A current claim. `embedding = None` keeps it out of the dense leg.
async fn insert_claim(
    pool: &PgPool,
    agent: Uuid,
    content: &str,
    embedding: Option<&str>,
    truth: f64,
) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[..16].copy_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, is_current, \
                             embedding) \
         VALUES ($1, $2, $3, $4, $5, true, $6::vector)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent)
    .bind(truth)
    .bind(embedding)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

fn params(query: &str, limit: i64) -> RecallParams {
    serde_json::from_value(json!({ "query": query, "limit": limit })).expect("params")
}

async fn recall_body(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    p: RecallParams,
    pgvec: Option<String>,
) -> Value {
    let out = recall_with_pgvec(server, viewer, p, pgvec)
        .await
        .expect("recall ok");
    let text = out
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    serde_json::from_str(&text).expect("recall envelope")
}

fn coverage(body: &Value) -> (Option<i64>, Option<f64>, Option<bool>) {
    (
        body.get("n_total_candidates").and_then(Value::as_i64),
        body.get("coverage_rate").and_then(Value::as_f64),
        body.get("candidate_pool_saturated")
            .and_then(Value::as_bool),
    )
}

/// 15 dense rows above the floor, 10 below it, and 5 lexical-only rows: 20
/// well-matched candidates. `limit = 10` takes dense ranks 1-5 and lexical
/// ranks 1-5, all well matched; `min_truth` then drops the two nearest dense
/// rows (truth 0.1), so 8 well-matched claims come back: coverage 8 / 20.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_reports_the_well_matched_pool_and_the_share_returned(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    // Near rows: 0..28 degrees, similarity 1.0 down to 0.88.
    for i in 0..15 {
        let truth = if i < 2 { 0.1 } else { 0.8 };
        let v = vec_angle(2.0 * f64::from(i));
        insert_claim(
            &pool,
            agent,
            &format!("near filler row {i}"),
            Some(&v),
            truth,
        )
        .await;
    }
    // Far rows: 70..88 degrees, similarity 0.34 down to 0.03 (below 0.40).
    for i in 0..10 {
        let v = vec_angle(70.0 + 2.0 * f64::from(i));
        insert_claim(&pool, agent, &format!("far filler row {i}"), Some(&v), 0.8).await;
    }
    // Lexical-only rows.
    for i in 0..5 {
        insert_claim(
            &pool,
            agent,
            &format!("quokkanite lattice note {i}"),
            None,
            0.8,
        )
        .await;
    }

    let server = build_test_server(pool.clone());
    let body = recall_body(
        &server,
        &viewer,
        params("quokkanite lattice", 10),
        Some(vec_angle(0.0)),
    )
    .await;
    let results = body["results"].as_array().expect("results");
    assert_eq!(
        results.len(),
        8,
        "calibration: 10 fused hits minus the 2 below min_truth; got {body}"
    );
    let (total, rate, saturated) = coverage(&body);
    assert_eq!(
        total,
        Some(20),
        "15 dense rows at or above the 0.40 floor plus 5 lexical rows; the 10 dense rows \
         below the floor must not count. Body: {body}"
    );
    let rate = rate.unwrap_or_else(|| panic!("coverage_rate missing: {body}"));
    assert!(
        (rate - 0.4).abs() < 1e-9,
        "8 well-matched claims returned of 20: coverage_rate {rate}, want 0.4"
    );
    assert_eq!(
        saturated,
        Some(false),
        "neither leg reached the 50-row pool: {body}"
    );

    // Embedder down: no ANN pool, so no coverage fields.
    let degraded = recall_body(&server, &viewer, params("quokkanite lattice", 10), None).await;
    assert_eq!(
        coverage(&degraded),
        (None, None, None),
        "the lexical fallback has no candidate pool to report: {degraded}"
    );
}

/// 55 lexical matches fill the 50-row lexical leg: the count stops at the
/// pool, and the response says so.
#[sqlx::test(migrations = "../../migrations")]
async fn a_full_lexical_leg_is_reported_as_saturated(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    for i in 0..55 {
        insert_claim(&pool, agent, &format!("zirconyx marker {i}"), None, 0.8).await;
    }

    let server = build_test_server(pool.clone());
    let body = recall_body(
        &server,
        &viewer,
        params("zirconyx", 10),
        Some(vec_angle(0.0)),
    )
    .await;
    let (total, rate, saturated) = coverage(&body);
    assert_eq!(total, Some(50), "the lexical leg caps at the pool: {body}");
    let rate = rate.unwrap_or_else(|| panic!("coverage_rate missing: {body}"));
    assert!((rate - 0.2).abs() < 1e-9, "10 of 50: coverage_rate {rate}");
    assert_eq!(
        saturated,
        Some(true),
        "a full lexical leg saturates: {body}"
    );
}

/// 60 embedded rows fill the 50-row dense leg, but only the 20 nearest clear
/// the floor: the leg's farthest row is below it, so nothing above the floor
/// was cut off and the count is exact.
#[sqlx::test(migrations = "../../migrations")]
async fn a_full_dense_leg_below_the_floor_is_not_saturated(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    // 20 rows at 0..38 degrees (similarity >= 0.78), 40 at 70..89.5 (< 0.35).
    for i in 0..20 {
        let v = vec_angle(2.0 * f64::from(i));
        insert_claim(&pool, agent, &format!("dense near {i}"), Some(&v), 0.8).await;
    }
    for i in 0..40 {
        let v = vec_angle(70.0 + 0.5 * f64::from(i));
        insert_claim(&pool, agent, &format!("dense far {i}"), Some(&v), 0.8).await;
    }

    let server = build_test_server(pool.clone());
    let body = recall_body(
        &server,
        &viewer,
        params("zzqxnomatch", 10),
        Some(vec_angle(0.0)),
    )
    .await;
    let (total, rate, saturated) = coverage(&body);
    assert_eq!(
        total,
        Some(20),
        "only the 20 rows above the floor count: {body}"
    );
    let rate = rate.unwrap_or_else(|| panic!("coverage_rate missing: {body}"));
    assert!((rate - 0.5).abs() < 1e-9, "10 of 20: coverage_rate {rate}");
    assert_eq!(
        saturated,
        Some(false),
        "the dense leg is full, but its farthest row is below the floor: {body}"
    );
}

/// 60 embedded rows, every one well above the floor, fill the 50-row dense
/// leg. Nothing matches lexically, so only the dense arm of the saturation rule
/// can fire: the leg is full and even its farthest row clears the floor, so
/// rows above the floor may have been cut off and the count is a lower bound.
#[sqlx::test(migrations = "../../migrations")]
async fn a_full_dense_leg_above_the_floor_is_saturated(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    // 0..29.5 degrees: similarity >= 0.87 for every row.
    for i in 0..60 {
        let v = vec_angle(0.5 * f64::from(i));
        insert_claim(&pool, agent, &format!("dense near {i}"), Some(&v), 0.8).await;
    }

    let server = build_test_server(pool.clone());
    let body = recall_body(
        &server,
        &viewer,
        params("zzqxnomatch", 10),
        Some(vec_angle(0.0)),
    )
    .await;
    let (total, rate, saturated) = coverage(&body);
    assert_eq!(total, Some(50), "the dense leg caps at the pool: {body}");
    let rate = rate.unwrap_or_else(|| panic!("coverage_rate missing: {body}"));
    assert!((rate - 0.2).abs() < 1e-9, "10 of 50: coverage_rate {rate}");
    assert_eq!(
        saturated,
        Some(true),
        "a full dense leg whose farthest row clears the floor saturates: {body}"
    );
}

/// The count covers only rows the viewer can read. A group-private lexical
/// match and a group-private near embedded row count for a member of the group
/// and not for the public viewer, on the same corpus and query. The member arm
/// is the control: it shows the private rows do match, so the public viewer's
/// smaller count comes from the visibility filter, not from a seed that never
/// matched.
#[sqlx::test(migrations = "../../migrations")]
async fn the_candidate_count_excludes_rows_the_viewer_cannot_read(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "coverage-member").await;
    let agent = seed_agent(&pool).await;

    // Public: 3 near embedded rows (no lexical match) and 2 lexical-only rows.
    for i in 0..3 {
        let v = vec_angle(10.0 + 5.0 * f64::from(i));
        insert_claim(&pool, agent, &format!("public near row {i}"), Some(&v), 0.8).await;
    }
    for i in 0..2 {
        insert_claim(
            &pool,
            agent,
            &format!("vorpalite ledger public {i}"),
            None,
            0.8,
        )
        .await;
    }
    // Group-private: one lexical match, and one embedded row nearer the query
    // than any public row.
    fixture::seed_group_claim(&pool, member, group, "vorpalite ledger private").await;
    let private_near = fixture::seed_group_claim(&pool, member, group, "private near row").await;
    fixture::set_claim_embedding(&pool, private_near, &vec_angle(1.0)).await;

    let server = build_test_server(pool.clone());
    let member_viewer = epigraph_db::visibility::Viewer::resolve(&pool, member)
        .await
        .expect("resolve member viewer");
    let public = fixture::public_viewer(&pool).await;

    let as_member = recall_body(
        &server,
        &member_viewer,
        params("vorpalite ledger", 10),
        Some(vec_angle(0.0)),
    )
    .await;
    assert_eq!(
        coverage(&as_member).0,
        Some(7),
        "control: a member counts the 5 public and the 2 group-private matches: {as_member}"
    );

    let as_public = recall_body(
        &server,
        &public,
        params("vorpalite ledger", 10),
        Some(vec_angle(0.0)),
    )
    .await;
    assert_eq!(
        coverage(&as_public).0,
        Some(5),
        "the public viewer counts only the 5 public matches: {as_public}"
    );
}
