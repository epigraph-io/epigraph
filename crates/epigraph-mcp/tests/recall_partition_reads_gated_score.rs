//! The epistemic partition must read the SAME score the `min_truth` gate reads.
//!
//! `recall` and `recall_with_context` gate on `belief_score` — the claim's
//! Dempster–Shafer pignistic probability when it carries a DS cache, and its
//! authored `truth_value` only when it does not. The `epistemic_partition`
//! regrouping then bucketed on `truth_value`, a column no DS write path
//! refreshes. Two numbers for "how believed is this claim" on one response,
//! and they could disagree in both directions:
//!
//! * a claim authored at 0.9 whose evidence has pulled its BetP down to 0.4
//!   was reported `confirmed`;
//! * a claim authored at 0.4 whose evidence has lifted its BetP to 0.9 was
//!   admitted by the gate ON that 0.9 and then reported `uncertain`.
//!
//! Every fixture below pairs claims that retrieval cannot tell apart (same
//! query, same vector bucket, same tags) and whose authored value and DS value
//! sit on OPPOSITE sides of the confirmed threshold, so the bucket a claim
//! lands in says which of the two numbers the partition read. An uncached
//! control rides along on every surface: with no DS state the gate falls back
//! to `truth_value`, and the partition must fall back with it rather than read
//! "no cache" as "not believed".
//!
//! The context-atom test covers the other half of the same defect on
//! `recall_with_context`: a hit's child atoms were reported with only their
//! authored `truth_value`, so the one surface that shows a compound next to its
//! atoms showed the atoms on a different scale from the hit itself.
//!
//! `#[sqlx::test]` throughout, never a skip macro: a red run without a database
//! must fail loudly rather than "pass".

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::memory::recall;
use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;
use epigraph_mcp::tools::recall::RecallWithContextParams;
use epigraph_mcp::types::RecallParams;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const TAG: &str = "partition-gated-score-fixture";
const DIM: usize = 1536;

/// Gate low enough that every fixture claim is admitted on either reading, so
/// the gate itself never decides the open-gate assertions — only the partition
/// does. It is also the retrievability control for the biting-gate pass: a
/// claim present here and absent there was dropped by the gate.
const OPEN_GATE: f64 = 0.3;

/// Gate strictly between the fixtures' low reading (0.4) and their high one
/// (0.9), so it admits a claim on exactly one of its two numbers. Under it the
/// SAME response must show the gate and the partition reading the same score:
/// the claim whose BetP is below the gate is gone from every bucket, and the
/// claims whose gated score clears it are present and `confirmed`.
const BITING_GATE: f64 = 0.5;

fn build_test_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None); // mock -> lexical leg
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false)
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-partition-gated', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, truth: f64) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, labels)
         VALUES ($1, sha256($1::bytea), $2, $3, true, ARRAY[$4])
         RETURNING id",
    )
    .bind(content)
    .bind(truth)
    .bind(agent)
    .bind(TAG)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

/// Write a coherent DS cache (Bel <= BetP <= Pl) the way an evidence recompute
/// leaves it. The read under test must honour these columns however they were
/// written; `truth_value` is deliberately left at its authored value.
async fn set_ds_cache(pool: &PgPool, claim: Uuid, belief: f64, plausibility: f64, betp: f64) {
    assert!(
        belief <= betp && betp <= plausibility,
        "fixture DS triple must be coherent"
    );
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

/// Evidence has pulled this claim well below what its author asserted.
async fn make_inflated(pool: &PgPool, claim: Uuid) {
    set_ds_cache(pool, claim, 0.3, 0.5, 0.4).await;
}

/// Evidence has lifted this claim well above what its author asserted.
async fn make_understated(pool: &PgPool, claim: Uuid) {
    set_ds_cache(pool, claim, 0.85, 0.95, 0.9).await;
}

fn envelope(result: rmcp::model::CallToolResult) -> Value {
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    serde_json::from_str::<Value>(&text).expect("parse recall envelope")
}

fn rows<'a>(env: &'a Value, bucket: &str) -> &'a [Value] {
    env["epistemic_partition"][bucket]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("bucket {bucket} missing from {env:#?}"))
}

fn ids(env: &Value, bucket: &str, key: &str) -> Vec<String> {
    rows(env, bucket)
        .iter()
        .map(|r| r[key].as_str().expect("id string").to_string())
        .collect()
}

/// Every id the partition returned, across all three buckets. Asserts the
/// bucket set is exactly the documented one first, so a renamed or added
/// bucket cannot make an absence check pass by looking in the wrong place.
fn all_ids(env: &Value, key: &str) -> Vec<String> {
    let mut buckets: Vec<&str> = env["epistemic_partition"]
        .as_object()
        .unwrap_or_else(|| panic!("epistemic_partition object missing from {env:#?}"))
        .keys()
        .map(String::as_str)
        .collect();
    buckets.sort_unstable();
    assert_eq!(
        buckets,
        ["confirmed", "open_question", "uncertain"],
        "unexpected partition buckets"
    );
    ["confirmed", "uncertain", "open_question"]
        .iter()
        .flat_map(|b| ids(env, b, key))
        .collect()
}

fn recall_params(query: &str, min_truth: f64) -> RecallParams {
    RecallParams {
        query: query.to_string(),
        min_truth: Some(min_truth),
        limit: Some(10),
        tags: vec![TAG.to_string()],
        agent_id: None,
        frame_id: None,
        perspective_id: None,
        include_workflows: false,
        exclude_contested: false,
        since: None,
        theme_id: None,
        theme_label: None,
        offset: None,
        epistemic_partition: true,
        diversity_radius: None,
    }
}

// ── recall ───────────────────────────────────────────────────────────────

/// `recall`: `confirmed` is decided on the gated score, the value `min_truth`
/// compares against.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_partitions_on_the_gated_score_not_truth_value(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    let inflated = seed_claim(&pool, agent, "quorvane anneal inflated finding", 0.9).await;
    let understated = seed_claim(&pool, agent, "quorvane anneal understated finding", 0.4).await;
    let uncached = seed_claim(&pool, agent, "quorvane anneal uncached finding", 0.9).await;
    make_inflated(&pool, inflated).await;
    make_understated(&pool, understated).await;

    let server = build_test_server(pool);
    let env = envelope(
        recall(
            &server,
            &viewer,
            recall_params("quorvane anneal finding", OPEN_GATE),
        )
        .await
        .expect("recall ok"),
    );
    let confirmed = ids(&env, "confirmed", "claim_id");
    let uncertain = ids(&env, "uncertain", "claim_id");

    assert!(
        !confirmed.contains(&inflated.to_string()),
        "a claim with truth_value 0.9 and BetP 0.4 was reported `confirmed`; the partition \
         read truth_value while the gate read BetP. confirmed={confirmed:?}"
    );
    assert!(
        uncertain.contains(&inflated.to_string()),
        "the BetP-0.4 claim was admitted by the gate and must be reported `uncertain`, \
         got uncertain={uncertain:?}"
    );
    assert!(
        confirmed.contains(&understated.to_string()),
        "a claim with BetP 0.9 was partitioned on its truth_value 0.4. \
         confirmed={confirmed:?} uncertain={uncertain:?}"
    );
    assert!(
        confirmed.contains(&uncached.to_string()),
        "with no DS state the gate falls back to truth_value 0.9 and so must the partition; \
         reading 'no cache' as 'not believed' would demote the whole un-assessed corpus. \
         confirmed={confirmed:?}"
    );

    // Same fixtures, gate between the two readings: gate and partition must
    // agree inside ONE response.
    let env = envelope(
        recall(
            &server,
            &viewer,
            recall_params("quorvane anneal finding", BITING_GATE),
        )
        .await
        .expect("recall ok"),
    );
    let returned = all_ids(&env, "claim_id");
    let confirmed = ids(&env, "confirmed", "claim_id");
    assert!(
        !returned.contains(&inflated.to_string()),
        "a claim with BetP 0.4 cleared a {BITING_GATE} gate on its truth_value 0.9; the gate \
         is not reading the score the partition reads. returned={returned:?}"
    );
    assert!(
        confirmed.contains(&understated.to_string()),
        "a claim with BetP 0.9 and truth_value 0.4 must be admitted by a {BITING_GATE} gate \
         and reported `confirmed`, both on its BetP. confirmed={confirmed:?} \
         returned={returned:?}"
    );
    assert!(
        confirmed.contains(&uncached.to_string()),
        "with no DS state both gate and partition fall back to truth_value 0.9. \
         confirmed={confirmed:?}"
    );
}

// ── recall_with_context ──────────────────────────────────────────────────

fn cluster_pgvec(bucket: usize, value: f32) -> String {
    const N_BUCKETS: usize = 8;
    const STRIDE: usize = DIM / N_BUCKETS;
    let mut v = vec![0.0f32; DIM];
    let start = bucket * STRIDE;
    for slot in v.iter_mut().take(start + STRIDE).skip(start) {
        *slot = value;
    }
    let inner: Vec<String> = v.iter().map(|x| x.to_string()).collect();
    format!("[{}]", inner.join(","))
}

async fn seed_paper(pool: &PgPool, doi: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, 'gated score fixture')")
        .bind(id)
        .bind(doi)
        .execute(pool)
        .await
        .expect("seed paper");
    id
}

/// A level-2 paragraph with an embedding and a paper attribution edge.
async fn seed_paragraph(
    pool: &PgPool,
    agent: Uuid,
    paper: Uuid,
    content: &str,
    truth: f64,
    pgvec: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[..16].copy_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding) \
         VALUES ($1, $2, $3, $4, $5, jsonb_build_object('level', 2::int), $6::vector)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent)
    .bind(truth)
    .bind(pgvec)
    .execute(pool)
    .await
    .expect("seed paragraph");
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
    )
    .bind(paper)
    .bind(id)
    .execute(pool)
    .await
    .expect("seed paper-attribution edge");
    id
}

/// A level-3 atom under `paragraph`, with no embedding so it is context only
/// and never a hit in its own right.
async fn seed_atom(pool: &PgPool, agent: Uuid, paragraph: Uuid, content: &str, truth: f64) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[..16].copy_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties) \
         VALUES ($1, $2, $3, $4, $5, jsonb_build_object('level', 3::int))",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent)
    .bind(truth)
    .execute(pool)
    .await
    .expect("seed atom");
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(paragraph)
    .bind(id)
    .execute(pool)
    .await
    .expect("seed decomposes_to edge");
    id
}

fn ctx_params(epistemic_partition: bool, min_truth: f64) -> RecallWithContextParams {
    RecallWithContextParams {
        query: "gated score probe".to_string(),
        limit: Some(10),
        min_truth: Some(min_truth),
        centroid_dim: Some(1536),
        paper_doi_filter: None,
        siblings_limit: None,
        corroborates_limit: None,
        epistemic_limit: None,
        neighbor_paragraphs_limit: None,
        diverse: None,
        max_themes: None,
        diversity_weight: None,
        candidate_pool: None,
        rerank: None,
        rerank_pool_factor: None,
        groundedness_gate: None,
        frame_id: None,
        perspective_id: None,
        graph_expansion_depth: None,
        exclude_contested: false,
        since: None,
        epistemic_partition,
        diversity_radius: None,
    }
}

/// The same property on the second surface, keyed by `paragraph_id`.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_partitions_on_the_gated_score_not_truth_value(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let paper = seed_paper(&pool, "10.9999/gated-score.1").await;
    let query_vec = cluster_pgvec(0, 1.0);

    let inflated = seed_paragraph(
        &pool,
        agent,
        paper,
        "paragraph whose evidence undercuts its author",
        0.9,
        &cluster_pgvec(0, 0.9),
    )
    .await;
    let understated = seed_paragraph(
        &pool,
        agent,
        paper,
        "paragraph whose evidence outruns its author",
        0.4,
        &cluster_pgvec(0, 0.8),
    )
    .await;
    let uncached = seed_paragraph(
        &pool,
        agent,
        paper,
        "paragraph with no evidence recompute yet",
        0.9,
        &cluster_pgvec(0, 0.7),
    )
    .await;
    make_inflated(&pool, inflated).await;
    make_understated(&pool, understated).await;

    let server = build_test_server(pool);
    let env = envelope(
        recall_with_context_with_pgvec(
            &server,
            &viewer,
            ctx_params(true, OPEN_GATE),
            1536,
            &query_vec,
        )
        .await
        .expect("recall_with_context ok"),
    );
    let confirmed = ids(&env, "confirmed", "paragraph_id");
    let uncertain = ids(&env, "uncertain", "paragraph_id");

    assert!(
        !confirmed.contains(&inflated.to_string()),
        "a paragraph with truth_value 0.9 and BetP 0.4 was reported `confirmed`; the \
         partition read truth_value while the gate read BetP. confirmed={confirmed:?}"
    );
    assert!(
        uncertain.contains(&inflated.to_string()),
        "the BetP-0.4 paragraph must be reported `uncertain`, got uncertain={uncertain:?}"
    );
    assert!(
        confirmed.contains(&understated.to_string()),
        "a paragraph with BetP 0.9 was partitioned on its truth_value 0.4. \
         confirmed={confirmed:?} uncertain={uncertain:?}"
    );
    assert!(
        confirmed.contains(&uncached.to_string()),
        "with no DS state the partition must fall back to truth_value 0.9, as the gate does. \
         confirmed={confirmed:?}"
    );

    // Same fixtures, gate between the two readings: on this surface the gate
    // runs in `recall_with_context_post_embed` and the partition after it, so
    // only one response can show they read the same number.
    let env = envelope(
        recall_with_context_with_pgvec(
            &server,
            &viewer,
            ctx_params(true, BITING_GATE),
            1536,
            &query_vec,
        )
        .await
        .expect("recall_with_context ok"),
    );
    let returned = all_ids(&env, "paragraph_id");
    let confirmed = ids(&env, "confirmed", "paragraph_id");
    assert!(
        !returned.contains(&inflated.to_string()),
        "a paragraph with BetP 0.4 cleared a {BITING_GATE} gate on its truth_value 0.9; the \
         gate is not reading the score the partition reads. returned={returned:?}"
    );
    assert!(
        confirmed.contains(&understated.to_string()),
        "a paragraph with BetP 0.9 and truth_value 0.4 must be admitted by a {BITING_GATE} \
         gate and reported `confirmed`, both on its BetP. confirmed={confirmed:?} \
         returned={returned:?}"
    );
    assert!(
        confirmed.contains(&uncached.to_string()),
        "with no DS state both gate and partition fall back to truth_value 0.9. \
         confirmed={confirmed:?}"
    );
}

/// `recall_with_context`: context atoms carry the atom's effective
/// belief next to its authored value. The atom with a DS cache must report the
/// cached BetP, which differs from its `truth_value`; the atom without one must
/// report the fall-back, equal to its `truth_value` — the same "equality means
/// no DS state" reading the hit's own `belief_score` already has.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_atoms_carry_effective_belief(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let paper = seed_paper(&pool, "10.9999/gated-score.2").await;
    let query_vec = cluster_pgvec(1, 1.0);

    let paragraph = seed_paragraph(
        &pool,
        agent,
        paper,
        "paragraph whose atoms disagree with their authors",
        0.8,
        &cluster_pgvec(1, 0.9),
    )
    .await;
    let doubted = seed_atom(
        &pool,
        agent,
        paragraph,
        "atom that evidence has undercut",
        0.9,
    )
    .await;
    let plain = seed_atom(
        &pool,
        agent,
        paragraph,
        "atom with no evidence recompute",
        0.7,
    )
    .await;
    set_ds_cache(&pool, doubted, 0.1, 0.3, 0.2).await;

    let server = build_test_server(pool);
    let env = envelope(
        recall_with_context_with_pgvec(
            &server,
            &viewer,
            ctx_params(false, OPEN_GATE),
            1536,
            &query_vec,
        )
        .await
        .expect("recall_with_context ok"),
    );
    let hit = env["results"]
        .as_array()
        .expect("flat results")
        .iter()
        .find(|h| h["paragraph_id"].as_str() == Some(paragraph.to_string().as_str()))
        .unwrap_or_else(|| panic!("the fixture paragraph must be a hit, got {env:#?}"));
    let atom = |id: Uuid| -> &Value {
        hit["atoms"]
            .as_array()
            .expect("atoms array")
            .iter()
            .find(|a| a["atom_id"].as_str() == Some(id.to_string().as_str()))
            .unwrap_or_else(|| panic!("atom {id} must be in the hit's context, got {hit:#?}"))
    };

    let d = atom(doubted);
    let d_belief = d["belief_score"].as_f64().unwrap_or_else(|| {
        panic!("a context atom must carry its effective belief as `belief_score`, got {d:#?}")
    });
    let d_truth = d["truth_value"].as_f64().expect("truth_value kept");
    assert!(
        (d_truth - 0.9).abs() < 1e-9,
        "the atom's authored truth_value must be reported unchanged, got {d_truth}"
    );
    assert!(
        (d_belief - 0.2).abs() < 1e-9,
        "the atom's belief_score must be its cached BetP (0.2), not its authored value; \
         got {d_belief}"
    );

    let p = atom(plain);
    let p_belief = p["belief_score"].as_f64().unwrap_or_else(|| {
        panic!("a context atom must carry its effective belief as `belief_score`, got {p:#?}")
    });
    let p_truth = p["truth_value"].as_f64().expect("truth_value kept");
    assert!(
        (p_belief - p_truth).abs() < 1e-9,
        "with no DS state the atom's belief_score must fall back to its truth_value \
         ({p_belief} vs {p_truth})"
    );
}
