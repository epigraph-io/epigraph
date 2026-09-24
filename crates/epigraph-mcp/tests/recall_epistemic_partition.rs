//! `epistemic_partition` on both recall surfaces (backlog e7736ff6).
//!
//! The parameter regroups an already-settled page into `confirmed` /
//! `uncertain` / `open_question`. Three properties make it correct, and each
//! has a test here that fails if it is lost:
//!
//! 1. **Contest beats score.** A high-`truth_value` claim carrying a live
//!    `contradicts`/`refutes` edge must land in `open_question`, not
//!    `confirmed`. This is also what pins the ORDERING of the pipeline:
//!    `is_contested` is `false` on every result until the dispute post-pass
//!    runs, so a partition computed even one stage too early puts that claim
//!    in `confirmed` and leaves `open_question` permanently empty — while
//!    every happy-path assertion still passes. The fixture therefore contains
//!    a genuinely contested claim, not a synthetic flag.
//!
//! 2. **Same set, same order.** The union of the three buckets is exactly the
//!    flat page, and each bucket preserves the flat page's relative order. The
//!    test compares a partitioned call against an otherwise-identical flat
//!    call rather than against a hand-written expectation, so a partition that
//!    silently dropped or re-ranked hits could not pass.
//!
//! 3. **Off is unchanged.** With the flag unset the envelope still carries
//!    `results` and carries no `epistemic_partition` key at all.
//!
//! `recall` uses the lexical (embedder-down) leg, as `recall_hybrid.rs` and
//! `recall_dispute_awareness.rs` do — no API key exists in CI, and bucketing
//! is orthogonal to which retrieval leg produced the page.
//! `recall_with_context` uses `__test_only::recall_with_context_with_pgvec`
//! with the bucketed-vector fixture `recall_graph_expansion.rs` established.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::memory::recall;
use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;
use epigraph_mcp::tools::recall::RecallWithContextParams;
use epigraph_mcp::types::RecallParams;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const TAG: &str = "epistemic-partition-fixture";

fn build_test_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None); // mock → lexical leg
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false)
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-partition-mcp', 'system', ARRAY['test'])
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

async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
         VALUES ($1, $2, 'claim', 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("seed edge");
}

fn params(query: &str, epistemic_partition: bool) -> RecallParams {
    RecallParams {
        query: query.to_string(),
        min_truth: Some(0.0),
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
        epistemic_partition,
        diversity_radius: None,
    }
}

fn envelope(result: rmcp::model::CallToolResult) -> Value {
    let text = result
        .content
        .iter()
        .find_map(|c| c.as_text().map(|t| t.text.clone()))
        .expect("text content");
    serde_json::from_str::<Value>(&text).expect("parse recall envelope")
}

/// Claim ids in a JSON array of hits, in the order the server emitted them.
fn ids_of(arr: &Value, key: &str) -> Vec<String> {
    arr.as_array()
        .expect("array of hits")
        .iter()
        .map(|r| r[key].as_str().expect("id string").to_string())
        .collect()
}

fn bucket(env: &Value, name: &str) -> Vec<String> {
    ids_of(&env["epistemic_partition"][name], "claim_id")
}

/// The whole point of the feature: contest is evaluated BEFORE score, so a
/// 0.95-truth claim with a live refutation is an open question, not a
/// confirmed fact — and `uncertain` catches the middle.
///
/// This is also the ordering test. `is_contested` is populated by the dispute
/// post-pass; partitioning before it runs would file `contested` under
/// `confirmed` (its truth_value is 0.95) and leave `open_question` empty.
#[sqlx::test(migrations = "../../migrations")]
async fn contest_outranks_truth_when_bucketing(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    let settled = seed_claim(&pool, agent, "flendrax coupling is stable", 0.9).await;
    let middling = seed_claim(&pool, agent, "flendrax coupling is periodic", 0.5).await;
    // Scores ABOVE the confirmed threshold, so the only thing that can keep it
    // out of `confirmed` is the dispute edge below.
    let disputed = seed_claim(&pool, agent, "flendrax coupling is monotonic", 0.95).await;
    let rebuttal = seed_claim(&pool, agent, "flendrax coupling rebuttal", 0.8).await;
    seed_edge(&pool, rebuttal, disputed, "contradicts").await;

    let server = build_test_server(pool);
    let env = envelope(
        recall(&server, &viewer, params("flendrax coupling", true))
            .await
            .expect("recall ok"),
    );

    assert!(
        env.get("results").is_none(),
        "epistemic_partition=true REPLACES the flat list; `results` must be absent, got {env:#?}"
    );

    let confirmed = bucket(&env, "confirmed");
    let uncertain = bucket(&env, "uncertain");
    let open = bucket(&env, "open_question");

    assert!(
        open.contains(&disputed.to_string()),
        "a contested 0.95 claim belongs in open_question, not confirmed. \
         open_question={open:?} confirmed={confirmed:?}"
    );
    assert!(
        !confirmed.contains(&disputed.to_string()),
        "contest must beat truth_value: {disputed} leaked into confirmed"
    );
    assert!(
        confirmed.contains(&settled.to_string()),
        "uncontested 0.9 belongs in confirmed, got confirmed={confirmed:?}"
    );
    assert!(
        uncertain.contains(&middling.to_string()),
        "uncontested 0.5 belongs in uncertain, got uncertain={uncertain:?}"
    );
    // The rebuttal is itself an uncontested 0.8 hit on this query, so it lands
    // in `confirmed`. Asserted so the fixture's own extra row is accounted for
    // rather than silently absorbed by a laxer check.
    assert!(
        confirmed.contains(&rebuttal.to_string()),
        "the rebuttal is itself uncontested and above threshold"
    );
}

/// Partitioning must not change WHICH hits come back or their ranking — it is
/// a regrouping of a page every other stage has already settled. Compared
/// against a flat call with identical params, so a partition that dropped or
/// reordered hits cannot pass.
#[sqlx::test(migrations = "../../migrations")]
async fn partition_is_exhaustive_and_order_preserving(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;

    let a = seed_claim(&pool, agent, "yotturn lattice alpha result", 0.9).await;
    let b = seed_claim(&pool, agent, "yotturn lattice beta result", 0.4).await;
    let c = seed_claim(&pool, agent, "yotturn lattice gamma result", 0.85).await;
    let d = seed_claim(&pool, agent, "yotturn lattice delta result", 0.6).await;
    let contester = seed_claim(&pool, agent, "yotturn lattice counterexample", 0.7).await;
    seed_edge(&pool, contester, c, "refutes").await;
    for id in [a, b, d] {
        assert_ne!(id, c);
    }

    let server = build_test_server(pool);

    let flat_env = envelope(
        recall(&server, &viewer, params("yotturn lattice result", false))
            .await
            .expect("flat recall ok"),
    );
    let flat_ids = ids_of(&flat_env["results"], "claim_id");
    assert!(
        flat_ids.len() >= 4,
        "fixture must produce a multi-hit page to be worth comparing, got {flat_ids:?}"
    );

    let part_env = envelope(
        recall(&server, &viewer, params("yotturn lattice result", true))
            .await
            .expect("partitioned recall ok"),
    );
    let confirmed = bucket(&part_env, "confirmed");
    let uncertain = bucket(&part_env, "uncertain");
    let open = bucket(&part_env, "open_question");

    // Exhaustive and disjoint: every flat hit appears in exactly one bucket.
    let mut union: Vec<String> = Vec::new();
    union.extend(confirmed.iter().cloned());
    union.extend(uncertain.iter().cloned());
    union.extend(open.iter().cloned());
    assert_eq!(
        union.len(),
        flat_ids.len(),
        "the three buckets must hold exactly the flat page — no drops, no duplicates. \
         flat={flat_ids:?} confirmed={confirmed:?} uncertain={uncertain:?} open={open:?}"
    );
    let mut sorted_union = union.clone();
    sorted_union.sort();
    let mut sorted_flat = flat_ids.clone();
    sorted_flat.sort();
    assert_eq!(sorted_union, sorted_flat, "bucket union != flat page");

    // Order-preserving: each bucket is the flat page filtered, not re-sorted.
    for b in [&confirmed, &uncertain, &open] {
        let projected: Vec<String> = flat_ids
            .iter()
            .filter(|id| b.contains(id))
            .cloned()
            .collect();
        assert_eq!(
            *b, projected,
            "bucket must keep the flat page's relative order; flat={flat_ids:?}"
        );
    }
}

/// With the flag unset the envelope is what it was before this parameter
/// existed: `results` present, no `epistemic_partition` key at all.
#[sqlx::test(migrations = "../../migrations")]
async fn partition_off_leaves_the_flat_envelope_untouched(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    seed_claim(&pool, agent, "ghelvin transport constant", 0.9).await;

    let server = build_test_server(pool);
    let env = envelope(
        recall(&server, &viewer, params("ghelvin transport", false))
            .await
            .expect("recall ok"),
    );

    assert!(
        env.get("epistemic_partition").is_none(),
        "the partition key must be absent when the flag is off, got {env:#?}"
    );
    assert!(
        env["results"].is_array(),
        "flat `results` array must still be present, got {env:#?}"
    );
    assert!(
        !env["results"].as_array().unwrap().is_empty(),
        "fixture claim should be recalled"
    );
}

// ── recall_with_context ───────────────────────────────────────────────────
//
// Same three properties on the second surface. The bucketed-vector helpers
// mirror `recall_graph_expansion.rs`'s fixture: `recall_with_context` is
// paragraph-primary (level=2 + paper attribution required), so a claim seeded
// the way the `recall` tests above seed one would never surface here.

mod ctxfx {
    use super::*;

    const DIM: usize = 1536;

    pub fn cluster_pgvec(bucket: usize, value: f32) -> String {
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

    pub async fn seed_paper(pool: &PgPool, doi: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, 'partition fixture')")
            .bind(id)
            .bind(doi)
            .execute(pool)
            .await
            .expect("seed paper");
        id
    }

    /// A level-2 paragraph with an embedding, a paper attribution edge (hits
    /// missing one are dropped by `recall_with_context`), and a caller-chosen
    /// `truth_value` — the graph-expansion fixture hardcodes 0.7, which sits
    /// on the wrong side of nothing and cannot exercise the threshold.
    pub async fn seed_paragraph(
        pool: &PgPool,
        agent_id: Uuid,
        paper_id: Uuid,
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
        .bind(agent_id)
        .bind(truth)
        .bind(pgvec)
        .execute(pool)
        .await
        .expect("seed paragraph");

        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
             VALUES (gen_random_uuid(), $1, 'paper', $2, 'claim', 'asserts')",
        )
        .bind(paper_id)
        .bind(id)
        .execute(pool)
        .await
        .expect("seed paper-attribution edge");
        id
    }

    pub fn params(epistemic_partition: bool) -> RecallWithContextParams {
        RecallWithContextParams {
            query: "partition probe".to_string(),
            limit: Some(10),
            min_truth: Some(0.0),
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
}

/// `recall_with_context` buckets by the same contest-first rule, on
/// `paragraph_id`. Same load-bearing shape as the `recall` test: the disputed
/// paragraph scores 0.95, so only the dispute post-pass having run BEFORE the
/// partition can keep it out of `confirmed`.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_buckets_contested_paragraph(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let paper = ctxfx::seed_paper(&pool, "10.9999/partition.1").await;
    let query_vec = ctxfx::cluster_pgvec(0, 1.0);

    let settled = ctxfx::seed_paragraph(
        &pool,
        agent,
        paper,
        "paragraph reporting a settled measurement",
        0.9,
        &ctxfx::cluster_pgvec(0, 0.9),
    )
    .await;
    let middling = ctxfx::seed_paragraph(
        &pool,
        agent,
        paper,
        "paragraph reporting a tentative measurement",
        0.5,
        &ctxfx::cluster_pgvec(0, 0.8),
    )
    .await;
    let disputed = ctxfx::seed_paragraph(
        &pool,
        agent,
        paper,
        "paragraph reporting a measurement that is challenged",
        0.95,
        &ctxfx::cluster_pgvec(0, 0.7),
    )
    .await;
    let rebuttal = seed_claim(&pool, agent, "the challenged measurement is wrong", 0.8).await;
    seed_edge(&pool, rebuttal, disputed, "refutes").await;

    let server = build_test_server(pool);
    let env = envelope(
        recall_with_context_with_pgvec(&server, &viewer, ctxfx::params(true), 1536, &query_vec)
            .await
            .expect("recall_with_context ok"),
    );

    assert!(
        env.get("results").is_none(),
        "epistemic_partition=true replaces `results` here too, got {env:#?}"
    );
    let confirmed = ids_of(&env["epistemic_partition"]["confirmed"], "paragraph_id");
    let uncertain = ids_of(&env["epistemic_partition"]["uncertain"], "paragraph_id");
    let open = ids_of(&env["epistemic_partition"]["open_question"], "paragraph_id");

    assert!(
        open.contains(&disputed.to_string()),
        "a refuted 0.95 paragraph belongs in open_question. open={open:?} confirmed={confirmed:?}"
    );
    assert!(
        confirmed.contains(&settled.to_string()),
        "uncontested 0.9 paragraph belongs in confirmed, got {confirmed:?}"
    );
    assert!(
        uncertain.contains(&middling.to_string()),
        "uncontested 0.5 paragraph belongs in uncertain, got {uncertain:?}"
    );
}

/// The flag-off envelope on the second surface, for the same reason as the
/// `recall` twin: `results` present, no partition key.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_partition_off_is_unchanged(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let paper = ctxfx::seed_paper(&pool, "10.9999/partition.2").await;
    let query_vec = ctxfx::cluster_pgvec(0, 1.0);
    ctxfx::seed_paragraph(
        &pool,
        agent,
        paper,
        "paragraph that should come back flat",
        0.9,
        &ctxfx::cluster_pgvec(0, 0.9),
    )
    .await;

    let server = build_test_server(pool);
    let env = envelope(
        recall_with_context_with_pgvec(&server, &viewer, ctxfx::params(false), 1536, &query_vec)
            .await
            .expect("recall_with_context ok"),
    );

    assert!(
        env.get("epistemic_partition").is_none(),
        "partition key absent when the flag is off, got {env:#?}"
    );
    assert!(
        !env["results"].as_array().expect("results array").is_empty(),
        "fixture paragraph should be recalled, got {env:#?}"
    );
}
