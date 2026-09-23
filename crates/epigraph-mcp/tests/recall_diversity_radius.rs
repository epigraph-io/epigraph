//! `diversity_radius` on both recall surfaces (backlog a9397e8a).
//!
//! The parameter runs a greedy MMR pass over the ranked page and drops any hit
//! within the given cosine distance of a better-ranked hit already kept. Four
//! properties decide whether it is correct rather than merely present, and each
//! has a test here whose failure mode is a real production bug:
//!
//! 1. **Near-duplicates collapse, distinct hits survive.** The baseline is the
//!    SAME query without the parameter, so a filter that dropped nothing (or
//!    dropped everything) cannot pass.
//!
//! 2. **An unmeasurable hit is KEPT.** A claim with no vector in the searched
//!    column has no measurable distance to anything. The natural-looking
//!    implementation — default a missing pair to distance `0.0` — marks every
//!    such hit a duplicate of everything and silently empties the page down to
//!    one row. The fixture seeds exactly that claim.
//!
//! 3. **Workflow hits are never dropped.** With `include_workflows=true`, a
//!    workflow hit carries a `workflows.id` in the `claim_id` field. It has no
//!    row in `claims`, so it can neither be measured nor suppress anything.
//!
//! 4. **The distance is measured in the dim the retrieval used.**
//!    `claims.embedding` (1536) and `claims.embedding_3072` are different
//!    spaces. The 3072 test seeds paragraphs embedded ONLY in the 3072 column;
//!    a filter hardcoded to 1536 finds no pairs there and reports a page of
//!    near-identical paragraphs as perfectly diverse.
//!
//! Both surfaces are driven through their `__test_only` pgvec seams — no API
//! key exists in the test environment, and unlike the dispute/partition tests
//! this feature genuinely needs the dense leg, because it needs vectors.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_mcp::tools::memory::__test_only::recall_with_pgvec;
use epigraph_mcp::tools::recall::__test_only::recall_with_context_with_pgvec;
use epigraph_mcp::tools::recall::RecallWithContextParams;
use epigraph_mcp::types::RecallParams;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const TAG: &str = "diversity-radius-fixture";
/// Cosine distance below which two hits are treated as redundant. The fixture's
/// near-duplicate pair sits at ~0 and its distinct rows at ~1 (orthogonal
/// buckets), so this threshold is nowhere near either boundary.
const RADIUS: f64 = 0.15;

fn build_test_server(pool: PgPool) -> epigraph_mcp::EpiGraphMcpFull {
    use epigraph_crypto::AgentSigner;
    use epigraph_mcp::embed::McpEmbedder;
    use epigraph_mcp::EpiGraphMcpFull;
    let signer = AgentSigner::from_bytes(&[0u8; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None);
    EpiGraphMcpFull::new(pool, signer, embedder, /*read_only=*/ false)
}

/// Pgvector literal concentrated in one bucket of `dim` slots. Same-bucket
/// vectors are near-identical (cosine distance ~0); different-bucket vectors
/// are orthogonal (~1). Same construction as `recall_graph_expansion.rs`.
fn cluster_pgvec(dim: usize, bucket: usize, value: f32) -> String {
    const N_BUCKETS: usize = 8;
    let stride = dim / N_BUCKETS;
    let mut v = vec![0.0f32; dim];
    let start = bucket * stride;
    for slot in v.iter_mut().take(start + stride).skip(start) {
        *slot = value;
    }
    let inner: Vec<String> = v.iter().map(|x| x.to_string()).collect();
    format!("[{}]", inner.join(","))
}

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO agents (public_key, display_name, agent_type, labels)
         VALUES (sha256(gen_random_uuid()::text::bytea), 'test-diversity-mcp', 'system', ARRAY['test'])
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// A claim with an optional 1536d embedding. `None` seeds a claim reachable
/// only through the lexical leg — the "unmeasurable" case.
async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, pgvec: Option<&str>) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, labels, embedding)
         VALUES ($1, sha256($1::bytea), 0.8, $2, true, ARRAY[$3], $4::vector)
         RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .bind(TAG)
    .bind(pgvec)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

fn params(query: &str, diversity_radius: Option<f64>, include_workflows: bool) -> RecallParams {
    RecallParams {
        query: query.to_string(),
        min_truth: Some(0.0),
        limit: Some(10),
        tags: if include_workflows {
            // A tag filter applies to the claims legs only; leaving it off
            // keeps the workflows leg comparable to the claims one.
            vec![]
        } else {
            vec![TAG.to_string()]
        },
        agent_id: None,
        frame_id: None,
        perspective_id: None,
        include_workflows,
        exclude_contested: false,
        since: None,
        theme_id: None,
        theme_label: None,
        offset: None,
        epistemic_partition: false,
        diversity_radius,
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

fn result_ids(env: &Value) -> Vec<String> {
    env["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|r| r["claim_id"].as_str().expect("claim_id").to_string())
        .collect()
}

/// The core behaviour, plus the trap that would silently empty the page.
///
/// `near_a` / `near_b` share a bucket, so their cosine distance is ~0 and one
/// must be dropped. `distinct` sits in an orthogonal bucket (~1) and must
/// survive. `unembedded` has NO vector at all and reaches the page through the
/// lexical leg — it has no measurable distance to anything and must ALSO
/// survive. An implementation that defaults a missing pair to `0.0` keeps only
/// the single top-ranked hit and fails on both of the last two.
#[sqlx::test(migrations = "../../migrations")]
async fn near_duplicates_collapse_while_distinct_and_unmeasurable_survive(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let query_vec = cluster_pgvec(1536, 0, 1.0);

    let near_a = seed_claim(
        &pool,
        agent,
        "phlogiston transfer coefficient measured at high pressure",
        Some(&cluster_pgvec(1536, 0, 1.0)),
    )
    .await;
    let near_b = seed_claim(
        &pool,
        agent,
        "phlogiston transfer coefficient measured under high pressure",
        Some(&cluster_pgvec(1536, 0, 0.98)),
    )
    .await;
    let distinct = seed_claim(
        &pool,
        agent,
        "phlogiston ledger accounting procedure",
        Some(&cluster_pgvec(1536, 4, 1.0)),
    )
    .await;
    let unembedded = seed_claim(&pool, agent, "phlogiston apparatus maintenance log", None).await;

    let server = build_test_server(pool);

    // Baseline: without the parameter all four come back. Without this the
    // "collapsed" assertion below could pass over a page that never held the
    // duplicate in the first place.
    let base = result_ids(&envelope(
        recall_with_pgvec(
            &server,
            &viewer,
            params("phlogiston", None, false),
            Some(query_vec.clone()),
        )
        .await
        .expect("baseline recall ok"),
    ));
    for id in [near_a, near_b, distinct, unembedded] {
        assert!(
            base.contains(&id.to_string()),
            "baseline page must hold every fixture row before filtering; missing {id}, got {base:?}"
        );
    }

    let filtered = result_ids(&envelope(
        recall_with_pgvec(
            &server,
            &viewer,
            params("phlogiston", Some(RADIUS), false),
            Some(query_vec),
        )
        .await
        .expect("filtered recall ok"),
    ));

    let near_kept = [near_a, near_b]
        .iter()
        .filter(|id| filtered.contains(&id.to_string()))
        .count();
    assert_eq!(
        near_kept, 1,
        "exactly one of the near-duplicate pair survives (which one depends on \
         rank, which is not what this pins); got {filtered:?}"
    );
    assert!(
        filtered.contains(&distinct.to_string()),
        "an orthogonal hit is not redundant and must survive; got {filtered:?}"
    );
    assert!(
        filtered.contains(&unembedded.to_string()),
        "a hit with NO embedding has no measurable distance and must be KEPT, \
         not treated as distance 0 from everything; got {filtered:?}"
    );
    assert_eq!(
        filtered.len(),
        base.len() - 1,
        "the page shrinks by exactly the one redundant hit — no back-fill, no \
         collateral drops. base={base:?} filtered={filtered:?}"
    );
}

/// A workflow hit's `claim_id` is a `workflows.id`, which has no row in
/// `claims`. It can be neither measured nor suppressed, so it must survive the
/// filter — including when a genuine near-duplicate pair is collapsing in the
/// same page.
#[sqlx::test(migrations = "../../migrations")]
async fn workflow_hits_survive_the_diversity_filter(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let query_vec = cluster_pgvec(1536, 0, 1.0);

    // Goal text deliberately shares no words with the claims, so only the
    // workflows ANN leg can surface it.
    // Same column set as `recall_workflows.rs`'s seed — `workflows` has no
    // `name`, and its `canonical_name` is NOT NULL.
    let workflow_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, generation, goal, metadata, truth_value, goal_embedding) \
         VALUES ($1, $2, 0, 'orchestrate quillamine beacon calibration', '{}'::jsonb, 0.8, $3::vector)",
    )
    .bind(workflow_id)
    .bind(format!("wf-{workflow_id}"))
    .bind(&query_vec)
    .execute(&pool)
    .await
    .expect("seed workflow with goal_embedding");

    let near_a = seed_claim(
        &pool,
        agent,
        "quillamine transfer coefficient measured at high pressure",
        Some(&cluster_pgvec(1536, 0, 1.0)),
    )
    .await;
    let near_b = seed_claim(
        &pool,
        agent,
        "quillamine transfer coefficient measured under high pressure",
        Some(&cluster_pgvec(1536, 0, 0.98)),
    )
    .await;

    let server = build_test_server(pool);
    let filtered = result_ids(&envelope(
        recall_with_pgvec(
            &server,
            &viewer,
            params("quillamine", Some(RADIUS), true),
            Some(query_vec),
        )
        .await
        .expect("recall ok"),
    ));

    assert!(
        filtered.contains(&workflow_id.to_string()),
        "a workflow hit is not a claims row and must never be dropped by the \
         claims-space diversity filter; got {filtered:?}"
    );
    let near_kept = [near_a, near_b]
        .iter()
        .filter(|id| filtered.contains(&id.to_string()))
        .count();
    assert_eq!(
        near_kept, 1,
        "the claim-side collapse still happens in the same page, so the \
         workflow's survival is not just the filter being inert; got {filtered:?}"
    );
}

/// An out-of-range radius is REJECTED, not clamped. A clamped value produces a
/// page that looks filtered and is not.
#[sqlx::test(migrations = "../../migrations")]
async fn an_out_of_range_radius_is_rejected(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    seed_claim(
        &pool,
        agent,
        "gravamen baseline row",
        Some(&cluster_pgvec(1536, 0, 1.0)),
    )
    .await;
    let server = build_test_server(pool);
    let query_vec = cluster_pgvec(1536, 0, 1.0);

    for bad in [0.0, -0.5, 2.5, f64::NAN, f64::INFINITY] {
        let out = recall_with_pgvec(
            &server,
            &viewer,
            params("gravamen", Some(bad), false),
            Some(query_vec.clone()),
        )
        .await;
        assert!(
            out.is_err(),
            "diversity_radius={bad} must be rejected, not clamped or ignored"
        );
    }

    // And the boundary value that IS legal still works, so the guard is not
    // simply refusing everything.
    assert!(recall_with_pgvec(
        &server,
        &viewer,
        params("gravamen", Some(2.0), false),
        Some(query_vec),
    )
    .await
    .is_ok());
}

// ── recall_with_context, at 3072 ──────────────────────────────────────────

async fn seed_paper(pool: &PgPool, doi: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO papers (id, doi, title) VALUES ($1, $2, 'diversity fixture')")
        .bind(id)
        .bind(doi)
        .execute(pool)
        .await
        .expect("seed paper");
    id
}

/// A level-2 paragraph embedded ONLY in `claims.embedding_3072`. The 1536
/// column is deliberately left NULL: that is what makes the dim-selection test
/// below load-bearing rather than incidental.
async fn seed_paragraph_3072(
    pool: &PgPool,
    agent: Uuid,
    paper: Uuid,
    content: &str,
    pgvec_3072: &str,
) -> Uuid {
    seed_paragraph_3072_at_truth(pool, agent, paper, content, 0.8, pgvec_3072).await
}

/// [`seed_paragraph_3072`] with a caller-chosen `truth_value`, so a fixture can
/// straddle a `min_truth` threshold.
async fn seed_paragraph_3072_at_truth(
    pool: &PgPool,
    agent: Uuid,
    paper: Uuid,
    content: &str,
    truth: f64,
    pgvec_3072: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let mut hash = vec![0u8; 32];
    hash[..16].copy_from_slice(id.as_bytes());
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, properties, embedding_3072) \
         VALUES ($1, $2, $3, $4, $6, jsonb_build_object('level', 2::int), $5::vector)",
    )
    .bind(id)
    .bind(content)
    .bind(hash)
    .bind(agent)
    .bind(pgvec_3072)
    .bind(truth)
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

fn ctx_params(diversity_radius: Option<f64>) -> RecallWithContextParams {
    RecallWithContextParams {
        query: "diversity probe".to_string(),
        limit: Some(10),
        min_truth: Some(0.0),
        centroid_dim: Some(3072),
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
        epistemic_partition: false,
        diversity_radius,
    }
}

/// The dim trap. These paragraphs exist ONLY in `claims.embedding_3072`, and
/// the retrieval runs at `centroid_dim=3072`. A diversity filter hardcoded to
/// `claims.embedding` measures nothing here — every pair is absent, every hit
/// is "not known to be near", and a page of near-identical paragraphs comes
/// back reported as perfectly diverse. Measured in the right space, the
/// duplicate collapses.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_with_context_measures_diversity_in_the_retrieved_dim(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let paper = seed_paper(&pool, "10.9999/diversity.1").await;
    let query_vec = cluster_pgvec(3072, 0, 1.0);

    let near_a = seed_paragraph_3072(
        &pool,
        agent,
        paper,
        "paragraph stating the coefficient at high pressure",
        &cluster_pgvec(3072, 0, 1.0),
    )
    .await;
    let near_b = seed_paragraph_3072(
        &pool,
        agent,
        paper,
        "paragraph restating the coefficient under high pressure",
        &cluster_pgvec(3072, 0, 0.98),
    )
    .await;
    let distinct = seed_paragraph_3072(
        &pool,
        agent,
        paper,
        "paragraph describing the ledger procedure",
        &cluster_pgvec(3072, 4, 1.0),
    )
    .await;

    let server = build_test_server(pool);

    let ids = |env: &Value| -> Vec<String> {
        env["results"]
            .as_array()
            .expect("results array")
            .iter()
            .map(|h| {
                h["paragraph_id"]
                    .as_str()
                    .expect("paragraph_id")
                    .to_string()
            })
            .collect()
    };

    let base = ids(&envelope(
        recall_with_context_with_pgvec(&server, &viewer, ctx_params(None), 3072, &query_vec)
            .await
            .expect("baseline ok"),
    ));
    for id in [near_a, near_b, distinct] {
        assert!(
            base.contains(&id.to_string()),
            "baseline must hold every fixture paragraph; missing {id}, got {base:?}"
        );
    }

    let filtered = ids(&envelope(
        recall_with_context_with_pgvec(
            &server,
            &viewer,
            ctx_params(Some(RADIUS)),
            3072,
            &query_vec,
        )
        .await
        .expect("filtered ok"),
    ));

    let near_kept = [near_a, near_b]
        .iter()
        .filter(|id| filtered.contains(&id.to_string()))
        .count();
    assert_eq!(
        near_kept, 1,
        "the near-duplicate pair must collapse when measured in the 3072 space \
         the retrieval actually used; a filter reading claims.embedding finds \
         nothing here and keeps both. base={base:?} filtered={filtered:?}"
    );
    assert!(
        filtered.contains(&distinct.to_string()),
        "the orthogonal paragraph survives; got {filtered:?}"
    );
}

/// A hit that another filter is about to drop must not be allowed to SUPPRESS
/// one that would have survived.
///
/// `recall_with_context` applies `min_truth` after context assembly, while the
/// diversity pass runs on the seed set. Order them naively and a low-truth
/// paragraph ranked first can evict its high-truth near-duplicate, and then be
/// dropped itself by `min_truth` — so switching on a DE-DUPLICATION filter
/// deletes the good paragraph and returns an empty page, when the same query
/// without it returns the good one.
///
/// `near_low` is embedded exactly on the query vector so it ranks first;
/// `near_high` is its near-duplicate one rank down. `min_truth=0.5` sits
/// between their truth values.
///
/// `recall`'s twin below pins the same property on the other surface, where
/// `min_truth` and `exclude_contested` already run before the diversity pass.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hit_another_filter_will_drop_cannot_suppress_a_surviving_one(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let paper = seed_paper(&pool, "10.9999/diversity.2").await;
    let query_vec = cluster_pgvec(3072, 0, 1.0);

    let near_low = seed_paragraph_3072_at_truth(
        &pool,
        agent,
        paper,
        "low-confidence paragraph on the coefficient",
        0.2,
        &cluster_pgvec(3072, 0, 1.0),
    )
    .await;
    let near_high = seed_paragraph_3072_at_truth(
        &pool,
        agent,
        paper,
        "high-confidence paragraph on the coefficient",
        0.9,
        &cluster_pgvec(3072, 0, 0.98),
    )
    .await;

    let server = build_test_server(pool);
    let ids = |env: &Value| -> Vec<String> {
        env["results"]
            .as_array()
            .expect("results array")
            .iter()
            .map(|h| {
                h["paragraph_id"]
                    .as_str()
                    .expect("paragraph_id")
                    .to_string()
            })
            .collect()
    };
    let with_min_truth = |radius: Option<f64>| {
        let mut p = ctx_params(radius);
        p.min_truth = Some(0.5);
        p
    };

    // Baseline: `min_truth` alone drops the 0.2 paragraph and keeps the 0.9 one.
    let base = ids(&envelope(
        recall_with_context_with_pgvec(&server, &viewer, with_min_truth(None), 3072, &query_vec)
            .await
            .expect("baseline ok"),
    ));
    assert_eq!(
        base,
        vec![near_high.to_string()],
        "precondition: without the radius, min_truth leaves exactly the 0.9 paragraph"
    );
    assert!(!base.contains(&near_low.to_string()));

    // Adding a de-duplication filter must not take the survivor with it.
    let filtered = ids(&envelope(
        recall_with_context_with_pgvec(
            &server,
            &viewer,
            with_min_truth(Some(RADIUS)),
            3072,
            &query_vec,
        )
        .await
        .expect("filtered ok"),
    ));
    assert!(
        filtered.contains(&near_high.to_string()),
        "switching on diversity_radius must not delete a hit that survives every \
         other filter, by letting a min_truth-doomed duplicate evict it first. \
         base={base:?} filtered={filtered:?}"
    );
}

/// The `recall` twin: a contested hit that `exclude_contested` is about to drop
/// must not evict its clean near-duplicate first.
#[sqlx::test(migrations = "../../migrations")]
async fn on_recall_a_contested_hit_cannot_suppress_its_clean_duplicate(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = seed_agent(&pool).await;
    let query_vec = cluster_pgvec(1536, 0, 1.0);

    let contested = seed_claim(
        &pool,
        agent,
        "vantril throughput ceiling reported at ambient",
        Some(&cluster_pgvec(1536, 0, 1.0)),
    )
    .await;
    let clean = seed_claim(
        &pool,
        agent,
        "vantril throughput ceiling reported under ambient",
        Some(&cluster_pgvec(1536, 0, 0.98)),
    )
    .await;
    let rebuttal = seed_claim(&pool, agent, "vantril ceiling rebuttal", None).await;
    sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
         VALUES ($1, $2, 'claim', 'claim', 'contradicts')",
    )
    .bind(rebuttal)
    .bind(contested)
    .execute(&pool)
    .await
    .expect("seed dispute edge");

    let server = build_test_server(pool);
    let with_exclude = |radius: Option<f64>| {
        let mut p = params("vantril throughput ceiling", radius, false);
        p.exclude_contested = true;
        p
    };

    let base = result_ids(&envelope(
        recall_with_pgvec(
            &server,
            &viewer,
            with_exclude(None),
            Some(query_vec.clone()),
        )
        .await
        .expect("baseline ok"),
    ));
    assert!(
        base.contains(&clean.to_string()) && !base.contains(&contested.to_string()),
        "precondition: exclude_contested alone leaves the clean duplicate. got {base:?}"
    );

    let filtered = result_ids(&envelope(
        recall_with_pgvec(
            &server,
            &viewer,
            with_exclude(Some(RADIUS)),
            Some(query_vec),
        )
        .await
        .expect("filtered ok"),
    ));
    assert!(
        filtered.contains(&clean.to_string()),
        "a contested hit that exclude_contested drops must not evict its clean \
         near-duplicate on the way out. base={base:?} filtered={filtered:?}"
    );
}
