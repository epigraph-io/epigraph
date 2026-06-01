//! T16: end-to-end pipeline test.
//!
//! A pair with identical embeddings and different paper_dois scores 0.40
//! (only embed_cosine contributes; default weight 0.40). With bands.high
//! lowered to 0.30, the pair auto-promotes: a `match_candidates` row with
//! `status='promoted'` is written and a `CORROBORATES` edge is emitted.

use async_trait::async_trait;
use epigraph_engine::matching::calibration::MatcherConfig;
use epigraph_engine::matching::pipeline::{run_pipeline, RunInputs};
use epigraph_engine::matching::verifier::{Verdict, VerifierClient};
use epigraph_db::repos::match_candidate::MatchCandidateRepo;
use sqlx::PgPool;
use uuid::Uuid;

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

async fn insert_claim(
    pool: &PgPool,
    agent: Uuid,
    properties: serde_json::Value,
    embedding: &[f32],
) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {id}");
    let lit = format!(
        "[{}]",
        embedding
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    sqlx::query(&format!(
        "INSERT INTO claims
           (id, content, content_hash, truth_value, agent_id, properties, embedding)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, $4, '{lit}'::vector)"
    ))
    .bind(id)
    .bind(&content)
    .bind(agent)
    .bind(properties)
    .execute(pool)
    .await
    .expect("claim");
    id
}

/// Always claims "supports" — used to assert the high-band path doesn't
/// invoke the verifier (verifier verdicts never appear on the row).
struct AlwaysSameVerifier;

#[async_trait]
impl VerifierClient for AlwaysSameVerifier {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Verdict>> {
        Ok(pairs
            .iter()
            .map(|(a, b)| Verdict {
                source_id: *a,
                target_id: *b,
                relationship: "supports".to_string(),
                strength: 0.9,
                rationale: "test".to_string(),
            })
            .collect())
    }
}

struct AlwaysContradictsVerifier;

#[async_trait]
impl VerifierClient for AlwaysContradictsVerifier {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Verdict>> {
        Ok(pairs
            .iter()
            .map(|(a, b)| Verdict {
                source_id: *a,
                target_id: *b,
                relationship: "contradicts".to_string(),
                strength: 0.85,
                rationale: "negation".to_string(),
            })
            .collect())
    }
}

struct AlwaysDerivesFromVerifier;

#[async_trait]
impl VerifierClient for AlwaysDerivesFromVerifier {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Verdict>> {
        // `derives_from` maps to MatchVerdict::Distinct → Reject branch.
        Ok(pairs
            .iter()
            .map(|(a, b)| Verdict {
                source_id: *a,
                target_id: *b,
                relationship: "derives_from".to_string(),
                strength: 0.7,
                rationale: "related not same".to_string(),
            })
            .collect())
    }
}

/// Move bands so the canonical 0.40-score pair lands in the mid band, where
/// the verifier is invoked.
fn mid_band_config() -> MatcherConfig {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../calibration.toml");
    let mut cfg = MatcherConfig::load_from(&p).expect("load calibration.toml");
    cfg.bands.high = 0.50; // above the 0.40 single-feature ceiling
    cfg.bands.mid = 0.30;
    cfg
}

fn test_config() -> MatcherConfig {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../calibration.toml");
    let mut cfg = MatcherConfig::load_from(&p).expect("load calibration.toml");
    // Default bands (high=0.85, mid=0.60) sit above the 0.40 a single-feature
    // pair can achieve. Lower them so the test exercises the auto-promote path
    // deterministically — this is exactly the "calibration override" use case.
    cfg.bands.high = 0.30;
    cfg.bands.mid = 0.20;
    cfg
}

#[sqlx::test(migrations = "../../migrations")]
async fn high_band_pair_emits_promoted_candidate_and_corroborates_edge(pool: PgPool) {
    let agent_x = insert_agent(&pool).await;
    let agent_y = insert_agent(&pool).await;
    let v = vec![1.0_f32; 1536];
    let seed = insert_claim(
        &pool,
        agent_x,
        serde_json::json!({"paper_doi": "10.1/A"}),
        &v,
    )
    .await;
    let peer = insert_claim(
        &pool,
        agent_y,
        serde_json::json!({"paper_doi": "10.1/B"}),
        &v,
    )
    .await;

    let inputs = RunInputs {
        seeds: vec![seed],
        cfg: test_config(),
        verifier: Box::new(AlwaysSameVerifier),
        auto_promote: true,
    };
    let report = run_pipeline(&pool, inputs).await.expect("pipeline");

    assert!(
        report.promoted >= 1,
        "expected ≥1 promotion, got {report:?}"
    );
    // The high-band fast path should NOT touch the verifier, so mid_band == 0.
    assert_eq!(report.mid_band, 0, "high-band pair leaked to verifier");

    // CORROBORATES edge in either direction (write_edge sends the seed→peer
    // order, but assert symmetrically).
    let edge_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE relationship = 'CORROBORATES'
           AND ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))",
    )
    .bind(seed)
    .bind(peer)
    .fetch_one(&pool)
    .await
    .expect("edge count");
    assert_eq!(edge_count.0, 1, "expected exactly one CORROBORATES edge");

    // match_candidates row with status=promoted (canonical order: min < max).
    let (lo, hi) = if seed < peer {
        (seed, peer)
    } else {
        (peer, seed)
    };
    let (status, run_id): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status, matcher_run_id FROM match_candidates
         WHERE claim_a = $1 AND claim_b = $2",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(&pool)
    .await
    .expect("candidate row");
    assert_eq!(status, "promoted");
    assert_eq!(run_id, Some(report.run_id));
}

#[sqlx::test(migrations = "../../migrations")]
async fn auto_promote_false_stages_pending_for_review_and_skips_edge(pool: PgPool) {
    let agent_x = insert_agent(&pool).await;
    let agent_y = insert_agent(&pool).await;
    let v = vec![1.0_f32; 1536];
    let seed = insert_claim(
        &pool,
        agent_x,
        serde_json::json!({"paper_doi": "10.1/C"}),
        &v,
    )
    .await;
    let peer = insert_claim(
        &pool,
        agent_y,
        serde_json::json!({"paper_doi": "10.1/D"}),
        &v,
    )
    .await;

    let inputs = RunInputs {
        seeds: vec![seed],
        cfg: test_config(),
        verifier: Box::new(AlwaysSameVerifier),
        auto_promote: false,
    };
    let report = run_pipeline(&pool, inputs).await.expect("pipeline");
    assert!(
        report.staged >= 1,
        "auto_promote=false must STAGE for human review, got {report:?}"
    );
    assert_eq!(
        report.promoted, 0,
        "nothing is promoted when auto_promote=false, got {report:?}"
    );

    let edge_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE relationship = 'CORROBORATES'
           AND ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))",
    )
    .bind(seed)
    .bind(peer)
    .fetch_one(&pool)
    .await
    .expect("edge count");
    assert_eq!(
        edge_count.0, 0,
        "auto_promote=false must not write the edge"
    );

    let (lo, hi) = if seed < peer {
        (seed, peer)
    } else {
        (peer, seed)
    };
    let exists: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM match_candidates
         WHERE claim_a = $1 AND claim_b = $2 AND status = 'pending'",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(&pool)
    .await
    .expect("candidate count");
    assert_eq!(
        exists.0, 1,
        "auto_promote=false must STAGE the candidate as 'pending' for human review, not silently 'promoted'"
    );
}

/// LOAD-BEARING (B1): the human-review queue must now have a PRODUCER.
/// Before this fix `Policy::act` only ever wrote `promoted`/`rejected`, so
/// `MatchCandidateRepo::list_pending` — the reader behind the MCP
/// `list_match_candidates`/`decide_match_candidate` tools and the API
/// `pending[]` array — always returned empty in normal operation. With
/// `auto_promote=false`, a high-band pair must now surface through
/// `list_pending`, proving the producer→consumer path end-to-end (the real
/// consumer API, not just a raw status check).
#[sqlx::test(migrations = "../../migrations")]
async fn auto_promote_false_populates_pending_review_queue(pool: PgPool) {
    let agent_x = insert_agent(&pool).await;
    let agent_y = insert_agent(&pool).await;
    let v = vec![1.0_f32; 1536];
    let seed = insert_claim(
        &pool,
        agent_x,
        serde_json::json!({"paper_doi": "10.1/E"}),
        &v,
    )
    .await;
    let peer = insert_claim(
        &pool,
        agent_y,
        serde_json::json!({"paper_doi": "10.1/F"}),
        &v,
    )
    .await;

    // The fresh per-test DB starts with an empty review queue.
    let repo = MatchCandidateRepo::new(pool.clone());
    assert!(
        repo.list_pending(50).await.expect("list_pending").is_empty(),
        "review queue must start empty before the pipeline runs"
    );

    let inputs = RunInputs {
        seeds: vec![seed],
        cfg: test_config(),
        verifier: Box::new(AlwaysSameVerifier),
        auto_promote: false,
    };
    run_pipeline(&pool, inputs).await.expect("pipeline");

    let pending = repo.list_pending(50).await.expect("list_pending");
    assert!(
        pending.iter().any(|r| (r.claim_a == seed && r.claim_b == peer)
            || (r.claim_a == peer && r.claim_b == seed)),
        "high-band pair must surface in the pending review queue under auto_promote=false"
    );
    assert!(
        pending.iter().all(|r| r.status == "pending"),
        "list_pending must return only pending rows"
    );
}

/// Drive the same 0.40-score pair into the mid band and verify the
/// AlwaysSame → AutoPromote branch writes both the row + edge and that the
/// verifier_verdict column persists the mapped `MatchVerdict` vocabulary.
#[sqlx::test(migrations = "../../migrations")]
async fn mid_band_same_verdict_promotes_and_writes_mapped_column(pool: PgPool) {
    let agent_x = insert_agent(&pool).await;
    let agent_y = insert_agent(&pool).await;
    let v = vec![1.0_f32; 1536];
    let seed = insert_claim(
        &pool,
        agent_x,
        serde_json::json!({"paper_doi": "10.1/E"}),
        &v,
    )
    .await;
    let peer = insert_claim(
        &pool,
        agent_y,
        serde_json::json!({"paper_doi": "10.1/F"}),
        &v,
    )
    .await;

    let inputs = RunInputs {
        seeds: vec![seed],
        cfg: mid_band_config(),
        verifier: Box::new(AlwaysSameVerifier),
        auto_promote: true,
    };
    let report = run_pipeline(&pool, inputs).await.expect("pipeline");
    assert!(
        report.mid_band >= 1,
        "expected verifier invocation: {report:?}"
    );
    assert!(report.promoted >= 1);

    let (lo, hi) = if seed < peer {
        (seed, peer)
    } else {
        (peer, seed)
    };
    let (verdict_col, rationale_col): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT verifier_verdict, verifier_rationale FROM match_candidates
         WHERE claim_a = $1 AND claim_b = $2",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(&pool)
    .await
    .expect("row");
    // Critical: store the mapped vocabulary, NOT the raw 'supports' string.
    assert_eq!(verdict_col.as_deref(), Some("same"));
    assert_eq!(rationale_col.as_deref(), Some("test"));

    let edge_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE relationship = 'CORROBORATES'
           AND ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))",
    )
    .bind(seed)
    .bind(peer)
    .fetch_one(&pool)
    .await
    .expect("edge count");
    assert_eq!(edge_count.0, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn mid_band_contradicts_writes_contradicts_edge(pool: PgPool) {
    let agent_x = insert_agent(&pool).await;
    let agent_y = insert_agent(&pool).await;
    let v = vec![1.0_f32; 1536];
    let seed = insert_claim(
        &pool,
        agent_x,
        serde_json::json!({"paper_doi": "10.1/G"}),
        &v,
    )
    .await;
    let peer = insert_claim(
        &pool,
        agent_y,
        serde_json::json!({"paper_doi": "10.1/H"}),
        &v,
    )
    .await;

    let inputs = RunInputs {
        seeds: vec![seed],
        cfg: mid_band_config(),
        verifier: Box::new(AlwaysContradictsVerifier),
        auto_promote: true,
    };
    let report = run_pipeline(&pool, inputs).await.expect("pipeline");
    assert!(report.mid_band >= 1);
    assert!(report.promoted >= 1);

    // No CORROBORATES — only contradicts.
    let corrob: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE relationship = 'CORROBORATES'
           AND ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))",
    )
    .bind(seed)
    .bind(peer)
    .fetch_one(&pool)
    .await
    .expect("corrob count");
    assert_eq!(corrob.0, 0, "contradicts path must NOT emit CORROBORATES");

    let contradict: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE relationship = 'contradicts'
           AND ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))",
    )
    .bind(seed)
    .bind(peer)
    .fetch_one(&pool)
    .await
    .expect("contradicts count");
    assert_eq!(contradict.0, 1);

    let (lo, hi) = if seed < peer {
        (seed, peer)
    } else {
        (peer, seed)
    };
    let verdict_col: (Option<String>,) = sqlx::query_as(
        "SELECT verifier_verdict FROM match_candidates
         WHERE claim_a = $1 AND claim_b = $2",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(&pool)
    .await
    .expect("row");
    assert_eq!(verdict_col.0.as_deref(), Some("contradicts"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn mid_band_distinct_verdict_records_rejected_row_and_no_edge(pool: PgPool) {
    let agent_x = insert_agent(&pool).await;
    let agent_y = insert_agent(&pool).await;
    let v = vec![1.0_f32; 1536];
    let seed = insert_claim(
        &pool,
        agent_x,
        serde_json::json!({"paper_doi": "10.1/I"}),
        &v,
    )
    .await;
    let peer = insert_claim(
        &pool,
        agent_y,
        serde_json::json!({"paper_doi": "10.1/J"}),
        &v,
    )
    .await;

    let inputs = RunInputs {
        seeds: vec![seed],
        cfg: mid_band_config(),
        verifier: Box::new(AlwaysDerivesFromVerifier),
        auto_promote: true,
    };
    let report = run_pipeline(&pool, inputs).await.expect("pipeline");
    assert!(report.mid_band >= 1);
    assert!(report.rejected >= 1);

    let edge_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))
           AND relationship IN ('CORROBORATES', 'contradicts')",
    )
    .bind(seed)
    .bind(peer)
    .fetch_one(&pool)
    .await
    .expect("edge count");
    assert_eq!(edge_count.0, 0, "distinct verdict must not write any edge");

    let (lo, hi) = if seed < peer {
        (seed, peer)
    } else {
        (peer, seed)
    };
    let (status, verdict_col): (String, Option<String>) = sqlx::query_as(
        "SELECT status, verifier_verdict FROM match_candidates
         WHERE claim_a = $1 AND claim_b = $2",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(&pool)
    .await
    .expect("row");
    assert_eq!(status, "rejected");
    assert_eq!(verdict_col.as_deref(), Some("distinct"));
}
