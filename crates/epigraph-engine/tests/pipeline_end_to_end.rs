//! T16: end-to-end pipeline test.
//!
//! A pair with identical embeddings and different paper_dois scores 0.40
//! (only embed_cosine contributes; default weight 0.40). Clearing `bands.mid`
//! routes the pair through the verifier; on a Same/`supports` verdict a
//! `match_candidates` row with `status='promoted'` is written and a
//! `CORROBORATES` edge is emitted. High-band pairs are NO LONGER auto-promoted
//! without verification — see `high_band_pair_is_verified_not_blindly_corroborated`.

use async_trait::async_trait;
use epigraph_db::repos::match_candidate::MatchCandidateRepo;
use epigraph_engine::matching::calibration::MatcherConfig;
use epigraph_engine::matching::pipeline::{run_pipeline, RunInputs};
use epigraph_engine::matching::verifier::{Verdict, VerifierClient};
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

/// Always claims "supports" (→ `MatchVerdict::Same` → corroborate).
struct AlwaysSameVerifier;

#[async_trait]
impl VerifierClient for AlwaysSameVerifier {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Option<Verdict>>> {
        Ok(pairs
            .iter()
            .map(|(a, b)| {
                Some(Verdict {
                    source_id: *a,
                    target_id: *b,
                    relationship: "supports".to_string(),
                    strength: 0.9,
                    rationale: "test".to_string(),
                })
            })
            .collect())
    }
}

struct AlwaysContradictsVerifier;

#[async_trait]
impl VerifierClient for AlwaysContradictsVerifier {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Option<Verdict>>> {
        Ok(pairs
            .iter()
            .map(|(a, b)| {
                Some(Verdict {
                    source_id: *a,
                    target_id: *b,
                    relationship: "contradicts".to_string(),
                    strength: 0.85,
                    rationale: "negation".to_string(),
                })
            })
            .collect())
    }
}

struct AlwaysDerivesFromVerifier;

#[async_trait]
impl VerifierClient for AlwaysDerivesFromVerifier {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Option<Verdict>>> {
        // `derives_from` maps to MatchVerdict::Distinct → Reject branch. This
        // is an ANSWER — the model was asked and said "related, not the same" —
        // as distinct from `NoAnswerVerifier`'s silence below.
        Ok(pairs
            .iter()
            .map(|(a, b)| {
                Some(Verdict {
                    source_id: *a,
                    target_id: *b,
                    relationship: "derives_from".to_string(),
                    strength: 0.7,
                    rationale: "related not same".to_string(),
                })
            })
            .collect())
    }
}

/// Records whether `verify` was invoked and returns a configurable
/// relationship — lets a test PROVE the verifier was (or was not) consulted.
struct SpyVerifier {
    called: std::sync::Arc<std::sync::atomic::AtomicBool>,
    relationship: &'static str,
}

#[async_trait]
impl VerifierClient for SpyVerifier {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Option<Verdict>>> {
        self.called.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(pairs
            .iter()
            .map(|(a, b)| {
                Some(Verdict {
                    source_id: *a,
                    target_id: *b,
                    relationship: self.relationship.to_string(),
                    strength: 0.9,
                    rationale: "spy".to_string(),
                })
            })
            .collect())
    }
}

/// LOAD-BEARING (B2): a high-band pair MUST be sent to the verifier before it
/// can become a CORROBORATES edge. Before this fix, `score >= bands.high`
/// auto-promoted with NO verification, so a strongly-cosine but opposite-stance
/// pair (or a missing-mass pair whose `belief_alignment` fell back to the
/// neutral 0.5) silently corroborated. The `SpyVerifier` proves the verifier is
/// now consulted on the high band; returning `contradicts` proves the pair does
/// NOT corroborate.
#[sqlx::test(migrations = "../../migrations")]
async fn high_band_pair_is_verified_not_blindly_corroborated(pool: PgPool) {
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

    let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let inputs = RunInputs {
        seeds: vec![seed],
        cfg: test_config(), // high=0.30, so the 0.40 pair is high-band
        verifier: Box::new(SpyVerifier {
            called: called.clone(),
            relationship: "contradicts",
        }),
        auto_promote: true,
    };
    run_pipeline(&pool, inputs).await.expect("pipeline");

    // THE load-bearing assertion: the high-band pair was sent to the verifier.
    assert!(
        called.load(std::sync::atomic::Ordering::SeqCst),
        "high-band pair MUST be routed through the verifier before corroborating \
         (the unverified fast-path was the bug)"
    );

    // The verifier said `contradicts`, so NO CORROBORATES edge may exist...
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
    .expect("corroborates count");
    assert_eq!(
        corrob.0, 0,
        "a verifier-rejected high-band pair must NOT auto-corroborate"
    );

    // ...and a `contradicts` edge IS written (auto_promote=true → WriteContradicts).
    let contra: (i64,) = sqlx::query_as(
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
    assert_eq!(
        contra.0, 1,
        "verifier `contradicts` verdict must write a contradicts edge"
    );
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
async fn high_band_pair_verified_then_promotes_and_corroborates(pool: PgPool) {
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
    // High-band pairs are now routed THROUGH the verifier (the unverified
    // fast-path was removed); on a `supports`→Same verdict they still promote.
    assert_eq!(
        report.mid_band, 1,
        "high-band pair must be verified before promotion, got {report:?}"
    );

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
        repo.list_pending(50)
            .await
            .expect("list_pending")
            .is_empty(),
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
        pending
            .iter()
            .any(|r| (r.claim_a == seed && r.claim_b == peer)
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

/// A verifier with NO answer for any pair — what
/// `epigraph_cli::matching_client::align_verdicts` now returns when the
/// reranker produced no row for a pair (model omitted it from the batch, the
/// batch's LLM call failed, or the pair was filtered out before it was sent).
///
/// This slot used to be filled by a fabricated
/// `relationship: "derives_from", strength: 0.0` verdict carrying the rationale
/// `"verifier returned no verdict for this pair"` — the literal borne by all
/// 123 corrupted `match_candidates` rows measured in prod. That is what this
/// test watched destroy a stored `same` before the fix.
struct NoAnswerVerifier;

#[async_trait]
impl VerifierClient for NoAnswerVerifier {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Option<Verdict>>> {
        Ok(pairs.iter().map(|_| None).collect())
    }
}

/// LOAD-BEARING (Defect B): a pair the verifier did NOT answer on must leave
/// the stored verdict untouched.
///
/// The verifier's silence is not a finding. Today it is laundered into one: the
/// fabricated `derives_from` placeholder maps to `MatchVerdict::Distinct` →
/// `PolicyAction::Reject` → `patch_verdict`, which destructively overwrites a
/// prior `same` with `distinct` — and under the promotion rules from #382 a
/// `distinct` row is permanently un-promotable, so the real verdict is not just
/// lost, the pair is retired.
#[sqlx::test(migrations = "../../migrations")]
async fn verifier_no_answer_must_not_overwrite_stored_verdict(pool: PgPool) {
    let agent_x = insert_agent(&pool).await;
    let agent_y = insert_agent(&pool).await;
    let v = vec![1.0_f32; 1536];
    let seed = insert_claim(
        &pool,
        agent_x,
        serde_json::json!({"paper_doi": "10.1/K"}),
        &v,
    )
    .await;
    let peer = insert_claim(
        &pool,
        agent_y,
        serde_json::json!({"paper_doi": "10.1/L"}),
        &v,
    )
    .await;

    // A prior run already got a real verdict for this pair. `decided_at` stays
    // NULL so the #380 status guard and the #384 verdict freeze are BOTH out of
    // the picture — this test isolates the verifier's own write path.
    let (lo, hi) = if seed < peer {
        (seed, peer)
    } else {
        (peer, seed)
    };
    sqlx::query(
        "INSERT INTO match_candidates
           (claim_a, claim_b, score, features, status, verifier_verdict, verifier_rationale)
         VALUES ($1, $2, 0.40, '{}'::jsonb, 'pending', 'same', 'earlier run: same underlying claim')",
    )
    .bind(lo)
    .bind(hi)
    .execute(&pool)
    .await
    .expect("seed prior verdict");

    let inputs = RunInputs {
        seeds: vec![seed],
        cfg: mid_band_config(),
        verifier: Box::new(NoAnswerVerifier),
        auto_promote: true,
    };
    let report = run_pipeline(&pool, inputs).await.expect("pipeline");

    // Anti-vacuity: the skip path never re-writes score/features either, so an
    // untouched row would ALSO be the result of the pair never reaching the
    // verifier (blocked out, or scored below `bands.mid`). Pin that it did.
    assert_eq!(
        report.skipped_no_verdict, 1,
        "the pair must actually have reached the verifier and been skipped, \
         otherwise the assertions below pass for the wrong reason: {report:?}"
    );

    let (verdict_col, rationale_col, status): (Option<String>, Option<String>, String) =
        sqlx::query_as(
            "SELECT verifier_verdict, verifier_rationale, status FROM match_candidates
             WHERE claim_a = $1 AND claim_b = $2",
        )
        .bind(lo)
        .bind(hi)
        .fetch_one(&pool)
        .await
        .expect("row");

    assert_eq!(
        verdict_col.as_deref(),
        Some("same"),
        "a pair the verifier never answered on must not overwrite the stored \
         verdict — the verifier's silence is not a finding"
    );
    assert_eq!(
        rationale_col.as_deref(),
        Some("earlier run: same underlying claim"),
        "the stored rationale must survive a no-answer too"
    );
    assert_eq!(
        status, "pending",
        "a no-answer must not reject the candidate"
    );
}

/// The same skip on a pair with no history: nothing is written at all, and the
/// skip is COUNTED rather than folded into `rejected`. Without the separate
/// counter a verifier outage is indistinguishable from a corpus that stopped
/// matching — the run log would show `rejected` climbing and look healthy.
#[sqlx::test(migrations = "../../migrations")]
async fn verifier_no_answer_writes_nothing_and_is_counted_separately(pool: PgPool) {
    let agent_x = insert_agent(&pool).await;
    let agent_y = insert_agent(&pool).await;
    let v = vec![1.0_f32; 1536];
    let seed = insert_claim(
        &pool,
        agent_x,
        serde_json::json!({"paper_doi": "10.1/M"}),
        &v,
    )
    .await;
    let peer = insert_claim(
        &pool,
        agent_y,
        serde_json::json!({"paper_doi": "10.1/N"}),
        &v,
    )
    .await;

    let inputs = RunInputs {
        seeds: vec![seed],
        cfg: mid_band_config(),
        verifier: Box::new(NoAnswerVerifier),
        auto_promote: true,
    };
    let report = run_pipeline(&pool, inputs).await.expect("pipeline");

    assert_eq!(
        report.mid_band, 1,
        "the pair WAS routed to the verifier — band telemetry must still see it: {report:?}"
    );
    assert_eq!(
        report.skipped_no_verdict, 1,
        "a no-answer must be counted so an outage is visible: {report:?}"
    );
    assert_eq!(report.rejected, 0, "a skip is not a rejection: {report:?}");
    assert_eq!(report.promoted, 0, "a skip is not a promotion: {report:?}");

    let (lo, hi) = if seed < peer {
        (seed, peer)
    } else {
        (peer, seed)
    };
    let rows: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM match_candidates
         WHERE claim_a = $1 AND claim_b = $2",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(&pool)
    .await
    .expect("candidate count");
    assert_eq!(
        rows.0, 0,
        "a pair the verifier never answered on must leave no candidate row — \
         a 'rejected' row here is a fabricated finding"
    );

    let edges: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE (source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)",
    )
    .bind(seed)
    .bind(peer)
    .fetch_one(&pool)
    .await
    .expect("edge count");
    assert_eq!(edges.0, 0, "a skip must not write an edge");
}
