//! a04248cf: the stance-seeking probe blocker retrieves a contradicting claim
//! that the seed's own embedding neighbourhood does not reach.
//!
//! Geometry (1536-d, unit axes `e_i`):
//! - seed `S` = `e0`, content "Compound K increases neuronal survival in culture";
//! - `DISTRACTORS` restatements at cosine 0.95 to `S`
//!   (`0.95 e0 + sqrt(1 - 0.95^2) e_{10+i}`), more than `top_k` of them;
//! - contradicting `C` = `0.6 e0 + 0.8 e1` (cosine 0.6 to `S`).
//!
//! The seed's ANN top-k is all distractors, so `(S, C)` is never retrieved by
//! the neighbourhood blockers. The probe text "Compound K decreases neuronal
//! survival in culture" embeds (in the lookup embedder) to `C`'s vector, so a
//! probe search returns `C` first.

use async_trait::async_trait;
use epigraph_embeddings::{EmbeddingError, EmbeddingService, TokenUsage};
use epigraph_engine::matching::blocker::stance_probe::{StanceProbeBlocker, StanceProbeStats};
use epigraph_engine::matching::blocker::{
    canonical, embedding_ann::EmbeddingAnnBlocker, union_block_with_stats, Blocker,
};
use epigraph_engine::matching::calibration::MatcherConfig;
use epigraph_engine::matching::pipeline::{run_pipeline, RunInputs};
use epigraph_engine::matching::verifier::{Verdict, VerifierClient};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const DIM: usize = 1536;
const TOP_K: usize = 3;
const DISTRACTORS: usize = 6;

const SEED_TEXT: &str = "Compound K increases neuronal survival in culture";
const INVERSION_PROBE: &str = "Compound K decreases neuronal survival in culture";
const NEGATION_PROBE: &str =
    "It is not the case that compound K increases neuronal survival in culture";
const CONTRA_TEXT: &str = "Neuronal survival in culture drops after compound K exposure";

fn axis(i: usize) -> Vec<f32> {
    let mut v = vec![0.0_f32; DIM];
    v[i] = 1.0;
    v
}

fn seed_vec() -> Vec<f32> {
    axis(0)
}

fn contra_vec() -> Vec<f32> {
    let mut v = vec![0.0_f32; DIM];
    v[0] = 0.6;
    v[1] = 0.8;
    v
}

fn distractor_vec(i: usize) -> Vec<f32> {
    let mut v = vec![0.0_f32; DIM];
    v[0] = 0.95;
    v[10 + i] = (1.0_f32 - 0.95 * 0.95).sqrt();
    v
}

/// Embeds only the texts it was told about and errors on anything else, so a
/// test also pins the exact probe texts the template produced.
struct LookupEmbedder {
    table: HashMap<String, Vec<f32>>,
    dim: usize,
    fail: bool,
}

impl LookupEmbedder {
    fn probes_for_seed() -> Self {
        let mut table = HashMap::new();
        table.insert(INVERSION_PROBE.to_string(), contra_vec());
        // The negation probe lands on an unrelated axis: it must not be what
        // finds C.
        table.insert(NEGATION_PROBE.to_string(), axis(1000));
        Self {
            table,
            dim: DIM,
            fail: false,
        }
    }
}

#[async_trait]
impl EmbeddingService for LookupEmbedder {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if self.fail {
            return Err(EmbeddingError::ApiError {
                message: "embedding outage".to_string(),
                status_code: Some(503),
            });
        }
        self.table
            .get(text)
            .map(|v| v[..self.dim.min(v.len())].to_vec())
            .ok_or_else(|| EmbeddingError::ApiError {
                message: format!("unexpected probe text: {text:?}"),
                status_code: None,
            })
    }

    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        let mut out = Vec::with_capacity(texts.len());
        for t in texts {
            out.push(self.generate(t).await?);
        }
        Ok(out)
    }

    fn dimension(&self) -> usize {
        self.dim
    }

    fn token_usage(&self) -> TokenUsage {
        TokenUsage::default()
    }

    fn reset_token_usage(&self) {}

    async fn health_check(&self) -> Result<(), EmbeddingError> {
        Ok(())
    }
}

/// Records every pair routed to it and answers nothing, so the pipeline
/// writes no candidate rows.
struct RecordingVerifier {
    seen: Arc<Mutex<Vec<(Uuid, Uuid)>>>,
}

#[async_trait]
impl VerifierClient for RecordingVerifier {
    async fn verify(&self, pairs: &[(Uuid, Uuid)]) -> anyhow::Result<Vec<Option<Verdict>>> {
        self.seen.lock().unwrap().extend_from_slice(pairs);
        Ok(pairs.iter().map(|_| None).collect())
    }
}

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
    content: &str,
    doi: &str,
    embedding: Option<&[f32]>,
) -> Uuid {
    let id = Uuid::new_v4();
    let lit = embedding.map(epigraph_db::pgvector_literal);
    sqlx::query(
        "INSERT INTO claims
           (id, content, content_hash, truth_value, agent_id, properties, embedding)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, $4, $5::vector)",
    )
    .bind(id)
    .bind(content)
    .bind(agent)
    .bind(serde_json::json!({ "paper_doi": doi }))
    .bind(lit)
    .execute(pool)
    .await
    .expect("claim");
    id
}

struct Fixture {
    seed: Uuid,
    contra: Uuid,
}

async fn fixture(pool: &PgPool) -> Fixture {
    let agent_s = insert_agent(pool).await;
    let agent_c = insert_agent(pool).await;
    let agent_d = insert_agent(pool).await;
    let seed = insert_claim(pool, agent_s, SEED_TEXT, "10.1/seed", Some(&seed_vec())).await;
    let contra = insert_claim(
        pool,
        agent_c,
        CONTRA_TEXT,
        "10.1/contra",
        Some(&contra_vec()),
    )
    .await;
    for i in 0..DISTRACTORS {
        insert_claim(
            pool,
            agent_d,
            &format!("Compound K raises neuronal viability, replicate {i}"),
            &format!("10.1/d{i}"),
            Some(&distractor_vec(i)),
        )
        .await;
    }
    Fixture { seed, contra }
}

fn test_config() -> MatcherConfig {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../calibration.toml");
    let mut cfg = MatcherConfig::load_from(&p).expect("load calibration.toml");
    cfg.fan_out.max_per_claim = TOP_K;
    // Low enough that the contradicting pair (cosine 0.6) is routed to the
    // verifier; the test is about recall, not about the band thresholds.
    cfg.bands.high = 1.01;
    cfg.bands.mid = 0.20;
    cfg
}

/// Blocker level: the seed's own ANN misses C; the probe search finds it.
#[sqlx::test(migrations = "../../migrations")]
async fn probe_retrieves_contradiction_the_seed_ann_misses(pool: PgPool) {
    let f = fixture(&pool).await;
    let want = canonical(f.seed, f.contra).unwrap();

    let ann = EmbeddingAnnBlocker::new(TOP_K)
        .candidates(&pool, &[f.seed])
        .await
        .expect("ann");
    assert!(
        !ann.contains(&want),
        "fixture invalid: the seed's ANN already reaches C ({ann:?})"
    );

    let embedder = LookupEmbedder::probes_for_seed();
    let (probe, stats) = StanceProbeBlocker::prepare(&pool, &embedder, &[f.seed], TOP_K)
        .await
        .expect("prepare");
    assert_eq!(
        stats,
        StanceProbeStats {
            seeds_probed: 1,
            probe_texts: 2,
            seeds_skipped: 0,
        }
    );
    let got = probe.candidates(&pool, &[f.seed]).await.expect("probe");
    assert!(got.contains(&want), "probe must retrieve C, got {got:?}");
    for (a, b) in &got {
        assert!(a < b, "pair not canonical: ({a}, {b})");
    }

    // Union accounting: the pair is a probe-only retrieval and survives the
    // filters (different agents, different papers).
    let blockers: Vec<Box<dyn Blocker>> =
        vec![Box::new(EmbeddingAnnBlocker::new(TOP_K)), Box::new(probe)];
    let (pairs, bs) = union_block_with_stats(
        &pool,
        &blockers,
        &[f.seed],
        test_config().filter,
        &test_config().eligibility,
    )
    .await
    .expect("union");
    assert!(pairs.contains(&want));
    assert!(bs.probe_only >= 1 && bs.probe_only_kept >= 1, "{bs:?}");
    assert!(bs.probe_only <= bs.probe_retrieved && bs.probe_retrieved <= bs.retrieved);
}

/// Pipeline level, the load-bearing test: with a probe embedder the
/// contradicting pair reaches the verifier; without one (the neighbourhood
/// blockers alone, i.e. the pre-a04248cf union) it does not.
#[sqlx::test(migrations = "../../migrations")]
async fn run_pipeline_routes_probe_found_contradiction_to_verifier(pool: PgPool) {
    let f = fixture(&pool).await;
    let want = canonical(f.seed, f.contra).unwrap();

    // Control: no probe embedder.
    let seen_without = Arc::new(Mutex::new(Vec::new()));
    let report = run_pipeline(
        &pool,
        RunInputs {
            seeds: vec![f.seed],
            cfg: test_config(),
            verifier: Box::new(RecordingVerifier {
                seen: seen_without.clone(),
            }),
            auto_promote: false,
            probe_embedder: None,
        },
    )
    .await
    .expect("pipeline without probes");
    assert!(!report.stance_probe_enabled);
    assert_eq!(report.probe_retrieved_pairs, 0);
    assert!(
        !seen_without.lock().unwrap().contains(&want),
        "fixture invalid: the neighbourhood blockers already reach C"
    );

    // With the probe stage.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let report = run_pipeline(
        &pool,
        RunInputs {
            seeds: vec![f.seed],
            cfg: test_config(),
            verifier: Box::new(RecordingVerifier { seen: seen.clone() }),
            auto_promote: false,
            probe_embedder: Some(Arc::new(LookupEmbedder::probes_for_seed())),
        },
    )
    .await
    .expect("pipeline with probes");
    assert!(
        seen.lock().unwrap().contains(&want),
        "the contradicting pair must reach the verifier, routed: {:?}",
        seen.lock().unwrap()
    );
    assert!(report.stance_probe_enabled);
    assert_eq!(report.stance_probe.seeds_probed, 1);
    assert_eq!(report.stance_probe.probe_texts, 2);
    assert!(report.probe_only_pairs >= 1, "{report:?}");
    assert!(report.probe_only_kept >= 1, "{report:?}");
    assert!(report.probe_only_routed >= 1, "{report:?}");
    assert!(report.probe_only_routed <= report.probe_only_kept);
    assert_eq!(
        report.retrieved_pairs,
        report.ineligible_dropped + report.same_source_dropped + report.scanned_pairs,
        "recall-stage invariant"
    );
}

/// An embedding failure aborts the run before anything is written, so the
/// caller does not stamp the seeds as scanned with no probe stage behind it.
#[sqlx::test(migrations = "../../migrations")]
async fn embedding_failure_aborts_before_any_write(pool: PgPool) {
    let f = fixture(&pool).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut embedder = LookupEmbedder::probes_for_seed();
    embedder.fail = true;
    let err = run_pipeline(
        &pool,
        RunInputs {
            seeds: vec![f.seed],
            cfg: test_config(),
            verifier: Box::new(RecordingVerifier { seen: seen.clone() }),
            auto_promote: true,
            probe_embedder: Some(Arc::new(embedder)),
        },
    )
    .await
    .expect_err("an embedding outage must fail the run");
    assert!(
        err.to_string().contains("stance probe embedding failed"),
        "{err}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "nothing may be verified after a failed probe stage"
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM match_candidates")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 0);
}

/// A probe vector whose dimension differs from the stored embeddings is
/// skipped rather than searched (pgvector refuses mixed dimensions), and a
/// seed with no stored embedding is not probed.
#[sqlx::test(migrations = "../../migrations")]
async fn dimension_mismatch_and_unembedded_seed_are_skipped(pool: PgPool) {
    let f = fixture(&pool).await;
    let agent = insert_agent(&pool).await;
    let unembedded = insert_claim(&pool, agent, "Compound K is toxic", "10.1/u", None).await;

    let mut embedder = LookupEmbedder::probes_for_seed();
    embedder.dim = 768;
    let (probe, stats) =
        StanceProbeBlocker::prepare(&pool, &embedder, &[f.seed, unembedded], TOP_K)
            .await
            .expect("a dimension mismatch is a skip, not an error");
    assert_eq!(
        stats,
        StanceProbeStats {
            seeds_probed: 0,
            probe_texts: 0,
            seeds_skipped: 2,
        }
    );
    let got = probe
        .candidates(&pool, &[f.seed, unembedded])
        .await
        .expect("no query errors");
    assert!(got.is_empty(), "{got:?}");
}

/// `probe_only_routed` counts only probe-only pairs that cleared `bands.mid`.
/// With the band above every fixture pair's score the probe still retrieves
/// and keeps the contradicting pair, but nothing is routed, so the report
/// shows "retrieved, then rejected on score" rather than a routed pair.
#[sqlx::test(migrations = "../../migrations")]
async fn probe_only_pair_below_mid_band_is_kept_but_not_routed(pool: PgPool) {
    let f = fixture(&pool).await;
    let mut cfg = test_config();
    cfg.bands.mid = 0.99;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let report = run_pipeline(
        &pool,
        RunInputs {
            seeds: vec![f.seed],
            cfg,
            verifier: Box::new(RecordingVerifier { seen: seen.clone() }),
            auto_promote: false,
            probe_embedder: Some(Arc::new(LookupEmbedder::probes_for_seed())),
        },
    )
    .await
    .expect("pipeline");
    assert!(report.probe_only_kept >= 1, "{report:?}");
    assert_eq!(
        report.probe_only_routed, 0,
        "a pair scored below bands.mid is not routed: {report:?}"
    );
    assert!(seen.lock().unwrap().is_empty());
    assert!(report.rejected >= report.probe_only_kept, "{report:?}");
}
