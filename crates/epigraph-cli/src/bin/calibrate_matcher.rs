//! T21: SciFact-driven matcher calibration harness.
//!
//! Reads SciFact JSONL files (data/scifact/data/), constructs labelled
//! claim-pair sets, computes a per-claim embedding (OpenAI when
//! `OPENAI_API_KEY` is set, deterministic byte-bucket fallback otherwise),
//! sweeps `embed_cosine` thresholds, and writes a JSON report.
//!
//! Pair definitions:
//! - **positive**: two SciFact claims sharing identical evidence (same
//!   `doc_id` and matching `sentences` set with the same label) — they are
//!   saying the same thing about the same passage.
//! - **hard_neg**: two SciFact claims annotated against the same `doc_id`
//!   but with opposite labels (SUPPORT vs CONTRADICT) on overlapping
//!   sentences — same topic, opposite assertion.
//! - **easy_neg**: random sample of pairs with disjoint `cited_doc_ids`.
//!
//! Two precision/recall views are reported per threshold:
//! 1. **strict** — `tp / (tp + fp_total)`, treats every negative the same.
//!    For SciFact this caps low (~0.40) because embeddings cannot
//!    distinguish "supports X" from "contradicts X" — both restate the
//!    same fact. This is a fundamental property of the embedding feature,
//!    not a calibration weakness.
//! 2. **matched-pair** — counts positives + hard_negatives together as
//!    "should-be-surfaced-by-matcher" (the verifier disambiguates
//!    corroboration vs contradiction downstream) and only easy_negatives
//!    as true noise. This is the metric that maps to the spec's two-stage
//!    design.
//!
//! Embedding cache: OpenAI calls are cached to `--cache` (JSON, keyed by
//! SipHash of claim text) so re-runs after code changes don't re-pay the
//! API.
//!
//! Scope: SciFact has no structured triples, no method tags, and no
//! theme-cluster membership, so the matcher's other features
//! (triple_overlap, entity_jaccard, method_match, nbhd_overlap,
//! citation_overlap) are all uniformly 0 here. We calibrate `embed_cosine`
//! directly; composite-score bands in calibration.toml need a richer
//! corpus that exercises the other features.

use clap::{Parser, ValueEnum};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, OpenAiProvider};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter};
use std::path::{Path, PathBuf};

const MOCK_DIM: usize = 1536;

fn native_dim(model: &str) -> usize {
    match model {
        "text-embedding-3-small" => 1536,
        "text-embedding-3-large" => 3072,
        "text-embedding-ada-002" => 1536,
        _ => 1536, // unknown — let the API tell us; we validate after fetch
    }
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum EmbeddingMode {
    /// Deterministic byte-bucket + trigram-hash. No external calls.
    Mock,
    /// OpenAI `text-embedding-3-small` (1536 dims). Requires `OPENAI_API_KEY`.
    Openai,
    /// Auto: OpenAI if `OPENAI_API_KEY` is set, otherwise mock.
    Auto,
}

// ── SciFact record types ───────────────────────────────────────────────────

#[derive(Deserialize)]
struct EvidenceEntry {
    sentences: Vec<usize>,
    label: String, // SUPPORT, CONTRADICT, NEI
}

#[derive(Deserialize)]
struct ClaimRow {
    id: u64,
    claim: String,
    #[serde(default)]
    evidence: HashMap<String, Vec<EvidenceEntry>>,
    #[serde(default)]
    cited_doc_ids: Vec<u64>,
}

// ── Pair set ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Positive,
    HardNegative,
    EasyNegative,
}

struct Pair {
    a: u64,
    b: u64,
    bucket: Bucket,
}

/// Per-pair signal bundle. Each pair is scored on multiple features so the
/// report can compare them — cosine-only, AA-only, theme-only, and combined.
struct PairScore {
    bucket:   Bucket,
    cosine:   f32,
    /// Raw Adamic-Adar sum (unbounded; reported for distribution sanity).
    aa_raw:   f32,
    /// tanh-normalized AA in (0, 1).
    aa_norm:  f32,
    /// 1.0 if the two claims fall in the same k-means cluster on their
    /// embeddings, 0.0 otherwise. SciFact has no native theme attribute, so
    /// the clustering is derived (auto-correlated with cosine to some
    /// degree). The test question: does discretized clustering carry signal
    /// beyond raw cosine + AA?
    theme:    f32,
    /// (cosine + aa_norm) / 2 — original two-feature combine.
    combined: f32,
    /// (cosine + aa_norm + theme) / 3 — three-feature combine.
    combined3: f32,
}

// ── Args ───────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "calibrate_matcher",
    about = "Sweep matcher thresholds against SciFact and emit a JSON report"
)]
struct Args {
    /// Path to SciFact data dir containing claims_*.jsonl + corpus.jsonl.
    #[arg(long, default_value = "data/scifact/data")]
    data_dir: PathBuf,

    /// Output JSON report path.
    #[arg(long, default_value = "data/scifact/calibration_report.json")]
    output: PathBuf,

    /// Maximum easy-negative pairs to sample. Easy negatives dominate the
    /// pool otherwise (O(n²)) — capping keeps the precision/recall math
    /// stable and the report readable.
    #[arg(long, default_value_t = 2000)]
    easy_neg_count: usize,

    /// Random seed for easy-negative sampling — deterministic by default
    /// so multiple runs over the same corpus produce identical reports.
    #[arg(long, default_value_t = 0xC401_1B2A_2EAD)]
    seed: u64,

    /// Embedding source. `auto` picks OpenAI when `OPENAI_API_KEY` is set.
    #[arg(long, value_enum, default_value_t = EmbeddingMode::Auto)]
    embeddings: EmbeddingMode,

    /// OpenAI model identifier. Common values: `text-embedding-3-small`
    /// (1536 dim, default), `text-embedding-3-large` (3072 dim).
    #[arg(long, default_value = "text-embedding-3-small")]
    openai_model: String,

    /// On-disk cache for OpenAI embeddings (text-hash → vector, JSON). One
    /// cache file per model — the default below interpolates `--openai-model`
    /// to keep vectors of different dimensions from colliding.
    #[arg(long)]
    cache: Option<PathBuf>,

    /// k-means cluster count for the derived "theme" feature. ~sqrt(n) by
    /// rule of thumb; for SciFact's ~1400 claims, 37 is a reasonable start.
    #[arg(long, default_value_t = 40)]
    theme_k: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let claims = load_claims(&args.data_dir)?;
    eprintln!("Loaded {} SciFact claims", claims.len());

    let pairs = build_pairs(&claims, args.easy_neg_count, args.seed);
    let mut bucket_counts = BTreeMap::new();
    for p in &pairs {
        *bucket_counts
            .entry(format!("{:?}", p.bucket))
            .or_insert(0usize) += 1;
    }
    eprintln!("Pair distribution: {bucket_counts:?}");

    let referenced: BTreeSet<u64> = pairs.iter().flat_map(|p| [p.a, p.b]).collect();
    let mode = resolve_embedding_mode(args.embeddings);
    eprintln!(
        "Embedding mode: {mode:?}  ({} unique claims)",
        referenced.len()
    );
    let cache_path = args.cache.clone().unwrap_or_else(|| {
        // Default cache path interpolates the model name so small/large
        // vectors stay in separate files.
        PathBuf::from(format!(
            "data/scifact/openai_embeddings_cache.{}.json",
            args.openai_model
        ))
    });
    let embeddings: HashMap<u64, Vec<f32>> = match mode {
        EmbeddingMode::Mock => referenced
            .iter()
            .map(|id| (*id, mock_embedding(&claims[id].claim)))
            .collect(),
        EmbeddingMode::Openai | EmbeddingMode::Auto => {
            openai_embeddings(&claims, &referenced, &args.openai_model, &cache_path).await?
        }
    };

    // Document degree map for Adamic-Adar: how many claims cite each doc.
    // This is the bipartite-graph degree on the doc side; AA(a,b) sums
    // 1/ln(deg(d)) over docs cited by both a and b. Niche docs (low deg)
    // contribute more — Tom-Cruise-shared-movie style.
    let mut doc_degree: HashMap<u64, usize> = HashMap::new();
    for row in claims.values() {
        for doc in &row.cited_doc_ids {
            *doc_degree.entry(*doc).or_insert(0) += 1;
        }
    }
    let doc_count = doc_degree.len();
    eprintln!(
        "Cited-doc degree map: {doc_count} unique docs, median citation count = {}",
        median(&doc_degree.values().map(|&v| v as f64).collect::<Vec<_>>())
    );

    // Derive synthetic "themes" via k-means on the embeddings so we can
    // probe whether discretized clustering carries any signal beyond raw
    // cosine + AA. K is chosen as ~sqrt(n_claims) — a common heuristic.
    let cluster_of = kmeans_clusters(&embeddings, args.theme_k);
    let theme_for = |id: u64| cluster_of.get(&id).copied().unwrap_or(usize::MAX);

    // Score each pair on four signals.
    let scored: Vec<PairScore> = pairs
        .iter()
        .map(|p| {
            let cosine_score = cosine(&embeddings[&p.a], &embeddings[&p.b]);
            let aa_raw = adamic_adar(&claims[&p.a], &claims[&p.b], &doc_degree);
            let aa_norm = aa_raw.tanh();
            let theme = if theme_for(p.a) != usize::MAX && theme_for(p.a) == theme_for(p.b) {
                1.0
            } else {
                0.0
            };
            let combined = (cosine_score + aa_norm as f32) / 2.0;
            let combined3 = (cosine_score + aa_norm as f32 + theme) / 3.0;
            PairScore {
                bucket: p.bucket,
                cosine: cosine_score,
                aa_raw: aa_raw as f32,
                aa_norm: aa_norm as f32,
                theme,
                combined,
                combined3,
            }
        })
        .collect();

    // Per-bucket AA distribution — sanity check that AA actually discriminates.
    let mut aa_buckets: BTreeMap<String, Vec<f32>> = BTreeMap::new();
    for s in &scored {
        aa_buckets
            .entry(format!("{:?}", s.bucket))
            .or_default()
            .push(s.aa_raw);
    }
    for (b, vs) in &aa_buckets {
        let n = vs.len();
        let mean: f32 = vs.iter().sum::<f32>() / n as f32;
        let max = vs.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let nonzero = vs.iter().filter(|&&v| v > 0.0).count();
        eprintln!(
            "AA distribution {b}: n={n} mean={mean:.3} max={max:.3} nonzero={nonzero}"
        );
    }

    // Per-bucket theme stats — does same-cluster discriminate?
    let mut theme_hits: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for s in &scored {
        let e = theme_hits.entry(format!("{:?}", s.bucket)).or_insert((0, 0));
        e.1 += 1;
        if s.theme > 0.5 {
            e.0 += 1;
        }
    }
    for (b, (hits, n)) in &theme_hits {
        let pct = (*hits as f32) * 100.0 / (*n as f32);
        eprintln!("Theme (k={}) {b}: {hits}/{n} same-cluster ({pct:.1}%)", args.theme_k);
    }

    // Threshold sweep on each signal independently.
    // Sweep 0.30-0.99 — extended down so we can compare the engine's
    // bands.mid (typically 0.40) operating point against the SciFact P/R
    // curve directly.
    let thresholds: Vec<f32> = (30..=99).map(|i| i as f32 / 100.0).collect();
    let metrics_cosine: Vec<ThresholdMetric> = thresholds
        .iter()
        .map(|&t| metric_at(&scored, t, |s| s.cosine))
        .collect();
    let metrics_aa: Vec<ThresholdMetric> = thresholds
        .iter()
        .map(|&t| metric_at(&scored, t, |s| s.aa_norm))
        .collect();
    let metrics_combined: Vec<ThresholdMetric> = thresholds
        .iter()
        .map(|&t| metric_at(&scored, t, |s| s.combined))
        .collect();
    let metrics_combined3: Vec<ThresholdMetric> = thresholds
        .iter()
        .map(|&t| metric_at(&scored, t, |s| s.combined3))
        .collect();

    let recommendation = recommend_high_threshold(&metrics_combined3);

    let report = Report {
        seed: args.seed,
        embedding_mode: format!("{mode:?}"),
        theme_k: args.theme_k,
        claim_count: claims.len(),
        pair_distribution: bucket_counts,
        metrics: metrics_combined3.clone(),
        metrics_cosine: Some(metrics_cosine),
        metrics_aa: Some(metrics_aa),
        metrics_combined_2: Some(metrics_combined),
        recommendation,
    };

    let out = BufWriter::new(File::create(&args.output)?);
    serde_json::to_writer_pretty(out, &report)?;
    eprintln!("Wrote calibration report to {}", args.output.display());

    // Stdout summary for shell consumption.
    println!("{}", serde_json::to_string(&report.recommendation)?);
    Ok(())
}

/// K-means clusters of claim embeddings, returning claim_id → cluster_id.
/// Used to derive a synthetic "theme" feature for the harness — see the
/// PairScore::theme doc comment. SciFact has no native theme attribute, so
/// the clusters are auto-correlated with cosine; the question is whether
/// discretizing carries signal beyond raw cosine.
fn kmeans_clusters(embeddings: &HashMap<u64, Vec<f32>>, k: usize) -> HashMap<u64, usize> {
    use linfa::prelude::*;
    use linfa_clustering::KMeans;
    use ndarray::Array2;

    if embeddings.is_empty() || k < 2 {
        return HashMap::new();
    }
    let ids: Vec<u64> = {
        let mut v: Vec<u64> = embeddings.keys().copied().collect();
        v.sort_unstable();
        v
    };
    let dim = embeddings[&ids[0]].len();
    let mut data = Array2::<f64>::zeros((ids.len(), dim));
    for (i, id) in ids.iter().enumerate() {
        for (j, &v) in embeddings[id].iter().enumerate() {
            data[[i, j]] = f64::from(v);
        }
    }
    let dataset = linfa::DatasetBase::from(data.view());
    let model = match KMeans::params(k)
        .max_n_iterations(50)
        .tolerance(1e-3)
        .fit(&dataset)
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("kmeans fit failed: {e:?} — themes disabled");
            return HashMap::new();
        }
    };
    let labels: Vec<usize> = model.predict(&dataset).iter().copied().collect();
    ids.into_iter().zip(labels).collect()
}

/// Adamic-Adar over the (claim → cited_doc) bipartite graph.
/// Two claims share a "neighbor" iff they cite the same doc; rare docs
/// (cited by few claims) carry more weight via 1/ln(degree).
fn adamic_adar(a: &ClaimRow, b: &ClaimRow, doc_degree: &HashMap<u64, usize>) -> f64 {
    let aset: std::collections::HashSet<u64> = a.cited_doc_ids.iter().copied().collect();
    let mut score = 0.0;
    for doc in &b.cited_doc_ids {
        if !aset.contains(doc) {
            continue;
        }
        // Degree 1 means only one of (a, b) cites it — but since we're
        // iterating common neighbors, deg ≥ 2 always. Cap ln to avoid
        // ln(2) → tiny denominator when both claims share an exclusive doc.
        let deg = *doc_degree.get(doc).unwrap_or(&2);
        let denom = (deg as f64).ln().max(0.5);
        score += 1.0 / denom;
    }
    score
}

fn median(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

// ── Data loading ───────────────────────────────────────────────────────────

fn load_claims(dir: &std::path::Path) -> anyhow::Result<HashMap<u64, ClaimRow>> {
    let mut out = HashMap::new();
    for name in [
        "claims_train.jsonl",
        "claims_dev.jsonl",
        "claims_test.jsonl",
    ] {
        let path = dir.join(name);
        let file = File::open(&path)
            .map_err(|e| anyhow::anyhow!("failed to open {}: {e}", path.display()))?;
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let row: ClaimRow = serde_json::from_str(&line)?;
            out.insert(row.id, row);
        }
    }
    Ok(out)
}

// ── Pair construction ──────────────────────────────────────────────────────

fn build_pairs(claims: &HashMap<u64, ClaimRow>, easy_neg_count: usize, seed: u64) -> Vec<Pair> {
    let mut pairs: Vec<Pair> = Vec::new();

    // Index claims by (doc_id, sentence_set, label) for positive pairs.
    let mut by_evidence: HashMap<(String, Vec<usize>, String), Vec<u64>> = HashMap::new();
    // Index claims by doc_id with their labels for hard-negative pairs.
    let mut by_doc_label: HashMap<String, Vec<(u64, String, Vec<usize>)>> = HashMap::new();

    for (id, row) in claims {
        for (doc_id, entries) in &row.evidence {
            for entry in entries {
                let mut sents = entry.sentences.clone();
                sents.sort_unstable();
                by_evidence
                    .entry((doc_id.clone(), sents.clone(), entry.label.clone()))
                    .or_default()
                    .push(*id);
                by_doc_label.entry(doc_id.clone()).or_default().push((
                    *id,
                    entry.label.clone(),
                    sents,
                ));
            }
        }
    }

    // Positives: identical (doc, sentences, label) — same exact verified claim.
    for ids in by_evidence.values() {
        if ids.len() < 2 {
            continue;
        }
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                let (a, b) = canonical(ids[i], ids[j]);
                pairs.push(Pair {
                    a,
                    b,
                    bucket: Bucket::Positive,
                });
            }
        }
    }

    // Hard negatives: same doc, opposite labels on overlapping sentences.
    let mut hard_seen: BTreeSet<(u64, u64)> = BTreeSet::new();
    for entries in by_doc_label.values() {
        for i in 0..entries.len() {
            for j in (i + 1)..entries.len() {
                let (id1, lab1, s1) = &entries[i];
                let (id2, lab2, s2) = &entries[j];
                if lab1 == lab2 {
                    continue;
                }
                let overlap = s1.iter().any(|x| s2.contains(x));
                if !overlap {
                    continue;
                }
                let (a, b) = canonical(*id1, *id2);
                if hard_seen.insert((a, b)) {
                    pairs.push(Pair {
                        a,
                        b,
                        bucket: Bucket::HardNegative,
                    });
                }
            }
        }
    }

    // Easy negatives: random pairs with disjoint cited_doc_ids.
    let ids: Vec<u64> = {
        let mut v: Vec<u64> = claims.keys().copied().collect();
        v.sort_unstable();
        v
    };
    let mut rng = SplitMix64::new(seed);
    let mut easy_seen: BTreeSet<(u64, u64)> = BTreeSet::new();
    let mut attempts = 0usize;
    let max_attempts = easy_neg_count * 50;
    while easy_seen.len() < easy_neg_count && attempts < max_attempts {
        attempts += 1;
        let i = rng.next_u64() as usize % ids.len();
        let j = rng.next_u64() as usize % ids.len();
        if i == j {
            continue;
        }
        let id_a = ids[i];
        let id_b = ids[j];
        let cited_a: BTreeSet<u64> = claims[&id_a].cited_doc_ids.iter().copied().collect();
        let cited_b: BTreeSet<u64> = claims[&id_b].cited_doc_ids.iter().copied().collect();
        if cited_a.intersection(&cited_b).next().is_some() {
            continue;
        }
        let (a, b) = canonical(id_a, id_b);
        if easy_seen.insert((a, b)) {
            pairs.push(Pair {
                a,
                b,
                bucket: Bucket::EasyNegative,
            });
        }
    }

    pairs
}

fn canonical(a: u64, b: u64) -> (u64, u64) {
    if a < b {
        (a, b)
    } else {
        (b, a)
    }
}

// ── Embedding mode resolution + OpenAI batch path ──────────────────────────

fn resolve_embedding_mode(req: EmbeddingMode) -> EmbeddingMode {
    match req {
        EmbeddingMode::Auto => {
            if std::env::var("OPENAI_API_KEY").is_ok() {
                EmbeddingMode::Openai
            } else {
                EmbeddingMode::Mock
            }
        }
        other => other,
    }
}

#[derive(Deserialize, Serialize, Default)]
struct EmbeddingCache {
    /// Hash of claim text -> vector. Hashing the text rather than keying on
    /// claim_id lets us invalidate entries automatically if SciFact updates
    /// a claim's wording (since the embedding would then be stale).
    by_text_hash: BTreeMap<String, Vec<f32>>,
}

fn text_hash(text: &str) -> String {
    // SipHash via DefaultHasher is good enough for cache invalidation —
    // collisions across the 1409 SciFact claims are vanishingly unlikely
    // and the failure mode (cache miss) is benign.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    text.hash(&mut h);
    format!("{:016x}", h.finish())
}

async fn openai_embeddings(
    claims: &HashMap<u64, ClaimRow>,
    referenced: &BTreeSet<u64>,
    model: &str,
    cache_path: &Path,
) -> anyhow::Result<HashMap<u64, Vec<f32>>> {
    let dim = native_dim(model);
    eprintln!("OpenAI model: {model} (native dim {dim}, cache {})", cache_path.display());
    let mut cache: EmbeddingCache = if cache_path.exists() {
        let file = File::open(cache_path)?;
        serde_json::from_reader(BufReader::new(file)).unwrap_or_default()
    } else {
        if let Some(parent) = cache_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        EmbeddingCache::default()
    };

    // Plan the work: which texts need fresh embeddings?
    let mut id_to_text: HashMap<u64, String> = HashMap::new();
    let mut id_to_hash: HashMap<u64, String> = HashMap::new();
    let mut needed: Vec<(u64, String)> = Vec::new(); // (id, text)
    for id in referenced {
        let text = claims[id].claim.clone();
        let hash = text_hash(&text);
        id_to_hash.insert(*id, hash.clone());
        id_to_text.insert(*id, text.clone());
        if !cache.by_text_hash.contains_key(&hash) {
            needed.push((*id, text));
        }
    }
    let prefilled = referenced.len() - needed.len();
    eprintln!(
        "Cache: {prefilled}/{} hit, {} need fresh embeddings",
        referenced.len(),
        needed.len()
    );

    if !needed.is_empty() {
        let api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| anyhow::anyhow!("OPENAI_API_KEY not set"))?;
        let mut config = EmbeddingConfig::openai(dim);
        // Override the default model on the provider config.
        if let epigraph_embeddings::config::ProviderConfig::OpenAi {
            model: ref mut current,
            ..
        } = config.provider
        {
            *current = model.to_string();
        }
        let provider = OpenAiProvider::new(config, api_key)
            .map_err(|e| anyhow::anyhow!("OpenAiProvider construction failed: {e}"))?;

        // Batch sized well under the 2048 hard cap to keep request bodies
        // reasonable. text-embedding-3-small charges per token, not per call,
        // so batch size is purely about latency + payload limits.
        const BATCH: usize = 256;
        let mut sent_total = 0usize;
        for chunk in needed.chunks(BATCH) {
            let texts: Vec<&str> = chunk.iter().map(|(_, t)| t.as_str()).collect();
            let vectors = provider
                .batch_generate(&texts)
                .await
                .map_err(|e| anyhow::anyhow!("batch_generate failed: {e}"))?;
            if vectors.len() != chunk.len() {
                anyhow::bail!(
                    "OpenAI returned {} vectors for {} texts",
                    vectors.len(),
                    chunk.len()
                );
            }
            for ((id, _), vec) in chunk.iter().zip(vectors) {
                let hash = id_to_hash[id].clone();
                cache.by_text_hash.insert(hash, vec);
            }
            sent_total += chunk.len();
            eprintln!("  {} / {} embedded", sent_total, needed.len());
        }

        // Flush cache to disk so re-runs don't re-pay.
        let out = BufWriter::new(File::create(cache_path)?);
        serde_json::to_writer(out, &cache)?;
        eprintln!("Updated cache: {}", cache_path.display());
    }

    // Final assembly.
    let mut out = HashMap::with_capacity(referenced.len());
    for id in referenced {
        let hash = &id_to_hash[id];
        let vec = cache
            .by_text_hash
            .get(hash)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing embedding for claim {id} after fetch"))?;
        if vec.len() != dim {
            anyhow::bail!(
                "claim {id}: expected {dim}-dim vector for {model}, got {}",
                vec.len()
            );
        }
        out.insert(*id, vec);
    }
    Ok(out)
}

// ── Mock embedding (deterministic, byte-bucket sum + L2 normalize) ─────────

fn mock_embedding(text: &str) -> Vec<f32> {
    let mut v = vec![0f32; MOCK_DIM];
    for (i, b) in text.as_bytes().iter().enumerate() {
        let idx = i % MOCK_DIM;
        v[idx] += f32::from(*b) / 255.0;
    }
    // Token-level shingle bonus so paraphrases that share substrings end up
    // closer than disjoint strings. Tiny weight to avoid swamping the byte
    // signal.
    for window in text.as_bytes().windows(3) {
        let hash = window.iter().fold(0u32, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(u32::from(*b))
        });
        let idx = (hash as usize) % MOCK_DIM;
        v[idx] += 0.25;
    }
    let mag: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if mag > 0.0 {
        for x in &mut v {
            *x /= mag;
        }
    }
    v
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

// ── Metrics ────────────────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
struct ThresholdMetric {
    threshold: f32,
    /// True positives at this threshold (positive pairs with sim ≥ t).
    tp: usize,
    /// False positives (negatives with sim ≥ t — both hard + easy).
    fp: usize,
    /// False negatives (positives with sim < t).
    r#fn: usize,
    precision: f32,
    recall: f32,
    f1: f32,
    /// Precision counting only hard negatives as "negative" — the more
    /// pessimistic signal, since random easy negatives can be discarded by
    /// even weak embeddings.
    hard_precision: f32,
    /// "Matched-pair" precision: treats `positive` + `hard_negative` together
    /// as "should-be-surfaced-by-matcher" and only `easy_negative` as the
    /// true noise. This is the metric that maps to the spec's two-stage
    /// design — scorer surfaces candidates, verifier disambiguates
    /// corroboration from contradiction. High `match_precision` means the
    /// embedding feature is fit-for-purpose as a candidate generator even
    /// when it can't auto-promote on its own.
    match_precision: f32,
    /// Matched-pair recall: (positives + hard_negs crossed) / (positives + hard_negs).
    match_recall: f32,
    match_f1: f32,
}

fn metric_at(scored: &[PairScore], t: f32, select: impl Fn(&PairScore) -> f32) -> ThresholdMetric {
    let mut tp = 0usize;
    let mut fp_total = 0usize;
    let mut fp_hard = 0usize;
    let mut fp_easy = 0usize;
    let mut fn_count = 0usize;
    let mut total_pos = 0usize;
    let mut total_hard = 0usize;
    for p in scored {
        let s = select(p);
        match p.bucket {
            Bucket::Positive => {
                total_pos += 1;
                if s >= t {
                    tp += 1;
                } else {
                    fn_count += 1;
                }
            }
            Bucket::HardNegative => {
                total_hard += 1;
                if s >= t {
                    fp_total += 1;
                    fp_hard += 1;
                }
            }
            Bucket::EasyNegative => {
                if s >= t {
                    fp_total += 1;
                    fp_easy += 1;
                }
            }
        }
    }

    let precision = safe_div(tp as f32, (tp + fp_total) as f32);
    let recall = safe_div(tp as f32, total_pos as f32);
    let f1 = safe_div(2.0 * precision * recall, precision + recall);
    let hard_precision = safe_div(tp as f32, (tp + fp_hard) as f32);

    // Matched-pair view: positive + hard_neg both count as "detected by
    // matcher" (both are real same-topic pairs the matcher should surface
    // for the verifier). Only easy negatives are true noise.
    let matched_detected = tp + fp_hard;
    let match_precision = safe_div(matched_detected as f32, (matched_detected + fp_easy) as f32);
    let match_recall = safe_div(matched_detected as f32, (total_pos + total_hard) as f32);
    let match_f1 = safe_div(
        2.0 * match_precision * match_recall,
        match_precision + match_recall,
    );

    ThresholdMetric {
        threshold: t,
        tp,
        fp: fp_total,
        r#fn: fn_count,
        precision,
        recall,
        f1,
        hard_precision,
        match_precision,
        match_recall,
        match_f1,
    }
}

fn safe_div(n: f32, d: f32) -> f32 {
    if d == 0.0 {
        0.0
    } else {
        n / d
    }
}

#[derive(Serialize)]
struct Recommendation {
    /// Lowest threshold whose strict precision (positives only) ≥ 0.95 —
    /// the threshold safe to auto-promote without a verifier. Often `None`
    /// because embeddings can't distinguish stance.
    high_band_strict: Option<RecommendedThreshold>,
    /// Lowest threshold whose **match_precision** (positives + hard_negs
    /// vs easy_neg noise) ≥ 0.95 — the threshold safe to use as a
    /// matcher candidate generator that hands stance decisions to the
    /// verifier. This is usually the operationally useful number.
    high_band_match: Option<RecommendedThreshold>,
    /// Lowest threshold whose F1 is within 0.02 of the max — the operating
    /// point for the mid band, where the verifier disambiguates.
    mid_band: Option<RecommendedThreshold>,
    /// Threshold maximizing F1 outright (informational, strict precision).
    max_f1: Option<RecommendedThreshold>,
    /// Threshold maximizing matched-pair F1 (informational).
    max_match_f1: Option<RecommendedThreshold>,
}

#[derive(Serialize, Clone)]
struct RecommendedThreshold {
    threshold: f32,
    precision: f32,
    recall: f32,
    f1: f32,
    match_precision: f32,
    match_recall: f32,
    match_f1: f32,
}

fn recommend_high_threshold(metrics: &[ThresholdMetric]) -> Recommendation {
    let high_band_strict = metrics.iter().find(|m| m.precision >= 0.95).map(snapshot);
    let high_band_match = metrics
        .iter()
        .find(|m| m.match_precision >= 0.95)
        .map(snapshot);

    let max_f1_m = metrics
        .iter()
        .max_by(|a, b| a.f1.partial_cmp(&b.f1).unwrap_or(std::cmp::Ordering::Equal));
    let max_f1 = max_f1_m.map(snapshot);

    let max_match_f1_m = metrics.iter().max_by(|a, b| {
        a.match_f1
            .partial_cmp(&b.match_f1)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let max_match_f1 = max_match_f1_m.map(snapshot);

    let mid_band = if let Some(top) = max_f1_m {
        metrics
            .iter()
            .find(|m| (top.f1 - m.f1).abs() <= 0.02)
            .map(snapshot)
    } else {
        None
    };
    Recommendation {
        high_band_strict,
        high_band_match,
        mid_band,
        max_f1,
        max_match_f1,
    }
}

fn snapshot(m: &ThresholdMetric) -> RecommendedThreshold {
    RecommendedThreshold {
        threshold: m.threshold,
        precision: m.precision,
        recall: m.recall,
        f1: m.f1,
        match_precision: m.match_precision,
        match_recall: m.match_recall,
        match_f1: m.match_f1,
    }
}

#[derive(Serialize)]
struct Report {
    seed: u64,
    embedding_mode: String,
    theme_k: usize,
    claim_count: usize,
    pair_distribution: BTreeMap<String, usize>,
    /// Threshold sweep on cosine + AA + theme (primary).
    metrics: Vec<ThresholdMetric>,
    /// Sweep on cosine-only (baseline comparator).
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics_cosine: Option<Vec<ThresholdMetric>>,
    /// Sweep on AA-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics_aa: Option<Vec<ThresholdMetric>>,
    /// Sweep on cosine + AA (two-feature combine, pre-theme baseline).
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics_combined_2: Option<Vec<ThresholdMetric>>,
    recommendation: Recommendation,
}

// ── Tiny deterministic RNG (SplitMix64) ────────────────────────────────────
// Avoids the heavier rand_chacha dep just to seed easy-negative sampling.

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self {
            state: seed.wrapping_add(0x9E37_79B9_7F4A_7C15),
        }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}
