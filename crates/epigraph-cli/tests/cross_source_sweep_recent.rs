//! `cross_source_sweep --recent` (backlog efc1d318), driven through the two
//! library calls the binary makes in that mode (`select_recent_seeds`, then
//! `sweep_seeds`) on a `#[sqlx::test]` database migrated 001 -> head, with a
//! mock verifier in place of the reranker.
//!
//! What is pinned:
//!
//! * a fresh claim whose near neighbour is an older, already-scanned claim
//!   from another source is the ONLY seed the drain picks, and one drain pass
//!   writes a `contradicts` match candidate (and edge) for the pair and stamps
//!   the seed, so the next pass selects nothing;
//! * the selection keeps an unlabelled claim and a topic-labelled one
//!   (`daily-journal`, exact matching), and drops a `status` marker claim, a
//!   `telemetry` claim, a `journal-status` claim (a `STATUS_CLAIM_LABELS`
//!   entry), an already-stamped claim, a non-current claim and a claim older
//!   than the window; a wider window picks the older claim up; the cap takes
//!   the oldest first.

#![cfg(feature = "db")]

use async_trait::async_trait;
use epigraph_cli::cross_source_recent::{select_recent_seeds, sweep_seeds, SweepInputs};
use epigraph_engine::matching::calibration::MatcherConfig;
use epigraph_engine::matching::verifier::{Verdict, VerifierClient};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

const DAY: Duration = Duration::from_secs(86_400);

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

/// One claim row. `age` backdates `created_at`; `stamped` sets
/// `last_match_scan_at`; `embedding: None` leaves it NULL (required for a
/// non-current claim by migration 052's CHECK).
struct Claim<'a> {
    agent: Uuid,
    labels: &'a [&'a str],
    age: &'a str,
    stamped: bool,
    is_current: bool,
    paper_doi: &'a str,
    embedding: Option<f32>,
}

impl<'a> Claim<'a> {
    fn fresh(agent: Uuid) -> Self {
        Self {
            agent,
            labels: &[],
            age: "1 hour",
            stamped: false,
            is_current: true,
            paper_doi: "10.1/recent-default",
            embedding: None,
        }
    }
}

async fn insert_claim(pool: &PgPool, c: Claim<'_>) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {id}");
    let emb = c
        .embedding
        .map(|x| format!("[{}]", vec![x.to_string(); 1536].join(",")));
    let labels: Vec<String> = c.labels.iter().map(|s| (*s).to_string()).collect();
    sqlx::query(
        "INSERT INTO claims
           (id, content, content_hash, truth_value, agent_id, properties, embedding,
            labels, is_current, created_at, last_match_scan_at)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, $4, $5::vector,
                 $6, $7, now() - $8::interval,
                 CASE WHEN $9 THEN now() - INTERVAL '1 hour' END)",
    )
    .bind(id)
    .bind(&content)
    .bind(c.agent)
    .bind(serde_json::json!({ "paper_doi": c.paper_doi }))
    .bind(emb)
    .bind(&labels)
    .bind(c.is_current)
    .bind(c.age)
    .bind(c.stamped)
    .execute(pool)
    .await
    .expect("claim");
    id
}

/// Every pair is judged a contradiction.
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

/// The served calibration with the bands lowered so the single-feature 0.40
/// score of an identical-embedding cross-source pair lands in the mid band,
/// where the verifier decides (as in epigraph-engine's pipeline_end_to_end).
fn mid_band_config() -> MatcherConfig {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../calibration.toml");
    let mut cfg = MatcherConfig::load_from(&p).expect("load calibration.toml");
    cfg.bands.high = 0.50;
    cfg.bands.mid = 0.30;
    cfg
}

#[sqlx::test(migrations = "../../migrations")]
async fn recent_drain_finds_a_fresh_contradiction_then_stamps_it(pool: PgPool) {
    let old_agent = insert_agent(&pool).await;
    let new_agent = insert_agent(&pool).await;

    // An existing claim, scanned long ago and well outside the window.
    let peer = insert_claim(
        &pool,
        Claim {
            age: "30 days",
            stamped: true,
            paper_doi: "10.1/old-source",
            embedding: Some(1.0),
            ..Claim::fresh(old_agent)
        },
    )
    .await;
    // A just-written claim from another source, same neighbourhood.
    let fresh = insert_claim(
        &pool,
        Claim {
            paper_doi: "10.1/new-source",
            embedding: Some(1.0),
            ..Claim::fresh(new_agent)
        },
    )
    .await;

    let seeds = select_recent_seeds(&pool, DAY, 200).await.expect("select");
    assert_eq!(seeds, vec![fresh], "only the fresh, unscanned claim is due");

    let report = sweep_seeds(
        &pool,
        &seeds,
        SweepInputs {
            cfg: mid_band_config(),
            verifier: Box::new(AlwaysContradictsVerifier),
            auto_promote: true,
            probe_embedder: None,
            stamp: true,
        },
    )
    .await
    .expect("sweep");
    assert!(
        report.mid_band >= 1,
        "the pair reached the verifier: {report:?}"
    );

    let (lo, hi) = if fresh < peer {
        (fresh, peer)
    } else {
        (peer, fresh)
    };
    let verdict: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT verifier_verdict FROM match_candidates WHERE claim_a = $1 AND claim_b = $2",
    )
    .bind(lo)
    .bind(hi)
    .fetch_optional(&pool)
    .await
    .expect("candidate");
    assert_eq!(
        verdict.and_then(|v| v.0).as_deref(),
        Some("contradicts"),
        "one --recent pass must record the fresh contradiction as a match candidate"
    );
    let contradicts: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE relationship = 'contradicts'
           AND ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1))",
    )
    .bind(fresh)
    .bind(peer)
    .fetch_one(&pool)
    .await
    .expect("edge count");
    assert_eq!(contradicts.0, 1, "auto_promote wires the contradicts edge");

    let stamped: (bool,) =
        sqlx::query_as("SELECT last_match_scan_at IS NOT NULL FROM claims WHERE id = $1")
            .bind(fresh)
            .fetch_one(&pool)
            .await
            .expect("stamp");
    assert!(stamped.0, "the drained seed is stamped");
    let again = select_recent_seeds(&pool, DAY, 200).await.expect("select");
    assert!(again.is_empty(), "the next pass has nothing due: {again:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn recent_selection_skips_status_scanned_superseded_and_old_claims(pool: PgPool) {
    let a = insert_agent(&pool).await;

    let plain = insert_claim(
        &pool,
        Claim {
            age: "2 hours",
            ..Claim::fresh(a)
        },
    )
    .await;
    let topic = insert_claim(
        &pool,
        Claim {
            labels: &["daily-journal"],
            ..Claim::fresh(a)
        },
    )
    .await;
    let mut dropped = Vec::new();
    for labels in [
        &["status"][..],
        &["telemetry"],
        &["notes", "journal-status"],
    ] {
        dropped.push(
            insert_claim(
                &pool,
                Claim {
                    labels,
                    ..Claim::fresh(a)
                },
            )
            .await,
        );
    }
    dropped.push(
        insert_claim(
            &pool,
            Claim {
                stamped: true,
                ..Claim::fresh(a)
            },
        )
        .await,
    );
    dropped.push(
        insert_claim(
            &pool,
            Claim {
                is_current: false,
                ..Claim::fresh(a)
            },
        )
        .await,
    );
    let old = insert_claim(
        &pool,
        Claim {
            age: "2 days",
            ..Claim::fresh(a)
        },
    )
    .await;

    let seeds = select_recent_seeds(&pool, DAY, 200).await.expect("select");
    assert_eq!(
        seeds,
        vec![plain, topic],
        "kept: unlabelled and topic-labelled, oldest first; dropped: {dropped:?} and {old}"
    );

    let wide = select_recent_seeds(&pool, 3 * DAY, 200)
        .await
        .expect("select wide");
    assert_eq!(wide, vec![old, plain, topic], "the window is the caller's");

    let capped = select_recent_seeds(&pool, DAY, 1)
        .await
        .expect("select capped");
    assert_eq!(capped, vec![plain], "the cap takes the oldest first");
}
