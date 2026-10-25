//! The MCP DS write folds honour the frame tier of the belief profile, so the
//! cache they leave is the value the recompute and the framed read reproduce.
//!
//! `auto_wire_ds_update` and `auto_wire_ds_for_claim` write the served cache
//! at submit/update time on `binary_truth`. A `belief_profile` object on that
//! frame (`frames.properties`) must reach both folds exactly as it reaches
//! `edge_factor::compute_combined_belief` (the recompute) and
//! `belief_query::get_belief` (the framed read).
//!
//! `binary_truth` is one frame per database, so the twin without the override
//! runs FIRST, then the override is set on the frame, then the same writes run
//! on fresh claims. For each write:
//! - the cache it wrote equals, bit for bit, the non-writing recompute preview
//!   and the framed read over the same rows;
//! - its Bel is the independent closed form for simple supports on TRUE under
//!   the parameters in force (served weights for the twin, the override's for
//!   the overridden claims), so the overridden write differs from the twin.
//!
//! The DS write folds write no classification; the classifier half of the
//! frame tier is checked on the recompute's own verdict
//! (`preview_claim_belief_on_frame`), which flips under the overridden
//! `nei_threshold`.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::MassFunctionRepository;
use epigraph_engine::belief_profile::BeliefProfile;
use epigraph_engine::belief_query::get_belief;
use epigraph_engine::edge_factor::preview_claim_belief_on_frame;
use epigraph_mcp::tools::ds_auto::{
    auto_wire_ds_for_claim, auto_wire_ds_update, ensure_binary_frame, DsAutoInput, DsAutoResult,
};
use sqlx::PgPool;
use uuid::Uuid;

/// The frame override: the intra locality factor (reaches the update fold's
/// intra row), the `logical` weight (reaches both folds' own rows), and the
/// classifier's NEI threshold.
const INTRA: f64 = 0.9;
const LOGICAL: f64 = 0.2;
const NEI: f64 = 0.1;

/// The intra-source row seeded before the update: m(TRUE).
const INTRA_MASS: f64 = 0.6;
/// The writers' own evidence: m(TRUE) = confidence × weight.
const CONFIDENCE: f64 = 0.5;

/// Parameters in force for one run.
struct Params {
    intra: f64,
    logical: f64,
}

impl Params {
    fn served() -> Self {
        let p = BeliefProfile::served();
        Self {
            intra: p.reliability.intra_evidence_locality_factor,
            logical: p.evidence_type_weight("logical"),
        }
    }
    fn overridden() -> Self {
        Self {
            intra: INTRA,
            logical: LOGICAL,
        }
    }
    /// α of the writer's own `logical` row (locality `unknown` → cross).
    fn alpha_writer(&self) -> f64 {
        self.logical * BeliefProfile::served().reliability.cross_locality_factor
    }
    /// α of the seeded `empirical` / `intra_self_cite` row.
    fn alpha_intra(&self) -> f64 {
        BeliefProfile::served().evidence_type_weight("empirical") * self.intra
    }
}

fn assert_close(got: f64, want: f64, what: &str) {
    assert!((got - want).abs() < 1e-12, "{what}: got {got}, want {want}");
}

async fn cached(pool: &PgPool, claim_id: Uuid) -> [f64; 3] {
    let (b, pl, p): (Option<f64>, Option<f64>, Option<f64>) =
        sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
            .bind(claim_id)
            .fetch_one(pool)
            .await
            .expect("cache read");
    [
        b.expect("belief cached"),
        pl.expect("plausibility cached"),
        p.expect("pignistic_prob cached"),
    ]
}

fn bits(v: [f64; 3]) -> [u64; 3] {
    v.map(f64::to_bits)
}

/// The write's cache equals the recompute preview and the framed read, bit
/// for bit; returns the cache and the recompute's classification.
async fn cache_agrees(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    frame_id: Uuid,
    claim_id: Uuid,
    res: &DsAutoResult,
    what: &str,
) -> ([f64; 3], Option<String>) {
    assert!(res.cache_written, "{what}: the writer must write the cache");
    let cache = cached(pool, claim_id).await;
    assert_eq!(
        bits(cache),
        bits([res.belief, res.plausibility, res.pignistic_prob]),
        "{what}: the cache is what the writer returned"
    );
    let mut conn = pool.acquire().await.expect("acquire");
    let preview = preview_claim_belief_on_frame(&mut conn, viewer, claim_id, frame_id)
        .await
        .expect("preview")
        .expect("BBAs exist");
    drop(conn);
    assert_eq!(
        bits(cache),
        bits([preview.belief, preview.plausibility, preview.pignistic_prob]),
        "{what}: the write and the recompute must fold under the same frame tier"
    );
    let framed = get_belief(pool, viewer, claim_id, Some(frame_id))
        .await
        .expect("framed read");
    assert_eq!(
        bits(cache),
        bits([framed.belief, framed.plausibility, framed.pignistic_prob]),
        "{what}: the write and the framed read must fold under the same frame tier"
    );
    (cache, preview.classification)
}

/// One `auto_wire_ds_update` over a claim that already carries an
/// intra-source empirical row from another writer.
async fn update_run(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    frame_id: Uuid,
    label: &str,
) -> (Uuid, DsAutoResult) {
    let claim_id = seed_claim(pool, &format!("frame tier, update path, {label}"), 0.5).await;
    let mut conn = pool.acquire().await.expect("acquire");
    MassFunctionRepository::store_with_perspective(
        &mut *conn,
        claim_id,
        frame_id,
        Some(seed_agent(pool).await),
        None,
        &serde_json::json!({ "0": INTRA_MASS, "0,1": 1.0 - INTRA_MASS }),
        None,
        None,
        None,
        Some("empirical"),
        "intra_self_cite",
        None,
    )
    .await
    .expect("store the intra-source row");
    let res = auto_wire_ds_update(
        &mut conn,
        viewer,
        claim_id,
        seed_agent(pool).await,
        CONFIDENCE,
        1.0,
        true,
        Some("logical"),
        None,
        false,
    )
    .await
    .expect("auto_wire_ds_update");
    (claim_id, res)
}

/// One `auto_wire_ds_for_claim` on a fresh claim.
async fn for_claim_run(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    label: &str,
) -> (Uuid, DsAutoResult) {
    let claim_id = seed_claim(pool, &format!("frame tier, new-claim path, {label}"), 0.5).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let res = auto_wire_ds_for_claim(
        &mut conn,
        viewer,
        claim_id,
        seed_agent(pool).await,
        DsAutoInput {
            confidence: CONFIDENCE,
            weight: 1.0,
            supports: true,
            evidence_type: Some("logical"),
            evidence_id: None,
        },
    )
    .await
    .expect("auto_wire_ds_for_claim");
    (claim_id, res)
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_ds_write_folds_honour_the_frame_tier_like_the_recompute(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let frame_id = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &viewer)
        .await
        .expect("binary_truth");

    let mut bel = Vec::new();
    let mut verdicts = Vec::new();
    for (label, params) in [
        ("twin", Params::served()),
        ("overridden", Params::overridden()),
    ] {
        if label == "overridden" {
            let set = sqlx::query(
                "UPDATE frames SET properties = COALESCE(properties, '{}'::jsonb) || $2 \
                 WHERE id = $1",
            )
            .bind(frame_id)
            .bind(serde_json::json!({
                "belief_profile": {
                    "reliability": {
                        "intra_evidence_locality_factor": INTRA,
                        "evidence_type_weights": { "logical": LOGICAL }
                    },
                    "classifier": { "nei_threshold": NEI }
                }
            }))
            .execute(&pool)
            .await
            .expect("set the frame override");
            assert_eq!(
                set.rows_affected(),
                1,
                "the override must land on binary_truth"
            );
        }

        let (claim, res) = update_run(&pool, &viewer, frame_id, label).await;
        let (cache, verdict) = cache_agrees(
            &pool,
            &viewer,
            frame_id,
            claim,
            &res,
            &format!("{label} update"),
        )
        .await;
        let want = 1.0
            - (1.0 - INTRA_MASS * params.alpha_intra())
                * (1.0 - CONFIDENCE * params.alpha_writer());
        assert_close(cache[0], want, &format!("{label} update Bel"));
        bel.push(cache[0]);
        verdicts.push(verdict);

        let (claim, res) = for_claim_run(&pool, &viewer, label).await;
        let (cache, _) = cache_agrees(
            &pool,
            &viewer,
            frame_id,
            claim,
            &res,
            &format!("{label} new claim"),
        )
        .await;
        assert_close(
            cache[0],
            CONFIDENCE * params.alpha_writer(),
            &format!("{label} new-claim Bel"),
        );
        bel.push(cache[0]);
    }

    assert_ne!(bel[0], bel[2], "the override must move the update write");
    assert_ne!(bel[1], bel[3], "the override must move the new-claim write");
    assert_eq!(
        verdicts,
        vec![
            Some("supported".to_string()),
            Some("not_enough_info".to_string())
        ],
        "the frame's classifier override must reach the recompute's verdict"
    );
}
