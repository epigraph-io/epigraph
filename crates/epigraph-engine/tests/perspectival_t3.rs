//! T3 — the engine adjudicates the adversarial loop's AGENT-GATHERED BBAs.
//!
//! Takes the v2 workflow's prove/refute BBAs (already lens-applied by each
//! perspective's agents), RECORDS them into the dev DB, then combines them with the
//! real `combine_multiple` and runs the calibrated `classify()` (SciFact thresholds:
//! conflict 0.05 / nei 0.85). So the conflict K and the consolidate/contradict verdict
//! become ENGINE outputs — not the agents' own estimates. The reviewers flagged that
//! the agents' "consolidated=true / 0.5 threshold" was ungrounded; here the engine's
//! calibrated classifier renders the real verdict. BBAs carry open-world mass.
//!
//! Run:
//!   DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_demo_dev \
//!   SQLX_OFFLINE=true cargo test -p epigraph-engine --test perspectival_t3 -- --nocapture

use std::collections::{BTreeMap, BTreeSet};

use epigraph_db::{MassFunctionRepository, PgPool};
use epigraph_ds::{combination, measures, FocalElement, FrameOfDiscernment, MassFunction};
use epigraph_engine::calibration::ClassifierThresholds;
use epigraph_engine::classifier::{classify, CdstClassification};
use uuid::Uuid;

const OW: f64 = 0.10;

/// Open-world BBA over a binary frame: mass m0 on idx0, m1 on idx1, `OW` reserved on
/// the missing (open-world) element, remainder on Θ.
fn bba(frame: &FrameOfDiscernment, m0: f64, m1: f64, theta: f64) -> MassFunction {
    let ow = OW.min(theta);
    let mut m: BTreeMap<FocalElement, f64> = BTreeMap::new();
    if m0 > 0.0 {
        m.insert(FocalElement::positive(BTreeSet::from([0])), m0);
    }
    if m1 > 0.0 {
        m.insert(FocalElement::positive(BTreeSet::from([1])), m1);
    }
    let tr = theta - ow;
    if tr > 1e-9 {
        m.insert(FocalElement::theta(frame), tr);
    }
    m.insert(FocalElement::missing(frame), ow);
    MassFunction::new(frame.clone(), m).expect("bba")
}

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, created_at, updated_at) VALUES ($1, sha256($1::text::bytea), NOW(), NOW())")
        .bind(id).execute(pool).await.expect("agent");
    id
}
async fn insert_claim(pool: &PgPool, author: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
        .bind(id).bind(content).bind(author).execute(pool).await.expect("claim");
    id
}

#[tokio::test]
#[ignore = "requires SEED_DIR + dedicated dev DB; run manually with --ignored"]
async fn t3_engine_adjudicates_agent_bbas() {
    let eff = FrameOfDiscernment::new(
        "treatment_efficacy",
        vec!["efficacious".into(), "no_effect".into()],
    )
    .unwrap();
    let saf =
        FrameOfDiscernment::new("treatment_safety", vec!["safe".into(), "harmful".into()]).unwrap();

    // v2 agent-gathered BBAs (label, frame, prove (m0,m1,theta), refute (m0,m1,theta),
    //                         agent_K, agent_consolidated, agent_BetP_target)
    let cases: Vec<(
        &str,
        &FrameOfDiscernment,
        (f64, f64, f64),
        (f64, f64, f64),
        f64,
        bool,
        f64,
    )> = vec![
        (
            "clinical/efficacy",
            &eff,
            (0.32, 0.13, 0.55),
            (0.12, 0.13, 0.75),
            0.057,
            true,
            0.584,
        ),
        (
            "clinical/safety",
            &saf,
            (0.27, 0.45, 0.28),
            (0.20, 0.52, 0.28),
            0.230,
            true,
            0.292,
        ),
        (
            "tradition/efficacy",
            &eff,
            (0.55, 0.08, 0.37),
            (0.22, 0.30, 0.48),
            0.183,
            true,
            0.679,
        ),
        (
            "tradition/safety",
            &saf,
            (0.50, 0.32, 0.18),
            (0.30, 0.45, 0.25),
            0.321,
            true,
            0.518,
        ),
    ];

    // Optional DB recording (records the agent-gathered evidence into the dev DB).
    let pool = match std::env::var("DATABASE_URL") {
        Ok(url) => PgPool::connect(&url).await.ok(),
        Err(_) => None,
    };
    let mut recorded = 0;
    if let Some(pool) = &pool {
        let author = insert_agent(pool).await;
        let prove_src = insert_agent(pool).await;
        let refute_src = insert_agent(pool).await;
        // frame UUIDs already exist in the loaded DB; look them up by name.
        for (label, frame, p, r, _ak, _ac, _ab) in &cases {
            let frame_name = frame.id.clone(); // FrameOfDiscernment.id == name we constructed
            let frame_id: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM frames WHERE name = $1 ORDER BY created_at LIMIT 1",
            )
            .bind(&frame_name)
            .fetch_optional(pool)
            .await
            .expect("frame lookup");
            let Some(frame_id) = frame_id else { continue };
            let claim = insert_claim(pool, author, &format!("T3 gathered: {label}")).await;
            for (src, m) in [
                (prove_src, bba(frame, p.0, p.1, p.2)),
                (refute_src, bba(frame, r.0, r.1, r.2)),
            ] {
                MassFunctionRepository::store_with_perspective(
                    pool,
                    claim,
                    frame_id,
                    Some(src),
                    None,
                    &m.masses_to_json(),
                    None,
                    Some("discount"),
                    Some(1.0),
                    Some("agent_gathered"),
                    "cross",
                    None,
                )
                .await
                .expect("record bba");
                recorded += 1;
            }
        }
    }

    let th = ClassifierThresholds::default();
    println!("\nT3 — ENGINE adjudication of agent-gathered BBAs (calibrated classify, conflict_threshold=0.05):");
    println!(
        "  {:<20} {:>8} {:>10} {:>11} {:>9}  {:<13} {}",
        "axis", "engineK", "BetP_tgt", "open-world", "(agentK)", "ENGINE", "(agent said)"
    );
    let mut safety_verdicts = vec![];
    for (label, frame, p, r, ak, ac, ab) in &cases {
        let prove = bba(frame, p.0, p.1, p.2);
        let refute = bba(frame, r.0, r.1, r.2);
        let (combined, reports) =
            combination::combine_multiple(&[prove.clone(), refute.clone()], 0.1).unwrap();
        let k = reports[0].conflict_k;
        let theta_m = combined.mass_of(&FocalElement::theta(frame)) + combined.mass_of_missing();
        let miss = combined.mass_of_missing();
        let bsup = measures::pignistic_probability(&combined, 0);
        let bunsup = measures::pignistic_probability(&combined, 1);
        let has_opposing_threshold = 0.1_f64; // calibrated value (calibration.toml [classifier_thresholds])
        let has_opp = measures::pignistic_probability(&prove, 1) > has_opposing_threshold
            || measures::pignistic_probability(&refute, 1) > has_opposing_threshold;
        let verdict = classify(k, theta_m, bsup, bunsup, has_opp, &th);
        println!("  {label:<20} {k:>8.3} {bsup:>10.3} {miss:>11.3} {:>9}  {:<13} consolidated={ac}, BetP~{ab}",
            format!("{ak:.3}"), format!("{verdict}"));
        if label.contains("safety") {
            safety_verdicts.push((label.to_string(), verdict));
        }
    }
    if recorded > 0 {
        println!("\nRecorded {recorded} agent-gathered BBAs into the dev DB (perspective evidence, evidence_type='agent_gathered').");
    }

    // The reviewers' core finding, now rendered by the calibrated engine: the agents stamped
    // "consolidated=true" using an ungrounded 0.5 threshold, but the SAFETY axes carry opposing
    // evidence with K well above the calibrated 0.05 line → the engine classifies them CONTRADICTED.
    for (label, v) in &safety_verdicts {
        assert!(matches!(v, CdstClassification::Contradicted),
            "{label}: engine should classify Contradicted (agents wrongly said consolidated), got {v}");
    }
    println!("\nT3 PASS: engine's calibrated classifier overrides the agents' ungrounded 'consolidated' on both safety axes.");
}
