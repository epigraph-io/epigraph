//! T2 — real DB compute-on-read validation for the perspectival-demo.
//!
//! Records the discriminating treatment-c-cluster BBAs into a dev epigraph DB,
//! sets per-perspective `source_reliability`, then calls the REAL
//! `belief_query::get_perspective_belief` (full compute-on-read path:
//! effective_source_strength_with_perspective -> combine_multiple -> pignistic)
//! and asserts it reproduces the demo's scripts/verify_beliefs.py.
//!
//! Run:
//!   DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_demo_dev \
//!   SQLX_OFFLINE=true cargo test -p epigraph-engine --test perspectival_demo_t2 -- --nocapture
//!
//! Leaves its rows in the dev DB for inspection (frames/claims/perspectives
//! suffixed with a per-run id so re-runs don't collide).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository, PgPool};
use epigraph_ds::{FocalElement, FrameOfDiscernment, MassFunction};
use uuid::Uuid;

async fn get_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPool::connect(&url).await.ok()?;
    sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
    Some(pool)
}

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at) \
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("insert agent");
    id
}

async fn insert_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
         VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)",
    )
    .bind(id)
    .bind(content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("insert claim");
    id
}

/// Store a BBA: mass on the focal singleton {idx}, remainder on Θ, tagged with
/// `evidence_type`, cross-source locality (locality factor 1.0), no perspective.
async fn store(
    pool: &PgPool,
    claim: Uuid,
    frame_id: Uuid,
    agent: Uuid,
    frame: &FrameOfDiscernment,
    evidence_type: &str,
    idx: usize,
    mass: f64,
) {
    let mut bba = BTreeMap::new();
    bba.insert(FocalElement::positive(BTreeSet::from([idx])), mass);
    bba.insert(FocalElement::theta(frame), 1.0 - mass);
    let mf = MassFunction::new(frame.clone(), bba).unwrap();
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame_id,
        Some(agent),
        None,
        &mf.masses_to_json(),
        None,
        Some("discount"),
        Some(1.0),
        Some(evidence_type),
        "cross",
        None,
    )
    .await
    .expect("store bba");
}

async fn make_perspective(pool: &PgPool, name: &str, rel: &[(&str, f64)]) -> Uuid {
    let p = PerspectiveRepository::create(pool, name, None, None, Some("disciplinary"), &[], None, None)
        .await
        .expect("create perspective");
    let map: HashMap<String, f64> = rel.iter().map(|(k, v)| ((*k).to_string(), *v)).collect();
    PerspectiveRepository::set_source_reliability(pool, p.id, &map)
        .await
        .expect("set source_reliability");
    p.id
}

async fn betp(pool: &PgPool, claim: Uuid, frame: Uuid, persp: Uuid) -> f64 {
    epigraph_engine::belief_query::get_perspective_belief(pool, claim, frame, persp)
        .await
        .expect("get_perspective_belief")
        .pignistic_prob
}

#[tokio::test]
async fn t2_real_engine_reproduces_python_model() {
    let Some(pool) = get_pool().await else {
        eprintln!("SKIP: DATABASE_URL not set");
        return;
    };
    let run = Uuid::new_v4().simple().to_string();
    let sfx = &run[..8];

    let author = insert_agent(&pool).await;
    let a_clin = insert_agent(&pool).await; // source_clinical corpus
    let a_trad = insert_agent(&pool).await; // source_tradition
    let a_prac = insert_agent(&pool).await; // source_practitioner

    let clinical = make_perspective(
        &pool,
        &format!("clinical_observer_{sfx}"),
        &[("source_clinical", 0.95), ("source_survey", 0.40), ("source_tradition", 0.15), ("source_practitioner", 0.10)],
    )
    .await;
    let tradition = make_perspective(
        &pool,
        &format!("tradition_observer_{sfx}"),
        &[("source_clinical", 0.60), ("source_survey", 0.70), ("source_tradition", 0.90), ("source_practitioner", 0.85)],
    )
    .await;

    let eff_row = FrameRepository::create(&pool, &format!("treatment_efficacy_{sfx}"), None, &["efficacious".to_string(), "no_effect".to_string()])
        .await
        .expect("eff frame");
    let saf_row = FrameRepository::create(&pool, &format!("treatment_safety_{sfx}"), None, &["safe".to_string(), "harmful".to_string()])
        .await
        .expect("saf frame");
    let eff = FrameOfDiscernment::new(eff_row.name.clone(), eff_row.hypotheses.clone()).unwrap();
    let saf = FrameOfDiscernment::new(saf_row.name.clone(), saf_row.hypotheses.clone()).unwrap();

    // Case A — treatment-c SAFETY {safe(0), harmful(1)}: clinical harmful vs tradition safe (K>0).
    let tc_saf = insert_claim(&pool, author, "treatment-c is safe at therapeutic dose").await;
    store(&pool, tc_saf, saf_row.id, a_clin, &saf, "source_clinical", 1, 0.70).await;
    store(&pool, tc_saf, saf_row.id, a_trad, &saf, "source_tradition", 0, 0.50).await;
    store(&pool, tc_saf, saf_row.id, a_prac, &saf, "source_practitioner", 0, 0.45).await;

    // Case B — treatment-e EFFICACY {efficacious(0), no_effect(1)}: tradition efficacious vs clinical no_effect (K>0).
    let te_eff = insert_claim(&pool, author, "treatment-e is efficacious for symptom-4").await;
    store(&pool, te_eff, eff_row.id, a_trad, &eff, "source_tradition", 0, 0.55).await;
    store(&pool, te_eff, eff_row.id, a_prac, &eff, "source_practitioner", 0, 0.45).await;
    store(&pool, te_eff, eff_row.id, a_clin, &eff, "source_clinical", 1, 0.60).await;

    // Case C — treatment-a EFFICACY (consensus control, K=0).
    let ta_eff = insert_claim(&pool, author, "treatment-a is efficacious for symptom-1").await;
    store(&pool, ta_eff, eff_row.id, a_clin, &eff, "source_clinical", 0, 0.75).await;
    store(&pool, ta_eff, eff_row.id, a_trad, &eff, "source_tradition", 0, 0.55).await;
    store(&pool, ta_eff, eff_row.id, a_prac, &eff, "source_practitioner", 0, 0.40).await;

    let saf_clin = betp(&pool, tc_saf, saf_row.id, clinical).await;
    let saf_trad = betp(&pool, tc_saf, saf_row.id, tradition).await;
    let te_clin = betp(&pool, te_eff, eff_row.id, clinical).await;
    let te_trad = betp(&pool, te_eff, eff_row.id, tradition).await;
    let ta_clin = betp(&pool, ta_eff, eff_row.id, clinical).await;
    let ta_trad = betp(&pool, ta_eff, eff_row.id, tradition).await;

    eprintln!("REAL ENGINE (get_perspective_belief, dev DB) vs Python model:");
    eprintln!("  treatment-c safety  clinical={saf_clin:.3} (py 0.203)   tradition={saf_trad:.3} (py 0.666)");
    eprintln!("  treatment-e eff     clinical={te_clin:.3} (py 0.260)   tradition={te_trad:.3} (py 0.718)");
    eprintln!("  treatment-a eff     clinical={ta_clin:.3} (py 0.873)   tradition={ta_trad:.3} (py 0.908)");

    let approx = |a: f64, b: f64| (a - b).abs() < 0.005;
    assert!(approx(saf_clin, 0.203), "treatment-c safety clinical = {saf_clin}");
    assert!(approx(saf_trad, 0.666), "treatment-c safety tradition = {saf_trad}");
    assert!(approx(te_clin, 0.260), "treatment-e eff clinical = {te_clin}");
    assert!(approx(te_trad, 0.718), "treatment-e eff tradition = {te_trad}");
    assert!(approx(ta_clin, 0.873), "treatment-a eff clinical = {ta_clin}");
    assert!(approx(ta_trad, 0.908), "treatment-a eff tradition = {ta_trad}");
}
