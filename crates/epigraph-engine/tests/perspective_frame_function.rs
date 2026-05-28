//! Integration test for the per-perspective source-reliability "frame
//! function": `belief_query::get_perspective_belief` must read the claim's
//! stored BBAs, discount each by the queried perspective's reliability for its
//! `evidence_type`, and combine — so two observers reach different beliefs from
//! the SAME evidence, with no dependency on how that evidence was ingested.

use std::collections::HashMap;

use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository, PgPool};
use epigraph_ds::{FocalElement, FrameOfDiscernment, MassFunction};
use uuid::Uuid;

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at) \
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

async fn insert_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

/// Store a supporting BBA (mass on TRUE=H0, rest on Θ) tagged with `evidence_type`.
async fn store_bba(
    pool: &PgPool,
    claim_id: Uuid,
    frame_id: Uuid,
    agent: Uuid,
    frame: &FrameOfDiscernment,
    evidence_type: &str,
    mass: f64,
) {
    let mut bba = std::collections::BTreeMap::new();
    bba.insert(FocalElement::positive(std::collections::BTreeSet::from([0])), mass);
    bba.insert(FocalElement::theta(frame), 1.0 - mass);
    let mf = MassFunction::new(frame.clone(), bba).unwrap();
    MassFunctionRepository::store_with_perspective(
        pool,
        claim_id,
        frame_id,
        Some(agent),
        None,
        &mf.masses_to_json(),
        None,
        Some("discount"),
        Some(1.0),
        Some(evidence_type),
        "unknown",
        None,
    )
    .await
    .expect("store bba");
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_perspective_belief_diverges_by_observer(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let claim_id = insert_claim(&pool, agent).await;
    let frame_row = FrameRepository::create(
        &pool,
        "ff_binary",
        None,
        &["H0".to_string(), "H1".to_string()],
    )
    .await
    .expect("frame");
    let frame_id = frame_row.id;
    let frame =
        FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone()).unwrap();

    // Shared corpus: a clinical result + a practitioner interview, both for H0.
    store_bba(&pool, claim_id, frame_id, agent, &frame, "western_clinical", 0.6).await;
    store_bba(&pool, claim_id, frame_id, agent, &frame, "practitioner_interview", 0.7).await;

    let skeptic = PerspectiveRepository::create(
        &pool, "skeptic", None, None, Some("analytical"), &[], None, None,
    )
    .await
    .expect("skeptic");
    let believer = PerspectiveRepository::create(
        &pool, "believer", None, None, Some("analytical"), &[], None, None,
    )
    .await
    .expect("believer");
    PerspectiveRepository::set_source_reliability(
        &pool,
        skeptic.id,
        &HashMap::from([
            ("western_clinical".to_string(), 1.0),
            ("practitioner_interview".to_string(), 0.3),
        ]),
    )
    .await
    .expect("skeptic map");
    PerspectiveRepository::set_source_reliability(
        &pool,
        believer.id,
        &HashMap::from([
            ("western_clinical".to_string(), 1.0),
            ("practitioner_interview".to_string(), 1.0),
        ]),
    )
    .await
    .expect("believer map");

    let skeptic_belief =
        epigraph_engine::belief_query::get_perspective_belief(&pool, claim_id, frame_id, skeptic.id)
            .await
            .expect("skeptic belief");
    let believer_belief = epigraph_engine::belief_query::get_perspective_belief(
        &pool, claim_id, frame_id, believer.id,
    )
    .await
    .expect("believer belief");

    // Same stored evidence, different observer reliability → different belief.
    assert!(
        skeptic_belief.belief < believer_belief.belief,
        "skeptic ({}) should believe H0 less than believer ({})",
        skeptic_belief.belief,
        believer_belief.belief
    );
    assert_eq!(skeptic_belief.source, "recomputed_perspective");

    // The all-α=1.0 believer must equal the global (no-perspective) belief —
    // a neutral observer adds no discount.
    let global = epigraph_engine::belief_query::get_belief(&pool, claim_id, Some(frame_id))
        .await
        .expect("global belief");
    assert!(
        (believer_belief.belief - global.belief).abs() < 1e-9,
        "neutral believer ({}) must match global ({})",
        believer_belief.belief,
        global.belief
    );
}

/// A perspective with no source_reliability map must reproduce the global
/// belief exactly (no silent divergence for un-configured observers).
#[sqlx::test(migrations = "../../migrations")]
async fn unmapped_perspective_equals_global(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let claim_id = insert_claim(&pool, agent).await;
    let frame_row = FrameRepository::create(
        &pool,
        "ff_binary2",
        None,
        &["H0".to_string(), "H1".to_string()],
    )
    .await
    .expect("frame");
    let frame =
        FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone()).unwrap();
    store_bba(&pool, claim_id, frame_row.id, agent, &frame, "practitioner_interview", 0.7).await;

    let plain = PerspectiveRepository::create(
        &pool, "plain", None, None, Some("analytical"), &[], None, None,
    )
    .await
    .expect("plain perspective");

    let scoped = epigraph_engine::belief_query::get_perspective_belief(
        &pool, claim_id, frame_row.id, plain.id,
    )
    .await
    .expect("scoped belief");
    let global = epigraph_engine::belief_query::get_belief(&pool, claim_id, Some(frame_row.id))
        .await
        .expect("global belief");
    assert!((scoped.belief - global.belief).abs() < 1e-9);
}
