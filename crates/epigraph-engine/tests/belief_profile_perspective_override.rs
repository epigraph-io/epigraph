//! Belief profile, perspective tier: a perspective's `belief_profile` override
//! of ONE parameter changes reads under that perspective and nothing else.
//!
//! The overridden parameter is the intra-source locality factor, which the
//! framed fold consumes today. It is set through the perspective's generic
//! `properties.belief_profile` object, NOT through the older per-tag
//! `locality_reliability` map, so this exercises the profile tier itself.
//!
//! Asserted, over the same stored BBAs:
//! - under the overriding perspective P the belief moves, in the direction the
//!   override implies (a larger intra factor discounts the intra row less);
//! - under a second perspective Q, whose profile override touches only a
//!   parameter no fold consumes yet, the read is bit-identical to the
//!   lens-less read;
//! - the lens-less read is bit-identical before and after P's read (resolving
//!   P must not leak into the served profile);
//! - the batch read under P equals the single read under P.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository, PgPool};
use epigraph_ds::{FocalElement, FrameOfDiscernment, MassFunction};
use epigraph_engine::belief_query::{get_belief, get_perspective_belief, get_perspective_belief_batch};
use epigraph_engine::BeliefInterval;
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

#[allow(clippy::too_many_arguments)]
async fn store_support(
    pool: &PgPool,
    claim_id: Uuid,
    frame_id: Uuid,
    agent: Uuid,
    frame: &FrameOfDiscernment,
    evidence_type: &str,
    locality_tag: &str,
    mass: f64,
) {
    let mut bba = std::collections::BTreeMap::new();
    bba.insert(
        FocalElement::positive(std::collections::BTreeSet::from([0])),
        mass,
    );
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
        None,
        Some(evidence_type),
        locality_tag,
        None,
    )
    .await
    .expect("store bba");
}

async fn perspective_with_properties(pool: &PgPool, name: &str, props: serde_json::Value) -> Uuid {
    let p = PerspectiveRepository::create(pool, name, None, None, Some("analytical"), &[], None, None)
        .await
        .expect("perspective");
    sqlx::query("UPDATE perspectives SET properties = $2 WHERE id = $1")
        .bind(p.id)
        .bind(props)
        .execute(pool)
        .await
        .expect("set perspective properties");
    p.id
}

fn bits(b: &BeliefInterval) -> [u64; 5] {
    [
        b.belief.to_bits(),
        b.plausibility.to_bits(),
        b.pignistic_prob.to_bits(),
        b.mass_on_conflict.to_bits(),
        b.mass_on_missing.to_bits(),
    ]
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_perspective_profile_override_moves_only_reads_under_that_perspective(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let agent = insert_agent(&pool).await;
    let claim_id = insert_claim(&pool, agent).await;
    let frame_row = FrameRepository::create(
        &pool,
        "profile_override_binary",
        None,
        &["H0".to_string(), "H1".to_string()],
    )
    .await
    .expect("frame");
    let frame_id = frame_row.id;
    let frame =
        FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone()).unwrap();

    // One intra-source row (discounted by the intra factor) and one
    // cross-source row (untouched by it).
    store_support(&pool, claim_id, frame_id, agent, &frame, "empirical", "intra_self_cite", 0.8).await;
    store_support(&pool, claim_id, frame_id, agent, &frame, "logical", "cross", 0.5).await;

    let p = perspective_with_properties(
        &pool,
        "lens_trusts_self_citation",
        serde_json::json!({
            "belief_profile": { "reliability": { "intra_evidence_locality_factor": 0.9 } }
        }),
    )
    .await;
    let q = perspective_with_properties(
        &pool,
        "lens_with_unconsumed_override",
        serde_json::json!({ "belief_profile": { "testimonial_ceiling": 0.3 } }),
    )
    .await;

    let global_before = get_belief(&pool, &viewer, claim_id, Some(frame_id))
        .await
        .expect("global read");
    let under_p = get_perspective_belief(&pool, &viewer, claim_id, frame_id, p)
        .await
        .expect("read under P");
    let under_q = get_perspective_belief(&pool, &viewer, claim_id, frame_id, q)
        .await
        .expect("read under Q");
    let global_after = get_belief(&pool, &viewer, claim_id, Some(frame_id))
        .await
        .expect("global read again");

    assert!(
        under_p.belief > global_before.belief,
        "P raises the intra factor, so its belief ({}) must exceed the global ({})",
        under_p.belief,
        global_before.belief
    );
    assert_eq!(
        bits(&under_q),
        bits(&global_before),
        "Q overrides no consumed parameter, so its read must equal the global read"
    );
    assert_eq!(
        bits(&global_after),
        bits(&global_before),
        "reading under P must not change the lens-less read"
    );

    let batch = get_perspective_belief_batch(&pool, &viewer, &[claim_id], frame_id, p)
        .await
        .expect("batch under P");
    let (id, one) = &batch[0];
    assert_eq!(*id, claim_id);
    assert_eq!(
        bits(one.as_ref().expect("batch item")),
        bits(&under_p),
        "batch and single reads under P must agree"
    );
}
