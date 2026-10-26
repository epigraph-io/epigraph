//! Belief profile, perspective tier: a perspective's `belief_profile` override
//! of ONE parameter changes reads under that perspective and nothing else.
//!
//! The overridden parameter is the intra-source locality factor, which the
//! framed fold consumes today. It is set through the perspective's generic
//! `properties.belief_profile` object, NOT through the older per-tag
//! `locality_reliability` map, so this exercises the profile tier itself.
//!
//! Asserted, over the same stored BBAs:
//! - under the overriding perspective P the belief moves to exactly the value
//!   the override implies: the intra row's α becomes `w(empirical) × 0.9`, the
//!   cross row's α stays `w(logical) × cross`, and two simple supports on H0
//!   combine to `1 − (1 − 0.8·α_intra)(1 − 0.5·α_cross)` (no conflict);
//! - under a second perspective Q, whose profile override touches only a
//!   parameter no fold consumes yet, the read is bit-identical to the
//!   lens-less read;
//! - the lens-less read is bit-identical before and after P's read (resolving
//!   P must not leak into the served profile);
//! - the batch read under P equals the single read under P;
//! - lens reads never write the cache: with the served cache seeded by a
//!   recompute first, the claim's row, its `ds_combined_beliefs` rows and its
//!   stored BBAs are byte-identical before and after every read under P and Q.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository, PgPool};
use epigraph_ds::{FocalElement, FrameOfDiscernment, MassFunction};
use epigraph_engine::belief_profile::BeliefProfile;
use epigraph_engine::belief_query::{
    get_belief, get_perspective_belief, get_perspective_belief_batch,
};
use epigraph_engine::BeliefInterval;
use uuid::Uuid;

/// Bel(H0) of two independent simple supports on {H0}, masses `m1`, `m2`,
/// discounted by α1, α2: Dempster's rule on a common singleton has no
/// conflict, so the uncommitted masses multiply.
fn two_simple_supports(m1: f64, a1: f64, m2: f64, a2: f64) -> f64 {
    1.0 - (1.0 - m1 * a1) * (1.0 - m2 * a2)
}

/// Bel(H0) of the fixture's two rows (empirical/intra 0.8, logical/cross 0.5)
/// under the served profile with the intra locality factor `intra`.
fn expected_bel(intra: f64) -> f64 {
    let p = BeliefProfile::served();
    two_simple_supports(
        0.8,
        p.evidence_type_weight("empirical") * intra,
        0.5,
        p.evidence_type_weight("logical") * p.reliability.cross_locality_factor,
    )
}

fn assert_close(got: f64, want: f64, what: &str) {
    assert!(
        (got - want).abs() < 1e-12,
        "{what}: got {got}, the override implies {want}"
    );
}

/// Everything a cache write could touch for this claim, as text: the claim
/// row, its `ds_combined_beliefs` rows and its stored BBAs.
async fn cache_snapshot(pool: &PgPool, claim_id: Uuid) -> (String, String, String) {
    let claim: String =
        sqlx::query_scalar("SELECT to_jsonb(c)::text FROM claims c WHERE c.id = $1")
            .bind(claim_id)
            .fetch_one(pool)
            .await
            .expect("claim snapshot");
    let combined: String = sqlx::query_scalar(
        "SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY d.id), '[]'::jsonb)::text \
         FROM ds_combined_beliefs d WHERE d.claim_id = $1",
    )
    .bind(claim_id)
    .fetch_one(pool)
    .await
    .expect("ds_combined_beliefs snapshot");
    let bbas: String = sqlx::query_scalar(
        "SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY m.id), '[]'::jsonb)::text \
         FROM mass_functions m WHERE m.claim_id = $1",
    )
    .bind(claim_id)
    .fetch_one(pool)
    .await
    .expect("mass_functions snapshot");
    (claim, combined, bbas)
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
    let p =
        PerspectiveRepository::create(pool, name, None, None, Some("analytical"), &[], None, None)
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
    // cross-source row (untouched by it), from two agents so the BBA read
    // returns both.
    let second_agent = insert_agent(&pool).await;
    store_support(
        &pool,
        claim_id,
        frame_id,
        agent,
        &frame,
        "empirical",
        "intra_self_cite",
        0.8,
    )
    .await;
    store_support(
        &pool,
        claim_id,
        frame_id,
        second_agent,
        &frame,
        "logical",
        "cross",
        0.5,
    )
    .await;
    let stored = MassFunctionRepository::get_for_claim_frame(&pool, &viewer, claim_id, frame_id)
        .await
        .expect("bbas");
    assert_eq!(stored.len(), 2, "both rows must reach the fold");

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

    // Seed the served cache, so a lens read that wrote it would be visible.
    let mut conn = pool.acquire().await.unwrap();
    assert!(
        epigraph_engine::edge_factor::recompute_claim_belief_on_frame(
            &mut conn, &viewer, claim_id, frame_id
        )
        .await
        .expect("seed the cache")
    );
    drop(conn);
    let cache_before = cache_snapshot(&pool, claim_id).await;
    let cached_bel: Option<f64> = sqlx::query_scalar("SELECT belief FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(cached_bel.is_some(), "the recompute seeded the cache");

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

    assert_close(
        global_before.belief,
        expected_bel(
            BeliefProfile::served()
                .reliability
                .intra_evidence_locality_factor,
        ),
        "lens-less read",
    );
    assert_close(under_p.belief, expected_bel(0.9), "read under P");
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

    assert_eq!(
        cache_snapshot(&pool, claim_id).await,
        cache_before,
        "lens reads recompute; they must never write the cache (addendum §3.1)"
    );
}

/// The frame tier: a frame's `belief_profile` override applies to the framed
/// read AND to the cached value the recompute writes, identically, so the
/// framed read keeps reproducing the cache. A twin frame without the override
/// over the same rows serves the un-overridden value.
#[sqlx::test(migrations = "../../migrations")]
async fn a_frame_profile_override_moves_the_read_and_the_cache_together(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let first_agent = insert_agent(&pool).await;
    let second_agent = insert_agent(&pool).await;

    let mut results = Vec::new();
    for (name, props) in [
        ("frame_without_override", None),
        (
            "frame_with_override",
            Some(serde_json::json!({
                "belief_profile": { "reliability": { "intra_evidence_locality_factor": 0.9 } }
            })),
        ),
    ] {
        let claim_id = insert_claim(&pool, first_agent).await;
        let frame_row =
            FrameRepository::create(&pool, name, None, &["H0".to_string(), "H1".to_string()])
                .await
                .expect("frame");
        if let Some(props) = props {
            sqlx::query("UPDATE frames SET properties = properties || $2 WHERE id = $1")
                .bind(frame_row.id)
                .bind(props)
                .execute(&pool)
                .await
                .expect("frame properties");
        }
        let frame =
            FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone()).unwrap();
        store_support(
            &pool,
            claim_id,
            frame_row.id,
            first_agent,
            &frame,
            "empirical",
            "intra_self_cite",
            0.8,
        )
        .await;
        store_support(
            &pool,
            claim_id,
            frame_row.id,
            second_agent,
            &frame,
            "logical",
            "cross",
            0.5,
        )
        .await;

        let mut conn = pool.acquire().await.unwrap();
        assert!(
            epigraph_engine::edge_factor::recompute_claim_belief_on_frame(
                &mut conn,
                &viewer,
                claim_id,
                frame_row.id
            )
            .await
            .expect("recompute")
        );
        drop(conn);
        let (cached_bel, cached_betp): (f64, f64) =
            sqlx::query_as("SELECT belief, pignistic_prob FROM claims WHERE id = $1")
                .bind(claim_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let framed = get_belief(&pool, &viewer, claim_id, Some(frame_row.id))
            .await
            .expect("framed read");
        assert_eq!(
            framed.belief.to_bits(),
            cached_bel.to_bits(),
            "{name}: framed read and cache must agree"
        );
        assert_eq!(
            framed.pignistic_prob.to_bits(),
            cached_betp.to_bits(),
            "{name}: framed read and cache must agree"
        );
        results.push(framed.belief);
    }
    assert_close(
        results[0],
        expected_bel(
            BeliefProfile::served()
                .reliability
                .intra_evidence_locality_factor,
        ),
        "twin frame without the override",
    );
    assert_close(results[1], expected_bel(0.9), "frame with the override");
}
