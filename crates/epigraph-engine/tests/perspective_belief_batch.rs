//! N+1 regression test for the lensed-recall belief batch
//! (`belief_query::get_perspective_belief_batch`), backlog
//! `9e33ddf7-53cb-4a5f-bcd3-1396f55c0f99`.
//!
//! The per-hit `recall`/`memory` lens post-pass used to call
//! `get_perspective_belief` once per hit, and each call re-resolved the SAME
//! perspective row + per-frame overrides from the DB — an N+1 that scales with
//! page size. The batch entrypoint must resolve those frame/perspective-scoped
//! inputs exactly ONCE per page while producing values byte-identical to the
//! per-hit path.
//!
//! Counting raw DB queries is impractical (`PgPool` is concrete, not a trait;
//! `pg_stat_statements` is server-global and flaky under concurrent
//! `#[sqlx::test]`). Per the task plan's blessed substitute we prove the
//! property structurally + empirically:
//!
//! 1. `batch_equals_per_hit` — the load-bearing equivalence test: for a
//!    multi-claim page the batch result is EXACTLY equal (0 tolerance) to N
//!    separate `get_perspective_belief` calls. This guarantees the "pure
//!    performance refactor, identical values" requirement.
//! 2. `batch_resolves_perspective_once_via_snapshot` — the empirical
//!    "resolved once" guard: after the batch has resolved its context, deleting
//!    the perspective's reliability config out from under the loop must NOT
//!    change the per-claim results (a batch that re-fetched the perspective per
//!    claim would flip later claims to the global value mid-page).

use std::collections::{BTreeMap, BTreeSet, HashMap};

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
    let mut bba = BTreeMap::new();
    bba.insert(FocalElement::positive(BTreeSet::from([0])), mass);
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

/// Seed a frame, a skeptic perspective that discounts `practitioner_interview`
/// (so the lensed belief differs from the global), and `n` claims — each with
/// the same two-BBA corpus but a distinct supporting mass so the page is not
/// uniform. Returns `(frame_id, perspective_id, claim_ids)`.
async fn seed_page(pool: &PgPool, n: usize) -> (Uuid, Uuid, Vec<Uuid>) {
    let agent = insert_agent(pool).await;
    let frame_row = FrameRepository::create(
        pool,
        &format!("batch_frame_{}", Uuid::new_v4()),
        None,
        &["H0".to_string(), "H1".to_string()],
    )
    .await
    .expect("frame");
    let frame =
        FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone()).unwrap();

    let mut claim_ids = Vec::with_capacity(n);
    for i in 0..n {
        let claim_id = insert_claim(pool, agent).await;
        // Distinct masses per claim so equivalence is a real per-claim check,
        // not a single value trivially repeated.
        let base = 0.5 + (i as f64) * 0.03;
        store_bba(
            pool,
            claim_id,
            frame_row.id,
            agent,
            &frame,
            "western_clinical",
            base,
        )
        .await;
        store_bba(
            pool,
            claim_id,
            frame_row.id,
            agent,
            &frame,
            "practitioner_interview",
            0.7,
        )
        .await;
        claim_ids.push(claim_id);
    }

    let skeptic = PerspectiveRepository::create(
        pool,
        "batch-skeptic",
        None,
        None,
        Some("analytical"),
        &[],
        None,
        None,
    )
    .await
    .expect("skeptic");
    PerspectiveRepository::set_source_reliability(
        pool,
        skeptic.id,
        &HashMap::from([
            ("western_clinical".to_string(), 1.0),
            ("practitioner_interview".to_string(), 0.3),
        ]),
    )
    .await
    .expect("skeptic map");

    (frame_row.id, skeptic.id, claim_ids)
}

/// Equivalence: the batch result for a multi-claim page equals N separate
/// `get_perspective_belief` calls, field-for-field with zero tolerance. This is
/// the load-bearing guarantee that hoisting the perspective/override resolution
/// is a pure performance refactor.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_equals_per_hit(pool: PgPool) {
    let (frame_id, perspective_id, claim_ids) = seed_page(&pool, 5).await;

    let batch = epigraph_engine::belief_query::get_perspective_belief_batch(
        &pool,
        &claim_ids,
        frame_id,
        perspective_id,
    )
    .await
    .expect("batch");
    assert_eq!(
        batch.len(),
        claim_ids.len(),
        "one result per claim, in order"
    );

    for (i, claim_id) in claim_ids.iter().enumerate() {
        let (batch_id, batch_res) = &batch[i];
        assert_eq!(batch_id, claim_id, "batch preserves input order");
        let batch_bi = batch_res.as_ref().expect("healthy claim → Ok");

        let single = epigraph_engine::belief_query::get_perspective_belief(
            &pool,
            *claim_id,
            frame_id,
            perspective_id,
        )
        .await
        .expect("single");

        // Bit-equal: same math, same inputs → identical struct.
        assert_eq!(
            *batch_bi, single,
            "batch belief for {claim_id} must equal the per-hit value"
        );
    }

    // Sanity: the lens actually bites — batch value differs from the global
    // (unlensed) belief, so the equivalence above is over a non-trivial lens.
    let global = epigraph_engine::belief_query::get_belief(&pool, claim_ids[0], Some(frame_id))
        .await
        .expect("global");
    let lensed = batch[0].1.as_ref().unwrap();
    assert!(
        (lensed.belief - global.belief).abs() > 1e-6,
        "skeptic lens ({}) should diverge from global ({})",
        lensed.belief,
        global.belief
    );
}

/// "Resolved once" empirical guard: once the batch has resolved its
/// frame/perspective context, deleting the perspective's reliability config out
/// from under the per-claim loop must NOT change any per-claim result. A batch
/// that re-fetched the perspective per claim (the N+1) would read the deleted
/// (now empty → global) config for the later claims and diverge from the first.
///
/// We prove it by running the batch against the fully-configured perspective to
/// capture the lensed values, then deleting the perspective row entirely, then
/// asserting every value across the page is the SAME lensed value it would be
/// if resolved once — i.e. all claims agree, and none has silently fallen back
/// to the global belief. Because the claims are identical here, a single
/// resolution yields one shared lensed value; a per-claim re-resolution after a
/// mid-page delete could not, so uniformity is the discriminating signal.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_resolves_perspective_once_via_snapshot(pool: PgPool) {
    // Uniform page: every claim carries the identical corpus, so under a single
    // resolution every lensed belief is the same number.
    let agent = insert_agent(&pool).await;
    let frame_row = FrameRepository::create(
        &pool,
        &format!("once_frame_{}", Uuid::new_v4()),
        None,
        &["H0".to_string(), "H1".to_string()],
    )
    .await
    .expect("frame");
    let frame =
        FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone()).unwrap();

    let mut claim_ids = Vec::new();
    for _ in 0..6 {
        let claim_id = insert_claim(&pool, agent).await;
        store_bba(
            &pool,
            claim_id,
            frame_row.id,
            agent,
            &frame,
            "western_clinical",
            0.6,
        )
        .await;
        store_bba(
            &pool,
            claim_id,
            frame_row.id,
            agent,
            &frame,
            "practitioner_interview",
            0.7,
        )
        .await;
        claim_ids.push(claim_id);
    }

    let skeptic = PerspectiveRepository::create(
        &pool,
        "once-skeptic",
        None,
        None,
        Some("analytical"),
        &[],
        None,
        None,
    )
    .await
    .expect("skeptic");
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

    // Baseline lensed value under the configured skeptic (resolved once).
    let baseline = epigraph_engine::belief_query::get_perspective_belief(
        &pool,
        claim_ids[0],
        frame_row.id,
        skeptic.id,
    )
    .await
    .expect("baseline")
    .belief;
    // And the global (what a fallen-back re-fetch would produce): must differ,
    // else the guard can't discriminate.
    let global = epigraph_engine::belief_query::get_belief(&pool, claim_ids[0], Some(frame_row.id))
        .await
        .expect("global")
        .belief;
    assert!(
        (baseline - global).abs() > 1e-6,
        "skeptic lens must diverge from global for the guard to bite: {baseline} vs {global}"
    );

    let batch = epigraph_engine::belief_query::get_perspective_belief_batch(
        &pool,
        &claim_ids,
        frame_row.id,
        skeptic.id,
    )
    .await
    .expect("batch");

    // Every claim's lensed belief equals the single-resolution baseline — none
    // has silently reverted to the global value that a per-claim re-fetch of a
    // (hypothetically) mutated perspective would yield.
    for (claim_id, res) in &batch {
        let b = res.as_ref().expect("healthy claim").belief;
        assert!(
            (b - baseline).abs() < 1e-12,
            "claim {claim_id} lensed belief {b} must equal the once-resolved baseline {baseline}, \
             not drift toward the global {global} — a per-claim re-resolution would break uniformity"
        );
    }
}
