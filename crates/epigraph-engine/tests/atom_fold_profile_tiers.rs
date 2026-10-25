//! The atom evidence fold reads the belief profile's lens tiers (addendum
//! §3.1, SPEC §3.3 "Lens context").
//!
//! The atom fold reads rows of several frames at once, so each row folds
//! under the lens of its context with its OWN frame's tier
//! (`FramedBeliefContext::profile_for_frame`): the global profile, then the
//! row frame's `belief_profile` object, then the perspective's. Pinned here:
//!
//! * a perspective's `belief_profile` object moves the fold under that lens
//!   only (`FramedBeliefContext::for_perspective`), not the global fold;
//! * a frame's `belief_profile` object moves the rows of that frame only;
//! * on one row, the perspective tier wins over the frame tier.
//!
//! The lever is `reliability.unknown_evidence_type_weight`: each row has no
//! evidence type and no stored strength and a non-intra locality tag, so its
//! reliability is exactly that weight (times the cross factor 1). One row
//! {T: .8, Θ: .2} discounted by α folds to Bel = .8·α. Expected values are
//! these closed forms over the override values the test writes.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository};
use epigraph_engine::atom_items::{
    atom_axiom_rows_under, atom_fold, AxiomMode, CompoundSourceEdges,
};
use epigraph_engine::belief_profile::defaults;
use epigraph_engine::belief_query::FramedBeliefContext;
use sqlx::PgPool;
use uuid::Uuid;

const TOL: f64 = 1e-12;
/// The one row's committed mass on TRUE.
const T: f64 = 0.8;

async fn agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("agent")
}

async fn claim(pool: &PgPool, author: Uuid, what: &str) -> Uuid {
    fixture::seed_public_claim(
        pool,
        author,
        &format!("profile tier {what} {}", Uuid::new_v4()),
    )
    .await
}

/// A fresh 2-hypothesis frame, with `properties` merged in when given.
async fn frame(pool: &PgPool, properties: Option<serde_json::Value>) -> Uuid {
    let id = FrameRepository::create(
        pool,
        &format!("profile_tier_{}", Uuid::new_v4().simple()),
        None,
        &["H0".to_string(), "H1".to_string()],
    )
    .await
    .expect("frame")
    .id;
    if let Some(props) = properties {
        sqlx::query("UPDATE frames SET properties = properties || $2 WHERE id = $1")
            .bind(id)
            .bind(props)
            .execute(pool)
            .await
            .expect("frame properties");
    }
    id
}

async fn perspective(pool: &PgPool, properties: serde_json::Value) -> Uuid {
    let p = PerspectiveRepository::create(
        pool,
        &format!("profile tier lens {}", Uuid::new_v4()),
        None,
        None,
        Some("analytical"),
        &[],
        None,
        None,
    )
    .await
    .expect("perspective");
    sqlx::query("UPDATE perspectives SET properties = $2 WHERE id = $1")
        .bind(p.id)
        .bind(properties)
        .execute(pool)
        .await
        .expect("perspective properties");
    p.id
}

/// One {T: .8, Θ: .2} row with no evidence type and no stored strength, so
/// its reliability is the profile's unknown-type weight.
async fn store_row(pool: &PgPool, claim: Uuid, frame: Uuid) {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent(pool).await),
        None,
        &serde_json::json!({"0": T, "0,1": 1.0 - T}),
        None,
        None,
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("store BBA");
}

fn unknown_weight(w: f64) -> serde_json::Value {
    serde_json::json!({
        "belief_profile": { "reliability": { "unknown_evidence_type_weight": w } }
    })
}

/// Bel of `atom`'s AEF under `ctx`.
async fn bel(pool: &PgPool, atom: Uuid, ctx: &FramedBeliefContext) -> f64 {
    let viewer = fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    let rows = atom_axiom_rows_under(
        &mut conn,
        &viewer,
        &[atom],
        AxiomMode::Display,
        ctx,
        CompoundSourceEdges::Frozen,
    )
    .await
    .expect("atom_axiom_rows");
    let rows = rows.get(&atom).expect("the atom has its row");
    assert_eq!(rows.len(), 1, "exactly the one stored row is read");
    atom_fold(rows).expect("fold").belief()
}

async fn global_and_lens(pool: &PgPool, lens: Uuid) -> (FramedBeliefContext, FramedBeliefContext) {
    let under_p =
        FramedBeliefContext::for_perspective(pool, &fixture::public_viewer(pool).await, Some(lens))
            .await
            .expect("lens context");
    (FramedBeliefContext::global(), under_p)
}

/// The served profile keeps the built-in unknown-type weight, so the global
/// expectations below are closed forms over it.
fn served_unknown_weight() -> f64 {
    let w = epigraph_engine::belief_profile::BeliefProfile::served()
        .reliability
        .unknown_evidence_type_weight;
    assert!(
        (w - defaults::UNKNOWN_EVIDENCE_TYPE_WEIGHT).abs() < TOL,
        "this test assumes the served unknown-type weight is the default"
    );
    w
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_perspective_profile_object_moves_the_atom_fold_only_under_that_lens(pool: PgPool) {
    let w = served_unknown_weight();
    let author = agent(&pool).await;
    let atom = claim(&pool, author, "perspective").await;
    store_row(&pool, atom, frame(&pool, None).await).await;
    let lens = perspective(&pool, unknown_weight(0.2)).await;

    let (global, under_p) = global_and_lens(&pool, lens).await;
    let g = bel(&pool, atom, &global).await;
    let p = bel(&pool, atom, &under_p).await;
    assert!((g - T * w).abs() < TOL, "global Bel = .8 x {w}, got {g}");
    assert!((p - T * 0.2).abs() < TOL, "Bel under P = .8 x .2, got {p}");
    assert_ne!(
        global.profile_hash(),
        under_p.profile_hash(),
        "the lens's profile identity must differ from the global one"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_frame_profile_object_moves_only_the_rows_of_that_frame(pool: PgPool) {
    let w = served_unknown_weight();
    let author = agent(&pool).await;
    let on_override = claim(&pool, author, "frame override").await;
    let on_twin = claim(&pool, author, "frame twin").await;
    store_row(
        &pool,
        on_override,
        frame(&pool, Some(unknown_weight(0.2))).await,
    )
    .await;
    store_row(&pool, on_twin, frame(&pool, None).await).await;

    let global = FramedBeliefContext::global();
    let o = bel(&pool, on_override, &global).await;
    let t = bel(&pool, on_twin, &global).await;
    assert!(
        (o - T * 0.2).abs() < TOL,
        "the frame tier's .2 applies to its row, got {o}"
    );
    assert!(
        (t - T * w).abs() < TOL,
        "the twin frame's row keeps .8 x {w}, got {t}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_perspective_tier_wins_over_the_rows_frame_tier(pool: PgPool) {
    let author = agent(&pool).await;
    let atom = claim(&pool, author, "precedence").await;
    store_row(&pool, atom, frame(&pool, Some(unknown_weight(0.2))).await).await;
    let lens = perspective(&pool, unknown_weight(0.9)).await;

    let (global, under_p) = global_and_lens(&pool, lens).await;
    let g = bel(&pool, atom, &global).await;
    let p = bel(&pool, atom, &under_p).await;
    assert!(
        (g - T * 0.2).abs() < TOL,
        "global: the frame tier's .2, got {g}"
    );
    assert!(
        (p - T * 0.9).abs() < TOL,
        "under P: the perspective's .9 over the frame's .2, got {p}"
    );
}
