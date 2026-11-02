//! `supersedes` carries no mass (supersede SPEC §11 K12(b); backlog 3ce5e00c,
//! its `supersedes` part).
//!
//! A `supersedes` edge records lineage: the newer claim replaces the older
//! one. It is not evidence that the older claim is false, so the restriction
//! map must not read it as a contradiction. Before K12(b) the engine mapped it
//! to `Negative(profile.contradicts)`, so an auto-wired `supersedes` edge
//! wrote a contradiction-shaped BBA onto its target and the sheaf counted it
//! as a negative restriction.
//!
//! Each assertion is paired with a control on `contradicts`, the relationship
//! `supersedes` used to borrow its strength from: a mapping that turned every
//! relationship Neutral would fail the control, not pass the pin.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::PgPool;
use epigraph_engine::edge_factor::{auto_wire_ds_for_edge, ensure_binary_frame, EdgeFactorOutcome};
use epigraph_engine::sheaf::{
    compute_edge_inconsistency, restriction_kind_with_profile, RestrictionKind, RestrictionProfile,
};
use uuid::Uuid;

#[test]
fn supersedes_is_a_neutral_restriction_in_every_profile_and_spelling() {
    for profile in [
        RestrictionProfile::scientific(),
        RestrictionProfile::regulatory(),
    ] {
        for rel in ["supersedes", "SUPERSEDES", "Supersedes"] {
            assert!(
                matches!(
                    restriction_kind_with_profile(rel, &profile),
                    RestrictionKind::Neutral
                ),
                "`{rel}` under the {} profile must be Neutral (lineage carries no mass); got {:?}",
                profile.name,
                restriction_kind_with_profile(rel, &profile)
            );
        }
        // Control: the relationship it used to borrow from is still negative.
        assert!(
            matches!(
                restriction_kind_with_profile("contradicts", &profile),
                RestrictionKind::Negative(f) if (f - profile.contradicts).abs() < 1e-12
            ),
            "control: contradicts stays Negative(profile.contradicts)"
        );
    }
}

#[test]
fn a_supersedes_edge_is_never_a_sheaf_obstruction() {
    // A believed source and a believed target: as a contradiction this pair is
    // maximally inconsistent (expected target <= 1 - 0.9 * 0.9 = 0.19).
    let (inconsistency, expected) = compute_edge_inconsistency(0.9, 0.9, "supersedes");
    assert_eq!(
        (inconsistency, expected),
        (0.0, 0.9),
        "a Neutral restriction contributes no inconsistency and expects the target as it is"
    );
    let (control, _) = compute_edge_inconsistency(0.9, 0.9, "contradicts");
    assert!(
        control > 0.7,
        "control: the same pair under contradicts is an obstruction (got {control})"
    );
}

async fn believed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, content).await;
    sqlx::query("UPDATE claims SET belief = 0.9, plausibility = 0.95 WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("give the source an interval");
    id
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, rel: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("insert edge")
}

async fn rows_keyed_on(pool: &PgPool, edge_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE perspective_id = $1")
        .bind(edge_id)
        .fetch_one(pool)
        .await
        .expect("count edge-keyed rows")
}

/// The DS half: `auto_wire_ds_for_edge` short-circuits on a Neutral
/// restriction, so a `supersedes` edge from a believed source writes no BBA
/// and leaves the target's cache alone. The control edge, from an identically
/// believed source onto an identical target, does wire.
#[sqlx::test(migrations = "../../migrations")]
async fn a_supersedes_edge_gets_no_auto_wired_bba(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "k12b-author").await;
    ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &viewer)
        .await
        .expect("binary frame");

    let newer = believed_claim(&pool, agent, "k12b newer").await;
    let older = fixture::seed_public_claim(&pool, agent, "k12b older").await;
    let lineage = edge(&pool, newer, older, "supersedes").await;

    let rival = believed_claim(&pool, agent, "k12b rival").await;
    let attacked = fixture::seed_public_claim(&pool, agent, "k12b attacked").await;
    let control = edge(&pool, rival, attacked, "contradicts").await;

    let mut conn = pool.acquire().await.expect("acquire");
    let got = auto_wire_ds_for_edge(
        &mut conn,
        &viewer,
        lineage,
        agent,
        newer,
        older,
        "supersedes",
    )
    .await
    .expect("auto-wire the supersedes edge");
    let control_got = auto_wire_ds_for_edge(
        &mut conn,
        &viewer,
        control,
        agent,
        rival,
        attacked,
        "contradicts",
    )
    .await
    .expect("auto-wire the control edge");
    drop(conn);

    assert_eq!(
        control_got,
        EdgeFactorOutcome::Wired,
        "control: a contradicts edge from a believed source wires"
    );
    assert_eq!(rows_keyed_on(&pool, control).await, 1, "control row stored");

    assert_eq!(
        got,
        EdgeFactorOutcome::NonEpistemic,
        "a supersedes edge must short-circuit as non-epistemic"
    );
    assert_eq!(
        rows_keyed_on(&pool, lineage).await,
        0,
        "no BBA may be keyed on a supersedes edge"
    );
    let older_cache: Option<f64> =
        sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
            .bind(older)
            .fetch_one(&pool)
            .await
            .expect("read the older claim's cache");
    assert_eq!(
        older_cache, None,
        "the superseded claim's cache is not written by its lineage edge"
    );
}
