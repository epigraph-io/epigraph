//! Ruling R-22 (backlog fef24216): a BBA derived from a NON-PUBLIC source never
//! enters a PUBLIC claim's cached or served-to-everyone belief, and a member
//! of the source's group still gets the full belief through its own reads.
//!
//! # What was wrong, measured at origin/main before this file
//!
//! A `mass_functions` row inherits its claim's tenancy, so every BBA on a
//! public claim is public, whatever it was derived from. An edge-factor BBA
//! written for a group-private edge from a group-private claim carries that
//! claim's belief onto the public target, and every fold of the target
//! (the cache recompute, the framed `get_belief` for ANY viewer) included it:
//! a public reader's Bel/Pl moved with private evidence it cannot see. The
//! same holds for a BBA citing an evidence row narrowed to a private group.
//!
//! # The oracle
//!
//! The public claim's belief from its public BBA alone (read before the
//! private-derived BBA exists). After the private-derived BBA is written and
//! the cache recomputed AS THE MEMBER, the cache and a public reader's framed
//! read must still equal it exactly; the member's framed read must be higher
//! (it folds both).
//!
//! On the `#[sqlx::test]` superuser pool the viewer predicates decide (row
//! security is bypassed), which is what pins the derivation rule itself.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::Viewer;
use epigraph_db::PgPool;
use epigraph_engine::belief_query;
use epigraph_engine::edge_factor::{
    auto_wire_ds_for_edge, ensure_binary_frame, recompute_claim_cached_belief, EdgeFactorOutcome,
};
use uuid::Uuid;

/// A claim whose stored interval is (bel, pl), so an edge from it wires a BBA.
async fn with_interval(pool: &PgPool, claim: Uuid, bel: f64, pl: f64) {
    sqlx::query("UPDATE claims SET belief = $2, plausibility = $3 WHERE id = $1")
        .bind(claim)
        .bind(bel)
        .bind(pl)
        .execute(pool)
        .await
        .expect("set the source interval");
}

/// The claim's cached (BetP, Bel, Pl): ruling R-22 names the whole interval
/// ("truth/pignistic/Bel/Pl caches"), not only BetP.
async fn cached(pool: &PgPool, claim: Uuid) -> (f64, f64, f64) {
    let row: (Option<f64>, Option<f64>, Option<f64>) =
        sqlx::query_as("SELECT pignistic_prob, belief, plausibility FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(pool)
            .await
            .expect("read the cache");
    match row {
        (Some(b), Some(bel), Some(pl)) => (b, bel, pl),
        other => panic!("the cache is filled: {other:?}"),
    }
}

fn close(a: (f64, f64, f64), b: (f64, f64, f64)) -> bool {
    (a.0 - b.0).abs() < 1e-9 && (a.1 - b.1).abs() < 1e-9 && (a.2 - b.2).abs() < 1e-9
}

/// Strictly more support on both BetP and Bel.
fn above(a: (f64, f64, f64), b: (f64, f64, f64)) -> bool {
    a.0 > b.0 + 1e-3 && a.1 > b.1 + 1e-3
}

async fn edge_visibility(pool: &PgPool, edge: Uuid) -> String {
    sqlx::query_scalar("SELECT visibility::text FROM edges WHERE id = $1")
        .bind(edge)
        .fetch_one(pool)
        .await
        .expect("edge")
}

async fn wire(pool: &PgPool, viewer: &Viewer, signer: Uuid, edge: Uuid, from: Uuid, to: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = auto_wire_ds_for_edge(&mut conn, viewer, edge, signer, from, to, "supports")
        .await
        .expect("wire the edge factor");
    assert_eq!(
        out,
        EdgeFactorOutcome::Wired,
        "PREMISE: the edge wires a BBA"
    );
}

async fn framed(pool: &PgPool, viewer: &Viewer, claim: Uuid, frame: Uuid) -> (f64, f64, f64) {
    let b = belief_query::get_belief(pool, viewer, claim, Some(frame))
        .await
        .expect("framed get_belief");
    (b.pignistic_prob, b.belief, b.plausibility)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_private_edge_factor_never_enters_a_public_claims_belief(pool: PgPool) {
    let public = fixture::public_viewer(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "r22-member").await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "r22-author").await;
    let member_viewer = Viewer::resolve(&pool, member).await.expect("member viewer");
    let frame = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary_truth");

    let target = fixture::seed_public_claim(&pool, author, "r22 public target").await;
    let public_source = fixture::seed_public_claim(&pool, author, "r22 public source").await;
    let private_source =
        fixture::seed_group_claim(&pool, member, group, "r22 group-private source").await;
    with_interval(&pool, public_source, 0.6, 0.8).await;
    with_interval(&pool, private_source, 0.9, 0.95).await;

    // The public BBA: a public edge from a public claim.
    let public_edge = fixture::seed_edge(&pool, public_source, target).await;
    assert_eq!(edge_visibility(&pool, public_edge).await, "public");
    wire(&pool, &public, author, public_edge, public_source, target).await;
    let public_only = cached(&pool, target).await;
    assert!(
        close(framed(&pool, &public, target, frame).await, public_only),
        "PREMISE: the framed read agrees with the cache"
    );

    // The private-derived BBA: the member's edge from its group's claim. The
    // trigger makes the edge the group's; the BBA row is the PUBLIC target's.
    let private_edge = fixture::seed_edge(&pool, private_source, target).await;
    assert_ne!(
        edge_visibility(&pool, private_edge).await,
        "public",
        "PREMISE: an edge from a group-private claim is not public"
    );
    wire(
        &pool,
        &member_viewer,
        member,
        private_edge,
        private_source,
        target,
    )
    .await;
    // The member's recompute is the one that used to write the leak.
    let mut conn = pool.acquire().await.expect("acquire");
    recompute_claim_cached_belief(&mut conn, &member_viewer, target)
        .await
        .expect("recompute as the member");
    drop(conn);

    let cached = cached(&pool, target).await;
    assert!(
        close(cached, public_only),
        "the public claim's cached belief moved with a group-private edge factor: \
         {public_only:?} -> {cached:?}"
    );
    let public_read = framed(&pool, &public, target, frame).await;
    assert!(
        close(public_read, public_only),
        "a public reader's framed belief folded a group-private edge factor: \
         {public_only:?} -> {public_read:?}"
    );
    let member_read = framed(&pool, &member_viewer, target, frame).await;
    assert!(
        above(member_read, public_only),
        "the group member's own read must still fold both BBAs: {member_read:?} vs {public_only:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_bba_citing_group_private_evidence_never_enters_a_public_claims_belief(pool: PgPool) {
    let public = fixture::public_viewer(&pool).await;
    let (member, group) = fixture::seed_agent_with_group(&pool, "r22-ev-member").await;
    let (author, _) = fixture::seed_agent_with_group(&pool, "r22-ev-author").await;
    let member_viewer = Viewer::resolve(&pool, member).await.expect("member viewer");
    let frame = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary_truth");
    let target = fixture::seed_public_claim(&pool, author, "r22 evidence target").await;
    let store = |agent: Uuid, evidence: Option<Uuid>, perspective: Option<Uuid>, t: f64| {
        let pool = pool.clone();
        async move {
            epigraph_db::MassFunctionRepository::store_with_perspective(
                &pool,
                target,
                frame,
                Some(agent),
                perspective,
                &serde_json::json!({"0": t, "0,1": 1.0 - t}),
                None,
                Some("auto_wire"),
                Some(1.0),
                None,
                "unknown",
                evidence,
            )
            .await
            .expect("store a BBA")
        }
    };

    // The public BBA cites public evidence on the claim.
    let public_ev = fixture::seed_evidence(&pool, target, "observation").await;
    epigraph_db::PerspectiveRepository::ensure_evidence_perspective(&pool, public_ev, Some(author))
        .await
        .expect("evidence perspective");
    store(author, Some(public_ev), Some(public_ev), 0.6).await;
    let mut conn = pool.acquire().await.expect("acquire");
    recompute_claim_cached_belief(&mut conn, &public, target)
        .await
        .expect("recompute");
    drop(conn);
    let public_only = cached(&pool, target).await;

    // The second BBA cites evidence narrowed to the member's group (the shape
    // `epigraph-operator hide-evidence` leaves: the BBA row stays public).
    let hidden_ev = fixture::seed_evidence(&pool, target, "document").await;
    // Pinned, as `epigraph-operator hide-evidence` pins it (migration 110):
    // without the pin the next evidence INSERT on the claim re-publishes it.
    sqlx::query(
        "INSERT INTO evidence_visibility_pins (evidence_id, pinned_by, reason) \
         VALUES ($1, $2, 'test: hidden')",
    )
    .bind(hidden_ev)
    .bind(member)
    .execute(&pool)
    .await
    .expect("pin the hidden evidence");
    sqlx::query("UPDATE evidence SET visibility = 'group', owner_group_id = $2 WHERE id = $1")
        .bind(hidden_ev)
        .bind(group)
        .execute(&pool)
        .await
        .expect("narrow the evidence to the group");
    epigraph_db::PerspectiveRepository::ensure_evidence_perspective(&pool, hidden_ev, Some(member))
        .await
        .expect("evidence perspective");
    store(member, Some(hidden_ev), Some(hidden_ev), 0.8).await;
    let mut conn = pool.acquire().await.expect("acquire");
    recompute_claim_cached_belief(&mut conn, &member_viewer, target)
        .await
        .expect("recompute as the member");
    drop(conn);

    let cached = cached(&pool, target).await;
    assert!(
        close(cached, public_only),
        "the public claim's cache folded a BBA citing group-private evidence: \
         {public_only:?} -> {cached:?}"
    );
    let public_read = framed(&pool, &public, target, frame).await;
    assert!(
        close(public_read, public_only),
        "a public reader folded a BBA citing group-private evidence: {public_read:?}"
    );
    let member_read = framed(&pool, &member_viewer, target, frame).await;
    assert!(
        above(member_read, public_only),
        "the group member's own read must still fold both BBAs: {member_read:?} vs {public_only:?}"
    );
}

/// A team group with no members yet.
async fn team_group(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind) \
         VALUES ($1, 'did:test:r22:' || gen_random_uuid(), decode(repeat('ab', 32), 'hex'), \
                 'team') RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("team group")
}

async fn join(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("membership");
}

/// The security review's generalisation of R-22: a GROUP claim's cache is
/// read by every member of its group, so a BBA derived from ANOTHER group's
/// private source must not enter it either. A member of only the claim's
/// group reads the belief without it; a member of both still gets both.
#[sqlx::test(migrations = "../../migrations")]
async fn another_groups_private_edge_factor_never_enters_a_group_claims_cache(pool: PgPool) {
    let public = fixture::public_viewer(&pool).await;
    let group_a = team_group(&pool, "r22 group A").await;
    let group_b = team_group(&pool, "r22 group B").await;
    let (both, _) = fixture::seed_agent_with_group(&pool, "r22-both").await;
    let (only_a, _) = fixture::seed_agent_with_group(&pool, "r22-only-a").await;
    join(&pool, group_a, both, "admin").await;
    join(&pool, group_b, both, "admin").await;
    join(&pool, group_a, only_a, "reader").await;
    let both_viewer = Viewer::resolve(&pool, both).await.expect("viewer");
    let a_viewer = Viewer::resolve(&pool, only_a).await.expect("viewer");
    let frame = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary_truth");

    let target = fixture::seed_group_claim(&pool, both, group_a, "r22 group-A target").await;
    let a_source = fixture::seed_group_claim(&pool, both, group_a, "r22 group-A source").await;
    let b_source = fixture::seed_group_claim(&pool, both, group_b, "r22 group-B source").await;
    with_interval(&pool, a_source, 0.6, 0.8).await;
    with_interval(&pool, b_source, 0.9, 0.95).await;

    // The group's own BBA: an edge between two of group A's claims.
    let a_edge = fixture::seed_edge(&pool, a_source, target).await;
    wire(&pool, &both_viewer, both, a_edge, a_source, target).await;
    let own_only = cached(&pool, target).await;
    assert!(
        close(framed(&pool, &a_viewer, target, frame).await, own_only),
        "PREMISE: a group-A reader's framed read agrees with the cache"
    );

    // Group B's: an edge from group B's claim, which the trigger co-owns.
    let b_edge = fixture::seed_edge(&pool, b_source, target).await;
    wire(&pool, &both_viewer, both, b_edge, b_source, target).await;
    let mut conn = pool.acquire().await.expect("acquire");
    recompute_claim_cached_belief(&mut conn, &both_viewer, target)
        .await
        .expect("recompute as the member of both groups");
    drop(conn);

    let cached = cached(&pool, target).await;
    assert!(
        close(cached, own_only),
        "group A's claim cached a BBA derived from group B's private claim: \
         {own_only:?} -> {cached:?}"
    );
    let a_read = framed(&pool, &a_viewer, target, frame).await;
    assert!(
        close(a_read, own_only),
        "a member of group A only folded group B's source: {own_only:?} -> {a_read:?}"
    );
    let both_read = framed(&pool, &both_viewer, target, frame).await;
    assert!(
        above(both_read, own_only),
        "a member of both groups must still fold both BBAs: {both_read:?} vs {own_only:?}"
    );
}
