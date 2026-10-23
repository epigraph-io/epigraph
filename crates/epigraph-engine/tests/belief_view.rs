//! A compound's belief derived per viewer from its visible leaves, the
//! `BeliefView` read shape and the readiness predicates (atom-level belief
//! program, PR-6; SPEC §2.2 spine, §3.2 statistics, §3.3 R-DEP, Legacy
//! pseudo-items and D11, §3.5 `BeliefView`, §3.6 `not_all`, §7.1 readiness,
//! §8 T1/T4 tenancy).
//!
//! Expected values are absolute numbers from the SPEC's worked examples (and
//! the design note's Example 3), sentinels, twin fixtures, or the value
//! another read path serves for the same rows; none is computed here by the
//! operator under test.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::HashMap;

use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository, Viewer};
use epigraph_engine::atom_items::{atom_axiom_rows, atom_fold, AxiomMode};
use epigraph_engine::belief_query::{get_perspective_belief, shadow_belief, FramedBeliefContext};
use epigraph_engine::belief_view::{Basis, BeliefView, CompoundBeliefMode, LeafState};
use epigraph_engine::calibration::CalibrationConfig;
use epigraph_engine::compound_belief::{
    atom_belief_view_batch, compound_ready_batch, derive_compound_belief_batch, leaf_states_batch,
};
use sqlx::PgPool;
use uuid::Uuid;

// ── fixtures ────────────────────────────────────────────────────────────────

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
    fixture::seed_public_claim(pool, author, &format!("bv {what} {}", Uuid::new_v4())).await
}

async fn group_claim(pool: &PgPool, author: Uuid, group: Uuid, what: &str) -> Uuid {
    fixture::seed_group_claim(
        pool,
        author,
        group,
        &format!("bv {what} {}", Uuid::new_v4()),
    )
    .await
}

async fn frame(pool: &PgPool, name: &str, hyps: &[&str]) -> Uuid {
    let viewer = fixture::public_viewer(pool).await;
    if let Some(f) = FrameRepository::get_by_name(pool, &viewer, name)
        .await
        .expect("frame lookup")
    {
        return f.id;
    }
    FrameRepository::create(
        pool,
        name,
        None,
        &hyps.iter().map(|h| (*h).to_string()).collect::<Vec<_>>(),
    )
    .await
    .expect("frame")
    .id
}

async fn binary(pool: &PgPool) -> Uuid {
    frame(pool, "binary_truth", &["TRUE", "FALSE"]).await
}

/// One BBA row on `binary_truth`. With `evidence_type` `None` and
/// `source_strength` 1.0 its reliability is exactly 1 whatever the
/// calibration.
#[derive(Clone)]
struct Row {
    agent: Option<Uuid>,
    perspective: Option<Uuid>,
    method: Option<&'static str>,
    strength: Option<f64>,
    evidence_type: Option<&'static str>,
    evidence: Option<Uuid>,
}

impl Row {
    fn plain(agent: Uuid) -> Self {
        Self {
            agent: Some(agent),
            perspective: None,
            method: None,
            strength: Some(1.0),
            evidence_type: None,
            evidence: None,
        }
    }
}

async fn store(pool: &PgPool, claim: Uuid, row: Row, masses: serde_json::Value) -> Uuid {
    let b = binary(pool).await;
    store_on(pool, claim, b, row, masses).await
}

/// One BBA row on frame `frame_id`.
async fn store_on(
    pool: &PgPool,
    claim: Uuid,
    frame_id: Uuid,
    row: Row,
    masses: serde_json::Value,
) -> Uuid {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame_id,
        row.agent,
        row.perspective,
        &masses,
        None,
        row.method,
        row.strength,
        row.evidence_type,
        "unknown",
        row.evidence,
    )
    .await
    .expect("store BBA")
}

/// An independent item: its own agent, no perspective, no evidence.
async fn support(pool: &PgPool, claim: Uuid, t: f64) -> Uuid {
    let a = agent(pool).await;
    store(
        pool,
        claim,
        Row::plain(a),
        serde_json::json!({"0": t, "0,1": 1.0 - t}),
    )
    .await
}

async fn refute(pool: &PgPool, claim: Uuid, f: f64) -> Uuid {
    let a = agent(pool).await;
    store(
        pool,
        claim,
        Row::plain(a),
        serde_json::json!({"1": f, "0,1": 1.0 - f}),
    )
    .await
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("edge")
}

async fn decompose(pool: &PgPool, parent: Uuid, child: Uuid) -> Uuid {
    edge(pool, parent, child, "decomposes_to").await
}

/// Make an edge private to `group` (its owner group, no co-owner).
async fn hide_edge(pool: &PgPool, edge_id: Uuid, group: Uuid) {
    sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE id = $1",
    )
    .bind(edge_id)
    .bind(group)
    .execute(pool)
    .await
    .expect("make the edge private");
}

/// Make a stored BBA row private to `group`.
async fn hide_row(pool: &PgPool, row_id: Uuid, group: Uuid) {
    sqlx::query(
        "UPDATE mass_functions SET visibility = 'group', owner_group_id = $2 WHERE id = $1",
    )
    .bind(row_id)
    .bind(group)
    .execute(pool)
    .await
    .expect("make the row private");
}

/// A row citing evidence `ev` (perspective and evidence both `ev`), as the
/// ingest or a submission files a text-bearing BBA.
fn citing(writer: Uuid, ev: Uuid) -> Row {
    Row {
        perspective: Some(ev),
        evidence: Some(ev),
        ..Row::plain(writer)
    }
}

/// An `attributed_v1` row citing evidence `ev`, with `masses`.
async fn attribute(
    pool: &PgPool,
    atom: Uuid,
    ev: Uuid,
    writer: Uuid,
    masses: serde_json::Value,
) -> Uuid {
    store(
        pool,
        atom,
        Row {
            method: Some("attributed_v1"),
            ..citing(writer, ev)
        },
        masses,
    )
    .await
}

/// A compound over `n` fresh leaves. Returns (compound, leaves).
async fn compound_of(pool: &PgPool, author: Uuid, what: &str, n: usize) -> (Uuid, Vec<Uuid>) {
    let k = claim(pool, author, what).await;
    let mut leaves = Vec::with_capacity(n);
    for i in 0..n {
        let l = claim(pool, author, &format!("{what} leaf {i}")).await;
        decompose(pool, k, l).await;
        leaves.push(l);
    }
    (k, leaves)
}

/// An evidence row on `holder` carrying `properties.doi`, plus the evidence
/// perspective a citation of it uses.
async fn doi_evidence(pool: &PgPool, holder: Uuid, doi: &str, cite_agent: Uuid) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO evidence (claim_id, evidence_type, content_hash, properties) \
         VALUES ($1, 'document', sha256(gen_random_uuid()::text::bytea), \
                 jsonb_build_object('doi', $2::text)) RETURNING id",
    )
    .bind(holder)
    .bind(doi)
    .fetch_one(pool)
    .await
    .expect("evidence");
    PerspectiveRepository::ensure_evidence_perspective(pool, id, Some(cite_agent))
        .await
        .expect("evidence perspective");
    id
}

/// An `attributed_v1` row citing evidence `ev` on `atom`.
async fn store_attributed(pool: &PgPool, atom: Uuid, ev: Uuid, writer: Uuid, t: f64) -> Uuid {
    store(
        pool,
        atom,
        Row {
            perspective: Some(ev),
            evidence: Some(ev),
            method: Some("attributed_v1"),
            ..Row::plain(writer)
        },
        serde_json::json!({"0": t, "0,1": 1.0 - t}),
    )
    .await
}

/// An edge-factor row on `target` for edge `edge_id`: perspective = edge id.
async fn store_edge_factor(
    pool: &PgPool,
    edge_id: Uuid,
    target: Uuid,
    masses: serde_json::Value,
) -> Uuid {
    sqlx::query("INSERT INTO perspectives (id, name) VALUES ($1, 'edge') ON CONFLICT DO NOTHING")
        .bind(edge_id)
        .execute(pool)
        .await
        .expect("edge perspective");
    let w = agent(pool).await;
    store(
        pool,
        target,
        Row {
            perspective: Some(edge_id),
            method: Some("edge_factor"),
            ..Row::plain(w)
        },
        masses,
    )
    .await
}

/// Write a cache on a claim: the shape a legacy writer leaves.
async fn set_cache(pool: &PgPool, id: Uuid, bel: f64, pl: f64, betp: f64, missing: f64) {
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4, \
         mass_on_empty = 0, mass_on_missing = $5 WHERE id = $1",
    )
    .bind(id)
    .bind(bel)
    .bind(pl)
    .bind(betp)
    .bind(missing)
    .execute(pool)
    .await
    .expect("set cache");
}

async fn cache_is_null(pool: &PgPool, id: Uuid) -> bool {
    let (b, p): (Option<f64>, Option<f64>) =
        sqlx::query_as("SELECT belief, plausibility FROM claims WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("cache");
    b.is_none() && p.is_none()
}

async fn set_level(pool: &PgPool, id: Uuid, level: &str) {
    sqlx::query(
        "UPDATE claims SET properties = properties || jsonb_build_object('level', $2::text) \
         WHERE id = $1",
    )
    .bind(id)
    .bind(level)
    .execute(pool)
    .await
    .expect("set level");
}

fn ctx() -> FramedBeliefContext {
    FramedBeliefContext::new(CalibrationConfig::default_for_phase2_fallback(), None)
}

async fn derive_as(
    pool: &PgPool,
    viewer: &Viewer,
    ids: &[Uuid],
    lens: &FramedBeliefContext,
) -> HashMap<Uuid, BeliefView> {
    let mut conn = pool.acquire().await.expect("conn");
    derive_compound_belief_batch(&mut conn, viewer, ids, lens)
        .await
        .expect("derive")
}

async fn derive(pool: &PgPool, id: Uuid) -> BeliefView {
    let viewer = fixture::public_viewer(pool).await;
    derive_as(pool, &viewer, &[id], &ctx())
        .await
        .remove(&id)
        .expect("a visible compound has a derived view")
}

async fn derive_one_as(pool: &PgPool, viewer: &Viewer, id: Uuid) -> BeliefView {
    derive_as(pool, viewer, &[id], &ctx())
        .await
        .remove(&id)
        .expect("a visible compound has a derived view")
}

fn near(a: f64, b: f64, tol: f64) -> bool {
    (a - b).abs() < tol
}

/// A view as JSON without its claim id: everything it discloses.
fn disclosed(v: &BeliefView) -> serde_json::Value {
    let mut j = serde_json::to_value(v).expect("serialize");
    j.as_object_mut().expect("object").remove("claim_id");
    j
}

/// Whether two disclosed views are the same: the same keys and non-float
/// values everywhere, and floats within 1e-12. (A twin's items have other
/// row ids, so the conjunction may sum them in another order; rounding to a
/// grid instead would split two values one ulp apart across a boundary.)
fn same_disclosure(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    use serde_json::Value::{Array, Number, Object};
    match (a, b) {
        (Number(x), Number(y)) if x.is_f64() || y.is_f64() => match (x.as_f64(), y.as_f64()) {
            (Some(x), Some(y)) => (x - y).abs() <= 1e-12,
            _ => false,
        },
        (Array(x), Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same_disclosure(x, y))
        }
        (Object(x), Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| same_disclosure(v, w)))
        }
        _ => a == b,
    }
}

// ── (1), (2): Example 3, leak by division and per-viewer leaf sets ──────────

/// The design note's Example 3: root R decomposes to mids M1 = {a1, a2} and
/// M2 = {a2, a3} (a2 shared), plus a private atom a4 visible only to one
/// group. a1 t .9, a3 t .6, a4 t .95, a2 a support .7 and an independent
/// refutation .5. Returns (R, M1, a4).
async fn example_three(pool: &PgPool, private: Option<(Uuid, Uuid)>) -> (Uuid, Uuid, Option<Uuid>) {
    let author = agent(pool).await;
    let r = claim(pool, author, "R").await;
    let m1 = claim(pool, author, "M1").await;
    let m2 = claim(pool, author, "M2").await;
    let a1 = claim(pool, author, "a1").await;
    let a2 = claim(pool, author, "a2").await;
    let a3 = claim(pool, author, "a3").await;
    for (p, c) in [(r, m1), (r, m2), (m1, a1), (m1, a2), (m2, a2), (m2, a3)] {
        decompose(pool, p, c).await;
    }
    support(pool, a1, 0.9).await;
    support(pool, a2, 0.7).await;
    refute(pool, a2, 0.5).await;
    support(pool, a3, 0.6).await;
    let a4 = match private {
        Some((member, group)) => {
            let a4 = group_claim(pool, member, group, "a4").await;
            decompose(pool, r, a4).await;
            support(pool, a4, 0.95).await;
            Some(a4)
        }
        None => None,
    };
    (r, m1, a4)
}

/// Plan test (1), leak by division (D§3.3 Ex. 3). The public viewer's value
/// is the conjunction over {a1, a2, a3}: .2908, flattened (mid composition
/// would give .149). The group sees a4 too: .2762. Changing a4's evidence
/// moves the group's value and leaves the public value exactly as it was, so
/// the public number carries nothing about a4.
#[sqlx::test(migrations = "../../migrations")]
async fn the_public_value_is_identical_whatever_the_hidden_atom_holds(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "bv-owner").await;
    let owner = Viewer::resolve(&pool, member).await.expect("owner viewer");
    let public = fixture::public_viewer(&pool).await;
    let (r, _, a4) = example_three(&pool, Some((member, group))).await;
    let a4 = a4.expect("a4");

    let pub_before = derive_one_as(&pool, &public, r).await;
    let grp_before = derive_one_as(&pool, &owner, r).await;
    assert_eq!(pub_before.basis, Basis::Derived);
    assert!(
        near(pub_before.bel, 0.2908, 5e-5),
        "public R-DEP over the flattened visible leaves is .2908, got {}",
        pub_before.bel
    );
    assert!(
        near(pub_before.pl, 0.7692, 5e-5),
        "public Pl is a2's .7692, got {}",
        pub_before.pl
    );
    assert!(
        near(grp_before.bel, 0.2762, 5e-5),
        "the group sees a4 too: .2762, got {}",
        grp_before.bel
    );

    // The hidden atom's evidence changes.
    refute(&pool, a4, 0.9).await;
    let pub_after = derive_one_as(&pool, &public, r).await;
    let grp_after = derive_one_as(&pool, &owner, r).await;
    assert_eq!(
        pub_after, pub_before,
        "the public view must not move when only a hidden atom changes"
    );
    assert!(
        grp_after.bel < grp_before.bel - 0.05,
        "control: the group's view does move ({} -> {})",
        grp_before.bel,
        grp_after.bel
    );
}

/// Plan test (2). A mixed-visibility compound gives each viewer its own
/// `leaves_used`, and the public response is exactly the response for a twin
/// tree that has no private atom at all: nothing in it (no total, no hidden
/// count, no partial flag) tells the two apart.
#[sqlx::test(migrations = "../../migrations")]
async fn each_viewer_counts_its_own_leaves_and_no_response_exposes_a_total(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "bv-owner").await;
    let owner = Viewer::resolve(&pool, member).await.expect("owner viewer");
    let public = fixture::public_viewer(&pool).await;
    let (r, _, _) = example_three(&pool, Some((member, group))).await;
    let (twin, _, _) = example_three(&pool, None).await;

    let pub_view = derive_one_as(&pool, &public, r).await;
    let grp_view = derive_one_as(&pool, &owner, r).await;
    let used = |v: &BeliefView| v.derived.as_ref().expect("derived").leaves_used;
    assert_eq!(used(&pub_view), 3, "public sees a1, a2, a3");
    assert_eq!(used(&grp_view), 4, "the group also sees a4");

    let twin_view = derive_one_as(&pool, &public, twin).await;
    let (pub_json, twin_json) = (disclosed(&pub_view), disclosed(&twin_view));
    assert!(
        same_disclosure(&pub_json, &twin_json),
        "the public response over a tree with a private atom must be the response over \
         a tree without one:\n{pub_json}\n{twin_json}"
    );
}

/// A compound's view does not depend on which other compounds share its
/// batch. R = {a1, a2} and S = {b1, b2} share no leaf, but one paper is cited
/// on a2 and on b1, so one item spans both compounds' leaves once S is in the
/// batch. b1 also carries an independent refutation and a row with mass on a
/// set the conjunction cannot spell (`~0`), which makes S inexact. None of
/// that is R's evidence: R's whole view (value, `exact`, item count) is the
/// same alone, after S and before S.
#[sqlx::test(migrations = "../../migrations")]
async fn a_compound_s_view_does_not_depend_on_its_batch(pool: PgPool) {
    let public = fixture::public_viewer(&pool).await;
    let author = agent(&pool).await;
    let holder = claim(&pool, author, "evidence holder").await;
    let (x, y) = (agent(&pool).await, agent(&pool).await);
    let (r, a) = compound_of(&pool, author, "R", 2).await;
    let (s, b) = compound_of(&pool, author, "S", 2).await;
    support(&pool, a[0], 0.9).await;
    let e1 = doi_evidence(&pool, holder, "10.5555/bv-batch", x).await;
    let e2 = doi_evidence(&pool, holder, "10.5555/bv-batch", y).await;
    store_attributed(&pool, a[1], e1, x, 0.8).await;
    store_attributed(&pool, b[0], e2, y, 0.6).await;
    refute(&pool, b[0], 0.5).await;
    store(
        &pool,
        b[0],
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.3, "~0": 0.2, "0,1": 0.5}),
    )
    .await;
    support(&pool, b[1], 0.7).await;

    let alone = derive_as(&pool, &public, &[r], &ctx()).await;
    let s_first = derive_as(&pool, &public, &[s, r], &ctx()).await;
    let r_first = derive_as(&pool, &public, &[r, s], &ctx()).await;
    let sv = s_first[&s].derived.as_ref().expect("S is derived");
    assert_eq!(
        sv.leaves_used, 2,
        "precondition: S's leaves are in the batch, so the batch atom sets differ"
    );
    assert!(
        !sv.exact,
        "precondition: S reads a set it cannot spell, so S is labelled inexact"
    );

    let rv = &alone[&r];
    assert!(
        near(rv.bel, 0.72, 1e-9),
        "R = a1 (.9) ∧ a2 (.8 from the shared paper): .72, got {}",
        rv.bel
    );
    assert!(rv.derived.as_ref().expect("derived").exact);
    assert_eq!(
        rv.inputs.items, 2,
        "R reads a1's item and the shared paper's item once"
    );
    assert_eq!(Some(rv), s_first.get(&r), "R after S in the batch");
    assert_eq!(Some(rv), r_first.get(&r), "R before S in the batch");
}

/// A mid node is derived over its own flattened leaves: M1 = a1 ∧ a2 of the
/// design note's Example 3 is .4846.
#[sqlx::test(migrations = "../../migrations")]
async fn a_mid_node_is_derived_over_its_own_leaves(pool: PgPool) {
    let public = fixture::public_viewer(&pool).await;
    let (_, m1, _) = example_three(&pool, None).await;
    let v = derive_one_as(&pool, &public, m1).await;
    assert!(
        near(v.bel, 0.4846, 5e-5),
        "M1 = a1 ∧ a2 over its own leaves (.4846), got {}",
        v.bel
    );
}

// ── (3) readiness ───────────────────────────────────────────────────────────

/// Plan test (3). P2 is false iff some visible leaf is served `Legacy`; an
/// unevidenced, uncached (unproven) leaf does not block readiness. A private
/// `Legacy` leaf blocks only the viewer who can see it (SPEC §8 T4).
#[sqlx::test(migrations = "../../migrations")]
async fn readiness_is_blocked_only_by_a_visible_legacy_leaf(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "bv-owner").await;
    let owner = Viewer::resolve(&pool, member).await.expect("owner viewer");
    let public = fixture::public_viewer(&pool).await;
    let author = agent(&pool).await;

    let evidenced = claim(&pool, author, "evidenced").await;
    support(&pool, evidenced, 0.8).await;
    let vacuous = claim(&pool, author, "vacuous").await;
    let cached = claim(&pool, author, "cached").await;
    set_cache(&pool, cached, 0.6, 0.9, 0.75, 0.0).await;
    let hidden_cached = group_claim(&pool, member, group, "hidden cached").await;
    set_cache(&pool, hidden_cached, 0.6, 0.9, 0.75, 0.0).await;
    assert!(
        cache_is_null(&pool, vacuous).await,
        "precondition: a fresh leaf has no cache"
    );

    let ready = claim(&pool, author, "evidenced + vacuous").await;
    let blocked = claim(&pool, author, "evidenced + vacuous + cached").await;
    let per_viewer = claim(&pool, author, "evidenced + private cached").await;
    for c in [evidenced, vacuous] {
        decompose(&pool, ready, c).await;
        decompose(&pool, blocked, c).await;
    }
    decompose(&pool, blocked, cached).await;
    decompose(&pool, per_viewer, evidenced).await;
    decompose(&pool, per_viewer, hidden_cached).await;

    let mut conn = pool.acquire().await.expect("conn");
    let states = leaf_states_batch(&mut conn, &public, &[evidenced, vacuous, cached], &ctx())
        .await
        .expect("leaf states");
    assert_eq!(states.get(&evidenced), Some(&LeafState::Axiom));
    assert_eq!(states.get(&vacuous), Some(&LeafState::Unproven));
    assert_eq!(states.get(&cached), Some(&LeafState::Legacy));

    let p2 = compound_ready_batch(&mut conn, &public, &[ready, blocked, per_viewer], &ctx())
        .await
        .expect("p2 public");
    assert_eq!(
        p2.get(&ready),
        Some(&true),
        "a vacuous leaf does not block P2"
    );
    assert_eq!(p2.get(&blocked), Some(&false), "a Legacy leaf blocks P2");
    assert_eq!(
        p2.get(&per_viewer),
        Some(&true),
        "a Legacy leaf the public cannot see does not block the public"
    );
    let p2_owner = compound_ready_batch(&mut conn, &owner, &[per_viewer], &ctx())
        .await
        .expect("p2 owner");
    assert_eq!(
        p2_owner.get(&per_viewer),
        Some(&false),
        "the group sees the Legacy leaf, so it is not ready for the group"
    );
}

/// A visible node whose whole decomposition is hidden is a leaf for that
/// viewer, but it is a compound: its frozen cache is compound belief, so it
/// must never enter the conjunction as a `Legacy` pseudo-item or block P2.
#[sqlx::test(migrations = "../../migrations")]
async fn a_compound_seen_as_a_leaf_is_never_read_from_its_cache(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "bv-owner").await;
    let public = fixture::public_viewer(&pool).await;
    let author = agent(&pool).await;
    let root = claim(&pool, author, "root").await;
    let mid = claim(&pool, author, "mid with a hidden decomposition").await;
    let hidden = group_claim(&pool, member, group, "hidden child").await;
    let other = claim(&pool, author, "other leaf").await;
    decompose(&pool, root, mid).await;
    decompose(&pool, root, other).await;
    let e = decompose(&pool, mid, hidden).await;
    hide_edge(&pool, e, group).await;
    support(&pool, other, 0.8).await;
    // The mid node carries a frozen compound cache a legacy writer left.
    set_cache(&pool, mid, 0.9, 0.95, 0.92, 0.0).await;

    let view = derive_one_as(&pool, &public, root).await;
    let d = view.derived.as_ref().expect("derived");
    assert_eq!(d.leaves_used, 2, "the public viewer sees mid as a leaf");
    assert_eq!(
        d.legacy_leaves, 0,
        "a compound's cache is never a Legacy leaf"
    );
    assert!(
        near(view.bel, 0.0, 1e-9),
        "mid is vacuous for this viewer, so Bel(root) = 0, got {}",
        view.bel
    );
    let mut conn = pool.acquire().await.expect("conn");
    let p2 = compound_ready_batch(&mut conn, &public, &[root], &ctx())
        .await
        .expect("p2");
    assert_eq!(p2.get(&root), Some(&true));
}

/// P1 wins over a kept cache. An atom with an AEF row AND a cache (the normal
/// state once the cache writer has run, or a stale write left by another
/// writer) is `Axiom` and is read from its fold (.8), never from the cache
/// (.2), as an atom view and as a leaf of a compound.
#[sqlx::test(migrations = "../../migrations")]
async fn an_evidenced_leaf_is_read_from_its_fold_never_from_its_cache(pool: PgPool) {
    let public = fixture::public_viewer(&pool).await;
    let author = agent(&pool).await;
    let leaf = claim(&pool, author, "evidenced and cached").await;
    support(&pool, leaf, 0.8).await;
    set_cache(&pool, leaf, 0.2, 0.3, 0.25, 0.0).await;

    let mut conn = pool.acquire().await.expect("conn");
    let states = leaf_states_batch(&mut conn, &public, &[leaf], &ctx())
        .await
        .expect("leaf states");
    assert_eq!(states.get(&leaf), Some(&LeafState::Axiom));
    let views = atom_belief_view_batch(&mut conn, &public, &[leaf], &ctx())
        .await
        .expect("atom views");
    assert_eq!(views[&leaf].basis, Basis::Axiom);
    assert!(
        near(views[&leaf].bel, 0.8, 1e-9),
        "the atom view is its fold (.8), not its cache (.2): {}",
        views[&leaf].bel
    );
    drop(conn);

    let v = single_leaf(&pool, leaf).await;
    let d = v.derived.as_ref().expect("derived");
    assert!(
        near(v.bel, 0.8, 1e-9),
        "the leaf enters the conjunction as its fold (.8), not its cache (.2): {}",
        v.bel
    );
    assert_eq!((d.evidenced, d.legacy_leaves), (1, 0));
}

/// P1 is decided per viewer (SPEC §7.1, §8 T4). A public atom with a kept
/// cache (Bel .6, Pl .9) whose only AEF row is private to a group is `Legacy`
/// for the public, read from its cache, and `Axiom` for the group, read from
/// its fold (.8). A compound over it and an independent .7 leaf is therefore
/// .42 and not ready for the public, .56 and ready for the group.
#[sqlx::test(migrations = "../../migrations")]
async fn p1_and_p2_are_decided_per_viewer(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "bv-owner").await;
    let owner = Viewer::resolve(&pool, member).await.expect("owner viewer");
    let public = fixture::public_viewer(&pool).await;
    let author = agent(&pool).await;
    let (k, leaves) = compound_of(&pool, author, "over a privately evidenced leaf", 2).await;
    let (private_row_leaf, other) = (leaves[0], leaves[1]);
    let row = support(&pool, private_row_leaf, 0.8).await;
    hide_row(&pool, row, group).await;
    set_cache(&pool, private_row_leaf, 0.6, 0.9, 0.75, 0.0).await;
    support(&pool, other, 0.7).await;

    let mut conn = pool.acquire().await.expect("conn");
    for (viewer, state, bel, ready) in [
        (&public, LeafState::Legacy, 0.6, false),
        (&owner, LeafState::Axiom, 0.8, true),
    ] {
        let states = leaf_states_batch(&mut conn, viewer, &[private_row_leaf], &ctx())
            .await
            .expect("leaf states");
        assert_eq!(states.get(&private_row_leaf), Some(&state));
        let views = atom_belief_view_batch(&mut conn, viewer, &[private_row_leaf], &ctx())
            .await
            .expect("atom views");
        assert!(
            near(views[&private_row_leaf].bel, bel, 1e-9),
            "{state:?}: {} must be {bel}",
            views[&private_row_leaf].bel
        );
        let p2 = compound_ready_batch(&mut conn, viewer, &[k], &ctx())
            .await
            .expect("p2");
        assert_eq!(p2.get(&k), Some(&ready), "P2 for a viewer seeing {state:?}");
    }
    drop(conn);
    let pub_v = derive_one_as(&pool, &public, k).await;
    let grp_v = derive_one_as(&pool, &owner, k).await;
    assert!(
        near(pub_v.bel, 0.42, 1e-9) && near(grp_v.bel, 0.56, 1e-9),
        "public reads the cache (.6 · .7 = .42), the group the fold (.8 · .7 = .56): {} / {}",
        pub_v.bel,
        grp_v.bel
    );
    assert_eq!(pub_v.derived.as_ref().unwrap().legacy_leaves, 1);
    assert_eq!(grp_v.derived.as_ref().unwrap().legacy_leaves, 0);
}

// ── (4) spine ───────────────────────────────────────────────────────────────

/// Plan test (4). A spine node (level 1) returns a profile, never a
/// conjunction: its two leaves share one paper's item at .8, so the
/// conjunction would be .8 (the control compound shows it), while the
/// profile serves the Fréchet floor .8 + .8 − 1 = .6.
#[sqlx::test(migrations = "../../migrations")]
async fn a_spine_node_returns_a_profile_never_a_conjunction(pool: PgPool) {
    let author = agent(&pool).await;
    let holder = claim(&pool, author, "evidence holder").await;
    let (x, y) = (agent(&pool).await, agent(&pool).await);
    let a1 = claim(&pool, author, "a1").await;
    let a2 = claim(&pool, author, "a2").await;
    let e1 = doi_evidence(&pool, holder, "10.5555/bv-spine", x).await;
    let e2 = doi_evidence(&pool, holder, "10.5555/bv-spine", y).await;
    store_attributed(&pool, a1, e1, x, 0.8).await;
    store_attributed(&pool, a2, e2, y, 0.8).await;

    let section = claim(&pool, author, "section").await;
    set_level(&pool, section, "1").await;
    let paragraph = claim(&pool, author, "paragraph").await;
    for k in [section, paragraph] {
        decompose(&pool, k, a1).await;
        decompose(&pool, k, a2).await;
    }

    let control = derive(&pool, paragraph).await;
    assert_eq!(control.basis, Basis::Derived);
    assert!(
        near(control.bel, 0.8, 1e-9),
        "control: one comonotone item over both leaves is .8, got {}",
        control.bel
    );

    let spine = derive(&pool, section).await;
    assert_eq!(spine.basis, Basis::Profile);
    assert!(
        spine.derived.is_none(),
        "a spine node carries no derivation"
    );
    let profile = spine.profile.as_ref().expect("profile");
    assert_eq!(profile.n, 2);
    assert!(
        near(spine.bel, 0.6, 1e-9),
        "a spine node serves the envelope floor .6, never the conjunction .8, got {}",
        spine.bel
    );
    // The whole profile, by hand: each leaf alone is Bel .8, Pl 1, BetP .9.
    assert_eq!(
        (profile.evidenced, profile.legacy_leaves, profile.contested),
        (2, 0, 0)
    );
    for (what, s3, want) in [("bel", profile.bel, 0.8), ("betp", profile.betp, 0.9)] {
        assert!(
            near(s3.min, want, 1e-9) && near(s3.median, want, 1e-9) && near(s3.max, want, 1e-9),
            "{what} summary must be {want} throughout: {s3:?}"
        );
    }
    assert!(
        near(profile.frechet.lo, 0.6, 1e-9)
            && near(profile.frechet.hi, 1.0, 1e-9)
            && near(profile.frechet.hi_nr, 1.0, 1e-9),
        "envelope [.6, 1], NR ≤ 1: {:?}",
        profile.frechet
    );
    assert!(near(spine.pl, 1.0, 1e-9) && near(spine.nr, 1.0, 1e-9) && near(spine.betp, 0.8, 1e-9));
}

/// A spine profile over leaves that differ: l1 .9, l2 .6, l3 refuted at .7
/// (Pl .3) and l4 unevidenced. Alone they are Bel {.9, .6, 0, 0}, `BetP`
/// {.95, .8, .15, .5} and Pl {1, 1, .3, 1}: medians .3 and .65 (an even
/// count), one contested leaf (Pl < .5), three evidenced (P1), and the
/// envelope [0, .3] (Fréchet floor 1.5 − 3 < 0; Pl and NR capped by l3).
#[sqlx::test(migrations = "../../migrations")]
async fn a_spine_profile_summarizes_each_leaf_alone(pool: PgPool) {
    let author = agent(&pool).await;
    let (section, l) = compound_of(&pool, author, "thesis", 4).await;
    set_level(&pool, section, "0").await;
    support(&pool, l[0], 0.9).await;
    support(&pool, l[1], 0.6).await;
    refute(&pool, l[2], 0.7).await;

    let v = derive(&pool, section).await;
    assert_eq!(v.basis, Basis::Profile);
    let p = v.profile.as_ref().expect("profile");
    assert_eq!(
        (p.n, p.evidenced, p.legacy_leaves, p.contested),
        (4, 3, 0, 1)
    );
    for (what, s3, (min, median, max)) in [
        ("bel", p.bel, (0.0, 0.3, 0.9)),
        ("betp", p.betp, (0.15, 0.65, 0.95)),
    ] {
        assert!(
            near(s3.min, min, 1e-9) && near(s3.median, median, 1e-9) && near(s3.max, max, 1e-9),
            "{what} summary must be ({min}, {median}, {max}): {s3:?}"
        );
    }
    assert!(
        near(p.frechet.lo, 0.0, 1e-9)
            && near(p.frechet.hi, 0.3, 1e-9)
            && near(p.frechet.hi_nr, 0.3, 1e-9),
        "envelope [0, .3], NR ≤ .3: {:?}",
        p.frechet
    );
    assert!(
        near(v.bel, 0.0, 1e-9)
            && near(v.pl, 0.3, 1e-9)
            && near(v.nr, 0.3, 1e-9)
            && near(v.betp, 0.15, 1e-9),
        "served: the envelope and its midpoint: Bel {} Pl {} NR {} BetP {}",
        v.bel,
        v.pl,
        v.nr,
        v.betp
    );
}

// ── (5), (6) not_all ────────────────────────────────────────────────────────

/// Plan test (5), SPEC §3.6. A compound whose only BBA is a textless f .7 is
/// refuted as a whole: Bel 0, Pl .3, NR .3, not ≈ 1. Its leaves hold nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_compound_whose_only_bba_is_f_point_seven_is_served_pl_and_nr_point_three(pool: PgPool) {
    let author = agent(&pool).await;
    let k = claim(&pool, author, "refuted whole").await;
    let (a, b) = (
        claim(&pool, author, "a").await,
        claim(&pool, author, "b").await,
    );
    decompose(&pool, k, a).await;
    decompose(&pool, k, b).await;
    assert!(cache_is_null(&pool, a).await && cache_is_null(&pool, b).await);
    refute(&pool, k, 0.7).await;

    let v = derive(&pool, k).await;
    assert!(near(v.bel, 0.0, 1e-9), "Bel {}", v.bel);
    assert!(near(v.pl, 0.3, 1e-9), "Pl must be .3, got {}", v.pl);
    assert!(near(v.nr, 0.3, 1e-9), "NR must be .3, got {}", v.nr);
    let not_all = v.derived.as_ref().expect("derived").not_all;
    assert!(near(not_all.m, 0.7, 1e-9), "not_all m {}", not_all.m);
}

/// Which of a compound's own rows refute it as a whole. A frozen edge-factor
/// row on the compound is inert (it is not refutation evidence about the
/// compound). A text-bearing pure refutation that an `attributed_v1` row
/// cites has moved to the atoms, so it no longer refutes the whole; the same
/// row unattributed still does.
#[sqlx::test(migrations = "../../migrations")]
async fn only_unmoved_refutation_rows_of_the_compound_refute_it_as_a_whole(pool: PgPool) {
    let author = agent(&pool).await;
    let x = agent(&pool).await;

    // An edge-factor row with F mass on the compound: no refutation.
    let k_edge = claim(&pool, author, "edge row on the compound").await;
    let (a, b) = (
        claim(&pool, author, "a").await,
        claim(&pool, author, "b").await,
    );
    decompose(&pool, k_edge, a).await;
    decompose(&pool, k_edge, b).await;
    let src = claim(&pool, author, "edge source").await;
    let e = edge(&pool, src, k_edge, "refutes").await;
    store_edge_factor(&pool, e, k_edge, serde_json::json!({"1": 0.7, "0,1": 0.3})).await;
    let v = derive(&pool, k_edge).await;
    assert!(
        near(v.derived.as_ref().unwrap().not_all.m, 0.0, 1e-12),
        "an edge-factor row on the compound is inert"
    );

    // A text-bearing refutation, attributed to atom c: it now sits on c.
    let k_moved = claim(&pool, author, "attributed refutation").await;
    let (c, d) = (
        claim(&pool, author, "c").await,
        claim(&pool, author, "d").await,
    );
    decompose(&pool, k_moved, c).await;
    decompose(&pool, k_moved, d).await;
    let ev = doi_evidence(&pool, k_moved, "10.5555/bv-moved", x).await;
    store(
        &pool,
        k_moved,
        Row {
            perspective: Some(ev),
            evidence: Some(ev),
            ..Row::plain(x)
        },
        serde_json::json!({"1": 0.7, "0,1": 0.3}),
    )
    .await;
    store(
        &pool,
        c,
        Row {
            perspective: Some(ev),
            evidence: Some(ev),
            method: Some("attributed_v1"),
            ..Row::plain(x)
        },
        serde_json::json!({"1": 0.7, "0,1": 0.3}),
    )
    .await;
    let v = derive(&pool, k_moved).await;
    let d_moved = v.derived.as_ref().expect("derived");
    assert!(
        near(d_moved.not_all.m, 0.0, 1e-12),
        "an attributed refutation is not counted again on the whole, got m {}",
        d_moved.not_all.m
    );
    assert!(
        near(v.nr, 0.3, 1e-9),
        "the refutation is counted once, on c: NR .3, got {}",
        v.nr
    );

    // The same refutation, not attributed: it refutes the whole.
    let k_kept = claim(&pool, author, "unattributed refutation").await;
    let (g, h) = (
        claim(&pool, author, "g").await,
        claim(&pool, author, "h").await,
    );
    decompose(&pool, k_kept, g).await;
    decompose(&pool, k_kept, h).await;
    let ev2 = doi_evidence(&pool, k_kept, "10.5555/bv-kept", x).await;
    store(
        &pool,
        k_kept,
        Row {
            perspective: Some(ev2),
            evidence: Some(ev2),
            ..Row::plain(x)
        },
        serde_json::json!({"1": 0.7, "0,1": 0.3}),
    )
    .await;
    let v = derive(&pool, k_kept).await;
    assert!(
        near(v.derived.as_ref().unwrap().not_all.m, 0.7, 1e-9),
        "an unattributed refutation filed on the compound refutes the whole"
    );
}

/// Plan test (6), SPEC §3.6 worked example. K = a1 ∧ a2 with two independent
/// .8 leaves (Bel .64, Pl 1); X at .8 contradicts K (f .9): m = .72, so
/// Bel .332 and Pl .519. Hidden from the public, the edge does nothing for
/// it; its group still sees the refutation. An edge whose source is one of
/// K's own leaves is skipped and counted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refuting_edge_into_a_compound_is_its_not_all_valuation_per_viewer(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "bv-owner").await;
    let owner = Viewer::resolve(&pool, member).await.expect("owner viewer");
    let public = fixture::public_viewer(&pool).await;
    let author = agent(&pool).await;

    let k = claim(&pool, author, "K").await;
    let (a1, a2) = (
        claim(&pool, author, "a1").await,
        claim(&pool, author, "a2").await,
    );
    decompose(&pool, k, a1).await;
    decompose(&pool, k, a2).await;
    support(&pool, a1, 0.8).await;
    support(&pool, a2, 0.8).await;
    let x = claim(&pool, author, "X").await;
    support(&pool, x, 0.8).await;
    edge(&pool, x, k, "contradicts").await;

    let v = derive_one_as(&pool, &public, k).await;
    assert!(near(v.bel, 0.332, 5e-4), "Bel must be .332, got {}", v.bel);
    assert!(near(v.pl, 0.519, 5e-4), "Pl must be .519, got {}", v.pl);
    assert!(
        near(v.nr, 0.519, 5e-4),
        "NR gains the refutation of the whole: .519, got {}",
        v.nr
    );

    // The same shape behind an edge only the group can read.
    let k2 = claim(&pool, author, "K2").await;
    let (b1, b2) = (
        claim(&pool, author, "b1").await,
        claim(&pool, author, "b2").await,
    );
    decompose(&pool, k2, b1).await;
    decompose(&pool, k2, b2).await;
    support(&pool, b1, 0.8).await;
    support(&pool, b2, 0.8).await;
    let hidden = edge(&pool, x, k2, "CONTRADICTS").await;
    hide_edge(&pool, hidden, group).await;
    let pub_v = derive_one_as(&pool, &public, k2).await;
    assert!(
        near(pub_v.bel, 0.64, 1e-9) && near(pub_v.pl, 1.0, 1e-9),
        "an edge the public cannot read refutes nothing for it: Bel {} Pl {}",
        pub_v.bel,
        pub_v.pl
    );
    assert_eq!(pub_v.derived.as_ref().unwrap().not_all.sources, 0);
    assert!(
        near(pub_v.betp, 0.81, 1e-9),
        "product-frame BetP of two independent .8 leaves: .64 + 2 · .16 · ½ + .04 · ¼ = .81, \
         got {}",
        pub_v.betp
    );
    assert!(pub_v.derived.as_ref().unwrap().exact);
    let grp_v = derive_one_as(&pool, &owner, k2).await;
    assert!(
        near(grp_v.bel, 0.332, 5e-4),
        "the group reads the edge (relationship matched in any case): Bel {}",
        grp_v.bel
    );

    // A refuting edge from one of K's own leaves shares that leaf: skipped.
    let k3 = claim(&pool, author, "K3").await;
    let c2 = claim(&pool, author, "c2").await;
    decompose(&pool, k3, a1).await;
    decompose(&pool, k3, c2).await;
    support(&pool, c2, 0.8).await;
    edge(&pool, a1, k3, "refutes").await;
    let v3 = derive(&pool, k3).await;
    let n3 = v3.derived.as_ref().unwrap().not_all;
    assert_eq!(n3.shared_leaf_skipped, 1, "the shared-leaf edge is counted");
    assert!(
        near(n3.m, 0.0, 1e-12) && near(v3.bel, 0.64, 1e-9),
        "and contributes nothing: m {} Bel {}",
        n3.m,
        v3.bel
    );
}

/// `not_all` across sources and from a compound source (SPEC §3.6):
/// - K1 (Bel .64) refuted by its own f .5 row and by X (.8) contradicts K1
///   (m .72): Dempster across the two, m = 1 − .5 · .28 = .86 from 2 sources,
///   so Bel .199 and Pl .311;
/// - K2 contradicted by a compound X2 = x1 ∧ x2 (each .9): Bel(X2) is the
///   conjunction of X2's leaves, .81, so m = .9 · .81 = .729, Bel .325,
///   Pl .508;
/// - K3 = d1 ∧ d2 contradicted by a compound X3 = d1 ∧ x3: they share d1, so
///   the edge is skipped and counted (m 0, Bel .64).
#[sqlx::test(migrations = "../../migrations")]
async fn not_all_combines_its_sources_and_reads_a_compound_source_over_its_leaves(pool: PgPool) {
    let author = agent(&pool).await;
    let not_all = |v: &BeliefView| v.derived.as_ref().expect("derived").not_all;

    let (k1, l1) = compound_of(&pool, author, "K1", 2).await;
    for &l in &l1 {
        support(&pool, l, 0.8).await;
    }
    refute(&pool, k1, 0.5).await;
    let x = claim(&pool, author, "X").await;
    support(&pool, x, 0.8).await;
    edge(&pool, x, k1, "contradicts").await;
    let v1 = derive(&pool, k1).await;
    let n1 = not_all(&v1);
    assert!(
        near(n1.m, 0.86, 1e-9) && n1.sources == 2,
        "two independent refuters: m .86 from 2 sources, got {} from {}",
        n1.m,
        n1.sources
    );
    assert!(
        near(v1.bel, 0.1993, 5e-4) && near(v1.pl, 0.3114, 5e-4),
        "Bel .199, Pl .311; got {} / {}",
        v1.bel,
        v1.pl
    );

    let (k2, l2) = compound_of(&pool, author, "K2", 2).await;
    for &l in &l2 {
        support(&pool, l, 0.8).await;
    }
    let (x2, xl) = compound_of(&pool, author, "X2", 2).await;
    for &l in &xl {
        support(&pool, l, 0.9).await;
    }
    edge(&pool, x2, k2, "contradicts").await;
    let v2 = derive(&pool, k2).await;
    assert!(
        near(not_all(&v2).m, 0.729, 1e-9),
        "a compound source is read as the conjunction of its leaves (.81): m .729, got {}",
        not_all(&v2).m
    );
    assert!(
        near(v2.bel, 0.3251, 5e-4) && near(v2.pl, 0.5080, 5e-4),
        "Bel .325, Pl .508; got {} / {}",
        v2.bel,
        v2.pl
    );

    let (k3, l3) = compound_of(&pool, author, "K3", 2).await;
    for &l in &l3 {
        support(&pool, l, 0.8).await;
    }
    let x3 = claim(&pool, author, "X3").await;
    let x3_leaf = claim(&pool, author, "X3's own leaf").await;
    decompose(&pool, x3, l3[0]).await;
    decompose(&pool, x3, x3_leaf).await;
    support(&pool, x3_leaf, 0.9).await;
    edge(&pool, x3, k3, "contradicts").await;
    let v3 = derive(&pool, k3).await;
    let n3 = not_all(&v3);
    assert_eq!(
        n3.shared_leaf_skipped, 1,
        "a compound source sharing a leaf is skipped and counted"
    );
    assert!(
        near(n3.m, 0.0, 1e-12) && near(v3.bel, 0.64, 1e-9),
        "and contributes nothing: m {} Bel {}",
        n3.m,
        v3.bel
    );
}

/// Which of a compound's own rows refute the whole, and how much:
/// - two refutations citing one paper (two agents) are one source, the max
///   (.7), not Dempster (.85);
/// - a row is discounted by its α (strength .5): f .7 counts .35;
/// - a mixed row (t .3, f .2) no citation moved counts its f (.2);
/// - seed, propagated and `auto_cdst` rows on the compound are inert;
/// - a refutation row only a group can read refutes the whole for that group
///   alone.
#[sqlx::test(migrations = "../../migrations")]
async fn own_rows_refute_the_whole_by_key_by_alpha_and_per_viewer(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "bv-owner").await;
    let owner = Viewer::resolve(&pool, member).await.expect("owner viewer");
    let public = fixture::public_viewer(&pool).await;
    let author = agent(&pool).await;
    let m_of = |v: &BeliefView| v.derived.as_ref().expect("derived").not_all.m;
    let f7 = serde_json::json!({"1": 0.7, "0,1": 0.3});

    let (k1, _) = compound_of(&pool, author, "one paper refutes twice", 2).await;
    let (x, y) = (agent(&pool).await, agent(&pool).await);
    let e1 = doi_evidence(&pool, k1, "10.5555/bv-same-paper", x).await;
    let e2 = doi_evidence(&pool, k1, "10.5555/bv-same-paper", y).await;
    store(&pool, k1, citing(x, e1), f7.clone()).await;
    store(
        &pool,
        k1,
        citing(y, e2),
        serde_json::json!({"1": 0.5, "0,1": 0.5}),
    )
    .await;
    let v1 = derive(&pool, k1).await;
    assert!(
        near(m_of(&v1), 0.7, 1e-9) && v1.derived.as_ref().unwrap().not_all.sources == 1,
        "one paper is one source, the max: m .7 from 1, got {} from {}",
        m_of(&v1),
        v1.derived.as_ref().unwrap().not_all.sources
    );

    let (k2, _) = compound_of(&pool, author, "discounted", 2).await;
    store(
        &pool,
        k2,
        Row {
            strength: Some(0.5),
            ..Row::plain(agent(&pool).await)
        },
        f7.clone(),
    )
    .await;
    let m2 = m_of(&derive(&pool, k2).await);
    assert!(near(m2, 0.35, 1e-9), "α · f = .5 · .7 = .35, got {m2}");

    let (k3, _) = compound_of(&pool, author, "mixed", 2).await;
    store(
        &pool,
        k3,
        Row::plain(agent(&pool).await),
        serde_json::json!({"0": 0.3, "1": 0.2, "0,1": 0.5}),
    )
    .await;
    let m3 = m_of(&derive(&pool, k3).await);
    assert!(near(m3, 0.2, 1e-9), "a mixed row's f counts: .2, got {m3}");

    let (k4, _) = compound_of(&pool, author, "machinery rows", 2).await;
    for method in ["truth_value_seed", "propagated_from_parent", "auto_cdst"] {
        store(
            &pool,
            k4,
            Row {
                method: Some(method),
                ..Row::plain(agent(&pool).await)
            },
            f7.clone(),
        )
        .await;
    }
    let m4 = m_of(&derive(&pool, k4).await);
    assert!(
        near(m4, 0.0, 1e-12),
        "seed, propagated and auto_cdst rows are not evidence about the whole: m {m4}"
    );

    let (k5, _) = compound_of(&pool, author, "privately refuted", 2).await;
    let row = refute(&pool, k5, 0.7).await;
    hide_row(&pool, row, group).await;
    let m_pub = m_of(&derive_one_as(&pool, &public, k5).await);
    let m_grp = m_of(&derive_one_as(&pool, &owner, k5).await);
    assert!(
        near(m_pub, 0.0, 1e-12) && near(m_grp, 0.7, 1e-9),
        "a private refutation refutes the whole for its group only: {m_pub} / {m_grp}"
    );
}

// ── negative siblings ───────────────────────────────────────────────────────

/// SPEC §3.3 "One negative sibling edge" and the design note's negative-edge
/// variant: two independent .8 leaves (R-DEP Bel .64, Pl 1) with a1
/// contradicts a2 (m .9). The edge's own frozen BBA on a2 is dropped and the
/// pair meets the closed form once: K' = .576, Bel .64·.1/.424 = .151,
/// Pl .1/.424 = .236. Two negative siblings have no closed form: the value is
/// the Fréchet envelope (floor .8·3 − 2 = .4, where R-DEP would give .512),
/// labelled internally contested.
#[sqlx::test(migrations = "../../migrations")]
async fn one_negative_sibling_uses_the_closed_form_and_two_serve_the_envelope(pool: PgPool) {
    let author = agent(&pool).await;
    let k = claim(&pool, author, "K").await;
    let (a1, a2) = (
        claim(&pool, author, "a1").await,
        claim(&pool, author, "a2").await,
    );
    decompose(&pool, k, a1).await;
    decompose(&pool, k, a2).await;
    support(&pool, a1, 0.8).await;
    support(&pool, a2, 0.8).await;
    let e = edge(&pool, a1, a2, "contradicts").await;
    // The frozen edge-factor BBA the edge wired onto its target.
    store_edge_factor(&pool, e, a2, serde_json::json!({"1": 0.72, "0,1": 0.28})).await;

    let v = derive(&pool, k).await;
    assert!(near(v.bel, 0.151, 5e-4), "Bel must be .151, got {}", v.bel);
    assert!(near(v.pl, 0.236, 5e-4), "Pl must be .236, got {}", v.pl);
    assert!(!v.derived.as_ref().expect("derived").internally_contested);

    let k2 = claim(&pool, author, "K2").await;
    let (b1, b2, b3) = (
        claim(&pool, author, "b1").await,
        claim(&pool, author, "b2").await,
        claim(&pool, author, "b3").await,
    );
    for b in [b1, b2, b3] {
        decompose(&pool, k2, b).await;
        support(&pool, b, 0.8).await;
    }
    edge(&pool, b1, b2, "contradicts").await;
    edge(&pool, b2, b3, "refutes").await;
    let v2 = derive(&pool, k2).await;
    let d2 = v2.derived.as_ref().expect("derived");
    assert!(
        d2.internally_contested && !d2.exact,
        "two negative siblings are contested, and the envelope is not exact"
    );
    assert!(
        near(v2.bel, 0.4, 1e-9) && near(v2.pl, 1.0, 1e-9),
        "two siblings serve the envelope [.4, 1], got Bel {} Pl {}",
        v2.bel,
        v2.pl
    );
}

/// Negative siblings as live data carries them, each with its frozen
/// edge-factor BBA on its target:
/// - two siblings, b1 contradicts b2 ({F .72} on b2) and b2 refutes b3
///   ({F .64} on b3): the envelope is built from the leaves as they are
///   served, frozen rows included (b2 T .528 / Pl .660, b3 T .590 / Pl .738),
///   so its floor is 0 and its ceiling .660, labelled inexact;
/// - a reciprocal pair (c1 contradicts c2 and c2 contradicts c1) is two
///   edges: the envelope [.6, 1], labelled internally contested;
/// - a sibling edge and its frozen row that only a group can read: the public
///   sees two independent leaves (.64, Pl 1), the group the closed form
///   (.151 / .236).
#[sqlx::test(migrations = "../../migrations")]
async fn negative_siblings_are_read_with_their_frozen_rows_and_per_viewer(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "bv-owner").await;
    let owner = Viewer::resolve(&pool, member).await.expect("owner viewer");
    let public = fixture::public_viewer(&pool).await;
    let author = agent(&pool).await;

    let (k, b) = compound_of(&pool, author, "two wired siblings", 3).await;
    for &l in &b {
        support(&pool, l, 0.8).await;
    }
    let e1 = edge(&pool, b[0], b[1], "contradicts").await;
    store_edge_factor(&pool, e1, b[1], serde_json::json!({"1": 0.72, "0,1": 0.28})).await;
    let e2 = edge(&pool, b[1], b[2], "refutes").await;
    store_edge_factor(&pool, e2, b[2], serde_json::json!({"1": 0.64, "0,1": 0.36})).await;
    let v = derive(&pool, k).await;
    let d = v.derived.as_ref().expect("derived");
    assert!(d.internally_contested && !d.exact);
    assert!(
        near(v.bel, 0.0, 1e-9) && near(v.pl, 0.6604, 5e-4),
        "the envelope of the served leaves is [0, .660]: Bel {} Pl {}",
        v.bel,
        v.pl
    );

    let (k2, c) = compound_of(&pool, author, "reciprocal pair", 2).await;
    for &l in &c {
        support(&pool, l, 0.8).await;
    }
    edge(&pool, c[0], c[1], "contradicts").await;
    edge(&pool, c[1], c[0], "contradicts").await;
    let v2 = derive(&pool, k2).await;
    assert!(v2.derived.as_ref().unwrap().internally_contested);
    assert!(
        near(v2.bel, 0.6, 1e-9) && near(v2.pl, 1.0, 1e-9),
        "a reciprocal pair is two siblings: the envelope [.6, 1], got Bel {} Pl {}",
        v2.bel,
        v2.pl
    );

    let (k3, d3) = compound_of(&pool, author, "privately contradicted", 2).await;
    for &l in &d3 {
        support(&pool, l, 0.8).await;
    }
    let e3 = edge(&pool, d3[0], d3[1], "contradicts").await;
    let row = store_edge_factor(
        &pool,
        e3,
        d3[1],
        serde_json::json!({"1": 0.72, "0,1": 0.28}),
    )
    .await;
    hide_edge(&pool, e3, group).await;
    hide_row(&pool, row, group).await;
    let pub_v = derive_one_as(&pool, &public, k3).await;
    let grp_v = derive_one_as(&pool, &owner, k3).await;
    assert!(
        near(pub_v.bel, 0.64, 1e-9)
            && near(pub_v.pl, 1.0, 1e-9)
            && !pub_v.derived.as_ref().unwrap().internally_contested,
        "the public reads no sibling: .64 / 1, got {} / {}",
        pub_v.bel,
        pub_v.pl
    );
    assert!(
        near(grp_v.bel, 0.151, 5e-4) && near(grp_v.pl, 0.236, 5e-4),
        "the group reads the closed form: .151 / .236, got {} / {}",
        grp_v.bel,
        grp_v.pl
    );
}

// ── (7) lens ────────────────────────────────────────────────────────────────

/// Plan test (7). A single-leaf compound under a lens equals the leaf's own
/// lensed read, `get_perspective_belief`, under the same perspective: one
/// empirical item at .8 under {empirical: .2} is .16 on both.
#[sqlx::test(migrations = "../../migrations")]
async fn a_single_leaf_compound_under_a_lens_equals_the_leaf_s_lensed_read(pool: PgPool) {
    let author = agent(&pool).await;
    let leaf = claim(&pool, author, "lensed leaf").await;
    store(
        &pool,
        leaf,
        Row {
            strength: None,
            evidence_type: Some("empirical"),
            ..Row::plain(agent(&pool).await)
        },
        serde_json::json!({"0": 0.8, "0,1": 0.2}),
    )
    .await;
    let k = claim(&pool, author, "single-leaf compound").await;
    decompose(&pool, k, leaf).await;

    let lens = PerspectiveRepository::create(
        &pool,
        "empirical skeptic",
        None,
        None,
        Some("analytical"),
        &[],
        None,
        None,
    )
    .await
    .expect("perspective");
    PerspectiveRepository::set_source_reliability(
        &pool,
        lens.id,
        &HashMap::from([("empirical".to_string(), 0.2)]),
    )
    .await
    .expect("reliability map");

    let viewer = fixture::public_viewer(&pool).await;
    let b = binary(&pool).await;
    let leaf_read = get_perspective_belief(&pool, &viewer, leaf, b, lens.id)
        .await
        .expect("lensed leaf read");
    let lens_ctx = FramedBeliefContext::for_perspective(&pool, &viewer, Some(lens.id))
        .await
        .expect("lens context");
    let view = derive_as(&pool, &viewer, &[k], &lens_ctx)
        .await
        .remove(&k)
        .expect("view");
    assert!(near(leaf_read.belief, 0.16, 1e-9), "{}", leaf_read.belief);
    assert!(
        near(view.bel, leaf_read.belief, 1e-9) && near(view.pl, leaf_read.plausibility, 1e-9),
        "single-leaf conj under the lens ({}, {}) must equal the leaf's lensed read ({}, {})",
        view.bel,
        view.pl,
        leaf_read.belief,
        leaf_read.plausibility
    );
}

// ── (8) Legacy leaf ─────────────────────────────────────────────────────────

/// Plan test (8), SPEC §3.3 "Legacy leaves". A leaf with no AEF input and a
/// kept cache (Bel .4, Pl .7, `~` .1) is one `legacy:<atom>` pseudo-item:
/// the single-leaf compound shows the cache's Bel .4 and Pl .7 (not .6, which
/// is what counting `~` twice would give), the interval's `BetP` .55 (not the
/// cache's BP-written .62), NR .8, and labels the leaf.
#[sqlx::test(migrations = "../../migrations")]
async fn a_single_leaf_compound_over_a_legacy_leaf_shows_its_cache_interval(pool: PgPool) {
    let author = agent(&pool).await;
    let leaf = claim(&pool, author, "legacy leaf").await;
    set_cache(&pool, leaf, 0.4, 0.7, 0.62, 0.1).await;
    let k = claim(&pool, author, "over a legacy leaf").await;
    decompose(&pool, k, leaf).await;

    let v = derive(&pool, k).await;
    assert!(near(v.bel, 0.4, 1e-9), "Bel {}", v.bel);
    assert!(
        near(v.pl, 0.7, 1e-9),
        "Pl must be the cache's .7, got {}",
        v.pl
    );
    assert!(near(v.betp, 0.55, 1e-9), "BetP {}", v.betp);
    assert!(near(v.nr, 0.8, 1e-9), "NR {}", v.nr);
    let d = v.derived.as_ref().expect("derived");
    assert_eq!(d.legacy_leaves, 1);
    assert_eq!(d.evidenced, 0);
}

// ── (9) D11 ─────────────────────────────────────────────────────────────────

/// The atom fold's value for one atom, as the public viewer reads it.
async fn atom_value(pool: &PgPool, atom: Uuid) -> (f64, f64, f64) {
    let viewer = fixture::public_viewer(pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    let rows = atom_axiom_rows(&mut conn, &viewer, &[atom], AxiomMode::Display, &ctx())
        .await
        .expect("rows");
    let f = atom_fold(rows.get(&atom).map(Vec::as_slice).unwrap_or_default()).expect("fold");
    (f.belief(), f.plausibility(), f.mass_on_conflict())
}

async fn single_leaf(pool: &PgPool, leaf: Uuid) -> BeliefView {
    let author = agent(pool).await;
    let k = claim(pool, author, "single-leaf compound").await;
    decompose(pool, k, leaf).await;
    derive(pool, k).await
}

/// Plan test (9a), D11 (the conj half of PR-5's plan test (4)). Two
/// `attributed_v1` items citing one paper, each .8: the single-leaf compound
/// is .8, not .96, and equals the atom fold.
#[sqlx::test(migrations = "../../migrations")]
async fn d11_one_paper_cited_twice_is_one_item_in_the_conjunction(pool: PgPool) {
    let author = agent(&pool).await;
    let holder = claim(&pool, author, "holder").await;
    let (x, y) = (agent(&pool).await, agent(&pool).await);
    let atom = claim(&pool, author, "one paper twice").await;
    let e1 = doi_evidence(&pool, holder, "10.5555/bv-one", x).await;
    let e2 = doi_evidence(&pool, holder, "https://doi.org/10.5555/BV-ONE", y).await;
    store_attributed(&pool, atom, e1, x, 0.8).await;
    store_attributed(&pool, atom, e2, y, 0.8).await;

    let v = single_leaf(&pool, atom).await;
    let (bel, pl, _) = atom_value(&pool, atom).await;
    assert!(near(v.bel, 0.8, 1e-9), "conj must be .8, got {}", v.bel);
    assert!(near(v.bel, bel, 1e-9) && near(v.pl, pl, 1e-9));
}

/// Plan test (9b), D11 with open-world mass: an edge-factor row
/// {T .5, ~ .3, Θ .2} plus {T .64, Θ .36} folds to Bel .628/.7 = .897 with
/// K .3, in the atom fold and in the single-leaf conjunction alike.
#[sqlx::test(migrations = "../../migrations")]
async fn d11_open_world_mass_meets_a_second_item_as_in_the_atom_fold(pool: PgPool) {
    let author = agent(&pool).await;
    let atom = claim(&pool, author, "open world").await;
    let source = claim(&pool, author, "source").await;
    let e = edge(&pool, source, atom, "supports").await;
    store_edge_factor(
        &pool,
        e,
        atom,
        serde_json::json!({"0": 0.5, "~0,1": 0.3, "0,1": 0.2}),
    )
    .await;
    support(&pool, atom, 0.64).await;

    let v = single_leaf(&pool, atom).await;
    let (bel, pl, k) = atom_value(&pool, atom).await;
    assert!(
        near(v.bel, 0.628 / 0.7, 1e-9),
        "conj must be .897, got {}",
        v.bel
    );
    let conflict = v.derived.as_ref().expect("derived").conflict;
    assert!(
        near(conflict, 0.3, 1e-9),
        "conj K must be .3, got {conflict}"
    );
    assert!(near(v.bel, bel, 1e-9) && near(v.pl, pl, 1e-9) && near(conflict, k, 1e-9));
}

/// Plan test (9c). At K = 1 between dogmatic items both reads use the atom
/// fold's Yager-closed convention (Bel 0, Pl 1); neither fails.
#[sqlx::test(migrations = "../../migrations")]
async fn d11_total_conflict_is_ignorance_in_both_reads(pool: PgPool) {
    let author = agent(&pool).await;
    let atom = claim(&pool, author, "dogmatic conflict").await;
    for masses in [serde_json::json!({"0": 1.0}), serde_json::json!({"1": 1.0})] {
        store(&pool, atom, Row::plain(agent(&pool).await), masses).await;
    }

    let v = single_leaf(&pool, atom).await;
    let (bel, pl, k) = atom_value(&pool, atom).await;
    assert!(
        near(v.bel, 0.0, 1e-9) && near(v.pl, 1.0, 1e-9),
        "Yager closed: Bel 0, Pl 1, got Bel {} Pl {}",
        v.bel,
        v.pl
    );
    let conflict = v.derived.as_ref().expect("derived").conflict;
    assert!(
        near(conflict, 1.0, 1e-9),
        "the conjunction saw K = 1 (and did not divide by 1 - K), got {conflict}"
    );
    assert!(near(v.bel, bel, 1e-9) && near(v.pl, pl, 1e-9) && near(conflict, k, 1e-9));
}

/// A leaf whose fold holds a frozen edge-factor row from a COMPOUND source is
/// a labelled fidelity cost (SPEC §6.3): a compound over it reports one
/// `legacy_compound_edge_items`, and one over an ordinary leaf reports none.
/// The positive row is read one-sided (T .5), so the compound is .5 · .8.
#[sqlx::test(migrations = "../../migrations")]
async fn a_compound_source_edge_row_is_reported_on_the_compounds_that_read_it(pool: PgPool) {
    let author = agent(&pool).await;
    let (y, y_leaves) = compound_of(&pool, author, "compound source Y", 1).await;
    support(&pool, y_leaves[0], 0.9).await;
    let (k, l) = compound_of(&pool, author, "reads a compound-source row", 2).await;
    let e = edge(&pool, y, l[0], "supports").await;
    store_edge_factor(&pool, e, l[0], serde_json::json!({"0": 0.5, "0,1": 0.5})).await;
    support(&pool, l[1], 0.8).await;
    let (plain, pl) = compound_of(&pool, author, "reads none", 1).await;
    support(&pool, pl[0], 0.8).await;

    let v = derive(&pool, k).await;
    assert_eq!(v.inputs.legacy_compound_edge_items, 1);
    assert_eq!(v.inputs.items, 2);
    assert!(near(v.bel, 0.4, 1e-9), "T .5 · .8 = .4, got {}", v.bel);
    assert_eq!(
        derive(&pool, plain).await.inputs.legacy_compound_edge_items,
        0
    );
}

// ── atom views and the shadow field ─────────────────────────────────────────

/// An atom's view: `Axiom` from its fold, `Legacy` from a kept cache with no
/// AEF input, `Unproven` with neither.
#[sqlx::test(migrations = "../../migrations")]
async fn an_atom_s_view_names_its_basis(pool: PgPool) {
    let author = agent(&pool).await;
    let evidenced = claim(&pool, author, "evidenced").await;
    support(&pool, evidenced, 0.8).await;
    let cached = claim(&pool, author, "cached").await;
    set_cache(&pool, cached, 0.4, 0.7, 0.62, 0.1).await;
    let bare = claim(&pool, author, "bare").await;

    let viewer = fixture::public_viewer(&pool).await;
    let mut conn = pool.acquire().await.expect("conn");
    let views = atom_belief_view_batch(&mut conn, &viewer, &[evidenced, cached, bare], &ctx())
        .await
        .expect("atom views");
    let e = &views[&evidenced];
    assert_eq!(e.basis, Basis::Axiom);
    assert!(near(e.bel, 0.8, 1e-9));
    let c = &views[&cached];
    assert_eq!(c.basis, Basis::Legacy);
    assert!(near(c.bel, 0.4, 1e-9) && near(c.pl, 0.7, 1e-9) && near(c.betp, 0.62, 1e-9));
    let b = &views[&bare];
    assert_eq!(b.basis, Basis::Unproven);
    assert!(near(b.bel, 0.0, 1e-9) && near(b.pl, 1.0, 1e-9) && near(b.betp, 0.5, 1e-9));
}

/// `get_belief`'s shadow (SPEC §7.1): nothing in `legacy` mode; in `shadow`
/// mode a compound's derived view and an atom's AEF view.
#[sqlx::test(migrations = "../../migrations")]
async fn the_shadow_view_exists_only_in_shadow_mode(pool: PgPool) {
    let author = agent(&pool).await;
    let k = claim(&pool, author, "K").await;
    let (a1, a2) = (
        claim(&pool, author, "a1").await,
        claim(&pool, author, "a2").await,
    );
    decompose(&pool, k, a1).await;
    decompose(&pool, k, a2).await;
    support(&pool, a1, 0.8).await;
    support(&pool, a2, 0.8).await;
    let viewer = fixture::public_viewer(&pool).await;

    assert!(shadow_belief(&pool, &viewer, k, CompoundBeliefMode::Legacy)
        .await
        .is_none());
    let sk = shadow_belief(&pool, &viewer, k, CompoundBeliefMode::Shadow)
        .await
        .expect("compound shadow");
    assert_eq!(sk.basis, Basis::Derived);
    assert!(near(sk.bel, 0.64, 1e-9), "{}", sk.bel);
    let sa = shadow_belief(&pool, &viewer, a1, CompoundBeliefMode::Shadow)
        .await
        .expect("atom shadow");
    assert_eq!(sa.basis, Basis::Axiom);
    assert!(near(sa.bel, 0.8, 1e-9), "{}", sa.bel);
}

// ── review: not_all sources counted once ────────────────────────────────────

/// A refuting X→K edge whose refutation already sits on one of K's leaves (a
/// retargeted parent: the parent edge stays in force and X now also refutes
/// the atom a1, whose frozen edge-factor BBA {F .64} is in a1's fold) is
/// counted once, on a1: K = a1 ∧ a2 is a1's fold (.590) times .8 = .472, Pl
/// a1's .738. Counted twice (the parent as `not_all` m .64 on top) it would
/// be ≈ .243. The control: the same atom edge with no frozen BBA (an unwired
/// retarget) puts nothing on the leaf, so the parent edge still refutes the
/// whole, at m = .8 (refutes) × .8 = .64: Bel .390, Pl .610.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retargeted_refutation_is_counted_once_on_the_atom(pool: PgPool) {
    let author = agent(&pool).await;
    let x = claim(&pool, author, "X").await;
    support(&pool, x, 0.8).await;

    let (k, leaves) = compound_of(&pool, author, "K", 2).await;
    for &l in &leaves {
        support(&pool, l, 0.8).await;
    }
    let parent = edge(&pool, x, k, "refutes").await;
    let atom_edge = edge(&pool, x, leaves[0], "refutes").await;
    store_edge_factor(
        &pool,
        atom_edge,
        leaves[0],
        serde_json::json!({"1": 0.64, "0,1": 0.36}),
    )
    .await;
    sqlx::query(
        "UPDATE edges SET properties = jsonb_build_object( \
             'retargeted_to', jsonb_build_array($2::text), 'retarget_unwired', '[]'::jsonb) \
         WHERE id = $1",
    )
    .bind(parent)
    .bind(atom_edge.to_string())
    .execute(&pool)
    .await
    .expect("mark the parent retargeted");

    let v = derive(&pool, k).await;
    let not_all = v.derived.as_ref().expect("derived").not_all;
    assert_eq!(
        not_all.leaf_edge_skipped, 1,
        "the parent edge is skipped and counted"
    );
    assert!(
        near(not_all.m, 0.0, 1e-12) && not_all.sources == 0,
        "the parent's refutation already sits on a1: not_all must be empty, got m {} from {} \
         sources",
        not_all.m,
        not_all.sources
    );
    assert!(
        near(v.bel, 0.4721, 5e-4) && near(v.pl, 0.7377, 5e-4),
        "counted once: Bel .472, Pl .738; got Bel {} Pl {}",
        v.bel,
        v.pl
    );

    // Control: the atom edge carries no BBA, so the parent still counts.
    let (k2, leaves2) = compound_of(&pool, author, "K unwired", 2).await;
    for &l in &leaves2 {
        support(&pool, l, 0.8).await;
    }
    edge(&pool, x, k2, "refutes").await;
    edge(&pool, x, leaves2[0], "refutes").await;
    let v2 = derive(&pool, k2).await;
    assert_eq!(v2.derived.as_ref().unwrap().not_all.leaf_edge_skipped, 0);
    assert!(
        near(v2.derived.as_ref().unwrap().not_all.m, 0.64, 1e-9),
        "an unwired atom edge leaves the parent's refutation on the whole: m .64, got {}",
        v2.derived.as_ref().unwrap().not_all.m
    );
    assert!(
        near(v2.bel, 0.3902, 5e-4) && near(v2.pl, 0.6098, 5e-4),
        "refutes (.8) from X at .8 over Bel .64: Bel .390, Pl .610; got Bel {} Pl {}",
        v2.bel,
        v2.pl
    );
}

/// Two negative siblings serve the Fréchet envelope, and the compound's
/// `not_all` valuation still meets it. Three independent .8 leaves give the
/// envelope [.4, 1]; refuted as a whole at .7, the floor follows the
/// valuation (.4·.3/(1 − .7·.4) = .167) and Pl and NR are bounded by the
/// largest Bel the conjunction can have, min Belᵢ = .8: .3/(1 − .7·.8) = .682,
/// not 1. The envelope still contains the independent coupling's value
/// (R-DEP with the valuation: Bel .239, Pl .468), and the twin without the
/// refutation still serves Pl = NR = 1.
#[sqlx::test(migrations = "../../migrations")]
async fn the_envelope_of_contested_siblings_meets_the_not_all_valuation(pool: PgPool) {
    let author = agent(&pool).await;
    let mut views = Vec::new();
    for refuted in [true, false] {
        let (k, b) = compound_of(&pool, author, "contested", 3).await;
        for &l in &b {
            support(&pool, l, 0.8).await;
        }
        edge(&pool, b[0], b[1], "contradicts").await;
        edge(&pool, b[1], b[2], "refutes").await;
        if refuted {
            refute(&pool, k, 0.7).await;
        }
        views.push(derive(&pool, k).await);
    }
    let (v, twin) = (&views[0], &views[1]);
    let d = v.derived.as_ref().expect("derived");
    assert!(d.internally_contested);
    assert!(near(d.not_all.m, 0.7, 1e-9), "not_all m {}", d.not_all.m);
    assert!(
        near(v.bel, 0.1667, 5e-4),
        "the floor follows the valuation: .167, got {}",
        v.bel
    );
    assert!(
        near(v.pl, 0.6818, 5e-4) && near(v.nr, 0.6818, 5e-4),
        "a compound refuted as a whole at .7 is not served Pl or NR 1: .682, got Pl {} NR {}",
        v.pl,
        v.nr
    );
    assert!(
        v.bel <= 0.2394 + 1e-9 && v.pl >= 0.4676 - 1e-9 && v.nr >= 0.4676 - 1e-9,
        "the envelope contains the independent coupling (.239 / .468): [{}, {}], NR {}",
        v.bel,
        v.pl,
        v.nr
    );
    assert!(
        near(twin.pl, 1.0, 1e-9) && near(twin.nr, 1.0, 1e-9),
        "control: without the refutation the envelope is [.4, 1]: Pl {} NR {}",
        twin.pl,
        twin.nr
    );
}

/// A compound's own refutation row has moved to the atoms only when an
/// `attributed_v1` row cites it on one of THIS compound's leaves, as the
/// viewer sees it:
/// - one paper's refutation filed on K1 and K2 (disjoint leaves), attributed
///   to a leaf of K1 only: K1's row has moved (m 0), K2's has not (m .7);
/// - a citation the viewer cannot read moves nothing for that viewer.
#[sqlx::test(migrations = "../../migrations")]
async fn an_own_refutation_moves_only_with_a_citation_on_this_compound_s_leaves(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "bv-owner").await;
    let owner = Viewer::resolve(&pool, member).await.expect("owner viewer");
    let public = fixture::public_viewer(&pool).await;
    let author = agent(&pool).await;
    let x = agent(&pool).await;
    let m_of = |v: &BeliefView| v.derived.as_ref().expect("derived").not_all.m;

    // One refutation filed on two compounds with disjoint leaves.
    let (k1, l1) = compound_of(&pool, author, "K1", 2).await;
    let (k2, _) = compound_of(&pool, author, "K2", 2).await;
    let ev = doi_evidence(&pool, k1, "10.5555/bv-shared-refutation", x).await;
    for k in [k1, k2] {
        store(
            &pool,
            k,
            citing(x, ev),
            serde_json::json!({"1": 0.7, "0,1": 0.3}),
        )
        .await;
    }
    attribute(
        &pool,
        l1[0],
        ev,
        x,
        serde_json::json!({"1": 0.7, "0,1": 0.3}),
    )
    .await;
    assert!(
        near(m_of(&derive(&pool, k1).await), 0.0, 1e-12),
        "K1's refutation sits on its leaf now"
    );
    let m2 = m_of(&derive(&pool, k2).await);
    assert!(
        near(m2, 0.7, 1e-9),
        "an attribution onto another compound's leaf moves nothing off K2: m .7, got {m2}"
    );

    // A citation only the group can read.
    let (k5, l5) = compound_of(&pool, author, "privately attributed", 2).await;
    let ev5 = doi_evidence(&pool, k5, "10.5555/bv-private-citer", x).await;
    store(
        &pool,
        k5,
        citing(x, ev5),
        serde_json::json!({"1": 0.7, "0,1": 0.3}),
    )
    .await;
    let citer = attribute(
        &pool,
        l5[0],
        ev5,
        x,
        serde_json::json!({"1": 0.7, "0,1": 0.3}),
    )
    .await;
    hide_row(&pool, citer, group).await;
    let m_pub = m_of(&derive_one_as(&pool, &public, k5).await);
    let m_grp = m_of(&derive_one_as(&pool, &owner, k5).await);
    assert!(
        near(m_pub, 0.7, 1e-9) && near(m_grp, 0.0, 1e-12),
        "the public cannot see the citation (m .7); the group can (m 0); got {m_pub} / {m_grp}"
    );
}

/// Only the side of a mixed own row that an `attributed_v1` row carried to a
/// leaf has moved (SPEC §5.3). A mixed row (t .3, f .2) whose refutation was
/// attributed to a leaf no longer refutes the whole (m 0); the same row whose
/// SUPPORT was attributed keeps its f on the compound (m .2).
#[sqlx::test(migrations = "../../migrations")]
async fn a_mixed_own_row_keeps_on_the_compound_the_side_that_did_not_move(pool: PgPool) {
    let author = agent(&pool).await;
    let x = agent(&pool).await;
    let m_of = |v: &BeliefView| v.derived.as_ref().expect("derived").not_all.m;

    // A mixed row whose refutation moved, and one whose support moved.
    let mixed = serde_json::json!({"0": 0.3, "1": 0.2, "0,1": 0.5});
    let (k3, l3) = compound_of(&pool, author, "mixed, f moved", 2).await;
    let ev3 = doi_evidence(&pool, k3, "10.5555/bv-mixed-f", x).await;
    store(&pool, k3, citing(x, ev3), mixed.clone()).await;
    attribute(
        &pool,
        l3[0],
        ev3,
        x,
        serde_json::json!({"1": 0.2, "0,1": 0.8}),
    )
    .await;
    let m3 = m_of(&derive(&pool, k3).await);
    assert!(
        near(m3, 0.0, 1e-12),
        "a mixed row whose refutation was attributed has moved its f: m 0, got {m3}"
    );
    let (k4, l4) = compound_of(&pool, author, "mixed, t moved", 2).await;
    let ev4 = doi_evidence(&pool, k4, "10.5555/bv-mixed-t", x).await;
    store(&pool, k4, citing(x, ev4), mixed).await;
    attribute(
        &pool,
        l4[0],
        ev4,
        x,
        serde_json::json!({"0": 0.3, "0,1": 0.7}),
    )
    .await;
    let m4 = m_of(&derive(&pool, k4).await);
    assert!(
        near(m4, 0.2, 1e-9),
        "a mixed row whose support was attributed keeps its f on the compound: m .2, got {m4}"
    );
}

/// A promoted hypothesis reads its promoted `research_validity` copy and an
/// unpromoted one its `hypothesis_assessment` row, never both (SPEC §11.4),
/// on a compound's own rows as on an atom's: one f .5 assessment refutes the
/// whole at m .5 either side of promotion, not 1 − .5² = .75.
#[sqlx::test(migrations = "../../migrations")]
async fn a_compound_hypothesis_reads_one_frame_either_side_of_promotion(pool: PgPool) {
    let author = agent(&pool).await;
    let experimenter = agent(&pool).await;
    let ha = frame(
        &pool,
        "hypothesis_assessment",
        &["supported", "unsupported"],
    )
    .await;
    let rv = frame(&pool, "research_validity", &["valid", "invalid"]).await;
    for promoted in [false, true] {
        let (h, _) = compound_of(&pool, author, "hypothesis", 2).await;
        for f in [ha, rv] {
            store_on(
                &pool,
                h,
                f,
                Row {
                    method: Some("error_derived"),
                    ..Row::plain(experimenter)
                },
                serde_json::json!({"1": 0.5, "0,1": 0.5}),
            )
            .await;
        }
        if promoted {
            sqlx::query(
                "UPDATE claims SET properties = properties || \
                 '{\"hypothesis_status\": \"promoted\"}' WHERE id = $1",
            )
            .bind(h)
            .execute(&pool)
            .await
            .expect("promote");
        }
        let m = derive(&pool, h).await.derived.expect("derived").not_all.m;
        assert!(
            near(m, 0.5, 1e-9),
            "promoted {promoted}: one assessment, read once: m .5, got {m}"
        );
    }
}
