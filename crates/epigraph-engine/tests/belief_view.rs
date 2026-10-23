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

async fn binary(pool: &PgPool) -> Uuid {
    let viewer = fixture::public_viewer(pool).await;
    if let Some(f) = FrameRepository::get_by_name(pool, &viewer, "binary_truth")
        .await
        .expect("frame lookup")
    {
        return f.id;
    }
    FrameRepository::create(
        pool,
        "binary_truth",
        None,
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("frame")
    .id
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
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        b,
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

/// A view as JSON without its claim id, every number rounded to 1e-12, so
/// two twin compounds compare by everything they disclose. (The twin's items
/// have other row ids, so the conjunction may sum them in another order.)
fn disclosed(v: &BeliefView) -> serde_json::Value {
    fn round(j: &mut serde_json::Value) {
        match j {
            serde_json::Value::Number(n) => {
                if let Some(f) = n.as_f64() {
                    if n.is_f64() {
                        *j = serde_json::json!((f * 1e12).round() / 1e12);
                    }
                }
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(round),
            serde_json::Value::Object(o) => o.values_mut().for_each(round),
            _ => {}
        }
    }
    let mut j = serde_json::to_value(v).expect("serialize");
    j.as_object_mut().expect("object").remove("claim_id");
    round(&mut j);
    j
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
    assert_eq!(
        disclosed(&pub_view),
        disclosed(&twin_view),
        "the public response over a tree with a private atom must be the response over \
         a tree without one"
    );
}

/// A compound's view does not depend on which other compounds share its batch
/// (the items are partitioned once over the whole batch).
#[sqlx::test(migrations = "../../migrations")]
async fn a_compound_s_view_does_not_depend_on_its_batch(pool: PgPool) {
    let public = fixture::public_viewer(&pool).await;
    let (r, m1, _) = example_three(&pool, None).await;
    let alone = derive_as(&pool, &public, &[r], &ctx()).await;
    let together = derive_as(&pool, &public, &[r, m1], &ctx()).await;
    assert_eq!(alone.get(&r), together.get(&r));
    let m1_alone = derive_as(&pool, &public, &[m1], &ctx()).await;
    assert_eq!(m1_alone.get(&m1), together.get(&m1));
    assert!(
        near(together[&m1].bel, 0.4846, 5e-5),
        "M1 = a1 ∧ a2 over its own leaves (.4846), got {}",
        together[&m1].bel
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
        d2.internally_contested,
        "two negative siblings are contested"
    );
    assert!(
        near(v2.bel, 0.4, 1e-9) && near(v2.pl, 1.0, 1e-9),
        "two siblings serve the envelope [.4, 1], got Bel {} Pl {}",
        v2.bel,
        v2.pl
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
