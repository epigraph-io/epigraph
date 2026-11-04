//! The read-only dry-run belief delta (supersede SPEC §11 K0, X-3).
//!
//! * The ORACLE is the real cascade on the same throwaway database: the
//!   delta runs first, then the fixes' own write paths run over the rows it
//!   measured (the K10(2) arm through `cascade_after_supersede`, the edge-BBA
//!   removal and repair through `delete_for_perspective` +
//!   `cascade_after_edge_withdrawal` for the `supersedes` rows, and the K3
//!   mint `regenerate_superseded_edge_factors_conn` for the R-131 set), and
//!   every value the delta predicted must be the value the cascade wrote.
//! * The delta's transaction is READ ONLY (a write inside it fails 25006), and
//!   a full run changes no row count, no cache column and no audit row.
//! * A claim no selected row touches is absent from every block.
//! * The delta's source names no write path (a grep pin; the READ ONLY
//!   transaction is the guarantee by construction).
//!
//! The fixture is a retirement the K10(2) arm never saw (a claim retired
//! before it existed): a refuter R retired by a plain `is_current` flip, so
//! its stayed edges' BBAs still weigh on current claims. It also holds rows
//! each selection must NOT return (a `supersedes`-keyed row on a retired
//! holder, a retracted `supersedes`-keyed row, a withdrawn factorless edge),
//! and one claim that loses rows to BOTH K10(3) and K12(b), so the `combined`
//! block is checked against the real writes too.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::visibility::{SystemReason, Viewer};
use epigraph_db::{ClaimRepository, MassFunctionRepository, PerspectiveRepository, PgPool};
use epigraph_engine::edge_factor::{auto_wire_ds_for_edge, ensure_binary_frame, EdgeFactorOutcome};
use epigraph_engine::supersede_delta::r173::R173Options;
use epigraph_engine::supersede_delta::{
    begin_read_only, run_read_only, ClaimDelta, DeltaItems, DeltaOptions, DeltaOutcome,
};
use uuid::Uuid;

const ALL: DeltaOptions = DeltaOptions {
    items: DeltaItems {
        r131: true,
        k10_retro: true,
        k12b: true,
        // The calibration item has its own suite (`r173_calibration_delta.rs`).
        r173: false,
    },
    top: 50,
    statement_timeout_ms: None,
    r173: R173Options {
        thresholds: Vec::new(),
        chunk: None,
        canary: None,
        only: None,
    },
};

struct World {
    /// Held: dropping it closes the pool the bypass viewer was minted from.
    _scoped: epigraph_db::ScopedPool,
    viewer: Viewer,
    retired: Uuid,
    successor: Uuid,
    refuted: Uuid,
    lonely: Uuid,
    kept_holder: Uuid,
    lineage_edge: Uuid,
    lineage_target: Uuid,
    /// Loses a K10(3) row (from the retired refuter) AND a K12(b) row.
    overlap: Uuid,
    overlap_lineage_edge: Uuid,
    /// Holds a live `supersedes`-keyed row, but is retired.
    retired_lineage_holder: Uuid,
    /// Holds only a RETRACTED `supersedes`-keyed row.
    retracted_lineage_holder: Uuid,
    /// The group-private holder of a row from the retired refuter, when the
    /// world was built with one.
    private_holder: Option<Uuid>,
    bystander: Uuid,
    r131: Vec<(Uuid, Uuid)>,
}

async fn believed(pool: &PgPool, agent: Uuid, tag: &str, bel: f64, pl: f64) -> Uuid {
    let id = fixture::seed_public_claim(pool, agent, tag).await;
    sqlx::query("UPDATE claims SET belief = $2, plausibility = $3 WHERE id = $1")
        .bind(id)
        .bind(bel)
        .bind(pl)
        .execute(pool)
        .await
        .expect("plant an interval");
    id
}

async fn edge(pool: &PgPool, s: Uuid, t: Uuid, rel: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(s)
    .bind(t)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("insert edge")
}

async fn wire(pool: &PgPool, viewer: &Viewer, agent: Uuid, s: Uuid, t: Uuid, rel: &str) -> Uuid {
    let e = edge(pool, s, t, rel).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let out = auto_wire_ds_for_edge(&mut conn, viewer, e, agent, s, t, rel)
        .await
        .expect("auto-wire");
    assert_eq!(
        out,
        EdgeFactorOutcome::Wired,
        "PREMISE: {rel} {s}->{t} wires"
    );
    e
}

async fn stamp(conn: &mut sqlx::PgConnection, pool: &PgPool, agent: Uuid) {
    let v = Viewer::resolve(pool, agent).await.expect("resolve viewer");
    let csv = |g: &[Uuid]| g.iter().map(Uuid::to_string).collect::<Vec<_>>().join(",");
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(csv(v.group_bind().expect("scoped viewer")))
    .bind(csv(v.writable_groups()))
    .bind(agent.to_string())
    .execute(&mut *conn)
    .await
    .expect("stamp the session");
}

/// A public claim owned by `group` (so `owner` may retract rows it holds).
async fn owned_claim(pool: &PgPool, owner: Uuid, group: Uuid, tag: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(tag)
    .bind(&hash)
    .bind(owner)
    .bind(group)
    .execute(pool)
    .await
    .expect("a public claim owned by the owner's group");
    id
}

/// Store a BBA on `holder` keyed on `edge` (a pre-K12(b) `supersedes` row:
/// nothing wires one any more) and return its id.
async fn store_on_edge(pool: &PgPool, holder: Uuid, frame: Uuid, agent: Uuid, edge: Uuid) -> Uuid {
    let mut conn = pool.acquire().await.expect("acquire");
    PerspectiveRepository::ensure_edge_perspective(&mut *conn, edge, Some(agent))
        .await
        .expect("edge perspective");
    MassFunctionRepository::store_with_perspective(
        &mut *conn,
        holder,
        frame,
        Some(agent),
        Some(edge),
        &serde_json::json!({"1": 0.7, "0,1": 0.3}),
        None,
        Some("edge_factor"),
        Some(0.9),
        Some("contradicts"),
        "cross",
        None,
    )
    .await
    .expect("the pre-K12(b) supersedes BBA");
    sqlx::query_scalar("SELECT id FROM mass_functions WHERE perspective_id = $1 AND claim_id = $2")
        .bind(edge)
        .bind(holder)
        .fetch_one(&mut *conn)
        .await
        .expect("the stored row")
}

/// Retract `row` as `owner` through the real repository path.
async fn retract_as(pool: &PgPool, owner: Uuid, row: Uuid) {
    let p = pool.clone();
    let retracted = fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, &p, owner).await;
        let r = MassFunctionRepository::retract_conn(&mut conn, row, "k0 fixture", None).await;
        (conn, r)
    })
    .await
    .expect("the owner retracts the row through the real path");
    assert_eq!(retracted.status.as_str(), "retracted", "PREMISE");
}

async fn retire(pool: &PgPool, id: Uuid) {
    sqlx::query(
        "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
          WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("retire by a plain flip");
}

async fn world(pool: &PgPool) -> World {
    world_with(pool, false).await
}

/// `private`: also give the retired refuter a live row on a GROUP-private
/// holder in a group no fixture agent below shares.
async fn world_with(pool: &PgPool, private: bool) -> World {
    let (scoped, bypass) = fixture::bypass(pool).await;
    let public = fixture::public_viewer(pool).await;
    let (agent, _) = fixture::seed_agent_with_group(pool, "k0-author").await;
    let (owner, group) = fixture::seed_agent_with_group(pool, "k0-owner").await;
    let frame = ensure_binary_frame(&mut pool.acquire().await.expect("acquire"), &public)
        .await
        .expect("binary frame");

    // K10(3): a refuter, later retired, with a refuted target that keeps a
    // supporter, a claim it alone contradicts, and a third holder whose row
    // from it is RETRACTED.
    let retired = believed(pool, agent, "k0 refuter", 0.9, 0.95).await;
    let supporter = believed(pool, agent, "k0 supporter", 0.6, 0.7).await;
    let refuted = fixture::seed_public_claim(pool, agent, "k0 refuted").await;
    let lonely = fixture::seed_public_claim(pool, agent, "k0 lonely").await;
    let kept_holder = owned_claim(pool, owner, group, "k0 kept holder").await;
    // The overlap claim: refuted by R AND (below) holding a supersedes row,
    // with a supporter that survives both removals.
    let overlap = fixture::seed_public_claim(pool, agent, "k0 overlap").await;
    let overlap_supporter = believed(pool, agent, "k0 overlap supporter", 0.65, 0.75).await;
    wire(pool, &public, agent, retired, refuted, "refutes").await;
    wire(pool, &public, agent, supporter, refuted, "supports").await;
    wire(pool, &public, agent, retired, lonely, "contradicts").await;
    wire(pool, &public, agent, retired, overlap, "refutes").await;
    wire(pool, &public, agent, overlap_supporter, overlap, "supports").await;
    let kept_edge = wire(pool, &public, agent, retired, kept_holder, "contradicts").await;
    let private_holder = if private {
        let (pagent, pgroup) = fixture::seed_agent_with_group(pool, "k0-private").await;
        let holder = fixture::seed_group_claim(pool, pagent, pgroup, "k0 private holder").await;
        // The public viewer cannot see a group-private holder; the bypass
        // viewer on this superuser connection can.
        wire(pool, &bypass, agent, retired, holder, "refutes").await;
        Some(holder)
    } else {
        None
    };
    let kept_row: Uuid =
        sqlx::query_scalar("SELECT id FROM mass_functions WHERE perspective_id = $1")
            .bind(kept_edge)
            .fetch_one(pool)
            .await
            .expect("the row to retract");
    retract_as(pool, owner, kept_row).await;
    // The retirement the K10(2) arm never saw.
    retire(pool, retired).await;
    let successor = fixture::seed_public_claim(pool, agent, "k0 successor").await;

    // K12(b): a graph-only lineage edge between current claims whose target
    // holds a BBA wired on it before K12(b), next to a supporter's.
    let newer = believed(pool, agent, "k0 newer", 0.85, 0.9).await;
    let lineage_target = fixture::seed_public_claim(pool, agent, "k0 lineage target").await;
    let other = believed(pool, agent, "k0 other supporter", 0.7, 0.8).await;
    wire(pool, &public, agent, other, lineage_target, "supports").await;
    let lineage_edge = edge(pool, newer, lineage_target, "supersedes").await;
    store_on_edge(pool, lineage_target, frame, agent, lineage_edge).await;
    let overlap_lineage_edge = edge(pool, newer, overlap, "SUPERSEDES").await;
    store_on_edge(pool, overlap, frame, agent, overlap_lineage_edge).await;
    let mut conn = pool.acquire().await.expect("acquire");
    for holder in [lineage_target, overlap] {
        epigraph_engine::edge_factor::recompute_claim_belief_on_frame(
            &mut conn, &public, holder, frame,
        )
        .await
        .expect("its cache folds every row it holds");
    }
    drop(conn);

    // NOT selected by K12(b): a live supersedes-keyed row on a RETIRED
    // holder, and a RETRACTED supersedes-keyed row on a current holder.
    let retired_lineage_holder =
        fixture::seed_public_claim(pool, agent, "k0 retired lineage holder").await;
    let e = edge(pool, newer, retired_lineage_holder, "supersedes").await;
    let row = store_on_edge(pool, retired_lineage_holder, frame, agent, e).await;
    retire(pool, retired_lineage_holder).await;
    let still: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions WHERE id = $1 AND retracted_at IS NULL",
    )
    .bind(row)
    .fetch_one(pool)
    .await
    .expect("count");
    assert_eq!(still, 1, "PREMISE: the retired holder keeps its live row");
    let retracted_lineage_holder =
        owned_claim(pool, owner, group, "k0 retracted lineage holder").await;
    let e = edge(pool, newer, retracted_lineage_holder, "supersedes").await;
    let row = store_on_edge(pool, retracted_lineage_holder, frame, agent, e).await;
    retract_as(pool, owner, row).await;

    // A bystander: a supported claim no selection touches.
    let s2 = believed(pool, agent, "k0 bystander supporter", 0.8, 0.9).await;
    let bystander = fixture::seed_public_claim(pool, agent, "k0 bystander").await;
    wire(pool, &public, agent, s2, bystander, "supports").await;

    // R-131: three factorless edges between current claims, two of them a
    // symmetric pair that shares one (type, pair) slot.
    let c1 = fixture::seed_public_claim(pool, agent, "k0 c1").await;
    let c2 = fixture::seed_public_claim(pool, agent, "k0 c2").await;
    let c3 = fixture::seed_public_claim(pool, agent, "k0 c3").await;
    let c4 = fixture::seed_public_claim(pool, agent, "k0 c4").await;
    let e1 = edge(pool, c1, c2, "corroborates").await;
    let e2 = edge(pool, c2, c1, "corroborates").await;
    let e3 = edge(pool, c3, c4, "refutes").await;
    // NOT selected by R-131: a factorless corroborates edge between current
    // claims that is no longer in force.
    let c5 = fixture::seed_public_claim(pool, agent, "k0 c5").await;
    let c6 = fixture::seed_public_claim(pool, agent, "k0 c6").await;
    let e4 = edge(pool, c5, c6, "corroborates").await;
    sqlx::query("UPDATE edges SET valid_to = now() - interval '1 day' WHERE id = $1")
        .bind(e4)
        .execute(pool)
        .await
        .expect("withdraw the edge");
    let dropped =
        sqlx::query("DELETE FROM factors WHERE properties->>'source_edge_id' = ANY($1::text[])")
            .bind(vec![
                e1.to_string(),
                e2.to_string(),
                e3.to_string(),
                e4.to_string(),
            ])
            .execute(pool)
            .await
            .expect("drop the trigger's factors (a casefold UPDATE never minted them)")
            .rows_affected();
    assert!(dropped >= 2, "PREMISE: the trigger minted their factors");
    let e4_factors: i64 =
        sqlx::query_scalar("SELECT count(*) FROM factors WHERE properties->>'source_edge_id' = $1")
            .bind(e4.to_string())
            .fetch_one(pool)
            .await
            .expect("count");
    assert_eq!(e4_factors, 0, "PREMISE: the withdrawn edge is factorless");

    World {
        _scoped: scoped,
        viewer: bypass,
        retired,
        successor,
        refuted,
        lonely,
        kept_holder,
        lineage_edge,
        lineage_target,
        overlap,
        overlap_lineage_edge,
        retired_lineage_holder,
        retracted_lineage_holder,
        private_holder,
        bystander,
        r131: vec![(c1, e1), (c1, e2), (c3, e3)],
    }
}

type Cache = (Option<f64>, Option<f64>, Option<f64>);

async fn cache(pool: &PgPool, id: Uuid) -> Cache {
    sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read cache")
}

fn ids(claims: &[ClaimDelta]) -> Vec<Uuid> {
    claims.iter().map(|c| c.id).collect()
}

fn sorted(mut v: Vec<Uuid>) -> Vec<Uuid> {
    v.sort();
    v
}

fn find(claims: &[ClaimDelta], id: Uuid) -> &ClaimDelta {
    claims
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{id} is in the block: {claims:?}"))
}

fn close(a: Option<f64>, b: Option<f64>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => (x - y).abs() < 1e-12,
        (None, None) => true,
        _ => false,
    }
}

async fn assert_written_as_predicted(pool: &PgPool, claims: &[ClaimDelta]) {
    for c in claims {
        let new = c
            .new
            .unwrap_or_else(|| panic!("{} has a prediction: {c:?}", c.id));
        let (bel, pl, betp) = cache(pool, c.id).await;
        assert!(
            close(bel, new.belief) && close(pl, new.plausibility) && close(betp, new.betp),
            "{}: the cascade wrote ({bel:?}, {pl:?}, {betp:?}); the delta predicted {new:?}",
            c.id
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_delta_predicts_what_the_real_cascade_then_writes(pool: PgPool) {
    let w = world(&pool).await;
    let bystander_before = cache(&pool, w.bystander).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let report = run_read_only(&mut conn, &w.viewer, &ALL)
        .await
        .expect("the delta runs");

    // ── What it measured ──
    let k10 = report.k10_retro.as_ref().expect("k10-retro block");
    assert_eq!(
        (
            k10.live_rows,
            k10.edges,
            k10.retired_sources,
            k10.retracted_key_kept
        ),
        (3, 3, 1, 1),
        "three live rows on three edges from one retired source; the retracted one is kept: {k10:?}"
    );
    assert_eq!(
        ids(&k10.delta.claims),
        sorted(vec![w.refuted, w.lonely, w.overlap]),
        "{k10:?}"
    );
    assert!(
        !ids(&k10.delta.claims).contains(&w.kept_holder),
        "a holder whose only row from the retired claim is retracted is not affected"
    );
    let refuted = &k10.delta.claims[k10
        .delta
        .claims
        .iter()
        .position(|c| c.id == w.refuted)
        .unwrap()];
    assert_eq!(refuted.outcome, DeltaOutcome::Recomputed);
    assert!(
        refuted.delta.expect("a delta").abs() > 1e-9,
        "dropping the refuter moves the refuted claim: {refuted:?}"
    );
    let lonely = &k10.delta.claims[k10
        .delta
        .claims
        .iter()
        .position(|c| c.id == w.lonely)
        .unwrap()];
    assert_eq!(lonely.outcome, DeltaOutcome::Unbacked, "{lonely:?}");

    let k12b = report.k12b.as_ref().expect("k12b block");
    assert_eq!(
        k12b.ds_rows, 2,
        "only the live rows on CURRENT holders: not the retired holder's live row, not the \
         retracted row: {k12b:?}"
    );
    assert_eq!(
        k12b.ds_rows_by_spelling,
        [("SUPERSEDES".to_string(), 1), ("supersedes".to_string(), 1)]
            .into_iter()
            .collect(),
        "both spellings are selected and counted apart"
    );
    assert_eq!(
        ids(&k12b.ds_delta.claims),
        sorted(vec![w.lineage_target, w.overlap]),
        "{k12b:?}"
    );
    for absent in [w.retired_lineage_holder, w.retracted_lineage_holder] {
        assert!(
            !ids(&k12b.ds_delta.claims).contains(&absent),
            "{absent}: a retired holder, or a holder of only a retracted row, is not affected"
        );
    }
    assert!(k12b.ds_counterfactual);

    let r131 = report.r131.as_ref().expect("r131 block");
    assert_eq!(
        (r131.edges, r131.slots_minted, r131.edges_on_held_slots),
        (3, 2, 0),
        "three factorless edges in force (not the withdrawn one), two slots (the symmetric pair \
         shares one): {r131:?}"
    );

    let combined = report.combined.as_ref().expect("combined block");
    assert_eq!(
        ids(&combined.claims),
        sorted(vec![w.refuted, w.lonely, w.lineage_target, w.overlap])
    );
    let both = find(&combined.claims, w.overlap);
    assert_eq!(
        (both.causes.clone(), both.rows_removed, both.outcome),
        (vec!["k10_retro", "k12b_ds"], 2, DeltaOutcome::Recomputed),
        "the overlap claim loses one row to each cause and keeps its supporter: {both:?}"
    );
    assert!(
        (both.new.and_then(|n| n.betp)).is_some()
            && find(&k10.delta.claims, w.overlap).new != both.new
            && find(&k12b.ds_delta.claims, w.overlap).new != both.new,
        "the combined value differs from each single-cause value, so it is a real union fold"
    );
    for block in [&k10.delta, &k12b.ds_delta, combined] {
        assert!(
            !ids(&block.claims).contains(&w.bystander),
            "a claim with no affected edge reports no delta"
        );
    }

    // ── The oracle: the real write paths over the same rows ──
    // K12(b) alone on the overlap claim, in a transaction rolled back: the
    // real removal + repair, before K10(2) runs, so the single-cause value can
    // be compared with what the write path does (the final state below holds
    // both removals, which is the `combined` value).
    {
        let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
        let n = MassFunctionRepository::delete_for_perspective(&mut *tx, w.overlap_lineage_edge)
            .await
            .expect("remove the overlap's supersedes BBA");
        assert_eq!(n, 1);
        let r = epigraph_engine::retraction_cascade::cascade_after_edge_withdrawal(
            &mut tx,
            &w.viewer,
            &[w.overlap],
            n,
        )
        .await;
        assert!(r.errors.is_empty(), "{r:?}");
        let written: Cache =
            sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
                .bind(w.overlap)
                .fetch_one(&mut *tx)
                .await
                .expect("read inside the transaction");
        let predicted = find(&k12b.ds_delta.claims, w.overlap)
            .new
            .expect("a prediction");
        assert!(
            close(written.0, predicted.belief)
                && close(written.1, predicted.plausibility)
                && close(written.2, predicted.betp),
            "K12(b) alone on the overlap claim: wrote {written:?}, predicted {predicted:?}"
        );
        tx.rollback().await.expect("rollback");
    }

    let r = epigraph_engine::retraction_cascade::cascade_after_supersede(
        &mut conn,
        &w.viewer,
        w.retired,
        w.successor,
    )
    .await;
    assert!(r.errors.is_empty(), "{r:?}");
    assert_written_as_predicted(&pool, &k10.delta.claims).await;

    // The retracted row survived the real invalidation.
    let kept: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions WHERE claim_id = $1 AND retracted_at IS NOT NULL",
    )
    .bind(w.kept_holder)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(kept, 1, "the retracted row is kept");

    let mut n = 0;
    for e in [w.lineage_edge, w.overlap_lineage_edge] {
        let one = MassFunctionRepository::delete_for_perspective(&mut *conn, e)
            .await
            .expect("remove the supersedes BBA");
        assert_eq!(one, 1);
        n += one;
    }
    let r = epigraph_engine::retraction_cascade::cascade_after_edge_withdrawal(
        &mut conn,
        &w.viewer,
        &[w.lineage_target, w.overlap],
        n,
    )
    .await;
    assert!(r.errors.is_empty(), "{r:?}");
    // The overlap claim now holds BOTH removals: its single-cause K12(b)
    // value was checked in the rolled-back transaction above.
    let k12b_only: Vec<ClaimDelta> = k12b
        .ds_delta
        .claims
        .iter()
        .filter(|c| c.id != w.overlap)
        .cloned()
        .collect();
    assert_written_as_predicted(&pool, &k12b_only).await;
    assert_written_as_predicted(&pool, &combined.claims).await;

    let mut minted = 0;
    for (claim, e) in &w.r131 {
        minted +=
            ClaimRepository::regenerate_superseded_edge_factors_conn(&mut conn, *claim, &[*e])
                .await
                .expect("mint")
                .len();
    }
    assert_eq!(
        minted, r131.slots_minted,
        "the mint fills the slots the delta counted"
    );

    assert_eq!(
        cache(&pool, w.bystander).await,
        bystander_before,
        "the bystander is untouched by the real cascade too"
    );
}

/// `(table, rows)` for every table a write path of the fixes touches, plus a
/// digest of every claim's cache columns and `updated_at`.
async fn footprint(pool: &PgPool) -> (Vec<(String, i64)>, String) {
    let mut counts = Vec::new();
    for t in [
        "claims",
        "edges",
        "mass_functions",
        "factors",
        "perspectives",
        "frames",
        "security_events",
        "ds_combined_beliefs",
    ] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {t}"))
            .fetch_one(pool)
            .await
            .expect("count");
        counts.push((t.to_string(), n));
    }
    let digest: String = sqlx::query_scalar(
        "SELECT md5(string_agg(concat_ws('|', id, belief, plausibility, pignistic_prob, \
                mass_on_empty, mass_on_missing, classification, updated_at), ',' ORDER BY id)) \
           FROM claims",
    )
    .fetch_one(pool)
    .await
    .expect("digest");
    (counts, digest)
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_delta_is_read_only_and_a_run_changes_nothing(pool: PgPool) {
    let w = world(&pool).await;
    let before = footprint(&pool).await;

    let mut conn = pool.acquire().await.expect("acquire");
    {
        let mut tx = begin_read_only(&mut conn).await.expect("begin");
        let err = sqlx::query(
            "INSERT INTO frames (name, hypotheses) VALUES ('k0 probe', ARRAY['a','b'])",
        )
        .execute(&mut *tx)
        .await
        .expect_err("a write inside the delta's transaction is refused");
        let code = err
            .as_database_error()
            .and_then(|d| d.code())
            .map(|c| c.to_string());
        assert_eq!(code.as_deref(), Some("25006"), "{err}");
        tx.rollback().await.expect("rollback");
    }

    let first = run_read_only(&mut conn, &w.viewer, &ALL)
        .await
        .expect("run");
    let second = run_read_only(&mut conn, &w.viewer, &ALL)
        .await
        .expect("rerun");
    assert!(
        first.k10_retro.as_ref().is_some_and(|k| k.live_rows > 0),
        "PREMISE: the run measured something"
    );
    assert_eq!(
        (
            first.transaction_read_only.as_str(),
            first.transaction_isolation.as_str()
        ),
        ("on", "repeatable read"),
        "the run itself was measured in one REPEATABLE READ READ ONLY transaction"
    );
    assert_eq!(
        serde_json::to_vec_pretty(&first).expect("json"),
        serde_json::to_vec_pretty(&second).expect("json"),
        "two runs on one snapshot are byte-identical"
    );
    assert_eq!(
        footprint(&pool).await,
        before,
        "a run changes no row, cache or audit row"
    );
}

/// The delta's source names no write path: its own module and the binary.
/// Comments are stripped first, so a doc that NAMES a write path (to say it
/// is not called) does not trip it.
#[test]
fn the_delta_calls_no_write_path() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let forbidden = [
        "recompute_claim_belief",
        "recompute_combined_belief",
        "recompute_atom_cache",
        "vacate_atom_cache",
        "update_claim_belief",
        "clear_claim_belief",
        "delete_for_perspective",
        "auto_wire",
        "store_with_perspective",
        "apply_after",
        "cascade_after",
        "replay_deferred",
        "regenerate_",
        "ensure_binary_frame",
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        // Only `begin_read_only` opens a transaction, and nothing commits.
        ".begin(",
        ".commit(",
    ];
    for rel in [
        "src/supersede_delta.rs",
        "src/supersede_delta/r173.rs",
        "../epigraph-cli/src/bin/supersede_belief_delta.rs",
    ] {
        let path = root.join(rel);
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
        assert!(
            src.contains("run_read_only"),
            "{rel}: the pin reads the right file"
        );
        for (n, line) in src.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for f in forbidden {
                assert!(
                    !code.contains(f),
                    "{rel}:{}: the delta must not call `{f}`: {line}",
                    n + 1
                );
            }
        }
    }
}

/// K12(b)'s sheaf half moves no served obstruction: the sheaf readers select
/// an explicit relationship list that names no `supersedes` (read-only pin on
/// the repository's text; the readers' owner may change their filters, not
/// this list's membership, without this test noticing).
#[test]
fn the_sheaf_readers_select_no_supersedes_edge() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("../epigraph-db/src/repos/sheaf.rs");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    for reader in ["get_epistemic_edge_pairs", "get_claim_neighbor_betp_pairs"] {
        assert!(
            src.contains(&format!("fn {reader}")),
            "the pin reads the file that defines {reader}"
        );
    }
    let lists: Vec<&str> = src
        .lines()
        .filter(|l| l.contains("lower(e.relationship) IN ("))
        .collect();
    assert!(
        lists.len() >= 2,
        "both readers' relationship lists are found: {lists:?}"
    );
    for l in lists {
        assert!(
            l.contains("'refutes'") && !l.to_ascii_lowercase().contains("supersedes"),
            "a sheaf reader's relationship list names supersedes: {l}"
        );
    }
}

/// The run sees, on the maintenance login the binary connects as (NOSUPERUSER,
/// no BYPASSRLS), exactly what it sees on the superuser test pool, including a
/// GROUP-private holder in a group the session has no part in: a smaller
/// count on that login would make every operator figure a selection bug.
#[sqlx::test(migrations = "../../migrations")]
async fn the_delta_reads_every_row_on_the_maintenance_login(pool: PgPool) {
    let w = world_with(&pool, true).await;
    let private = w.private_holder.expect("built with a private holder");

    let mut conn = pool.acquire().await.expect("acquire");
    let as_superuser = run_read_only(&mut conn, &w.viewer, &ALL)
        .await
        .expect("superuser run");
    drop(conn);
    let k10 = as_superuser.k10_retro.as_ref().expect("k10-retro block");
    assert!(
        ids(&k10.delta.claims).contains(&private) && k10.live_rows == 4,
        "PREMISE: the superuser run selects the private holder's row too: {k10:?}"
    );

    // The binary's own path: a maintenance session on a ScopedPool whose
    // maintenance pool is the epigraph_maintenance login.
    let maint = fixture::downgraded_pool(&pool, "epigraph_maintenance").await;
    let scoped = fixture::scoped_pool(&pool)
        .await
        .with_maintenance_pool(maint);
    let mut session = scoped
        .maintenance_session(SystemReason::BeliefRecomputation)
        .await
        .expect("maintenance session");
    let (conn, viewer) = session.split();
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&mut *conn)
        .await
        .expect("current_user");
    assert_eq!(role, "epigraph_maintenance", "PREMISE: the run's login");
    let as_maintenance = run_read_only(conn, viewer, &ALL)
        .await
        .expect("maintenance run");

    assert_eq!(
        serde_json::to_value(&as_maintenance).expect("json"),
        serde_json::to_value(&as_superuser).expect("json"),
        "the maintenance login measures exactly what the superuser measures"
    );
}
