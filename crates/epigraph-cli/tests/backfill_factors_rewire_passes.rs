//! The targeted rewire's passes, snapshots and compare-and-swap restore
//! (R-176(2), R-177(4) class E; design §1.5, §1.7, §1.8, §1.11 items 2, 4, 5
//! and 12).
//!
//! `edge_rewire::run_targeted_rewire` takes the claims a wave moved, rewires
//! the edges they source, then the edges sourced at the targets that moved,
//! until a pass moves nothing; every rewrite appends a wave record (the
//! target cache) and an edge-row record before it commits.
//! `edge_rewire::restore_edge_rows` then puts each row back only where it
//! still holds exactly what the rewire wrote, and
//! `belief_cache::restore_wave` the target caches.
#![cfg(feature = "db")]

mod rewire_fixture;
mod viewer_fixture;

use std::collections::BTreeSet;

use epigraph_cli::belief_cache::{
    plan_restore, read_wave, restore_wave, RestoreOptions, WaveRecord,
};
use epigraph_cli::edge_rewire::{
    read_edge_row_records, restore_edge_rows, run_targeted_rewire, seed_from_waves, EdgeRowRecord,
    TargetedRunOptions, TargetedRunReport,
};
use epigraph_db::visibility::Viewer;
use rewire_fixture::*;
use sqlx::PgPool;
use uuid::Uuid;

/// `a —supports→ b —supports→ c`, every claim fresh with its own evidence,
/// both edges wired by the real wire. Then the wave moves `a`.
struct Chain {
    frame: Uuid,
    author: Uuid,
    a: Uuid,
    b: Uuid,
    c: Uuid,
    ab: Uuid,
    bc: Uuid,
    wave: Vec<WaveRecord>,
}

async fn chain(pool: &PgPool, viewer: &Viewer, tag: &str) -> Chain {
    let author = seed_agent(pool, &format!("passes-{tag}")).await;
    let frame = binary_frame(pool, viewer).await;
    let a = fresh_claim(pool, viewer, author, frame, &format!("a {tag}"), EVIDENCE_A).await;
    let b = fresh_claim(
        pool,
        viewer,
        author,
        frame,
        &format!("b {tag}"),
        TARGET_EVIDENCE,
    )
    .await;
    let c = fresh_claim(
        pool,
        viewer,
        author,
        frame,
        &format!("c {tag}"),
        TARGET_EVIDENCE,
    )
    .await;
    let ab = wired_edge(pool, viewer, author, a, b, "supports").await;
    let bc = wired_edge(pool, viewer, author, b, c, "supports").await;
    let wave = vec![move_claim(pool, viewer, a, EVIDENCE_B).await];
    Chain {
        frame,
        author,
        a,
        b,
        c,
        ab,
        bc,
        wave,
    }
}

/// Run the targeted rewire into in-memory snapshot files; return the report
/// and the parsed records.
async fn apply(
    pool: &PgPool,
    viewer: &Viewer,
    wave: &[WaveRecord],
    opts: &TargetedRunOptions,
) -> (TargetedRunReport, Vec<WaveRecord>, Vec<EdgeRowRecord>) {
    let seed = seed_from_waves(wave, opts.epsilon);
    let mut wave_out: Vec<u8> = Vec::new();
    let mut rows_out: Vec<u8> = Vec::new();
    let report = run_targeted_rewire(pool, viewer, &seed, opts, &mut wave_out, &mut rows_out)
        .await
        .expect("targeted run");
    (
        report,
        read_wave(wave_out.as_slice()).expect("wave file"),
        read_edge_row_records(rows_out.as_slice()).expect("edge-rows file"),
    )
}

fn until_fixed(max_passes: usize) -> TargetedRunOptions {
    TargetedRunOptions {
        max_passes,
        ..TargetedRunOptions::default()
    }
}

/// The row a fresh wire of `src —supports→ (twin of tgt)` stores from `src`'s
/// CURRENT cache: the oracle for "rewired to what a fresh wire writes".
async fn fresh_wire_masses(
    pool: &PgPool,
    viewer: &Viewer,
    author: Uuid,
    frame: Uuid,
    src: Uuid,
) -> String {
    let twin = fresh_claim(pool, viewer, author, frame, "oracle twin", TARGET_EVIDENCE).await;
    let e = wired_edge(pool, viewer, author, src, twin, "supports").await;
    edge_rows(pool, e).await.remove(0).1
}

async fn same_text_jsonb(pool: &PgPool, a: &str, b: &str) -> bool {
    sqlx::query_scalar("SELECT $1::jsonb = $2::jsonb")
        .bind(a)
        .bind(b)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Pass 1 rewires a→b, pass 2 b→c (b moved in pass 1), and the run stops
/// converged after a pass that writes nothing. Each final row is what a fresh
/// wire from its source's final cache stores, and each record pair was
/// written for exactly one rewrite.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_passes_follow_the_chain_to_a_fixed_point(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let ch = chain(&pool, &viewer, "chain").await;
    let b_before = cache(&pool, ch.b).await;
    let c_before = cache(&pool, ch.c).await;

    let (report, wave, rows) = apply(&pool, &viewer, &ch.wave, &until_fixed(10)).await;

    assert!(report.converged, "{report:?}");
    // Pass 3 takes the edges sourced at c (none) and writes nothing: the
    // loop ends with a pass that writes nothing (§1.5 (a)).
    assert_eq!(report.passes.len(), 3, "{report:?}");
    assert_eq!(
        (
            report.passes[0].rewired,
            report.passes[1].rewired,
            report.passes[2].rewired
        ),
        (1, 1, 0),
        "{report:?}"
    );
    assert_eq!(report.failed(), 0);
    assert_eq!(
        rows.iter().map(|r| r.edge_id).collect::<Vec<_>>(),
        vec![ch.ab, ch.bc]
    );
    assert_eq!(
        wave.iter().map(|r| r.claim_id).collect::<Vec<_>>(),
        vec![ch.b, ch.c]
    );
    assert_eq!(wave[0].wave, "r176e-pass-1");
    assert_eq!(wave[1].wave, "r176e-pass-2");
    assert_eq!(wave[0].before, b_before);
    assert_eq!(wave[1].before, c_before);
    assert_eq!(wave[0].written, cache(&pool, ch.b).await);
    assert_eq!(wave[1].written, cache(&pool, ch.c).await);

    let ab_now = edge_rows(&pool, ch.ab).await.remove(0).1;
    let bc_now = edge_rows(&pool, ch.bc).await.remove(0).1;
    let ab_fresh = fresh_wire_masses(&pool, &viewer, ch.author, ch.frame, ch.a).await;
    let bc_fresh = fresh_wire_masses(&pool, &viewer, ch.author, ch.frame, ch.b).await;
    assert!(
        same_text_jsonb(&pool, &ab_now, &ab_fresh).await,
        "a→b = fresh wire from a"
    );
    assert!(
        same_text_jsonb(&pool, &bc_now, &bc_fresh).await,
        "b→c = fresh wire from b"
    );

    // A second run finds nothing left to move.
    let (again, _, again_rows) = apply(
        &pool,
        &viewer,
        &ch.wave,
        &TargetedRunOptions {
            only_changed: true,
            ..until_fixed(10)
        },
    )
    .await;
    assert_eq!(again.rewired(), 0, "{again:?}");
    assert!(again_rows.is_empty());
}

/// A wired edge whose source is not in the wave is never touched, even with
/// a row exactly as stale: masses, `created_at` and the target's
/// `updated_at` are unchanged.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_run_never_touches_an_edge_sourced_outside_the_wave(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let ch = chain(&pool, &viewer, "listed").await;
    // d moves exactly as a did, but no wave records it.
    let d = fresh_claim(
        &pool,
        &viewer,
        ch.author,
        ch.frame,
        "unlisted d",
        EVIDENCE_A,
    )
    .await;
    let t = fresh_claim(
        &pool,
        &viewer,
        ch.author,
        ch.frame,
        "unlisted target",
        TARGET_EVIDENCE,
    )
    .await;
    let dt = wired_edge(&pool, &viewer, ch.author, d, t, "supports").await;
    let _unrecorded = move_claim(&pool, &viewer, d, EVIDENCE_B).await;
    let rows_before = edge_rows(&pool, dt).await;
    let t_at = updated_at(&pool, t).await;

    let (report, _, rows) = apply(&pool, &viewer, &ch.wave, &until_fixed(10)).await;

    assert!(report.rewired() >= 1);
    assert!(rows.iter().all(|r| r.edge_id != dt));
    assert_eq!(edge_rows(&pool, dt).await, rows_before);
    assert_eq!(updated_at(&pool, t).await, t_at);
}

/// The pass cap: with one pass, b→c (which pass 2 would take) is not
/// written, and the run reports it unconverged. Without `until_fixed` the
/// binary runs exactly this.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_run_stops_at_the_pass_cap_and_reports_what_it_did_not_reach(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let ch = chain(&pool, &viewer, "cap").await;
    let bc_before = edge_rows(&pool, ch.bc).await;
    let c_before = cache(&pool, ch.c).await;

    let (report, _, rows) = apply(&pool, &viewer, &ch.wave, &until_fixed(1)).await;

    assert!(!report.converged);
    assert_eq!(report.unconverged_edges, vec![ch.bc]);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        edge_rows(&pool, ch.bc).await,
        bc_before,
        "nothing beyond pass 1"
    );
    assert_eq!(cache(&pool, ch.c).await, c_before);
}

/// The accepted list bounds the run: an edge a pass reaches but the list
/// does not name is `chain_boundary_held` and left alone.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_run_never_rewires_an_edge_outside_the_accepted_list(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let ch = chain(&pool, &viewer, "accepted").await;
    let bc_before = edge_rows(&pool, ch.bc).await;

    let (report, _, rows) = apply(
        &pool,
        &viewer,
        &ch.wave,
        &TargetedRunOptions {
            edges: Some(BTreeSet::from([ch.ab])),
            ..until_fixed(10)
        },
    )
    .await;

    assert_eq!(report.rewired(), 1, "{report:?}");
    assert_eq!(report.chain_boundary_held(), 1, "{report:?}");
    assert_eq!(rows.len(), 1);
    assert_eq!(edge_rows(&pool, ch.bc).await, bc_before);
}

/// A cycle a ⇄ b converges: the passes alternate until the moves fall below
/// epsilon, and the final rows are fresh wires from the final caches.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_passes_converge_on_a_cycle(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let author = seed_agent(&pool, "cycle").await;
    let frame = binary_frame(&pool, &viewer).await;
    let a = fresh_claim(&pool, &viewer, author, frame, "cycle a", EVIDENCE_A).await;
    let b = fresh_claim(&pool, &viewer, author, frame, "cycle b", TARGET_EVIDENCE).await;
    let ab = wired_edge(&pool, &viewer, author, a, b, "supports").await;
    let ba = wired_edge(&pool, &viewer, author, b, a, "supports").await;
    settle(&pool, &viewer, &[a, b]).await;
    let wave = vec![move_claim(&pool, &viewer, a, EVIDENCE_B).await];

    let (report, _, _) = apply(&pool, &viewer, &wave, &until_fixed(80)).await;

    assert!(report.converged, "{report:?}");
    assert!(
        report.passes.len() > 2,
        "the cycle takes several passes: {report:?}"
    );
    assert_eq!(report.failed(), 0);
    let held: usize = report
        .passes
        .iter()
        .map(|p| p.held.values().sum::<usize>())
        .sum();
    assert_eq!(
        held, 0,
        "a cycle's second visit is not held as mixed: {report:?}"
    );
    // Fixed point: one more run from the final state moves no target by more
    // than 1e-6 (a cycle's rows are within about epsilon of a fresh wire, so
    // a further rewrite may land, but only that residual).
    let (again, again_wave, _) = apply(
        &pool,
        &viewer,
        &[WaveRecord {
            claim_id: a,
            before: wave[0].before.clone(),
            written: cache(&pool, a).await,
            wave: "check".into(),
            at: chrono::Utc::now(),
        }],
        &TargetedRunOptions {
            only_changed: true,
            epsilon: 1e-7,
            ..until_fixed(80)
        },
    )
    .await;
    assert!(again.passes.iter().all(|p| p.held.is_empty()), "{again:?}");
    assert!(again.converged, "{again:?}");
    for rec in &again_wave {
        assert!(
            !epigraph_cli::edge_rewire::cache_moved(&rec.before, &rec.written, 1e-6),
            "one more run moved {} by more than 1e-6: {rec:?}",
            rec.claim_id
        );
    }
    for (edge, src) in [(ab, a), (ba, b)] {
        let now = edge_rows(&pool, edge).await.remove(0).1;
        let fresh = fresh_wire_masses(&pool, &viewer, author, frame, src).await;
        let close: bool = sqlx::query_scalar(
            "SELECT bool_and(abs((x.value)::float8 - COALESCE((y.masses ->> x.key)::float8, 0)) < 1e-6) \
               FROM jsonb_each_text($1::jsonb) x, (SELECT $2::jsonb AS masses) y",
        )
        .bind(&now)
        .bind(&fresh)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(close, "edge {edge}: {now} vs fresh {fresh}");
    }
}

/// Rollback round trip (§1.8): restore the rows from the edge-rows file and
/// the caches from the wave file. The rows come back byte-identical
/// (`masses` text, `source_strength`, `evidence_type`, `locality_tag`,
/// `created_at`) and so do the caches. A row rewritten organically since is
/// `superseded_since_rewire` and left alone; a row retracted since is
/// `retracted_since_rewire` and left alone, with no retracted-row guard
/// error.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_rewire_restores_rows_and_caches_byte_identical(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let author = seed_agent(&pool, "restore").await;
    let frame = binary_frame(&pool, &viewer).await;
    let a = fresh_claim(&pool, &viewer, author, frame, "restore a", EVIDENCE_A).await;
    let mut targets = Vec::new();
    let mut edges = Vec::new();
    for i in 0..3 {
        let t = fresh_claim(
            &pool,
            &viewer,
            author,
            frame,
            &format!("restore t{i}"),
            TARGET_EVIDENCE,
        )
        .await;
        edges.push(wired_edge(&pool, &viewer, author, a, t, "supports").await);
        targets.push(t);
    }
    let wave = vec![move_claim(&pool, &viewer, a, EVIDENCE_B).await];
    let mut rows_before = Vec::new();
    let mut caches_before = Vec::new();
    for (e, t) in edges.iter().zip(&targets) {
        rows_before.push(edge_rows(&pool, *e).await);
        caches_before.push(cache(&pool, *t).await);
    }

    let (report, wave_e, rows) = apply(&pool, &viewer, &wave, &until_fixed(10)).await;
    assert_eq!(report.rewired(), 3, "{report:?}");

    // Edge 1 is rewritten organically after the rewire; edge 2 is retracted.
    sqlx::query("UPDATE mass_functions SET masses = $2::jsonb WHERE perspective_id = $1")
        .bind(edges[1])
        .bind(STALE_PRE_401)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE mass_functions SET retracted_at = now(), retracted_by = $2, \
                retract_reason = 'cal4 restore fixture' WHERE perspective_id = $1",
    )
    .bind(edges[2])
    .bind(author)
    .execute(&pool)
    .await
    .unwrap();
    let row1_now = edge_rows(&pool, edges[1]).await;
    let row2_now = edge_rows(&pool, edges[2]).await;

    let restored = restore_edge_rows(&pool, &rows, false)
        .await
        .expect("restore rows");
    let id = |e: usize| rows_before[e][0].0;
    assert_eq!(restored.restored, vec![id(0)], "{restored:?}");
    assert_eq!(
        restored.superseded_since_rewire,
        vec![id(1)],
        "{restored:?}"
    );
    assert_eq!(restored.retracted_since_rewire, vec![id(2)], "{restored:?}");
    assert_eq!(
        edge_rows(&pool, edges[0]).await,
        rows_before[0],
        "byte-identical row"
    );
    assert_eq!(edge_rows(&pool, edges[1]).await, row1_now, "left alone");
    assert_eq!(
        edge_rows(&pool, edges[2]).await,
        row2_now,
        "left alone, still retracted"
    );

    let caches = restore_wave(
        &pool,
        &plan_restore(&wave_e, None),
        &RestoreOptions::default(),
    )
    .await
    .expect("restore caches");
    assert!(caches.restored.contains(&targets[0]), "{caches:?}");
    assert_eq!(
        cache(&pool, targets[0]).await,
        caches_before[0],
        "byte-identical cache"
    );

    // Idempotent: a second restore writes nothing.
    let again = restore_edge_rows(&pool, &rows, false).await.unwrap();
    assert_eq!(again.already_restored, vec![id(0)], "{again:?}");
    assert!(again.restored.is_empty());
}

/// A settled cycle `a ⇄ b` and a wave that moved `a`. Returns the claims,
/// the edges and the wave.
async fn settled_cycle(
    pool: &PgPool,
    viewer: &Viewer,
    tag: &str,
) -> ((Uuid, Uuid), (Uuid, Uuid), Vec<WaveRecord>) {
    let author = seed_agent(pool, &format!("cycle-restore-{tag}")).await;
    let frame = binary_frame(pool, viewer).await;
    let a = fresh_claim(
        pool,
        viewer,
        author,
        frame,
        &format!("cr a {tag}"),
        EVIDENCE_A,
    )
    .await;
    let b = fresh_claim(
        pool,
        viewer,
        author,
        frame,
        &format!("cr b {tag}"),
        TARGET_EVIDENCE,
    )
    .await;
    let ab = wired_edge(pool, viewer, author, a, b, "supports").await;
    let ba = wired_edge(pool, viewer, author, b, a, "supports").await;
    settle(pool, viewer, &[a, b]).await;
    let wave = vec![move_claim(pool, viewer, a, EVIDENCE_B).await];
    ((a, b), (ab, ba), wave)
}

/// Rollback of a CYCLE run (§1.8): the run rewrites each of the two rows in
/// several passes, so the edge-rows file holds a chain of records per row
/// (each `before` the previous `written`) and the wave file a chain per
/// claim. The restore walks each chain back to its first `before`: both rows
/// (`created_at` included) and both caches come back byte-identical to the
/// state before the run, LIFO over the last write. A row rewritten
/// organically after the run (its last `written` no longer matches) is
/// `superseded_since_rewire` and left alone; the other row is restored.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_restore_unwinds_a_cycle_run_to_the_pre_run_rows(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let ((a, b), (ab, ba), wave) = settled_cycle(&pool, &viewer, "one").await;
    let rows_pre = (edge_rows(&pool, ab).await, edge_rows(&pool, ba).await);
    let caches_pre = (cache(&pool, a).await, cache(&pool, b).await);

    let (report, wave_e, rows) = apply(&pool, &viewer, &wave, &until_fixed(80)).await;
    assert!(report.converged, "{report:?}");
    let per_row = |id: Uuid| rows.iter().filter(|r| r.mf_id == id).count();
    let (ab_id, ba_id) = (rows_pre.0[0].0, rows_pre.1[0].0);
    assert!(
        per_row(ab_id) > 1 && per_row(ba_id) > 1,
        "PREMISE: the cycle rewrote each row more than once ({} and {} records)",
        per_row(ab_id),
        per_row(ba_id)
    );
    assert_ne!(
        (edge_rows(&pool, ab).await, edge_rows(&pool, ba).await),
        rows_pre,
        "the run moved the rows"
    );

    let restored = restore_edge_rows(&pool, &rows, false)
        .await
        .expect("restore rows");
    let mut got = restored.restored.clone();
    got.sort_unstable();
    let mut want = vec![ab_id, ba_id];
    want.sort_unstable();
    assert_eq!(got, want, "{restored:?}");
    let caches = restore_wave(
        &pool,
        &plan_restore(&wave_e, None),
        &RestoreOptions::default(),
    )
    .await
    .expect("restore caches");
    assert_eq!(caches.restored.len(), 2, "{caches:?}");
    assert_eq!(
        (edge_rows(&pool, ab).await, edge_rows(&pool, ba).await),
        rows_pre,
        "rows back to the pre-run rows, created_at included"
    );
    assert_eq!(
        (cache(&pool, a).await, cache(&pool, b).await),
        caches_pre,
        "caches back to the pre-run caches"
    );

    // Variant: a second cycle, one row rewritten organically after the run.
    let ((_a2, _b2), (ab2, ba2), wave2) = settled_cycle(&pool, &viewer, "two").await;
    let ba2_pre = edge_rows(&pool, ba2).await;
    let (_, _, rows2) = apply(&pool, &viewer, &wave2, &until_fixed(80)).await;
    sqlx::query("UPDATE mass_functions SET masses = $2::jsonb WHERE perspective_id = $1")
        .bind(ab2)
        .bind(STALE_PRE_401)
        .execute(&pool)
        .await
        .unwrap();
    let ab2_now = edge_rows(&pool, ab2).await;
    let restored2 = restore_edge_rows(&pool, &rows2, false)
        .await
        .expect("restore rows");
    assert_eq!(
        restored2.superseded_since_rewire,
        vec![ab2_now[0].0],
        "{restored2:?}"
    );
    assert_eq!(restored2.restored, vec![ba2_pre[0].0], "{restored2:?}");
    assert_eq!(edge_rows(&pool, ab2).await, ab2_now, "left alone");
    assert_eq!(edge_rows(&pool, ba2).await, ba2_pre, "restored");
}
