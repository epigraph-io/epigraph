//! The targeted rewire's predicting dry run (R-176(2), R-177(4) class E;
//! design §1.5, §1.6, §1.11 items 3 and 4).
//!
//! `edge_rewire::predict_targeted_rewire` runs the same passes and the same
//! per-edge decision as the apply, in one READ ONLY transaction, with an
//! overlay in place of every write. The oracle for its numbers is the real
//! apply run afterwards on the same database: the predicted rows are the
//! rows the apply writes, the predicted target caches are the caches it
//! writes. It writes nothing, it is deterministic, and after the apply a
//! final predict reports nothing left to change (the fixed-point proof, §1.5
//! (b)).
#![cfg(feature = "db")]

mod rewire_fixture;
mod viewer_fixture;

use epigraph_cli::belief_cache::{CacheColumns, WaveRecord};
use epigraph_cli::edge_rewire::{
    begin_predict_tx, predict_targeted_rewire, run_targeted_rewire, seed_from_waves, PredictReport,
    TargetedRunOptions,
};
use epigraph_db::visibility::Viewer;
use rewire_fixture::*;
use sqlx::PgPool;
use uuid::Uuid;

struct Chain {
    a: Uuid,
    b: Uuid,
    c: Uuid,
    ab: Uuid,
    bc: Uuid,
    held_edge: Uuid,
    wave: Vec<WaveRecord>,
}

/// `a → b → c` (fresh, `r173`) plus `a → m`, whose row has the pre-#401 shape
/// (held `row_mixed`); the wave moves `a`.
async fn chain(pool: &PgPool, viewer: &Viewer) -> Chain {
    let author = seed_agent(pool, "predict").await;
    let frame = binary_frame(pool, viewer).await;
    let a = fresh_claim(pool, viewer, author, frame, "predict a", EVIDENCE_A).await;
    let b = fresh_claim(pool, viewer, author, frame, "predict b", TARGET_EVIDENCE).await;
    let c = fresh_claim(pool, viewer, author, frame, "predict c", TARGET_EVIDENCE).await;
    let m = fresh_claim(pool, viewer, author, frame, "predict m", TARGET_EVIDENCE).await;
    let ab = wired_edge(pool, viewer, author, a, b, "supports").await;
    let bc = wired_edge(pool, viewer, author, b, c, "contradicts").await;
    let held_edge = wired_edge(pool, viewer, author, a, m, "supports").await;
    sqlx::query("UPDATE mass_functions SET masses = $2::jsonb WHERE perspective_id = $1")
        .bind(held_edge)
        .bind(STALE_PRE_401)
        .execute(pool)
        .await
        .unwrap();
    refold(pool, viewer, m).await;
    let wave = vec![move_claim(pool, viewer, a, EVIDENCE_B).await];
    Chain {
        a,
        b,
        c,
        ab,
        bc,
        held_edge,
        wave,
    }
}

fn opts() -> TargetedRunOptions {
    TargetedRunOptions {
        max_passes: 10,
        only_changed: true,
        ..TargetedRunOptions::default()
    }
}

async fn predict(pool: &PgPool, viewer: &Viewer, wave: &[WaveRecord]) -> PredictReport {
    let o = opts();
    predict_targeted_rewire(pool, viewer, &seed_from_waves(wave, o.epsilon), &o)
        .await
        .expect("predict")
}

/// Everything the fixture's rows and claims hold, to show a predict wrote
/// nothing: row counts, every edge row's text and `created_at`, every claim
/// cache and `updated_at`.
async fn fingerprint(
    pool: &PgPool,
) -> (i64, i64, Vec<(Uuid, String, String)>, Vec<(Uuid, String)>) {
    let mf: i64 = sqlx::query_scalar("SELECT count(*) FROM mass_functions")
        .fetch_one(pool)
        .await
        .unwrap();
    let cl: i64 = sqlx::query_scalar("SELECT count(*) FROM claims")
        .fetch_one(pool)
        .await
        .unwrap();
    let rows: Vec<(Uuid, String, String)> =
        sqlx::query_as("SELECT id, masses::text, created_at::text FROM mass_functions ORDER BY id")
            .fetch_all(pool)
            .await
            .unwrap();
    let claims: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, concat_ws('|', belief, plausibility, pignistic_prob, mass_on_empty, \
                mass_on_missing, belief_frame_id, classification, updated_at) \
           FROM claims ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    (mf, cl, rows, claims)
}

/// The oracle test: what the predict says each rewired row and each target
/// cache will be is what the real apply then writes, on the same database;
/// held edges are predicted held and stay untouched.
#[sqlx::test(migrations = "../../migrations")]
async fn predict_equals_what_the_apply_then_writes(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let ch = chain(&pool, &viewer).await;

    let report = predict(&pool, &viewer, &ch.wave).await;
    assert!(report.converged, "{report:?}");
    assert_eq!(report.seed_mode, "db");
    assert_eq!(
        report.would_rewrite(),
        vec![ch.ab, ch.bc],
        "{:?}",
        report.edges
    );
    assert_eq!(
        report.totals.held.get("row_mixed"),
        Some(&1),
        "{:?}",
        report.totals
    );
    assert_eq!(report.totals.would_remove, 0);
    assert_eq!(report.totals.would_vacate, 0);

    let o = opts();
    let mut w = Vec::new();
    let mut r = Vec::new();
    let applied = run_targeted_rewire(
        &pool,
        &viewer,
        &seed_from_waves(&ch.wave, o.epsilon),
        &o,
        &mut w,
        &mut r,
    )
    .await
    .expect("apply");
    assert_eq!(applied.rewired(), 2, "{applied:?}");

    for e in report.edges.iter().filter(|e| e.outcome == "rewire") {
        let stored = edge_rows(&pool, e.edge_id).await.remove(0);
        assert!(
            same_jsonb(&pool, e.p1_masses.as_ref().unwrap(), &stored.1).await,
            "edge {}: predicted {:?}, written {}",
            e.edge_id,
            e.p1_masses,
            stored.1
        );
        assert_eq!(stored.2, e.p1_source_strength);
        assert_eq!(stored.3, e.p1_evidence_type);
    }
    for t in [ch.b, ch.c] {
        let predicted: &CacheColumns = report.targets[&t].w.as_ref().expect("predicted cache");
        let written = cache(&pool, t).await;
        for (p, g, what) in [
            (predicted.belief, written.belief, "belief"),
            (predicted.plausibility, written.plausibility, "plausibility"),
            (predicted.pignistic_prob, written.pignistic_prob, "betp"),
        ] {
            assert_close(g.unwrap(), p.unwrap(), 1e-12, &format!("{t} {what}"));
        }
        let d = report.targets[&t].d_edge.expect("d_edge");
        assert!(d.abs() > 1e-6, "the target moves: {d}");
    }
    assert_eq!(
        edge_rows(&pool, ch.held_edge).await[0].1,
        sqlx::query_scalar::<_, String>("SELECT $1::jsonb::text")
            .bind(STALE_PRE_401)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "the held row was not rewritten"
    );

    // §1.5 (b): after the apply, a final predict has nothing left to change.
    let after = predict(&pool, &viewer, &ch.wave).await;
    assert!(after.would_rewrite().is_empty(), "{:?}", after.edges);
    assert!(after.totals.unchanged >= 1, "{:?}", after.totals);
}

/// The predict writes nothing: its transaction is READ ONLY (a write inside
/// it fails with SQLSTATE 25006), and across a predict no row count, edge
/// row, cache column or timestamp changes.
#[sqlx::test(migrations = "../../migrations")]
async fn predict_is_read_only_and_changes_nothing(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let ch = chain(&pool, &viewer).await;

    let mut tx = begin_predict_tx(&pool).await.expect("predict tx");
    let err = sqlx::query("UPDATE claims SET truth_value = 0.4 WHERE id = $1")
        .bind(ch.a)
        .execute(&mut *tx)
        .await
        .expect_err("a write inside the predict transaction must fail");
    let code = err
        .as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.to_string());
    assert_eq!(code.as_deref(), Some("25006"), "{err}");
    drop(tx);

    let before = fingerprint(&pool).await;
    let report = predict(&pool, &viewer, &ch.wave).await;
    assert!(
        !report.would_rewrite().is_empty(),
        "the predict found work to do"
    );
    assert_eq!(
        fingerprint(&pool).await,
        before,
        "the predict changed nothing"
    );
}

/// Two predicts on one snapshot give byte-identical reports (no timestamp,
/// ordered output).
#[sqlx::test(migrations = "../../migrations")]
async fn predict_is_deterministic(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let ch = chain(&pool, &viewer).await;
    let one = serde_json::to_string(&predict(&pool, &viewer, &ch.wave).await).unwrap();
    let two = serde_json::to_string(&predict(&pool, &viewer, &ch.wave).await).unwrap();
    assert_eq!(one, two);
}

/// On a copy restored from before the wave (the wave claim still holds its
/// `before`), the predict seeds its overlay with the wave's `written` and
/// predicts the same rewrites as on the post-wave database. A wave claim
/// holding neither value was written since: the predict refuses.
#[sqlx::test(migrations = "../../migrations")]
async fn predict_seeds_from_the_wave_and_refuses_an_unknown_state(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let ch = chain(&pool, &viewer).await;
    let post = predict(&pool, &viewer, &ch.wave).await;

    let before = &ch.wave[0].before;
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4, \
                mass_on_empty = $5, mass_on_missing = $6, belief_frame_id = $7, \
                classification = $8 WHERE id = $1",
    )
    .bind(ch.a)
    .bind(before.belief)
    .bind(before.plausibility)
    .bind(before.pignistic_prob)
    .bind(before.mass_on_empty)
    .bind(before.mass_on_missing)
    .bind(before.belief_frame_id)
    .bind(&before.classification)
    .execute(&pool)
    .await
    .unwrap();
    let seeded = predict(&pool, &viewer, &ch.wave).await;
    assert_eq!(seeded.seed_mode, "seeded");
    assert_eq!(seeded.would_rewrite(), post.would_rewrite());
    assert_eq!(seeded.edges, post.edges);

    sqlx::query("UPDATE claims SET belief = 0.33 WHERE id = $1")
        .bind(ch.a)
        .execute(&pool)
        .await
        .unwrap();
    let o = opts();
    let err = predict_targeted_rewire(&pool, &viewer, &seed_from_waves(&ch.wave, o.epsilon), &o)
        .await
        .expect_err("an unknown wave-claim state is refused");
    assert!(err.to_string().contains("l1_state_unknown"), "{err}");
    let _ = (ch.bc, ch.c);
}

/// The fixed-point verify after an apply (§1.5 (b)) when an L1 claim was
/// also a rewire TARGET: `a → b` with both `a` and `b` moved by L1. After the
/// apply, `b` holds the rewire's value, neither its L1 `before` nor its L1
/// `written`, so a predict over the L1 waves alone refuses
/// (`l1_state_unknown`). Handed the L1 waves AND the apply's snapshot (wave
/// records chain: each E `before` is the previous `written`), it reads the
/// database as current and reports nothing to rewrite.
#[sqlx::test(migrations = "../../migrations")]
async fn the_verify_predict_reads_l1_and_e_waves_together(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let author = seed_agent(&pool, "verify").await;
    let frame = binary_frame(&pool, &viewer).await;
    let a = fresh_claim(&pool, &viewer, author, frame, "verify a", EVIDENCE_A).await;
    let b = fresh_claim(&pool, &viewer, author, frame, "verify b", TARGET_EVIDENCE).await;
    let ab = wired_edge(&pool, &viewer, author, a, b, "supports").await;
    let mut l1 = vec![move_claim(&pool, &viewer, a, EVIDENCE_B).await];
    l1.push(move_claim(&pool, &viewer, b, EVIDENCE_C).await);

    let o = opts();
    let predicted = predict(&pool, &viewer, &l1).await;
    assert_eq!(predicted.would_rewrite(), vec![ab], "{:?}", predicted.edges);
    assert_eq!(predicted.run.moved_sources, 2);
    assert_eq!(predicted.run.wave_claims, 2);
    assert_eq!(predicted.run.epsilon, o.epsilon);
    assert_eq!(predicted.run.only_changed, o.only_changed);
    let mut w = Vec::new();
    let mut r = Vec::new();
    let applied = run_targeted_rewire(
        &pool,
        &viewer,
        &seed_from_waves(&l1, o.epsilon),
        &o,
        &mut w,
        &mut r,
    )
    .await
    .expect("apply");
    assert_eq!(applied.rewired(), 1, "{applied:?}");
    let e_wave = epigraph_cli::belief_cache::read_wave(w.as_slice()).expect("E wave file");
    assert_eq!(
        e_wave.iter().map(|r| r.claim_id).collect::<Vec<_>>(),
        vec![b]
    );

    let err = predict_targeted_rewire(&pool, &viewer, &seed_from_waves(&l1, o.epsilon), &o)
        .await
        .expect_err("the L1 waves alone no longer describe b");
    assert!(err.to_string().contains("l1_state_unknown"), "{err}");

    let mut both = l1.clone();
    both.extend(e_wave);
    let verify = predict(&pool, &viewer, &both).await;
    assert_eq!(verify.seed_mode, "db");
    assert!(verify.would_rewrite().is_empty(), "{:?}", verify.edges);
    assert!(verify.totals.held.is_empty(), "{:?}", verify.totals);
    assert!(verify.totals.unchanged >= 1, "{:?}", verify.totals);
}

/// Every test above runs as the harness superuser, which skips row security
/// and every grant. The binary runs on a maintenance LOGIN (a member of
/// `epigraph_maintenance`, NOSUPERUSER NOBYPASSRLS): the targeted surfaces
/// must work there too, the definer compound test and the live/retracted
/// counts of `edge_shape`, the READ ONLY predict transaction, the guarded
/// rewrite and its row lock, and the restore's UPDATE (`created_at`
/// included). A read that row security filtered would come back empty and be
/// miscounted with no error, so every count is asserted.
#[sqlx::test(migrations = "../../migrations")]
async fn targeted_predict_apply_and_restore_run_on_a_maintenance_login(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let ch = chain(&pool, &viewer).await;
    // A retracted off-key row on the mixed edge (held retracted_on_edge, read
    // through row security), and an edge into a compound (held compound_end,
    // decided by migration 193's definer).
    let author = seed_agent(&pool, "maint-extra").await;
    let frame = binary_frame(&pool, &viewer).await;
    let other_frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("cal4-maint-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .unwrap();
    let held_target: Uuid = sqlx::query_scalar("SELECT target_id FROM edges WHERE id = $1")
        .bind(ch.held_edge)
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, perspective_id, masses, \
                                     combination_method, source_strength, evidence_type, locality_tag, \
                                     retracted_at, retracted_by, retract_reason) \
         VALUES ($1, $2, $3, $4, $5::jsonb, 'edge_factor', 0.8, 'derived_support', 'cross', \
                 now(), $3, 'cal4 maint fixture')",
    )
    .bind(held_target)
    .bind(other_frame)
    .bind(author)
    .bind(ch.held_edge)
    .bind(STALE_PRE_401)
    .execute(&pool)
    .await
    .unwrap();
    let k = fresh_claim(
        &pool,
        &viewer,
        author,
        frame,
        "maint compound k",
        TARGET_EVIDENCE,
    )
    .await;
    let ak = wired_edge(&pool, &viewer, author, ch.a, k, "supports").await;
    make_compound(&pool, k, author).await;
    let ak_before = edge_rows(&pool, ak).await;
    let rows_before = (edge_rows(&pool, ch.ab).await, edge_rows(&pool, ch.bc).await);
    let caches_before = (cache(&pool, ch.b).await, cache(&pool, ch.c).await);

    let role = format!("cal4_maint_{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}' \
         IN ROLE epigraph_maintenance"
    ))
    .execute(&pool)
    .await
    .expect("maintenance login");
    let base = viewer_fixture::database_url_for(&pool).await;
    let scheme_end = base.find("://").expect("scheme") + 3;
    let host_path = &base[base.find('@').expect("credentials") + 1..];
    let url = format!("{}{role}:{password}@{host_path}", &base[..scheme_end]);
    let maint = sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .expect("connect as the maintenance login");

    let o = opts();
    let seed = seed_from_waves(&ch.wave, o.epsilon);
    let predicted = predict_targeted_rewire(&maint, &viewer, &seed, &o)
        .await
        .expect("predict as the maintenance login");
    let mut w = Vec::new();
    let mut r = Vec::new();
    let applied = run_targeted_rewire(&maint, &viewer, &seed, &o, &mut w, &mut r)
        .await
        .expect("apply as the maintenance login");
    let records = epigraph_cli::edge_rewire::read_edge_row_records(r.as_slice()).unwrap();
    let after_apply = (cache(&pool, ch.b).await, cache(&pool, ch.c).await);
    let restored = epigraph_cli::edge_rewire::restore_edge_rows(&maint, &records, false)
        .await
        .expect("restore as the maintenance login");
    let caches = epigraph_cli::belief_cache::restore_wave(
        &maint,
        &epigraph_cli::belief_cache::plan_restore(
            &epigraph_cli::belief_cache::read_wave(w.as_slice()).unwrap(),
            None,
        ),
        &epigraph_cli::belief_cache::RestoreOptions::default(),
    )
    .await
    .expect("restore caches as the maintenance login");
    maint.close().await;
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {role}"))
        .execute(&pool)
        .await;

    assert_eq!(
        predicted.would_rewrite(),
        vec![ch.ab, ch.bc],
        "{:?}",
        predicted.edges
    );
    for bucket in ["retracted_on_edge", "compound_end"] {
        assert_eq!(
            predicted.totals.held.get(bucket),
            Some(&1),
            "{bucket}: {:?}",
            predicted.totals
        );
    }
    assert_eq!(applied.rewired(), 2, "{applied:?}");
    assert_eq!(
        applied.held(epigraph_cli::backfill_factors::HeldBucket::RetractedOnEdge),
        1
    );
    assert_eq!(
        applied.held(epigraph_cli::backfill_factors::HeldBucket::CompoundEnd),
        1
    );
    assert_eq!(
        edge_rows(&pool, ak).await,
        ak_before,
        "the compound-ended row is untouched"
    );
    assert_eq!(applied.failed(), 0, "{applied:?}");
    assert_ne!(after_apply, caches_before, "the apply moved the targets");
    assert_eq!(restored.restored.len(), 2, "{restored:?}");
    assert_eq!(caches.restored.len(), 2, "{caches:?}");
    assert_eq!(
        (edge_rows(&pool, ch.ab).await, edge_rows(&pool, ch.bc).await),
        rows_before,
        "rows back byte-identical, created_at included"
    );
    assert_eq!(
        (cache(&pool, ch.b).await, cache(&pool, ch.c).await),
        caches_before,
        "caches back byte-identical"
    );
}

/// A wave record for a move made by hand: the claim's cache before, the
/// UPDATE `set` (a SQL `SET` list over `claims`), and the cache after.
async fn hand_move(pool: &PgPool, claim: Uuid, set: &str) -> WaveRecord {
    let before = cache(pool, claim).await;
    sqlx::query(&format!("UPDATE claims SET {set} WHERE id = $1"))
        .bind(claim)
        .execute(pool)
        .await
        .expect("move the claim's cache");
    let written = cache(pool, claim).await;
    assert_ne!(before, written, "fixture move must move the cache");
    WaveRecord {
        claim_id: claim,
        before,
        written,
        wave: "l1-fixture".to_string(),
        at: chrono::Utc::now(),
    }
}

/// OD-E1's count is measured, not assumed: two listed edges whose fresh wire
/// would store nothing, one from a source the wave left VACUOUS (Bel 0, Pl 1)
/// and one from a source it left FACTORLESS (NULL). The predict reports each
/// `held_would_remove` and `totals.would_remove == 2`; the real apply with the
/// same options holds the same two and writes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn predict_counts_would_remove_for_a_vacuous_and_a_factorless_source(pool: PgPool) {
    let (_scoped, viewer) = viewer_fixture::bypass(&pool).await;
    let author = seed_agent(&pool, "predict-f2").await;
    let frame = binary_frame(&pool, &viewer).await;
    let vac = fresh_claim(&pool, &viewer, author, frame, "f2 vacuous src", EVIDENCE_A).await;
    let nul = fresh_claim(
        &pool,
        &viewer,
        author,
        frame,
        "f2 factorless src",
        EVIDENCE_A,
    )
    .await;
    let t1 = seed_claim(&pool, author, "f2 edge-only target 1", None, 0.0).await;
    let t2 = seed_claim(&pool, author, "f2 edge-only target 2", None, 0.0).await;
    let e1 = wired_edge(&pool, &viewer, author, vac, t1, "supports").await;
    let e2 = wired_edge(&pool, &viewer, author, nul, t2, "supports").await;
    let wave = vec![
        hand_move(
            &pool,
            vac,
            "belief = 0.0, plausibility = 1.0, pignistic_prob = 0.5",
        )
        .await,
        hand_move(
            &pool,
            nul,
            "belief = NULL, plausibility = NULL, pignistic_prob = NULL",
        )
        .await,
    ];
    let before = fingerprint(&pool).await;
    let o = TargetedRunOptions {
        edges: Some(std::collections::BTreeSet::from([e1, e2])),
        ..opts()
    };

    let report = predict_targeted_rewire(&pool, &viewer, &seed_from_waves(&wave, o.epsilon), &o)
        .await
        .expect("predict");

    assert_eq!(report.totals.would_remove, 2, "{:?}", report.totals);
    for e in [e1, e2] {
        let p = report
            .edges
            .iter()
            .find(|x| x.edge_id == e)
            .expect("the predict reached the edge");
        assert_eq!(p.outcome, "held_would_remove", "{p:?}");
    }
    assert!(report.would_rewrite().is_empty(), "{:?}", report.edges);

    let mut w = Vec::new();
    let mut r = Vec::new();
    let applied = run_targeted_rewire(
        &pool,
        &viewer,
        &seed_from_waves(&wave, o.epsilon),
        &o,
        &mut w,
        &mut r,
    )
    .await
    .expect("apply");
    assert_eq!(
        applied.held(epigraph_cli::backfill_factors::HeldBucket::WouldRemove),
        2,
        "{applied:?}"
    );
    assert_eq!(applied.rewired(), 0, "{applied:?}");
    assert!(w.is_empty() && r.is_empty(), "no snapshot record");
    assert_eq!(fingerprint(&pool).await, before, "the apply wrote nothing");
}
