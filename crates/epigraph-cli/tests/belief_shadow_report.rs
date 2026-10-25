//! The belief shadow report (atom-level belief program; SPEC §1.3 one atom
//! value on the served cache, §3.2 statistics, §7.1 readiness, §8 T2 floor
//! viewer, §10.4 recall replay and strict-entry replay).
//!
//! Every expected value is an absolute number from a fixture whose masses
//! are written here, a twin fixture, or a value another path serves for the
//! same rows; none is computed here by the code under test.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::collections::HashMap;

use chrono::{Duration, Utc};
use epigraph_cli::shadow_report::{
    run_report, ClaimLine, Flips, ObstructionChanges, ReportOptions, Scope, Summary,
    DEFAULT_MIN_TRUTH,
};
use epigraph_db::repos::recall_event::{NewRecallEvent, RecallEventRepository};
use epigraph_db::{FrameRepository, MassFunctionRepository, Viewer};
use epigraph_engine::atom_items::{AtomFoldMode, CompoundSourceEdges};
use epigraph_engine::edge_factor::{
    recompute_atom_cache_with, AtomCacheOutcome, AtomCacheSettings, CacheWriteCause, LegacyFold,
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

/// A public claim. Its `truth_value` is the fixture's .8.
async fn claim(pool: &PgPool, author: Uuid, what: &str) -> Uuid {
    fixture::seed_public_claim(pool, author, &format!("sr {what} {}", Uuid::new_v4())).await
}

async fn group_claim(pool: &PgPool, author: Uuid, group: Uuid, what: &str) -> Uuid {
    fixture::seed_group_claim(
        pool,
        author,
        group,
        &format!("sr {what} {}", Uuid::new_v4()),
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

/// One BBA row on `binary_truth` from a fresh agent: an independent item.
/// With no `evidence_type` and `source_strength` 1.0 its reliability is
/// exactly 1 whatever the calibration.
async fn bba(pool: &PgPool, claim: Uuid, masses: serde_json::Value) -> Uuid {
    let b = binary(pool).await;
    let a = agent(pool).await;
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        b,
        Some(a),
        None,
        &masses,
        None,
        None,
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store BBA")
}

async fn support(pool: &PgPool, claim: Uuid, t: f64) -> Uuid {
    bba(pool, claim, serde_json::json!({"0": t, "0,1": 1.0 - t})).await
}

async fn refute(pool: &PgPool, claim: Uuid, f: f64) -> Uuid {
    bba(pool, claim, serde_json::json!({"1": f, "0,1": 1.0 - f})).await
}

async fn decompose(pool: &PgPool, parent: Uuid, child: Uuid) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(parent)
    .bind(child)
    .execute(pool)
    .await
    .expect("decomposes_to edge");
}

/// A compound over fresh public leaves, each carrying the given supports
/// (one independent item per value). Returns (compound, leaves).
async fn compound(pool: &PgPool, author: Uuid, what: &str, leaves: &[&[f64]]) -> (Uuid, Vec<Uuid>) {
    let k = claim(pool, author, what).await;
    let mut out = Vec::with_capacity(leaves.len());
    for (i, supports) in leaves.iter().enumerate() {
        let l = claim(pool, author, &format!("{what} leaf {i}")).await;
        decompose(pool, k, l).await;
        for &t in *supports {
            support(pool, l, t).await;
        }
        out.push(l);
    }
    (k, out)
}

/// Write a cache on a claim directly: the shape a writer outside the single
/// atom-cache writer leaves.
async fn set_cache(pool: &PgPool, id: Uuid, bel: f64, pl: f64, betp: f64) {
    sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4, \
         mass_on_empty = 0, mass_on_missing = 0 WHERE id = $1",
    )
    .bind(id)
    .bind(bel)
    .bind(pl)
    .bind(betp)
    .execute(pool)
    .await
    .expect("set cache");
}

/// Log one recall event returning `returned` in that order, with
/// `params.min_truth` when given.
async fn recall_event(pool: &PgPool, min_truth: Option<f64>, returned: &[Uuid]) -> Uuid {
    let params = match min_truth {
        Some(m) => serde_json::json!({"limit": 10, "min_truth": m}),
        None => serde_json::json!({"limit": 10}),
    };
    RecallEventRepository::log(
        pool,
        NewRecallEvent {
            id: Uuid::new_v4(),
            agent_id: None,
            tool: "recall".to_string(),
            query_text: "shadow report fixture".to_string(),
            query_pgvector: None,
            params,
            returned_claim_ids: returned.to_vec(),
            owner_group_id: None,
        },
    )
    .await
    .expect("recall event")
}

fn opts(scope: Scope) -> ReportOptions {
    ReportOptions::new(scope, Utc::now() - Duration::days(30))
}

async fn report(
    pool: &PgPool,
    viewer: &Viewer,
    events: &Viewer,
    o: &ReportOptions,
) -> (Summary, HashMap<Uuid, ClaimLine>) {
    let mut lines = HashMap::new();
    let summary = run_report(pool, viewer, events, o, |l: &ClaimLine| {
        lines.insert(l.claim_id, l.clone());
        Ok(())
    })
    .await
    .expect("report");
    (summary, lines)
}

/// A line as JSON with every `claim_id` removed: everything it discloses
/// apart from which claim it is about.
fn disclosed(l: &ClaimLine) -> serde_json::Value {
    fn strip(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(m) => {
                m.remove("claim_id");
                m.values_mut().for_each(strip);
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(strip),
            _ => {}
        }
    }
    let mut j = serde_json::to_value(l).expect("serialize");
    strip(&mut j);
    j
}

/// Two disclosures are the same: the same keys and non-float values, floats
/// within 1e-12 (a twin's items carry other ids, so sums may run in another
/// order).
fn same(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    use serde_json::Value::{Array, Number, Object};
    match (a, b) {
        (Number(x), Number(y)) if x.is_f64() || y.is_f64() => match (x.as_f64(), y.as_f64()) {
            (Some(x), Some(y)) => (x - y).abs() <= 1e-12,
            _ => false,
        },
        (Array(x), Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same(x, y)),
        (Object(x), Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

// ── (1) the recall replay counts a gate loss ────────────────────────────────

/// Plan test (1). Atom `a` serves a cache of `BetP` .7 that a writer outside
/// the plan left, while its only evidence is a refutation f .8 (the fold:
/// Bel 0, Pl .2, `BetP` .1). Atom `b` serves .95 over a support .9 (fold
/// .95). An event at `min_truth` .5 that returned both loses exactly `a`;
/// the same event at .05 loses nothing; an event with no `min_truth` reads
/// the default .3 and loses `a`; an event at .9 already failed `a` today, so
/// it is no loss of the cutover's.
#[sqlx::test(migrations = "../../migrations")]
async fn a_returned_claim_that_falls_below_its_min_truth_counts_one_loss(pool: PgPool) {
    let author = agent(&pool).await;
    let a = claim(&pool, author, "a").await;
    let b = claim(&pool, author, "b").await;
    refute(&pool, a, 0.8).await;
    set_cache(&pool, a, 0.6, 0.8, 0.7).await;
    support(&pool, b, 0.9).await;
    set_cache(&pool, b, 0.9, 1.0, 0.95).await;

    let e_half = recall_event(&pool, Some(0.5), &[a, b]).await;
    let e_low = recall_event(&pool, Some(0.05), &[a, b]).await;
    let e_default = recall_event(&pool, None, &[b, a]).await;
    let e_high = recall_event(&pool, Some(0.9), &[a]).await;

    let public = fixture::public_viewer(&pool).await;
    let (_scoped, events) = fixture::bypass(&pool).await;
    let (summary, lines) = report(&pool, &public, &events, &opts(Scope::Ids(vec![a, b]))).await;

    let line_a = lines.get(&a).expect("a line for a");
    assert!(
        (line_a.served.score - 0.7).abs() < 1e-12 && (line_a.strict.gate - 0.1).abs() < 1e-9,
        "a passes today at .7 and gates at its fold's .1 under the candidate, got {} / {}",
        line_a.served.score,
        line_a.strict.gate
    );

    for (mode, replay) in [
        ("progressive", &summary.replay.progressive),
        ("strict", &summary.replay.strict),
    ] {
        let by_id: HashMap<Uuid, _> = replay.per_event.iter().map(|e| (e.event_id, e)).collect();
        assert_eq!(
            by_id.len(),
            4,
            "{mode}: every event in the window is replayed"
        );
        let half = by_id[&e_half];
        assert_eq!(
            (half.lost, half.lost_in_first_10, half.resolved),
            (1, 1, 2),
            "{mode}: at min_truth .5 exactly a is lost"
        );
        assert_eq!(by_id[&e_low].lost, 0, "{mode}: at .05 a still passes (.1)");
        let default = by_id[&e_default];
        assert!(
            (default.min_truth - DEFAULT_MIN_TRUTH).abs() < 1e-12 && default.lost == 1,
            "{mode}: an event with no min_truth gates at .3 and loses a, got {default:?}"
        );
        let high = by_id[&e_high];
        assert_eq!(
            (high.lost, high.already_failing),
            (0, 1),
            "{mode}: a claim that fails today is no loss of the cutover's"
        );
        assert_eq!(replay.lost, 2, "{mode}: two losses in all");
        assert!(
            (replay.mean_share_lost - (0.5 + 0.0 + 0.5 + 0.0) / 4.0).abs() < 1e-12,
            "{mode}: mean share lost over the four events, got {}",
            replay.mean_share_lost
        );
    }
}

// ── (2) a compound crossing Bel .75 is one confirmed flip ───────────────────

/// Plan test (2). Three two-leaf compounds, each leaf with its own
/// independent support, no refutation anywhere (NR 1, uncontested):
///
/// * `k_down`: leaves .8 and .8, so R-DEP Bel .64; it serves a cache of
///   `BetP` .85, `confirmed` today. Strict serves Bel .64: one flip FROM.
/// * `k_up`: leaves .95 and .95, Bel .9025; it serves .5 today: one flip TO.
/// * `k_stay`: leaves .95 and .95, serving .85: `confirmed` both ways.
///
/// Every leaf is evidenced, so each compound is ready and progressive
/// agrees with strict.
#[sqlx::test(migrations = "../../migrations")]
async fn a_compound_crossing_bel_075_counts_one_confirmed_flip(pool: PgPool) {
    let author = agent(&pool).await;
    let (k_down, down) = compound(&pool, author, "down", &[&[0.8], &[0.8]]).await;
    let (k_up, up) = compound(&pool, author, "up", &[&[0.95], &[0.95]]).await;
    let (k_stay, stay) = compound(&pool, author, "stay", &[&[0.95], &[0.95]]).await;
    set_cache(&pool, k_down, 0.8, 0.9, 0.85).await;
    set_cache(&pool, k_up, 0.4, 0.6, 0.5).await;
    set_cache(&pool, k_stay, 0.8, 0.9, 0.85).await;
    recall_event(&pool, Some(0.3), &[k_down, k_up, k_stay]).await;

    let mut ids = vec![k_down, k_up, k_stay];
    ids.extend(down.iter().chain(&up).chain(&stay));
    let public = fixture::public_viewer(&pool).await;
    let (_scoped, events) = fixture::bypass(&pool).await;
    let (summary, lines) = report(&pool, &public, &events, &opts(Scope::Ids(ids))).await;

    let down_line = lines.get(&k_down).expect("a line for k_down");
    assert!(
        down_line.served.confirmed
            && !down_line.strict.confirmed
            && (down_line.strict.rank - 0.64).abs() < 1e-9,
        "k_down: confirmed today, Bel .64 under strict, got {down_line:?}"
    );
    assert_eq!(
        (
            summary.strict_entry.compounds,
            summary.strict_entry.confirmed.from,
            summary.strict_entry.confirmed.to
        ),
        (3, 1, 1),
        "one compound leaves confirmed (k_down) and one enters it (k_up); k_stay does not flip"
    );
    assert_eq!(
        summary.strict_entry.confirmed_recall_weighted, summary.strict_entry.confirmed,
        "each flipped compound was returned by exactly one event"
    );
    assert_eq!(
        (
            summary.compound_confirmed_set.strict,
            summary.compound_confirmed_set.progressive
        ),
        (2, 2),
        "k_up and k_stay are confirmed under the candidate; every leaf is evidenced, so \
         progressive serves the derived value too"
    );
    for (mode, replay) in [
        ("progressive", &summary.replay.progressive),
        ("strict", &summary.replay.strict),
    ] {
        assert_eq!(
            (replay.confirmed.from, replay.confirmed.to),
            (1, 1),
            "{mode}: the event that returned all three sees one flip each way"
        );
        assert_eq!(replay.lost, 0, "{mode}: NR is 1, nothing fails the gate");
    }
    assert!(
        summary.strict_entry.confirmed_graph_view_weighted.is_none(),
        "graph-view exposure is not measured in this run: null, never 0"
    );
}

// ── (3) the anonymous run is the public floor ───────────────────────────────

/// Plan test (3). `k` is public over a public leaf `a` (support .6: Bel .6,
/// `BetP` .8, so only the single-leaf partition makes `k` confirmed) and a
/// leaf `p` private to a group (support .3, a stored K .6, and a public
/// claim's `refutes` edge into it); its twin `t` is public over one public
/// leaf (support .6) and nothing else. As the anonymous viewer the report's
/// lines for `k` and `a` are exactly its lines for `t` and its leaf, `p` has
/// no line and is in no count (claims, P1, residue, the conflict set, the
/// confirmed sets, vacates, the sheaf, the replay's resolution and flips),
/// and the event that returned `p` resolves nothing for it. Were `p` read
/// into `k` (its leaf set, its dispute, its K), `k` would be contested or
/// partitioned on Bel, and its line would differ. As the maintenance viewer
/// `k` reads `p` too, so its value differs from the twin's: the comparison
/// can fail.
#[sqlx::test(migrations = "../../migrations")]
async fn the_anonymous_run_equals_the_public_floor(pool: PgPool) {
    let (member, group) = fixture::seed_agent_with_group(&pool, "sr-owner").await;
    let author = agent(&pool).await;
    let (k, leaves) = compound(&pool, author, "k", &[&[0.6]]).await;
    let a = leaves[0];
    let p = group_claim(&pool, member, group, "p").await;
    decompose(&pool, k, p).await;
    let p_row = support(&pool, p, 0.3).await;
    sqlx::query("UPDATE mass_functions SET conflict_k = 0.6 WHERE id = $1")
        .bind(p_row)
        .execute(&pool)
        .await
        .expect("p's stored K");
    let x = claim(&pool, author, "x refutes p").await;
    edge(&pool, x, p, "refutes").await;
    let (t, twin_leaves) = compound(&pool, author, "t", &[&[0.6]]).await;
    let a2 = twin_leaves[0];
    recall_event(&pool, Some(0.3), &[k, p]).await;
    recall_event(&pool, Some(0.3), &[t]).await;

    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let (s_k, l_k) = report(&pool, &public, &maint, &opts(Scope::Ids(vec![k, a, p]))).await;
    let (s_t, l_t) = report(&pool, &public, &maint, &opts(Scope::Ids(vec![t, a2]))).await;

    assert!(
        l_k.contains_key(&k) && l_k.contains_key(&a),
        "k and a have lines"
    );
    assert!(
        !l_k.contains_key(&p),
        "the private leaf has no line for the anonymous viewer"
    );
    for (ours, twin) in [(k, t), (a, a2)] {
        let (x, y) = (disclosed(&l_k[&ours]), disclosed(&l_t[&twin]));
        assert!(
            same(&x, &y),
            "the anonymous line must be the public floor's:\n{x}\n{y}"
        );
    }
    assert_eq!(
        (s_k.claims, s_k.fold_mismatch.p1_atoms, s_k.residue),
        (s_t.claims, s_t.fold_mismatch.p1_atoms, s_t.residue),
        "the private leaf is in no count"
    );
    assert!(
        l_k[&k].served.confirmed && l_k[&k].strict.confirmed && !l_k[&k].strict.contested,
        "k takes a's partition (BetP .8) and is not contested: {:?}",
        l_k[&k].strict
    );
    assert_eq!(
        (
            &s_k.conflicts,
            &s_k.compound_confirmed_set,
            &s_k.vacate,
            &s_k.sheaf,
        ),
        (
            &s_t.conflicts,
            &s_t.compound_confirmed_set,
            &s_t.vacate,
            &s_t.sheaf,
        ),
        "the private leaf's K, refuting edge and value are in no corpus statistic"
    );
    for (ours, twin) in [
        (&s_k.replay.progressive, &s_t.replay.progressive),
        (&s_k.replay.strict, &s_t.replay.strict),
    ] {
        assert_eq!(
            (
                ours.resolved,
                ours.unresolved,
                ours.lost,
                ours.confirmed,
                ours.contested
            ),
            (
                twin.resolved,
                twin.unresolved,
                twin.lost,
                twin.confirmed,
                twin.contested
            ),
            "the replay resolves and flips the same for k as for its twin"
        );
    }
    assert_eq!(s_k.claims, 2, "k and a");
    assert_eq!(
        (s_k.replay.strict.resolved, s_k.replay.strict.unresolved),
        (1, 2),
        "of the returned ids only k resolves: p is hidden from the anonymous viewer and t \
         is outside this run's scope"
    );

    let (_, l_m) = report(&pool, &maint, &maint, &opts(Scope::Ids(vec![k, a, p]))).await;
    let m = l_m.get(&k).expect("the maintenance run has a line for k");
    assert!(
        (m.strict.rank - l_t[&t].strict.rank).abs() > 0.1,
        "control: the maintenance run reads p (Bel .6 x .3), the twin does not ({} vs {})",
        m.strict.rank,
        l_t[&t].strict.rank
    );
}

// ── (4) the served value against the atom's own fold ────────────────────────

fn aef() -> AtomCacheSettings {
    AtomCacheSettings {
        fold: AtomFoldMode::Aef,
        compound_source_edges: CompoundSourceEdges::Frozen,
        vacate_on_evidence_removal: true,
    }
}

/// Plan test (4). Atoms `x` (support .7, refutation .2) and `y` (support .6)
/// are written through the single atom-cache writer under the AEF; `z` has
/// no evidence and a kept cache (the residue). The mismatch is 0 of 2 (`z`
/// is not P1, so not in the denominator). A writer outside the plan then
/// raises `y`'s `BetP` by .03 and leaves Bel and Pl alone, as the
/// monotonicity clamp does: 1 of 2.
#[sqlx::test(migrations = "../../migrations")]
async fn the_fold_mismatch_is_zero_after_the_single_writer_and_one_after_a_clamp(pool: PgPool) {
    let author = agent(&pool).await;
    let x = claim(&pool, author, "x").await;
    let y = claim(&pool, author, "y").await;
    let z = claim(&pool, author, "z").await;
    support(&pool, x, 0.7).await;
    refute(&pool, x, 0.2).await;
    support(&pool, y, 0.6).await;
    set_cache(&pool, z, 0.64, 1.0, 0.82).await;

    let (_scoped, maint) = fixture::bypass(&pool).await;
    {
        let mut conn = pool.acquire().await.expect("conn");
        for id in [x, y] {
            let out = recompute_atom_cache_with(
                &mut conn,
                &maint,
                id,
                CacheWriteCause::Organic,
                LegacyFold::OwnerFrame,
                aef(),
            )
            .await
            .expect("single writer");
            assert!(
                matches!(out, AtomCacheOutcome::Folded { written: true, .. }),
                "the writer folds and writes {id}: {out:?}"
            );
        }
    }

    let public = fixture::public_viewer(&pool).await;
    let scope = Scope::Ids(vec![x, y, z]);
    let (before, _) = report(&pool, &public, &maint, &opts(scope.clone())).await;
    assert_eq!(
        (
            before.fold_mismatch.p1_atoms,
            before.fold_mismatch.mismatched,
            before.residue
        ),
        (2, 0, 1),
        "after the single writer every P1 atom serves its fold; z is residue"
    );

    sqlx::query("UPDATE claims SET pignistic_prob = pignistic_prob + 0.03 WHERE id = $1")
        .bind(y)
        .execute(&pool)
        .await
        .expect("clamp-shaped write");
    let (after, lines) = report(&pool, &public, &maint, &opts(scope)).await;
    assert_eq!(
        (after.fold_mismatch.p1_atoms, after.fold_mismatch.mismatched),
        (2, 1),
        "a BetP the fold did not produce is one mismatch"
    );
    assert!((after.fold_mismatch.share - 0.5).abs() < 1e-12, "1 of 2");
    let y_gap = lines[&y].served_vs_fold.expect("y is P1");
    assert!(
        (y_gap - 0.03).abs() < 1e-9,
        "y's gap is the .03 the clamp added, got {y_gap}"
    );
    assert!(
        lines[&z].served_vs_fold.is_none(),
        "z has no fold to compare"
    );

    // A Bel the fold did not produce, Pl and BetP untouched: x mismatches too.
    sqlx::query("UPDATE claims SET belief = belief + 0.02 WHERE id = $1")
        .bind(x)
        .execute(&pool)
        .await
        .expect("bel-only write");
    // `w` has a row and no cache at all: each missing column is the full gap.
    let w = claim(&pool, author, "w").await;
    support(&pool, w, 0.6).await;
    let (bel_only, lines) =
        report(&pool, &public, &maint, &opts(Scope::Ids(vec![x, y, z, w]))).await;
    assert_eq!(
        (
            bel_only.fold_mismatch.p1_atoms,
            bel_only.fold_mismatch.mismatched
        ),
        (3, 3),
        "x (Bel), y (BetP) and w (no cache) all mismatch; z is not P1"
    );
    let x_gap = lines[&x].served_vs_fold.expect("x is P1");
    assert!(
        (x_gap - 0.02).abs() < 1e-9,
        "x's gap is the .02 added to Bel alone, got {x_gap}"
    );
    assert_eq!(
        lines[&w].served_vs_fold,
        Some(1.0),
        "a NULL cache column is a gap of 1"
    );
}

// ── the report writes nothing ───────────────────────────────────────────────

/// Everything a run could write, as one value: every column of every row of
/// the tables a belief path writes, so an UPDATE shows as well as an INSERT.
async fn fingerprint(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT concat_ws('|', \
           (SELECT md5(coalesce(string_agg(concat_ws(',', id, belief, plausibility, \
                pignistic_prob, mass_on_missing, mass_on_empty, belief_frame_id, \
                truth_value, updated_at), ';' ORDER BY id), '')) FROM claims), \
           (SELECT md5(coalesce(string_agg(t::text, ';' ORDER BY t::text), '')) \
              FROM mass_functions t), \
           (SELECT md5(coalesce(string_agg(t::text, ';' ORDER BY t::text), '')) FROM frames t), \
           (SELECT md5(coalesce(string_agg(t::text, ';' ORDER BY t::text), '')) FROM edges t), \
           (SELECT md5(coalesce(string_agg(t::text, ';' ORDER BY t::text), '')) \
              FROM ds_combined_beliefs t), \
           (SELECT md5(coalesce(string_agg(t::text, ';' ORDER BY t::text), '')) \
              FROM recall_events t), \
           (SELECT md5(coalesce(string_agg(t::text, ';' ORDER BY t::text), '')) \
              FROM perspectives t))",
    )
    .fetch_one(pool)
    .await
    .expect("fingerprint")
}

/// A whole-corpus run under both viewers, with the owner-rule stage on,
/// leaves the database exactly as it found it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_full_run_writes_nothing(pool: PgPool) {
    let author = agent(&pool).await;
    let (k, leaves) = compound(&pool, author, "k", &[&[0.8], &[0.6]]).await;
    refute(&pool, leaves[1], 0.3).await;
    set_cache(&pool, k, 0.5, 0.9, 0.7).await;
    recall_event(&pool, Some(0.3), &[k, leaves[0]]).await;

    let before = fingerprint(&pool).await;
    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let mut o = opts(Scope::All);
    o.owner_preview = true;
    let (s_pub, _) = report(&pool, &public, &maint, &o).await;
    let (s_maint, _) = report(&pool, &maint, &maint, &o).await;
    assert!(
        s_pub.claims >= 3 && s_maint.claims >= 3,
        "the run covered the fixture"
    );
    assert_eq!(
        fingerprint(&pool).await,
        before,
        "the report wrote to the database"
    );
}

// ── the sheaf shadow and the conflict set ───────────────────────────────────

async fn single_writer(pool: &PgPool, viewer: &Viewer, ids: &[Uuid]) {
    let mut conn = pool.acquire().await.expect("conn");
    for id in ids {
        recompute_atom_cache_with(
            &mut conn,
            viewer,
            *id,
            CacheWriteCause::Organic,
            LegacyFold::OwnerFrame,
            aef(),
        )
        .await
        .expect("single writer");
    }
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3)",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("edge");
}

/// The sheaf shadow reads each endpoint's candidate interval, not its cache.
/// `s -supports-> t` between two atoms whose caches the single writer set
/// to their folds, and `k -supports-> s` from a compound. With every cache
/// equal to its fold (and `k` out of scope) the shadow's cohomology is the
/// served one. A writer outside the plan then rewrites t's interval: the
/// served cohomology moves and the shadow's does not. Strict drops the
/// compound-ended edge; the coverage denominator (SPEC §1.3) is the
/// atom-atom edge `s -> t` (`k -> s` is not replaced by atom edges, so its
/// drop is reported, not counted against coverage), and strict evaluates
/// it: coverage 1.
#[sqlx::test(migrations = "../../migrations")]
async fn the_sheaf_shadow_reads_the_folds_and_strict_drops_compound_ended_edges(pool: PgPool) {
    let author = agent(&pool).await;
    let s = claim(&pool, author, "s").await;
    let t = claim(&pool, author, "t").await;
    support(&pool, s, 0.9).await;
    support(&pool, t, 0.2).await;
    refute(&pool, t, 0.6).await;
    let (k, leaves) = compound(&pool, author, "k", &[&[0.7], &[0.7]]).await;
    set_cache(&pool, k, 0.5, 0.9, 0.7).await;
    edge(&pool, s, t, "supports").await;
    edge(&pool, k, s, "supports").await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    single_writer(&pool, &maint, &[s, t]).await;

    let public = fixture::public_viewer(&pool).await;
    let mut ids = vec![s, t, k];
    ids.extend(&leaves);
    let scope = Scope::Ids(ids);
    let (before, _) = report(&pool, &public, &maint, &opts(scope.clone())).await;
    let sh = &before.sheaf;
    assert_eq!(
        (
            sh.served.edge_count,
            sh.progressive.edge_count,
            sh.strict.edge_count
        ),
        (2, 2, 1),
        "strict drops the compound-ended edge"
    );
    assert_eq!(
        (
            sh.coverage_denominator,
            sh.atom_atom_edges,
            sh.compound_ended_edges,
            sh.compound_ended_replaced
        ),
        (1, 1, 1, 0),
        "the denominator is s -> t; k -> s is compound-ended and not replaced"
    );
    assert!(
        (sh.strict.coverage - 1.0).abs() < 1e-12,
        "strict evaluates the one denominator edge: {sh:?}"
    );
    assert!(
        sh.served.h1 > 0.0,
        "the fixture is inconsistent somewhere: {sh:?}"
    );

    // With k out of scope only s -> t is evaluated, and every cache equals
    // its fold: the served cohomology and the shadow's are the same.
    let (no_k, _) = report(
        &pool,
        &public,
        &maint,
        &opts(Scope::Ids(
            [s, t].iter().chain(&leaves).copied().collect::<Vec<_>>(),
        )),
    )
    .await;
    assert_eq!(
        no_k.sheaf.pairs_outside_scope, 1,
        "k -> s has an end outside the scope"
    );
    assert!(
        no_k.sheaf.served.h1 > 0.0
            && (no_k.sheaf.served.h1 - no_k.sheaf.strict.h1).abs() < 1e-12
            && (no_k.sheaf.served.h1 - no_k.sheaf.progressive.h1).abs() < 1e-12,
        "caches equal to their folds give the served cohomology: {:?}",
        no_k.sheaf
    );

    // The served side of s -> t alone, against the shadow's, with k's edge
    // out of the way: the strict pass holds exactly that edge.
    let (served_st, strict_st) = (before.sheaf.served.h1, before.sheaf.strict.h1);
    set_cache(&pool, t, 0.0, 0.05, 0.025).await;
    let (after, _) = report(&pool, &public, &maint, &opts(scope)).await;
    assert!(
        (after.sheaf.strict.h1 - strict_st).abs() < 1e-12,
        "the shadow reads t's fold, which did not change ({strict_st} -> {})",
        after.sheaf.strict.h1
    );
    assert!(
        (after.sheaf.served.h1 - served_st).abs() > 1e-6,
        "control: the served cohomology reads t's cache, which did change"
    );
}

/// The conflict set (per-claim K at least .3): today from the stored rows'
/// `conflict_k`, under strict from each atom's fold K, with compounds out.
///
/// * `c_keep`: a stored K .5 and folds support .8 + refutation .8 (K .64):
///   in both.
/// * `c_drop`: a stored K .5 and a lone support (K 0): removed.
/// * `l`: a leaf of `k_leaf` with the same .8 / .8 rows and no stored K:
///   added.
/// * `k_leaf`: a compound with a stored K .6: dropped, explained by `l`.
/// * `k_bare`: a compound with a stored K .6 whose leaves are quiet: dropped,
///   unexplained.
#[sqlx::test(migrations = "../../migrations")]
async fn the_conflict_set_moves_from_stored_k_to_the_folds_and_drops_compounds(pool: PgPool) {
    let author = agent(&pool).await;
    let c_keep = claim(&pool, author, "c_keep").await;
    let c_drop = claim(&pool, author, "c_drop").await;
    let keep_row = support(&pool, c_keep, 0.8).await;
    refute(&pool, c_keep, 0.8).await;
    let drop_row = support(&pool, c_drop, 0.8).await;
    let (k_leaf, leaf_ids) = compound(&pool, author, "k_leaf", &[&[0.8], &[0.6]]).await;
    let l = leaf_ids[0];
    refute(&pool, l, 0.8).await;
    let k_leaf_row = support(&pool, k_leaf, 0.5).await;
    let (k_bare, bare_leaves) = compound(&pool, author, "k_bare", &[&[0.6], &[0.6]]).await;
    let k_bare_row = support(&pool, k_bare, 0.5).await;
    for (row, k) in [
        (keep_row, 0.5),
        (drop_row, 0.5),
        (k_leaf_row, 0.6),
        (k_bare_row, 0.6),
    ] {
        sqlx::query("UPDATE mass_functions SET conflict_k = $2 WHERE id = $1")
            .bind(row)
            .bind(k)
            .execute(&pool)
            .await
            .expect("stored K");
    }

    let mut ids = vec![c_keep, c_drop, k_leaf, k_bare];
    ids.extend(leaf_ids.iter().chain(&bare_leaves));
    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let (summary, _) = report(&pool, &public, &maint, &opts(Scope::Ids(ids))).await;
    let c = &summary.conflicts;
    assert_eq!(
        (c.served, c.shadow, c.atoms_added, c.atoms_removed),
        (4, 2, 1, 1),
        "today: c_keep, c_drop, k_leaf, k_bare; under strict: c_keep and l; got {c:?}"
    );
    assert_eq!(
        (
            c.compounds_dropped,
            c.compounds_dropped_with_leaf_conflict,
            c.compounds_dropped_unexplained
        ),
        (2, 1, 1),
        "k_leaf's K shows on its leaf l; k_bare's shows nowhere"
    );
}

// ── the binary ──────────────────────────────────────────────────────────────

/// The binary, driven as a process over a claims file, a snapshot and a
/// graph-view exposure file: under a fresh UTC-stamped directory it writes,
/// for each viewer, one JSON line per claim in scope (the snapshot starting
/// a leaf's decomposition, the exposure on the compound's line), a summary
/// recording what it ran under, and one replay line per event and mode,
/// every directory mode 0700; and the database is exactly as it was. A
/// second run straight after writes a second directory, never into the
/// first.
#[sqlx::test(migrations = "../../migrations")]
async fn the_binary_writes_its_report_files_and_nothing_to_the_database(pool: PgPool) {
    use std::os::unix::fs::PermissionsExt;

    let author = agent(&pool).await;
    let (k, leaves) = compound(&pool, author, "bin", &[&[0.8], &[0.6]]).await;
    set_cache(&pool, k, 0.5, 0.9, 0.7).await;
    recall_event(&pool, Some(0.3), &[k]).await;

    let tmp = std::env::temp_dir().join(format!("shadow-report-{}", Uuid::new_v4().simple()));
    std::fs::create_dir_all(&tmp).expect("tmp dir");
    let ids = tmp.join("claims.txt");
    std::fs::write(
        &ids,
        [k, leaves[0], leaves[1]]
            .iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .expect("ids file");
    let s0 = tmp.join("s0.jsonl");
    std::fs::write(
        &s0,
        format!(
            "{{\"claim_id\": \"{}\", \"pignistic_prob\": 0.42}}\n",
            leaves[0]
        ),
    )
    .expect("s0 file");
    let gv = tmp.join("gv.jsonl");
    std::fs::write(&gv, format!("{{\"claim_id\": \"{k}\", \"count\": 4}}\n")).expect("gv file");
    let out = tmp.join("out");

    let before = fingerprint(&pool).await;
    let url = fixture::database_url_for(&pool).await;
    let run_binary = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_belief_shadow_report"))
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("DATABASE_URL", &url)
            .env("RUST_LOG", "warn")
            .arg("--out")
            .arg(&out)
            .arg("--claims")
            .arg(&ids)
            .arg("--s0")
            .arg(&s0)
            .arg("--graph-view-exposure")
            .arg(&gv)
            .current_dir(&tmp)
            .output()
            .expect("run the binary")
    };
    let run = run_binary();
    assert!(
        run.status.success(),
        "exit {:?}\n{}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        fingerprint(&pool).await,
        before,
        "the binary wrote to the database"
    );

    let stamped: Vec<_> = std::fs::read_dir(&out)
        .expect("out dir")
        .map(|e| e.expect("entry").path())
        .collect();
    assert_eq!(stamped.len(), 1, "one stamped run directory");
    let root_mode = std::fs::metadata(&stamped[0])
        .expect("stamped dir")
        .permissions()
        .mode();
    assert_eq!(root_mode & 0o777, 0o700, "the stamped directory is private");
    for viewer in ["maintenance", "anonymous"] {
        let dir = stamped[0].join(viewer);
        let mode = std::fs::metadata(&dir)
            .expect("viewer dir")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "{viewer}: the report directory is private"
        );
        let lines = std::fs::read_to_string(dir.join("claims.jsonl")).expect("claims.jsonl");
        let parsed: HashMap<Uuid, serde_json::Value> = lines
            .lines()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).expect("a JSON line");
                let id = Uuid::parse_str(v["claim_id"].as_str().expect("claim_id")).expect("uuid");
                (id, v)
            })
            .collect();
        assert_eq!(parsed.len(), 3, "{viewer}: one line per claim in scope");
        assert_eq!(
            parsed.get(&k).map(|v| v["graph_view_exposure"].clone()),
            Some(serde_json::json!(4)),
            "{viewer}: the compound's line carries its graph-view exposure"
        );
        assert_eq!(
            parsed[&leaves[0]]["drift"]["stages"]["0"],
            serde_json::json!(0.42),
            "{viewer}: the snapshot starts the leaf's decomposition"
        );
        let summary: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("summary.json")).expect("summary.json"),
        )
        .expect("summary JSON");
        assert_eq!(
            summary["claims"], 3,
            "{viewer}: the summary counts the scope"
        );
        let settings = &summary["settings"];
        assert_eq!(
            (
                &settings["target_fold"],
                &settings["scope"],
                &settings["scope_ids"],
                &settings["s0_given"],
                &settings["graph_view_exposure_given"]
            ),
            (
                &serde_json::json!("aef"),
                &serde_json::json!("ids"),
                &serde_json::json!(3),
                &serde_json::json!(true),
                &serde_json::json!(true)
            ),
            "{viewer}: the summary records what it ran under"
        );
        for mode in ["replay_progressive.jsonl", "replay_strict.jsonl"] {
            let replay = std::fs::read_to_string(dir.join(mode)).expect("replay");
            assert_eq!(
                replay.lines().count(),
                1,
                "{viewer}: {mode} has one line per event"
            );
        }
    }

    let again = run_binary();
    assert!(again.status.success(), "the second run");
    let stamped_after = std::fs::read_dir(&out).expect("out dir").count();
    assert_eq!(
        stamped_after, 2,
        "a second run writes its own directory, never into the first"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

// ── the drift decomposition ─────────────────────────────────────────────────

/// One `attributed_v1` row from a fresh agent, citing nothing.
async fn attributed_support(pool: &PgPool, claim: Uuid, t: f64) -> Uuid {
    let b = binary(pool).await;
    let a = agent(pool).await;
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        b,
        Some(a),
        None,
        &serde_json::json!({"0": t, "0,1": 1.0 - t}),
        None,
        Some("attributed_v1"),
        Some(1.0),
        None,
        "unknown",
        None,
    )
    .await
    .expect("store attributed BBA")
}

/// An atom with a plain support .6 and an `attributed_v1` support .5 (two
/// independent items), serving a hand-set cache of `BetP` .7, with S0 at .55.
/// Its AEF without attribution is the plain row alone: Bel .6, `BetP` .8;
/// with it, Bel 1 - .4 x .5 = .8, `BetP` .9. The decomposition starts at S0,
/// its stages are those values in order, the stages it cannot separate are
/// null, and its components sum to the total, with and without the
/// owner-rule stage.
#[sqlx::test(migrations = "../../migrations")]
async fn the_drift_decomposition_telescopes_from_s0_through_attribution(pool: PgPool) {
    let author = agent(&pool).await;
    let a = claim(&pool, author, "drift").await;
    support(&pool, a, 0.6).await;
    attributed_support(&pool, a, 0.5).await;
    set_cache(&pool, a, 0.4, 1.0, 0.7).await;

    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    for owner_preview in [false, true] {
        let mut o = opts(Scope::Ids(vec![a]));
        o.s0 = Some(HashMap::from([(a, 0.55)]));
        o.owner_preview = owner_preview;
        let (_, lines) = report(&pool, &public, &maint, &o).await;
        let d = lines[&a]
            .drift
            .clone()
            .expect("a P1 atom has a decomposition");
        let stage = |k: &str| d.stages[k];
        let near = |x: Option<f64>, y: f64| x.is_some_and(|x| (x - y).abs() < 1e-9);
        assert!(
            near(stage("0"), 0.55) && (d.start - 0.55).abs() < 1e-12,
            "S0 starts it: {d:?}"
        );
        assert!(near(stage("0b"), 0.7), "0b is today's served score: {d:?}");
        assert!(
            near(stage("3c"), 0.8),
            "3c folds the plain row alone: {d:?}"
        );
        assert!(near(stage("4"), 0.9), "4 folds both items: {d:?}");
        assert!((d.final_value - 0.9).abs() < 1e-9 && (d.total - 0.35).abs() < 1e-9);
        for k in ["1'", "2", "3", "3a", "3b"] {
            assert!(
                stage(k).is_none() && d.components[k].is_none(),
                "{k} is not separable"
            );
        }
        assert_eq!(
            stage("1").is_some(),
            owner_preview,
            "1 only with the owner preview"
        );
        let sum: f64 = d.components.values().flatten().sum();
        assert!(
            (sum - d.total).abs() < 1e-12,
            "the components sum to the total ({sum} vs {}), owner_preview {owner_preview}",
            d.total
        );
    }
}

// ── the vacate count, by role ───────────────────────────────────────────────

/// The vacate count (served value newly vacuous: Bel under .01, Pl over .99)
/// gates the atom waves, so compounds are counted apart.
///
/// * `v`: an atom whose only row is vacuous (all mass on {TRUE, FALSE}),
///   serving a non-vacuous cache: an atom vacate.
/// * `k`: a compound over two leaves with no evidence and no cache, serving
///   a cache of its own: strict derives Bel 0, Pl 1, a compound vacate.
/// * `r`: a residue atom (no rows, a kept cache): served `legacy`, no
///   vacate.
#[sqlx::test(migrations = "../../migrations")]
async fn the_vacate_count_keeps_atoms_and_compounds_apart(pool: PgPool) {
    let author = agent(&pool).await;
    let v = claim(&pool, author, "v").await;
    bba(&pool, v, serde_json::json!({"0,1": 1.0})).await;
    set_cache(&pool, v, 0.6, 0.9, 0.75).await;
    let (k, leaves) = compound(&pool, author, "k", &[&[], &[]]).await;
    set_cache(&pool, k, 0.5, 0.9, 0.7).await;
    let r = claim(&pool, author, "r").await;
    set_cache(&pool, r, 0.64, 1.0, 0.82).await;

    let mut ids = vec![v, k, r];
    ids.extend(&leaves);
    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let (summary, lines) = report(&pool, &public, &maint, &opts(Scope::Ids(ids))).await;
    assert_eq!(lines[&r].strict.basis, "legacy", "r keeps its cache");
    assert_eq!(
        (summary.vacate.atoms, summary.vacate.compounds),
        (1, 1),
        "v is an atom vacate and k a compound one; r is residue, not a vacate"
    );
    assert_eq!(summary.residue, 1, "r");
}

// ── readiness: a Legacy leaf holds progressive at today's value ─────────────

/// Readiness (SPEC §7.1 P2) is what separates progressive from strict.
///
/// * `kl`: a compound over `e` (support .95) and `g`, a leaf with no rows and
///   a kept cache (Bel .9, Pl 1, `BetP` .95): `g` is served `Legacy`, so `kl`
///   is not ready. It serves .5 today (not confirmed). Strict derives R-DEP
///   over `e`'s item and `g`'s pseudo-item: Bel .95 x .9 = .855, confirmed.
///   Progressive keeps today's .5.
/// * `kr`: a compound over two evidenced leaves (.95, .95), serving .5: ready,
///   so progressive serves its derivation (Bel .9025) as strict does.
#[sqlx::test(migrations = "../../migrations")]
async fn a_compound_over_a_legacy_leaf_is_not_ready_and_progressive_keeps_today(pool: PgPool) {
    let author = agent(&pool).await;
    let (kl, kl_leaves) = compound(&pool, author, "kl", &[&[0.95], &[]]).await;
    let g = kl_leaves[1];
    set_cache(&pool, g, 0.9, 1.0, 0.95).await;
    set_cache(&pool, kl, 0.4, 0.6, 0.5).await;
    let (kr, kr_leaves) = compound(&pool, author, "kr", &[&[0.95], &[0.95]]).await;
    set_cache(&pool, kr, 0.4, 0.6, 0.5).await;
    recall_event(&pool, Some(0.3), &[kl]).await;
    recall_event(&pool, Some(0.3), &[kr]).await;

    let mut ids = vec![kl, kr];
    ids.extend(kl_leaves.iter().chain(&kr_leaves));
    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let (summary, lines) = report(&pool, &public, &maint, &opts(Scope::Ids(ids))).await;

    assert_eq!(
        lines[&g].strict.basis, "legacy",
        "g is served from its kept cache"
    );
    let l = &lines[&kl];
    assert_eq!(
        l.ready,
        Some(false),
        "a visible Legacy leaf blocks readiness"
    );
    assert_eq!(
        (l.progressive.basis, l.strict.basis),
        ("legacy", "derived"),
        "progressive keeps today's value; strict serves the derivation"
    );
    assert!(
        (l.progressive.gate - 0.5).abs() < 1e-12
            && (l.progressive.rank - 0.5).abs() < 1e-12
            && !l.progressive.confirmed,
        "progressive gates and ranks on today's .5: {:?}",
        l.progressive
    );
    assert!(
        (l.strict.rank - 0.855).abs() < 1e-9 && l.strict.confirmed,
        "strict ranks on Bel .95 x .9 = .855 and is confirmed: {:?}",
        l.strict
    );
    let r = &lines[&kr];
    assert!(
        r.ready == Some(true)
            && r.progressive.basis == "derived"
            && (r.progressive.rank - 0.9025).abs() < 1e-9,
        "control: a compound over evidenced leaves is ready, progressive serves Bel .9025: {r:?}"
    );
    assert_eq!(
        (
            summary.compound_confirmed_set.progressive,
            summary.compound_confirmed_set.strict
        ),
        (1, 2),
        "progressive: kr only; strict: kl and kr"
    );
    assert_eq!(
        (
            summary.replay.progressive.confirmed,
            summary.replay.strict.confirmed
        ),
        (Flips { to: 1, from: 0 }, Flips { to: 2, from: 0 }),
        "kl enters confirmed only under strict; kr under both"
    );
}

// ── contested: each disjunct of the roll-up ─────────────────────────────────

/// A compound is contested (SPEC §3.2) when a visible leaf is, when NR is
/// under .5, when its `not_all` valuation is at least .5, or on a live
/// refuting edge of its own. Each compound here trips exactly one of the
/// first three; every compound serves .5 today, uncontested:
///
/// * `k_own`: leaves .95 and .95 and a refutation row .6 of its own: `not_all`
///   .6; NR = .4 / (1 - .6 x .9025) = .87, above .5.
/// * `k_leaf`: leaves .95 and .95; a standalone `x` refutes leaf `l1` (an edge
///   with no BBA, so no value moves).
/// * `k_nr`: a leaf refuted .8 (Pl .2) and a leaf .95: NR .2.
/// * `c`: an atom a standalone contradicts: contested today and under the
///   candidate, so no flip.
/// * `u`: leaves .95 and .95, nothing against it: the uncontested control.
///
/// One event returns all five: three flips into contested under each mode.
#[sqlx::test(migrations = "../../migrations")]
async fn each_contested_disjunct_flips_a_compound_into_contested(pool: PgPool) {
    let author = agent(&pool).await;
    let (k_own, own_leaves) = compound(&pool, author, "k_own", &[&[0.95], &[0.95]]).await;
    refute(&pool, k_own, 0.6).await;
    let (k_leaf, leaf_leaves) = compound(&pool, author, "k_leaf", &[&[0.95], &[0.95]]).await;
    let x = claim(&pool, author, "x").await;
    edge(&pool, x, leaf_leaves[0], "refutes").await;
    let (k_nr, nr_leaves) = compound(&pool, author, "k_nr", &[&[], &[0.95]]).await;
    refute(&pool, nr_leaves[0], 0.8).await;
    let c = claim(&pool, author, "c").await;
    support(&pool, c, 0.9).await;
    let y = claim(&pool, author, "y").await;
    edge(&pool, y, c, "contradicts").await;
    let (u, u_leaves) = compound(&pool, author, "u", &[&[0.95], &[0.95]]).await;
    for k in [k_own, k_leaf, k_nr, u] {
        set_cache(&pool, k, 0.4, 0.6, 0.5).await;
    }
    recall_event(&pool, Some(0.3), &[k_own, k_leaf, k_nr, c, u]).await;

    let mut ids = vec![k_own, k_leaf, k_nr, c, u];
    for l in [&own_leaves, &leaf_leaves, &nr_leaves, &u_leaves] {
        ids.extend(l.iter());
    }
    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let (summary, lines) = report(&pool, &public, &maint, &opts(Scope::Ids(ids))).await;

    let not_all = |id: Uuid| {
        lines[&id]
            .derived
            .as_ref()
            .and_then(|v| v.derived.as_ref())
            .map(|d| d.not_all.m)
    };
    let own = &lines[&k_own];
    assert!(
        not_all(k_own).is_some_and(|m| (m - 0.6).abs() < 1e-9)
            && own.strict.gate > 0.5
            && own.strict.contested,
        "k_own: its own refutation row is a not_all of .6, NR stays above .5, contested: {own:?}"
    );
    let leaf = &lines[&k_leaf];
    assert!(
        lines[&leaf_leaves[0]].strict.contested
            && not_all(k_leaf) == Some(0.0)
            && (leaf.strict.gate - 1.0).abs() < 1e-9
            && leaf.strict.contested,
        "k_leaf: contested through its refuted leaf alone: {leaf:?}"
    );
    let nr = &lines[&k_nr];
    assert!(
        (nr.strict.gate - 0.2).abs() < 1e-9 && not_all(k_nr) == Some(0.0) && nr.strict.contested,
        "k_nr: NR .2 alone makes it contested: {nr:?}"
    );
    assert!(
        lines[&c].served.contested && lines[&c].strict.contested,
        "c is contested both ways"
    );
    assert!(
        !lines[&u].served.contested && !lines[&u].strict.contested,
        "control: u is contested neither way"
    );
    for (mode, replay) in [
        ("progressive", &summary.replay.progressive),
        ("strict", &summary.replay.strict),
    ] {
        assert_eq!(
            replay.contested,
            Flips { to: 3, from: 0 },
            "{mode}: k_own, k_leaf and k_nr flip into contested; c and u do not flip"
        );
        assert_eq!(
            replay.lost, 1,
            "{mode}: k_nr gates at NR .2 under the event's .3"
        );
    }
}

// ── the strict-entry replay's rank moves and exposure weights ───────────────

/// The strict-entry replay (SPEC §10.4): `confirmed` flips and rank moves of
/// compounds, each also weighted by recall and graph-view exposure. Leaves
/// serve their `truth_value` .8 today and their fold's `BetP` under strict.
///
/// * `k_down`: leaves .8 / .8 (`BetP` .9 each), serving .85: Bel .64, a flip
///   FROM confirmed. Places 2 -> 9.
/// * `k_up`: leaves .95 / .95 (`BetP` .975), serving .5: Bel .9025, a flip TO.
///   Places 9 -> 5.
/// * `k_stay`: leaves .9 / .9 (`BetP` .95), serving .86: Bel .81, confirmed
///   both ways. Places 1 -> 8.
///
/// Today's order: `k_stay` .86, `k_down` .85, six leaves at .8, `k_up` .5.
/// Strict's: two leaves .975, two .95, `k_up` .9025, two .9, `k_stay` .81,
/// `k_down` .64. Moves 4, 7 and 7; over a threshold of 5, `k_stay` and
/// `k_down`. Recall exposure: `k_down` 2 (two events), the others 1.
/// Graph-view exposure: `k_down` 3, `k_up` 5, `k_stay` 7.
#[sqlx::test(migrations = "../../migrations")]
async fn the_strict_entry_replay_weights_flips_and_rank_moves_by_exposure(pool: PgPool) {
    let author = agent(&pool).await;
    let (k_down, down) = compound(&pool, author, "down", &[&[0.8], &[0.8]]).await;
    let (k_up, up) = compound(&pool, author, "up", &[&[0.95], &[0.95]]).await;
    let (k_stay, stay) = compound(&pool, author, "stay", &[&[0.9], &[0.9]]).await;
    set_cache(&pool, k_down, 0.8, 0.9, 0.85).await;
    set_cache(&pool, k_up, 0.4, 0.6, 0.5).await;
    set_cache(&pool, k_stay, 0.85, 0.9, 0.86).await;
    recall_event(&pool, Some(0.3), &[k_down, k_up, k_stay]).await;
    recall_event(&pool, Some(0.3), &[k_down]).await;

    let mut ids = vec![k_down, k_up, k_stay];
    ids.extend(down.iter().chain(&up).chain(&stay));
    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let mut o = opts(Scope::Ids(ids));
    o.rank_threshold = 5;
    o.graph_view_exposure = Some(HashMap::from([(k_down, 3), (k_up, 5), (k_stay, 7)]));
    let (summary, _) = report(&pool, &public, &maint, &o).await;
    let se = &summary.strict_entry;

    assert_eq!(se.compounds, 3, "three compounds");
    assert_eq!(
        se.confirmed,
        Flips { to: 1, from: 1 },
        "k_up in, k_down out"
    );
    assert_eq!(
        se.confirmed_recall_weighted,
        Flips { to: 1, from: 2 },
        "k_down was returned by two events"
    );
    assert_eq!(
        se.confirmed_graph_view_weighted,
        Some(Flips { to: 5, from: 3 }),
        "weighted by k_up's 5 and k_down's 3 graph views"
    );
    assert_eq!(
        (
            se.rank_moves_over_threshold,
            se.rank_moves_recall_weighted,
            se.rank_moves_graph_view_weighted
        ),
        (2, 3, Some(10)),
        "k_stay and k_down move 7 places, over 5; k_up moves 4"
    );
    let moves: Vec<(Uuid, usize, usize)> = se
        .top_rank_moves
        .iter()
        .map(|m| (m.claim_id, m.from, m.to))
        .collect();
    assert_eq!(
        moves,
        vec![(k_down, 2, 9), (k_stay, 1, 8), (k_up, 9, 5)],
        "largest move first, a tie broken by recall exposure"
    );
    assert_eq!(
        (
            se.rank_move_quantiles.n,
            se.rank_move_quantiles.p50,
            se.rank_move_quantiles.max
        ),
        (3, 7.0, 7.0),
        "moves 4, 7, 7"
    );
}

// ── the first-10 metric ─────────────────────────────────────────────────────

/// SPEC §10.4: no event may lose more than one of its first ten. Losers (a
/// cache of .7 over a refutation .8, so the fold's .1) sit at positions 0, 1
/// and 10 of an 11-id event at `min_truth` .5, with eight passing atoms
/// (.9 support, served .95) between them: 3 lost, 2 of them in the first ten.
/// A second event loses one of its first ten: not over the bound.
#[sqlx::test(migrations = "../../migrations")]
async fn an_event_losing_two_of_its_first_ten_is_counted_once(pool: PgPool) {
    let author = agent(&pool).await;
    let mut losers = Vec::new();
    for i in 0..3 {
        let l = claim(&pool, author, &format!("loser {i}")).await;
        refute(&pool, l, 0.8).await;
        set_cache(&pool, l, 0.6, 0.8, 0.7).await;
        losers.push(l);
    }
    let mut passers = Vec::new();
    for i in 0..8 {
        let p = claim(&pool, author, &format!("passer {i}")).await;
        support(&pool, p, 0.9).await;
        set_cache(&pool, p, 0.9, 1.0, 0.95).await;
        passers.push(p);
    }
    let mut returned = vec![losers[0], losers[1]];
    returned.extend(&passers);
    returned.push(losers[2]);
    assert_eq!(returned.len(), 11);
    let wide = recall_event(&pool, Some(0.5), &returned).await;
    let narrow = recall_event(&pool, Some(0.5), &[losers[0], passers[0]]).await;

    let mut ids = losers.clone();
    ids.extend(&passers);
    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let (summary, _) = report(&pool, &public, &maint, &opts(Scope::Ids(ids))).await;
    for (mode, replay) in [
        ("progressive", &summary.replay.progressive),
        ("strict", &summary.replay.strict),
    ] {
        let by_id: HashMap<Uuid, _> = replay.per_event.iter().map(|e| (e.event_id, e)).collect();
        assert_eq!(
            (by_id[&wide].lost, by_id[&wide].lost_in_first_10),
            (3, 2),
            "{mode}: the loser at position 10 is not in the first ten"
        );
        assert_eq!(
            (by_id[&narrow].lost, by_id[&narrow].lost_in_first_10),
            (1, 1),
            "{mode}: one loss in the first ten"
        );
        assert_eq!(
            (
                replay.max_lost_in_first_10,
                replay.events_losing_more_than_one_in_first_10
            ),
            (2, 1),
            "{mode}: only the wide event loses more than one of its first ten"
        );
    }
}

// ── the owner-rule stage ────────────────────────────────────────────────────

/// Stage (1) of the drift decomposition is what the owner-rule recompute
/// would write: the combination of every row on the owner frame. The atom
/// has a plain support .6 and an `attributed_v1` support .5 on `binary_truth`
/// (no conflict): m(TRUE) = 1 - .4 x .5 = .8, `BetP` .9.
#[sqlx::test(migrations = "../../migrations")]
async fn the_owner_rule_stage_is_the_owner_frame_combination(pool: PgPool) {
    let author = agent(&pool).await;
    let a = claim(&pool, author, "owner").await;
    support(&pool, a, 0.6).await;
    attributed_support(&pool, a, 0.5).await;
    set_cache(&pool, a, 0.4, 1.0, 0.7).await;

    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let mut o = opts(Scope::Ids(vec![a]));
    o.owner_preview = true;
    let (_, lines) = report(&pool, &public, &maint, &o).await;
    let d = lines[&a]
        .drift
        .clone()
        .expect("a P1 atom has a decomposition");
    let one = d.stages["1"].expect("owner preview on");
    assert!(
        (one - 0.9).abs() < 1e-9,
        "the owner-frame combination of .6 and .5 is BetP .9, got {one}"
    );
}

// ── spine compounds are tallied apart ───────────────────────────────────────

/// Mark a compound as a spine node (level 1: a section).
async fn make_spine(pool: &PgPool, id: Uuid) {
    sqlx::query(
        "UPDATE claims SET properties = \
         jsonb_set(COALESCE(properties, '{}'::jsonb), '{level}', '\"1\"') WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("spine level");
}

/// A spine compound is served a profile (SPEC §2.2), whose Bel is a Fréchet
/// floor, never a conjunction; the compound tallies the cutover is reviewed
/// on count conjunctions, and spines on their own.
///
/// * `sp`: a spine over two leaves with no evidence and no cache, serving
///   .85 today (confirmed): its profile is Bel 0, Pl 1 (vacuous), a spine
///   vacate and a spine flip FROM confirmed.
/// * `kc`: a conjunction over leaves .95 / .95, serving .5: Bel .9025, a
///   conjunction flip TO confirmed.
#[sqlx::test(migrations = "../../migrations")]
async fn spine_compounds_are_tallied_apart_from_conjunctions(pool: PgPool) {
    let author = agent(&pool).await;
    let (sp, sp_leaves) = compound(&pool, author, "sp", &[&[], &[]]).await;
    make_spine(&pool, sp).await;
    set_cache(&pool, sp, 0.8, 0.9, 0.85).await;
    let (kc, kc_leaves) = compound(&pool, author, "kc", &[&[0.95], &[0.95]]).await;
    set_cache(&pool, kc, 0.4, 0.6, 0.5).await;

    let mut ids = vec![sp, kc];
    ids.extend(sp_leaves.iter().chain(&kc_leaves));
    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let (summary, lines) = report(&pool, &public, &maint, &opts(Scope::Ids(ids))).await;

    assert!(
        lines[&sp].spine && lines[&sp].strict.basis == "profile",
        "sp is a spine served a profile: {:?}",
        lines[&sp].strict
    );
    assert_eq!(
        (
            summary.by_role.get("compound").copied(),
            summary.by_role.get("compound_spine").copied()
        ),
        (Some(1), Some(1)),
        "one conjunction, one spine: {:?}",
        summary.by_role
    );
    assert!(
        summary.abs_delta.contains_key("compound_spine"),
        "the spine's |delta| has its own quantiles"
    );
    assert_eq!(
        (
            summary.vacate.atoms,
            summary.vacate.compounds,
            summary.vacate.spines
        ),
        (0, 0, 1),
        "the vacuous profile is a spine vacate, not a compound one"
    );
    assert_eq!(
        (
            summary.compound_confirmed_set.strict,
            summary.spine_confirmed_set.strict
        ),
        (1, 0),
        "kc is the confirmed conjunction; the spine's floor is 0"
    );
    assert_eq!(
        (
            summary.strict_entry.compounds,
            summary.strict_entry.confirmed
        ),
        (1, Flips { to: 1, from: 0 }),
        "the conjunction replay sees kc enter confirmed and nothing leave"
    );
    assert_eq!(
        (
            summary.strict_entry_spine.compounds,
            summary.strict_entry_spine.confirmed
        ),
        (1, Flips { to: 0, from: 1 }),
        "the spine replay sees sp leave confirmed"
    );
    let sp_mover = summary.top_movers.iter().find(|m| m.claim_id == sp);
    assert_eq!(
        sp_mover.map(|m| m.role),
        Some("compound_spine"),
        "a mover says it is a spine"
    );
}

// ── the target fold and the floor-viewer measure ────────────────────────────

/// Under `aef_standalone` only standalones fold under the AEF; a leaf keeps
/// today's value, so its fold is not what the run serves and is not in the
/// mismatch denominator, and the compound numbers read leaf folds the run
/// does not serve. The fold mismatch is the floor-viewer measure (SPEC §1.3)
/// only for the anonymous viewer under `aef`.
///
/// * `st`: a standalone with a support .9 (fold `BetP` .95) and a stale cache
///   (`BetP` .55): delta .4, returned by two events.
/// * `kx`: a compound over the leaf `lf`, which has a support .8 (fold `BetP`
///   .9) and a stale cache (`BetP` .35): delta .55, returned by none.
#[sqlx::test(migrations = "../../migrations")]
async fn the_target_fold_bounds_the_fold_mismatch_and_flags_compound_statistics(pool: PgPool) {
    let author = agent(&pool).await;
    let st = claim(&pool, author, "st").await;
    support(&pool, st, 0.9).await;
    set_cache(&pool, st, 0.5, 0.6, 0.55).await;
    let (kx, kx_leaves) = compound(&pool, author, "kx", &[&[0.8]]).await;
    let lf = kx_leaves[0];
    set_cache(&pool, lf, 0.3, 0.4, 0.35).await;
    recall_event(&pool, Some(0.3), &[st]).await;
    recall_event(&pool, Some(0.3), &[st]).await;

    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let scope = Scope::Ids(vec![st, kx, lf]);

    let mut o = opts(scope.clone());
    o.target_fold = AtomFoldMode::AefStandalone;
    let (w0, lines) = report(&pool, &public, &maint, &o).await;
    assert_eq!(
        (lines[&st].strict.basis, lines[&lf].strict.basis),
        ("axiom", "served"),
        "the standalone folds; the leaf keeps today's value"
    );
    assert_eq!(
        (w0.fold_mismatch.p1_atoms, w0.fold_mismatch.mismatched),
        (1, 1),
        "only the standalone's fold is what this run serves"
    );
    assert!(
        !w0.fold_mismatch.measures_floor && !w0.compound_statistics_valid,
        "not the floor measure, and the compound numbers read unserved leaf folds"
    );

    let (w1, _) = report(&pool, &public, &maint, &opts(scope.clone())).await;
    assert_eq!(
        (w1.fold_mismatch.p1_atoms, w1.fold_mismatch.mismatched),
        (2, 2),
        "under aef both atoms serve their folds, and both caches are stale"
    );
    assert!(
        w1.fold_mismatch.measures_floor && w1.compound_statistics_valid,
        "the anonymous run under aef is the floor measure"
    );
    let order: Vec<Uuid> = w1.top_movers.iter().map(|m| m.claim_id).collect();
    assert_eq!(
        order.first(),
        Some(&st),
        "st's .4 returned twice outweighs lf's unreturned .55: {:?}",
        w1.top_movers
    );
    assert_eq!(order.get(1), Some(&lf), "then lf");

    let (as_maint, _) = report(&pool, &maint, &maint, &opts(scope)).await;
    assert!(
        !as_maint.fold_mismatch.measures_floor,
        "the maintenance viewer's run is not the floor measure"
    );
}

// ── the drift decomposition: the clamp stage and compounds ──────────────────

/// SPEC §10.4 names a clamp-residue stage (0c) between (0b) and (1); the
/// report cannot separate it, so it is present and null, and the next stage
/// absorbs it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_drift_decomposition_carries_the_clamp_stage_as_null(pool: PgPool) {
    let author = agent(&pool).await;
    let a = claim(&pool, author, "clamp").await;
    support(&pool, a, 0.6).await;
    set_cache(&pool, a, 0.4, 1.0, 0.7).await;
    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let (_, lines) = report(&pool, &public, &maint, &opts(Scope::Ids(vec![a]))).await;
    let d = lines[&a]
        .drift
        .clone()
        .expect("a P1 atom has a decomposition");
    assert_eq!(d.unit, "betp", "an atom's stages are in BetP");
    assert!(
        d.stages.contains_key("0c") && d.stages.get("0c") == Some(&None),
        "0c is named and null: {:?}",
        d.stages
    );
    assert_eq!(
        d.components.get("0c"),
        Some(&None),
        "and its component is null"
    );
}

/// A compound's decomposition (SPEC §10.4), in Bel: (a) the legacy own-fold
/// (today's cache), (b) R-DEP without attribution (not separable here,
/// null), (c) R-DEP with attribution, (d) (c) met by the `not_all`
/// valuation; and the product-frame `BetP` as its own line.
///
/// `kd`: leaves .95 / .95 (R-DEP Bel .9025), a refutation row .6 of its own
/// (`not_all` .6), serving Bel .7 / `BetP` .8. Met by `not_all`, Bel becomes
/// .9025 x .4 / (1 - .6 x .9025) = .787350.
#[sqlx::test(migrations = "../../migrations")]
async fn a_compound_drift_names_the_conjunction_and_its_not_all(pool: PgPool) {
    let author = agent(&pool).await;
    let (kd, leaves) = compound(&pool, author, "kd", &[&[0.95], &[0.95]]).await;
    refute(&pool, kd, 0.6).await;
    set_cache(&pool, kd, 0.7, 0.9, 0.8).await;
    let mut ids = vec![kd];
    ids.extend(&leaves);
    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let (_, lines) = report(&pool, &public, &maint, &opts(Scope::Ids(ids))).await;
    let line = &lines[&kd];
    assert!(
        line.drift.is_some(),
        "a compound line carries its decomposition: {line:?}"
    );
    let d = line.drift.clone().unwrap_or_default();
    let near = |x: Option<f64>, y: f64| x.is_some_and(|x| (x - y).abs() < 1e-6);
    assert_eq!(d.unit, "bel", "a compound's stages are in Bel");
    assert!(near(d.stages.get("a").copied().flatten(), 0.7), "(a) {d:?}");
    assert_eq!(d.stages.get("b"), Some(&None), "(b) is null: {d:?}");
    assert!(
        near(d.stages.get("c").copied().flatten(), 0.9025),
        "(c) {d:?}"
    );
    assert!(
        near(d.stages.get("d").copied().flatten(), 0.787_350),
        "(d) {d:?}"
    );
    assert!(
        (d.start - 0.7).abs() < 1e-9
            && near(Some(d.final_value), 0.787_350)
            && near(Some(d.total), 0.787_350 - 0.7),
        "from today's Bel to the served Bel: {d:?}"
    );
    let sum: f64 = d.components.values().flatten().sum();
    assert!((sum - d.total).abs() < 1e-12, "components sum to the total");
    let betp = d.product_frame_betp.expect("the product-frame line");
    assert!(
        (betp.today - 0.8).abs() < 1e-12
            && (betp.derived - line.strict.interval.betp).abs() < 1e-12
            && (betp.delta - (betp.derived - betp.today)).abs() < 1e-12,
        "today's .8 beside the served product-frame BetP: {betp:?}"
    );
}

// ── the sheaf shadow maps every changed obstruction to a cause ──────────────

/// An epistemic edge with properties, returning its id.
async fn edge_with(
    pool: &PgPool,
    source: Uuid,
    target: Uuid,
    relationship: &str,
    properties: serde_json::Value,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, \
         properties) VALUES ($1, 'claim', $2, 'claim', $3, $4) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .bind(properties)
    .fetch_one(pool)
    .await
    .expect("edge")
}

/// Every obstruction that vanishes or appears under a candidate mode has a
/// cause (SPEC §1.3, §10.4). `contradicts` caps its target's Bel at
/// 1 - .9 x Bel(source); a `supports` edge floors it at .8 x Bel(source).
/// Atoms marked (w) were written through the single atom-cache writer.
///
/// * `s -supports-> t` (w; .9 over t's .2 / refutation .6, Bel .09):
///   obstructed both ways, no change.
/// * `k -contradicts-> s`: `k` serves Bel .5 (cap .55) and derives Bel .49
///   (cap .559) over leaves .7 / .7, under s's .9: obstructed today and in
///   progressive; strict drops the compound-ended edge, unreplaced.
/// * `k2 -contradicts-> s2` (s2 w, .9), replaced by `l2 -contradicts-> s2`
///   (l2 a leaf of `k2`, w, .7: cap .37): progressive and strict drop the
///   replaced edge; its replacement is obstructed both ways.
/// * `u -contradicts-> w` (u w, .9; cap .19): `w` serves Bel .95 by a hand
///   write, but its fold is a refutation .8 (Bel 0): resolved on value.
/// * `h -contradicts-> g` (h w, .9): `g` has a support .9 and no cache, so
///   today's cohomology cannot evaluate the edge; its fold (Bel .9) is over
///   the cap .19: new, with a gained value.
/// * `r -contradicts-> q` (r w, .9): `q` serves Bel 0 by a hand write over a
///   support .9: new on value.
///
/// The denominator: the four atom-atom edges today evaluates (not h -> g)
/// plus the replaced compound edge; every mode covers all five.
#[sqlx::test(migrations = "../../migrations")]
async fn the_sheaf_shadow_maps_each_changed_obstruction_to_a_cause(pool: PgPool) {
    let author = agent(&pool).await;
    let atom = |name: &'static str| {
        let pool = pool.clone();
        async move { claim(&pool, author, name).await }
    };
    let (s, t, s2, u, w, h, g, r, q) = (
        atom("s").await,
        atom("t").await,
        atom("s2").await,
        atom("u").await,
        atom("w").await,
        atom("h").await,
        atom("g").await,
        atom("r").await,
        atom("q").await,
    );
    for id in [s, s2, u, h, g, r, q] {
        support(&pool, id, 0.9).await;
    }
    support(&pool, t, 0.2).await;
    refute(&pool, t, 0.6).await;
    refute(&pool, w, 0.8).await;
    let (k, k_leaves) = compound(&pool, author, "k", &[&[0.7], &[0.7]]).await;
    let (k2, k2_leaves) = compound(&pool, author, "k2", &[&[0.7], &[0.7]]).await;
    let l2 = k2_leaves[0];
    set_cache(&pool, k, 0.5, 0.9, 0.7).await;
    set_cache(&pool, k2, 0.5, 0.9, 0.7).await;

    edge(&pool, s, t, "supports").await;
    edge(&pool, k, s, "contradicts").await;
    let replacement = edge_with(&pool, l2, s2, "contradicts", serde_json::json!({})).await;
    edge_with(
        &pool,
        k2,
        s2,
        "contradicts",
        serde_json::json!({"retargeted_to": [replacement], "retarget_unwired": []}),
    )
    .await;
    edge(&pool, u, w, "contradicts").await;
    edge(&pool, h, g, "contradicts").await;
    edge(&pool, r, q, "contradicts").await;

    let (_scoped, maint) = fixture::bypass(&pool).await;
    single_writer(&pool, &maint, &[s, t, s2, l2, u, h, r]).await;
    set_cache(&pool, w, 0.95, 1.0, 0.975).await;
    set_cache(&pool, q, 0.0, 1.0, 0.5).await;

    let mut ids = vec![s, t, s2, u, w, h, g, r, q, k, k2];
    ids.extend(k_leaves.iter().chain(&k2_leaves));
    let public = fixture::public_viewer(&pool).await;
    let (summary, _) = report(&pool, &public, &maint, &opts(Scope::Ids(ids))).await;
    let sh = &summary.sheaf;

    assert_eq!(
        (
            sh.coverage_denominator,
            sh.atom_atom_edges,
            sh.compound_ended_edges,
            sh.compound_ended_replaced
        ),
        (5, 4, 2, 1),
        "four atom-atom edges evaluated today plus the replaced compound edge: {sh:?}"
    );
    assert_eq!(
        (
            sh.served.edge_count,
            sh.progressive.edge_count,
            sh.strict.edge_count
        ),
        (6, 6, 5),
        "today: every edge but h -> g; progressive: all but the replaced edge; strict: the \
         five atom-atom edges"
    );
    for (mode, stats) in [("progressive", &sh.progressive), ("strict", &sh.strict)] {
        assert!(
            (stats.coverage - 1.0).abs() < 1e-12,
            "{mode} covers the denominator: {stats:?}"
        );
    }
    assert_eq!(
        sh.progressive_changes,
        ObstructionChanges {
            vanished_on_value: 1,
            vanished_edge_replaced: 1,
            vanished_edge_dropped: 0,
            vanished_endpoint_without_value: 0,
            new_on_value: 1,
            new_endpoint_gained_value: 1,
        },
        "progressive: u -> w resolves, k2 -> s2 is replaced, r -> q and h -> g appear"
    );
    assert_eq!(
        sh.strict_changes,
        ObstructionChanges {
            vanished_on_value: 1,
            vanished_edge_replaced: 1,
            vanished_edge_dropped: 1,
            vanished_endpoint_without_value: 0,
            new_on_value: 1,
            new_endpoint_gained_value: 1,
        },
        "strict also drops k -> s, which nothing replaced"
    );
}

/// `served_as_tool` is today's cohomology exactly as the sheaf tool computes
/// it: intervals from the cache with the claim's `open_world_mass` (never
/// written, so 0). The like-for-like `served` reads `mass_on_missing`, the
/// column the candidate's open-world mass is compared with. With
/// `mass_on_missing` .2 on t, only `served` carries an open-world component.
#[sqlx::test(migrations = "../../migrations")]
async fn served_as_tool_reads_what_the_sheaf_tool_reads(pool: PgPool) {
    let author = agent(&pool).await;
    let s = claim(&pool, author, "s").await;
    let t = claim(&pool, author, "t").await;
    support(&pool, s, 0.9).await;
    support(&pool, t, 0.9).await;
    edge(&pool, s, t, "supports").await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    single_writer(&pool, &maint, &[s, t]).await;
    sqlx::query("UPDATE claims SET mass_on_missing = 0.2 WHERE id = $1")
        .bind(t)
        .execute(&pool)
        .await
        .expect("open-world mass on t");

    let public = fixture::public_viewer(&pool).await;
    let (summary, _) = report(&pool, &public, &maint, &opts(Scope::Ids(vec![s, t]))).await;
    let sh = &summary.sheaf;
    assert_eq!(
        (sh.served_as_tool.edge_count, sh.served.edge_count),
        (1, 1),
        "both read s -> t"
    );
    assert!(
        sh.served_as_tool.open_world_h1.abs() < 1e-12 && sh.served.open_world_h1 > 1e-6,
        "the tool reads open_world_mass (0); the like-for-like reads t's .2: {sh:?}"
    );
}

// ── every recall event in the window is replayed ────────────────────────────

/// Recall events logged in one statement share `created_at`. Six hundred of
/// them span two pages of the event read; every one is replayed once.
#[sqlx::test(migrations = "../../migrations")]
async fn recall_events_with_one_timestamp_across_pages_are_each_replayed(pool: PgPool) {
    let author = agent(&pool).await;
    let a = claim(&pool, author, "a").await;
    support(&pool, a, 0.9).await;
    sqlx::query(
        "INSERT INTO recall_events (tool, query_text, params, returned_claim_ids, visibility) \
         SELECT 'recall', 'tied', '{\"min_truth\": 0.3}'::jsonb, ARRAY[$1]::uuid[], 'public' \
           FROM generate_series(1, 600)",
    )
    .bind(a)
    .execute(&pool)
    .await
    .expect("tied events");
    let public = fixture::public_viewer(&pool).await;
    let (_scoped, maint) = fixture::bypass(&pool).await;
    let (summary, lines) = report(&pool, &public, &maint, &opts(Scope::Ids(vec![a]))).await;
    let ids: std::collections::HashSet<Uuid> = summary
        .replay
        .strict
        .per_event
        .iter()
        .map(|e| e.event_id)
        .collect();
    assert_eq!(
        (summary.replay.strict.events, ids.len()),
        (600, 600),
        "each tied event once"
    );
    assert_eq!(lines[&a].recall_exposure, 600, "a's exposure is 600");
}
