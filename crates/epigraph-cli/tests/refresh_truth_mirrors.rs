//! `refresh_truth_mirrors` (operator rulings R-176(2), R-177(5): class D):
//! the compare-and-set refresh of `claims.truth_value` copies of an old
//! belief cache, from the recomputes' wave files.
//!
//! How every fixture is built, so a pass means what it says:
//!
//! * **The mirror** is written by the real evidence path:
//!   `ds_auto::auto_wire_ds_update` folds a BBA (`combination_method =
//!   'auto_wire'`) into the cache, then `ClaimRepository::update_truth_value_conn`
//!   persists `TruthValue::clamped(pignistic_prob)`, the sequence MCP
//!   `update_with_evidence` runs. Each fixture asserts the two columns hold
//!   the same bits, and that the value is neither round nor the sentinel.
//! * **The wave** is a real cache writer that leaves `truth_value` alone (a
//!   second `auto_wire_ds_update` from another source, without the truth
//!   persist), with its `{before, written}` read around that write and
//!   sent through the wave FILE format (`write_wave_record` → `read_wave`).
//!   Each fixture asserts the wave moved `pignistic_prob`.
//! * Hand-set columns are used only where no write path produces the state
//!   (the 0.05 sentinel as a current cache, a round cache, a step's
//!   `step_lineage_id`, a `workflows` row, a label), and each says so.
//! * **Every "left untouched" test runs beside a positive control** in the
//!   same call that IS refreshed, so a tool that writes nothing fails it.
//!
//! The four the batch names (an authored `truth_value`, the 0.05 sentinel, a
//! workflow step claim, a value changed since the snapshot) are each left
//! untouched; the CAS, the dry run, the restore and the binary are covered
//! below them.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::belief_cache::{
    read_cache_columns, read_wave, write_wave_record, CacheColumns, WaveRecord,
};
use epigraph_cli::belief_mode_check::MODE_CHECK_REFUSED_EXIT;
use epigraph_cli::truth_mirror::{
    apply, begin_dry_run_tx, cas_refresh, dry_run, plan_candidates, read_truth_records, restore,
    write_truth_record, Bucket, Candidate, MirrorReport, RefreshOptions, TruthRecord, TxMode,
};
use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::repos::claim_role::{self, ClaimRole};
use epigraph_db::{ClaimRepository, Viewer};

#[path = "viewer_fixture.rs"]
mod fixture;

const BIN: &str = env!("CARGO_BIN_EXE_refresh_truth_mirrors");

// ── fixtures ────────────────────────────────────────────────────────────────

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'refresh-truth-mirrors-test', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let content = format!("refresh truth mirrors claim {}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
    )
    .bind(content)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim")
}

async fn truth_of(pool: &PgPool, id: Uuid) -> f64 {
    sqlx::query_scalar("SELECT truth_value FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("truth_value")
}

async fn cache_of(pool: &PgPool, id: Uuid) -> CacheColumns {
    read_cache_columns(pool, &[id])
        .await
        .expect("read cache")
        .remove(&id)
        .expect("claim exists")
}

/// `(xmin, updated_at)`: a write of any kind changes the first.
async fn row_version(pool: &PgPool, id: Uuid) -> (i64, DateTime<Utc>) {
    sqlx::query_as("SELECT xmin::text::bigint, updated_at FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("row version")
}

/// Every stored BBA of `id`, as text, in a stable order.
async fn mass_rows(pool: &PgPool, id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT row_to_json(mf)::text FROM mass_functions mf WHERE mf.claim_id = $1 ORDER BY mf.id",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .expect("mass rows")
}

fn is_round(v: f64) -> bool {
    let k = 1000.0 * v;
    (k - k.round()).abs() <= 1e-6
}

/// One evidence fold on `claim` by `source` (the `auto_wire` writer); with
/// `persist_truth`, `truth_value = clamped(pignistic_prob)` in the same
/// transaction, as `update_with_evidence` does.
async fn evidence(pool: &PgPool, claim: Uuid, source: Uuid, confidence: f64, persist_truth: bool) {
    let viewer = fixture::public_viewer(pool).await;
    let mut tx = pool.begin().await.expect("begin");
    let ds = epigraph_mcp::tools::ds_auto::auto_wire_ds_update(
        &mut tx, &viewer, claim, source, confidence, 0.8, true, None, None, false,
    )
    .await
    .expect("auto_wire_ds_update");
    if persist_truth {
        ClaimRepository::update_truth_value_conn(
            &mut tx,
            ClaimId::from_uuid(claim),
            TruthValue::clamped(ds.pignistic_prob),
        )
        .await
        .expect("persist truth_value");
    }
    tx.commit().await.expect("commit");
}

/// A claim whose `truth_value` mirrors its cache through the real evidence
/// path. Returns the claim id.
async fn mirror_claim(pool: &PgPool, author: Uuid, confidence: f64) -> Uuid {
    let id = seed_claim(pool, author).await;
    let source = seed_agent(pool).await;
    evidence(pool, id, source, confidence, true).await;
    let t = truth_of(pool, id).await;
    let p = cache_of(pool, id)
        .await
        .pignistic_prob
        .expect("cache written");
    assert_eq!(
        t.to_bits(),
        p.to_bits(),
        "precondition: truth_value mirrors the cache"
    );
    assert!(!is_round(t), "precondition: the mirror {t} is not round");
    assert!(
        (t - 0.05).abs() > 1e-6,
        "precondition: the mirror is not the sentinel"
    );
    id
}

/// A wave over `ids`: per claim, read the cache, fold one more `auto_wire` BBA
/// from a fresh source WITHOUT the truth persist (nothing else writes the
/// claim meanwhile), read the cache back. The records come back through the
/// wave file format.
async fn wave(pool: &PgPool, ids: &[Uuid], name: &str) -> Vec<WaveRecord> {
    let at: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(pool)
        .await
        .expect("now");
    let mut file = Vec::new();
    for &id in ids {
        let before = cache_of(pool, id).await;
        let source = seed_agent(pool).await;
        evidence(pool, id, source, 0.613_7, false).await;
        let written = cache_of(pool, id).await;
        assert_ne!(
            before.pignistic_prob, written.pignistic_prob,
            "precondition: the wave moved the cache of {id}"
        );
        write_wave_record(
            &mut file,
            &WaveRecord {
                claim_id: id,
                before,
                written,
                wave: name.to_string(),
                at,
            },
        )
        .expect("write wave record");
    }
    read_wave(file.as_slice()).expect("read wave file back")
}

/// Hand-set (no write path produces it): `truth_value` and every BetP-shaped
/// cache column to `v`, as a mirror of a cache at `v` would hold them.
async fn set_mirror_value(pool: &PgPool, id: Uuid, v: f64) {
    sqlx::query(
        "UPDATE claims SET truth_value = $2, pignistic_prob = $2, belief = $2 - 0.01, \
                plausibility = $2 + 0.01 WHERE id = $1",
    )
    .bind(id)
    .bind(v)
    .execute(pool)
    .await
    .expect("set mirror value");
}

/// A public `workflows` row `id`, owned by `owner_of`'s group (declared: the
/// root tenancy trigger requires it of a non-seed writer).
async fn workflow_row(pool: &PgPool, id: Uuid, owner_of: Uuid) {
    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal, generation, metadata, visibility, \
                                owner_group_id) \
         SELECT $1, 'refresh-truth-mirrors-' || $1::text, 'goal', 0, '{}'::jsonb, 'public', \
                c.owner_group_id \
           FROM claims c WHERE c.id = $2",
    )
    .bind(id)
    .bind(owner_of)
    .execute(pool)
    .await
    .expect("workflows row");
}

/// What `update_truth_value_conn` (the REST PATCH / outcome writers' repo
/// call) does: an authored scalar.
async fn author_truth(pool: &PgPool, id: Uuid, v: f64) {
    let mut conn = pool.acquire().await.expect("acquire");
    ClaimRepository::update_truth_value_conn(
        &mut conn,
        ClaimId::from_uuid(id),
        TruthValue::new(v).unwrap(),
    )
    .await
    .expect("author truth_value");
}

fn opts(include_round: bool) -> RefreshOptions {
    RefreshOptions {
        batch_size: 3,
        include_round,
    }
}

async fn run_apply(
    pool: &PgPool,
    viewer: &Viewer,
    records: &[WaveRecord],
    include_round: bool,
) -> (MirrorReport, Vec<TruthRecord>) {
    let mut written = Vec::new();
    let report = apply(
        pool,
        viewer,
        &plan_candidates(records),
        &opts(include_round),
        |r| {
            written.push(r.clone());
            Ok(())
        },
    )
    .await
    .expect("apply");
    (report, written)
}

/// The claim was not written at all, and kept the value it had.
async fn assert_untouched(
    pool: &PgPool,
    id: Uuid,
    truth_before: f64,
    version_before: (i64, DateTime<Utc>),
    why: &str,
) {
    assert_eq!(
        truth_of(pool, id).await.to_bits(),
        truth_before.to_bits(),
        "{why}: truth_value changed"
    );
    assert_eq!(
        row_version(pool, id).await,
        version_before,
        "{why}: the row was written"
    );
}

/// The control: refreshed to exactly the new cache.
async fn assert_refreshed(pool: &PgPool, id: Uuid, report: &MirrorReport) {
    assert_eq!(
        report.bucket_of(id),
        Some(Bucket::Refresh),
        "control not refreshed"
    );
    let p = cache_of(pool, id).await.pignistic_prob.unwrap();
    assert_eq!(
        truth_of(pool, id).await.to_bits(),
        p.to_bits(),
        "control truth is not the new cache"
    );
}

// ── (1) a mirror is refreshed, and nothing else moves ──────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn a_mirror_is_refreshed_to_the_new_cache_and_nothing_else_moves(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let a = mirror_claim(&pool, author, 0.731_37).await;
    let old = truth_of(&pool, a).await;
    let records = wave(&pool, &[a], "L1-slice-1").await;
    let cache_after_wave = cache_of(&pool, a).await;
    let rows_after_wave = mass_rows(&pool, a).await;

    let (report, written) = run_apply(&pool, &viewer, &records, false).await;

    assert_refreshed(&pool, a, &report).await;
    let new = cache_after_wave.pignistic_prob.unwrap();
    assert_ne!(old.to_bits(), new.to_bits());
    assert_eq!(
        cache_of(&pool, a).await,
        cache_after_wave,
        "a cache column moved"
    );
    assert_eq!(
        mass_rows(&pool, a).await,
        rows_after_wave,
        "a mass_functions row moved"
    );
    assert_eq!(written.len(), 1);
    let r = &written[0];
    assert_eq!(r.claim_id, a);
    assert_eq!(r.truth_before.to_bits(), old.to_bits());
    assert_eq!(r.cache_old.to_bits(), old.to_bits());
    assert_eq!(r.truth_written.to_bits(), new.to_bits());
    assert_eq!(r.cache_new.to_bits(), new.to_bits());
    assert_eq!(r.waves, vec!["L1-slice-1".to_string()]);
}

// ── (2) an authored truth_value is left untouched ──────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn an_authored_truth_value_is_left_untouched(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let control = mirror_claim(&pool, author, 0.731_37).await;
    let authored = mirror_claim(&pool, author, 0.682_91).await;
    // The author re-states it 1e-6 off the cache: it is no longer a mirror,
    // although it has an auto_wire row, is current and non-round.
    let mirrored = truth_of(&pool, authored).await;
    author_truth(&pool, authored, mirrored + 1e-6).await;
    let records = wave(&pool, &[control, authored], "L1").await;
    let t = truth_of(&pool, authored).await;
    let v = row_version(&pool, authored).await;

    let (report, written) = run_apply(&pool, &viewer, &records, false).await;

    assert_refreshed(&pool, control, &report).await;
    assert_eq!(report.bucket_of(authored), Some(Bucket::NotAMirror));
    assert_untouched(&pool, authored, t, v, "authored").await;
    assert!(
        written.iter().all(|r| r.claim_id != authored),
        "an authored value was recorded as a write"
    );
}

// ── (3) the 0.05 sentinel is never written, on either side ─────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn the_sentinel_is_left_untouched_even_with_include_round(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let control = mirror_claim(&pool, author, 0.731_37).await;

    // A CURRENT claim whose truth and old cache are both exactly 0.05
    // (hand-set: the sentinel is otherwise written only with is_current =
    // false); the wave then folds real evidence over it.
    let at_sentinel = mirror_claim(&pool, author, 0.682_91).await;
    set_mirror_value(&pool, at_sentinel, 0.05).await;

    // A deprecated claim (the real deprecation: 0.05, not current).
    let deprecated = mirror_claim(&pool, author, 0.655_13).await;

    let mut records = wave(&pool, &[control, at_sentinel, deprecated], "L1").await;
    ClaimRepository::deprecate_claim(&pool, ClaimId::from_uuid(deprecated))
        .await
        .expect("deprecate");

    // A mirror whose NEW cache is the sentinel (stand-in wave writer: no fold
    // lands exactly on 0.05).
    let to_sentinel = mirror_claim(&pool, author, 0.701_77).await;
    let before = cache_of(&pool, to_sentinel).await;
    sqlx::query("UPDATE claims SET pignistic_prob = 0.05 WHERE id = $1")
        .bind(to_sentinel)
        .execute(&pool)
        .await
        .unwrap();
    let written = cache_of(&pool, to_sentinel).await;
    records.push(WaveRecord {
        claim_id: to_sentinel,
        before,
        written,
        wave: "L1".to_string(),
        at: records[0].at,
    });

    let snap = |id| {
        let pool = pool.clone();
        async move { (truth_of(&pool, id).await, row_version(&pool, id).await) }
    };
    let (t1, v1) = snap(at_sentinel).await;
    let (t2, v2) = snap(to_sentinel).await;
    let (t3, v3) = snap(deprecated).await;
    assert_eq!(t1, 0.05);
    assert_eq!(t3, 0.05);

    // --include-round admits round values, never the sentinel.
    let (report, _) = run_apply(&pool, &viewer, &records, true).await;

    assert_refreshed(&pool, control, &report).await;
    assert_eq!(report.bucket_of(at_sentinel), Some(Bucket::Sentinel005));
    assert_eq!(report.bucket_of(to_sentinel), Some(Bucket::Sentinel005));
    assert_eq!(report.bucket_of(deprecated), Some(Bucket::NotCurrent));
    assert_untouched(&pool, at_sentinel, t1, v1, "truth at the sentinel").await;
    assert_untouched(&pool, to_sentinel, t2, v2, "new value at the sentinel").await;
    assert_untouched(&pool, deprecated, t3, v3, "deprecated").await;
}

// ── (4) workflow and step claims: one per arm of the rule ──────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn workflow_and_step_claims_are_left_untouched(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let control = mirror_claim(&pool, author, 0.731_37).await;
    let step_by_edge = mirror_claim(&pool, author, 0.682_91).await;
    let step_by_lineage = mirror_claim(&pool, author, 0.655_13).await;
    let workflow_row_claim = mirror_claim(&pool, author, 0.701_77).await;
    let workflow_label = mirror_claim(&pool, author, 0.718_23).await;

    // Each claim carries exactly ONE arm (hand-set structure; the fold and
    // the mirror are the real ones).
    let workflow_root = Uuid::new_v4();
    workflow_row(&pool, workflow_root, control).await;
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'workflow', $2, 'claim', 'executes')",
    )
    .bind(workflow_root)
    .bind(step_by_edge)
    .execute(&pool)
    .await
    .expect("executes edge");
    sqlx::query("UPDATE claims SET step_lineage_id = gen_random_uuid() WHERE id = $1")
        .bind(step_by_lineage)
        .execute(&pool)
        .await
        .unwrap();
    workflow_row(&pool, workflow_row_claim, workflow_row_claim).await;
    sqlx::query("UPDATE claims SET labels = array_append(labels, 'workflow') WHERE id = $1")
        .bind(workflow_label)
        .execute(&pool)
        .await
        .unwrap();
    let wf_truth_before: f64 =
        sqlx::query_scalar("SELECT truth_value FROM workflows WHERE id = $1")
            .bind(workflow_row_claim)
            .fetch_one(&pool)
            .await
            .unwrap();

    let steps = [
        step_by_edge,
        step_by_lineage,
        workflow_row_claim,
        workflow_label,
    ];
    let mut ids = vec![control];
    ids.extend(steps);
    let records = wave(&pool, &ids, "L1").await;
    let mut before = Vec::new();
    for &s in &steps {
        before.push((truth_of(&pool, s).await, row_version(&pool, s).await));
    }

    let (report, _) = run_apply(&pool, &viewer, &records, false).await;

    assert_refreshed(&pool, control, &report).await;
    for (&s, (t, v)) in steps.iter().zip(before) {
        assert_eq!(
            report.bucket_of(s),
            Some(Bucket::WorkflowOrStep),
            "arm of {s}"
        );
        assert_untouched(&pool, s, t, v, "workflow or step").await;
    }
    let wf_truth_after: f64 = sqlx::query_scalar("SELECT truth_value FROM workflows WHERE id = $1")
        .bind(workflow_row_claim)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        wf_truth_after.to_bits(),
        wf_truth_before.to_bits(),
        "the workflows row moved"
    );
}

// ── (5) a value changed since the snapshot is left untouched ───────────────

/// The cache moved after the wave (an organic evidence fold): the wave's value
/// is no longer the one served, so the mirror is not refreshed to it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cache_moved_since_the_wave_is_left_untouched(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let control = mirror_claim(&pool, author, 0.731_37).await;
    let moved = mirror_claim(&pool, author, 0.682_91).await;
    let records = wave(&pool, &[control, moved], "L1").await;
    let organic = seed_agent(&pool).await;
    evidence(&pool, moved, organic, 0.577_31, false).await;
    let t = truth_of(&pool, moved).await;
    let v = row_version(&pool, moved).await;

    let (report, _) = run_apply(&pool, &viewer, &records, false).await;

    assert_refreshed(&pool, control, &report).await;
    assert_eq!(report.bucket_of(moved), Some(Bucket::SupersededSinceWave));
    assert_untouched(&pool, moved, t, v, "cache moved since the wave").await;
}

/// `truth_value` re-authored between the dry run and the apply: the apply
/// re-reads under its row lock, finds no mirror, and the authored value
/// survives. (It is reported `not_a_mirror`: under the lock the CAS itself
/// cannot lose a race; that guard is pinned on its own below.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_truth_value_changed_after_the_dry_run_survives_the_apply(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let control = mirror_claim(&pool, author, 0.731_37).await;
    let patched = mirror_claim(&pool, author, 0.682_91).await;
    let records = wave(&pool, &[control, patched], "L1").await;

    let dry = dry_run(&pool, &viewer, &plan_candidates(&records), &opts(false))
        .await
        .expect("dry run");
    assert_eq!(
        dry.bucket_of(patched),
        Some(Bucket::Refresh),
        "eligible at the dry run"
    );
    author_truth(&pool, patched, 0.432_198_7).await;
    let v = row_version(&pool, patched).await;

    let (report, _) = run_apply(&pool, &viewer, &records, false).await;

    assert_refreshed(&pool, control, &report).await;
    assert_eq!(report.bucket_of(patched), Some(Bucket::NotAMirror));
    assert_untouched(&pool, patched, 0.432_198_7, v, "patched after the dry run").await;
}

// ── (6) the compare-and-set guard itself ───────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn the_compare_and_set_matches_only_the_exact_values_on_a_current_non_compound(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let a = mirror_claim(&pool, author, 0.731_37).await;
    let t = truth_of(&pool, a).await;
    let p = cache_of(&pool, a).await.pignistic_prob.unwrap();
    let mut conn = pool.acquire().await.unwrap();

    let stale_truth = f64::from_bits(t.to_bits() + 1);
    assert!(
        !cas_refresh(&mut conn, a, stale_truth, p, 0.612_3)
            .await
            .unwrap(),
        "raced on truth"
    );
    let stale_cache = f64::from_bits(p.to_bits() + 1);
    assert!(
        !cas_refresh(&mut conn, a, t, stale_cache, 0.612_3)
            .await
            .unwrap(),
        "raced on cache"
    );
    assert_eq!(truth_of(&pool, a).await.to_bits(), t.to_bits());

    // A decomposition lands: the claim is a compound now.
    let child = seed_claim(&pool, author).await;
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(a)
    .bind(child)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        !cas_refresh(&mut conn, a, t, p, 0.612_3).await.unwrap(),
        "wrote a compound"
    );
    assert_eq!(truth_of(&pool, a).await.to_bits(), t.to_bits());

    // The same exact values on a current standalone do match.
    let b = mirror_claim(&pool, author, 0.682_91).await;
    let tb = truth_of(&pool, b).await;
    let pb = cache_of(&pool, b).await.pignistic_prob.unwrap();
    assert!(
        cas_refresh(&mut conn, b, tb, pb, 0.612_3).await.unwrap(),
        "the exact values did not match"
    );
    assert_eq!(truth_of(&pool, b).await, 0.612_3);

    // Not current: no match, whatever the values.
    let c = mirror_claim(&pool, author, 0.655_13).await;
    let tc = truth_of(&pool, c).await;
    let pc = cache_of(&pool, c).await.pignistic_prob.unwrap();
    sqlx::query("UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL WHERE id = $1")
        .bind(c)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        !cas_refresh(&mut conn, c, tc, pc, 0.612_3).await.unwrap(),
        "wrote a non-current claim"
    );
}

// ── (7) round values are held; compounds are left untouched ────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn a_round_mirror_is_held_unless_included_and_a_compound_is_left_untouched(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let control = mirror_claim(&pool, author, 0.731_37).await;
    // Hand-set: a mirror at a round 0.75 (the wave folds real evidence over it).
    let round = mirror_claim(&pool, author, 0.682_91).await;
    set_mirror_value(&pool, round, 0.75).await;
    let compound = mirror_claim(&pool, author, 0.655_13).await;
    let records = wave(&pool, &[control, round, compound], "L1").await;
    let child = seed_claim(&pool, author).await;
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(compound)
    .bind(child)
    .execute(&pool)
    .await
    .unwrap();
    let vr = row_version(&pool, round).await;
    let tc = truth_of(&pool, compound).await;
    let vc = row_version(&pool, compound).await;

    let (report, _) = run_apply(&pool, &viewer, &records, false).await;
    assert_refreshed(&pool, control, &report).await;
    assert_eq!(report.bucket_of(round), Some(Bucket::RoundValue));
    assert_untouched(&pool, round, 0.75, vr, "round, not included").await;
    assert!(matches!(report.bucket_of(compound), Some(Bucket::Compound)));
    assert_untouched(&pool, compound, tc, vc, "compound").await;

    // After review: --include-round admits it, and only it moves.
    let (report, _) = run_apply(&pool, &viewer, &records, true).await;
    assert_refreshed(&pool, round, &report).await;
    assert_eq!(report.bucket_of(compound), Some(Bucket::Compound));
    assert_untouched(&pool, compound, tc, vc, "compound, round included").await;
}

// ── (8) chained and broken chains of wave files ────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn two_chained_waves_refresh_to_the_last_and_a_broken_chain_is_left_untouched(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let chained = mirror_claim(&pool, author, 0.731_37).await;
    let broken = mirror_claim(&pool, author, 0.682_91).await;
    let old_chained = truth_of(&pool, chained).await;

    let mut records = wave(&pool, &[chained, broken], "L1").await;
    // Another writer lands on `broken` between the two waves.
    let organic = seed_agent(&pool).await;
    evidence(&pool, broken, organic, 0.577_31, false).await;
    records.extend(wave(&pool, &[chained, broken], "E-pass-1").await);
    let tb = truth_of(&pool, broken).await;
    let vb = row_version(&pool, broken).await;

    let (report, written) = run_apply(&pool, &viewer, &records, false).await;

    assert_refreshed(&pool, chained, &report).await;
    let r = written.iter().find(|r| r.claim_id == chained).unwrap();
    assert_eq!(
        r.cache_old.to_bits(),
        old_chained.to_bits(),
        "old = first.before"
    );
    // Chain order (L1 ran first), not name order.
    assert_eq!(r.waves, vec!["L1".to_string(), "E-pass-1".to_string()]);
    assert_eq!(report.bucket_of(broken), Some(Bucket::BrokenChain));
    assert_untouched(&pool, broken, tb, vb, "broken chain").await;
}

// ── (9) no mirror-capable writer row ───────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_without_a_live_mirror_writer_row_is_left_untouched(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let control = mirror_claim(&pool, author, 0.731_37).await;
    let no_writer = mirror_claim(&pool, author, 0.682_91).await;
    let retracted = mirror_claim(&pool, author, 0.655_13).await;
    let records = wave(&pool, &[control, no_writer, retracted], "L1").await;
    // `retracted`'s auto_wire rows are all retracted, through the retraction
    // definer (the real path): it has auto_wire rows, none live.
    retract_all_mass_rows(&pool, retracted, author).await;
    let tr = truth_of(&pool, retracted).await;
    let vr = row_version(&pool, retracted).await;
    // Hand-set: its rows were written by another method (the cache and the
    // fold are unchanged, so only this rule fails).
    sqlx::query("UPDATE mass_functions SET combination_method = 'conjunctive' WHERE claim_id = $1")
        .bind(no_writer)
        .execute(&pool)
        .await
        .unwrap();
    let t = truth_of(&pool, no_writer).await;
    let v = row_version(&pool, no_writer).await;

    let (report, _) = run_apply(&pool, &viewer, &records, false).await;

    assert_refreshed(&pool, control, &report).await;
    assert_eq!(report.bucket_of(no_writer), Some(Bucket::NoMirrorWriter));
    assert_untouched(&pool, no_writer, t, v, "no mirror writer").await;
    assert_eq!(report.bucket_of(retracted), Some(Bucket::NoMirrorWriter));
    assert_untouched(&pool, retracted, tr, vr, "only retracted auto_wire rows").await;
}

/// Every mass function of `claim` marked retracted, by `principal`.
/// Hand-set on the privileged test session (the retraction guard admits a
/// bypass session): `epigraph_retract_mass_function` needs a writer of the
/// row's owning group, which this fixture does not build. Checks none is
/// live while at least one is still an `auto_wire` row.
async fn retract_all_mass_rows(pool: &PgPool, claim: Uuid, principal: Uuid) {
    sqlx::query(
        "UPDATE mass_functions \
            SET retracted_at = now(), retracted_by = $2, retract_reason = 'refresh test' \
          WHERE claim_id = $1",
    )
    .bind(claim)
    .bind(principal)
    .execute(pool)
    .await
    .expect("retract");
    let (live, auto_wire): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE retracted_at IS NULL), \
                count(*) FILTER (WHERE combination_method = 'auto_wire') \
           FROM mass_functions WHERE claim_id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("count");
    assert_eq!(live, 0, "precondition: no live row");
    assert!(auto_wire > 0, "precondition: an auto_wire row, retracted");
}

// ── (10) the dry run writes nothing ────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn the_dry_run_writes_nothing_and_reports_the_would_change_set(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let a = mirror_claim(&pool, author, 0.731_37).await;
    let b = mirror_claim(&pool, author, 0.682_91).await;
    let records = wave(&pool, &[a, b], "L1").await;
    let before = [
        (truth_of(&pool, a).await, row_version(&pool, a).await),
        (truth_of(&pool, b).await, row_version(&pool, b).await),
    ];

    let report = dry_run(&pool, &viewer, &plan_candidates(&records), &opts(false))
        .await
        .expect("dry run");

    assert_eq!(report.ids(Bucket::Refresh), vec![a, b]);
    for (&id, (t, v)) in [a, b].iter().zip(before) {
        assert_untouched(&pool, id, t, v, "dry run").await;
    }
    // The dry run's own transaction reported itself read-only and
    // repeatable-read: it ran in `begin_dry_run_tx`'s transaction, where any
    // write fails (test (15)).
    assert_eq!(
        report.transaction,
        Some(TxMode {
            read_only: "on".into(),
            isolation: "repeatable read".into(),
        })
    );
    let json = report.to_json(true, false, records.len());
    assert_eq!(json["buckets"]["refresh"]["count"], 2);
    assert_eq!(json["refresh"].as_array().unwrap().len(), 2);
    assert_eq!(json["transaction"]["read_only"], "on");
    assert_eq!(json["transaction"]["isolation"], "repeatable read");
}

// ── (11) restore ───────────────────────────────────────────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn a_restore_puts_the_mirror_back_bit_exactly_and_leaves_a_later_write(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let a = mirror_claim(&pool, author, 0.731_37).await;
    let k = mirror_claim(&pool, author, 0.682_91).await;
    let ta = truth_of(&pool, a).await;
    let records = wave(&pool, &[a, k], "L1").await;
    let (report, written) = run_apply(&pool, &viewer, &records, false).await;
    assert_eq!(report.ids(Bucket::Refresh), vec![a, k]);

    // Through the record file.
    let mut file = Vec::new();
    for r in &written {
        write_truth_record(&mut file, r).unwrap();
    }
    let back = read_truth_records(file.as_slice()).unwrap();
    assert_eq!(back, written);

    // A later authored write on k.
    author_truth(&pool, k, 0.444_321).await;

    let dry = restore(&pool, &back, 1, true).await.unwrap();
    assert_eq!(dry.restored, vec![a], "dry-run restore outcome");
    assert_ne!(
        truth_of(&pool, a).await.to_bits(),
        ta.to_bits(),
        "a dry-run restore wrote"
    );

    let out = restore(&pool, &back, 1, false).await.unwrap();
    assert_eq!(out.restored, vec![a]);
    assert_eq!(out.superseded_since_refresh, vec![k]);
    assert_eq!(
        truth_of(&pool, a).await.to_bits(),
        ta.to_bits(),
        "not bit-exact"
    );
    assert_eq!(
        truth_of(&pool, k).await,
        0.444_321,
        "a later write was undone"
    );

    let again = restore(&pool, &back, 1, false).await.unwrap();
    assert_eq!(again.already_restored, vec![a]);
    assert_eq!(again.superseded_since_refresh, vec![k]);
}

// ── (12) the binary: dry run, apply, restore, through files ────────────────

fn scratch_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("refresh-truth-mirrors-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

/// A cleared environment (no operator DSN leaks in), a cwd with no `.env`,
/// and an API base nothing answers on (a writing run refuses there unless it
/// passes the hidden `--allow-mode-skew`).
fn run_bin(cwd: &Path, url: &str, args: &[&str]) -> Output {
    Command::new(BIN)
        .env_clear()
        .env("DATABASE_URL", url)
        .env("EPIGRAPH_API", "http://127.0.0.1:9")
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("spawn")
}

fn stdout_count(out: &Output, key: &str) -> usize {
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")))
        .unwrap_or_else(|| panic!("no `{key}:` line in stdout"))
        .trim()
        .parse()
        .expect("a count")
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_binary_dry_runs_applies_and_restores_through_files(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let dir = scratch_dir();
    let author = seed_agent(&pool).await;
    let a = mirror_claim(&pool, author, 0.731_37).await;
    let authored = mirror_claim(&pool, author, 0.682_91).await;
    author_truth(&pool, authored, truth_of(&pool, authored).await + 1e-6).await;
    let ta = truth_of(&pool, a).await;
    let t_authored = truth_of(&pool, authored).await;
    let records = wave(&pool, &[a, authored], "L1").await;
    let wave_file = dir.join("L1.jsonl");
    let mut buf = Vec::new();
    for r in &records {
        write_wave_record(&mut buf, r).unwrap();
    }
    std::fs::write(&wave_file, buf).unwrap();
    let w = wave_file.to_str().unwrap();

    // Dry run (the default).
    let dry_report = dir.join("dry.json");
    // The design's spelling: an explicit --dry-run and --batch.
    let o = run_bin(
        &dir,
        &url,
        &[
            "--waves",
            w,
            "--dry-run",
            "--batch",
            "1",
            "--report",
            dry_report.to_str().unwrap(),
        ],
    );
    assert!(
        o.status.success(),
        "dry run failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(stdout_count(&o, "refresh"), 1);
    assert_eq!(stdout_count(&o, "not_a_mirror"), 1);
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(
        stdout.contains(&format!("  {a} ")),
        "the would-change set does not list the mirror"
    );
    assert!(!stdout.contains(&format!("  {authored} ")));
    assert_eq!(
        truth_of(&pool, a).await.to_bits(),
        ta.to_bits(),
        "the dry run wrote"
    );
    let rep: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&dry_report).unwrap()).unwrap();
    assert_eq!(rep["dry_run"], true);
    assert_eq!(rep["buckets"]["refresh"]["ids"][0], a.to_string());

    // An existing report path refuses the run before the database.
    let o = run_bin(
        &dir,
        &url,
        &["--waves", w, "--report", dry_report.to_str().unwrap()],
    );
    assert!(!o.status.success(), "overwrote an existing report");

    // --apply and --dry-run together are refused (argv error, nothing written).
    let record = dir.join("D-RECORD.jsonl");
    let o = run_bin(
        &dir,
        &url,
        &[
            "--waves",
            w,
            "--apply",
            "--dry-run",
            "--record",
            record.to_str().unwrap(),
            "--report",
            dir.join("both.json").to_str().unwrap(),
            "--allow-mode-skew",
        ],
    );
    assert!(!o.status.success(), "--apply --dry-run was accepted");
    assert!(!record.exists(), "a refused run created the record file");
    assert_eq!(truth_of(&pool, a).await.to_bits(), ta.to_bits());

    // A writing run without --allow-mode-skew: nothing answers at
    // EPIGRAPH_API, so the belief-mode check refuses it (exit 3) before any
    // output file or the database is touched.
    let refused_record = dir.join("REFUSED-RECORD.jsonl");
    let refused_report = dir.join("refused.json");
    let va = row_version(&pool, a).await;
    let o = run_bin(
        &dir,
        &url,
        &[
            "--waves",
            w,
            "--apply",
            "--record",
            refused_record.to_str().unwrap(),
            "--report",
            refused_report.to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert_eq!(
        o.status.code(),
        Some(MODE_CHECK_REFUSED_EXIT),
        "an apply with unreadable server modes must refuse; stderr: {stderr}"
    );
    assert!(stderr.contains("belief_modes"), "stderr: {stderr}");
    assert!(
        !refused_record.exists(),
        "a refused apply created its record"
    );
    assert!(
        !refused_report.exists(),
        "a refused apply created its report"
    );
    assert_eq!(truth_of(&pool, a).await.to_bits(), ta.to_bits());
    assert_eq!(row_version(&pool, a).await, va, "a refused apply wrote");

    // Apply.
    let o = run_bin(
        &dir,
        &url,
        &[
            "--waves",
            w,
            "--apply",
            "--record",
            record.to_str().unwrap(),
            "--report",
            dir.join("apply.json").to_str().unwrap(),
            "--allow-mode-skew",
        ],
    );
    assert!(
        o.status.success(),
        "apply failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(stdout_count(&o, "refresh"), 1);
    let new = cache_of(&pool, a).await.pignistic_prob.unwrap();
    assert_eq!(truth_of(&pool, a).await.to_bits(), new.to_bits());
    assert_eq!(
        truth_of(&pool, authored).await.to_bits(),
        t_authored.to_bits()
    );
    let recs = read_truth_records(std::io::BufReader::new(
        std::fs::File::open(&record).unwrap(),
    ))
    .unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].claim_id, a);

    // A non-dry restore without --allow-mode-skew is a writing run too: it
    // refuses (exit 3) before its default report is created.
    let va = row_version(&pool, a).await;
    let o = run_bin(&dir, &url, &["--restore", record.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert_eq!(
        o.status.code(),
        Some(MODE_CHECK_REFUSED_EXIT),
        "a restore with unreadable server modes must refuse; stderr: {stderr}"
    );
    assert!(stderr.contains("belief_modes"), "stderr: {stderr}");
    assert_eq!(
        truth_of(&pool, a).await.to_bits(),
        new.to_bits(),
        "a refused restore wrote"
    );
    assert_eq!(row_version(&pool, a).await, va, "a refused restore wrote");
    assert!(
        !std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e
                .file_name()
                .to_string_lossy()
                .starts_with("D-RECORD.jsonl.restore-")),
        "a refused restore created its report"
    );

    // Restore, as the design spells it: no --report (it defaults next to the
    // record file). A dry run first, which writes nothing.
    let o = run_bin(
        &dir,
        &url,
        &["--restore", record.to_str().unwrap(), "--dry-run"],
    );
    assert!(
        o.status.success(),
        "restore dry run failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(stdout_count(&o, "restored"), 1);
    assert_eq!(
        truth_of(&pool, a).await.to_bits(),
        new.to_bits(),
        "a dry-run restore wrote"
    );
    let o = run_bin(
        &dir,
        &url,
        &["--restore", record.to_str().unwrap(), "--allow-mode-skew"],
    );
    assert!(
        o.status.success(),
        "restore failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(stdout_count(&o, "restored"), 1);
    assert_eq!(truth_of(&pool, a).await.to_bits(), ta.to_bits());
    let reports: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("D-RECORD.jsonl.restore-") && n.ends_with(".report.json"))
        .collect();
    assert_eq!(
        reports.len(),
        2,
        "the two restores' default reports: {reports:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── (13) a record that cannot be written stops the run, its batch rolled back ─

/// `apply` with an `on_record` that fails on its `fail_on`-th call (1-based)
/// and keeps every record it accepted before that.
async fn apply_failing_on(
    pool: &PgPool,
    viewer: &Viewer,
    candidates: &[Candidate],
    batch_size: usize,
    fail_on: usize,
) -> (anyhow::Result<MirrorReport>, Vec<TruthRecord>) {
    let mut delivered = Vec::new();
    let mut calls = 0;
    let result = apply(
        pool,
        viewer,
        candidates,
        &RefreshOptions {
            batch_size,
            include_round: false,
        },
        |r| {
            calls += 1;
            if calls == fail_on {
                anyhow::bail!("disk full (test record writer)");
            }
            delivered.push(r.clone());
            Ok(())
        },
    )
    .await;
    (result, delivered)
}

/// The restore guarantee: no committed write lacks a record. A record writer
/// that fails rolls its whole batch back and stops the run; batches that
/// committed before it keep their writes, and their records were delivered.
#[sqlx::test(migrations = "../../migrations")]
async fn apply_rolls_back_a_batch_whose_record_fails(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let a = mirror_claim(&pool, author, 0.731_37).await;
    let b = mirror_claim(&pool, author, 0.682_91).await;
    let records = wave(&pool, &[a, b], "L1").await;
    // The run's order is the planner's.
    let cands = plan_candidates(&records);
    let (first, second) = (cands[0].claim_id, cands[1].claim_id);
    let t1 = truth_of(&pool, first).await;
    let v1 = row_version(&pool, first).await;
    let t2 = truth_of(&pool, second).await;
    let v2 = row_version(&pool, second).await;

    // (i) The first record fails: nothing is written.
    let (result, delivered) = apply_failing_on(&pool, &viewer, &cands, 1, 1).await;
    let err = result.expect_err("a failed record writer must stop the run");
    assert!(
        format!("{err:#}").contains("disk full"),
        "the run stopped for another reason: {err:#}"
    );
    assert!(delivered.is_empty());
    assert_untouched(&pool, first, t1, v1, "1st record failed: 1st claim").await;
    assert_untouched(&pool, second, t2, v2, "1st record failed: 2nd claim").await;

    // (ii) One batch of two, the second record fails: the first record WAS
    // delivered, and its write still rolls back with the batch.
    let (result, delivered) = apply_failing_on(&pool, &viewer, &cands, 2, 2).await;
    assert!(result.is_err(), "a failed record writer must stop the run");
    assert_eq!(
        delivered.iter().map(|r| r.claim_id).collect::<Vec<_>>(),
        vec![first]
    );
    assert_untouched(&pool, first, t1, v1, "batch of two rolled back: 1st claim").await;
    assert_untouched(&pool, second, t2, v2, "batch of two rolled back: 2nd claim").await;

    // (iii) Batches of one, the second record fails: the first batch
    // committed with its record delivered; the second rolled back.
    let (result, delivered) = apply_failing_on(&pool, &viewer, &cands, 1, 2).await;
    assert!(result.is_err(), "a failed record writer must stop the run");
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].claim_id, first);
    let new_first = cache_of(&pool, first).await.pignistic_prob.unwrap();
    assert_eq!(
        truth_of(&pool, first).await.to_bits(),
        new_first.to_bits(),
        "the committed first batch was not refreshed"
    );
    assert_eq!(delivered[0].truth_written.to_bits(), new_first.to_bits());
    assert_untouched(&pool, second, t2, v2, "second batch rolled back").await;
}

// ── (14) a procedural claim (a node of a workflow-ingest tree) ─────────────

/// An agent registered as the `workflow-ingest` system agent (migration 148),
/// the one author whose `source_type: workflow` root makes a tree procedural.
/// Planted with triggers off, as `bulk_recompute_guard.rs` does.
async fn workflow_ingest_agent(pool: &PgPool) -> Uuid {
    let id = seed_agent(pool).await;
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("replica");
    sqlx::query(
        "INSERT INTO public.system_agents (role, agent_id, registered_public_key, reason) \
         SELECT 'workflow-ingest', a.id, a.public_key, 'refresh-truth-mirrors test plant' \
           FROM public.agents a WHERE a.id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .expect("plant the workflow-ingest system agent");
    tx.commit().await.expect("commit");
    id
}

/// A decomposed descendant of a workflow-ingest root can carry none of the
/// `workflow_or_step` arms (no `executes` in-edge, no `step_lineage_id`, no
/// `workflow` label, no `workflows` row); its procedural role is then its
/// only guard (R-177 OD-D2). Both `classify` and the CAS refuse it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_procedural_claim_is_left_untouched(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let wf_agent = workflow_ingest_agent(&pool).await;
    let control = mirror_claim(&pool, author, 0.731_37).await;
    let node = mirror_claim(&pool, author, 0.682_91).await;
    let records = wave(&pool, &[control, node], "L1").await;

    // Hand-set structure: a workflow-ingest root stamped `source_type:
    // workflow` decomposes to `node`.
    let content = format!("workflow thesis {}", Uuid::new_v4());
    let root: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current, properties) \
         VALUES ($1, sha256($1::bytea), 0.5, $2, true, $3) RETURNING id",
    )
    .bind(&content)
    .bind(wf_agent)
    .bind(serde_json::json!({ "source_type": "workflow", "level": 0 }))
    .fetch_one(&pool)
    .await
    .expect("workflow root");
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(root)
    .bind(node)
    .execute(&pool)
    .await
    .expect("decomposes_to edge");
    let roles = claim_role::roles_batch(&pool, &viewer, &[control, node])
        .await
        .expect("roles");
    assert_eq!(
        roles[&node],
        ClaimRole::Procedural,
        "precondition: the node is procedural"
    );
    assert_eq!(roles[&control], ClaimRole::Standalone, "precondition");
    let t = truth_of(&pool, node).await;
    let p = cache_of(&pool, node).await.pignistic_prob.unwrap();
    let v = row_version(&pool, node).await;

    let (report, written) = run_apply(&pool, &viewer, &records, false).await;

    assert_refreshed(&pool, control, &report).await;
    assert_eq!(report.bucket_of(node), Some(Bucket::Procedural));
    assert!(written.iter().all(|r| r.claim_id != node));
    assert_untouched(&pool, node, t, v, "procedural").await;

    // The compare-and-set refuses it on its own, on the exact values.
    let mut conn = pool.acquire().await.unwrap();
    assert!(
        !cas_refresh(&mut conn, node, t, p, 0.612_3).await.unwrap(),
        "the CAS wrote a procedural claim"
    );
    assert_untouched(&pool, node, t, v, "procedural, direct CAS").await;
}

// ── (15) the dry run's transaction cannot write ────────────────────────────

/// Design section 2.5 test 10: the dry run's transaction is READ ONLY (a write
/// inside it fails with 25006) and REPEATABLE READ (one snapshot).
#[sqlx::test(migrations = "../../migrations")]
async fn the_dry_run_transaction_is_read_only_and_repeatable_read(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let a = mirror_claim(&pool, author, 0.731_37).await;
    let t = truth_of(&pool, a).await;
    let v = row_version(&pool, a).await;

    let mut tx = begin_dry_run_tx(&pool).await.expect("open the dry run tx");
    let iso: String = sqlx::query_scalar("SHOW transaction_isolation")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(iso, "repeatable read");
    let err = sqlx::query("UPDATE claims SET truth_value = truth_value WHERE id = $1")
        .bind(a)
        .execute(&mut *tx)
        .await
        .expect_err("a write inside the dry run's transaction succeeded");
    let code = err
        .as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned());
    assert_eq!(
        code.as_deref(),
        Some("25006"),
        "expected read_only_sql_transaction, got {err}"
    );
    tx.rollback().await.unwrap();
    assert_untouched(&pool, a, t, v, "read-only tx").await;
}

// ── (16) the compare-and-set re-checks every workflow/step arm ─────────────

/// The four arms of the workflow-or-step rule, each on its own claim, each
/// present on the row the CAS writes: the CAS refuses all four on the exact
/// values (an arm committed after the locked read is caught by the write),
/// and writes the control.
#[sqlx::test(migrations = "../../migrations")]
async fn the_compare_and_set_refuses_every_workflow_or_step_arm(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let control = mirror_claim(&pool, author, 0.731_37).await;
    let step_by_edge = mirror_claim(&pool, author, 0.682_91).await;
    let step_by_lineage = mirror_claim(&pool, author, 0.655_13).await;
    let workflow_row_claim = mirror_claim(&pool, author, 0.701_77).await;
    let workflow_label = mirror_claim(&pool, author, 0.718_23).await;
    // Hand-set structure, one arm per claim, as test (4) builds it.
    let workflow_root = Uuid::new_v4();
    workflow_row(&pool, workflow_root, control).await;
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'workflow', $2, 'claim', 'executes')",
    )
    .bind(workflow_root)
    .bind(step_by_edge)
    .execute(&pool)
    .await
    .expect("executes edge");
    sqlx::query("UPDATE claims SET step_lineage_id = gen_random_uuid() WHERE id = $1")
        .bind(step_by_lineage)
        .execute(&pool)
        .await
        .unwrap();
    workflow_row(&pool, workflow_row_claim, workflow_row_claim).await;
    sqlx::query("UPDATE claims SET labels = array_append(labels, 'workflow') WHERE id = $1")
        .bind(workflow_label)
        .execute(&pool)
        .await
        .unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let mut wrote = Vec::new();
    for (id, arm) in [
        (step_by_edge, "executes in-edge"),
        (step_by_lineage, "step_lineage_id"),
        (workflow_row_claim, "workflows row"),
        (workflow_label, "workflow label"),
    ] {
        let t = truth_of(&pool, id).await;
        let p = cache_of(&pool, id).await.pignistic_prob.unwrap();
        let v = row_version(&pool, id).await;
        if cas_refresh(&mut conn, id, t, p, 0.612_3).await.unwrap() {
            wrote.push(arm);
        } else {
            assert_untouched(&pool, id, t, v, arm).await;
        }
    }
    assert!(wrote.is_empty(), "the CAS wrote a claim with: {wrote:?}");
    let t = truth_of(&pool, control).await;
    let p = cache_of(&pool, control).await.pignistic_prob.unwrap();
    assert!(
        cas_refresh(&mut conn, control, t, p, 0.612_3)
            .await
            .unwrap(),
        "control: the exact values on a plain claim match"
    );
}

// ── (17) a claim superseded after the refresh, then restored ───────────────

/// `actor` supersedes `old` through the real act (the privileged test pool);
/// the predecessor's `truth_value` is not touched by it.
async fn supersede(pool: &PgPool, old: Uuid, actor: Uuid) {
    let t = truth_of(pool, old).await;
    ClaimRepository::supersede(
        pool,
        ClaimId::from_uuid(old),
        &format!("a restatement of {old}"),
        TruthValue::clamped(0.6),
        "refresh truth mirrors test",
        epigraph_db::SupersedeActor::new(actor, epigraph_db::SupersedeTool::SupersedeClaim),
    )
    .await
    .expect("supersede");
    let current: bool = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(old)
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(!current, "precondition: the predecessor is retired");
    assert_eq!(
        truth_of(pool, old).await.to_bits(),
        t.to_bits(),
        "precondition: the supersede left the predecessor's truth_value"
    );
}

/// Backlog 7e8a0ee2: the restore is a faithful undo (it also restores a claim
/// superseded after the refresh, whose truth_value still holds what the
/// refresh wrote, as `restore_belief_cache` restores its cache), and it says
/// so: that claim is `restored_not_current`, never counted `restored`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_superseded_after_the_refresh_is_restored_and_reported_not_current(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let live = mirror_claim(&pool, author, 0.731_37).await;
    let retired = mirror_claim(&pool, author, 0.682_91).await;
    let t_live = truth_of(&pool, live).await;
    let t_retired = truth_of(&pool, retired).await;
    let records = wave(&pool, &[live, retired], "L1").await;
    let (report, written) = run_apply(&pool, &viewer, &records, false).await;
    assert_eq!(report.ids(Bucket::Refresh), vec![live, retired]);

    supersede(&pool, retired, author).await;

    let dry = restore(&pool, &written, 1, true).await.unwrap();
    assert_eq!(dry.restored, vec![live], "dry run");
    assert_eq!(dry.restored_not_current, vec![retired], "dry run");

    let out = restore(&pool, &written, 1, false).await.unwrap();
    assert_eq!(
        out.restored,
        vec![live],
        "only the live claim counts restored"
    );
    assert_eq!(out.restored_not_current, vec![retired]);
    assert!(out.superseded_since_refresh.is_empty() && out.missing.is_empty());
    assert_eq!(truth_of(&pool, live).await.to_bits(), t_live.to_bits());
    assert_eq!(
        truth_of(&pool, retired).await.to_bits(),
        t_retired.to_bits(),
        "the faithful undo restores the retired row too"
    );
    let names: Vec<&str> = out.buckets().iter().map(|(n, _)| *n).collect();
    assert!(names.contains(&"restored_not_current"), "{names:?}");

    let again = restore(&pool, &written, 1, false).await.unwrap();
    assert_eq!(again.already_restored, vec![retired, live]);
}

// ── (18) a mirror superseded after the wave, through apply ─────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn a_mirror_superseded_after_the_wave_is_not_current_through_apply(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let control = mirror_claim(&pool, author, 0.731_37).await;
    let retired = mirror_claim(&pool, author, 0.682_91).await;
    let records = wave(&pool, &[control, retired], "L1").await;
    supersede(&pool, retired, author).await;
    // Still a mirror of the old cache, with the wave's cache: only the
    // currency rule fails.
    let c = plan_candidates(&records)
        .into_iter()
        .find(|c| c.claim_id == retired)
        .unwrap();
    assert_eq!(Some(truth_of(&pool, retired).await), c.old);
    assert_eq!(cache_of(&pool, retired).await, c.written);
    let t = truth_of(&pool, retired).await;
    let v = row_version(&pool, retired).await;

    let (report, written) = run_apply(&pool, &viewer, &records, false).await;

    assert_refreshed(&pool, control, &report).await;
    assert_eq!(report.bucket_of(retired), Some(Bucket::NotCurrent));
    assert!(written.iter().all(|r| r.claim_id != retired));
    assert_untouched(&pool, retired, t, v, "not current").await;
}

// ── (19) a missing claim, through apply and through the restore ────────────

#[sqlx::test(migrations = "../../migrations")]
async fn a_missing_claim_is_reported_missing_by_apply_and_by_the_restore(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let control = mirror_claim(&pool, author, 0.731_37).await;
    let mut records = wave(&pool, &[control], "L1").await;
    // A wave record for a claim that does not exist (deleted since, or a
    // record file from another database).
    let ghost = Uuid::new_v4();
    let mut ghost_rec = records[0].clone();
    ghost_rec.claim_id = ghost;
    records.push(ghost_rec);

    let (report, written) = run_apply(&pool, &viewer, &records, false).await;
    assert_refreshed(&pool, control, &report).await;
    assert_eq!(report.bucket_of(ghost), Some(Bucket::Missing));
    assert_eq!(
        written.iter().map(|r| r.claim_id).collect::<Vec<_>>(),
        vec![control]
    );

    let mut with_ghost = written.clone();
    let mut g = written[0].clone();
    g.claim_id = ghost;
    with_ghost.push(g);
    let out = restore(&pool, &with_ghost, 1, false).await.unwrap();
    assert_eq!(out.missing, vec![ghost]);
    assert_eq!(out.restored, vec![control]);
    assert!(out.already_restored.is_empty() && out.superseded_since_refresh.is_empty());
}

// ── (20) a non-BetP cache column moved since the wave ──────────────────────

#[sqlx::test(migrations = "../../migrations")]
async fn a_cache_moved_since_the_wave_in_a_column_other_than_betp_is_left_untouched(pool: PgPool) {
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let control = mirror_claim(&pool, author, 0.731_37).await;
    let belief_moved = mirror_claim(&pool, author, 0.682_91).await;
    let empty_moved = mirror_claim(&pool, author, 0.655_13).await;
    let records = wave(&pool, &[control, belief_moved, empty_moved], "L1").await;
    // Hand-set (no writer moves one cache column alone): BetP, and so the
    // mirror and the CAS's cache test, stay exactly as the wave left them.
    for (id, col) in [(belief_moved, "belief"), (empty_moved, "mass_on_empty")] {
        sqlx::query(&format!(
            "UPDATE claims SET {col} = COALESCE({col}, 0) + 1e-6 WHERE id = $1"
        ))
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    }
    let snaps = [
        (
            belief_moved,
            truth_of(&pool, belief_moved).await,
            row_version(&pool, belief_moved).await,
        ),
        (
            empty_moved,
            truth_of(&pool, empty_moved).await,
            row_version(&pool, empty_moved).await,
        ),
    ];
    for (id, _, _) in &snaps {
        let c = plan_candidates(&records)
            .into_iter()
            .find(|c| c.claim_id == *id)
            .unwrap();
        assert_eq!(
            cache_of(&pool, *id).await.pignistic_prob,
            c.written.pignistic_prob,
            "precondition: BetP unmoved"
        );
    }

    let (report, _) = run_apply(&pool, &viewer, &records, false).await;

    assert_refreshed(&pool, control, &report).await;
    for (id, t, v) in snaps {
        assert_eq!(report.bucket_of(id), Some(Bucket::SupersededSinceWave));
        assert_untouched(&pool, id, t, v, "a non-BetP cache column moved").await;
    }
}

// ── (21) end to end through a real cache-only wave writer ──────────────────

/// The wave is `recompute_betp`'s own writer (`write_wave_claim`, a
/// standalone wave under the AEF), which rewrites the cache, never
/// `truth_value`, and records through `WaveLog` into a real wave file.
#[sqlx::test(migrations = "../../migrations")]
async fn a_mirror_is_refreshed_from_a_recompute_betp_wave_file(pool: PgPool) {
    use epigraph_cli::recompute_betp::{write_wave_claim, WaveLog, WaveRole};
    use epigraph_engine::atom_items::{AtomFoldMode, CompoundSourceEdges};
    use epigraph_engine::edge_factor::AtomCacheSettings;

    let dir = scratch_dir();
    let author = seed_agent(&pool).await;
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let a = mirror_claim(&pool, author, 0.731_37).await;
    // A second BBA, from another source, stored WITHOUT a fold
    // (`MassFunctionRepository::store`, the writer that stores a row and
    // leaves the cache): the cache, and so the mirror, still reflect the
    // first row only, and the wave's fold of both moves BetP.
    let frame: Uuid = sqlx::query_scalar("SELECT frame_id FROM mass_functions WHERE claim_id = $1")
        .bind(a)
        .fetch_one(&pool)
        .await
        .unwrap();
    let other = seed_agent(&pool).await;
    epigraph_db::MassFunctionRepository::store(
        &pool,
        a,
        frame,
        Some(other),
        &serde_json::json!({ "1": 0.4, "0,1": 0.6 }),
        Some(0.0),
        Some("auto_wire"),
        Some("empirical"),
        "unknown",
        None,
    )
    .await
    .expect("store a second BBA");
    let old = truth_of(&pool, a).await;
    let cache_before = cache_of(&pool, a).await;
    assert_eq!(
        cache_before.pignistic_prob.map(f64::to_bits),
        Some(old.to_bits()),
        "precondition: still a mirror after the unfolded store"
    );

    let wave_file = dir.join("standalone-wave.jsonl");
    let at: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let log = WaveLog::open(&wave_file, "standalone-aef", at).expect("open the wave log");
    let o = write_wave_claim(
        &pool,
        &viewer,
        a,
        WaveRole::Standalone,
        AtomCacheSettings {
            fold: AtomFoldMode::Aef,
            compound_source_edges: CompoundSourceEdges::Frozen,
            vacate_on_evidence_removal: true,
        },
        &log,
    )
    .await
    .expect("write_wave_claim");
    assert!(o.changed, "precondition: the wave moved the cache: {o:?}");
    assert_ne!(
        cache_of(&pool, a).await.pignistic_prob,
        cache_before.pignistic_prob,
        "precondition: the wave moved BetP"
    );
    assert_eq!(
        truth_of(&pool, a).await.to_bits(),
        old.to_bits(),
        "precondition: the wave writer left truth_value"
    );
    let records = read_wave(std::io::BufReader::new(
        std::fs::File::open(&wave_file).unwrap(),
    ))
    .expect("read the wave file");
    assert_eq!(records.len(), 1);

    let (report, written) = run_apply(&pool, &viewer, &records, false).await;

    assert_refreshed(&pool, a, &report).await;
    assert_eq!(written.len(), 1);
    assert_eq!(written[0].truth_before.to_bits(), old.to_bits());
    assert_eq!(written[0].waves, vec!["standalone-aef".to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

// ── (22) the binary: argument refusals write nothing ───────────────────────

/// A refreshable mirror `a`, its wave file, and its state before the run.
struct Refusal {
    url: String,
    dir: PathBuf,
    a: Uuid,
    wave_file: PathBuf,
    t: f64,
    v: (i64, DateTime<Utc>),
}

async fn refusal_fixture(pool: &PgPool) -> Refusal {
    let url = fixture::database_url_for(pool).await;
    let dir = scratch_dir();
    let author = seed_agent(pool).await;
    let a = mirror_claim(pool, author, 0.731_37).await;
    let records = wave(pool, &[a], "L1").await;
    let wave_file = dir.join("L1.jsonl");
    let mut buf = Vec::new();
    for r in &records {
        write_wave_record(&mut buf, r).unwrap();
    }
    std::fs::write(&wave_file, buf).unwrap();
    let t = truth_of(pool, a).await;
    let v = row_version(pool, a).await;
    Refusal {
        url,
        dir,
        a,
        wave_file,
        t,
        v,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_binary_refuses_an_existing_record_and_leaves_no_report(pool: PgPool) {
    let Refusal {
        url,
        dir,
        a,
        wave_file,
        t,
        v,
    } = refusal_fixture(&pool).await;
    let w = wave_file.to_str().unwrap();
    // An existing --record: refused before the database, the record kept
    // as it was, and no report left behind.
    let existing = dir.join("EXISTING-RECORD.jsonl");
    std::fs::write(&existing, b"an operator's earlier record\n").unwrap();
    let report = dir.join("existing.json");
    let o = run_bin(
        &dir,
        &url,
        &[
            "--waves",
            w,
            "--apply",
            "--record",
            existing.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
            "--allow-mode-skew",
        ],
    );
    assert!(!o.status.success(), "an existing record was accepted");
    assert_eq!(
        std::fs::read(&existing).unwrap(),
        b"an operator's earlier record\n"
    );
    assert!(!report.exists(), "a refused run left its report behind");
    assert_untouched(&pool, a, t, v, "existing record").await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_binary_refuses_a_record_without_apply(pool: PgPool) {
    let Refusal {
        url,
        dir,
        a,
        wave_file,
        t,
        v,
    } = refusal_fixture(&pool).await;
    let w = wave_file.to_str().unwrap();
    // --record without --apply: a usage error, never an apply.
    let record = dir.join("NO-APPLY-RECORD.jsonl");
    let report = dir.join("no-apply.json");
    let o = run_bin(
        &dir,
        &url,
        &[
            "--waves",
            w,
            "--record",
            record.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
            "--allow-mode-skew",
        ],
    );
    assert_eq!(o.status.code(), Some(2), "--record without --apply");
    assert!(!record.exists() && !report.exists());
    assert_untouched(&pool, a, t, v, "--record without --apply").await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_binary_refuses_include_round_with_restore(pool: PgPool) {
    let Refusal {
        url, dir, a, t, v, ..
    } = refusal_fixture(&pool).await;
    // --include-round with --restore: a usage error, nothing restored.
    // The record would restore `a` to 0.4 if the run went ahead.
    let restore_record = dir.join("RESTORE-RECORD.jsonl");
    let mut rec = Vec::new();
    write_truth_record(
        &mut rec,
        &TruthRecord {
            claim_id: a,
            truth_before: 0.4,
            truth_written: t,
            cache_old: 0.4,
            cache_new: t,
            waves: vec!["L1".into()],
            at: Utc::now(),
        },
    )
    .unwrap();
    std::fs::write(&restore_record, rec).unwrap();
    let report = dir.join("restore-round.json");
    let o = run_bin(
        &dir,
        &url,
        &[
            "--restore",
            restore_record.to_str().unwrap(),
            "--include-round",
            "--report",
            report.to_str().unwrap(),
            "--allow-mode-skew",
        ],
    );
    assert_eq!(o.status.code(), Some(2), "--include-round with --restore");
    assert!(!report.exists());
    assert_untouched(&pool, a, t, v, "--include-round with --restore").await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ── (23) a run that stops still writes its (partial) report ────────────────

/// A test-only trigger that refuses any `truth_value` write to `id` (an
/// error at a known batch, deterministically).
async fn refuse_truth_writes_to(pool: &PgPool, id: Uuid) {
    sqlx::query(
        "CREATE OR REPLACE FUNCTION refresh_test_refuse() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
           RAISE EXCEPTION 'refresh test: refused write of %', OLD.id; END $$",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("DROP TRIGGER IF EXISTS refresh_test_refuse ON claims")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER refresh_test_refuse BEFORE UPDATE OF truth_value ON claims \
         FOR EACH ROW WHEN (OLD.id = '{id}'::uuid) EXECUTE FUNCTION refresh_test_refuse()"
    ))
    .execute(pool)
    .await
    .unwrap();
}

fn report_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path).expect("the report file");
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("report {text:?}: {e}"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_run_that_stops_writes_a_partial_report_of_what_it_committed(pool: PgPool) {
    let url = fixture::database_url_for(&pool).await;
    let dir = scratch_dir();
    let author = seed_agent(&pool).await;
    let a = mirror_claim(&pool, author, 0.731_37).await;
    let b = mirror_claim(&pool, author, 0.682_91).await;
    let (ta, tb) = (truth_of(&pool, a).await, truth_of(&pool, b).await);
    let records = wave(&pool, &[a, b], "L1").await;
    assert_eq!(
        plan_candidates(&records)
            .iter()
            .map(|c| c.claim_id)
            .collect::<Vec<_>>(),
        vec![a, b],
        "precondition: a runs in the first batch"
    );
    let wave_file = dir.join("L1.jsonl");
    let mut buf = Vec::new();
    for r in &records {
        write_wave_record(&mut buf, r).unwrap();
    }
    std::fs::write(&wave_file, buf).unwrap();
    let w = wave_file.to_str().unwrap();

    // The refresh: batch 1 (a) commits, batch 2 (b) fails.
    refuse_truth_writes_to(&pool, b).await;
    let r1 = dir.join("R1.jsonl");
    let rep1 = dir.join("apply-1.json");
    let o = run_bin(
        &dir,
        &url,
        &[
            "--waves",
            w,
            "--apply",
            "--batch",
            "1",
            "--record",
            r1.to_str().unwrap(),
            "--report",
            rep1.to_str().unwrap(),
            "--allow-mode-skew",
        ],
    );
    assert_eq!(o.status.code(), Some(1), "the run must stop");
    let j = report_json(&rep1);
    assert_eq!(j["partial"], true);
    assert!(
        j["error"].as_str().unwrap().contains("refused write"),
        "{}",
        j["error"]
    );
    assert_eq!(j["buckets"]["refresh"]["ids"], serde_json::json!([a]));
    assert_eq!(j["claims"], 1, "only the committed batch's outcomes");
    let recs1 =
        read_truth_records(std::io::BufReader::new(std::fs::File::open(&r1).unwrap())).unwrap();
    assert_eq!(
        recs1.iter().map(|r| r.claim_id).collect::<Vec<_>>(),
        vec![a]
    );
    assert_ne!(truth_of(&pool, a).await.to_bits(), ta.to_bits());
    assert_eq!(truth_of(&pool, b).await.to_bits(), tb.to_bits());

    // A complete run says so.
    sqlx::query("DROP TRIGGER refresh_test_refuse ON claims")
        .execute(&pool)
        .await
        .unwrap();
    let r2 = dir.join("R2.jsonl");
    let rep2 = dir.join("apply-2.json");
    let o = run_bin(
        &dir,
        &url,
        &[
            "--waves",
            w,
            "--apply",
            "--batch",
            "1",
            "--record",
            r2.to_str().unwrap(),
            "--report",
            rep2.to_str().unwrap(),
            "--allow-mode-skew",
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let j = report_json(&rep2);
    assert_eq!(j["partial"], false);
    assert!(j["error"].is_null());
    assert_eq!(j["buckets"]["refresh"]["ids"], serde_json::json!([b]));

    // The restore of both records (last first: b, then a), stopped at a.
    let r3 = dir.join("R3.jsonl");
    let mut both = std::fs::read(&r1).unwrap();
    both.extend(std::fs::read(&r2).unwrap());
    std::fs::write(&r3, both).unwrap();
    refuse_truth_writes_to(&pool, a).await;
    let rep3 = dir.join("restore.json");
    let o = run_bin(
        &dir,
        &url,
        &[
            "--restore",
            r3.to_str().unwrap(),
            "--batch",
            "1",
            "--report",
            rep3.to_str().unwrap(),
            "--allow-mode-skew",
        ],
    );
    assert_eq!(o.status.code(), Some(1), "the restore must stop");
    let j = report_json(&rep3);
    assert_eq!(j["partial"], true);
    assert_eq!(j["buckets"]["restored"]["ids"], serde_json::json!([b]));
    assert_eq!(truth_of(&pool, b).await.to_bits(), tb.to_bits());
    assert_ne!(truth_of(&pool, a).await.to_bits(), ta.to_bits());
    let _ = std::fs::remove_dir_all(&dir);
}
