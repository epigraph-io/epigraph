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
use epigraph_cli::truth_mirror::{
    apply, cas_refresh, dry_run, plan_candidates, read_truth_records, restore, write_truth_record,
    Bucket, Candidate, MirrorReport, RefreshOptions, TruthRecord,
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
    assert_eq!(r.waves, vec!["E-pass-1".to_string(), "L1".to_string()]);
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
    let records = wave(&pool, &[control, no_writer], "L1").await;
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
    let json = report.to_json(true, false, records.len());
    assert_eq!(json["buckets"]["refresh"]["count"], 2);
    assert_eq!(json["refresh"].as_array().unwrap().len(), 2);
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
/// and an API base nothing answers on (the writing runs pass the hidden
/// `--allow-mode-skew`).
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
