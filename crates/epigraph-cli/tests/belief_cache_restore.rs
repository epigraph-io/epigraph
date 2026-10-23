//! Belief-cache snapshot and compare-and-swap restore (SPEC §10.8, plan row
//! PR-C1).
//!
//! The properties pinned here:
//!
//! 1. A restore never undoes a write that landed after the wave. A claim whose
//!    cache differs from what the wave wrote in ANY one cache column is left
//!    exactly as the later write left it, and is reported
//!    `superseded_since_wave`; its untouched neighbours in the same batch are
//!    restored.
//! 2. A restore is idempotent: a second run writes no row (the tuple version
//!    `xmin` is unchanged) and reports every claim as already restored, not as
//!    superseded.
//! 3. NULL → value → restore is exact, bit for bit, through the wave FILE
//!    (the format the writing run and the restore share), including a column
//!    that is NULL in what the wave wrote.
//! 4. The downstream list holds every edge whose SOURCE is a wave claim and
//!    which was created, or had its edge-factor BBA written, after the wave
//!    started (reaching back a slack for transactions open across the stamp).
//!
//! plus the snapshot: every current claim exactly once across page
//! boundaries, bit-exact, and the chaining rule for a claim a wave file
//! records twice.
//!
//! Every test drives the wave through `write_wave_record` → `read_wave`, so a
//! lossy file format fails the CAS here rather than in an operator's restore.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use rand::{Rng, SeedableRng};
use sqlx::PgPool;
use uuid::Uuid;

use epigraph_cli::belief_cache::{
    downstream_edges, plan_restore, read_cache_columns, read_snapshot, read_wave, restore_wave,
    write_snapshot, write_wave_record, CacheColumns, RestoreOptions, SnapshotOptions, WaveRecord,
};

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'belief-cache-restore-test', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, description, hypotheses) \
         VALUES ('belief_cache_restore_' || gen_random_uuid()::text, 'test binary frame', ARRAY['TRUE', 'FALSE']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed frame")
}

async fn seed_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let content = format!("belief cache restore claim {}", Uuid::new_v4());
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

/// Stand-in for any cache writer (a wave, or a later organic write).
async fn set_cache(pool: &PgPool, id: Uuid, c: &CacheColumns) {
    let n = sqlx::query(
        "UPDATE claims SET belief = $2, plausibility = $3, pignistic_prob = $4, \
                mass_on_empty = $5, mass_on_missing = $6, belief_frame_id = $7, \
                classification = $8 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(c.belief)
    .bind(c.plausibility)
    .bind(c.pignistic_prob)
    .bind(c.mass_on_empty)
    .bind(c.mass_on_missing)
    .bind(c.belief_frame_id)
    .bind(c.classification.as_deref())
    .execute(pool)
    .await
    .expect("set cache")
    .rows_affected();
    assert_eq!(n, 1, "set_cache wrote its claim");
}

async fn cache_of(pool: &PgPool, id: Uuid) -> CacheColumns {
    read_cache_columns(pool, &[id])
        .await
        .expect("read cache")
        .remove(&id)
        .expect("claim exists")
}

async fn xmin(pool: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT xmin::text::bigint FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("xmin")
}

/// A random interval with ~17 significant digits in every float: the class of
/// value a lossy decimal parse gets wrong by one ULP.
fn random_cache(rng: &mut impl Rng, frame: Option<Uuid>, class: Option<&str>) -> CacheColumns {
    let a: f64 = rng.gen();
    let b: f64 = rng.gen();
    let (bel, pl) = if a <= b { (a, b) } else { (b, a) };
    CacheColumns {
        belief: Some(bel),
        plausibility: Some(pl),
        pignistic_prob: Some(bel + (pl - bel) * rng.gen::<f64>()),
        mass_on_empty: Some(rng.gen::<f64>() * 0.1),
        mass_on_missing: Some(rng.gen::<f64>() * 0.1),
        belief_frame_id: frame,
        classification: class.map(str::to_string),
    }
}

fn float_bits(c: &CacheColumns) -> [Option<u64>; 5] {
    [
        c.belief.map(f64::to_bits),
        c.plausibility.map(f64::to_bits),
        c.pignistic_prob.map(f64::to_bits),
        c.mass_on_empty.map(f64::to_bits),
        c.mass_on_missing.map(f64::to_bits),
    ]
}

/// Simulate a writing wave over `ids`: record `before`, write `new_cache(i)`,
/// record `written`, all stamped `at`. The records are returned AFTER a trip
/// through the wave file format.
async fn run_wave(
    pool: &PgPool,
    ids: &[Uuid],
    at: DateTime<Utc>,
    mut new_cache: impl FnMut(usize) -> CacheColumns,
) -> Vec<WaveRecord> {
    let mut file = Vec::new();
    for (i, &id) in ids.iter().enumerate() {
        let before = cache_of(pool, id).await;
        set_cache(pool, id, &new_cache(i)).await;
        let written = cache_of(pool, id).await;
        write_wave_record(
            &mut file,
            &WaveRecord {
                claim_id: id,
                before,
                written,
                wave: "test-wave".to_string(),
                at,
            },
        )
        .expect("write wave record");
    }
    read_wave(file.as_slice()).expect("read wave file back")
}

async fn db_now(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT now()")
        .fetch_one(pool)
        .await
        .expect("now")
}

fn opts(batch_size: usize) -> RestoreOptions {
    RestoreOptions {
        batch_size,
        dry_run: false,
    }
}

fn set_of(ids: &[Uuid]) -> HashSet<Uuid> {
    ids.iter().copied().collect()
}

// ---------------------------------------------------------------------------
// (1) a later legitimate write is never undone
// ---------------------------------------------------------------------------

/// Seven claims each get a later write that differs from the wave's in exactly
/// ONE cache column (one claim per column), so a CAS that forgets any column
/// overwrites that claim. Two control claims in the same batches are untouched
/// after the wave and must be restored.
#[sqlx::test(migrations = "../../migrations")]
async fn a_restore_never_undoes_a_later_write_in_any_cache_column(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let frame = seed_frame(&pool).await;
    let other_frame = seed_frame(&pool).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(11);

    let mut ids = Vec::new();
    let mut befores = HashMap::new();
    for _ in 0..9 {
        let id = seed_claim(&pool, agent).await;
        let before = random_cache(&mut rng, Some(frame), Some("not_enough_info"));
        set_cache(&pool, id, &before).await;
        befores.insert(id, cache_of(&pool, id).await);
        ids.push(id);
    }

    let at = db_now(&pool).await;
    let wave_values: Vec<CacheColumns> = (0..ids.len())
        .map(|_| random_cache(&mut rng, Some(frame), Some("supported")))
        .collect();
    let records = run_wave(&pool, &ids, at, |i| wave_values[i].clone()).await;

    // Later writes: claim k changes only column k.
    let mut later = HashMap::new();
    for (k, &id) in ids.iter().enumerate().take(7) {
        let mut c = cache_of(&pool, id).await;
        match k {
            0 => c.belief = Some(c.belief.unwrap() * 0.5),
            1 => c.plausibility = Some((c.plausibility.unwrap() + 1.0) / 2.0),
            2 => {
                let (b, p) = (c.belief.unwrap(), c.plausibility.unwrap());
                let mid = (b + p) / 2.0;
                c.pignistic_prob = Some(if c.pignistic_prob == Some(mid) {
                    b
                } else {
                    mid
                });
            }
            3 => c.mass_on_empty = Some(c.mass_on_empty.unwrap() + 0.5),
            4 => c.mass_on_missing = Some(c.mass_on_missing.unwrap() + 0.5),
            5 => c.belief_frame_id = Some(other_frame),
            6 => c.classification = Some("contradicted".to_string()),
            _ => unreachable!(),
        }
        set_cache(&pool, id, &c).await;
        later.insert(id, cache_of(&pool, id).await);
    }

    let plan = plan_restore(&records, None);
    let report = restore_wave(&pool, &plan, &opts(2)).await.expect("restore");

    for (k, &id) in ids.iter().enumerate() {
        let now = cache_of(&pool, id).await;
        if k < 7 {
            assert_eq!(
                now, later[&id],
                "claim with a later write to cache column #{k} was overwritten by the restore"
            );
        } else {
            assert_eq!(
                now, befores[&id],
                "untouched control claim {k} was not restored"
            );
        }
    }
    assert_eq!(
        set_of(&report.superseded_since_wave),
        set_of(&ids[..7]),
        "every claim written after the wave, and only those, is reported superseded_since_wave"
    );
    assert_eq!(set_of(&report.restored), set_of(&ids[7..]));
}

// ---------------------------------------------------------------------------
// (2) idempotence
// ---------------------------------------------------------------------------

/// Idempotence, and its edge case: claim 0's wave write left its cache exactly
/// as it was (`written` == `before`), which happens whenever a recompute lands
/// on the value already cached. A restore must not rewrite such a row on ANY
/// run: there is nothing to undo.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_restore_writes_no_row_and_reports_already_restored(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let frame = seed_frame(&pool).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(22);

    let mut ids = Vec::new();
    let mut befores = HashMap::new();
    for _ in 0..5 {
        let id = seed_claim(&pool, agent).await;
        set_cache(&pool, id, &random_cache(&mut rng, Some(frame), None)).await;
        befores.insert(id, cache_of(&pool, id).await);
        ids.push(id);
    }
    let unchanged = ids[0];
    let at = db_now(&pool).await;
    let records = run_wave(&pool, &ids, at, |i| {
        if i == 0 {
            befores[&unchanged].clone()
        } else {
            random_cache(&mut rng, Some(frame), Some("supported"))
        }
    })
    .await;
    assert_eq!(
        records[0].before, records[0].written,
        "fixture: a no-op write"
    );
    let plan = plan_restore(&records, None);
    let unchanged_version = xmin(&pool, unchanged).await;

    let first = restore_wave(&pool, &plan, &opts(2)).await.expect("first");
    assert_eq!(
        set_of(&first.restored),
        set_of(&ids[1..]),
        "first run restores every claim the wave changed"
    );
    assert_eq!(first.already_restored, vec![unchanged]);
    assert_eq!(
        xmin(&pool, unchanged).await,
        unchanged_version,
        "a claim the wave did not change was rewritten"
    );

    let mut versions = HashMap::new();
    for &id in &ids {
        versions.insert(id, xmin(&pool, id).await);
    }

    let second = restore_wave(&pool, &plan, &opts(2)).await.expect("second");
    assert!(
        second.restored.is_empty(),
        "second run restored {} claims again",
        second.restored.len()
    );
    assert!(
        second.superseded_since_wave.is_empty(),
        "second run mistook {} already-restored claims for superseded ones",
        second.superseded_since_wave.len()
    );
    assert_eq!(set_of(&second.already_restored), set_of(&ids));
    for &id in &ids {
        assert_eq!(
            xmin(&pool, id).await,
            versions[&id],
            "second run rewrote a row (new tuple version)"
        );
        assert_eq!(cache_of(&pool, id).await, befores[&id]);
    }
}

/// A write that is in flight when the restore reaches its row: the restore's
/// UPDATE waits on the row lock, and when the writer commits it re-checks its
/// compare-and-swap against the NEW row (READ COMMITTED), so the live write
/// survives and is reported `superseded_since_wave`, and the rest of the batch
/// is restored. Under REPEATABLE READ the batch would abort instead; with the
/// check moved out of the UPDATE the write would be overwritten.
#[sqlx::test(migrations = "../../migrations")]
async fn a_write_committing_during_the_restore_is_never_overwritten(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let frame = seed_frame(&pool).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(99);

    let mut ids = Vec::new();
    let mut befores = HashMap::new();
    for _ in 0..3 {
        let id = seed_claim(&pool, agent).await;
        set_cache(&pool, id, &random_cache(&mut rng, Some(frame), None)).await;
        befores.insert(id, cache_of(&pool, id).await);
        ids.push(id);
    }
    let at = db_now(&pool).await;
    let records = run_wave(&pool, &ids, at, |_| {
        random_cache(&mut rng, Some(frame), Some("supported"))
    })
    .await;
    let plan = plan_restore(&records, None);
    let contested = ids[1];

    // Writer A: changes the contested claim and holds its transaction open.
    let mut a = pool.begin().await.expect("writer A");
    sqlx::query("UPDATE claims SET belief = 0.123456789 WHERE id = $1")
        .bind(contested)
        .execute(&mut *a)
        .await
        .expect("A's write");

    let restore = tokio::spawn({
        let pool = pool.clone();
        async move { restore_wave(&pool, &plan, &opts(10)).await }
    });

    // Wait until the restore is blocked on A's row lock.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
              WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(&pool)
        .await
        .expect("pg_stat_activity");
        if waiting > 0 {
            break;
        }
        assert!(
            !restore.is_finished(),
            "the restore finished without waiting on the in-flight write"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "the restore never blocked on the in-flight write"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    a.commit().await.expect("A commits");
    let a_value = cache_of(&pool, contested).await;
    assert_eq!(a_value.belief, Some(0.123456789), "fixture: A committed");

    let report = restore
        .await
        .expect("restore task")
        .expect("a concurrent write must not abort the restore");
    assert_eq!(report.superseded_since_wave, vec![contested]);
    assert_eq!(
        cache_of(&pool, contested).await,
        a_value,
        "the write that committed during the restore was overwritten"
    );
    for id in [ids[0], ids[2]] {
        assert_eq!(cache_of(&pool, id).await, befores[&id]);
    }
    assert_eq!(set_of(&report.restored), set_of(&[ids[0], ids[2]]));
}

/// A frame deleted after the wave (the operator's `delete-frames` verb exists)
/// leaves a `before` whose `belief_frame_id` the foreign key refuses. That one
/// claim is skipped and reported; the claims sharing its transaction are
/// still restored rather than the whole batch aborting.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deleted_before_frame_skips_only_its_claim(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let doomed = seed_frame(&pool).await;
    let kept = seed_frame(&pool).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(77);

    let orphaned = seed_claim(&pool, agent).await;
    let neighbour = seed_claim(&pool, agent).await;
    set_cache(&pool, orphaned, &random_cache(&mut rng, Some(doomed), None)).await;
    set_cache(&pool, neighbour, &random_cache(&mut rng, Some(kept), None)).await;
    let neighbour_before = cache_of(&pool, neighbour).await;

    let at = db_now(&pool).await;
    let records = run_wave(&pool, &[orphaned, neighbour], at, |_| {
        random_cache(&mut rng, Some(kept), Some("supported"))
    })
    .await;
    let orphaned_written = cache_of(&pool, orphaned).await;
    sqlx::query("DELETE FROM frames WHERE id = $1")
        .bind(doomed)
        .execute(&pool)
        .await
        .expect("delete the before frame");

    let report = restore_wave(&pool, &plan_restore(&records, None), &opts(10))
        .await
        .expect("a deleted frame must not abort the batch");
    assert_eq!(report.frame_gone, vec![orphaned]);
    assert_eq!(report.restored, vec![neighbour]);
    assert_eq!(cache_of(&pool, orphaned).await, orphaned_written);
    assert_eq!(cache_of(&pool, neighbour).await, neighbour_before);
}

/// A wave claim that no longer exists (deleted since the wave), or never did
/// (a record for an unknown id), is reported `missing` and nowhere else. The
/// unknown id's `before` is all-NULL on purpose: against the LEFT JOIN's NULL
/// row it compares equal, so a classifier that tested "already holds
/// `before`" ahead of "exists" would call it `already_restored`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_wave_claim_that_no_longer_exists_is_reported_missing(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let frame = seed_frame(&pool).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(111);

    let deleted = seed_claim(&pool, agent).await;
    let kept = seed_claim(&pool, agent).await;
    for id in [deleted, kept] {
        set_cache(&pool, id, &random_cache(&mut rng, Some(frame), None)).await;
    }
    let kept_before = cache_of(&pool, kept).await;
    let at = db_now(&pool).await;
    let mut records = run_wave(&pool, &[deleted, kept], at, |_| {
        random_cache(&mut rng, Some(frame), Some("supported"))
    })
    .await;
    let ghost = Uuid::new_v4();
    let mut file = Vec::new();
    write_wave_record(
        &mut file,
        &WaveRecord {
            claim_id: ghost,
            before: CacheColumns {
                belief: None,
                plausibility: None,
                pignistic_prob: None,
                mass_on_empty: None,
                mass_on_missing: None,
                belief_frame_id: None,
                classification: None,
            },
            written: random_cache(&mut rng, Some(frame), None),
            wave: "test-wave".to_string(),
            at,
        },
    )
    .expect("write ghost record");
    records.extend(read_wave(file.as_slice()).expect("read ghost record"));
    sqlx::query("DELETE FROM claims WHERE id = $1")
        .bind(deleted)
        .execute(&pool)
        .await
        .expect("delete a wave claim");

    let report = restore_wave(&pool, &plan_restore(&records, None), &opts(10))
        .await
        .expect("restore");
    assert_eq!(set_of(&report.missing), set_of(&[deleted, ghost]));
    assert_eq!(report.restored, vec![kept]);
    assert_eq!(cache_of(&pool, kept).await, kept_before);
    assert_partition(&report, &[deleted, kept, ghost]);
}

// ---------------------------------------------------------------------------
// (3) NULL -> value -> restore is exact
// ---------------------------------------------------------------------------

/// Claim 0 starts with every cache column NULL (including `mass_on_empty`,
/// whose column default is 0.0). Every wave write leaves `classification`
/// NULL, so the CAS must treat NULL as equal to NULL.
#[sqlx::test(migrations = "../../migrations")]
async fn null_to_value_to_restore_round_trips_bit_for_bit(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let frame = seed_frame(&pool).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(33);

    let null_cache = CacheColumns {
        belief: None,
        plausibility: None,
        pignistic_prob: None,
        mass_on_empty: None,
        mass_on_missing: None,
        belief_frame_id: None,
        classification: None,
    };
    let mut ids = Vec::new();
    let mut befores = HashMap::new();
    for i in 0..12 {
        let id = seed_claim(&pool, agent).await;
        let before = if i == 0 {
            null_cache.clone()
        } else {
            random_cache(&mut rng, Some(frame), Some("not_enough_info"))
        };
        set_cache(&pool, id, &before).await;
        befores.insert(id, cache_of(&pool, id).await);
        ids.push(id);
    }
    assert_eq!(
        befores[&ids[0]], null_cache,
        "claim 0 really starts all-NULL"
    );

    let at = db_now(&pool).await;
    let records = run_wave(&pool, &ids, at, |_| {
        random_cache(&mut rng, Some(frame), None)
    })
    .await;
    assert!(
        records.iter().all(|r| r.written.classification.is_none()),
        "fixture: the wave leaves classification NULL"
    );

    let report = restore_wave(&pool, &plan_restore(&records, None), &opts(5))
        .await
        .expect("restore");
    assert_eq!(
        set_of(&report.restored),
        set_of(&ids),
        "every claim restored"
    );

    for &id in &ids {
        let now = cache_of(&pool, id).await;
        let want = &befores[&id];
        assert_eq!(
            float_bits(&now),
            float_bits(want),
            "restored floats differ from the pre-wave values in their bits"
        );
        assert_eq!(now.belief_frame_id, want.belief_frame_id);
        assert_eq!(now.classification, want.classification);
    }
}

/// The wave file alone: every f64 the cache can hold survives
/// `write_wave_record` → `read_wave` with the same bits. A restore's CAS
/// compares against these values with `IS NOT DISTINCT FROM`, so one ULP of
/// parse error reads as "a later write landed" and the claim is never restored.
#[test]
fn the_wave_file_preserves_every_float_bit() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(44);
    let mut file = Vec::new();
    let mut sent = Vec::new();
    for _ in 0..4000 {
        let rec = WaveRecord {
            claim_id: Uuid::new_v4(),
            before: random_cache(&mut rng, None, None),
            written: random_cache(&mut rng, Some(Uuid::new_v4()), Some("supported")),
            wave: "w".to_string(),
            at: Utc::now(),
        };
        write_wave_record(&mut file, &rec).expect("write");
        sent.push(rec);
    }
    let got = read_wave(file.as_slice()).expect("read");
    assert_eq!(got.len(), sent.len());
    let lossy = sent
        .iter()
        .zip(&got)
        .filter(|(s, g)| {
            float_bits(&s.before) != float_bits(&g.before)
                || float_bits(&s.written) != float_bits(&g.written)
        })
        .count();
    assert_eq!(
        lossy,
        0,
        "{lossy} of {} records changed a float bit",
        sent.len()
    );
}

/// A non-finite value has no JSON number; writing it must fail rather than
/// silently become `null` (which a restore would then write back as NULL).
#[test]
fn a_non_finite_cache_value_is_refused_by_the_wave_writer() {
    let mut c = CacheColumns {
        belief: Some(0.25),
        plausibility: Some(0.75),
        pignistic_prob: Some(0.5),
        mass_on_empty: Some(0.0),
        mass_on_missing: Some(0.0),
        belief_frame_id: None,
        classification: None,
    };
    c.pignistic_prob = Some(f64::NAN);
    let rec = WaveRecord {
        claim_id: Uuid::new_v4(),
        before: c.clone(),
        written: c,
        wave: "w".to_string(),
        at: Utc::now(),
    };
    let mut file = Vec::new();
    assert!(write_wave_record(&mut file, &rec).is_err());
}

// ---------------------------------------------------------------------------
// (4) downstream edges
// ---------------------------------------------------------------------------

async fn seed_edge(pool: &PgPool, src: Uuid, tgt: Uuid, at: DateTime<Utc>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, created_at) \
         VALUES ($1, 'claim', $2, 'claim', 'supports', $3) RETURNING id",
    )
    .bind(src)
    .bind(tgt)
    .bind(at)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

/// An edge-factor BBA on `edge`'s target, keyed on the edge (the shape
/// `auto_wire_ds_for_edge` stores: `perspective_id = edge`, `claim_id =
/// target`), written at `at`. This is the moment an edge freezes its source's
/// value, and it need not be the edge's own `created_at`: an edge written while
/// its source was factorless is wired later, on a dedup re-hit or by
/// `backfill_factors`.
async fn seed_edge_factor(
    pool: &PgPool,
    edge: Uuid,
    target: Uuid,
    agent: Uuid,
    frame: Uuid,
    at: DateTime<Utc>,
) {
    epigraph_db::PerspectiveRepository::ensure_edge_perspective(pool, edge, Some(agent))
        .await
        .expect("edge perspective");
    epigraph_db::MassFunctionRepository::store_with_perspective(
        pool,
        target,
        frame,
        Some(agent),
        Some(edge),
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("edge_factor"),
        Some(0.7),
        None,
        "cross",
        None,
    )
    .await
    .expect("edge-factor BBA");
    sqlx::query("UPDATE mass_functions SET created_at = $2 WHERE perspective_id = $1")
        .bind(edge)
        .bind(at)
        .execute(pool)
        .await
        .expect("date the BBA");
}

/// The downstream list must cover EVERY edge-factor BBA that may have frozen a
/// wave value, and over-listing only costs an idempotent re-wire, so it errs
/// wide:
///
/// * the cutoff is the WAVE's earliest record time, not each claim's own, and
///   reaches back a slack before it: `edges.created_at` (and
///   `mass_functions.created_at`) are the writing transaction's START time,
///   so an edge whose transaction began just before the stamp can still have
///   read the wave's value;
/// * an edge older than the wave is listed when its edge-factor BBA was
///   written after the wave (the factorless wake-up path).
#[sqlx::test(migrations = "../../migrations")]
async fn downstream_lists_exactly_the_edges_a_wave_claim_sourced_after_its_write(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let frame = seed_frame(&pool).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(55);

    let a = seed_claim(&pool, agent).await;
    let b = seed_claim(&pool, agent).await;
    // Written twice by the wave with another write in between: held back from
    // the restore (broken chain), but still a wave claim whose value the wave
    // wrote, so its post-wave edges froze a wave value too.
    let c = seed_claim(&pool, agent).await;
    let outside = seed_claim(&pool, agent).await;
    let mut targets = Vec::new();
    for _ in 0..12 {
        targets.push(seed_claim(&pool, agent).await);
    }

    let t0: DateTime<Utc> = "2031-03-01T12:00:00Z".parse().unwrap();
    let h = Duration::hours(1);
    let long_before = t0 - Duration::days(30);
    let mut rec_a = run_wave(&pool, &[a], t0, |_| {
        random_cache(&mut rng, Some(frame), None)
    })
    .await;
    let mut rec_b = run_wave(&pool, &[b], t0 + h * 2, |_| {
        random_cache(&mut rng, Some(frame), None)
    })
    .await;
    rec_a.append(&mut rec_b);
    let mut rec_c1 = run_wave(&pool, &[c], t0, |_| {
        random_cache(&mut rng, Some(frame), None)
    })
    .await;
    set_cache(&pool, c, &random_cache(&mut rng, Some(frame), None)).await;
    let mut rec_c2 = run_wave(&pool, &[c], t0 + h * 4, |_| {
        random_cache(&mut rng, Some(frame), None)
    })
    .await;
    rec_a.append(&mut rec_c1);
    rec_a.append(&mut rec_c2);

    // Listed.
    let after_a = seed_edge(&pool, a, targets[0], t0 + h).await;
    let at_the_stamp = seed_edge(&pool, a, targets[7], t0).await;
    // Its transaction began a second before the wave's stamp.
    let just_before_the_stamp = seed_edge(&pool, a, targets[8], t0 - Duration::seconds(1)).await;
    // After the wave started, before b's own record: with one wave-level cutoff
    // this is inside the wave, and b's value may already have been the wave's
    // when the edge was wired after its commit.
    let between_a_and_b = seed_edge(&pool, b, targets[4], t0 + h).await;
    let after_b = seed_edge(&pool, b, targets[5], t0 + h * 3).await;
    // After c's FIRST wave write, before its second.
    let after_c = seed_edge(&pool, c, targets[6], t0 + h).await;
    // Created long before the wave while `a` had no value, wired after it.
    let woken_after_the_wave = seed_edge(&pool, a, targets[9], long_before).await;
    seed_edge_factor(
        &pool,
        woken_after_the_wave,
        targets[9],
        agent,
        frame,
        t0 + h,
    )
    .await;

    // Not listed.
    let _before_the_wave = seed_edge(&pool, a, targets[1], long_before).await;
    let wired_before_the_wave = seed_edge(&pool, a, targets[10], long_before).await;
    seed_edge_factor(
        &pool,
        wired_before_the_wave,
        targets[10],
        agent,
        frame,
        long_before,
    )
    .await;
    let _not_in_wave = seed_edge(&pool, outside, targets[2], t0 + h).await;
    let outside_woken = seed_edge(&pool, outside, targets[11], long_before).await;
    seed_edge_factor(&pool, outside_woken, targets[11], agent, frame, t0 + h).await;
    let _into_a = seed_edge(&pool, targets[3], a, t0 + h).await;

    // Closed after the wave: its BBA may outlive the close, so it is listed.
    let closed_at = t0 + h * 2;
    sqlx::query("UPDATE edges SET valid_to = $2 WHERE id = $1")
        .bind(after_a)
        .bind(closed_at)
        .execute(&pool)
        .await
        .expect("close an edge");

    let plan = plan_restore(&rec_a, None);
    assert_eq!(plan.broken_chain, vec![c], "fixture: c is held back");
    let listed = downstream_edges(&pool, &plan).await.expect("downstream");
    let got: HashSet<Uuid> = listed.iter().map(|e| e.edge_id).collect();
    assert_eq!(
        got,
        set_of(&[
            after_a,
            at_the_stamp,
            just_before_the_stamp,
            between_a_and_b,
            after_b,
            after_c,
            woken_after_the_wave,
        ])
    );
    assert_eq!(listed.len(), got.len(), "no edge listed twice");
    let closed = listed.iter().find(|e| e.edge_id == after_a).unwrap();
    assert_eq!(
        closed.valid_to,
        Some(closed_at),
        "a closed edge carries valid_to"
    );
    for e in &listed {
        assert!(e.source_id == a || e.source_id == b || e.source_id == c);
    }
}

// ---------------------------------------------------------------------------
// the snapshot
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn the_snapshot_holds_every_current_claim_once_across_pages_bit_for_bit(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let frame = seed_frame(&pool).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(66);

    let mut seeded = HashMap::new();
    for i in 0..7 {
        let id = seed_claim(&pool, agent).await;
        if i % 3 != 0 {
            set_cache(
                &pool,
                id,
                &random_cache(&mut rng, Some(frame), Some("supported")),
            )
            .await;
        }
        seeded.insert(id, cache_of(&pool, id).await);
    }
    let superseded = seed_claim(&pool, agent).await;
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(superseded)
        .execute(&pool)
        .await
        .expect("mark superseded");

    let current_total: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE is_current")
        .fetch_one(&pool)
        .await
        .expect("count");

    let mut file = Vec::new();
    let summary = write_snapshot(
        &pool,
        &mut file,
        &SnapshotOptions {
            page_size: 2,
            include_superseded: false,
        },
    )
    .await
    .expect("snapshot");
    let rows = read_snapshot(file.as_slice()).expect("read snapshot");

    assert_eq!(
        rows.len() as i64,
        current_total,
        "one line per current claim"
    );
    assert_eq!(summary.rows as usize, rows.len());
    let ids: HashSet<Uuid> = rows.iter().map(|r| r.claim_id).collect();
    assert_eq!(ids.len(), rows.len(), "no claim appears twice");
    assert!(
        !ids.contains(&superseded),
        "a superseded claim is not current"
    );
    for r in &rows {
        if let Some(want) = seeded.get(&r.claim_id) {
            let got = r.cache();
            assert_eq!(float_bits(&got), float_bits(want));
            assert_eq!(got.belief_frame_id, want.belief_frame_id);
            assert_eq!(got.classification, want.classification);
        }
    }
    assert!(
        seeded.keys().all(|id| ids.contains(id)),
        "every seeded current claim is in the snapshot"
    );

    let mut all = Vec::new();
    write_snapshot(
        &pool,
        &mut all,
        &SnapshotOptions {
            page_size: 3,
            include_superseded: true,
        },
    )
    .await
    .expect("snapshot all");
    let all_ids: HashSet<Uuid> = read_snapshot(all.as_slice())
        .expect("read")
        .iter()
        .map(|r| r.claim_id)
        .collect();
    assert!(all_ids.contains(&superseded));
}

/// A sink that, on the snapshot's FIRST write, commits an update to a
/// later-id claim and inserts a new last-id claim through a separate
/// connection (its own thread and runtime), as an organic writer would while a
/// long export runs.
struct WriteMidExport {
    buf: Vec<u8>,
    fired: bool,
    opts: sqlx::postgres::PgConnectOptions,
    update: Uuid,
    insert: Uuid,
    agent: Uuid,
}

impl std::io::Write for WriteMidExport {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if !self.fired {
            self.fired = true;
            let (opts, update, insert, agent) =
                (self.opts.clone(), self.update, self.insert, self.agent);
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime")
                    .block_on(async move {
                        use sqlx::Connection;
                        let mut c = sqlx::PgConnection::connect_with(&opts)
                            .await
                            .expect("second connection");
                        sqlx::query("UPDATE claims SET belief = 0.987654321 WHERE id = $1")
                            .bind(update)
                            .execute(&mut c)
                            .await
                            .expect("mid-export update");
                        sqlx::query(
                            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id) \
                             VALUES ($1, $2, sha256($2::bytea), 0.5, $3)",
                        )
                        .bind(insert)
                        .bind(format!("mid-export claim {insert}"))
                        .bind(agent)
                        .execute(&mut c)
                        .await
                        .expect("mid-export insert");
                    });
            })
            .join()
            .expect("mid-export writer");
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// S0 is the baseline every drift report is measured from, so it must be ONE
/// database state: a write that commits while the export runs is in no page,
/// whichever page its row falls on. Keyset paging alone guarantees no row is
/// skipped or repeated; only the single REPEATABLE READ transaction makes the
/// pages agree on WHEN.
#[sqlx::test(migrations = "../../migrations")]
async fn the_snapshot_is_one_point_in_time_while_writes_land(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let first: Uuid = "00000000-0000-4000-8000-000000000001".parse().unwrap();
    let later: Uuid = "ffffffff-ffff-4fff-bfff-fffffffffffe".parse().unwrap();
    let inserted: Uuid = "ffffffff-ffff-4fff-bfff-ffffffffffff".parse().unwrap();
    for id in [first, later] {
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, belief) \
             VALUES ($1, $2, sha256($2::bytea), 0.5, $3, 0.25)",
        )
        .bind(id)
        .bind(format!("snapshot point-in-time claim {id}"))
        .bind(agent)
        .execute(&pool)
        .await
        .expect("seed claim");
    }

    let mut sink = WriteMidExport {
        buf: Vec::new(),
        fired: false,
        opts: (*pool.connect_options()).clone(),
        update: later,
        insert: inserted,
        agent,
    };
    let summary = write_snapshot(
        &pool,
        &mut sink,
        &SnapshotOptions {
            page_size: 1,
            include_superseded: false,
        },
    )
    .await
    .expect("snapshot");
    assert!(sink.fired, "fixture: the mid-export writer ran");
    assert_eq!(
        cache_of(&pool, later).await.belief,
        Some(0.987654321),
        "fixture: the mid-export update committed"
    );

    let rows = read_snapshot(sink.buf.as_slice()).expect("read snapshot");
    let row = rows
        .iter()
        .find(|r| r.claim_id == later)
        .expect("the later-id claim is in the snapshot");
    assert_eq!(
        row.belief,
        Some(0.25),
        "a later page saw a write that committed after the export began"
    );
    assert!(
        rows.iter().all(|r| r.claim_id != inserted),
        "a claim inserted after the export began is in it"
    );
    let updated_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT updated_at FROM claims WHERE id = $1")
            .bind(later)
            .fetch_one(&pool)
            .await
            .expect("updated_at");
    assert!(
        summary.snapshot_at < updated_at,
        "snapshot_at must predate the write it excluded"
    );
}

// ---------------------------------------------------------------------------
// the plan: a claim recorded twice, and the --claims filter
// ---------------------------------------------------------------------------

fn cache_at(v: f64) -> CacheColumns {
    CacheColumns {
        belief: Some(v),
        plausibility: Some(v),
        pignistic_prob: Some(v),
        mass_on_empty: Some(0.0),
        mass_on_missing: Some(0.0),
        belief_frame_id: None,
        classification: None,
    }
}

fn rec(id: Uuid, before: f64, written: f64, at: DateTime<Utc>) -> WaveRecord {
    WaveRecord {
        claim_id: id,
        before: cache_at(before),
        written: cache_at(written),
        wave: "w".to_string(),
        at,
    }
}

/// A wave re-run with the same file appends a second record for a claim.
/// Records that chain (each `before` is the previous `written`, in time
/// order) restore the FIRST `before` and compare against the LAST `written`.
/// Records that do not chain all the way back restore the `before` of the
/// trailing chained run, the newest value the wave did not write, marked
/// `partial`.
#[test]
fn a_claim_recorded_twice_chains_or_restores_past_the_gap() {
    let t: DateTime<Utc> = "2031-03-01T12:00:00Z".parse().unwrap();
    let m = Duration::minutes(1);
    let (chained, broken, single, wanted_absent) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let records = vec![
        rec(chained, 0.2, 0.25, t + m * 5),
        rec(broken, 0.3, 0.4, t),
        rec(single, 0.6, 0.7, t + m),
        rec(chained, 0.1, 0.2, t),
        // 0.4 -> 0.45 was someone else's write.
        rec(broken, 0.45, 0.5, t + m * 5),
        rec(broken, 0.5, 0.55, t + m * 10),
    ];

    let plan = plan_restore(&records, None);
    let by_id: HashMap<Uuid, _> = plan.entries.iter().map(|e| (e.claim_id, e)).collect();
    assert_eq!(plan.entries.len(), 3, "one entry per claim");
    let c = by_id[&chained];
    assert_eq!(c.before, cache_at(0.1));
    assert_eq!(c.written, cache_at(0.25));
    assert!(!c.partial);
    assert_eq!(by_id[&single].before, cache_at(0.6));
    assert!(!by_id[&single].partial);
    let b = by_id[&broken];
    assert_eq!(
        b.before,
        cache_at(0.45),
        "the trailing chained run's before"
    );
    assert_eq!(b.written, cache_at(0.55), "the last written");
    assert!(b.partial);
    assert_eq!(plan.broken_chain, vec![broken]);
    assert_eq!(
        set_of(&plan.sources),
        set_of(&[chained, broken, single]),
        "every wave claim is a downstream source"
    );
    assert_eq!(plan.sources.len(), 3, "each source once");
    assert_eq!(
        plan.wave_at,
        Some(t),
        "the earliest record time bounds the downstream list"
    );

    let only = set_of(&[single, wanted_absent]);
    let filtered = plan_restore(&records, Some(&only));
    assert_eq!(
        filtered
            .entries
            .iter()
            .map(|e| e.claim_id)
            .collect::<Vec<_>>(),
        vec![single]
    );
    assert_eq!(filtered.not_in_wave, vec![wanted_absent]);
    assert!(filtered.broken_chain.is_empty());
    assert_eq!(
        filtered.sources,
        vec![single],
        "only in-scope claims are sources"
    );
    assert_eq!(
        filtered.wave_at,
        Some(t + m),
        "the earliest IN-SCOPE record time"
    );
}

/// Two runs appended to one file chain in TIME order, whatever order their
/// lines are in: an operator who concatenates the second run's file before
/// the first's has not created an intervening write.
#[test]
fn records_chain_in_time_order_not_file_order() {
    let t: DateTime<Utc> = "2031-03-01T12:00:00Z".parse().unwrap();
    let id = Uuid::new_v4();
    let second_run = rec(id, 0.2, 0.3, t + Duration::hours(1));
    let first_run = rec(id, 0.1, 0.2, t);
    let plan = plan_restore(&[second_run, first_run], None);
    assert!(
        plan.broken_chain.is_empty(),
        "two runs that chain in time were read as an intervening write"
    );
    assert_eq!(plan.entries.len(), 1);
    assert_eq!(
        plan.entries[0].before,
        cache_at(0.1),
        "the first run's before"
    );
    assert_eq!(
        plan.entries[0].written,
        cache_at(0.3),
        "the last run's written"
    );
}

/// A broken chain: run 1 wrote X1, an organic write set Y, run 2 found Y and
/// wrote X2, and X2 is still current. The rollback target is Y, the newest
/// value the wave did not write; leaving X2 in place and calling the claim
/// superseded would keep the wave's value while telling the operator that a
/// later write had replaced it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_broken_chain_is_restored_to_the_intervening_write(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let frame = seed_frame(&pool).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(88);

    let k = seed_claim(&pool, agent).await;
    let neighbour = seed_claim(&pool, agent).await;
    set_cache(&pool, k, &random_cache(&mut rng, Some(frame), None)).await;
    set_cache(&pool, neighbour, &random_cache(&mut rng, Some(frame), None)).await;
    let neighbour_before = cache_of(&pool, neighbour).await;

    let t: DateTime<Utc> = "2031-03-01T12:00:00Z".parse().unwrap();
    let mut records = run_wave(&pool, &[k, neighbour], t, |_| {
        random_cache(&mut rng, Some(frame), Some("supported"))
    })
    .await;
    set_cache(&pool, k, &random_cache(&mut rng, Some(frame), None)).await;
    let intervening = cache_of(&pool, k).await;
    records.extend(
        run_wave(&pool, &[k], t + Duration::hours(2), |_| {
            random_cache(&mut rng, Some(frame), Some("supported"))
        })
        .await,
    );

    let report = restore_wave(&pool, &plan_restore(&records, None), &opts(10))
        .await
        .expect("restore");
    assert_eq!(
        cache_of(&pool, k).await,
        intervening,
        "the wave's last value was left in place (or the intervening write was erased)"
    );
    assert!(
        !report.superseded_since_wave.contains(&k),
        "a claim still holding the wave's value was reported superseded"
    );
    assert_eq!(cache_of(&pool, neighbour).await, neighbour_before);
    assert_eq!(report.restored, vec![neighbour]);
    assert_eq!(report.restored_partial, vec![k]);
    assert_partition(&report, &[k, neighbour]);
}

/// Every claim the restore considered is in exactly one outcome bucket.
fn assert_partition(report: &epigraph_cli::belief_cache::RestoreReport, considered: &[Uuid]) {
    let mut seen: HashMap<Uuid, Vec<&str>> = HashMap::new();
    for (name, ids) in report.buckets() {
        for &id in ids {
            seen.entry(id).or_default().push(name);
        }
    }
    for (id, names) in &seen {
        assert_eq!(names.len(), 1, "{id} reported in {names:?}");
    }
    assert_eq!(
        seen.keys().copied().collect::<HashSet<_>>(),
        set_of(considered),
        "the buckets hold exactly the claims considered"
    );
}
