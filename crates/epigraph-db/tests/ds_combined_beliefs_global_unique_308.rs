//! Migration 308 (backlog 3adc219b): one stored `ds_combined_beliefs` row per
//! (frame, claim, scope_type, scope_id), the `global` scope (`scope_id IS
//! NULL`) included.
//!
//! 001's key was NULLS DISTINCT, so `ScopedBeliefRepository::upsert`'s
//! `ON CONFLICT (frame_id, claim_id, scope_type, scope_id) DO UPDATE` never
//! fired for a global row and every global write inserted another one.
//!
//! * `two_global_upserts_leave_one_row_holding_the_second_value`: the upsert
//!   replaces a global row in place;
//! * `duplicate_global_rows_collapse_to_the_newest_and_other_keys_stay`: on a
//!   database migrated to the head below 308 and seeded with the duplicates
//!   the old key let through, 308 keeps only the newest row of each key and
//!   touches no other key;
//! * `the_308_undo_restores_the_nulls_distinct_key`: the runbook puts 001's
//!   key back, and is idempotent.
//!
//! On the code before 308 the first two fail (two global rows; three
//! duplicates kept), and the third fails on the key's catalog flag.

#[path = "viewer_fixture.rs"]
mod fixture;

use sqlx::PgPool;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const KEY: &str = "ds_combined_beliefs_frame_id_claim_id_scope_type_scope_id_key";
const EPS: f64 = 1e-9;

/// The last migration below 308 in this tree (computed, so a migration
/// merged below 308 later is part of "below").
fn below() -> i64 {
    MIGRATOR
        .migrations
        .iter()
        .map(|m| m.version)
        .filter(|v| *v < 308)
        .max()
        .expect("migrations below 308")
}

fn up_to(max: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= max)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

/// Run `migrator` on one connection and reset it: 001's pg_dump header leaves
/// session-level SETs behind.
async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

async fn frame(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) \
         RETURNING id",
    )
    .bind(format!("m308-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed a frame")
}

async fn claim(pool: &PgPool, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    fixture::seed_public_claim(pool, agent, &format!("m308 {label}")).await
}

/// A stored scoped belief as a pre-308 writer left it, `age_s` seconds old.
async fn row(
    pool: &PgPool,
    frame: Uuid,
    claim: Uuid,
    scope: Option<Uuid>,
    belief: f64,
    age_s: f64,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO ds_combined_beliefs \
             (frame_id, claim_id, scope_type, scope_id, belief, plausibility, computed_at) \
         VALUES ($1, $2, CASE WHEN $3::uuid IS NULL THEN 'global' ELSE 'perspective' END, \
                 $3, $4, 1.0, now() - make_interval(secs => $5)) \
         RETURNING id",
    )
    .bind(frame)
    .bind(claim)
    .bind(scope)
    .bind(belief)
    .bind(age_s)
    .fetch_one(pool)
    .await
    .expect("seed a scoped belief")
}

/// The beliefs stored at one key.
async fn beliefs_at(pool: &PgPool, frame: Uuid, claim: Uuid, scope: Option<Uuid>) -> Vec<f64> {
    sqlx::query_scalar(
        "SELECT belief FROM ds_combined_beliefs \
          WHERE frame_id = $1 AND claim_id = $2 AND scope_id IS NOT DISTINCT FROM $3 \
          ORDER BY computed_at DESC",
    )
    .bind(frame)
    .bind(claim)
    .bind(scope)
    .fetch_all(pool)
    .await
    .expect("read the stored scoped beliefs")
}

/// Whether the table's key treats NULLs as equal (`None`: no such key).
async fn key_nulls_not_distinct(pool: &PgPool) -> Option<bool> {
    sqlx::query_scalar(
        "SELECT i.indnullsnotdistinct \
           FROM pg_constraint c JOIN pg_index i ON i.indexrelid = c.conindid \
          WHERE c.conrelid = 'public.ds_combined_beliefs'::regclass \
            AND c.conname = $1 AND c.contype = 'u'",
    )
    .bind(KEY)
    .fetch_optional(pool)
    .await
    .expect("read the key")
}

async fn upsert_global(pool: &PgPool, frame: Uuid, claim: Uuid, belief: f64) -> Uuid {
    epigraph_db::ScopedBeliefRepository::upsert(
        pool,
        frame,
        claim,
        "global",
        None,
        belief,
        1.0,
        0.0,
        0.0,
        None,
        None,
        Some(belief),
    )
    .await
    .expect("upsert a global scoped belief")
}

#[sqlx::test(migrations = "../../migrations")]
async fn two_global_upserts_leave_one_row_holding_the_second_value(pool: PgPool) {
    let frame = frame(&pool).await;
    let claim = claim(&pool, "upsert").await;

    let first = upsert_global(&pool, frame, claim, 0.4).await;
    let second = upsert_global(&pool, frame, claim, 0.7).await;

    let stored = beliefs_at(&pool, frame, claim, None).await;
    assert_eq!(
        stored.len(),
        1,
        "two global writes of one (frame, claim) must leave ONE row: {stored:?}"
    );
    assert!(
        (stored[0] - 0.7).abs() < EPS,
        "the row holds the second write's value: {stored:?}"
    );
    assert_eq!(first, second, "the second write updated the first row");
}

#[sqlx::test(migrations = false)]
async fn duplicate_global_rows_collapse_to_the_newest_and_other_keys_stay(pool: PgPool) {
    migrate(&pool, &up_to(below())).await;
    let f = frame(&pool).await;
    let other_frame = frame(&pool).await;
    let a = claim(&pool, "dup").await;
    let b = claim(&pool, "single").await;
    let p = Uuid::new_v4();

    // Three global rows of (f, a) as the old key let through; the newest
    // (1 s old) holds 0.9 and is neither the first nor the last inserted.
    row(&pool, f, a, None, 0.2, 7200.0).await;
    let newest = row(&pool, f, a, None, 0.9, 1.0).await;
    row(&pool, f, a, None, 0.5, 3600.0).await;
    // Other keys: a perspective row of (f, a), a global row of (other, a), a
    // global row of (f, b). None is a duplicate.
    let perspective = row(&pool, f, a, Some(p), 0.3, 9000.0).await;
    let other = row(&pool, other_frame, a, None, 0.6, 9000.0).await;
    let single = row(&pool, f, b, None, 0.1, 9000.0).await;
    assert_eq!(
        beliefs_at(&pool, f, a, None).await.len(),
        3,
        "the head below 308 stores the duplicates (the fixture is live)"
    );

    migrate(&pool, &up_to(308)).await;

    assert_eq!(
        beliefs_at(&pool, f, a, None).await,
        vec![0.9],
        "only the newest global row of (f, a) is kept"
    );
    let kept: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM ds_combined_beliefs WHERE frame_id = $1 AND claim_id = $2 \
            AND scope_id IS NULL",
    )
    .bind(f)
    .bind(a)
    .fetch_all(&pool)
    .await
    .expect("read the kept row");
    assert_eq!(kept, vec![newest], "the kept row is the newest one itself");
    for (id, what) in [
        (perspective, "the perspective row of (f, a)"),
        (other, "the global row of (other frame, a)"),
        (single, "the global row of (f, b)"),
    ] {
        let present: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM ds_combined_beliefs WHERE id = $1)")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("read a row");
        assert!(present, "{what} is not a duplicate and stays");
    }
    assert_eq!(
        key_nulls_not_distinct(&pool).await,
        Some(true),
        "308 re-adds the key as NULLS NOT DISTINCT under its name"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_308_undo_restores_the_nulls_distinct_key(pool: PgPool) {
    assert_eq!(key_nulls_not_distinct(&pool).await, Some(true), "at head");
    let undo = repo_file("docs/runbooks/308-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
    }
    assert_eq!(
        key_nulls_not_distinct(&pool).await,
        Some(false),
        "the undo restores 001's NULLS DISTINCT key under its name"
    );
    let frame = frame(&pool).await;
    let claim = claim(&pool, "undo").await;
    upsert_global(&pool, frame, claim, 0.4).await;
    upsert_global(&pool, frame, claim, 0.7).await;
    assert_eq!(
        beliefs_at(&pool, frame, claim, None).await.len(),
        2,
        "under 001's key a second global write inserts again"
    );
}
