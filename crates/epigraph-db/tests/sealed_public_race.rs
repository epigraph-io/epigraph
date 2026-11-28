//! Migration 227 (backlog e8f9c07e): a seal and a publicize of the same claim
//! can no longer both commit.
//!
//! # The race
//!
//! "A sealed claim is never public" is held by two triggers, each of which
//! read the OTHER table with a plain SELECT: 081/176's
//! `epigraph_no_public_sealed` (BEFORE INSERT on `claim_encryption`) reads
//! `claims.visibility`, and 074's `epigraph_claims_block_widening` (BEFORE
//! UPDATE OF visibility on `claims`) reads `claim_encryption`. Under READ
//! COMMITTED neither sees the other's uncommitted write and nothing makes one
//! wait for the other, so both commit and leave a public sealed claim.
//!
//! # How the interleaving is forced
//!
//! Connection A runs the FIRST write (the publicize's UPDATE, or the seal's
//! INSERT) and stays open. Connection B runs the SECOND write in a spawned
//! task. The test commits A only once B has either finished or is observed in
//! `pg_stat_activity` waiting on a lock (bounded), then awaits B. No sleep
//! decides the order: A's write is done before B's starts.
//!
//! The seal and the raw publicize run as `epigraph_maintenance`, the role the
//! shipped seal (`seal_claims_conn`, on a maintenance connection) and 206's
//! publicize body write as. The shipped publicize is called as `epigraph_app`
//! with the admin's session GUCs, as the route calls it.
//!
//! # What is pinned
//!
//! [`the_seal_and_publicize_race_commits_at_176_and_is_refused_at_227`]: on a
//! database at 226 (176's body) BOTH orderings commit a public claim with a
//! ciphertext row (the calibration: this is the defect). After 227, on fresh
//! claims, B waits on A's row lock in both orderings and is refused:
//! publicize-first by PRV01, seal-first by 074's SEALED refusal (074 is not
//! changed; its EXISTS takes a fresh snapshot after the row wait).
//!
//! [`the_shipped_publicize_races_at_176_and_is_serialized_at_227`]: the same
//! race through 206's `epigraph_publicize_claims` (as `epigraph_app`, the
//! route's caller). At 226 both orderings commit a public sealed claim; at 227
//! seal-first returns the `refused_sealed` outcome after waiting, and
//! publicize-first refuses the seal by PRV01.
//!
//! [`every_role_that_may_seal_may_lock_the_claim_row`] (a precondition guard
//! that passes at 226 too): a locking read needs
//! UPDATE on `claims`, so a role that may write `claim_encryption` without it
//! would have every seal turned into a permission error.
//!
//! [`the_app_role_seal_check_refuses_what_176_refused`] (a non-regression
//! check that passes at 226 by design): on the application
//! role (row security on), sealing its own group claim succeeds and sealing a
//! public claim is refused with PRV01, at 226 and at 227 alike.
//!
//! [`a_redelivered_seal_is_a_no_op_not_a_deadlock`]: two deliveries of one
//! seal (`ON CONFLICT DO NOTHING`) still end in one commit and one no-op. A
//! FOR SHARE lock in the trigger deadlocked them (measured), which is why 227
//! takes FOR NO KEY UPDATE.
//!
//! [`a_claim_hidden_from_the_locking_read_is_still_refused`]: 227's fallback
//! to the unlocked read, under a test-local policy that hides the row from a
//! locking read only.
//!
//! [`the_227_undo_returns_the_catalog_below_227`]: the undo runbook restores
//! 176's body (whole definition by md5) and is idempotent.
//!
//! [`a_multi_claim_seal_and_publicize_in_opposite_orders_do_not_deadlock`]
//! (backlog d1818fd0): the real `seal_claims_conn`, handed its items in
//! DESCENDING id order, beside 206's shipped publicize of the same two claims
//! (which locks in ascending id order). Both finish; the publicize answers
//! `refused_sealed` for both.
//!
//! # Verified to fail
//!
//! - `FOR NO KEY UPDATE OF c` removed from 227's locked read: the 227 halves
//!   of both race tests fail (B never waits; both writes commit).
//! - `REVOKE UPDATE ON public.claims FROM epigraph_app` appended to 227: the
//!   precondition guard fails.
//! - `FOR SHARE OF c` in its place: the redelivered-seal test fails at 227
//!   with `deadlock detected`.
//! - The `IF NOT FOUND` fallback removed: the hidden-row test fails (the seal
//!   of the public claim is admitted).
//! - `seal_claims_conn`'s sort of its items and its `ORDER BY t.claim_id`
//!   removed (the code before d1818fd0): the opposite-order test fails, one
//!   side aborted with `deadlock detected`.
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is
//! not extended.

mod viewer_fixture;

use sqlx::migrate::Migrator;
use sqlx::{Executor, PgPool};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::time::Duration;
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// The role the shipped seal and 206's publicize write as.
const MAINTENANCE: &str = "epigraph_maintenance";

fn up_to(max: i64) -> Migrator {
    Migrator {
        migrations: Cow::Owned(
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
async fn migrate(pool: &PgPool, migrator: &Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

/// A team group with an active key epoch 0 and an author writing in it:
/// `(author, group)`.
async fn seal_group(pool: &PgPool) -> (Uuid, Uuid) {
    let (author, _) = viewer_fixture::seed_agent_with_group(pool, "seal-race").await;
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, status, \
                             created_by_agent_id) \
         VALUES ('seal race', 'did:epigraph:team:' || gen_random_uuid()::text, \
                 decode(repeat('ab', 32), 'hex'), 'team', 'active', $1) \
         RETURNING id",
    )
    .bind(author)
    .fetch_one(pool)
    .await
    .expect("seed team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(group)
    .bind(author)
    .execute(pool)
    .await
    .expect("seed team membership");
    sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active')")
        .bind(group)
        .execute(pool)
        .await
        .expect("seed key epoch");
    (author, group)
}

const SEAL: &str = "INSERT INTO claim_encryption \
                        (claim_id, group_id, epoch, privacy_tier, encrypted_content) \
                    VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea)";

/// 074's ordinary group -> public guard is an interlock armed by the
/// declassification surface; arm it as 206's publicize does, for the one
/// statement's transaction. 074's SEALED arm is not reached by the GUC.
const ARM_DECLASSIFY: &str = "SELECT set_config('epigraph.allow_declassify', 'yes', true)";
const PUBLICIZE: &str = "UPDATE claims SET visibility = 'public' WHERE id = $1";

/// 206's shipped publicize, as `ClaimVisibilityRepository::publicize_conn`
/// calls it. It arms the declassify GUC itself.
const SHIPPED_PUBLICIZE: &str =
    "SELECT outcome FROM public.epigraph_publicize_claims(ARRAY[$1]::uuid[], 'race test')";

/// One write of the race.
#[derive(Clone, Copy, Debug)]
enum Op {
    /// The seal's INSERT, as `epigraph_maintenance` (the shipped seal's role).
    Seal,
    /// A raw `UPDATE claims SET visibility = 'public'`, as
    /// `epigraph_maintenance` (the role 206's publicize body writes as).
    RawPublicize,
    /// 206's `epigraph_publicize_claims`, called as `epigraph_app` by the
    /// group's admin, as the route calls it.
    ShippedPublicize,
}

impl Op {
    fn role(self) -> &'static str {
        match self {
            Op::Seal | Op::RawPublicize => MAINTENANCE,
            Op::ShippedPublicize => "epigraph_app",
        }
    }
}

/// Run one write inside `conn`'s open transaction. `Some(outcome)` is the
/// shipped publicize's per-claim outcome.
async fn write(
    conn: &mut sqlx::PgConnection,
    op: Op,
    claim: Uuid,
    group: Uuid,
    author: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    match op {
        Op::Seal => {
            sqlx::query(SEAL)
                .bind(claim)
                .bind(group)
                .execute(&mut *conn)
                .await?;
            Ok(None)
        }
        Op::RawPublicize => {
            sqlx::query(ARM_DECLASSIFY).execute(&mut *conn).await?;
            sqlx::query(PUBLICIZE)
                .bind(claim)
                .execute(&mut *conn)
                .await?;
            Ok(None)
        }
        Op::ShippedPublicize => {
            sqlx::query(
                "SELECT set_config('epigraph.principal_id', $1, true), \
                        set_config('epigraph.group_ids', $2, true), \
                        set_config('epigraph.writable_group_ids', $2, true)",
            )
            .bind(author.to_string())
            .bind(group.to_string())
            .execute(&mut *conn)
            .await?;
            let outcome: String = sqlx::query_scalar(SHIPPED_PUBLICIZE)
                .bind(claim)
                .fetch_one(&mut *conn)
                .await?;
            Ok(Some(outcome))
        }
    }
}

struct Outcome {
    /// B was observed waiting on a lock before A committed.
    waited: bool,
    /// B's write and commit: the shipped publicize's outcome, or the error
    /// text on failure.
    second: Result<Option<String>, String>,
    /// The end state: the claim is public AND carries a ciphertext row.
    public_and_sealed: bool,
}

/// A: the `first` write, left open. B: the `second` write in its own
/// transaction, in a task. Commit A once B finished or is seen waiting on a
/// lock.
async fn race(
    pool: &PgPool,
    first: Op,
    second: Op,
    claim: Uuid,
    group: Uuid,
    author: Uuid,
) -> Outcome {
    let mut a = pool.acquire().await.expect("acquire A");
    a.execute(format!("SET SESSION AUTHORIZATION {}", first.role()).as_str())
        .await
        .expect("A's role");
    a.execute("BEGIN").await.expect("begin A");
    write(&mut a, first, claim, group, author)
        .await
        .unwrap_or_else(|e| panic!("A ({first:?}) applies on its own: {e}"));

    let mut b = pool.acquire().await.expect("acquire B");
    b.execute(format!("SET SESSION AUTHORIZATION {}", second.role()).as_str())
        .await
        .expect("B's role");
    let b_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *b)
        .await
        .expect("B's pid");
    let task = tokio::spawn(async move {
        let run = async {
            b.execute("BEGIN").await?;
            b.execute("SET LOCAL lock_timeout = '30s'").await?;
            let outcome = write(&mut b, second, claim, group, author).await?;
            b.execute("COMMIT").await?;
            Ok::<Option<String>, sqlx::Error>(outcome)
        };
        let out = run.await.map_err(|e| e.to_string());
        if out.is_err() {
            let _ = b.execute("ROLLBACK").await;
        }
        let _ = b.execute("RESET SESSION AUTHORIZATION").await;
        out
    });

    let mut waited = false;
    for _ in 0..500 {
        if task.is_finished() {
            break;
        }
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
                             WHERE pid = $1 AND wait_event_type = 'Lock')",
        )
        .bind(b_pid)
        .fetch_one(pool)
        .await
        .expect("read pg_stat_activity");
        if blocked {
            waited = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    a.execute("COMMIT").await.expect("commit A");
    a.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset A");
    let second = task.await.expect("B's task");

    let public_and_sealed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM claims c \
                         WHERE c.id = $1 AND c.visibility = 'public' \
                           AND EXISTS (SELECT 1 FROM claim_encryption ce \
                                        WHERE ce.claim_id = c.id))",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the end state");
    Outcome {
        waited,
        second,
        public_and_sealed,
    }
}

#[sqlx::test(migrations = false)]
async fn the_seal_and_publicize_race_commits_at_176_and_is_refused_at_227(pool: PgPool) {
    migrate(&pool, &up_to(226)).await;
    let (author, group) = seal_group(&pool).await;

    // CALIBRATION, 176's body: both orderings commit a public sealed claim.
    for (first, second) in [(Op::RawPublicize, Op::Seal), (Op::Seal, Op::RawPublicize)] {
        let claim = viewer_fixture::seed_group_claim(&pool, author, group, "a claim").await;
        let out = race(&pool, first, second, claim, group, author).await;
        assert!(
            out.second.is_ok(),
            "CALIBRATION ({first:?} first, 176): the second write commits: {:?}",
            out.second
        );
        assert!(
            out.public_and_sealed,
            "CALIBRATION ({first:?} first, 176): the race leaves a public sealed claim"
        );
    }

    migrate(&pool, &MIGRATOR).await;

    for (first, second, refusal) in [
        (Op::RawPublicize, Op::Seal, "PRV01:"),
        (
            Op::Seal,
            Op::RawPublicize,
            "is SEALED and cannot be made public",
        ),
    ] {
        let claim = viewer_fixture::seed_group_claim(&pool, author, group, "a claim").await;
        let out = race(&pool, first, second, claim, group, author).await;
        assert!(
            out.waited,
            "({first:?} first, 227): the second write never waited on the claim row's \
             lock, so the two writes were not serialized (second: {:?})",
            out.second
        );
        let err = out.second.expect_err(&format!(
            "({first:?} first, 227): the second write must be refused"
        ));
        assert!(
            err.contains(refusal),
            "({first:?} first, 227): refused by `{refusal}`, got: {err}"
        );
        assert!(
            !out.public_and_sealed,
            "({first:?} first, 227): a public sealed claim committed"
        );
    }
}

/// The race through 206's SHIPPED publicize (`epigraph_publicize_claims`,
/// called as `epigraph_app` by the group's admin), which guest routes rely on.
/// Its `ORDER BY c.id FOR NO KEY UPDATE` pre-lock does not conflict with the
/// KEY SHARE a seal's FK check takes, and its classification EXISTS does not
/// see an uncommitted ciphertext row, so at 226 it races exactly as the raw
/// UPDATE does. At 227, seal first: the pre-lock waits on the seal trigger's
/// row lock and the classification then answers `refused_sealed` (a result
/// row, not 074's exception). Publicize first: the seal waits on the
/// function's row lock and PRV01 refuses it.
#[sqlx::test(migrations = false)]
async fn the_shipped_publicize_races_at_176_and_is_serialized_at_227(pool: PgPool) {
    migrate(&pool, &up_to(226)).await;
    let (author, group) = seal_group(&pool).await;

    // CALIBRATION, 176's body: the shipped publicize commits a public sealed
    // claim in both orderings.
    let claim = viewer_fixture::seed_group_claim(&pool, author, group, "a claim").await;
    let out = race(&pool, Op::Seal, Op::ShippedPublicize, claim, group, author).await;
    assert_eq!(
        out.second,
        Ok(Some("publicized".to_string())),
        "CALIBRATION (seal first, 176): the shipped publicize classifies the claim \
         publicizable and commits"
    );
    assert!(
        out.public_and_sealed,
        "CALIBRATION (seal first, 176): the race leaves a public sealed claim"
    );
    let claim = viewer_fixture::seed_group_claim(&pool, author, group, "a claim").await;
    let out = race(&pool, Op::ShippedPublicize, Op::Seal, claim, group, author).await;
    assert_eq!(
        out.second,
        Ok(None),
        "CALIBRATION (shipped publicize first, 176): the seal commits"
    );
    assert!(
        out.public_and_sealed,
        "CALIBRATION (shipped publicize first, 176): the race leaves a public sealed claim"
    );

    migrate(&pool, &MIGRATOR).await;

    let claim = viewer_fixture::seed_group_claim(&pool, author, group, "a claim").await;
    let out = race(&pool, Op::Seal, Op::ShippedPublicize, claim, group, author).await;
    assert!(
        out.waited,
        "(seal first, 227): the shipped publicize never waited on the seal's row lock \
         (second: {:?})",
        out.second
    );
    assert_eq!(
        out.second,
        Ok(Some("refused_sealed".to_string())),
        "(seal first, 227): the shipped publicize classifies the claim refused_sealed"
    );
    assert!(
        !out.public_and_sealed,
        "(seal first, 227): a public sealed claim committed"
    );

    let claim = viewer_fixture::seed_group_claim(&pool, author, group, "a claim").await;
    let out = race(&pool, Op::ShippedPublicize, Op::Seal, claim, group, author).await;
    assert!(
        out.waited,
        "(shipped publicize first, 227): the seal never waited on the publicize's row lock \
         (second: {:?})",
        out.second
    );
    let err = out
        .second
        .expect_err("(shipped publicize first, 227): the seal must be refused");
    assert!(
        err.contains("PRV01:"),
        "(shipped publicize first, 227): refused by PRV01, got: {err}"
    );
    assert!(
        !out.public_and_sealed,
        "(shipped publicize first, 227): a public sealed claim committed"
    );
}

/// PRECONDITION GUARD, not a proof of 227's change: it passes at 226 as well.
/// It pins the grant 227 newly depends on. Mutation: `REVOKE UPDATE ON
/// public.claims FROM epigraph_app` -> this fails (and every app-role seal at
/// 227 would become a permission error).
#[sqlx::test(migrations = "../../migrations")]
async fn every_role_that_may_seal_may_lock_the_claim_row(pool: PgPool) {
    let sealers: Vec<(String, bool)> = sqlx::query_as(
        "SELECT r.rolname::text, has_table_privilege(r.oid, 'public.claims', 'UPDATE') \
           FROM pg_roles r \
          WHERE NOT r.rolsuper \
            AND (has_table_privilege(r.oid, 'public.claim_encryption', 'INSERT') \
                 OR has_table_privilege(r.oid, 'public.claim_encryption', 'UPDATE'))",
    )
    .fetch_all(&pool)
    .await
    .expect("read the sealer roles");
    let names: BTreeSet<&str> = sealers.iter().map(|(r, _)| r.as_str()).collect();
    assert!(
        names.contains("epigraph_app") && names.contains(MAINTENANCE),
        "CALIBRATION: the application and maintenance roles may write claim_encryption: \
         {names:?}"
    );
    let cannot_lock: Vec<&str> = sealers
        .iter()
        .filter(|(_, update)| !update)
        .map(|(r, _)| r.as_str())
        .collect();
    assert!(
        cannot_lock.is_empty(),
        "these roles may write claim_encryption but not lock a claims row \
         (a locking read needs UPDATE), so 227 would refuse every seal they make: \
         {cannot_lock:?}"
    );
}

/// Seal `claim` as `epigraph_app`, stamped as a writer of `group`.
async fn app_seal(pool: &PgPool, author: Uuid, group: Uuid, claim: Uuid) -> Result<(), String> {
    viewer_fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        let run = async {
            conn.execute("BEGIN").await?;
            sqlx::query(
                "SELECT set_config('epigraph.principal_id', $1, true), \
                        set_config('epigraph.group_ids', $2, true), \
                        set_config('epigraph.writable_group_ids', $2, true)",
            )
            .bind(author.to_string())
            .bind(group.to_string())
            .execute(&mut *conn)
            .await?;
            sqlx::query(SEAL)
                .bind(claim)
                .bind(group)
                .execute(&mut *conn)
                .await?;
            conn.execute("COMMIT").await?;
            Ok::<(), sqlx::Error>(())
        };
        let out = run.await.map_err(|e| e.to_string());
        if out.is_err() {
            let _ = conn.execute("ROLLBACK").await;
        }
        (conn, out)
    })
    .await
}

/// NON-REGRESSION CHECK, not a proof of 227's change: it passes at 226 by
/// design and pins that the locking read refuses and admits what 176's did
/// under row security (the app role's seal path, `ClaimEncryptionRepository::
/// insert_conn`, runs under it). It is not counted as a fail-on-old-code test.
#[sqlx::test(migrations = false)]
async fn the_app_role_seal_check_refuses_what_176_refused(pool: PgPool) {
    for (at, migrator) in [("226", up_to(226)), ("227", up_to(227))] {
        migrate(&pool, &migrator).await;
        let (author, group) = seal_group(&pool).await;

        let own = viewer_fixture::seed_group_claim(&pool, author, group, "own").await;
        app_seal(&pool, author, group, own)
            .await
            .unwrap_or_else(|e| panic!("(at {at}) the app role seals its own group claim: {e}"));

        let public = viewer_fixture::seed_public_claim(&pool, author, "public").await;
        let err = app_seal(&pool, author, group, public)
            .await
            .expect_err(&format!("(at {at}) sealing a public claim is refused"));
        assert!(
            err.contains("PRV01:"),
            "(at {at}) refused by PRV01 under row security, got: {err}"
        );
    }
}

/// The seal's INSERT, as `seal_claims_conn` writes it: a re-delivered commit
/// is a no-op through `ON CONFLICT DO NOTHING`.
const SEAL_REDELIVERABLE: &str = "INSERT INTO claim_encryption \
                                      (claim_id, group_id, epoch, privacy_tier, encrypted_content) \
                                  VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea) \
                                  ON CONFLICT (claim_id) DO NOTHING";
/// The seal's statement 2 (the sentinel), which takes the claim row's lock.
const SEAL_SENTINEL: &str = "UPDATE claims c \
                             SET content = '[sealed:x' || replace(c.id::text, '-', '') || ']' \
                             WHERE c.id = $1";

/// Two deliveries of one seal: A runs the INSERT, B runs the same INSERT
/// (which waits on A's unique-index entry), then A runs its sentinel UPDATE and
/// commits. Returns (A's result, B's result, B was seen waiting).
async fn redelivered_seal(
    pool: &PgPool,
    claim: Uuid,
    group: Uuid,
) -> (Result<(), String>, Result<(), String>, bool) {
    let mut a = pool.acquire().await.expect("acquire A");
    a.execute(format!("SET SESSION AUTHORIZATION {MAINTENANCE}").as_str())
        .await
        .expect("A as maintenance");
    a.execute("BEGIN").await.expect("begin A");
    a.execute("SET LOCAL lock_timeout = '30s'")
        .await
        .expect("A lock_timeout");
    sqlx::query(SEAL_REDELIVERABLE)
        .bind(claim)
        .bind(group)
        .execute(&mut *a)
        .await
        .expect("A: the first delivery's INSERT");

    let mut b = pool.acquire().await.expect("acquire B");
    b.execute(format!("SET SESSION AUTHORIZATION {MAINTENANCE}").as_str())
        .await
        .expect("B as maintenance");
    let b_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *b)
        .await
        .expect("B's pid");
    let task = tokio::spawn(async move {
        let run = async {
            b.execute("BEGIN").await?;
            b.execute("SET LOCAL lock_timeout = '30s'").await?;
            sqlx::query(SEAL_REDELIVERABLE)
                .bind(claim)
                .bind(group)
                .execute(&mut *b)
                .await?;
            b.execute("COMMIT").await?;
            Ok::<(), sqlx::Error>(())
        };
        let out = run.await.map_err(|e| e.to_string());
        if out.is_err() {
            let _ = b.execute("ROLLBACK").await;
        }
        let _ = b.execute("RESET SESSION AUTHORIZATION").await;
        out
    });

    let mut waited = false;
    for _ in 0..500 {
        if task.is_finished() {
            break;
        }
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
                             WHERE pid = $1 AND wait_event_type = 'Lock')",
        )
        .bind(b_pid)
        .fetch_one(pool)
        .await
        .expect("read pg_stat_activity");
        if blocked {
            waited = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let first = async {
        sqlx::query(SEAL_SENTINEL)
            .bind(claim)
            .execute(&mut *a)
            .await?;
        a.execute("COMMIT").await?;
        Ok::<(), sqlx::Error>(())
    }
    .await
    .map_err(|e| e.to_string());
    if first.is_err() {
        let _ = a.execute("ROLLBACK").await;
    }
    a.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset A");
    let second = task.await.expect("B's task");
    (first, second, waited)
}

/// A seal delivered twice concurrently must stay what `seal_claims_conn`
/// documents: the second delivery is a no-op, not an error. A lock in the
/// trigger that two deliveries can both hold (FOR SHARE) deadlocks them: B
/// holds it while waiting on A's unique-index entry, and A's sentinel UPDATE
/// then waits on B. Calibrated at 226, where B takes no row lock.
#[sqlx::test(migrations = false)]
async fn a_redelivered_seal_is_a_no_op_not_a_deadlock(pool: PgPool) {
    for (at, migrator) in [("226", up_to(226)), ("227", up_to(227))] {
        migrate(&pool, &migrator).await;
        let (author, group) = seal_group(&pool).await;
        let claim = viewer_fixture::seed_group_claim(&pool, author, group, "a claim").await;
        let (first, second, waited) = redelivered_seal(&pool, claim, group).await;
        assert!(
            waited,
            "(at {at}) CALIBRATION: the second delivery waited on the first"
        );
        assert!(
            first.is_ok(),
            "(at {at}) the first delivery commits: {first:?}"
        );
        assert!(
            second.is_ok(),
            "(at {at}) the second delivery is a no-op, not an error: {second:?}"
        );
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM claim_encryption WHERE claim_id = $1")
                .bind(claim)
                .fetch_one(&pool)
                .await
                .expect("count ciphertext rows");
        assert_eq!(rows, 1, "(at {at}) one ciphertext row");
    }
}

/// 227's fallback: a locking read applies `claims`' UPDATE policies, so a
/// policy that hides a row from UPDATE but not from SELECT would make the
/// locked read find nothing. The check must then still refuse a public claim,
/// by 176's unlocked read. The policy is test-local; no shipped policy does
/// this today. Mutation: the `IF NOT FOUND` fallback removed -> the seal of
/// the public claim is admitted.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_hidden_from_the_locking_read_is_still_refused(pool: PgPool) {
    let (author, group) = seal_group(&pool).await;
    sqlx::query(
        "CREATE POLICY test_claims_no_update ON public.claims \
             AS RESTRICTIVE FOR UPDATE TO epigraph_app USING (false)",
    )
    .execute(&pool)
    .await
    .expect("test-local policy");

    let public = viewer_fixture::seed_public_claim(&pool, author, "public").await;
    let err = app_seal(&pool, author, group, public)
        .await
        .expect_err("sealing a public claim is refused even when the locking read sees no row");
    assert!(err.contains("PRV01:"), "refused by PRV01, got: {err}");

    // CALIBRATION: the policy does hide the row from the locking read.
    let locked: Option<String> =
        viewer_fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            let v = sqlx::query_scalar(
                "SELECT c.visibility::text FROM claims c WHERE c.id = $1 FOR NO KEY UPDATE OF c",
            )
            .bind(public)
            .fetch_optional(&mut *conn)
            .await
            .expect("locking read");
            (conn, v)
        })
        .await;
    assert_eq!(
        locked, None,
        "CALIBRATION: the test policy hides the row from a locking read"
    );
}

/// The `public` catalog by name: functions (whole definition by md5, owner
/// and ACL), policies, triggers and constraints.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' \
                || COALESCE(p.proacl::text, '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'pol ' || c.relname || '.' || pol.polname \
           FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'trg ' || c.relname || '.' || t.tgname \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'con ' || c.relname || '.' || k.conname \
           FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
          WHERE c.relnamespace = 'public'::regnamespace",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Mutation: the undo's re-statement of 176's body edited by one character ->
/// the function's md5 differs from the one below 227 and is named in the diff.
#[sqlx::test(migrations = false)]
async fn the_227_undo_returns_the_catalog_below_227(pool: PgPool) {
    migrate(&pool, &up_to(226)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(227)).await;
    let through = catalog(&pool).await;
    let added: Vec<&String> = through.difference(&before).collect();
    let removed: Vec<&String> = before.difference(&through).collect();
    assert!(
        added.len() == 1
            && removed.len() == 1
            && added[0].starts_with("fn epigraph_no_public_sealed() ")
            && removed[0].starts_with("fn epigraph_no_public_sealed() "),
        "CALIBRATION: 227 changes exactly epigraph_no_public_sealed's definition: \
         added {added:?}, removed {removed:?}"
    );

    let undo = repo_file("docs/runbooks/227-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 227"
        );
    }
}

// ===========================================================================
// Lock order of the multi-claim privatization writes (backlog d1818fd0)
// ===========================================================================

/// Poll `pg_stat_activity` until backend `pid` waits on a lock, or `task`
/// has finished, bounded at ten seconds. `true` when the wait was seen.
async fn seen_waiting<T>(pool: &PgPool, pid: i32, task: &tokio::task::JoinHandle<T>) -> bool {
    for _ in 0..500 {
        if task.is_finished() {
            return false;
        }
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity \
                             WHERE pid = $1 AND wait_event_type = 'Lock')",
        )
        .bind(pid)
        .fetch_one(pool)
        .await
        .expect("read pg_stat_activity");
        if blocked {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// A fresh non-superuser, non-BYPASSRLS member of `epigraph_maintenance`, the
/// shape of a deployed maintenance login, with the DELETE grant such a login
/// needs for the seal's derived-extraction DELETEs (as in
/// `sealed_row_encryption_write_scope.rs`).
async fn maintenance_member(pool: &PgPool) -> String {
    let role = format!("d1818fd0_maint_{}", Uuid::new_v4().simple());
    for stmt in [
        format!("CREATE ROLE {role} NOLOGIN"),
        format!("GRANT {MAINTENANCE} TO {role}"),
        format!("GRANT DELETE ON ALL TABLES IN SCHEMA public TO {role}"),
    ] {
        sqlx::query(&stmt)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("{stmt}: {e}"));
    }
    role
}

/// Two claims of `group`, `(lo, hi)` by id, with `hi` stored BEFORE `lo` in
/// the heap, so a sequential or bitmap scan meets `hi` first, as an unnest of
/// `[hi, lo]` does. Seeds until two consecutive claims come out in descending
/// id order (the spares are harmless).
async fn descending_pair(pool: &PgPool, author: Uuid, group: Uuid) -> (Uuid, Uuid) {
    let mut prev = viewer_fixture::seed_group_claim(pool, author, group, "pair 0").await;
    for n in 1..32 {
        let next =
            viewer_fixture::seed_group_claim(pool, author, group, &format!("pair {n}")).await;
        if prev > next {
            return (next, prev);
        }
        prev = next;
    }
    panic!("no descending pair in 32 seeded claims");
}

fn seal_item(claim_id: Uuid) -> epigraph_db::repos::privatization::SealCommitItem {
    epigraph_db::repos::privatization::SealCommitItem {
        claim_id,
        content_ct: vec![0xAA; 48],
        labels_ct: vec![0xAB; 48],
        properties_ct: vec![0xAC; 48],
        content_hash: vec![0x11; 32],
        versions: Vec::new(),
        evidence: Vec::new(),
    }
}

fn unseal_item(claim_id: Uuid) -> epigraph_db::repos::privatization::UnsealCommitItem {
    epigraph_db::repos::privatization::UnsealCommitItem {
        claim_id,
        content: format!("restored {claim_id}"),
        content_hash: vec![0x22; 32],
        labels: Vec::new(),
        properties: serde_json::json!({}),
        versions: Vec::new(),
        evidence: Vec::new(),
    }
}

/// The multi-claim privatization write under test, each handed its claims in
/// DESCENDING id order `[hi, lo]`.
enum Act {
    /// `seal_claims_conn` under `group`.
    Seal { group: Uuid },
    /// `unseal_claims_conn` under `group`.
    Unseal { group: Uuid },
    /// `restrict_claims_conn` into `target`.
    Restrict { target: Uuid },
    /// `restore_claims_conn` of `plan`'s items out of `target`.
    Restore { plan: Uuid, target: Uuid },
}

impl Act {
    /// Run in `conn`'s open transaction. `Ok` carries the ids the act
    /// reported (the restore reports a count; its ids are not returned).
    async fn run(
        &self,
        conn: &mut sqlx::PgConnection,
        lo: Uuid,
        hi: Uuid,
    ) -> Result<Vec<Uuid>, epigraph_db::DbError> {
        use epigraph_db::repos::privatization::PrivatizationRepository as R;
        match *self {
            Act::Seal { group } => {
                R::seal_claims_conn(conn, group, 0, &[seal_item(hi), seal_item(lo)], None).await
            }
            Act::Unseal { group } => {
                R::unseal_claims_conn(conn, group, &[unseal_item(hi), unseal_item(lo)]).await
            }
            Act::Restrict { target } => R::restrict_claims_conn(conn, &[hi, lo], target).await,
            Act::Restore { plan, target } => R::restore_claims_conn(conn, plan, &[hi, lo], target)
                .await
                .map(|n| vec![Uuid::nil(); usize::try_from(n).unwrap_or(0)]),
        }
    }
}

/// What the race left: the act's result and the publicize's per-claim
/// outcomes, each `Err` carrying the error text.
struct Race {
    act: Result<Vec<Uuid>, String>,
    publicize: Result<Vec<(Uuid, String)>, String>,
}

/// Force the interleaving in which a caller-order lock deadlocks against
/// 206's id-order publicize, and return what both sides did.
///
/// A holder session takes `hi`'s row lock (`FOR NO KEY UPDATE`, the mode
/// both sides take). The act starts, handed `[hi, lo]`, on a fresh
/// maintenance member, and is seen waiting. 206's `epigraph_publicize_claims`
/// of `[lo, hi]` starts as `epigraph_app` with `publicizer`'s session GUCs
/// over `readable`, and is seen waiting. The holder rolls back.
///
/// An act that locks in its caller's order waited on `hi` holding nothing
/// while the publicize took `lo` and queued on `hi`; released, the act takes
/// `hi` and waits on `lo`: `deadlock detected` (40P01), one side aborted. An
/// act that locks in id order took `lo` before waiting on `hi`, so the
/// publicize queued behind it and runs after it commits. `lock_timeout` is
/// 30 s on both sides, far above `deadlock_timeout`, so a 55P03 cannot stand
/// in for the deadlock.
async fn opposite_order_race(
    pool: &PgPool,
    act: Act,
    (lo, hi): (Uuid, Uuid),
    publicizer: Uuid,
    readable: Uuid,
) -> Race {
    let role = maintenance_member(pool).await;

    let mut holder = pool.acquire().await.expect("acquire the holder");
    holder.execute("BEGIN").await.expect("begin the holder");
    sqlx::query("SELECT 1 FROM claims WHERE id = $1 FOR NO KEY UPDATE")
        .bind(hi)
        .execute(&mut *holder)
        .await
        .expect("the holder locks the higher claim");

    let mut actor = pool.acquire().await.expect("acquire the act's session");
    actor
        .execute(format!("SET SESSION AUTHORIZATION {role}").as_str())
        .await
        .expect("the act's role");
    let act_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *actor)
        .await
        .expect("the act's pid");
    let act_task = tokio::spawn(async move {
        let run = async {
            let mut tx = sqlx::Connection::begin(&mut *actor).await?;
            sqlx::query("SET LOCAL lock_timeout = '30s'")
                .execute(&mut *tx)
                .await?;
            match act.run(&mut tx, lo, hi).await {
                Ok(ids) => {
                    tx.commit().await?;
                    Ok(Ok(ids))
                }
                Err(e) => Ok::<_, sqlx::Error>(Err(format!("{e:?}"))),
            }
        };
        let out = run.await.map_err(|e| e.to_string()).and_then(|r| r);
        let _ = actor.execute("RESET SESSION AUTHORIZATION").await;
        out
    });
    assert!(
        seen_waiting(pool, act_pid, &act_task).await,
        "CALIBRATION: the act must wait on the holder's lock of the higher claim"
    );

    let mut public = pool.acquire().await.expect("acquire the publicizer");
    public
        .execute("SET SESSION AUTHORIZATION epigraph_app")
        .await
        .expect("the publicizer's role");
    let publicize_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *public)
        .await
        .expect("the publicizer's pid");
    let publicize_task = tokio::spawn(async move {
        let run = async {
            public.execute("BEGIN").await?;
            public.execute("SET LOCAL lock_timeout = '30s'").await?;
            sqlx::query(
                "SELECT set_config('epigraph.principal_id', $1, true), \
                        set_config('epigraph.group_ids', $2, true), \
                        set_config('epigraph.writable_group_ids', $2, true)",
            )
            .bind(publicizer.to_string())
            .bind(readable.to_string())
            .execute(&mut *public)
            .await?;
            let outcomes: Vec<(Uuid, String)> = sqlx::query_as(
                "SELECT claim_id, outcome \
                   FROM public.epigraph_publicize_claims(ARRAY[$1, $2]::uuid[], 'd1818fd0')",
            )
            .bind(lo)
            .bind(hi)
            .fetch_all(&mut *public)
            .await?;
            public.execute("COMMIT").await?;
            Ok::<_, sqlx::Error>(outcomes)
        };
        let out = run.await.map_err(|e| e.to_string());
        if out.is_err() {
            let _ = public.execute("ROLLBACK").await;
        }
        let _ = public.execute("RESET SESSION AUTHORIZATION").await;
        out
    });
    assert!(
        seen_waiting(pool, publicize_pid, &publicize_task).await,
        "CALIBRATION: the publicize must wait on a lock before the holder is released"
    );

    holder
        .execute("ROLLBACK")
        .await
        .expect("release the holder");
    let act = act_task.await.expect("the act's task");
    let publicize = publicize_task.await.expect("the publicize's task");
    let race = Race {
        act: act.map(|mut ids| {
            ids.sort();
            ids
        }),
        publicize: publicize.map(|mut o| {
            o.sort();
            o
        }),
    };
    for (who, err) in [
        ("the act", race.act.as_ref().err()),
        ("the publicize", race.publicize.as_ref().err()),
    ] {
        if let Some(e) = err {
            assert!(
                !e.contains("deadlock") && !e.contains("40P01"),
                "{who} was aborted by a lock-order deadlock: {e}"
            );
        }
    }
    race
}

/// Backlog d1818fd0: the real `seal_claims_conn`, handed `[hi, lo]`, beside
/// 206's publicize of `[lo, hi]`. Both commit; the publicize, serialized
/// after the seal, refuses both sealed claims.
#[sqlx::test(migrations = "../../migrations")]
async fn a_multi_claim_seal_and_publicize_in_opposite_orders_do_not_deadlock(pool: PgPool) {
    let (author, group) = seal_group(&pool).await;
    let pair = descending_pair(&pool, author, group).await;
    let (lo, hi) = pair;
    let race = opposite_order_race(&pool, Act::Seal { group }, pair, author, group).await;
    assert_eq!(race.act, Ok(vec![lo, hi]), "the seal seals both claims");
    assert_eq!(
        race.publicize,
        Ok(vec![
            (lo, "refused_sealed".to_string()),
            (hi, "refused_sealed".to_string())
        ]),
        "the publicize, serialized after the seal, refuses both sealed claims"
    );
    let public_and_sealed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims c \
          WHERE c.id = ANY($1) AND c.visibility = 'public' \
            AND EXISTS (SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = c.id)",
    )
    .bind(vec![lo, hi])
    .fetch_one(&pool)
    .await
    .expect("read the end state");
    assert_eq!(public_and_sealed, 0, "no claim ends public and sealed");
}

/// The unseal path: `unseal_claims_conn`, handed `[hi, lo]`, beside 206's
/// publicize of the same (sealed) claims `[lo, hi]`. 206 locks a sealed group
/// claim before classifying it, so the two contend. Both commit; the
/// publicize, serialized after the unseal, finds plain group claims and
/// publicizes them.
#[sqlx::test(migrations = "../../migrations")]
async fn a_multi_claim_unseal_and_publicize_in_opposite_orders_do_not_deadlock(pool: PgPool) {
    use epigraph_db::repos::privatization::PrivatizationRepository;

    let (author, group) = seal_group(&pool).await;
    let pair = descending_pair(&pool, author, group).await;
    let (lo, hi) = pair;
    // Sealed one at a time, `hi` first: the seal rewrites each claim row, so
    // this leaves `hi`'s new version ahead of `lo`'s in the heap, the order
    // a scan of the unseal's join meets them in.
    for claim in [hi, lo] {
        let mut tx = pool.begin().await.expect("begin the seal");
        let sealed =
            PrivatizationRepository::seal_claims_conn(&mut tx, group, 0, &[seal_item(claim)], None)
                .await
                .expect("seal the claim first");
        tx.commit().await.expect("commit the seal");
        assert_eq!(sealed, vec![claim], "CALIBRATION: the claim is sealed");
    }

    let race = opposite_order_race(&pool, Act::Unseal { group }, pair, author, group).await;
    assert_eq!(
        race.act,
        Ok(vec![lo, hi]),
        "the unseal restores both claims"
    );
    assert_eq!(
        race.publicize,
        Ok(vec![
            (lo, "publicized".to_string()),
            (hi, "publicized".to_string())
        ]),
        "the publicize, serialized after the unseal, publicizes both restored claims"
    );
}

/// The apply path: `restrict_claims_conn`, handed `[hi, lo]`, moving two
/// claims of the publicizer's group into another group, beside 206's
/// publicize of `[lo, hi]` by that group's admin. Both commit; the restrict
/// moves both claims.
#[sqlx::test(migrations = "../../migrations")]
async fn a_multi_claim_restrict_and_publicize_in_opposite_orders_do_not_deadlock(pool: PgPool) {
    let (author, group) = seal_group(&pool).await;
    let (_, target) = seal_group(&pool).await;
    let pair = descending_pair(&pool, author, group).await;
    let (lo, hi) = pair;
    let race = opposite_order_race(&pool, Act::Restrict { target }, pair, author, group).await;
    assert_eq!(race.act, Ok(vec![lo, hi]), "the restrict moves both claims");
    assert!(race.publicize.is_ok(), "{:?}", race.publicize);
    let moved: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE id = ANY($1) \
            AND visibility = 'group' AND owner_group_id = $2",
    )
    .bind(vec![lo, hi])
    .bind(target)
    .fetch_one(&pool)
    .await
    .expect("read the end state");
    assert_eq!(moved, 2, "both claims end in the target group");
}

/// The revert path: `restore_claims_conn`, handed `[hi, lo]`, moving two
/// claims of the publicizer's group back to the group a plan recorded,
/// beside 206's publicize of `[lo, hi]` by the current group's admin. Both
/// commit; the restore moves both claims.
#[sqlx::test(migrations = "../../migrations")]
async fn a_multi_claim_restore_and_publicize_in_opposite_orders_do_not_deadlock(pool: PgPool) {
    let (author, target) = seal_group(&pool).await;
    let (_, before) = seal_group(&pool).await;
    let pair = descending_pair(&pool, author, target).await;
    let (lo, hi) = pair;
    // The plan and its items are FIXTURE rows: 081's plan guards (target
    // age, a quorum of other live admins) are not what this test is about, so
    // they are seeded with triggers off, in one superuser transaction. Every
    // id they name is real.
    let mut tx = pool.begin().await.expect("begin the plan fixture");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("fixture rows without the plan guards");
    let plan: Uuid = sqlx::query_scalar(
        "INSERT INTO privatization_plans (mode, target_group_id, selector, created_by) \
         VALUES ('restrict', $1, '{}'::jsonb, $2) RETURNING id",
    )
    .bind(target)
    .bind(author)
    .fetch_one(&mut *tx)
    .await
    .expect("a plan");
    sqlx::query(
        "INSERT INTO privatization_plan_items (plan_id, kind, entity_id, depth, via, \
             before_visibility, before_owner_group_id, before_had_embedding) \
         SELECT $1, 'claim', id, 0, 'seed', 'group', $2, false FROM claims WHERE id = ANY($3)",
    )
    .bind(plan)
    .bind(before)
    .bind(vec![hi, lo])
    .execute(&mut *tx)
    .await
    .expect("the plan's items");
    tx.commit().await.expect("commit the plan fixture");

    let race =
        opposite_order_race(&pool, Act::Restore { plan, target }, pair, author, target).await;
    assert_eq!(
        race.act.as_ref().map(Vec::len),
        Ok(2),
        "the restore moves both claims: {:?}",
        race.act
    );
    assert!(race.publicize.is_ok(), "{:?}", race.publicize);
    let restored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE id = ANY($1) \
            AND visibility = 'group' AND owner_group_id = $2",
    )
    .bind(vec![lo, hi])
    .bind(before)
    .fetch_one(&pool)
    .await
    .expect("read the end state");
    assert_eq!(restored, 2, "both claims end in the recorded group");
}
