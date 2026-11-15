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
//! Both sides run as `epigraph_maintenance`, the role the shipped seal
//! (`seal_claims_conn`, on a maintenance connection) and 206's publicize body
//! write as.
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
//! [`every_role_that_may_seal_may_lock_the_claim_row`]: `FOR SHARE` needs
//! UPDATE on `claims`, so a role that may write `claim_encryption` without it
//! would have every seal turned into a permission error.
//!
//! [`the_app_role_seal_check_refuses_what_176_refused`]: on the application
//! role (row security on), sealing its own group claim succeeds and sealing a
//! public claim is refused with PRV01, at 226 and at 227 alike.
//!
//! [`the_227_undo_returns_the_catalog_below_227`]: the undo runbook restores
//! 176's body (whole definition by md5) and is idempotent.
//!
//! # Verified to fail
//!
//! With `FOR SHARE OF c` removed from 227's locked read, the 227 half of the
//! race test fails: B never waits and both writes commit.
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

#[derive(Clone, Copy, Debug)]
enum First {
    Publicize,
    Seal,
}

/// Run one write (`seal` or publicize) inside `conn`'s open transaction.
async fn write(
    conn: &mut sqlx::PgConnection,
    seal: bool,
    claim: Uuid,
    group: Uuid,
) -> Result<(), sqlx::Error> {
    if seal {
        sqlx::query(SEAL)
            .bind(claim)
            .bind(group)
            .execute(&mut *conn)
            .await?;
    } else {
        sqlx::query(ARM_DECLASSIFY).execute(&mut *conn).await?;
        sqlx::query(PUBLICIZE)
            .bind(claim)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

struct Outcome {
    /// B was observed waiting on a lock before A committed.
    waited: bool,
    /// B's write and commit, as the error text on failure.
    second: Result<(), String>,
    /// The end state: the claim is public AND carries a ciphertext row.
    public_and_sealed: bool,
}

/// A: the `first` write, left open. B: the other write in its own transaction,
/// in a task. Commit A once B finished or is seen waiting on a lock.
async fn race(pool: &PgPool, first: First, claim: Uuid, group: Uuid) -> Outcome {
    let mut a = pool.acquire().await.expect("acquire A");
    a.execute(format!("SET SESSION AUTHORIZATION {MAINTENANCE}").as_str())
        .await
        .expect("A as maintenance");
    a.execute("BEGIN").await.expect("begin A");
    write(&mut a, matches!(first, First::Seal), claim, group)
        .await
        .unwrap_or_else(|e| panic!("A ({first:?}) applies on its own: {e}"));

    let mut b = pool.acquire().await.expect("acquire B");
    b.execute(format!("SET SESSION AUTHORIZATION {MAINTENANCE}").as_str())
        .await
        .expect("B as maintenance");
    let b_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *b)
        .await
        .expect("B's pid");
    let second_is_seal = matches!(first, First::Publicize);
    let task = tokio::spawn(async move {
        let run = async {
            b.execute("BEGIN").await?;
            b.execute("SET LOCAL lock_timeout = '30s'").await?;
            write(&mut b, second_is_seal, claim, group).await?;
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
    for first in [First::Publicize, First::Seal] {
        let claim = viewer_fixture::seed_group_claim(&pool, author, group, "a claim").await;
        let out = race(&pool, first, claim, group).await;
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

    for (first, refusal) in [
        (First::Publicize, "PRV01:"),
        (First::Seal, "is SEALED and cannot be made public"),
    ] {
        let claim = viewer_fixture::seed_group_claim(&pool, author, group, "a claim").await;
        let out = race(&pool, first, claim, group).await;
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
         (FOR SHARE needs UPDATE), so 227 would refuse every seal they make: \
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
