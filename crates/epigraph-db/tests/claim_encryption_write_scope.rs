//! Migration 232 (backlog candidate B90-claim-encryption-write-scope): a
//! `claim_encryption` row is bound to its claim's owner group.
//!
//! # The defect
//!
//! 077's `claim_encryption_tenancy` policy is `FOR ALL` with WITH CHECK
//! `group_id = ANY (epigraph_writable_groups())`. It checks the SEALING group
//! and never the claim. So an application session that writes group A could
//! insert a ciphertext row, keyed under A, for a claim group B owns:
//!
//!   * a claim it cannot even read (the PRV01 trigger's read finds no row, so
//!     it admits, and the FK check ignores row security);
//!   * a claim it reads but cannot write;
//!   * a claim of another group it also writes, sealed under the wrong key.
//!
//! `claim_encryption` is keyed by `claim_id`, so that row squats on the claim:
//! the owner's own seal (`INSERT … ON CONFLICT (claim_id) DO NOTHING`) then
//! silently seals nothing, and the owner's sessions cannot see the row to
//! remove it. The same held for an UPDATE that moves an own row's `claim_id`
//! or `group_id` onto another group's claim.
//!
//! # What is pinned
//!
//! [`a_seal_is_bound_to_the_claims_owner_group`]: as `epigraph_app` with row
//! security on, each of the three cross-group INSERTs is ADMITTED below 232 (the
//! calibration: this is the defect) and REFUSED with 42501 at head; sealing
//! the session's own group claim under its own group is admitted at both.
//!
//! [`a_seal_row_cannot_be_moved_onto_another_groups_claim`]: the UPDATE
//! direction. Moving an own row's `claim_id` to another group's claim, or its
//! `group_id` to another writable group, is admitted below 232 and refused at
//! head; rewriting an own row's ciphertext is admitted at both.
//!
//! [`a_claim_created_and_sealed_in_one_app_transaction_is_admitted`]: the
//! shipped `POST /claims` fully_private shape (INSERT the claim, then seal it,
//! in one application-role transaction) is admitted below 232 and at head.
//!
//! [`the_232_undo_returns_the_policies_below_232`]: 232 adds exactly its two
//! policies, and the undo runbook removes exactly them, idempotently.
//!
//! # Verified to fail
//!
//! - Every head assertion of the first two tests fails with 232 absent (the
//!   branch was written test-first and run before the migration existed).
//! - 232's predicate weakened to the sketch's "the claim's owner group is in
//!   the writable set" (`c.owner_group_id = ANY (writable)` in place of
//!   `c.owner_group_id = claim_encryption.group_id`): the writer-of-both case
//!   and the `group_id` move are admitted.
//! - The FOR UPDATE policy dropped from 232: both UPDATE cases are admitted.
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is
//! not extended.

mod viewer_fixture;

use sqlx::migrate::Migrator;
use sqlx::{Executor, PgPool};
use std::borrow::Cow;
use std::collections::BTreeSet;
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// Everything below 232 (229 on this branch's base; 230 and 231 are other
/// open PRs and touch no `claim_encryption` policy).
const BELOW: i64 = 231;

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

/// A team group with an active key epoch 0, administered by a fresh agent:
/// `(agent, group)`.
async fn team(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    let (agent, _) = viewer_fixture::seed_agent_with_group(pool, label).await;
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, status, \
                             created_by_agent_id) \
         VALUES ($1, 'did:epigraph:team:' || gen_random_uuid()::text, \
                 decode(repeat('ab', 32), 'hex'), 'team', 'active', $2) \
         RETURNING id",
    )
    .bind(label)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed team group");
    join(pool, group, agent, "admin").await;
    sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active')")
        .bind(group)
        .execute(pool)
        .await
        .expect("seed key epoch");
    (agent, group)
}

async fn join(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, $3)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed membership");
}

/// An application session's identity: the GUCs the route stamps.
struct Session {
    principal: Uuid,
    read: Vec<Uuid>,
    write: Vec<Uuid>,
}

fn csv(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Run `sql` (binding `binds` in order) as `epigraph_app` under `s`, in one
/// committed transaction. `Err` is the database's message, with its SQLSTATE.
async fn app_write(
    pool: &PgPool,
    s: &Session,
    sql: &'static str,
    binds: Vec<Uuid>,
) -> Result<u64, String> {
    let principal = s.principal.to_string();
    let read = csv(&s.read);
    let write = csv(&s.write);
    viewer_fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        let run = async {
            conn.execute("BEGIN").await?;
            sqlx::query(
                "SELECT set_config('epigraph.principal_id', $1, true), \
                        set_config('epigraph.group_ids', $2, true), \
                        set_config('epigraph.writable_group_ids', $3, true)",
            )
            .bind(&principal)
            .bind(&read)
            .bind(&write)
            .execute(&mut *conn)
            .await?;
            let mut q = sqlx::query(sql);
            for b in &binds {
                q = q.bind(*b);
            }
            let n = q.execute(&mut *conn).await?.rows_affected();
            conn.execute("COMMIT").await?;
            Ok::<u64, sqlx::Error>(n)
        };
        let out = run.await.map_err(|e| match &e {
            sqlx::Error::Database(d) => {
                format!("{} [{}]", d.message(), d.code().unwrap_or_default())
            }
            _ => e.to_string(),
        });
        if out.is_err() {
            let _ = conn.execute("ROLLBACK").await;
        }
        (conn, out)
    })
    .await
}

/// The seal INSERT as `ClaimEncryptionRepository::insert_conn` writes it.
const SEAL: &str = "INSERT INTO claim_encryption \
                        (claim_id, group_id, epoch, privacy_tier, encrypted_content) \
                    VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea)";

async fn sealed_under(pool: &PgPool, claim: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT group_id FROM claim_encryption WHERE claim_id = $1")
        .bind(claim)
        .fetch_optional(pool)
        .await
        .expect("read the seal row")
}

fn assert_row_security_refusal(at: &str, case: &str, r: &Result<u64, String>) {
    match r {
        Err(e) if e.contains("row-level security") && e.contains("[42501]") => {}
        other => panic!("(at {at}) {case}: expected a 42501 row-security refusal, got {other:?}"),
    }
}

/// The three cross-group seals, and the own-group control, on fresh claims at
/// each stage. Returns nothing; asserts per stage.
#[sqlx::test(migrations = false)]
async fn a_seal_is_bound_to_the_claims_owner_group(pool: PgPool) {
    for (at, migrator, head) in [
        ("below 232", up_to(BELOW), false),
        ("head", up_to(i64::MAX), true),
    ] {
        migrate(&pool, &migrator).await;
        let (a, group_a) = team(&pool, "seal-scope-a").await;
        let (b, group_b) = team(&pool, "seal-scope-b").await;
        let writer_of_a = Session {
            principal: a,
            read: vec![group_a],
            write: vec![group_a],
        };

        // CONTROL: the shipped shape. The owner group seals its own claim.
        let own = viewer_fixture::seed_group_claim(&pool, a, group_a, "own").await;
        let r = app_write(&pool, &writer_of_a, SEAL, vec![own, group_a]).await;
        assert_eq!(r, Ok(1), "(at {at}) a writer seals its own group's claim");
        assert_eq!(sealed_under(&pool, own).await, Some(group_a));

        // (a) A claim the session cannot read.
        let hidden = viewer_fixture::seed_group_claim(&pool, b, group_b, "hidden").await;
        let r = app_write(&pool, &writer_of_a, SEAL, vec![hidden, group_a]).await;
        if head {
            assert_row_security_refusal(at, "sealing a claim the session cannot read", &r);
            assert_eq!(sealed_under(&pool, hidden).await, None);
        } else {
            assert_eq!(
                r,
                Ok(1),
                "CALIBRATION (at {at}): a writer of A seals B's unreadable claim under A"
            );
            assert_eq!(sealed_under(&pool, hidden).await, Some(group_a));
        }

        // (b) A claim the session reads (a reader of B) but cannot write.
        join(&pool, group_b, a, "reader").await;
        let reader_of_b = Session {
            principal: a,
            read: vec![group_a, group_b],
            write: vec![group_a],
        };
        let readable = viewer_fixture::seed_group_claim(&pool, b, group_b, "readable").await;
        let r = app_write(&pool, &reader_of_b, SEAL, vec![readable, group_a]).await;
        if head {
            assert_row_security_refusal(at, "sealing a readable, unwritable claim", &r);
            assert_eq!(sealed_under(&pool, readable).await, None);
        } else {
            assert_eq!(
                r,
                Ok(1),
                "CALIBRATION (at {at}): a reader of B seals B's claim under A"
            );
        }

        // (c) A writer of BOTH groups seals B's claim under A's key. The owner's
        //     other members hold no share of A's key.
        let (c, _) = viewer_fixture::seed_agent_with_group(&pool, "seal-scope-c").await;
        join(&pool, group_a, c, "writer").await;
        join(&pool, group_b, c, "writer").await;
        let writer_of_both = Session {
            principal: c,
            read: vec![group_a, group_b],
            write: vec![group_a, group_b],
        };
        let wrong_key = viewer_fixture::seed_group_claim(&pool, b, group_b, "wrong key").await;
        let r = app_write(&pool, &writer_of_both, SEAL, vec![wrong_key, group_a]).await;
        if head {
            assert_row_security_refusal(at, "sealing B's claim under A's key", &r);
            assert_eq!(sealed_under(&pool, wrong_key).await, None);
            // The same writer sealing the same claim under its OWNER's group
            // is the shipped shape and is admitted.
            let r = app_write(&pool, &writer_of_both, SEAL, vec![wrong_key, group_b]).await;
            assert_eq!(r, Ok(1), "(at {at}) sealing B's claim under B is admitted");
            assert_eq!(sealed_under(&pool, wrong_key).await, Some(group_b));
        } else {
            assert_eq!(
                r,
                Ok(1),
                "CALIBRATION (at {at}): a writer of both seals B's claim under A"
            );
        }

        // A seal squatting on B's claim (the 229 state of case (a)) makes the
        // owner's redeliverable seal a silent no-op. Pinned at 229 only, as
        // the consequence the head refusal prevents.
        if !head {
            let owner = Session {
                principal: b,
                read: vec![group_b],
                write: vec![group_b],
            };
            let r = app_write(
                &pool,
                &owner,
                "INSERT INTO claim_encryption \
                     (claim_id, group_id, epoch, privacy_tier, encrypted_content) \
                 VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea) \
                 ON CONFLICT (claim_id) DO NOTHING",
                vec![hidden, group_b],
            )
            .await;
            assert_eq!(
                r,
                Ok(0),
                "CALIBRATION (at {at}): the owner's own seal of a squatted claim writes nothing"
            );
        }
    }
}

/// The UPDATE direction: an own seal row moved onto another group's claim or
/// re-keyed to another writable group.
#[sqlx::test(migrations = false)]
async fn a_seal_row_cannot_be_moved_onto_another_groups_claim(pool: PgPool) {
    for (at, migrator, head) in [
        ("below 232", up_to(BELOW), false),
        ("head", up_to(i64::MAX), true),
    ] {
        migrate(&pool, &migrator).await;
        let (a, group_a) = team(&pool, "seal-move-a").await;
        let (b, group_b) = team(&pool, "seal-move-b").await;
        join(&pool, group_b, a, "writer").await;
        let writer_of_a = Session {
            principal: a,
            read: vec![group_a],
            write: vec![group_a],
        };
        let writer_of_both = Session {
            principal: a,
            read: vec![group_a, group_b],
            write: vec![group_a, group_b],
        };

        // CONTROL: rewriting an own row's ciphertext.
        let own = viewer_fixture::seed_group_claim(&pool, a, group_a, "own").await;
        assert_eq!(
            app_write(&pool, &writer_of_a, SEAL, vec![own, group_a]).await,
            Ok(1)
        );
        let r = app_write(
            &pool,
            &writer_of_a,
            "UPDATE claim_encryption SET encrypted_content = '\\x01'::bytea WHERE claim_id = $1",
            vec![own],
        )
        .await;
        assert_eq!(r, Ok(1), "(at {at}) a writer rewrites its own seal row");

        // Move the row onto B's claim, which A cannot read.
        let theirs = viewer_fixture::seed_group_claim(&pool, b, group_b, "theirs").await;
        let r = app_write(
            &pool,
            &writer_of_a,
            "UPDATE claim_encryption SET claim_id = $2 WHERE claim_id = $1",
            vec![own, theirs],
        )
        .await;
        if head {
            assert_row_security_refusal(at, "moving a seal row onto B's claim", &r);
            assert_eq!(sealed_under(&pool, theirs).await, None);
            assert_eq!(sealed_under(&pool, own).await, Some(group_a));
        } else {
            assert_eq!(
                r,
                Ok(1),
                "CALIBRATION (at {at}): an own seal row moves onto B's claim"
            );
            assert_eq!(sealed_under(&pool, theirs).await, Some(group_a));
        }

        // Re-key an own row to another group the session writes.
        let own2 = viewer_fixture::seed_group_claim(&pool, a, group_a, "own2").await;
        assert_eq!(
            app_write(&pool, &writer_of_both, SEAL, vec![own2, group_a]).await,
            Ok(1)
        );
        let r = app_write(
            &pool,
            &writer_of_both,
            "UPDATE claim_encryption SET group_id = $2 WHERE claim_id = $1",
            vec![own2, group_b],
        )
        .await;
        if head {
            assert_row_security_refusal(at, "re-keying A's seal row to B", &r);
            assert_eq!(sealed_under(&pool, own2).await, Some(group_a));
        } else {
            assert_eq!(
                r,
                Ok(1),
                "CALIBRATION (at {at}): an own seal row re-keys to another writable group"
            );
        }
    }
}

/// The shipped writer's shape, end to end on the application role: one
/// transaction INSERTs the group claim (`ClaimRepository::create_strict`'s
/// `INSERT … RETURNING`) and then seals it under the same group
/// (`ClaimEncryptionRepository::insert_conn`), before anything commits.
///
/// The control in [`a_seal_is_bound_to_the_claims_owner_group`] seals a claim
/// a superuser seeded and COMMITTED earlier, which is not how `POST /claims`
/// with `fully_private` runs. 232's `EXISTS` reads `claims` under the caller's
/// row security in the caller's snapshot; if that read could not see the
/// caller's own just-inserted, not-yet-sealed claim, every legitimate
/// fully_private create would be refused while the committed-claim control
/// still passed. This pins the admitted shape.
///
/// Verified to fail: with 232's INSERT predicate mutated to also require
/// `c.created_at < now()` (a stand-in for any predicate that hides a claim
/// created in the current transaction), this test is refused 42501 while the
/// committed-claim controls in the other tests still pass.
#[sqlx::test(migrations = false)]
async fn a_claim_created_and_sealed_in_one_app_transaction_is_admitted(pool: PgPool) {
    for (at, migrator) in [("below 232", up_to(BELOW)), ("head", up_to(i64::MAX))] {
        migrate(&pool, &migrator).await;
        let (a, group_a) = team(&pool, "seal-create-a").await;
        let principal = a.to_string();
        let groups = group_a.to_string();
        let out: Result<Uuid, String> =
            viewer_fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
                let run = async {
                    conn.execute("BEGIN").await?;
                    sqlx::query(
                        "SELECT set_config('epigraph.principal_id', $1, true), \
                                set_config('epigraph.group_ids', $2, true), \
                                set_config('epigraph.writable_group_ids', $2, true)",
                    )
                    .bind(&principal)
                    .bind(&groups)
                    .execute(&mut *conn)
                    .await?;
                    let id: Uuid = sqlx::query_scalar(
                        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                                             is_current, visibility, owner_group_id) \
                         VALUES (gen_random_uuid(), 'created and sealed', \
                                 decode(md5(gen_random_uuid()::text) || \
                                        md5(gen_random_uuid()::text), 'hex'), \
                                 0.8, $1, true, 'group', $2) \
                         RETURNING id",
                    )
                    .bind(a)
                    .bind(group_a)
                    .fetch_one(&mut *conn)
                    .await?;
                    sqlx::query(SEAL)
                        .bind(id)
                        .bind(group_a)
                        .execute(&mut *conn)
                        .await?;
                    conn.execute("COMMIT").await?;
                    Ok::<Uuid, sqlx::Error>(id)
                };
                let out = run.await.map_err(|e| match &e {
                    sqlx::Error::Database(d) => {
                        format!("{} [{}]", d.message(), d.code().unwrap_or_default())
                    }
                    _ => e.to_string(),
                });
                if out.is_err() {
                    let _ = conn.execute("ROLLBACK").await;
                }
                (conn, out)
            })
            .await;
        let id = out.unwrap_or_else(|e| {
            panic!(
                "(at {at}) the app role creates a group claim and seals it in one transaction: {e}"
            )
        });
        assert_eq!(
            sealed_under(&pool, id).await,
            Some(group_a),
            "(at {at}) the fresh claim is sealed under its owner group"
        );
    }
}

/// Every policy on `claim_encryption`, with its kind, command, roles and both
/// expressions.
async fn policies(pool: &PgPool) -> BTreeSet<String> {
    sqlx::query_scalar(
        "SELECT p.polname || ' ' || p.polcmd::text || ' ' || p.polpermissive::text || ' ' || \
                p.polroles::regrole[]::text || ' ' || \
                coalesce(pg_get_expr(p.polqual, p.polrelid), '-') || ' ' || \
                coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '-') \
           FROM pg_policy p WHERE p.polrelid = 'public.claim_encryption'::regclass",
    )
    .fetch_all(pool)
    .await
    .expect("policies")
    .into_iter()
    .collect()
}

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[sqlx::test(migrations = false)]
async fn the_232_undo_returns_the_policies_below_232(pool: PgPool) {
    migrate(&pool, &up_to(BELOW)).await;
    let before = policies(&pool).await;
    migrate(&pool, &up_to(232)).await;
    let through = policies(&pool).await;
    let added: Vec<&str> = through
        .difference(&before)
        .map(|s| s.split(' ').next().unwrap_or_default())
        .collect();
    assert_eq!(
        (added, before.is_subset(&through)),
        (
            vec![
                "claim_encryption_owner_scope_insert",
                "claim_encryption_owner_scope_update"
            ],
            true
        ),
        "CALIBRATION: 232 adds exactly its two policies and changes no other"
    );

    let undo = repo_file("docs/runbooks/232-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        assert_eq!(
            policies(&pool).await,
            before,
            "after the {run} run the policies are exactly the ones below 232"
        );
    }
}
