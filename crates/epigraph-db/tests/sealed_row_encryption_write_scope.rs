//! Migration 233 (backlog candidate B102-other-encryption-tables): a
//! `claim_version_encryption`, `evidence_encryption` or `edge_encryption` row
//! is bound to the owner group of the row it seals.
//!
//! # The defect
//!
//! 077 gives each of the four ciphertext tables one `FOR ALL` policy,
//! `<table>_tenancy`, whose WITH CHECK is `group_id = ANY
//! (epigraph_writable_groups())`. It checks the SEALING group and never the
//! sealed row. 232 closed that for `claim_encryption`; the other three kept
//! it. So an application session that writes group A could insert a
//! ciphertext row, keyed under A, for a claim version, evidence row or edge
//! that group B owns:
//!
//!   * one it cannot even read (the FK check ignores row security);
//!   * one it reads but cannot write;
//!   * one of another group it also writes, sealed under the wrong key.
//!
//! Each table is keyed by the sealed row's id, so such a row squats on it:
//! the owner's privatization seal (`INSERT … ON CONFLICT (<id>) DO NOTHING`,
//! then blank the plaintext) writes no ciphertext under the owner's key, and
//! the owner's sessions cannot see the squatting row (077's USING is the
//! sealing group's read set). An UPDATE that moves an own row's key column or
//! `group_id` onto such a pair did the same.
//!
//! `claim_version_encryption` also carries a denormalized `claim_id`, which
//! nothing tied to the version's own claim: an own version's seal could name
//! another group's claim, which the ciphertext then follows on cascade and
//! which the operator tools read as "has a sealed version".
//!
//! # What is pinned
//!
//! [`a_seal_is_bound_to_the_sealed_rows_owner_group`]: as `epigraph_app` with
//! row security on, for each table, each cross-group INSERT is ADMITTED below
//! 233 (the calibration: this is the defect) and REFUSED with 42501 at head;
//! sealing the session's own group's row under its own group is admitted at
//! both. Below 233 it also pins the consequence: the owner's seal of a
//! squatted row, in the shape `seal_claims_conn` writes it, inserts nothing.
//!
//! [`a_seal_row_cannot_be_moved_onto_another_groups_row`]: the UPDATE
//! direction, per table. Moving an own row's key column (and, for versions,
//! `claim_id`) onto B's row, or its `group_id` to another writable group, is
//! admitted below 233 and refused at head; rewriting an own row's ciphertext
//! is admitted at both.
//!
//! [`the_233_undo_returns_the_policies_below_233`]: 233 adds exactly its six
//! policies across the three tables, and the undo runbook removes exactly
//! them, idempotently.
//!
//! # Verified to fail
//!
//! - With 233 absent, the first two tests fail at their first head assertion
//!   (the file was written and run before the migration existed), after every
//!   below-233 calibration, on all three tables, had passed.
//! - 233's `claim_version_encryption` predicate without its
//!   `v.claim_id = claim_version_encryption.claim_id` conjunct: the
//!   foreign-claim INSERT and the `claim_id` move are admitted.
//! - One table at a time (each of the three), the predicate weakened to "the
//!   owner group is in the writable set" (`owner_group_id = ANY (writable)` in
//!   place of `= group_id`): that table's writer-of-both INSERT and its
//!   `group_id` move are admitted.
//! - One table at a time, its FOR UPDATE policy dropped: that table's move
//!   onto B's row is admitted; its FOR INSERT policy dropped: that table's
//!   unreadable-row seal is admitted.
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

/// Everything below 233. Whether or not 232 (the `claim_encryption` half,
/// another PR) is present, it touches no policy on these three tables.
const BELOW: i64 = 232;

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

fn assert_row_security_refusal(at: &str, case: &str, r: &Result<u64, String>) {
    match r {
        Err(e) if e.contains("row-level security") && e.contains("[42501]") => {}
        other => panic!("(at {at}) {case}: expected a 42501 row-security refusal, got {other:?}"),
    }
}

/// One of the three ciphertext tables, with the SQL each case needs. Every
/// statement binds the sealed row's key first; `claim` is that row's claim
/// (bound only where the table carries `claim_id`).
#[derive(Clone, Copy)]
enum Table {
    ClaimVersion,
    Evidence,
    Edge,
}

const TABLES: [Table; 3] = [Table::ClaimVersion, Table::Evidence, Table::Edge];

/// A sealable row owned by a group: its key and the claim it hangs off.
#[derive(Clone, Copy)]
struct Target {
    id: Uuid,
    claim: Uuid,
}

impl Table {
    fn name(self) -> &'static str {
        match self {
            Table::ClaimVersion => "claim_version_encryption",
            Table::Evidence => "evidence_encryption",
            Table::Edge => "edge_encryption",
        }
    }

    /// A row of the owning table, owned (`visibility = 'group'`) by `group`,
    /// seeded on the superuser connection.
    async fn seed(self, pool: &PgPool, agent: Uuid, group: Uuid, label: &str) -> Target {
        let claim = viewer_fixture::seed_group_claim(pool, agent, group, label).await;
        let id = match self {
            // 070 arm (c): the version inherits the claim's tenancy.
            Table::ClaimVersion => sqlx::query_scalar(
                "INSERT INTO claim_versions (claim_id, version_number, content, truth_value) \
                 VALUES ($1, 1, 'v1', 0.5) RETURNING id",
            )
            .bind(claim)
            .fetch_one(pool)
            .await
            .expect("seed claim version"),
            // 070 arm (c): the evidence row inherits the claim's tenancy.
            Table::Evidence => viewer_fixture::seed_evidence(pool, claim, "document").await,
            Table::Edge => {
                let other = viewer_fixture::seed_group_claim(pool, agent, group, label).await;
                viewer_fixture::seed_edge_owned_by(pool, claim, other, "group", group).await
            }
        };
        let owner: Uuid = sqlx::query_scalar(match self {
            Table::ClaimVersion => "SELECT owner_group_id FROM claim_versions WHERE id = $1",
            Table::Evidence => "SELECT owner_group_id FROM evidence WHERE id = $1",
            Table::Edge => "SELECT owner_group_id FROM edges WHERE id = $1",
        })
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read the seeded row's owner");
        assert_eq!(
            owner,
            group,
            "{}: the seeded row is owned by its group",
            self.name()
        );
        Target { id, claim }
    }

    /// The seal INSERT, binds `(id, [claim,] group)`.
    fn seal(self) -> &'static str {
        match self {
            Table::ClaimVersion => {
                "INSERT INTO claim_version_encryption \
                     (claim_version_id, claim_id, group_id, epoch, encrypted_content) \
                 VALUES ($1, $2, $3, 0, '\\x00'::bytea)"
            }
            Table::Evidence => {
                "INSERT INTO evidence_encryption \
                     (evidence_id, group_id, epoch, privacy_tier, encrypted_content) \
                 VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea)"
            }
            Table::Edge => {
                "INSERT INTO edge_encryption \
                     (edge_id, group_id, epoch, privacy_tier, encrypted_labels) \
                 VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea)"
            }
        }
    }

    /// The privatization seal's redeliverable form, as `seal_claims_conn`
    /// writes it (on a bypassed connection), binds as [`Table::seal`].
    fn seal_on_conflict_do_nothing(self) -> String {
        let key = match self {
            Table::ClaimVersion => "claim_version_id",
            Table::Evidence => "evidence_id",
            Table::Edge => "edge_id",
        };
        format!("{} ON CONFLICT ({key}) DO NOTHING", self.seal())
    }

    fn seal_binds(self, t: Target, group: Uuid) -> Vec<Uuid> {
        match self {
            Table::ClaimVersion => vec![t.id, t.claim, group],
            Table::Evidence | Table::Edge => vec![t.id, group],
        }
    }

    /// Rewrite an own row's ciphertext, binds `(id)`.
    fn rewrite(self) -> &'static str {
        match self {
            Table::ClaimVersion => {
                "UPDATE claim_version_encryption SET encrypted_content = '\\x01'::bytea \
                 WHERE claim_version_id = $1"
            }
            Table::Evidence => {
                "UPDATE evidence_encryption SET encrypted_content = '\\x01'::bytea \
                 WHERE evidence_id = $1"
            }
            Table::Edge => {
                "UPDATE edge_encryption SET encrypted_labels = '\\x01'::bytea WHERE edge_id = $1"
            }
        }
    }

    /// Move an own row onto another row, binds `(own id, other id, other claim)`.
    fn move_onto(self) -> &'static str {
        match self {
            Table::ClaimVersion => {
                "UPDATE claim_version_encryption SET claim_version_id = $2, claim_id = $3 \
                 WHERE claim_version_id = $1"
            }
            Table::Evidence => {
                "UPDATE evidence_encryption SET evidence_id = $2 \
                 WHERE evidence_id = $1 AND $3::uuid IS NOT NULL"
            }
            Table::Edge => {
                "UPDATE edge_encryption SET edge_id = $2 \
                 WHERE edge_id = $1 AND $3::uuid IS NOT NULL"
            }
        }
    }

    /// Re-key an own row to another group, binds `(id, group)`.
    fn rekey(self) -> &'static str {
        match self {
            Table::ClaimVersion => {
                "UPDATE claim_version_encryption SET group_id = $2 WHERE claim_version_id = $1"
            }
            Table::Evidence => {
                "UPDATE evidence_encryption SET group_id = $2 WHERE evidence_id = $1"
            }
            Table::Edge => "UPDATE edge_encryption SET group_id = $2 WHERE edge_id = $1",
        }
    }

    /// The group a row is sealed under, read on the superuser connection.
    async fn sealed_under(self, pool: &PgPool, id: Uuid) -> Option<Uuid> {
        let sql = match self {
            Table::ClaimVersion => {
                "SELECT group_id FROM claim_version_encryption WHERE claim_version_id = $1"
            }
            Table::Evidence => "SELECT group_id FROM evidence_encryption WHERE evidence_id = $1",
            Table::Edge => "SELECT group_id FROM edge_encryption WHERE edge_id = $1",
        };
        sqlx::query_scalar(sql)
            .bind(id)
            .fetch_optional(pool)
            .await
            .expect("read the seal row")
    }
}

/// The cross-group seals, and the own-group control, on fresh rows of each
/// table at each stage.
#[sqlx::test(migrations = false)]
async fn a_seal_is_bound_to_the_sealed_rows_owner_group(pool: PgPool) {
    for (at, migrator, head) in [
        ("below 233", up_to(BELOW), false),
        ("head", up_to(i64::MAX), true),
    ] {
        migrate(&pool, &migrator).await;
        for table in TABLES {
            let tn = table.name();
            let (a, group_a) = team(&pool, "seal-scope-a").await;
            let (b, group_b) = team(&pool, "seal-scope-b").await;
            let writer_of_a = Session {
                principal: a,
                read: vec![group_a],
                write: vec![group_a],
            };

            // CONTROL: the owner group seals its own row under its own key.
            let own = table.seed(&pool, a, group_a, "own").await;
            let r = app_write(
                &pool,
                &writer_of_a,
                table.seal(),
                table.seal_binds(own, group_a),
            )
            .await;
            assert_eq!(
                r,
                Ok(1),
                "(at {at}) {tn}: a writer seals its own group's row"
            );
            assert_eq!(table.sealed_under(&pool, own.id).await, Some(group_a));

            // (a) A row the session cannot read.
            let hidden = table.seed(&pool, b, group_b, "hidden").await;
            let r = app_write(
                &pool,
                &writer_of_a,
                table.seal(),
                table.seal_binds(hidden, group_a),
            )
            .await;
            if head {
                assert_row_security_refusal(at, &format!("{tn}: sealing an unreadable row"), &r);
                assert_eq!(table.sealed_under(&pool, hidden.id).await, None);
            } else {
                assert_eq!(
                    r,
                    Ok(1),
                    "CALIBRATION (at {at}) {tn}: a writer of A seals B's unreadable row under A"
                );
                assert_eq!(table.sealed_under(&pool, hidden.id).await, Some(group_a));
                // The consequence: the owner's privatization seal of that row,
                // in the redeliverable form it ships in, writes no ciphertext
                // under the owner's key (and then blanks the plaintext).
                let owner_seal = table.seal_on_conflict_do_nothing();
                let n = sqlx::query(&owner_seal).bind(hidden.id);
                let n = match table {
                    Table::ClaimVersion => n.bind(hidden.claim),
                    Table::Evidence | Table::Edge => n,
                }
                .bind(group_b)
                .execute(&pool)
                .await
                .expect("owner's seal")
                .rows_affected();
                assert_eq!(
                    (n, table.sealed_under(&pool, hidden.id).await),
                    (0, Some(group_a)),
                    "CALIBRATION (at {at}) {tn}: the owner's seal of a squatted row writes nothing"
                );
            }

            // (b) A row the session reads (a reader of B) but cannot write.
            join(&pool, group_b, a, "reader").await;
            let reader_of_b = Session {
                principal: a,
                read: vec![group_a, group_b],
                write: vec![group_a],
            };
            let readable = table.seed(&pool, b, group_b, "readable").await;
            let r = app_write(
                &pool,
                &reader_of_b,
                table.seal(),
                table.seal_binds(readable, group_a),
            )
            .await;
            if head {
                assert_row_security_refusal(at, &format!("{tn}: sealing a read-only row"), &r);
                assert_eq!(table.sealed_under(&pool, readable.id).await, None);
            } else {
                assert_eq!(
                    r,
                    Ok(1),
                    "CALIBRATION (at {at}) {tn}: a reader of B seals B's row under A"
                );
            }

            // (c) A writer of BOTH groups seals B's row under A's key. B's other
            //     members hold no share of A's key.
            let (c, _) = viewer_fixture::seed_agent_with_group(&pool, "seal-scope-c").await;
            join(&pool, group_a, c, "writer").await;
            join(&pool, group_b, c, "writer").await;
            let writer_of_both = Session {
                principal: c,
                read: vec![group_a, group_b],
                write: vec![group_a, group_b],
            };
            let wrong_key = table.seed(&pool, b, group_b, "wrong key").await;
            let r = app_write(
                &pool,
                &writer_of_both,
                table.seal(),
                table.seal_binds(wrong_key, group_a),
            )
            .await;
            if head {
                assert_row_security_refusal(at, &format!("{tn}: sealing B's row under A"), &r);
                assert_eq!(table.sealed_under(&pool, wrong_key.id).await, None);
                // The same writer sealing the same row under its OWNER's group
                // is admitted.
                let r = app_write(
                    &pool,
                    &writer_of_both,
                    table.seal(),
                    table.seal_binds(wrong_key, group_b),
                )
                .await;
                assert_eq!(
                    r,
                    Ok(1),
                    "(at {at}) {tn}: sealing B's row under B is admitted"
                );
                assert_eq!(table.sealed_under(&pool, wrong_key.id).await, Some(group_b));
            } else {
                assert_eq!(
                    r,
                    Ok(1),
                    "CALIBRATION (at {at}) {tn}: a writer of both seals B's row under A"
                );
            }

            // (d) Versions only: an own version's seal naming another group's
            //     claim in its denormalized `claim_id`.
            if let Table::ClaimVersion = table {
                let mine = table.seed(&pool, a, group_a, "mine").await;
                let foreign = Target {
                    id: mine.id,
                    claim: hidden.claim,
                };
                let r = app_write(
                    &pool,
                    &writer_of_a,
                    table.seal(),
                    table.seal_binds(foreign, group_a),
                )
                .await;
                if head {
                    assert_row_security_refusal(
                        at,
                        &format!("{tn}: sealing an own version under B's claim_id"),
                        &r,
                    );
                    assert_eq!(table.sealed_under(&pool, mine.id).await, None);
                } else {
                    assert_eq!(
                        r,
                        Ok(1),
                        "CALIBRATION (at {at}) {tn}: an own version's seal names B's claim"
                    );
                }
            }
        }
    }
}

/// The UPDATE direction: an own seal row moved onto another group's row or
/// re-keyed to another writable group.
#[sqlx::test(migrations = false)]
async fn a_seal_row_cannot_be_moved_onto_another_groups_row(pool: PgPool) {
    for (at, migrator, head) in [
        ("below 233", up_to(BELOW), false),
        ("head", up_to(i64::MAX), true),
    ] {
        migrate(&pool, &migrator).await;
        for table in TABLES {
            let tn = table.name();
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
            let own = table.seed(&pool, a, group_a, "own").await;
            assert_eq!(
                app_write(
                    &pool,
                    &writer_of_a,
                    table.seal(),
                    table.seal_binds(own, group_a)
                )
                .await,
                Ok(1)
            );
            let r = app_write(&pool, &writer_of_a, table.rewrite(), vec![own.id]).await;
            assert_eq!(
                r,
                Ok(1),
                "(at {at}) {tn}: a writer rewrites its own seal row"
            );

            // Move the row onto B's row, which A cannot read.
            let theirs = table.seed(&pool, b, group_b, "theirs").await;
            let r = app_write(
                &pool,
                &writer_of_a,
                table.move_onto(),
                vec![own.id, theirs.id, theirs.claim],
            )
            .await;
            if head {
                assert_row_security_refusal(at, &format!("{tn}: moving a seal row onto B's"), &r);
                assert_eq!(table.sealed_under(&pool, theirs.id).await, None);
                assert_eq!(table.sealed_under(&pool, own.id).await, Some(group_a));
            } else {
                assert_eq!(
                    r,
                    Ok(1),
                    "CALIBRATION (at {at}) {tn}: an own seal row moves onto B's row"
                );
                assert_eq!(table.sealed_under(&pool, theirs.id).await, Some(group_a));
            }

            // Re-key an own row to another group the session writes.
            let own2 = table.seed(&pool, a, group_a, "own2").await;
            assert_eq!(
                app_write(
                    &pool,
                    &writer_of_both,
                    table.seal(),
                    table.seal_binds(own2, group_a)
                )
                .await,
                Ok(1)
            );
            let r = app_write(
                &pool,
                &writer_of_both,
                table.rekey(),
                vec![own2.id, group_b],
            )
            .await;
            if head {
                assert_row_security_refusal(at, &format!("{tn}: re-keying A's row to B"), &r);
                assert_eq!(table.sealed_under(&pool, own2.id).await, Some(group_a));
            } else {
                assert_eq!(
                    r,
                    Ok(1),
                    "CALIBRATION (at {at}) {tn}: an own seal row re-keys to another writable group"
                );
            }

            // Versions only: point an own version's seal at B's claim.
            if let Table::ClaimVersion = table {
                let own3 = table.seed(&pool, a, group_a, "own3").await;
                assert_eq!(
                    app_write(
                        &pool,
                        &writer_of_a,
                        table.seal(),
                        table.seal_binds(own3, group_a)
                    )
                    .await,
                    Ok(1)
                );
                let r = app_write(
                    &pool,
                    &writer_of_a,
                    "UPDATE claim_version_encryption SET claim_id = $2 \
                     WHERE claim_version_id = $1",
                    vec![own3.id, theirs.claim],
                )
                .await;
                if head {
                    assert_row_security_refusal(
                        at,
                        &format!("{tn}: pointing an own version's seal at B's claim"),
                        &r,
                    );
                } else {
                    assert_eq!(
                        r,
                        Ok(1),
                        "CALIBRATION (at {at}) {tn}: an own version's seal moves to B's claim"
                    );
                }
            }
        }
    }
}

/// Every policy on the three tables, with its table, kind, command, roles
/// and both expressions.
async fn policies(pool: &PgPool) -> BTreeSet<String> {
    sqlx::query_scalar(
        "SELECT p.polrelid::regclass::text || ' ' || p.polname || ' ' || p.polcmd::text || ' ' || \
                p.polpermissive::text || ' ' || p.polroles::regrole[]::text || ' ' || \
                coalesce(pg_get_expr(p.polqual, p.polrelid), '-') || ' ' || \
                coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '-') \
           FROM pg_policy p \
          WHERE p.polrelid IN ('public.claim_version_encryption'::regclass, \
                               'public.evidence_encryption'::regclass, \
                               'public.edge_encryption'::regclass)",
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
async fn the_233_undo_returns_the_policies_below_233(pool: PgPool) {
    migrate(&pool, &up_to(BELOW)).await;
    let before = policies(&pool).await;
    migrate(&pool, &up_to(233)).await;
    let through = policies(&pool).await;
    let added: Vec<String> = through
        .difference(&before)
        .map(|s| s.split(' ').take(2).collect::<Vec<_>>().join(" "))
        .collect();
    assert_eq!(
        (added, before.is_subset(&through)),
        (
            vec![
                "claim_version_encryption claim_version_encryption_owner_scope_insert".to_string(),
                "claim_version_encryption claim_version_encryption_owner_scope_update".to_string(),
                "edge_encryption edge_encryption_owner_scope_insert".to_string(),
                "edge_encryption edge_encryption_owner_scope_update".to_string(),
                "evidence_encryption evidence_encryption_owner_scope_insert".to_string(),
                "evidence_encryption evidence_encryption_owner_scope_update".to_string(),
            ],
            true
        ),
        "CALIBRATION: 233 adds exactly its six policies and changes no other"
    );

    let undo = repo_file("docs/runbooks/233-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        assert_eq!(
            policies(&pool).await,
            before,
            "after the {run} run the policies are exactly the ones below 233"
        );
    }
}
