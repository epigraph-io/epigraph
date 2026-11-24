//! Migration 238 (backlog b5f6883b): 074's sealed-claim widening guard reads
//! `claim_encryption` with definer rights, so a caller that cannot see the
//! ciphertext row cannot make the sealed claim public.
//!
//! # The defect
//!
//! 074's `epigraph_claims_block_widening` (BEFORE UPDATE OF visibility on
//! `claims`) refuses `visibility = 'public'` while a `claim_encryption` row
//! exists for the claim. The body was SECURITY INVOKER, so its
//! `EXISTS (SELECT 1 FROM claim_encryption ...)` ran under the CALLER's row
//! security. `claim_encryption` is FORCEd under 077 section 5's policy, which
//! shows a row only to a session whose read set holds the row's `group_id`.
//! An application-role session that writes the claim's owner group but is
//! not in the group the ciphertext is keyed to saw no row, and was admitted:
//! a raw `UPDATE claims SET visibility = 'public'` (with the self-settable
//! declassify GUC armed) committed a PUBLIC claim whose content is the seal
//! sentinel. 232 stops NEW seal rows from diverging from the claim's owner
//! group on the application role, but it repairs no existing row, and the
//! maintenance role and definer bodies bypass it.
//!
//! # What is pinned
//!
//! [`a_non_member_of_the_ciphertext_group_cannot_publicize_a_sealed_claim`]:
//! as `epigraph_app` with row security on, a writer of the claim's owner group
//! outside the seal row's group publicizes the sealed claim. Below 238 the
//! UPDATE moves exactly one row and the claim ends public and sealed (the
//! calibration: this is the defect). At 238 it is refused 42501 with 074's
//! SEALED text and the claim stays `group`.
//!
//! [`the_definer_body_keeps_every_other_answer_of_074`] (a non-regression
//! check that passes below 238 by design): a member of the ciphertext group
//! is refused by the SEALED arm, an unsealed claim with the declassify GUC is
//! admitted, and a group -> public UPDATE without the GUC is refused by arm
//! (b), below 238 and at 238 alike. Arm (b) reads a session GUC, which the
//! definer frame must not change.
//!
//! [`migration_238_makes_the_body_a_pinned_maintenance_definer`]: the
//! catalog shape (SECURITY DEFINER, `search_path = pg_catalog, pg_temp`,
//! owned by `epigraph_maintenance`, EXECUTE held by no application role).
//!
//! [`migration_238_refuses_to_apply_over_another_body`]: the md5 guard.
//!
//! [`the_238_undo_returns_the_catalog_below_238`]: the undo runbook restores
//! 074's body, owner and ACL, and is idempotent.
//!
//! # Verified to fail
//!
//! - Run before 238 existed (test-first): the head half of the first test
//!   fails (the UPDATE commits).
//! - `SECURITY DEFINER` removed from 238's header: the head half of the first
//!   test fails, and so does the catalog-shape test.
//! - 238's `OWNER TO epigraph_maintenance` removed: the head half of the first
//!   test still refuses (the migration runner is a superuser and sees every
//!   row), and the catalog-shape test fails on the owner.
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

/// Everything below 238.
const BELOW: i64 = 237;

/// 074's SEALED refusal, which 238 keeps byte for byte.
const SEALED_TEXT: &str = "is SEALED and cannot be made public";
/// 074's arm (b) refusal.
const DECLASSIFY_TEXT: &str = "refusing to declassify claim";

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

/// A team group with an active key epoch 0 and an admin member:
/// `(member, group)`. The ciphertext group.
async fn key_group(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    let (member, _) = viewer_fixture::seed_agent_with_group(pool, label).await;
    let group: Uuid = sqlx::query_scalar(
        "INSERT INTO groups (display_name, did_key, public_key, kind, status, \
                             created_by_agent_id) \
         VALUES ($1, 'did:epigraph:team:' || gen_random_uuid()::text, \
                 decode(repeat('ab', 32), 'hex'), 'team', 'active', $2) \
         RETURNING id",
    )
    .bind(label)
    .bind(member)
    .fetch_one(pool)
    .await
    .expect("seed team group");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'admin')",
    )
    .bind(group)
    .bind(member)
    .execute(pool)
    .await
    .expect("seed team membership");
    sqlx::query("INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active')")
        .bind(group)
        .execute(pool)
        .await
        .expect("seed key epoch");
    (member, group)
}

/// Seal `claim` under `group`'s key, on the harness (superuser) connection:
/// the shape of a seal row written before 232 bound it to the claim's owner
/// group, or by a role 232's policies do not reach.
async fn seal_under(pool: &PgPool, claim: Uuid, group: Uuid) {
    sqlx::query(
        "INSERT INTO claim_encryption \
             (claim_id, group_id, epoch, privacy_tier, encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea)",
    )
    .bind(claim)
    .bind(group)
    .execute(pool)
    .await
    .expect("seal the claim");
}

/// As `epigraph_app`, stamped as `principal` reading and writing `group`
/// only: optionally arm 074's declassify GUC (any session can set it), then
/// `UPDATE claims SET visibility = 'public'`. `Ok(rows moved)` or the error
/// text.
async fn app_publicize(
    pool: &PgPool,
    principal: Uuid,
    group: Uuid,
    claim: Uuid,
    arm_declassify: bool,
) -> Result<u64, String> {
    viewer_fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        let run = async {
            conn.execute("BEGIN").await?;
            sqlx::query(
                "SELECT set_config('epigraph.principal_id', $1, true), \
                        set_config('epigraph.group_ids', $2, true), \
                        set_config('epigraph.writable_group_ids', $2, true)",
            )
            .bind(principal.to_string())
            .bind(group.to_string())
            .execute(&mut *conn)
            .await?;
            if arm_declassify {
                conn.execute("SELECT set_config('epigraph.allow_declassify', 'yes', true)")
                    .await?;
            }
            let moved = sqlx::query("UPDATE claims SET visibility = 'public' WHERE id = $1")
                .bind(claim)
                .execute(&mut *conn)
                .await?
                .rows_affected();
            conn.execute("COMMIT").await?;
            Ok::<u64, sqlx::Error>(moved)
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

async fn visibility(pool: &PgPool, claim: Uuid) -> String {
    sqlx::query_scalar("SELECT visibility FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read visibility")
}

async fn is_sealed(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM claim_encryption WHERE claim_id = $1)")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the seal row")
}

/// The writer: an agent whose personal group owns the claim, sealed under a
/// team group the writer is not in. `(writer, owner group, sealed claim)`.
async fn divergent_sealed_claim(pool: &PgPool, key: Uuid) -> (Uuid, Uuid, Uuid) {
    let (writer, owner) = viewer_fixture::seed_agent_with_group(pool, "widening-writer").await;
    let claim = viewer_fixture::seed_group_claim(pool, writer, owner, "sealed claim").await;
    seal_under(pool, claim, key).await;
    (writer, owner, claim)
}

#[sqlx::test(migrations = false)]
async fn a_non_member_of_the_ciphertext_group_cannot_publicize_a_sealed_claim(pool: PgPool) {
    migrate(&pool, &up_to(BELOW)).await;
    let (_, key) = key_group(&pool, "widening key").await;

    // CALIBRATION, 074's invoker body: the writer of the owner group cannot
    // see the ciphertext row, so the SEALED arm admits, and the declassify GUC
    // it armed itself admits arm (b).
    let (writer, owner, claim) = divergent_sealed_claim(&pool, key).await;
    let moved = app_publicize(&pool, writer, owner, claim, true).await;
    assert_eq!(
        moved,
        Ok(1),
        "CALIBRATION (below 238): the UPDATE reaches the claim and commits"
    );
    assert!(
        visibility(&pool, claim).await == "public" && is_sealed(&pool, claim).await,
        "CALIBRATION (below 238): the claim ends public AND sealed"
    );

    migrate(&pool, &MIGRATOR).await;

    let (writer, owner, claim) = divergent_sealed_claim(&pool, key).await;
    let err = app_publicize(&pool, writer, owner, claim, true)
        .await
        .expect_err(
            "(238) publicizing a sealed claim from outside its ciphertext group is refused",
        );
    assert!(
        err.contains(SEALED_TEXT) && err.contains("[42501]"),
        "(238) refused by 074's SEALED arm with 42501, got: {err}"
    );
    assert_eq!(
        visibility(&pool, claim).await,
        "group",
        "(238) the claim stays group-private"
    );
}

/// NON-REGRESSION CHECK, not a proof of 238's change: it passes below 238 by
/// design. It is not counted as a fail-on-old-code test.
#[sqlx::test(migrations = false)]
async fn the_definer_body_keeps_every_other_answer_of_074(pool: PgPool) {
    for (at, migrator) in [("237", up_to(BELOW)), ("238", up_to(238))] {
        migrate(&pool, &migrator).await;
        let (member, key) = key_group(&pool, &format!("widening member {at}")).await;

        // A member of the ciphertext group, which also owns the claim: the
        // SEALED arm sees the row under either body.
        let claim = viewer_fixture::seed_group_claim(&pool, member, key, "own sealed").await;
        seal_under(&pool, claim, key).await;
        let err = app_publicize(&pool, member, key, claim, true)
            .await
            .expect_err(&format!(
                "(at {at}) the ciphertext group's member is refused"
            ));
        assert!(
            err.contains(SEALED_TEXT) && err.contains("[42501]"),
            "(at {at}) refused by the SEALED arm, got: {err}"
        );

        // An unsealed group claim, declassify armed: admitted.
        let plain = viewer_fixture::seed_group_claim(&pool, member, key, "plain").await;
        assert_eq!(
            app_publicize(&pool, member, key, plain, true).await,
            Ok(1),
            "(at {at}) an unsealed claim with the declassify GUC is publicized"
        );
        assert_eq!(visibility(&pool, plain).await, "public");

        // An unsealed group claim, GUC not armed: arm (b) refuses.
        let unarmed = viewer_fixture::seed_group_claim(&pool, member, key, "unarmed").await;
        let err = app_publicize(&pool, member, key, unarmed, false)
            .await
            .expect_err(&format!(
                "(at {at}) group -> public without the GUC is refused"
            ));
        assert!(
            err.contains(DECLASSIFY_TEXT) && err.contains("[42501]"),
            "(at {at}) refused by arm (b), got: {err}"
        );
        assert_eq!(visibility(&pool, unarmed).await, "group");
    }
}

#[sqlx::test(migrations = false)]
async fn migration_238_makes_the_body_a_pinned_maintenance_definer(pool: PgPool) {
    migrate(&pool, &MIGRATOR).await;
    let (secdef, config, owner): (bool, Option<Vec<String>>, String) = sqlx::query_as(
        "SELECT p.prosecdef, p.proconfig, pg_get_userbyid(p.proowner)::text \
           FROM pg_proc p \
          WHERE p.oid = 'public.epigraph_claims_block_widening()'::regprocedure",
    )
    .fetch_one(&pool)
    .await
    .expect("read the function");
    assert!(secdef, "the body is SECURITY DEFINER");
    assert_eq!(
        config,
        Some(vec!["search_path=pg_catalog, pg_temp".to_string()]),
        "the body pins 172's search_path"
    );
    assert_eq!(
        owner, "epigraph_maintenance",
        "owned by the role whose frame passes 077's definer bypass"
    );
    for role in ["epigraph_app", "public"] {
        let can: bool = sqlx::query_scalar(
            "SELECT has_function_privilege($1, \
                    'public.epigraph_claims_block_widening()', 'EXECUTE')",
        )
        .bind(role)
        .fetch_one(&pool)
        .await
        .expect("read EXECUTE");
        assert!(!can, "{role} holds no EXECUTE on the trigger body");
    }
    let trigger: String = sqlx::query_scalar(
        "SELECT pg_get_triggerdef(t.oid) FROM pg_trigger t \
          WHERE t.tgrelid = 'public.claims'::regclass AND t.tgname = 'claims_block_widening'",
    )
    .fetch_one(&pool)
    .await
    .expect("read the trigger");
    assert!(
        trigger.contains("BEFORE UPDATE OF visibility ON public.claims FOR EACH ROW"),
        "074's trigger is unchanged: {trigger}"
    );
}

#[sqlx::test(migrations = false)]
async fn migration_238_refuses_to_apply_over_another_body(pool: PgPool) {
    migrate(&pool, &up_to(BELOW)).await;
    // Another migration's re-statement of the body (one character apart).
    sqlx::raw_sql(
        "CREATE OR REPLACE FUNCTION public.epigraph_claims_block_widening() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
    )
    .execute(&pool)
    .await
    .expect("re-state the body");
    let mut conn = pool.acquire().await.expect("acquire");
    let err = up_to(238)
        .run(&mut *conn)
        .await
        .expect_err("238 refuses a body that is not 074's");
    let text = err.to_string();
    assert!(
        text.contains("238: epigraph_claims_block_widening"),
        "refused by 238's md5 guard, got: {text}"
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

/// Mutation: the undo's re-statement of 074's body edited by one character,
/// or its `OWNER TO CURRENT_USER` dropped -> the function's entry differs
/// from the one below 238 and is named in the diff.
#[sqlx::test(migrations = false)]
async fn the_238_undo_returns_the_catalog_below_238(pool: PgPool) {
    migrate(&pool, &up_to(BELOW)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(238)).await;
    let through = catalog(&pool).await;
    let added: Vec<&String> = through.difference(&before).collect();
    let removed: Vec<&String> = before.difference(&through).collect();
    assert!(
        added.len() == 1
            && removed.len() == 1
            && added[0].starts_with("fn epigraph_claims_block_widening() ")
            && removed[0].starts_with("fn epigraph_claims_block_widening() "),
        "CALIBRATION: 238 changes exactly epigraph_claims_block_widening's definition: \
         added {added:?}, removed {removed:?}"
    );

    let undo = repo_file("docs/runbooks/238-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 238"
        );
    }
}
