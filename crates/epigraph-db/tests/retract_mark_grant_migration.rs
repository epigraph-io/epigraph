//! Migration 274 (backlog 03d444a9): the shape of the change that confines
//! 184's retract guard MARK arm to a `retract` grant of 251's ledger. What
//! it re-states and over what (its md5 preconditions), what is at head, that
//! it refuses over another body with nothing changed, and that
//! `docs/runbooks/274-undo.sql` puts the four bodies back and 274 then
//! re-applies. The behaviour (a maintenance login refused, the definer still
//! retracting and auditing) is pinned in `bba_retract.rs`.
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is not
//! extended.

use sqlx::migrate::Migrator;
use sqlx::{Executor, PgPool};
use std::borrow::Cow;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

const RETRACT_GUARD: &str = "public.epigraph_mass_function_retract_guard()";
const GRANT_FN: &str = "public.epigraph_mf_guard_grant(text, uuid[], text, uuid)";
const CONSUME_FN: &str = "public.epigraph_mf_guard_consume(text, uuid, jsonb)";
const RETRACT: &str = "public.epigraph_retract_mass_function(uuid, text, uuid, uuid)";
const LEDGER: &str = "public.mass_function_purge_grants";
const OWNER: &str = "epigraph_bba_guard_owner";

/// The four bodies 274 re-states, as a database at 271 holds them:
/// `(signature, md5(prosrc), proconfig)`, measured by
/// `the_bodies_before_274_are_the_ones_it_restates`.
const BEFORE_274: &[(&str, &str, &str)] = &[
    (
        RETRACT_GUARD,
        "67fff432f24ba8c26be693c0c2d7f35b",
        "search_path=pg_catalog, public, pg_temp",
    ),
    (
        GRANT_FN,
        "7833508787fa01cffcf972d4c814a6a8",
        "search_path=pg_catalog, pg_temp",
    ),
    (
        CONSUME_FN,
        "a3a0ba7efcd8c45d9e2816ec0c8f1599",
        "search_path=pg_catalog, pg_temp",
    ),
    (
        RETRACT,
        "aca3e3d55092b3814cfebe8f062b1e37",
        "search_path=pg_catalog, public, pg_temp",
    ),
];

fn repo_file(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel} must exist: {e}"))
}

/// `(md5(prosrc), proconfig, prosrc, owner)` of one function.
async fn facts(pool: &PgPool, sig: &str) -> (String, Vec<String>, String, String) {
    sqlx::query_as(
        "SELECT md5(p.prosrc), COALESCE(p.proconfig, ARRAY[]::text[]), p.prosrc, \
                pg_get_userbyid(p.proowner)::text \
           FROM pg_proc p WHERE p.oid = to_regprocedure($1)",
    )
    .bind(sig)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("read {sig}: {e}"))
}

async fn kind_check(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
          WHERE conrelid = $1::regclass AND conname = 'mass_function_purge_grants_kind_check'",
    )
    .bind(LEDGER)
    .fetch_one(pool)
    .await
    .expect("the ledger's kind check")
}

async fn faults(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar("SELECT public.epigraph_bba_guard_owner_faults()")
        .fetch_one(pool)
        .await
        .expect("epigraph_bba_guard_owner_faults()")
}

async fn migrate_below_274(pool: &PgPool) {
    let below = Migrator {
        migrations: Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < 274)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    let mut conn = pool.acquire().await.expect("acquire");
    below.run(&mut *conn).await.expect("migrate below 274");
    conn.execute("RESET ALL").await.expect("RESET ALL");
}

async fn migrate_rest(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    let mut conn = pool.acquire().await.expect("acquire");
    let r = MIGRATOR.run(&mut *conn).await;
    conn.execute("RESET ALL").await.expect("RESET ALL");
    r
}

async fn assert_bodies_are_271s(pool: &PgPool, when: &str) {
    for (sig, md5, config) in BEFORE_274 {
        let (got_md5, got_config, _, _) = facts(pool, sig).await;
        assert_eq!(&got_md5, md5, "md5(prosrc) of {sig} {when}");
        assert_eq!(
            got_config,
            vec![(*config).to_string()],
            "proconfig of {sig} {when}"
        );
    }
}

/// The measurement behind [`BEFORE_274`] and 274's header: below 274 the four
/// bodies are 251's and 184's (on 190's path), and the ledger has two kinds.
#[sqlx::test(migrations = false)]
async fn the_bodies_before_274_are_the_ones_it_restates(pool: PgPool) {
    migrate_below_274(&pool).await;
    assert_bodies_are_271s(&pool, "below 274").await;
    assert!(
        !kind_check(&pool).await.contains("'retract'"),
        "below 274 the ledger has no retract kind"
    );
}

/// At head the mark arm consumes a `retract` grant and reads neither session
/// bypass; the definer writes that grant; the consumer binds it to the row's
/// retractor and reason; the owner's functions stay its own on their path,
/// and the fault check is clean.
#[sqlx::test(migrations = "../../migrations")]
async fn at_head_the_mark_arm_consumes_a_retract_grant(pool: PgPool) {
    assert_eq!(faults(&pool).await, Vec::<String>::new(), "no fault");
    assert!(kind_check(&pool).await.contains("'retract'"));

    let (_, config, src, _) = facts(&pool, RETRACT_GUARD).await;
    assert_eq!(
        config,
        vec!["search_path=pg_catalog, public, pg_temp".to_string()]
    );
    assert!(
        src.contains(
            "public.epigraph_mf_guard_consume('retract', NEW.id, pg_catalog.to_jsonb(NEW))"
        ),
        "{src}"
    );
    assert!(
        !src.contains("epigraph_bypass()") && !src.contains("epigraph_definer_bypass()"),
        "the mark arm reads no session bypass: {src}"
    );

    let (_, config, src, owner) = facts(&pool, RETRACT).await;
    assert_eq!(owner, "epigraph_maintenance");
    assert_eq!(
        config,
        vec!["search_path=pg_catalog, public, pg_temp".to_string()]
    );
    assert!(
        src.contains(
            "public.epigraph_mf_guard_grant('retract', ARRAY[p_id], v_reason, v_principal)"
        ),
        "{src}"
    );

    for sig in [GRANT_FN, CONSUME_FN] {
        let (_, config, _, owner) = facts(&pool, sig).await;
        assert_eq!(owner, OWNER, "{sig}");
        assert_eq!(
            config,
            vec!["search_path=pg_catalog, pg_temp".to_string()],
            "{sig}"
        );
    }
    let (_, _, src, _) = facts(&pool, CONSUME_FN).await;
    assert!(
        src.contains("(p_row ->> 'retracted_by') = c.granted_by::pg_catalog.text")
            && src.contains("(p_row ->> 'retract_reason') = c.reason"),
        "{src}"
    );
}

/// 274 refuses (55000) over a body it does not re-state, with nothing
/// changed: the ledger keeps two kinds and the guard keeps the other body.
#[sqlx::test(migrations = false)]
async fn migration_274_refuses_to_apply_over_another_body(pool: PgPool) {
    migrate_below_274(&pool).await;
    // The same definer with one comment changed: another md5.
    let (_, _, src, _) = facts(&pool, RETRACT).await;
    let other = src.replacen(
        "-- After the authority checks",
        "-- (edited) After the authority checks",
        1,
    );
    assert_ne!(other, src, "fixture: the edit lands");
    sqlx::raw_sql(&format!(
        "CREATE OR REPLACE FUNCTION public.epigraph_retract_mass_function(\
             p_id uuid, p_reason text, p_admin_client uuid, p_admin_jti uuid) \
         RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER \
         SET search_path = pg_catalog, public, pg_temp AS $body${other}$body$"
    ))
    .execute(&pool)
    .await
    .expect("re-body the definer");

    let err = migrate_rest(&pool).await.expect_err("274 refuses");
    let msg = err.to_string();
    assert!(msg.contains("274: these bodies are not the ones"), "{msg}");
    assert!(msg.contains("epigraph_retract_mass_function"), "{msg}");
    assert!(
        !kind_check(&pool).await.contains("'retract'"),
        "nothing was changed"
    );
    let (got_md5, _, _, _) = facts(&pool, RETRACT_GUARD).await;
    assert_eq!(got_md5, BEFORE_274[0].1, "the guard is 251's still");
}

/// `docs/runbooks/274-undo.sql` puts the four bodies back as they are at 271
/// (md5 and path), keeps the owner's functions the owner's and the ledger's
/// `retract` rows, runs twice, and 274's own text then applies again.
#[sqlx::test(migrations = "../../migrations")]
async fn the_274_undo_restores_the_bodies_and_274_re_applies(pool: PgPool) {
    let undo = repo_file("docs/runbooks/274-undo.sql");
    let m274 = repo_file("migrations/274_retract_mark_grant.sql");

    let mut tx = pool.begin().await.unwrap();
    tx.execute("SET LOCAL SESSION AUTHORIZATION epigraph_maintenance")
        .await
        .unwrap();
    let id = uuid::Uuid::new_v4();
    sqlx::query("SELECT public.epigraph_mf_guard_grant('retract', ARRAY[$1]::uuid[], 'undo', $1)")
        .bind(id)
        .execute(&mut *tx)
        .await
        .expect("a retract grant before the undo");
    tx.commit().await.unwrap();

    for _ in 0..2 {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .expect("the undo runs");
    }
    assert_bodies_are_271s(&pool, "after the undo").await;
    for sig in [GRANT_FN, CONSUME_FN] {
        let (_, _, _, owner) = facts(&pool, sig).await;
        assert_eq!(owner, OWNER, "{sig} keeps its owner");
    }
    let (_, _, _, owner) = facts(&pool, RETRACT).await;
    assert_eq!(owner, "epigraph_maintenance");
    assert_eq!(faults(&pool).await, Vec::<String>::new());
    let kept: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mass_function_purge_grants WHERE mf_id = $1 AND kind = 'retract'",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kept, 1, "the ledger keeps its retract rows");

    sqlx::raw_sql(&format!("BEGIN;\n{m274}\nCOMMIT;"))
        .execute(&pool)
        .await
        .expect("274 re-applies after its undo");
    assert_eq!(faults(&pool).await, Vec::<String>::new());
    let (_, _, src, _) = facts(&pool, RETRACT_GUARD).await;
    assert!(src.contains("epigraph_mf_guard_consume('retract'"), "{src}");
}
