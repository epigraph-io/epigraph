//! Migration 228 (backlog 01807a57): `mass_functions.locality_tag` is
//! `varchar(64)`, no longer 045's `varchar(20)`.
//!
//! * `a_28_character_tag_stores_and_a_65_character_tag_does_not`: the
//!   engine-named `intra_methodological_overlap` (28 characters) round-trips
//!   through the repository writer every BBA path uses; a 65-character tag is
//!   still refused by the column (the bound is real, not `text`). Below 228
//!   the 28-character store fails with 22001.
//! * `the_rewrite_guard_survives_the_widening`: 228 drops and re-creates
//!   184's `mass_functions_retracted_rewrite_guard` around the ALTER; its
//!   definition is byte-identical to the one below 228 and it still refuses
//!   re-tagging a retracted row (RT07).
//! * `the_228_undo_returns_the_column_and_refuses_over_long_rows`: the
//!   runbook narrows the column back with the trigger intact, twice, and
//!   refuses (writing nothing) while a row holds a tag over 20 characters.

use epigraph_db::MassFunctionRepository;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const LONG_ENGINE_TAG: &str = "intra_methodological_overlap";

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

/// The column's declared type, e.g. `character varying(64)`.
async fn column_type(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT format_type(a.atttypid, a.atttypmod) FROM pg_attribute a \
          WHERE a.attrelid = 'public.mass_functions'::regclass \
            AND a.attname = 'locality_tag' AND NOT a.attisdropped",
    )
    .fetch_one(pool)
    .await
    .expect("locality_tag column type")
}

/// Every non-internal trigger on `mass_functions`, by name, with its full
/// definition and enabled state.
async fn triggers(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT t.tgname || ' ' || t.tgenabled::text || ' ' || pg_get_triggerdef(t.oid) \
           FROM pg_trigger t \
          WHERE t.tgrelid = 'public.mass_functions'::regclass AND NOT t.tgisinternal \
          ORDER BY t.tgname",
    )
    .fetch_all(pool)
    .await
    .expect("triggers")
}

/// A claim, a frame and an agent on the harness (superuser) connection.
async fn seed(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
    let agent: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key) VALUES (sha256(gen_random_uuid()::text::bytea)) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent");
    let claim: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, is_current) \
         VALUES ($1, sha256($1::bytea), $2, 0.5, true) RETURNING id",
    )
    .bind(format!("locality-width-{}", Uuid::new_v4()))
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("seed claim");
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, '{\"TRUE\",\"FALSE\"}') RETURNING id",
    )
    .bind(format!("locality-width-frame-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .expect("seed frame");
    (agent, claim, frame)
}

async fn store(pool: &PgPool, tag: &str) -> Result<Uuid, epigraph_db::DbError> {
    let (agent, claim, frame) = seed(pool).await;
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        None,
        &json!({"0": 0.6, "0,1": 0.4}),
        None,
        Some("test"),
        None,
        Some("empirical"),
        tag,
        None,
    )
    .await
}

/// The same store on a database BELOW 267, for the tests that stop at 227 or
/// 228. Since 267 the repository writer keys a row on its `slot_kind` /
/// `slot_id` columns, which do not exist there (42703), so these tests issue
/// the INSERT the repository writer issued before 267: the same columns and
/// values as [`store`], `perspective_id` NULL.
async fn store_below_267(pool: &PgPool, tag: &str) -> Result<Uuid, sqlx::Error> {
    let (agent, claim, frame) = seed(pool).await;
    sqlx::query_scalar(
        "INSERT INTO mass_functions \
            (claim_id, frame_id, source_agent_id, perspective_id, masses, conflict_k, \
             combination_method, source_strength, evidence_type, locality_tag, evidence_id) \
         VALUES ($1, $2, $3, NULL, $4, NULL, 'test', NULL, 'empirical', $5, NULL) \
         RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(agent)
    .bind(json!({"0": 0.6, "0,1": 0.4}))
    .bind(tag)
    .fetch_one(pool)
    .await
}

/// Whether the error is PostgreSQL's 22001 (value too long for the column).
/// Read off the Debug form, which carries the driver's SQLSTATE whatever
/// error type wraps it.
fn is_too_long(e: &impl std::fmt::Debug) -> bool {
    format!("{e:?}").contains("\"22001\"")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_28_character_tag_stores_and_a_65_character_tag_does_not(pool: PgPool) {
    assert_eq!(column_type(&pool).await, "character varying(64)");

    let id = store(&pool, LONG_ENGINE_TAG)
        .await
        .expect("the engine-named 28-character tag stores");
    let stored: String =
        sqlx::query_scalar("SELECT locality_tag FROM mass_functions WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read back");
    assert_eq!(stored, LONG_ENGINE_TAG);

    // 64 characters (multi-byte, so more than 64 bytes) is the limit: stored.
    store(&pool, &"é".repeat(64))
        .await
        .expect("64 characters is within the column");

    // 65 characters is still refused by the column: the bound is real.
    let err = store(&pool, &"a".repeat(65))
        .await
        .expect_err("a 65-character tag exceeds varchar(64)");
    assert!(is_too_long(&err), "{err:?}");
}

/// The calibration for the test above: below 228 the same store (in its
/// pre-267 form, [`store_below_267`]) fails with 22001, so the assertion above
/// measures 228 and not some other path.
#[sqlx::test(migrations = false)]
async fn below_228_the_28_character_tag_is_refused(pool: PgPool) {
    migrate(&pool, &up_to(227)).await;
    assert_eq!(column_type(&pool).await, "character varying(20)");
    let err = store_below_267(&pool, LONG_ENGINE_TAG)
        .await
        .expect_err("varchar(20) cannot hold 28 characters");
    assert!(is_too_long(&err), "{err:?}");
}

#[sqlx::test(migrations = false)]
async fn the_rewrite_guard_survives_the_widening(pool: PgPool) {
    migrate(&pool, &up_to(227)).await;
    let before = triggers(&pool).await;
    assert!(
        before
            .iter()
            .any(|t| t.starts_with("mass_functions_retracted_rewrite_guard O ")),
        "CALIBRATION: 184's rewrite guard is present and enabled below 228: {before:?}"
    );
    migrate(&pool, &up_to(228)).await;
    assert_eq!(
        triggers(&pool).await,
        before,
        "228 re-creates the rewrite guard exactly as 184 defined it"
    );

    // And it still fires: re-tagging a retracted row is refused (RT07).
    let id = store_below_267(&pool, "cross").await.expect("store");
    sqlx::query(
        "UPDATE mass_functions \
            SET retracted_at = now(), retracted_by = source_agent_id, retract_reason = 'fixture' \
          WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .expect("mark retracted on the harness connection");
    let err = sqlx::query("UPDATE mass_functions SET locality_tag = $2 WHERE id = $1")
        .bind(id)
        .bind(LONG_ENGINE_TAG)
        .execute(&pool)
        .await
        .expect_err("a retracted row's locality_tag is part of its assessment");
    let msg = err.as_database_error().map(|d| d.message().to_string());
    assert!(
        msg.as_deref().is_some_and(|m| m.starts_with("RT07")),
        "{err:?}"
    );
}

#[sqlx::test(migrations = false)]
async fn the_228_undo_returns_the_column_and_refuses_over_long_rows(pool: PgPool) {
    migrate(&pool, &up_to(227)).await;
    let before = triggers(&pool).await;
    migrate(&pool, &up_to(228)).await;
    assert_eq!(column_type(&pool).await, "character varying(64)");

    let undo = repo_file("docs/runbooks/228-undo.sql");

    // A row the narrowed column cannot hold: the undo refuses and changes nothing.
    let id = store_below_267(&pool, LONG_ENGINE_TAG)
        .await
        .expect("store long tag");
    // On its own connection: the refusal leaves that connection's explicit
    // transaction aborted, so it is rolled back before the connection is
    // returned to the pool.
    let mut conn = pool.acquire().await.expect("acquire");
    let err = sqlx::raw_sql(&undo)
        .execute(&mut *conn)
        .await
        .expect_err("the undo refuses while a row holds a tag over 20 characters");
    assert!(err.to_string().contains("228-undo"), "{err}");
    sqlx::query("ROLLBACK")
        .execute(&mut *conn)
        .await
        .expect("roll the aborted undo back");
    drop(conn);
    assert_eq!(column_type(&pool).await, "character varying(64)");
    assert_eq!(
        triggers(&pool).await,
        before,
        "the refused undo dropped nothing"
    );

    sqlx::query("DELETE FROM mass_functions WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("remove the long-tag row");

    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        assert_eq!(column_type(&pool).await, "character varying(20)", "{run}");
        assert_eq!(
            triggers(&pool).await,
            before,
            "after the {run} run the triggers are exactly the ones below 228"
        );
    }
}
