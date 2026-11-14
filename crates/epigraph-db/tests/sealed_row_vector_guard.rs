//! Migration 212: the database refuses a vector on a sealed row (backlog
//! f78526ad; tenancy register D-SEAL-vector-column-row-guard).
//!
//! The invariant "a sealed row carries no vector" was enforced only by each
//! writer's own `NOT EXISTS (… _encryption …)` predicate, and four writers
//! lacked it. 212 adds `BEFORE UPDATE OF embedding, embedding_3072` triggers on
//! `claims` and `evidence` that refuse a non-NULL vector on a row with its own
//! encryption row. These arms write with the bare statement a predicate-less
//! writer would run, on the harness superuser, which bypasses row security, so
//! the trigger is the only thing that can refuse them.
//!
//! Each refusal is calibrated by the same statement on an unsealed sibling,
//! and the admitted shapes are pinned too: the seal's own nulling, an UPDATE
//! that names no vector column on a sealed row that still carries a legacy
//! vector, and another group's plaintext evidence under a sealed claim.

mod viewer_fixture;

use sqlx::PgPool;
use uuid::Uuid;

/// A pgvector literal of `dim` components, each `x`.
fn vector(dim: usize, x: f32) -> String {
    format!("[{}]", vec![x.to_string(); dim].join(","))
}

async fn key_epoch(pool: &PgPool, group: Uuid) {
    sqlx::query(
        "INSERT INTO group_key_epochs (group_id, epoch, status) VALUES ($1, 0, 'active') \
         ON CONFLICT DO NOTHING",
    )
    .bind(group)
    .execute(pool)
    .await
    .expect("seed the group key epoch the encryption FKs require");
}

async fn seal_claim(pool: &PgPool, claim: Uuid, group: Uuid) {
    key_epoch(pool, group).await;
    sqlx::query(
        "INSERT INTO claim_encryption (claim_id, group_id, epoch, privacy_tier, \
                                       encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', decode('0badc0de', 'hex'))",
    )
    .bind(claim)
    .bind(group)
    .execute(pool)
    .await
    .expect("seal the claim");
}

async fn seal_evidence(pool: &PgPool, evidence: Uuid, group: Uuid) {
    key_epoch(pool, group).await;
    sqlx::query(
        "INSERT INTO evidence_encryption (evidence_id, group_id, epoch, privacy_tier, \
                                          encrypted_content) \
         VALUES ($1, $2, 0, 'fully_private', '\\x00'::bytea)",
    )
    .bind(evidence)
    .bind(group)
    .execute(pool)
    .await
    .expect("seal the evidence row");
}

/// Run `sql` with `$1 = id`, `$2 = a 1536-d vector`, `$3 = a 3072-d vector`.
async fn write(pool: &PgPool, sql: &str, id: Uuid) -> Result<u64, sqlx::Error> {
    sqlx::query(sql)
        .bind(id)
        .bind(vector(1536, 0.5))
        .bind(vector(3072, 0.25))
        .execute(pool)
        .await
        .map(|r| r.rows_affected())
}

fn sqlstate(r: &Result<u64, sqlx::Error>) -> Option<String> {
    match r {
        Err(sqlx::Error::Database(e)) => e.code().map(|c| c.to_string()),
        _ => None,
    }
}

async fn vectors(pool: &PgPool, table: &str, id: Uuid) -> (bool, bool) {
    sqlx::query_as(&format!(
        "SELECT embedding IS NOT NULL, embedding_3072 IS NOT NULL FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read vectors")
}

const CLAIM_1536: &str =
    "UPDATE claims SET embedding = $2::vector WHERE id = $1 AND $3::text <> ''";
const CLAIM_3072: &str =
    "UPDATE claims SET embedding_3072 = $3::vector WHERE id = $1 AND $2::text <> ''";
const EVIDENCE_1536: &str =
    "UPDATE evidence SET embedding = $2::vector WHERE id = $1 AND $3::text <> ''";
const EVIDENCE_3072: &str =
    "UPDATE evidence SET embedding_3072 = $3::vector WHERE id = $1 AND $2::text <> ''";

#[sqlx::test(migrations = "../../migrations")]
async fn a_sealed_claim_refuses_either_vector_column(pool: PgPool) {
    let (agent, group) = viewer_fixture::seed_agent_with_group(&pool, "guard-claim").await;
    let open = viewer_fixture::seed_group_claim(&pool, agent, group, "guard open claim").await;
    let sealed = viewer_fixture::seed_group_claim(&pool, agent, group, "guard sealed claim").await;
    seal_claim(&pool, sealed, group).await;

    for sql in [CLAIM_1536, CLAIM_3072] {
        // CALIBRATION: the same statement lands on the unsealed sibling.
        assert_eq!(write(&pool, sql, open).await.expect("unsealed"), 1, "{sql}");
        let r = write(&pool, sql, sealed).await;
        assert_eq!(
            sqlstate(&r).as_deref(),
            Some("42501"),
            "{sql} on a sealed claim must be refused 42501, got {r:?}"
        );
    }
    assert_eq!(vectors(&pool, "claims", open).await, (true, true));
    assert_eq!(
        vectors(&pool, "claims", sealed).await,
        (false, false),
        "the sealed claim carries neither vector"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_sealed_evidence_row_refuses_a_vector_but_a_plaintext_sibling_does_not(pool: PgPool) {
    let (owner, group) = viewer_fixture::seed_agent_with_group(&pool, "guard-ev").await;
    let claim = viewer_fixture::seed_group_claim(&pool, owner, group, "guard ev claim").await;
    let sealed = viewer_fixture::seed_evidence(&pool, claim, "document").await;
    let plaintext = viewer_fixture::seed_evidence(&pool, claim, "observation").await;
    // The claim is sealed too: the evidence key is the ROW's own ciphertext,
    // never its parent's, so the unsealed row must still be writable.
    seal_claim(&pool, claim, group).await;
    seal_evidence(&pool, sealed, group).await;

    for sql in [EVIDENCE_1536, EVIDENCE_3072] {
        assert_eq!(
            write(&pool, sql, plaintext).await.expect("plaintext row"),
            1,
            "CALIBRATION: an unsealed evidence row under a sealed claim keeps its vector: {sql}"
        );
        let r = write(&pool, sql, sealed).await;
        assert_eq!(
            sqlstate(&r).as_deref(),
            Some("42501"),
            "{sql} on a sealed evidence row must be refused 42501, got {r:?}"
        );
    }
    assert_eq!(vectors(&pool, "evidence", plaintext).await, (true, true));
    assert_eq!(vectors(&pool, "evidence", sealed).await, (false, false));
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_seal_nulling_and_unrelated_updates_are_admitted(pool: PgPool) {
    let (agent, group) = viewer_fixture::seed_agent_with_group(&pool, "guard-admit").await;
    let claim = viewer_fixture::seed_group_claim(&pool, agent, group, "guard legacy claim").await;
    // A legacy violation: the vector was planted BEFORE the seal, as a row
    // sealed before this migration could have been left.
    write(
        &pool,
        "UPDATE claims SET embedding = $2::vector, embedding_3072 = $3::vector WHERE id = $1",
        claim,
    )
    .await
    .expect("plant the legacy vectors");
    seal_claim(&pool, claim, group).await;

    // An UPDATE that names no vector column does not fire the trigger.
    sqlx::query("UPDATE claims SET labels = ARRAY['guard-relabel'] WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("an unrelated update of a sealed row is admitted");
    // Re-writing a vector onto it is refused, even though one is already there.
    let r = write(&pool, CLAIM_1536, claim).await;
    assert_eq!(sqlstate(&r).as_deref(), Some("42501"), "{r:?}");
    // A partial nulling leaves the other vector in place, so it is refused:
    // the remedy is both columns in one statement (the README says so).
    let partial = sqlx::query("UPDATE claims SET embedding = NULL WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .map(|r| r.rows_affected());
    assert_eq!(sqlstate(&partial).as_deref(), Some("42501"), "{partial:?}");
    // The remedy, the seal's own nulling, is admitted.
    sqlx::query("UPDATE claims SET embedding = NULL, embedding_3072 = NULL WHERE id = $1")
        .bind(claim)
        .execute(&pool)
        .await
        .expect("nulling a sealed row's vectors is admitted");
    assert_eq!(vectors(&pool, "claims", claim).await, (false, false));
}

/// 172's definer form, and the owner the encryption tables' definer-bypass
/// disjunct admits: an INVOKER body would see the encryption row only for a
/// session in the sealing group and admit the vector for every other one.
#[sqlx::test(migrations = "../../migrations")]
async fn both_guards_are_maintenance_owned_definers_off_public(pool: PgPool) {
    for f in [
        "epigraph_refuse_sealed_claim_vector",
        "epigraph_refuse_sealed_evidence_vector",
    ] {
        let (definer, owner, config, public_exec): (bool, String, String, bool) = sqlx::query_as(
            "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, \
                    coalesce(array_to_string(p.proconfig, ';'), ''), \
                    has_function_privilege('public', p.oid, 'EXECUTE') \
               FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
              WHERE n.nspname = 'public' AND p.proname = $1",
        )
        .bind(f)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("{f} exists: {e}"));
        assert!(definer, "{f} is SECURITY DEFINER");
        assert_eq!(owner, "epigraph_maintenance", "{f} owner");
        assert_eq!(config, "search_path=pg_catalog, pg_temp", "{f} search_path");
        assert!(!public_exec, "{f}: EXECUTE revoked from PUBLIC");
    }
}

/// `docs/runbooks/212-undo.sql` removes both guards, is idempotent, and
/// leaves the pre-212 behaviour: the same bare write on a sealed claim lands
/// again (which is why the undo's header says the invariant is then
/// statement-level only).
#[sqlx::test(migrations = "../../migrations")]
async fn the_212_undo_removes_both_guards_and_is_idempotent(pool: PgPool) {
    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/212-undo.sql"),
    )
    .expect("read the 212 undo");
    let (agent, group) = viewer_fixture::seed_agent_with_group(&pool, "guard-undo").await;
    let sealed = viewer_fixture::seed_group_claim(&pool, agent, group, "guard undo claim").await;
    seal_claim(&pool, sealed, group).await;
    let r = write(&pool, CLAIM_1536, sealed).await;
    assert_eq!(
        sqlstate(&r).as_deref(),
        Some("42501"),
        "CALIBRATION: guarded before the undo"
    );

    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
    }
    let left: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM pg_trigger \
                  WHERE tgname IN ('claims_refuse_sealed_vector', 'evidence_refuse_sealed_vector')) \
              + (SELECT count(*) FROM pg_proc \
                  WHERE proname IN ('epigraph_refuse_sealed_claim_vector', \
                                    'epigraph_refuse_sealed_evidence_vector'))",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog");
    assert_eq!(left, 0, "no trigger or function of 212 survives the undo");
    assert_eq!(
        write(&pool, CLAIM_1536, sealed)
            .await
            .expect("unguarded write"),
        1,
        "after the undo the bare write lands again"
    );
}

/// 212 takes SHARE ROW EXCLUSIVE on `claims` and `evidence` (CREATE TRIGGER).
/// Behind a long open write transaction it must fail fast rather than queue
/// every later write to those tables behind it, so the file sets a
/// transaction-local `lock_timeout` (197's form) before its first CREATE
/// TRIGGER. Static: the migration text, comments stripped.
#[test]
fn the_212_migration_sets_a_lock_timeout_before_it_creates_a_trigger() {
    let raw = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../migrations/212_sealed_row_vector_guard.sql"),
    )
    .expect("read migration 212");
    let sql: String = raw
        .lines()
        .map(|l| l.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();
    let timeout = sql
        .find("set local lock_timeout")
        .expect("212 sets no transaction-local lock_timeout");
    let trigger = sql
        .find("create trigger")
        .expect("CALIBRATION: 212 creates a trigger");
    assert!(
        timeout < trigger,
        "212's lock_timeout must be set before its first CREATE TRIGGER"
    );
}
