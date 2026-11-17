//! `agents.key_kind = 'seed-derived'` (backlog bfc2eff8, migration 230): the
//! kind, its repository insert, the verifier's refusal, and the undo.
//!
//! A seed-derived key is the Ed25519 key of `BLAKE3(<public seed>)` (an author
//! name, an ORCID, an org name, the legacy system constant, an unkeyed LLM
//! identity). Anyone who knows the seed holds the private key, so the row's
//! key names the agent and must never verify a signature. Before 230 the
//! CHECK admitted only `ed25519` and `derived`, and these rows took the
//! default `ed25519`. Each test measures the stored row or the catalog.

mod viewer_fixture;

use epigraph_core::Agent;
use epigraph_db::{AgentRepository, DbError, KEY_KIND_SEED_DERIVED};
use sqlx::PgPool;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const UNDO_230: &str = include_str!("../../../docs/runbooks/230-undo.sql");

async fn kind(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT key_kind::text FROM agents WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("key_kind")
}

async fn verifier(pool: &PgPool, id: Uuid) -> Option<Vec<u8>> {
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::public_key_if_signer(&mut conn, id)
        .await
        .expect("public_key_if_signer")
}

/// The CHECK admits `seed-derived` and still rejects any other new value, and
/// `public_key_if_signer` (the packet-signature verifier's key source) returns
/// nothing for a seed-derived row while an `ed25519` row still verifies.
/// Raw SQL on purpose: this is the catalog's answer, not the repository's.
#[sqlx::test(migrations = "../../migrations")]
async fn the_check_admits_seed_derived_and_the_verifier_refuses_it(pool: PgPool) {
    let seeded = epigraph_crypto::did_key::did_key_for_author(None, "Halvard Ekstrom-Bisset").1;
    let seed_id: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, key_kind) \
         VALUES ($1, 'seed-derived probe', 'seed-derived') RETURNING id",
    )
    .bind(seeded.as_slice())
    .fetch_one(&pool)
    .await
    .expect("the CHECK must admit seed-derived (migration 230)");
    assert_eq!(verifier(&pool, seed_id).await, None);

    let real = epigraph_crypto::AgentSigner::generate().public_key();
    let real_id: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'ed25519 probe') RETURNING id",
    )
    .bind(real.as_slice())
    .fetch_one(&pool)
    .await
    .expect("default kind");
    assert_eq!(kind(&pool, real_id).await, "ed25519");
    assert_eq!(
        verifier(&pool, real_id).await,
        Some(real.to_vec()),
        "calibration: a real key still verifies"
    );

    let err = sqlx::query(
        "INSERT INTO agents (public_key, display_name, key_kind) \
         VALUES (decode(repeat('cd', 32), 'hex'), 'widened-check-probe', 'legacy')",
    )
    .execute(&pool)
    .await
    .expect_err("a fourth kind must still be refused");
    let code = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(code, "23514", "a CHECK violation, got {err}");
}

/// `create_seed_derived_conn` stores the kind on the APPLICATION role (row
/// security: 077's `agents_provision` refuses only `derived`), returns the
/// same agent `create_conn` would, and maps a second insert of the same key to
/// `DuplicateKey` exactly as `create_conn` does.
#[sqlx::test(migrations = "../../migrations")]
async fn the_repository_insert_stores_the_kind_on_the_app_role(pool: PgPool) {
    let app = viewer_fixture::downgraded_pool(&pool, "epigraph_app").await;
    let key = epigraph_crypto::did_key::did_key_for_author(None, "Ysolde Marchetti-Oake").1;
    let mut agent = Agent::new(key, Some("Ysolde Marchetti-Oake".to_string()));
    agent.labels = vec!["author".to_string()];

    let mut conn = app.acquire().await.expect("acquire");
    let created = AgentRepository::create_seed_derived_conn(&mut conn, &agent)
        .await
        .expect("the application role may insert a seed-derived agent");
    assert_eq!(created.public_key, key);
    assert_eq!(
        created.display_name.as_deref(),
        Some("Ysolde Marchetti-Oake")
    );
    assert_eq!(created.labels, vec!["author".to_string()]);
    let id: Uuid = created.id.into();
    assert_eq!(kind(&pool, id).await, KEY_KIND_SEED_DERIVED);
    assert_eq!(verifier(&pool, id).await, None);

    let again = Agent::new(key, Some("again".to_string()));
    let err = AgentRepository::create_seed_derived_conn(&mut conn, &again)
        .await
        .expect_err("the same key twice");
    assert!(matches!(err, DbError::DuplicateKey { .. }), "{err:?}");
}

/// 161's re-runnable `epigraph_backfill_legacy_agent_keys()` gives every agent
/// without one an ACTIVE `identity-legacy` row, an ATTESTED key that
/// `verify_claim` binds signatures to. Since 230 it skips a seed-derived agent
/// (its key is computable by anyone), and still keys an `ed25519` agent
/// created beside it (calibration: the backfill ran and was not a no-op).
/// Run as the maintenance role, which is who runs it at a cut-over.
#[sqlx::test(migrations = "../../migrations")]
async fn the_legacy_key_backfill_never_attests_a_seed_derived_key(pool: PgPool) {
    let seeded = epigraph_crypto::did_key::did_key_for_author(None, "Corvina Aldermoot").1;
    let seed_id: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, key_kind) VALUES ($1, 'seed-derived') RETURNING id",
    )
    .bind(seeded.as_slice())
    .fetch_one(&pool)
    .await
    .expect("seed-derived agent");
    let real = epigraph_crypto::AgentSigner::generate().public_key();
    let real_id: Uuid =
        sqlx::query_scalar("INSERT INTO agents (public_key) VALUES ($1) RETURNING id")
            .bind(real.as_slice())
            .fetch_one(&pool)
            .await
            .expect("ed25519 agent");

    let added: i32 =
        viewer_fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
            let n: i32 = sqlx::query_scalar("SELECT public.epigraph_backfill_legacy_agent_keys()")
                .fetch_one(&mut *conn)
                .await
                .expect("maintenance runs the backfill");
            (conn, n)
        })
        .await;
    assert!(added >= 1, "calibration: the backfill added rows");

    let legacy = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM agent_keys WHERE agent_id = $1 AND key_type = 'identity-legacy'",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("legacy rows")
        }
    };
    assert_eq!(
        legacy(real_id).await,
        1,
        "calibration: the ed25519 agent is keyed"
    );
    assert_eq!(
        legacy(seed_id).await,
        0,
        "a seed-derived key must never become an attested identity-legacy key"
    );
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

async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

async fn constraint_def(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
          WHERE conrelid = 'public.agents'::regclass AND conname = 'agents_key_kind_check'",
    )
    .fetch_one(pool)
    .await
    .expect("agents_key_kind_check exists")
}

async fn backfill_def(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT pg_get_functiondef('public.epigraph_backfill_legacy_agent_keys()'::regprocedure)",
    )
    .fetch_one(pool)
    .await
    .expect("the backfill exists")
}

async fn column_comment(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT col_description('public.agents'::regclass, \
                (SELECT attnum FROM pg_attribute \
                  WHERE attrelid = 'public.agents'::regclass AND attname = 'key_kind'))",
    )
    .fetch_one(pool)
    .await
    .expect("key_kind comment")
}

async fn run_undo(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = sqlx::raw_sql(UNDO_230)
        .execute(&mut *conn)
        .await
        .map(|_| ());
    if out.is_err() {
        // The script's own BEGIN is left open by the refusal, as psql would
        // leave it before exiting; end it so the pooled connection is usable.
        sqlx::query("ROLLBACK")
            .execute(&mut *conn)
            .await
            .expect("ROLLBACK");
    }
    out
}

/// `docs/runbooks/230-undo.sql`: on a database migrated through 230 it returns
/// the CHECK and the column comment to their state below 230, a second run
/// changes nothing, and while a seed-derived row exists it refuses and
/// changes nothing.
#[sqlx::test(migrations = false)]
async fn the_230_undo_restores_the_catalog_below_230(pool: PgPool) {
    migrate(&pool, &up_to(229)).await;
    let (below, below_comment) = (constraint_def(&pool).await, column_comment(&pool).await);
    let below_backfill = backfill_def(&pool).await;
    assert!(!below.contains("seed-derived"), "{below}");

    migrate(&pool, &MIGRATOR).await;
    let at_230 = constraint_def(&pool).await;
    assert!(at_230.contains("'seed-derived'"), "{at_230}");
    assert_ne!(column_comment(&pool).await, below_comment);
    assert!(backfill_def(&pool).await.contains("seed-derived"));

    let key = epigraph_crypto::did_key::did_key_for_author(None, "Undo Probe").1;
    let row: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, key_kind) VALUES ($1, 'seed-derived') RETURNING id",
    )
    .bind(key.as_slice())
    .fetch_one(&pool)
    .await
    .expect("a seed-derived row");
    let err = run_undo(&pool).await.expect_err("the undo must refuse");
    assert!(err.to_string().contains("230-undo"), "{err}");
    assert_eq!(constraint_def(&pool).await, at_230);

    sqlx::query("DELETE FROM agents WHERE id = $1")
        .bind(row)
        .execute(&pool)
        .await
        .expect("delete the probe");
    run_undo(&pool).await.expect("undo");
    assert_eq!(constraint_def(&pool).await, below);
    assert_eq!(column_comment(&pool).await, below_comment);
    assert_eq!(backfill_def(&pool).await, below_backfill);
    run_undo(&pool).await.expect("undo, second run");
    assert_eq!(constraint_def(&pool).await, below);
}
