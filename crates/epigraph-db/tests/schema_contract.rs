//! Schema contract for the group-tenancy tables created by
//! `migrations/060_group_tenancy_tables.sql`.
//!
//! **Why this file exists.** Every repository that reads these eight tables —
//! `claim_encryption`, `claim_version_encryption`, `edge_encryption`,
//! `evidence_encryption`, `group`, `group_key_epoch`, `group_membership`,
//! `pattern_template` — uses the *runtime* `sqlx::query` / `query_as` forms, not
//! the `query!` macros. Runtime queries are never checked against the offline
//! (`.sqlx/`) prepare cache, so a column renamed or dropped in a later migration
//! is invisible to `SQLX_OFFLINE=true cargo check` and surfaces as a 42703 at
//! request time. This test is the only guard against *in-tree* drift — a later
//! public migration renaming or dropping one of these columns.
//!
//! **What this file structurally CANNOT catch,** and where that check lives
//! instead: `#[sqlx::test]` always provisions a fresh database, so 060 always
//! created these tables itself and the contract only ever asserts that 060
//! matches 060. A long-lived database that already carried, say, the
//! epigraph-enterprise shape of `groups` or `claim_encryption` would have every
//! `CREATE TABLE IF NOT EXISTS` no-op, and the divergence would be invisible
//! here forever. That check therefore lives *in the migration*, as the drift
//! guard at the top of 060, which is the only place it can see a legacy
//! database. `drift_guard_rejects_a_pre_060_table_shape` below exercises it.
//!
//! Deliberately non-macro `sqlx::query` / `query_scalar` throughout, for the
//! same reason `crates/epigraph-api/tests/migrate_on_startup.rs` is: CI runs
//! with `SQLX_OFFLINE=true`, and a macro here would demand a `.sqlx/` entry.
//!
//! Scope note: this asserts the contract for the eight tables 060 creates. It is
//! deliberately *not* a "every table any repo references exists" test —
//! `propaganda_techniques`, `coalitions` and `syntheses` are referenced by
//! `repos/political.rs` and the `entity_types` registry and are created by no
//! migration. Those are pre-existing gaps, tracked separately; widening this
//! test to cover them would land it red for reasons PR-01 does not own.

use sqlx::{PgPool, Row};

/// The migration file itself, embedded so replay tests cannot drift from it.
const MIGRATION_060: &str = include_str!("../../../migrations/060_group_tenancy_tables.sql");
const MIGRATION_061: &str = include_str!("../../../migrations/061_agents_key_kind.sql");

/// `(column_name, data_type, is_nullable)` triples for one table, sorted by
/// column name — the exact shape `information_schema.columns` reports.
type ColumnContract = &'static [(&'static str, &'static str, &'static str)];

const GROUPS: ColumnContract = &[
    ("created_at", "timestamp with time zone", "NO"),
    ("created_by_agent_id", "uuid", "YES"),
    ("did_key", "text", "NO"),
    ("display_name", "character varying", "YES"),
    ("id", "uuid", "NO"),
    ("kind", "character varying", "NO"),
    ("pre_public_key", "bytea", "YES"),
    ("properties", "jsonb", "NO"),
    ("public_key", "bytea", "NO"),
    ("reseal_required_at", "timestamp with time zone", "YES"),
    ("status", "character varying", "NO"),
    ("updated_at", "timestamp with time zone", "NO"),
];

const GROUP_KEY_EPOCHS: ColumnContract = &[
    ("created_at", "timestamp with time zone", "NO"),
    ("epoch", "integer", "NO"),
    ("group_id", "uuid", "NO"),
    ("id", "uuid", "NO"),
    ("retired_at", "timestamp with time zone", "YES"),
    ("status", "character varying", "NO"),
    ("wrapped_key", "bytea", "YES"),
];

const GROUP_MEMBERSHIPS: ColumnContract = &[
    ("agent_id", "uuid", "NO"),
    ("epoch", "integer", "NO"),
    ("group_id", "uuid", "NO"),
    ("id", "uuid", "NO"),
    ("joined_at", "timestamp with time zone", "NO"),
    ("revoked_at", "timestamp with time zone", "YES"),
    ("role", "character varying", "NO"),
    // repos/group_membership.rs binds Vec<u8>, not Option<Vec<u8>>.
    ("wrapped_key_share", "bytea", "NO"),
];

const CLAIM_ENCRYPTION: ColumnContract = &[
    ("claim_id", "uuid", "NO"),
    ("created_at", "timestamp with time zone", "NO"),
    ("encrypted_content", "bytea", "NO"),
    ("encrypted_labels", "bytea", "YES"),
    ("encrypted_properties", "bytea", "YES"),
    ("epoch", "integer", "NO"),
    ("group_id", "uuid", "NO"),
    ("privacy_tier", "character varying", "NO"),
];

const CLAIM_VERSION_ENCRYPTION: ColumnContract = &[
    ("claim_id", "uuid", "NO"),
    ("claim_version_id", "uuid", "NO"),
    ("created_at", "timestamp with time zone", "NO"),
    ("encrypted_content", "bytea", "NO"),
    ("epoch", "integer", "NO"),
    ("group_id", "uuid", "NO"),
];

const EVIDENCE_ENCRYPTION: ColumnContract = &[
    ("created_at", "timestamp with time zone", "NO"),
    // EvidenceEncryptionRepository SELECTs evidence_id, group_id, epoch,
    // privacy_tier, encrypted_content, encrypted_labels, created_at — all seven
    // must stay. encrypted_properties is the section 6.5.6 addition.
    ("encrypted_content", "bytea", "NO"),
    ("encrypted_labels", "bytea", "YES"),
    ("encrypted_properties", "bytea", "YES"),
    ("epoch", "integer", "NO"),
    ("evidence_id", "uuid", "NO"),
    ("group_id", "uuid", "NO"),
    ("privacy_tier", "character varying", "NO"),
];

const EDGE_ENCRYPTION: ColumnContract = &[
    ("created_at", "timestamp with time zone", "NO"),
    ("edge_id", "uuid", "NO"),
    // EdgeEncryptionRepository SELECTs encrypted_labels + encrypted_properties.
    ("encrypted_labels", "bytea", "YES"),
    ("encrypted_properties", "bytea", "YES"),
    ("epoch", "integer", "NO"),
    ("group_id", "uuid", "NO"),
    ("privacy_tier", "character varying", "NO"),
];

const PATTERN_TEMPLATES: ColumnContract = &[
    ("category", "character varying", "NO"),
    ("created_at", "timestamp with time zone", "NO"),
    ("description", "text", "YES"),
    ("id", "uuid", "NO"),
    ("min_confidence", "double precision", "NO"),
    ("name", "character varying", "NO"),
    ("skeleton", "jsonb", "NO"),
];

const CONTRACTS: &[(&str, ColumnContract)] = &[
    ("groups", GROUPS),
    ("group_key_epochs", GROUP_KEY_EPOCHS),
    ("group_memberships", GROUP_MEMBERSHIPS),
    ("claim_encryption", CLAIM_ENCRYPTION),
    ("claim_version_encryption", CLAIM_VERSION_ENCRYPTION),
    ("evidence_encryption", EVIDENCE_ENCRYPTION),
    ("edge_encryption", EDGE_ENCRYPTION),
    ("pattern_templates", PATTERN_TEMPLATES),
];

async fn observed_columns(pool: &PgPool, table: &str) -> Vec<(String, String, String)> {
    let rows = sqlx::query(
        "SELECT column_name, data_type, is_nullable \
         FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = $1 \
         ORDER BY column_name",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| panic!("information_schema lookup for `{table}` failed: {e}"));

    rows.into_iter()
        .map(|r| {
            (
                r.get::<String, _>("column_name"),
                r.get::<String, _>("data_type"),
                r.get::<String, _>("is_nullable"),
            )
        })
        .collect()
}

/// Every table 060 creates has exactly the expected columns, types and
/// nullability. An added or dropped column fails loudly, by name.
#[sqlx::test(migrations = "../../migrations")]
async fn schema_contract_group_tenancy_tables(pool: PgPool) {
    for (table, expected) in CONTRACTS {
        let observed = observed_columns(&pool, table).await;
        assert!(
            !observed.is_empty(),
            "table `{table}` does not exist — migration 060 did not apply"
        );

        let expected_owned: Vec<(String, String, String)> = expected
            .iter()
            .map(|(c, t, n)| ((*c).to_string(), (*t).to_string(), (*n).to_string()))
            .collect();

        assert_eq!(
            observed, expected_owned,
            "column contract drift on `{table}`.\n  observed: {observed:?}\n  expected: {expected_owned:?}"
        );
    }
}

/// `DELETE FROM groups` is refused by `epigraph_block_group_delete` unless the
/// caller explicitly opts in. Deprovisioning is a status transition; a raw
/// DELETE would CASCADE away every membership, epoch and ciphertext.
#[sqlx::test(migrations = "../../migrations")]
async fn delete_from_groups_raises(pool: PgPool) {
    let group_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind) \
         VALUES ($1, 'contract-test', $2, decode(repeat('00', 32), 'hex'), 'team')",
    )
    .bind(group_id)
    .bind(format!("did:key:{group_id}"))
    .execute(&pool)
    .await
    .expect("insert team group");

    let err = sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(group_id)
        .execute(&pool)
        .await
        .expect_err("DELETE FROM groups must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("refusing DELETE FROM groups"),
        "unexpected error text: {msg}"
    );

    // The documented escape hatch: an explicit, transaction-local opt-in.
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL epigraph.allow_group_delete = 'yes'")
        .execute(&mut *tx)
        .await
        .expect("set local");
    sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(group_id)
        .execute(&mut *tx)
        .await
        .expect("forced delete should succeed");
    tx.commit().await.expect("commit");

    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM groups WHERE id = $1")
        .bind(group_id)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(remaining, 0, "forced delete should have removed the row");
}

/// 060 must be re-runnable by hand against an already-migrated database:
/// operators replay a migration file directly when reconciling
/// `_sqlx_migrations`, and `ops/reconcile_2026_05_05.sql` (docs/deploy.md) is
/// precedent that this repo does exactly that. Cheap insurance, too, against a
/// future edit dropping an `IF NOT EXISTS` from one of the seven
/// `CREATE INDEX`es.
///
/// It is NOT insurance against a `lock_timeout` abort — sqlx wraps the migration
/// body and its `_sqlx_migrations` insert in one transaction, so an abort rolls
/// the DDL back too and the retry meets an untouched schema, which is just the
/// fresh-install path `schema_contract_group_tenancy_tables` already covers.
///
/// The file opens with `SET LOCAL lock_timeout`, which merely warns outside a
/// transaction, so the replay runs inside one.
#[sqlx::test(migrations = "../../migrations")]
async fn migration_060_is_idempotent(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::raw_sql(MIGRATION_060)
        .execute(&mut *tx)
        .await
        .expect("re-applying migration 060 must succeed");
    tx.commit().await.expect("commit");
}

/// The drift guard at the top of 060 must refuse a database where one of these
/// tables already exists in a shape 060 did not create — the epigraph-enterprise
/// lineage, where `CREATE TABLE IF NOT EXISTS` would silently no-op and leave
/// the RESTRICT FKs, the `fully_private` tier CHECK and the least-privilege
/// membership default unapplied while the migration reported success.
///
/// Simulated by removing one sentinel constraint and replaying the file. This is
/// the discriminating case the fresh-database contract test cannot reach.
#[sqlx::test(migrations = "../../migrations")]
async fn drift_guard_rejects_a_pre_060_table_shape(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");

    // Make `groups` look pre-060 to the guard.
    sqlx::query("ALTER TABLE public.groups DROP CONSTRAINT groups_kind_check")
        .execute(&mut *tx)
        .await
        .expect("drop sentinel constraint");

    let err = sqlx::raw_sql(MIGRATION_060)
        .execute(&mut *tx)
        .await
        .expect_err("060 must refuse to run against a pre-060 `groups`");
    let msg = err.to_string();
    assert!(
        msg.contains("already exists in a pre-060 shape") && msg.contains("groups"),
        "unexpected error text: {msg}"
    );

    // Nothing is kept: the simulation must not leak out of the test.
    tx.rollback().await.expect("rollback");
}

/// The three tenancy roles are cluster-scoped, so 060 creates them under a guard
/// that swallows `duplicate_object` and `unique_violation` (a parallel test
/// database won the race) and `insufficient_privilege` (managed Postgres, where
/// the deploy system provisions them out of band).
///
/// Absence is not fatal here on purpose: the fatal assertion belongs in
/// `AppState::with_db` (PR-17), where a production process can refuse to boot.
/// What IS asserted is the one property 060 decides and nothing else checks —
/// every role it creates is `NOLOGIN`. These roles exist to be `GRANT`ed to and
/// to be tested by `pg_has_role` in 070; a role that can log in is an
/// authentication surface nobody meant to open.
///
/// (The old "0 or 3" assertion could not fail: the `DO` block wraps each
/// iteration in its own `BEGIN … EXCEPTION`, so 1 and 2 are unreachable by
/// construction — which is exactly what it claimed to prove.)
#[sqlx::test(migrations = "../../migrations")]
async fn tenancy_roles_are_nologin(pool: PgPool) {
    let rows = sqlx::query(
        "SELECT rolname, rolcanlogin FROM pg_roles \
         WHERE rolname IN ('epigraph_app', 'epigraph_maintenance', 'epigraph_seed') \
         ORDER BY rolname",
    )
    .fetch_all(&pool)
    .await
    .expect("pg_roles lookup");

    for row in &rows {
        let name: String = row.get("rolname");
        let can_login: bool = row.get("rolcanlogin");
        assert!(
            !can_login,
            "role `{name}` must be NOLOGIN — migration 060 creates it that way"
        );
    }
}

// =============================================================================
// PR-02 — agents.key_kind (migration 061)
// =============================================================================

/// `agents` is deliberately NOT covered by a full `ColumnContract` above: it is
/// created by migration 001, not 060, and pinning its whole shape here would
/// make this file the contract for a table PR-01 does not own.
///
/// What IS pinned is the ONE column the signature path now depends on.
/// `AgentRepository::public_key_if_signer` filters `key_kind = 'ed25519'`, which
/// is the only thing separating a real Ed25519 verifier from the 32-byte BLAKE3
/// placeholder `ensure_for_client` writes for every keyless OAuth principal. A
/// later migration that dropped the column, widened the CHECK, or made it
/// nullable would silently readmit those placeholders to the verifier — and
/// because that query is a runtime `sqlx::query_as`, `SQLX_OFFLINE=true cargo
/// check` would not notice.
#[sqlx::test(migrations = "../../migrations")]
async fn agents_key_kind_discriminator_is_intact(pool: PgPool) {
    let row = sqlx::query(
        "SELECT data_type, is_nullable, column_default \
         FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'agents' AND column_name = 'key_kind'",
    )
    .fetch_optional(&pool)
    .await
    .expect("information_schema lookup")
    .expect("agents.key_kind must exist (migration 061)");

    let data_type: String = row.get("data_type");
    let is_nullable: String = row.get("is_nullable");
    let column_default: Option<String> = row.get("column_default");

    assert_eq!(data_type, "character varying");
    assert_eq!(
        is_nullable, "NO",
        "a NULL key_kind would be neither 'ed25519' nor 'derived' and would fall \
         out of every signature filter"
    );
    assert!(
        column_default
            .as_deref()
            .unwrap_or("")
            .contains("'ed25519'"),
        "pre-existing agents predate the discriminator and must default to being \
         real signers; got {column_default:?}"
    );

    // The CHECK is what makes the two-valued vocabulary enforceable.
    let check: Option<(String,)> = sqlx::query_as(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
         WHERE conname = 'agents_key_kind_check'",
    )
    .fetch_optional(&pool)
    .await
    .expect("pg_constraint lookup");

    let check = check.expect("agents_key_kind_check must exist").0;
    for value in ["ed25519", "derived"] {
        assert!(
            check.contains(value),
            "CHECK must admit {value}; got {check}"
        );
    }

    // `contains` alone is the wrong shape of assertion: a CHECK widened to
    // `key_kind IN ('ed25519','derived','legacy')` satisfies it, and a widened
    // CHECK is exactly the regression this test exists to catch. Prove EXCLUSION
    // by making the database reject a third value.
    let bogus = sqlx::query(
        "INSERT INTO agents (public_key, display_name, key_kind) \
         VALUES (decode(repeat('ab', 32), 'hex'), 'widened-check-probe', 'legacy')",
    )
    .execute(&pool)
    .await;
    let err = bogus.expect_err("agents_key_kind_check must reject a third value");
    let code = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    assert_eq!(
        code, "23514",
        "expected a CHECK violation (23514), got {err}"
    );

    // And the two real values are actually storable — otherwise a CHECK that
    // rejects EVERYTHING would pass the assertion above.
    for (i, kind) in ["ed25519", "derived"].iter().enumerate() {
        sqlx::query(
            "INSERT INTO agents (public_key, display_name, key_kind) \
             VALUES (decode(repeat($1, 32), 'hex'), $2, $3)",
        )
        .bind(format!("{:02x}", 0x10 + i))
        .bind(format!("probe-{kind}"))
        .bind(kind)
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("key_kind={kind} must be storable: {e}"));
    }
}

/// 061 must be re-runnable by hand against an already-migrated database, for the
/// same reason 060 must (see [`migration_060_is_idempotent`]) — and for one more:
/// 061's own header tells PR-04 it may keep the identical statements in its
/// tenancy-columns migration, "where they will simply no-op". That is a promise
/// a later PR will rely on, so it is pinned here rather than left as a comment.
#[sqlx::test(migrations = "../../migrations")]
async fn migration_061_is_idempotent(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::raw_sql(MIGRATION_061)
        .execute(&mut *tx)
        .await
        .expect("re-applying migration 061 must succeed");

    // Exactly one constraint, still valid — a second ADD CONSTRAINT would have
    // been rejected outright, but a guard that silently created a differently
    // named duplicate would not.
    let n: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM pg_constraint \
         WHERE conrelid = 'public.agents'::regclass AND contype = 'c' \
           AND conname = 'agents_key_kind_check' AND convalidated",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("pg_constraint count");
    assert_eq!(
        n.0, 1,
        "expected exactly one VALIDATED agents_key_kind_check"
    );

    tx.commit().await.expect("commit");
}

/// 061's drift guard, the counterpart to `drift_guard_rejects_a_pre_060_table_shape`.
///
/// `ADD COLUMN IF NOT EXISTS` is silent about a column that already exists in a
/// DIFFERENT shape, and a SQL CHECK passes on NULL — so a pre-existing NULLABLE
/// `agents.key_kind` would survive the file untouched and every NULL row would
/// fall out of `public_key_if_signer`'s `key_kind = 'ed25519'` filter, silently
/// disabling packet signing for those agents. Catalog-guarded and shape-guarded
/// are not the same thing.
#[sqlx::test(migrations = "../../migrations")]
async fn migration_061_refuses_a_nullable_key_kind(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");

    sqlx::query("ALTER TABLE public.agents ALTER COLUMN key_kind DROP NOT NULL")
        .execute(&mut *tx)
        .await
        .expect("make key_kind nullable");

    let err = sqlx::raw_sql(MIGRATION_061)
        .execute(&mut *tx)
        .await
        .expect_err("061 must refuse a nullable agents.key_kind");
    let msg = err.to_string();
    assert!(
        msg.contains("already exists in a shape 061 did not create"),
        "unexpected error text: {msg}"
    );

    tx.rollback().await.expect("rollback");
}
