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
