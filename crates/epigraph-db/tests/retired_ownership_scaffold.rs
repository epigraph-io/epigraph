//! Recreate the `public.ownership` relation migration 084 retired, from the DDL
//! of the frozen migrations that created it.
//!
//! Included with `#[path]` by the two test binaries that still need the relation
//! to exist for the duration of one transaction:
//!
//! * `retire_ownership_preflight.rs`, which has to manufacture the failing state
//!   each of 084's pre-flights refuses — and cannot, because by the time a
//!   `#[sqlx::test]` body runs, 084 has applied and the table is gone;
//! * `tenancy_coverage.rs`, which replays migration 068. Half of 068 operates on
//!   `ownership`, so at head the replay raises `42P01` on a relation the file
//!   legitimately expected to exist when it was written.
//!
//! # Why it is sliced out of the migrations rather than written here
//!
//! A hand-written stand-in would be a relation this file invented, and every
//! predicate evaluated against it would be a statement about the invention. The
//! shape comes from `001_initial_schema.sql`'s `CREATE TABLE public.ownership`
//! and from `068_communities_to_groups.sql`'s `community_id` column and
//! `ownership_key_id_quarantine` view. Both files are applied and frozen, so the
//! text cannot drift, and [`the_scaffold_is_the_retired_relations_own_ddl`]
//! (in `retire_ownership_preflight.rs`) checks that each slice came out whole.
//!
//! # What it deliberately does NOT recreate
//!
//! The constraints and indexes migrations 062–076 added to `ownership`, and the
//! foreign keys to `agents` and `communities`. Nothing here needs them, and a
//! scaffold that reproduced the whole history of a dropped table would be a
//! second definition of it — which is the thing the drop exists to remove.
//! `068` adds `ownership_community_fkey`, `ownership_key_id_is_uuid` and
//! `ownership_community_needs_community_partition` itself when it is replayed
//! over this scaffold, which is why the replay test can still assert on them.

#![allow(dead_code)]

/// The relation's birth DDL.
const MIGRATION_001: &str = include_str!("../../../migrations/001_initial_schema.sql");

/// `community_id` and the quarantine view.
const MIGRATION_068: &str = include_str!("../../../migrations/068_communities_to_groups.sql");

/// One DDL statement from a frozen migration: from `needle` to the next `;`.
///
/// Every block this is used on is a single statement with no embedded
/// semicolon. That is checked, not assumed — see the calibration test in
/// `retire_ownership_preflight.rs`.
pub fn ddl(src: &str, needle: &str) -> String {
    let start = src
        .find(needle)
        .unwrap_or_else(|| panic!("no `{needle}` in the migration"));
    let end = src[start..]
        .find(';')
        .unwrap_or_else(|| panic!("`{needle}` is not terminated by `;`"))
        + start;
    src[start..=end].to_string()
}

/// `001_initial_schema.sql`'s `CREATE TABLE public.ownership`.
pub fn ownership_table_ddl() -> String {
    ddl(MIGRATION_001, "CREATE TABLE public.ownership (")
}

/// `068`'s `community_id` column.
pub fn community_id_ddl() -> String {
    ddl(
        MIGRATION_068,
        "ALTER TABLE public.ownership ADD COLUMN IF NOT EXISTS community_id",
    )
}

/// `068`'s `ownership_key_id_quarantine` view, `security_invoker` included.
pub fn quarantine_view_ddl() -> String {
    ddl(
        MIGRATION_068,
        "CREATE OR REPLACE VIEW public.ownership_key_id_quarantine",
    )
}

/// Recreate the table (with `community_id`) inside `tx`. No view.
///
/// Callers that go on to replay migration 068 want this one: 068 creates the
/// view itself, and a pre-existing view would mask a `CREATE OR REPLACE` that
/// had stopped working.
pub async fn scaffold_table(tx: &mut sqlx::PgConnection) {
    for stmt in [ownership_table_ddl(), community_id_ddl()] {
        sqlx::raw_sql(&stmt)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| panic!("scaffold statement failed: {e}\n{stmt}"));
    }
}

/// Recreate the table and the quarantine view inside `tx`.
pub async fn scaffold(tx: &mut sqlx::PgConnection) {
    scaffold_table(tx).await;
    let stmt = quarantine_view_ddl();
    sqlx::raw_sql(&stmt)
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|e| panic!("scaffold view failed: {e}\n{stmt}"));
}
