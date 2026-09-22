//! Regression test: `method` edges were refused by the entity_types registry.
//!
//! Migration 001 creates `public.methods`, and method edges were writable under
//! the static `edges_entity_types_valid` CHECK (migration 020). Migration 054
//! seeded the `entity_types` registry with 23 rows and omitted `method`;
//! migration 055 then dropped that CHECK and replaced it with
//! `edges_source_type_fkey` REFERENCES entity_types(type_name). From 055
//! onward, an edge naming a kernel-owned table's type was refused by the kernel.
//!
//! Migration 094 seeds the missing row. These tests assert the *behaviour* that
//! restores — a method edge inserts end-to-end — not merely that a row exists,
//! because the row has to satisfy two independent gates: the registry-driven
//! `ELSE` arm of `validate_edge_reference` (a BEFORE-INSERT trigger, so it fires
//! FIRST; it resolves schema_name/table_name/id_column from the registry to
//! existence-check the referenced id, and `method` is absent from that
//! function's hardcoded fast-path arms so it takes the dynamic route), and then
//! the 055 FK.

use sqlx::PgPool;
use uuid::Uuid;

/// Seed an agent + claim (the edge target) and a real `public.methods` row
/// (the edge source).
async fn seed_method_and_claim(pool: &PgPool, byte: u8) -> sqlx::Result<(Uuid, Uuid)> {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind(format!("{byte:02x}").repeat(32))
        .execute(pool)
        .await?;

    let claim_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id) \
         VALUES ($1, 'method-edge-test', decode($2, 'hex'), $3)",
    )
    .bind(claim_id)
    .bind(format!("{byte:02x}").repeat(32))
    .bind(agent_id)
    .execute(pool)
    .await?;

    let method_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO methods (id, name, canonical_name, technique_type) \
         VALUES ($1, 'STM', 'scanning_tunneling_microscopy', 'imaging')",
    )
    .bind(method_id)
    .execute(pool)
    .await?;

    Ok((method_id, claim_id))
}

/// A `method -> claim` edge must insert. This is the end-to-end behaviour the
/// backlog item reported as broken.
#[sqlx::test(migrations = "../../migrations")]
async fn method_source_edge_inserts_end_to_end(pool: PgPool) -> sqlx::Result<()> {
    let (method_id, claim_id) = seed_method_and_claim(&pool, 0xB1).await?;

    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'method', $2, 'claim', 'MEASURED_BY')",
    )
    .bind(method_id)
    .bind(claim_id)
    .execute(&pool)
    .await?;

    Ok(())
}

/// The `method` side must work as an edge TARGET too — 055 added FKs on both
/// `source_type` and `target_type`.
#[sqlx::test(migrations = "../../migrations")]
async fn method_target_edge_inserts_end_to_end(pool: PgPool) -> sqlx::Result<()> {
    let (method_id, claim_id) = seed_method_and_claim(&pool, 0xB2).await?;

    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'method', 'USES_METHOD')",
    )
    .bind(claim_id)
    .bind(method_id)
    .execute(&pool)
    .await?;

    Ok(())
}

/// Load-bearing control: deleting the seeded row reproduces the pre-094 failure.
///
/// This is what pins the two tests above to migration 094 rather than to some
/// other permissive path. Without the registry row the insert must fail on an
/// *entity-type* gate, not on some unrelated constraint that would make the
/// control vacuous.
///
/// MEASURED, and it corrects the backlog item's reading: the item said such an
/// edge is "REJECTED by edges_source_type_fkey". The FK is real, but it is the
/// SECOND gate — `validate_edge_reference` is a BEFORE-INSERT trigger, so with
/// the registry row absent its dynamic `ELSE` arm finds no backing table and
/// raises `Edge source references nonexistent method` first. That message, not
/// the FK's, is the pre-094 symptom an operator would have seen. Either spelling
/// is accepted below; both are the registry refusing the type.
#[sqlx::test(migrations = "../../migrations")]
async fn method_edge_fails_when_the_registry_row_is_absent(pool: PgPool) -> sqlx::Result<()> {
    let (method_id, claim_id) = seed_method_and_claim(&pool, 0xB3).await?;

    // Reproduce the pre-094 registry state. Safe on this throwaway
    // `#[sqlx::test]` database and done before any edge references the row.
    let deleted = sqlx::query("DELETE FROM entity_types WHERE type_name = 'method'")
        .execute(&pool)
        .await?
        .rows_affected();
    assert_eq!(
        deleted, 1,
        "migration 094 must have seeded exactly one `method` row for this control \
         to mean anything; deleted {deleted}"
    );

    let err = sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'method', $2, 'claim', 'MEASURED_BY')",
    )
    .bind(method_id)
    .bind(claim_id)
    .execute(&pool)
    .await
    .expect_err("a method edge must be rejected while the registry row is absent");

    let msg = err.to_string();
    assert!(
        msg.contains("nonexistent method") || msg.contains("edges_source_type_fkey"),
        "the control must fail on an entity-type gate (the validate_edge_reference \
         trigger or edges_source_type_fkey), not something incidental; got: {msg}"
    );

    Ok(())
}

/// The migration must reach its END STATE on a database that already carries a
/// NON-CORE `method` row, not skip.
///
/// This is the case the sibling
/// `seeded_method_row_resolves_to_public_methods_and_is_core` is structurally
/// incapable of catching: `#[sqlx::test]` hands out a virgin database, where
/// 094's INSERT always takes the insert branch, so `ON CONFLICT … DO NOTHING`
/// and `… DO UPDATE` are indistinguishable there.
///
/// The pre-existing row is not hypothetical. MEASURED on the local `epigraph`
/// database: `SELECT type_name, …, is_core FROM entity_types WHERE
/// type_name='method'` → `method|public|methods|id|f|f`. It comes from
/// episcience's `migrations/5000_register_entity_types.sql`, which registers
/// ('method','public','methods','id',false,false) as a downstream stopgap. Under
/// DO NOTHING, 094 is a silent no-op on such a database and `is_core` stays
/// false — while `EntityTypeRepository::register`'s hijack guard is
/// `WHERE entity_types.is_core = false`, i.e. the very condition that leaves a
/// kernel-owned table's type re-pointable.
///
/// Rather than mock that state, the test reproduces it (downgrade the row to the
/// episcience shape) and then re-executes the REAL migration file via
/// `include_str!`, so it fails if the shipped SQL ever goes back to skipping.
#[sqlx::test(migrations = "../../migrations")]
async fn migration_094_promotes_a_pre_existing_non_core_method_row(
    pool: PgPool,
) -> sqlx::Result<()> {
    /// The shipped migration, not a paraphrase of it.
    const MIGRATION_094: &str = include_str!("../../../migrations/094_seed_method_entity_type.sql");

    // Reproduce episcience's downstream stopgap row exactly (is_core=false,
    // its own description), as it exists on the measured dev database.
    let downgraded = sqlx::query(
        "UPDATE entity_types SET is_core = false, \
         description = 'Research method entity (kernel-owned public.methods table); \
         registered by episcience so method edges remain writable under the \
         registry-driven kernel FK/validation (kernel migrations 054/055).' \
         WHERE type_name = 'method'",
    )
    .execute(&pool)
    .await?
    .rows_affected();
    assert_eq!(
        downgraded, 1,
        "the fixture must have had exactly one `method` row to downgrade; \
         updated {downgraded}"
    );

    // Re-run the migration against that state.
    sqlx::raw_sql(MIGRATION_094).execute(&pool).await?;

    let row: (
        String,
        Option<String>,
        String,
        bool,
        bool,
        Option<uuid::Uuid>,
    ) = sqlx::query_as(
        "SELECT schema_name, table_name, id_column, is_optional, is_core, registered_by \
         FROM entity_types WHERE type_name = 'method'",
    )
    .fetch_one(&pool)
    .await?;

    assert!(
        row.4,
        "094 must ASSERT is_core = true on a pre-existing non-core row, not skip it \
         — with `ON CONFLICT DO NOTHING` this is exactly where the hijack guard \
         silently does not exist"
    );
    assert_eq!(row.0, "public");
    assert_eq!(row.1.as_deref(), Some("methods"));
    assert_eq!(row.2, "id");
    assert!(!row.3, "is_optional must remain false");
    assert!(
        row.5.is_none(),
        "a kernel-seeded row carries no registrar client_id; got {:?}",
        row.5
    );

    // Still exactly one row, and the type is still usable as an edge endpoint
    // after the promotion (the thing the migration exists to restore).
    let (method_id, claim_id) = seed_method_and_claim(&pool, 0xB4).await?;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'method', $2, 'claim', 'MEASURED_BY')",
    )
    .bind(method_id)
    .bind(claim_id)
    .execute(&pool)
    .await?;

    Ok(())
}

/// Pin the seeded row's resolution target and its immutability flag.
///
/// Not decoration: `table_name`/`id_column` are what the registry-driven
/// `validate_edge_reference` arm interpolates to existence-check a method id, and
/// `is_core = true` is what makes the row API-immutable —
/// `EntityTypeRepository::register` carries `WHERE entity_types.is_core = false`,
/// so a `false` here would leave a kernel-owned table's type re-pointable by any
/// downstream registrar.
///
/// SCOPE LIMIT, stated because this test used to be read as proving more than it
/// does: it runs on a virgin `#[sqlx::test]` database, where 094 always inserts.
/// The pre-existing-row case is covered by
/// `migration_094_promotes_a_pre_existing_non_core_method_row` above.
#[sqlx::test(migrations = "../../migrations")]
async fn seeded_method_row_resolves_to_public_methods_and_is_core(
    pool: PgPool,
) -> sqlx::Result<()> {
    let row: (String, Option<String>, String, bool, bool) = sqlx::query_as(
        "SELECT schema_name, table_name, id_column, is_optional, is_core \
         FROM entity_types WHERE type_name = 'method'",
    )
    .fetch_one(&pool)
    .await?;

    assert_eq!(row.0, "public");
    assert_eq!(row.1.as_deref(), Some("methods"));
    assert_eq!(row.2, "id");
    assert!(
        !row.3,
        "methods is kernel-owned and always present, so a dangling method \
         reference must fail loud — is_optional must be false"
    );
    assert!(row.4, "the kernel's own types are is_core (hijack guard)");

    Ok(())
}
