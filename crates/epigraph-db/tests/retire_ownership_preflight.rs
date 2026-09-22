//! PR-22 — migration `084_retire_ownership.sql`'s two pre-flights, exercised
//! against the failing state each one exists to refuse.
//!
//! # Why this file cannot use the ordinary harness
//!
//! `#[sqlx::test(migrations = "../../migrations")]` runs the WHOLE migrator
//! before the body executes, so by the time any test here starts, 084 has
//! already applied and `public.ownership` no longer exists. There is nothing
//! left to seed, and a whole-file replay would be worse than no test: the
//! pre-flight's `SELECT count(*) FROM public.ownership` would raise `42P01`,
//! and an assertion keyed on "the migration errored" would report that as the
//! guard firing.
//!
//! So each test scaffolds the retired relation inside a transaction,
//! manufactures the state, executes **one pre-flight block in isolation**, and
//! rolls back. Two properties make that a real test rather than a mock:
//!
//! * **The SQL under test is the file's own text.** [`MIGRATION_084`] is
//!   `include_str!`d and the blocks are sliced out at the `-- >>> PRE-FLIGHT n`
//!   sentinels the migration carries for this purpose. A pre-flight edited in
//!   the migration is the pre-flight executed here; a pre-flight deleted from
//!   it fails [`the_migration_declares_both_pre_flights`].
//! * **The scaffold is the retired relation's own DDL**, sliced out of the
//!   frozen migrations that created it — `001_initial_schema.sql`'s
//!   `CREATE TABLE public.ownership`, `068_communities_to_groups.sql`'s
//!   `community_id` column and its `ownership_key_id_quarantine` view. Nothing
//!   here re-derives a shape by hand, so the predicate is evaluated against the
//!   columns it was written for.
//!
//! # Non-vacuity
//!
//! Every refusal test is paired with a *passing* test over the same scaffold and
//! the same block, differing only in the row state. Without the pair, a block
//! that raised unconditionally — or one that failed for an unrelated reason,
//! such as a mistyped relation name — would look identical to a working guard.
//! The refusal assertions key on the RAISE's own message text, not on "an error
//! happened", for the same reason.

use sqlx::PgPool;
use uuid::Uuid;

/// The migration under test, embedded so this file cannot drift from it.
const MIGRATION_084: &str = include_str!("../../../migrations/084_retire_ownership.sql");

/// The text between `-- >>> PRE-FLIGHT n` and `-- <<< PRE-FLIGHT n`.
fn pre_flight(n: u8) -> &'static str {
    let open = format!("-- >>> PRE-FLIGHT {n}");
    let close = format!("-- <<< PRE-FLIGHT {n}");
    let start = MIGRATION_084
        .find(&open)
        .unwrap_or_else(|| panic!("migration 084 has no `{open}` sentinel"))
        + open.len();
    let end = MIGRATION_084[start..]
        .find(&close)
        .unwrap_or_else(|| panic!("migration 084 has no `{close}` sentinel"))
        + start;
    MIGRATION_084[start..end].trim()
}

/// [`MIGRATION_084`] with every `--` line comment stripped: what the server
/// actually executes.
///
/// The migration's header is long and it explains, among other things, why the
/// file does NOT `DROP TABLE ... CASCADE`. A check over the raw text therefore
/// matches the explanation and fails on a correct migration; that happened on
/// this test's first run. Assertions about what 084 DOES must read the
/// statements.
///
/// Deliberately not a SQL parser: it strips `--` to end of line and nothing
/// else. That is sound here because nothing in 084 puts `--` inside a string
/// literal or a dollar-quoted body, which
/// [`the_comment_stripper_is_not_vacuous`] checks rather than assumes.
fn executable_sql() -> String {
    MIGRATION_084
        .lines()
        .map(|l| match l.find("--") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The stripper above removes comments and keeps statements.
///
/// Without this, a stripper that returned the empty string would make every
/// `contains` assertion in [`the_migration_declares_both_pre_flights`] fail
/// loudly — but one that returned its input unchanged would make the CASCADE
/// assertion silently unfalsifiable again.
#[test]
fn the_comment_stripper_is_not_vacuous() {
    let sql = executable_sql();
    assert!(
        !sql.contains("NO CASCADE, DELIBERATELY"),
        "the stripper must remove the header prose: {sql}"
    );
    assert!(
        sql.contains("SET LOCAL lock_timeout"),
        "the stripper must keep the statements: {sql}"
    );
    assert!(
        !MIGRATION_084.contains("$$'") && !MIGRATION_084.contains("'--"),
        "084 has grown a `--` inside a literal or a dollar-quoted body; the \
         line-based stripper is no longer sound for it"
    );
}

/// The scaffold, shared with `tenancy_coverage.rs`. See its module docs for why
/// the retired relation is sliced out of the frozen migrations rather than
/// written out here.
#[path = "retired_ownership_scaffold.rs"]
mod scaffold_mod;

use scaffold_mod::{ownership_table_ddl, quarantine_view_ddl, scaffold};

/// An `ownership` row in the scaffolded table.
async fn seed_row(
    tx: &mut sqlx::PgConnection,
    node_id: Uuid,
    partition_type: &str,
    encryption_key_id: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO public.ownership (node_id, node_type, partition_type, owner_id, \
                                       encryption_key_id) \
         VALUES ($1, 'claim', $2, $3, $4)",
    )
    .bind(node_id)
    .bind(partition_type)
    .bind(Uuid::new_v4())
    .bind(encryption_key_id)
    .execute(&mut *tx)
    .await
    .expect("seed a scaffolded ownership row");
}

/// A `tenancy_transcription_log` row for `node_id`. The table SURVIVES 084 —
/// this is the real relation, not a scaffold.
///
/// `from_partition` is a PARAMETER, not a constant, because pre-flight 2 joins
/// on it: the ledger is `node_id PRIMARY KEY` overwritten on every firing, so a
/// row recording an OLDER partition than the one the `ownership` row currently
/// holds is exactly the state the guard must refuse. A helper that hardcoded
/// `'private'` could only ever construct the passing case.
async fn seed_transcription(tx: &mut sqlx::PgConnection, node_id: Uuid, from_partition: &str) {
    let group: Uuid = sqlx::query_scalar("SELECT id FROM groups WHERE kind = 'world' LIMIT 1")
        .fetch_one(&mut *tx)
        .await
        .expect("the world group is seeded by migration 060");
    sqlx::query(
        "INSERT INTO public.tenancy_transcription_log \
             (node_id, node_type, from_partition, to_visibility, to_group_id) \
         VALUES ($1, 'claim', $3, 'group', $2)",
    )
    .bind(node_id)
    .bind(group)
    .bind(from_partition)
    .execute(&mut *tx)
    .await
    .expect("seed a transcription ledger row");
}

// =============================================================================
// Calibration — the instrument, before the measurements
// =============================================================================

/// The sentinels exist, both blocks raise, and the drop is not a CASCADE.
///
/// Every other test in this file executes text produced by [`pre_flight`]. A
/// slicer that returned an empty string, or a migration whose guards had been
/// softened to `RAISE WARNING`, would make all four of them pass while
/// asserting nothing.
#[test]
fn the_migration_declares_both_pre_flights() {
    for n in [1u8, 2] {
        let block = pre_flight(n);
        assert!(
            block.contains("DO $$") && block.contains("END $$;"),
            "pre-flight {n} is not a DO block: {block}"
        );
        assert!(
            block.contains("RAISE EXCEPTION"),
            "pre-flight {n} must RAISE EXCEPTION, not warn and proceed. A guard \
             that logs is not a guard: {block}"
        );
    }
    assert!(
        pre_flight(1).contains("ownership_key_id_quarantine"),
        "pre-flight 1 must read the quarantine view"
    );
    assert!(
        pre_flight(2).contains("tenancy_transcription_log"),
        "pre-flight 2 must read the transcription ledger"
    );

    // AGAINST THE STATEMENTS, NOT THE PROSE. 084's header explains at length
    // why it does not CASCADE, so a check over the raw file text matches its own
    // explanation and fails on a correct migration — measured, on the first run
    // of this test. `executable_sql` strips `--` comments first.
    let sql = executable_sql();
    assert!(
        !sql.to_ascii_uppercase().contains("CASCADE"),
        "084 must not CASCADE: the quarantine view is a VIEW over `ownership`, \
         so a CASCADE drop would destroy the object pre-flight 1 inspects. \
         Statements were:\n{sql}"
    );
    assert!(
        sql.contains("DROP VIEW IF EXISTS public.ownership_key_id_quarantine"),
        "084 must drop the quarantine view explicitly, in its own statement"
    );
    assert!(
        sql.contains("DROP FUNCTION IF EXISTS public.epigraph_ownership_transcribe()"),
        "084 must drop 071's write-through body: DROP TABLE removes the trigger \
         but leaves the SECURITY DEFINER function behind"
    );
    assert!(
        sql.contains("DROP TABLE IF EXISTS public.ownership;"),
        "084 must drop the table itself"
    );
}

/// The scaffold is sliced out of the frozen migrations, not written here.
#[test]
fn the_scaffold_is_the_retired_relations_own_ddl() {
    let table = ownership_table_ddl();
    assert!(
        table.contains("node_id uuid NOT NULL")
            && table.contains("partition_type")
            && table.contains("encryption_key_id"),
        "001's CREATE TABLE block did not slice cleanly: {table}"
    );
    assert_eq!(
        table.matches(';').count(),
        1,
        "the slicer takes text up to the FIRST `;`, so a block with an embedded \
         semicolon would be truncated: {table}"
    );

    let view = quarantine_view_ddl();
    assert!(
        view.contains("encryption_key_id IS NOT NULL") && view.contains("community_id IS NULL"),
        "068's view definition did not slice cleanly: {view}"
    );
    assert!(
        view.contains("security_invoker = true"),
        "the scaffolded view must carry the option the real one was created \
         with; a view without it executes as its owner: {view}"
    );
}

// =============================================================================
// Pre-flight 1 — the encryption_key_id quarantine must be empty
// =============================================================================

/// A quarantined row refuses the drop.
#[sqlx::test(migrations = "../../migrations")]
async fn pre_flight_1_refuses_an_untriaged_quarantine_row(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    scaffold(&mut tx).await;
    // `encryption_key_id` set and `community_id` NULL is exactly the view's
    // predicate: a key that was never drained into a live community.
    seed_row(
        &mut tx,
        Uuid::new_v4(),
        "community",
        Some("00000000-0000-0000-0000-0000000000ff"),
    )
    .await;

    let err = sqlx::raw_sql(pre_flight(1))
        .execute(&mut *tx)
        .await
        .expect_err("pre-flight 1 must refuse a non-empty quarantine");
    let msg = err.to_string();
    assert!(
        msg.contains("refusing to DROP ownership") && msg.contains("quarantined"),
        "the failure must be the pre-flight's own RAISE, not an incidental \
         error: {msg}"
    );

    tx.rollback().await.expect("rollback");
}

/// ...and an empty quarantine does not. The control for the test above.
#[sqlx::test(migrations = "../../migrations")]
async fn pre_flight_1_passes_on_an_empty_quarantine(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    scaffold(&mut tx).await;
    // A row that is NOT quarantined: no `encryption_key_id` at all.
    seed_row(&mut tx, Uuid::new_v4(), "public", None).await;

    sqlx::raw_sql(pre_flight(1))
        .execute(&mut *tx)
        .await
        .expect("pre-flight 1 must pass over an empty quarantine");

    tx.rollback().await.expect("rollback");
}

// =============================================================================
// Pre-flight 2 — every non-public row must be in the transcription ledger
// =============================================================================

/// An untranscribed non-public row refuses the drop.
///
/// This is the plan's *Tests* line for PR-22, and it is the one that decides
/// whether the guard is load-bearing: without a ledger row the node's
/// declaration never reached a visibility column, so dropping it silently
/// widens that node.
#[sqlx::test(migrations = "../../migrations")]
async fn pre_flight_2_refuses_an_untranscribed_non_public_row(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    scaffold(&mut tx).await;
    seed_row(&mut tx, Uuid::new_v4(), "private", None).await;

    let err = sqlx::raw_sql(pre_flight(2))
        .execute(&mut *tx)
        .await
        .expect_err("pre-flight 2 must refuse an untranscribed non-public row");
    let msg = err.to_string();
    assert!(
        msg.contains("refusing to DROP ownership")
            && msg.contains("no transcription recording their current partition"),
        "the failure must be the pre-flight's own RAISE, not an incidental \
         error: {msg}"
    );

    tx.rollback().await.expect("rollback");
}

/// ...and the same row with a ledger entry does not.
///
/// The control. It also pins which side of the predicate the ledger row is on:
/// a pre-flight keyed on `EXISTS` rather than `NOT EXISTS` would refuse here and
/// pass above.
#[sqlx::test(migrations = "../../migrations")]
async fn pre_flight_2_passes_when_the_non_public_row_is_logged(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    scaffold(&mut tx).await;
    let node = Uuid::new_v4();
    seed_row(&mut tx, node, "private", None).await;
    seed_transcription(&mut tx, node, "private").await;

    sqlx::raw_sql(pre_flight(2))
        .execute(&mut *tx)
        .await
        .expect("pre-flight 2 must pass once every non-public row is logged");

    tx.rollback().await.expect("rollback");
}

/// A ledger entry that records an OLDER partition than the row now holds is
/// refused — presence of a `node_id` is not enough.
///
/// This is the paired refusal for
/// [`pre_flight_2_passes_when_the_non_public_row_is_logged`], differing from it
/// in exactly one value: the ledger's `from_partition`. Both rows are
/// `partition_type = 'private'`; the passing case logs `'private'` and this one
/// logs `'public'`.
///
/// It is the case a bare `NOT EXISTS (… l.node_id = o.node_id)` would let
/// through, and letting it through is a silent widening on a one-way door.
/// `tenancy_transcription_log` is `node_id PRIMARY KEY` written `ON CONFLICT
/// (node_id) DO UPDATE SET from_partition = EXCLUDED.from_partition` by
/// migration 071's trigger, and written for EVERY `partition_type` including
/// `'public'` — so the ledger holds only the most recent firing. A node last
/// transcribed while public, then moved to a non-public partition without the
/// trigger firing, reaches exactly this state: a ledger row is present, the
/// claim is still stamped public, and the non-public declaration exists nowhere
/// but the `ownership` row 084 is about to destroy.
///
/// Without this test the `from_partition` conjunct would be untested prose, and
/// removing it would leave every other test in this file green.
#[sqlx::test(migrations = "../../migrations")]
async fn pre_flight_2_refuses_a_ledger_entry_for_a_stale_partition(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    scaffold(&mut tx).await;
    let node = Uuid::new_v4();
    seed_row(&mut tx, node, "private", None).await;
    seed_transcription(&mut tx, node, "public").await;

    let err = sqlx::raw_sql(pre_flight(2))
        .execute(&mut *tx)
        .await
        .expect_err(
            "pre-flight 2 must refuse a non-public row whose only ledger entry \
             records a different partition",
        );
    let msg = err.to_string();
    assert!(
        msg.contains("refusing to DROP ownership")
            && msg.contains("no transcription recording their current partition"),
        "the failure must be the pre-flight's own RAISE, not an incidental \
         error: {msg}"
    );

    tx.rollback().await.expect("rollback");
}

/// A PUBLIC row needs no ledger entry — the predicate is `partition_type <>
/// 'public'`, and a public declaration lost nothing by never being transcribed.
#[sqlx::test(migrations = "../../migrations")]
async fn pre_flight_2_ignores_public_rows(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    scaffold(&mut tx).await;
    seed_row(&mut tx, Uuid::new_v4(), "public", None).await;

    sqlx::raw_sql(pre_flight(2))
        .execute(&mut *tx)
        .await
        .expect("a public row without a ledger entry must not block the drop");

    tx.rollback().await.expect("rollback");
}

// =============================================================================
// The acceptance the whole PR is about
// =============================================================================

/// At head, the relation and everything 084 names are gone.
///
/// The migrator has run by the time this body executes, so this asserts the
/// outcome of the real file applied in the real order — not a replay.
#[sqlx::test(migrations = "../../migrations")]
async fn the_ownership_relation_is_retired_at_head(pool: PgPool) {
    for relation in ["public.ownership", "public.ownership_key_id_quarantine"] {
        let reg: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
            .bind(relation)
            .fetch_one(&pool)
            .await
            .expect("to_regclass");
        assert!(reg.is_none(), "{relation} still exists after migration 084");
    }

    let fn_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
                         WHERE n.nspname = 'public' AND p.proname = 'epigraph_ownership_transcribe')",
    )
    .fetch_one(&pool)
    .await
    .expect("read pg_proc");
    assert!(
        !fn_exists,
        "epigraph_ownership_transcribe() survived the table it guarded. \
         DROP TABLE removes the trigger, not the SECURITY DEFINER body behind it."
    );

    // The ledger 084's pre-flight reads OUTLIVES the table. Migration 062 owns
    // it and `schema_contract.rs` pins its shape; asserting it here states that
    // the drop was scoped to `ownership` and did not take the record of what
    // used to be there.
    let log: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.tenancy_transcription_log')::text")
            .fetch_one(&pool)
            .await
            .expect("to_regclass");
    assert!(
        log.is_some(),
        "tenancy_transcription_log must survive 084 — it is the only surviving \
         record of what the dropped rows declared"
    );
}
