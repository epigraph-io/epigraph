//! The shape migrations 062–067 create, and the `-- no-transaction` rule they
//! introduced.
//!
//! Three of these assertions are named on PR-04's Tests line and belong to no
//! existing file:
//!
//! * `-- no-transaction` is honoured, and no index is left INVALID;
//! * `idx_claims_embedding_hnsw_public` does not exist;
//! * migration 062 applies twice.
//!
//! The fourth is a **source lint** with no counterpart anywhere else: a
//! `-- no-transaction` migration must contain exactly one statement. That is not
//! style. sqlx-postgres 0.8.6's `execute_migration` runs
//! `conn.execute(&*migration.sql)` (`src/migrate.rs:280`), i.e. the whole file as
//! ONE simple-query message; PostgreSQL wraps a multi-statement simple query in
//! an implicit transaction block; and `CREATE INDEX CONCURRENTLY` inside one
//! raises 25001. Reproduced against this cluster. Without the lint, the next
//! person merges the four index migrations back into one file and the entire
//! workspace suite goes red at once, with an error message that names sqlx
//! rather than the edit.

use sqlx::{PgPool, Row};
use std::collections::BTreeSet;

/// The migration file itself, embedded so the replay test cannot drift from it.
const MIGRATION_062: &str = include_str!("../../../migrations/062_tenancy_columns.sql");

/// The `-- no-transaction` index migrations, and the index each creates.
const INDEX_MIGRATIONS: &[(&str, &str)] = &[
    (
        "063_idx_claims_group_current.sql",
        "idx_claims_group_current",
    ),
    (
        "064_idx_evidence_owner_group.sql",
        "idx_evidence_owner_group",
    ),
    ("065_idx_edges_owner_group.sql", "idx_edges_owner_group"),
    ("066_idx_claims_world_owned.sql", "idx_claims_world_owned"),
];

/// The tier-A set migration 062 widens. Duplicated here on purpose: a test that
/// re-derived the list from the migration file would pass whatever the migration
/// did.
const TIER_A: &[&str] = &[
    "claims",
    "evidence",
    "edges",
    "triples",
    "entity_mentions",
    "claim_versions",
    "mass_functions",
    "ds_combined_beliefs",
    "ds_bayesian_divergence",
    "claim_frames",
    "harvester_claim_provenance",
    "challenges",
    "reasoning_traces",
    "experiment_triples",
    "experiment_entity_mentions",
    "claim_clusters",
    "claim_cluster_membership",
    "claim_neighborhood_membership",
    "claim_signature_revocations",
    "harvester_fragments",
    "frames",
    "contexts",
    "perspectives",
    "communities",
    "recall_events",
];

const WORLD_GROUP: &str = "00000000-0000-0000-0000-000000000000";
const SEED_GROUP: &str = "00000000-0000-0000-0000-00000000dead";

fn migrations_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations"))
}

// ===========================================================================
// 1 — `-- no-transaction` was honoured, and every index is valid
// ===========================================================================

/// That this test's database exists at all is the proof that `-- no-transaction`
/// was honoured: without it, migration 063 raises
/// `CREATE INDEX CONCURRENTLY cannot run inside a transaction block` and every
/// `#[sqlx::test]` in the workspace fails at setup. The assertions below add the
/// part that a mere "it applied" does not cover — a CIC can succeed as a
/// statement and still leave an index `indisvalid = false`.
#[sqlx::test(migrations = "../../migrations")]
async fn no_transaction_is_honoured_and_every_index_is_valid(pool: PgPool) {
    for (file, index) in INDEX_MIGRATIONS {
        let row = sqlx::query(
            "SELECT i.indisvalid FROM pg_class c \
               JOIN pg_index i ON i.indexrelid = c.oid \
              WHERE c.relname = $1",
        )
        .bind(index)
        .fetch_optional(&pool)
        .await
        .expect("pg_index lookup")
        .unwrap_or_else(|| panic!("{index} does not exist — did {file} apply?"));

        let valid: bool = row.get("indisvalid");
        assert!(
            valid,
            "{index} exists but is INVALID. A failed CREATE INDEX CONCURRENTLY \
             leaves an unusable index behind and, because the migration ran with \
             no transaction, no _sqlx_migrations row either. Recovery: \
             DROP INDEX CONCURRENTLY {index}; then re-run the migration."
        );
    }

    let invalid: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid \
          WHERE NOT i.indisvalid",
    )
    .fetch_one(&pool)
    .await
    .expect("invalid-index count");
    assert_eq!(
        invalid, 0,
        "the migrated schema contains {invalid} INVALID index(es). Detect them \
         with: SELECT c.relname FROM pg_class c JOIN pg_index i ON \
         i.indexrelid = c.oid WHERE NOT i.indisvalid;"
    );
}

/// The three partial tenancy indexes must all spell their predicate the SAME
/// way, and it must be `<> 'public'`.
///
/// This is not tidiness. `check_index_predicates` proves implication
/// syntactically and never consults table CHECK constraints, so
/// `visibility = 'group'` and `visibility <> 'public'` are NOT interchangeable
/// even though `claims_visibility_check` makes them match the same rows (and
/// that constraint ships `NOT VALID`, which `plancat.c` skips outright). `=` is
/// provable from the btree opfamily to imply `<>`, but not conversely, so
/// `<> 'public'` is the dominant spelling. An earlier draft had `claims` on `=`
/// and `evidence`/`edges` on `<>`, which means one uniformly generated qual
/// index-scans two of them and seq-scans the third.
#[sqlx::test(migrations = "../../migrations")]
async fn the_three_partial_tenancy_indexes_share_one_predicate_spelling(pool: PgPool) {
    for index in [
        "idx_claims_group_current",
        "idx_evidence_owner_group",
        "idx_edges_owner_group",
    ] {
        let def: String = sqlx::query_scalar("SELECT indexdef FROM pg_indexes WHERE indexname = $1")
            .bind(index)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("{index} must exist: {e}"));
        assert!(
            def.contains("WHERE ((visibility)::text <> 'public'::text)"),
            "{index} must predicate on `visibility <> 'public'`, the spelling that \
             is implied by BOTH `<> 'public'` and `= 'group'` quals. Got: {def}"
        );
    }
}

/// A planner pin for what those indexes actually serve.
///
/// They are reachable from an EXPLICIT `visibility` qual — the D4 admin surface
/// and PR-18's privatization plans — and NOT from the ordinary D3 read
/// predicate, because `A OR B` implies neither disjunct. Both halves are
/// asserted, so a later reshuffle of either the index predicate or the emitted
/// qual cannot silently orphan the indexes (or silently start relying on them).
#[sqlx::test(migrations = "../../migrations")]
async fn the_partial_tenancy_indexes_serve_an_explicit_visibility_qual(pool: PgPool) {
    // ONE connection for the whole test: `SET enable_seqscan` is session-scoped,
    // and a pool is free to hand the next statement a different backend.
    let mut conn = pool.acquire().await.expect("acquire");

    // Force the choice: on an empty table a seq scan is always cheapest, so
    // without this the plan says nothing about whether the index is a CANDIDATE.
    // With seqscan disabled, a Seq Scan in the output means `predOK` was false —
    // the index was not even considered.
    sqlx::query("SET enable_seqscan = off")
        .execute(&mut *conn)
        .await
        .expect("disable seqscan");

    async fn explain(conn: &mut sqlx::PgConnection, sql: &str) -> String {
        sqlx::query_scalar::<_, String>(&format!("EXPLAIN (COSTS OFF) {sql}"))
            .fetch_all(conn)
            .await
            .expect("EXPLAIN")
            .join("\n")
    }

    // Reachable: an explicit `visibility = 'group'` qual.
    let plan = explain(
        &mut conn,
        "SELECT id FROM claims WHERE visibility = 'group' \
           AND owner_group_id = '00000000-0000-0000-0000-00000000beef'::uuid",
    )
    .await;
    assert!(
        plan.contains("idx_claims_group_current"),
        "an explicit `visibility = 'group'` qual must reach idx_claims_group_current \
         (this is the D4/PR-18 shape the index exists for). Plan:\n{plan}"
    );

    // Also reachable from the `<>` spelling, which `= 'group'` does not admit.
    let plan = explain(
        &mut conn,
        "SELECT id FROM evidence WHERE visibility <> 'public' \
           AND owner_group_id = '00000000-0000-0000-0000-00000000beef'::uuid",
    )
    .await;
    assert!(
        plan.contains("idx_evidence_owner_group"),
        "a `visibility <> 'public'` qual must reach idx_evidence_owner_group. Plan:\n{plan}"
    );

    // NOT reachable: the D3 read predicate. Recorded so nobody adds an index
    // "for the read path" on the same false premise the deleted
    // idx_claims_embedding_hnsw_public rested on.
    let plan = explain(
        &mut conn,
        "SELECT id FROM claims WHERE (visibility = 'public' \
           OR owner_group_id = ANY(ARRAY['00000000-0000-0000-0000-00000000beef'::uuid]))",
    )
    .await;
    assert!(
        !plan.contains("idx_claims_group_current"),
        "the D3 read predicate must NOT be served by a partial index on `visibility`: \
         `A OR B` implies neither disjunct. If this now passes, the emitted qual \
         changed shape and PR-06's index story needs revisiting. Plan:\n{plan}"
    );
}

// ===========================================================================
// 2 — the one-statement-per-file rule, as a source lint
// ===========================================================================

/// Strip SQL comments (`--` to end of line, and `/* … */`) and collapse string
/// literals, so `;` inside either does not count as a statement terminator.
///
/// **Known limitation:** `$$`-quoted bodies are NOT handled. Correct for
/// 063–066, which contain no `DO` block, and the lint only runs over
/// `-- no-transaction` files — which by the rule in `migrations/README.md` hold
/// index statements only. The first `-- no-transaction` file to contain a `DO`
/// block will be mis-counted and this lint will fire spuriously; teach the
/// scanner about dollar quoting at that point rather than deleting the lint.
fn strip_sql_noise(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'-' && i + 1 < b.len() && b[i + 1] == b'-' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(b.len());
        } else if b[i] == b'\'' {
            // A single-quoted literal. '' is an escaped quote.
            i += 1;
            while i < b.len() {
                if b[i] == b'\'' {
                    if i + 1 < b.len() && b[i + 1] == b'\'' {
                        i += 2;
                        continue;
                    }
                    break;
                }
                i += 1;
            }
            i += 1;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

#[test]
fn no_transaction_files_contain_exactly_one_statement() {
    let dir = migrations_dir();
    let mut checked = 0usize;

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    entries.sort();

    for path in entries {
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

        // sqlx-core 0.8.6 `src/migrate/source.rs:127` does
        // `sql.starts_with("-- no-transaction")`, on the LITERAL first bytes of
        // the file. No BOM, no blank line, no `-- <name>.sql` header above it.
        if !src.starts_with("-- no-transaction") {
            continue;
        }
        checked += 1;

        let stripped = strip_sql_noise(&src);
        let statements: Vec<&str> = stripped
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        assert_eq!(
            statements.len(),
            1,
            "{} is a `-- no-transaction` migration with {} statements.\n\
             \n\
             sqlx-postgres 0.8.6 executes the WHOLE FILE as one simple query \
             (src/migrate.rs:280), PostgreSQL wraps a multi-statement simple \
             query in an implicit transaction block, and CREATE INDEX \
             CONCURRENTLY inside one raises 25001. Interleaving `COMMIT;` does \
             not help — that was tested. Split it into one file per statement.",
            path.file_name().unwrap_or_default().to_string_lossy(),
            statements.len()
        );

        assert!(
            statements[0].to_ascii_uppercase().contains("CONCURRENTLY"),
            "{} is `-- no-transaction` but does not run a CONCURRENTLY \
             statement. A migration that does not need to escape the transaction \
             should not: without one, a failure leaves no _sqlx_migrations row \
             AND a partially applied file.",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
    }

    assert_eq!(
        checked,
        INDEX_MIGRATIONS.len(),
        "expected exactly {} `-- no-transaction` migrations (063-066); found {checked}. \
         Adding one is fine — add it to INDEX_MIGRATIONS so its index validity is \
         checked too.",
        INDEX_MIGRATIONS.len()
    );
}

/// The lint's own instrument, tested. A statement scanner that silently returned
/// 1 for everything would make the ratchet above vacuous.
#[test]
fn the_statement_scanner_is_not_vacuous() {
    assert_eq!(
        strip_sql_noise("SELECT 1; -- ; ; ;\n").matches(';').count(),
        1
    );
    assert_eq!(
        strip_sql_noise("SELECT ';;;'::text;").matches(';').count(),
        1
    );
    assert_eq!(
        strip_sql_noise("/* ; ; */ SELECT 1;").matches(';').count(),
        1
    );
    assert_eq!(
        strip_sql_noise("SELECT 1; SELECT 2;").matches(';').count(),
        2
    );
}

// ===========================================================================
// 3 — the public HNSW index the plan called for does not exist
// ===========================================================================

/// PR-04 acceptance, stated as a negative.
///
/// `idx_claims_embedding_hnsw_public` was deleted from the plan because under D3
/// the anonymous caller cannot exist, and the only app-emitted qual on `claims`
/// becomes `… AND (visibility = 'public' OR owner_group_id = ANY($V))`. `A OR B`
/// does not imply `A`, so PostgreSQL can never prove the index's predicate and
/// the index is unreachable — a second HNSW index on the largest table, built and
/// maintained for nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn no_public_hnsw_index_exists(pool: PgPool) {
    let reg: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.idx_claims_embedding_hnsw_public')::text")
            .fetch_one(&pool)
            .await
            .expect("to_regclass");
    assert!(
        reg.is_none(),
        "idx_claims_embedding_hnsw_public exists ({reg:?}). It is unreachable \
         under the D3 predicate; do not reintroduce it without the two-leg UNION \
         rewrite the plan defers as `062b`."
    );

    // And more generally: no partial index on `claims` combines `hnsw` with a
    // `visibility` predicate, whatever it is called.
    let rows = sqlx::query(
        "SELECT c.relname, pg_get_expr(i.indpred, i.indrelid) AS pred, am.amname \
           FROM pg_index i \
           JOIN pg_class c  ON c.oid = i.indexrelid \
           JOIN pg_class t  ON t.oid = i.indrelid \
           JOIN pg_am    am ON am.oid = c.relam \
          WHERE t.relname = 'claims' AND i.indpred IS NOT NULL",
    )
    .fetch_all(&pool)
    .await
    .expect("partial index scan");

    for row in rows {
        let name: String = row.get("relname");
        let pred: Option<String> = row.get("pred");
        let am: String = row.get("amname");
        let pred = pred.unwrap_or_default();
        assert!(
            !(am == "hnsw" && pred.contains("visibility")),
            "partial ANN index {name} predicates on visibility ({pred}); see above"
        );
    }
}

// ===========================================================================
// 4 — migration 062 is idempotent
// ===========================================================================

/// A `lock_timeout` abort inside 062 leaves no `_sqlx_migrations` row, so the
/// operator's remedy is to re-run the file. Every statement in it is
/// `IF NOT EXISTS` or catalog-guarded for that reason, and this replays it to
/// prove it.
///
/// Replayed inside a transaction: 062 opens with `SET LOCAL lock_timeout`, which
/// merely WARNs outside one, and the whole file is transactional anyway. (The
/// index migrations cannot be replayed this way — `CREATE INDEX CONCURRENTLY`
/// raises 25001 inside a transaction — which is exactly why their idempotence is
/// asserted as `indisvalid` above instead.)
#[sqlx::test(migrations = "../../migrations")]
async fn migration_062_is_idempotent(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::raw_sql(MIGRATION_062)
        .execute(&mut *tx)
        .await
        .expect("re-applying migration 062 must succeed");

    // A guard that silently created a differently named duplicate would not be
    // caught by "the statement did not error".
    //
    // CONRELID-QUALIFIED, matching the migration's own guards. `conname` is
    // unique per RELATION, not per database, so a bare name lookup here would
    // share the migration's blind spot exactly — a same-named constraint on any
    // other table would satisfy both, and the test could never disagree with
    // the guard it is checking.
    let n: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM pg_constraint \
          WHERE conrelid = 'public.claims'::regclass \
            AND conname = 'claims_visibility_check'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("constraint count");
    assert_eq!(n.0, 1, "expected exactly one claims_visibility_check");

    // The transcription-log FK is guarded on the COLUMN, not on a name (the
    // inline REFERENCES is auto-named). A name guard there would add a
    // duplicate on every fresh database; this catches that.
    let fks: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM pg_constraint \
          WHERE conrelid = 'public.tenancy_transcription_log'::regclass \
            AND contype = 'f'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("fk count");
    assert_eq!(
        fks.0, 1,
        "tenancy_transcription_log must carry exactly one FK after a replay"
    );

    // And the world/seed rows were not duplicated by the ON CONFLICT DO NOTHING.
    let g: (i64,) = sqlx::query_as("SELECT count(*) FROM groups WHERE kind IN ('world','seed')")
        .fetch_one(&mut *tx)
        .await
        .expect("group count");
    assert_eq!(g.0, 2);

    tx.commit().await.expect("commit");
}

// ===========================================================================
// 5 — the world and seed groups
// ===========================================================================

/// `world` is a SHAPE CONSTANT, not an owner. `seed` exists so migration 074's
/// backfill has something real to stamp: plan §8.2 A4 requires
/// `count(*) FROM claims WHERE owner_group_id = <world>` to reach zero, which is
/// unachievable if the backfill stamps world.
#[sqlx::test(migrations = "../../migrations")]
async fn world_and_seed_groups_exist_with_the_right_shape(pool: PgPool) {
    for (id, kind) in [(WORLD_GROUP, "world"), (SEED_GROUP, "seed")] {
        let row = sqlx::query(
            "SELECT kind, octet_length(public_key) AS keylen, status \
               FROM groups WHERE id = $1::uuid",
        )
        .bind(id)
        .fetch_optional(&pool)
        .await
        .expect("groups lookup")
        .unwrap_or_else(|| panic!("the {kind} group ({id}) must exist"));

        assert_eq!(row.get::<String, _>("kind"), kind);
        assert_eq!(
            row.get::<i32, _>("keylen"),
            0,
            "groups_public_key_shape requires octet_length(public_key) = 0 for \
             every kind <> 'team'; the {kind} group carries no key material"
        );
        assert_eq!(row.get::<String, _>("status"), "active");

        let epochs: i64 =
            sqlx::query_scalar("SELECT count(*) FROM group_key_epochs WHERE group_id = $1::uuid")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("epoch count");
        assert_eq!(epochs, 1, "{kind} has exactly one (keyless) epoch row");
    }

    // The world group has NO members, by design: that is what makes a
    // `visibility = 'group'` row owned by it a black hole, and it is why the
    // `_group_needs_real_group` CHECK exists.
    let members: i64 =
        sqlx::query_scalar("SELECT count(*) FROM group_memberships WHERE group_id = $1::uuid")
            .bind(WORLD_GROUP)
            .fetch_one(&pool)
            .await
            .expect("membership count");
    assert_eq!(
        members, 0,
        "the world group must have no memberships — `owner_group_id = ANY(<viewer \
         groups>)` must never be satisfiable by it"
    );
}

/// The pairing invariant is enforced by the database, not only by convention.
///
/// A `NOT VALID` CHECK still applies to every new row, which is the half that
/// matters: existing rows are the backfill's problem, new ones are not.
/// BOTH arms, and the CONSTRAINT NAME, not just the SQLSTATE.
///
/// The seed group is the same black hole as the world group and is the likelier
/// one to be hit: it has no `group_memberships` rows either, and migration 074
/// arm 4 deliberately stamps it as the owner of legacy rows. An earlier draft
/// excluded only `world`, and nothing here caught it.
///
/// Two traps this test used to fall into, both fixed by the closing positive
/// control:
///
/// * `frames` carries a PRE-EXISTING `frames_not_empty` CHECK
///   (`array_length(hypotheses, 1) >= 2`), and the earlier probe row supplied
///   ONE hypothesis. It was rejected — by the wrong constraint. Both raise
///   SQLSTATE 23514, so asserting the code alone made the whole test vacuous.
///   It now asserts `constraint()`.
/// * A CHECK that rejects everything would also have passed. The final INSERT
///   is the control: `('public', seed)` is precisely the pairing migration 074
///   creates and must remain legal.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_visible_row_cannot_be_owned_by_a_memberless_group(pool: PgPool) {
    for (id, name) in [(WORLD_GROUP, "world"), (SEED_GROUP, "seed")] {
        // The premise: neither group has members, so `owner_group_id = ANY(<viewer
        // groups>)` can never be satisfied by either.
        let members: i64 =
            sqlx::query_scalar("SELECT count(*) FROM group_memberships WHERE group_id = $1::uuid")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("membership count");
        assert_eq!(members, 0, "the {name} group must have no memberships");

        let err = sqlx::query(
            "INSERT INTO frames (name, description, hypotheses, visibility, owner_group_id) \
             VALUES ($2, 'x', ARRAY['h1','h2'], 'group', $1::uuid)",
        )
        .bind(id)
        .bind(format!("black-hole-probe-{name}"))
        .execute(&pool)
        .await
        .expect_err("frames_group_needs_real_group must reject this");

        let db_err = err.as_database_error().expect("a database error");
        assert_eq!(
            db_err.code().map(std::borrow::Cow::into_owned).as_deref(),
            Some("23514"),
            "expected a CHECK violation (23514). Got: {err}"
        );
        assert_eq!(
            db_err.constraint(),
            Some("frames_group_needs_real_group"),
            "rejected by the WRONG constraint. A group-visible row owned by the \
             {name} group is unreadable by ANYBODY, including its author, and \
             `_group_needs_real_group` is what must say so. Got: {err}"
        );
    }

    // The control. Without it a CHECK that rejected every row would pass above.
    // `('public', seed)` is exactly what migration 074 arm 4 writes.
    sqlx::query(
        "INSERT INTO frames (name, description, hypotheses, visibility, owner_group_id) \
         VALUES ('seed-owns-public', 'x', ARRAY['h1','h2'], 'public', $1::uuid)",
    )
    .bind(SEED_GROUP)
    .execute(&pool)
    .await
    .expect("a PUBLIC row owned by seed is exactly what migration 074 creates");
}

// ===========================================================================
// 6 — tier-A coverage
// ===========================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn every_tier_a_table_has_both_columns(pool: PgPool) {
    for table in TIER_A {
        let rows = sqlx::query(
            "SELECT column_name, data_type, is_nullable, column_default \
               FROM information_schema.columns \
              WHERE table_schema = 'public' AND table_name = $1 \
                AND column_name IN ('owner_group_id','visibility') \
              ORDER BY column_name",
        )
        .bind(table)
        .fetch_all(&pool)
        .await
        .expect("information_schema lookup");

        let observed: Vec<(String, String, String)> = rows
            .iter()
            .map(|r| {
                (
                    r.get::<String, _>("column_name"),
                    r.get::<String, _>("data_type"),
                    r.get::<String, _>("is_nullable"),
                )
            })
            .collect();

        assert_eq!(
            observed,
            vec![
                (
                    "owner_group_id".to_string(),
                    "uuid".to_string(),
                    "NO".to_string()
                ),
                (
                    "visibility".to_string(),
                    "character varying".to_string(),
                    "NO".to_string()
                ),
            ],
            "public.{table} does not carry the tenancy columns in the shape 062 \
             creates. A NULLABLE visibility would make every later predicate \
             silently drop rows."
        );

        // The transition DEFAULTs are PRESENT at PR-04. Migration 074 drops them;
        // asserting their absence is PR-16's job (see locked_decisions.rs).
        for r in &rows {
            let default: Option<String> = r.get("column_default");
            assert!(
                default.is_some(),
                "public.{table}.{} lost its transition DEFAULT. Without it, \
                 ADD COLUMN is a table rewrite on a live claims table and every \
                 pre-PR-06 INSERT fails.",
                r.get::<String, _>("column_name")
            );
        }

        // All three constraints, all NOT VALID: validating them is migration
        // 075's job, after the backfill, and doing it here would take an ACCESS
        // EXCLUSIVE lock and a full scan on the largest tables in the schema.
        for suffix in [
            "_visibility_check",
            "_owner_group_fkey",
            "_group_needs_real_group",
        ] {
            let name = format!("{table}{suffix}");
            // conrelid-qualified: see migration_062_is_idempotent for why a bare
            // `conname` lookup shares the migration guard's blind spot.
            let row = sqlx::query(
                "SELECT convalidated FROM pg_constraint \
                  WHERE conrelid = format('public.%I', $2::text)::regclass AND conname = $1",
            )
            .bind(&name)
            .bind(table)
            .fetch_optional(&pool)
            .await
            .expect("pg_constraint lookup")
            .unwrap_or_else(|| panic!("constraint {name} is missing"));
            let validated: bool = row.get("convalidated");
            assert!(
                !validated,
                "{name} is VALIDATED at PR-04. It must ship NOT VALID: validation \
                 is a full scan under ACCESS EXCLUSIVE, and it belongs after the \
                 backfill (migration 075)."
            );
        }

        // The backfill ledger names every tier-A table.
        let seeded: i64 =
            sqlx::query_scalar("SELECT count(*) FROM tenancy_backfill_progress WHERE entity = $1")
                .bind(table)
                .fetch_one(&pool)
                .await
                .expect("tenancy_backfill_progress lookup");
        assert_eq!(seeded, 1, "tenancy_backfill_progress is missing {table}");
    }

    // Exactly 25 tables, no more: a table that gained the columns without being
    // registered in the tier-A array is a table nothing backfills.
    let widened: Vec<String> = sqlx::query_scalar(
        "SELECT table_name FROM information_schema.columns \
          WHERE table_schema = 'public' AND column_name = 'owner_group_id' \
          ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await
    .expect("owner_group_id census");

    let observed: BTreeSet<&str> = widened.iter().map(String::as_str).collect();
    let expected: BTreeSet<&str> = TIER_A.iter().copied().collect();
    assert_eq!(
        observed, expected,
        "the set of tables carrying owner_group_id has drifted from the tier-A \
         array. PR-05's tenancy_coverage.rs re-runs the plan §2.4 generator; \
         this is the cheap pin in the meantime."
    );

    let ledger: i64 = sqlx::query_scalar("SELECT count(*) FROM tenancy_backfill_progress")
        .fetch_one(&pool)
        .await
        .expect("ledger count");
    assert_eq!(
        ledger,
        TIER_A.len() as i64,
        "tenancy_backfill_progress must be seeded from exactly the tier-A array"
    );
}
