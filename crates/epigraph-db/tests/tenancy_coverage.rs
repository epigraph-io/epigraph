//! Coverage ratchet for the §2.4 *generated* protected set (PR-05).
//!
//! # Why this file exists
//!
//! `tenancy_migration_shape.rs` pins an ENUMERATED list: the 25 tables
//! migration 062 chose to widen. An enumerated list can only ever prove that
//! 062 did what 062 said. It structurally cannot notice the failure the plan's
//! §12 summary names as the whole risk of this series — *"a derived table
//! nobody listed keeps the plaintext public after privatization"* — because a
//! table nobody listed is, by construction, not in the list.
//!
//! This file replaces the list with two GENERATORS run against the live
//! catalogs, so a table added by any future migration is in scope the moment it
//! exists:
//!
//! * **Generator A** — every relation with a `claim_id` column.
//! * **Generator B** — every relation with a FOREIGN KEY referencing `claims`.
//!
//! Plus two **manual additions**, `harvester_fragments` and `edges`, which
//! migration 062 registered by hand. MEASURED: neither is found by either
//! generator — `edges` has no `claim_id` column and no FK to `claims`, and
//! `harvester_fragments` has neither. The manual arm is therefore
//! LOAD-BEARING, not belt-and-braces: it is the entire arithmetic difference
//! between Generator A ∪ B (27 relations) and the protected set (29), and
//! deleting it would silently drop `edges` — a tier-A table 062 widened by
//! hand — out of scope. `manual_additions_are_in_the_protected_set` asserts
//! this so the claim cannot rot.
//!
//! Every member must then be either **covered** — `(visibility,
//! owner_group_id)` both `NOT NULL` — or **registered in
//! `public.tenancy_exempt`** with a stated residual. There is no third option
//! and no silence.
//!
//! # Deliberately non-macro
//!
//! `sqlx::query` / `query_scalar` throughout, never `query!`. CI runs with
//! `SQLX_OFFLINE=true` and a macro here would demand a `.sqlx/` entry —
//! the same rule `schema_contract.rs` and `migrate_on_startup.rs` document at
//! their heads. It also matters more here than there: these queries are ABOUT
//! the catalogs, and a compile-time-checked one would be checked against the
//! developer's database rather than the one under test.
//!
//! # Known limitation of Generator B
//!
//! `information_schema.constraint_column_usage` shows only constraints on
//! relations the querying role has some privilege on. Under a restricted CI
//! role it silently returns fewer rows and the ratchet goes quiet rather than
//! red. `generator_b_is_not_vacuous` asserts a floor against that.

use sqlx::{PgPool, Row};

/// Migration files embedded so the replay test cannot drift from them.
const MIGRATION_068: &str = include_str!("../../../migrations/068_communities_to_groups.sql");
const MIGRATION_069: &str = include_str!("../../../migrations/069_entity_types_tenancy_tier.sql");
/// PR-13's transactional half. Embedded for the same reason as 068/069: a
/// replay test that re-derived the SQL could not catch the file drifting.
const MIGRATION_072: &str = include_str!("../../../migrations/072_edge_co_ownership.sql");

/// The retired `ownership` relation, recreated inside a transaction so migration
/// 068 can be replayed at head. See the module's own docs.
#[path = "retired_ownership_scaffold.rs"]
mod retired_ownership;

/// Registered by migration 062's tier-A list by hand; neither generator's
/// definition names them, so the union states them explicitly.
const MANUAL_ADDITIONS: &[&str] = &["harvester_fragments", "edges"];

/// The union of Generator A, Generator B, and [`MANUAL_ADDITIONS`].
///
/// Written as SQL rather than three round trips so the set the assertions see
/// is exactly the set §2.4 defines, in one place.
const PROTECTED_SET_SQL: &str = r"
WITH gen_a AS (
    SELECT c.table_name AS relname
      FROM information_schema.columns c
     WHERE c.table_schema = 'public' AND c.column_name = 'claim_id'
),
gen_b AS (
    SELECT DISTINCT tc.table_name AS relname
      FROM information_schema.table_constraints tc
      JOIN information_schema.constraint_column_usage ccu
        ON ccu.constraint_name = tc.constraint_name
       AND ccu.constraint_schema = tc.constraint_schema
     WHERE tc.constraint_type = 'FOREIGN KEY'
       AND tc.table_schema = 'public'
       AND ccu.table_name = 'claims'
),
manual AS (SELECT unnest($1::text[]) AS relname)
SELECT relname FROM gen_a
UNION SELECT relname FROM gen_b
UNION SELECT relname FROM manual
ORDER BY 1
";

async fn protected_set(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, String>(PROTECTED_SET_SQL)
        .bind(MANUAL_ADDITIONS)
        .fetch_all(pool)
        .await
        .expect("protected-set generators must run")
}

/// `(visibility NOT NULL, owner_group_id NOT NULL)` for one relation.
async fn tenancy_columns(pool: &PgPool, relname: &str) -> (bool, bool) {
    let row = sqlx::query(
        "SELECT
           bool_or(column_name = 'visibility'     AND is_nullable = 'NO') AS vis,
           bool_or(column_name = 'owner_group_id' AND is_nullable = 'NO') AS ogid
         FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = $1",
    )
    .bind(relname)
    .fetch_one(pool)
    .await
    .expect("column probe");
    (
        row.try_get::<Option<bool>, _>("vis")
            .unwrap()
            .unwrap_or(false),
        row.try_get::<Option<bool>, _>("ogid")
            .unwrap()
            .unwrap_or(false),
    )
}

async fn exempt_tables(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar::<_, String>("SELECT table_name FROM tenancy_exempt")
        .fetch_all(pool)
        .await
        .expect("tenancy_exempt must exist after migration 069")
}

// ===========================================================================
// (a) — every `columns`-tier entity type's backing table really has the columns
// ===========================================================================

/// Plan §3/069 assertion (a). The `columns` tier is a CLAIM about a table; this
/// is the only thing that makes the claim true rather than decorative.
///
/// Passes today: the six `columns` types are claim/evidence/frame/context/
/// perspective/community, and migration 062 gave all six backing tables both
/// columns `NOT NULL`.
#[sqlx::test(migrations = "../../migrations")]
async fn every_columns_tier_registry_row_has_both_not_null_columns(pool: PgPool) {
    let rows = sqlx::query(
        "SELECT type_name, schema_name, table_name FROM entity_types \
          WHERE tenancy_tier = 'columns' ORDER BY type_name",
    )
    .fetch_all(&pool)
    .await
    .expect("registry read");

    assert!(
        !rows.is_empty(),
        "no 'columns'-tier types at all would make this test vacuous"
    );

    let mut violations: Vec<String> = Vec::new();
    for row in &rows {
        let type_name: String = row.try_get("type_name").unwrap();
        let schema: String = row.try_get("schema_name").unwrap();
        let table: Option<String> = row.try_get("table_name").unwrap();
        let Some(table) = table else {
            violations.push(format!("{type_name}: 'columns' tier with NO backing table"));
            continue;
        };
        assert_eq!(schema, "public", "{type_name}: only public is registrable");
        let (vis, ogid) = tenancy_columns(&pool, &table).await;
        if !vis || !ogid {
            violations.push(format!(
                "{type_name} -> {table}: visibility NOT NULL = {vis}, \
                 owner_group_id NOT NULL = {ogid}"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "every 'columns'-tier entity type must have both tenancy columns NOT NULL \
         on its backing table; violations:\n  {}",
        violations.join("\n  ")
    );
}

// ===========================================================================
// (b) — the generated set is covered or exempt. No third option.
// ===========================================================================

/// Plan §3/069 assertion (b), and the reason this file exists.
///
/// MEASURED at migration head 069: Generator A ∪ Generator B returns 27
/// relations and the protected set (with the two manual additions) 29, of which
/// 9 carry no tenancy columns — `alternative_set`, `alt_set_decisions`,
/// `claim_encryption`, `claim_version_encryption`, `behavioral_executions`,
/// `counterfactual_scenarios`, `experiments`, `learning_events`,
/// `match_candidates`. All nine are seeded into `tenancy_exempt` by migration
/// 069. The plan's own three-row seed (claim_themes / agents / jobs) is found
/// by NEITHER generator and would have left this test red on its first run with
/// nine violations; 069 seeds twelve rows for that reason.
#[sqlx::test(migrations = "../../migrations")]
async fn generator_a_and_b_are_covered_or_exempt(pool: PgPool) {
    let protected = protected_set(&pool).await;
    let exempt = exempt_tables(&pool).await;

    let mut violations: Vec<String> = Vec::new();
    for relname in &protected {
        if exempt.iter().any(|e| e == relname) {
            continue;
        }
        let (vis, ogid) = tenancy_columns(&pool, relname).await;
        if !vis || !ogid {
            violations.push(format!(
                "{relname}: visibility NOT NULL = {vis}, owner_group_id NOT NULL = {ogid}, \
                 and no tenancy_exempt row"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "every member of the §2.4 generated protected set must carry both tenancy \
         columns NOT NULL or be registered in tenancy_exempt with a stated residual. \
         A NEW TABLE THAT DERIVES FROM `claims` IS IN SCOPE THE MOMENT IT EXISTS — if \
         this fired on a table you just added, give it the columns or argue the \
         exemption in a migration; do not delete the row from the generator.\n  {}",
        violations.join("\n  ")
    );
}

/// Generator B reads `information_schema.constraint_column_usage`, which shows
/// only constraints on relations the querying role has privileges on. Under a
/// restricted CI role it returns fewer rows and the ratchet above goes VACUOUS
/// rather than red — it would pass by finding nothing to check. A floor is the
/// only defence a test can mount against its own instrument going blind.
#[sqlx::test(migrations = "../../migrations")]
async fn generator_b_is_not_vacuous(pool: PgPool) {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT tc.table_name)::bigint
           FROM information_schema.table_constraints tc
           JOIN information_schema.constraint_column_usage ccu
             ON ccu.constraint_name = tc.constraint_name
            AND ccu.constraint_schema = tc.constraint_schema
          WHERE tc.constraint_type = 'FOREIGN KEY'
            AND tc.table_schema = 'public'
            AND ccu.table_name = 'claims'",
    )
    .fetch_one(&pool)
    .await
    .expect("generator B");
    // FLOORS ARE SET JUST BELOW THE MEASURED VALUE, NOT WELL BELOW IT. A floor
    // of 15 against a measured 22 tolerates SEVEN relations vanishing before
    // the guard that exists to notice exactly that fires, which defeats it.
    assert!(
        n >= 20,
        "Generator B found only {n} relations with an FK to claims. Either the role \
         running this test cannot see the catalogs (constraint_column_usage is \
         privilege-filtered) or the schema shrank. MEASURED at head 069: 22."
    );

    let total = protected_set(&pool).await.len();
    assert!(
        total >= 27,
        "the generated protected set collapsed to {total} relations. MEASURED at head \
         069: 29 (Generator A ∪ B = 27, plus the two manual additions, neither of \
         which either generator finds)."
    );
}

/// The manual arm is load-bearing, and the module header says so. Asserted
/// rather than asserted-in-prose: if a future migration gives `edges` a
/// `claim_id` or an FK to `claims`, the generators pick it up and this still
/// passes; if someone deletes `MANUAL_ADDITIONS` believing it redundant, the
/// protected set silently loses a tier-A table and only this fires.
#[sqlx::test(migrations = "../../migrations")]
async fn manual_additions_are_in_the_protected_set(pool: PgPool) {
    let protected = protected_set(&pool).await;
    for name in MANUAL_ADDITIONS {
        assert!(
            protected.iter().any(|r| r == name),
            "{name} is a MANUAL_ADDITION but is not in the protected set — the union \
             query stopped including the manual arm"
        );
    }

    // And they really are manual: measured at head 069, NEITHER generator finds
    // either one. If that changes the header's arithmetic (27 vs 29) changes
    // with it, so state it here rather than only in prose.
    let generated_only: i64 = sqlx::query_scalar(
        "WITH gen_a AS (
             SELECT c.table_name AS relname
               FROM information_schema.columns c
              WHERE c.table_schema = 'public' AND c.column_name = 'claim_id'
         ),
         gen_b AS (
             SELECT DISTINCT tc.table_name AS relname
               FROM information_schema.table_constraints tc
               JOIN information_schema.constraint_column_usage ccu
                 ON ccu.constraint_name = tc.constraint_name
                AND ccu.constraint_schema = tc.constraint_schema
              WHERE tc.constraint_type = 'FOREIGN KEY'
                AND tc.table_schema = 'public'
                AND ccu.table_name = 'claims'
         )
         SELECT count(*)::bigint FROM (
             SELECT relname FROM gen_a UNION SELECT relname FROM gen_b
         ) u WHERE relname = ANY($1::text[])",
    )
    .bind(MANUAL_ADDITIONS)
    .fetch_one(&pool)
    .await
    .expect("generated-only probe");
    assert_eq!(
        generated_only, 0,
        "a MANUAL_ADDITION is now ALSO found by a generator. That is fine, but the \
         module header's 27-vs-29 arithmetic and the floors above must be re-measured."
    );
}

/// The registry's whole value is that an exemption is an ARGUED, visible diff.
/// A row with an empty `residual` is an exemption that says nothing about what
/// an attacker still learns, which is the same as no exemption at all.
#[sqlx::test(migrations = "../../migrations")]
async fn tenancy_exempt_rows_state_a_residual(pool: PgPool) {
    let rows = sqlx::query(
        "SELECT table_name, reason, residual, reviewed_by FROM tenancy_exempt ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await
    .expect("tenancy_exempt read");

    assert!(
        !rows.is_empty(),
        "the registry must not be empty at head 069"
    );

    for row in &rows {
        let table: String = row.try_get("table_name").unwrap();
        let reason: String = row.try_get("reason").unwrap();
        let residual: String = row.try_get("residual").unwrap();
        let reviewed_by: String = row.try_get("reviewed_by").unwrap();
        assert!(
            reason.trim().len() > 20,
            "{table}: `reason` must argue the exemption, not restate it"
        );
        assert!(
            residual.trim().len() > 20,
            "{table}: `residual` must say what an attacker STILL learns. An exemption \
             with no stated residual is silence with extra steps."
        );
        assert!(
            !reviewed_by.trim().is_empty(),
            "{table}: `reviewed_by` must name someone (or 'PENDING')"
        );
    }

    // A DOWNWARD RATCHET ON THE UNREVIEWED COUNT.
    //
    // The assertion above is satisfied by the literal string 'PENDING', and
    // migration 069 seeds all twelve rows with it — so on its own it certifies
    // nothing about review having happened. Nothing in PR-05 can cause a review,
    // and inventing a reviewer name here would be worse than admitting that.
    // What CAN be enforced is that the backlog only shrinks: a review lowers
    // this count and never trips the assertion, while a THIRTEENTH unreviewed
    // exemption does. The five content-bearing rows (`experiments`,
    // `counterfactual_scenarios`, `learning_events`, `match_candidates`,
    // `behavioral_executions`) are named in docs/tenancy/HANDOFF.md as a
    // PR-16/PR-18 gate; that is where the obligation lives.
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM tenancy_exempt WHERE reviewed_by = 'PENDING'",
    )
    .fetch_one(&pool)
    .await
    .expect("pending count");
    assert!(
        pending <= 12,
        "{pending} exemptions are still 'PENDING' — 069 seeded 12 and this number may \
         only go DOWN. A new exemption must arrive with a named reviewer, or the \
         registry is a place to put things rather than a place to argue for them."
    );
}

/// The nine relations the generators find but 062 did not widen are exactly the
/// nine 069 seeds. Pinned so that "add a table, add an exemption" cannot become
/// the reflex: a NEW unlisted exemption is a diff to this constant, which a
/// reviewer reads.
#[sqlx::test(migrations = "../../migrations")]
async fn the_generated_exemptions_are_exactly_the_nine_measured(pool: PgPool) {
    const GENERATED_EXEMPT: &[&str] = &[
        "alt_set_decisions",
        "alternative_set",
        "behavioral_executions",
        "claim_encryption",
        "claim_version_encryption",
        "counterfactual_scenarios",
        "experiments",
        "learning_events",
        "match_candidates",
    ];

    let protected = protected_set(&pool).await;
    let mut uncovered: Vec<String> = Vec::new();
    for relname in &protected {
        let (vis, ogid) = tenancy_columns(&pool, relname).await;
        if !vis || !ogid {
            uncovered.push(relname.clone());
        }
    }
    uncovered.sort();
    assert_eq!(
        uncovered, GENERATED_EXEMPT,
        "the set of generated-but-uncovered relations changed. If a table was ADDED, \
         give it tenancy columns or a tenancy_exempt row AND update this constant. If \
         one was COVERED, drop its tenancy_exempt row in the same migration."
    );
}

/// Two of the exemptions are VIEWS, not tables — `information_schema.columns`
/// does not distinguish `relkind`, so Generator A returns them and a view can
/// never carry a `NOT NULL` column. They are kept in the generated set on
/// purpose rather than filtered out by `relkind = 'r'`: both HAD
/// `security_invoker` UNSET and would therefore have executed as the view OWNER
/// and BYPASSED the invoker's RLS once migration 079 FORCEd it. A relkind filter
/// would have erased that finding.
///
/// # PR-17 DISCHARGED IT, AND THIS ASSERTION IS NOW INVERTED
///
/// `public.tenancy_exempt` recorded the obligation against PR-17 in the
/// strongest terms it had: *"Migration 077 MUST set security_invoker=true on it
/// or drop it. THIS IS AN OPEN RLS BYPASS, RECORDED HERE SO PR-17 CANNOT MISS
/// IT."* Migration 077 sets it on both, and rewrites the `tenancy_exempt`
/// residual in the same file — which the previous version of this test demanded
/// happen "in the same commit".
///
/// The assertion is kept, not deleted, and simply points the other way: these
/// two views read `edges` and `claims`, so a future migration that recreated
/// either without `security_invoker` would silently reopen a read path around
/// every policy in 077. `migrations/README.md` states the general rule for the
/// whole 060–085 range; this is its enforcement for the two relations that
/// actually got it wrong.
#[sqlx::test(migrations = "../../migrations")]
async fn the_two_view_exemptions_are_security_invoker(pool: PgPool) {
    for view in ["alternative_set", "alt_set_decisions"] {
        let kind: Option<String> = sqlx::query_scalar(
            "SELECT relkind::text FROM pg_class \
              WHERE relnamespace = 'public'::regnamespace AND relname = $1",
        )
        .bind(view)
        .fetch_optional(&pool)
        .await
        .expect("relkind probe");
        assert_eq!(
            kind.as_deref(),
            Some("v"),
            "{view} is expected to be a VIEW; if it became a table, give it tenancy \
             columns and drop its tenancy_exempt row"
        );

        let invoker: Option<bool> = sqlx::query_scalar(
            "SELECT 'security_invoker=true' = ANY(c.reloptions) FROM pg_class c \
              WHERE c.relnamespace = 'public'::regnamespace AND c.relname = $1",
        )
        .bind(view)
        .fetch_one(&pool)
        .await
        .expect("reloptions probe");

        assert_eq!(
            invoker,
            Some(true),
            "{view} has lost security_invoker=true. It would execute as its OWNER and BYPASS \
             every policy migration 077 installs on the claims and edges it reads — an open \
             read path around row-level security. Restore it with \
             ALTER VIEW public.{view} SET (security_invoker = true)."
        );

        // The registry must agree with the catalog. Migration 077 rewrites both
        // residuals; a future edit that reverted the view without touching
        // `tenancy_exempt` would leave the ledger claiming a closed finding.
        let residual: String =
            sqlx::query_scalar("SELECT residual FROM public.tenancy_exempt WHERE table_name = $1")
                .bind(view)
                .fetch_one(&pool)
                .await
                .expect("tenancy_exempt residual");
        assert!(
            residual.contains("CLOSED by migration 077"),
            "{view} is security_invoker=true but its tenancy_exempt residual still describes \
             an open RLS bypass; got: {residual}"
        );
    }
}

// ===========================================================================
// entity_types.tenancy_tier — D1 for types that do not exist yet
// ===========================================================================

/// `unclassified` is the pre-069 transition value. After the seed it is
/// un-registerable at the database, not merely discouraged in the handler.
#[sqlx::test(migrations = "../../migrations")]
async fn unclassified_is_unregisterable(pool: PgPool) {
    let err = sqlx::query(
        "INSERT INTO entity_types (type_name, table_name, is_core, tenancy_tier) \
         VALUES ('probe_unclassified', 'claims', false, 'unclassified')",
    )
    .execute(&pool)
    .await
    .expect_err("'unclassified' must be rejected");

    let db = err.as_database_error().expect("a database error");
    assert_eq!(
        db.code().as_deref(),
        Some("23514"),
        "expected a CHECK violation"
    );
    assert_eq!(
        db.constraint(),
        Some("entity_types_no_unclassified"),
        "the rejection must come from the named constraint, not some other CHECK"
    );
}

/// The hard coupling between migration 069 and the Rust: `DROP DEFAULT` is what
/// makes `EntityTypeRepository::upsert_non_core`'s new `tenancy_tier` parameter
/// LOAD-BEARING rather than cosmetic. If this ever stops raising 23502, the
/// handler's required-field gate has become bypassable by a direct writer.
#[sqlx::test(migrations = "../../migrations")]
async fn tenancy_tier_has_no_default(pool: PgPool) {
    let err = sqlx::query(
        "INSERT INTO entity_types (type_name, table_name, is_core) \
         VALUES ('probe_no_tier', 'claims', false)",
    )
    .execute(&pool)
    .await
    .expect_err("omitting tenancy_tier must fail");

    let db = err.as_database_error().expect("a database error");
    assert_eq!(
        db.code().as_deref(),
        Some("23502"),
        "expected NOT NULL violation (no DEFAULT), got: {err}"
    );

    // And the catalog agrees there is no default to fall back on.
    let default: Option<String> = sqlx::query_scalar(
        "SELECT column_default FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'entity_types' \
            AND column_name = 'tenancy_tier'",
    )
    .fetch_one(&pool)
    .await
    .expect("column_default probe");
    assert_eq!(default, None, "tenancy_tier must have no column_default");
}

/// Every seeded type is classified, and the split is the measured 6/1/16.
#[sqlx::test(migrations = "../../migrations")]
async fn all_23_core_types_are_classified(pool: PgPool) {
    let unclassified: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM entity_types WHERE tenancy_tier = 'unclassified'",
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(
        unclassified, 0,
        "migration 069 must leave nothing unclassified"
    );

    // `WHERE is_core = true` IS NOT COSMETIC. The assertion is about the 23
    // types migration 054 seeded. Without the filter the histogram also counts
    // anything a fixture or a later migration REGISTERS through
    // `upsert_non_core`, and the test fails for a reason that has nothing to do
    // with what it claims to check. It passes today only because the two sets
    // happen to coincide on a fresh `#[sqlx::test]` database.
    let rows = sqlx::query(
        "SELECT tenancy_tier, count(*)::bigint AS n FROM entity_types \
          WHERE is_core = true GROUP BY 1 ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("tier histogram");
    let histogram: Vec<(String, i64)> = rows
        .iter()
        .map(|r| {
            (
                r.try_get::<String, _>("tenancy_tier").unwrap(),
                r.try_get::<i64, _>("n").unwrap(),
            )
        })
        .collect();
    assert_eq!(
        histogram,
        vec![
            ("columns".to_string(), 6),
            ("derived".to_string(), 16),
            ("identity".to_string(), 1),
        ],
        "the 23 types seeded by migration 054 must split 6 columns / 16 derived / \
         1 identity. A new core type added by a later migration must classify itself \
         and bump this."
    );

    // The six `columns` types are named, not merely counted: a migration that
    // demoted `claim` to `derived` and promoted something else would keep the
    // count at six.
    let columns_types: Vec<String> = sqlx::query_scalar(
        "SELECT type_name FROM entity_types \
          WHERE is_core = true AND tenancy_tier = 'columns' ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .expect("columns types");
    assert_eq!(
        columns_types,
        vec![
            "claim",
            "community",
            "context",
            "evidence",
            "frame",
            "perspective"
        ]
    );
}

// ===========================================================================
// Migration replay + the quarantine
// ===========================================================================

/// A `lock_timeout` abort leaves no `_sqlx_migrations` row, so the operator's
/// remedy is to re-run the file. Replayed inside a transaction, which is also
/// what makes each file's opening `SET LOCAL lock_timeout` meaningful (it merely
/// WARNs outside one).
#[sqlx::test(migrations = "../../migrations")]
async fn migration_068_and_069_apply_twice(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");
    // PR-22: `public.ownership` is dropped by migration 084, and half of 068
    // operates on it, so the replay needs the relation back for the duration of
    // this transaction. The scaffold is 001's and 068's own DDL, sliced out of
    // the frozen files — see `retired_ownership_scaffold.rs`. The VIEW is
    // deliberately not scaffolded: 068 creates it, and a pre-existing one would
    // mask a `CREATE OR REPLACE` that had stopped working.
    //
    // 068 is therefore applied TWICE here rather than once, because against a
    // fresh scaffold the first application is not a replay. That is a stronger
    // exercise of its guards than the single re-application this test used to
    // do: every `IF NOT EXISTS` / `pg_constraint` guard now sees both the absent
    // and the present state in one test.
    retired_ownership::scaffold_table(&mut tx).await;
    for pass in 1..=2 {
        sqlx::raw_sql(MIGRATION_068)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| panic!("applying migration 068, pass {pass}: {e}"));
    }
    sqlx::raw_sql(MIGRATION_069)
        .execute(&mut *tx)
        .await
        .expect("re-applying migration 069 must succeed");

    // "Did not error" is not enough: a guard that created a differently-named
    // duplicate would also not error. CONRELID-qualified, matching the
    // migrations' own guards — `conname` is unique per RELATION, not per
    // database, so a bare name lookup would share their blind spot exactly.
    for (relation, constraint) in [
        ("public.ownership", "ownership_community_fkey"),
        ("public.ownership", "ownership_key_id_is_uuid"),
        (
            "public.ownership",
            "ownership_community_needs_community_partition",
        ),
        ("public.entity_types", "entity_types_tier_vocab"),
        ("public.entity_types", "entity_types_no_unclassified"),
    ] {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM pg_constraint \
              WHERE conrelid = $1::regclass AND conname = $2",
        )
        .bind(relation)
        .bind(constraint)
        .fetch_one(&mut *tx)
        .await
        .expect("constraint count");
        assert_eq!(
            n, 1,
            "{relation}.{constraint} must exist exactly once after a replay"
        );
    }

    // The projections are INSERT ... ON CONFLICT DO NOTHING; a replay must not
    // double them.
    let dupe_groups: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM (SELECT id FROM groups WHERE kind = 'community' \
          GROUP BY id HAVING count(*) > 1) d",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("dupe probe");
    assert_eq!(dupe_groups, 0);

    let exempt: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM tenancy_exempt")
        .fetch_one(&mut *tx)
        .await
        .expect("exempt count");
    assert_eq!(exempt, 12, "the 069 seed must not double on replay");
}

/// PR-13's acceptance clause: migration 072 applies twice.
///
/// Same reasoning as `migration_068_and_069_apply_twice` — a `lock_timeout`
/// abort records no `_sqlx_migrations` row, so the operator's remedy is to
/// re-run the file, and "it applied once" is not the property that makes that
/// safe.
///
/// 072 has three idempotence mechanisms and this exercises all three:
/// `ADD COLUMN IF NOT EXISTS`, two CONRELID-qualified `pg_constraint` guards
/// around `ADD CONSTRAINT` (which has no `IF NOT EXISTS`), and
/// `CREATE OR REPLACE FUNCTION` for the two trigger arms. The post-conditions
/// below are what distinguishes a real replay from "did not error": a guard
/// that created a differently-named duplicate constraint, or a replay that
/// dropped the column's data, would both return `Ok`.
///
/// 073 is deliberately NOT replayed here. It is `-- no-transaction` (a
/// `CREATE INDEX CONCURRENTLY` cannot run in one) and this test body IS a
/// transaction; its idempotence is `IF NOT EXISTS` plus the `indisvalid` sweep
/// in `tenancy_migration_shape.rs`.
#[sqlx::test(migrations = "../../migrations")]
async fn migration_072_applies_twice(pool: PgPool) {
    let mut tx = pool.begin().await.expect("begin");

    // A row that must survive the replay: the column is added with no DEFAULT,
    // so a re-run that dropped and re-added it would silently null this out.
    // Written through the trigger arms, not around them — arm (b) is what 072
    // replaces, so this also proves the replaced body still stamps.
    //
    // Real claims on both ends: `trigger_validate_edge_refs` (a pre-tenancy
    // trigger) rejects an edge naming a nonexistent node, so a pair of random
    // uuids is not a shortcut here.
    let agent = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(
            agent
                .as_bytes()
                .iter()
                .copied()
                .cycle()
                .take(32)
                .collect::<Vec<u8>>(),
        )
        .execute(&mut *tx)
        .await
        .expect("seed agent");
    let mut claims = Vec::new();
    for label in ["072 replay A", "072 replay B"] {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current) \
             VALUES ($1, $2, $3, 0.5, $4, true)",
        )
        .bind(id)
        .bind(label)
        .bind(
            id.as_bytes()
                .iter()
                .copied()
                .cycle()
                .take(32)
                .collect::<Vec<u8>>(),
        )
        .bind(agent)
        .execute(&mut *tx)
        .await
        .expect("seed claim");
        claims.push(id);
    }
    let edge_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', 'supports') RETURNING id",
    )
    .bind(claims[0])
    .bind(claims[1])
    .fetch_one(&mut *tx)
    .await
    .expect("seed a public edge");

    sqlx::raw_sql(MIGRATION_072)
        .execute(&mut *tx)
        .await
        .expect("re-applying migration 072 must succeed");

    for constraint in ["edges_co_owner_fkey", "edges_co_owner_shape"] {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM pg_constraint \
              WHERE conrelid = 'public.edges'::regclass AND conname = $1",
        )
        .bind(constraint)
        .fetch_one(&mut *tx)
        .await
        .expect("constraint count");
        assert_eq!(
            n, 1,
            "edges.{constraint} must exist exactly once after a replay — a guard \
             that is not CONRELID-qualified would either skip creating it or \
             create a duplicate"
        );
    }

    // INVERTED BY PR-16. This asserted that both constraints were still
    // NOT VALID, with the reason that promoting them takes a full scan in a
    // migration advertised as metadata-only. That reason named PR-16's 075/076
    // as where the scan belongs, and migration 076 is now that file, so the
    // assertion turns over rather than being deleted — the decision (add the
    // constraint NOT VALID in 072, validate it LATE in its own deploy step)
    // stays pinned by both halves.
    //
    // Note what is still being tested: this runs inside a REPLAY of migration
    // 072 (the surrounding `tx` re-applies the file). What must not happen is
    // 072 itself promoting the constraints. It does not — 076 already validated
    // them before this test's transaction began, and 072's guards are
    // catalog-checked so the replay is a no-op on them either way.
    let validated: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM pg_constraint \
          WHERE conrelid = 'public.edges'::regclass \
            AND conname IN ('edges_co_owner_fkey', 'edges_co_owner_shape') \
            AND convalidated",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("convalidated probe");
    assert_eq!(
        validated, 2,
        "both 072 constraints must be VALIDATED after migration 076, and must \
         survive a replay of 072"
    );

    // The column survived, still nullable, still with no DEFAULT (a DEFAULT
    // would be D1's implicit-public in a new place).
    let (nullable, default): (String, Option<String>) = sqlx::query_as(
        "SELECT is_nullable, column_default FROM information_schema.columns \
          WHERE table_name = 'edges' AND column_name = 'co_owner_group_id'",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("column probe");
    assert_eq!(
        nullable, "YES",
        "co_owner_group_id is NULL for a single owner"
    );
    assert_eq!(
        default, None,
        "a DEFAULT here would be implicit co-ownership"
    );

    let still_there: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM edges WHERE id = $1")
        .bind(edge_id)
        .fetch_one(&mut *tx)
        .await
        .expect("row probe");
    assert_eq!(still_there, 1, "a replay must not touch existing rows");

    // Both trigger arms are still bound to their triggers after the replace.
    // CREATE OR REPLACE FUNCTION does not re-create the trigger, so a body
    // replaced under a different signature would leave the OLD body live —
    // exactly the failure mode 072's header calls out for migration 066.
    for (trigger, table, function) in [
        ("edges_tenancy", "edges", "epigraph_edges_tenancy"),
        (
            "claims_propagate_tenancy",
            "claims",
            "epigraph_propagate_tenancy",
        ),
    ] {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM pg_trigger t \
               JOIN pg_proc p ON p.oid = t.tgfoid \
              WHERE t.tgrelid = ('public.' || $2)::regclass \
                AND t.tgname = $1 AND p.proname = $3 AND NOT t.tgisinternal",
        )
        .bind(trigger)
        .bind(table)
        .bind(function)
        .fetch_one(&mut *tx)
        .await
        .expect("trigger probe");
        assert_eq!(n, 1, "{trigger} on {table} must still call {function}");
    }
}

// FOUR `ownership` CASES LIVED HERE AND ARE DELETED IN PR-22.
//
//   ownership_key_id_quarantine_is_a_view      — that the quarantine is a VIEW
//                                                (`relkind = 'v'`), not a
//                                                `CREATE TABLE AS` snapshot, AND
//                                                that it carries
//                                                `security_invoker = true`
//   quarantine_reports_a_dangling_community_uuid
//   the_drain_clears_the_source_column
//   community_id_requires_the_community_partition
//
// Migration 084 drops both the table and the view, so all four assert properties
// of relations that do not exist at head.
//
// THE FIRST OF THEM IS A DELIBERATE UN-PINNING AND IT IS SAID OUT LOUD.
// `migrations/README.md` named that test as the pin for BOTH properties of the
// quarantine view, and its `Non-table objects` table states the general rule the
// view was the example of: *any VIEW added in the 060–090 range must be created
// `WITH (security_invoker = true)`*, because a view without it executes as its
// OWNER and bypasses the invoker's policies once migration 079 FORCEs RLS. The
// rule outlives its example. README's row is updated in the same change to
// record that 084 has run and that the rule now stands on the two view
// exemptions in `tenancy_exempt` — which
// [`the_two_view_exemptions_are_security_invoker`] below still pins, in both
// directions.
//
// What the other three protected — that a legacy `encryption_key_id` which does
// not resolve is REPORTED rather than swallowed, and that the drain clears its
// source so the quarantine means exactly "did not resolve" — was ultimately in
// service of one thing: that migration 084's first pre-flight comes up empty.
// That is now asserted against the migration itself, with a manufactured
// non-empty quarantine, in `retire_ownership_preflight.rs`.

/// PR-05's other two acceptance queries, over the migration's own projection.
/// Both are trivially 0 on a fresh database, so this seeds a community first —
/// otherwise the assertion is "0 = 0" and proves nothing.
///
/// **WHAT THIS DOES NOT ASSERT.** It seeds, then REPLAYS migration 068, then
/// checks. It is therefore a test of the MIGRATION's output, not of a standing
/// invariant, and it is structurally incapable of noticing projection drift:
/// `CommunityRepository::create` / `add_member` / `remove_member`
/// (`crates/epigraph-db/src/repos/community.rs:42,110,144`) still write only
/// `communities` / `community_members`, so the first `POST /communities` after
/// deploy breaks the invariant and nothing here fires. That is the plan's R7
/// and PR-12's write-side stamping triggers own it; it is recorded in
/// docs/tenancy/HANDOFF.md. Do not read a green run here as "the two membership
/// models agree".
#[sqlx::test(migrations = "../../migrations")]
async fn every_community_projects_onto_a_group_and_its_members_onto_memberships(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let community: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO communities (name) VALUES ($1) RETURNING id")
            .bind(format!("comm-{}", uuid::Uuid::new_v4()))
            .fetch_one(&pool)
            .await
            .expect("seed community");
    let perspective: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind("p")
    .bind(agent)
    .fetch_one(&pool)
    .await
    .expect("seed perspective");
    // A perspective with NO owning agent: `perspectives.owner_agent_id` is
    // NULLABLE, so such a pair CANNOT produce a membership. The plan's
    // acceptance sentence omits this qualification; its own INSERT carries it.
    let orphan: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO perspectives (name) VALUES ($1) RETURNING id")
            .bind("p-no-agent")
            .fetch_one(&pool)
            .await
            .expect("seed orphan perspective");
    for p in [perspective, orphan] {
        sqlx::query("INSERT INTO community_members (community_id, perspective_id) VALUES ($1, $2)")
            .bind(community)
            .bind(p)
            .execute(&pool)
            .await
            .expect("seed membership");
    }

    // Replay 068 so the projection sees the rows seeded above. The `ownership`
    // half of 068 needs the relation migration 084 retired, so it is scaffolded
    // inside this transaction first — see `retired_ownership_scaffold.rs`.
    let mut tx = pool.begin().await.expect("begin");
    retired_ownership::scaffold_table(&mut tx).await;
    sqlx::raw_sql(MIGRATION_068)
        .execute(&mut *tx)
        .await
        .expect("replay 068");

    let unprojected_communities: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM communities c \
           LEFT JOIN groups g ON g.id = c.id AND g.kind = 'community' \
          WHERE g.id IS NULL",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("acceptance q1");
    assert_eq!(
        unprojected_communities, 0,
        "every community must have a group"
    );

    let unprojected_members: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM community_members cm \
           JOIN perspectives p ON p.id = cm.perspective_id \
           LEFT JOIN group_memberships gm \
             ON gm.group_id = cm.community_id AND gm.agent_id = p.owner_agent_id \
            AND gm.revoked_at IS NULL \
          WHERE p.owner_agent_id IS NOT NULL AND gm.id IS NULL",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("acceptance q2");
    assert_eq!(
        unprojected_members, 0,
        "every community_members ⋈ perspectives pair WITH AN OWNING AGENT must have \
         a group_memberships row"
    );

    // The orphan pair produced no membership, and could not have.
    let memberships: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM group_memberships WHERE group_id = $1")
            .bind(community)
            .fetch_one(&mut *tx)
            .await
            .expect("membership count");
    assert_eq!(
        memberships, 1,
        "two community_members rows, one with a NULL owner_agent_id -> exactly one \
         membership"
    );

    // ROLE = 'reader', the column's own DEFAULT and the least privilege the
    // source data supports. `community_members` records READ eligibility and
    // nothing else, while `Viewer::resolve` puts `admin|writer` into the
    // WRITABLE set — so projecting 'writer' would hand every historical
    // community member write authority over the group's corpus at PR-11/PR-17
    // and privatization eligibility at PR-18, on the strength of a row that
    // never said so.
    let role: String = sqlx::query_scalar("SELECT role FROM group_memberships WHERE group_id = $1")
        .bind(community)
        .fetch_one(&mut *tx)
        .await
        .expect("role");
    assert_eq!(
        role, "reader",
        "a projected community membership must be least-privilege; upgrading this to \
         'writer' is a deliberate widening and needs its own argument"
    );

    // The projected group is key-free at epoch 0 (groups_public_key_shape
    // requires octet_length(public_key) = 0 for kind <> 'team').
    let epoch: i32 = sqlx::query_scalar(
        "SELECT epoch FROM group_key_epochs WHERE group_id = $1 AND status = 'active'",
    )
    .bind(community)
    .fetch_one(&mut *tx)
    .await
    .expect("epoch");
    assert_eq!(epoch, 0);
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// `agents.public_key` is `UNIQUE` and length-checked; derive 32 bytes from a
/// fresh uuid so several agents in one test cannot collide.
async fn seed_agent(pool: &PgPool) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}
