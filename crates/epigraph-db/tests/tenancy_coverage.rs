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
        row.try_get::<Option<bool>, _>("vis").unwrap().unwrap_or(false),
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

    assert!(!rows.is_empty(), "the registry must not be empty at head 069");

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
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM tenancy_exempt WHERE reviewed_by = 'PENDING'")
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
        uncovered,
        GENERATED_EXEMPT,
        "the set of generated-but-uncovered relations changed. If a table was ADDED, \
         give it tenancy columns or a tenancy_exempt row AND update this constant. If \
         one was COVERED, drop its tenancy_exempt row in the same migration."
    );
}

/// Two of the exemptions are VIEWS, not tables — `information_schema.columns`
/// does not distinguish `relkind`, so Generator A returns them and a view can
/// never carry a `NOT NULL` column. They are kept in the generated set on
/// purpose rather than filtered out by `relkind = 'r'`: both have
/// `security_invoker` UNSET and will therefore execute as the view OWNER and
/// BYPASS the invoker's RLS once migration 079 FORCEs it. A relkind filter would
/// have erased that finding. **Migration 077 owes both of them
/// `security_invoker = true` (or a DROP).**
#[sqlx::test(migrations = "../../migrations")]
async fn the_two_view_exemptions_are_still_security_definer(pool: PgPool) {
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

        // This is a RECORD of an open finding, not an endorsement. When PR-17
        // sets security_invoker on these views, this assertion flips and the
        // tenancy_exempt residual text must be rewritten in the same commit.
        assert_ne!(
            invoker,
            Some(true),
            "{view} now has security_invoker=true — PR-17 discharged the RLS-bypass \
             obligation. Update its tenancy_exempt residual and invert this assertion."
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
    assert_eq!(db.code().as_deref(), Some("23514"), "expected a CHECK violation");
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
    assert_eq!(unclassified, 0, "migration 069 must leave nothing unclassified");

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
        vec!["claim", "community", "context", "evidence", "frame", "perspective"]
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
    sqlx::raw_sql(MIGRATION_068)
        .execute(&mut *tx)
        .await
        .expect("re-applying migration 068 must succeed");
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
        assert_eq!(n, 1, "{relation}.{constraint} must exist exactly once after a replay");
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

/// PR-05's acceptance clause, made machine-checkable: the quarantine is a VIEW,
/// not a `CREATE TABLE AS` snapshot.
///
/// The distinction is operational, not stylistic (ops F20). A snapshot taken at
/// 068 time cannot see a row that becomes unparseable AFTERWARDS, so migration
/// 084's pre-flight would pass over a value it was supposed to catch. A view is
/// always current.
#[sqlx::test(migrations = "../../migrations")]
async fn ownership_key_id_quarantine_is_a_view(pool: PgPool) {
    let kind: Option<String> = sqlx::query_scalar(
        "SELECT relkind::text FROM pg_class \
          WHERE relnamespace = 'public'::regnamespace \
            AND relname = 'ownership_key_id_quarantine'",
    )
    .fetch_optional(&pool)
    .await
    .expect("relkind probe");
    assert_eq!(
        kind.as_deref(),
        Some("v"),
        "ownership_key_id_quarantine must be a VIEW ('v'); a table ('r') would be a \
         snapshot that cannot see a value that goes bad after migration 068"
    );

    // AND `security_invoker = true`. `relkind = 'v'` alone is exactly what
    // `alternative_set` / `alt_set_decisions` satisfy, and those two are in
    // `tenancy_exempt` labelled "THIS IS AN OPEN RLS BYPASS" for the option
    // this one sets. A view that exposes ownership metadata and executes as its
    // OWNER after migration 079's FORCE would be the same finding, filed by the
    // same PR that filed the finding.
    let invoker: Option<bool> = sqlx::query_scalar(
        "SELECT 'security_invoker=true' = ANY(c.reloptions) FROM pg_class c \
          WHERE c.relnamespace = 'public'::regnamespace \
            AND c.relname = 'ownership_key_id_quarantine'",
    )
    .fetch_one(&pool)
    .await
    .expect("reloptions probe");
    assert_eq!(
        invoker,
        Some(true),
        "ownership_key_id_quarantine must be created WITH (security_invoker = true); \
         without it the view runs as its owner and bypasses the invoker's RLS once \
         migration 079 FORCEs it"
    );

    // Empty on a fresh database, which is what makes case 9 below discriminating.
    let n: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM ownership_key_id_quarantine")
        .fetch_one(&pool)
        .await
        .expect("quarantine count");
    assert_eq!(n, 0, "a fresh database has nothing to quarantine");
}

/// The failure mode the plan's own 064 SQL would have hit in production, turned
/// into a test: a well-formed UUID naming a community that no longer exists.
///
/// The plan's unguarded `UPDATE ... SET community_id = encryption_key_id::uuid`
/// runs AFTER `ownership_community_fkey` is added, and `NOT VALID` exempts
/// pre-existing rows from the back-check but NOT rows the same statement
/// modifies — so a dangling UUID raises 23503 and rolls the whole migration
/// back. `communities` has no cascade to `ownership`, so this state is reachable
/// by ordinary use. Migration 068 adds `AND EXISTS (SELECT 1 FROM communities …)`
/// so the value is REPORTED in the quarantine instead of aborting a deploy.
#[sqlx::test(migrations = "../../migrations")]
async fn quarantine_reports_a_dangling_community_uuid(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let node = uuid::Uuid::new_v4();
    let dangling = uuid::Uuid::new_v4();

    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, encryption_key_id) \
         VALUES ($1, 'claim', 'community', $2, $3::text)",
    )
    .bind(node)
    .bind(agent)
    .bind(dangling)
    .execute(&pool)
    .await
    .expect(
        "a well-formed UUID naming no community must still be WRITABLE — \
         ownership_key_id_is_uuid checks the shape, not the referent",
    );

    let reported: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT node_id FROM ownership_key_id_quarantine")
            .fetch_all(&pool)
            .await
            .expect("quarantine read");
    assert_eq!(
        reported,
        vec![node],
        "a dangling community UUID must be REPORTED, not swallowed and not fatal"
    );

    // And the non-UUID legacy shape is refused outright, so no NEW junk accrues.
    let err = sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, encryption_key_id) \
         VALUES ($1, 'claim', 'community', $2, 'key-2026-001')",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(agent)
    .execute(&pool)
    .await
    .expect_err("a non-UUID encryption_key_id must be refused");
    assert_eq!(
        err.as_database_error().and_then(|e| e.constraint()),
        Some("ownership_key_id_is_uuid")
    );
}

/// The drain CLEARS ITS SOURCE, so `ownership_key_id_quarantine` means exactly
/// "did not resolve" and nothing else.
///
/// Draining without clearing would leave the same UUID in two columns — the
/// two-sources-of-truth this whole migration exists to remove — and would arm
/// two later failures: the row enters the quarantine the moment `community_id`
/// goes NULL (blocking migration 084's pre-flight with a value that DID
/// resolve), and every subsequent UPDATE of it re-checks the `NOT VALID`
/// `ownership_key_id_is_uuid` against a string nobody maintains.
#[sqlx::test(migrations = "../../migrations")]
async fn the_drain_clears_the_source_column(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let community: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO communities (name) VALUES ($1) RETURNING id")
            .bind(format!("comm-{}", uuid::Uuid::new_v4()))
            .fetch_one(&pool)
            .await
            .expect("seed community");
    let node = uuid::Uuid::new_v4();

    // A pre-068 row exactly as the old writer left it: the community UUID
    // stringified into `encryption_key_id`, `community_id` untouched.
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, encryption_key_id) \
         VALUES ($1, 'claim', 'community', $2, $3::text)",
    )
    .bind(node)
    .bind(agent)
    .bind(community)
    .execute(&pool)
    .await
    .expect("seed legacy row");

    let mut tx = pool.begin().await.expect("begin");
    sqlx::raw_sql(MIGRATION_068)
        .execute(&mut *tx)
        .await
        .expect("replay 068");

    let (drained, leftover): (Option<uuid::Uuid>, Option<String>) =
        sqlx::query_as("SELECT community_id, encryption_key_id FROM ownership WHERE node_id = $1")
            .bind(node)
            .fetch_one(&mut *tx)
            .await
            .expect("post-drain read");
    assert_eq!(drained, Some(community), "the value must reach the typed column");
    assert_eq!(
        leftover, None,
        "and must NOT also remain in encryption_key_id — a drained row carrying both \
         is the two-sources-of-truth this migration removes"
    );

    let quarantined: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM ownership_key_id_quarantine")
            .fetch_one(&mut *tx)
            .await
            .expect("quarantine count");
    assert_eq!(quarantined, 0, "a resolvable value must not appear in the quarantine");
}

/// A gate on a row that is not on the community partition gates nothing today
/// and is inherited by a later promotion to `community` — the exact hazard
/// `OwnershipRepository::update_partition` argues against when it nulls
/// `community_id` on demotion. One writer enforcing an invariant the other can
/// pre-load is not an invariant; migration 068 enforces it structurally for
/// every writer, in-tree or not.
#[sqlx::test(migrations = "../../migrations")]
async fn community_id_requires_the_community_partition(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let community: uuid::Uuid =
        sqlx::query_scalar("INSERT INTO communities (name) VALUES ($1) RETURNING id")
            .bind(format!("comm-{}", uuid::Uuid::new_v4()))
            .fetch_one(&pool)
            .await
            .expect("seed community");

    let err = sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, community_id) \
         VALUES ($1, 'claim', 'private', $2, $3)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(agent)
    .bind(community)
    .execute(&pool)
    .await
    .expect_err("a community_id on a private row must be refused");
    assert_eq!(
        err.as_database_error().and_then(|e| e.constraint()),
        Some("ownership_community_needs_community_partition")
    );

    // The same pair IS accepted on the community partition.
    sqlx::query(
        "INSERT INTO ownership (node_id, node_type, partition_type, owner_id, community_id) \
         VALUES ($1, 'claim', 'community', $2, $3)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(agent)
    .bind(community)
    .execute(&pool)
    .await
    .expect("community partition + community_id is the legal pair");
}

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

    // Replay 068 so the projection sees the rows seeded above.
    let mut tx = pool.begin().await.expect("begin");
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
    assert_eq!(unprojected_communities, 0, "every community must have a group");

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
    let memberships: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM group_memberships WHERE group_id = $1",
    )
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
    let role: String =
        sqlx::query_scalar("SELECT role FROM group_memberships WHERE group_id = $1")
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
