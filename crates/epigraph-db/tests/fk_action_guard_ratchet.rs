//! SPEC §7.1, "No setting where an FK action can act" (SF-17), and §11 phase 1
//! S-1 tests (n) / (n2): the foreign-key referential actions that can WRITE a
//! guarded table.
//!
//! PostgreSQL runs an FK referential action (`ON DELETE CASCADE / SET NULL /
//! SET DEFAULT`, `ON UPDATE CASCADE / SET NULL / SET DEFAULT`) as the owner of
//! the referencing table, so inside it `epigraph_definer_bypass()` can be true
//! and any session's custom settings are in force. A guard keyed on a
//! row-naming setting plus the definer bypass therefore discriminates nothing
//! for a write an FK action performs. This ratchet lists, for every table such
//! a guard protects (`claims`, `edges`), each foreign key whose action writes
//! that table, and for `mass_functions` (H10's table, whose guard uses a
//! table-backed purge grant instead) every foreign key with its actions. A new
//! foreign key with a writing action on `claims` or `edges`, or any change to
//! `mass_functions`' six, fails here until the guard question is answered for
//! it and the list below is edited.
//!
//! Calibrated in-test: a probe foreign key with a writing action is added to
//! `claims` and must be reported.
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is not
//! extended.

use sqlx::PgPool;
use std::collections::BTreeSet;

/// `(table, constraint, column, referenced table, ON DELETE, ON UPDATE)`.
type Fk = (String, String, String, String, String, String);

/// Every foreign key on `claims` or `edges` whose referential action writes
/// the referencing row. Measured on a fresh database migrated to head: three
/// `ON DELETE SET NULL`s, each an UPDATE of a signer or trace column only. None
/// writes `claims.is_current`, `claims.content`, `claims.agent_id` or an edge
/// endpoint, the columns this specification's setting-keyed guards protect.
const GUARDED_WRITING_ACTIONS: &[(&str, &str, &str, &str, &str, &str)] = &[
    (
        "claims",
        "claims_signer_id_fkey",
        "signer_id",
        "agents",
        "SET NULL",
        "NO ACTION",
    ),
    (
        "claims",
        "claims_trace_id_fkey",
        "trace_id",
        "reasoning_traces",
        "SET NULL",
        "NO ACTION",
    ),
    (
        "edges",
        "edges_signer_id_fkey",
        "signer_id",
        "agents",
        "SET NULL",
        "NO ACTION",
    ),
];

/// Every foreign key on `mass_functions` (SPEC §7.3 H10), measured: the two
/// `ON DELETE CASCADE` paths into H10 (001); `perspective_id` and
/// `source_agent_id` NO ACTION (001; a referenced delete is refused while rows
/// reference it); `evidence_id`'s `SET NULL` (046; an UPDATE, not H10's
/// concern); and the tenancy owner's `owner_group_id` `ON DELETE RESTRICT`
/// (refused, no cascade).
const MASS_FUNCTIONS_FKS: &[(&str, &str, &str, &str, &str, &str)] = &[
    (
        "mass_functions",
        "mass_functions_claim_id_fkey",
        "claim_id",
        "claims",
        "CASCADE",
        "NO ACTION",
    ),
    (
        "mass_functions",
        "mass_functions_evidence_id_fkey",
        "evidence_id",
        "evidence",
        "SET NULL",
        "NO ACTION",
    ),
    (
        "mass_functions",
        "mass_functions_frame_id_fkey",
        "frame_id",
        "frames",
        "CASCADE",
        "NO ACTION",
    ),
    (
        "mass_functions",
        "mass_functions_owner_group_fkey",
        "owner_group_id",
        "groups",
        "RESTRICT",
        "NO ACTION",
    ),
    (
        "mass_functions",
        "mass_functions_perspective_id_fkey",
        "perspective_id",
        "perspectives",
        "NO ACTION",
        "NO ACTION",
    ),
    (
        "mass_functions",
        "mass_functions_source_agent_id_fkey",
        "source_agent_id",
        "agents",
        "NO ACTION",
        "NO ACTION",
    ),
];

const ACTION_SQL: &str = "CASE {} WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT' \
    WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL' WHEN 'd' THEN 'SET DEFAULT' END";

/// Every foreign key on `tables`, as [`Fk`] rows.
async fn foreign_keys(pool: &PgPool, tables: &[&str]) -> BTreeSet<Fk> {
    let sql = format!(
        "SELECT c.conrelid::regclass::text, c.conname::text, \
                (SELECT string_agg(a.attname::text, ',' ORDER BY k.ord) \
                   FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) \
                   JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum), \
                c.confrelid::regclass::text, {}, {} \
           FROM pg_constraint c \
          WHERE c.contype = 'f' AND c.conrelid = ANY ($1::regclass[])",
        ACTION_SQL.replace("{}", "c.confdeltype"),
        ACTION_SQL.replace("{}", "c.confupdtype"),
    );
    let names: Vec<String> = tables.iter().map(|t| format!("public.{t}")).collect();
    sqlx::query_as::<_, Fk>(&sql)
        .bind(&names)
        .fetch_all(pool)
        .await
        .expect("read the foreign keys")
        .into_iter()
        .collect()
}

fn writes(action: &str) -> bool {
    matches!(action, "CASCADE" | "SET NULL" | "SET DEFAULT")
}

/// The [`Fk`] rows on `claims` / `edges` whose action writes the row.
async fn guarded_writing_actions(pool: &PgPool) -> BTreeSet<Fk> {
    foreign_keys(pool, &["claims", "edges"])
        .await
        .into_iter()
        .filter(|fk| writes(&fk.4) || writes(&fk.5))
        .collect()
}

fn listed(rows: &[(&str, &str, &str, &str, &str, &str)]) -> BTreeSet<Fk> {
    rows.iter()
        .map(|(t, n, c, r, d, u)| {
            (
                (*t).to_string(),
                (*n).to_string(),
                (*c).to_string(),
                (*r).to_string(),
                (*d).to_string(),
                (*u).to_string(),
            )
        })
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn no_unlisted_fk_action_writes_a_setting_guarded_table(pool: PgPool) {
    let found = guarded_writing_actions(&pool).await;
    assert_eq!(
        found,
        listed(GUARDED_WRITING_ACTIONS),
        "the foreign keys whose referential action writes `claims` or `edges` changed. An FK \
         action runs as the referencing table's owner, so a guard keyed on a row-naming \
         setting and epigraph_definer_bypass() does not discriminate it (SPEC §7.1, SF-17). \
         Decide whether any setting-keyed guard on that table must hold against it (if so, \
         use a table-backed grant as H10 does), then update GUARDED_WRITING_ACTIONS"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn mass_functions_keeps_exactly_its_six_foreign_keys(pool: PgPool) {
    let found = foreign_keys(&pool, &["mass_functions"]).await;
    assert_eq!(
        found,
        listed(MASS_FUNCTIONS_FKS),
        "mass_functions' foreign keys changed. Its two ON DELETE CASCADE keys are the delete \
         paths into H10 (migration 194's guard refuses a cascade onto a retracted row, and \
         claim and frame hard-deletes purge first); a new delete path must be accounted for \
         the same way. Update MASS_FUNCTIONS_FKS once it is"
    );
}

/// Calibration: the scan reports a writing action it was not told about.
#[sqlx::test(migrations = "../../migrations")]
async fn the_scan_reports_a_probe_writing_action(pool: PgPool) {
    sqlx::query("ALTER TABLE public.claims ADD COLUMN fk_ratchet_probe uuid")
        .execute(&pool)
        .await
        .expect("add a probe column");
    sqlx::query(
        "ALTER TABLE public.claims ADD CONSTRAINT claims_fk_ratchet_probe_fkey \
         FOREIGN KEY (fk_ratchet_probe) REFERENCES public.agents(id) ON UPDATE CASCADE",
    )
    .execute(&pool)
    .await
    .expect("add a probe foreign key");
    let found = guarded_writing_actions(&pool).await;
    let known = listed(GUARDED_WRITING_ACTIONS);
    let extra: Vec<&Fk> = found.difference(&known).collect();
    assert_eq!(
        extra,
        vec![&(
            "claims".to_string(),
            "claims_fk_ratchet_probe_fkey".to_string(),
            "fk_ratchet_probe".to_string(),
            "agents".to_string(),
            "NO ACTION".to_string(),
            "CASCADE".to_string(),
        )],
        "the scan must report the probe's ON UPDATE CASCADE (and nothing else new)"
    );
}

/// The tables this ratchet covers: `claims` and `edges` through
/// [`GUARDED_WRITING_ACTIONS`], `mass_functions` through [`MASS_FUNCTIONS_FKS`].
const RATCHETED_TABLES: &[&str] = &["claims", "edges", "mass_functions"];

/// T-N9: the guarded-table list, DERIVED from the catalog for the shape SF-17
/// is about: a table one of whose own triggers runs a function that reads a
/// custom setting (`current_setting`) AND consults
/// `epigraph_definer_bypass()`. That is the guard an FK referential action
/// defeats (it runs as the referencing table's owner, where the definer
/// bypass can be true and the session's settings are in force). Measured on a
/// fresh database migrated to head: none. Before migration 251 it was
/// `mass_functions` alone (184's `epigraph_mass_function_retract_guard`, whose
/// clear arm read `epigraph.mf_unretract_id`); 251 keys that arm on a consumed
/// ledger grant and the guard reads no setting. The scan's calibration is
/// [`the_guard_scan_reports_a_probe_setting_keyed_guard`].
///
/// Not derived: a guard that reaches the setting through a helper function,
/// rather than in its own body. A scan for any trigger function reading a
/// setting is not a usable proxy: 166's statement trigger
/// (`epigraph_role_agent_write_check`, the stamped principal) puts every
/// application-writable table in it, about sixty, none of them keyed on a
/// row-naming setting. That judgment stays with the reviewer of
/// [`GUARDED_WRITING_ACTIONS`].
async fn setting_keyed_guard_tables(pool: &PgPool) -> BTreeSet<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT c.relname::text \
           FROM pg_trigger t \
           JOIN pg_class c ON c.oid = t.tgrelid \
           JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public' \
           JOIN pg_proc p ON p.oid = t.tgfoid \
          WHERE NOT t.tgisinternal \
            AND p.prosrc ~ 'current_setting' \
            AND p.prosrc ~ 'epigraph_definer_bypass'",
    )
    .fetch_all(pool)
    .await
    .expect("read the trigger functions")
    .into_iter()
    .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_table_with_a_setting_keyed_trigger_guard_is_ratcheted(pool: PgPool) {
    // No calibration on a real table: since 251 none carries the shape (see
    // `setting_keyed_guard_tables`); the probe test below proves the scan.
    let found = setting_keyed_guard_tables(&pool).await;
    let ratcheted: BTreeSet<String> = RATCHETED_TABLES.iter().map(|t| (*t).to_string()).collect();
    let unlisted: Vec<&String> = found.difference(&ratcheted).collect();
    assert!(
        unlisted.is_empty(),
        "table(s) {unlisted:?} carry a trigger guard that reads a custom setting and consults \
         epigraph_definer_bypass(), which an FK referential action defeats (SPEC §7.1, SF-17). \
         Add each table's writing foreign keys to this ratchet (a list like \
         GUARDED_WRITING_ACTIONS) and to RATCHETED_TABLES, or key the guard on a table-backed \
         grant as H10 does"
    );
}

/// Calibration: a probe guard of that shape on another table is reported.
#[sqlx::test(migrations = "../../migrations")]
async fn the_guard_scan_reports_a_probe_setting_keyed_guard(pool: PgPool) {
    sqlx::query(
        "CREATE FUNCTION public.fk_ratchet_probe_guard() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN \
           IF current_setting('epigraph.probe_ids', true) IS NOT NULL \
              AND public.epigraph_definer_bypass() THEN RETURN OLD; END IF; \
           RETURN OLD; \
         END $$",
    )
    .execute(&pool)
    .await
    .expect("create the probe guard");
    sqlx::query(
        "CREATE TRIGGER fk_ratchet_probe_guard BEFORE DELETE ON public.frames \
         FOR EACH ROW EXECUTE FUNCTION public.fk_ratchet_probe_guard()",
    )
    .execute(&pool)
    .await
    .expect("attach the probe guard");
    let found = setting_keyed_guard_tables(&pool).await;
    assert!(found.contains("frames"), "the probe is reported: {found:?}");
}
