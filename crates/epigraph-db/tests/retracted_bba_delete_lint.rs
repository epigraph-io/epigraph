//! **The retracted-BBA delete ratchet** (SPEC §11 phase 1, K4a; rulings
//! R-79 / R-103).
//!
//! A retracted mass function (migration 184) is excluded from every fold and
//! KEPT for audit. Every served path that deletes `mass_functions` rows is a
//! re-derivation, a move or a cleanup of LIVE evidence, and must leave a
//! retracted row where it is. This file refuses any non-test
//! `DELETE FROM mass_functions` in `crates/*/src` whose SQL carries no
//! `retracted_at IS NULL` predicate, unless it is registered here with the
//! reason it may delete a retracted row (none is, today).
//!
//! It is also the code-side check of SPEC §10.1's deploy order: a binary
//! built from a tree where this passes holds no privileged delete that would
//! meet a retracted row.
//!
//! # What counts
//!
//! A **delete site** is a `DELETE FROM mass_functions` (schema qualifier
//! allowed) in a Rust string literal that is SQL (`belief_lint::is_sql`),
//! with its SQL comments removed. Scanned: `crates/*/src/**/*.rs`,
//! `#[cfg(test)]` items excluded. A site is **guarded** by a
//! `retracted_at IS NULL` (any qualifier) or a `{not_retracted}` format
//! argument (`mass_function::not_retracted_predicate`) in the same literal.
//! A literal's unguarded count is its delete sites minus its guards (never
//! below zero); a unit's count is the sum over its literals. Every unit with a
//! non-zero count must be in [`REGISTER`] at exactly that count.
//!
//! # Known limits, stated so a green run is not read as more
//!
//! * A guard is counted per literal, not tied to the DELETE's own `WHERE`: a
//!   literal whose DELETE is unguarded but whose other clause carries the
//!   predicate passes.
//! * SQL built at runtime from pieces that are not literals, SQL in
//!   `scripts/` and in `migrations/` (definer bodies; slot 194 guards those),
//!   and `ON DELETE CASCADE` from `claims` / `frames` are not scanned.

mod belief_lint;

use belief_lint::{
    find_words, is_sql, rust_sources, rust_view, sql_without_comments, with_scratch, RustUnits,
    Source,
};
use std::collections::BTreeMap;

/// Every delete of `mass_functions` that may delete a retracted row, keyed
/// `(path, unit)`, with its count and the reason. Sorted by path, then unit.
/// Empty: every served delete carries the predicate (the model is
/// `crates/epigraph-cli/src/backfill_factors.rs::delete_edge_rows`).
#[rustfmt::skip]
const REGISTER: &[(&str, &str, usize, &str)] = &[];

/// The comment-free literal with escaped newlines and runs of whitespace
/// folded to single spaces.
fn flat(sql: &str) -> String {
    sql.replace("\\\n", " ")
        .replace("\\n", " ")
        .replace("\\t", " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Delete sites of `mass_functions` in one comment-free SQL text.
fn delete_sites(sql: &str) -> usize {
    let flat = flat(sql);
    find_words(&flat, "mass_functions")
        .into_iter()
        .filter(|&at| {
            let before = flat[..at].trim_end();
            let before = before.strip_suffix("public.").unwrap_or(before).trim_end();
            before.ends_with("DELETE FROM")
        })
        .count()
}

/// Guards in one comment-free SQL text.
fn guards(sql: &str) -> usize {
    let flat = flat(sql);
    flat.matches("retracted_at IS NULL").count() + flat.matches("{not_retracted}").count()
}

/// The unguarded delete sites of one comment-free SQL text.
fn unguarded(sql: &str) -> usize {
    delete_sites(sql).saturating_sub(guards(sql))
}

/// Every delete site (guarded or not) and every unguarded one, keyed
/// `(path, unit)`.
#[allow(clippy::type_complexity)]
fn measure(
    rust: &[Source],
) -> (
    BTreeMap<(String, String), usize>,
    BTreeMap<(String, String), usize>,
) {
    let mut all: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut open: BTreeMap<(String, String), usize> = BTreeMap::new();
    for s in rust {
        let view = rust_view(&s.text);
        let units = RustUnits::new(&view.code);
        for lit in &view.literals {
            if !is_sql(&lit.text) {
                continue;
            }
            let sql = sql_without_comments(&lit.text);
            let d = delete_sites(&sql);
            if d == 0 {
                continue;
            }
            let key = (s.path.clone(), units.unit_at(lit.start).0);
            *all.entry(key.clone()).or_default() += d;
            let n = unguarded(&sql);
            if n > 0 {
                *open.entry(key).or_default() += n;
            }
        }
    }
    (all, open)
}

/// The ratchet's verdict over the unguarded sites, one line per finding.
fn findings(unguarded: &BTreeMap<(String, String), usize>) -> Vec<String> {
    let mut out = Vec::new();
    let mut register: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for (path, unit, n, _) in REGISTER {
        if register.insert((path, unit), *n).is_some() {
            out.push(format!("  {path}::{unit}: registered twice"));
        }
    }
    for ((path, unit), n) in unguarded {
        match register.get(&(path.as_str(), unit.as_str())) {
            None => out.push(format!(
                "  {path}::{unit}: {n} DELETE FROM mass_functions with no retracted_at IS NULL \
                 predicate.\n    A retracted BBA is kept for audit (R-79, R-103): delete only \
                 live rows, or register the delete here with the reason it may take a \
                 retracted one."
            )),
            Some(e) if e != n => out.push(format!(
                "  {path}::{unit}: recorded {e}, measured {n}. {}",
                if n > e {
                    "A NEW unguarded delete was added to a registered unit."
                } else {
                    "Deletes were guarded or removed; lower the count in the same commit."
                }
            )),
            Some(_) => {}
        }
    }
    for (path, unit) in register.keys() {
        if !unguarded.contains_key(&(path.to_string(), unit.to_string())) {
            out.push(format!(
                "  {path}::{unit}: registered but measures nothing; REMOVE the entry"
            ));
        }
    }
    out
}

fn names(findings: &[String], path: &str) -> bool {
    findings.iter().any(|f| f.contains(path))
}

/// The live tree passes: every served delete of `mass_functions` keeps
/// retracted rows, or is registered with its reason.
#[test]
fn every_mass_functions_delete_keeps_retracted_rows_or_is_registered() {
    let (_, unguarded) = measure(&rust_sources());
    let f = findings(&unguarded);
    assert!(
        f.is_empty(),
        "the retracted-BBA delete register is out of date. {} finding(s):\n{}\nunguarded: \
         {unguarded:#?}",
        f.len(),
        f.join("\n")
    );
}

/// A new unguarded delete fails; the same delete with the predicate
/// (qualified, schema-qualified, across a line continuation, or through the
/// shared predicate's format argument) passes.
#[test]
fn a_new_unguarded_delete_fails_and_a_guarded_one_passes() {
    let rust = rust_sources();
    let path = "crates/epigraph-engine/src/scratch_delete.rs";
    let bare = r#"
pub async fn scratch_delete(pool: &sqlx::PgPool, claim: uuid::Uuid) {
    let _ = sqlx::query("DELETE FROM mass_functions WHERE claim_id = $1")
        .bind(claim).execute(pool).await;
}
"#;
    let f = findings(&measure(&with_scratch(&rust, path, bare)).1);
    assert!(
        names(&f, path),
        "an unguarded delete must be a finding; got {f:#?}"
    );

    for guarded in [
        r#"
pub async fn scratch_delete(pool: &sqlx::PgPool, claim: uuid::Uuid) {
    let _ = sqlx::query("DELETE FROM public.mass_functions mf WHERE mf.claim_id = $1 AND mf.retracted_at IS NULL")
        .bind(claim).execute(pool).await;
}
"#,
        "
pub async fn scratch_delete(pool: &sqlx::PgPool, claim: uuid::Uuid) {
    let _ = sqlx::query(\"DELETE FROM mass_functions \\
          WHERE claim_id = $1 \\
            AND retracted_at IS NULL\")
        .bind(claim).execute(pool).await;
}
",
        r#"
pub async fn scratch_delete(pool: &sqlx::PgPool, claim: uuid::Uuid) {
    let sql = format!("DELETE FROM mass_functions mf WHERE mf.claim_id = $1 AND {not_retracted}", not_retracted = x("mf."));
    let _ = sqlx::query(&sql).bind(claim).execute(pool).await;
}
"#,
    ] {
        let f = findings(&measure(&with_scratch(&rust, path, guarded)).1);
        assert!(
            !names(&f, path),
            "a guarded delete is not a finding; got {f:#?}"
        );
    }
}

/// A guard only in a comment does not count, and only a `DELETE FROM` of the
/// table itself is a delete site.
#[test]
fn only_a_real_delete_is_a_site_and_only_live_sql_guards_it() {
    assert_eq!(delete_sites("DELETE FROM mass_functions WHERE id = $1"), 1);
    assert_eq!(
        delete_sites(
            "WITH gone AS (DELETE FROM public.mass_functions mf WHERE mf.id = $1) SELECT 1"
        ),
        1
    );
    assert_eq!(delete_sites("SELECT 1 FROM mass_functions"), 0);
    assert_eq!(delete_sites("UPDATE mass_functions SET masses = $2"), 0);
    assert_eq!(
        delete_sites("DELETE FROM mass_functions_archive WHERE id = $1"),
        0
    );
    let commented = sql_without_comments(
        "DELETE FROM mass_functions WHERE id = $1 /* AND retracted_at IS NULL */",
    );
    assert_eq!(
        delete_sites(&commented).saturating_sub(guards(&commented)),
        1,
        "a guard in a comment guards nothing"
    );
}

/// A guard binds to the DELETE's OWN target, in the DELETE's own clauses: a
/// `retracted_at IS NULL` on another table reference (inside an `EXISTS`
/// subquery, or on a `USING` table) guards nothing, and neither the keyword
/// case nor an `ONLY` hides a delete site. Without this, dropping the
/// predicate on the target of `repair_marked_duplicate`'s part-2 drop (whose
/// `EXISTS` still names `c.retracted_at IS NULL`) would leave the ratchet
/// green.
#[test]
fn a_guard_inside_a_subquery_does_not_guard_the_delete() {
    let subquery = "DELETE FROM mass_functions d WHERE d.claim_id = $1 AND EXISTS (SELECT 1 \
                    FROM mass_functions c WHERE c.claim_id = $2 AND c.retracted_at IS NULL)";
    assert_eq!(
        unguarded(subquery),
        1,
        "a guard on the subquery's row does not guard the delete"
    );
    let using = "DELETE FROM mass_functions k USING mass_functions m \
                 WHERE k.claim_id = $1 AND m.id = $2 AND m.retracted_at IS NULL";
    assert_eq!(
        unguarded(using),
        1,
        "a guard on the USING table does not guard the delete"
    );
    assert_eq!(
        unguarded(&subquery.replace(
            "WHERE d.claim_id",
            "WHERE d.retracted_at IS NULL AND d.claim_id"
        )),
        0,
        "the same delete with a guard on its own target passes"
    );
    assert_eq!(
        unguarded(&using.replace("AND m.id", "AND k.retracted_at IS NULL AND m.id")),
        0,
        "the USING delete with a guard on its own target passes"
    );
    assert_eq!(
        unguarded("delete from only mass_functions where id = $1"),
        1,
        "keyword case and ONLY do not hide a delete site"
    );
    assert_eq!(
        unguarded("delete from mass_functions as mf where mf.id = $1 and mf.retracted_at is null"),
        0,
        "a lower-case guard on the target guards it"
    );
    assert_eq!(
        unguarded(
            "WITH gone AS (DELETE FROM mass_functions WHERE claim_id = $1 RETURNING 1) \
             SELECT count(*) FROM mass_functions WHERE retracted_at IS NULL"
        ),
        1,
        "a guard after the delete's own statement guards nothing"
    );
}

/// Calibration: the scan sees every served delete of `mass_functions` SPEC
/// §11 K4a names, so a green run with an empty register is not a scan that
/// reads nothing.
#[test]
fn the_named_deletes_are_scanned() {
    let (all, _) = measure(&rust_sources());
    for (path, unit) in [
        (
            "crates/epigraph-cli/src/backfill_factors.rs",
            "delete_edge_rows",
        ),
        (
            "crates/epigraph-db/src/repos/claim.rs",
            "repair_marked_duplicate",
        ),
        (
            "crates/epigraph-db/src/repos/claim.rs",
            "reverse_marked_duplicate",
        ),
        (
            "crates/epigraph-db/src/repos/edge.rs",
            "withdraw_edge_bbas_conn",
        ),
        (
            "crates/epigraph-db/src/repos/edge.rs",
            "remove_withdrawn_edge_bbas_conn",
        ),
        (
            "crates/epigraph-db/src/repos/experiment.rs",
            "retire_promoted_hypothesis_bba",
        ),
        (
            "crates/epigraph-db/src/repos/mass_function.rs",
            "delete_edge_bbas",
        ),
        (
            "crates/epigraph-db/src/repos/mass_function.rs",
            "delete_for_claim",
        ),
    ] {
        assert!(
            all.contains_key(&(path.to_string(), unit.to_string())),
            "{path}::{unit} deletes mass_functions and the scan does not see it; scanned: \
             {all:#?}"
        );
    }
    assert!(
        REGISTER
            .iter()
            .all(|(_, _, n, why)| *n > 0 && why.len() > 20),
        "every entry needs a count and a reason"
    );
}
