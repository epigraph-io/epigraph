//! **The retracted-BBA read ratchet** (migration 184, ruling R-79).
//!
//! A retracted mass function is kept for audit and must be excluded from
//! every fold and belief read. Nothing in the schema hides it (the row stays
//! in `mass_functions`), so the exclusion is a predicate every reader has to
//! carry. This file refuses any NEW read of `mass_functions` that carries
//! none, unless it is registered here with the reason it may see retracted
//! rows.
//!
//! # What counts
//!
//! A **read site** is a `FROM mass_functions` or `JOIN mass_functions`
//! (schema qualifier allowed; `DELETE FROM` is a write, not a read) in a
//! Rust string literal that is SQL (`belief_lint::is_sql`), with its SQL
//! comments removed. Scanned: `crates/*/src/**/*.rs`, `#[cfg(test)]` items
//! excluded.
//!
//! A read site is **filtered** by one of, in the same literal:
//! * `retracted_at IS NULL` (the column test itself);
//! * `{not_retracted}`, the `format!` argument every converted reader binds
//!   to `mass_function::not_retracted_predicate`;
//! * the `/* {NOT_RETRACTED} */` or `/* {NOT_CACHED_COMBINATION} */` marker
//!   (counted in the raw literal, comments kept), which
//!   `with_retracted_excluded` / `with_cached_combination_excluded` replace
//!   with the predicate.
//!
//! A literal's unfiltered count is its read sites minus its filters (never
//! below zero); a unit's count is the sum over its literals. Every unit with
//! a non-zero count must be in [`REGISTER`] at exactly that count.
//!
//! # Known limits, stated so a green run is not read as more
//!
//! * A filter is counted per literal, not tied to the read it filters: a
//!   literal with two reads and one filter counts one unfiltered read,
//!   whichever read the filter sits on.
//! * SQL built at runtime from pieces that are not literals, and SQL in
//!   `scripts/` (operator tools, outside the served binaries), are not
//!   scanned.
//! * Lower-case SQL is not SQL to this scan; the tree has none today.

mod belief_lint;

use belief_lint::{
    find_words, is_sql, rust_sources, rust_view, sql_without_comments, with_scratch, RustUnits,
    Source,
};
use std::collections::BTreeMap;

/// Every read of `mass_functions` that may see retracted rows, keyed
/// `(path, unit)`, with its count and the reason. Sorted by path, then unit.
#[rustfmt::skip]
const REGISTER: &[(&str, &str, usize, &str)] = &[
    // --- epigraph-cli -------------------------------------------------------
    ("crates/epigraph-cli/src/backfill_factors.rs", "const EDGE_QUERY", 1, "existence gate: edges whose target holds NO mass function row; a retracted row still counts as present, so the backfill never re-derives a BBA that was retracted"),
    ("crates/epigraph-cli/src/belief_cache.rs", "downstream_edges", 1, "restore planner: finds edges whose BBA was WRITTEN after a wave cutoff (a write timestamp, not a fold)"),
    ("crates/epigraph-cli/src/bin/backfill_factors.rs", "const EVIDENCE_QUERY", 1, "existence gate: claims holding NO mass function row; a retracted row still counts as present, so the backfill never re-derives a BBA that was retracted"),
    ("crates/epigraph-cli/src/bin/dekg.rs", "handle_migrate", 4, "legacy DEKG migration tool: mass-sum validation, missing-row gate and CONTRIBUTES_TO edge derivation over every stored row; no belief fold"),
    ("crates/epigraph-cli/src/operator/hide.rs", "print_surfaces", 1, "operator hide report: counts every stored row naming a hidden evidence row, retracted or not (the rows the hide leaves in place)"),
    ("crates/epigraph-cli/src/recompute_betp.rs", "select_wave_cohort", 1, "recompute cohort enumerator: a claim whose every BBA is retracted still enters, so the single atom-cache writer sees its (empty) fold"),
    ("crates/epigraph-cli/src/recompute_betp.rs", "template_row_ids", 1, "ids of ingest-template rows, used only to drop them from rows a filtered reader already returned"),
    ("crates/epigraph-cli/src/shadow_report.rs", "attributed_rows", 1, "narrows ids a filtered reader already returned to the attributed_v1 ones; it cannot add a row"),
    // --- epigraph-db --------------------------------------------------------
    ("crates/epigraph-db/src/repos/claim.rs", "const CANONICAL_HOLDS_KEY_SQL", 1, "dedup move: the upsert key collision test; a retracted row holds its key (migration 034's unique constraint), so a duplicate's LIVE row at that key stays on the duplicate and the merged claim folds neither (known limit, pinned by bba_retract.rs::a_dedup_keeps_a_live_row_whose_key_a_retracted_canonical_row_holds)"),
    ("crates/epigraph-db/src/repos/claim.rs", "mark_duplicate_act_attributed_conn", 1, "dedup guard: whether the duplicate holds ANY stored BBA the repair will move; retracted rows move with their marks"),
    ("crates/epigraph-db/src/repos/claim.rs", "repair_marked_duplicate", 7, "dedup repair: moves, snapshots and collision-checks stored rows, retracted ones included with their marks; no fold"),
    ("crates/epigraph-db/src/repos/claim.rs", "reverse_marked_duplicate", 3, "dedup undo: puts the repair's rows back, retracted ones included with their marks; no fold"),
    ("crates/epigraph-db/src/repos/edge.rs", "withdrawn_edges_with_bbas_conn", 1, "cleanup enumerator: withdrawn edges that still hold ANY stored row, retracted or not"),
    ("crates/epigraph-db/src/repos/mass_function.rs", "delete_for_claim", 1, "the delete's own readability probe: every stored row of the claim goes, retracted or not"),
    ("crates/epigraph-db/src/repos/mass_function.rs", "exists_for_perspective", 1, "edge wake-up gate (\"has this edge ever been wired\"): a retracted edge BBA counts as wired, so a re-asserted edge does not silently re-derive it"),
    ("crates/epigraph-db/src/repos/mass_function.rs", "get_by_id", 1, "one row by id, for audit and the retract target lookup; returns a retracted row as stored"),
    ("crates/epigraph-db/src/repos/mass_function.rs", "list_claim_ids", 1, "recompute enumerator: a claim whose every BBA is retracted still enters, so its recompute reads the (filtered) empty fold"),
    ("crates/epigraph-db/src/repos/mass_function.rs", "retracted_row_at_key", 1, "upsert-key probe for RETRACTED rows only (R-103): an automated side write skips a key a retracted row holds; no fold"),
    ("crates/epigraph-db/src/repos/mass_function.rs", "untyped_provenance_page", 2, "evidence-type backfill of a metadata tag; masses untouched and no fold"),
];

/// Read sites of `mass_functions` in one comment-free SQL text.
fn read_sites(sql: &str) -> usize {
    let flat = sql
        .replace("\\\n", " ")
        .replace("\\n", " ")
        .replace("\\t", " ");
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut n = 0;
    for at in find_words(&flat, "mass_functions") {
        let before = flat[..at].trim_end();
        let before = before.strip_suffix("public.").unwrap_or(before).trim_end();
        let is_from = before.ends_with("FROM")
            && !before.ends_with("DELETE FROM")
            && before
                .as_bytes()
                .get(before.len().wrapping_sub(5))
                .is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'_'));
        let is_join = before.ends_with("JOIN");
        if is_from || is_join {
            n += 1;
        }
    }
    n
}

/// Filters in one literal: `raw` keeps its comments (for the markers), `sql`
/// has them removed (for the predicate and the format argument).
fn filters(raw: &str, sql: &str) -> usize {
    let flat = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.matches("retracted_at IS NULL").count()
        + flat.matches("{not_retracted}").count()
        + raw.matches("{NOT_RETRACTED}").count()
        + raw.matches("{NOT_CACHED_COMBINATION}").count()
}

/// The unfiltered read sites, keyed `(path, unit)`, with their count.
fn measure(rust: &[Source]) -> BTreeMap<(String, String), usize> {
    let mut out: BTreeMap<(String, String), usize> = BTreeMap::new();
    for s in rust {
        let view = rust_view(&s.text);
        let units = RustUnits::new(&view.code);
        for lit in &view.literals {
            if !is_sql(&lit.text) {
                continue;
            }
            let sql = sql_without_comments(&lit.text);
            let n = read_sites(&sql).saturating_sub(filters(&lit.text, &sql));
            if n > 0 {
                *out.entry((s.path.clone(), units.unit_at(lit.start).0))
                    .or_default() += n;
            }
        }
    }
    out
}

/// The ratchet's verdict over `measured`, one line per finding.
fn findings(measured: &BTreeMap<(String, String), usize>) -> Vec<String> {
    let mut out = Vec::new();
    let mut register: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for (path, unit, n, _) in REGISTER {
        if register.insert((path, unit), *n).is_some() {
            out.push(format!("  {path}::{unit}: registered twice"));
        }
    }
    for ((path, unit), n) in measured {
        match register.get(&(path.as_str(), unit.as_str())) {
            None => out.push(format!(
                "  {path}::{unit}: {n} read(s) of mass_functions with no retracted-row filter.\n    \
                 A fold or belief read must exclude retracted BBAs \
                 (mass_function::not_retracted_predicate); a read that may see them \
                 (audit, a write path, an existence gate) is registered here with its reason."
            )),
            Some(e) if e != n => out.push(format!(
                "  {path}::{unit}: recorded {e}, measured {n}. {}",
                if n > e {
                    "A NEW unfiltered read was added to a registered unit."
                } else {
                    "Reads were filtered or removed; lower the count in the same commit."
                }
            )),
            Some(_) => {}
        }
    }
    for (path, unit) in register.keys() {
        if !measured.contains_key(&(path.to_string(), unit.to_string())) {
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

/// The live tree passes: every unfiltered read is registered at its count,
/// and every entry still measures.
#[test]
fn every_mass_functions_read_excludes_retracted_rows_or_is_registered() {
    let measured = measure(&rust_sources());
    let f = findings(&measured);
    assert!(
        f.is_empty(),
        "the retracted-BBA read register is out of date. {} finding(s):\n{}\nmeasured: {measured:#?}",
        f.len(),
        f.join("\n")
    );
}

/// A new fold that reads `mass_functions` with no filter fails; the same read
/// with the predicate, or through the combine-input marker, passes.
#[test]
fn a_new_unfiltered_fold_read_fails_and_a_filtered_one_passes() {
    let rust = rust_sources();
    let path = "crates/epigraph-engine/src/scratch_fold.rs";
    let bare = r#"
pub async fn scratch_fold(pool: &sqlx::PgPool, claim: uuid::Uuid) {
    let _ = sqlx::query("SELECT masses FROM mass_functions WHERE claim_id = $1")
        .bind(claim).fetch_all(pool).await;
}
"#;
    let f = findings(&measure(&with_scratch(&rust, path, bare)));
    assert!(
        names(&f, path),
        "an unfiltered fold read must be a finding; got {f:#?}"
    );

    for filtered in [
        r#"
pub async fn scratch_fold(pool: &sqlx::PgPool, claim: uuid::Uuid) {
    let _ = sqlx::query("SELECT masses FROM public.mass_functions mf WHERE mf.claim_id = $1 AND mf.retracted_at IS NULL")
        .bind(claim).fetch_all(pool).await;
}
"#,
        r#"
pub async fn scratch_fold(pool: &sqlx::PgPool, claim: uuid::Uuid) {
    let sql = format!("SELECT masses FROM mass_functions mf JOIN frames f ON f.id = mf.frame_id WHERE mf.claim_id = $1 AND {not_retracted}", not_retracted = x("mf."));
    let _ = sqlx::query(&sql).bind(claim).fetch_all(pool).await;
}
"#,
        r#"
pub async fn scratch_fold(pool: &sqlx::PgPool, claim: uuid::Uuid) {
    let sql = w(r"SELECT masses FROM mass_functions WHERE claim_id = $1 /* {NOT_CACHED_COMBINATION} */");
    let _ = sqlx::query(&sql).bind(claim).fetch_all(pool).await;
}
"#,
    ] {
        let f = findings(&measure(&with_scratch(&rust, path, filtered)));
        assert!(
            !names(&f, path),
            "a filtered read is not a finding; got {f:#?}"
        );
    }
}

/// Writes, a comment and a `DELETE FROM` are not read sites; a JOIN is.
#[test]
fn only_from_and_join_reads_are_read_sites() {
    assert_eq!(read_sites("DELETE FROM mass_functions WHERE id = $1"), 0);
    assert_eq!(read_sites("INSERT INTO mass_functions (id) VALUES ($1)"), 0);
    assert_eq!(read_sites("UPDATE mass_functions SET masses = $2"), 0);
    assert_eq!(
        read_sites(&sql_without_comments(
            "SELECT 1 /* FROM mass_functions */ FROM claims"
        )),
        0
    );
    assert_eq!(
        read_sites("SELECT 1 FROM claims c JOIN public.mass_functions mf ON mf.claim_id = c.id"),
        1
    );
    assert_eq!(
        read_sites("DELETE FROM mass_functions k USING mass_functions m WHERE EXISTS (SELECT 1 FROM mass_functions x)"),
        1
    );
}

/// Calibration: the scan sees the readers the ruling names, so a green run is
/// not a scan that reads nothing. Each of these units reads `mass_functions`
/// in a literal (filtered or not).
#[test]
fn the_named_readers_are_scanned() {
    let rust = rust_sources();
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    for s in &rust {
        let view = rust_view(&s.text);
        let units = RustUnits::new(&view.code);
        for lit in &view.literals {
            let n = read_sites(&sql_without_comments(&lit.text));
            if n > 0 {
                *seen
                    .entry((s.path.clone(), units.unit_at(lit.start).0))
                    .or_default() += n;
            }
        }
    }
    for (path, unit) in [
        (
            "crates/epigraph-db/src/repos/mass_function.rs",
            "get_for_claim_frame",
        ),
        (
            "crates/epigraph-db/src/repos/mass_function.rs",
            "cache_owner_frame_for_claim",
        ),
        (
            "crates/epigraph-db/src/repos/mass_function.rs",
            "get_for_claim_frame_perspective",
        ),
        (
            "crates/epigraph-db/src/repos/atom_axiom.rs",
            "atom_input_rows",
        ),
        (
            "crates/epigraph-db/src/repos/compound_valuation.rs",
            "compound_own_rows",
        ),
        (
            "crates/epigraph-engine/src/matching/scorer.rs",
            "score_pair",
        ),
        ("crates/epigraph-cli/src/recompute_betp.rs", "select_cohort"),
    ] {
        assert!(
            seen.contains_key(&(path.to_string(), unit.to_string())),
            "{path}::{unit} reads mass_functions and the scan does not see it"
        );
    }
    assert!(
        REGISTER
            .iter()
            .all(|(_, _, n, why)| *n > 0 && why.len() > 20),
        "every entry needs a count and a reason"
    );
}
