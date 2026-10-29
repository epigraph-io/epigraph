//! **The BBA writer lint** (SPEC §4.1, §7.3, DONE criterion D1).
//!
//! Every write to `mass_functions` must be one the writer table of SPEC §4.1
//! knows about, so that the compound guards land on all of them. This file
//! refuses any NEW caller of the repo-layer BBA writers and any NEW raw
//! `INSERT INTO` / `UPDATE` / `DELETE FROM mass_functions`, in Rust sources
//! and in `scripts/`.

mod belief_lint;

use belief_lint::{
    find_words, python_unit_at, python_view, rust_sources, rust_view, script_sources,
    sql_without_comments, with_scratch, RustUnits, Source,
};
use std::collections::BTreeMap;

/// Every BBA write site in the tree today, measured on this branch, keyed
/// `(path, unit)` with its site count, and the SPEC §4.1 writer row (or the
/// reason) it stands for. Sorted by path, then unit.
const REGISTER: &[(&str, &str, usize, &str)] = &[
    // --- epigraph-api -------------------------------------------------------
    ("crates/epigraph-api/src/routes/assess.rs", "assess_claim", 1, "SPEC §4.1 W3: assess writes a claim_validity BBA; the compound refusal is PR-W1d"),
    ("crates/epigraph-api/src/routes/belief.rs", "submit_evidence", 1, "SPEC §4.1 W3: REST frames/:id/evidence; warn-then-refuse on compounds is PR-W1a"),
    ("crates/epigraph-api/src/routes/experiment_loop.rs", "analyze_result", 1, "SPEC §4.1 W13: experiment outcome BBA; PR-W4 refuses compounds and routes outcomes as evidence"),
    ("crates/epigraph-api/src/routes/hypothesis.rs", "create_hypothesis", 1, "SPEC §4.1 W13: hypothesis prior BBA; PR-W4"),
    ("crates/epigraph-api/src/routes/hypothesis.rs", "promote_hypothesis", 1, "SPEC §4.1 W13: copy_to_frame on promotion; PR-W4"),
    // --- epigraph-cli -------------------------------------------------------
    ("crates/epigraph-cli/src/backfill_factors.rs", "delete_edge_rows", 1, "SPEC §10.1 H3: rewire deletes an edge's BBAs; PR-F2 maps compound outcomes to keep, never to delete"),
    ("crates/epigraph-cli/src/backfill_factors.rs", "rewire_one", 1, "SPEC §4.1 W8: rewire restamps an edge BBA's tenancy columns; masses untouched"),
    ("crates/epigraph-cli/src/bin/dekg.rs", "handle_migrate", 1, "SPEC §4.1 W13: raw INSERT of bootstrap BBAs; PR-W4"),
    ("crates/epigraph-cli/src/bin/experiment.rs", "analyze", 1, "SPEC §4.1 W13: CLI experiment outcome BBA; PR-W4"),
    ("crates/epigraph-cli/src/bin/hypothesis.rs", "create", 1, "SPEC §4.1 W13: CLI hypothesis prior BBA; PR-W4"),
    ("crates/epigraph-cli/src/bin/hypothesis.rs", "promote", 1, "SPEC §4.1 W13: CLI copy_to_frame on promotion; PR-W4"),
    // --- epigraph-db --------------------------------------------------------
    ("crates/epigraph-db/src/repos/claim.rs", "const MOVE_BBAS_ONTO_CANONICAL_SQL", 1, "SPEC §4.1 W14: dedup moves a duplicate's BBAs onto its canonical; PR-L1c never moves rows onto a compound"),
    ("crates/epigraph-db/src/repos/claim.rs", "repair_marked_duplicate", 1, "SPEC §4.1 W14: dedup repair re-points BBAs; PR-L1c"),
    ("crates/epigraph-db/src/repos/claim.rs", "reverse_marked_duplicate", 4, "SPEC §4.1 W14: undoing a dedup moves BBAs back; PR-L1c"),
    ("crates/epigraph-db/src/repos/edge.rs", "remove_withdrawn_edge_bbas_conn", 1, "SPEC §4.2: edge withdrawal deletes the edge's factor BBAs (a lifecycle act on the target atom)"),
    ("crates/epigraph-db/src/repos/edge.rs", "withdraw_edge_bbas_conn", 1, "SPEC §4.2: edge withdrawal deletes the edge's factor BBAs (a lifecycle act on the target atom)"),
    ("crates/epigraph-db/src/repos/experiment.rs", "retire_promoted_hypothesis_bba", 1, "SPEC §4.1 W13: a promotion's DELETE of the hypothesis_assessment row it just copied, in the same transaction as copy_to_frame; it adds nothing to any claim, and PR-W4's refusal at the copy refuses the whole promotion"),
    ("crates/epigraph-db/src/repos/mass_function.rs", "backfill_evidence_type_where_untyped", 1, "maintenance backfill of the evidence_type tag only; masses untouched"),
    ("crates/epigraph-db/src/repos/mass_function.rs", "copy_to_frame", 1, "the repo-layer BBA writer API itself, delegating to store_with_perspective"),
    ("crates/epigraph-db/src/repos/mass_function.rs", "delete_edge_bbas", 1, "the repo-layer delete of an edge's factor BBAs, behind the SPEC §4.1 W8 callers"),
    ("crates/epigraph-db/src/repos/mass_function.rs", "delete_for_claim", 1, "the repo-layer delete of a claim's BBAs, behind its lifecycle callers"),
    ("crates/epigraph-db/src/repos/mass_function.rs", "store", 1, "the repo-layer BBA writer API itself, delegating to store_with_perspective"),
    ("crates/epigraph-db/src/repos/mass_function.rs", "store_with_perspective", 1, "the one repo-layer INSERT INTO mass_functions every BBA writer goes through"),
    // --- epigraph-engine ----------------------------------------------------
    ("crates/epigraph-engine/src/edge_factor.rs", "auto_wire_ds_for_edge", 1, "SPEC §4.1 W8: edge-factor BBA; PR-F2 puts the compound guard inside this function"),
    // --- epigraph-mcp -------------------------------------------------------
    ("crates/epigraph-mcp/src/tools/ds.rs", "submit_ds_evidence", 1, "SPEC §4.1 W3: MCP submit_ds_evidence; warn-then-refuse on compounds is PR-W1a"),
    ("crates/epigraph-mcp/src/tools/ds_auto.rs", "auto_wire_ds_for_claim", 1, "SPEC §4.1 W2: the first BBA of a newly created claim"),
    ("crates/epigraph-mcp/src/tools/ds_auto.rs", "auto_wire_ds_update_filed_on", 2, "SPEC §4.1 W1 and W4: the evidence BBA and the truth_value seed; PR-W1e puts the compound guard inside"),
    ("crates/epigraph-mcp/src/tools/ds_auto.rs", "wire_single_batch_entry", 1, "SPEC §4.1 W5: ingest atom BBA; PR-W3 keys it to the atom's evidence row"),
    // --- scripts ------------------------------------------------------------
    ("scripts/backfill_intra_source_evidence_discount.py", "execute_backfill", 1, "SPEC §4.1 W13 script: rewrites source_strength; frozen, not edited"),
    ("scripts/backfill_locality_tag.py", "<module>", 2, "rewrites the locality_tag metadata column only; masses untouched"),
    ("scripts/backfill_source_strength.py", "execute_backfill", 2, "SPEC §4.1 W13 script: rewrites source_strength (alpha); frozen, not edited"),
    ("scripts/e2e/probe-batch-h.sh", "<file>", 1, "end-to-end probe seeding one BBA in its own throwaway database"),
    ("scripts/link_mass_function_evidence.py", "<module>", 1, "SPEC §4.1 W13 script: rewrites evidence_id, so item keys; frozen, not edited"),
    ("scripts/migrate_mixed_bbas.py", "main", 1, "SPEC §4.1 W13 script: splits mixed BBAs; frozen, not edited"),
    ("scripts/migrate_provenance_bba.py", "migrate", 1, "SPEC §4.1 W13 script: inserts truth_value seed BBAs; frozen, not edited"),
    ("scripts/migrate_provenance_bba.py", "rollback", 1, "SPEC §4.1 W13 script: deletes the seed BBAs it inserted"),
    ("scripts/phase2_locality_tag_vocab_migration.py", "<module>", 1, "rewrites the evidence_type vocabulary only; masses untouched"),
    ("scripts/phase2_locality_tag_vocab_migration.py", "main", 1, "rewrites the evidence_type vocabulary only; masses untouched"),
    ("scripts/tests/test_migrate_provenance_bba.py", "execute", 1, "a test double that matches the statement text of migrate_provenance_bba.py; writes nothing"),
];

/// Is the text before `at` the `fn` keyword (a declaration, not a call)?
fn declared_at(code: &str, at: usize) -> bool {
    let before = code[..at].trim_end();
    before.ends_with("fn")
        && before
            .as_bytes()
            .get(before.len().wrapping_sub(3))
            .is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
}

/// Is `code[at..]` (just past a name) a call: `(`, or a turbofish then `(`?
fn called_after(code: &str, at: usize) -> bool {
    let after = code[at..].trim_start();
    let after = match after.strip_prefix("::<") {
        Some(r) => r.find('>').map_or("", |e| r[e + 1..].trim_start()),
        None => after,
    };
    after.starts_with('(')
}

/// Offsets of calls to the repo-layer BBA writers in a code view:
/// `store_with_perspective(…)` and `copy_to_frame(…)` however qualified, and
/// `store(…)` qualified by `MassFunctionRepository::` (or `Self::` inside its
/// impl).
fn writer_calls(code: &str, units: &RustUnits) -> Vec<usize> {
    let mut out = Vec::new();
    for name in ["store_with_perspective", "copy_to_frame"] {
        for at in find_words(code, name) {
            if !declared_at(code, at) && called_after(code, at + name.len()) {
                out.push(at);
            }
        }
    }
    for at in find_words(code, "store") {
        if !called_after(code, at + "store".len()) {
            continue;
        }
        let Some(before) = code[..at].trim_end().strip_suffix("::") else {
            continue;
        };
        let before = before.trim_end();
        let qualified = before.ends_with("MassFunctionRepository")
            || (before.ends_with("Self")
                && units
                    .fn_at(at)
                    .and_then(|f| f.impl_type.as_deref())
                    .is_some_and(|t| t == "MassFunctionRepository"));
        if qualified {
            out.push(at);
        }
    }
    out
}

/// Raw `INSERT INTO` / `UPDATE` / `DELETE FROM` `mass_functions` statements
/// in one text (schema qualifier and any whitespace, including `\n` escapes
/// and line continuations, allowed). Keywords are matched UPPER-case.
fn raw_writes(text: &str) -> usize {
    let flat = text
        .replace("\\\n", " ")
        .replace("\\n", " ")
        .replace("\\t", " ");
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut n = 0;
    for at in find_words(&flat, "mass_functions") {
        let before = flat[..at].trim_end();
        let before = before.strip_suffix("public.").unwrap_or(before).trim_end();
        if before.ends_with("INSERT INTO")
            || before.ends_with("DELETE FROM")
            || (before.ends_with("UPDATE")
                && before
                    .as_bytes()
                    .get(before.len().wrapping_sub(7))
                    .is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'_')))
        {
            n += 1;
        }
    }
    n
}

/// The measured BBA write sites, keyed `(path, unit)`, with their count.
fn measure(rust: &[Source], scripts: &[Source]) -> BTreeMap<(String, String), usize> {
    let mut out: BTreeMap<(String, String), usize> = BTreeMap::new();
    for s in rust {
        let view = rust_view(&s.text);
        let units = RustUnits::new(&view.code);
        for at in writer_calls(&view.code, &units) {
            *out.entry((s.path.clone(), units.unit_at(at).0))
                .or_default() += 1;
        }
        for lit in &view.literals {
            let n = raw_writes(&sql_without_comments(&lit.text));
            if n > 0 {
                *out.entry((s.path.clone(), units.unit_at(lit.start).0))
                    .or_default() += n;
            }
        }
    }
    for s in scripts {
        if s.path.ends_with(".py") {
            let view = python_view(&s.text);
            for lit in &view.literals {
                let n = raw_writes(&sql_without_comments(&lit.text));
                if n > 0 {
                    *out.entry((s.path.clone(), python_unit_at(&view.code, lit.start)))
                        .or_default() += n;
                }
            }
        } else {
            // Shell, SQL and other script files: every line that is not a
            // whole-line comment.
            let text: String = s
                .text
                .lines()
                .filter(|l| {
                    let t = l.trim_start();
                    !(t.starts_with('#') || t.starts_with("--") || t.starts_with("//"))
                })
                .collect::<Vec<_>>()
                .join("\n");
            let n = raw_writes(&text);
            if n > 0 {
                *out.entry((s.path.clone(), "<file>".to_string()))
                    .or_default() += n;
            }
        }
    }
    out
}

/// The lint's verdict over `measured`, one line per finding.
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
                "  {path}::{unit}: {n} NEW BBA write site(s) outside the register.\n    \
                 A new mass_functions writer must carry the compound guard of SPEC §4.1 and be \
                 registered here with the writer row it implements."
            )),
            Some(e) if e != n => out.push(format!(
                "  {path}::{unit}: recorded {e}, measured {n}. {}",
                if n > e {
                    "A NEW write site was added to a registered unit; register it deliberately."
                } else {
                    "Sites were removed; lower the count in the same commit."
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

/// The live tree passes: every BBA write site is registered at its count,
/// and every entry still measures.
#[test]
fn the_tree_has_no_unregistered_bba_writer() {
    let f = findings(&measure(&rust_sources(), &script_sources()));
    assert!(
        f.is_empty(),
        "the BBA writer register is out of date. {} finding(s):\n{}",
        f.len(),
        f.join("\n")
    );
}

/// A new direct call of each repo-layer BBA writer, outside the register,
/// fails.
#[test]
fn a_new_direct_bba_writer_call_outside_the_register_fails() {
    let rust = rust_sources();
    let scripts = script_sources();
    let path = "crates/epigraph-mcp/src/tools/scratch_bba_writer.rs";
    for call in [
        "epigraph_db::MassFunctionRepository::store(pool, claim, frame, None, &masses, None, None, None)",
        "MassFunctionRepository::store_with_perspective(&mut *tx, claim, frame, None, None, &masses, None, None, None)",
        "epigraph_db::MassFunctionRepository::copy_to_frame(&mut *tx, latest, frame)",
    ] {
        let src = format!(
            "pub async fn scratch_write(pool: &sqlx::PgPool) {{\n    let _ = {call}.await;\n}}\n"
        );
        let f = findings(&measure(&with_scratch(&rust, path, &src), &scripts));
        assert!(
            names(&f, path),
            "a new `{call}` outside the register must be a finding; got {f:#?}"
        );
    }
}

/// A raw `UPDATE mass_functions` in a new script fails.
#[test]
fn a_raw_mass_functions_update_in_a_scratch_script_fails() {
    let path = "scripts/scratch_rescale_bbas.py";
    let src = r#"
def rescale(cur, factor):
    cur.execute(
        "UPDATE mass_functions SET source_strength = source_strength * %s",
        (factor,),
    )
"#;
    let f = findings(&measure(
        &rust_sources(),
        &with_scratch(&script_sources(), path, src),
    ));
    assert!(
        names(&f, path),
        "a raw `UPDATE mass_functions` in a script must be a finding; got {f:#?}"
    );
}

/// A raw `INSERT INTO mass_functions` in Rust source fails, as `bin/dekg.rs`
/// would if it were new.
#[test]
fn a_raw_mass_functions_insert_in_rust_src_fails() {
    let path = "crates/epigraph-cli/src/bin/scratch_bba_import.rs";
    let src = r#"
async fn import_one(pool: &sqlx::PgPool, claim: uuid::Uuid, frame: uuid::Uuid) {
    sqlx::query("INSERT INTO mass_functions (claim_id, frame_id, masses) VALUES ($1, $2, '{}')")
        .bind(claim)
        .bind(frame)
        .execute(pool)
        .await
        .ok();
}
"#;
    let f = findings(&measure(
        &with_scratch(&rust_sources(), path, src),
        &script_sources(),
    ));
    assert!(
        names(&f, path),
        "a raw `INSERT INTO mass_functions` in Rust source must be a finding; got {f:#?}"
    );
}

// ---------------------------------------------------------------------------
// Calibration
// ---------------------------------------------------------------------------

/// Both trees are read, and every writer SPEC §4.1 names by path is seen.
#[test]
fn the_spec_named_writers_are_measured() {
    let measured = measure(&rust_sources(), &script_sources());
    assert!(
        measured.len() > 30,
        "expected >30 BBA write units today, measured {}",
        measured.len()
    );
    for path in [
        "crates/epigraph-api/src/routes/hypothesis.rs",
        "crates/epigraph-api/src/routes/experiment_loop.rs",
        "crates/epigraph-api/src/routes/belief.rs",
        "crates/epigraph-api/src/routes/assess.rs",
        "crates/epigraph-cli/src/bin/hypothesis.rs",
        "crates/epigraph-cli/src/bin/experiment.rs",
        "crates/epigraph-cli/src/bin/dekg.rs",
        "crates/epigraph-engine/src/edge_factor.rs",
        "crates/epigraph-mcp/src/tools/ds.rs",
        "crates/epigraph-mcp/src/tools/ds_auto.rs",
        "scripts/migrate_provenance_bba.py",
        "scripts/link_mass_function_evidence.py",
        "scripts/backfill_source_strength.py",
        "scripts/backfill_intra_source_evidence_discount.py",
        "scripts/migrate_mixed_bbas.py",
        // SPEC §4.1 W14 names `scripts/fuzzy_dedup_claims.py`. The script now
        // marks duplicates through the REST dedup act and writes no BBA
        // itself; the act's BBA moves are this file's
        // `MOVE_BBAS_ONTO_CANONICAL_SQL` and the dedup repair / reverse.
        "crates/epigraph-db/src/repos/claim.rs",
    ] {
        assert!(
            measured.keys().any(|(p, _)| p == path),
            "SPEC §4.1 names {path} as a BBA writer, and the lint does not see it"
        );
    }
    let reasons_ok = REGISTER
        .iter()
        .all(|(_, _, n, why)| *n > 0 && why.len() > 20);
    assert!(reasons_ok, "every entry needs a count and a reason");
}

/// The register counts sites: one more call inside a registered unit is a
/// finding, not absorbed by the unit's entry.
#[test]
fn a_new_call_inside_a_registered_unit_is_a_finding() {
    let path = "crates/epigraph-api/src/routes/experiment_loop.rs";
    let mut rust = rust_sources();
    let src = rust
        .iter_mut()
        .find(|s| s.path == path)
        .expect("experiment_loop.rs is scanned");
    let call = "epigraph_db::MassFunctionRepository::store(";
    let at = src.text.find(call).expect("the registered store call");
    src.text
        .insert_str(at, "epigraph_db::MassFunctionRepository::store(); ");
    let f = findings(&measure(&rust, &script_sources()));
    assert!(
        f.iter()
            .any(|l| l.contains(&format!("{path}::analyze_result"))
                && l.contains("recorded 1, measured 2")),
        "a second store call in a registered unit must be a finding; got {f:#?}"
    );
}

/// A declaration, a `use`, a comment and a doc line are not write sites.
#[test]
fn only_calls_and_statements_are_write_sites() {
    let path = "crates/epigraph-db/src/repos/scratch_not_a_writer.rs";
    let src = r#"
use crate::repos::mass_function::MassFunctionRepository;
/// Delegates like `MassFunctionRepository::store(pool, ...)` and
/// `UPDATE mass_functions SET masses = ...` would; this one does neither.
pub async fn store_with_perspective_doc_only() {}
pub trait Writer { fn store_with_perspective(&self); fn copy_to_frame(&self); }
// MassFunctionRepository::copy_to_frame(&mut *tx, latest, frame).await;
fn kv_store(store: &mut Vec<u8>) { store.clear(); }
"#;
    let f = findings(&measure(
        &with_scratch(&rust_sources(), path, src),
        &script_sources(),
    ));
    assert!(!names(&f, path), "nothing here writes a BBA; got {f:#?}");
}
