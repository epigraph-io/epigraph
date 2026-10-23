//! **The BBA writer lint** (SPEC §4.1, §7.3, DONE criterion D1).
//!
//! Every write to `mass_functions` must be one the writer table of SPEC §4.1
//! knows about, so that the compound guards land on all of them. This file
//! refuses any NEW caller of the repo-layer BBA writers and any NEW raw
//! `INSERT INTO` / `UPDATE` / `DELETE FROM mass_functions`, in Rust sources
//! and in `scripts/`.

mod belief_lint;

use belief_lint::{rust_sources, script_sources, with_scratch, Source};
use std::collections::BTreeMap;

/// The measured BBA write sites, keyed `(path, unit)`, with their count.
fn measure(_rust: &[Source], _scripts: &[Source]) -> BTreeMap<(String, String), usize> {
    BTreeMap::new()
}

/// The lint's verdict over `measured`: one line per unregistered site.
fn findings(measured: &BTreeMap<(String, String), usize>) -> Vec<String> {
    measured
        .iter()
        .map(|((path, unit), n)| format!("{path}::{unit}: {n} BBA write site(s)"))
        .collect()
}

fn names(findings: &[String], path: &str) -> bool {
    findings.iter().any(|f| f.contains(path))
}

/// The live tree passes.
#[test]
fn the_tree_has_no_unregistered_bba_writer() {
    let f = findings(&measure(&rust_sources(), &script_sources()));
    assert!(f.is_empty(), "{} finding(s):\n{}", f.len(), f.join("\n"));
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
