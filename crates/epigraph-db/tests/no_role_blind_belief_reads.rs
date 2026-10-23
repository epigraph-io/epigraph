//! **The role-blind belief-read ratchet** (SPEC §7.3, DONE criterion D5).
//!
//! A compound's cached belief columns are a fold of its own BBAs, not a
//! value derived from its leaves, so every reader that serves or computes
//! with `claims.belief` / `plausibility` / `pignistic_prob` (or with
//! `truth_value` as a belief) must know the claim's role. This file refuses
//! any NEW reader that does not.

mod belief_lint;

use belief_lint::{rust_sources, script_sources, with_scratch, Source};
use std::collections::{BTreeMap, BTreeSet};

/// What a unit reads, as the ratchet measured it.
#[derive(Debug, Default)]
struct Unit {
    kinds: BTreeSet<&'static str>,
}

/// The measured role-blind readers, keyed `(path, unit)`.
fn measure(_rust: &[Source], _scripts: &[Source]) -> BTreeMap<(String, String), Unit> {
    BTreeMap::new()
}

/// The ratchet's verdict over `measured`: one line per unregistered reader.
fn findings(measured: &BTreeMap<(String, String), Unit>) -> Vec<String> {
    measured
        .iter()
        .map(|((path, unit), u)| format!("{path}::{unit} reads {:?}", u.kinds))
        .collect()
}

fn names(findings: &[String], path: &str) -> bool {
    findings.iter().any(|f| f.contains(path))
}

/// The live tree passes.
#[test]
fn the_tree_has_no_unregistered_role_blind_reader() {
    let f = findings(&measure(&rust_sources(), &script_sources()));
    assert!(f.is_empty(), "{} finding(s):\n{}", f.len(), f.join("\n"));
}

const SCRATCH_READER_PATH: &str = "crates/epigraph-api/src/routes/scratch_belief_reader.rs";

/// A new raw `c.pignistic_prob` reader fails; the same reader with the
/// compound predicate spliced passes.
#[test]
fn a_raw_pignistic_reader_fails_and_its_role_spliced_twin_passes() {
    let rust = rust_sources();
    let scripts = script_sources();

    let raw = r#"
pub async fn scratch_low_belief(pool: &sqlx::PgPool) -> Vec<uuid::Uuid> {
    sqlx::query_scalar("SELECT c.id FROM claims c WHERE c.pignistic_prob < 0.3")
        .fetch_all(pool)
        .await
        .unwrap_or_default()
}
"#;
    let f = findings(&measure(
        &with_scratch(&rust, SCRATCH_READER_PATH, raw),
        &scripts,
    ));
    assert!(
        names(&f, SCRATCH_READER_PATH),
        "a new role-blind `c.pignistic_prob` reader must be a finding; got {f:#?}"
    );

    let spliced = r#"
use epigraph_db::repos::claim_role::{render, IS_COMPOUND_SQL};
pub async fn scratch_low_belief(pool: &sqlx::PgPool) -> Vec<uuid::Uuid> {
    let sql = format!(
        "SELECT c.id FROM claims c WHERE c.pignistic_prob < 0.3 AND NOT {}",
        render(IS_COMPOUND_SQL, "c")
    );
    sqlx::query_scalar(&sql).fetch_all(pool).await.unwrap_or_default()
}
"#;
    let f = findings(&measure(
        &with_scratch(&rust, SCRATCH_READER_PATH, spliced),
        &scripts,
    ));
    assert!(
        !names(&f, SCRATCH_READER_PATH),
        "a reader that splices IS_COMPOUND_SQL is classified; got {f:#?}"
    );
}

/// A field read on the row type `ClaimRepository::semantic_search_flat`
/// returns fails: SQL-text scanning alone cannot see this consumer.
#[test]
fn a_field_read_on_the_semantic_search_flat_row_fails() {
    let path = "crates/epigraph-api/src/routes/scratch_flat_reader.rs";
    let src = r#"
pub async fn scratch_mean_belief(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::Viewer,
    embedding: &str,
) -> f64 {
    let rows = epigraph_db::ClaimRepository::semantic_search_flat(
        pool, viewer, embedding, 0.0, None, None, None, None, 10,
    )
    .await
    .unwrap_or_default();
    rows.iter().map(|row| row.belief.unwrap_or(0.0)).sum::<f64>()
}
"#;
    let f = findings(&measure(
        &with_scratch(&rust_sources(), path, src),
        &script_sources(),
    ));
    assert!(
        names(&f, path),
        "a `.belief` read on a semantic_search_flat row must be a finding; got {f:#?}"
    );
}
