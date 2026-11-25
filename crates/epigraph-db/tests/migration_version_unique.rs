//! Every migration version is claimed by exactly one file.
//!
//! sqlx keys a migration by the integer before the first `_` of its file name
//! and nothing else. Two branches that each add a migration with the same
//! number but a different name merge with NO git conflict (the paths differ),
//! and the resulting tree carries two files for one version. `sqlx::migrate!`
//! embeds such a pair without a compile error (measured with a planted
//! duplicate, which failed both checks below), so nothing static stops the
//! merge; any failure surfaces only when a database applies the second file.
//! This ratchet fails the merged tree instead, on the file listing and on the
//! migrator sqlx actually embeds.
//!
//! The version is parsed the way sqlx parses it (an integer, so `09001_a` and
//! `9001_b` collide). A reversible pair (`N_x.up.sql` / `N_x.down.sql`) shares
//! one version by design; only the up half is counted.

use std::collections::BTreeMap;
use std::path::PathBuf;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// The versions claimed by more than one migration file, with the files.
fn duplicate_versions<'a>(names: impl IntoIterator<Item = &'a str>) -> BTreeMap<i64, Vec<String>> {
    let mut by_version: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    for name in names {
        if !name.ends_with(".sql") || name.ends_with(".down.sql") {
            continue;
        }
        let Some((prefix, _)) = name.split_once('_') else {
            continue;
        };
        let Ok(version) = prefix.parse::<i64>() else {
            continue;
        };
        by_version
            .entry(version)
            .or_default()
            .push(name.to_string());
    }
    by_version.retain(|_, files| files.len() > 1);
    by_version
}

fn migration_file_names() -> Vec<String> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| {
            entry
                .expect("directory entry")
                .file_name()
                .into_string()
                .expect("a UTF-8 file name")
        })
        .collect();
    names.sort();
    names
}

#[test]
fn every_migration_file_claims_its_own_version() {
    let names = migration_file_names();
    let versioned = names
        .iter()
        .filter(|n| n.ends_with(".sql") && n.split_once('_').is_some())
        .count();
    // Floor: a scan that silently read nothing (a moved directory, a filter
    // that drops every name) must not pass as "no duplicates".
    assert!(
        versioned >= 250,
        "PREMISE: the scan reads the migration directory ({versioned} versioned files)"
    );
    let dups = duplicate_versions(names.iter().map(String::as_str));
    assert!(
        dups.is_empty(),
        "two migration files claim one version (sqlx keys on the number alone; renumber the \
         branch that is merged second above main's head): {dups:?}"
    );
}

#[test]
fn the_embedded_migrator_holds_each_version_once() {
    let mut seen: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    for m in MIGRATOR.iter() {
        if m.migration_type.is_down_migration() {
            continue;
        }
        seen.entry(m.version)
            .or_default()
            .push(m.description.to_string());
    }
    assert!(
        seen.len() >= 250,
        "PREMISE: the migrator embeds the directory ({} versions)",
        seen.len()
    );
    seen.retain(|_, d| d.len() > 1);
    assert!(
        seen.is_empty(),
        "the embedded migrator holds one version twice: {seen:?}"
    );
}

/// Self-test: the checker reports a planted duplicate, including one spelled
/// with a leading zero, and leaves a reversible pair and non-migrations alone.
#[test]
fn a_planted_duplicate_version_is_reported() {
    // Versions far above any migration range: a later mechanical renumber of
    // the migrations rewrites in-range numbers on the lines it touches, and
    // must not rewrite this fixture.
    let planted = [
        "9000_first.sql",
        "9001_one_branch.sql",
        "9001_another_branch.sql",
        "09002_padded.sql",
        "9002_unpadded.sql",
        "9003_reversible.up.sql",
        "9003_reversible.down.sql",
        "README.md",
        "SCHEMA_DIAGRAM.md",
    ];
    let dups = duplicate_versions(planted);
    assert_eq!(
        dups.keys().copied().collect::<Vec<_>>(),
        vec![9001, 9002],
        "the planted 9001 pair and the zero-padded 9002 pair, nothing else: {dups:?}"
    );
    assert!(
        duplicate_versions(["9000_a.sql", "9001_b.sql", "README.md"]).is_empty(),
        "CALIBRATION: distinct versions report nothing"
    );
}
