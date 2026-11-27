//! Self-tests for `source_files/mod.rs`, the module-aware path resolution the
//! path-keyed lints share (backlog 7174d30f, split 3/6 of 39955709).
//!
//! What must hold for a lint to survive `claim.rs` becoming a directory
//! module without loosening:
//! * a function moved into the directory is still found, and keys as the
//!   registered path;
//! * a function that exists nowhere still fails;
//! * nothing outside the listed module's directory is folded onto it.

mod source_files;

use source_files::{
    belongs_to, files_defining, fn_body, module_files, module_files_in, module_key, repo_sources,
    repo_sources_in, split_module, SPLIT_MODULES,
};
use std::path::PathBuf;

const CLAIM: &str = "crates/epigraph-db/src/repos/claim.rs";

fn files(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(p, t)| (p.to_string(), t.to_string()))
        .collect()
}

/// A scratch directory under the system temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "epigraph-source-files-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
    fn write(&self, rel: &str, text: &str) {
        let p = self.0.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn files_inside_the_module_directory_key_as_the_module_in_every_path_form() {
    for (path, key) in [
        (CLAIM, CLAIM),
        ("crates/epigraph-db/src/repos/claim/mod.rs", CLAIM),
        ("crates/epigraph-db/src/repos/claim/dedup.rs", CLAIM),
        ("crates/epigraph-db/src/repos/claim/search/hybrid.rs", CLAIM),
        (
            "epigraph-db/src/repos/claim/dedup.rs",
            "epigraph-db/src/repos/claim.rs",
        ),
        ("src/repos/claim/mod.rs", "src/repos/claim.rs"),
        ("claim/dedup.rs", "claim.rs"),
        ("claim.rs", "claim.rs"),
    ] {
        assert_eq!(module_key(path), key, "{path}");
    }
}

#[test]
fn nothing_outside_the_listed_module_directory_is_folded() {
    for path in [
        // Siblings sharing the name as a PREFIX, not a directory.
        "crates/epigraph-db/src/repos/claim_history.rs",
        "crates/epigraph-db/src/repos/claim_context.rs",
        "crates/epigraph-db/src/repos/claim_role.rs",
        "claim_history.rs",
        "epigraph-db/src/repos/claim_ingest.rs",
        // The existing `X.rs` + `X/` pairs that are NOT listed.
        "crates/epigraph-engine/src/supersede_delta/apply.rs",
        "crates/epigraph-api/src/routes/elevate/ceremony.rs",
        "epigraph-api/src/routes/elevate/ceremony.rs",
        // A `claim/` directory somewhere else.
        "crates/epigraph-api/src/routes/claim/x.rs",
        "crates/epigraph-db/src/claim/x.rs",
        // Not Rust.
        "crates/epigraph-db/src/repos/claim/notes.md",
    ] {
        assert_eq!(module_key(path), path, "{path} must key as itself");
    }
    assert_eq!(
        SPLIT_MODULES,
        &[CLAIM],
        "list a module here only when it is split"
    );
}

#[test]
fn a_moved_function_is_found_and_a_missing_one_fails() {
    // The split's end state: no claim.rs, a mod.rs and a child.
    let tree = files(&[
        (
            "crates/epigraph-db/src/repos/claim/mod.rs",
            "mod history;\npub async fn get_by_id_conn(c: u8) -> u8 {\n    c\n}\n",
        ),
        (
            "crates/epigraph-db/src/repos/claim/history.rs",
            "impl X {\n    pub async fn predecessors_of(c: u8) -> u8 {\n        { c }\n    }\n}\n",
        ),
        (
            "crates/epigraph-db/src/repos/claim_history.rs",
            "pub async fn elsewhere() {}\n",
        ),
    ]);
    let module: Vec<(String, String)> = tree
        .iter()
        .filter(|(p, _)| belongs_to(CLAIM, p))
        .cloned()
        .collect();
    assert_eq!(
        module.len(),
        2,
        "the sibling claim_history.rs is not the module"
    );

    assert_eq!(
        files_defining(&module, "predecessors_of"),
        vec!["crates/epigraph-db/src/repos/claim/history.rs".to_string()]
    );
    assert_eq!(
        fn_body(&module, "pub async fn predecessors_of("),
        "{\n        { c }\n    }"
    );
    assert_eq!(
        fn_body(&module, "pub async fn get_by_id_conn("),
        "{\n    c\n}"
    );
    assert!(files_defining(&module, "elsewhere").is_empty());
    assert!(files_defining(&module, "no_such_fn").is_empty());

    let missing = std::panic::catch_unwind(|| {
        let _ = fn_body(&module, "pub async fn no_such_fn(");
    });
    assert!(missing.is_err(), "a function in no file must fail");

    // A copy left behind by a move is two definitions, and fails too.
    let mut doubled = module.clone();
    doubled.push((
        "crates/epigraph-db/src/repos/claim/stale.rs".to_string(),
        "pub async fn predecessors_of(c: u8) -> u8 { c }\n".to_string(),
    ));
    let twice = std::panic::catch_unwind(|| {
        let _ = fn_body(&doubled, "pub async fn predecessors_of(");
    });
    assert!(
        twice.is_err(),
        "two definitions across the module must fail"
    );
}

#[test]
fn the_disk_reader_takes_the_file_and_its_directory_and_recurses() {
    let s = Scratch::new("module");
    s.write("crates/epigraph-db/src/repos/claim.rs", "fn root() {}\n");
    s.write(
        "crates/epigraph-db/src/repos/claim/dedup.rs",
        "fn moved() {}\n",
    );
    s.write(
        "crates/epigraph-db/src/repos/claim/a/b.rs",
        "fn deep() {}\n",
    );
    s.write(
        "crates/epigraph-db/src/repos/claim_history.rs",
        "fn sibling() {}\n",
    );
    let got = module_files_in(&s.0, CLAIM);
    assert_eq!(
        got.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
        vec![
            "crates/epigraph-db/src/repos/claim.rs",
            "crates/epigraph-db/src/repos/claim/a/b.rs",
            "crates/epigraph-db/src/repos/claim/dedup.rs",
        ]
    );

    // The `mod.rs` layout, with no claim.rs at all.
    let m = Scratch::new("modrs");
    m.write(
        "crates/epigraph-db/src/repos/claim/mod.rs",
        "fn root() {}\n",
    );
    m.write(
        "crates/epigraph-db/src/repos/claim/dedup.rs",
        "fn moved() {}\n",
    );
    let got = module_files_in(&m.0, CLAIM);
    assert_eq!(got.len(), 2);
    assert_eq!(files_defining(&got, "moved").len(), 1);
}

#[test]
fn the_repos_walk_recurses_and_keys_a_split_module_by_its_file_name() {
    let s = Scratch::new("repos");
    s.write("claim.rs", "fn root() {}\n");
    s.write("claim/dedup.rs", "fn moved() {}\n");
    s.write("claim_history.rs", "fn sibling() {}\n");
    s.write("other/child.rs", "fn other() {}\n");
    let got: Vec<(String, String)> = repo_sources_in(&s.0);
    assert_eq!(
        got,
        files(&[
            ("claim.rs", "fn root() {}\n"),
            ("claim.rs", "fn moved() {}\n"),
            ("claim_history.rs", "fn sibling() {}\n"),
            ("other/child.rs", "fn other() {}\n"),
        ]),
        "a file in the split module's directory is scanned under the module's name; a file \
         in any other subdirectory is scanned under its own path, never skipped"
    );
}

#[test]
fn split_module_moves_whole_items_into_the_module_directory() {
    let text = "use x;\n\nimpl A {\n    fn a() {}\n}\n\nimpl B {\n    fn b() {}\n}\n";
    let sibling =
        "impl S {\n    fn s() {}\n}\nimpl T {\n    fn t() {}\n}\n// larger than claim.rs\n";
    let tree = files(&[
        (CLAIM, text),
        ("crates/epigraph-db/src/repos/claim_history.rs", sibling),
    ]);
    let split = split_module(&tree, CLAIM);
    let paths: Vec<&str> = split.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            CLAIM,
            "crates/epigraph-db/src/repos/claim/split_probe.rs",
            "crates/epigraph-db/src/repos/claim_history.rs",
        ],
        "the module's file is split, never a larger sibling"
    );
    assert_eq!(
        split[0].1.clone() + &split[1].1,
        text,
        "nothing lost or added"
    );
    assert!(
        split[1].1.starts_with("impl "),
        "split at a top-level impl line"
    );
    assert_eq!(split[2].1, sibling);
}

/// After the split (`claim/mod.rs` and children, no `claim.rs`) the probe
/// still resolves the module: its largest file is split.
#[test]
fn split_module_works_on_the_mod_rs_layout() {
    let small = "mod dedup;\n";
    let big = "impl A {\n    fn a() {}\n}\n\nimpl B {\n    fn b() {}\n}\n";
    let tree = files(&[
        ("crates/epigraph-db/src/repos/claim/mod.rs", small),
        ("crates/epigraph-db/src/repos/claim/dedup.rs", big),
    ]);
    let split = split_module(&tree, CLAIM);
    assert_eq!(
        split.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
        vec![
            "crates/epigraph-db/src/repos/claim/dedup.rs",
            "crates/epigraph-db/src/repos/claim/mod.rs",
            "crates/epigraph-db/src/repos/claim/split_probe.rs",
        ]
    );
    assert_eq!(split[0].1.clone() + &split[2].1, big);
    assert_eq!(split[1].1, small);

    let taken = files(&[
        (CLAIM, big),
        ("crates/epigraph-db/src/repos/claim/split_probe.rs", small),
    ]);
    assert!(
        std::panic::catch_unwind(|| split_module(&taken, CLAIM)).is_err(),
        "an existing probe path is refused, not overwritten"
    );
    let absent = files(&[("crates/epigraph-db/src/repos/claim_history.rs", big)]);
    assert!(
        std::panic::catch_unwind(|| split_module(&absent, CLAIM)).is_err(),
        "a tree without the module is refused"
    );
}

/// Calibration on the live tree: the registered module resolves to source
/// that defines the functions the structural lints pin, and the repos walk
/// sees the module under its registered name.
#[test]
fn the_live_claim_module_resolves() {
    let module = module_files(CLAIM);
    assert!(module.iter().all(|(p, _)| belongs_to(CLAIM, p)));
    assert_eq!(files_defining(&module, "get_by_id_conn").len(), 1);
    assert_eq!(files_defining(&module, "repair_marked_duplicate").len(), 1);
    let repos = repo_sources();
    assert!(repos
        .iter()
        .any(|(k, t)| k == "claim.rs" && t.contains("fn get_by_id_conn(")));
    assert!(repos.iter().any(|(k, _)| k == "claim_history.rs"));
}
