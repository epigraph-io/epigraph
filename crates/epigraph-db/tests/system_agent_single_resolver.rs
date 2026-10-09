//! Source ratchet (static, no database): the workflow-ingest system agent is
//! resolved in ONE place.
//!
//! Migration 148 moved "which agent is the workflow-ingest system agent" from a
//! key derived from the public constant `"workflow-ingest-system"` to the
//! `system_agents` registry. Before it, that derivation was spelled out in two
//! resolver bodies (`epigraph-ingest-executor::system_agent` and
//! `epigraph-api::routes::workflows`), each looking the key up and creating an
//! agent on a miss. A copy of that body anywhere would keep its caller on the
//! pre-148 rule, and after a key rotation it would try to re-create the
//! public-constant identity. So this file pins, in both directions:
//!
//! 1. the quoted literal `"workflow-ingest-system"` appears in non-test source
//!    under `crates/*/src` ONLY in `epigraph-db/src/repos/system_agent.rs`;
//! 2. `legacy_public_key(` is called only by that module and the executor's
//!    one resolver (its unarmed, unregistered fallback);
//! 3. `epigraph-api`'s `routes/workflows.rs::get_or_create_system_agent` holds
//!    no `get_by_public_key` and no `did_key_for_author`: it delegates.
//!
//! Whole-line comments and a trailing `#[cfg(test)] mod` are not scanned.
//! [`the_scanner_is_not_vacuous`] calibrates each rule on a synthetic copy of
//! the pre-148 body.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const LITERAL: &str = "\"workflow-ingest-system\"";
const LEGACY_KEY_CALL: &str = "legacy_public_key(";

/// The only file that may name the public constant.
const LITERAL_HOME: &str = "epigraph-db/src/repos/system_agent.rs";

/// The only callers of `legacy_public_key(`.
const LEGACY_KEY_CALLERS: &[&str] = &[
    "epigraph-db/src/repos/system_agent.rs",
    "epigraph-ingest-executor/src/system_agent.rs",
];

fn crates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf()
}

fn collect(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Every `crates/<crate>/src/**/*.rs`, keyed `<crate>/src/...`.
fn source_files() -> Vec<(String, String)> {
    let root = crates_root();
    let mut out = Vec::new();
    for krate in std::fs::read_dir(&root).expect("crates/").flatten() {
        let src = krate.path().join("src");
        if !src.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        collect(&src, &mut files);
        for f in files {
            let rel = f
                .strip_prefix(&root)
                .expect("under crates/")
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&f).expect("read source");
            out.push((rel, text));
        }
    }
    out
}

/// The code a production build compiles: whole-line comments dropped, and the
/// file cut at its first `#[cfg(test)]` that opens a `mod`.
fn production_code(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if t == "#[cfg(test)]"
            && lines[i + 1..]
                .iter()
                .find(|l| !l.trim().is_empty())
                .is_some_and(|l| l.trim_start().starts_with("mod "))
        {
            break;
        }
        if t.starts_with("//") {
            continue;
        }
        out.push(*line);
    }
    out.join("\n")
}

fn files_containing(files: &[(String, String)], needle: &str) -> BTreeSet<String> {
    files
        .iter()
        .filter(|(_, text)| production_code(text).contains(needle))
        .map(|(rel, _)| rel.clone())
        .collect()
}

/// The body of the first `fn <name>(` in `src`, by brace matching.
fn fn_body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let start = src.find(&format!("fn {name}("))?;
    let open = start + src[start..].find('{')?;
    let mut depth = 0usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&src[open..=open + i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn api_resolver_violations(src: &str) -> Vec<&'static str> {
    let body = fn_body(src, "get_or_create_system_agent")
        .expect("routes/workflows.rs::get_or_create_system_agent exists");
    let body = production_code(body);
    ["get_by_public_key", "did_key_for_author"]
        .into_iter()
        .filter(|n| body.contains(n))
        .collect()
}

#[test]
fn only_the_registry_module_names_the_public_constant() {
    let files = source_files();
    assert!(files.len() > 200, "the scan found {} files", files.len());
    let found = files_containing(&files, LITERAL);
    assert_eq!(
        found,
        BTreeSet::from([LITERAL_HOME.to_string()]),
        "the public-constant name of the workflow-ingest system agent is spelled outside \
         `{LITERAL_HOME}`. Resolve the agent through `get_or_create_system_agent` (the registry, \
         migration 148), and name the legacy seed only through `SystemAgentRole`."
    );
}

#[test]
fn only_the_resolver_and_its_tools_derive_the_legacy_key() {
    let found = files_containing(&source_files(), LEGACY_KEY_CALL);
    let want: BTreeSet<String> = LEGACY_KEY_CALLERS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(
        found, want,
        "`legacy_public_key(` is called from an unexpected file. The legacy key is a fallback \
         of the one resolver on an unarmed, unregistered database and a reserved-author check \
         (`is_reserved_author_key`); anything else re-derives the system identity from a \
         public constant."
    );
}

#[test]
fn the_api_resolver_delegates() {
    let path = crates_root().join("epigraph-api/src/routes/workflows.rs");
    let src = std::fs::read_to_string(path).expect("routes/workflows.rs");
    assert_eq!(
        api_resolver_violations(&src),
        Vec::<&str>::new(),
        "routes/workflows.rs::get_or_create_system_agent must delegate to \
         epigraph_ingest_executor::get_or_create_system_agent, not look a key up itself"
    );
}

/// Each rule fires on a synthetic copy of the pre-148 resolver body, and the
/// comment / test-module stripping does not hide live code.
#[test]
fn the_scanner_is_not_vacuous() {
    let pre_148 = r#"
pub(crate) async fn get_or_create_system_agent(pool: &sqlx::PgPool) -> Result<Uuid, ApiError> {
    let (_did, pub_key_bytes) =
        epigraph_crypto::did_key::did_key_for_author(None, "workflow-ingest-system");
    if let Some(a) = epigraph_db::AgentRepository::get_by_public_key(pool, &pub_key_bytes)
        .await
        .map_err(|e| ApiError::InternalError { message: e.to_string() })?
    {
        return Ok(a.id.as_uuid());
    }
    todo!()
}
"#;
    assert_eq!(
        api_resolver_violations(pre_148),
        vec!["get_by_public_key", "did_key_for_author"]
    );
    let files = vec![("x/src/a.rs".to_string(), pre_148.to_string())];
    assert_eq!(
        files_containing(&files, LITERAL),
        BTreeSet::from(["x/src/a.rs".to_string()])
    );
    let commented = "// \"workflow-ingest-system\"\nfn f() {}\n";
    let in_tests = "fn f() {}\n#[cfg(test)]\nmod tests {\n    const X: &str = \"workflow-ingest-system\";\n}\n";
    let files = vec![
        ("x/src/c.rs".to_string(), commented.to_string()),
        ("x/src/t.rs".to_string(), in_tests.to_string()),
    ];
    assert!(files_containing(&files, LITERAL).is_empty());
}
