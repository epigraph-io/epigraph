//! Every evidence insert writes the evidence's stored edge to its claim
//! (backlog 2d60f619). A static lint, no database.
//!
//! # Why
//!
//! The Atlas leaf view draws stored `evidence -> claim` edges only; there is no
//! derived edge (operator ruling). So every evidence row must be written with
//! its edge, in the same transaction, and the one writer of that edge is
//! `EvidenceRepository::link_to_claims_signed_conn`. A new evidence writer that
//! forgot it would quietly bring back edge-less evidence, which the backfill
//! would then have to find again. This lint makes forgetting it a test
//! failure.
//!
//! # What it measures
//!
//! * **Rust.** Every non-test source file under `crates/*/src`, for an
//!   `INSERT INTO evidence` / `INSERT INTO public.evidence` statement. The
//!   function the statement sits in (the text from its `fn` declaration to the
//!   next `fn` declaration) must call `link_to_claims_signed_conn(`. `#[cfg(test)]`
//!   modules are skipped.
//! * **SQL.** Every function defined in `migrations/*.sql`, at its LIVE
//!   definition (the last `CREATE [OR REPLACE] FUNCTION` of that name, in
//!   migration order), whose body inserts into `evidence` must also insert
//!   into `edges`.
//!
//! # What it does not see
//!
//! An INSERT assembled from pieces, or through `EXECUTE format(..)`, or a
//! function body quoted with single quotes. None writes evidence in-tree; the
//! inventory counts below fail if the scanner stops finding the writers it
//! knows about.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// `true` when `line` (trimmed) declares a function.
fn is_fn_decl(line: &str) -> bool {
    let t = line.trim_start();
    let t = t
        .strip_prefix("pub(crate) ")
        .or_else(|| t.strip_prefix("pub(super) "))
        .or_else(|| t.strip_prefix("pub "))
        .unwrap_or(t);
    let t = t.strip_prefix("const ").unwrap_or(t);
    let t = t.strip_prefix("async ").unwrap_or(t);
    let t = t.strip_prefix("unsafe ").unwrap_or(t);
    t.starts_with("fn ")
}

fn fn_name(line: &str) -> String {
    let after = &line[line.find("fn ").expect("a fn declaration") + 3..];
    after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// Whether a line holds an evidence INSERT (either schema spelling).
fn inserts_evidence(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    let Some(at) = l.find("insert into ") else {
        return false;
    };
    let rest = l[at + "insert into ".len()..].trim_start();
    let rest = rest.strip_prefix("public.").unwrap_or(rest);
    rest.starts_with("evidence ") || rest.starts_with("evidence(") || rest == "evidence"
}

/// One Rust function holding an evidence INSERT: (file, fn, calls the helper).
#[derive(Debug)]
struct RustSite {
    file: String,
    func: String,
    calls_helper: bool,
}

fn scan_rust(src: &str, file: &str) -> Vec<RustSite> {
    let lines: Vec<&str> = src.lines().collect();
    // Cut the file at its first `#[cfg(test)]` (the in-crate test module).
    let end = lines
        .iter()
        .position(|l| l.trim_start().starts_with("#[cfg(test)]"))
        .unwrap_or(lines.len());
    let decls: Vec<usize> = (0..end).filter(|&i| is_fn_decl(lines[i])).collect();
    let mut by_fn: BTreeMap<usize, RustSite> = BTreeMap::new();
    for i in 0..end {
        let code = lines[i].trim_start();
        if code.starts_with("//") || !inserts_evidence(lines[i]) {
            continue;
        }
        let Some(&decl) = decls.iter().rev().find(|&&d| d <= i) else {
            continue;
        };
        let next = decls.iter().find(|&&d| d > decl).copied().unwrap_or(end);
        let body = lines[decl..next].join("\n");
        by_fn.entry(decl).or_insert_with(|| RustSite {
            file: file.to_string(),
            func: fn_name(lines[decl]),
            calls_helper: body.contains("link_to_claims_signed_conn("),
        });
    }
    by_fn.into_values().collect()
}

/// The live body of every SQL function, by name, in migration order.
fn sql_function_bodies(migrations: &Path) -> BTreeMap<String, (String, String)> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(migrations)
        .expect("migrations dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();
    let mut live = BTreeMap::new();
    for f in files {
        let text = std::fs::read_to_string(&f).expect("read migration");
        let name_of_file = f.file_name().unwrap().to_string_lossy().to_string();
        let lower = text.to_ascii_lowercase();
        let mut at = 0;
        while let Some(off) = lower[at..].find("function ") {
            let start = at + off;
            at = start + "function ".len();
            let head = lower[..start].trim_end();
            if !(head.ends_with("create") || head.ends_with("or replace")) {
                continue;
            }
            let name: String = lower[at..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
                .collect();
            let name = name.trim_start_matches("public.").to_string();
            // The dollar-quoted body.
            let Some(as_off) = lower[at..].find("as $") else {
                continue;
            };
            let tag_start = at + as_off + 3;
            let Some(tag_len) = lower[tag_start + 1..].find('$') else {
                continue;
            };
            let tag = &lower[tag_start..tag_start + tag_len + 2];
            let body_start = tag_start + tag.len();
            let Some(body_len) = lower[body_start..].find(tag) else {
                continue;
            };
            let body: String = lower[body_start..body_start + body_len]
                .lines()
                .map(|l| l.split("--").next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n");
            live.insert(name, (name_of_file.clone(), body));
            at = body_start + body_len;
        }
    }
    live
}

fn sql_inserts_into(body: &str, table: &str) -> bool {
    body.lines().any(|l| {
        let l = l.trim();
        l.contains(&format!("insert into public.{table} "))
            || l.contains(&format!("insert into public.{table}("))
            || l.contains(&format!("insert into {table} "))
            || l.contains(&format!("insert into {table}("))
    })
}

#[test]
fn every_rust_evidence_insert_writes_the_claim_edge() {
    let root = workspace_root();
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    let mut sites = Vec::new();
    for f in files {
        let rel = f.strip_prefix(&root).unwrap().to_string_lossy().to_string();
        if !rel.contains("/src/") {
            continue;
        }
        let src = std::fs::read_to_string(&f).expect("read source");
        sites.extend(scan_rust(&src, &rel));
    }
    // The inventory: the repository's three inserts (create_with_source_url,
    // record_derivation_conn, batch_create) and the packet route's.
    assert!(
        sites.len() >= 4,
        "the scanner found {} evidence-inserting functions; it has stopped seeing the \
         known writers: {sites:#?}",
        sites.len()
    );
    let missing: Vec<String> = sites
        .iter()
        .filter(|s| !s.calls_helper)
        .map(|s| format!("{}::{}", s.file, s.func))
        .collect();
    assert!(
        missing.is_empty(),
        "these functions INSERT evidence without writing its edge to its claim through \
         EvidenceRepository::link_to_claims_signed_conn in the same function (backlog 2d60f619): \
         {missing:?}"
    );
}

#[test]
fn every_sql_evidence_writer_writes_the_claim_edge() {
    let root = workspace_root();
    let live = sql_function_bodies(&root.join("migrations"));
    let writers: Vec<(&String, &(String, String))> = live
        .iter()
        .filter(|(_, (_, body))| sql_inserts_into(body, "evidence"))
        .collect();
    assert!(
        !writers.is_empty(),
        "the scanner found no SQL evidence writer; the bug-report intake is one"
    );
    let missing: Vec<String> = writers
        .iter()
        .filter(|(_, (_, body))| !sql_inserts_into(body, "edges"))
        .map(|(name, (file, _))| format!("{file}::{name}"))
        .collect();
    assert!(
        missing.is_empty(),
        "these SQL functions INSERT evidence without its evidence -> claim edge \
         (backlog 2d60f619): {missing:?}"
    );
}

#[test]
fn the_scanner_sees_a_writer_and_its_helper_call() {
    let src = "\
impl X {
    pub async fn good(conn: &mut PgConnection) {
        sqlx::query(\"INSERT INTO evidence (id) VALUES ($1)\");
        Self::link_to_claims_signed_conn(conn, None, id, &[c], d).await;
    }
    async fn bad() {
        sqlx::query(\"INSERT INTO public.evidence (id) VALUES ($1)\");
    }
    fn reads() {
        sqlx::query(\"SELECT 1 FROM evidence_encryption\");
        sqlx::query(\"INSERT INTO evidence_encryption (id) VALUES ($1)\");
    }
}
#[cfg(test)]
mod tests {
    fn seeds() { sqlx::query(\"INSERT INTO evidence (id) VALUES (1)\"); }
}
";
    let sites = scan_rust(src, "x.rs");
    let got: Vec<(String, bool)> = sites
        .iter()
        .map(|s| (s.func.clone(), s.calls_helper))
        .collect();
    assert_eq!(
        got,
        vec![("good".to_string(), true), ("bad".to_string(), false)],
        "a writer with the helper, a writer without it; not evidence_encryption, not a test"
    );
}
