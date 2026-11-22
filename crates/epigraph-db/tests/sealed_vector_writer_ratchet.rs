//! Every statement under `crates/*/src` that writes a non-NULL vector into
//! `embedding` / `embedding_3072` must (a) carry the not-sealed predicate in
//! the statement and (b) lock the row in an EARLIER statement of the same
//! function (backlog f9807254).
//!
//! # Why both halves
//!
//! Migration 212's `BEFORE UPDATE OF embedding, embedding_3072` triggers on
//! `claims` and `evidence` raise 42501 per row when a non-NULL vector lands on
//! a row with its own encryption row. A raise aborts the whole statement and,
//! in every batch job built on these writers (`reembed`, `embed_backfill`),
//! the run or the row. So the trigger is a backstop; the writers must never
//! reach it:
//!
//! * (a) `NOT EXISTS (… claim_encryption / evidence_encryption …)` in the
//!   UPDATE filters a row sealed BEFORE the statement started.
//! * (b) The predicate does NOT see a seal that commits while the UPDATE waits
//!   on the row lock the seal's own blanking UPDATE holds: READ COMMITTED
//!   re-checks the qual on the new row version against the statement's
//!   original snapshot for the encryption table, and the trigger (fresh
//!   snapshot) raises. A `SELECT … FOR UPDATE` in a separate, earlier statement
//!   makes the guarded UPDATE take a snapshot that includes that seal.
//!   Pinned at runtime by `claim_store_embedding_seal_race.rs`,
//!   `evidence_embedding_seal_race.rs` and
//!   `epigraph-cli/tests/reembed_concurrent_seal.rs`.
//!
//! A future multi-row writer (`UPDATE … FROM unnest(…)`) needs the same two
//! halves: the predicate inside the UPDATE, and the rows locked first in one
//! statement (`WHERE id = ANY($1) ORDER BY id FOR UPDATE`, ordered so two
//! writers cannot deadlock).
//!
//! # What the scanner counts as a vector write
//!
//! A non-comment line with `embedding` or `embedding_3072` (word-bounded, so
//! `goal_embedding` is out: 212 does not cover it) assigned something other
//! than `NULL` (the seal's own nulling is the admitted shape), where the line
//! is SQL-shaped: a `SET ` precedes the assignment, or the right-hand side is a
//! bind (`$n`), a `::vector` cast, or a qualified column (`d.v`,
//! `EXCLUDED.embedding`: the second assignment of a multi-row
//! `UPDATE … FROM unnest(…)`, or an upsert's `DO UPDATE`, on which the trigger
//! fires too) on a line that is not a Rust `let` or statement.
//!
//! Only writes into `claims` or `evidence` count (the tables 212 guards): the
//! nearest `UPDATE <t>` / `INSERT INTO <t>` above the assignment names the
//! target, and a spliced `{table}` (reembed) or no visible target at all counts
//! conservatively. `entities.embedding` (never sealed) is therefore out.
//!
//! The enclosing function is the nearest preceding `fn` declaration; it ends
//! at the next one. The calibration test pins that the four writers on this
//! tree are all found, so a scanner that went blind fails rather than passes.

use std::path::{Path, PathBuf};

#[derive(Debug)]
struct Writer {
    /// `crate/src/…/file.rs::function`
    site: String,
    has_predicate: bool,
    locks_first: bool,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

/// The name declared by a `fn` on this line, if any.
fn fn_name(line: &str) -> Option<&str> {
    if is_comment(line) {
        return None;
    }
    let at = line.find("fn ")?;
    if at > 0 {
        let prev = line.as_bytes()[at - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' {
            return None;
        }
    }
    let rest = &line[at + 3..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let name = &rest[..end];
    let after = rest[end..].trim_start();
    (!name.is_empty() && (after.starts_with('(') || after.starts_with('<'))).then_some(name)
}

/// Whether `line` assigns a non-NULL value to a vector column in SQL.
fn writes_vector(line: &str) -> bool {
    if is_comment(line) {
        return false;
    }
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(off) = line[from..].find("embedding") {
        let at = from + off;
        from = at + "embedding".len();
        if at > 0 {
            let prev = bytes[at - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'.' {
                continue;
            }
        }
        let mut rest = &line[from..];
        if let Some(r) = rest.strip_prefix("_3072") {
            rest = r;
        }
        if rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let rest = rest.trim_start();
        let Some(rhs) = rest.strip_prefix('=') else {
            continue;
        };
        if rhs.starts_with('=') {
            continue;
        }
        let rhs = rhs.trim_start();
        if rhs.to_ascii_uppercase().starts_with("NULL") {
            continue;
        }
        let sql_shaped = line[..at].contains("SET ")
            || rhs.starts_with('$')
            || rhs.contains("::vector")
            || (qualified_column(rhs) && !line.contains("let ") && !rust_statement(line, rhs));
        if sql_shaped {
            return true;
        }
    }
    false
}

/// A Rust assignment statement (`embedding = other.field;`), not SQL text: it
/// ends in `;` and the line holds no string delimiter.
fn rust_statement(line: &str, rhs: &str) -> bool {
    rhs.trim_end().ends_with(';') && !line.contains('"')
}

/// `ident.ident` at the start of `rhs` (`d.v`, `EXCLUDED.embedding`).
fn qualified_column(rhs: &str) -> bool {
    let ident = |s: &str| {
        let n = s
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(s.len());
        let first_ok = s
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        (first_ok && n > 0).then_some(n)
    };
    let Some(n) = ident(rhs) else { return false };
    rhs[n..].strip_prefix('.').and_then(ident).is_some()
}

/// The table the statement around line `i` writes, from the nearest
/// `UPDATE <t>` / `INSERT INTO <t>` at or above it within the function. An
/// upsert's `DO UPDATE SET` names no table, so it is passed over in favour of
/// the `INSERT INTO` above it.
fn target_table(lines: &[&str], start: usize, i: usize) -> Option<String> {
    for j in (start..=i).rev() {
        let line = lines[j];
        if is_comment(line) {
            continue;
        }
        let upper = line.to_ascii_uppercase();
        let mut best: Option<(usize, String)> = None;
        for kw in ["INSERT INTO ", "UPDATE "] {
            for (pos, _) in upper.match_indices(kw) {
                let rest = line[pos + kw.len()..].trim_start();
                let rest = rest.strip_prefix("public.").unwrap_or(rest);
                let end = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '{' | '}')))
                    .unwrap_or(rest.len());
                let name = &rest[..end];
                if name.is_empty() || name.eq_ignore_ascii_case("SET") {
                    continue;
                }
                if best.as_ref().is_none_or(|(p, _)| pos > *p) {
                    best = Some((pos, name.to_string()));
                }
            }
        }
        if let Some((_, name)) = best {
            return Some(name);
        }
    }
    None
}

fn scan_source(label: &str, text: &str) -> Vec<Writer> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !writes_vector(line) {
            continue;
        }
        let start = (0..=i).rev().find(|&j| fn_name(lines[j]).is_some());
        let name = start
            .and_then(|j| fn_name(lines[j]))
            .unwrap_or("<top level>");
        let start = start.unwrap_or(0);
        let table = target_table(&lines, start, i);
        let key = match table.as_deref() {
            Some("claims") => Some("claim_encryption"),
            Some("evidence") => Some("evidence_encryption"),
            // Spliced (`{table}`) or not visible: count it, key either way.
            Some(t) if t.starts_with('{') => None,
            None => None,
            // Another table (`entities`, `workflows`, …): 212 does not guard it.
            Some(_) => continue,
        };
        let end = (i + 1..lines.len())
            .find(|&j| fn_name(lines[j]).is_some())
            .unwrap_or(lines.len());
        let code = |a: usize, b: usize| {
            lines[a..b]
                .iter()
                .filter(|l| !is_comment(l))
                .copied()
                .collect::<Vec<_>>()
                .join("\n")
        };
        let body = code(start, end);
        let before = code(start, i);
        let literal = body.contains("NOT EXISTS")
            && match key {
                Some(k) => body.contains(k),
                None => body.contains("claim_encryption") || body.contains("evidence_encryption"),
            };
        // `reembed` splices its per-table `sealed_predicate()` as `NOT {sealed}`.
        let spliced = body.contains("sealed_predicate()") && body.contains("NOT {sealed}");
        out.push(Writer {
            site: format!("{label}::{name}"),
            has_predicate: literal || spliced,
            locks_first: before.contains("FOR UPDATE"),
        });
    }
    out
}

fn scan_tree() -> Vec<Writer> {
    let root = workspace_root();
    let mut files = Vec::new();
    for krate in std::fs::read_dir(root.join("crates"))
        .expect("crates/")
        .flatten()
    {
        rust_files(&krate.path().join("src"), &mut files);
    }
    files.sort();
    let mut out = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read source");
        let label = file
            .strip_prefix(root.join("crates"))
            .unwrap_or(&file)
            .display()
            .to_string();
        out.extend(scan_source(&label, &text));
    }
    out
}

#[test]
fn every_vector_writer_filters_sealed_rows_and_locks_the_row_first() {
    let writers = scan_tree();

    // CALIBRATION: the writers on this tree are all found, so the scanner has
    // not gone blind (a blind scanner would pass the assertions below).
    for known in [
        "epigraph-db/src/repos/claim.rs::store_embedding",
        "epigraph-db/src/repos/claim.rs::store_embedding_if_unsealed",
        "epigraph-db/src/repos/evidence.rs::store_embedding_as",
        "epigraph-cli/src/reembed.rs::update_embedding_3072",
    ] {
        assert!(
            writers.iter().any(|w| w.site == known),
            "calibration: the scanner no longer finds {known}; found {writers:#?}"
        );
    }

    let unguarded: Vec<&str> = writers
        .iter()
        .filter(|w| !w.has_predicate)
        .map(|w| w.site.as_str())
        .collect();
    assert!(
        unguarded.is_empty(),
        "vector writers without the not-sealed `NOT EXISTS (… _encryption …)` predicate \
         in the statement (migration 212's trigger would abort them on a sealed row): \
         {unguarded:#?}"
    );

    let unlocked: Vec<&str> = writers
        .iter()
        .filter(|w| !w.locks_first)
        .map(|w| w.site.as_str())
        .collect();
    assert!(
        unlocked.is_empty(),
        "vector writers that do not take the row lock (`SELECT … FOR UPDATE`) in an earlier \
         statement, so a seal committing while the UPDATE waits reaches migration 212's \
         trigger and aborts it: {unlocked:#?}"
    );
}

/// The scanner itself, on shapes it must and must not flag.
#[test]
fn the_scanner_flags_an_unguarded_or_unlocked_writer_and_ignores_the_rest() {
    let src = r#"
/// `UPDATE claims SET embedding = $1` in a doc comment is not a writer.
async fn bare(pool: &PgPool) {
    sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2");
}
async fn predicate_only(pool: &PgPool) {
    sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2 \
                 AND NOT EXISTS (SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = claims.id)");
}
async fn wrong_table_key(pool: &PgPool) {
    sqlx::query("SELECT 1 FROM evidence WHERE id = $1 FOR UPDATE");
    sqlx::query("UPDATE evidence SET embedding = $1::vector WHERE id = $2 \
                 AND NOT EXISTS (SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = evidence.claim_id)");
}
async fn guarded(pool: &PgPool) {
    sqlx::query("SELECT 1 FROM claims WHERE id = $1 FOR UPDATE");
    sqlx::query("UPDATE claims SET embedding_3072 = $1::vector WHERE id = $2 \
                 AND NOT EXISTS (SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = claims.id)");
}
async fn multi_row_unguarded(pool: &PgPool) {
    sqlx::query("UPDATE claims AS c SET \
                 embedding = v.vec::vector FROM unnest($1::uuid[], $2::text[]) AS v(id, vec)");
}
async fn multi_row_second_assignment(pool: &PgPool) {
    sqlx::query("UPDATE claims AS c \
                 SET labels = d.l, \
                     embedding = d.v \
                 FROM unnest($1::uuid[], $2::vector[], $3::text[]) AS d(id, v, l) \
                 WHERE c.id = d.id");
}
async fn evidence_upsert(pool: &PgPool) {
    sqlx::query("INSERT INTO evidence (id, embedding) VALUES ($1, $2::vector) \
                 ON CONFLICT (id) DO UPDATE SET \
                     embedding = EXCLUDED.embedding");
}
async fn entity_upsert(pool: &PgPool) {
    sqlx::query("INSERT INTO entities (canonical_name, embedding) VALUES ($1, $2::vector) \
                 ON CONFLICT DO UPDATE SET \
                     embedding = EXCLUDED.embedding");
}
async fn not_writers(pool: &PgPool) {
    sqlx::query("UPDATE claims SET embedding = NULL, embedding_3072 = NULL WHERE id = $1");
    sqlx::query("UPDATE workflows SET goal_embedding = $1::vector WHERE id = $2");
    let embedding = provider.generate(text).await;
    row.embedding = Some(embedding);
    embedding = other.field;
    if embedding == other {}
}
"#;
    let found = scan_source("x.rs", src);
    let get = |name: &str| {
        found
            .iter()
            .find(|w| w.site == format!("x.rs::{name}"))
            .unwrap_or_else(|| panic!("{name} not found in {found:#?}"))
    };
    assert_eq!(
        found.len(),
        7,
        "exactly the seven claims/evidence writer fns are vector writes: {found:#?}"
    );
    assert!(!get("bare").has_predicate && !get("bare").locks_first);
    assert!(get("predicate_only").has_predicate && !get("predicate_only").locks_first);
    assert!(
        !get("wrong_table_key").has_predicate,
        "an evidence writer keyed on claim_encryption is not guarded"
    );
    assert!(get("guarded").has_predicate && get("guarded").locks_first);
    assert!(!get("multi_row_unguarded").has_predicate);
    assert!(
        !get("multi_row_second_assignment").has_predicate,
        "a vector that is not the first assignment of a multi-row UPDATE is found"
    );
    assert!(
        !get("evidence_upsert").has_predicate && !get("evidence_upsert").locks_first,
        "an upsert's DO UPDATE onto evidence is a vector write the trigger fires on"
    );
    assert!(
        !found.iter().any(|w| w.site == "x.rs::entity_upsert"),
        "entities are not sealed and not guarded by 212"
    );
}
