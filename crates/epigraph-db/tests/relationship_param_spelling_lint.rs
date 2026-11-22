//! No repository function compares a CALLER-SUPPLIED relationship
//! byte-exactly (backlog 5ff9c9d9; the defect class of backlog 3ce5e00c).
//!
//! `edges.relationship` stores the case-folded relationships
//! (`epigraph_core::edge::relationships::CASE_FOLDED_RELATIONSHIPS`) in two
//! spellings until the operator case-fold runs, so a reader that takes a
//! `relationship: &str` and binds it to `relationship = $N` silently drops the
//! rows stored in the other spelling. Every such reader matches
//! `= ANY($N)` over `relationship_spellings(..)` instead.
//! `EdgeRepository::get_current_edges` was the last one; it had no caller and
//! was removed rather than converted.
//!
//! Static, no database: every `fn` under `crates/epigraph-db/src` whose
//! signature takes a parameter named `relationship` and whose body (comments
//! stripped) contains a `relationship = $<n>` comparison must also call
//! `relationship_spellings`. A function that binds a constant such as
//! `DUPLICATE_IDENTITY_RELATIONSHIP` (`same_as`, not case-folded) takes no
//! `relationship` parameter and is out of scope by construction.

use std::path::{Path, PathBuf};

/// One function: its name, its signature (up to the line that opens the
/// body) and its body with `//` comment lines removed.
struct Function {
    name: String,
    signature: String,
    body: String,
}

/// Split Rust source into functions at every line whose first token after
/// visibility / `async` / `const` / `unsafe` qualifiers is `fn`. Text between
/// two such lines belongs to the first; doc comments of the next function are
/// stripped with every other comment line, so they cannot be misattributed.
fn functions(src: &str) -> Vec<Function> {
    let lines: Vec<&str> = src.lines().collect();
    let starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| fn_name(l).is_some())
        .map(|(i, _)| i)
        .collect();
    let mut out = Vec::new();
    for (k, &start) in starts.iter().enumerate() {
        let end = starts.get(k + 1).copied().unwrap_or(lines.len());
        let chunk = &lines[start..end];
        let open = chunk
            .iter()
            .position(|l| {
                let t = l.trim_end();
                t.ends_with('{') || t.ends_with(';')
            })
            .unwrap_or(0);
        let signature = chunk[..=open].join("\n");
        let body = chunk[open + 1..]
            .iter()
            .filter(|l| !l.trim_start().starts_with("//"))
            .copied()
            .collect::<Vec<_>>()
            .join("\n");
        out.push(Function {
            name: fn_name(lines[start]).unwrap_or_default(),
            signature,
            body,
        });
    }
    out
}

/// The function name declared on `line`, if the line declares one.
fn fn_name(line: &str) -> Option<String> {
    let mut rest = line.trim_start();
    loop {
        let before = rest;
        for q in [
            "pub(crate) ",
            "pub(super) ",
            "pub ",
            "async ",
            "const ",
            "unsafe ",
        ] {
            if let Some(r) = rest.strip_prefix(q) {
                rest = r;
            }
        }
        if rest == before {
            break;
        }
    }
    let r = rest.strip_prefix("fn ")?;
    let name: String = r
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// Does the signature take a parameter named exactly `relationship`?
fn takes_relationship_param(signature: &str) -> bool {
    signature.match_indices("relationship:").any(|(i, _)| {
        signature[..i]
            .chars()
            .last()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
    })
}

/// Does `body` compare a column named `relationship` to a placeholder with
/// `=` (not `!=`, `<=`, `>=`)? `old_relationship = $1` does not count.
fn byte_exact_placeholder_compare(body: &str) -> bool {
    body.match_indices("relationship").any(|(i, m)| {
        let prev_ok = body[..i]
            .chars()
            .last()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        let after = body[i + m.len()..].trim_start();
        let Some(after_eq) = after.strip_prefix('=') else {
            return false;
        };
        let after_eq = after_eq.trim_start();
        prev_ok
            && after_eq.starts_with('$')
            && after_eq[1..].starts_with(|c: char| c.is_ascii_digit())
    })
}

/// The functions in `src` that take a relationship and match it byte-exactly.
fn offenders(src: &str) -> Vec<String> {
    functions(src)
        .into_iter()
        .filter(|f| {
            takes_relationship_param(&f.signature)
                && byte_exact_placeholder_compare(&f.body)
                && !f.body.contains("relationship_spellings")
        })
        .map(|f| f.name)
        .collect()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_repo_function_matches_a_relationship_parameter_byte_exactly() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files.sort();
    assert!(
        files.iter().any(|p| p.ends_with("repos/edge.rs")),
        "CALIBRATION: the scan must reach repos/edge.rs"
    );

    let mut found = Vec::new();
    let mut readers_seen = 0usize;
    for path in &files {
        let src = std::fs::read_to_string(path).expect("read source");
        readers_seen += functions(&src)
            .iter()
            .filter(|f| {
                takes_relationship_param(&f.signature) && f.body.contains("relationship_spellings")
            })
            .count();
        for name in offenders(&src) {
            found.push(format!(
                "{}::{name}",
                path.strip_prefix(&root).unwrap_or(path).display()
            ));
        }
    }
    assert!(
        readers_seen >= 3,
        "CALIBRATION: the scan must see the spelling-aware readers that take a \
         relationship (found {readers_seen}); if it sees none it is not parsing \
         signatures and every check below is vacuous"
    );
    assert!(
        found.is_empty(),
        "these functions take a `relationship` and compare it with `relationship = $N`, \
         which misses rows stored in the other spelling of a case-folded relationship; \
         bind `relationship_spellings(relationship)` to `= ANY($N)` instead:\n  {}",
        found.join("\n  ")
    );
}

/// The detector itself: the removed `get_current_edges` shape is flagged, the
/// spelling-aware shape and a constant-bound `same_as` reader are not.
#[test]
fn the_detector_flags_the_removed_shape_and_only_it() {
    let removed = r#"
    pub async fn get_current_edges<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        entity_id: Uuid,
        relationship: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        // AND relationship = $2 in a comment does not count on its own
        let rows = sqlx::query!(
            "SELECT id FROM edges WHERE source_id = $1 AND relationship = $2",
            entity_id,
            relationship,
        );
    }
    "#;
    assert_eq!(offenders(removed), vec!["get_current_edges".to_string()]);

    let spelling_aware = r#"
    pub async fn get_by_relationship(
        executor: E,
        relationship: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        let q = sqlx::query("SELECT id FROM edges WHERE relationship = ANY($1)")
            .bind(relationship_spellings(relationship));
    }
    "#;
    assert!(offenders(spelling_aware).is_empty());

    let constant_bound = r#"
    pub async fn marked_duplicates_of(executor: E, claim: Uuid) -> Result<Vec<Uuid>, DbError> {
        let q = sqlx::query("SELECT 1 FROM edges e WHERE e.relationship = $2")
            .bind(claim)
            .bind(DUPLICATE_IDENTITY_RELATIONSHIP);
    }
    "#;
    assert!(offenders(constant_bound).is_empty());

    let comment_only = r#"
    pub fn doc(relationship: &str) -> bool {
        // compared `relationship = $2` byte-exactly, once
        relationship.is_empty()
    }
    "#;
    assert!(offenders(comment_only).is_empty());

    let not_equal = r#"
    pub fn other(relationship: &str) {
        let s = "WHERE old_relationship = $1 AND relationship != $2";
    }
    "#;
    assert!(offenders(not_equal).is_empty());
}
