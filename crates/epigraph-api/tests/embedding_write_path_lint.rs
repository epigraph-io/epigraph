//! **No `epigraph-api` source file writes a vector column itself, or builds
//! a pgvector literal itself.**
//!
//! # Why this file exists (deferred-commitment key `embed-on-write-helper`)
//!
//! `docs/superpowers/plans/2026-05-18-embedding-pipeline-fix.md` follow-up #3
//! deferred lifting the inline embed-on-create block into one shared helper.
//! By the time it was picked up, the block had been copied into six route
//! files as eight raw statements (`UPDATE claims|evidence SET embedding =
//! $1::vector WHERE id = $2`). Every copy skipped the seal predicate that
//! `ClaimRepository::store_embedding` carries, and two of them were
//! reachable by any bearer for any id. They now go through
//! `ClaimRepository::store_embedding_vec{,_if_unsealed}` and
//! `EvidenceRepository::store_embedding_vec{,_if_unsealed}`.
//!
//! `viewer_route_table_lint.rs::ROUTE_LAYER_WRITES` counts route-layer writes
//! per FILE, so a new embedding write could hide behind an unrelated
//! conversion elsewhere in the same file. This lint names the property
//! directly. No source under `crates/epigraph-api/src` may assign
//! `embedding` or `embedding_3072`. The repo helpers are the only writers,
//! and the seal and write predicates live there.
//!
//! # One formatter
//!
//! The pgvector literal (`[v1,v2,...]`) had eight private copies in this
//! crate (`format_embedding` in five route files, `format_embedding_for_pgvector`
//! in two, `format_pgvector` in `embedding_restore.rs`) plus seven inline
//! `format!("[{}]", ….join(","))` blocks. All of them are now
//! `epigraph_db::format_pgvector`, the function the repo helpers call.
//! [`no_api_source_builds_a_pgvector_literal`] keeps it that way. It is a
//! HEURISTIC: it catches the `"[{…}]"` + `join(",")` shape every copy used and
//! any `fn` named like a formatter. A hand-rolled push loop under another name
//! would pass it.
//!
//! # What it deliberately does not catch
//!
//! An INSERT that names `embedding` in its column list is not an assignment.
//! `routes/hypothesis.rs::create_hypothesis` inserts a claim with its vector in
//! one statement. That is route-layer INSERT debt of a different shape (a
//! create with no caller-supplied id, so no seal or write predicate applies),
//! and it is outside this lint.

use std::path::{Path, PathBuf};

fn src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir").flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Source text lowercased with every whitespace run collapsed to one space,
/// so a statement split across Rust string continuation lines reads as one.
fn normalise(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut in_ws = false;
    for c in src.chars() {
        if c.is_whitespace() {
            if !in_ws {
                out.push(' ');
            }
            in_ws = true;
        } else {
            out.push(c.to_ascii_lowercase());
            in_ws = false;
        }
    }
    out
}

/// Offsets of SQL assignments to a vector column: `embedding = $n`,
/// `embedding = null`, and the same for `embedding_3072`, with or without
/// spaces around `=`. A Rust `let embedding = …` binding does not match,
/// because what follows its `=` is never `$` or `null`.
fn vector_assignments(src: &str) -> Vec<usize> {
    let norm = normalise(src);
    let bytes = norm.as_bytes();
    let mut hits = Vec::new();
    for column in ["embedding_3072", "embedding"] {
        let mut from = 0usize;
        while let Some(rel) = norm[from..].find(column) {
            let at = from + rel;
            from = at + column.len();
            let before_ok = at == 0 || {
                let b = bytes[at - 1];
                !(b.is_ascii_alphanumeric() || b == b'_')
            };
            let tail = &norm[at + column.len()..];
            // `embedding` must not match the prefix of `embedding_3072`; that
            // column has its own pass.
            if !before_ok
                || tail.starts_with('_')
                || tail.starts_with(|c: char| c.is_ascii_alphanumeric())
            {
                continue;
            }
            let tail = tail.trim_start();
            let Some(rhs) = tail.strip_prefix('=') else {
                continue;
            };
            if rhs.starts_with('=') {
                continue; // `==`
            }
            let rhs = rhs.trim_start();
            if rhs.starts_with('$') || rhs.starts_with("null") {
                hits.push(at);
            }
        }
    }
    hits
}

#[test]
fn no_api_source_assigns_a_vector_column() {
    let mut files = Vec::new();
    collect(&src_root(), &mut files);
    assert!(
        files.len() > 80,
        "expected >80 .rs files under crates/epigraph-api/src; found {}. The \
         scan is probably looking in the wrong place.",
        files.len()
    );

    let mut offenders = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).expect("read source");
        let n = vector_assignments(&src).len();
        if n > 0 {
            offenders.push(format!(
                "  {} ({n})",
                f.strip_prefix(src_root()).unwrap_or(f).display()
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "\n\nA source file under crates/epigraph-api/src writes `embedding` or \
         `embedding_3072` itself:\n{}\n\n\
         Write the vector through the repo layer instead:\n\
         * a row this request just inserted: `ClaimRepository::store_embedding_vec` \
           / `EvidenceRepository::store_embedding_vec` (seal-guarded);\n\
         * an id the caller supplied (a path parameter, a row loaded by id): \
           `..::store_embedding_vec_if_unsealed` with the caller's `Viewer`, \
           which adds the WRITABLE predicate and maps to one 404.\n\
         Both format the pgvector literal themselves. See CLAUDE.md \"Embedding \
         policy\" and deferred-commitment key embed-on-write-helper.\n",
        offenders.join("\n")
    );
}

/// Offsets of a pgvector-literal builder: a `.join(",")` with a `"[{` format
/// string within 400 normalised bytes before it or 200 after it, or a `fn`
/// whose name marks it as a vector formatter.
fn pgvector_literal_builders(src: &str) -> Vec<usize> {
    let norm = normalise(src);
    let mut hits = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = norm[from..].find(".join(\",\")") {
        let at = from + rel;
        from = at + 1;
        // Both directions: the inline blocks put `"[{}]"` BEFORE the join,
        // `embedding_restore.rs`'s copy joined into `body` first and wrapped
        // it with `format!("[{body}]")` after.
        let mut lo = at.saturating_sub(400);
        while !norm.is_char_boundary(lo) {
            lo -= 1;
        }
        let mut hi = (at + 200).min(norm.len());
        while !norm.is_char_boundary(hi) {
            hi += 1;
        }
        if norm[lo..hi].contains("\"[{") {
            hits.push(at);
        }
    }
    for prefix in [
        "fn format_embedding",
        "fn format_pgvector",
        "fn format_as_pgvector",
    ] {
        let mut from = 0usize;
        while let Some(rel) = norm[from..].find(prefix) {
            hits.push(from + rel);
            from += rel + prefix.len();
        }
    }
    hits.sort_unstable();
    hits.dedup();
    hits
}

#[test]
fn no_api_source_builds_a_pgvector_literal() {
    let mut files = Vec::new();
    collect(&src_root(), &mut files);
    assert!(
        files.len() > 80,
        "the scan found only {} files",
        files.len()
    );

    let mut offenders = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).expect("read source");
        let n = pgvector_literal_builders(&src).len();
        if n > 0 {
            offenders.push(format!(
                "  {} ({n})",
                f.strip_prefix(src_root()).unwrap_or(f).display()
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "\n\nA source file under crates/epigraph-api/src builds a pgvector literal \
         itself:\n{}\n\n\
         Call `epigraph_db::format_pgvector(&vec)` for a read, or hand the \
         `&[f32]` to a repo helper that formats it for a write. One formatter is \
         the point of deferred-commitment key embed-on-write-helper.\n",
        offenders.join("\n")
    );
}

#[test]
fn the_pgvector_literal_scanner_is_not_vacuous() {
    for builder in [
        // The shape of the seven inline blocks.
        "let s = format!(\n    \"[{}]\",\n    v.iter()\n        .map(|x| x.to_string())\n        .collect::<Vec<_>>()\n        .join(\",\")\n);",
        // `embedding_restore.rs`'s named-argument spelling.
        "let body = v.iter().map(ToString::to_string).collect::<Vec<_>>().join(\",\");\nformat!(\"[{body}]\")",
        // A private formatter, whatever its body.
        "fn format_embedding(embedding: &[f32]) -> String { todo!() }",
        "fn format_pgvector(v: &[f32]) -> String { todo!() }",
    ] {
        assert!(
            !pgvector_literal_builders(builder).is_empty(),
            "the scanner must see a pgvector literal builder in: {builder}"
        );
    }
    for not_a_builder in [
        "let s = epigraph_db::format_pgvector(&v);",
        "let csv = names.join(\",\");",
        "let labels = format!(\"{{{}}}\", xs.join(\";\"));",
    ] {
        assert!(
            pgvector_literal_builders(not_a_builder).is_empty(),
            "the scanner must not charge: {not_a_builder}"
        );
    }
}

/// The scanner, over synthetic source. Without it, a scanner that matches
/// nothing would pass the test above over any tree.
#[test]
fn the_vector_assignment_scanner_is_not_vacuous() {
    // Every spelling the eight removed statements used, and the neighbours
    // CLAUDE.md's cleanup paths use.
    for sql in [
        r#"sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2")"#,
        r#"sqlx::query("UPDATE evidence SET embedding=$1::vector WHERE id = $2")"#,
        "\"UPDATE claims AS c SET embedding = $2::vector \\\n  WHERE c.id = $1\"",
        r#""UPDATE claims SET is_current = false, embedding = NULL WHERE id = $1""#,
        r#""UPDATE evidence SET embedding_3072 = $1::vector WHERE id = $2""#,
    ] {
        assert_eq!(
            vector_assignments(sql).len(),
            1,
            "the scanner must see exactly one vector assignment in: {sql}"
        );
    }

    // Things that are not a write of the column.
    for not_a_write in [
        "let embedding =\n    generate(&text).await?;",
        "let query_embedding = embedder.generate(q).await?;",
        "if embedding == other { }",
        r#""SELECT 1 - (embedding <=> $1::vector) FROM claims""#,
        r#""INSERT INTO claims (content, embedding) VALUES ($1, $2::vector)""#,
        r#""WHERE embedding IS NOT NULL""#,
        "let embedding_dim = embedding.len();",
    ] {
        assert!(
            vector_assignments(not_a_write).is_empty(),
            "the scanner must not charge: {not_a_write}"
        );
    }
}
