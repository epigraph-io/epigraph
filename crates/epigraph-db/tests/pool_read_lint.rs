//! A repo function that takes a `&PgPool`, takes NO `Viewer`, and reads a
//! tenanted table is either a reviewed exemption or a fail-open.
//!
//! # The blind spot this closes
//!
//! The four tenancy ratchets each key on something a viewer-less pool read
//! does not carry:
//!
//! * `visibility_lint.rs::every_viewer_taking_repo_fn_that_runs_sql_spends_the_viewer`
//!   selects functions whose parameters mention `Viewer`;
//! * `visibility_lint.rs::every_conn_taking_repo_fn_takes_a_viewer_or_is_exempt`
//!   keys on `PgConnection`, and its executor twin on `PgExecutor`;
//! * the splice-marker lints key on `.splice(`;
//! * `no_unscoped_pool.rs` scans HANDLER call sites for `state.db_pool`, not
//!   the repo function a pool is passed into.
//!
//! So `pub async fn get_properties(pool: &PgPool, claim_id: ClaimId)` running
//! `SELECT ... FROM claims WHERE id = $1` passed all four until it was given a
//! `&Viewer` by hand. This file selects that shape directly: every `fn` under
//! `src/repos/` whose parameter list names `PgPool` (or `Pool<Postgres>`) and
//! not `Viewer`, and whose live SQL reads `FROM` / `JOIN` one of
//! [`TENANTED_TABLES`]. The selected set must equal [`POOL_WITHOUT_VIEWER`]
//! exactly, in both directions.
//!
//! # What the scan reads
//!
//! Each repo file is reduced to `lint_text::spend_views(..).1`, the LIVE-SQL
//! view: Rust comments removed (so a doc-test `fn example(pool: &PgPool)` is
//! not a declaration) and SQL comments removed from string literals (so a
//! table named only in `-- ...` does not count). `#[cfg(test)] mod` blocks are
//! then cut out: a unit test's fixture reading `claims` through the test pool
//! is not a request path. Table names match on word boundaries and case-
//! insensitively, with an optional `public.` qualifier.
//!
//! # Limits, stated so a green run is not read as more than it is
//!
//! * The root is `src/repos/` only, the same root the other repo lints scan.
//! * A statement assembled with `format!` from a helper that holds the table
//!   name is not seen unless the literal `FROM <table>` is in the function.
//! * A function generic over `sqlx::Acquire` or similar, which receives a pool
//!   without naming one, is outside this selector (the executor lint owns
//!   `PgExecutor`).
//! * Writes are selected too (`DELETE FROM claims`, `UPDATE ... FROM edges`).
//!   Every entry today IS a write, and each is registered with the reason it
//!   needs no viewer, so the register is the review record.
//! * [`TENANTED_TABLES`] names six tables: the claim graph's core (`claims`,
//!   `edges`, `evidence`, `mass_functions`, `reasoning_traces`,
//!   `claim_versions`). It is NOT the full tier-A list from migration 062
//!   (`triples`, `frames`, `perspectives`, `recall_events`, the `harvester_*`
//!   tables, and others carry tenancy too); a viewer-less pool read of one of
//!   those is not selected here.
//! * Only a pool named in the PARAMETER list is seen. A repo struct that holds
//!   its pool in a field and reads it through `&self` / `self.pool` is outside
//!   this selector.

mod lint_text;

use std::path::{Path, PathBuf};

/// The tenanted tables this lint covers: the claim graph's core, a SUBSET of
/// the tables whose rows carry tenancy (`owner_group_id` / `visibility`). See
/// the module's Limits section for what is not covered.
const TENANTED_TABLES: &[&str] = &[
    "claims",
    "edges",
    "evidence",
    "mass_functions",
    "reasoning_traces",
    "claim_versions",
];

/// Viewer-less `&PgPool` repo functions that touch a tenanted table, each with
/// the reviewed reason. Keyed on `(file, fn)`.
///
/// Do not add a READ here. A read gets a `&Viewer` parameter and a spliced
/// marker; this register is for statements that must not be narrowed by a
/// caller's visibility.
const POOL_WITHOUT_VIEWER: &[(&str, &str, &str)] = &[
    (
        "claim.rs",
        "delete",
        "WRITE. `DELETE FROM claims` gated by migration 115's owner-scoped DELETE policy; its \
         `SELECT 1 FROM claims` CTE only compares what the session saw with what it deleted, \
         to turn a silent refusal into WriteRefused, and returns no row content.",
    ),
    (
        "claim.rs",
        "inherit_evidence",
        "WRITE. Copies evidence links from a superseded claim onto its successor via \
         derived_from edges (`INSERT INTO edges ... FROM evidence`); carries an in-SQL \
         VISIBILITY-EXEMPT marker: the read is part of the mutation, not a disclosure.",
    ),
    (
        "claim.rs",
        "update_labels",
        "WRITE. Read-modify-write of `claims.labels` for one claim id under the write-side \
         predicate; the `SELECT ... FROM claims` CTE feeds the UPDATE and carries an in-SQL \
         VISIBILITY-EXEMPT marker; nothing it reads is returned to a caller.",
    ),
    (
        "edge.rs",
        "retract",
        "WRITE. Closes `valid_to` on the given edge ids (`UPDATE edges`); the `seen` CTE over \
         `FROM edges` exists only to detect migration 117's owner-scoped UPDATE refusing a row \
         and to report WriteRefused, returning edge ids the caller already supplied.",
    ),
    (
        "edge.rs",
        "retract_between",
        "WRITE. Retracts every in-force edge between two entities (`UPDATE edges`); the `seen` \
         CTE over `FROM edges` only counts what the session could see against what it closed, \
         so a policy refusal surfaces as WriteRefused. Returns counts, never row content.",
    ),
    (
        "mass_function.rs",
        "delete_for_claim",
        "WRITE. `DELETE FROM mass_functions` for one claim under migration 115's owner-scoped \
         DELETE; the `seen` CTE only detects a partial refusal so the claim's belief is never \
         combined from survivors. Returns a row count, never BBA content.",
    ),
];

fn repos_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/repos")
}

fn repo_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(repos_dir()).expect("read repos dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 file name")
            .to_string();
        out.push((
            name,
            std::fs::read_to_string(&path).expect("read repo file"),
        ));
    }
    out.sort();
    assert!(
        out.len() > 30,
        "expected the repos directory to hold the whole SQL surface, found {} files: the lint \
         is probably looking in the wrong place and would pass vacuously",
        out.len()
    );
    out
}

/// The balanced region starting at `src[start]`, which must be `open`.
///
/// Skips string literals (normal and raw) and line comments, so braces or
/// parens inside SQL text cannot unbalance the count. Copied from
/// `visibility_lint.rs::balanced`.
fn balanced(src: &str, start: usize, open: u8, close: u8) -> &str {
    let b = src.as_bytes();
    debug_assert_eq!(b[start], open);
    let n = src.len();
    let mut j = start;
    let mut depth = 0usize;
    while j < n {
        if b[j] == b'r' && j + 1 < n && (b[j + 1] == b'#' || b[j + 1] == b'"') {
            let mut k = j + 1;
            let mut hashes = 0usize;
            while k < n && b[k] == b'#' {
                hashes += 1;
                k += 1;
            }
            if k < n && b[k] == b'"' {
                let mut term = String::from('"');
                for _ in 0..hashes {
                    term.push('#');
                }
                j = match src[k + 1..].find(&term) {
                    Some(e) => k + 1 + e + term.len(),
                    None => n,
                };
                continue;
            }
        }
        match b[j] {
            b'"' => {
                let mut k = j + 1;
                while k < n {
                    if b[k] == b'\\' {
                        k += 2;
                        continue;
                    }
                    if b[k] == b'"' {
                        break;
                    }
                    k += 1;
                }
                j = k + 1;
                continue;
            }
            b'\'' if j + 2 < n && b[j + 2] == b'\'' => {
                j += 3;
                continue;
            }
            b'/' if j + 1 < n && b[j + 1] == b'/' => {
                j = src[j..].find('\n').map_or(n, |e| j + e + 1);
                continue;
            }
            c if c == open => depth += 1,
            c if c == close => {
                depth -= 1;
                if depth == 0 {
                    let mut e = j + 1;
                    while e < n && !src.is_char_boundary(e) {
                        e += 1;
                    }
                    return &src[start..e];
                }
            }
            _ => {}
        }
        j += 1;
    }
    &src[start..]
}

struct RepoFn {
    name: String,
    params: String,
    body: String,
}

/// Every `fn` declaration in `src`, with its parameter list and body. Adapted
/// from `visibility_lint.rs::repo_fns_in`.
fn repo_fns_in(src: &str) -> Vec<RepoFn> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find("fn ") {
        let at = from + rel;
        from = at + 3;
        if at > 0 {
            let prev = src.as_bytes()[at - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                continue;
            }
        }
        let after = &src[at + 3..];
        let name_end = after
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(after.len());
        if name_end == 0 {
            continue;
        }
        let name = after[..name_end].to_string();
        let mut cursor = at + 3 + name_end;
        if src[cursor..].trim_start().starts_with('<') {
            let lt = src[cursor..].find('<').expect("just matched") + cursor;
            cursor = lt + balanced(src, lt, b'<', b'>').len();
        }
        let Some(paren_rel) = src[cursor..].find('(') else {
            continue;
        };
        let paren = cursor + paren_rel;
        if !src[cursor..paren].trim().is_empty() {
            continue;
        }
        let params = balanced(src, paren, b'(', b')');
        let Some(brace_rel) = src[paren + params.len()..].find('{') else {
            continue;
        };
        let brace = paren + params.len() + brace_rel;
        out.push(RepoFn {
            name,
            params: params.to_string(),
            body: balanced(src, brace, b'{', b'}').to_string(),
        });
    }
    out
}

/// `src` with every `#[cfg(test)] mod <name> { ... }` block removed.
fn without_test_modules(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(at) = rest.find("#[cfg(test)]") {
        let after = rest[at + "#[cfg(test)]".len()..].trim_start();
        let is_mod = after.starts_with("mod ") || after.starts_with("pub mod ");
        let brace = rest[at..].find('{').map(|b| at + b);
        match (is_mod, brace) {
            (true, Some(b)) if !rest[at..b].contains(';') => {
                out.push_str(&rest[..at]);
                let block = balanced(rest, b, b'{', b'}');
                rest = &rest[b + block.len()..];
            }
            _ => {
                let skip = at + "#[cfg(test)]".len();
                out.push_str(&rest[..skip]);
                rest = &rest[skip..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The [`TENANTED_TABLES`] that `body` reads with `FROM` or `JOIN`.
fn tenanted_tables_read(body: &str) -> Vec<&'static str> {
    let low = body.to_ascii_lowercase();
    let b = low.as_bytes();
    let mut hits = Vec::new();
    for kw in ["from", "join"] {
        let mut from = 0usize;
        while let Some(rel) = low[from..].find(kw) {
            let at = from + rel;
            from = at + kw.len();
            if at > 0 && is_ident_byte(b[at - 1]) {
                continue;
            }
            let mut k = at + kw.len();
            if k >= b.len() || !b[k].is_ascii_whitespace() {
                continue;
            }
            while k < b.len() && b[k].is_ascii_whitespace() {
                k += 1;
            }
            if low[k..].starts_with("public.") {
                k += "public.".len();
            }
            let end = (k..b.len())
                .find(|&e| !is_ident_byte(b[e]))
                .unwrap_or(b.len());
            let ident = &low[k..end];
            if let Some(t) = TENANTED_TABLES.iter().find(|t| **t == ident) {
                if !hits.contains(t) {
                    hits.push(*t);
                }
            }
        }
    }
    hits
}

/// A parameter list naming a Postgres pool: `PgPool`, or `Pool<Postgres>` with
/// or without the `sqlx::` paths.
fn takes_a_pool(params: &str) -> bool {
    let flat: String = params.split_whitespace().collect();
    flat.contains("PgPool")
        || flat.contains("Pool<Postgres>")
        || flat.contains("Pool<sqlx::Postgres>")
        || flat.contains("Pool<sqlx::postgres::Postgres>")
}

/// THE SELECTOR, over one source file: the names of the functions that take a
/// pool, take no `Viewer`, and read a tenanted table. The full scan and every
/// fixture go through this one function, so a fixture is judged by exactly
/// the rule the real scan uses.
fn pool_reads_without_viewer_in(src: &str) -> Vec<String> {
    let (_code, live_sql) = lint_text::spend_views(src);
    let scanned = without_test_modules(&live_sql);
    repo_fns_in(&scanned)
        .into_iter()
        .filter(|f| {
            takes_a_pool(&f.params)
                && !f.params.contains("Viewer")
                && !tenanted_tables_read(&f.body).is_empty()
        })
        .map(|f| f.name)
        .collect()
}

#[test]
fn every_pool_taking_repo_fn_reading_a_tenanted_table_takes_a_viewer_or_is_exempt() {
    let mut found: Vec<(String, String)> = Vec::new();
    let mut pool_fns = 0usize;
    for (file, src) in repo_files() {
        let (_c, live) = lint_text::spend_views(&src);
        pool_fns += repo_fns_in(&without_test_modules(&live))
            .iter()
            .filter(|f| takes_a_pool(&f.params))
            .count();
        for name in pool_reads_without_viewer_in(&src) {
            found.push((file.clone(), name));
        }
    }
    found.sort();
    found.dedup();

    // A floor, not a measurement: a scanner that stopped matching declarations
    // finds no pool-taking function at all and must not pass on an empty set.
    assert!(
        pool_fns >= 50,
        "found only {pool_fns} pool-taking repo fns: the scanner is not matching declarations \
         and this lint would pass vacuously"
    );

    let mut want: Vec<(String, String)> = POOL_WITHOUT_VIEWER
        .iter()
        .map(|(f, n, _)| ((*f).to_string(), (*n).to_string()))
        .collect();
    want.sort();

    assert_eq!(
        found, want,
        "\n\nThe set of viewer-less `&PgPool` repo fns that read a tenanted table changed. A \
         new one that READS must take a `&Viewer` and splice its marker: no other tenancy lint \
         sees a pool-taking function, so this register is the only thing between it and a \
         fail-open. A genuine write that needs no viewer goes in POOL_WITHOUT_VIEWER with a \
         reason naming the statement and why. An entry that no longer matches must be \
         removed.\n"
    );

    for (file, name, reason) in POOL_WITHOUT_VIEWER {
        assert!(
            reason.len() > 80,
            "the reason for {file}::{name} is {} chars. Name the statement and why it needs no \
             viewer, not a label.",
            reason.len()
        );
    }
}

/// The pre-fix `ClaimRepository::get_properties`, verbatim: the concrete
/// instance that passed every other tenancy lint.
const PRE_FIX_GET_PROPERTIES: &str = r##"
impl ClaimRepository {
    pub async fn get_properties(
        pool: &PgPool,
        claim_id: ClaimId,
    ) -> Result<Option<serde_json::Value>, DbError> {
        let id: Uuid = claim_id.into();
        // Runtime `query_scalar`, not the `query!` macro: adding a macro call
        // would require regenerating `.sqlx`.
        let props: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT COALESCE(properties, '{}'::jsonb) FROM claims WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;
        Ok(props)
    }
}
"##;

#[test]
fn a_pool_taking_claim_read_without_a_viewer_is_selected() {
    assert_eq!(
        pool_reads_without_viewer_in(PRE_FIX_GET_PROPERTIES),
        vec!["get_properties".to_string()],
        "the pre-fix get_properties (pool: &PgPool, no Viewer, FROM claims) must be selected"
    );
}

#[test]
fn the_selector_is_shaped_by_signature_live_sql_and_test_modules() {
    // Same function given a Viewer: the viewer lints own it, not this one.
    let with_viewer = PRE_FIX_GET_PROPERTIES.replace(
        "pool: &PgPool,\n        claim_id",
        "pool: &PgPool,\n        viewer: &crate::visibility::Viewer,\n        claim_id",
    );
    assert_ne!(with_viewer, PRE_FIX_GET_PROPERTIES, "fixture edit applied");
    assert!(pool_reads_without_viewer_in(&with_viewer).is_empty());

    // The `Pool<Postgres>` spelling and lowercase SQL with a schema qualifier
    // are still selected.
    let spelled = "fn f(pool: &sqlx::Pool<sqlx::Postgres>) { sqlx::query(\"select 1 from \
                   public.edges e join claims c on true\"); }";
    assert_eq!(pool_reads_without_viewer_in(spelled), vec!["f".to_string()]);

    // A table named only in an SQL comment, or only in a Rust comment, is not
    // read; neither is a table whose name merely starts with a tenanted one.
    let commented = "fn f(pool: &PgPool) {\n    // SELECT x FROM claims\n    \
                     sqlx::query(\"SELECT 1 /* FROM claims */ -- JOIN edges\\n FROM \
                     claims_archive\");\n}";
    assert!(
        pool_reads_without_viewer_in(commented).is_empty(),
        "comment-only or prefix-only table names must not select"
    );

    // A doc-test declaration is a comment, not a function.
    let doc = "/// ```\n/// async fn example(pool: &PgPool) { query(\"SELECT 1 FROM claims\") }\n\
               /// ```\nfn real() {}";
    assert!(pool_reads_without_viewer_in(doc).is_empty());

    // A unit-test fixture inside `#[cfg(test)] mod` is not a request path, but
    // a function after the module is scanned again.
    let test_mod = "#[cfg(test)]\nmod tests {\n    async fn cleanup(pool: &PgPool) { \
                    sqlx::query(\"DELETE FROM claims\"); }\n}\nasync fn after(pool: &PgPool) \
                    { sqlx::query(\"SELECT 1 FROM evidence\"); }";
    assert_eq!(
        pool_reads_without_viewer_in(test_mod),
        vec!["after".to_string()]
    );
}
