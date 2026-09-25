//! Source ratchet: route-layer WRITES whose result is discarded with `let _ =`.
//!
//! # The class this pins
//!
//! A write on a request path whose `Result` is thrown away turns every refusal
//! into a success response. On a schema without the orphan `*_privacy`
//! policies, row security refuses an unstamped `claims` write with `42501`, and
//! hides a row it will not let the session see, so the UPDATE touches zero rows
//! with NO error. A handler that discards either answers 2xx over nothing. The
//! batch H-a review measured exactly that on `DELETE /api/v1/workflows/:id`
//! (200, `deprecated_ids`, `is_current` unchanged), `POST
//! /api/v1/workflows/:id/outcome` (200, the new truth value, claims untouched)
//! and `POST /api/v1/bp/propagate` (200, `applied: true`, zero rows), and
//! counted 51 `let _ =` write statements across `routes/` by a static scan.
//!
//! # What it matches
//!
//! A `let _ =` statement (up to its `;`), after comments are stripped, that
//! names a write (a SQL `INSERT`/`UPDATE`/`DELETE`, or a callee whose name
//! carries one of [`WRITE_CALLEES`]) AND a pool or connection (`pool`,
//! `db_pool`, `tx`, `conn`). Counted per file.
//!
//! Not every entry is a defect. An `events` INSERT that is genuinely
//! best-effort after a committed write, on a table with no row security, is a
//! defensible `let _ =`. The register does not judge each site; it pins the
//! COUNT, so a new swallowed write is a failure a reviewer must look at, and a
//! conversion that propagates an error is a visible lowering.
//!
//! # What it does NOT see, stated so its green is not over-read
//!
//! * `.ok()`, `.unwrap_or_default()` and `if .. .is_err() { count += 1 }` on a
//!   write. The reviewer's scan counted only `let _ =`, and so does this one.
//! * A zero-row UPDATE whose result IS kept but whose `rows_affected()` is
//!   never checked. That is a semantic property, not a syntactic one.
//! * Writes outside `crates/epigraph-api/src/routes/`.

#![cfg(feature = "db")]

mod lint_text;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Callee-name fragments that make a `Repository::fn(` call write-shaped.
const WRITE_CALLEES: &[&str] = &[
    "create",
    "insert",
    "update",
    "upsert",
    "delete",
    "deprecate",
    "set_",
    "store",
    "assign",
    "record",
    "mark",
    "supersede",
    "increment",
    "retract",
    "merge",
    "evolve",
];

/// The register: `(file, count)`, 46 in total. Measured on the batch H-a
/// revision after its HTTP conversions. The same rule over the tree before them
/// (80398b7a) finds 51: `report_outcome`'s two claim UPDATEs,
/// `deprecate_workflow`'s `deprecate_claim` and `set_truth_value`, and the
/// scalar `bp/propagate` UPDATE are the five that now propagate.
/// Lower a row when a conversion propagates an error; delete it at zero. Never
/// raise one: convert the write instead.
const REGISTER: &[(&str, usize)] = &[
    ("assess.rs", 6),
    ("belief.rs", 16),
    ("challenge.rs", 1),
    ("claims.rs", 3),
    ("community.rs", 1),
    ("conflicts.rs", 2),
    ("conventions.rs", 5),
    ("crud.rs", 2),
    ("gaps.rs", 1),
    ("perspective.rs", 1),
    ("reasoning.rs", 3),
    ("spans.rs", 3),
    // The two `events` INSERTs after `store_workflow` and `deprecate_workflow`
    // commit. `events` has no row security; best-effort by design.
    ("workflows.rs", 2),
];

/// Ceiling on the total, so growth fails structurally even if a row and the
/// total were raised together.
const HIGH_WATER: usize = 46;

fn routes_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes")
}

/// Is `stmt` (one `let _ = ...;` statement, comments stripped) a write on a
/// pool or connection?
fn is_discarded_write(stmt: &str) -> bool {
    let upper_sql = ["INSERT ", "UPDATE ", "DELETE "]
        .iter()
        .any(|kw| stmt.contains(kw));
    let callee = stmt.split("::").skip(1).any(|seg| {
        let name: String = seg
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        seg[name.len()..].trim_start().starts_with('(')
            && WRITE_CALLEES.iter().any(|t| name.contains(t))
    });
    let on_a_connection = ["pool", "tx", "conn"].iter().any(|p| stmt.contains(p));
    (upper_sql || callee) && on_a_connection
}

/// Every `let _ = ...;` statement in `src`, comments already stripped.
fn discarded_statements(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(i) = rest.find("let _ =") {
        let tail = &rest[i..];
        let end = tail.find(';').unwrap_or(tail.len());
        out.push(tail[..end].to_string());
        rest = &tail[end.min(tail.len())..];
        if rest.is_empty() {
            break;
        }
        rest = &rest[1..];
    }
    out
}

fn measure_src(src: &str) -> usize {
    discarded_statements(&lint_text::strip_comments(src))
        .iter()
        .filter(|s| is_discarded_write(s))
        .count()
}

fn measure() -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    let mut entries: Vec<_> = std::fs::read_dir(routes_dir())
        .expect("routes dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .collect();
    entries.sort();
    for path in entries {
        let src = std::fs::read_to_string(&path).expect("read route file");
        let n = measure_src(&src);
        if n > 0 {
            out.insert(path.file_name().unwrap().to_string_lossy().into_owned(), n);
        }
    }
    out
}

#[test]
fn discarded_route_writes_are_exactly_the_register() {
    let measured = measure();
    let expected: BTreeMap<String, usize> = REGISTER
        .iter()
        .map(|(f, n)| ((*f).to_string(), *n))
        .collect();
    assert_eq!(
        measured, expected,
        "\n\nThe set of `let _ =` writes under crates/epigraph-api/src/routes/ changed.\n\
         A write whose result is discarded answers success over a refusal (and a row-security \
         UPDATE that matches zero rows raises no error at all). Propagate the error instead; \
         if you REMOVED one, lower its row here. Never raise a row.\n"
    );
}

#[test]
fn the_total_never_rises() {
    let total: usize = measure().values().sum();
    assert!(
        total <= HIGH_WATER,
        "{total} discarded route-layer writes, above the high-water mark {HIGH_WATER}"
    );
}

/// Calibration: the matcher must SEE the shapes the batch H-a review measured,
/// and must NOT count a discarded read or a comment.
#[test]
fn the_matcher_is_not_vacuous() {
    let planted = r#"
        fn a() {
            let _ = sqlx::query("UPDATE claims SET truth_value = $1 WHERE id = $2")
                .bind(x).execute(&state.db_pool).await;
            let _ = epigraph_db::ClaimRepository::deprecate_claim(&state.db_pool, id).await;
            let _ = epigraph_db::EventRepository::insert(&mut *tx, "e", None, &p).await;
            // let _ = ClaimRepository::deprecate_claim(&state.db_pool, id).await;
            let _ = ClaimRepository::get_by_id(&state.db_pool, &viewer, id).await;
            let _ = state.event_bus.publish(ev).await;
        }
    "#;
    assert_eq!(
        measure_src(planted),
        3,
        "the matcher must count the three planted writes and nothing else (not the commented \
         one, not the read, not the in-memory publish)"
    );
}
