//! The number of offset/page pagination parameters under `routes/` may only
//! fall.
//!
//! Backlog 763974af (split 3/4 of 98d54f97). New list endpoints page with an
//! opaque keyset cursor: the request carries `after` (or `cursor`) and the
//! response returns `next_cursor` (`routes/search.rs` is the model today; a
//! shared `routes/pagination.rs` is planned). OFFSET pagination re-scans the
//! skipped rows on every page and skips or repeats rows when the list changes
//! between pages. This ratchet counts the request-struct fields that page by
//! offset, `pub offset: Option<` and `pub page: Option<`, in
//! `crates/epigraph-api/src/routes/**/*.rs`, and fails when the count rises
//! above [`BASELINE`].
//!
//! * Converting an endpoint to the cursor convention lowers the count: lower
//!   [`BASELINE`] in the same change (allowed, and expected).
//! * Raising [`BASELINE`] needs an edit to this file with a stated reason in
//!   the commit and here.
//! * A field with the same spelling that is NOT pagination goes in
//!   [`NOT_PAGINATION`], keyed by file and enclosing struct (not by line).
//!
//! Static, no database. Whole-line comments are skipped.

use std::path::{Path, PathBuf};

/// Measured when this test landed: one `offset` each in `claims.rs`
/// (`ClaimsByLabelsQuery`), `claims_query.rs` (`ClaimQueryParams`), `crud.rs`
/// (`ListEvidenceQuery`) and `events.rs` (`EventFilter`).
const BASELINE: usize = 4;

const NEEDLES: &[&str] = &["pub offset: Option<", "pub page: Option<"];

/// `(file relative to routes/, enclosing struct, why)`.
const NOT_PAGINATION: &[(&str, &str, &str)] = &[(
    "edges.rs",
    "EvidenceDetailResponse",
    "the figure's page number in its source document, not a list page",
)];

fn routes_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes")
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
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

/// The struct a field line belongs to: the nearest preceding `struct` line.
fn enclosing_struct<'a>(above: &[&'a str]) -> Option<&'a str> {
    above.iter().rev().find_map(|l| {
        let t = l.trim_start();
        let after = t
            .strip_prefix("pub struct ")
            .or_else(|| t.strip_prefix("pub(crate) struct "))
            .or_else(|| t.strip_prefix("struct "))?;
        let end = after
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        Some(&after[..end])
    })
}

#[derive(Debug)]
struct Site {
    file: String,
    line: usize,
    owner: String,
}

fn scan(file: &str, src: &str) -> Vec<Site> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if t.starts_with("//") || !NEEDLES.iter().any(|n| t.starts_with(n)) {
            continue;
        }
        out.push(Site {
            file: file.to_string(),
            line: i + 1,
            owner: enclosing_struct(&lines[..i]).unwrap_or("").to_string(),
        });
    }
    out
}

fn measure() -> Vec<Site> {
    let root = routes_root();
    let mut files = Vec::new();
    collect(&root, &mut files);
    files.sort();
    let mut out = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let src = std::fs::read_to_string(&path).expect("read source");
        out.extend(scan(&rel, &src));
    }
    out
}

fn is_pagination(s: &Site) -> bool {
    !NOT_PAGINATION
        .iter()
        .any(|(f, owner, _)| *f == s.file && *owner == s.owner)
}

#[test]
fn offset_pagination_params_do_not_grow() {
    let sites: Vec<Site> = measure().into_iter().filter(is_pagination).collect();
    let listed: Vec<String> = sites
        .iter()
        .map(|s| format!("  src/routes/{}:{} (struct {})", s.file, s.line, s.owner))
        .collect();
    assert!(
        sites.len() <= BASELINE,
        "{} offset/page pagination parameters under src/routes, above the baseline of \
         {BASELINE}:\n{}\n\nPage a new list endpoint with an opaque keyset cursor: take \
         `after` (or `cursor`) in the query and return `next_cursor` in the response, as \
         routes/search.rs does (routes/pagination.rs once it exists). If the field is not \
         pagination, add it to NOT_PAGINATION with its reason; raising BASELINE needs an \
         edit to this test with a reason.",
        sites.len(),
        listed.join("\n")
    );
}

/// Calibration: the scanner sees the real spellings, skips comments, and the
/// tree still carries the baseline's sites (a scanner that finds nothing is
/// broken, not green).
#[test]
fn the_scanner_is_not_vacuous() {
    let sample = "\
#[derive(Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    // pub page: Option<u32>,
}

pub struct EvidenceDetailResponse {
    pub page: Option<i64>,
}
";
    let sites = scan("edges.rs", sample);
    let got: Vec<(usize, &str, bool)> = sites
        .iter()
        .map(|s| (s.line, s.owner.as_str(), is_pagination(s)))
        .collect();
    assert_eq!(
        got,
        vec![(4, "ListQuery", true), (9, "EvidenceDetailResponse", false),]
    );

    let real = measure();
    assert!(
        real.iter().any(|s| !is_pagination(s)),
        "the NOT_PAGINATION entry no longer matches a site; delete it"
    );
    assert!(
        real.iter().filter(|s| is_pagination(s)).count() > 0 || BASELINE == 0,
        "no offset/page site found under src/routes but BASELINE is {BASELINE}: \
         if they are all converted, set BASELINE to 0; otherwise the scanner broke"
    );
}
