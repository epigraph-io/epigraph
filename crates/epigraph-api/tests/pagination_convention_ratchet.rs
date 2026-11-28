//! The number of offset/page pagination parameters under `routes/` may only
//! fall.
//!
//! Backlog 763974af (split 3/4 of 98d54f97). New list endpoints page with an
//! opaque keyset cursor: the request carries `after` (or `cursor`) and the
//! response returns `next_cursor` (`routes/search.rs` is the model today; a
//! shared `routes/pagination.rs` is planned). OFFSET pagination re-scans the
//! skipped rows on every page and skips or repeats rows when the list changes
//! between pages.
//!
//! What is counted: every field named `offset` or `page`, of ANY visibility
//! (`pub`, `pub(crate)`, private) and ANY type (`i64`, `Option<u32>`, ...),
//! including one written after a same-line attribute such as
//! `#[serde(default)] pub offset: i64,`, that is declared inside the body of a
//! `struct` or `enum` whose derive list includes `Deserialize` (a request
//! shape), in `crates/epigraph-api/src/routes/**/*.rs`. Serialize-only
//! response structs, struct literals (`offset: 0,`) and fn parameters are not
//! declarations of a request field and are not counted. The test fails when
//! the count rises above [`BASELINE`].
//!
//! * Converting an endpoint to the cursor convention lowers the count: lower
//!   [`BASELINE`] in the same change (allowed, and expected).
//! * Raising [`BASELINE`] needs an edit to this file with a stated reason in
//!   the commit and here.
//! * A Deserialize field with one of these names that is NOT a pagination
//!   parameter goes in [`NOT_PAGINATION`], keyed by file and enclosing item
//!   (not by line); every entry must still match a site.
//!
//! Not covered: offset carried in an untyped map (`Query<HashMap<..>>`) or in
//! a field with another name. Static, no database; comment lines are skipped.

use std::path::{Path, PathBuf};

/// Measured on the tree this ratchet landed on (14 request fields):
///
/// * `agents.rs`: `AgentListParams`, `AgentClaimsParams`
/// * `belief.rs`: `ListFramesQuery`, `BeliefFilterQuery`, `FrameClaimsQuery`
/// * `claims.rs`: `PaginationParams` (shared by several list endpoints),
///   `ClaimsByLabelsQuery`
/// * `claims_query.rs`: `ClaimQueryParams`
/// * `community.rs`: `ListCommunitiesQuery`
/// * `context.rs`: `ListContextsQuery`
/// * `crud.rs`: `ListEvidenceQuery`
/// * `events.rs`: `EventFilter`
/// * `papers.rs`: `PaperListParams`
/// * `perspective.rs`: `ListPerspectivesQuery`
const BASELINE: usize = 14;

const NAMES: &[&str] = &["offset", "page"];

/// `(file relative to routes/, enclosing struct or enum, why)`.
const NOT_PAGINATION: &[(&str, &str, &str)] = &[
    (
        "submit.rs",
        "EvidenceTypeSubmission",
        "the `Figure` variant's page number in its source document, not a list page",
    ),
    (
        "claims_query.rs",
        "ClaimListResponse",
        "a response (Serialize + Deserialize) echoing the offset that was applied, \
         not a request parameter",
    ),
];

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

/// Drop leading `#[...]` attributes written on the same line as the code.
fn strip_leading_attrs(mut t: &str) -> &str {
    while let Some(rest) = t.strip_prefix("#[") {
        let mut depth = 1usize;
        let mut cut = None;
        for (i, c) in rest.char_indices() {
            match c {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        cut = Some(i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        match cut {
            Some(i) => t = rest[i..].trim_start(),
            None => return "",
        }
    }
    t
}

/// Drop a leading visibility (`pub`, `pub(crate)`, `pub(in path)`, ...).
fn strip_vis(t: &str) -> &str {
    let Some(rest) = t.strip_prefix("pub") else {
        return t;
    };
    if let Some(inner) = rest.strip_prefix('(') {
        return inner.find(')').map_or(t, |i| inner[i + 1..].trim_start());
    }
    if rest.starts_with(char::is_whitespace) {
        return rest.trim_start();
    }
    t
}

/// The item name if `code` (attributes and visibility stripped) declares a
/// `struct` or `enum`.
fn item_name(code: &str) -> Option<&str> {
    let after = code
        .strip_prefix("struct ")
        .or_else(|| code.strip_prefix("enum "))?
        .trim_start();
    let end = after
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(after.len());
    (end > 0).then(|| &after[..end])
}

/// The field name if `code` declares a named field (`name: Type`).
fn field_name(code: &str) -> Option<&str> {
    let code = strip_vis(strip_leading_attrs(code));
    let end = code
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(code.len());
    if end == 0 {
        return None;
    }
    let rest = code[end..].trim_start();
    // `name: Type`, not a path `name::x`.
    (rest.starts_with(':') && !rest.starts_with("::")).then(|| &code[..end])
}

/// Whether the attributes directly above line `at` (a struct/enum header), or
/// on the header line itself, derive `Deserialize`. Handles a derive split
/// over several lines and the `serde::Deserialize` path form.
fn derives_deserialize(lines: &[&str], at: usize) -> bool {
    let mut attrs = String::new();
    let mut k = at;
    while k > 0 {
        k -= 1;
        let t = lines[k].trim();
        if t.starts_with("//") {
            continue;
        }
        // Attribute lines and the continuation lines of a multi-line
        // attribute (`Debug,` / `serde::Deserialize,` / `)]`). A blank line or
        // the end of the previous item (`;`, `}`, `{`) stops the walk.
        let previous_item_end =
            t.is_empty() || t.ends_with(';') || t.ends_with('}') || t.ends_with('{');
        if t.starts_with("#[") || !previous_item_end {
            attrs.push_str(t);
            attrs.push(' ');
        } else {
            break;
        }
    }
    let header = lines[at].trim();
    if header.starts_with("#[") {
        attrs.push_str(header);
    }
    attrs.contains("derive") && attrs.contains("Deserialize")
}

fn brace_delta(code: &str) -> i64 {
    code.chars().fold(0, |d, c| match c {
        '{' => d + 1,
        '}' => d - 1,
        _ => d,
    })
}

#[derive(Debug)]
struct Site {
    file: String,
    line: usize,
    owner: String,
    field: String,
}

fn scan(file: &str, src: &str) -> Vec<Site> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        let name = if t.starts_with("//") {
            None
        } else {
            item_name(strip_vis(strip_leading_attrs(t)))
        };
        let Some(name) = name else {
            i += 1;
            continue;
        };
        // The body's opening brace may follow generics or a `where` clause on
        // later lines. `struct X;` and `struct X(..);` have none.
        let mut open = Some(i);
        while let Some(o) = open {
            let l = lines[o].trim();
            if !l.starts_with("//") && l.contains('{') {
                break;
            }
            open = (!l.ends_with(';') && o + 1 < lines.len()).then_some(o + 1);
        }
        let Some(open) = open else {
            i += 1;
            continue;
        };
        let counted = derives_deserialize(&lines, i);
        // Walk the body by brace depth.
        let mut depth = 0i64;
        let mut k = i;
        while k < lines.len() {
            let l = lines[k].trim();
            if !l.starts_with("//") {
                if counted && k > open {
                    if let Some(f) = field_name(l).filter(|f| NAMES.contains(f)) {
                        out.push(Site {
                            file: file.to_string(),
                            line: k + 1,
                            owner: name.to_string(),
                            field: f.to_string(),
                        });
                    }
                }
                depth += brace_delta(l);
            }
            if k >= open && depth <= 0 {
                break;
            }
            k += 1;
        }
        i = k + 1;
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
        .map(|s| {
            format!(
                "  src/routes/{}:{} ({} in {})",
                s.file, s.line, s.field, s.owner
            )
        })
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

/// Calibration: the scanner sees every spelling a request field can take,
/// ignores responses, literals, parameters and comments, and the tree still
/// carries sites (a scanner that finds nothing is broken, not green).
#[test]
fn the_scanner_is_not_vacuous() {
    let sample = r#"
#[derive(Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    // pub page: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct CopiedQuery {
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Deserialize)]
pub struct OneLine {
    #[serde(default)] pub offset: i64,
}

#[derive(
    Debug,
    serde::Deserialize,
)]
pub(crate) struct Spread<T>
where
    T: Clone,
{
    offset: Option<i64>,
    pub(crate) page: u32,
    inner: T,
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub offset: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct Validated {
    pub offset: i64,
}

#[derive(Deserialize)]
pub struct Marker;

#[derive(Deserialize)]
pub enum Evidence {
    Figure {
        page: Option<u32>,
    },
}

fn build(page: u32) -> ListResponse {
    ListResponse { offset: 0 }
}
"#;
    let got: Vec<(usize, String, String)> = scan("x.rs", sample)
        .into_iter()
        .map(|s| (s.line, s.owner, s.field))
        .collect();
    let want: Vec<(usize, String, String)> = [
        (5, "ListQuery", "offset"),
        (12, "CopiedQuery", "offset"),
        (17, "OneLine", "offset"),
        (28, "Spread", "offset"),
        (29, "Spread", "page"),
        (49, "Evidence", "page"),
    ]
    .into_iter()
    .map(|(l, o, f)| (l, o.to_string(), f.to_string()))
    .collect();
    assert_eq!(got, want);

    let real = measure();
    for (file, owner, _) in NOT_PAGINATION {
        assert!(
            real.iter().any(|s| s.file == *file && s.owner == *owner),
            "NOT_PAGINATION entry ({file}, {owner}) no longer matches a site; delete it"
        );
    }
    assert!(
        real.iter().filter(|s| is_pagination(s)).count() > 0 || BASELINE == 0,
        "no offset/page site found under src/routes but BASELINE is {BASELINE}: \
         if they are all converted, set BASELINE to 0; otherwise the scanner broke"
    );
}

/// The baseline is exact: a count below it means an endpoint was converted
/// and BASELINE must be lowered in the same change, so the ratchet keeps no
/// slack for a new offset field to hide in.
#[test]
fn the_baseline_has_no_slack() {
    let n = measure().into_iter().filter(is_pagination).count();
    assert!(
        n >= BASELINE,
        "only {n} offset/page pagination parameters under src/routes, below the baseline \
         of {BASELINE}: lower BASELINE to {n} in this change"
    );
}
