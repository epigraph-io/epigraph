//! The HTTP edge writes that still run on the UNSTAMPED raw pool (batch W12b,
//! migration 120, operator decision D8). A shrink-only register.
//!
//! # The consequence of a site in this register
//!
//! Migration 120 owns an edge between two public claims (or evidence) by the
//! writing session's group. A site here writes on `state.db_pool` with no
//! principal stamped, so its edge lands `('public', world)`: ADMINISTRATIVE from
//! birth. Its writer cannot patch, retract or delete it on the application
//! role (it answers `not_owner` / `administrative_edge`), and only the
//! maintenance path changes it. For a STRUCTURAL edge (an agent, trace, frame,
//! context, span, perspective or community endpoint) that is D8's rule anyway;
//! for an in-scope edge (claim or evidence at both ends) it is a loss of
//! ownership until the handler is stamped.
//!
//! The five edge write handlers in `routes/edges.rs` were converted by W12b and
//! are not in this register, and so were the in-scope edge statements of
//! `conventions.rs::share_skill` (claim -> claim SHARED_BY) and
//! `conventions.rs::forget_convention` (evidence -> claim REFUTES): both
//! handlers hold a `Viewer`, and every other statement they make autocommits on
//! the raw pool, so moving the one edge statement onto `AppState::write_as`
//! splits no transaction. None of the sites below holds a stamped transaction
//! where it writes. Each in-scope site's disposition is in the table: a
//! STRUCTURAL site (an agent, trace, frame, context, span, perspective or
//! community endpoint) is administrative by D8's own rule, and stamping it
//! would only record `writer_group_id`.
//!
//! # The register (per site, at this commit)
//!
//! | file | handler | endpoints -> relationship | in D8 scope | disposition |
//! |---|---|---|---|---|
//! | assess.rs | assess_claim | claim -> frame WITHIN_FRAME | no | structural |
//! | assess.rs | assess_claim | evidence -> claim SUPPORTS | yes | DEAD WRITE: the source id is a `mass_functions` id typed `evidence`; `edges_validate_refs` refuses it (measured) and `let _` swallows the error, so no edge lands |
//! | assess.rs | assess_claim | evidence -> claim CONTRADICTS | yes | DEAD WRITE, as above |
//! | belief.rs | submit_evidence | claim -> context SCOPED_BY | no | structural |
//! | belief.rs | submit_evidence | claim -> frame WITHIN_FRAME | no | structural |
//! | belief.rs | submit_evidence | evidence -> claim SUPPORTS | yes | DEAD WRITE: the same `mass_functions`-id-as-evidence shape |
//! | belief.rs | submit_evidence | evidence -> claim CONTRADICTS | yes | DEAD WRITE, as above |
//! | belief.rs | submit_evidence | evidence -> agent GENERATED_BY | no | structural (and the same dead shape) |
//! | belief.rs | submit_evidence | perspective -> claim CONTRIBUTES_TO | no | structural |
//! | claims.rs | create_claim | agent -> claim AUTHORED | no | structural |
//! | claims.rs | create_claim | claim -> trace HAS_TRACE | no | structural |
//! | claims.rs | create_claim | claim -> evidence DERIVED_FROM | yes | holds a `Viewer`; a post-commit best-effort statement; conversion deferred (no direct test harness for the signed create path yet) |
//! | community.rs | add_member | perspective -> community MEMBER_OF | no | structural |
//! | conventions.rs | learn_convention | agent -> claim AUTHORED | no | structural |
//! | conventions.rs | learn_convention | evidence -> claim SUPPORTS | yes | holds no `Viewer` (an `AuthContext` only) |
//! | conventions.rs | learn_convention | trace -> claim TRACES | no | structural |
//! | conventions.rs | learn_convention | claim -> trace HAS_TRACE | no | structural |
//! | cross_source.rs | decide_candidate (promote) | claim -> claim (matcher) | yes | OPERATOR CONFIRMATION: the MCP `decide_match_candidate` promote writes the same matcher edge on its unstamped pool, so stamping the HTTP side alone would split the matcher edges' owner by surface; the matcher retirement path deletes them administratively either way |
//! | crud.rs | create_evidence | claim -> evidence DERIVED_FROM | yes | holds no `Viewer` |
//! | crud.rs | create_reasoning_trace | claim -> trace HAS_TRACE | no |
//! | perspective.rs | create_perspective | perspective -> agent PERSPECTIVE_OF | no |
//! | provenance.rs | set_provenance | claim -> agent ATTRIBUTED_TO | no |
//! | provenance.rs | set_provenance | agent -> claim AUTHORED | no |
//! | provenance.rs | set_provenance | agent -> agent AFFILIATED_WITH | no |
//! | provenance.rs | set_provenance | claim -> agent WAS_ASSOCIATED_WITH | no |
//! | spans.rs | create_span | agent -> span attributed_to | no |
//! | spans.rs | close_span | span -> claim generated | no |
//! | spans.rs | close_span | span -> claim uses_evidence | no |
//!
//!
//! # The second register: raw `INSERT INTO edges` in a route file
//!
//! A route file that writes an edge with its own SQL instead of the repo layer
//! is registered too ([`RAW_INSERTS`]), stamped or not. Measured at this commit
//! every one of them runs unstamped:
//!
//! | file | handler | endpoints -> relationship | executor | in D8 scope |
//! |---|---|---|---|---|
//! | crud.rs | promote_staged_edges (claims:admin) | any staged pair (x2 statements) | `state.db_pool` | when the staged pair is claim/evidence at both ends |
//! | experiment_loop.rs | create_experiment | experiment -> claim tests_hypothesis | `state.db_pool` | no |
//! | experiment_loop.rs | submit_results | experiment_result -> experiment result_of | `state.db_pool` | no |
//! | experiment_loop.rs | analyze_result | analysis -> experiment_result analyzes | `state.db_pool` | no |
//! | experiment_loop.rs | analyze_result | analysis -> claim provides_evidence | `state.db_pool` | no |
//! | submit.rs | persist_packet | agent -> claim AUTHORED, claim -> trace HAS_TRACE, trace -> claim TRACES, trace -> evidence USES_EVIDENCE | a transaction begun on `state.db_pool` | no |
//! | submit.rs | persist_packet | evidence -> claim SUPPORTS | a transaction begun on `state.db_pool` | yes |
//!
//! # What this file does NOT see
//!
//! An edge INSERT inside another repo function that a raw-pool handler reaches
//! (for example `ClaimRepository`, `AnalysisRepository`, `WorkflowRepository`,
//! `SemanticLinkRepository` writing edges of their own) is not counted here. The
//! raw-pool handler that reaches it is in `no_unscoped_pool.rs`'s per-file
//! register, which is where its stamping is tracked.
//!
//! # How a site is counted
//!
//! [`UNSTAMPED`]: a code line (not a whole-line comment) of a non-test region
//! of a file under `crates/epigraph-api/src/routes` that names
//! `EdgeRepository::create` (any `create*` form), whose executor argument (the
//! text up to the first comma over that line and the next two) is the raw
//! pool: `state.db_pool` or a `pool` alias.
//!
//! [`RAW_INSERTS`]: a code line of a non-test region of any file under
//! `crates/epigraph-api/src/routes` (`edges.rs` included) that contains
//! `INSERT INTO edges` or `INSERT INTO public.edges`.
//!
//! A file's test code is not scanned: the brace extent of every inline module
//! gated `#[cfg(test)]` or `#[cfg(all(test, ..))]` (its attributes included),
//! and the whole file of an out-of-line one (`#[cfg(test)] mod name;` in any
//! route file excludes `routes/name.rs`). Everything else IS scanned, including
//! code after a test module and a `cfg(test)` item that is not a module (a
//! test-only const or fn): a brace inside a string, char literal or comment
//! does not move a module's extent.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const ROUTES: &str = "crates/epigraph-api/src/routes";

/// The unstamped HTTP edge writes, per file. Lower a row when a handler is
/// stamped; delete it at zero. Never raise one.
const UNSTAMPED: &[(&str, usize)] = &[
    ("assess.rs", 3),
    ("belief.rs", 6),
    ("claims.rs", 3),
    ("community.rs", 1),
    // 6 before the W12b revise, which stamped `share_skill`'s and
    // `forget_convention`'s in-scope edge statements.
    ("conventions.rs", 4),
    ("cross_source.rs", 1),
    ("crud.rs", 2),
    ("perspective.rs", 1),
    ("provenance.rs", 4),
    ("spans.rs", 3),
];

/// The total the register may never exceed.
const HIGH_WATER: usize = 28;

/// Route-layer raw `INSERT INTO edges` statements, per file (see the module
/// doc's second register). Lower a row when a statement moves to the repo
/// layer on a stamped transaction; delete it at zero. Never raise one.
const RAW_INSERTS: &[(&str, usize)] =
    &[("crud.rs", 2), ("experiment_loop.rs", 4), ("submit.rs", 5)];

/// The total [`RAW_INSERTS`] may never exceed.
const RAW_HIGH_WATER: usize = 11;

/// Whether `line` (trimmed) opens with a test-gating `cfg` attribute.
fn is_cfg_test(line: &str) -> bool {
    line.starts_with("#[cfg(test)]") || line.starts_with("#[cfg(all(test")
}

/// `text` with every leading outer attribute (`#[...]`) removed.
fn strip_attributes(mut text: &str) -> &str {
    loop {
        let t = text.trim_start();
        if !t.starts_with("#[") {
            return t;
        }
        let mut depth = 0usize;
        let mut end = None;
        for (i, c) in t.char_indices() {
            match c {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        match end {
            Some(e) => text = &t[e..],
            None => return "",
        }
    }
}

/// The name of the module `item` declares, when it declares one.
fn module_name(item: &str) -> Option<&str> {
    let mut t = item.trim_start();
    for vis in ["pub(crate) ", "pub(super) ", "pub "] {
        if let Some(rest) = t.strip_prefix(vis) {
            t = rest.trim_start();
        }
    }
    let rest = t.strip_prefix("mod ")?;
    let name: &str = rest
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .next()
        .unwrap_or("");
    (!name.is_empty()).then_some(name)
}

/// How many lines `text` (starting at an item whose first `{` opens a block)
/// spans up to that block's matching `}`, skipping braces inside string, raw
/// string, byte string and char literals and comments. `None` when the block
/// never closes.
fn block_line_span(text: &str) -> Option<usize> {
    let b = text.as_bytes();
    let (mut i, mut depth, mut lines, mut opened) = (0usize, 0usize, 0usize, false);
    let ident = |k: usize| k > 0 && (b[k - 1].is_ascii_alphanumeric() || b[k - 1] == b'_');
    while i < b.len() {
        match b[i] {
            b'\n' => lines += 1,
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut nest = 0usize;
                while i < b.len() {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        nest += 1;
                        i += 2;
                        continue;
                    }
                    if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        nest -= 1;
                        i += 2;
                        if nest == 0 {
                            break;
                        }
                        continue;
                    }
                    if b[i] == b'\n' {
                        lines += 1;
                    }
                    i += 1;
                }
                continue;
            }
            b'r' if !ident(i) && matches!(b.get(i + 1), Some(b'"' | b'#')) => {
                let mut j = i + 1;
                let mut hashes = 0usize;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) == Some(&b'"') {
                    j += 1;
                    loop {
                        match b.get(j) {
                            None => return None,
                            Some(b'"')
                                if b[j + 1..]
                                    .iter()
                                    .take(hashes)
                                    .filter(|c| **c == b'#')
                                    .count()
                                    == hashes =>
                            {
                                j += 1 + hashes;
                                break;
                            }
                            Some(b'\n') => lines += 1,
                            _ => {}
                        }
                        j += 1;
                    }
                    i = j;
                    continue;
                }
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    if i < b.len() && b[i] == b'\n' {
                        lines += 1;
                    }
                    i += 1;
                }
            }
            b'\'' => {
                // A char literal ('x', '\n', '\u{..}'); otherwise a lifetime.
                if b.get(i + 1) == Some(&b'\\') {
                    i += 2;
                    while i < b.len() && b[i] != b'\'' {
                        i += 1;
                    }
                } else if b.get(i + 2) == Some(&b'\'') {
                    i += 2;
                }
            }
            b'{' => {
                depth += 1;
                opened = true;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                if opened && depth == 0 {
                    return Some(lines);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Which lines of a route file are test code (not scanned), and the names of
/// the out-of-line test modules it declares (their files are not scanned).
fn test_lines(src: &str) -> (Vec<bool>, Vec<String>) {
    let lines: Vec<&str> = src.lines().collect();
    let mut mask = vec![false; lines.len()];
    let mut out_of_line = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        if !is_cfg_test(lines[i].trim_start()) {
            i += 1;
            continue;
        }
        // The gated item: the rest of the attribute line, or the next line
        // that is not blank, an attribute or a comment.
        let mut j = i;
        let mut item = strip_attributes(lines[i]);
        while item.is_empty() || item.starts_with("//") {
            j += 1;
            if j >= lines.len() {
                break;
            }
            item = strip_attributes(lines[j]);
        }
        let Some(name) = (j < lines.len()).then(|| module_name(item)).flatten() else {
            // Not a module: a test-only const or fn is scanned.
            i += 1;
            continue;
        };
        let rest = lines[j..].join("\n");
        let from = rest.find(item).unwrap_or(0);
        let (semi, brace) = (rest[from..].find(';'), rest[from..].find('{'));
        let last = match (semi, brace) {
            (Some(sc), Some(br)) if sc < br => {
                out_of_line.push(name.to_string());
                j
            }
            (Some(_), None) => {
                out_of_line.push(name.to_string());
                j
            }
            (_, Some(_)) => {
                j + block_line_span(&rest[from..])
                    .unwrap_or_else(|| panic!("the test module `{name}` never closes"))
            }
            (None, None) => lines.len() - 1,
        };
        for m in mask.iter_mut().take(last + 1).skip(i) {
            *m = true;
        }
        i = last + 1;
    }
    (mask, out_of_line)
}

/// Raw `INSERT INTO edges` code lines of one route file, outside its test code.
fn count_raw_inserts(src: &str) -> usize {
    let (mask, _) = test_lines(src);
    src.lines()
        .zip(mask)
        .filter(|(l, test)| {
            !test
                && !l.trim_start().starts_with("//")
                && (l.contains("INSERT INTO edges") || l.contains("INSERT INTO public.edges"))
        })
        .count()
}

/// `EdgeRepository::create*` calls on the raw pool in one route file, outside
/// its test code.
fn count_unstamped_creates(src: &str) -> usize {
    let lines: Vec<&str> = src.lines().collect();
    let (mask, _) = test_lines(src);
    let mut n = 0usize;
    for i in 0..lines.len() {
        let l = lines[i];
        if mask[i] || l.trim_start().starts_with("//") || !l.contains("EdgeRepository::create") {
            continue;
        }
        let call: String = lines[i..(i + 3).min(lines.len())].join(" ");
        let from = call.find("EdgeRepository::create").expect("present");
        if is_raw_pool_executor(&call[from..]) {
            n += 1;
        }
    }
    n
}

/// Every route file except the out-of-line test modules route files declare.
fn route_files() -> Vec<PathBuf> {
    let dir = repo_root().join(ROUTES);
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    let test_files: Vec<String> = entries
        .iter()
        .flat_map(|p| test_lines(&std::fs::read_to_string(p).expect("read route file")).1)
        .map(|m| format!("{m}.rs"))
        .collect();
    entries.retain(|p| {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        !test_files.contains(&name)
    });
    entries.sort();
    entries
}

fn measure_raw_inserts() -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for p in route_files() {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let src = std::fs::read_to_string(&p).expect("read route file");
        let n = count_raw_inserts(&src);
        if n > 0 {
            out.insert(name, n);
        }
    }
    out
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/epigraph-db has two ancestors")
        .to_path_buf()
}

fn is_raw_pool_executor(call: &str) -> bool {
    let after = match call.find('(') {
        Some(i) => &call[i + 1..],
        None => return false,
    };
    let arg = after.split(',').next().unwrap_or("").trim();
    matches!(arg, "&state.db_pool" | "state.db_pool" | "pool" | "&pool")
        || arg.starts_with("&state.db_pool")
}

fn measure() -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for p in route_files() {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if name == "edges.rs" {
            // Converted by W12b; its remaining raw-pool sites are post-commit
            // side effects, registered in `no_unscoped_pool.rs`.
            continue;
        }
        let src = std::fs::read_to_string(&p).expect("read route file");
        let n = count_unstamped_creates(&src);
        if n > 0 {
            out.insert(name, n);
        }
    }
    out
}

#[test]
fn the_unstamped_http_edge_writes_are_exactly_the_register() {
    let measured = measure();
    let recorded: BTreeMap<String, usize> = UNSTAMPED
        .iter()
        .map(|(f, n)| ((*f).to_string(), *n))
        .collect();
    assert_eq!(
        measured, recorded,
        "the unstamped HTTP edge writes changed. A NEW site writes a world-owned, \
         administrative edge (migration 120): stamp it with the caller's viewer \
         (`AppState::write_as`) instead. A site that went away: lower its row."
    );
}

#[test]
fn the_register_can_only_shrink() {
    let total: usize = UNSTAMPED.iter().map(|(_, n)| n).sum();
    assert!(
        total <= HIGH_WATER,
        "the register grew past its high-water mark ({total} > {HIGH_WATER})"
    );
}

#[test]
fn the_scanner_sees_a_raw_pool_executor_and_not_a_stamped_one() {
    assert!(is_raw_pool_executor(
        "EdgeRepository::create( &state.db_pool, a, \"claim\""
    ));
    assert!(is_raw_pool_executor("EdgeRepository::create( pool, a,"));
    assert!(!is_raw_pool_executor(
        "EdgeRepository::create( &mut *tx, a,"
    ));
    assert!(!is_raw_pool_executor(
        "EdgeRepository::create_if_not_exists_conn( &mut tx, a,"
    ));
    // The converted edges.rs is skipped; everything else is found.
    assert!(!measure().contains_key("edges.rs"));
    assert!(
        measure().values().sum::<usize>() > 0,
        "the scanner is vacuous"
    );
}

#[test]
fn the_route_layer_raw_edge_inserts_are_exactly_the_register() {
    let measured = measure_raw_inserts();
    let recorded: BTreeMap<String, usize> = RAW_INSERTS
        .iter()
        .map(|(f, n)| ((*f).to_string(), *n))
        .collect();
    assert_eq!(
        measured, recorded,
        "the route-layer raw `INSERT INTO edges` statements changed. A NEW one writes \
         an edge outside the repo layer: move it into `crates/epigraph-db/src/repos/` \
         and run it on a transaction stamped with the caller's viewer \
         (`AppState::write_as`). A statement that went away: lower its row."
    );
    let total: usize = RAW_INSERTS.iter().map(|(_, n)| n).sum();
    assert!(
        total <= RAW_HIGH_WATER,
        "the raw-insert register grew past its high-water mark ({total} > {RAW_HIGH_WATER})"
    );
}

#[test]
fn the_raw_insert_scanner_skips_comments_and_every_test_region_spelling() {
    let src = "fn a() {\n\
               sqlx::query(\"INSERT INTO edges (source_id) VALUES ($1)\");\n\
               // INSERT INTO edges in a comment\n\
               sqlx::query(\"INSERT INTO public.edges (source_id) VALUES ($1)\");\n\
               }\n\
               #[cfg(all(test, feature = \"db\"))]\n\
               mod tests { const S: &str = \"INSERT INTO edges\"; }\n";
    assert_eq!(count_raw_inserts(src), 2);
    let plain = "fn a() {}\n#[cfg(test)]\nmod t { const S: &str = \"INSERT INTO edges\"; }\n";
    assert_eq!(count_raw_inserts(plain), 0);
    assert!(
        measure_raw_inserts().values().sum::<usize>() > 0,
        "the raw-insert scanner is vacuous"
    );
}

/// A test region is a gated MODULE's extent, never "the rest of the file".
#[test]
fn only_a_test_modules_extent_is_skipped_and_code_after_it_is_scanned() {
    // An early test-only const (routes/agents.rs has one) does not hide the
    // production code after it, from either register.
    let early = "#[cfg(test)]\n\
                 const K: usize = 64;\n\
                 fn prod() {\n\
                 sqlx::query(\"INSERT INTO edges (source_id) VALUES ($1)\");\n\
                 EdgeRepository::create(\n&state.db_pool, a, \"claim\");\n\
                 }\n";
    assert_eq!(count_raw_inserts(early), 1);
    assert_eq!(count_unstamped_creates(early), 1);
    // A brace in a string, a char literal or a comment inside a test module
    // does not move its end; code after the module is scanned.
    let braces = "#[cfg(test)]\n\
                  #[allow(clippy::all)]\n\
                  mod tests {\n\
                  const S: &str = \"{ INSERT INTO edges {\";\n\
                  const C: char = '{';\n\
                  // }\n\
                  fn t<'a>(x: &'a str) -> &'a str { x }\n\
                  }\n\
                  fn after() { sqlx::query(\"INSERT INTO edges (x) VALUES ($1)\"); }\n";
    assert_eq!(count_raw_inserts(braces), 1);
    // `mod name;` masks only its own line; the file is excluded instead.
    let outline = "#[cfg(test)]\nmod negative_tests;\n\
                   fn c() { sqlx::query(\"INSERT INTO public.edges (x) VALUES ($1)\"); }\n";
    assert_eq!(count_raw_inserts(outline), 1);
    assert_eq!(test_lines(outline).1, vec!["negative_tests".to_string()]);
    // The attribute on the same line as the module.
    let same = "#[cfg(all(test, feature = \"db\"))] mod db_tests {\n\
                const S: &str = \"INSERT INTO edges\";\n}\n";
    assert_eq!(count_raw_inserts(same), 0);
    // The route tree's own out-of-line test module is not a route file.
    assert!(route_files()
        .iter()
        .all(|p| p.file_name().unwrap() != "negative_tests.rs"));
    // On the real route files, every skipped run ends where its module does
    // (a closing brace, or `mod name;`), so no extent swallows the file.
    let mut runs = 0usize;
    for p in route_files() {
        let src = std::fs::read_to_string(&p).expect("read route file");
        let lines: Vec<&str> = src.lines().collect();
        let (mask, _) = test_lines(&src);
        for i in 0..lines.len() {
            if mask[i] && mask.get(i + 1) != Some(&true) {
                runs += 1;
                let end = lines[i].trim_end();
                assert!(
                    end.ends_with('}') || end.ends_with(';'),
                    "{}:{}: a test module's extent ends on {end:?}",
                    p.display(),
                    i + 1
                );
            }
        }
    }
    assert!(
        runs > 10,
        "the test-module scanner found almost nothing: {runs}"
    );
}
