//! The HYBRID SHAPE: mint a bypass `Viewer`, then spend it on a pool that is
//! not the maintenance one.
//!
//! Recorded as `D-PR17-hybrid-shape-lint`, and named as a known limit by
//! `no_unmaintained_dsn.rs`'s own module doc.
//!
//! # Why a third key was needed
//!
//! Three lints already exist over this surface and none of them can see this
//! shape:
//!
//! * `no_unmaintained_dsn.rs` is keyed on pool **CONSTRUCTION**. It proves a
//!   scanned file builds no unmaintained pool. A file that takes an injected
//!   `PgPool` constructs nothing and passes green — its own doc says so.
//! * `no_unscoped_pool.rs` is keyed on the `state.db_pool` **FIELD ACCESS**
//!   count, as a monotone ratchet. It measures how much of the request path is
//!   unconverted, not whether a bypass viewer is spent somewhere it cannot work.
//! * `no_bypass_in_handlers.rs` is keyed on a handler **MINTING** a bypass at
//!   all. It has nothing to say about where a legitimately-minted one is spent.
//!
//! What determines whether a statement is filtered is the pool it RUNS on. A
//! bypass `Viewer` emits no SQL predicate; from plan §9.2 step 11d on, the
//! database policy still filters. So a bypass viewer spent on an ordinary
//! application connection returns **zero** rows rather than all of them — a
//! wrong answer with no error, which plan §4.3's R2 calls the worse failure
//! because *"fail-closed regressions look like data loss, not errors."*
//!
//! # What this lint checks, stated precisely
//!
//! Within a scanned file, it splits the source into function-sized regions and,
//! for each region that MINTS a bypass ([`MINTS`]), asserts that the region
//! names no FOREIGN POOL HANDLE ([`FOREIGN_POOLS`]).
//!
//! The granularity is the FUNCTION and that is an over-approximation, the same
//! one `visibility_lint.rs` states for `no_spliced_statement_binds_the_unconditional_group_array`:
//! a function that mints a bypass for one statement and legitimately uses an
//! application pool for an unrelated one is flagged. That is deliberate — the
//! two things being adjacent in one body is itself the review signal.
//!
//! # COMMENTS ARE STRIPPED BEFORE MATCHING, and this is NOT a re-litigation of
//! `lint_robustness_repos_is_not_a_stripping_root`
//!
//! That decision refused comment-stripping for `visibility_lint.rs`, and the
//! reason was specific: *"the VISIBILITY-EXEMPT convention is carried in
//! COMMENTS BY DESIGN"*, so stripping there deletes the very thing the lint
//! reads. Nothing this lint matches on is a convention — [`MINTS`] and
//! [`FOREIGN_POOLS`] are both CODE spellings. Measured on the tree before the
//! stripper existed: two false positives, both prose. `state.rs::maintenance_viewer`
//! and `routes/claims.rs::find_claims_needing_embeddings` each carry a doc
//! comment explaining why the statement must NOT run on `state.db_pool` — the
//! correct reasoning, flagged as the defect it warns against. A lint that
//! punishes a call site for documenting its own hazard is worse than no lint.
//!
//! The stripper tracks string and char literals so a `"postgres://…"` DSN is
//! not mistaken for a line comment; `the_stripper_does_not_eat_code` pins that.
//!
//! `#[cfg(test)]` MODULES are removed too, by brace matching rather than by
//! truncating at the first occurrence — see `strip_cfg_test_modules` for the
//! measurement that forced that, and `the_cfg_test_strip_keeps_production_code`
//! for the pin.
//!
//! # KNOWN LIMITS, measured rather than assumed
//!
//! **(a) `maint.pool()` is not foreign.** The eleven `epigraph-cli` binaries
//! pass `maint.pool()` into their repo calls and are **not** hybrids:
//! `MaintenancePool::connect_to` builds its `ScopedPool` from the MAINTENANCE
//! DSN and attaches no separate pool, so `pool()` is `scoped.inner()` is the
//! privileged pool. This lint does not key on `MaintenancePool::viewer` for that
//! reason. If a future revision of `MaintenancePool` ever attaches a second
//! pool, that assumption dies and this paragraph is the thing to re-measure.
//!
//! **(b) A MINT AND A SPEND IN DIFFERENT FUNCTIONS — OR DIFFERENT FILES — ARE
//! INVISIBLE TO THIS SCANNER, AND THAT IS WHERE THE LARGEST RESIDUAL LIVES.**
//! [`scan`] keys on one function-sized region containing BOTH a [`MINTS`]
//! spelling and a [`FOREIGN_POOLS`] one. A function that mints and hands the
//! `&Viewer` to a callee that runs the statements elsewhere matches neither
//! half anywhere. **Measured instance:** `epigraph-mcp/src/server.rs`'s three
//! maintenance tools mint through `maintenance_viewer(` and pass the viewer
//! into `crates/epigraph-mcp/src/tools/`, whose statements run on
//! `server.pool`. No file under `crates/epigraph-mcp/src` that names
//! `server.pool` also carries a [`MINTS`] spelling, so the `"server.pool"` entry
//! in [`FOREIGN_POOLS`] contributes **zero** detections today and a reader of
//! this file alone would wrongly conclude that surface is covered.
//!
//! Those three sites are NOT in [`EXPECTED_HYBRIDS`], deliberately: [`scan`]
//! cannot find them, so registering them would put them in the `fixed` set and
//! fail the second assertion of
//! `no_function_mints_a_bypass_and_names_a_foreign_pool` — a register can only
//! hold rows this scanner can confirm. The class IS recorded elsewhere:
//! `no_unmaintained_dsn.rs`'s register carries `epigraph-mcp/src/main.rs` with
//! the reasoning, `main.rs` documents it, and `EpiGraphMcpFull::with_scoped_pool`
//! has no production caller, so `maintenance_viewer` fails CLOSED there today.
//! Owner for closing the gap: `D-PR17-hybrid-shape-lint`.
//!
//! **(c) Passing a `MaintenanceSession` into a callee has the same shape as
//! (b).** A helper taking `&mut MaintenanceSession`
//! and a pool handle contains no [`MINTS`] spelling in its own region. The type
//! is new in this batch and is designed to be handed around as one value, so the
//! ergonomics win and this blind spot are the same change. Recorded rather than
//! left for the next reader to discover.
//!
//! # A RATCHET WITH A NAMED RESIDUE, not an invariant
//!
//! [`EXPECTED_HYBRIDS`] is asserted as an EXACT SET in both directions **over
//! what this function-granular scanner keys on**: an unregistered same-region
//! hybrid fails the build, and a registered one that has been fixed also fails,
//! so the register cannot rot into a licence. Same shape as
//! `no_inline_sql_in_tools.rs`'s `EXPECTED_INLINE_SQL`. It is not a statement
//! about hybrids in general — limits (b) and (c) above bound it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Spellings that mint a bypass `Viewer` in a production body.
///
/// `ScopedPool::maintenance_session` is the single mint inside `epigraph-db`
/// and the three wrappers route through it, so keying on the wrapper names plus
/// the raw `Viewer::system(` covers every production site that can hold one.
const MINTS: &[&str] = &[
    "Viewer::system(",
    "maintenance_viewer(",
    "maintenance_session(",
];

/// Pool handles that are NOT derived from a maintenance connection.
///
/// Each is a field or accessor on a long-lived application object. A
/// `MaintenanceConn`, a `MaintenanceSession`, a `ScopedTx` begun on one, and
/// `maint.pool()` are all absent from this list on purpose — see the module
/// doc's known limit.
const FOREIGN_POOLS: &[&str] = &[
    "self.pool",
    "self.db_pool",
    "state.db_pool",
    "server.pool",
    "app.db_pool",
];

/// Crates whose `src/` is scanned. `epigraph-db` itself is included: the mint
/// lives there, and a repo module that minted and spent one would be the worst
/// version of this.
const SCAN_ROOTS: &[&str] = &[
    "../epigraph-api/src",
    "../epigraph-cli/src",
    "../epigraph-db/src",
    "../epigraph-embeddings/src",
    "../epigraph-engine/src",
    "../epigraph-ingest-executor/src",
    "../epigraph-jobs/src",
    "../epigraph-mcp/src",
];

/// The hybrids that exist today, as `(path suffix, function name)`.
///
/// `db_reputation_service.rs::get_claim_outcomes` mints a bypass viewer from
/// the privileged pool and then runs the read on an injected `PgPool`. It has
/// no production constructor — `DbReputationService::new` and
/// `::with_scoped_pool` have no caller outside their own file — which is the
/// only reason it is a register entry rather than a live defect. Owner:
/// `D-PR17-hybrid-shape-lint`, re-owned by PR-17 to the `acquire_as`
/// conversion PR.
///
/// Fixing it means routing the read onto the maintenance connection, which is a
/// signature change to a public struct and therefore not this batch's to make.
const EXPECTED_HYBRIDS: &[(&str, &str)] = &[(
    "epigraph-jobs/src/db_reputation_service.rs",
    "get_claim_outcomes",
)];

/// Remove comments, leaving code positions otherwise intact.
///
/// Line and block comments both go. String and char literals are tracked so a
/// DSN like `"postgres://host/db"` does not read as a line comment and take the
/// rest of the line with it — which would silently delete real matches.
fn strip_comments(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    let mut in_str = false;
    let mut in_char = false;
    let mut block_depth = 0usize;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if block_depth > 0 {
            if c == '/' && next == Some('*') {
                block_depth += 1;
                i += 2;
                continue;
            }
            if c == '*' && next == Some('/') {
                block_depth -= 1;
                i += 2;
                continue;
            }
            if c == '\n' {
                out.push('\n');
            }
            i += 1;
            continue;
        }
        if in_str {
            out.push(c);
            if c == '\\' {
                if let Some(n) = next {
                    out.push(n);
                }
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if in_char {
            out.push(c);
            if c == '\\' {
                if let Some(n) = next {
                    out.push(n);
                }
                i += 2;
                continue;
            }
            if c == '\'' {
                in_char = false;
            }
            i += 1;
            continue;
        }
        if c == '/' && next == Some('/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            block_depth = 1;
            i += 2;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        // A lifetime (`'a`) is not a char literal. Only treat `'` as opening one
        // when the character two ahead closes it or an escape follows.
        if c == '\'' && (b.get(i + 2) == Some(&'\'') || next == Some('\\')) {
            in_char = true;
            out.push(c);
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Remove `#[cfg(test)]` MODULES, and only those.
///
/// # Why not `src.split("#[cfg(test)]").next()`
///
/// That was the first version and it is wrong in the direction that certifies a
/// broken tree as clean: it keeps only the text BEFORE the first occurrence, so
/// a file whose `#[cfg(test)]` sits anywhere but the end loses all production
/// code after it. Measured across the eight scan roots: **125 files** carry a
/// `#[cfg(test)]` that is not in the final stretch, and
/// `epigraph-api/src/routes/agents.rs` carries one at 4% of the file — the
/// truncating version scanned 4% of it and reported a clean run.
///
/// This walks braces from the `mod NAME {` that follows the attribute and
/// removes exactly that block. A `#[cfg(test)]` on anything other than a module
/// — a helper fn, a field, an import — is deliberately LEFT IN the scan: over-
/// scanning can only produce a finding to triage, whereas under-scanning
/// produces silence.
fn strip_cfg_test_modules(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i..].starts_with(&['#', '[', 'c']) && src_at(&b, i, "#[cfg(test)]") {
            // Look ahead for `mod <name> {` with only whitespace, attributes and
            // visibility between. If it is not a module, fall through and keep it.
            if let Some(open) = module_open_brace(&b, i + "#[cfg(test)]".len()) {
                let mut depth = 0usize;
                let mut j = open;
                let mut in_str = false;
                while j < b.len() {
                    let c = b[j];
                    if in_str {
                        if c == '\\' {
                            j += 2;
                            continue;
                        }
                        if c == '"' {
                            in_str = false;
                        }
                    } else if c == '"' {
                        in_str = true;
                    } else if c == '{' {
                        depth += 1;
                    } else if c == '}' {
                        depth -= 1;
                        if depth == 0 {
                            j += 1;
                            break;
                        }
                    }
                    j += 1;
                }
                // Preserve line structure so `regions` still splits sanely.
                for c in &b[i..j] {
                    if *c == '\n' {
                        out.push('\n');
                    }
                }
                i = j;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn src_at(b: &[char], i: usize, needle: &str) -> bool {
    let n: Vec<char> = needle.chars().collect();
    b.len() >= i + n.len() && b[i..i + n.len()] == n[..]
}

/// From just after a `#[cfg(test)]`, the index of the `{` that opens the module
/// it annotates — or `None` if it annotates something that is not a module.
fn module_open_brace(b: &[char], mut i: usize) -> Option<usize> {
    while i < b.len() {
        let c = b[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if src_at(b, i, "pub(crate) ") {
            i += "pub(crate) ".len();
            continue;
        }
        if src_at(b, i, "pub ") {
            i += "pub ".len();
            continue;
        }
        if src_at(b, i, "mod ") {
            let mut j = i + "mod ".len();
            while j < b.len() && b[j] != '{' && b[j] != ';' {
                j += 1;
            }
            return (b.get(j) == Some(&'{')).then_some(j);
        }
        return None;
    }
    None
}

/// A function-sized region of a source file: its name, and its body text.
struct Region {
    name: String,
    body: String,
}

/// Split a Rust source file into function-sized regions.
///
/// Text, not AST, and the module doc says why that is acceptable here. A region
/// runs from one `fn` header line to the next, so a nested `fn` starts a new
/// region and its enclosing tail is attributed to the nested one. That can only
/// SPLIT a body, never merge two — so it can lose a finding whose mint and
/// spend straddle a nested `fn`, and it cannot invent one.
fn regions(src: &str) -> Vec<Region> {
    let mut out: Vec<Region> = Vec::new();
    let mut current: Option<Region> = None;
    for line in src.lines() {
        if let Some(name) = fn_name(line) {
            if let Some(r) = current.take() {
                out.push(r);
            }
            current = Some(Region {
                name,
                body: String::new(),
            });
        }
        if let Some(r) = current.as_mut() {
            r.body.push_str(line);
            r.body.push('\n');
        }
    }
    if let Some(r) = current.take() {
        out.push(r);
    }
    out
}

/// The function name on a `fn` header line, if the line is one.
fn fn_name(line: &str) -> Option<String> {
    let t = line.trim_start();
    let rest = t
        .strip_prefix("pub(crate) ")
        .or_else(|| t.strip_prefix("pub(super) "))
        .or_else(|| t.strip_prefix("pub "))
        .unwrap_or(t);
    let rest = rest.strip_prefix("const ").unwrap_or(rest);
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    let rest = rest.strip_prefix("unsafe ").unwrap_or(rest);
    let rest = rest.strip_prefix("fn ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn rust_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
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

/// `crates/<crate>/src/...` suffix of a path, for stable register keys.
fn key_for(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    s.split_once("crates/").map_or_else(
        || s.trim_start_matches("../").to_string(),
        |(_, rest)| rest.to_string(),
    )
}

/// Every production region that mints a bypass and names a foreign pool handle.
fn scan() -> BTreeSet<(String, String)> {
    let mut found = BTreeSet::new();
    for root in SCAN_ROOTS {
        let mut files = Vec::new();
        rust_files(Path::new(root), &mut files);
        for f in files {
            let src = strip_comments(&std::fs::read_to_string(&f).expect("read source"));
            // `#[cfg(test)]` bodies are excluded: a test that stands a pool in
            // for a maintenance one is a fixture choice, not a production path,
            // and the production half is what this lint is about.
            let prod = strip_cfg_test_modules(&src);
            for r in regions(&prod) {
                let mints = MINTS.iter().any(|m| r.body.contains(m));
                if !mints {
                    continue;
                }
                if FOREIGN_POOLS.iter().any(|p| r.body.contains(p)) {
                    found.insert((key_for(&f), r.name));
                }
            }
        }
    }
    found
}

/// No production function may mint a bypass viewer and spend it on a pool that
/// is not the maintenance one, except the registered residue.
#[test]
fn no_function_mints_a_bypass_and_names_a_foreign_pool() {
    let found = scan();
    let expected: BTreeSet<(String, String)> = EXPECTED_HYBRIDS
        .iter()
        .map(|(f, n)| ((*f).to_string(), (*n).to_string()))
        .collect();

    let unregistered: Vec<_> = found.difference(&expected).collect();
    assert!(
        unregistered.is_empty(),
        "these functions mint a bypass Viewer and also name an application pool \
         handle. A bypass viewer emits no SQL predicate, so once RLS is FORCEd \
         it returns ZERO rows on a connection the policy applies to — a wrong \
         answer with no error. Route the statement onto the maintenance \
         connection (`MaintenanceSession::split`), or add a row to \
         EXPECTED_HYBRIDS with an owner. Unregistered: {unregistered:?}"
    );

    let fixed: Vec<_> = expected.difference(&found).collect();
    assert!(
        fixed.is_empty(),
        "these rows are in EXPECTED_HYBRIDS but no longer scan as hybrids. If \
         they were fixed, DELETE the row in the same commit — a register that \
         keeps entries for code that no longer matches is how a ratchet decays \
         into a licence. Stale: {fixed:?}"
    );
}

/// The scanner is not vacuous, in BOTH directions.
///
/// A scanner that matched nothing would satisfy the test above perfectly, and a
/// scanner whose FOREIGN_POOLS list matched nothing in the tree would too. Each
/// arm below fails if the corresponding population empties out.
#[test]
fn the_scanner_is_not_vacuous() {
    let mut minting_regions = 0usize;
    let mut foreign_pool_regions = 0usize;
    let mut files_seen = 0usize;
    for root in SCAN_ROOTS {
        let mut files = Vec::new();
        rust_files(Path::new(root), &mut files);
        files_seen += files.len();
        for f in files {
            let src = strip_comments(&std::fs::read_to_string(&f).expect("read source"));
            let prod = strip_cfg_test_modules(&src);
            for r in regions(&prod) {
                if MINTS.iter().any(|m| r.body.contains(m)) {
                    minting_regions += 1;
                }
                if FOREIGN_POOLS.iter().any(|p| r.body.contains(p)) {
                    foreign_pool_regions += 1;
                }
            }
        }
    }
    assert!(
        files_seen > 200,
        "the scan roots resolved to {files_seen} files; the lint is looking at \
         the wrong directory"
    );
    assert!(
        minting_regions >= 5,
        "only {minting_regions} regions mint a bypass. If the mint spellings in \
         MINTS ever go stale the whole lint passes by matching nothing."
    );
    // DELIBERATELY LOW, and not a ratchet. COMPLETION-PLAN 2.1's conversion tail
    // exists to drive `state.db_pool` uses toward zero, so a floor set at
    // today's count would fail a CORRECT tree partway through that work — the
    // failure mode the tenancy recon brief opens by warning about. Five is a
    // number the conversion cannot cross while any application pool handle
    // remains named anywhere, which is all this arm needs to establish.
    assert!(
        foreign_pool_regions >= 5,
        "only {foreign_pool_regions} regions name a foreign pool handle. If \
         FOREIGN_POOLS goes stale the lint passes by matching nothing on the \
         other side."
    );
}

/// THE POSITIVE CONTROL the obligation names, asserted by NAME rather than by
/// absence from a list.
///
/// `routes/claims.rs::find_claims_needing_embeddings` WAS an instance of this
/// shape and PR-15 fixed it; nothing would have caught the regression, because
/// `routes/` is an explicit non-root of the construction lint. It must stay
/// clean, and "it is not in `scan()`" is a weaker statement than it looks —
/// a broken scanner satisfies it too. So this asserts the two halves directly:
/// the function still mints, and it still spends on the maintenance connection.
#[test]
fn the_positive_control_is_still_clean() {
    let src = strip_comments(include_str!("../../epigraph-api/src/routes/claims.rs"));
    let region = regions(&src)
        .into_iter()
        .find(|r| r.name == "find_claims_needing_embeddings")
        .expect("routes/claims.rs must still define find_claims_needing_embeddings");
    assert!(
        MINTS.iter().any(|m| region.body.contains(m)),
        "CALIBRATION: the positive control must still MINT a bypass. If it \
         stopped, this test is passing for the wrong reason and the lint has no \
         clean case to calibrate against."
    );
    assert!(
        region.body.contains("session.split()"),
        "the positive control must spend its bypass on the maintenance \
         connection. `split` is the only accessor that yields the connection \
         and the viewer together."
    );
    assert!(
        !FOREIGN_POOLS.iter().any(|p| region.body.contains(p)),
        "the positive control has regressed to an application pool handle"
    );
    assert!(
        !scan().contains(&(
            "epigraph-api/src/routes/claims.rs".to_string(),
            "find_claims_needing_embeddings".to_string()
        )),
        "and the scanner agrees"
    );
}

/// THE NEGATIVE CONTROL the obligation names, asserted by NAME.
///
/// The register entry must correspond to a function the scanner actually finds.
/// A register row pointing at nothing is how this lint would quietly stop
/// having a calibration case at all.
#[test]
fn the_registered_hybrid_is_really_there() {
    let src = strip_comments(include_str!(
        "../../epigraph-jobs/src/db_reputation_service.rs"
    ));
    let region = regions(&src)
        .into_iter()
        .find(|r| r.name == "get_claim_outcomes")
        .expect("db_reputation_service.rs must still define get_claim_outcomes");
    assert!(
        MINTS.iter().any(|m| region.body.contains(m)),
        "CALIBRATION: the registered hybrid must still mint a bypass"
    );
    assert!(
        FOREIGN_POOLS.iter().any(|p| region.body.contains(p)),
        "CALIBRATION: the registered hybrid must still name a foreign pool \
         handle. If it does not, the row belongs in a DELETE, not here."
    );
}

/// The comment stripper must not eat code, and must not leave prose behind.
///
/// Both directions matter. A stripper that ate too much would delete real
/// matches and make the whole lint pass by seeing nothing; a stripper that ate
/// too little would reinstate the two prose false positives the module doc
/// records. The `postgres://` case is the one that motivates tracking string
/// literals at all: a naive `//` scan takes the rest of that line with it.
#[test]
fn the_stripper_does_not_eat_code() {
    let src = r#"
fn sample() {
    // self.pool must never be used here
    let dsn = "postgres://user@host/db"; let a = &self.pool;
    /* block: state.db_pool */
    let b = 'x';
    let _ = (dsn, a, b);
}
"#;
    let out = strip_comments(src);
    assert!(
        out.contains("&self.pool"),
        "the code occurrence survived stripping; got:\n{out}"
    );
    assert!(
        out.contains("postgres://user@host/db"),
        "a DSN inside a string literal must not be read as a line comment, or \
         everything after it on that line is silently deleted; got:\n{out}"
    );
    assert_eq!(
        out.matches("self.pool").count(),
        1,
        "the comment occurrence must be gone and the code one must remain; \
         got:\n{out}"
    );
    assert!(
        !out.contains("state.db_pool"),
        "a block comment must be stripped too; got:\n{out}"
    );
    assert!(
        out.lines().count() >= src.lines().count() - 1,
        "stripping must preserve line structure so a future line-numbered \
         report stays honest"
    );
}

/// The `#[cfg(test)]` strip must remove the test module and KEEP the production
/// code that follows it.
///
/// This is the pin on the measurement in `strip_cfg_test_modules`' own doc. The
/// first version of this lint truncated at the first `#[cfg(test)]`, and 125
/// files under the scan roots carry one that is not at the end — one of them at
/// 4% of the file. Under-scanning is invisible: the lint reports clean and the
/// non-vacuity floors still pass, because they count what survives the strip.
#[test]
fn the_cfg_test_strip_keeps_production_code() {
    let src = r#"
fn before() { let _ = &self.pool; }

#[cfg(test)]
mod tests {
    fn helper() { let _ = &self.pool; }
    fn nested() { if true { let _ = 1; } }
}

fn after() { Viewer::system(&lease, r); let _ = &state.db_pool; }
"#;
    let out = strip_cfg_test_modules(src);
    assert!(out.contains("fn before()"), "got:\n{out}");
    assert!(
        out.contains("fn after()") && out.contains("state.db_pool"),
        "PRODUCTION CODE AFTER THE TEST MODULE MUST SURVIVE. This is the whole \
         reason the strip is brace-matched instead of a truncating split; \
         got:\n{out}"
    );
    assert!(
        !out.contains("fn helper()") && !out.contains("fn nested()"),
        "the whole test module must go, nested braces included; got:\n{out}"
    );
    // And the region splitter still finds the function after it.
    assert!(
        regions(&out).iter().any(|r| r.name == "after"),
        "regions() must still see the post-module function"
    );

    // A `#[cfg(test)]` on something that is NOT a module is deliberately left
    // in: over-scanning yields a finding to triage, under-scanning yields
    // silence.
    let attr_on_fn = "#[cfg(test)]\nfn only_in_tests() { let _ = &self.pool; }\n";
    assert!(
        strip_cfg_test_modules(attr_on_fn).contains("only_in_tests"),
        "a non-module #[cfg(test)] must not swallow anything"
    );
}
