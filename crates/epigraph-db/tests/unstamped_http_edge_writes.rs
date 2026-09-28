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
//! are not in this register. None of the sites below holds a stamped
//! transaction where it writes; several handlers hold a `Viewer`, but their
//! other statements run on the raw pool too, and converting one statement of a
//! handler would leave it on two connections (the "whole handlers or nothing"
//! rule `no_unscoped_pool.rs` records). Stamping them is a follow-up.
//!
//! # The register (per site, at this commit)
//!
//! | file | handler | endpoints -> relationship | in D8 scope |
//! |---|---|---|---|
//! | assess.rs | assess_claim | claim -> frame WITHIN_FRAME | no |
//! | assess.rs | assess_claim | evidence -> claim SUPPORTS | yes |
//! | assess.rs | assess_claim | evidence -> claim CONTRADICTS | yes |
//! | belief.rs | submit_evidence | claim -> context SCOPED_BY | no |
//! | belief.rs | submit_evidence | claim -> frame WITHIN_FRAME | no |
//! | belief.rs | submit_evidence | evidence -> claim SUPPORTS | yes |
//! | belief.rs | submit_evidence | evidence -> claim CONTRADICTS | yes |
//! | belief.rs | submit_evidence | evidence -> agent GENERATED_BY | no |
//! | belief.rs | submit_evidence | perspective -> claim CONTRIBUTES_TO | no |
//! | claims.rs | create_claim | agent -> claim AUTHORED | no |
//! | claims.rs | create_claim | claim -> trace HAS_TRACE | no |
//! | claims.rs | create_claim | claim -> evidence DERIVED_FROM | yes |
//! | community.rs | add_member | perspective -> community MEMBER_OF | no |
//! | conventions.rs | learn_convention | agent -> claim AUTHORED | no |
//! | conventions.rs | learn_convention | evidence -> claim SUPPORTS | yes |
//! | conventions.rs | learn_convention | trace -> claim TRACES | no |
//! | conventions.rs | learn_convention | claim -> trace HAS_TRACE | no |
//! | conventions.rs | forget_convention | evidence -> claim REFUTES | yes |
//! | conventions.rs | share_skill | claim -> claim SHARED_BY | yes |
//! | cross_source.rs | decide_candidate (promote) | claim -> claim (matcher) | yes |
//! | crud.rs | create_evidence | claim -> evidence DERIVED_FROM | yes |
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
//! # How a site is counted
//!
//! A code line (not a whole-line comment) of a non-test region of a file under
//! `crates/epigraph-api/src/routes` that names `EdgeRepository::create` (any
//! `create*` form), whose executor argument (the text up to the first comma
//! over that line and the next two) is the raw pool: `state.db_pool` or a
//! `pool` alias. A file's `#[cfg(test)]` region is not scanned.

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
    ("conventions.rs", 6),
    ("cross_source.rs", 1),
    ("crud.rs", 2),
    ("perspective.rs", 1),
    ("provenance.rs", 4),
    ("spans.rs", 3),
];

/// The total the register may never exceed.
const HIGH_WATER: usize = 30;

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
    let dir = repo_root().join(ROUTES);
    let mut out = BTreeMap::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    entries.sort();
    for p in entries {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if name == "edges.rs" {
            // Converted by W12b; its remaining raw-pool sites are post-commit
            // side effects, registered in `no_unscoped_pool.rs`.
            continue;
        }
        let src = std::fs::read_to_string(&p).expect("read route file");
        let lines: Vec<&str> = src.lines().collect();
        let end = lines
            .iter()
            .position(|l| l.trim_start().starts_with("#[cfg(test)]"))
            .unwrap_or(lines.len());
        let mut n = 0usize;
        for i in 0..end {
            let l = lines[i];
            if l.trim_start().starts_with("//") || !l.contains("EdgeRepository::create") {
                continue;
            }
            let call: String = lines[i..(i + 3).min(end)].join(" ");
            let from = call.find("EdgeRepository::create").expect("present");
            if is_raw_pool_executor(&call[from..]) {
                n += 1;
            }
        }
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
