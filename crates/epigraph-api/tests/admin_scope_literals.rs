//! The admin-only scope LITERAL ratchet (elevation plan EL-10, §1.7).
//!
//! Every scope decision goes through ONE check chokepoint,
//! `epigraph_auth::AuthContext::has_scope`, which treats the admin-only
//! scopes as absent on an unelevated request once the admin-scope switch is
//! armed. Three static rules keep it the only one, over the source of
//! `epigraph-api`, `epigraph-mcp` and `epigraph-auth` (the gate module,
//! `epigraph-auth/src/lib.rs`, aside):
//!
//! 1. The number of admin-only scope string literals (`"claims:admin"`,
//!    `"clients:admin"`, `"entity-types:write"`, `"groups:admin"`,
//!    `"instance:admin"`) may only go DOWN ([`HIGH_WATER`]). A new one is
//!    usually a new admin decision: name it through the chokepoint, and lower
//!    nothing here unless one went away.
//! 2. No code reads a field named `scopes` with `.contains(` or
//!    `.iter().any(`: that is a scope decision that skips the chokepoint (it
//!    would honour a standing admin scope on an armed database). The client
//!    record's `granted_scopes` / `allowed_scopes` are not a request's scopes
//!    and are not matched.
//! 3. Every `issue_access_token(` call in `epigraph-api` sits in a file that
//!    builds its scopes through the mint chokepoint (`scopes::grantable(`) at
//!    least as many times (EL-9 hand-off: no structural rule forced a seventh
//!    mint site through it).
//!
//! Each rule names the planted regression it was run against.

use std::path::{Path, PathBuf};

/// The admin-only scope literals counted (`epigraph_core::canonical_scopes::ADMIN_ONLY_SCOPES`).
const ADMIN_ONLY: &[&str] = &[
    "claims:admin",
    "clients:admin",
    "entity-types:write",
    "groups:admin",
    "instance:admin",
];

/// The measured count at the commit that introduced this ratchet (EL-10).
/// Lower it when a literal goes away; never raise it.
const HIGH_WATER: usize = 73;

/// The gate module: the chokepoint itself spells the scopes.
const GATE: &str = "epigraph-auth/src/lib.rs";

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
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

/// `(crate-relative display path, source)` for every `src` file of the three
/// crates, the gate module aside.
fn sources() -> Vec<(String, String)> {
    let mut files = Vec::new();
    for c in ["epigraph-api", "epigraph-mcp", "epigraph-auth"] {
        rust_files(&crates_dir().join(c).join("src"), &mut files);
    }
    let mut out: Vec<(String, String)> = files
        .into_iter()
        .map(|p| {
            let shown = p
                .strip_prefix(crates_dir())
                .unwrap_or(&p)
                .display()
                .to_string();
            let src = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{shown}: {e}"));
            (shown, src)
        })
        .filter(|(shown, _)| !shown.ends_with(GATE))
        .collect();
    out.sort();
    out
}

fn literal_count(src: &str) -> usize {
    ADMIN_ONLY
        .iter()
        .map(|s| src.matches(&format!("\"{s}\"")).count())
        .sum()
}

/// Rule 1. Verified to fail with one more `"claims:admin"` literal planted in
/// `epigraph-api/src/middleware/scopes.rs` (the count rises above the high
/// water).
#[test]
fn admin_only_scope_literals_only_go_down() {
    let sources = sources();
    assert!(
        sources.len() > 100,
        "CALIBRATION: the scan found {} files; it is not reading the crates",
        sources.len()
    );
    let per_file: Vec<(String, usize)> = sources
        .iter()
        .map(|(f, s)| (f.clone(), literal_count(s)))
        .filter(|(_, n)| *n > 0)
        .collect();
    let total: usize = per_file.iter().map(|(_, n)| n).sum();
    assert!(
        total <= HIGH_WATER,
        "{total} admin-only scope literals (high water {HIGH_WATER}): a new admin decision \
         must go through the check chokepoint (AuthContext::has_scope), not spell the scope \
         again. Per file: {per_file:?}"
    );
    assert!(
        total == HIGH_WATER,
        "{total} admin-only scope literals, below the high water {HIGH_WATER}: lower \
         HIGH_WATER to {total} so the ratchet holds what was won"
    );
}

/// The position of every direct read of a field named exactly `scopes` with
/// `.contains(` or `.iter().any(` in `src`.
fn direct_scope_reads(src: &str) -> Vec<usize> {
    let mut hits = Vec::new();
    for (i, _) in src.match_indices(".scopes") {
        let after = &src[i + ".scopes".len()..];
        let rest: String = after
            .chars()
            .filter(|c| !c.is_whitespace())
            .take(20)
            .collect();
        if rest.starts_with(".contains(") || rest.starts_with(".iter().any(") {
            hits.push(i);
        }
    }
    hits
}

/// Rule 2. Verified to fail with `auth.scopes.contains(&"claims:admin".to_string())`
/// planted in `epigraph-mcp/src/server.rs` (and the scanner's own calibration
/// below).
#[test]
fn no_scope_decision_skips_the_chokepoint() {
    assert_eq!(
        direct_scope_reads(
            "x = auth.scopes . iter() . any(|s| s == y); z = c.granted_scopes.contains(&w);"
        )
        .len(),
        1,
        "CALIBRATION: the scanner finds a direct read and skips granted_scopes"
    );
    let offenders: Vec<String> = sources()
        .iter()
        .filter(|(_, s)| !direct_scope_reads(s).is_empty())
        .map(|(f, s)| format!("{f} ({} reads)", direct_scope_reads(s).len()))
        .collect();
    assert!(
        offenders.is_empty(),
        "a request's scopes are read directly, skipping AuthContext::has_scope (the check \
         chokepoint): {offenders:?}"
    );
}

/// Rule 3. Verified to fail with one `scopes::grantable(` call in
/// `oauth/token.rs` replaced by the client's `granted_scopes`.
#[test]
fn every_mint_site_takes_its_scopes_from_the_mint_chokepoint() {
    let mut mints = 0;
    for (f, s) in sources()
        .iter()
        .filter(|(f, _)| f.starts_with("epigraph-api"))
    {
        let minted = s.matches("issue_access_token(").count();
        let chosen = s.matches("scopes::grantable(").count();
        mints += minted;
        assert!(
            minted <= chosen,
            "{f} mints {minted} token(s) but builds scopes through \
             oauth::scopes::grantable only {chosen} time(s): every grant's scopes go through \
             the mint chokepoint (it strips admin-only scopes once armed)"
        );
    }
    assert!(mints >= 5, "CALIBRATION: only {mints} mint sites found");
}
