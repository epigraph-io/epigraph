//! The TLS stack links no `rustls-pemfile` (RUSTSEC-2025-0134, crate
//! unmaintained; backlog 8157bd62 item 3, operator ruling R-26).
//!
//! PEM parsing goes through `rustls-pki-types`' `PemObject` API, which is the
//! upstream replacement. `cargo audit` reports an unmaintained crate as a
//! warning that does NOT fail the job, so nothing else would notice if a
//! dependency brought `rustls-pemfile` back; this test is that ratchet.
//!
//! The graph is read with `cargo tree --locked` over the checked-in lockfile,
//! for the whole workspace under every feature (the `tls` feature of
//! `epigraph-api` is off by default) and over every edge kind, because
//! `cargo audit` scans every package of `Cargo.lock`. A `cargo tree` that fails
//! is a test FAILURE, never an empty tree: an unreadable graph must not read as
//! a clean boundary. `--offline` is not used: on a fresh CI runner the
//! `--all-features` graph can name crates the default build never downloaded.

use std::collections::BTreeSet;
use std::process::Command;

/// The package names of `cargo tree --locked -e all --workspace --all-features`.
fn workspace_tree() -> BTreeSet<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let args = [
        "tree",
        "--locked",
        "-e",
        "all",
        "--prefix",
        "none",
        "--workspace",
        "--all-features",
        "--manifest-path",
        manifest,
    ];
    let out = Command::new(&cargo)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {cargo} tree: {e}"));
    assert!(
        out.status.success(),
        "`cargo {}` failed ({}); an unreadable graph is not a clean boundary:\n{}",
        args.join(" "),
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("utf-8 tree")
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// No workspace crate, under any feature, links `rustls-pemfile`. The
/// CALIBRATION is that the same tree contains the TLS server stack
/// (`axum-server`) and the PEM parser that replaces it (`rustls-pki-types`),
/// so the absence is a measurement of the graph that loads PEM files.
///
/// Mutation: `axum-server` pinned back to 0.7 (whose `tls-rustls` feature
/// depends on `rustls-pemfile`) -> the tree contains it.
#[test]
fn the_tls_stack_links_no_rustls_pemfile() {
    let names = workspace_tree();
    assert!(
        names.contains("axum-server") && names.contains("rustls-pki-types"),
        "CALIBRATION: the all-features tree must contain axum-server and \
         rustls-pki-types, or the absence below proves nothing"
    );
    assert!(
        !names.contains("rustls-pemfile"),
        "rustls-pemfile (unmaintained, RUSTSEC-2025-0134) is linked again; parse \
         PEM through rustls-pki-types' PemObject API instead"
    );
}
