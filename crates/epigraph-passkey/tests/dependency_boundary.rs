//! The dependency boundary of this crate (elevation plan EL-3, §1.8).
//!
//! `epigraph-passkey` links OpenSSL through webauthn-rs. It is reached from
//! `epigraph-api` only through the `db` feature, and it is NEVER a dependency
//! of `epigraph-mcp`, so the fleet MCP image and the stdio server stay free of
//! it. Both halves are pinned here with `cargo tree` over the checked-in
//! lockfile (`--locked`), as normal (non-dev, non-build) edges, which is what
//! a release binary links.
//!
//! The plan's original wording ("`--no-default-features` pulls no
//! openssl-sys") does not hold at the base: reqwest's native-tls already
//! brings openssl-sys into that tree. The invariant pinned instead is the one
//! this crate is responsible for: no webauthn crate and no `epigraph-passkey`.
//!
//! A `cargo tree` that fails is a test FAILURE, never an empty tree: an
//! unreadable graph must not read as a clean boundary. `--offline` is not
//! used: on a fresh CI runner the `--all-features` graph can name crates the
//! default build never downloaded.

use std::collections::BTreeSet;
use std::process::Command;

/// The package names of `cargo tree --locked -e normal <args>` over this
/// workspace, one per distinct package.
fn tree(args: &[&str]) -> BTreeSet<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let out = Command::new(&cargo)
        .args([
            "tree",
            "--locked",
            "-e",
            "normal",
            "--prefix",
            "none",
            "--manifest-path",
            manifest,
        ])
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {cargo} tree: {e}"));
    assert!(
        out.status.success(),
        "`cargo tree {}` failed ({}); an unreadable graph is not a clean boundary:\n{}",
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

/// The packages of `names` that belong to the passkey stack.
fn passkey_stack(names: &BTreeSet<String>) -> Vec<&String> {
    names
        .iter()
        .filter(|n| n.starts_with("webauthn") || n.as_str() == "epigraph-passkey")
        .collect()
}

/// `epigraph-api --no-default-features` links no part of the passkey stack;
/// with its default features (`db`) it does, which is the CALIBRATION: the
/// probe sees the stack where it is, so its absence below is a measurement.
///
/// Mutation: `epigraph-passkey` made a non-optional dependency of
/// `epigraph-api` -> the no-default tree contains it.
#[test]
fn the_api_reaches_the_passkey_stack_only_through_db() {
    let default = tree(&["-p", "epigraph-api"]);
    let found = passkey_stack(&default);
    assert!(
        found.iter().any(|n| n.as_str() == "epigraph-passkey")
            && found.iter().any(|n| n.as_str() == "webauthn-rs"),
        "CALIBRATION: the default epigraph-api tree must contain epigraph-passkey and \
         webauthn-rs, or the absence below proves nothing; found {found:?}"
    );

    let lean = tree(&["-p", "epigraph-api", "--no-default-features"]);
    assert!(
        lean.contains("epigraph-api"),
        "CALIBRATION: the tree is epigraph-api's"
    );
    let found = passkey_stack(&lean);
    assert!(
        found.is_empty(),
        "epigraph-api --no-default-features links the passkey stack: {found:?}"
    );
}

/// `epigraph-mcp`, under EVERY feature, links no part of the passkey stack:
/// the fleet image and the stdio server stay free of it.
///
/// Mutation: `epigraph-passkey` added as a dependency of `epigraph-mcp` -> the
/// tree contains it.
#[test]
fn the_mcp_server_never_links_the_passkey_stack() {
    let mcp = tree(&["-p", "epigraph-mcp", "--all-features"]);
    assert!(
        mcp.contains("epigraph-mcp"),
        "CALIBRATION: the tree is epigraph-mcp's"
    );
    let found = passkey_stack(&mcp);
    assert!(
        found.is_empty(),
        "epigraph-mcp (all features) links the passkey stack: {found:?}"
    );
}
