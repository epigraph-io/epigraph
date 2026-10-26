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

/// Advisory floors held only by `Cargo.lock` (backlog 8157bd62 item 1,
/// operator ruling R-26): `(crate, first fixed release, advisories)`. Each
/// floor applies to its semver-compatible series only, so the
/// `webpki-roots` 0.26 compatibility shim (which re-exports 1.x) is not held
/// to a 1.x floor, and a stale copy of the series cannot hide beside a fixed
/// one.
const LOCK_FLOORS: &[(&str, &str, &str)] = &[
    ("rustls", "0.23.46", "RUSTSEC-2026-0346..0349"),
    ("rustls-webpki", "0.103.16", "RUSTSEC-2026-0382"),
    ("webpki-roots", "1.0.10", "RUSTSEC-2026-0381"),
];

/// `(name, version)` of every `[[package]]` in the checked-in `Cargo.lock`.
fn locked_packages() -> Vec<(String, String)> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock");
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let field = |line: &str, key: &str| {
        line.strip_prefix(key)
            .and_then(|v| v.strip_prefix(" = \""))
            .and_then(|v| v.strip_suffix('"'))
            .map(str::to_string)
    };
    let mut out = Vec::new();
    for block in text.split("[[package]]").skip(1) {
        let mut name = None;
        let mut version = None;
        for line in block.lines() {
            name = name.or_else(|| field(line, "name"));
            version = version.or_else(|| field(line, "version"));
        }
        if let (Some(n), Some(v)) = (name, version) {
            out.push((n, v));
        }
    }
    out
}

/// `major.minor.patch` (pre-release and build metadata dropped).
fn triple(v: &str) -> (u64, u64, u64) {
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let mut it = core
        .split('.')
        .map(|p| p.parse::<u64>().unwrap_or_else(|_| panic!("version {v}")));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// The semver-compatible series of a version: the major for >=1, the minor
/// for 0.y (cargo's caret rule).
fn series(v: (u64, u64, u64)) -> (u64, u64) {
    if v.0 == 0 {
        (0, v.1)
    } else {
        (v.0, u64::MAX)
    }
}

/// Every locked copy of `rustls`, `rustls-webpki` and `webpki-roots` in the
/// fixed series sits at or above the release that fixed its advisories, so
/// a lockfile regeneration or a dependency pinning an older patch fails a
/// BLOCKING test (the `cargo audit` job is advisory and can already be red
/// for unrelated advisories). CALIBRATION: each floor's series must be in the
/// lock, or the floor would hold vacuously.
///
/// Mutation: `Cargo.lock` from before the bump (rustls 0.23.45, rustls-webpki
/// 0.103.15, webpki-roots 1.0.8) -> all three are named.
#[test]
fn the_lockfile_holds_the_tls_advisory_floors() {
    let locked = locked_packages();
    let mut violations = Vec::new();
    for (krate, floor, advisories) in LOCK_FLOORS {
        let floor_v = triple(floor);
        let in_series: Vec<&String> = locked
            .iter()
            .filter(|(n, v)| n == krate && series(triple(v)) == series(floor_v))
            .map(|(_, v)| v)
            .collect();
        assert!(
            !in_series.is_empty(),
            "CALIBRATION: Cargo.lock has no {krate} in the series of {floor}; \
             re-derive the floor before trusting this ratchet"
        );
        for v in in_series {
            if triple(v) < floor_v {
                violations.push(format!("{krate} {v} < {floor} ({advisories})"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Cargo.lock regressed below a TLS advisory floor: {}",
        violations.join("; ")
    );
}
