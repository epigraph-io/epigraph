//! The zstd binding that `epigraph-db` uses for agent prompt-history blobs
//! (migration 161, `AgentIdentityRepository`) is locked at or above the
//! releases that fixed RUSTSEC-2026-0391 (`zstd`) and RUSTSEC-2026-0398 /
//! RUSTSEC-2026-0403 (`zstd-safe`) (backlog 52cb2c4f, operator ruling R-93).
//!
//! The `cargo audit` CI job is advisory (`continue-on-error`) and can already
//! be red for an unrelated advisory, so a lockfile regeneration or a
//! dependency that pinned the old binding back would go unnoticed there. This
//! test reads the checked-in `Cargo.lock` and fails a BLOCKING job instead.
//!
//! Unlike the TLS floors in `epigraph-api/tests/tls_dependency_boundary.rs`,
//! these floors are not per semver series: the fixes shipped only in new
//! series (`zstd` 0.14, `zstd-safe` 8), with no backport to `zstd` 0.13 or
//! `zstd-safe` 7, so EVERY locked copy of either crate, in any series, must
//! sit at or above its floor. A stale 0.13 copy beside a fixed 0.14 one is a
//! violation, not a pass.

/// `(crate, first fixed release, advisories)`.
const ZSTD_FLOORS: &[(&str, &str, &str)] = &[
    ("zstd", "0.14.3", "RUSTSEC-2026-0391"),
    ("zstd-safe", "8.2.0", "RUSTSEC-2026-0398, RUSTSEC-2026-0403"),
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

/// Every locked `zstd` is >= 0.14.3 and every locked `zstd-safe` is >= 8.2.0.
/// CALIBRATION: both crates must be in the lock (`epigraph-db` depends on
/// `zstd` directly), or the floors would hold vacuously.
///
/// Mutation: `Cargo.lock` from before the bump (zstd 0.13.3, zstd-safe
/// 7.3.0) -> both are named.
#[test]
fn the_lockfile_holds_the_zstd_advisory_floors() {
    let locked = locked_packages();
    let mut violations = Vec::new();
    for (krate, floor, advisories) in ZSTD_FLOORS {
        let floor_v = triple(floor);
        let copies: Vec<&String> = locked
            .iter()
            .filter(|(n, _)| n == krate)
            .map(|(_, v)| v)
            .collect();
        assert!(
            !copies.is_empty(),
            "CALIBRATION: Cargo.lock has no {krate}; epigraph-db links zstd \
             directly, so the lock parse is broken or the dependency moved"
        );
        for v in copies {
            if triple(v) < floor_v {
                violations.push(format!("{krate} {v} < {floor} ({advisories})"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Cargo.lock is below a zstd advisory floor: {}",
        violations.join("; ")
    );
}
