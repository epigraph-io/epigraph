//! This repository is PUBLIC. A wildcard-DNS hostname that ENCODES an IP
//! address names a specific machine, so committing one publishes where a
//! deployment lives.
//!
//! Services like `nip.io`, `sslip.io` and `xip.io` resolve a name of the shape
//! `a-b-c-d.<service>` to the address `a.b.c.d`. The name is therefore not a
//! placeholder — it IS the address, written in a form that reads like a
//! hostname and slips past review for exactly that reason. One such name
//! reached shipped source here in four files and three design documents,
//! entirely as doc-comment examples and test fixtures, which is precisely how
//! it went unnoticed: nothing read it at runtime, so nothing failed.
//!
//! # What this test does NOT cover, stated so it is not mistaken for completeness
//!
//! * **A bare IPv4 literal.** The tree legitimately contains many — `127.0.0.1`
//!   over two hundred times, plus RFC1918 and RFC5737 ranges used as fixtures by
//!   the SSRF and host-allowlist tests, which need real-looking addresses to
//!   refuse. Classifying those would need an allowlist large enough that the
//!   next genuine leak would be added to it rather than fixed.
//! * **An ordinary hostname.** `api.internal.example` is indistinguishable from
//!   a placeholder without knowing the deployment.
//!
//! So this is a narrow, zero-false-positive guard on the one shape that is
//! self-evidently an address. Use a reserved name from RFC 2606
//! (`example.com`, `.invalid`, `.test`) for documentation and fixtures.
//!
//! # Why the scanner cannot trip on itself
//!
//! The pattern is written with character classes (`[0-9]+`), not digits, so this
//! file's own source does not match it. The file is skipped anyway, and that
//! belt-and-braces is deliberate: a sentinel that must name the thing it forbids
//! is a sentinel that reintroduces it.

use std::path::{Path, PathBuf};

/// Directories whose contents are not ours to police.
const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".sqlx", ".claude"];

/// Extensions worth scanning. The leak appeared in both source and prose, so
/// scanning only `.rs` would have caught four of the seven affected files.
const SCAN_EXTS: &[&str] = &["rs", "md", "toml", "yml", "yaml", "sql", "json", "sh"];

fn repo_root() -> PathBuf {
    // tests/ -> epigraph-mcp/ -> crates/ -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/<crate>/ is two levels below the repo root")
        .to_path_buf()
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !SKIP_DIRS.contains(&name.as_ref()) {
                collect(&path, out);
            }
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| SCAN_EXTS.contains(&e))
        {
            out.push(path);
        }
    }
}

/// `true` if `line` contains `<digits>-<digits>-<digits>-<digits>.<service>`.
///
/// Hand-rolled rather than a regex dependency: this crate has none, and adding
/// one to a test that exists to stop a string from being committed would be a
/// poor trade.
fn encodes_an_address(line: &str, service: &str) -> bool {
    for (idx, _) in line.match_indices(service) {
        let before = &line[..idx];
        // Walk back over exactly four dash-separated runs of digits.
        let mut rest = before;
        let mut groups = 0;
        loop {
            let digits: &str = rest.trim_end_matches(|c: char| !c.is_ascii_digit());
            if digits.len() != rest.len() {
                break; // the char immediately before `service` was not a digit
            }
            let start = rest
                .rfind(|c: char| !c.is_ascii_digit())
                .map_or(0, |i| i + 1);
            if start == rest.len() {
                break; // no digits here
            }
            groups += 1;
            rest = &rest[..start];
            if groups == 4 {
                return true;
            }
            if !rest.ends_with('-') {
                break;
            }
            rest = &rest[..rest.len() - 1];
        }
    }
    false
}

/// Wildcard-DNS suffixes that resolve an encoded address.
const WILDCARD_DNS: &[&str] = &[".nip.io", ".sslip.io", ".xip.io"];

#[test]
fn no_wildcard_dns_hostname_encodes_a_deployment_address() {
    let root = repo_root();
    let mut files = Vec::new();
    collect(&root, &mut files);

    // Non-vacuity floor. A scanner that stopped walking, or whose root moved,
    // would otherwise pass over an empty set and report safety it never checked.
    assert!(
        files.len() > 300,
        "expected the walk to reach the whole repository, found only {} files \
         under {} — the scanner is probably rooted in the wrong place and would \
         pass vacuously",
        files.len(),
        root.display()
    );

    let this_file = Path::new(file!()).file_name().unwrap_or_default();
    let mut hits = Vec::new();

    for path in &files {
        if path.file_name().unwrap_or_default() == this_file {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        for (n, line) in src.lines().enumerate() {
            for service in WILDCARD_DNS {
                if encodes_an_address(line, service) {
                    let rel = path.strip_prefix(&root).unwrap_or(path);
                    hits.push(format!("  {}:{}", rel.display(), n + 1));
                }
            }
        }
    }

    assert!(
        hits.is_empty(),
        "\n\nA wildcard-DNS hostname encoding an IP address is committed to this \
         PUBLIC repository:\n{}\n\n\
         That name resolves to the address it spells, so it publishes where a \
         deployment lives. Replace it with a reserved name — RFC 2606 gives you \
         `example.com`, `.invalid` and `.test` — and put the real value in \
         configuration. `ApiConfig::public_base_url` and the MCP listener's \
         `--allowed-host` already take it at run time; neither needs a literal \
         in source.\n",
        hits.join("\n")
    );
}

#[test]
fn the_scanner_recognises_the_shape_it_is_looking_for() {
    // Non-vacuity in the other direction: prove the matcher fires, so a green
    // result above means "nothing found" rather than "nothing can be found".
    // These are synthesised here and are not deployment addresses.
    assert!(encodes_an_address(
        "https://192-0-2-1.nip.io/mcp",
        ".nip.io"
    ));
    assert!(encodes_an_address(
        "  host = \"198-51-100-7.sslip.io\"",
        ".sslip.io"
    ));
    assert!(encodes_an_address("203-0-113-9.xip.io", ".xip.io"));

    // And that it does not fire on a name that merely mentions the service,
    // which is what lets this file's own prose discuss the hazard.
    assert!(!encodes_an_address(
        "see the nip.io wildcard service",
        ".nip.io"
    ));
    assert!(!encodes_an_address("https://mcp.example.com", ".nip.io"));
    assert!(!encodes_an_address("a-b-c-d.nip.io", ".nip.io"));
}
