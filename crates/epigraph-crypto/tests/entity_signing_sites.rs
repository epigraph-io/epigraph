//! Ratchet: outside this crate, no source signs a raw message with `.sign(`;
//! entity signatures go through `AgentSigner::sign_entity` (ruling R-34,
//! backlog `1a79c4d9`).
//!
//! # Why
//!
//! The defect R-34 closed was a writer signing the BARE content digest
//! (`server.signer.sign(&content_hash)`), so a signature over one entity
//! type's hash verified as another type's. `sign_entity(kind, digest)` signs
//! the tagged v1 message instead. The verifiers still accept a legacy bare
//! digest for old rows, so a writer that slid back to `.sign(&hash)` would
//! keep "verifying" (reported `legacy`) and nothing would fail. This test is
//! what fails.
//!
//! # What it measures
//!
//! Every non-test source file under `crates/*/src` except `epigraph-crypto`
//! (whose `sign_entity` is built on `sign`), line by line, for a `.sign(`
//! call. Sites are keyed by `(file, enclosing fn)` with an exact count. Rust
//! line comments and `#[cfg(..test..)] mod` blocks are skipped. Every site
//! that remains is a signature over something OTHER than an entity digest,
//! registered with what it signs. A new site fails until it is either moved to
//! `sign_entity` or registered here with the reason it is not an entity
//! signature.
//!
//! # What it does not see
//!
//! A call spelled without `.sign(` (UFCS `Signer::sign(&key, msg)`, a wrapper
//! of another name). None exists in-tree today.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const NEEDLE: &str = ".sign(";

const PACKET_ENVELOPE: &str = "the submit_packet ENVELOPE signature over the canonical packet \
     bytes, a request signature with its own verifier, not an entity digest";
const SIGNABLE_STRUCT: &str = "the core Signable trait's canonical-JSON struct signature \
     (`value.sign(&signer)`), a separate untagged scheme, not a bare-digest entity signature";

/// `(file, fn, count, what it signs)`.
const REGISTER: &[(&str, &str, usize, &str)] = &[
    (
        "crates/epigraph-cli/src/bin/ingest_git.rs",
        "build_packet",
        1,
        PACKET_ENVELOPE,
    ),
    (
        "crates/epigraph-harvester/src/commit.rs",
        "create_claim_with_evidence_and_trace",
        1,
        SIGNABLE_STRUCT,
    ),
    (
        "crates/epigraph-harvester/src/commit.rs",
        "create_evidence_from_citation",
        1,
        SIGNABLE_STRUCT,
    ),
    (
        "crates/epigraph-harvester/src/commit.rs",
        "create_reasoning_trace",
        1,
        SIGNABLE_STRUCT,
    ),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

/// The first `fn <ident>` on a code line, if any.
fn fn_name(code: &str) -> Option<&str> {
    let bytes = code.as_bytes();
    for (i, _) in code.match_indices("fn ") {
        if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
            continue;
        }
        let rest = code[i + 3..].trim_start();
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let ident = &rest[..end];
        if ident
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        {
            return Some(ident);
        }
    }
    None
}

/// `fn -> number of .sign( calls` in one source file.
fn scan_source(src: &str) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut skip_depth: Option<i64> = None;
    let mut pending_cfg_test = false;
    for line in src.split('\n') {
        let t = line.trim();
        if let Some(depth) = skip_depth.as_mut() {
            *depth += line.matches('{').count() as i64 - line.matches('}').count() as i64;
            if *depth <= 0 {
                skip_depth = None;
            }
            continue;
        }
        if t.starts_with("//") {
            continue;
        }
        if t.starts_with("#[cfg(") && t.contains("test") {
            pending_cfg_test = true;
            continue;
        }
        if pending_cfg_test {
            pending_cfg_test = false;
            if t.starts_with("mod ") && t.ends_with('{') {
                skip_depth =
                    Some(line.matches('{').count() as i64 - line.matches('}').count() as i64);
                continue;
            }
        }
        let code = if line.contains('"') {
            line
        } else {
            line.split("//").next().unwrap_or("")
        };
        if !t.starts_with("let") {
            if let Some(name) = fn_name(code) {
                current = Some(name.to_string());
            }
        }
        let n = code.matches(NEEDLE).count();
        if n > 0 {
            let func = current.clone().unwrap_or_else(|| "<top level>".to_string());
            *out.entry(func).or_default() += n;
        }
    }
    out
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

fn measure() -> BTreeMap<(String, String), usize> {
    let root = workspace_root();
    let mut crates: Vec<_> = std::fs::read_dir(root.join("crates"))
        .expect("crates/")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().is_some_and(|n| n != "epigraph-crypto"))
        .collect();
    crates.sort();
    let mut out = BTreeMap::new();
    for krate in crates {
        let mut files = Vec::new();
        rs_files(&krate.join("src"), &mut files);
        for f in files {
            let rel = f
                .strip_prefix(&root)
                .expect("under the root")
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&f).expect("read source");
            for (func, n) in scan_source(&src) {
                out.insert((rel.clone(), func), n);
            }
        }
    }
    out
}

#[test]
fn no_source_outside_the_crypto_crate_signs_a_raw_message() {
    let measured = measure();
    let mut problems = Vec::new();
    for ((file, func), n) in &measured {
        match REGISTER.iter().find(|r| r.0 == file && r.1 == func) {
            None => problems.push(format!(
                "{file}::{func} calls `.sign(` {n} time(s): sign an entity digest with \
                 AgentSigner::sign_entity(SignedEntity::<kind>, &digest), never the bare digest \
                 or raw text; if it signs something that is not an entity, register it here \
                 with what it signs"
            )),
            Some(r) if r.2 != *n => problems.push(format!(
                "{file}::{func} calls `.sign(` {n} time(s), registered {}: review the new or \
                 removed call",
                r.2
            )),
            Some(_) => {}
        }
    }
    for (file, func, _, _) in REGISTER {
        if !measured.contains_key(&(file.to_string(), func.to_string())) {
            problems.push(format!(
                "STALE register entry {file}::{func}: the call is gone, remove the entry"
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The scanner sees the regression it exists for, attributes it to its
/// function, and ignores a comment, `sign_entity` and a test module.
#[test]
fn the_scanner_sees_a_bare_digest_sign_and_only_that() {
    let src = r#"
/// server.signer.sign(&content_hash) in a doc comment
pub async fn writer(server: &Server) {
    claim.signature = Some(
        server
            .signer
            .sign(&content_hash),
    );
    evidence.signature = Some(server.signer.sign_entity(SignedEntity::Evidence, &h));
}

fn quiet() {
    // signer.sign(&h)
}

#[cfg(test)]
mod tests {
    fn fixture() {
        let legacy = signer.sign(&h);
    }
}
"#;
    assert_eq!(
        scan_source(src).into_iter().collect::<Vec<_>>(),
        vec![("writer".to_string(), 1)]
    );
    // And the live tree is not vacuous.
    assert!(
        measure().contains_key(&(
            "crates/epigraph-harvester/src/commit.rs".to_string(),
            "create_reasoning_trace".to_string()
        )),
        "the scanner no longer sees a registered site: it has gone vacuous"
    );
}
