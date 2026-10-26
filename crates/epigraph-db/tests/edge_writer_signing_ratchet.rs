//! Ratchet: every edge-emitting code path is registered with its signing
//! status, and the register can only shrink (backlog `dae795f8`, step 3).
//!
//! # Why
//!
//! Edges carry the EVENT semantics of the noun-claim / verb-edge model (who
//! spawned what, which run asserts which fact), and an edge row is only
//! independently verifiable if its writer attested it
//! (`EdgeSignatureRepository::sign_created_edge_conn`, migration-free since the
//! columns exist). Coverage was "realised per writer", so nothing stopped a new
//! writer from landing unsigned and nobody had an inventory of the old ones.
//! This file IS that inventory, measured from the tree.
//!
//! # What it measures
//!
//! Every non-test source file under `crates/*/src`, line by line, for an
//! edge-emitting site: a call to one of the `EdgeRepository` insert
//! primitives ([`CALLS`]) or a raw `INSERT INTO edges` / `INSERT INTO
//! public.edges` statement. Sites are keyed by `(file, enclosing fn)` with an
//! exact count. Rust line comments and `#[cfg(..test..)] mod` blocks are
//! skipped, so a doc-comment mention and an in-crate unit test are not
//! writers.
//!
//! # The rules
//!
//! * A new site (a new function, or one more site in a registered function) is
//!   a failure until it is registered here. Sign it
//!   (`sign_created_edge_conn` on the writer's connection, for an edge THIS act
//!   created), register it [`Signed`], or register it [`Unsigned`] with the
//!   reason it cannot sign.
//! * A [`Signed`] entry's function must call `sign_created_edge_conn`, so a
//!   signed writer cannot silently stop signing.
//! * A site that disappears must have its entry REMOVED (exact match both ways).
//! * [`UNSIGNED_SITES_HIGH_WATER`] is the exact number of unsigned sites. It
//!   only goes down: signing a writer lowers it in the same commit.
//!
//! # What it does not see
//!
//! Whether a [`Signed`] writer's edges are really signed. The check reads the
//! call, and `sign_created_edge_conn` returns `Ok(NotSignable)` without an
//! error for an edge the session may not update (a world-owned structural
//! verb-edge, another writer's edge). Every writer flipped to `Signed` needs a
//! DB test asserting that its edge carries a verifying v1 signature
//! (`EdgeSignatureRepository::verify_conn`).
//!
//! A writer that builds `INSERT INTO edges` from pieces split across string
//! literals or lines, or that calls a private wrapper with another name, is
//! invisible to a line scanner. The wrappers in-tree today are themselves
//! sites (`emit_verb_edge_best_effort`, `create_edge_under_savepoint`, the
//! `EdgeRepository` primitives), so their callers are covered through them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The `EdgeRepository` insert primitives. The symmetric family is matched by
/// prefix so `create_symmetric_if_absent{,_conn,_returning,_oriented,..}` all
/// count.
const CALLS: &[&str] = &[
    "EdgeRepository::create(",
    "EdgeRepository::create_if_not_exists(",
    "EdgeRepository::create_if_not_exists_conn(",
    "EdgeRepository::create_if_absent_including_retracted(",
    "EdgeRepository::create_if_absent_including_retracted_conn(",
    "EdgeRepository::create_symmetric_if_absent",
    "EdgeRepository::create_processed_by_stamp_if_absent_conn(",
];

/// The call a [`Signed`] writer's function must contain.
const SIGN_CALL: &str = "sign_created_edge_conn";

/// Why an unsigned site does not sign. Each is a measured property of the
/// tree, not a preference.
const NO_KEY_API: &str = "epigraph-api holds no entity signing key: HTTP claims are signed by \
     their client in the packet, and giving the API server a key is a deployment decision";
const NO_KEY_CLI: &str = "an operator CLI on a database DSN with no entity signer";
const NO_KEY_ENGINE: &str = "epigraph-engine (matching) holds no signing key";
const NO_KEY_EXECUTOR: &str = "epigraph-ingest-executor is pure-DB and holds no key; its MCP \
     and HTTP callers would sign through the returned edge ids";
const REPO_INTERNAL: &str = "emitted inside a repository act (supersede, dedup, consolidate, \
     analysis, lineage, semantic link, match promotion); the repository holds no key, so the \
     signing caller must receive the edge id";
const PRIMITIVE: &str = "the EdgeRepository insert primitive itself; writers sign after it";
const PENDING_SIGNER_ID_RULING: &str = "the MCP server holds a key, but stamping \
     edges.signer_id with the server's agent changes what backfill_factors::EDGE_QUERY reads \
     as an edge factor's agent (COALESCE(e.signer_id, src.agent_id)); awaiting an operator \
     ruling (backlog dae795f8)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// The function attests the edges it creates.
    // No writer is registered Signed yet: wiring the MCP writers waits on the
    // signer_id ruling named in PENDING_SIGNER_ID_RULING.
    #[allow(dead_code)]
    Signed,
    /// The function does not sign, for the stated reason.
    Unsigned(&'static str),
}
use Status::{Signed, Unsigned};

struct Site {
    file: &'static str,
    func: &'static str,
    count: usize,
    status: Status,
}

const fn site(file: &'static str, func: &'static str, count: usize, status: Status) -> Site {
    Site {
        file,
        func,
        count,
        status,
    }
}

/// The exact number of unsigned edge-emitting sites. Only goes down.
const UNSIGNED_SITES_HIGH_WATER: usize = 98;

/// The inventory (backlog `dae795f8` step 1), measured.
const REGISTER: &[Site] = &[
    site(
        "crates/epigraph-api/src/routes/assess.rs",
        "assess_claim",
        3,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/belief.rs",
        "create_edge_under_savepoint",
        1,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/claims.rs",
        "create_claim_core",
        3,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/community.rs",
        "add_member",
        1,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/conventions.rs",
        "learn_convention",
        4,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/conventions.rs",
        "forget_convention",
        1,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/conventions.rs",
        "share_skill",
        1,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/crud.rs",
        "create_evidence",
        1,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/crud.rs",
        "create_reasoning_trace",
        1,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/crud.rs",
        "promote_staged_edges",
        2,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/edges.rs",
        "create_edge",
        3,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/edges.rs",
        "create_hierarchical_edge",
        1,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/edges.rs",
        "relate_claims",
        2,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/experiment_loop.rs",
        "create_experiment",
        1,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/experiment_loop.rs",
        "submit_results",
        1,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/experiment_loop.rs",
        "analyze_result",
        2,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/perspective.rs",
        "create_perspective",
        1,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/provenance.rs",
        "set_provenance",
        4,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/spans.rs",
        "create_span",
        1,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/spans.rs",
        "close_span",
        2,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-api/src/routes/submit.rs",
        "persist_packet",
        5,
        Unsigned(NO_KEY_API),
    ),
    site(
        "crates/epigraph-cli/src/decompose.rs",
        "persist_decomposition",
        1,
        Unsigned(NO_KEY_CLI),
    ),
    site(
        "crates/epigraph-cli/src/bin/dekg.rs",
        "handle_migrate",
        3,
        Unsigned(NO_KEY_CLI),
    ),
    site(
        "crates/epigraph-cli/src/bin/experiment.rs",
        "run",
        1,
        Unsigned(NO_KEY_CLI),
    ),
    site(
        "crates/epigraph-cli/src/bin/experiment.rs",
        "submit_results",
        1,
        Unsigned(NO_KEY_CLI),
    ),
    site(
        "crates/epigraph-cli/src/bin/experiment.rs",
        "analyze",
        2,
        Unsigned(NO_KEY_CLI),
    ),
    site(
        "crates/epigraph-cli/src/bin/method_search.rs",
        "run",
        1,
        Unsigned(NO_KEY_CLI),
    ),
    site(
        "crates/epigraph-cli/src/rerank/core.rs",
        "create_edge",
        1,
        Unsigned(NO_KEY_CLI),
    ),
    site(
        "crates/epigraph-db/src/repos/analysis.rs",
        "link_evidence",
        1,
        Unsigned(REPO_INTERNAL),
    ),
    site(
        "crates/epigraph-db/src/repos/analysis.rs",
        "link_claim",
        1,
        Unsigned(REPO_INTERNAL),
    ),
    site(
        "crates/epigraph-db/src/repos/analysis.rs",
        "persist_bundle",
        2,
        Unsigned(REPO_INTERNAL),
    ),
    site(
        "crates/epigraph-db/src/repos/claim.rs",
        "supersede_act_conn",
        1,
        Unsigned(REPO_INTERNAL),
    ),
    site(
        "crates/epigraph-db/src/repos/claim.rs",
        "inherit_evidence",
        1,
        Unsigned(REPO_INTERNAL),
    ),
    site(
        "crates/epigraph-db/src/repos/claim.rs",
        "evolve_step_conn",
        1,
        Unsigned(REPO_INTERNAL),
    ),
    site(
        "crates/epigraph-db/src/repos/claim.rs",
        "backfill_legacy_dedup_identity_edges_conn",
        1,
        Unsigned(REPO_INTERNAL),
    ),
    site(
        "crates/epigraph-db/src/repos/claim.rs",
        "consolidate_act_conn",
        1,
        Unsigned(REPO_INTERNAL),
    ),
    site(
        "crates/epigraph-db/src/repos/claim.rs",
        "mark_duplicate_act",
        1,
        Unsigned(REPO_INTERNAL),
    ),
    site(
        "crates/epigraph-db/src/repos/edge.rs",
        "create",
        1,
        Unsigned(PRIMITIVE),
    ),
    site(
        "crates/epigraph-db/src/repos/edge.rs",
        "create_if_absent_conn",
        1,
        Unsigned(PRIMITIVE),
    ),
    site(
        "crates/epigraph-db/src/repos/edge.rs",
        "create_symmetric_if_absent_conn",
        1,
        Unsigned(PRIMITIVE),
    ),
    site(
        "crates/epigraph-db/src/repos/edge.rs",
        "create_symmetric_if_absent_returning_conn",
        1,
        Unsigned(PRIMITIVE),
    ),
    site(
        "crates/epigraph-db/src/repos/edge.rs",
        "create_symmetric_if_absent_oriented_conn",
        1,
        Unsigned(PRIMITIVE),
    ),
    site(
        "crates/epigraph-db/src/repos/edge.rs",
        "edge_row",
        1,
        Unsigned(PRIMITIVE),
    ),
    site(
        "crates/epigraph-db/src/repos/match_candidate.rs",
        "promote_if_pending",
        1,
        Unsigned(REPO_INTERNAL),
    ),
    site(
        "crates/epigraph-db/src/repos/semantic_link.rs",
        "create",
        1,
        Unsigned(REPO_INTERNAL),
    ),
    site(
        "crates/epigraph-engine/src/matching/policy.rs",
        "write_edge",
        1,
        Unsigned(NO_KEY_ENGINE),
    ),
    site(
        "crates/epigraph-ingest-executor/src/authorship.rs",
        "record_caller_authorship",
        1,
        Unsigned(NO_KEY_EXECUTOR),
    ),
    site(
        "crates/epigraph-ingest-executor/src/workflow.rs",
        "execute_plan",
        3,
        Unsigned(NO_KEY_EXECUTOR),
    ),
    site(
        "crates/epigraph-ingest-executor/src/workflow_steps.rs",
        "add_step",
        6,
        Unsigned(NO_KEY_EXECUTOR),
    ),
    site(
        "crates/epigraph-mcp/src/claim_helper.rs",
        "emit_verb_edge_best_effort",
        1,
        Unsigned(PENDING_SIGNER_ID_RULING),
    ),
    site(
        "crates/epigraph-mcp/src/server.rs",
        "record_auth_lineage",
        1,
        Unsigned(PENDING_SIGNER_ID_RULING),
    ),
    site(
        "crates/epigraph-mcp/src/tools/claims.rs",
        "resolve_backlog_item",
        1,
        Unsigned(PENDING_SIGNER_ID_RULING),
    ),
    site(
        "crates/epigraph-mcp/src/tools/ingestion.rs",
        "do_ingest_document",
        5,
        Unsigned(PENDING_SIGNER_ID_RULING),
    ),
    site(
        "crates/epigraph-mcp/src/tools/ingestion.rs",
        "do_ingest_document_spine",
        5,
        Unsigned(PENDING_SIGNER_ID_RULING),
    ),
    site(
        "crates/epigraph-mcp/src/tools/link_alternative.rs",
        "do_link_alternative",
        1,
        Unsigned(PENDING_SIGNER_ID_RULING),
    ),
    site(
        "crates/epigraph-mcp/src/tools/link_epistemic.rs",
        "do_link_epistemic",
        2,
        Unsigned(PENDING_SIGNER_ID_RULING),
    ),
    site(
        "crates/epigraph-mcp/src/tools/link_hierarchical.rs",
        "do_link_hierarchical",
        1,
        Unsigned(PENDING_SIGNER_ID_RULING),
    ),
    site(
        "crates/epigraph-mcp/src/tools/perspectives.rs",
        "create_perspective",
        1,
        Unsigned(PENDING_SIGNER_ID_RULING),
    ),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn is_raw_insert(line: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    ["INSERT INTO EDGES", "INSERT INTO PUBLIC.EDGES"]
        .iter()
        .any(|pre| {
            upper.match_indices(pre).any(|(i, _)| {
                upper[i + pre.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
            })
        })
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

/// What one source file contributes: `fn -> (site count, the fn's code text)`.
#[derive(Default)]
struct FileScan {
    sites: BTreeMap<String, usize>,
    bodies: BTreeMap<String, String>,
}

fn scan_source(src: &str) -> FileScan {
    let mut out = FileScan::default();
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
        let Some(func) = current.clone() else {
            continue;
        };
        let body = out.bodies.entry(func.clone()).or_default();
        body.push_str(code);
        body.push('\n');
        if CALLS.iter().any(|c| code.contains(c)) || is_raw_insert(code) {
            *out.sites.entry(func).or_default() += 1;
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

/// `(file, fn) -> (count, body)` over every crate's `src/`.
fn measure() -> BTreeMap<(String, String), (usize, String)> {
    let root = workspace_root();
    let mut crates: Vec<_> = std::fs::read_dir(root.join("crates"))
        .expect("crates/")
        .flatten()
        .map(|e| e.path())
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
            let scan = scan_source(&src);
            for (func, n) in scan.sites {
                let body = scan.bodies.get(&func).cloned().unwrap_or_default();
                out.insert((rel.clone(), func), (n, body));
            }
        }
    }
    out
}

#[test]
fn every_edge_emitting_site_is_registered_with_its_signing_status() {
    let measured = measure();
    let mut problems = Vec::new();

    let mut registered = BTreeMap::new();
    for s in REGISTER {
        let key = (s.file.to_string(), s.func.to_string());
        assert!(
            registered.insert(key, s).is_none(),
            "duplicate register entry {}::{}",
            s.file,
            s.func
        );
    }

    for ((file, func), (n, body)) in &measured {
        match registered.get(&(file.clone(), func.clone())) {
            None => problems.push(format!(
                "UNREGISTERED edge-emitting site {file}::{func} ({n} site(s)): sign the edges it \
                 creates with EdgeSignatureRepository::{SIGN_CALL} and register it Signed, or \
                 register it Unsigned with the reason it cannot sign"
            )),
            Some(s) => {
                if s.count != *n {
                    problems.push(format!(
                        "{file}::{func} has {n} edge-emitting site(s), registered {}: review the \
                         new or removed site and update the count",
                        s.count
                    ));
                }
                if s.status == Signed && !body.contains(SIGN_CALL) {
                    problems.push(format!(
                        "{file}::{func} is registered Signed but no longer calls {SIGN_CALL}"
                    ));
                }
            }
        }
    }
    for s in REGISTER {
        if !measured.contains_key(&(s.file.to_string(), s.func.to_string())) {
            problems.push(format!(
                "STALE register entry {}::{}: the site is gone, remove the entry",
                s.file, s.func
            ));
        }
    }

    let unsigned: usize = REGISTER
        .iter()
        .filter(|s| matches!(s.status, Unsigned(_)))
        .map(|s| s.count)
        .sum();
    if unsigned != UNSIGNED_SITES_HIGH_WATER {
        problems.push(format!(
            "{unsigned} unsigned edge-emitting sites, UNSIGNED_SITES_HIGH_WATER says \
             {UNSIGNED_SITES_HIGH_WATER}: the number only goes down; lower it when a writer \
             starts signing, never raise it"
        ));
    }

    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The scanner is not vacuous, and it ignores what is not a writer: it sees a
/// primitive call and a raw INSERT, attributes each to its function, skips a
/// comment mention, an `edges_staging` table and a `#[cfg(test)]` module, and
/// keeps each function's body so the Signed check has something to read.
#[test]
fn the_scanner_finds_writers_and_only_writers() {
    let src = r#"
/// A doc mention: EdgeRepository::create(..) is not a call.
pub async fn emits(conn: &mut PgConnection) {
    let id = EdgeRepository::create_if_not_exists_conn(
        conn, a, "claim", b, "claim", "supports", None, None, None,
    ).await?;
    EdgeSignatureRepository::sign_created_edge_conn(conn, id, signer, me).await?;
}

fn raw(pool: &PgPool) {
    sqlx::query("INSERT INTO public.edges (source_id) VALUES ($1)");
    sqlx::query("INSERT INTO edges_staging (source_id) VALUES ($1)");
}

fn quiet() {
    // EdgeRepository::create(pool, ..) in a comment
}

#[cfg(all(test, feature = "db"))]
mod tests {
    fn fixture() {
        sqlx::query("INSERT INTO edges (id) VALUES ($1)");
        let _ = EdgeRepository::create(pool, a, "claim", b, "claim", "x", None, None, None);
    }
}
"#;
    let scan = scan_source(src);
    assert_eq!(
        scan.sites.into_iter().collect::<Vec<_>>(),
        vec![("emits".to_string(), 1), ("raw".to_string(), 1)]
    );
    assert!(scan.bodies["emits"].contains(SIGN_CALL));
    assert!(!scan.bodies["raw"].contains(SIGN_CALL));

    // And the live tree: two sites this register must always see.
    let measured = measure();
    for key in [
        (
            "crates/epigraph-mcp/src/claim_helper.rs",
            "emit_verb_edge_best_effort",
        ),
        (
            "crates/epigraph-db/src/repos/claim.rs",
            "supersede_act_conn",
        ),
    ] {
        assert!(
            measured.contains_key(&(key.0.to_string(), key.1.to_string())),
            "the scanner no longer sees {}::{}: it has gone vacuous",
            key.0,
            key.1
        );
    }
}
