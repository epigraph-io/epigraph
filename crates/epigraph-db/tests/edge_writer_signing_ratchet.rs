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
//! And the DATABASE-SIDE writers: every SQL function (SECURITY DEFINER entry
//! point or trigger function) defined in `migrations/*.sql` whose LIVE
//! definition inserts into `edges` ([`DB_REGISTER`]). Files are read in
//! migration order and `CREATE [OR REPLACE] FUNCTION` / `DROP FUNCTION` in
//! statement order, so only each function's latest definition counts, and a
//! site is keyed by `(the migration holding that definition, function)`: a
//! later migration that redefines a registered function trips the ratchet
//! until its entry is moved to the new file and re-reviewed. One-shot data
//! statements (a top-level `INSERT` or `DO` block) run once at migrate time
//! and are not writers.
//!
//! # The rules
//!
//! * A new site (a new function, or one more site in a registered function) is
//!   a failure until it is registered here. Sign it and register it
//!   [`Signed`], or register it [`Unsigned`] with the reason it cannot sign.
//!   A writer signs AT INSERT (ruling R-50: an `EdgeRepository::*_signed_conn`
//!   twin called with the writer's `EdgeSigningKey`, which also signs a
//!   world-owned structural edge no application session may UPDATE), or
//!   after it (`sign_created_edge_conn` on the writer's connection, for an
//!   edge THIS act created and the session may update).
//! * A [`Signed`] entry's function must call `sign_created_edge_conn`, or a
//!   signed twin and name its key ([`signs`]), so a signed writer cannot
//!   silently stop signing.
//! * A site that disappears must have its entry REMOVED (exact match both ways).
//! * [`UNSIGNED_SITES_HIGH_WATER`] is the exact number of unsigned sites
//!   (Rust and database). It should only go down: signing a writer lowers it
//!   in the same commit. The test checks that the number EQUALS the register,
//!   not that it never rises: raising it (a new unsigned writer) is a
//!   reviewed act, visible in the diff of this file, not something the test
//!   can refuse.
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
//! invisible to a line scanner. On the SQL side the scanner reads
//! dollar-quoted function bodies (`AS $$ .. $$`, `AS $tag$ .. $tag$`) with
//! `--` comments removed; it does not see a body quoted with single quotes, an
//! `INSERT` assembled by `EXECUTE format(..)`, or a writer reached only
//! through a function of another name (none of these write edges in-tree
//! today), and it keys overloads by name. The wrappers in-tree today are themselves
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
    // The INSERT-time signed twins (ruling R-50); the symmetric family's
    // `_signed_conn` forms match the prefix above.
    "EdgeRepository::create_signed_conn(",
    "EdgeRepository::create_if_not_exists_signed_conn(",
    "EdgeRepository::create_if_absent_including_retracted_signed_conn(",
    "EdgeRepository::create_processed_by_stamp_if_absent_signed_conn(",
];

/// The after-the-fact signing call: one way a [`Signed`] writer attests.
const SIGN_CALL: &str = "sign_created_edge_conn";

/// The INSERT-time way (ruling R-50): a signed twin called with a key the
/// writer holds. A [`Signed`] function must name both a `_signed_conn`
/// primitive and the key (`edge_signing_key()` / an `EdgeSigningKey`).
const SIGNED_TWIN: &str = "_signed_conn(";
const KEY_MARKERS: &[&str] = &["edge_signing_key", "EdgeSigningKey"];

/// The attested INSERT itself (`edge_signature::insert_attested_conn`): it
/// signs the edge message in the statement that writes the row.
const SIGN_AT_INSERT: &str = "sign_entity(SignedEntity::Edge";

/// Whether a function body attests the edges it creates, by any of the three
/// ways above.
fn signs(body: &str) -> bool {
    body.contains(SIGN_CALL)
        || body.contains(SIGN_AT_INSERT)
        || (body.contains(SIGNED_TWIN) && KEY_MARKERS.iter().any(|k| body.contains(k)))
}

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
const PRIMITIVE: &str = "the unsigned arm (no key) of an EdgeRepository insert primitive; a \
     writer signs by passing its key to the primitive's _signed_conn twin";

const NO_KEY_DB_FUNCTION: &str = "a database function (SECURITY DEFINER entry point or \
     trigger) holds no entity key; its edges could only be signed at INSERT time by a key the \
     caller passes in, or by a database-held key (backlog dae795f8 Q2)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// The function attests the edges it creates.
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

/// The exact number of unsigned edge-emitting sites, Rust ([`REGISTER`]) plus
/// database ([`DB_REGISTER`]). Should only go down; see the module docs.
const UNSIGNED_SITES_HIGH_WATER: usize = 85;

/// A database-side edge writer: the migration holding the function's LIVE
/// definition, the function, and its `INSERT INTO edges` count.
struct DbSite {
    migration: &'static str,
    function: &'static str,
    count: usize,
    status: Status,
}

/// The database-side inventory, measured from `migrations/*.sql`.
const DB_REGISTER: &[DbSite] = &[
    // The legacy-author OPERATED_BY backfill (custodian role).
    DbSite {
        migration: "123_custodian_role.sql",
        function: "epigraph_link_legacy_authors",
        count: 1,
        status: Unsigned(NO_KEY_DB_FUNCTION),
    },
    // OPERATED_BY, behind epigraph_link_operator and the identity lineage.
    DbSite {
        migration: "161_agent_identity_lineage.sql",
        function: "epigraph_link_operator_body",
        count: 1,
        status: Unsigned(NO_KEY_DB_FUNCTION),
    },
    DbSite {
        migration: "122_operator_binding.sql",
        function: "epigraph_link_retired_agent",
        count: 1,
        status: Unsigned(NO_KEY_DB_FUNCTION),
    },
    DbSite {
        migration: "122_operator_binding.sql",
        function: "epigraph_link_retired_shared_signer",
        count: 1,
        status: Unsigned(NO_KEY_DB_FUNCTION),
    },
    // The role-assignment audit trigger (OCCUPIES verb-edges).
    DbSite {
        migration: "130_pending_admin_acts.sql",
        function: "epigraph_role_assignments_audit",
        count: 1,
        status: Unsigned(NO_KEY_DB_FUNCTION),
    },
];

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
        "create_symmetric_if_absent_returning_signed_conn",
        1,
        Unsigned(PRIMITIVE),
    ),
    site(
        "crates/epigraph-db/src/repos/edge.rs",
        "create_symmetric_if_absent_oriented_signed_conn",
        1,
        Unsigned(PRIMITIVE),
    ),
    site(
        "crates/epigraph-db/src/repos/edge.rs",
        "create_symmetric_if_absent_row_signed_conn",
        1,
        Unsigned(PRIMITIVE),
    ),
    // The attested INSERT (ruling R-50): every signed twin's key path.
    site(
        "crates/epigraph-db/src/repos/edge_signature.rs",
        "insert_attested_conn",
        1,
        Signed,
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
        Signed,
    ),
    site(
        "crates/epigraph-mcp/src/server.rs",
        "record_auth_lineage",
        1,
        Signed,
    ),
    site(
        "crates/epigraph-mcp/src/tools/claims.rs",
        "resolve_backlog_item",
        1,
        Signed,
    ),
    site(
        "crates/epigraph-mcp/src/tools/ingestion.rs",
        "do_ingest_document",
        5,
        Signed,
    ),
    site(
        "crates/epigraph-mcp/src/tools/ingestion.rs",
        "do_ingest_document_spine",
        5,
        Signed,
    ),
    site(
        "crates/epigraph-mcp/src/tools/link_alternative.rs",
        "do_link_alternative",
        1,
        Signed,
    ),
    site(
        "crates/epigraph-mcp/src/tools/link_epistemic.rs",
        "do_link_epistemic",
        2,
        Signed,
    ),
    site(
        "crates/epigraph-mcp/src/tools/link_hierarchical.rs",
        "do_link_hierarchical",
        1,
        Signed,
    ),
    site(
        "crates/epigraph-mcp/src/tools/perspectives.rs",
        "create_perspective",
        1,
        Signed,
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

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The SQL text with `--` line comments removed (a migration's comments
/// mention functions and `INSERT INTO edges` freely).
fn strip_sql_comments(sql: &str) -> String {
    sql.split('\n')
        .map(|l| l.find("--").map_or(l, |i| &l[..i]))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Count `INSERT INTO [public.]edges` (word-bounded, any case and spacing).
fn edge_inserts(sql: &str) -> usize {
    let words: Vec<String> = sql
        .split(|c: char| c.is_whitespace() || c == '(' || c == ';')
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    words
        .windows(3)
        .filter(|w| {
            w[0] == "insert" && w[1] == "into" && (w[2] == "edges" || w[2] == "public.edges")
        })
        .count()
}

/// The function name after a `FUNCTION` keyword at `at`, lower-cased and
/// without a `public.` prefix, and the byte offset just past it.
fn sql_name_at(lower: &str, at: usize) -> Option<(String, usize)> {
    let rest = &lower[at..];
    let skipped = rest.len() - rest.trim_start().len();
    let start = at + skipped;
    let end = lower[start..]
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '"'))
        .map_or(lower.len(), |i| start + i);
    let name = lower[start..end].replace('"', "");
    let name = name.strip_prefix("public.").unwrap_or(&name).to_string();
    (!name.is_empty()).then_some((name, end))
}

/// The dollar-quoted body that follows `from`: `(body start, body end, past
/// the closing quote)`.
fn dollar_body(sql: &str, from: usize) -> Option<(usize, usize, usize)> {
    let bytes = sql.as_bytes();
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            let mut j = i + 1;
            while j < bytes.len() && is_ident_byte(bytes[j]) {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'$' && !bytes[i + 1].is_ascii_digit() {
                let tag = &sql[i..=j];
                let close = sql[j + 1..].find(tag)? + j + 1;
                return Some((j + 1, close, close + tag.len()));
            }
        }
        i += 1;
    }
    None
}

/// Apply one migration file's `CREATE [OR REPLACE] FUNCTION` / `DROP FUNCTION`
/// statements, in order, to `live` (`function -> (migration, edge INSERTs)`).
fn apply_migration(live: &mut BTreeMap<String, (String, usize)>, file: &str, sql: &str) {
    let sql = strip_sql_comments(sql);
    let lower = sql.to_ascii_lowercase();
    let words: Vec<(usize, &str)> = {
        let mut out = Vec::new();
        let mut start = None;
        for (i, b) in lower.bytes().enumerate() {
            if is_ident_byte(b) {
                start.get_or_insert(i);
            } else if let Some(s0) = start.take() {
                out.push((s0, &lower[s0..i]));
            }
        }
        if let Some(s0) = start {
            out.push((s0, &lower[s0..]));
        }
        out
    };
    let mut skip_until = 0;
    for (k, (pos, word)) in words.iter().enumerate() {
        if *pos < skip_until || *word != "function" || k == 0 {
            continue;
        }
        let prev = words[k - 1].1;
        let prev2 = k.checked_sub(2).map(|i| words[i].1);
        let prev3 = k.checked_sub(3).map(|i| words[i].1);
        let create = prev == "create"
            || (prev == "replace" && prev2 == Some("or") && prev3 == Some("create"));
        let drop = prev == "drop";
        if !(create || drop) {
            continue;
        }
        let mut at = pos + word.len();
        if drop {
            // DROP FUNCTION [IF EXISTS] a(..), b(..) [CASCADE];
            let stmt_end = lower[at..].find(';').map_or(lower.len(), |i| at + i);
            let mut list = lower[at..stmt_end].trim_start().to_string();
            if let Some(rest) = list.strip_prefix("if exists") {
                list = rest.to_string();
            }
            let mut depth = 0i32;
            let mut item = String::new();
            for c in list.chars().chain(std::iter::once(',')) {
                match c {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    ',' if depth == 0 => {
                        if let Some((name, _)) = sql_name_at(&item, 0) {
                            live.remove(&name);
                        }
                        item.clear();
                        continue;
                    }
                    _ if depth == 0 => item.push(c),
                    _ => {}
                }
            }
            skip_until = stmt_end;
            continue;
        }
        let Some((name, after)) = sql_name_at(&lower, at) else {
            continue;
        };
        at = after;
        let Some((body_start, body_end, past)) = dollar_body(&sql, at) else {
            continue;
        };
        let n = edge_inserts(&sql[body_start..body_end]);
        live.insert(name, (file.to_string(), n));
        skip_until = past;
    }
}

/// `function -> (migration, edge INSERTs)` for every SQL function whose LIVE
/// definition inserts into `edges`.
fn scan_migrations(files: &[(String, String)]) -> BTreeMap<String, (String, usize)> {
    let mut live = BTreeMap::new();
    for (file, sql) in files {
        apply_migration(&mut live, file, sql);
    }
    live.retain(|_, (_, n)| *n > 0);
    live
}

fn measure_migrations() -> BTreeMap<String, (String, usize)> {
    let dir = workspace_root().join("migrations");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("migrations/")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "sql"))
        .collect();
    files.sort();
    let files: Vec<(String, String)> = files
        .into_iter()
        .map(|p| {
            (
                p.file_name().expect("name").to_string_lossy().into_owned(),
                std::fs::read_to_string(&p).expect("read migration"),
            )
        })
        .collect();
    scan_migrations(&files)
}

/// The SQL scanner: only the LIVE definition counts (a redefinition without
/// the INSERT, a DROP, and a drop-then-recreate in one file), comments and
/// one-shot statements are not writers, and a `$tag$` body is read.
#[test]
fn the_migration_scanner_tracks_each_functions_live_definition() {
    let files: Vec<(String, String)> = [
        (
            "001_a.sql",
            "-- CREATE FUNCTION public.commented() .. INSERT INTO edges\n\
             CREATE OR REPLACE FUNCTION public.f_kept(p uuid) RETURNS void LANGUAGE plpgsql AS $$\n\
             BEGIN INSERT INTO public.edges (source_id) VALUES (p); END $$;\n\
             CREATE FUNCTION g_redefined() RETURNS void AS $body$\n\
             BEGIN INSERT INTO edges(id) VALUES (gen_random_uuid()); END $body$ LANGUAGE plpgsql;\n\
             CREATE FUNCTION h_dropped() RETURNS void AS $$ BEGIN INSERT INTO edges (id) VALUES (1); END $$;\n\
             CREATE FUNCTION staging_only() RETURNS void AS $$ BEGIN INSERT INTO edges_staging (id) VALUES (1); END $$;\n\
             INSERT INTO edges (id) VALUES (gen_random_uuid());\n\
             DO $$ BEGIN INSERT INTO edges (id) VALUES (gen_random_uuid()); END $$;",
        ),
        (
            "002_b.sql",
            "CREATE OR REPLACE FUNCTION public.g_redefined() RETURNS void AS $$ BEGIN PERFORM 1; END $$;\n\
             DROP FUNCTION IF EXISTS public.h_dropped(), other(uuid);\n\
             DROP FUNCTION public.r_recreated(uuid);\n\
             CREATE FUNCTION public.r_recreated(p uuid) RETURNS void AS $$\n\
             BEGIN INSERT INTO edges (id) VALUES (p); INSERT INTO public.edges (id) VALUES (p); END $$;",
        ),
    ]
    .into_iter()
    .map(|(f, s)| (f.to_string(), s.to_string()))
    .collect();
    let live = scan_migrations(&files);
    assert_eq!(
        live.into_iter().collect::<Vec<_>>(),
        vec![
            ("f_kept".to_string(), ("001_a.sql".to_string(), 1)),
            ("r_recreated".to_string(), ("002_b.sql".to_string(), 2)),
        ]
    );

    // And the live tree is not vacuous: OPERATED_BY's writer is seen.
    assert!(
        measure_migrations().contains_key("epigraph_link_operator_body"),
        "the migration scanner no longer sees epigraph_link_operator_body"
    );
}

/// Everything wrong between a measurement and a register, as messages.
fn check(
    measured: &BTreeMap<(String, String), (usize, String)>,
    register: &[Site],
    db_measured: &BTreeMap<String, (String, usize)>,
    db_register: &[DbSite],
    high_water: usize,
) -> Vec<String> {
    let mut problems = Vec::new();

    let mut registered = BTreeMap::new();
    for s in register {
        let key = (s.file.to_string(), s.func.to_string());
        if registered.insert(key, s).is_some() {
            problems.push(format!("duplicate register entry {}::{}", s.file, s.func));
        }
    }

    for ((file, func), (n, body)) in measured {
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
                if s.status == Signed && !signs(body) {
                    problems.push(format!(
                        "{file}::{func} is registered Signed but no longer calls {SIGN_CALL} \
                         or a signed twin with its key"
                    ));
                }
            }
        }
    }
    for s in register {
        if !measured.contains_key(&(s.file.to_string(), s.func.to_string())) {
            problems.push(format!(
                "STALE register entry {}::{}: the site is gone, remove the entry",
                s.file, s.func
            ));
        }
    }

    for (function, (migration, n)) in db_measured {
        match db_register.iter().find(|d| d.function == function) {
            None => problems.push(format!(
                "UNREGISTERED database edge writer {migration}::{function} ({n} INSERT(s) into \
                 edges): register it in DB_REGISTER with its signing status"
            )),
            Some(d) => {
                if d.migration != migration || d.count != *n {
                    problems.push(format!(
                        "database edge writer {function} is live in {migration} with {n} \
                         INSERT(s), registered {}/{}: a migration redefined it; review the new \
                         definition and update the entry",
                        d.migration, d.count
                    ));
                }
                if d.status == Signed {
                    problems.push(format!(
                        "database edge writer {function} is registered Signed, but no database \
                         function holds a key to sign with"
                    ));
                }
            }
        }
    }
    for d in db_register {
        if !db_measured.contains_key(d.function) {
            problems.push(format!(
                "STALE database register entry {}::{}: no live definition inserts into edges",
                d.migration, d.function
            ));
        }
    }

    let unsigned: usize = register
        .iter()
        .filter(|s| matches!(s.status, Unsigned(_)))
        .map(|s| s.count)
        .chain(
            db_register
                .iter()
                .filter(|d| matches!(d.status, Unsigned(_)))
                .map(|d| d.count),
        )
        .sum();
    if unsigned != high_water {
        problems.push(format!(
            "{unsigned} unsigned edge-emitting sites, UNSIGNED_SITES_HIGH_WATER says \
             {high_water}: lower it when a writer starts signing; raising it registers a new \
             unsigned writer, which is a reviewed act"
        ));
    }
    problems
}

#[test]
fn every_edge_emitting_site_is_registered_with_its_signing_status() {
    let problems = check(
        &measure(),
        REGISTER,
        &measure_migrations(),
        DB_REGISTER,
        UNSIGNED_SITES_HIGH_WATER,
    );
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The rules themselves, on a synthetic register (so each has a committed
/// test, not only the live tree, where no writer is `Signed` yet): a `Signed`
/// entry whose function does not call `sign_created_edge_conn` fails, one
/// that does passes, a count drift and an unregistered site fail, and the
/// high-water number must equal the register.
#[test]
fn the_register_rules_hold_on_a_synthetic_register() {
    let body_signing = format!("let id = EdgeRepository::create(..);\n{SIGN_CALL}(conn, ..);\n");
    let body_silent = "let id = EdgeRepository::create(..);\n".to_string();
    let measured: BTreeMap<(String, String), (usize, String)> = [
        (("a.rs".to_string(), "signs".to_string()), (1, body_signing)),
        (
            ("a.rs".to_string(), "stopped".to_string()),
            (1, body_silent),
        ),
    ]
    .into_iter()
    .collect();
    let register = [
        site("a.rs", "signs", 1, Signed),
        site("a.rs", "stopped", 1, Signed),
    ];
    let no_db = BTreeMap::new();
    assert_eq!(
        check(&measured, &register, &no_db, &[], 0),
        vec![format!(
            "a.rs::stopped is registered Signed but no longer calls {SIGN_CALL} or a signed \
             twin with its key"
        )]
    );

    // The INSERT-time way: a signed twin WITH the writer's key signs; the twin
    // alone (a `None` key) does not.
    let twin_keyed = "EdgeRepository::create_signed_conn(conn, server.edge_signing_key(), ..);\n";
    let twin_bare = "EdgeRepository::create_signed_conn(conn, None, ..);\n";
    assert!(signs(twin_keyed));
    assert!(!signs(twin_bare));
    assert!(signs(
        "let s = key.signer.sign_entity(SignedEntity::Edge, &digest);\n"
    ));

    let register = [
        site("a.rs", "signs", 1, Signed),
        site("a.rs", "stopped", 2, Unsigned("why")),
    ];
    let problems = check(&measured, &register, &no_db, &[], 1);
    assert_eq!(problems.len(), 2, "{problems:?}");
    assert!(problems[0].contains("has 1 edge-emitting site(s), registered 2"));
    assert!(problems[1].contains("2 unsigned edge-emitting sites"));

    let problems = check(&measured, &register[..1], &no_db, &[], 0);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].starts_with("UNREGISTERED edge-emitting site a.rs::stopped"));

    // The database half: an unregistered function, a redefinition that moved
    // it to another migration, and a stale entry.
    let db: BTreeMap<String, (String, usize)> = [
        ("f_new".to_string(), ("200_new.sql".to_string(), 1)),
        ("f_moved".to_string(), ("201_redefine.sql".to_string(), 1)),
    ]
    .into_iter()
    .collect();
    let db_register = [
        DbSite {
            migration: "150_old.sql",
            function: "f_moved",
            count: 1,
            status: Unsigned("why"),
        },
        DbSite {
            migration: "150_old.sql",
            function: "f_gone",
            count: 1,
            status: Unsigned("why"),
        },
    ];
    let problems = check(&BTreeMap::new(), &[], &db, &db_register, 2);
    assert_eq!(problems.len(), 3, "{problems:?}");
    assert!(problems[0].contains("database edge writer f_moved is live in 201_redefine.sql"));
    assert!(problems[1].starts_with("UNREGISTERED database edge writer 200_new.sql::f_new"));
    assert!(problems[2].starts_with("STALE database register entry 150_old.sql::f_gone"));
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
