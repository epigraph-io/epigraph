//! Source ratchet for batch H-b's D1: every MCP write authors and stamps as the
//! request's principal, resolved in ONE place.
//!
//! The compiler already enforces the strongest half:
//! `claim_helper::begin_author_stamped_tx` takes a `WriteIdentity`, whose only
//! constructor is `EpiGraphMcpFull::write_identity(auth, viewer)`. What the type
//! cannot see, and these scans pin:
//!
//! 1. **No tool module resolves the server agent itself.** A tool that called
//!    `server.agent_id()` and then built its own author would bypass the
//!    resolver without touching a stamp — exactly how every tool authored as the
//!    shared signer before D1 (#505 F5). `signer_agent_id()` is the one
//!    sanctioned accessor, and it names the SIGNER (`claims.signer_id`), never an
//!    author. `tools/viewer.rs` is exempt: it is the READ principal's resolution,
//!    the `None => server.agent_id()` arm `write_identity` mirrors.
//! 2. **No `#[tool]` body hands a write-tool function a `None` token.** The
//!    functions take `auth: Option<&AuthContext>` and map `None` to the server
//!    agent — correct on stdio and for direct callers (the operator CLI, this
//!    suite), and precisely the pre-D1 defect if `server.rs` passed `None` over
//!    HTTP. Every body must forward the request's own `auth`.
//!
//! 3. **No tool module resolves the write identity with a `None` token.**
//! 4. **Only the resolver constructs a `WriteIdentity`** (batch H-b review):
//!    `from_resolved` is `pub(crate)`, and the review measured a tool module
//!    minting one from the signer that passed scans 1-3.
//! 2b. **Every write body forwards `auth`, or is listed with its reason** (batch
//!    H-b review): scan 2 sees only a literal `None`, so a body that forgot the
//!    token entirely was invisible.
//! 5. **The signer accessor only ever names a signer** (batch H-b review):
//!    `signer_agent_id()` returns the same agent `server.agent_id()` does, so
//!    scan 1 alone let a tool author as the shared signer through it.
//!
//! Verified load-bearing by reverting: re-adding `let agent_id =
//! server.agent_id().await?;` to `tools/memory.rs` fails scan 1, and changing
//! `submit_claim(self, viewer, params, auth)` to `..., None)` in `server.rs`
//! fails scan 2. Scans 4, 2b and 5 each fail on their own planted mutation (see
//! each test's doc), while scans 1-3 pass on all three.

use std::path::{Path, PathBuf};

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Drop `//` line comments (doc comments included), so prose that quotes the
/// forbidden call does not trip the scan. String literals are kept: none of the
/// tokens below is a plausible string.
fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Tool modules that may name `server.agent_id()` / `server_agent_id()`, and why.
const RESOLVER_EXEMPT: &[(&str, &str)] = &[(
    "viewer.rs",
    "request_viewer's stdio arm: the READ principal, which write_identity mirrors",
)];

#[test]
fn no_tool_module_resolves_the_server_agent_as_an_author() {
    let dir = src().join("tools");
    let mut offenders = Vec::new();
    let mut scanned = 0usize;
    for entry in std::fs::read_dir(&dir).expect("read src/tools") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if RESOLVER_EXEMPT.iter().any(|(f, _)| *f == name) {
            continue;
        }
        scanned += 1;
        let text = strip_line_comments(&std::fs::read_to_string(&path).expect("read"));
        for (i, line) in text.lines().enumerate() {
            // `.agent_id()` preceded by a receiver, but not `signer_agent_id()`.
            let hit = ["server.agent_id()", "self.agent_id()", ".server_agent_id()"]
                .iter()
                .any(|needle| line.contains(needle));
            if hit {
                offenders.push(format!("tools/{name}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        scanned >= 30,
        "the scan must see the tool modules; saw {scanned}"
    );
    assert!(
        offenders.is_empty(),
        "a tool module resolves the server agent directly instead of through \
         EpiGraphMcpFull::write_identity(auth, viewer) (or signer_agent_id for the signer):\n{}",
        offenders.join("\n")
    );
}

/// The `#[tool]` bodies of `server.rs`, as `(tool name, body)`.
fn tool_bodies(server_rs: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for chunk in server_rs.split("#[tool(").skip(1) {
        let Some(at) = chunk.find("async fn ") else {
            continue;
        };
        let rest = &chunk[at + "async fn ".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        out.push((name, rest.to_string()));
    }
    out
}

#[test]
fn every_tool_body_forwards_the_requests_own_token() {
    let text = strip_line_comments(
        &std::fs::read_to_string(src().join("server.rs")).expect("read server.rs"),
    );
    let bodies = tool_bodies(&text);
    assert!(bodies.len() > 60, "saw only {} tool bodies", bodies.len());
    let mut offenders = Vec::new();
    let mut forwarding = 0usize;
    for (name, body) in &bodies {
        // The body proper: up to the method's closing brace.
        let body = body.split("\n    }\n").next().unwrap_or(body);
        // Every `tools::` dispatch in it, except the viewer acquisition itself
        // (`tools::viewer::request_viewer(self, auth)`), which is not a write.
        for (at, _) in body.match_indices("tools::") {
            let call: String = body[at..].split(".await").next().unwrap_or("").into();
            if call.starts_with("tools::viewer::") {
                continue;
            }
            if call.contains(", None)") || call.contains(",None)") {
                offenders.push(format!("{name}: {}", call.trim()));
            }
            if call.contains(", auth)") {
                forwarding += 1;
            }
        }
    }
    assert!(
        forwarding >= 25,
        "the scan must see the write tools forwarding `auth`; saw {forwarding}"
    );
    assert!(
        offenders.is_empty(),
        "a #[tool] body passes `None` where the request's token belongs; over HTTP \
         that authors the write as the shared server signer (#505 F5):\n{}",
        offenders.join("\n")
    );
}

/// The third hole: a tool module resolving the write identity with a literal
/// `None` token. `write_identity(None, viewer)` is the stdio answer — the server
/// agent — so a tool that wrote it would author every HTTP caller's write as the
/// shared signer again while still "going through the resolver". Only the
/// request's own `auth` may be handed to it under `src/tools/`.
///
/// Verified load-bearing by reverting: changing `tools/memory.rs`'s
/// `server.write_identity(auth, viewer)` to `server.write_identity(None, viewer)`
/// fails this scan.
#[test]
fn no_tool_module_resolves_the_write_identity_without_the_requests_token() {
    let dir = src().join("tools");
    let mut offenders = Vec::new();
    let mut resolver_calls = 0usize;
    for entry in std::fs::read_dir(&dir).expect("read src/tools") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let text = strip_line_comments(&std::fs::read_to_string(&path).expect("read"));
        let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        resolver_calls += flat.matches("write_identity(").count();
        for bad in ["write_identity(None", "write_identity( None"] {
            if flat.contains(bad) {
                offenders.push(format!("tools/{name}: {bad}"));
            }
        }
    }
    assert!(
        resolver_calls >= 20,
        "the scan must see the tool modules' resolver calls; saw {resolver_calls}"
    );
    assert!(
        offenders.is_empty(),
        "a tool module resolves the write identity with a literal None token, which \
         authors an HTTP caller's write as the server agent:\n{}",
        offenders.join("\n")
    );
}

/// Every file under `src/` except the two that own the resolver, as
/// `(relative path, comment-stripped text)`.
fn src_files() -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let rel = path
                    .strip_prefix(root)
                    .expect("under src")
                    .to_string_lossy()
                    .to_string();
                let text = strip_line_comments(&std::fs::read_to_string(&path).expect("read"));
                out.push((rel, text));
            }
        }
    }
    let mut out = Vec::new();
    walk(&src(), &src(), &mut out);
    out
}

/// Scan 4 (batch H-b review, authority-attack low-medium). `WriteIdentity`'s
/// private field is only half of the ratchet: its constructor
/// `WriteIdentity::from_resolved` is `pub(crate)`, so any module could mint an
/// identity from an agent it chose itself and pass the three scans above.
/// MEASURED by the review: `tools/memory.rs` changed to
/// `WriteIdentity::from_resolved(server.signer_agent_id().await?)` compiled and
/// passed all three. Only `write_identity.rs` (which defines it) and
/// `server.rs` (whose `write_identity` resolver is the one sanctioned caller)
/// may name it.
///
/// Verified load-bearing by reverting: planting that exact line in
/// `tools/memory.rs` fails this scan.
#[test]
fn only_the_resolver_constructs_a_write_identity() {
    let files = src_files();
    assert!(
        files.len() > 40,
        "the scan must see src/; saw {}",
        files.len()
    );
    let offenders: Vec<String> = files
        .iter()
        .filter(|(rel, _)| rel != "write_identity.rs" && rel != "server.rs")
        .filter(|(_, text)| text.contains("from_resolved("))
        .map(|(rel, _)| rel.clone())
        .collect();
    let in_server = files
        .iter()
        .find(|(rel, _)| rel == "server.rs")
        .map_or(0, |(_, t)| t.matches("from_resolved(").count());
    assert!(
        in_server >= 1,
        "calibration: the resolver in server.rs must be found"
    );
    assert!(
        offenders.is_empty(),
        "a module constructs a WriteIdentity itself instead of through \
         EpiGraphMcpFull::write_identity(auth, viewer):\n{}",
        offenders.join("\n")
    );
}

/// `#[tool]` bodies that run a WRITE (they call `reject_if_read_only`) and do
/// NOT forward the request's `auth`, each with the reason. A new write tool
/// that forgets `auth` is invisible to scan 2, which only sees a literal
/// `None`; this list makes forgetting it a test failure instead (batch H-b
/// review). Remove a row when its tool starts forwarding `auth`; never add one
/// without the reason.
const WRITE_BODIES_WITHOUT_AUTH: &[(&str, &str)] = &[
    (
        "backfill_embeddings",
        "maintenance session over the maintenance connection, gated by claims:admin before the \
         body runs; writes no authored row",
    ),
    (
        "create_frame",
        "frames are an instance-wide registry with no author column; R3 checklist",
    ),
    (
        "recompute_beliefs",
        "maintenance session over the maintenance connection; writes derived caches only",
    ),
    (
        "refresh_workflow_promotion",
        "writes workflows-table promotion properties with no author column; R3 checklist \
         item 4 (still on the unstamped pool)",
    ),
    (
        "report_hierarchical_outcome",
        "read-modify-write of workflows.metadata counters (no row security) plus \
         behavioral_executions rows; its authority is an open item in the R3 checklist",
    ),
    (
        "sweep_semantic_duplicates",
        "maintenance session over the maintenance connection, gated by claims:admin",
    ),
    (
        "theme_cluster",
        "corpus-wide job with no author stamp that covers it; R3 checklist item 4",
    ),
];

/// Scan 2b (batch H-b review): every write body forwards `auth`, or is listed
/// above with its reason. The list is also checked for STALE rows, so it
/// cannot silently outlive a conversion.
///
/// Verified load-bearing by reverting: renaming `auth` to `a` in
/// `publish_event`'s body (so it forwards the token under another name the
/// scan cannot see) fails this scan, and so does deleting any row above.
#[test]
fn every_write_body_forwards_auth_or_is_listed() {
    let text = strip_line_comments(
        &std::fs::read_to_string(src().join("server.rs")).expect("read server.rs"),
    );
    let mut unlisted = Vec::new();
    let mut stale = Vec::new();
    let mut writes = 0usize;
    for (name, body) in tool_bodies(&text) {
        let body = body.split("\n    }\n").next().unwrap_or(&body).to_string();
        if !body.contains("reject_if_read_only") {
            continue;
        }
        writes += 1;
        // A dispatch into a tool module that hands over the token; the viewer
        // acquisition (`tools::viewer::request_viewer(self, auth)`) is not one.
        let forwards = body.match_indices("tools::").any(|(at, _)| {
            let call = body[at..].split(".await").next().unwrap_or("");
            !call.starts_with("tools::viewer::")
                && (call.contains(", auth)") || call.contains(",auth)"))
        });
        let listed = WRITE_BODIES_WITHOUT_AUTH.iter().any(|(n, _)| *n == name);
        match (forwards, listed) {
            (false, false) => unlisted.push(name),
            (true, true) => stale.push(name),
            _ => {}
        }
    }
    for (name, _) in WRITE_BODIES_WITHOUT_AUTH {
        if !text.contains(&format!("async fn {name}(")) {
            stale.push(format!("{name} (no such tool)"));
        }
    }
    assert!(
        writes >= 35,
        "the scan must see the write tools; saw {writes}"
    );
    assert!(
        unlisted.is_empty(),
        "a write #[tool] body does not forward the request's auth, so the tool cannot author \
         or authorize as the caller over HTTP; forward it, or list the tool with its reason:\n{}",
        unlisted.join("\n")
    );
    assert!(
        stale.is_empty(),
        "WRITE_BODIES_WITHOUT_AUTH lists tools that now forward auth (or no longer exist); \
         delete the rows:\n{}",
        stale.join("\n")
    );
}

/// Scan 5 (batch H-b review, compat-and-R3 low): scan 1 forbids
/// `server.agent_id()` in tool modules but not `signer_agent_id()`, which
/// returns the same agent. Its value must only ever be a SIGNER: every call is
/// bound to a `signer*`-named variable, and no such variable is handed to an
/// author position.
///
/// Verified load-bearing by reverting: planting
/// `let _author = server.signer_agent_id().await?;` in `tools/memory.rs` fails
/// the binding half; `agent_id: signer_agent_id` in a struct literal fails the
/// position half.
#[test]
fn the_signer_accessor_only_ever_names_a_signer() {
    let dir = src().join("tools");
    let mut offenders = Vec::new();
    let mut calls = 0usize;
    for entry in std::fs::read_dir(&dir).expect("read src/tools") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let text = strip_line_comments(&std::fs::read_to_string(&path).expect("read"));
        for (i, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.contains("signer_agent_id()") {
                calls += 1;
                if !t.starts_with("let signer") {
                    offenders.push(format!("tools/{name}:{}: {t}", i + 1));
                }
            }
        }
        let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        for bad in [
            "agent_id: signer",
            "author: signer",
            "let agent_id = signer",
            "let author = signer",
            "begin_author_stamped_tx(server, signer",
        ] {
            if flat.contains(bad) {
                offenders.push(format!("tools/{name}: `{bad}`"));
            }
        }
    }
    assert!(
        calls >= 4,
        "the scan must see the signer accessor's call sites; saw {calls}"
    );
    assert!(
        offenders.is_empty(),
        "the server's SIGNER (signer_agent_id) is bound to something other than a signer, or \
         handed to an author position; authors come from write_identity:\n{}",
        offenders.join("\n")
    );
}
