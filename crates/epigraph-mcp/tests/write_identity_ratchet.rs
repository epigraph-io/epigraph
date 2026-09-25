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
//! Verified load-bearing by reverting: re-adding `let agent_id =
//! server.agent_id().await?;` to `tools/memory.rs` fails scan 1, and changing
//! `submit_claim(self, viewer, params, auth)` to `..., None)` in `server.rs`
//! fails scan 2.

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
