//! Source lock: an HTTP MCP call with no `AuthContext` is refused **before**
//! dispatch, so `tools::viewer::request_viewer`'s `None` arm means stdio.
//!
//! # The property, and why it needs a lock rather than a comment
//!
//! Plan §4.12 sketches `request_viewer` with an explicit transport
//! discriminator and an explicit `(is_http, None) => Err(unauthorized)` arm,
//! added — in the plan's own words — "so it cannot become reachable silently".
//! PR-09 ships `request_viewer` without that arm: `auth == None` falls through
//! to `server.agent_id()`, i.e. the server agent's viewer, which after PR-09's
//! `ensure_personal_group` call is a *populated* group set rather than an empty
//! one. If an HTTP call could ever arrive with no `AuthContext`, that would be
//! a silent authority grant to an unauthenticated caller.
//!
//! It cannot, and the reason is one frame up in `server.rs::call_tool`, which
//! already computes the discriminator the plan asked for:
//!
//! ```ignore
//! let http_parts = context.extensions.get::<Parts>();
//! is_http_call = http_parts.is_some();
//! ...
//! if is_http_call {
//!     if let Err(err) = Self::enforce_tool_scope(auth_owned.as_ref(), &request.name) { ... }
//! }
//! ```
//!
//! and `enforce_tool_scope`'s first branch is `let Some(auth) = auth else {
//! return Err(...) }`. Every HTTP call without an `AuthContext` is refused
//! there, before any `#[tool]` body runs.
//!
//! This is load-bearing rather than belt-and-braces, because `main.rs` has a
//! router arm that layers **neither** auth middleware: given neither
//! `--jwt-secret` nor `--allow-unauthenticated-http`, the `/mcp` service is
//! nested bare. The dispatch gate is what closes that arm.
//!
//! # What this file checks
//!
//! Three source properties over `crates/epigraph-mcp/src/server.rs`, none of
//! which a behavioural test can reach (driving the router needs an
//! `rmcp::service::RequestContext`, which no test in this crate synthesizes):
//!
//! 1. `call_tool` still derives `is_http_call` from the presence of `Parts`.
//! 2. The `if is_http_call {` block still calls `enforce_tool_scope`.
//! 3. That block appears **before** the dispatch call
//!    (`self.tool_router.call(...)`), because a gate that runs after dispatch
//!    is not a gate.
//!
//! Plus one behavioural property that IS reachable: `enforce_tool_scope(None,
//! ..)` refuses. Together they are the chain the `request_viewer` module doc
//! cites. If someone deletes the gate to "simplify", this fails and the doc
//! stops being true at the same moment.

use std::path::PathBuf;

fn server_rs() -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "src", "server.rs"]
        .iter()
        .collect();
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The body of `call_tool`, from its signature to the end of the file.
///
/// Deliberately coarse: this lint is a tripwire on a two-line invariant, not a
/// parser. A rename of `call_tool` fails the first assertion, which is the
/// correct outcome — the reviewer is then forced to re-establish the property
/// by hand.
fn call_tool_body(src: &str) -> &str {
    let start = src
        .find("async fn call_tool(")
        .expect("server.rs must still define `call_tool`");
    &src[start..]
}

#[test]
fn call_tool_derives_the_http_discriminator_from_request_parts() {
    let src = server_rs();
    let body = call_tool_body(&src);
    assert!(
        body.contains("is_http_call = http_parts.is_some()"),
        "`call_tool` no longer derives `is_http_call` from the presence of \
         `http::request::Parts`. `tools/viewer.rs`'s module doc cites exactly \
         this line as the reason `request_viewer` needs no HTTP-with-no-context \
         arm. Either restore it or add that arm."
    );
    assert!(
        body.contains("context.extensions.get::<Parts>()"),
        "the `Parts` lookup that distinguishes HTTP from stdio is gone from \
         `call_tool`"
    );
}

#[test]
fn an_http_call_with_no_auth_context_is_refused_before_dispatch() {
    let src = server_rs();
    let body = call_tool_body(&src);

    let gate = body
        .find("if is_http_call {")
        .expect("`call_tool` must still gate on `is_http_call`");
    let enforce = body[gate..]
        .find("Self::enforce_tool_scope(")
        .map(|i| gate + i)
        .expect("the `is_http_call` gate must still call `enforce_tool_scope`");
    let dispatch = body
        .find("self.tool_router.call(")
        .expect("`call_tool` must still dispatch through `tool_router.call`");

    assert!(
        enforce < dispatch,
        "`enforce_tool_scope` must run BEFORE `tool_router.call`. It is at byte \
         {enforce} and dispatch is at {dispatch}. A scope gate after dispatch \
         has already let the tool read."
    );
}

#[test]
fn enforce_tool_scope_refuses_a_missing_auth_context() {
    // The behavioural half. `enforce_tool_scope` is `pub`, so this is a real
    // call rather than a source assertion: the source lints above pin that it
    // is REACHED on the HTTP path, this pins what it DOES when it is.
    let err = epigraph_mcp::server::EpiGraphMcpFull::enforce_tool_scope(None, "query_claims")
        .expect_err("no AuthContext must be refused");
    assert!(
        err.message.contains("no auth context"),
        "unexpected refusal message: {}",
        err.message
    );
}

#[test]
fn request_viewers_stdio_arm_is_documented_as_relying_on_that_gate() {
    // The doc and the gate are one control; a lint that pins the gate while the
    // doc silently drops the citation leaves the next reader with no way to
    // find this file.
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "src", "tools", "viewer.rs"]
        .iter()
        .collect();
    let src = std::fs::read_to_string(&path).expect("read tools/viewer.rs");
    assert!(
        src.contains("is_http_call") && src.contains("enforce_tool_scope"),
        "`tools/viewer.rs` no longer explains why it has no \
         HTTP-with-no-context arm. Either restore the citation of \
         `call_tool`'s `is_http_call` / `enforce_tool_scope` gate, or add the \
         arm plan §4.12 specifies."
    );
}
