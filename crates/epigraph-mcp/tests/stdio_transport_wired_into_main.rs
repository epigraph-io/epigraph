//! `epigraph-mcp-full`'s stdio mode must serve through
//! [`epigraph_mcp::stdio_transport::stdio_server_transport`], the transport
//! with no line-length cap. `mcp_stdio_transport.rs`
//! (`a_request_line_over_16_mib_is_answered_not_dropped`) proves the helper
//! answers a request line over rmcp 3.x's 16 MiB default; this file proves
//! `main` uses it. A merge that put back `server.serve(rmcp::transport::stdio())`
//! (what `main` ran before the helper existed) would leave every helper test
//! green while rmcp's silent drop of a large request returned.
//!
//! Source-level, unlike its binary-level precedent
//! `log_filter_wired_into_main.rs`: that one observes a WARN logged before the
//! database connect, but serving stdio needs a booted server, the binary
//! refuses a privileged DSN, and the test database's application role cannot
//! log in, so a test process cannot boot it into stdio mode. Instead this
//! reads `src/main.rs` with `//` comment lines dropped and all whitespace
//! removed (so rustfmt's reflow does not matter) and requires:
//!
//! - exactly one `stdio_server_transport(` call, bound with `let <name> = ...`;
//! - at least one `.serve(` call, and every `.serve(` argument is `<name>`.

/// `main.rs` without its `//` comment lines, with all whitespace removed.
fn normalized(source: &str) -> String {
    source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// The argument text of every `.serve(` call in `code` (already normalized),
/// up to its matching close paren.
fn serve_arguments(code: &str) -> Vec<String> {
    let mut args = Vec::new();
    for (at, _) in code.match_indices(".serve(") {
        let rest = &code[at + ".serve(".len()..];
        let mut depth = 1usize;
        let end = rest
            .char_indices()
            .find_map(|(i, c)| {
                match c {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                (depth == 0).then_some(i)
            })
            .unwrap_or(rest.len());
        args.push(rest[..end].to_string());
    }
    args
}

/// Every way `source` fails to serve stdio through `stdio_server_transport`.
fn stdio_wiring_violations(source: &str) -> Vec<String> {
    let code = normalized(source);
    let mut violations = Vec::new();

    let calls: Vec<usize> = code
        .match_indices("stdio_server_transport(")
        .map(|(at, _)| at)
        .collect();
    if calls.len() != 1 {
        violations.push(format!(
            "expected exactly one stdio_server_transport( call, found {}",
            calls.len()
        ));
    }
    // The name the transport is bound to: the statement holding the call must
    // be `let <name> = <path>stdio_server_transport(...)`.
    let bound = calls.first().and_then(|&at| {
        let start = code[..at].rfind([';', '{', '}']).map_or(0, |i| i + 1);
        let statement = code[start..at].strip_prefix("let")?;
        let name = statement.split_once('=')?.0;
        Some(name.strip_prefix("mut").unwrap_or(name).to_string())
    });
    let Some(bound) = bound else {
        violations.push("the stdio_server_transport( call is not bound with `let`".into());
        return violations;
    };

    let args = serve_arguments(&code);
    if args.is_empty() {
        violations.push("no .serve( call".into());
    }
    for arg in args {
        if arg != bound {
            violations.push(format!(
                ".serve({arg}) does not serve the stdio_server_transport binding `{bound}`"
            ));
        }
    }
    violations
}

#[test]
fn main_serves_stdio_through_stdio_server_transport() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs");
    let source = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let violations = stdio_wiring_violations(&source);
    assert!(
        violations.is_empty(),
        "main.rs must serve stdio through epigraph_mcp::stdio_transport::\
         stdio_server_transport (rmcp's own stdio framing silently drops a request \
         line over 16 MiB): {}",
        violations.join("; ")
    );
}

// ── The check itself, on synthetic sources ────────────────────────────────

#[test]
fn the_current_shape_passes_however_rustfmt_wraps_it() {
    let one_line = r#"
        // Not `serve(rmcp::transport::stdio())`: see the helper.
        let (stdin, stdout) = rmcp::transport::stdio();
        let transport = epigraph_mcp::stdio_transport::stdio_server_transport(stdin, stdout);
        let service = server.serve(transport).await.map_err(|e| e)?;
    "#;
    let wrapped = r#"
        let (stdin, stdout) = rmcp::transport::stdio();
        let mut transport =
            epigraph_mcp::stdio_transport::stdio_server_transport(
                stdin,
                stdout,
            );
        let service = server
            .serve(transport)
            .await?;
    "#;
    assert_eq!(stdio_wiring_violations(one_line), Vec::<String>::new());
    assert_eq!(stdio_wiring_violations(wrapped), Vec::<String>::new());
}

#[test]
fn the_pre_helper_shape_and_an_unused_helper_are_caught() {
    // What main.rs ran before the helper existed.
    let old = "let service = server.serve(rmcp::transport::stdio()).await?;";
    assert!(!stdio_wiring_violations(old).is_empty());

    // The helper built, but the server served on rmcp's own framing.
    let unused = r#"
        let (stdin, stdout) = rmcp::transport::stdio();
        let transport = epigraph_mcp::stdio_transport::stdio_server_transport(stdin, stdout);
        let service = server.serve(rmcp::transport::stdio()).await?;
    "#;
    assert_eq!(
        stdio_wiring_violations(unused),
        vec![".serve(rmcp::transport::stdio()) does not serve the \
             stdio_server_transport binding `transport`"
            .to_string()]
    );

    // A second, unbound call is not a pin.
    let unbound =
        "server.serve(epigraph_mcp::stdio_transport::stdio_server_transport(stdin, stdout));";
    assert!(!stdio_wiring_violations(unbound).is_empty());
}
