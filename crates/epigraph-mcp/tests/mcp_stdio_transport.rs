//! The stdio transport, end to end through rmcp's framing.
//!
//! `main.rs` serves stdio with `server.serve(rmcp::transport::stdio())`, which
//! is rmcp's `transport-io` codec over an `(AsyncRead, AsyncWrite)` pair. Local
//! MCP clients (Claude Code, epiclaw's scheduled agents) use it. The suites
//! with "stdio" in their names call tool handlers directly; this one sends
//! JSON-RPC through the same codec instead, with an rmcp client on the other
//! end of an in-memory duplex pipe split into the same reader/writer pair
//! shape `stdio()` returns.
//!
//! It is a characterization test written with the rmcp 0.15 -> 2.x bump, not
//! a red-first one: it pins behaviour stdio clients already rely on, and fails
//! if an rmcp change breaks the line framing, the handshake, the tool listing
//! or a tool call over stdio.

use std::sync::Arc;

use rmcp::model::CallToolRequestParams;
use rmcp::ServiceExt;

fn server() -> epigraph_mcp::EpiGraphMcpFull {
    // A lazy pool against an unreachable address: nothing below needs the DB,
    // and anything that tried would fail fast instead of hanging.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(100))
        .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/invalid")
        .expect("connect_lazy never errors");
    let signer = Arc::new(epigraph_crypto::AgentSigner::generate());
    let embedder = Arc::new(epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None));
    epigraph_mcp::EpiGraphMcpFull::new_shared(pool, signer, embedder, false)
}

#[tokio::test]
async fn stdio_framing_serves_handshake_tool_list_and_a_tool_call() {
    let (server_end, client_end) = tokio::io::duplex(1 << 20);

    let served = tokio::spawn(async move {
        let running = server()
            .serve(tokio::io::split(server_end))
            .await
            .expect("server side of the stdio handshake");
        let _ = running.waiting().await;
    });

    let client =
        ().serve(tokio::io::split(client_end))
            .await
            .expect("client side of the stdio handshake");

    // Handshake: the server identifies itself with its own instructions.
    let info = client
        .peer_info()
        .expect("initialize result is recorded after the handshake");
    assert!(
        info.instructions
            .as_deref()
            .is_some_and(|i| i.contains("EpiGraph")),
        "initialize must carry the server's instructions; got {:?}",
        info.instructions
    );

    // tools/list over the wire: exactly the manifest this server computes for
    // a stdio caller (no HTTP, no auth context; the elevation-only tools are
    // filtered out of it), name for name.
    let mut expected: Vec<String> = server()
        .manifest_for(false, None)
        .await
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    expected.sort();
    assert!(
        expected.len() > 50,
        "stdio manifest unexpectedly small: {}",
        expected.len()
    );
    let tools = client
        .peer()
        .list_all_tools()
        .await
        .expect("tools/list over stdio");
    let mut got: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    got.sort();
    assert_eq!(
        got, expected,
        "stdio tools/list must return the server's whole stdio manifest"
    );
    assert!(tools.iter().any(|t| t.name == "submit_claim"));

    // tools/call over the wire, on a tool that needs no database.
    let result = client
        .peer()
        .call_tool(CallToolRequestParams::new("list_mcp_tools"))
        .await
        .expect("tools/call over stdio");
    assert_ne!(
        result.is_error,
        Some(true),
        "list_mcp_tools failed: {result:?}"
    );
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("list_mcp_tools returns text content");
    assert!(
        text.contains("\"recall\"") && text.contains("\"submit_claim\""),
        "list_mcp_tools text must enumerate the tools; got {} bytes",
        text.len()
    );

    client.cancel().await.expect("client shuts down cleanly");
    let _ = served.await;
}
