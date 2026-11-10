//! The stdio transport, end to end through rmcp's framing.
//!
//! `main.rs` serves stdio through
//! `epigraph_mcp::stdio_transport::stdio_server_transport`, rmcp's
//! `AsyncRwTransport` line codec over the `(AsyncRead, AsyncWrite)` pair of
//! `rmcp::transport::stdio()`, with this server's line-length limit. Local MCP
//! clients (Claude Code, epiclaw's scheduled agents) use it. The suites with
//! "stdio" in their names call tool handlers directly; this one sends JSON-RPC
//! through the same function, with a client on the other end of an in-memory
//! duplex pipe split into the reader/writer pair shape `stdio()` returns.
//!
//! The first two tests are characterization tests written with the rmcp 0.15
//! -> 2.x bump, not red-first ones: they pin behaviour stdio clients already
//! rely on, and fail if an rmcp change breaks the line framing, the handshake,
//! the tool listing or a tool call over stdio. The oversized-line test was
//! written red-first with the rmcp 2.2 -> 3.9 bump (see its doc).

use std::sync::Arc;

use epigraph_mcp::stdio_transport::stdio_server_transport;
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
        let (read, write) = tokio::io::split(server_end);
        let running = server()
            .serve(stdio_server_transport(read, write))
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

/// The tool manifest is per caller (`manifest_for` filters by transport, auth
/// and elevation), so on a protocol that carries cache hints (2026-07-28 and
/// later, SEP-2549) `tools/list` must be marked `cacheScope: "private"` with
/// `ttlMs: 0`. rmcp's `#[tool_handler]` default marks the list `public`,
/// which would let a shared cache serve one caller's manifest to another;
/// `EpiGraphMcpFull::list_tools` replaces that default and leaves the hints
/// unset, so rmcp fills the private ones.
///
/// Mutation: set `cache_scope: Some(CacheScope::Public)` on the
/// `ListToolsResult` in `EpiGraphMcpFull::list_tools` -> this test fails.
#[tokio::test]
async fn tools_list_is_marked_private_and_uncached_for_cache_hint_peers() {
    use rmcp::model::{CacheScope, ProtocolVersion};
    use rmcp::{ClientLifecycleMode, ClientServiceExt};

    let (server_end, client_end) = tokio::io::duplex(1 << 20);
    let served = tokio::spawn(async move {
        let (read, write) = tokio::io::split(server_end);
        let running = server()
            .serve(stdio_server_transport(read, write))
            .await
            .expect("server side of the stdio handshake");
        let _ = running.waiting().await;
    });
    // The default client still uses the legacy `initialize` handshake (it
    // negotiates 2025-11-25, which carries no cache hints), so the 2026-07-28
    // peer is selected explicitly: `server/discover` offering ONLY that
    // version, so a successful start is itself the proof it was negotiated.
    let client = ()
        .serve_with_lifecycle(
            tokio::io::split(client_end),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .expect("the server accepts a 2026-07-28 discover start");

    let listed = client
        .peer()
        .list_tools(None)
        .await
        .expect("tools/list over stdio");
    assert!(!listed.tools.is_empty(), "the manifest is not empty");
    assert_eq!(
        listed.cache_scope,
        Some(CacheScope::Private),
        "a per-caller manifest must not be cacheable for other users"
    );
    assert_eq!(
        listed.ttl_ms,
        Some(0),
        "and must not be served from a cache"
    );

    client.cancel().await.expect("client shuts down cleanly");
    let _ = served.await;
}

/// A single stdio JSON-RPC line over 16 MiB gets an answer, as it did on rmcp
/// 2.2.
///
/// rmcp 3.x's default stdio framing caps one line at 16 MiB
/// (`rmcp::transport::async_rw::DEFAULT_MAX_LINE_LENGTH`) and DROPS a longer
/// one: it logs, sends nothing back, and the client waits on that id until its
/// own timeout. `stdio_server_transport` lifts the cap
/// (`STDIO_MAX_LINE_LENGTH`), so the request is read and answered.
///
/// The client end is raw JSON-RPC lines, not an rmcp client: rmcp's client
/// transport has the same 16 MiB read cap, so an rmcp client could not tell a
/// dropped request from a dropped reply. The call names a tool that does not
/// exist, so the answer is a small error that cannot echo the argument; ANY
/// answer for id 2 proves the line was read rather than dropped. The ping
/// after it (id 3) shows the connection is still serving.
///
/// Red (the transport without `.with_max_line_length(STDIO_MAX_LINE_LENGTH)`,
/// i.e. rmcp's default): id 3 is answered and id 2 never is, so the read times
/// out.
#[tokio::test]
async fn a_request_line_over_16_mib_is_answered_not_dropped() {
    use std::collections::HashMap;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    const OVER_RMCP_DEFAULT_CAP: usize = 17 * 1024 * 1024;

    let (server_end, client_end) = tokio::io::duplex(1 << 20);
    let served = tokio::spawn(async move {
        let (read, write) = tokio::io::split(server_end);
        let running = server()
            .serve(stdio_server_transport(read, write))
            .await
            .expect("server side of the stdio handshake");
        let _ = running.waiting().await;
    });

    let (client_read, mut client_write) = tokio::io::split(client_end);
    let mut lines = BufReader::new(client_read);

    // Reads lines until every wanted id has an answer, returning id -> line.
    async fn answers_for(
        lines: &mut BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
        wanted: &[i64],
    ) -> HashMap<i64, String> {
        let mut got = HashMap::new();
        while wanted.iter().any(|id| !got.contains_key(id)) {
            let mut line = String::new();
            let n = lines.read_line(&mut line).await.expect("read a line");
            assert!(n > 0, "server closed stdout; answered so far: {got:?}");
            let msg: serde_json::Value =
                serde_json::from_str(line.trim_end()).expect("every server line is JSON");
            if let Some(id) = msg.get("id").and_then(serde_json::Value::as_i64) {
                got.insert(id, line);
            }
        }
        got
    }

    let init = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "stdio-oversize-test", "version": "0.1"}
        }
    });
    client_write
        .write_all(format!("{init}\n").as_bytes())
        .await
        .unwrap();
    let init_answer = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        answers_for(&mut lines, &[1]),
    )
    .await
    .expect("initialize is answered");
    assert!(
        init_answer[&1].contains("\"result\""),
        "{}",
        init_answer[&1]
    );

    let initialized = serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    let oversized = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "no_such_tool_oversize_probe",
            "arguments": {"pad": "x".repeat(OVER_RMCP_DEFAULT_CAP)}
        }
    })
    .to_string();
    assert!(oversized.len() > OVER_RMCP_DEFAULT_CAP);
    let ping = serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "ping"});

    // Written from a task: the duplex buffer is 1 MiB, so a 17 MiB line only
    // drains as the server reads it, while this task reads the answers.
    let writer = tokio::spawn(async move {
        client_write
            .write_all(format!("{initialized}\n").as_bytes())
            .await
            .unwrap();
        client_write.write_all(oversized.as_bytes()).await.unwrap();
        client_write.write_all(b"\n").await.unwrap();
        client_write
            .write_all(format!("{ping}\n").as_bytes())
            .await
            .unwrap();
        client_write
    });

    let answers = tokio::time::timeout(
        std::time::Duration::from_secs(90),
        answers_for(&mut lines, &[2, 3]),
    )
    .await
    .expect(
        "the >16 MiB tools/call (id 2) and the ping after it (id 3) must both be answered; \
         a timeout here means the oversized line was dropped without a reply",
    );
    // The answer's shape is not the point (an unknown tool may come back as a
    // JSON-RPC error or as an `isError` result); that it exists is.
    assert!(
        answers[&2].contains("\"error\"") || answers[&2].contains("\"isError\":true"),
        "the unknown tool must be refused, not run: {}",
        answers[&2]
    );
    assert!(answers[&3].contains("\"result\""), "{}", answers[&3]);

    drop(writer.await.expect("writer task"));
    served.abort();
}
