//! rmcp logs two lines ABOVE the INFO cap with a whole MCP message in a
//! field, and the binary's subscriber must drop both under every `RUST_LOG`
//! (backlog e6ed6cc9):
//!
//! - `received notification` (INFO, `?notification`) in the service loop, on
//!   every notification a peer sends;
//! - `Received unexpected message` (WARN, `?notification` / `?message`) in the
//!   client handshake, on a server message that arrives before the
//!   `initialize` answer. The gateway is a client of every extension it
//!   mounts.
//!
//! These tests drive rmcp's REAL callsites over an in-memory pipe, not
//! hand-written events on rmcp's targets, so a callsite rmcp renames or a
//! field it moves shows up here. Each carries a canary in the payload, and
//! each is calibrated: with the payload opt-in the same run DOES log the
//! canary, so "no canary" means "filtered", not "never emitted".
//!
//! `#[tokio::test]` is current-thread: rmcp's spawned service tasks run on
//! the test's thread, where `set_default` installed the subscriber.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use epigraph_mcp::log_filter;
use rmcp::model::{CancelledNotificationParam, NumberOrString, RequestId};
use rmcp::{ServerHandler, ServiceExt};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// The payload a peer sends; it must never reach the log.
const CANARY: &str = "CANARY-mcp-payload-e6ed6cc9";

/// `RUST_LOG` values under which rmcp's INFO/WARN lines pass the level cap.
/// (The default filter excludes rmcp altogether, so it is not one of them.)
const RUST_LOGS: &[&str] = &[
    "info",
    "debug",
    "trace",
    "rmcp=info",
    "rmcp=warn",
    "rmcp::service=trace,rmcp::service::client=trace",
    "[serve_inner]=info",
];

/// A server with rmcp's default handler: no tools, nothing of its own logged.
struct Bare;
impl ServerHandler for Bare {}

/// A client sends a `notifications/cancelled` whose `reason` is the canary,
/// then a request; the request's answer means the server's loop has handled
/// (and logged) the notification before it.
async fn peer_sends_a_notification() {
    let (server_end, client_end) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move {
        let running = Bare
            .serve(tokio::io::split(server_end))
            .await
            .expect("server handshake");
        let _ = running.waiting().await;
    });
    let client = ().serve(tokio::io::split(client_end)).await.expect("client handshake");
    client
        .peer()
        .notify_cancelled(CancelledNotificationParam::new(
            Some(RequestId::from(NumberOrString::Number(4242))),
            Some(CANARY.to_string()),
        ))
        .await
        .expect("send the notification");
    // Answered (an error is an answer too) only after the notification ahead
    // of it was handled.
    let _ = tokio::time::timeout(Duration::from_secs(10), client.peer().list_all_tools())
        .await
        .expect("the server answers");
    let _ = client.cancel().await;
    let _ = tokio::time::timeout(Duration::from_secs(10), server).await;
}

/// A raw server sends, before its `initialize` answer, a non-logging
/// notification and a non-ping request, each carrying the canary: the two
/// `Received unexpected message` branches of rmcp's client handshake.
async fn server_sends_messages_before_the_handshake() {
    let (server_end, client_end) = tokio::io::duplex(1 << 16);
    let client = tokio::spawn(async move { ().serve(tokio::io::split(client_end)).await });

    let (read, mut write) = tokio::io::split(server_end);
    let mut lines = BufReader::new(read).lines();
    let init = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("the client sends initialize")
        .expect("read")
        .expect("a line");
    let init: serde_json::Value = serde_json::from_str(&init).expect("initialize is JSON");
    assert_eq!(init["method"], "initialize", "{init}");

    let early = [
        serde_json::json!({
            "jsonrpc": "2.0", "method": "notifications/progress",
            "params": {"progressToken": CANARY, "progress": 1}
        }),
        serde_json::json!({"jsonrpc": "2.0", "id": CANARY, "method": "roots/list"}),
        serde_json::json!({
            "jsonrpc": "2.0", "id": init["id"],
            "result": {
                "protocolVersion": init["params"]["protocolVersion"],
                "capabilities": {},
                "serverInfo": {"name": "raw", "version": "0"}
            }
        }),
    ];
    for msg in early {
        write
            .write_all(format!("{msg}\n").as_bytes())
            .await
            .expect("write");
    }
    write.flush().await.expect("flush");
    let running = tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("the handshake completes")
        .expect("join")
        .expect("the client accepts the initialize answer");
    let _ = running.cancel().await;
}

/// Run `scenario` under the binary's subscriber; what it logged.
async fn logged<F, Fut>(rust_log: &str, log_payloads: bool, scenario: F) -> String
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let buf = Capture::default();
    let _guard = tracing::subscriber::set_default(log_filter::subscriber(
        Some(rust_log),
        log_payloads,
        buf.clone(),
    ));
    scenario().await;
    buf.text()
}

/// Mutation: drop the payload filter from `log_filter::subscriber` (or
/// return `false` from `log_filter::carries_rmcp_payload`) -> the canary is
/// logged under every value here, and this fails.
#[tokio::test]
async fn a_received_notification_is_never_logged_with_its_payload() {
    let calibration = logged("info", true, peer_sends_a_notification).await;
    assert!(
        calibration.contains(CANARY) && calibration.contains("received notification"),
        "CALIBRATION: rmcp's `received notification` line fires and carries the payload \
         when the opt-in lifts the filter:\n{calibration}"
    );

    for rust_log in RUST_LOGS {
        let out = logged(rust_log, false, peer_sends_a_notification).await;
        assert!(
            !out.contains(CANARY),
            "RUST_LOG={rust_log}: a notification's payload reached the log:\n{out}"
        );
        if *rust_log == "info" {
            assert!(
                out.contains("serve finished") || out.contains("Service initialized"),
                "RUST_LOG=info: rmcp's lifecycle lines must still be logged:\n{out}"
            );
        }
    }
}

/// Mutation: as above -> both early messages' canary is logged, and this
/// fails.
#[tokio::test]
async fn an_unexpected_message_before_the_handshake_is_never_logged_with_its_payload() {
    let calibration = logged("info", true, server_sends_messages_before_the_handshake).await;
    assert_eq!(
        calibration.matches("Received unexpected message").count(),
        2,
        "CALIBRATION: both branches of rmcp's `Received unexpected message` fire:\n{calibration}"
    );
    assert!(
        calibration.matches(CANARY).count() >= 2,
        "CALIBRATION: and each carries the payload when the opt-in lifts the filter:\n{calibration}"
    );

    for rust_log in RUST_LOGS {
        let out = logged(rust_log, false, server_sends_messages_before_the_handshake).await;
        assert!(
            !out.contains(CANARY),
            "RUST_LOG={rust_log}: an unexpected message's payload reached the log:\n{out}"
        );
    }
}
