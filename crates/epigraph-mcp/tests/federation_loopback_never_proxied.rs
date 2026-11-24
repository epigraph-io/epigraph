//! Loopback federation traffic is never sent through a proxy the environment
//! names (backlog b0d05192).
//!
//! The gateway sends bearers on two loopback hops: each caller's own token to
//! the kernel's token-exchange endpoint, and the exchanged (or discovery)
//! token to every extension. Both are cleartext `http`. reqwest reads
//! `HTTP_PROXY` / `ALL_PROXY` from the environment, and `NO_PROXY` matches
//! names and IP literals separately, so `NO_PROXY=localhost` does not cover
//! the `127.0.0.1` a configured `localhost` is dialled at. With a proxy set,
//! a default client would send those bearers off the machine while the boot
//! check reports the hop as loopback.
//!
//! This binary holds ONE test because it sets process-wide environment
//! variables before any HTTP client exists (reqwest reads them when a client
//! is built). It is calibrated twice: a default reqwest client and rmcp's own
//! default transport client DO go to the recording proxy under this
//! environment, so "the proxy saw nothing" below means "bypassed", not
//! "no proxy configured".

#[path = "support/federation_stub.rs"]
mod stub;

#[path = "support/token_exchange_endpoint.rs"]
mod tx;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use epigraph_mcp::federation::client::{discovery_session, TokenExchange};
use rmcp::serve_client;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransport;

/// A "proxy" that counts the connections it is offered and closes each one.
async fn spawn_recording_proxy() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            drop(socket);
        }
    });
    (url, hits)
}

const SHORT: Duration = Duration::from_secs(5);

/// Mutations, each separately:
/// - drop `.no_proxy()` from `TokenExchange::new` -> the exchange goes to
///   the proxy, which closes it, and "the exchange is answered directly"
///   fails;
/// - drop `.no_proxy()` from `federation::client::extension_http_client` (or
///   go back to rmcp's `from_config`) -> the dial goes to the proxy and "the
///   extension is dialled directly" fails.
#[tokio::test]
async fn loopback_federation_traffic_never_goes_through_an_environment_proxy() {
    let (proxy, hits) = spawn_recording_proxy().await;
    for var in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::set_var(var, &proxy);
    }
    // The shape an operator would write to keep local traffic direct.
    for var in ["NO_PROXY", "no_proxy"] {
        std::env::set_var(var, "localhost");
    }

    let endpoint = tx::spawn_token_endpoint(tx::SECRET, &["ext"]).await;
    let (ext_addr, _control) = stub::spawn_controlled_stub(&["echo"]).await;

    // CALIBRATION 1: a default reqwest client to the 127.0.0.1 endpoint goes
    // to the proxy despite NO_PROXY=localhost.
    let _ = tokio::time::timeout(SHORT, reqwest::Client::new().post(&endpoint.url).send()).await;
    assert!(
        hits.load(Ordering::SeqCst) >= 1,
        "CALIBRATION: under this environment a default client to a loopback literal is proxied"
    );
    assert!(
        endpoint.subjects.lock().unwrap().is_empty(),
        "CALIBRATION: the proxied request never reached the endpoint"
    );

    // CALIBRATION 2: so does rmcp's own default transport client (what the
    // gateway used to dial extensions with).
    let before = hits.load(Ordering::SeqCst);
    let rmcp_default = StreamableHttpClientTransport::<reqwest_rmcp::Client>::from_uri(format!(
        "http://{ext_addr}/mcp"
    ));
    let _ = tokio::time::timeout(SHORT, serve_client((), rmcp_default)).await;
    assert!(
        hits.load(Ordering::SeqCst) > before,
        "CALIBRATION: rmcp's default client dials an extension through the proxy"
    );

    // The gateway's token exchange, configured as `localhost` (dialled at
    // 127.0.0.1), reaches the endpoint directly.
    let before = hits.load(Ordering::SeqCst);
    let exchange = TokenExchange::new(&endpoint.url.replace("127.0.0.1", "localhost"))
        .expect("a loopback http URL is accepted");
    let caller = tx::kernel_token(tx::SECRET, &["ext:tools"]);
    let exchanged = tokio::time::timeout(SHORT, exchange.exchange(&caller, "ext"))
        .await
        .expect("the exchange answers")
        .expect("the exchange is answered directly, not by the proxy");
    assert_eq!(
        *endpoint.subjects.lock().unwrap(),
        vec![caller.clone()],
        "the caller's bearer reached the endpoint itself"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        before,
        "the exchange offered the proxy a connection"
    );

    // The gateway's extension dial reaches the extension directly.
    let session = discovery_session(&ext_addr, &exchanged)
        .await
        .expect("the extension is dialled directly, not through the proxy");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        before,
        "the extension dial offered the proxy a connection"
    );
    let _ = session.cancel().await;
}
