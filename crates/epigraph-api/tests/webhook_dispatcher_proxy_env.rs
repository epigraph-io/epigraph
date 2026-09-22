//! The webhook dispatcher's client does not route through a proxy named in the
//! environment. Here that is an SSRF property, not a networking preference.
//!
//! # Why a proxy switches the connect-time guard off
//!
//! `SsrfGuardedResolver` refuses a delivery NAME that resolves to an internal
//! address, at the resolution reqwest performs before it dials. Behind an HTTP
//! proxy, reqwest resolves the PROXY'S host, not the target's, and hands the
//! target URL to the proxy. The guard is never asked about the target, and
//! the proxy opens the internal connection on the server's behalf. reqwest
//! reads `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` from the environment by
//! default, so one deploy-time env var would silently disable the guard.
//! `dispatcher_client_builder` calls `.no_proxy()` to stop that.
//!
//! # Why this is its own test binary
//!
//! The test sets process-global environment variables. In a binary shared with
//! other tests, every concurrently built reqwest client would pick them up. A
//! binary holding exactly one test has no concurrent reader.
//!
//! # Non-vacuity
//!
//! The same request, sent by a client built WITHOUT `.no_proxy()`, is asserted
//! to reach the stand-in proxy. That proves reqwest honours the variables in
//! this environment. Without that control, the zero-connection assertion would
//! also hold on a machine where reqwest ignored them.

use epigraph_api::routes::webhooks::{
    dispatcher_client_builder_with_lookup, ResolvedToInternalAddress,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Answers every name with loopback, as `127-0-0-1.nip.io` would.
struct LoopbackLookup;

impl reqwest::dns::Resolve for LoopbackLookup {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
            Ok(Box::new(std::iter::once(addr)) as reqwest::dns::Addrs)
        })
    }
}

/// A loopback listener that counts accepted connections and answers each with
/// `200 OK`. A proxy that forwarded the request would make an unguarded run
/// report success.
async fn counting_listener() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener addr");
    let count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&count);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            let _ = stream.flush().await;
        }
    });
    (addr, count)
}

fn refusal_in(err: &reqwest::Error) -> Option<&ResolvedToInternalAddress> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(r) = e.downcast_ref::<ResolvedToInternalAddress>() {
            return Some(r);
        }
        cur = e.source();
    }
    None
}

#[tokio::test]
async fn the_dispatcher_client_ignores_an_environment_proxy() {
    let (proxy_addr, proxy_connections) = counting_listener().await;
    let (target_addr, target_connections) = counting_listener().await;

    // Every spelling reqwest consults for an `http://` target. The NO_PROXY
    // variables are cleared so a developer's or CI's own exclusions cannot
    // exempt the target host and make the control below pass for the wrong
    // reason.
    let proxy_url = format!("http://{proxy_addr}");
    for var in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::set_var(var, &proxy_url);
    }
    for var in ["NO_PROXY", "no_proxy", "REQUEST_METHOD"] {
        std::env::remove_var(var);
    }

    let timeout = std::time::Duration::from_millis(1000);
    let target = format!("http://rebind.example:{}/hook", target_addr.port());

    let client = dispatcher_client_builder_with_lookup(timeout, Arc::new(LoopbackLookup))
        .build()
        .expect("dispatcher client must build");
    let outcome = client.post(&target).body("{}").send().await;

    // The connection counts first: they name the bypass, where the `Err`
    // check below would only report an unexpected success.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        proxy_connections.load(Ordering::SeqCst),
        0,
        "the dispatcher client routed through HTTP_PROXY: the proxy would have \
         made the internal connection and the connect-time guard never ran"
    );
    assert_eq!(
        target_connections.load(Ordering::SeqCst),
        0,
        "no connection may reach the internal target"
    );
    let err = outcome.expect_err("a name resolving to loopback must be refused");
    let refusal = refusal_in(&err)
        .unwrap_or_else(|| panic!("the refusal must be the connect-time guard's: {err:?}"));
    assert_eq!(refusal.host, "rebind.example");

    // Control: a client that honours the environment DOES go to the proxy.
    let default_client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .expect("control client must build");
    let _ = default_client.post(&target).body("{}").send().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        proxy_connections.load(Ordering::SeqCst),
        1,
        "control: a client that reads the environment must reach the stand-in \
         proxy, or this test cannot tell `.no_proxy()` from an ignored variable"
    );
}
