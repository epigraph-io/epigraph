#![cfg(feature = "db")]

//! `POST /api/v1/webhooks` refuses internal delivery targets and non-`http(s)`
//! schemes — and still accepts an ordinary one.
//!
//! # Why this file exists at all
//!
//! The URL-validation tests this extends
//! (`test_register_webhook_rejects_empty_url` and friends) live in
//! `routes/webhooks.rs`'s `#[cfg(not(feature = "db"))] mod handler_tests`, which
//! no configuration in this workspace compiles: `epigraph-api`'s default features
//! are `["db"]`. Extending them would have added an assertion nothing runs.
//!
//! # The policy, and what these tests deliberately do not claim
//!
//! Rejection here is by **scheme**, by **IP literal**, and by the small set of
//! names RFC 6761 reserves to loopback. Every other hostname is accepted on its
//! face, so none of these tests asserts anything about DNS: there is no
//! resolution in the checked path, on purpose, and the registration-time check is
//! not a defence against a name that merely resolves somewhere private. See
//! `routes/webhooks.rs::validate_webhook_url`'s doc for the full statement of
//! what the policy does not cover.
//!
//! `a_conventional_https_target_is_still_accepted` is the control, and it is not
//! optional: a validator that refuses everything satisfies every rejection test
//! in this file.

mod common;

const SECRET: &str = "Xk9mP2qL7vN8wBjH5cT0yDrF3gU6eA1s"; // 32 chars

async fn spawn() -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    common::spawn_app(&url).await
}

async fn pool() -> sqlx::PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect test pool")
}

/// A token bound to a real `agents` row, because migration 085's FK makes a
/// random principal a 500 rather than a 201 on the success path.
async fn writer_token() -> String {
    let p = pool().await;
    let agent = common::seed_system_agent(&p).await;
    common::mint_token_with_agent(&["webhooks:write"], agent)
}

async fn register(addr: std::net::SocketAddr, token: &str, url: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/webhooks"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "url": url,
            "event_types": [],
            "secret": SECRET,
        }))
        .send()
        .await
        .unwrap()
}

/// Each case is a separate delivery target the policy names, asserted in one
/// test so a partial implementation (scheme but not addresses, or IPv4 but not
/// IPv6) cannot pass by covering the one case a reviewer happened to read.
#[tokio::test(flavor = "multi_thread")]
async fn an_internal_or_non_http_delivery_target_is_refused() {
    let (addr, _shutdown) = spawn().await;
    let token = writer_token().await;

    for (target, why) in [
        ("http://127.0.0.1:9000/hook", "IPv4 loopback"),
        ("https://127.0.0.1/hook", "IPv4 loopback over https"),
        (
            "http://169.254.169.254/latest/meta-data/",
            "IPv4 link-local",
        ),
        ("http://10.0.0.7/hook", "private range 10/8"),
        ("http://192.168.1.10/hook", "private range 192.168/16"),
        ("http://172.16.0.5/hook", "private range 172.16/12"),
        ("http://0.0.0.0/hook", "unspecified"),
        ("http://[::1]/hook", "IPv6 loopback"),
        ("http://[fe80::1]/hook", "IPv6 link-local"),
        ("http://[fd00::1]/hook", "IPv6 unique-local"),
        (
            "http://[::ffff:127.0.0.1]/hook",
            "IPv4-mapped IPv6 spelling of loopback",
        ),
        ("file:///etc/passwd", "non-http scheme"),
        ("gopher://example.com/1", "non-http scheme"),
        ("not-a-url", "not an absolute URL"),
        // RFC 6761 reserves these to loopback BY DEFINITION, so they are
        // judgeable without a resolver. Included because rule 4 alone refused
        // the literal and accepted the ordinary spelling of the same socket.
        ("http://localhost:9000/hook", "reserved loopback name"),
        (
            "http://LocalHost/hook",
            "reserved loopback name, mixed case",
        ),
        ("http://localhost./hook", "reserved loopback name, root dot"),
        ("http://api.localhost/hook", "name under .localhost"),
    ] {
        let resp = register(addr, &token, target).await;
        assert_eq!(
            resp.status(),
            400,
            "{why} ({target}) must be refused at registration; got {}",
            resp.status()
        );
    }
}

/// THE CONTROL. An ordinary public https target still registers, and the row it
/// creates is the one the caller asked for.
#[tokio::test(flavor = "multi_thread")]
async fn a_conventional_https_target_is_still_accepted() {
    let (addr, _shutdown) = spawn().await;
    let token = writer_token().await;

    let target = "https://hooks.example.com/epigraph/events";
    let resp = register(addr, &token, target).await;
    assert_eq!(
        resp.status(),
        201,
        "a public https target is legitimate and must not be refused; got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("subscription body is json");
    assert_eq!(
        body["url"], target,
        "the accepted target must be stored verbatim: {body}"
    );
}

/// Surrounding whitespace neither smuggles a target past the policy nor survives
/// into the row.
///
/// Both halves are the same property from opposite sides: the value the policy
/// judges and the value that gets POSTed must be the same string. The check runs
/// on the trimmed form (so a padded loopback target is still refused), and the
/// stored form is now the trimmed one too (so the row cannot differ from what was
/// inspected).
#[tokio::test(flavor = "multi_thread")]
async fn whitespace_does_not_separate_the_judged_url_from_the_stored_one() {
    let (addr, _shutdown) = spawn().await;
    let token = writer_token().await;

    let refused = register(addr, &token, "  http://127.0.0.1/hook\n").await;
    assert_eq!(
        refused.status(),
        400,
        "a padded internal target is still an internal target; got {}",
        refused.status()
    );

    let accepted = register(addr, &token, "  https://hooks.example.com/padded  ").await;
    assert_eq!(
        accepted.status(),
        201,
        "padding is not itself a reason to refuse a public target; got {}",
        accepted.status()
    );
    let body: serde_json::Value = accepted.json().await.expect("subscription body is json");
    assert_eq!(
        body["url"], "https://hooks.example.com/padded",
        "the persisted target must be the string the policy inspected: {body}"
    );
}

/// A hostname is accepted even though it could resolve anywhere. Asserted, not
/// implied: it is the boundary of the policy, and a future change that started
/// resolving names here would make registration latency a function of DNS and
/// would need to be a deliberate decision rather than a side effect.
///
/// The fixture is under `.example` (RFC 2606), which never resolves and carries
/// no loopback semantics, so what this pins is "names are not resolved" and
/// nothing else. An earlier revision used a name that is on the default
/// `/etc/hosts` loopback line of several distributions, which would have pinned
/// "a loopback name is acceptable" as intended behaviour — an assertion a later
/// author narrowing the name side would have had to delete in order to make
/// their change.
#[tokio::test(flavor = "multi_thread")]
async fn a_hostname_is_not_resolved_and_is_accepted_on_its_face() {
    let (addr, _shutdown) = spawn().await;
    let token = writer_token().await;

    let resp = register(addr, &token, "http://consumer.internal.example/hook").await;
    assert_eq!(
        resp.status(),
        201,
        "the registration-time check judges IP literals and the reserved-to-\
         loopback name set only; any other name is accepted and DNS rebinding is \
         explicitly out of scope; got {}",
        resp.status()
    );
}
