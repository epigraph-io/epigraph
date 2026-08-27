//! The anonymous surface is an allowlist, and this test is the lock on it.
//!
//! Plan §4.7. Two halves.
//!
//! # 1. A source lint over `routes/mod.rs`
//!
//! The plan called for a test that "walks BOTH `create_router` variants". It
//! cannot be that, for two independent reasons:
//!
//!   * **axum 0.7.9's `Router` exposes no route enumeration.** There is no API
//!     that yields the set of registered paths, so even the variant that
//!     compiles cannot be interrogated at runtime.
//!   * **The `#[cfg(not(feature = "db"))]` variant is not built in any
//!     buildable configuration.** `epigraph-api`'s default features are
//!     `["db"]`, every CI job builds with defaults, and
//!     `cargo check -p epigraph-api --no-default-features` fails with
//!     pre-existing errors unrelated to tenancy. No compiler checks that
//!     function.
//!
//! So this is a **source-text lint**, which is the stronger choice anyway: it
//! is the only mechanism that covers the second variant at all. Precedent for
//! source scanning in this crate: `tests/identity_provisioning.rs`, which scans
//! `src/` text for `.issue_access_token(` argument shapes.
//!
//! It parses the `let public = Router::new()` chain in each variant and asserts
//! the set of `.route("…")` path literals is EXACTLY the allowlist. Adding a
//! route to `public` fails here, which is the point: putting a route back on
//! the anonymous surface should require editing a file called
//! `public_router_allowlist.rs`.
//!
//! # 2. A live half
//!
//! Boots the real app and checks that **every** route on the `protected` chain
//! — the list derived by the same parser, not a hand-picked sample — actually
//! 401s with an RFC 6750 challenge, and that the two allowlisted routes still
//! answer 200. The source lint proves the registration moved; only the live
//! half proves the middleware is actually layered on it.
//!
//! # What this file does NOT cover
//!
//! Nine `OK → UNAUTHORIZED` assertion flips made in PR-03 live in
//! `#[cfg(not(feature = "db"))]` test modules inside `src/routes/` (`rag.rs`,
//! `admin.rs`, `versioning.rs`, `challenge.rs`, `negative_tests.rs`). That
//! configuration has never compiled — `admin.rs`'s `ApiConfig` literal alone
//! omits a field that exists — so those edits are documentation, not coverage,
//! and `cargo test -p epigraph-api --lib -- --list` does not name them. The
//! classes they claimed to cover (RAG, evidence search, history, challenges,
//! admin stats) are covered here instead, and now exhaustively.

#![cfg(feature = "db")]

mod common;

use std::collections::BTreeSet;

const ROUTES_MOD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/routes/mod.rs");

/// The complete anonymous surface of the `db` build.
///
/// Two application routes + the 11 OAuth/discovery routes = 13 paths reachable
/// with no `Authorization` header. Note this is not the plan's flat 14: it
/// counted `/metrics`, which PR-03 moved off the public listener entirely to
/// the internal listener bound by `bin/server.rs`.
const PUBLIC_ALLOWLIST: &[&str] = &["/health", "/api/v1/openapi.json"];

/// The OAuth/discovery router, `db` variant. Anonymous by construction —
/// discovery and token issuance must precede authentication.
const OAUTH_ALLOWLIST_DB: &[&str] = &[
    "/oauth/token",
    "/oauth/register",
    "/oauth/revoke",
    "/oauth/introspect",
    "/oauth/authorize",
    "/oauth/callback",
    "/oauth/authorize/consent",
    "/oauth/:provider/auth-url",
    "/oauth/:provider/exchange",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
];

/// The OAuth router of the `not(db)` variant is **9** routes, not 11: it lacks
/// `/oauth/callback` and `/oauth/authorize/consent`. That divergence predates
/// PR-03 and is asserted rather than fixed — closing it would mean adding
/// handlers to a build configuration that does not compile.
const OAUTH_ALLOWLIST_NO_DB: &[&str] = &[
    "/oauth/token",
    "/oauth/register",
    "/oauth/revoke",
    "/oauth/introspect",
    "/oauth/authorize",
    "/oauth/:provider/auth-url",
    "/oauth/:provider/exchange",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
];

// ---------------------------------------------------------------------------
// Source lint
// ---------------------------------------------------------------------------

fn source() -> String {
    std::fs::read_to_string(ROUTES_MOD).unwrap_or_else(|e| panic!("cannot read {ROUTES_MOD}: {e}"))
}

/// The source text of one `let <binding> = …;` statement beginning at `start`.
///
/// Terminator detection is **depth-aware**, not line-based. The previous
/// version consumed lines until one whose trimmed form ended in `;`, which had
/// a silent-truncation mode: a `;` inside a route closure
/// (`get(|| async { let x = f(); … })`) ends the scan early, and a truncation
/// that happens to fall *after* the last expected route but *before* a newly
/// added one passes the allowlist assertion while missing the new route. Here a
/// `;` only terminates at paren/bracket/brace depth zero, and string, char and
/// comment contents are skipped, so the returned slice is the whole statement
/// or the function panics.
fn statement_at(src: &str, start: usize) -> &str {
    let bytes = src.as_bytes();
    let mut depth = 0i32;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b';' if depth == 0 => return &src[start..=i],
            b'"' => {
                // Skip a string literal, honouring backslash escapes. Raw
                // strings (r"…", r#"…"#) do not appear in this file; if one is
                // added, the `#` form would need handling here.
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' => i += 1,
                        b'"' => break,
                        _ => {}
                    }
                    i += 1;
                }
            }
            b'\'' => {
                // A char literal, or a lifetime. `'a` (lifetime) has no closing
                // quote, so only treat this as a literal when a closing quote
                // follows within six chars — enough for 'x' and '\n', short
                // enough that `'a` followed by a later quote is not swallowed.
                let close = src[i + 1..]
                    .char_indices()
                    .take(6)
                    .find(|(_, c)| *c == '\'')
                    .map(|(o, _)| i + 1 + o);
                if let Some(c) = close {
                    i = c;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                // Line comment: skip to end of line so a `;` or a quote inside
                // prose cannot confuse the scan.
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    panic!(
        "unterminated statement starting at byte {start} in {ROUTES_MOD}: no \
         `;` at depth zero. The scanner, not the source, is probably wrong."
    );
}

/// Extract every `.route("…")` path literal from a statement's source text.
///
/// Comments inside the statement are NOT stripped, so a doc comment that quotes
/// `.route("/x")` yields a phantom path. That is deliberate: a phantom fails
/// loudly in both directions — the allowlist test reports an unexpected
/// anonymous route, and the live probe gets 404 instead of 401 — whereas a
/// comment-stripping pass that got the boundaries wrong could hide a real one.
fn routes_in(stmt: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut cursor = 0usize;
    while let Some(idx) = stmt[cursor..].find(".route(") {
        let after = cursor + idx + ".route(".len();
        // The path literal is the next `"…"`, whether on this line or the next.
        let open = stmt[after..]
            .find('"')
            .unwrap_or_else(|| panic!("`.route(` with no string literal after it"));
        let lit_start = after + open + 1;
        let close = stmt[lit_start..]
            .find('"')
            .unwrap_or_else(|| panic!("unterminated route literal"));
        paths.push(stmt[lit_start..lit_start + close].to_string());
        cursor = lit_start + close;
    }
    paths
}

/// Byte offsets of every `let <binding> = ` statement, whatever its right-hand
/// side.
///
/// Matching the binding rather than `Router::new()` is what closes the
/// rebinding hole: the chain rebinds `public` and `protected` several times
/// (`let public = public.layer(…)`), and a `.route(` added to one of those
/// rebindings was invisible to a scanner that only looked at the
/// `Router::new()` statement. `no_rebinding_adds_a_route_to_public` asserts
/// those statements are route-free.
fn binding_starts(src: &str, binding: &str) -> Vec<usize> {
    let needle = format!("let {binding} = ");
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(idx) = src[from..].find(&needle) {
        out.push(from + idx);
        from += idx + needle.len();
    }
    out
}

/// The subset of [`binding_starts`] whose right-hand side opens a fresh
/// `Router::new()`. The `db` variant comes first in the file.
fn router_new_starts(src: &str, binding: &str) -> Vec<usize> {
    binding_starts(src, binding)
        .into_iter()
        .filter(|&i| statement_at(src, i).starts_with(&format!("let {binding} = Router::new()")))
        .collect()
}

fn set(v: &[String]) -> BTreeSet<String> {
    v.iter().cloned().collect()
}

fn expected(v: &[&str]) -> BTreeSet<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn public_router_is_exactly_the_allowlist_in_both_variants() {
    let src = source();
    let starts = router_new_starts(&src, "public");
    assert_eq!(
        starts.len(),
        2,
        "expected exactly two `let public = Router::new()` statements (the db \
         and not(db) create_router variants); found {}. If a variant was added \
         or removed, this test must be updated deliberately.",
        starts.len()
    );

    for (variant, start) in [("db", starts[0]), ("not(db)", starts[1])] {
        let found = set(&routes_in(statement_at(&src, start)));
        let want = expected(PUBLIC_ALLOWLIST);
        assert_eq!(
            found,
            want,
            "\n\nThe anonymous route surface of the `{variant}` create_router \
             variant changed.\n\n\
             unexpectedly anonymous: {:?}\n\
             expected but missing:   {:?}\n\n\
             A route in the `public` Router is reachable with NO Authorization \
             header at all — `optional_bearer_auth_middleware` passes a \
             credential-less request straight through. If this route genuinely \
             must be anonymous, add it to PUBLIC_ALLOWLIST here and say why in \
             the commit body. If it does not, move the registration into the \
             `protected` chain.\n",
            found.difference(&want).collect::<Vec<_>>(),
            want.difference(&found).collect::<Vec<_>>(),
        );
    }
}

#[test]
fn oauth_router_is_unchanged_in_both_variants() {
    let src = source();
    let starts = router_new_starts(&src, "oauth");
    assert_eq!(starts.len(), 2, "expected two `let oauth = Router::new()`");

    for (variant, start, want) in [
        ("db", starts[0], expected(OAUTH_ALLOWLIST_DB)),
        ("not(db)", starts[1], expected(OAUTH_ALLOWLIST_NO_DB)),
    ] {
        let found = set(&routes_in(statement_at(&src, start)));
        assert_eq!(
            found, want,
            "\n\nThe `{variant}` OAuth/discovery router changed. These routes \
             are anonymous by construction — a client cannot authenticate \
             before it can discover and obtain a token — so every addition is a \
             new unauthenticated endpoint. Update the allowlist here \
             deliberately.\n"
        );
    }
}

/// The rebinding hole, closed.
///
/// `let public = Router::new()…;` is not the only statement that can put a
/// route on the anonymous surface. The chain rebinds `public` again to attach
/// `optional_bearer_auth_middleware`:
///
/// ```ignore
/// let public = public.layer(middleware::from_fn_with_state(state.clone(), …));
/// ```
///
/// Appending `.route("/leak", get(h))` to *that* statement is a one-token
/// change that puts a route on the anonymous surface, and a lint that only ever
/// looked at the `Router::new()` statement could not see it. Neither could the
/// live half, which probes a finite path list and would never think to try
/// `/leak`.
///
/// So: every `let public = …` statement whose right-hand side is not
/// `Router::new()` must contain no `.route(` at all.
#[test]
fn no_rebinding_adds_a_route_to_public() {
    let src = source();
    let all = binding_starts(&src, "public");
    let fresh = router_new_starts(&src, "public");
    assert_eq!(fresh.len(), 2, "expected two `let public = Router::new()`");
    assert!(
        all.len() >= fresh.len(),
        "binding_starts must be a superset of router_new_starts"
    );

    for start in all {
        if fresh.contains(&start) {
            continue;
        }
        let stmt = statement_at(&src, start);
        let found = routes_in(stmt);
        assert!(
            found.is_empty(),
            "\n\nA `let public = …` REBINDING registers {found:?}.\n\n\
             These routes are on the anonymous surface but are invisible to \
             `public_router_is_exactly_the_allowlist_in_both_variants`, which \
             only reads the `Router::new()` statement. Register anonymous \
             routes in the `Router::new()` chain and add them to \
             PUBLIC_ALLOWLIST, or move them to `protected`.\n\n\
             Offending statement:\n{stmt}\n"
        );
    }
}

/// The same hole on the other side: a route that leaves `protected` silently.
///
/// `let protected = protected.layer(…)` is where `bearer_auth_middleware` is
/// attached. If a future edit splits that into "layer some routes, then
/// re-merge the rest", a route could end up merged into the final router with
/// no auth layer on it and no test would notice: it is in neither the `public`
/// statement (so the allowlist lint is silent) nor behind the layer.
///
/// Assert instead that the final router is assembled from exactly the three
/// bindings this file knows about.
#[test]
fn the_final_router_merges_only_protected_public_and_oauth() {
    let src = source();
    let merges: Vec<&str> = src
        .match_indices(".merge(")
        .map(|(i, _)| {
            let rest = &src[i + ".merge(".len()..];
            let end = rest.find(')').expect("`.merge(` with no closing paren");
            rest[..end].trim()
        })
        .collect();

    assert_eq!(
        merges,
        vec!["protected", "public", "oauth", "protected", "public", "oauth"],
        "routes/mod.rs merges something other than the three known routers \
         (db variant then not(db) variant). A fourth router is a fourth \
         authentication story; this file only knows three."
    );
}

#[test]
fn metrics_is_not_registered_on_either_router() {
    let src = source();
    assert!(
        !src.contains("\"/metrics\""),
        "`/metrics` is registered on an application router again. PR-03 moved \
         Prometheus exposition to a separate internal listener bound by \
         bin/server.rs (EPIGRAPH_METRICS_ADDR, default 127.0.0.1:9090). \
         Putting it back on the public listener reopens the one \
         unauthenticated route that the router inversion deliberately closed."
    );
    // The literal check above is evaded by `const METRICS_PATH: &str = …` or by
    // any other indirection. This second check is on the handler rather than
    // the path: `metrics::metrics_router` and `metrics::metrics_handler` are
    // the only things that can serve Prometheus text, and neither belongs in
    // an application router regardless of the path spelling.
    for needle in ["metrics_router", "metrics_handler"] {
        assert!(
            !src.contains(needle),
            "routes/mod.rs references `{needle}`. Prometheus exposition is \
             served by the internal listener in bin/server.rs; routing it from \
             an application router puts it back on the public port whatever \
             path literal it is registered under."
        );
    }
}

#[test]
fn require_signature_middleware_is_gone() {
    let src = source();
    assert!(
        !src.contains("require_signature,") && !src.contains("require_signature)"),
        "`require_signature` is referenced by routes/mod.rs again. The Ed25519 \
         request-signing middleware was deleted in PR-03: it was unreachable \
         through either create_router, and transport authentication is now \
         OAuth2 Bearer unconditionally. Payload-level packet signatures live in \
         routes/submit.rs behind `require_packet_signatures`."
    );
}

// ---------------------------------------------------------------------------
// Live half
// ---------------------------------------------------------------------------

/// Every path registered on the `db` variant's `protected` router, derived
/// from the source rather than hand-listed.
///
/// This used to be a hand-picked sample of eight, chosen by leak class. A
/// sample is the wrong instrument for the acceptance criterion, which is
/// *"every one of the moved routes returns 401 with a challenge"*: with 200+
/// registrations and PR-07 about to rewrite the handlers, the route that slips
/// out of `protected` is by definition the one nobody thought to sample.
/// Deriving the list costs the same parser the source lint above already uses,
/// and turns the sample into a proof.
///
/// Path parameters are substituted with the nil UUID. That is safe because
/// `bearer_auth_middleware` is a `Router::layer`, so it runs *before* routing
/// resolves a handler and before any extractor parses a segment — a
/// credential-less request is refused whatever the parameter contains, and even
/// on a method the path does not register (no 405 leaks past the layer).
fn protected_paths(src: &str) -> Vec<String> {
    let starts = binding_starts(src, "protected");
    // db variant: `Router::new()`, the `protected.` continuation, and the
    // `.layer(bearer_auth_middleware)` statement. Then the same three for
    // not(db). Only the db variant is buildable, so only it can be probed.
    assert_eq!(
        starts.len(),
        6,
        "expected three `let protected = …` statements per create_router \
         variant; found {}. The derivation below takes the first three as the \
         db variant, so a change in shape must be reflected here.",
        starts.len()
    );

    let mut paths: Vec<String> = Vec::new();
    for &start in &starts[..3] {
        for path in routes_in(statement_at(src, start)) {
            let concrete = path
                .split('/')
                .map(|seg| {
                    if seg.starts_with(':') {
                        "00000000-0000-0000-0000-000000000000"
                    } else {
                        seg
                    }
                })
                .collect::<Vec<_>>()
                .join("/");
            if !paths.contains(&concrete) {
                paths.push(concrete);
            }
        }
    }
    paths
}

#[test]
fn the_protected_router_is_where_the_routes_went() {
    let src = source();
    let protected = protected_paths(&src);
    // A floor, not an exact count: this asserts the derivation found the chain
    // rather than an empty statement, without turning every new route into a
    // failing test. The exhaustive 401 probe below is the real assertion.
    assert!(
        protected.len() > 150,
        "only {} protected paths derived from routes/mod.rs — the parser \
         probably lost the chain, which would make the exhaustive probe below \
         vacuously green",
        protected.len()
    );
    for allowlisted in PUBLIC_ALLOWLIST {
        assert!(
            !protected.contains(&(*allowlisted).to_string()),
            "{allowlisted} is registered on BOTH routers. axum's merge would \
             panic on an exact duplicate, but a path registered for different \
             methods on the two routers would not — and half of it would be \
             anonymous."
        );
    }
}

/// The acceptance criterion, exhaustively: **every** route that moved to
/// `protected` returns 401 with an RFC 6750 challenge to a credential-less
/// request.
#[tokio::test(flavor = "multi_thread")]
async fn moved_routes_401_with_an_rfc6750_challenge() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();

    let paths = protected_paths(&source());
    let mut failures: Vec<String> = Vec::new();

    for path in &paths {
        let resp = client
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path}: {e}"));

        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            failures.push(format!(
                "GET {path} → {} (expected 401). A route on the `protected` \
                 chain answered a request with no Authorization header.",
                resp.status()
            ));
            continue;
        }

        // RFC 6750 §3: without the challenge the client has no
        // machine-readable way to discover which authorization server to talk
        // to, which is the whole point of returning 401 rather than 404.
        match resp.headers().get(reqwest::header::WWW_AUTHENTICATE) {
            None => failures.push(format!("GET {path} → 401 with no WWW-Authenticate header")),
            Some(v) => match v.to_str() {
                Err(_) => failures.push(format!("GET {path} → 401 with a non-ASCII challenge")),
                Ok(challenge) => {
                    if !challenge.starts_with("Bearer ") {
                        failures.push(format!("GET {path} → not a Bearer challenge: {challenge}"));
                    } else if !challenge.contains(r#"error="invalid_token""#) {
                        failures.push(format!(
                            "GET {path} → challenge lacks error=\"invalid_token\": {challenge}"
                        ));
                    }
                }
            },
        }
        // NOT asserted here: the `resource_metadata=` parameter. It comes from
        // a process-global OnceLock that only bin/server.rs initialises, so in
        // this binary the challenge is the bare (still RFC-valid) form.
        // `tests/resource_metadata_challenge.rs` is the single-test binary that
        // installs a URL and asserts the full form.
    }

    assert!(
        failures.is_empty(),
        "\n\n{} of {} protected routes did not refuse an anonymous \
         request correctly:\n\n{}\n",
        failures.len(),
        paths.len(),
        failures.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn allowlisted_routes_still_answer_anonymously() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();

    for path in ["/health", "/api/v1/openapi.json"] {
        let resp = client
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path}: {e}"));
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::OK,
            "GET {path} must stay reachable with no credential — a load \
             balancer cannot mint a token, and a client cannot read the schema \
             to learn how to authenticate if reading the schema requires \
             authentication"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_endpoints_still_answer_anonymously() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let client = reqwest::Client::new();

    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
    ] {
        let resp = client
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path}: {e}"));
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::OK,
            "GET {path} is the document a 401's WWW-Authenticate challenge \
             points at. If it needs a token, the challenge is a loop."
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_is_not_on_the_application_listener() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "/metrics must not be routable on the application listener; it is \
         served by the internal listener bin/server.rs binds from \
         EPIGRAPH_METRICS_ADDR"
    );
}

/// A structurally deficient credential — a valid, unexpired, correctly scoped
/// JWT whose `agent_id` claim is null — is refused 401 `invalid_token` on a
/// protected content route.
///
/// This is the token shape every OAuth client minted before PR-02 populated
/// `oauth_clients.agent_id`, so it is the failure real deployments will hit
/// first. It must be 401 and not 403: 403 says "you are known and the answer is
/// no", inviting an endless retry, whereas `invalid_token` tells the client the
/// remedy is to re-mint.
///
/// `POST /api/v1/claims` is the route under test because it is the one place in
/// PR-03 where a handler (rather than the extractor) enforces this: its author
/// public-key chain used to end in `[0u8; 32]` for exactly this token.
#[tokio::test(flavor = "multi_thread")]
async fn principal_less_token_is_401_invalid_token_on_a_protected_content_route() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;

    // agent_id: None — `test_bearer_token_with_scopes` passes `None` for the
    // principal, which is precisely the case under test.
    let token = common::test_bearer_token_with_scopes(&["claims:write"]);
    // `agent_id` is a required field of `CreateClaimRequest`'s wire shape. It
    // is deliberately set to a random uuid here: the point of the test is that
    // the BODY's agent_id is not a credential, so supplying one must not
    // rescue a token that names no principal.
    let body = serde_json::json!({
        "agent_id": uuid::Uuid::new_v4(),
        "content": format!("principal-less token probe {}", uuid::Uuid::new_v4()),
        "privacy_tier": "public",
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/claims"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let challenge = resp
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().expect("challenge is ASCII").to_string());
    assert_eq!(
        status,
        reqwest::StatusCode::UNAUTHORIZED,
        "a token with a null agent_id must be refused, not absorbed into a \
         zero author key; body={}",
        resp.text().await.unwrap_or_default()
    );
    let challenge = challenge.expect("401 carries an RFC 6750 challenge");
    assert!(
        challenge.contains(r#"error="invalid_token""#),
        "got: {challenge}"
    );
}
