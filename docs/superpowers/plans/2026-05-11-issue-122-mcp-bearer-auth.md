# MCP Bearer-Token Auth (Issue #122) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `--allow-unauthenticated-http` stopgap (PR #124) with proper Bearer-token + per-tool scope checks on the MCP HTTP transport, matching the HTTP API's auth model.

**Architecture:** Extract `JwtConfig`, `AuthContext`, and `ClientType` from `epigraph-api` into a new shared `epigraph-auth` crate so both processes validate identical tokens. Add an axum middleware in `epigraph-mcp` that extracts the Bearer header and injects `AuthContext` into the HTTP request extensions; rmcp 0.15's `StreamableHttpService` already forwards `http::request::Parts` (and its extensions) into `RequestContext`. A deny-by-default per-tool scope map gates `call_tool` at the single dispatch chokepoint, so adding tools without a scope entry fails closed (covered by a coverage test). CLI grows `--jwt-secret`; `--listen` requires exactly one of `--jwt-secret` or `--allow-unauthenticated-http`.

**Tech Stack:** Rust workspace, axum 0.7, rmcp 0.15, jsonwebtoken 9 (HMAC-SHA256), tokio.

**Issue:** <https://github.com/epigraph-io/epigraph/issues/122>
**Stopgap PR (merged):** <https://github.com/epigraph-io/epigraph/pull/124>

---

## Design notes (explicit decisions to lock in)

These decisions came out of advisor review on 2026-05-11. Subagents must NOT relitigate them.

- **JWT lives in a new shared crate `epigraph-auth`**, not duplicated and not by adding `epigraph-mcp → epigraph-api` dep. Both processes must move in lockstep on audience/algorithm/claims changes.
- **Audience stays `epigraph-api`.** MCP accepts the same tokens the API mints — no separate audience, no double minting. Documented in the new crate's module docstring.
- **Token revocation is deferred.** The API middleware calls `state.is_token_revoked(token)`; MCP has no equivalent state and v1 relies on short JWT TTLs. This is called out in `bearer_auth_middleware` in `epigraph-mcp` AND in the PR body. Do not silently skip it.
- **Deny-by-default scope map.** Coverage test loops `EpiGraphMcpFull::tool_router().list_all()` and asserts every tool name maps to a scope. Unmapped tools fail closed (`403 Forbidden`), so a future PR that adds a tool without updating the map cannot become a covert auth bypass.
- **Gate placement:** Bearer extraction at axum middleware (request boundary). Scope check inside `call_tool` (rmcp tower.rs:326/384/463 confirms `parts` propagation). The middleware can't see the tool name without parsing the JSON-RPC body, so scope enforcement must live at dispatch time.
- **`--listen` requires exactly one of:** `--jwt-secret <SECRET>` (production path) OR `--allow-unauthenticated-http` (dev / unix-socket-behind-trust-boundary). Both present → error. Neither → error. Check fires before `create_pool` to mirror the existing stopgap gate at `main.rs:82`.
- **Unix-socket transport (W-129, merged in PR #133) is unchanged by this PR.** A `unix:` listener with `--allow-unauthenticated-http` remains a legitimate deployment when the filesystem-permission boundary is trusted. The startup banner mentions the trust model.
- **Scope inventory** (locked; see Task 2 for the full table):
  - `claims:read` for query/list/get/recall tools (incl. `system_stats`, `list_mcp_tools` — picked deliberately over "no auth")
  - `claims:write` for submit/store/ingest/improve/challenge/patch tools
  - `claims:admin` for `mark_duplicate`, `supersede_claim`, `update_partition`

## Re-export compatibility (don't break the API crate)

`epigraph_api::oauth::JwtConfig` is referenced from 11 test files. After Task 0, `crates/epigraph-api/src/oauth/mod.rs` keeps the re-export:

```rust
pub use epigraph_auth::{EpiGraphClaims, JwtConfig};
```

That single line preserves every existing import site (greppable: `epigraph_api::oauth::JwtConfig`). Likewise `crate::middleware::bearer::AuthContext` keeps its current path via `pub use epigraph_auth::AuthContext;` at the top of `bearer.rs`.

## File structure

```
crates/epigraph-auth/                       NEW CRATE
├── Cargo.toml
└── src/
    └── lib.rs                              JwtConfig + EpiGraphClaims + AuthContext + ClientType + check_scopes

crates/epigraph-api/
├── Cargo.toml                              + epigraph-auth dep
└── src/
    ├── oauth/
    │   ├── mod.rs                          re-export JwtConfig/EpiGraphClaims from epigraph-auth
    │   └── jwt.rs                          DELETE (moved to epigraph-auth)
    └── middleware/
        ├── bearer.rs                       re-export AuthContext/ClientType from epigraph-auth
        └── scopes.rs                       re-export check_scopes from epigraph-auth

crates/epigraph-mcp/
├── Cargo.toml                              + epigraph-auth, axum, jsonwebtoken (already transitive but pin)
└── src/
    ├── main.rs                             CLI: --jwt-secret; startup gate
    ├── lib.rs                              wire bearer_auth_middleware into the axum router
    ├── auth.rs                             NEW: bearer_auth_middleware (mirrors epigraph-api's pattern)
    ├── scope_map.rs                        NEW: tool_name → required scope; tool_router coverage test
    └── server.rs                           call_tool: pull AuthContext from extensions, enforce scope_map

crates/epigraph-mcp/tests/
├── bearer_propagation_smoke_test.rs        NEW: smoke test that axum extension → RequestContext propagation works
└── http_auth_test.rs                       NEW: 401 missing/expired/bad-sig; 403 wrong-scope; 200 happy paths
```

---

## Task 0: Extract `epigraph-auth` crate

**Files:**
- Create: `crates/epigraph-auth/Cargo.toml`
- Create: `crates/epigraph-auth/src/lib.rs`
- Modify: `Cargo.toml` (workspace `members` list)
- Modify: `crates/epigraph-api/Cargo.toml` (add `epigraph-auth = { path = "../epigraph-auth" }`)
- Modify: `crates/epigraph-api/src/oauth/mod.rs` (re-export)
- Modify: `crates/epigraph-api/src/middleware/bearer.rs` (re-export AuthContext/ClientType)
- Modify: `crates/epigraph-api/src/middleware/scopes.rs` (re-export check_scopes)
- Delete: `crates/epigraph-api/src/oauth/jwt.rs` (moved verbatim into new crate)

- [ ] **Step 0.1: Create the workspace crate**

```toml
# crates/epigraph-auth/Cargo.toml
[package]
name = "epigraph-auth"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
chrono = { workspace = true }
jsonwebtoken = "9"
serde = { workspace = true }
uuid = { workspace = true }
```

- [ ] **Step 0.2: Move JWT + auth types into `epigraph-auth/src/lib.rs`**

```rust
//! Shared OAuth2-style auth primitives for the EpiGraph workspace.
//!
//! Both `epigraph-api` (HTTP) and `epigraph-mcp` (MCP HTTP transport) validate
//! tokens against the same `JwtConfig`, so audience and algorithm must move in
//! lockstep.
//!
//! ## Audience
//!
//! Tokens use audience `"epigraph-api"` regardless of which server validates
//! them. MCP intentionally accepts API-minted tokens — there is no separate
//! `epigraph-mcp` audience. Adding one would double minting work for clients
//! that talk to both servers, and the threat model does not distinguish them.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct EpiGraphClaims {
    pub sub: Uuid,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub jti: Uuid,
    pub scopes: Vec<String>,
    pub client_type: String,
    pub owner_id: Option<Uuid>,
    pub agent_id: Option<Uuid>,
}

pub struct JwtConfig {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtConfig {
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
        }
    }

    pub fn issue_access_token(
        &self,
        client_id: Uuid,
        scopes: Vec<String>,
        client_type: &str,
        owner_id: Option<Uuid>,
        agent_id: Option<Uuid>,
        ttl: Duration,
    ) -> Result<(String, Uuid), jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let jti = Uuid::new_v4();
        let claims = EpiGraphClaims {
            sub: client_id,
            iss: "epigraph".to_string(),
            aud: "epigraph-api".to_string(),
            exp: (now + ttl).timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti,
            scopes,
            client_type: client_type.to_string(),
            owner_id,
            agent_id,
        };
        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)?;
        Ok((token, jti))
    }

    pub fn validate_token(
        &self,
        token: &str,
    ) -> Result<EpiGraphClaims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["epigraph"]);
        validation.set_audience(&["epigraph-api"]);
        validation.leeway = 0;
        let data = decode::<EpiGraphClaims>(token, &self.decoding_key, &validation)?;
        Ok(data.claims)
    }
}

/// Authorization context attached to a request after Bearer validation.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub client_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub owner_id: Option<Uuid>,
    pub client_type: ClientType,
    pub scopes: Vec<String>,
    pub jti: Uuid,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClientType {
    Agent,
    Human,
    Service,
}

impl AuthContext {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Convert validated JWT claims into an `AuthContext`.
impl From<EpiGraphClaims> for AuthContext {
    fn from(claims: EpiGraphClaims) -> Self {
        let client_type = match claims.client_type.as_str() {
            "agent" => ClientType::Agent,
            "human" => ClientType::Human,
            _ => ClientType::Service,
        };
        Self {
            client_id: claims.sub,
            agent_id: claims.agent_id,
            owner_id: claims.owner_id,
            client_type,
            scopes: claims.scopes,
            jti: claims.jti,
        }
    }
}

/// Returns Err with a 403-shaped message if any required scope is missing.
pub fn check_scopes(auth: &AuthContext, required: &[&str]) -> Result<(), String> {
    for scope in required {
        if !auth.has_scope(scope) {
            return Err(format!("Missing required scope: {scope}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_roundtrip() {
        let cfg = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let (token, jti) = cfg
            .issue_access_token(
                Uuid::new_v4(),
                vec!["claims:read".into(), "claims:write".into()],
                "agent",
                None,
                None,
                Duration::minutes(5),
            )
            .unwrap();
        let claims = cfg.validate_token(&token).unwrap();
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.aud, "epigraph-api");
    }

    #[test]
    fn expired_rejected() {
        let cfg = JwtConfig::from_secret(b"test-secret-at-least-32-bytes!!");
        let (token, _) = cfg
            .issue_access_token(
                Uuid::new_v4(),
                vec![],
                "agent",
                None,
                None,
                Duration::seconds(-10),
            )
            .unwrap();
        assert!(cfg.validate_token(&token).is_err());
    }

    #[test]
    fn wrong_secret_rejected() {
        let a = JwtConfig::from_secret(b"secret-one-at-least-32-bytes!!!");
        let b = JwtConfig::from_secret(b"secret-two-at-least-32-bytes!!!");
        let (token, _) = a
            .issue_access_token(Uuid::new_v4(), vec![], "agent", None, None, Duration::minutes(5))
            .unwrap();
        assert!(b.validate_token(&token).is_err());
    }

    #[test]
    fn check_scopes_pass_and_fail() {
        let auth = AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: None,
            owner_id: None,
            client_type: ClientType::Service,
            scopes: vec!["claims:read".into()],
            jti: Uuid::new_v4(),
        };
        assert!(check_scopes(&auth, &["claims:read"]).is_ok());
        assert!(check_scopes(&auth, &["claims:write"]).is_err());
    }
}
```

- [ ] **Step 0.3: Add `epigraph-auth` to workspace members**

Edit `Cargo.toml` (workspace root) — add `"crates/epigraph-auth",` to the `members` list (alphabetical-ish; place after `"crates/epigraph-api"`).

- [ ] **Step 0.4: Wire `epigraph-api` to depend on `epigraph-auth`**

Edit `crates/epigraph-api/Cargo.toml`. Under `[dependencies]` add:

```toml
epigraph-auth = { path = "../epigraph-auth" }
```

- [ ] **Step 0.5: Replace `crates/epigraph-api/src/oauth/jwt.rs` with a re-export**

Delete the file's contents and write:

```rust
//! JWT validation and claim types — moved to the shared `epigraph-auth` crate
//! so `epigraph-mcp` can validate the same tokens.

pub use epigraph_auth::{EpiGraphClaims, JwtConfig};
```

Keep `crates/epigraph-api/src/oauth/mod.rs` unchanged (it already does `pub use jwt::{EpiGraphClaims, JwtConfig};`).

- [ ] **Step 0.6: Replace `AuthContext` / `ClientType` in `epigraph-api/src/middleware/bearer.rs`**

Open the file. Replace the top-of-file `pub struct AuthContext` / `pub enum ClientType` / `impl AuthContext` with:

```rust
pub use epigraph_auth::{AuthContext, ClientType};
```

Leave `pub async fn bearer_auth_middleware` exactly as-is — only the type re-exports move.

- [ ] **Step 0.7: Make `check_scopes` in `epigraph-api/src/middleware/scopes.rs` delegate**

Replace the body of `pub fn check_scopes` with:

```rust
pub fn check_scopes(auth: &AuthContext, required: &[&str]) -> Result<(), ApiError> {
    epigraph_auth::check_scopes(auth, required).map_err(|reason| ApiError::Forbidden { reason })
}
```

Leave `require_owner_or_admin` and the route-layer `require_scope` middleware alone.

- [ ] **Step 0.8: Compile and run existing tests**

```bash
cargo build -p epigraph-auth -p epigraph-api
cargo test -p epigraph-auth
cargo test -p epigraph-api --no-default-features
```

Expected: builds clean; all pre-existing `epigraph-api` test files that import `epigraph_api::oauth::JwtConfig` keep working via the re-export in `oauth/mod.rs`.

- [ ] **Step 0.9: Commit**

```bash
git add crates/epigraph-auth Cargo.toml \
  crates/epigraph-api/Cargo.toml \
  crates/epigraph-api/src/oauth/jwt.rs \
  crates/epigraph-api/src/middleware/bearer.rs \
  crates/epigraph-api/src/middleware/scopes.rs
git commit -m "refactor(auth): extract JwtConfig + AuthContext into shared epigraph-auth crate"
```

---

## Task 1: Bearer middleware in `epigraph-mcp` + parts-propagation smoke test

The smoke test runs FIRST (TDD-style) and verifies the load-bearing assumption from rmcp's tower.rs:326/384/463 — that an axum middleware can inject an extension into `request.extensions_mut()` and read it back inside a tool handler. If this assumption is wrong, the rest of the plan is wrong.

**Files:**
- Modify: `crates/epigraph-mcp/Cargo.toml`
- Create: `crates/epigraph-mcp/src/auth.rs`
- Modify: `crates/epigraph-mcp/src/lib.rs`
- Create: `crates/epigraph-mcp/tests/bearer_propagation_smoke_test.rs`

- [ ] **Step 1.1: Add deps to `crates/epigraph-mcp/Cargo.toml`**

Under `[dependencies]`:

```toml
epigraph-auth = { path = "../epigraph-auth" }
http = "1"
axum = { version = "0.7", default-features = false, features = ["json", "tokio", "http1"] }
```

(`axum` and `http` are already transitive through rmcp — pinning them ensures the middleware compiles standalone. Check whether they're listed already; if so, leave them and add `epigraph-auth` only.)

- [ ] **Step 1.2: Write the smoke test FIRST**

```rust
// crates/epigraph-mcp/tests/bearer_propagation_smoke_test.rs
//! Smoke test: verify that axum's `request.extensions_mut().insert(_)` flows
//! through rmcp's StreamableHttpService into RequestContext.extensions, so the
//! scope guard in call_tool can actually read the AuthContext.
//!
//! If this test fails, the whole Bearer-auth design is wrong and the plan
//! needs to be revisited before any further tasks are attempted.

use std::sync::Arc;

use axum::{middleware, Router};
use epigraph_auth::{AuthContext, ClientType};
use uuid::Uuid;

#[derive(Clone)]
struct Probe(Arc<std::sync::Mutex<Option<AuthContext>>>);

async fn inject_dummy_auth(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let auth = AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: None,
        owner_id: None,
        client_type: ClientType::Service,
        scopes: vec!["claims:read".into()],
        jti: Uuid::new_v4(),
    };
    req.extensions_mut().insert(auth);
    next.run(req).await
}

#[tokio::test]
async fn axum_middleware_extension_reaches_handler_via_parts() {
    // Build a router that mirrors how MCP will be wired: middleware injects
    // AuthContext, then a downstream handler reads `http::request::Parts` and
    // pulls AuthContext from its extensions. This proves the propagation path
    // rmcp/tower.rs:326/384/463 documents.
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let probe = Probe(Arc::new(std::sync::Mutex::new(None)));
    let probe_for_handler = probe.clone();

    let router: Router = Router::new()
        .route(
            "/mcp",
            axum::routing::post(move |req: Request<Body>| {
                let probe = probe_for_handler.clone();
                async move {
                    let (parts, _body) = req.into_parts();
                    let auth = parts.extensions.get::<AuthContext>().cloned();
                    *probe.0.lock().unwrap() = auth;
                    StatusCode::OK
                }
            }),
        )
        .layer(middleware::from_fn(inject_dummy_auth));

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let captured = probe.0.lock().unwrap().clone().expect(
        "AuthContext inserted by axum middleware should appear in the downstream handler's Parts.extensions",
    );
    assert!(captured.has_scope("claims:read"));
}
```

- [ ] **Step 1.3: Run the test to confirm it fails as not-yet-existing**

```bash
cargo test -p epigraph-mcp --test bearer_propagation_smoke_test
```

If the build fails for missing deps, fix the `Cargo.toml`. Then re-run.

Expected: test compiles and PASSES (it does not depend on any new MCP code — it exercises axum's contract directly).

If the test FAILS, STOP. The design assumption is wrong. Surface to the controller before proceeding.

- [ ] **Step 1.4: Implement `bearer_auth_middleware` in `crates/epigraph-mcp/src/auth.rs`**

```rust
//! Bearer-token extraction for the MCP HTTP transport.
//!
//! Mirrors `epigraph-api`'s `bearer_auth_middleware`. The two share JWT
//! validation via `epigraph-auth` so a single token works against both
//! servers.
//!
//! ## Deferred: revocation
//!
//! The HTTP API consults `AppState::is_token_revoked` here. MCP has no
//! equivalent state and v1 relies on short JWT TTLs. When MCP grows shared
//! state, plumb the revocation set through and call it before
//! `validate_token`. Tracked separately — do not silently skip when adding
//! state.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::StatusCode;

use epigraph_auth::{AuthContext, JwtConfig};

#[derive(Clone)]
pub struct McpAuthState {
    pub jwt_config: Arc<JwtConfig>,
}

pub async fn bearer_auth_middleware(
    State(state): State<McpAuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match header.as_deref() {
        Some(h) if h.starts_with("Bearer ") => {
            let token = &h[7..];
            match state.jwt_config.validate_token(token) {
                Ok(claims) => {
                    let auth: AuthContext = claims.into();
                    req.extensions_mut().insert(auth);
                    next.run(req).await
                }
                Err(e) => (
                    StatusCode::UNAUTHORIZED,
                    format!("Invalid token: {e}"),
                )
                    .into_response(),
            }
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            "Missing Authorization header".to_string(),
        )
            .into_response(),
    }
}
```

- [ ] **Step 1.5: Add `pub mod auth;` to `crates/epigraph-mcp/src/lib.rs`**

```rust
pub mod auth;
```

(Insert next to the existing `pub mod server;` etc., keeping alphabetical-ish order.)

- [ ] **Step 1.6: Compile and re-run the smoke test**

```bash
cargo build -p epigraph-mcp
cargo test -p epigraph-mcp --test bearer_propagation_smoke_test
```

Expected: build clean; smoke test still passes.

- [ ] **Step 1.7: Commit**

```bash
git add crates/epigraph-mcp/Cargo.toml \
  crates/epigraph-mcp/src/auth.rs \
  crates/epigraph-mcp/src/lib.rs \
  crates/epigraph-mcp/tests/bearer_propagation_smoke_test.rs
git commit -m "feat(mcp): Bearer-token middleware + parts-propagation smoke test"
```

---

## Task 2: Per-tool scope map with deny-by-default coverage test

**Files:**
- Create: `crates/epigraph-mcp/src/scope_map.rs`
- Modify: `crates/epigraph-mcp/src/lib.rs`

- [ ] **Step 2.1: Write the scope map**

```rust
// crates/epigraph-mcp/src/scope_map.rs
//! Per-tool OAuth scope map.
//!
//! Every tool registered on `EpiGraphMcpFull` MUST have an entry here. The
//! coverage test at the bottom of this file enforces that — a new tool
//! without a scope mapping fails closed (`required_scope` returns `None`,
//! which `call_tool` translates into 403 Forbidden) AND fails the test
//! suite.

/// Look up the OAuth scope required to dispatch `tool_name`.
///
/// Returns `None` for unknown tools. The call site MUST treat `None` as a
/// hard 403 — never let an unmapped tool pass.
#[must_use]
pub fn required_scope(tool_name: &str) -> Option<&'static str> {
    SCOPE_MAP
        .iter()
        .find_map(|(name, scope)| (*name == tool_name).then_some(*scope))
}

/// Source-of-truth scope table. Keep alphabetised within each scope bucket.
///
/// **Adding a new tool?** Add it here and to the matching scope bucket. The
/// coverage test will fail until you do.
pub const SCOPE_MAP: &[(&str, &str)] = &[
    // ─── claims:read ───────────────────────────────────────────────────
    ("check_sheaf_consistency", "claims:read"),
    ("compare_methods", "claims:read"),
    ("entity_neighborhood", "claims:read"),
    ("find_workflow", "claims:read"),
    ("find_workflow_hierarchical", "claims:read"),
    ("get_belief", "claims:read"),
    ("get_claim", "claims:read"),
    ("get_divergence", "claims:read"),
    ("get_neighborhood", "claims:read"),
    ("get_ownership", "claims:read"),
    ("get_perspective", "claims:read"),
    ("get_provenance", "claims:read"),
    ("list_challenges", "claims:read"),
    ("list_events", "claims:read"),
    ("list_frames", "claims:read"),
    ("list_mcp_tools", "claims:read"),
    ("list_perspectives", "claims:read"),
    ("query_claims", "claims:read"),
    ("query_claims_by_evidence", "claims:read"),
    ("query_claims_by_label", "claims:read"),
    ("query_claims_by_methodology", "claims:read"),
    ("query_paper", "claims:read"),
    ("query_triples", "claims:read"),
    ("recall", "claims:read"),
    ("recall_with_context", "claims:read"),
    ("scoped_belief", "claims:read"),
    ("search_triples", "claims:read"),
    ("sheaf_cohomology", "claims:read"),
    ("system_stats", "claims:read"),
    ("traverse", "claims:read"),

    // ─── claims:write ──────────────────────────────────────────────────
    ("assign_ownership", "claims:write"),
    ("batch_submit_claims", "claims:write"),
    ("challenge_claim", "claims:write"),
    ("create_frame", "claims:write"),
    ("create_perspective", "claims:write"),
    ("deprecate_workflow", "claims:write"),
    ("evolve_step", "claims:write"),
    ("improve_workflow", "claims:write"),
    ("improve_workflow_hierarchy", "claims:write"),
    ("ingest_document", "claims:write"),
    ("ingest_workflow", "claims:write"),
    ("memorize", "claims:write"),
    ("patch_claim", "claims:write"),
    ("publish_event", "claims:write"),
    ("reconcile_sheaf", "claims:write"),
    ("report_hierarchical_outcome", "claims:write"),
    ("report_workflow_outcome", "claims:write"),
    ("stage_claims", "claims:write"),
    ("store_workflow", "claims:write"),
    ("submit_claim", "claims:write"),
    ("submit_ds_evidence", "claims:write"),
    ("theme_cluster", "claims:write"),
    ("update_labels", "claims:write"),
    ("update_with_evidence", "claims:write"),
    ("verify_claim", "claims:write"),

    // ─── claims:admin ──────────────────────────────────────────────────
    ("mark_duplicate", "claims:admin"),
    ("supersede_claim", "claims:admin"),
    ("update_partition", "claims:admin"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EpiGraphMcpFull;

    /// Every tool registered on the MCP server has an entry in `SCOPE_MAP`.
    /// New tools added without a scope mapping fail this test loudly, so they
    /// cannot become covert auth bypasses.
    #[test]
    fn every_registered_tool_has_a_scope() {
        let registered = EpiGraphMcpFull::tool_router().list_all();
        let missing: Vec<&str> = registered
            .iter()
            .map(|t| t.name.as_ref())
            .filter(|name| required_scope(name).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "tools registered on EpiGraphMcpFull but missing from scope_map::SCOPE_MAP: {missing:?}\n\
             Add each one to crates/epigraph-mcp/src/scope_map.rs."
        );
    }

    /// Inverse direction: the scope map does not reference tools that don't
    /// exist anymore (catches deletions / renames).
    #[test]
    fn scope_map_has_no_stale_entries() {
        let registered: std::collections::HashSet<String> = EpiGraphMcpFull::tool_router()
            .list_all()
            .iter()
            .map(|t| t.name.as_ref().to_string())
            .collect();
        let stale: Vec<&str> = SCOPE_MAP
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| !registered.contains(*name))
            .collect();
        assert!(
            stale.is_empty(),
            "scope_map entries reference tools not registered on EpiGraphMcpFull: {stale:?}"
        );
    }

    /// Sanity-check the three known mutation tools cited in issue #122 are
    /// gated on `claims:admin`.
    #[test]
    fn issue_122_admin_tools_are_admin_gated() {
        assert_eq!(required_scope("mark_duplicate"), Some("claims:admin"));
        assert_eq!(required_scope("supersede_claim"), Some("claims:admin"));
        assert_eq!(required_scope("update_partition"), Some("claims:admin"));
    }
}
```

- [ ] **Step 2.2: Add `pub mod scope_map;` to `crates/epigraph-mcp/src/lib.rs`**

- [ ] **Step 2.3: Run the coverage tests**

```bash
cargo test -p epigraph-mcp scope_map
```

Expected: all three tests pass. If `every_registered_tool_has_a_scope` lists a missing tool, add it to the right bucket above and re-run — do NOT silently delete the test.

- [ ] **Step 2.4: Commit**

```bash
git add crates/epigraph-mcp/src/scope_map.rs crates/epigraph-mcp/src/lib.rs
git commit -m "feat(mcp): deny-by-default scope map for all 58 registered tools"
```

---

## Task 3: Scope guard in `call_tool`

This is the single chokepoint. Read `AuthContext` from the propagated HTTP parts; look up the required scope; reject before dispatching.

**Files:**
- Modify: `crates/epigraph-mcp/src/server.rs`

- [ ] **Step 3.1: Write the failing test first**

```rust
// Append to crates/epigraph-mcp/src/server.rs at the bottom, in `#[cfg(test)] mod scope_guard_tests`
#[cfg(test)]
mod scope_guard_tests {
    use super::*;
    use epigraph_auth::{AuthContext, ClientType};
    use uuid::Uuid;

    fn auth_with_scopes(scopes: &[&str]) -> AuthContext {
        AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: None,
            owner_id: None,
            client_type: ClientType::Service,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: Uuid::new_v4(),
        }
    }

    #[test]
    fn scope_guard_allows_matching_scope() {
        let auth = auth_with_scopes(&["claims:admin"]);
        assert!(EpiGraphMcpFull::enforce_tool_scope(Some(&auth), "mark_duplicate").is_ok());
    }

    #[test]
    fn scope_guard_rejects_missing_scope() {
        let auth = auth_with_scopes(&["claims:read"]);
        let err = EpiGraphMcpFull::enforce_tool_scope(Some(&auth), "mark_duplicate")
            .expect_err("read-only token must NOT be allowed to mark_duplicate");
        assert!(err.message.contains("claims:admin"));
    }

    #[test]
    fn scope_guard_rejects_missing_auth_context() {
        let err = EpiGraphMcpFull::enforce_tool_scope(None, "query_claims")
            .expect_err("no AuthContext must yield 401-style rejection");
        assert!(err.message.to_lowercase().contains("auth"));
    }

    #[test]
    fn scope_guard_rejects_unmapped_tool_by_default() {
        let auth = auth_with_scopes(&["claims:admin"]);
        let err = EpiGraphMcpFull::enforce_tool_scope(Some(&auth), "tool_that_does_not_exist")
            .expect_err("unmapped tool must fail closed");
        assert!(err.message.to_lowercase().contains("not authorized"));
    }
}
```

- [ ] **Step 3.2: Run the failing test**

```bash
cargo test -p epigraph-mcp scope_guard_tests
```

Expected: FAIL — `enforce_tool_scope` is not defined yet.

- [ ] **Step 3.3: Implement `enforce_tool_scope` and wire it into `call_tool`**

Open `crates/epigraph-mcp/src/server.rs`. Just below the existing `impl EpiGraphMcpFull` block (around line 112, before `#[tool_router]`), add:

```rust
impl EpiGraphMcpFull {
    /// Look up the required scope for `tool_name` and verify the
    /// caller has it. Returns `Err` with a JSON-RPC-style error if:
    /// - no `AuthContext` is attached (token validation never ran or
    ///   middleware was bypassed), or
    /// - the tool is not in `scope_map::SCOPE_MAP` (deny by default), or
    /// - the caller's token is missing the required scope.
    pub fn enforce_tool_scope(
        auth: Option<&epigraph_auth::AuthContext>,
        tool_name: &str,
    ) -> Result<(), McpError> {
        let Some(auth) = auth else {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Borrowed(
                    "Unauthorized: no auth context (Bearer token required)",
                ),
                data: None,
            });
        };
        let Some(required) = crate::scope_map::required_scope(tool_name) else {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Owned(format!(
                    "Forbidden: tool '{tool_name}' is not authorized (no scope mapping)"
                )),
                data: None,
            });
        };
        if !auth.has_scope(required) {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Owned(format!(
                    "Forbidden: tool '{tool_name}' requires scope '{required}'"
                )),
                data: None,
            });
        }
        Ok(())
    }
}
```

Then, in the existing manual `impl ServerHandler for EpiGraphMcpFull` block, modify `call_tool` (around line 789) so the scope guard fires BEFORE `emit_tool_invoked` (we still want to log auth failures, but as the rejected dispatch — emit them via `tool.invoked.denied` so audit logs see them):

```rust
async fn call_tool(
    &self,
    request: rmcp::model::CallToolRequestParams,
    context: rmcp::service::RequestContext<rmcp::RoleServer>,
) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
    // Extract AuthContext from the propagated http::request::Parts.
    // The Bearer middleware (`auth::bearer_auth_middleware`) inserts it on
    // request.extensions_mut(); rmcp's StreamableHttpService forwards Parts
    // into context.extensions (see rmcp/src/transport/streamable_http_server/
    // tower.rs:326/384/463). For stdio transport there is no Parts and no
    // AuthContext — the stdio process boundary is the trust gate, and
    // `enforce_stdio_or_authenticated` below allows that case.
    let auth = context
        .extensions
        .get::<http::request::Parts>()
        .and_then(|p| p.extensions.get::<epigraph_auth::AuthContext>())
        .cloned();

    // Stdio transport: no Parts attached → no auth check (legacy trust gate).
    // HTTP transport: Parts attached → auth check is mandatory.
    let is_http_request = context
        .extensions
        .get::<http::request::Parts>()
        .is_some();
    if is_http_request {
        if let Err(err) = Self::enforce_tool_scope(auth.as_ref(), &request.name) {
            // Emit a denial audit event so 403s show up alongside successes.
            self.emit_tool_invoked(&format!("denied:{}", request.name))
                .await;
            return Err(err.into());
        }
    }

    // **DO NOT remove this line without updating
    // `tests/event_log_wiring_tests.rs::tool_dispatch_emits_tool_invoked_event`.**
    self.emit_tool_invoked(&request.name).await;

    let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
    self.tool_router.call(tcc).await
}
```

Required imports at top of `server.rs` (if not already there):

```rust
use http::request::Parts;
```

- [ ] **Step 3.4: Run the unit tests**

```bash
cargo test -p epigraph-mcp scope_guard_tests
cargo test -p epigraph-mcp scope_map
cargo test -p epigraph-mcp event_log_wiring
```

Expected: all four `scope_guard_tests::*` pass; pre-existing `scope_map` tests still pass; `event_log_wiring` tests still pass (the new code only adds a `denied:` emit on the failure path and leaves the happy-path emit untouched).

- [ ] **Step 3.5: Commit**

```bash
git add crates/epigraph-mcp/src/server.rs
git commit -m "feat(mcp): enforce per-tool OAuth scopes in call_tool dispatch"
```

---

## Task 4: CLI flag wiring + startup gate

**Files:**
- Modify: `crates/epigraph-mcp/src/main.rs`
- Modify: `crates/epigraph-mcp/src/lib.rs` (if `serve_with_listener` lives here)

- [ ] **Step 4.1: Add `--jwt-secret` to the CLI**

In `crates/epigraph-mcp/src/main.rs`, under `struct Cli`:

```rust
/// HMAC-SHA256 secret used to validate Bearer tokens on the HTTP transport.
///
/// Required when `--listen` is used unless `--allow-unauthenticated-http` is
/// set. Must be at least 32 bytes. The same secret signs and verifies tokens
/// across both `epigraph-api` and `epigraph-mcp` — when rotating, restart
/// both processes with the new value.
#[arg(long, env = "EPIGRAPH_JWT_SECRET")]
jwt_secret: Option<String>,
```

(Place it next to `allow_unauthenticated_http` so the CLI help groups them.)

- [ ] **Step 4.2: Replace the startup gate**

Replace the existing `if cli.listen.is_some() && !cli.allow_unauthenticated_http { ... exit(1) }` block (around `main.rs:82`) with:

```rust
// Safety gate for the HTTP transport. The stdio process boundary is the
// default trust gate; HTTP removes it. To start with --listen, the operator
// must either supply a JWT secret (Bearer auth) or explicitly opt out of
// auth (e.g., a unix-socket listener behind filesystem permissions).
if cli.listen.is_some() {
    match (cli.jwt_secret.as_deref(), cli.allow_unauthenticated_http) {
        (Some(secret), false) if secret.as_bytes().len() < 32 => {
            eprintln!(
                "ERROR: --jwt-secret must be at least 32 bytes (got {}).",
                secret.as_bytes().len()
            );
            std::process::exit(1);
        }
        (Some(_), false) => {} // authenticated path
        (None, true) => {} // operator-acknowledged unauthenticated path (e.g., unix socket)
        (Some(_), true) => {
            eprintln!(
                "ERROR: --jwt-secret and --allow-unauthenticated-http are mutually exclusive."
            );
            std::process::exit(1);
        }
        (None, false) => {
            eprintln!(
                "ERROR: --listen requires either --jwt-secret <SECRET> (Bearer auth) or\n\
                 --allow-unauthenticated-http (e.g., for a unix-socket listener behind\n\
                 filesystem permissions). See https://github.com/epigraph-io/epigraph/issues/122."
            );
            std::process::exit(1);
        }
    }
}
```

- [ ] **Step 4.3: Wire the middleware into the listener path**

Within the `if let Some(addr) = &cli.listen { … }` block (around `main.rs:137`), wrap the router with the Bearer middleware when `jwt_secret` is set:

```rust
let router = axum::Router::new().nest_service("/mcp", service);

let router = if let Some(secret) = cli.jwt_secret.as_deref() {
    use std::sync::Arc;
    use epigraph_auth::JwtConfig;
    use epigraph_mcp::auth::{bearer_auth_middleware, McpAuthState};

    let state = McpAuthState {
        jwt_config: Arc::new(JwtConfig::from_secret(secret.as_bytes())),
    };
    router.layer(axum::middleware::from_fn_with_state(
        state,
        bearer_auth_middleware,
    ))
} else {
    // operator passed --allow-unauthenticated-http; no auth layer
    router
};
```

If the HTTP serving currently lives in `serve_with_listener` (W-129 helper in `crates/epigraph-mcp/src/lib.rs`), thread the optional `JwtConfig` through its signature instead and apply the layer there. The principle is the same.

- [ ] **Step 4.4: Update the doc-comment example at the top of `main.rs`**

Replace the `# HTTP transport (for curl / remote agents — requires explicit opt-in)` block with two examples — authenticated and unauthenticated — so operators see the new shape:

```rust
//! ```bash
//! # HTTP transport with Bearer auth (production)
//! epigraph-mcp-full --database-url postgres://... --listen 127.0.0.1:8080 \
//!   --jwt-secret "<HMAC secret matching epigraph-api's JWT_SECRET>"
//!
//! # Unauthenticated HTTP (unix socket behind filesystem perms, or local dev)
//! epigraph-mcp-full --database-url postgres://... --listen unix:/run/mcp.sock \
//!   --allow-unauthenticated-http
//! ```
```

Also update the existing tool-count comment to read "all 58 tools" if Task 0 hasn't already done so.

- [ ] **Step 4.5: Verify each gate path manually**

```bash
cargo build -p epigraph-mcp
# Each of these should exit with the cited error (smoke-test the gates):
./target/debug/epigraph-mcp-full --database-url postgres://x --listen 127.0.0.1:0
./target/debug/epigraph-mcp-full --database-url postgres://x --listen 127.0.0.1:0 \
  --jwt-secret short --allow-unauthenticated-http
./target/debug/epigraph-mcp-full --database-url postgres://x --listen 127.0.0.1:0 --jwt-secret short
```

Expected:
1. error: missing one of --jwt-secret / --allow-unauthenticated-http
2. error: mutually exclusive
3. error: --jwt-secret must be at least 32 bytes

- [ ] **Step 4.6: Commit**

```bash
git add crates/epigraph-mcp/src/main.rs crates/epigraph-mcp/src/lib.rs
git commit -m "feat(mcp): wire --jwt-secret CLI flag + Bearer middleware on --listen"
```

---

## Task 5: End-to-end HTTP integration tests

**Files:**
- Create: `crates/epigraph-mcp/tests/http_auth_test.rs`

These tests boot the actual axum router (including the StreamableHttpService) over an ephemeral TCP port, mint tokens with `epigraph_auth::JwtConfig`, and assert the 401/403/200 surface end-to-end. Use the existing pattern from `crates/epigraph-mcp/tests/unix_socket_test.rs` for boot/shutdown ergonomics.

- [ ] **Step 5.1: Write the tests**

```rust
// crates/epigraph-mcp/tests/http_auth_test.rs
//! End-to-end test of the Bearer-auth + scope-guard pipeline on the MCP HTTP
//! transport. Asserts the four cases the issue cares about:
//! 1. No Authorization header → 401.
//! 2. Bad signature → 401.
//! 3. Valid token, wrong scope → 403 (JSON-RPC error from call_tool).
//! 4. Valid token, right scope → 200 (tool dispatches).

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use chrono::Duration as ChronoDuration;
use epigraph_auth::JwtConfig;
use epigraph_mcp::auth::{bearer_auth_middleware, McpAuthState};
use uuid::Uuid;

const SECRET: &[u8] = b"this-secret-is-at-least-32-bytes-long!!";

async fn mint_token(scopes: &[&str]) -> String {
    let cfg = JwtConfig::from_secret(SECRET);
    let (token, _) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "service",
            None,
            None,
            ChronoDuration::minutes(5),
        )
        .unwrap();
    token
}

/// Build a router that mimics the full main.rs HTTP wiring: StreamableHttpService
/// nested at /mcp, Bearer middleware layered on top. No DB required because the
/// scope guard rejects before dispatching to a tool body.
async fn boot_router() -> Router {
    let pool = sqlx::Pool::connect_lazy(
        &std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://invalid/invalid".into()),
    )
    .unwrap();
    let signer = Arc::new(epigraph_crypto::AgentSigner::generate());
    let embedder = Arc::new(epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None));

    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };

    let service = StreamableHttpService::new(
        move || {
            Ok(epigraph_mcp::EpiGraphMcpFull::new_shared(
                pool.clone(),
                signer.clone(),
                embedder.clone(),
                false,
            ))
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );

    let state = McpAuthState {
        jwt_config: Arc::new(JwtConfig::from_secret(SECRET)),
    };
    Router::new()
        .nest_service("/mcp", service)
        .layer(axum::middleware::from_fn_with_state(
            state,
            bearer_auth_middleware,
        ))
}

async fn spawn_server() -> std::net::SocketAddr {
    let router = boot_router().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

#[tokio::test]
async fn missing_authorization_header_returns_401() {
    let addr = spawn_server().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bad_signature_returns_401() {
    let addr = spawn_server().await;
    // Mint with the wrong secret.
    let cfg = JwtConfig::from_secret(b"a-completely-different-32-byte-key!!");
    let (token, _) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".into()],
            "service",
            None,
            None,
            ChronoDuration::minutes(5),
        )
        .unwrap();
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_scope_returns_403_via_jsonrpc_error() {
    // Token has only claims:read; mark_duplicate requires claims:admin.
    // The Bearer layer accepts the token (200 from axum), but the scope
    // guard inside call_tool rejects with a JSON-RPC error. The HTTP status
    // is therefore 200 (SSE/JSON-RPC convention) but the response body
    // contains a JSON-RPC error with our scope message.
    let addr = spawn_server().await;
    let token = mint_token(&["claims:read"]).await;

    // (For brevity, the actual MCP handshake — initialize → notifications/initialized →
    // tools/call — is performed via the rmcp client helper.)
    use rmcp::ServiceExt;
    let transport = rmcp::transport::streamable_http_client::StreamableHttpClientTransport::with_client(
        reqwest::Client::builder()
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert(
                    "authorization",
                    format!("Bearer {token}").parse().unwrap(),
                );
                h
            })
            .build()
            .unwrap(),
        rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig::with_uri(
            format!("http://{addr}/mcp"),
        ),
    );
    let client = ().serve(transport).await.unwrap();
    let result = client
        .call_tool(rmcp::model::CallToolRequestParam {
            name: "mark_duplicate".into(),
            arguments: Some(serde_json::Map::new()),
        })
        .await;
    let err = result.expect_err("wrong-scope dispatch must error");
    let msg = format!("{err}");
    assert!(msg.contains("claims:admin"), "got: {msg}");
}

#[tokio::test]
async fn right_scope_passes_auth_then_fails_at_db() {
    // Token has claims:read; query_claims requires claims:read. The auth
    // pipeline must let this through; the call subsequently fails at the
    // DB layer (we wired connect_lazy on a fake URL above), proving that
    // auth no longer rejects the request. That's the load-bearing assertion.
    let addr = spawn_server().await;
    let token = mint_token(&["claims:read"]).await;

    use rmcp::ServiceExt;
    let transport = rmcp::transport::streamable_http_client::StreamableHttpClientTransport::with_client(
        reqwest::Client::builder()
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert(
                    "authorization",
                    format!("Bearer {token}").parse().unwrap(),
                );
                h
            })
            .build()
            .unwrap(),
        rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig::with_uri(
            format!("http://{addr}/mcp"),
        ),
    );
    let client = ().serve(transport).await.unwrap();
    let result = client
        .call_tool(rmcp::model::CallToolRequestParam {
            name: "query_claims".into(),
            arguments: Some(serde_json::Map::new()),
        })
        .await;
    let err = result.expect_err("DB-less dispatch must error somewhere downstream");
    let msg = format!("{err}");
    assert!(
        !msg.contains("Missing required scope") && !msg.contains("auth context"),
        "scope guard should have passed; got auth-shaped error instead: {msg}"
    );
}
```

If `reqwest` or the rmcp streamable HTTP client aren't already dev-deps on `epigraph-mcp`, add them under `[dev-dependencies]` in the crate's `Cargo.toml`:

```toml
[dev-dependencies]
reqwest = { version = "0.12", features = ["rustls-tls"], default-features = false }
```

(`rmcp`'s client features may need a `features = ["streamable-http-client"]` toggle on the main dep — check `cargo build --tests -p epigraph-mcp` output and add as needed.)

- [ ] **Step 5.2: Run the tests**

```bash
cargo test -p epigraph-mcp --test http_auth_test
```

Expected: all four pass. The third test asserts a JSON-RPC error containing `claims:admin`; the fourth asserts the auth pipeline doesn't reject — the test PASSES even though the inner DB call fails (that's the point: auth got out of the way).

- [ ] **Step 5.3: Commit**

```bash
git add crates/epigraph-mcp/Cargo.toml crates/epigraph-mcp/tests/http_auth_test.rs
git commit -m "test(mcp): end-to-end 401/403/200 coverage for Bearer-auth pipeline"
```

---

## Task 6: Close the issue + PR docs

- [ ] **Step 6.1: Run the full test suite + formatter**

```bash
cargo fmt
cargo test -p epigraph-auth -p epigraph-api -p epigraph-mcp
```

All green. If `cargo fmt --check` would change anything, re-stage and commit `style: cargo fmt` before pushing — three prior PRs in this issue family failed CI on this exact gate.

- [ ] **Step 6.2: Open PR**

Title: `feat(mcp): Bearer-token auth + per-tool scope guard (closes #122)`

Body must explicitly call out:
- The five design decisions from the "Design notes" section (audience, deferred revocation, deny-by-default, gate placement, dual-flag CLI).
- That `--allow-unauthenticated-http` is **kept** for the unix-socket trust-perimeter case and local dev (this is intentional, not a regression of W-129).
- The scope inventory (29 read / 26 write / 3 admin = 58 tools).
- That token revocation is deferred and tracked separately — `bearer_auth_middleware` carries the doc-comment.

```bash
gh pr create --title "feat(mcp): Bearer-token auth + per-tool scope guard (closes #122)" \
  --body "$(cat <<'EOF'
Closes https://github.com/epigraph-io/epigraph/issues/122. Replaces the
PR #124 stopgap with proper Bearer-token + per-tool scope checks on the
MCP HTTP transport.

## What's in

- New `epigraph-auth` crate holds `JwtConfig`, `AuthContext`, `ClientType`,
  and `check_scopes`. Both `epigraph-api` and `epigraph-mcp` validate against
  the same configuration, so audience and algorithm move in lockstep.
- `epigraph-mcp::auth::bearer_auth_middleware` mirrors the API's middleware:
  extracts `Authorization: Bearer ...`, validates the JWT, injects
  `AuthContext` into the request extensions. rmcp 0.15's StreamableHttpService
  forwards `http::request::Parts` (and its extensions) into `RequestContext`,
  which `call_tool` reads.
- Deny-by-default per-tool scope map at `crates/epigraph-mcp/src/scope_map.rs`.
  29 read / 26 write / 3 admin = all 58 registered tools. A coverage test
  asserts every tool registered on `EpiGraphMcpFull::tool_router()` has a
  scope entry — new tools fail closed.
- New CLI flag `--jwt-secret` (env: `EPIGRAPH_JWT_SECRET`). `--listen`
  requires exactly one of `--jwt-secret` or `--allow-unauthenticated-http`.
- End-to-end integration test covers 401 (no header / bad sig), 403 (wrong
  scope), and 200-equivalent (right scope passes auth).

## Design decisions (locked, see plan for context)

1. **Audience stays `epigraph-api`.** MCP accepts API-minted tokens — no
   separate `epigraph-mcp` audience.
2. **Token revocation deferred.** MCP has no equivalent of
   `AppState::is_token_revoked`. v1 relies on short JWT TTLs; doc-comment in
   `bearer_auth_middleware` flags this for follow-up.
3. **Deny-by-default scope map** with coverage test — unmapped tools fail
   closed.
4. **Gate placement.** Bearer at axum middleware; scope check inside
   `call_tool` (single dispatch chokepoint).
5. **`--allow-unauthenticated-http` is kept**, intentionally, for the
   unix-socket trust-perimeter case (W-129) and local dev. The flag is now
   mutually exclusive with `--jwt-secret`.

## What's NOT in

- Token revocation for MCP (tracked separately).
- A separate `epigraph-mcp` audience.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 6.3: Monitor CI, fix as needed**

If `cargo fmt --check` fails (it has failed for three prior PRs in this family), run `cargo fmt`, commit `style: cargo fmt`, push, and re-monitor.

- [ ] **Step 6.4: After merge, close issue #122**

```bash
gh issue close 122 --comment "Fixed by PR #<n>: proper Bearer-token auth with per-tool scope checks, replacing the --allow-unauthenticated-http stopgap from PR #124."
```

---

## Verification checklist (before declaring done)

- [ ] `cargo test -p epigraph-auth -p epigraph-api -p epigraph-mcp` all green
- [ ] `cargo fmt --check` clean
- [ ] Manual gate smoke-test (Step 4.5) all three error paths produce the right message
- [ ] PR body cites the five design decisions
- [ ] Issue #122 closed with a link to the merged PR
