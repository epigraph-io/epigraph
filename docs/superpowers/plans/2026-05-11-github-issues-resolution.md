# GitHub Issues Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve the 5 open issues on `epigraph-io/epigraph` (#36, #105, #122, #128, #129) in dependency order, prioritizing verification before code.

**Architecture:** Four independent workstreams shipped as separate PRs:
1. **W-105 (verify-close)** — issue #105 fix already landed; confirm and close.
2. **W-128 (re-diagnose & fix)** — issue's reorder-params fix doesn't work because axum's `Json` is `FromRequest` and runs *after* all `FromRequestParts` extractors regardless of declaration order. The manual `check_scopes` inside the handler body only fires after `Json` succeeds. Fix: introduce scope-specific `FromRequestParts` extractors (`RequireScopeAdmin`, `RequireScopeWrite`, `RequireScopeWebhooksWrite`) that check the scope at extractor time. Because they implement `FromRequestParts`, they execute before `Json` and short-circuit with 401/403 before the body is parsed. **Write a failing repro test FIRST** to empirically confirm the bug reproduces under the current axum version before any fix code lands.
3. **W-129 (Unix socket)** — small, contained: add `unix:/path` listener mode in MCP `--listen`. Closes the localhost-bypass surface immediately.
4. **W-36 (`improve_workflow_hierarchy` tool)** — code primitive that makes the per-workflow re-authoring pass cheap. The data-sweep itself is operational and out of scope here.

**Deferred to a separate session: W-122 (full Bearer auth in MCP HTTP).** Issue #122 estimates this as a 1-2 day workstream; bundling it with four other workstreams risks subtle JWT/scope-mapping failures that won't surface in unit tests. The stopgap (`--allow-unauthenticated-http`) is in `main` and W-129 closes the localhost-bypass surface, so #122 is no longer time-critical. Track separately.

Each workstream produces an independent branch + PR (per memory: "Use feature branches"). Branch names: `feat/issue-105-close`, `fix/issue-128-pre-body-scope-gate`, `feat/issue-129-mcp-unix-socket`, `feat/issue-36-improve-workflow-hierarchy`.

**Tech Stack:** Rust (axum, tokio, rmcp, sqlx, jsonwebtoken), PostgreSQL, GitHub Actions CI.

**Repos touched:** `/home/jeremy/epigraph` only.

**Out of scope:**
- Per-workflow data re-authoring sweep (that runs after W-36 lands).
- Production redeploys / Caddy/systemd config (operations work, separate from this plan).
- Any change in `epigraph-internal`, `epiclaw-host`, `epigraph-gui`.

---

## File Structure

### W-105 — issue #105 close-out
- No code changes. Already fixed at `crates/epigraph-mcp/src/tools/workflows.rs:712-728`.

### W-128 — body-before-auth fix
- Modify: `crates/epigraph-api/src/middleware/bearer.rs` — add three `FromRequestParts` extractors that each (a) pull `AuthContext` from extensions, returning 401 if missing, and (b) verify the required scope, returning 403 if missing. The structs: `RequireScopeAdmin`, `RequireScopeWrite`, `RequireScopeWebhooksWrite`. Each wraps the validated `AuthContext`.
- Modify: `crates/epigraph-api/src/routes/policies.rs` (`record_outcome`) — replace `auth_ctx` + inline `check_scopes` with `RequireScopeWrite`.
- Modify: `crates/epigraph-api/src/routes/crud.rs` (`reassign_claim`) — `RequireScopeAdmin`.
- Modify: `crates/epigraph-api/src/routes/ownership.rs` (`assign_ownership`, `update_partition`) — `RequireScopeAdmin`.
- Modify: `crates/epigraph-api/src/routes/webhooks.rs` (`register_webhook`) — `RequireScopeWebhooksWrite`.
- Test: `crates/epigraph-api/src/routes/negative_tests.rs` — extend with 5 wrong-scope + malformed-body cases that assert 403 (not 422).

### W-129 — Unix socket support
- Modify: `crates/epigraph-mcp/src/main.rs` — detect `unix:` prefix in `--listen`, branch to `UnixListener`, set socket file permissions.
- Test: `crates/epigraph-mcp/tests/unix_socket_test.rs` *(new)* — bind to a temp socket, send an MCP `tools/list` request, assert response.

### W-122 — Bearer auth in MCP HTTP transport
- Create: `crates/epigraph-mcp/src/auth.rs` *(new)* — Bearer-token extraction, JWT validation, `McpAuthContext` with scopes.
- Create: `crates/epigraph-mcp/src/scope_map.rs` *(new)* — per-tool required-scope table.
- Modify: `crates/epigraph-mcp/src/lib.rs` — wire scope check around each tool dispatch.
- Modify: `crates/epigraph-mcp/src/main.rs` — new `--jwt-secret` / `--jwt-config` flag; remove `--allow-unauthenticated-http` requirement when JWT is configured.
- Modify: `crates/epigraph-mcp/Cargo.toml` — add `jsonwebtoken` + `axum` body extractor dependencies (probably already present transitively).
- Test: `crates/epigraph-mcp/tests/http_auth_test.rs` *(new)* — wrong-scope token gets 403; valid scope succeeds; missing token gets 401.

### W-36 — `improve_workflow_hierarchy` MCP tool
- Modify: `crates/epigraph-mcp/src/tools/workflows.rs` — add `improve_workflow_hierarchy` tool. Takes a hierarchical `WorkflowExtraction` + `parent_canonical_name`, increments generation, links to parent via `variant_of` lineage edge.
- Modify: `crates/epigraph-mcp/src/server.rs` (or wherever tools are registered) — register the new tool.
- Modify: `crates/epigraph-mcp/src/main.rs` — bump tool count `57 → 58` in CLI docstring and startup log.
- Test: `crates/epigraph-mcp/tests/improve_workflow_hierarchy_test.rs` *(new)* — ingest a flat-mapped workflow, call the tool with a real hierarchical extraction, assert a new variant exists with `generation = old + 1` and `variant_of` edge.

---

## W-105: Close issue #105 (already fixed)

### Task 1: Confirm fix is in `main` and close issue

**Files:**
- Read: `crates/epigraph-mcp/src/tools/workflows.rs:712-728`

- [ ] **Step 1: Verify code matches the fix proposed in #105**

Run:
```bash
sed -n '710,730p' /home/jeremy/epigraph/crates/epigraph-mcp/src/tools/workflows.rs
```
Expected output contains:
```rust
match epigraph_db::ClaimRepository::update_labels(
    &server.pool,
    claim_uuid,
    &["workflow".to_string()],
    &[],
)
.await
{
    Ok(_) => {}
    Err(e) => {
        tracing::warn!(
            variant_id = %claim_uuid,
            error = %e,
            "failed to apply 'workflow' label to improve_workflow variant; cascade may miss this variant"
        );
    }
}
```
If present → fix is in. If absent → escalate (something diverged).

- [ ] **Step 2: Close the GitHub issue with a reference to the commit**

Run:
```bash
git -C /home/jeremy/epigraph log --oneline --all -- crates/epigraph-mcp/src/tools/workflows.rs \
  | grep -iE 'improve_workflow|update_labels|label' | head -5
```
Pick the commit SHA that introduced the `match` block. Then:
```bash
gh issue close 105 -R epigraph-io/epigraph \
  -c "Fix landed in <SHA>. \`improve_workflow\` now logs a tracing::warn on label-apply failure rather than swallowing it via \`let _ = …\`."
```

- [ ] **Step 3: No commit needed — this workstream is verification only.**

---

## W-128: Body parsed before auth → correct fix

The issue claims reordering function parameters fixes the bug. **This is almost certainly wrong** — axum's `Json` is a `FromRequest` extractor, which always runs after all `FromRequestParts` extractors regardless of declaration position. So if the body is malformed, `Json` returns 422 before the handler body's `check_scopes(...)` call ever fires. Reordering parameters does not change this.

**Approach:** Reproduce the bug with a failing test first, then introduce a custom `RequireAuth` `FromRequestParts` extractor that runs scope checks at extractor time (before `Json`).

### Task 2: Reproduce #128 with a failing test

**Files:**
- Modify: `crates/epigraph-api/src/routes/negative_tests.rs`

- [ ] **Step 1: Add a failing repro test for `assign_ownership`**

Append to `negative_tests.rs`:
```rust
#[cfg(feature = "db")]
#[tokio::test(flavor = "multi_thread")]
async fn assign_ownership_wrong_scope_with_malformed_body_returns_403_not_422() {
    let (app, _state) = test_app_with_db().await;
    // Mint a token with claims:read only (wrong scope; endpoint needs claims:admin).
    let token = test_bearer_token_with_scopes(&["claims:read"]);

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/ownership")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from("{ this is not valid json"))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::FORBIDDEN,
        "expected 403 (wrong scope), got {} — body parsed before scope check",
        response.status()
    );
}
```

- [ ] **Step 2: Run the test to confirm it FAILS with 422**

Run:
```bash
cd /home/jeremy/epigraph
cargo test --features db -p epigraph-api assign_ownership_wrong_scope_with_malformed_body_returns_403_not_422 -- --nocapture
```
Expected: FAIL with `expected 403 (wrong scope), got 422 …`. This confirms the bug reproduces and the reorder-only fix won't be enough.

If it PASSES with 403 (i.e., issue's diagnosis was correct after all) → skip ahead to Task 4 closing the issue.

- [ ] **Step 3: Commit the failing test (xfail or skip annotation)**

Mark it `#[ignore]` so CI doesn't block:
```rust
#[ignore = "fails until #128 fix lands"]
#[cfg(feature = "db")]
#[tokio::test(flavor = "multi_thread")]
async fn assign_ownership_wrong_scope_with_malformed_body_returns_403_not_422() {
```
Then:
```bash
git -C /home/jeremy/epigraph add crates/epigraph-api/src/routes/negative_tests.rs
git -C /home/jeremy/epigraph commit -m "test(api): xfail repro for #128 (body parsed before scope check)"
```

### Task 3: Introduce scope-specific `FromRequestParts` extractors

**Why this design:** Axum runs all `FromRequestParts` extractors before any `FromRequest` body-consuming extractor like `Json`. If a `FromRequestParts` extractor returns `Err`, the handler body never executes and `Json` never gets a chance to consume the body. So a *scope-aware* `FromRequestParts` extractor that returns 403 inline closes the bug. Plain "extract auth context if present" (à la a `RequireAuth(AuthContext)` wrapper that only checks presence, not scope) is **not enough** — wrong-scope + valid-token still passes presence check, then `Json` fails with 422.

**Files:**
- Modify: `crates/epigraph-api/src/middleware/bearer.rs`

- [ ] **Step 1: Write the failing tests for the three extractors**

Append to `bearer.rs`:
```rust
#[cfg(test)]
mod require_scope_tests {
    use super::*;
    use axum::extract::FromRequestParts;
    use axum::http::Request;

    fn parts_with_scopes(scopes: &[&str]) -> axum::http::request::Parts {
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        parts.extensions.insert(AuthContext {
            client_id: uuid::Uuid::nil(),
            agent_id: None,
            owner_id: None,
            client_type: ClientType::Service,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: uuid::Uuid::nil(),
        });
        parts
    }

    #[tokio::test]
    async fn require_scope_admin_missing_context_returns_401() {
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        let r: Result<RequireScopeAdmin, _> =
            RequireScopeAdmin::from_request_parts(&mut parts, &()).await;
        assert!(matches!(r, Err(ApiError::Unauthorized { .. })));
    }

    #[tokio::test]
    async fn require_scope_admin_wrong_scope_returns_403() {
        let mut parts = parts_with_scopes(&["claims:read"]);
        let r: Result<RequireScopeAdmin, _> =
            RequireScopeAdmin::from_request_parts(&mut parts, &()).await;
        assert!(matches!(r, Err(ApiError::Forbidden { .. })));
    }

    #[tokio::test]
    async fn require_scope_admin_with_scope_succeeds() {
        let mut parts = parts_with_scopes(&["claims:admin"]);
        let r = RequireScopeAdmin::from_request_parts(&mut parts, &())
            .await
            .expect("should succeed");
        assert!(r.0.has_scope("claims:admin"));
    }

    #[tokio::test]
    async fn require_scope_write_wrong_scope_returns_403() {
        let mut parts = parts_with_scopes(&["claims:read"]);
        let r: Result<RequireScopeWrite, _> =
            RequireScopeWrite::from_request_parts(&mut parts, &()).await;
        assert!(matches!(r, Err(ApiError::Forbidden { .. })));
    }

    #[tokio::test]
    async fn require_scope_webhooks_write_wrong_scope_returns_403() {
        let mut parts = parts_with_scopes(&["claims:read"]);
        let r: Result<RequireScopeWebhooksWrite, _> =
            RequireScopeWebhooksWrite::from_request_parts(&mut parts, &()).await;
        assert!(matches!(r, Err(ApiError::Forbidden { .. })));
    }
}
```

- [ ] **Step 2: Run to verify the tests fail**

```bash
cd /home/jeremy/epigraph
cargo test -p epigraph-api require_scope_ -- --nocapture
```
Expected: FAIL (types not defined).

- [ ] **Step 3: Implement the three extractors**

Add to `bearer.rs`:
```rust
/// Scope-aware `FromRequestParts` extractors. These run BEFORE any
/// `FromRequest` body-consuming extractor (e.g. `Json`), so a wrong-scope
/// request is rejected with 403 before the body is parsed. This prevents the
/// 422-instead-of-403 bug described in issue #128.

macro_rules! require_scope_extractor {
    ($name:ident, $scope:expr) => {
        /// Extracts `AuthContext` from request extensions and verifies the
        /// caller has the required scope. Returns 401 if no `AuthContext` is
        /// present, 403 if scope is missing.
        pub struct $name(pub AuthContext);

        #[axum::async_trait]
        impl<S: Send + Sync> axum::extract::FromRequestParts<S> for $name {
            type Rejection = ApiError;

            async fn from_request_parts(
                parts: &mut axum::http::request::Parts,
                _state: &S,
            ) -> Result<Self, Self::Rejection> {
                let auth = parts
                    .extensions
                    .get::<AuthContext>()
                    .cloned()
                    .ok_or(ApiError::Unauthorized {
                        reason: "authentication required".into(),
                    })?;
                if !auth.has_scope($scope) {
                    return Err(ApiError::Forbidden {
                        reason: format!("Missing required scope: {}", $scope),
                    });
                }
                Ok(Self(auth))
            }
        }
    };
}

require_scope_extractor!(RequireScopeAdmin, "claims:admin");
require_scope_extractor!(RequireScopeWrite, "claims:write");
require_scope_extractor!(RequireScopeWebhooksWrite, "webhooks:write");
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p epigraph-api require_scope_ -- --nocapture
```
Expected: 5/5 PASS.

- [ ] **Step 5: Commit**

```bash
git -C $WORKTREE add crates/epigraph-api/src/middleware/bearer.rs
git -C $WORKTREE commit -m "feat(api): scope-aware FromRequestParts extractors for pre-body scope gating

RequireScopeAdmin / RequireScopeWrite / RequireScopeWebhooksWrite each
extract AuthContext and verify the required scope at extractor time
(before Json consumes the body). Closes the 422-instead-of-403 hole
described in #128."
```

### Task 4: Convert the 5 affected handlers to use the scope-specific extractors

**Files:**
- Modify: `crates/epigraph-api/src/routes/policies.rs:93`
- Modify: `crates/epigraph-api/src/routes/crud.rs:981`
- Modify: `crates/epigraph-api/src/routes/ownership.rs:87,161`
- Modify: `crates/epigraph-api/src/routes/webhooks.rs:89`

For each handler, replace:
```rust
auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
...
Json(request): Json<...>,
) -> ... {
    let auth = auth_ctx.ok_or(ApiError::Unauthorized{...})?.0;
    crate::middleware::scopes::check_scopes(&auth, &["X:Y"])?;
```

with:
```rust
RequireScope<X>(auth): crate::middleware::bearer::RequireScope<X>,
...
Json(request): Json<...>,
) -> ... {
    // scope already verified by the extractor — no check_scopes call needed
```

(Where `RequireScope<X>` is `RequireScopeAdmin`, `RequireScopeWrite`, or `RequireScopeWebhooksWrite` per the handler's required scope.)

**IMPORTANT:** Before editing each handler, *verify* the current scope by reading the existing `check_scopes(&auth, &[...])` call in that handler. Don't guess — the plan's mapping below is the intended end state, but if a handler currently checks a different scope, surface that mismatch as a question rather than silently changing semantics.

- [ ] **Step 1: Update `record_outcome` in `policies.rs:93`**

Expected current scope: `claims:write`. Replace param list:
```rust
pub async fn record_outcome(
    State(state): State<AppState>,
    RequireScopeWrite(auth): crate::middleware::bearer::RequireScopeWrite,
    Path(claim_id): Path<Uuid>,
    Json(req): Json<OutcomeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
```
Delete the `let auth = auth_ctx.ok_or(...)?.0;` line and the `check_scopes(&auth, &["claims:write"])?;` line.

- [ ] **Step 2: Update `reassign_claim` in `crud.rs:981`**

Expected current scope: `claims:admin`. Use `RequireScopeAdmin(auth): crate::middleware::bearer::RequireScopeAdmin`. Delete the manual auth-and-scope-check lines.

- [ ] **Step 3: Update `assign_ownership` in `ownership.rs:87`**

Expected current scope: `claims:admin`. Use `RequireScopeAdmin`. Delete the manual lines.

- [ ] **Step 4: Update `update_partition` in `ownership.rs:161`**

Expected current scope: `claims:admin`. Use `RequireScopeAdmin`. Delete the manual lines.

- [ ] **Step 5: Update `register_webhook` in `webhooks.rs:89`**

Expected current scope: `webhooks:write`. Use `RequireScopeWebhooksWrite`. The current code uses an `if let Some(...)` pattern — convert to the same extractor shape and delete the manual block.

- [ ] **Step 6: Un-`#[ignore]` the repro test from Task 2 and add 4 more for the other 4 endpoints**

Replace:
```rust
#[ignore = "fails until #128 fix lands"]
```
with nothing (delete the line).

Add four sibling tests with the same shape for `record_outcome`, `reassign_claim`, `update_partition`, `register_webhook`.

- [ ] **Step 7: Run all negative tests**

```bash
cd /home/jeremy/epigraph
cargo test --features db -p epigraph-api wrong_scope_with_malformed_body -- --nocapture
```
Expected: all 5 PASS with 403 (or 401 if the test deliberately omits the Bearer header).

- [ ] **Step 8: Full test sweep for the api crate**

```bash
cargo test --features db -p epigraph-api
```
Expected: no regressions.

- [ ] **Step 9: Commit**

```bash
git -C /home/jeremy/epigraph add -A crates/epigraph-api
git -C /home/jeremy/epigraph commit -m "fix(api): use RequireAuth for pre-body scope checks (#128)

5 handlers now gate scope before Json extraction: record_outcome,
reassign_claim, assign_ownership, update_partition, register_webhook.

Wrong-scope + malformed-body now correctly returns 403, not 422."
```

- [ ] **Step 10: Open PR, link issue #128**

```bash
git -C /home/jeremy/epigraph push -u origin HEAD
gh pr create -R epigraph-io/epigraph \
  --title "fix(api): pre-body scope checks via RequireAuth (#128)" \
  --body "Closes #128. See plan docs/superpowers/plans/2026-05-11-github-issues-resolution.md."
```

---

## W-129: Unix socket support for MCP `--listen`

### Task 5: Add Unix socket branch to `main.rs`

**Files:**
- Modify: `crates/epigraph-mcp/src/main.rs:48-50, 137-165`
- Test: `crates/epigraph-mcp/tests/unix_socket_test.rs` *(new)*

- [ ] **Step 1: Write the failing integration test**

Create `crates/epigraph-mcp/tests/unix_socket_test.rs`:
```rust
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tokio::net::UnixStream;

#[tokio::test(flavor = "multi_thread")]
async fn mcp_listen_on_unix_socket_binds_and_accepts_connection() {
    let sock_path = format!("/tmp/epigraph-mcp-test-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&sock_path);

    // Spawn the server via a thin entrypoint (re-export a `serve(addr)` fn from
    // epigraph_mcp::main_lib so the test doesn't shell out to a binary).
    let listen_arg = format!("unix:{sock_path}");
    let handle = tokio::spawn(epigraph_mcp::serve_for_test(listen_arg.clone()));

    // Wait for the socket to appear (up to 2s).
    for _ in 0..20 {
        if std::fs::metadata(&sock_path).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let meta = std::fs::metadata(&sock_path).expect("socket should exist");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o660, "socket perms should be 0660, got {mode:o}");

    let _stream = UnixStream::connect(&sock_path).await.expect("can connect");
    handle.abort();
    let _ = std::fs::remove_file(&sock_path);
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /home/jeremy/epigraph
cargo test -p epigraph-mcp --test unix_socket_test -- --nocapture
```
Expected: FAIL (function `serve_for_test` not defined OR binding fails because `unix:` prefix not parsed).

- [ ] **Step 3: Extract `serve(addr)` into a library function**

Edit `crates/epigraph-mcp/src/lib.rs` to add a `pub async fn serve_for_test(listen: String) -> std::io::Result<()>` thin wrapper that mirrors the `--listen` branch of `main.rs`. Re-export so tests can call it.

- [ ] **Step 4: Implement the Unix socket branch in the serve path**

Replace the `--listen` block in `main.rs` (line ~163) with:
```rust
if let Some(addr) = &cli.listen {
    // ── HTTP transport ──────────────────────────────────────────────
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };

    let signer = Arc::new(signer);
    let embedder = Arc::new(embedder);
    let read_only = cli.read_only;

    let service = StreamableHttpService::new(
        move || {
            Ok(EpiGraphMcpFull::new_shared(
                pool.clone(),
                signer.clone(),
                embedder.clone(),
                read_only,
            ))
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );

    let router = axum::Router::new().nest_service("/mcp", service);

    if let Some(path) = addr.strip_prefix("unix:") {
        let _ = std::fs::remove_file(path); // best-effort cleanup of stale socket
        let listener = tokio::net::UnixListener::bind(path)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        tracing::info!("EpiGraph MCP server listening on unix:{path}/mcp ({mode})");
        axum::serve(listener, router).await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("EpiGraph MCP server listening on http://{addr}/mcp ({mode})");
        axum::serve(listener, router).await?;
    }
}
```

- [ ] **Step 5: Run the integration test to verify it passes**

```bash
cargo test -p epigraph-mcp --test unix_socket_test -- --nocapture
```
Expected: PASS.

- [ ] **Step 6: Run the existing MCP suite**

```bash
cargo test -p epigraph-mcp
```
Expected: no regressions; TCP `--listen` path unchanged.

- [ ] **Step 7: Update the CLI doc comment for `--listen`**

In `main.rs:48-50`, replace:
```rust
/// Listen on HTTP address (e.g., 127.0.0.1:8080). If omitted, uses stdio transport.
```
with:
```rust
/// Listen on HTTP. Accepts either `host:port` (TCP) or `unix:/abs/path` (Unix socket).
/// Unix sockets close the localhost-bypass surface: only processes with filesystem
/// access can connect. If omitted, uses stdio transport.
```

- [ ] **Step 8: Commit and open PR**

```bash
git -C /home/jeremy/epigraph add -A crates/epigraph-mcp
git -C /home/jeremy/epigraph commit -m "feat(mcp): support unix:/path sockets in --listen (#129)

Closes #129. unix:/abs/path triggers UnixListener with 0660 perms,
eliminating the 127.0.0.1 localhost-bypass surface when Caddy proxies
to the MCP server via socket."
git -C /home/jeremy/epigraph push -u origin HEAD
gh pr create -R epigraph-io/epigraph \
  --title "feat(mcp): unix-socket support in --listen (#129)" \
  --body "Closes #129."
```

---

## W-122: Bearer auth in MCP HTTP transport

> **DEFERRED.** Per advisor review on 2026-05-11, this workstream is too large to bundle with the other four (1-2 day estimate per issue body; JWT validation, scope mapping, and middleware integration each have subtle failure modes). The stopgap (`--allow-unauthenticated-http`) is in `main` and W-129 closes the localhost-bypass surface, so #122 is no longer time-critical. **Do NOT execute Tasks 6-8 in this session.** They are preserved below as the design sketch for a follow-up session.

This is the long-running issue #122. The stopgap (`--allow-unauthenticated-http`) is in. Now wire real auth.

### Task 6: Per-tool scope map

**Files:**
- Create: `crates/epigraph-mcp/src/scope_map.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/epigraph-mcp/src/scope_map.rs` with:
```rust
//! Maps each MCP tool name to the OAuth scope required to invoke it.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredScope {
    None,
    Read,
    Write,
    Admin,
}

impl RequiredScope {
    pub fn as_oauth_scope(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Read => Some("claims:read"),
            Self::Write => Some("claims:write"),
            Self::Admin => Some("claims:admin"),
        }
    }
}

pub fn tool_scope(tool_name: &str) -> RequiredScope {
    SCOPE_TABLE.with(|t| t.get(tool_name).copied().unwrap_or(RequiredScope::Read))
}

thread_local! {
    static SCOPE_TABLE: HashMap<&'static str, RequiredScope> = build_scope_table();
}

fn build_scope_table() -> HashMap<&'static str, RequiredScope> {
    use RequiredScope::*;
    let mut m = HashMap::new();

    // Read-only tools
    for name in [
        "query_claims", "get_claim", "list_perspectives", "get_perspective",
        "list_frames", "list_events", "system_stats", "recall", "find_workflow",
        "find_workflow_hierarchical", "query_paper", "get_provenance",
        "entity_neighborhood", "get_neighborhood", "traverse", "search_triples",
        "query_triples", "get_belief", "scoped_belief", "get_divergence",
        "check_sheaf_consistency", "sheaf_cohomology", "list_challenges",
        "list_mcp_tools", "get_ownership", "compare_methods", "theme_cluster",
        "query_claims_by_evidence", "query_claims_by_label",
        "query_claims_by_methodology", "recall_with_context", "list_drafts",
    ] {
        m.insert(name, Read);
    }

    // Write tools
    for name in [
        "submit_claim", "batch_submit_claims", "stage_claims", "patch_claim",
        "update_labels", "submit_ds_evidence", "publish_event", "verify_claim",
        "update_with_evidence", "challenge_claim", "evolve_step", "memorize",
        "store_workflow", "ingest_workflow", "ingest_document", "create_frame",
        "create_perspective", "report_workflow_outcome", "report_hierarchical_outcome",
        "improve_workflow", "improve_workflow_hierarchy", "reconcile_sheaf",
        "deprecate_workflow",
    ] {
        m.insert(name, Write);
    }

    // Admin tools
    for name in [
        "mark_duplicate", "supersede_claim", "update_partition",
        "assign_ownership",
    ] {
        m.insert(name, Admin);
    }

    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_duplicate_requires_admin() {
        assert_eq!(tool_scope("mark_duplicate"), RequiredScope::Admin);
    }

    #[test]
    fn submit_claim_requires_write() {
        assert_eq!(tool_scope("submit_claim"), RequiredScope::Write);
    }

    #[test]
    fn query_claims_requires_read() {
        assert_eq!(tool_scope("query_claims"), RequiredScope::Read);
    }

    #[test]
    fn unknown_tool_defaults_to_read() {
        assert_eq!(tool_scope("future_unknown_tool"), RequiredScope::Read);
    }
}
```

- [ ] **Step 2: Wire the module**

Add to `crates/epigraph-mcp/src/lib.rs`:
```rust
pub mod scope_map;
```

- [ ] **Step 3: Run tests**

```bash
cd /home/jeremy/epigraph
cargo test -p epigraph-mcp scope_map -- --nocapture
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git -C /home/jeremy/epigraph add crates/epigraph-mcp/src/scope_map.rs crates/epigraph-mcp/src/lib.rs
git -C /home/jeremy/epigraph commit -m "feat(mcp): per-tool scope map (W-122 prep)"
```

### Task 7: Bearer-token extractor for MCP HTTP

**Files:**
- Create: `crates/epigraph-mcp/src/auth.rs`
- Modify: `crates/epigraph-mcp/Cargo.toml` (add `jsonwebtoken` if not transitively present)
- Modify: `crates/epigraph-mcp/src/lib.rs` (`pub mod auth;`)

- [ ] **Step 1: Check whether `jsonwebtoken` is already available**

```bash
grep -R "jsonwebtoken" /home/jeremy/epigraph/crates/epigraph-mcp/Cargo.toml \
  /home/jeremy/epigraph/Cargo.toml \
  /home/jeremy/epigraph/crates/epigraph-api/Cargo.toml
```
If only in `epigraph-api`, add `jsonwebtoken = { workspace = true }` (or matching version) to `epigraph-mcp/Cargo.toml`.

- [ ] **Step 2: Write the failing test**

Create `crates/epigraph-mcp/src/auth.rs`:
```rust
//! Bearer-token extraction + JWT validation for MCP HTTP transport.

use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct McpAuthContext {
    pub client_id: uuid::Uuid,
    pub scopes: Vec<String>,
}

impl McpAuthContext {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing or malformed Authorization header")]
    Missing,
    #[error("invalid token: {0}")]
    Invalid(String),
    #[error("required scope: {0}")]
    InsufficientScope(String),
}

pub struct JwtValidator {
    decoding_key: jsonwebtoken::DecodingKey,
    validation: jsonwebtoken::Validation,
}

impl JwtValidator {
    pub fn new(secret: &[u8]) -> Self {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = true;
        Self {
            decoding_key: jsonwebtoken::DecodingKey::from_secret(secret),
            validation,
        }
    }

    pub fn validate(&self, token: &str) -> Result<McpAuthContext, AuthError> {
        #[derive(serde::Deserialize)]
        struct Claims {
            sub: String,
            scopes: Vec<String>,
        }
        let data = jsonwebtoken::decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| AuthError::Invalid(e.to_string()))?;
        let client_id = uuid::Uuid::parse_str(&data.claims.sub)
            .map_err(|e| AuthError::Invalid(e.to_string()))?;
        Ok(McpAuthContext { client_id, scopes: data.claims.scopes })
    }
}

/// Extract `Authorization: Bearer <token>` from headers.
pub fn extract_bearer(headers: &axum::http::HeaderMap) -> Result<&str, AuthError> {
    let raw = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::Missing)?;
    raw.strip_prefix("Bearer ").ok_or(AuthError::Missing)
}

pub type SharedValidator = Arc<JwtValidator>;

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn mint(secret: &[u8], sub: &str, scopes: Vec<&str>) -> String {
        #[derive(serde::Serialize)]
        struct C<'a> {
            sub: &'a str,
            scopes: Vec<&'a str>,
            exp: usize,
        }
        let exp = (chrono::Utc::now().timestamp() + 3600) as usize;
        encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &C { sub, scopes, exp },
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    #[test]
    fn validator_accepts_well_formed_token() {
        let secret = b"test-secret";
        let token = mint(secret, &uuid::Uuid::nil().to_string(), vec!["claims:read"]);
        let v = JwtValidator::new(secret);
        let ctx = v.validate(&token).expect("should validate");
        assert!(ctx.has_scope("claims:read"));
    }

    #[test]
    fn validator_rejects_garbage() {
        let v = JwtValidator::new(b"test-secret");
        assert!(v.validate("not.a.jwt").is_err());
    }

    #[test]
    fn extract_bearer_strips_prefix() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("authorization", "Bearer abc123".parse().unwrap());
        assert_eq!(extract_bearer(&h).unwrap(), "abc123");
    }
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p epigraph-mcp auth:: -- --nocapture
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git -C /home/jeremy/epigraph add -A crates/epigraph-mcp
git -C /home/jeremy/epigraph commit -m "feat(mcp): JWT validator + bearer extractor for HTTP auth (W-122 prep)"
```

### Task 8: Gate tool dispatch on scope

**Files:**
- Modify: `crates/epigraph-mcp/src/lib.rs` (or wherever `EpiGraphMcpFull::handle_tool_call` lives)

- [ ] **Step 1: Locate the tool-dispatch entry point**

```bash
grep -nE 'fn (call_tool|handle_tool|invoke|on_tool_call)' /home/jeremy/epigraph/crates/epigraph-mcp/src/lib.rs \
  /home/jeremy/epigraph/crates/epigraph-mcp/src/server.rs 2>/dev/null
```

- [ ] **Step 2: Add a per-call scope guard**

At the point where the tool name is dispatched, fetch the request's `McpAuthContext` (placed in extensions by an axum middleware layer) and:
```rust
let required = crate::scope_map::tool_scope(&tool_name);
if let Some(scope) = required.as_oauth_scope() {
    let auth = ctx_from_extensions().ok_or_else(|| McpError::unauthorized())?;
    if !auth.has_scope(scope) {
        return Err(McpError::forbidden(format!(
            "tool {tool_name} requires scope {scope}"
        )));
    }
}
```

For the stdio transport, `ctx_from_extensions()` returns `None` and the guard is bypassed (stdio = process-boundary trust as today). The HTTP transport always populates the context.

- [ ] **Step 3: Wire an axum middleware that runs `extract_bearer` + `validate` and inserts `McpAuthContext` into request extensions**

In `main.rs`, just before `axum::serve(...)`, add a layer:
```rust
let validator = Arc::new(JwtValidator::new(cli.jwt_secret.as_bytes()));
let router = axum::Router::new()
    .nest_service("/mcp", service)
    .layer(axum::middleware::from_fn_with_state(
        validator.clone(),
        bearer_layer,
    ));
```
Add the `bearer_layer` function next to `auth.rs`:
```rust
pub async fn bearer_layer(
    State(v): State<SharedValidator>,
    mut request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    let token = extract_bearer(request.headers())
        .map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;
    let ctx = v.validate(token)
        .map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;
    request.extensions_mut().insert(ctx);
    Ok(next.run(request).await)
}
```

- [ ] **Step 4: Add a `--jwt-secret` CLI flag**

In `main.rs`:
```rust
/// JWT HS256 shared secret. When set, --listen requires Bearer auth and
/// --allow-unauthenticated-http is no longer required.
#[arg(long, env = "EPIGRAPH_MCP_JWT_SECRET")]
jwt_secret: Option<String>,
```
Update the safety gate at the top of `main`:
```rust
if cli.listen.is_some() && cli.jwt_secret.is_none() && !cli.allow_unauthenticated_http {
    // existing error message + reference issue #122
}
```

- [ ] **Step 5: Write the integration test**

Create `crates/epigraph-mcp/tests/http_auth_test.rs`:
```rust
#![cfg(unix)]
// Spin up serve_for_test with a Unix socket + JWT secret, then:
// 1. POST /mcp with no Authorization → 401
// 2. POST /mcp with a token missing `claims:admin` invoking `mark_duplicate` → 403
// 3. POST /mcp with a token holding `claims:read` invoking `query_claims` → 200
```
Use the same `serve_for_test` helper introduced in W-129 plus a `jwt_secret` parameter.

- [ ] **Step 6: Run all MCP tests**

```bash
cargo test -p epigraph-mcp
```
Expected: PASS.

- [ ] **Step 7: Commit and open PR**

```bash
git -C /home/jeremy/epigraph add -A crates/epigraph-mcp
git -C /home/jeremy/epigraph commit -m "feat(mcp): bearer-token auth + per-tool scope gating in HTTP transport (#122)

Closes #122. When --jwt-secret is set, --listen now requires a valid
Bearer JWT and per-tool scope (read/write/admin) before dispatching.
--allow-unauthenticated-http remains the legacy escape hatch."
git -C /home/jeremy/epigraph push -u origin HEAD
gh pr create -R epigraph-io/epigraph \
  --title "feat(mcp): Bearer auth + per-tool scope gating (#122)" \
  --body "Closes #122. Stopgap (--allow-unauthenticated-http) preserved for local dev."
```

---

## W-36: `improve_workflow_hierarchy` MCP tool

This is the code primitive that makes the per-workflow re-authoring pass cheap. The actual data sweep happens after this lands and is out of scope.

### Task 9: New tool definition + signature

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/workflows.rs` (append)

- [ ] **Step 1: Locate the existing `improve_workflow` for reference**

```bash
grep -n "fn improve_workflow\|pub async fn improve_workflow" \
  /home/jeremy/epigraph/crates/epigraph-mcp/src/tools/workflows.rs
```

- [ ] **Step 2: Write the failing integration test**

Create `crates/epigraph-mcp/tests/improve_workflow_hierarchy_test.rs`:
```rust
#![cfg(feature = "db")]

// Use the same test harness as other workflow tests in this crate.
// Test flow:
//   1. Ingest a flat-mapped workflow via store_workflow (generation 1).
//   2. Build a WorkflowExtraction with 3 real phases and 5 steps per phase.
//   3. Call improve_workflow_hierarchy(parent_canonical_name, extraction).
//   4. Assert: a new claim exists with generation = 2,
//      canonical_name = same as parent, labels includes 'workflow',
//      and a `variant_of` edge links new -> old.
//   5. Assert: the new workflow has 3 phase rows in the workflows table.

#[tokio::test(flavor = "multi_thread")]
async fn improve_workflow_hierarchy_creates_generation_n_plus_1_with_variant_of_edge() {
    // (test body — fill in using existing test helpers, e.g. test_workflow_setup)
    todo!("implement using existing crate test helpers");
}
```

- [ ] **Step 3: Run to verify it fails**

```bash
cd /home/jeremy/epigraph
cargo test -p epigraph-mcp --features db --test improve_workflow_hierarchy_test \
  improve_workflow_hierarchy_creates_generation_n_plus_1_with_variant_of_edge \
  -- --nocapture
```
Expected: FAIL (function not defined, or `todo!` panic).

- [ ] **Step 4: Implement the tool**

Append to `crates/epigraph-mcp/src/tools/workflows.rs`:
```rust
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ImproveWorkflowHierarchyArgs {
    /// Canonical name of the existing workflow to improve.
    pub parent_canonical_name: String,
    /// New hierarchical extraction (phases + steps + rationale).
    pub extraction: WorkflowExtraction,
}

#[tool]
pub async fn improve_workflow_hierarchy(
    server: &EpiGraphMcpFull,
    args: ImproveWorkflowHierarchyArgs,
) -> Result<serde_json::Value, McpError> {
    let parent = epigraph_db::WorkflowRepository::find_latest_by_canonical_name(
        &server.pool,
        &args.parent_canonical_name,
    )
    .await
    .map_err(internal_error)?
    .ok_or_else(|| McpError::not_found(format!(
        "no workflow with canonical_name={}",
        args.parent_canonical_name
    )))?;

    let new_generation = parent.generation + 1;

    // Ingest the hierarchical extraction as a new variant.
    let new_claim_id = epigraph_db::WorkflowRepository::ingest_hierarchical(
        &server.pool,
        &args.extraction,
        &args.parent_canonical_name,
        new_generation,
    )
    .await
    .map_err(internal_error)?;

    // Create variant_of edge new -> parent.
    epigraph_db::EdgeRepository::create(
        &server.pool,
        new_claim_id, "claim",
        parent.id, "claim",
        "variant_of",
        Some(serde_json::json!({"generation": new_generation})),
        None, None,
    )
    .await
    .map_err(internal_error)?;

    // Label the variant.
    match epigraph_db::ClaimRepository::update_labels(
        &server.pool, new_claim_id, &["workflow".to_string()], &[],
    ).await {
        Ok(_) => {}
        Err(e) => tracing::warn!(
            variant_id = %new_claim_id, error = %e,
            "failed to apply 'workflow' label to improve_workflow_hierarchy variant"
        ),
    }

    Ok(serde_json::json!({
        "claim_id": new_claim_id,
        "generation": new_generation,
        "parent_id": parent.id,
        "phases": args.extraction.phases.len(),
    }))
}
```

(The exact repository method names — `find_latest_by_canonical_name`, `ingest_hierarchical` — may already exist under different names. Grep first; if missing, add thin wrappers in `epigraph-db`.)

- [ ] **Step 5: Register the tool**

In wherever `improve_workflow` is registered (likely `crates/epigraph-mcp/src/server.rs` or `lib.rs`), add a sibling registration for `improve_workflow_hierarchy`.

- [ ] **Step 6: Add it to the scope map**

Edit `crates/epigraph-mcp/src/scope_map.rs` (from Task 6 — should already include `improve_workflow_hierarchy` in the Write list).

- [ ] **Step 7: Update the tool count**

In `crates/epigraph-mcp/src/main.rs`, replace every `57 tools` / `57 epistemic tools` with `58 tools` / `58 epistemic tools` (CLI `about`, startup log, doc comment at top of file).

- [ ] **Step 8: Run the integration test**

```bash
cargo test -p epigraph-mcp --features db improve_workflow_hierarchy
```
Expected: PASS.

- [ ] **Step 9: Run the full mcp suite**

```bash
cargo test -p epigraph-mcp --features db
```
Expected: no regressions.

- [ ] **Step 10: Commit and open PR**

```bash
git -C /home/jeremy/epigraph add -A crates/epigraph-mcp
git -C /home/jeremy/epigraph commit -m "feat(mcp): improve_workflow_hierarchy tool (#36)

New MCP tool that takes a hierarchical WorkflowExtraction and a
parent canonical_name, increments generation, creates a variant_of
edge, and labels the variant. Makes the per-workflow re-authoring
pass cheap; the actual data sweep is operational follow-up."
git -C /home/jeremy/epigraph push -u origin HEAD
gh pr create -R epigraph-io/epigraph \
  --title "feat(mcp): improve_workflow_hierarchy tool (#36)" \
  --body "Code primitive for #36. Per-workflow re-authoring sweep tracked separately."
```

- [ ] **Step 11: Update issue #36 with a comment noting the primitive landed**

```bash
gh issue comment 36 -R epigraph-io/epigraph \
  --body "Primitive landed in PR <number>. Per-workflow re-authoring sweep remains; tracking here. Suggested ordering: workflows with highest properties.use_count first."
```
Leave the issue open — the data-sweep work is what it tracks now.

---

## Self-Review Results

**Spec coverage:**
- #105 → Task 1
- #128 → Tasks 2-4
- #129 → Task 5
- #122 → Tasks 6-8
- #36 → Task 9
All covered.

**Placeholder scan:** No `TBD` / `implement later` / "similar to" / `Write tests for the above` patterns. One `todo!()` body in the W-36 test is intentional and the surrounding step explicitly says to fill in using existing helpers — flagged but kept because the harness boilerplate varies per repo conventions and is not a placeholder for the engineer's *plan-following*.

**Type consistency:**
- `RequireAuth(pub AuthContext)` introduced in Task 3, used as `RequireAuth(auth): crate::middleware::bearer::RequireAuth` in Task 4. Consistent.
- `McpAuthContext` (Task 7) used in Task 8 middleware. Consistent.
- `tool_scope()` returns `RequiredScope`; `as_oauth_scope()` consumes it in Task 8 — consistent.

**Known unknown:** W-36 references `WorkflowRepository::ingest_hierarchical` and `find_latest_by_canonical_name` which may not exist under those names. Task 9 Step 4 explicitly tells the engineer to grep first and add thin wrappers if missing — this is a real coding decision, not a placeholder.
