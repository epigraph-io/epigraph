# Router Extension Seam Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a program that embeds `epigraph-api` as a library mount its own HTTP routes inside the kernel's authenticated router, under a reserved `/api/v1/ext/<name>` prefix, without forking `create_router`.

**Architecture:** A new `routes/extensions.rs` defines `RouterExtension` (a validated name plus an axum `Router<AppState>`) and a `mount_all` helper. It binds each extension to the kernel state and mounts it with `nest_service` at `/api/v1/ext/<name>`, so the whole prefix is one set of ordinary routes, the extension's own fallback included. `create_router` becomes a one-line delegate to a new `create_router_with_extensions(state, Vec<RouterExtension>)`. In both cfg variants, `mount_all` is called inside the existing statement that adds the auth layers, so extension routes sit under the elevated-access recorder (db variant) and the bearer layer, as well as the outer body-limit and rate-limit layers. An embedder that has its own state type passes it through `RouterExtension::with_state`, which uses axum 0.7's `Router::with_state::<AppState>` to turn its router into a `Router<AppState>`.

**Tech Stack:** Rust, axum 0.7.9, tower 0.5 (`ServiceExt::oneshot`), sqlx 0.8 `#[sqlx::test]`, `epigraph-auth` JWT minting.

**Spec:** GitHub issue epigraph-io/epigraph#481, plus the "Design decisions" section below, which replaces the patch in #481. That patch no longer applies to `main`, and its description of the middleware (a "conditional signature middleware") is out of date: `require_signature` was deleted and `protected` is bearer-only.

## Design decisions (what changed from #481, and why)

| #481 proposed | This plan | Why |
|---|---|---|
| `extra_routes: Router<AppState>` merged into `protected` at any path | `Vec<RouterExtension>`, each nested at `/api/v1/ext/<name>` | A route added to the kernel later can no longer collide with an embedder's route, which would make the embedder's server panic at startup after an upgrade. Each extension gets one namespace and can't take over kernel paths. |
| Merge placed before "the auth middleware stack" | Mount inside the third `let protected = …` statement, before `.route_layer(record_elevated_access)` and `.layer(bearer_auth_middleware)` | In axum, `route_layer` and `layer` only wrap routes that already exist. If the mount came after them, extension routes would have no bearer authentication and no elevated-write refusal. |
| `protected.merge(extra_routes)` in `routes/mod.rs` | `extensions::mount_all(protected, extensions, &state)`; the `nest_service` calls live in `extensions.rs` | `tests/public_router_allowlist.rs::the_final_router_merges_only_protected_public_and_oauth` requires the `.merge(` calls in `routes/mod.rs` to be exactly `protected, public, oauth` twice. `protected_paths` requires exactly six `let protected = ` statements. Both lints read the raw file text, comments included. |
| Kernel state only | `RouterExtension::new` (kernel state) **and** `RouterExtension::with_state` (the embedder's own state) | A separate service with its own state type, such as episcience's `ElnState`, could not use the seam otherwise. |
| (merge, so routes are nested route-by-route) | `nest_service(path, ext.router.with_state(state))` | In axum 0.7.9, `Router::nest` moves a nested router's custom fallback into the outer `fallback_router` (`routing/mod.rs::nest`: `this.fallback_router.nest(path, fallback_router)`), and `route_layer` does not wrap `fallback_router` (`routing/mod.rs::route_layer`: `fallback_router: this.fallback_router`). An elevated write to an unmatched path under the prefix would therefore reach the extension's fallback without passing the per-access recorder. `nest_service` registers `prefix`, `prefix/` and `prefix/*tail` as ordinary routes (`path_router.rs::nest_service`), which `route_layer` and `layer` both wrap, and the extension's fallback runs inside them. The cost: the recorder sees the matched route as the prefix wildcard, not the extension's own route pattern. It still logs the concrete request path (`record_elevated_access`: `bounded(request.uri().path(), …)`). |

**What extension routes inherit:**
- bearer authentication, including the revocation check (missing or invalid token → 401 with an RFC 6750 challenge);
- `AuthContext` in request extensions;
- refusal of elevated writes, plus elevated-access recording (db variant), on every path under the prefix, the extension's fallback included. Recorded at prefix granularity: the surface is `<METHOD> /api/v1/ext/<name>/*…`, and the concrete path is logged alongside it;
- `DefaultBodyLimit(max_request_size)`;
- the rate limiter.

**What they do NOT inherit (the embedder's responsibility, stated in the rustdoc):**
- **Scope checks.** Use `epigraph_api::middleware::check_scopes` or the `bearer::RequireScope*` extractors.
- **Tenancy-scoped reads.** `ViewerExtractor` is `FromRequestParts<AppState>`, so only kernel-state extensions can use it.
- **The crate's in-tree lints.** `no_unscoped_pool` and `public_router_allowlist` scan only kernel source.
- **OpenAPI listing.** Extension routes do not appear in `/api/v1/openapi.json`.

## Non-goals

- **Moving episcience onto the seam.** episcience-api is on axum 0.7, as the kernel is (the 0.8 copy in its lockfile comes only through `epigraph-mcp`/`rmcp`), so the types are compatible. To adopt the seam it would need to depend on `epigraph-api` at the same revision as its other epigraph crates and run inside the kernel's process. That would be its own plan in that repo. This plan only guarantees that the `with_state` path works for a router with foreign state (Task 2 tests it).
- Listing extensions in the OpenAPI document.
- Changing `ViewerExtractor` to work with any state.
- Anonymous (public-router) extensions. The anonymous surface stays the two-route allowlist.

## Global Constraints

- axum stays `0.7` (workspace `Cargo.toml`: `axum = { version = "0.7", features = ["macros"] }`). Add no dependencies.
- The extension prefix is exactly `/api/v1/ext`. Mount path = `/api/v1/ext/<name>`.
- Extension name: 1 to 32 bytes, matching `[a-z][a-z0-9-]*`.
- `RouterExtension`, `ExtensionNameError`, `EXTENSION_PREFIX` and `create_router_with_extensions` must exist with **identical signatures in both** `#[cfg(feature = "db")]` and `#[cfg(not(feature = "db"))]` builds. CI runs `cargo check -p epigraph-api --no-default-features --locked`.
- In `crates/epigraph-api/src/routes/mod.rs`, add **no** new occurrence of the text `let protected = `, `let public = ` or `.merge(`, in code **or comments**. The source lints count them in the raw file.
- Commit messages follow the repository's Evidence / Reasoning / Verification commit schema.
- Push and open a PR only after the operator says to. Never merge.

## Review Focus

1. **An extension router with its own `.fallback()`.** Two cases, both pinned in Task 2:
   - A request with no credentials to an unmatched path under the prefix must get 401, not the fallback body (`fallback_under_prefix_is_still_behind_bearer`).
   - An elevated POST to that unmatched path must get `ELEVATED READ-ONLY`, not reach the fallback (`elevated_post_to_extension_fallback_is_refused`).

   With plain `nest`, the second case fails: see the Design decisions row on `nest_service`.
2. **An elevated token writing through an extension route with a path parameter.** It must be refused with `ELEVATED READ-ONLY` (not 401, not 200), and the handler must not run. Pinned in Task 2 (`elevated_post_to_extension_is_refused_as_read_only`).
3. **An oversized body sent to an extension.** It must get 413 before the handler runs. Pinned in Task 2 (`oversized_body_to_extension_is_413`).
4. **Bad extension names** (`""`, `"Eln"`, `"eln/x"`, `".."`, `"-x"`, a 33-byte name). Each must be rejected when the extension is constructed, with a typed error. Pinned in Task 1.
5. **Two extensions with the same name.** Startup must panic with a message naming the extension, not silently let one replace the other. Pinned in Task 1 (`duplicate_names_panic_with_the_name`).

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/epigraph-api/src/routes/extensions.rs` (create) | `EXTENSION_PREFIX`, `ExtensionNameError`, `RouterExtension` (`new`, `with_state`, `name`, `mount_path`), `fn assert_unique_names`, `pub(crate) fn mount_all`. Not cfg-gated. Holds unit tests for name validation and duplicates. |
| `crates/epigraph-api/src/routes/mod.rs` (modify) | Declare `pub mod extensions;`. In both variants, split `create_router` into a delegate plus `create_router_with_extensions`, and call `extensions::mount_all` at the head of the auth-layer statement. |
| `crates/epigraph-api/src/lib.rs` (modify) | Re-export the new public items. |
| `crates/epigraph-api/tests/router_extension_seam.rs` (create) | DB-backed behaviour tests through the real router. |
| `crates/epigraph-api/tests/router_extension_seam_lint.rs` (create) | Source-text lint: the prefix is reserved for extensions, and `mount_all` sits before the auth layers in both variants. This lint is the only check that covers the not(db) variant. |

---

### Task 1: `RouterExtension` and name validation

**Files:**
- Create: `crates/epigraph-api/src/routes/extensions.rs`
- Modify: `crates/epigraph-api/src/routes/mod.rs` (module list near the top: add `pub mod extensions;` next to the other un-gated `pub mod` lines; add **no** cfg attribute)

**Interfaces:**
- Consumes: `crate::state::AppState` (exists in both cfg variants), `axum::Router`.
- Produces:
  - `pub const EXTENSION_PREFIX: &str = "/api/v1/ext";`
  - `pub enum ExtensionNameError { Empty, TooLong(String), InvalidCharacters(String) }` (derives `Debug, Clone, PartialEq, Eq, thiserror::Error`)
  - `pub struct RouterExtension`
  - `RouterExtension::new(name: &str, router: Router<AppState>) -> Result<RouterExtension, ExtensionNameError>`
  - `RouterExtension::with_state<S: Clone + Send + Sync + 'static>(name: &str, router: Router<S>, state: S) -> Result<RouterExtension, ExtensionNameError>`
  - `RouterExtension::name(&self) -> &str`
  - `RouterExtension::mount_path(&self) -> String`
  - `fn assert_unique_names(extensions: &[RouterExtension])` (panics on a duplicate; needs no state, so it is unit-testable in the db build, where `AppState::new` does not exist)
  - `pub(crate) fn mount_all(protected: Router<AppState>, extensions: Vec<RouterExtension>, state: &AppState) -> Router<AppState>`

- [ ] **Step 1: Write the file with the tests first and `todo!()` bodies**

Create `crates/epigraph-api/src/routes/extensions.rs`:

```rust
//! Embedder routes mounted inside the kernel's authenticated router.
//!
//! A program that runs `epigraph-api` as a library, rather than the stock
//! binary, passes [`RouterExtension`]s to
//! [`crate::routes::create_router_with_extensions`]. Each is nested at
//! `/api/v1/ext/<name>` ([`EXTENSION_PREFIX`]); no first-party route is
//! registered under that prefix (`tests/router_extension_seam_lint.rs`), so a
//! kernel upgrade cannot collide with an extension.
//!
//! # What an extension route inherits
//!
//! It is mounted into the authenticated router before its layers are applied,
//! so it receives exactly what a first-party authenticated route receives:
//!
//! * bearer authentication, revocation included: a missing, malformed,
//!   expired or revoked token is refused 401 before the handler runs;
//! * the caller's `AuthContext` in the request extensions;
//! * (db builds) the per-access recorder: a token carrying an elevation claim
//!   may not write through an extension (`ELEVATED READ-ONLY`), and its reads
//!   are recorded;
//! * the request body limit (`ApiConfig::max_request_size`) and the rate
//!   limiter.
//!
//! # What it does NOT inherit — the embedder owns these
//!
//! * **Scopes.** Authentication is not authorization. Check scopes in the
//!   handler: `crate::middleware::check_scopes`, or a
//!   `crate::middleware::bearer::RequireScope*` extractor (generic over state).
//! * **Tenancy.** A kernel-state extension ([`RouterExtension::new`]) can take
//!   `ViewerExtractor` and read through the scoped pool. An own-state extension
//!   ([`RouterExtension::with_state`]) cannot, because `ViewerExtractor`
//!   requires `AppState`; it must apply its own visibility rules.
//! * **The crate's lints.** `no_unscoped_pool`, `public_router_allowlist` and
//!   the handler audits scan this crate's source only.
//! * **OpenAPI.** Extension routes are not listed in `/api/v1/openapi.json`.

use axum::Router;

use crate::state::AppState;

/// The prefix every extension is nested under: `/api/v1/ext/<name>`.
pub const EXTENSION_PREFIX: &str = "/api/v1/ext";

/// The longest extension name, in bytes.
const MAX_NAME_LEN: usize = 32;

/// Why an extension name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtensionNameError {
    #[error("router extension name is empty")]
    Empty,
    #[error("router extension name {0:?} is longer than 32 bytes")]
    TooLong(String),
    #[error("router extension name {0:?} must match [a-z][a-z0-9-]*")]
    InvalidCharacters(String),
}

/// An embedder-supplied router, mounted at `/api/v1/ext/<name>` inside the
/// authenticated router.
pub struct RouterExtension {
    name: String,
    router: Router<AppState>,
}

impl RouterExtension {
    /// An extension whose handlers take the kernel's `State<AppState>` (and so
    /// may use `ViewerExtractor`).
    ///
    /// # Errors
    /// [`ExtensionNameError`] when `name` is empty, longer than 32 bytes, or
    /// not `[a-z][a-z0-9-]*`.
    pub fn new(name: &str, router: Router<AppState>) -> Result<Self, ExtensionNameError> {
        todo!()
    }

    /// An extension whose handlers take the embedder's own state `S`. The state
    /// is bound here, so the kernel never sees `S`.
    ///
    /// # Errors
    /// As [`RouterExtension::new`].
    pub fn with_state<S>(name: &str, router: Router<S>, state: S) -> Result<Self, ExtensionNameError>
    where
        S: Clone + Send + Sync + 'static,
    {
        todo!()
    }

    /// The validated name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Where this extension is nested: `/api/v1/ext/<name>`.
    #[must_use]
    pub fn mount_path(&self) -> String {
        format!("{EXTENSION_PREFIX}/{}", self.name)
    }
}

fn validate_name(name: &str) -> Result<(), ExtensionNameError> {
    todo!()
}

/// Panic if two extensions share a name. A second registration under one
/// prefix is a startup bug in the embedder, and refusing it loudly is the
/// contract axum applies to an overlapping route.
fn assert_unique_names(extensions: &[RouterExtension]) {
    todo!()
}

/// Mount every extension into `protected` at its mount path, bound to `state`.
///
/// Called by `create_router_with_extensions` at the head of the statement that
/// applies the authenticated router's layers, so the mounted routes are
/// wrapped by them.
///
/// `nest_service`, not `nest`: axum 0.7's `nest` moves a nested router's custom
/// fallback into the outer router's fallback, which `route_layer` (the
/// per-access recorder) does not wrap. `nest_service` registers the prefix
/// and everything under it as ordinary routes, so the extension's fallback
/// runs inside both layers too.
///
/// # Panics
/// When two extensions share a name.
pub(crate) fn mount_all(
    protected: Router<AppState>,
    extensions: Vec<RouterExtension>,
    state: &AppState,
) -> Router<AppState> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_lowercase_digits_and_hyphens() {
        for ok in ["eln", "e", "eln-2", "a0-b1", &"a".repeat(32)] {
            assert!(
                RouterExtension::new(ok, Router::new()).is_ok(),
                "{ok:?} should be accepted"
            );
        }
    }

    #[test]
    fn rejects_each_bad_name_with_its_reason() {
        let cases: [(&str, ExtensionNameError); 7] = [
            ("", ExtensionNameError::Empty),
            ("Eln", ExtensionNameError::InvalidCharacters("Eln".into())),
            ("eln/x", ExtensionNameError::InvalidCharacters("eln/x".into())),
            ("..", ExtensionNameError::InvalidCharacters("..".into())),
            ("-x", ExtensionNameError::InvalidCharacters("-x".into())),
            ("1x", ExtensionNameError::InvalidCharacters("1x".into())),
            ("e\u{301}", ExtensionNameError::InvalidCharacters("e\u{301}".into())),
        ];
        for (name, want) in cases {
            assert_eq!(
                RouterExtension::new(name, Router::new()).err(),
                Some(want),
                "{name:?}"
            );
        }
        let long = "a".repeat(33);
        assert_eq!(
            RouterExtension::new(&long, Router::new()).err(),
            Some(ExtensionNameError::TooLong(long.clone()))
        );
    }

    #[test]
    fn with_state_validates_the_name_too() {
        #[derive(Clone)]
        struct Own;
        assert_eq!(
            RouterExtension::with_state("Bad", Router::<Own>::new(), Own).err(),
            Some(ExtensionNameError::InvalidCharacters("Bad".into()))
        );
    }

    #[test]
    fn mount_path_is_under_the_reserved_prefix() {
        let ext = RouterExtension::new("eln", Router::new()).unwrap();
        assert_eq!(ext.mount_path(), "/api/v1/ext/eln");
        assert_eq!(ext.name(), "eln");
    }

    #[test]
    #[should_panic(expected = "router extension \"eln\" is registered twice")]
    fn duplicate_names_panic_with_the_name() {
        let a = RouterExtension::new("eln", Router::new()).unwrap();
        let other = RouterExtension::new("other", Router::new()).unwrap();
        let b = RouterExtension::new("eln", Router::new()).unwrap();
        assert_unique_names(&[a, other, b]);
    }

    #[test]
    fn distinct_names_pass_the_uniqueness_check() {
        let a = RouterExtension::new("eln", Router::new()).unwrap();
        let b = RouterExtension::new("eln-2", Router::new()).unwrap();
        assert_unique_names(&[a, b]);
    }
}
```

Add to `crates/epigraph-api/src/routes/mod.rs`, in the `pub mod` list near the top, with no `#[cfg]` attribute:

```rust
pub mod extensions;
```

- [ ] **Step 2: Run the tests and see them fail**

Run: `cargo test -p epigraph-api --lib routes::extensions`
Expected: FAIL. Every test panics with `not yet implemented`, from the `todo!()` bodies.

- [ ] **Step 3: Implement**

Replace the five `todo!()` bodies:

```rust
    pub fn new(name: &str, router: Router<AppState>) -> Result<Self, ExtensionNameError> {
        validate_name(name)?;
        Ok(Self {
            name: name.to_owned(),
            router,
        })
    }
```

```rust
    {
        Self::new(name, router.with_state(state))
    }
```

```rust
fn validate_name(name: &str) -> Result<(), ExtensionNameError> {
    if name.is_empty() {
        return Err(ExtensionNameError::Empty);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(ExtensionNameError::TooLong(name.to_owned()));
    }
    let mut bytes = name.bytes();
    let first_ok = bytes.next().is_some_and(|b| b.is_ascii_lowercase());
    let rest_ok = bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if first_ok && rest_ok {
        Ok(())
    } else {
        Err(ExtensionNameError::InvalidCharacters(name.to_owned()))
    }
}
```

```rust
fn assert_unique_names(extensions: &[RouterExtension]) {
    let mut seen = std::collections::BTreeSet::new();
    for ext in extensions {
        assert!(
            seen.insert(ext.name.as_str()),
            "router extension {:?} is registered twice; each name mounts exactly one prefix",
            ext.name
        );
    }
}
```

```rust
pub(crate) fn mount_all(
    protected: Router<AppState>,
    extensions: Vec<RouterExtension>,
    state: &AppState,
) -> Router<AppState> {
    assert_unique_names(&extensions);
    extensions.into_iter().fold(protected, |router, ext| {
        let path = ext.mount_path();
        router.nest_service(&path, ext.router.with_state(state.clone()))
    })
}
```

`ext.router.with_state(state.clone())` yields a `Router<()>`, which is a `Service<Request, Error = Infallible>`. For a `with_state` extension, whose handlers are already bound to their own state, this call only gives the router the unit state type and never exposes `AppState` to those handlers.

The rejection test uses `"e\u{301}"` (a combining accent, which is multi-byte). Checking bytes rather than chars makes any non-ASCII byte fail `rest_ok`, so it is rejected.

- [ ] **Step 4: Run the tests and see them pass**

Run: `cargo test -p epigraph-api --lib routes::extensions`
Expected: PASS, 6 tests.

Run: `cargo check -p epigraph-api --no-default-features --locked`
Expected: no *new* errors. `extensions.rs` uses nothing db-only. If the command fails on `main` before this change, record the baseline error count first and compare against it.

- [ ] **Step 5: Commit**

```bash
git add crates/epigraph-api/src/routes/extensions.rs crates/epigraph-api/src/routes/mod.rs
git commit -m "feat(api): define RouterExtension, a named router bound for /api/v1/ext/<name>

**Evidence:**
- Issue #481: embedders running the kernel as a library must fork create_router to add routes

**Reasoning:**
- A validated name maps each extension to one prefix, so a later kernel route cannot collide with it
- with_state binds an embedder's own state, so the seam is not limited to AppState handlers
- Duplicate names panic at startup, matching axum's overlapping-route contract

**Verification:**
- cargo test -p epigraph-api --lib routes::extensions: 6 pass (valid/invalid names, with_state, mount path, duplicate panic, distinct names)
- cargo check -p epigraph-api --no-default-features --locked: no new errors"
```

---

### Task 2: `create_router_with_extensions`, wired under the auth layers

**Files:**
- Modify: `crates/epigraph-api/src/routes/mod.rs`. There are two `pub fn create_router(state: AppState) -> Router {` items, the `#[cfg(feature = "db")]` one and the `#[cfg(not(feature = "db"))]` one. In each, change the statement that begins `let protected = protected` and contains `bearer_auth_middleware`.
- Modify: `crates/epigraph-api/src/lib.rs` (the `pub use routes::create_router;` line)
- Modify: `CLAUDE.md` (repo root; add a section after "Adding MCP tools — `epigraph-tools` is not the extension point")
- Create: `crates/epigraph-api/tests/router_extension_seam.rs`

**Interfaces:**
- Consumes: from Task 1, `RouterExtension::{new, with_state}` and `extensions::mount_all(Router<AppState>, Vec<RouterExtension>) -> Router<AppState>`.
- Produces: `pub fn create_router_with_extensions(state: AppState, extensions: Vec<RouterExtension>) -> Router` in both cfg variants, re-exported at the crate root together with `RouterExtension`, `ExtensionNameError` and `EXTENSION_PREFIX`.

- [ ] **Step 1: Write the failing integration test**

Create `crates/epigraph-api/tests/router_extension_seam.rs`:

```rust
//! The router extension seam, through the real router: an embedder's routes
//! sit under the authenticated router's layers, whatever state they carry.
//!
//! Every assertion that names a layer goes through the OWN-STATE extension,
//! the path most likely to end up outside the layers (`with_state` turns it
//! into a separately stated router before it is nested).
//! `#[sqlx::test]` gives each test a fresh migrated database: the bearer
//! layer's revocation lookup reads it.

use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use epigraph_api::middleware::bearer::RequireScopeWrite;
use epigraph_api::middleware::AuthContext;
use epigraph_api::{create_router_with_extensions, ApiConfig, AppState, RouterExtension};
use epigraph_auth::AccessTokenBinding;
use sqlx::PgPool;
use tower::ServiceExt as _;
use uuid::Uuid;

/// An embedder's own state, unrelated to `AppState`.
#[derive(Clone)]
struct EmbedderState {
    marker: &'static str,
}

const BODY_LIMIT: usize = 1024;

fn app(pool: &PgPool) -> (Router, AppState) {
    let state = AppState::with_db(
        pool.clone(),
        ApiConfig {
            max_request_size: BODY_LIMIT,
            ..ApiConfig::default()
        },
    );

    // Own-state extension: a read, a write with a path parameter, a body
    // reader, a scope-gated route, and its own fallback.
    let own = Router::new()
        .route(
            "/whoami",
            get(|State(s): State<EmbedderState>, Extension(auth): Extension<AuthContext>| async move {
                format!("{}:{}", s.marker, auth.agent_id.expect("agent token"))
            }),
        )
        .route(
            "/items/:id",
            post(|Path(id): Path<Uuid>| async move { format!("wrote {id}") }),
        )
        .route(
            "/echo",
            post(|Json(v): Json<serde_json::Value>| async move { Json(v) }),
        )
        .route(
            "/needs-write",
            get(|RequireScopeWrite(_auth): RequireScopeWrite| async { "ok" }),
        )
        .fallback(|| async { "extension fallback" });
    let own = RouterExtension::with_state("demo", own, EmbedderState { marker: "embedder" })
        .expect("valid name");

    // Kernel-state extension: reads AppState.
    let kernel = Router::new().route(
        "/limit",
        get(|State(s): State<AppState>| async move { s.config.max_request_size.to_string() }),
    );
    let kernel = RouterExtension::new("kstate", kernel).expect("valid name");

    let router = create_router_with_extensions(state.clone(), vec![own, kernel]);
    (router, state)
}

fn token(state: &AppState, agent: Uuid, scopes: &[&str], elevation: Option<Uuid>) -> String {
    state
        .jwt_config
        .issue_access_token(
            agent,
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "agent",
            None,
            Some(agent),
            chrono::Duration::minutes(10),
            AccessTokenBinding {
                family_id: elevation.map(|_| Uuid::new_v4()),
                elevation_id: elevation,
            },
        )
        .expect("mint")
        .0
}

async fn send(
    router: &Router,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<String>,
) -> (StatusCode, String, Option<String>) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned(), challenge)
}

#[sqlx::test(migrations = "../../migrations")]
async fn extension_without_a_token_is_401_with_a_bearer_challenge(pool: PgPool) {
    let (router, _) = app(&pool);
    let (status, body, challenge) = send(&router, "GET", "/api/v1/ext/demo/whoami", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(
        challenge.as_deref().is_some_and(|c| c.starts_with("Bearer")),
        "missing RFC 6750 challenge: {challenge:?}"
    );
    assert!(!body.contains("embedder"), "handler ran without a token: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn own_state_extension_sees_its_state_and_the_callers_auth_context(pool: PgPool) {
    let (router, state) = app(&pool);
    let agent = Uuid::new_v4();
    let t = token(&state, agent, &["claims:read"], None);
    let (status, body, _) = send(&router, "GET", "/api/v1/ext/demo/whoami", Some(&t), None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body, format!("embedder:{agent}"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn kernel_state_extension_reads_app_state(pool: PgPool) {
    let (router, state) = app(&pool);
    let t = token(&state, Uuid::new_v4(), &["claims:read"], None);
    let (status, body, _) = send(&router, "GET", "/api/v1/ext/kstate/limit", Some(&t), None).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body, BODY_LIMIT.to_string());
}

#[sqlx::test(migrations = "../../migrations")]
async fn own_state_extension_can_enforce_a_kernel_scope(pool: PgPool) {
    let (router, state) = app(&pool);
    let reader = token(&state, Uuid::new_v4(), &["claims:read"], None);
    let writer = token(&state, Uuid::new_v4(), &["claims:write"], None);
    let (denied, body, _) =
        send(&router, "GET", "/api/v1/ext/demo/needs-write", Some(&reader), None).await;
    assert_eq!(denied, StatusCode::FORBIDDEN, "body: {body}");
    let (allowed, body, _) =
        send(&router, "GET", "/api/v1/ext/demo/needs-write", Some(&writer), None).await;
    assert_eq!(allowed, StatusCode::OK, "body: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn elevated_post_to_extension_is_refused_as_read_only(pool: PgPool) {
    let (router, state) = app(&pool);
    let elevated = token(&state, Uuid::new_v4(), &["claims:write"], Some(Uuid::new_v4()));
    let path = format!("/api/v1/ext/demo/items/{}", Uuid::new_v4());
    let (status, body, _) = send(&router, "POST", &path, Some(&elevated), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert!(body.contains("ELEVATED READ-ONLY"), "not the recorder's refusal: {body}");
    assert!(!body.contains("wrote"), "handler ran for an elevated write: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn oversized_body_to_extension_is_413(pool: PgPool) {
    let (router, state) = app(&pool);
    let t = token(&state, Uuid::new_v4(), &["claims:write"], None);
    let big = format!("{{\"pad\":\"{}\"}}", "x".repeat(BODY_LIMIT * 4));
    let (status, body, _) = send(&router, "POST", "/api/v1/ext/demo/echo", Some(&t), Some(big)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "body: {body}");
    let (ok, body, _) = send(
        &router,
        "POST",
        "/api/v1/ext/demo/echo",
        Some(&t),
        Some("{\"pad\":\"x\"}".into()),
    )
    .await;
    assert_eq!(ok, StatusCode::OK, "a small body must pass: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn fallback_under_prefix_is_still_behind_bearer(pool: PgPool) {
    let (router, _) = app(&pool);
    let (status, body, _) =
        send(&router, "GET", "/api/v1/ext/demo/no-such-route", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(!body.contains("extension fallback"), "fallback served anonymously: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn elevated_post_to_extension_fallback_is_refused(pool: PgPool) {
    let (router, state) = app(&pool);
    let elevated = token(&state, Uuid::new_v4(), &["claims:write"], Some(Uuid::new_v4()));
    let (status, body, _) =
        send(&router, "POST", "/api/v1/ext/demo/no-such-route", Some(&elevated), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");
    assert!(body.contains("ELEVATED READ-ONLY"), "not the recorder's refusal: {body}");
    assert!(
        !body.contains("extension fallback"),
        "elevated write reached the extension's fallback past the recorder: {body}"
    );
}
```

- [ ] **Step 2: Run it and see it fail**

Run: `cargo test -p epigraph-api --test router_extension_seam`
Expected: FAIL to compile with `unresolved imports epigraph_api::create_router_with_extensions, epigraph_api::RouterExtension`.

- [ ] **Step 3: Implement, db variant**

In `crates/epigraph-api/src/routes/mod.rs`, at the `#[cfg(feature = "db")]` `pub fn create_router(state: AppState) -> Router {` line, keep the existing doc comment above it and replace that one line with:

```rust
#[cfg(feature = "db")]
pub fn create_router(state: AppState) -> Router {
    create_router_with_extensions(state, Vec::new())
}

/// [`create_router`] with embedder routes nested inside the authenticated
/// router, at `/api/v1/ext/<name>` each. They are mounted before the
/// authenticated router's layers, so they inherit bearer authentication, the
/// per-access recorder, the body limit and the rate limiter. They do not
/// inherit scope checks or tenancy; see [`extensions`] for that contract.
/// Passing no extensions is exactly [`create_router`].
///
/// # Panics
/// When two extensions share a name.
#[cfg(feature = "db")]
pub fn create_router_with_extensions(
    state: AppState,
    extensions: Vec<extensions::RouterExtension>,
) -> Router {
```

The existing body follows unchanged, except for one statement. Find the statement in this variant that begins `let protected = protected` and is followed by `.route_layer(middleware::from_fn_with_state(` and `crate::middleware::elevated_access::record_elevated_access`. Change only its first line, so it reads:

```rust
    let protected = extensions::mount_all(protected, extensions, &state)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::elevated_access::record_elevated_access,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            bearer_auth_middleware,
        ));
```

Add this line to the comment block directly above that statement. It must not contain `let protected = ` or `.merge(`:

```rust
    // Embedder extensions (`extensions::mount_all`) are nested HERE, before
    // either layer: `route_layer` and `layer` wrap only routes that already
    // exist, so a mount below them would be unauthenticated.
```

- [ ] **Step 4: Implement, not(db) variant**

Do the same at the `#[cfg(not(feature = "db"))]` `pub fn create_router(state: AppState) -> Router {` line, with both new items carrying `#[cfg(not(feature = "db"))]` and the same doc text, except that "the per-access recorder" is omitted, since this variant has none. Then replace that variant's statement `let protected = protected.layer(middleware::from_fn_with_state(` (the four-line statement that applies `bearer_auth_middleware`) with the chained form used in the db variant:

```rust
    let protected = extensions::mount_all(protected, extensions, &state)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            bearer_auth_middleware,
        ));
```

Run `cargo fmt -p epigraph-api`. Then confirm the text `let protected = ` still appears on one line in exactly as many places as on `main`:
`git grep -c 'let protected = ' origin/main -- crates/epigraph-api/src/routes/mod.rs` must equal `grep -c 'let protected = ' crates/epigraph-api/src/routes/mod.rs`.
`public_router_allowlist::protected_paths` counts that exact text. If rustfmt broke a line after `=`, that lint now fails.

- [ ] **Step 5: Re-export**

In `crates/epigraph-api/src/lib.rs`, replace `pub use routes::create_router;` with:

```rust
pub use routes::extensions::{ExtensionNameError, RouterExtension, EXTENSION_PREFIX};
pub use routes::{create_router, create_router_with_extensions};
```

In the repo-root `CLAUDE.md`, directly after the "Adding MCP tools" section, add:

```markdown
## Adding HTTP routes from a downstream product

The MCP surface is extended by federation (above). The REST surface is
extended in-process: an embedder that runs `epigraph-api` as a library passes
`RouterExtension`s to `create_router_with_extensions`, and each is mounted at
`/api/v1/ext/<name>` inside the authenticated router (bearer, per-access
recorder, body limit, rate limit). Scope checks and tenancy are the
extension's own job; see `crates/epigraph-api/src/routes/extensions.rs`.
Never register a first-party route under `/api/v1/ext`
(`tests/router_extension_seam_lint.rs` fails if you do).
```

- [ ] **Step 6: Run the tests and see them pass**

Run: `DATABASE_URL=<test-postgres-url> cargo test -p epigraph-api --test router_extension_seam`
Expected: PASS, 8 tests.

If either fallback test fails, a layer does not wrap the extension's fallback. That is a real defect, not a test to relax. Check that `mount_all` uses `nest_service`, not `nest` (see the Design decisions row).

- [ ] **Step 7: Mutation check (the tests must fail when the seam is misplaced)**

Temporarily move the db-variant mount below the layers. Turn the statement back into `let protected = protected` and, in the final assembly, change `.merge(protected)` to `.merge(extensions::mount_all(protected, extensions, &state))`. Run the test file again.
Expected: `extension_without_a_token_is_401_with_a_bearer_challenge`, `elevated_post_to_extension_is_refused_as_read_only`, `elevated_post_to_extension_fallback_is_refused` and `fallback_under_prefix_is_still_behind_bearer` FAIL. Revert with `git checkout -- crates/epigraph-api/src/routes/mod.rs`, then re-apply Steps 3 and 4 if the checkout dropped them. Simplest is to commit Steps 3–5 to a WIP commit before mutating, then `git reset --hard` to it. Run the tests again: PASS.

Second mutation, the reason for `nest_service`: in `extensions.rs::mount_all`, change `router.nest_service(&path, ext.router.with_state(state.clone()))` to `router.nest(&path, ext.router)`. Run the test file again.
Expected: `elevated_post_to_extension_fallback_is_refused` FAILS, because the elevated POST reaches the fallback. The other seven still pass. Revert.

- [ ] **Step 8: Run every suite that reads route source**

Many test binaries scan `routes/mod.rs` or `src/routes/` as text. They include `public_router_allowlist`, `viewer_route_table_lint`, `no_bypass_in_handlers`, `elevation_ceremony`, `evidence_list_route_test` and `lint_text` in this crate, and `no_unscoped_pool`, `visibility_lint` and `write_gate_lint` in `epigraph-db`. Run the whole packages rather than a hand-picked list:

```
DATABASE_URL=<test-postgres-url> cargo test -p epigraph-api
DATABASE_URL=<test-postgres-url> cargo test -p epigraph-db
cargo check -p epigraph-api --no-default-features --locked
```

Expected: all pass, and the no-db check shows no new errors. In particular, `the_final_router_merges_only_protected_public_and_oauth` and `protected_paths` must still see the same `.merge(` list and the same `let protected = ` count as `main`.

- [ ] **Step 9: Commit**

```bash
git add crates/epigraph-api/src/routes/mod.rs crates/epigraph-api/src/lib.rs crates/epigraph-api/tests/router_extension_seam.rs CLAUDE.md
git commit -m "feat(api): mount embedder routes under the authenticated router's layers

**Evidence:**
- Issue #481; its patch no longer applies to main and placed the merge relative to a deleted signature layer

**Reasoning:**
- create_router_with_extensions mounts each RouterExtension (nest_service, bound to AppState) at /api/v1/ext/<name> inside the statement that applies route_layer(record_elevated_access) and layer(bearer_auth_middleware); axum wraps only routes that exist when those calls run
- mount_all keeps .merge( and 'let protected = ' counts unchanged, so the public-router lints still hold
- create_router delegates with no extensions, so existing callers are unchanged

**Verification:**
- tests/router_extension_seam.rs: 8 pass (401 + challenge, own/kernel state, scope 403/200, elevated POST refused on a route and on the fallback, 413, fallback behind bearer)
- nest_service rather than nest: axum 0.7.9 moves a nested custom fallback outside route_layer, so an elevated write to an unmatched extension path would skip the recorder
- Mutations: mounting after the layers fails the 401, elevated-refusal and fallback tests; nest instead of nest_service fails the elevated-fallback test
- cargo test -p epigraph-api and -p epigraph-db (whole packages) pass; no-db check adds no errors"
```

---

### Task 3: Lint that reserves the prefix and pins where the mount sits

**Files:**
- Create: `crates/epigraph-api/tests/router_extension_seam_lint.rs`

**Interfaces:**
- Consumes: the source text of `crates/epigraph-api/src/routes/mod.rs` after Task 2; `epigraph_api::EXTENSION_PREFIX`.
- Produces: nothing used by other tasks.

This lint is the only check on the not(db) variant's placement: CI type-checks that variant but runs no test against it.

- [ ] **Step 1: Write the lint**

```rust
//! Source lint for the router extension seam (`routes/extensions.rs`).
//!
//! 1. `/api/v1/ext` belongs to extensions: no first-party `.route(` or
//!    `.nest(` in `routes/mod.rs` may register at or under it, or a kernel
//!    upgrade could collide with an embedder's routes.
//! 2. In BOTH create_router variants, `extensions::mount_all(protected,
//!    extensions, &state)` heads the statement that applies `bearer_auth_middleware`
//!    (and, in the db variant, `record_elevated_access`). axum layers wrap only
//!    routes that already exist, so a mount anywhere else is unauthenticated.
//!    `tests/router_extension_seam.rs` proves this at runtime for the db
//!    variant only; this lint is what covers not(db).

const ROUTES_MOD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/routes/mod.rs");
/// Matched against [`compact`] source, so rustfmt's line breaks cannot hide it.
const MOUNT: &str = "letprotected=extensions::mount_all(protected,extensions,&state)";

fn source() -> String {
    std::fs::read_to_string(ROUTES_MOD).unwrap_or_else(|e| panic!("cannot read {ROUTES_MOD}: {e}"))
}

/// The source with every whitespace character removed. Used only for the
/// placement checks; string literals are not compared in this form.
fn compact(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Every string literal passed as the first argument of `.{method}(`.
fn first_literals(src: &str, method: &str) -> Vec<String> {
    let needle = format!(".{method}(");
    src.match_indices(&needle)
        .filter_map(|(i, _)| {
            let rest = src[i + needle.len()..].trim_start();
            let rest = rest.strip_prefix('"')?;
            rest.find('"').map(|end| rest[..end].to_string())
        })
        .collect()
}

#[test]
fn no_first_party_route_is_registered_under_the_extension_prefix() {
    let src = source();
    let prefix = epigraph_api::EXTENSION_PREFIX;
    let routes = first_literals(&src, "route");
    assert!(
        routes.len() > 150,
        "only {} route literals found; the scan lost the router",
        routes.len()
    );
    let mut offenders: Vec<String> = routes
        .into_iter()
        .chain(first_literals(&src, "nest"))
        .filter(|p| p == prefix || p.starts_with(&format!("{prefix}/")))
        .collect();
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "{offenders:?} registered under {prefix}, which is reserved for \
         embedder extensions (routes/extensions.rs). Move the route elsewhere."
    );
}

#[test]
fn both_variants_mount_extensions_at_the_head_of_the_auth_layer_statement() {
    let src = compact(&source());
    let starts: Vec<usize> = src.match_indices(MOUNT).map(|(i, _)| i).collect();
    assert_eq!(
        starts.len(),
        2,
        "expected `{MOUNT}` (whitespace removed) exactly twice (db, then not(db)); found {}",
        starts.len()
    );
    assert_eq!(
        src.matches("extensions::mount_all(").count(),
        2,
        "extensions::mount_all is called somewhere other than the two auth-layer statements"
    );
    for (variant, &start) in ["db", "not(db)"].iter().zip(&starts) {
        // The layer statements contain no `;` before their end.
        let stmt = &src[start..start + src[start..].find(';').expect("statement end")];
        assert!(
            stmt.contains("bearer_auth_middleware"),
            "{variant}: the mount statement does not apply bearer_auth_middleware:\n{stmt}"
        );
        if *variant == "db" {
            assert!(
                stmt.contains("record_elevated_access"),
                "db: the mount statement does not apply the per-access recorder:\n{stmt}"
            );
        }
    }
}

#[test]
fn create_router_delegates_with_no_extensions_in_both_variants() {
    let src = compact(&source());
    assert_eq!(
        src.matches("create_router_with_extensions(state,Vec::new())").count(),
        2,
        "each create_router variant must delegate to create_router_with_extensions \
         with no extensions, so the two cannot drift"
    );
}
```

- [ ] **Step 2: Run it, then mutate it**

Run: `cargo test -p epigraph-api --test router_extension_seam_lint`
Expected: PASS, 3 tests. No database needed.

Mutation: in the not(db) variant, move `extensions::mount_all(protected, extensions, &state)` out of the layer statement, into a `let protected = extensions::mount_all(protected, extensions, &state);` just after it. Run again.
Expected: `both_variants_mount_extensions_at_the_head_of_the_auth_layer_statement` FAILS, because the second statement does not apply `bearer_auth_middleware`. `public_router_allowlist::protected_paths` also fails on the seventh `let protected = `. Revert.

Mutation: add `.route("/api/v1/ext/x", get(health::health_check))` to the db `protected` chain. Run again.
Expected: `no_first_party_route_is_registered_under_the_extension_prefix` FAILS naming `/api/v1/ext/x`. Revert.

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-api/tests/router_extension_seam_lint.rs
git commit -m "test(api): reserve /api/v1/ext and pin the extension mount above the auth layers

**Evidence:**
- CI type-checks the not(db) create_router variant but runs no runtime test against it

**Reasoning:**
- A source lint is the only check that covers the not(db) mount placement
- Reserving the prefix in a lint keeps kernel routes out of the extension namespace

**Verification:**
- 3 pass; mutations (mount moved out of the layer statement, a first-party /api/v1/ext route) each fail the matching test"
```

---

### Task 4: Full gate and PR

**Files:** none new.

- [ ] **Step 1: Run the repository's ci-local gate on the branch head.** It runs the branch's own `ci.yml` steps, including fmt, clippy `-D warnings`, the workspace tests, and the no-db build check. Fix anything it reports in the task that owns the code, with its own commit.
- [ ] **Step 2: Ask the operator before pushing.** On approval, push `plan/router-extension-seam`, renaming the branch to `feat/router-extension-seam` first if preferred, and open a PR against `main`. The PR body links #481 and summarises the Design decisions table (what changed from the proposal and why) and the inherits / does-not-inherit list. Do not merge.
- [ ] **Step 3: After the PR is open, offer to draft a comment on #481** for the operator to post. It explains the prefix and layer-placement changes relative to the proposed patch, and that the 26-line patch was not applied as-is.
