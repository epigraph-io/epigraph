# Multi-Provider OAuth Identity Port — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Port the multi-provider external identity system from `epigraph-internal` (PR #7 there). Adds an `oauth/providers/` submodule with a provider trait, JWKS cache, Google + Cloudflare Access providers, TOML config loader, registry, and provisioning. Refactors `oauth/token.rs` and `oauth/device.rs` to dispatch through the registry. Wires startup loading from `providers.toml`.

**Architecture:** Plugin pattern. `ExternalIdentityProvider` trait + `ProviderRegistry` indexed by name and grant_type. Two ship-ready impls: `GoogleProvider` (OIDC redirect flow) and `CloudflareAccessProvider` (assertion flow). `JwksCache` provides single-flight + stale-grace fetching. `provision_external_user` is the provider-agnostic provisioning seam. Existing agent / service / refresh auth paths unchanged.

**Tech Stack:** Rust workspace · axum · sqlx 0.7 · jsonwebtoken · reqwest · TOML config · `wiremock` for HTTP fixtures (new dev-dep).

**Base branch:** `origin/main` (independent of slices 4 + 5 in flight).

**Out of scope:**
- `crates/epigraph-api/Cargo.toml` change adding `dep:epigraph-mcp` to the `db` feature (couples with `routes/mcp_tools.rs`, separate slice).
- The internal removal of `dep:epigraph-cli` from the `genai` feature (the Claude CLI exclusion has its own scrub branch).
- The internal removal of `epigraph-jobs` from `[dependencies]` and the deletion of the cluster-graph job runner from `bin/server.rs` — public still uses these.
- Removal of the `[[test]] graph_routes_test` Cargo entry — public-only test config; keep.

## File Structure

**Create (new in this slice):**
- `crates/epigraph-api/src/oauth/providers/mod.rs` (registry build helper)
- `crates/epigraph-api/src/oauth/providers/traits.rs` (ExternalIdentityProvider trait + ProviderError)
- `crates/epigraph-api/src/oauth/providers/registry.rs` (lookup by name + grant_type)
- `crates/epigraph-api/src/oauth/providers/jwks.rs` (JwksCache)
- `crates/epigraph-api/src/oauth/providers/config.rs` (TOML schema + validation)
- `crates/epigraph-api/src/oauth/providers/google.rs` (GoogleProvider)
- `crates/epigraph-api/src/oauth/providers/cloudflare_access.rs` (CloudflareAccessProvider)
- `crates/epigraph-api/src/oauth/providers/provision.rs` (provision_external_user)
- `crates/epigraph-api/tests/oauth_db.rs` (DB-level provisioning tests)
- `crates/epigraph-api/tests/oauth_http.rs` (HTTP-level provider routes tests)
- `crates/epigraph-api/tests/oauth_redirect_flow.rs` (redirect flow exchange test)
- `crates/epigraph-api/tests/oauth_token_grant.rs` (token grant tests)
- `crates/epigraph-api/tests/oauth_providers/mod.rs` + `fixtures.rs` (RSA + wiremock fixtures)
- `providers.toml` (sample config at workspace root)

**Modify:**
- `crates/epigraph-api/Cargo.toml` — add `toml = "0.8"` and `wiremock = "0.6"` dev-dep. Keep `epigraph-jobs`, `epigraph-cli`, `[[test]] graph_routes_test` (public-only).
- `crates/epigraph-api/src/oauth/mod.rs` — register `pub mod providers;`.
- `crates/epigraph-api/src/oauth/token.rs` — replace with internal version (dispatches to registry).
- `crates/epigraph-api/src/oauth/device.rs` — replace with internal version (dispatches to registry).
- `crates/epigraph-api/src/state.rs` — add `providers: Arc<ProviderRegistry>` field; init `ProviderRegistry::empty()` in all constructors; add `with_providers` builder.
- `crates/epigraph-api/src/bin/server.rs` — surgical insert of providers.toml load + `state.with_providers(...)` chain. Leave the existing job runner / cluster graph wiring alone.

---

## Pre-Task: Worktree

```bash
cd /home/jeremy/epigraph
git fetch origin main
git worktree add -b feat/s3-multi-provider-oauth-port /home/jeremy/epigraph-wt-oauth origin/main
cd /home/jeremy/epigraph-wt-oauth
cargo check -p epigraph-api
```

Expected: clean compile baseline.

---

## Task 1: Cargo.toml additions

Add to `crates/epigraph-api/Cargo.toml`:
- `toml = "0.8"` in `[dependencies]` (provider config parsing).
- `wiremock = "0.6"` in `[dev-dependencies]` (HTTP test fixtures).

**Do not** copy internal-main's Cargo.toml verbatim — it removes `epigraph-jobs`, `epigraph-cli` and the `[[test]] graph_routes_test` entry. Surgical adds only.

Verify: `cargo build -p epigraph-api --tests` fetches the new deps.

Commit: `chore(api): add toml + wiremock deps for OAuth provider config and tests`

---

## Task 2: Port `oauth/providers/` submodule (8 new files)

```bash
mkdir -p crates/epigraph-api/src/oauth/providers
for f in mod.rs traits.rs registry.rs jwks.rs config.rs google.rs cloudflare_access.rs provision.rs; do
    git show internal-main:crates/epigraph-api/src/oauth/providers/$f > crates/epigraph-api/src/oauth/providers/$f
done
wc -l crates/epigraph-api/src/oauth/providers/*.rs
```

Expected total: ~1400 lines across the 8 files (mod 65, traits 71, registry 130, jwks 289, config 256, google 255, cloudflare 144, provision 168).

Don't compile yet — needs token.rs/device.rs integration in later tasks.

Commit: `feat(oauth): scaffold multi-provider identity submodule`

---

## Task 3: Register submodule in `oauth/mod.rs`

```bash
git diff origin/main internal-main -- crates/epigraph-api/src/oauth/mod.rs
```

Apply the additions verbatim (small diff, ~3 lines). Commit: `feat(oauth): wire providers submodule in oauth/mod.rs`.

---

## Task 4: state.rs surgery

Apply surgically (do not clobber — there are 4 constructors plus extensive other state):

1. Add `use crate::oauth::providers::ProviderRegistry;` near the existing `use crate::middleware::SignatureVerificationState;`.
2. Add field to `pub struct AppState`:
   ```rust
   /// External identity provider registry. Built once at startup from `providers.toml`.
   /// Empty by default — server still works for agent/service auth and existing tokens,
   /// but external `grant_type=*` requests return 400 unsupported_grant_type.
   pub providers: Arc<ProviderRegistry>,
   ```
3. In each constructor (`AppState::new`, `with_db`, `with_signature_verifier`, etc.), add `providers: Arc::new(ProviderRegistry::empty()),` to the struct literal.
4. Add `with_providers` builder near `with_orchestration_backend`:
   ```rust
   /// Replace the external-provider registry. Idiomatic builder.
   ///
   /// Call at startup after loading `providers.toml`. When omitted, the registry
   /// is empty — agent/service/refresh auth still works; external grant types
   /// return 400 unsupported_grant_type.
   #[must_use]
   pub fn with_providers(mut self, providers: Arc<ProviderRegistry>) -> Self {
       self.providers = providers;
       self
   }
   ```

Verify: `grep -c "providers: Arc::new(ProviderRegistry::empty())" crates/epigraph-api/src/state.rs` matches the constructor count.

Commit: `feat(state): add providers field + with_providers builder`.

---

## Task 5: Replace `oauth/token.rs`

```bash
git show internal-main:crates/epigraph-api/src/oauth/token.rs > crates/epigraph-api/src/oauth/token.rs
```

Compile: `cargo check -p epigraph-api 2>&1 | tail -20`. Expect clean.

Likely surface error: missing imports if internal token.rs uses something public's doesn't have. Inspect the file head; cross-reference with `crates/epigraph-api/src/oauth/mod.rs` exports.

Commit: `feat(oauth): dispatch token grants through provider registry`.

---

## Task 6: Replace `oauth/device.rs`

```bash
git show internal-main:crates/epigraph-api/src/oauth/device.rs > crates/epigraph-api/src/oauth/device.rs
```

Compile + commit: `feat(oauth): dispatch device flow through provider registry`.

---

## Task 7: Wire `bin/server.rs` (surgical add only)

Locate the line after `let state = AppState::with_db(pool, config).with_embedding_service(embedding_service);` (don't touch the surrounding `#[cfg(feature = "db")]` block or the job runner wiring that follows).

Insert immediately after the `let state = ...` line:

```rust
    // Load external identity providers from providers.toml.
    // EPIGRAPH_PROVIDERS_CONFIG overrides the default path.
    let state = {
        let providers_path = std::env::var("EPIGRAPH_PROVIDERS_CONFIG")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("providers.toml"));
        let providers = epigraph_api::oauth::providers::build_registry(providers_path.as_path())
            .expect("failed to build providers registry");
        state.with_providers(providers)
    };
```

This must run after both `db` and `not(db)` paths have set `state`. If the existing structure makes that awkward, place the block after the `let state = ...` line that's outside the cfg gates. (Read internal-main's server.rs for guidance, but DO NOT clobber: it removes the job runner.)

Compile + commit: `feat(server): load providers.toml into AppState at startup`.

---

## Task 8: Port `providers.toml` sample

```bash
git show internal-main:providers.toml > providers.toml
```

This is a sample config at the workspace root.

Commit: `chore: add sample providers.toml`.

---

## Task 9: Port test fixtures + 4 test files

```bash
mkdir -p crates/epigraph-api/tests/oauth_providers
for f in fixtures.rs mod.rs; do
    git show internal-main:crates/epigraph-api/tests/oauth_providers/$f > crates/epigraph-api/tests/oauth_providers/$f
done
for f in oauth_db.rs oauth_http.rs oauth_redirect_flow.rs oauth_token_grant.rs; do
    git show internal-main:crates/epigraph-api/tests/$f > crates/epigraph-api/tests/$f
done
```

Compile: `cargo test -p epigraph-api --no-run 2>&1 | tail -20`.

Commit: `test(oauth): port DB + HTTP + redirect + token-grant integration suites`.

---

## Task 10: Verification

```bash
# Apply migrations (DB has been pre-created at epigraph_oauth_test).
DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_oauth_test sqlx migrate run --source migrations

# Tests
DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_oauth_test cargo test -p epigraph-api -- --test-threads=1

# Lint scoped (workspace clippy has pre-existing baseline noise)
cargo clippy -p epigraph-api --lib --tests -- -D warnings

# fmt
cargo fmt --all -- --check
```

All green. Note any pre-existing baseline issues in PR body.

---

## Task 11: Push + PR

```bash
git push -u origin feat/s3-multi-provider-oauth-port
gh pr create --title "feat: port multi-provider external identity from epigraph-internal" --base main --body "..."
```

PR body sections: Summary, Excluded scope, Architecture, Coverage, Test plan.
