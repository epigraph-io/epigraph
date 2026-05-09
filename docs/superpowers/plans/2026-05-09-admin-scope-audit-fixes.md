# Admin-Scope Audit Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the 5 security/policy gaps surfaced by the 2026-05-09 admin-scope audit (issues #116, #117, #118, #120, #121) plus the two un-filed footguns (MCP `--http` exposure, `forget_convention` attribution laundering).

**Architecture:** Bundles E–I. Each bundle is a separate PR off main, ordered by severity. The bundles are independent at the code level but build a coherent scope-policy story:

- **E (#118)**: stop the bleeding — 4 mutation endpoints reachable without auth move to the protected router.
- **F (#117 + #120)**: pure scope-string promotions — bulk graph-integrity ops require `claims:admin`.
- **G (#116)**: add ownership-or-admin gate to the 4 claim-mutation endpoints. New helper `require_owner_or_admin`.
- **H (#121)**: webhooks get a new `webhooks:write` scope; `update_agent` / `revoke_agent_key` get caller==agent_id check.
- **I (footguns)**: file 2 issues first (MCP `--http` auth, `forget_convention` attribution), then plan their fixes — they were not filed by the audit.

**Tech Stack:** Rust workspace (axum, sqlx + Postgres, `crate::middleware::scopes::check_scopes`, `epigraph_db::ProvenanceRepository`).

**Pre-flight:**
- Plan citations reference function/symbol names + grep-able snippets, not file:line numbers (per `feedback_code_citations_function_not_line` memory).
- Sqlx tests use `postgres://epigraph:epigraph@...` (not `epigraph_admin`) per `feedback_sqlx_test_uses_superuser`.
- Each bundle gets its own worktree off the latest origin/main (PR #115 / #119 may land first; if so, rebase).

---

## Bundle E — #118 STOP THE BLEEDING (urgent)

**Severity:** CRITICAL. Four `policies` mutation endpoints are wired to the **public** router and run raw SQL `UPDATE`s on `claims` with no Bearer token required.

### Affected handlers

In `crates/epigraph-api/src/routes/policies.rs`:
- `record_outcome`
- `decay_sweep`
- `create_challenge`
- `resolve_challenge`

In `crates/epigraph-api/src/routes/mod.rs`, the public router (look for `Router::new()` block that does NOT chain `.layer(bearer_auth_middleware)` — search for the section that includes `policies::record_outcome` etc.) wires these into the auth-free surface.

### Task E.1 — Move routes from public to protected

**Files:**
- Modify: `crates/epigraph-api/src/routes/mod.rs` — relocate the four `.route("/api/v1/policies/...", ...)` lines into the protected router block.
- Modify: each handler — add `auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>` parameter and `check_scopes` guard.

**Scope assignment per handler:**
| Handler | Scope |
|---|---|
| `record_outcome` | `claims:admin` (mutates beliefs across claims; operator-driven) |
| `decay_sweep` | `claims:admin` (bulk; operator-driven) |
| `create_challenge` | `claims:write` (any authenticated agent can challenge) |
| `resolve_challenge` | `claims:admin` (operator-driven) |

**Steps:**
- [ ] Read `crates/epigraph-api/src/routes/mod.rs` to confirm which Router block currently mounts these. Confirm the protected block applies `bearer_auth_middleware`.
- [ ] Move the four `.route(...)` lines into the protected block.
- [ ] In each of the four handlers, add the auth/scope guard pattern (mirror `mark_duplicate`):
  ```rust
  let auth = auth_ctx.ok_or(ApiError::Unauthorized {
      reason: "<handler> requires authentication".into(),
  })?.0;
  crate::middleware::scopes::check_scopes(&auth, &["<scope>"])?;
  ```
- [ ] Update OpenAPI doc-stubs for each (in handler annotation + `crates/epigraph-api/src/openapi.rs` if entries exist) to add `(status = 401)` and `(status = 403)`.

### Task E.2 — Tests

**Test:** `crates/epigraph-api/tests/policies_auth_test.rs` (new)

For each of the four handlers: 401 (no token), 403 (wrong scope where applicable), happy path (correct scope).

```rust
#[tokio::test(flavor = "multi_thread")]
async fn record_outcome_without_token_returns_401() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let (addr, _shutdown) = common::spawn_app(&url).await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/policies/<some-claim>/outcome"))
        .json(&serde_json::json!({"success": true}))
        .send().await.unwrap();
    assert_eq!(resp.status(), 401);
}
```

Repeat the 401 test for each handler. Add 403 tests using `claims:read`-only tokens. Add at least one happy-path test using `claims:admin` to confirm the new gate doesn't break valid callers.

### Commit

```
fix(api): move policies write endpoints to protected router

Closes #118.

record_outcome, decay_sweep, create_challenge, and resolve_challenge
were wired into the public router and reachable without a Bearer
token. They mutate claims via raw SQL. Now require auth + appropriate
scope (claims:admin for record_outcome/decay_sweep/resolve_challenge,
claims:write for create_challenge).
```

---

## Bundle F — #117 + #120 admin-scope promotions (mechanical)

**Severity:** HIGH. Pure scope-string changes on 16 handlers (14 from #117 + 2 from #120). These currently accept `claims:write`; should require `claims:admin`.

### Affected handlers

#### From #117 (14 handlers)

In `crates/epigraph-api/src/routes/crud.rs`:
- `build_themes_from_corpus`
- `reassign_claim`
- `assign_unthemed`
- `recompute_centroids`
- `create_theme_with_centroid`
- `upsert_cluster`
- `assign_claim_to_frame`
- `promote_staged_edges`

In `crates/epigraph-api/src/routes/clusters.rs`:
- `build_from_bridges`

In `crates/epigraph-api/src/routes/conflicts.rs`:
- `resolve_conflict`

In `crates/epigraph-api/src/routes/conventions.rs`:
- `learn_convention`
- `forget_convention` (also see Bundle I.2 — attribution laundering)

In `crates/epigraph-api/src/routes/policies.rs` (post-Bundle E):
- `record_outcome`, `decay_sweep`, `resolve_challenge` — already on `claims:admin` from Bundle E. NO ADDITIONAL CHANGE here.

#### From #120 (2 handlers)

In `crates/epigraph-api/src/routes/ownership.rs`:
- `assign_ownership` (currently no scope check at all)
- `update_partition` (currently no scope check at all)

### Tasks

#### F.1 — Promote scope strings

For each handler:
- [ ] If it currently calls `check_scopes(&auth, &["claims:write"])`: change to `&["claims:admin"]`.
- [ ] If it currently has NO scope check (the #120 ownership endpoints + several #117 handlers like `build_from_bridges`, `learn_convention`, `forget_convention`, `resolve_conflict`): add the auth_ctx parameter and the full guard pattern.
- [ ] Update OpenAPI annotations to include `(status = 401)` + `(status = 403)`.
- [ ] Audit each handler's existing tests — any test minting a `claims:write` token to call these endpoints will now 403. Update tokens to `claims:admin`.

**Files touched (estimate):**
- `crates/epigraph-api/src/routes/{crud,clusters,conflicts,conventions,ownership}.rs`
- `crates/epigraph-api/src/openapi.rs` (doc-stub updates if any of these have stubs)
- Existing tests under `crates/epigraph-api/tests/` referencing these endpoints

#### F.2 — Tests

For each of the 16 handlers, add (or extend an existing test file with) a 403 case using a `claims:write`-only token. This locks the gate against accidental scope downgrade.

A single new file `crates/epigraph-api/tests/admin_scope_gate_test.rs` covering all 16 endpoints in one place is reasonable — they all do the same thing (mint wrong-scope token, fire request, assert 403).

### Risk: caller breakage

These changes WILL break callers using `claims:write` for any of these operations. Per the user's policy decision, that's intended — these are operator-only.

**Mitigation:** PR description should call out the migration explicitly. Existing callers must:
1. Use a token from the `epigraph-admin` OAuth client (provisioned via the bootstrap binary from PR #111).
2. Or have their token's `granted_scopes` extended to include `claims:admin`.

### Commit

```
fix(api): require claims:admin on bulk graph-integrity + ownership ops

Closes #117 and #120.

16 handlers covering theme management, cluster ops, conflict
resolution, conventions, ownership partitioning, and policies cleanup
move from claims:write (or no check) to claims:admin. These are
operator-driven operations on the graph; non-admin callers should not
be able to invoke them.

BREAKING: callers using claims:write tokens for any of these
endpoints will now receive 403. Migrate to a claims:admin token
(see the epigraph-admin OAuth client bootstrap from PR #111).
```

---

## Bundle G — #116 ownership-or-admin on claim mutations

**Severity:** HIGH. Four claim-mutation endpoints accept `claims:write` without verifying the caller authored the target claim. This means anyone with `claims:write` can rewrite anyone else's claim content, labels, or metadata.

### Affected handlers

| Handler | File | Current scope | Need |
|---|---|---|---|
| `supersede_claim` | `crates/epigraph-api/src/routes/versioning.rs` | `claims:write` | + ownership-or-admin |
| `update_claim` | `crates/epigraph-api/src/routes/claims.rs` | `claims:write` | + ownership-or-admin |
| `patch_claim` | `crates/epigraph-api/src/routes/claims.rs` | `claims:write` | + ownership-or-admin |
| `update_labels` | `crates/epigraph-api/src/routes/claims.rs` | none currently | + `claims:write` + ownership-or-admin |

### Architecture

Add a helper to `crates/epigraph-api/src/middleware/scopes.rs`:

```rust
/// Returns Ok(()) if either:
/// - auth has the `claims:admin` scope, OR
/// - auth.owner_id (or auth.client_id when owner_id is None) matches `claim_agent_id`.
///
/// Used to gate per-claim mutations: admins can edit any claim; others can
/// only edit claims they authored.
pub fn require_owner_or_admin(
    auth: &AuthContext,
    claim_agent_id: Uuid,
) -> Result<(), ApiError> {
    if auth.has_scope("claims:admin") {
        return Ok(());
    }
    let principal = auth.owner_id.unwrap_or(auth.client_id);
    if principal == claim_agent_id {
        return Ok(());
    }
    Err(ApiError::Forbidden {
        reason: "claim is owned by another agent and caller lacks claims:admin".into(),
    })
}
```

### Tasks

#### G.1 — Helper

- [ ] Add `require_owner_or_admin` to `scopes.rs`.
- [ ] Add three unit tests: admin scope passes, matching-owner passes, non-matching-no-admin fails.

#### G.2 — Wire into handlers

For each of the 4 handlers:
- [ ] After the existing `check_scopes(&auth, &["claims:write"])`, fetch `claim.agent_id` from the DB by the `claim_id` path param (single-row query, ideally as part of the existing fetch the handler already does).
- [ ] Call `require_owner_or_admin(&auth, agent_id)?` before any mutation.
- [ ] For `supersede_claim`, the existing fetch already reads agent_id (line `SELECT agent_id FROM claims WHERE id = $1`). Reuse that.
- [ ] For `patch_claim` / `update_claim`, the handler probably loads the row before patching — extract agent_id from that load.
- [ ] For `update_labels` (currently no scope check): add full auth + scope + ownership chain.

#### G.3 — Tests

For each handler, add three cases:
- 200 happy path with matching-owner `claims:write` token
- 200 happy path with `claims:admin` token (override)
- 403 with `claims:write` token but mismatched owner

Add to existing test files where they exist (`patch_claim_http_test.rs`, `supersede_scope_check_test.rs`) or create new files.

### Commit

```
fix(api): ownership-or-admin gate on claim-mutation endpoints

Closes #116.

supersede_claim, update_claim, patch_claim, and update_labels
previously accepted any claims:write token regardless of who
authored the target claim. Anyone could rewrite anyone's content.
Now: callers must EITHER hold claims:admin OR be the original
authoring agent (owner_id matches claim.agent_id).

Adds require_owner_or_admin helper in middleware::scopes.
```

---

## Bundle H — #121 webhooks + agent mutations

**Severity:** MEDIUM-HIGH. Webhooks have no scope check; agent mutations check `agents:write` but not caller==target.

### H.1 — New `webhooks:write` scope

In `crates/epigraph-core/src/canonical_scopes.rs`:
- [ ] Add `"webhooks:write"` to `WRITE_SCOPES`.
- [ ] Increments to `read_write_scopes()` and `admin_scopes()` flow automatically.

In `crates/epigraph-api/src/routes/webhooks.rs`:
- [ ] `register_webhook` and `delete_webhook` get the auth + `check_scopes(["webhooks:write"])` guard.
- [ ] Persist the webhook's `owner_client_id` (whichever column the schema has — likely already there as `created_by` or similar). Read the webhooks table schema first.
- [ ] On `delete_webhook`: caller must own the row OR have `claims:admin`. Use `require_owner_or_admin`-style check adapted for webhooks (probably `require_webhook_owner_or_admin` since the column name differs).

If the schema doesn't have an owner column, file a separate migration issue and gate on `claims:admin` for now as the conservative fallback.

### H.2 — Agent self-mutation check

In `crates/epigraph-api/src/routes/agents.rs::update_agent` and `crates/epigraph-api/src/routes/agent_keys.rs::revoke_agent_key`:
- [ ] Add caller-is-target check: `auth.agent_id == path_id OR auth.has_scope("claims:admin")`.
- [ ] Mirror the helper-pattern from Bundle G.

### H.3 — Tests

`crates/epigraph-api/tests/webhooks_auth_test.rs` and `agent_mutation_auth_test.rs` covering 401/403/200 cases per endpoint.

### H.4 — Update bootstrap_clients

The new `webhooks:write` scope must be picked up by `epigraph-wo` (read+write) and `epigraph-admin` automatically (the constants in `canonical_scopes.rs` chain). No code change needed in `bootstrap_clients` itself, but verify by re-running the canonical_scopes unit tests.

### Commit

```
fix(api): scope + ownership gates on webhooks and agent mutations

Closes #121.

- New webhooks:write scope (added to canonical_scopes; flows to ro/wo/admin).
- register_webhook + delete_webhook now require it; delete also requires
  caller owns the webhook row (or has claims:admin).
- update_agent + revoke_agent_key now require caller is the target
  agent (auth.agent_id == :id) or has claims:admin.
```

---

## Bundle I — Footguns (file issues first, then plan)

The audit surfaced two issues NOT yet filed:

### I.1 — MCP `--http` mode lacks auth

In `crates/epigraph-mcp/src/main.rs`, the `--http` transport flag exposes all MCP tools (including `mark_duplicate`, `supersede_claim`, `patch_claim`, `update_partition`) over HTTP with no auth checks — MCP tools assume stdio process boundary as the trust boundary.

**File issue first:**
```
gh issue create --repo epigraph-io/epigraph \
  --title "Security: MCP --http transport exposes mutation tools without auth" \
  --body "..."
```

Issue body should describe:
- The MCP tools rely on stdio process boundary as their trust gate (no per-tool auth checks).
- Enabling `--http` removes that boundary; mutation tools become reachable network-wide.
- Recommended fix: `--http` mode requires a `--auth-config` flag that wires Bearer token + scope checks identical to the HTTP API.
- Stopgap: refuse to start in `--http` mode unless an explicit `--allow-unauthenticated-http` flag is also set.

**Plan: Bundle I.1 PR**
- [ ] Refuse `--http` mode without `--auth-config` (cheap stopgap; prevents accidental exposure)
- [ ] Tracked separately for the proper auth wiring.

### I.2 — `forget_convention` attribution laundering

`crates/epigraph-api/src/routes/conventions.rs::forget_convention` writes refuting evidence attributed to a `[0u8;32]` zero-byte system agent identity rather than the calling client_id. The `truth_value` decay surface is also non-trivial (uses deprecated `BayesianUpdater`).

**File issue:**
```
gh issue create --repo epigraph-io/epigraph \
  --title "Security: forget_convention launders attribution via [0u8;32] system agent" \
  --body "..."
```

**Plan: Bundle I.2 PR**
- [ ] Replace `[0u8;32]` with the calling principal's client_id.
- [ ] Either drop the `BayesianUpdater` decay logic (deprecated per `feedback_pignistic_not_bayesian` memory) or leave a `// TODO: migrate to CDST` comment with a follow-up issue.
- [ ] Add a test asserting the refute evidence row's `agent_id` matches the caller.

This bundle merges into Bundle F's `forget_convention` admin-scope change for efficiency — same handler, same PR.

---

## Recommended sequence

1. **Bundle E (this week, urgent)** — #118 is reachable without auth; close before anything else.
2. **Bundle F (next)** — #117 + #120 in a single PR. Mostly mechanical; biggest effort is updating existing tests that use `claims:write` tokens for these endpoints.
3. **Bundle G** — #116 ownership-or-admin. Architecturally meaningful; needs the new helper and per-endpoint integration. Half the bundle is updating existing happy-path tests to use a matching-owner token via `test_bearer_token_with_seeded_client`.
4. **Bundle H** — #121 webhooks + agent mutations. New scope + helper.
5. **Bundle I** — file the two issues, do the cheap stopgap on `--http`, fold the `forget_convention` attribution fix into Bundle F.

## Out of scope

- Migrating the deprecated `BayesianUpdater` belief-update path to CDST (separate, larger initiative — see `project_bp_cdst_primary` memory).
- Adding ownership columns to tables that don't have them (file as separate migration issues if encountered during Bundle H).
- Sweeping every handler with the `Option<axum::Extension<AuthContext>>` pattern that does `if let Some` then `check_scopes` — it's a defense-in-depth concern but not currently exploitable since `bearer_auth_middleware` enforces auth at the protected layer. File as cleanup follow-up.

## Cross-cutting notes

- Every new test must use `postgres://epigraph:epigraph@...` per the sqlx-test memory.
- Every new admin-scope test should mint via `test_bearer_token_with_scopes` to bypass the OAuth client provisioning step.
- Bundle G's `require_owner_or_admin` helper is the prototype for similar gates in the future; design it for reuse.
- The bootstrap binary from PR #111 must remain compatible — verify after each bundle that the canonical_scopes unit tests still pass.

## Estimated effort

| Bundle | Size | Effort |
|---|---|---|
| E | XS | ½ day |
| F | M | 1 day (most cost is test-token updates) |
| G | M | 1.5 days |
| H | M | 1 day |
| I.1 stopgap | XS | ¼ day |
| I.2 (folded) | XS | included in F |
| **Total** | | **~4 days focused work** |
