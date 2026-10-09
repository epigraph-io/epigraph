# Persisting Batch Claim Route Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `POST /api/v1/claims/batch` persist every item to `claims`, through the exact code path `POST /api/v1/claims` uses. Attribution, ownership, idempotency (`if_not_exists`), properties, labels and embedding then behave the same for a batch item as for a single claim.

**Architecture:** The body of `routes/claims.rs::create_claim` (db build) moves into `create_claim_core(&AppState, &Viewer, Option<&AuthContext>, CreateClaimRequest) -> Result<ClaimResponse, ApiError>`, and the handler becomes a one-line delegate. The db build's batch handler authenticates once, decodes each item into a `CreateClaimRequest` (adding the caller's `agent_id` when the item omits one, and accepting the legacy `truth_value` key), and calls `create_claim_core` once per item. Each item gets its own transaction, as MCP `batch_submit_claims` does. A failing item is reported in its result slot and doesn't affect the others. The not(db) build keeps today's in-memory handler unchanged.

**Tech Stack:** Rust, axum 0.7, sqlx 0.8 (Postgres), serde_json, reqwest (integration tests).

**Spec:** GitHub issue epigraph-io/epigraph#477, plus the "Design decisions" section below. The issue asked for the batch item to accept the single-claim fields and for the two paths to stop drifting. Its follow-up comment records that the route persists nothing at all (`AppState::claim_store` only). The repo's tenancy ledger (`docs/tenancy/progress.json`, finding `F-PR10-unknown-claim-id-delivers`) deferred "make it persist" because it needed "SQL in the repo layer, an ownership decision at INSERT … and an auth extractor". `create_claim` already has all three, which is why this plan reuses it rather than building a second writer.

## Design decisions

| Question | Decision | Why |
|---|---|---|
| Second writer, or reuse the single-claim path? | Reuse: `create_claim_core` is the single path's body, moved unchanged | The issue's core request is that the two paths can't drift. Ownership (`default_decl_for_author`), the stamped write transaction (`begin_claim_write`), the dedup contract, the content-hash override check, labels, embedding, edges and provenance live in one place. |
| How does an item become a `CreateClaimRequest`? | `batch_item_to_create_request(serde_json::Value, caller_agent_id) -> Result<CreateClaimRequest, String>`: fill `agent_id` with the caller's when absent, rename `truth_value` to `initial_truth`, then `serde_json::from_value` | A batch item *is* a `CreateClaimRequest` with two defaults, so any field added to `CreateClaimRequest` later reaches batch automatically. A malformed item becomes a per-item error instead of a 422 for the whole body. |
| Author when the item names none | The caller's own `agent_id` (from the token) | Fixes the issue's "fresh synthetic agent per claim". Legacy clients that send only `{content, truth_value}` get claims attributed to them. |
| Item that names an `agent_id` | Same semantics as the single route: recorded as `claims.agent_id`. The public key and the ownership group still come from the token. | Exact parity. The body `agent_id` "is NOT a credential" gap (`D-PR16-claim-authorship-is-not-a-credential`, documented at `create_claim`) is neither widened nor closed here. |
| One transaction for the batch, or one per item? | One per item | Matches MCP `batch_submit_claims` and today's partial-success contract (`created`/`failed`/per-item results). An all-or-nothing batch would be a new contract nobody has asked for. |
| Events | None. `POST /api/v1/claims` and MCP `batch_submit_claims` publish no `ClaimSubmitted` either. | Parity. The removal of the batch publish (deploy note 1d) stays in force; `tests/batch_publish_test.rs` keeps asserting it against the persisting handler. |
| Per-item content cap (65,536 bytes) | Kept as a batch-only check before `create_claim_core` | Today's batch contract rejects longer items. Removing the cap would loosen a published limit. The single route has only the body limit, so it is unchanged. |
| Response shape | Add `existing` (count of `if_not_exists` hits) to the response, and `was_created` and `status` to each result. Existing fields are unchanged. | `created` keeps its meaning (rows inserted). A dedup hit is neither created nor failed, so it needs its own counter. `status` lets a client tell a 409 from a 400 without parsing the message. |
| not(db) build | Keep the in-memory handler unchanged behind `#[cfg(not(feature = "db"))]` | That build has no database. `claims_query`'s not(db) arm reads the same in-memory store. |

## Non-goals

- `routes/reasoning.rs::analyze` reads `AppState::claim_store` in the db build too. After this change nothing writes that store in a db build, so `analyze` returns an empty analysis in a db build unless a test seeds the store. This is a separate defect: `analyze` should read through a viewer-scoped repo call. It gets its own backlog item and PR.
- Closing the authorship gap above.
- Running items in parallel or batching the INSERTs. Correctness and parity come first. Per-item embedding calls run sequentially, as in MCP batch.
- Any change to MCP `batch_submit_claims`.

## Global Constraints

- All SQL stays in `crates/epigraph-db/src/repos/` (repo `CLAUDE.md`). This plan adds no SQL: the batch path reaches the database only through `create_claim_core`.
- The source-lint ratchets must keep passing with **unchanged** numbers:
  - `crates/epigraph-db/tests/no_unscoped_pool.rs` (`("routes/claims.rs", 18)`, `HIGH_WATER = 258`);
  - `crates/epigraph-db/tests/personal_group_mint_ratchet.rs` (one `default_decl_for_author` in `routes/claims.rs`).
  
  `routes/batch.rs` must contain no `state.db_pool` and no `default_decl_for_author`.
- `create_claim`'s public signature is unchanged. `tests/claim_routes_bind_the_caller.rs` calls it directly as `create_claim(ViewerExtractor(viewer), State(state), Some(Extension(ctx)), Json(req))`.
- `MAX_BATCH_SIZE` stays 100. The per-item content cap stays 65,536 bytes.
- Existing response fields `created`, `failed`, `results[].index`, `results[].claim_id` and `results[].error` keep their names and meanings.
- `cargo check -p epigraph-api --no-default-features --locked` must still compile (CI step "No-db build check").
- Commit messages follow the repo `CLAUDE.md` Evidence / Reasoning / Verification schema.
- Nothing operator-local (hosts, ports, database names, local tooling) in committed files or messages.

## Review Focus

1. **Re-running the same batch without `if_not_exists`:** every item gets a per-item 409, and no duplicate rows land. Pinned by `rerun_without_if_not_exists_is_a_per_item_409` (Task 3).
2. **The same content twice inside one batch with `if_not_exists: true`:** both slots return the same id, the second with `was_created: false`. Pinned by `duplicate_items_in_one_batch_share_an_id` (Task 3).
3. **A failing item in the middle:** the items before and after it still persist. Pinned by `persists_each_valid_item_attributed_to_the_caller`, which checks that rows exist for items 0 and 2 (Task 3).
4. **A legacy client body `{content, truth_value}`:** it keeps working, now attributed to the caller with the caller's key. Pinned by the same test, which asserts `agent_id`, `public_key` and `truth_value` (Task 3).
5. **An agentless token or a token without `claims:write`:** the whole request is refused before any row is written. Pinned by `missing_scope_is_403_and_writes_nothing` and `agentless_token_is_401_and_writes_nothing` (Task 3).

---

## File Structure

| File | Change |
|---|---|
| `crates/epigraph-api/src/routes/claims.rs` | Move the db `create_claim` body into `pub(crate) async fn create_claim_core`; the handler delegates. |
| `crates/epigraph-api/src/routes/batch.rs` | Gate the existing request/item types and handler with `cfg(not(feature = "db"))`. Add the db `BatchClaimRequest`, `batch_item_to_create_request` (with unit tests) and the db `batch_create_claims`. Add `existing`, `was_created` and `status` to the response types. |
| `crates/epigraph-api/tests/batch_claims_persist.rs` (create) | HTTP tests through `spawn_app`. |
| `crates/epigraph-api/tests/batch_publish_test.rs` | Drive the new handler signature. Same two assertions (imports work, no event published). |
| `docs/deploy.md`, `scripts/e2e/README.md`, `CLAUDE.md` | Operator note, remove batch from the "succeeds while writing nothing" list, and add batch to the embed-on-insert write paths. |

---

### Task 1: Extract `create_claim_core` (behaviour-preserving)

**Files:**
- Modify: `crates/epigraph-api/src/routes/claims.rs`, the `#[cfg(feature = "db")] pub async fn create_claim(` item, from its signature through `Ok(Json(response))`.

**Interfaces:**
- Produces: `#[cfg(feature = "db")] pub(crate) async fn create_claim_core(state: &AppState, viewer: &epigraph_db::visibility::Viewer, auth_ctx: Option<&crate::middleware::bearer::AuthContext>, request: CreateClaimRequest) -> Result<ClaimResponse, ApiError>`

- [ ] **Step 1: Record the baseline.** Run the create-claim suites and the two ratchets on the unmodified tree, and save the pass counts in your report:

```
cargo test -p epigraph-api --locked --test post_claims_dedup_409 --test create_claim_tenancy_boundary --test create_claim_label_overwrite --test claim_routes_bind_the_caller --test content_hash_override_verification_test --test embed_on_create_claim -- --test-threads=1
cargo test -p epigraph-db --locked --test no_unscoped_pool --test personal_group_mint_ratchet
```
Expected: all pass. If a target name differs, find it with `cargo metadata --no-deps --format-version 1` and record the real name.

- [ ] **Step 2: Move the body.** Rename the db `create_claim` function to `create_claim_core` with the signature above, marked `pub(crate)` and keeping `#[cfg(feature = "db")]`. Keep its doc comment on the new `create_claim` handler. Apply exactly these edits inside the moved body and nothing else:

| Before | After |
|---|---|
| `if let Some(axum::Extension(ref auth)) = auth_ctx {` (two places: the scope check and the provenance block) | `if let Some(auth) = auth_ctx {` |
| `let caller_agent_id = auth_ctx` / `.as_ref()` / `.and_then(\|axum::Extension(ctx)\| ctx.agent_id.or(Some(ctx.client_id)))` | `let caller_agent_id = auth_ctx` / `.and_then(\|ctx\| ctx.agent_id.or(Some(ctx.client_id)))` |
| `let Some(axum::Extension(ctx)) = &auth_ctx else {` | `let Some(ctx) = auth_ctx else {` |
| `state.begin_claim_write(&viewer, "create_claim")` | `state.begin_claim_write(viewer, "create_claim")` |
| `ClaimRepository::create_or_get(&mut tx, &viewer, &claim, decl)` | `ClaimRepository::create_or_get(&mut tx, viewer, &claim, decl)` |
| `&viewer,` (the argument to `find_by_content_hash_and_agent`) | `viewer,` |
| `Ok(Json(response))` | `Ok(response)` |

Then add the handler directly above `create_claim_core`:

```rust
#[cfg(feature = "db")]
pub async fn create_claim(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    // Still `Option<Extension<..>>` rather than a required extractor: PR-07
    // replaces the whole `Option<AuthContext>` idiom with `ViewerExtractor`
    // across all 39 sites at once. Until then `create_claim_core` rejects
    // `None` explicitly rather than falling open.
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<CreateClaimRequest>,
) -> Result<Json<ClaimResponse>, ApiError> {
    create_claim_core(&state, &viewer, auth_ctx.as_ref().map(|axum::Extension(a)| a), request)
        .await
        .map(Json)
}
```

Give `create_claim_core` a short doc comment of its own: "The body of `POST /api/v1/claims`, shared with `POST /api/v1/claims/batch` (one call per item) so the two cannot drift. Opens and commits its own transaction."

Leave the comments inside the moved body as they are: they explain decisions the body still makes. Do not reorder any statement.

- [ ] **Step 3: Re-run Step 1's commands.**
Expected: identical pass counts, and the ratchets unchanged. `no_unscoped_pool` counts per file, so `routes/claims.rs` is still 18.

- [ ] **Step 4: Run** `cargo check -p epigraph-api --no-default-features --locked`, `cargo fmt --check` and `cargo clippy -p epigraph-api --all-targets --locked -- -D warnings`.
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/epigraph-api/src/routes/claims.rs
git commit   # refactor(api): move create_claim's body into create_claim_core so batch can share it
             # Evidence: issue #477 asks that batch reuse single-claim validation and construction so the two cannot drift
             # Reasoning: a move with seven mechanical edits keeps every decision in one place; the handler signature is unchanged for its direct callers
             # Verification: the create-claim suites and the no_unscoped_pool / personal_group_mint_ratchet lints pass with unchanged counts
```

---

### Task 2: Decode a batch item into a `CreateClaimRequest`

**Files:**
- Modify: `crates/epigraph-api/src/routes/batch.rs`

**Interfaces:**
- Consumes: `crate::routes::claims::CreateClaimRequest` (public fields; not cfg-gated).
- Produces: `pub fn batch_item_to_create_request(item: serde_json::Value, caller_agent_id: uuid::Uuid) -> Result<crate::routes::claims::CreateClaimRequest, String>`, available in both cfg builds.

- [ ] **Step 1: Write the failing unit tests.** Append a new test module to `batch.rs`. It is a separate module from the existing `cfg(all(test, not(feature = "db")))` one, and it is compiled in the db build.

```rust
#[cfg(test)]
mod item_decoding_tests {
    use super::batch_item_to_create_request;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn a_legacy_item_gets_the_callers_agent_and_its_truth_value() {
        let caller = Uuid::new_v4();
        let req = batch_item_to_create_request(json!({"content": "c", "truth_value": 0.6}), caller)
            .expect("legacy shape decodes");
        assert_eq!(req.agent_id, caller);
        assert_eq!(req.initial_truth, Some(0.6));
        assert_eq!(req.content, "c");
        assert!(!req.if_not_exists);
    }

    #[test]
    fn an_explicit_agent_and_every_single_claim_field_pass_through() {
        let caller = Uuid::new_v4();
        let named = Uuid::new_v4();
        let trace = Uuid::new_v4();
        let req = batch_item_to_create_request(
            json!({
                "content": "c", "agent_id": named, "initial_truth": 0.7, "trace_id": trace,
                "properties": {"source_uri": "doi:10.1/x", "page": 3},
                "labels": ["a", "b"], "if_not_exists": true
            }),
            caller,
        )
        .expect("full shape decodes");
        assert_eq!(req.agent_id, named, "an item that names an author keeps it");
        assert_eq!(req.initial_truth, Some(0.7));
        assert_eq!(req.trace_id, Some(trace));
        assert_eq!(req.properties, Some(json!({"source_uri": "doi:10.1/x", "page": 3})));
        assert_eq!(req.labels, vec!["a".to_string(), "b".to_string()]);
        assert!(req.if_not_exists);
    }

    #[test]
    fn both_truth_keys_is_refused() {
        let err = batch_item_to_create_request(
            json!({"content": "c", "truth_value": 0.6, "initial_truth": 0.6}),
            Uuid::new_v4(),
        )
        .err()
        .expect("ambiguous truth is an error");
        assert!(err.contains("truth_value") && err.contains("initial_truth"), "{err}");
    }

    #[test]
    fn a_non_object_item_is_refused() {
        let err = batch_item_to_create_request(json!("just a string"), Uuid::new_v4())
            .err()
            .expect("non-object is an error");
        assert!(err.contains("JSON object"), "{err}");
    }

    #[test]
    fn a_missing_content_is_refused_by_the_shared_request_type() {
        let err = batch_item_to_create_request(json!({"truth_value": 0.5}), Uuid::new_v4())
            .err()
            .expect("content is required by CreateClaimRequest");
        assert!(err.contains("content"), "{err}");
    }

    #[test]
    fn a_malformed_agent_id_is_refused_not_replaced() {
        let caller = Uuid::new_v4();
        let err = batch_item_to_create_request(json!({"content": "c", "agent_id": "nope"}), caller)
            .err()
            .expect("a present-but-invalid agent_id must not fall back to the caller");
        assert!(err.contains("invalid batch item"), "{err}");
    }
}
```

- [ ] **Step 2: Run:** `cargo test -p epigraph-api --locked --lib item_decoding_tests`
Expected: FAIL to compile with `cannot find function batch_item_to_create_request`.

- [ ] **Step 3: Implement.** Add this to `batch.rs` with no cfg attribute, after the response types:

```rust
/// Turn one batch item into the request `POST /api/v1/claims` takes.
///
/// A batch item IS a `CreateClaimRequest` with two conveniences, so a field
/// added to that type later reaches batch with no change here:
///
/// * `agent_id` defaults to the caller's own agent when the item omits it.
///   An item that names one keeps it, with exactly the single route's
///   semantics (recorded as the author; the key and the owning group still
///   come from the token).
/// * `truth_value`, this route's original key, is accepted as
///   `initial_truth`. Giving both is refused rather than guessed.
///
/// # Errors
/// A human-readable reason, reported in the item's result slot.
pub fn batch_item_to_create_request(
    mut item: serde_json::Value,
    caller_agent_id: uuid::Uuid,
) -> Result<crate::routes::claims::CreateClaimRequest, String> {
    let obj = item
        .as_object_mut()
        .ok_or_else(|| "each batch item must be a JSON object".to_string())?;
    if let Some(truth) = obj.remove("truth_value") {
        if obj.contains_key("initial_truth") {
            return Err("give either truth_value or initial_truth, not both".to_string());
        }
        obj.insert("initial_truth".to_string(), truth);
    }
    obj.entry("agent_id")
        .or_insert_with(|| serde_json::Value::String(caller_agent_id.to_string()));
    serde_json::from_value(item).map_err(|e| format!("invalid batch item: {e}"))
}
```

`CreateClaimRequest` derives only `Deserialize`. The tests read its public fields directly, so they need no other derive. If a field's type differs from what a test assumes (for example `initial_truth: Option<f64>`), fix the test's expectation to the real type, never the decode logic.

- [ ] **Step 4: Run** Step 2's command, then `cargo check -p epigraph-api --no-default-features --locked`.
Expected: 6 passed, and the no-db check compiles.

- [ ] **Step 5: Commit** `feat(api): decode a batch item as a CreateClaimRequest with caller and truth_value defaults`, with Evidence (#477: the 2-field `BatchClaimItem` vs the 13-field `CreateClaimRequest`), Reasoning (decoding to the shared type stops drift and makes malformed items per-item errors) and Verification (6 unit tests).

---

### Task 3: Persist batch items through `create_claim_core`

**Files:**
- Modify: `crates/epigraph-api/src/routes/batch.rs`
- Create: `crates/epigraph-api/tests/batch_claims_persist.rs`
- Modify: `crates/epigraph-api/tests/batch_publish_test.rs`

**Interfaces:**
- Consumes: `create_claim_core` (Task 1) and `batch_item_to_create_request` (Task 2).
- Produces (db build):
  - `pub struct BatchClaimRequest { pub claims: Vec<serde_json::Value> }`
  - `pub async fn batch_create_claims(ViewerExtractor, State<AppState>, Option<Extension<AuthContext>>, Json<BatchClaimRequest>) -> Result<Json<BatchClaimResponse>, ApiError>`
- Produces (both builds):
  - `BatchClaimResponse { created, existing, failed, results }`
  - `BatchClaimResult { index, claim_id, was_created, status, error }`

- [ ] **Step 1: Write the failing HTTP tests.** Create `crates/epigraph-api/tests/batch_claims_persist.rs`:

```rust
#![cfg(feature = "db")]
//! `POST /api/v1/claims/batch` persists each item through the single-claim
//! create path (issue #477): rows exist, the caller is the default author,
//! `if_not_exists` makes a re-run idempotent, and a failing item is reported
//! in its own slot without affecting the others.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

mod common;

struct Fixture {
    pool: PgPool,
    url: String,
    token: String,
    agent: Uuid,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn fixture(scopes: &[&str]) -> Fixture {
    let db = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new().max_connections(2).connect(&db).await.unwrap();
    let agent = common::seed_system_agent(&pool).await;
    let (addr, shutdown) = common::spawn_app(&db).await;
    let (token, _) =
        common::test_bearer_token_with_seeded_client_for_agent(&pool, scopes, agent).await;
    Fixture { pool, url: format!("http://{addr}/api/v1/claims/batch"), token, agent, _shutdown: shutdown }
}

async fn post(f: &Fixture, body: serde_json::Value) -> (u16, serde_json::Value) {
    let r = reqwest::Client::new().post(&f.url).bearer_auth(&f.token).json(&body).send().await.unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or(serde_json::Value::Null))
}

fn uniq(tag: &str) -> String {
    format!("batch477 {tag} {}", Uuid::new_v4())
}

fn id_at(body: &serde_json::Value, i: usize) -> Option<String> {
    body["results"][i]["claim_id"].as_str().map(str::to_string)
}

async fn count_content(pool: &PgPool, content: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM claims WHERE content = $1")
        .bind(content).fetch_one(pool).await.unwrap()
}

/// The seeded agent's public key, as `common::seed_system_agent` derives it.
fn seeded_key(agent: Uuid) -> Vec<u8> {
    agent.as_bytes().iter().copied().cycle().take(32).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn persists_each_valid_item_attributed_to_the_caller() {
    let f = fixture(&["claims:write"]).await;
    let (a, b) = (uniq("a"), uniq("b"));
    let (status, body) = post(&f, serde_json::json!({"claims": [
        {"content": a, "truth_value": 0.6},
        {"content": "", "truth_value": 0.5},
        {"content": b, "truth_value": 0.8}
    ]})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["created"], 2, "{body}");
    assert_eq!(body["failed"], 1, "{body}");
    assert_eq!(body["results"][1]["status"], 400, "{body}");
    assert!(body["results"][1]["claim_id"].is_null(), "{body}");

    for (i, truth) in [(0usize, 0.6f64), (2, 0.8)] {
        let id: Uuid = id_at(&body, i).expect("id").parse().unwrap();
        let (agent_id, key, tv): (Uuid, Vec<u8>, f64) = sqlx::query_as(
            "SELECT agent_id, public_key, truth_value FROM claims WHERE id = $1",
        )
        .bind(id).fetch_one(&f.pool).await
        .unwrap_or_else(|e| panic!("item {i} must be a real claims row: {e}"));
        assert_eq!(agent_id, f.agent, "item {i}: the caller is the default author");
        assert_eq!(key, seeded_key(f.agent), "item {i}: the key is the caller's, never zero");
        assert!((tv - truth).abs() < 1e-9, "item {i}: truth_value carried");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn carries_properties_labels_and_an_explicit_author() {
    let f = fixture(&["claims:write"]).await;
    let c = uniq("props");
    let (status, body) = post(&f, serde_json::json!({"claims": [{
        "content": c, "agent_id": f.agent, "initial_truth": 0.7,
        "properties": {"source_uri": "doi:10.1/x", "page": 3}, "labels": ["batch477"]
    }]})).await;
    assert_eq!(status, 200, "{body}");
    let id: Uuid = id_at(&body, 0).expect("id").parse().unwrap();
    let (props, labels): (Option<serde_json::Value>, Vec<String>) =
        sqlx::query_as("SELECT properties, labels FROM claims WHERE id = $1")
            .bind(id).fetch_one(&f.pool).await.unwrap();
    assert_eq!(props, Some(serde_json::json!({"source_uri": "doi:10.1/x", "page": 3})));
    assert_eq!(labels, vec!["batch477".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn rerun_with_if_not_exists_returns_the_same_ids() {
    let f = fixture(&["claims:write"]).await;
    let (a, b) = (uniq("idem-a"), uniq("idem-b"));
    let batch = serde_json::json!({"claims": [
        {"content": a, "if_not_exists": true}, {"content": b, "if_not_exists": true}
    ]});
    let (_, first) = post(&f, batch.clone()).await;
    let (status, second) = post(&f, batch).await;
    assert_eq!(status, 200, "{second}");
    assert_eq!(second["created"], 0, "{second}");
    assert_eq!(second["existing"], 2, "{second}");
    assert_eq!(second["failed"], 0, "{second}");
    for i in 0..2 {
        assert_eq!(id_at(&first, i), id_at(&second, i), "slot {i} returns the existing id");
        assert_eq!(second["results"][i]["was_created"], false);
    }
    assert_eq!(count_content(&f.pool, &a).await, 1);
    assert_eq!(count_content(&f.pool, &b).await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn rerun_without_if_not_exists_is_a_per_item_409() {
    let f = fixture(&["claims:write"]).await;
    let a = uniq("dup");
    let batch = serde_json::json!({"claims": [{"content": a}]});
    let (_, first) = post(&f, batch.clone()).await;
    assert_eq!(first["created"], 1, "{first}");
    let (status, second) = post(&f, batch).await;
    assert_eq!(status, 200, "{second}");
    assert_eq!(second["failed"], 1, "{second}");
    assert_eq!(second["results"][0]["status"], 409, "{second}");
    assert_eq!(count_content(&f.pool, &a).await, 1, "no duplicate row landed");
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_items_in_one_batch_share_an_id() {
    let f = fixture(&["claims:write"]).await;
    let a = uniq("twice");
    let (status, body) = post(&f, serde_json::json!({"claims": [
        {"content": a, "if_not_exists": true}, {"content": a, "if_not_exists": true}
    ]})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(id_at(&body, 0), id_at(&body, 1), "{body}");
    assert_eq!(body["results"][0]["was_created"], true);
    assert_eq!(body["results"][1]["was_created"], false);
    assert_eq!(count_content(&f.pool, &a).await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_and_oversized_items_fail_alone() {
    let f = fixture(&["claims:write"]).await;
    let ok = uniq("survivor");
    let (status, body) = post(&f, serde_json::json!({"claims": [
        "not an object",
        {"content": "x", "truth_value": 0.5, "initial_truth": 0.5},
        {"content": "y".repeat(65_537)},
        {"content": ok}
    ]})).await;
    assert_eq!(status, 200, "{body}");
    for i in 0..3 {
        assert_eq!(body["results"][i]["status"], 400, "slot {i}: {body}");
    }
    assert_eq!(body["created"], 1, "{body}");
    assert_eq!(count_content(&f.pool, &ok).await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_scope_is_403_and_writes_nothing() {
    let f = fixture(&["claims:read"]).await;
    let a = uniq("noscope");
    let (status, body) = post(&f, serde_json::json!({"claims": [{"content": a}]})).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(count_content(&f.pool, &a).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn agentless_token_is_401_and_writes_nothing() {
    let f = fixture(&["claims:write"]).await;
    let secret = std::env::var("EPIGRAPH_JWT_SECRET")
        .unwrap_or_else(|_| "epigraph-dev-secret-change-in-production!!".to_string());
    let cfg = epigraph_api::oauth::JwtConfig::from_secret(secret.as_bytes());
    let (agentless, _) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:write".to_string()],
            "service",
            None,
            None,
            chrono::Duration::minutes(10),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("mint");
    let a = uniq("agentless");
    let r = reqwest::Client::new()
        .post(&f.url)
        .bearer_auth(&agentless)
        .json(&serde_json::json!({"claims": [{"content": a}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    assert_eq!(count_content(&f.pool, &a).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn over_max_batch_size_is_400() {
    let f = fixture(&["claims:write"]).await;
    let items: Vec<_> = (0..101).map(|i| serde_json::json!({"content": format!("{} {i}", uniq("big"))})).collect();
    let (status, body) = post(&f, serde_json::json!({"claims": items})).await;
    assert_eq!(status, 400, "{body}");
}
```

If a column type differs from the tuple a test reads (for example `truth_value` stored as `real`), change the tuple's Rust type to match the column, never the assertion.

- [ ] **Step 2: Run:** `cargo test -p epigraph-api --locked --test batch_claims_persist -- --test-threads=1`
Expected: FAIL. Every test either sees ids that name no row (today's handler writes only the in-memory store) or misses the `existing`, `status` and `was_created` fields.

- [ ] **Step 3: Gate the in-memory path on not(db).** In `batch.rs`, add `#[cfg(not(feature = "db"))]` to the existing `BatchClaimRequest`, `BatchClaimItem`, `batch_create_claims` and `validate_batch_item` items, and to what only they use in a db build. Otherwise `clippy -D warnings` fails on dead code in the db build:
  - `const DEFAULT_TRUTH_VALUE`;
  - `use epigraph_core::{AgentId, Claim, TruthValue};`.

  `MAX_BATCH_SIZE` and `MAX_CLAIM_CONTENT_LENGTH` stay un-gated, because both handlers use them. Before gating, confirm nothing else uses these items in a db build: `git grep -n -E 'BatchClaimItem|validate_batch_item|routes::batch::' -- crates`. The only expected hits are `batch.rs` itself, `routes/mod.rs` (route registration), `routes/negative_tests.rs` (a not(db) test module) and `tests/batch_publish_test.rs` (rewritten in Step 6). Leave their bodies and the existing not(db) test module untouched, except for the struct-literal updates in Step 4.

- [ ] **Step 4: Extend the response types (both builds):**

```rust
/// Response for a batch claim creation request
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchClaimResponse {
    /// Number of items that inserted a new claim
    pub created: usize,
    /// Number of `if_not_exists` items that matched an existing claim
    #[serde(default)]
    pub existing: usize,
    /// Number of items that failed
    pub failed: usize,
    /// Per-item results in the same order as the request
    pub results: Vec<BatchClaimResult>,
}

/// Result for a single item in a batch
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchClaimResult {
    /// Index of this item in the original request array
    pub index: usize,
    /// The claim id, when the item succeeded
    pub claim_id: Option<Uuid>,
    /// Whether this item inserted a row (false on an `if_not_exists` match)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub was_created: Option<bool>,
    /// The HTTP status the single-claim route would have answered, when the item failed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Error message, when the item failed
    pub error: Option<String>,
}
```

`claim_id` and `error` keep today's plain `Option` fields (always serialized, `null` when absent), so existing clients see no change. In the not(db) handler, add `existing: 0` to the response literal, and `was_created: Some(true), status: None` or `was_created: None, status: Some(400)` to each result literal.

- [ ] **Step 5: Add the db request type and handler:**

```rust
/// Request body for `POST /api/v1/claims/batch` (db build). Each item is
/// decoded by [`batch_item_to_create_request`], so it takes every field
/// `POST /api/v1/claims` takes.
#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct BatchClaimRequest {
    pub claims: Vec<serde_json::Value>,
}

/// Create up to [`MAX_BATCH_SIZE`] claims, each through the exact path
/// `POST /api/v1/claims` takes (`create_claim_core`), on its own transaction.
///
/// * An item that omits `agent_id` is authored by the caller.
/// * `if_not_exists: true` makes a re-run return the existing ids
///   (`was_created: false`, counted in `existing`).
/// * A failing item reports the single route's status and message in its
///   slot; the other items are unaffected.
/// * No event is published, the same as `POST /api/v1/claims`.
///
/// # Errors
/// Whole-request: 401 with no authenticated agent, 403 without
/// `claims:write`, 400 above [`MAX_BATCH_SIZE`] items.
#[cfg(feature = "db")]
pub async fn batch_create_claims(
    crate::middleware::bearer::ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<axum::Extension<crate::middleware::bearer::AuthContext>>,
    Json(request): Json<BatchClaimRequest>,
) -> Result<Json<BatchClaimResponse>, ApiError> {
    use axum::response::IntoResponse;

    let Some(axum::Extension(auth)) = auth_ctx.as_ref() else {
        return Err(ApiError::Unauthorized {
            reason: "authentication required to create claims".to_string(),
        });
    };
    crate::middleware::scopes::check_scopes(auth, &["claims:write"])?;
    let Some(caller_agent_id) = auth.agent_id else {
        return Err(ApiError::Unauthorized {
            reason: "token carries no agent_id; re-authenticate to obtain a token bound to a principal"
                .to_string(),
        });
    };
    if request.claims.len() > MAX_BATCH_SIZE {
        return Err(ApiError::BadRequest {
            message: format!(
                "Batch size {} exceeds maximum of {}",
                request.claims.len(),
                MAX_BATCH_SIZE
            ),
        });
    }

    let (mut created, mut existing, mut failed) = (0usize, 0usize, 0usize);
    let mut results = Vec::with_capacity(request.claims.len());
    for (index, item) in request.claims.into_iter().enumerate() {
        let outcome = match batch_item_to_create_request(item, caller_agent_id) {
            Err(reason) => Err(ApiError::ValidationError {
                field: format!("claims[{index}]"),
                reason,
            }),
            Ok(req) if req.content.len() > MAX_CLAIM_CONTENT_LENGTH => Err(ApiError::ValidationError {
                field: format!("claims[{index}].content"),
                reason: format!(
                    "Content too long: {} bytes, maximum is {} bytes",
                    req.content.len(),
                    MAX_CLAIM_CONTENT_LENGTH
                ),
            }),
            Ok(req) => {
                crate::routes::claims::create_claim_core(&state, &viewer, Some(auth), req).await
            }
        };
        match outcome {
            Ok(resp) => {
                if resp.was_created {
                    created += 1;
                } else {
                    existing += 1;
                }
                results.push(BatchClaimResult {
                    index,
                    claim_id: Some(resp.id),
                    was_created: Some(resp.was_created),
                    status: None,
                    error: None,
                });
            }
            Err(e) => {
                failed += 1;
                let message = e.to_string();
                let status = e.into_response().status().as_u16();
                results.push(BatchClaimResult {
                    index,
                    claim_id: None,
                    was_created: None,
                    status: Some(status),
                    error: Some(message),
                });
            }
        }
    }
    Ok(Json(BatchClaimResponse { created, existing, failed, results }))
}
```

The over-size error is the not(db) handler's existing `ApiError::BadRequest` with the same message, so both builds answer alike. Check `MAX_CLAIM_CONTENT_LENGTH` is reachable from the db item: it is a module-level `const` today, so it must stay un-gated. Write `validate_batch_item`'s length check the same way so the two can't diverge.

The route registration in `routes/mod.rs` (`.route("/api/v1/claims/batch", post(batch::batch_create_claims))`, in both variants) needs no change.

- [ ] **Step 6: Rewrite `tests/batch_publish_test.rs` for the new signature.** Keep the module doc's two-assertion argument, but update its first section: the handler now persists claims, and the property is that it announces none, the same as `POST /api/v1/claims`. Replace the handler call with:

```rust
let agent = seed_agent(&pool).await; // same INSERT as tests/common's seed_system_agent
let viewer = epigraph_db::visibility::Viewer::resolve(&pool, agent).await.expect("viewer");
let auth = epigraph_api::middleware::bearer::AuthContext {
    client_id: uuid::Uuid::new_v4(),
    agent_id: Some(agent),
    owner_id: Some(agent),
    client_type: epigraph_api::middleware::ClientType::Agent,
    scopes: vec!["claims:write".to_string()],
    jti: uuid::Uuid::new_v4(),
    family_id: None,
    elevation_claim: None,
    elevation: None,
    admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
};
let response = epigraph_api::routes::batch::batch_create_claims(
    epigraph_api::middleware::bearer::ViewerExtractor(viewer),
    State(state.clone()),
    Some(axum::Extension(auth)),
    Json(request),
)
.await
.expect("a batch with one invalid item is a partial success, not an error");
```

Make the test's content strings unique per run (append a `Uuid`), because the import now writes real rows. Keep `assert_eq!(response.0.created, 2)`, `failed == 1`, the two-ids check, and `history_size() == 0`. Add: both returned ids name rows in `claims`. Keep `the_event_bus_history_counts_what_is_published` unchanged. Add `mod common;` only if you use its seed helper; otherwise inline the agent INSERT (`INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')`).

- [ ] **Step 7: Run:**

```
cargo test -p epigraph-api --locked --test batch_claims_persist --test batch_publish_test -- --test-threads=1
cargo test -p epigraph-api --locked --lib item_decoding_tests
cargo test -p epigraph-db --locked --test no_unscoped_pool --test personal_group_mint_ratchet
cargo test -p epigraph-api --locked --test public_router_allowlist --test viewer_route_table_lint --test no_bypass_in_handlers --test handler_audit_tests -- --test-threads=1
cargo check -p epigraph-api --no-default-features --locked
```
Expected: 9 + 2 + 6 tests pass, the ratchets are unchanged, the route lints pass, and the no-db check compiles.

- [ ] **Step 8: Mutation checks.** Stage the change with `git add`, mutate, run, then restore with `git checkout -- <path>` and `touch` the file.
  1. In the db `batch_create_claims`, replace the `create_claim_core` call with `Err(ApiError::InternalError { message: "x".into() })`.
     Expected: every `batch_claims_persist` test except the 401, 403 and 400 ones FAILS.
  2. In `batch_item_to_create_request`, delete the `or_insert_with(...)` line.
     Expected: `persists_each_valid_item_attributed_to_the_caller` FAILS with a missing-field error, and the unit test `a_legacy_item_gets_the_callers_agent_and_its_truth_value` fails.
  3. In the db handler, change `existing += 1` to `created += 1`.
     Expected: `rerun_with_if_not_exists_returns_the_same_ids` FAILS.

  Record each run's failing-test lines in your report.

- [ ] **Step 9: Commit** `feat(api): persist POST /api/v1/claims/batch items through the single-claim create path`, with:
  - Evidence: #477, and the issue comment that ids named no row;
  - Reasoning: one write path, per-item transactions, caller as the default author, `existing`/`status`/`was_created` fields;
  - Verification: the tests and mutations above.

---

### Task 4: Update the docs that describe the old behaviour

**Files:**
- Modify: `docs/deploy.md`, the section after `### 1d.`. Add a new section with the next free number/letter in that list.
- Modify: `scripts/e2e/README.md`, under item 6 ("Known shapes that meet the R3 gate's 'succeeds while writing nothing' definition"). Delete the `POST /api/v1/claims/batch` bullet.
- Modify: `CLAUDE.md`, the "Write paths (must embed on insert)" list. After the `HTTP POST /api/v1/claims` bullet, add: `- **HTTP \`POST /api/v1/claims/batch\`** — delegates each item to \`create_claim_core\` in \`crates/epigraph-api/src/routes/claims.rs\``

- [ ] **Step 1: Write the deploy note** (operator-facing; no hosts or paths):

```markdown
### <next>. `POST /api/v1/claims/batch` now persists its claims

Each item goes through the same code as `POST /api/v1/claims`, on its own
transaction. Before this change the route returned ids that named no row.

- An item may carry any `POST /api/v1/claims` field. An item without
  `agent_id` is authored by the caller. `truth_value` is still accepted as
  `initial_truth`, but giving both is refused.
- `if_not_exists: true` makes re-running a batch safe: matched items return
  the existing id with `was_created: false` and are counted in the new
  `existing` field.
- Each failed item's result carries `status` (the code the single route would
  return, e.g. 400 or 409) next to `error`.
- The request now needs an authenticated agent with `claims:write`, the same
  as the single route.
- Still no `ClaimSubmitted` event, the same as `POST /api/v1/claims`.

Clients that relied on the old behaviour see real rows, and the response ids
now name them.
```

- [ ] **Step 2: Check that no doc still describes the old behaviour:**
`git grep -n -i "claims/batch" -- docs scripts '*.md'`
Every remaining hit must describe the new behaviour or be explicitly historical, such as the dated `docs/tenancy/progress.json` entries, which stay as they are.

- [ ] **Step 3: Commit** `docs(api): describe the persisting batch route and list it as an embedding write path`.

---

## Related backlog

An exhaustive sweep of the EpiGraph `backlog` label found **no backlog claim about the REST batch route**. That covered 986 claims, current and retired. It searched for the route path, the handler and type names, `claim_store`, the synthetic agent, and the issue number. The route's defects are tracked only in this repository and on GitHub:

- **GitHub:** issue #477, and its follow-up comment that the route persists nothing.
- **Repo tracking:**
  - `docs/tenancy/progress.json` finding `F-PR10-unknown-claim-id-delivers`: the publish half is closed; "make it persist" is deferred, and this plan does it.
  - `docs/deploy.md` §1d: the publish removal.
  - `scripts/e2e/README.md` item 6: batch is listed as a "succeeds while writing nothing" shape. Task 4 removes it.

Adjacent EpiGraph backlog, about the MCP tool `batch_submit_claims` rather than the REST route:

| Claim | State | Relation to this plan |
|---|---|---|
| `73657204` — `batch_submit_claims` lacks `submit_claim`'s fields (G15) | open, not labelled resolved | Fixed by PR #513 (merged 2026-09-26, "batch_submit_claims parity (Batch G-b)"). The backlog item was never retired; retire it with `resolve_backlog_item`, citing #513. |
| `f6c1a668` — after G15 deploys, update stored workflows that say "submit in parallel with submit_claim" | open, `blocked-on:73657204` | Unblocked once #513 is in production. Independent of this plan. |
| `32c62901`, `daf7db58` — `batch_submit_claims` "unknown methodology" | resolved | None. |

Retire or file EpiGraph backlog items only with the operator's go-ahead, and retire items this plan closes only after its PR merges.
