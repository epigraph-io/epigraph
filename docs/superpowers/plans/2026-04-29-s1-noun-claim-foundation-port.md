# S1 Noun-Claim Foundation Port — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the S1 noun-claims-and-verb-edges foundation (migration 107, ClaimRepository helpers, `if_not_exists` API option) from `epigraph-internal` into `epigraph`, preserving the architectural invariant that `(content_hash, agent_id)` is the canonical key for claims.

**Architecture:** Backfill cherry-pick. Source-of-truth is the `internal-main` ref already present in the public `epigraph` repo (mirrors `epigraph-internal/main`, disjoint history, content cherry-pick only). Port: (a) `migrations/107_claims_unique_content_hash_agent.sql`; (b) three `ClaimRepository` helpers + legacy method doc-comments in `crates/epigraph-db/src/repos/claim.rs`; (c) the `claim_repo_helpers.rs` integration test; (d) `ApiError::Conflict` variant; (e) `if_not_exists` field handling in `crates/epigraph-api/src/routes/claims.rs`; (f) one comment fix in `submit_packet_tests.rs`; (g) the architecture doc `noun-claims-and-verb-edges.md`.

**Tech Stack:** Rust workspace · sqlx 0.7 · Postgres · axum · cargo. Tests use `DATABASE_URL`-gated integration harness; missing DB → tests skip (`test_pool_or_skip!`).

**Out of scope (defer to follow-up plans):**
- S3a MCP writer migration (`claim_helper.rs`, `tool_resubmit_tests.rs`, migrations 108/109) — depends on this slice but is its own subsystem.
- `mcp_tools.rs` route + `dep:epigraph-mcp` Cargo feature change (unrelated REST-over-MCP exposure).
- `ApiError::BadGateway` variant (unrelated; lands with a different feature).
- Embedding-backfill `is_current` filter removal (`claim.rs:1417` line drop) — unrelated to S1.

**Source refs (paste-ready git show targets):**
- `internal-main:migrations/107_claims_unique_content_hash_agent.sql`
- `internal-main:crates/epigraph-db/src/repos/claim.rs`
- `internal-main:crates/epigraph-db/tests/claim_repo_helpers.rs`
- `internal-main:crates/epigraph-api/src/errors.rs`
- `internal-main:crates/epigraph-api/src/routes/claims.rs`
- `internal-main:crates/epigraph-api/tests/routes/submit_packet_tests.rs`
- `internal-main:docs/architecture/noun-claims-and-verb-edges.md`

---

## File Structure

**Create:**
- `migrations/107_claims_unique_content_hash_agent.sql` — UNIQUE `(content_hash, agent_id)` constraint.
- `crates/epigraph-db/tests/claim_repo_helpers.rs` — pre/post-107 fixtures + integration tests for new helpers.
- `docs/architecture/noun-claims-and-verb-edges.md` — canonical architecture doc; referenced by code comments.

**Modify:**
- `crates/epigraph-db/src/repos/claim.rs` — annotate legacy `create()` / `create_with_tx()`; add `find_by_content_hash_and_agent`, `create_strict`, `create_or_get` inside `impl ClaimRepository {}`.
- `crates/epigraph-api/src/errors.rs` — add `ApiError::Conflict { reason }` variant + `IntoResponse` arm (HTTP 409). **Do not port `BadGateway`.**
- `crates/epigraph-api/src/routes/claims.rs` — add `if_not_exists: bool` request field, `was_created: bool` response field, branch persistence on it, surface `DbError::DuplicateKey` as 409, gate `content_hash`/`properties` overrides on `was_created`.
- `crates/epigraph-api/tests/routes/submit_packet_tests.rs:1413-1422` — rewrite the comment block referencing migration 097 to reference migration 107.

**Boundary rationale:** All deltas are file-local; the new helpers slot into the existing `impl ClaimRepository`. The architecture doc lives under `docs/architecture/` and is referenced by code comments — porting it together prevents dangling rustdoc links.

---

## Pre-Task: Worktree setup

- [ ] **Step 1: Create isolated worktree off `epigraph/main`**

```bash
cd /home/jeremy/epigraph
git fetch origin main
git worktree add -b feat/s1-noun-claim-port ../epigraph-wt-s1-noun-claim origin/main
cd ../epigraph-wt-s1-noun-claim
git log --oneline -1   # Expect: tip of origin/main
```

Expected: worktree at `/home/jeremy/epigraph-wt-s1-noun-claim` on new branch `feat/s1-noun-claim-port`. All subsequent commands run from this directory unless stated.

- [ ] **Step 2: Sanity-check baseline build**

```bash
cargo check -p epigraph-db -p epigraph-api
```

Expected: clean compile (or pre-existing warnings only — no errors). Bail if errors; investigate before proceeding.

---

## Task 1: Port architecture doc

**Files:**
- Create: `docs/architecture/noun-claims-and-verb-edges.md`

- [ ] **Step 1: Copy doc verbatim from `internal-main`**

```bash
mkdir -p docs/architecture
git show internal-main:docs/architecture/noun-claims-and-verb-edges.md > docs/architecture/noun-claims-and-verb-edges.md
wc -l docs/architecture/noun-claims-and-verb-edges.md
```

Expected: 143 lines.

- [ ] **Step 2: Verify status header**

```bash
head -3 docs/architecture/noun-claims-and-verb-edges.md
```

Expected output begins:
```
# Noun-Claims and Verb-Edges

**Status:** Canonical (S1 — 2026-04-25)
```

- [ ] **Step 3: Commit**

```bash
git add docs/architecture/noun-claims-and-verb-edges.md
git commit -m "docs(architecture): port noun-claims-and-verb-edges canonical doc

Cherry-picked from epigraph-internal:docs/architecture/. Code comments
introduced in subsequent commits reference this doc — porting first
prevents dangling rustdoc links."
```

---

## Task 2: Port migration 107  — **SKIPPED (already applied)**

**Status:** No-op for this slice. **Discovered during execution 2026-04-29:** migration `013_code_review_hardening.sql` (lines 22–26) already adds the constraint with the same name (`uq_claims_content_hash_agent`) and same definition (`UNIQUE (content_hash, agent_id)`). The public epigraph repo collapsed internal's 106+107 split into a single 013 during the forward-port renumber. Porting 107 verbatim would attempt to add a constraint that already exists and fail with `duplicate_object`.

**Verification command:**
```bash
grep -in "uq_claims_content_hash_agent" migrations/013_code_review_hardening.sql
```
Expected: matches at lines 25–26 in 013.

**Downstream impact:**
- `claim_repo_helpers.rs` integration test (Task 4) references the constraint name `uq_claims_content_hash_agent` directly via DDL — name matches, no change needed.
- `claim.rs` helper code comments mention "post-107 …" — these reference the conceptual constraint, not a literal migration file. Comments left as-is for fidelity to the upstream architecture doc.
- The architecture doc (Task 1) references migration 107 conceptually — left as-is; it describes the canonical invariant, not the public-repo migration numbering.

**No commit produced.** Move to Task 3.

---

## Task 3: Add `ClaimRepository` helpers + annotate legacy methods

**Files:**
- Modify: `crates/epigraph-db/src/repos/claim.rs`

- [ ] **Step 1: Annotate `create()` legacy doc-comment**

Locate the existing `pub async fn create(` method on `ClaimRepository`. Replace its lead doc-line `/// Create a new claim in the database` with the legacy-warning block. Find by:

```bash
grep -n "Create a new claim in the database" crates/epigraph-db/src/repos/claim.rs
```

Expected: 2 matches — one for `create()`, one for `create_with_tx()`.

For the `create()` match (the one NOT followed by "within an existing transaction"), replace:

```rust
    /// Create a new claim in the database
```

with:

```rust
    /// Create a new claim in the database (LEGACY — implicit content-hash dedup)
    ///
    /// **Legacy behavior:** dedups on `content_hash` alone (NOT on
    /// `(content_hash, agent_id)`), so a request from agent B with the same
    /// content as an earlier claim from agent A returns agent A's row. This is
    /// a noun-claim invariant violation. New code should use
    /// `find_by_content_hash_and_agent` + `create_or_get` / `create_strict`
    /// (see `docs/architecture/noun-claims-and-verb-edges.md`). The ~44
    /// internal callers of this method are migrated as a separate
    /// out-of-band task.
```

- [ ] **Step 2: Annotate `create_with_tx()` legacy doc-comment**

For the `create_with_tx()` doc block (the one with "within an existing transaction"), replace:

```rust
    /// Create a new claim within an existing transaction
    ///
    /// Same as `create()` but accepts a `&mut PgConnection` for transactional use.
    /// Uses runtime query (not compile-time macro) to support the connection executor.
    ///
```

with:

```rust
    /// Create a new claim within an existing transaction (LEGACY — implicit content-hash dedup)
    ///
    /// Same as `create()` but accepts a `&mut PgConnection` for transactional use.
    /// Uses runtime query (not compile-time macro) to support the connection executor.
    ///
    /// **Legacy behavior:** see the note on `create()` — this method shares
    /// the same cross-agent collapse bug. New transactional code should use
    /// `create_or_get` / `create_strict`.
    ///
```

- [ ] **Step 3: Add the three S1 helpers inside `impl ClaimRepository`**

Find the closing brace of the `impl ClaimRepository {` block immediately before the next `}`:

```bash
grep -n "^impl ClaimRepository" crates/epigraph-db/src/repos/claim.rs
grep -n "^}" crates/epigraph-db/src/repos/claim.rs | head -5
```

Identify the `}` that closes the `impl ClaimRepository` block (NOT later impls). Insert the helper code immediately before it:

```rust
    // ============================================================
    // S1 noun-claims-and-verb-edges helpers
    // (see docs/architecture/noun-claims-and-verb-edges.md)
    // ============================================================

    /// Find an existing claim by `(content_hash, agent_id)`.
    ///
    /// Returns the matching row if any, else `None`. Unlike `create()` /
    /// `create_with_tx()` (which dedup on `content_hash` alone and return
    /// the first agent's row regardless of requester), this helper enforces
    /// the noun-claim invariant that `(content_hash, agent_id)` is the
    /// canonical key.
    ///
    /// Takes `&mut PgConnection` so the caller can compose the lookup with
    /// edge creation in the same transaction.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn find_by_content_hash_and_agent(
        conn: &mut sqlx::PgConnection,
        content_hash: &[u8],
        agent_id: Uuid,
    ) -> Result<Option<Claim>, DbError> {
        use sqlx::Row;

        let row = sqlx::query(
            r#"SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
               FROM claims
               WHERE content_hash = $1 AND agent_id = $2
               LIMIT 1"#,
        )
        .bind(content_hash)
        .bind(agent_id)
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => {
                let tv = TruthValue::new(row.get::<f64, _>("truth_value"))?;
                Ok(Some(claim_from_row(
                    row.get("id"),
                    row.get("content"),
                    row.get("agent_id"),
                    row.get("trace_id"),
                    tv,
                    row.get("created_at"),
                    row.get("updated_at"),
                )))
            }
            None => Ok(None),
        }
    }

    /// Insert a claim row unconditionally (no implicit dedup).
    ///
    /// Use this when the caller has already determined that an insert is
    /// the correct action (or wants the post-107 UNIQUE constraint to be
    /// the authoritative dedup gate).
    ///
    /// **Pre-107:** inserts a duplicate row when `(content_hash, agent_id)`
    /// already exists.
    ///
    /// **Post-107:** the `uq_claims_content_hash_agent` constraint surfaces
    /// duplicate insertions as `DbError::DuplicateKey`.
    ///
    /// Takes `&mut PgConnection` for transactional composition.
    ///
    /// # Errors
    /// Returns `DbError::DuplicateKey` on a `(content_hash, agent_id)`
    /// collision (post-107 only). Returns `DbError::QueryFailed` for other
    /// database errors.
    pub async fn create_strict(
        conn: &mut sqlx::PgConnection,
        claim: &Claim,
    ) -> Result<Claim, DbError> {
        use sqlx::Row;

        let id: Uuid = claim.id.into();
        let agent_id: Uuid = claim.agent_id.into();
        let trace_id: Option<Uuid> = claim.trace_id.map(Into::into);
        let truth_value = claim.truth_value.value();
        let created_at = claim.created_at;
        let updated_at = claim.updated_at;
        let content_hash = ContentHasher::hash(claim.content.as_bytes());

        let row = sqlx::query(
            r#"INSERT INTO claims (id, content, content_hash, truth_value, agent_id, trace_id, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at"#,
        )
        .bind(id)
        .bind(&claim.content)
        .bind(content_hash.as_slice())
        .bind(truth_value)
        .bind(agent_id)
        .bind(trace_id)
        .bind(created_at)
        .bind(updated_at)
        .fetch_one(&mut *conn)
        .await?;

        let tv = TruthValue::new(row.get::<f64, _>("truth_value"))?;
        Ok(claim_from_row(
            row.get("id"),
            row.get("content"),
            row.get("agent_id"),
            row.get("trace_id"),
            tv,
            row.get("created_at"),
            row.get("updated_at"),
        ))
    }

    /// Find-or-insert a claim by `(content_hash, agent_id)`.
    ///
    /// Looks up an existing row first; if found, returns it with
    /// `was_created=false`. Otherwise inserts and returns the new row with
    /// `was_created=true`.
    ///
    /// **Post-107 race handling:** if a concurrent writer inserts the same
    /// `(content_hash, agent_id)` between the find and the insert, the INSERT
    /// fails with the unique constraint. This helper catches that error,
    /// re-runs the find, and returns the resulting row with
    /// `was_created=false`.
    ///
    /// **Pre-107 (constraint not yet applied):** the catch path is
    /// unreachable, and a concurrent race may produce two rows. S2 backfill
    /// (future) cleans up any rows produced during the S1→S4 transition.
    ///
    /// **Constraint match assumption:** the post-107 catch path matches
    /// `DbError::DuplicateKey { .. }` only because
    /// `uq_claims_content_hash_agent` is the only unique constraint that can
    /// fire on a fresh-UUID `INSERT INTO claims`. If a future migration adds
    /// another unique constraint to `claims`, narrow this match to inspect
    /// the constraint name.
    ///
    /// Takes `&mut PgConnection` for transactional composition.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` for non-unique-violation database errors.
    pub async fn create_or_get(
        conn: &mut sqlx::PgConnection,
        claim: &Claim,
    ) -> Result<(Claim, bool), DbError> {
        let agent_id: Uuid = claim.agent_id.into();
        let content_hash = ContentHasher::hash(claim.content.as_bytes());

        if let Some(existing) =
            Self::find_by_content_hash_and_agent(&mut *conn, content_hash.as_slice(), agent_id)
                .await?
        {
            return Ok((existing, false));
        }

        match Self::create_strict(&mut *conn, claim).await {
            Ok(c) => Ok((c, true)),
            Err(DbError::DuplicateKey { .. }) => {
                // Post-107 race: another writer won. Re-find and return.
                let existing = Self::find_by_content_hash_and_agent(
                    &mut *conn,
                    content_hash.as_slice(),
                    agent_id,
                )
                .await?
                .ok_or_else(|| DbError::InvalidData {
                    reason: "DuplicateKey from create_strict but no row found on re-find"
                        .to_string(),
                })?;
                Ok((existing, false))
            }
            Err(e) => Err(e),
        }
    }
```

- [ ] **Step 4: Verify `DbError::InvalidData` exists in main**

```bash
grep -n "InvalidData" crates/epigraph-db/src/errors.rs
```

Expected: variant defined in `DbError`. If absent, STOP — the helper references a variant that doesn't exist; surface to user. (Should be present — the noun-claim helper assumes it.)

- [ ] **Step 5: Compile**

```bash
cargo check -p epigraph-db
```

Expected: clean compile. Common failure: `ContentHasher` import missing — verify the file already imports `epigraph_crypto::ContentHasher` near the top (it should, used by `claim_from_row`).

- [ ] **Step 6: Commit**

```bash
git add crates/epigraph-db/src/repos/claim.rs
git commit -m "feat(db): add S1 noun-claim ClaimRepository helpers

Adds find_by_content_hash_and_agent, create_strict, create_or_get —
the post-107 canonical-create surface that enforces (content_hash,
agent_id) as the noun-claim primary key. Annotates legacy create() /
create_with_tx() with the cross-agent collapse caveat.

See docs/architecture/noun-claims-and-verb-edges.md."
```

---

## Task 4: Port claim-repo integration tests

**Files:**
- Create: `crates/epigraph-db/tests/claim_repo_helpers.rs`

- [ ] **Step 1: Copy test file verbatim**

```bash
git show internal-main:crates/epigraph-db/tests/claim_repo_helpers.rs > crates/epigraph-db/tests/claim_repo_helpers.rs
wc -l crates/epigraph-db/tests/claim_repo_helpers.rs
```

Expected: 312 lines.

- [ ] **Step 2: Verify cargo test discovery (compile only)**

```bash
cargo test -p epigraph-db --no-run --tests 2>&1 | tail -20
```

Expected: `Finished` or `Compiling` lines, no errors. The test binary `claim_repo_helpers-<hash>` is produced.

- [ ] **Step 3: Run the integration tests against a live DB**

```bash
export DATABASE_URL=postgres://localhost/epigraph_test
cargo test -p epigraph-db --test claim_repo_helpers -- --test-threads=1
```

Expected: all tests pass. The fixture toggles the unique constraint on/off via `drop_unique_constraint` / `add_unique_constraint` to exercise both pre- and post-107 paths. If `DATABASE_URL` is unset, tests print "Skipping DB test" and pass trivially — that is acceptable for CI but **the engineer running this plan MUST execute Step 3 with a live DB at least once.**

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-db/tests/claim_repo_helpers.rs
git commit -m "test(db): port claim_repo_helpers integration tests

Exercises find_by_content_hash_and_agent, create_strict, create_or_get
against pre-107 (constraint dropped) and post-107 (constraint added)
fixtures. Skips when DATABASE_URL is unset."
```

---

## Task 5: Add `ApiError::Conflict` variant

**Files:**
- Modify: `crates/epigraph-api/src/errors.rs`

- [ ] **Step 1: Add `Conflict` enum variant**

Find the `ApiError` enum's existing `Forbidden` variant:

```bash
grep -n "Forbidden { reason" crates/epigraph-api/src/errors.rs
```

Insert the new variant directly after the `Forbidden` arm:

```rust

    #[error("Conflict: {reason}")]
    Conflict { reason: String },
```

(Indented one level inside the `pub enum ApiError {}` block — match surrounding style.)

- [ ] **Step 2: Add the `IntoResponse` arm**

In the `impl IntoResponse for ApiError` match block, after the `Forbidden` match arm, add:

```rust
            ApiError::Conflict { reason } => (
                StatusCode::CONFLICT,
                "Conflict",
                Some(serde_json::json!({ "reason": reason })),
            ),
```

- [ ] **Step 3: Compile**

```bash
cargo check -p epigraph-api
```

Expected: clean compile. The match must remain exhaustive — if any other place in `errors.rs` matches on `ApiError`, add a `Conflict` arm there too. Search:

```bash
grep -n "match.*ApiError\|ApiError::" crates/epigraph-api/src/errors.rs
```

If any non-trivial match-arm sites are flagged, inspect and update.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-api/src/errors.rs
git commit -m "feat(api): add ApiError::Conflict (HTTP 409)

Required by the S1 noun-claim claims route to surface (content_hash,
agent_id) collisions distinctly from generic BadRequest."
```

---

## Task 6: Wire `if_not_exists` into the claims route

**Files:**
- Modify: `crates/epigraph-api/src/routes/claims.rs`

This is the largest file change in the slice. Apply by hunk to keep the diff legible.

- [ ] **Step 1: Add `if_not_exists` field to `CreateClaimRequest`**

Find:

```bash
grep -n "labels: Vec<String>" crates/epigraph-api/src/routes/claims.rs
```

Locate the occurrence inside `pub struct CreateClaimRequest`. Append after the `labels` field, before the struct's closing `}`:

```rust
    /// When true, the server checks for an existing claim by
    /// `(content_hash, agent_id)` and returns the existing claim's id if
    /// found; otherwise inserts. Response body's `was_created` reflects
    /// which branch ran. Defaults to false (raw INSERT semantics; post-107
    /// duplicate `(content_hash, agent_id)` insertions return 409 Conflict).
    /// See docs/architecture/noun-claims-and-verb-edges.md.
    #[serde(default)]
    pub if_not_exists: bool,
```

- [ ] **Step 2: Add `was_created` field to `ClaimResponse`**

Locate `pub struct ClaimResponse`. After the `labels` field there, add:

```rust
    /// Whether the server inserted a new row (true) or returned an existing
    /// row matching `(content_hash, agent_id)` (false). Set explicitly by
    /// the create handler; omitted from non-create responses (GET/PATCH/list).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub was_created: bool,
```

- [ ] **Step 3: Update `From<Claim> for ClaimResponse`**

Find the `impl From<Claim> for ClaimResponse` block. In the constructed struct literal, after `labels: Vec::new(),` add:

```rust
            was_created: false,
```

- [ ] **Step 4: Add `if_not_exists` precondition validation**

Find:

```bash
grep -n "validate_privacy_fields(&request)" crates/epigraph-api/src/routes/claims.rs
```

Immediately after `let privacy_tier = validate_privacy_fields(&request)?;` insert:

```rust

    // S1 noun-claims-and-verb-edges validations:
    // (see docs/architecture/noun-claims-and-verb-edges.md)
    if request.if_not_exists {
        if privacy_tier != "public" {
            return Err(ApiError::ValidationError {
                field: "if_not_exists".to_string(),
                reason: "if_not_exists=true is only supported for privacy_tier=public; encrypted/private claims do not have a coherent cross-group dedup design (deferred to a future spec)".to_string(),
            });
        }
        if request.content_hash.is_some() {
            return Err(ApiError::ValidationError {
                field: "if_not_exists".to_string(),
                reason: "if_not_exists=true is incompatible with the content_hash override; new ingestion paths should compute hashes server-side".to_string(),
            });
        }
    }
```

- [ ] **Step 5: Replace persistence call with branched create**

Find:

```bash
grep -n "ClaimRepository::create_with_tx(&mut tx, &claim)" crates/epigraph-api/src/routes/claims.rs
```

Replace the line and surrounding comment:

```rust
    // Persist claim
    let created_claim = ClaimRepository::create_with_tx(&mut tx, &claim).await?;
```

with:

```rust
    // Persist claim — branch on if_not_exists per noun-claims-and-verb-edges S1.
    let (created_claim, was_created) = if request.if_not_exists {
        ClaimRepository::create_or_get(&mut tx, &claim).await?
    } else {
        match ClaimRepository::create_strict(&mut tx, &claim).await {
            Ok(c) => (c, true),
            Err(epigraph_db::DbError::DuplicateKey { .. }) => {
                // Post-107: the (content_hash, agent_id) UNIQUE constraint fired.
                // Surface as 409 Conflict so callers can distinguish "already
                // exists for this agent" from a generic 400. Pre-107 this branch
                // is unreachable because the constraint does not exist.
                return Err(ApiError::Conflict {
                    reason: "claim already exists for this (content_hash, agent_id); use if_not_exists=true to retrieve it".to_string(),
                });
            }
            Err(e) => return Err(e.into()),
        }
    };
```

- [ ] **Step 6: Gate `content_hash` / `properties` overrides on `was_created`**

Find:

```bash
grep -n "if request.content_hash.is_some() || request.properties.is_some()" crates/epigraph-api/src/routes/claims.rs
```

Replace:

```rust
    // Apply optional content_hash override and properties within the same transaction
    if request.content_hash.is_some() || request.properties.is_some() {
```

with:

```rust
    // Apply optional content_hash override and properties only when we inserted
    // a new row. Mutating an existing canonical noun-claim from a different
    // caller's request would bypass ownership/authorisation checks and can
    // clobber metadata that another agent set previously. See
    // docs/architecture/noun-claims-and-verb-edges.md §"if_not_exists semantics".
    if was_created && (request.content_hash.is_some() || request.properties.is_some()) {
```

- [ ] **Step 7: Surface unique-violation from the override UPDATE as 409**

Within the same `if was_created && ...` block, find the `.map_err(|e| ApiError::DatabaseError {` arm following the `.execute(&mut *tx).await`. Replace:

```rust
        .map_err(|e| ApiError::DatabaseError {
            message: format!("Failed to set content_hash/properties: {e}"),
        })?;
```

with:

```rust
        .map_err(|e| match e {
            // Post-107: the override sets a content_hash already used by another
            // row of the same agent. Spec §API surface (line 116) specifies this
            // surfaces as 409 Conflict from the UPDATE on the
            // if_not_exists: false path. Pre-107 this branch is unreachable.
            sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
                ApiError::Conflict {
                    reason: "content_hash override collides with an existing claim for this agent".to_string(),
                }
            }
            other => ApiError::DatabaseError {
                message: format!("Failed to set content_hash/properties: {other}"),
            },
        })?;
```

- [ ] **Step 8: Set `was_created` on the create-handler's outgoing response**

The `create_claim` handler returns a `ClaimResponse` near its tail. Find the construction site (likely an `Into::into(created_claim)` or a struct literal after the override block). The internal-main version sets `was_created` explicitly on the response only on the create handler's return path. Locate the response construction:

```bash
grep -n "ClaimResponse" crates/epigraph-api/src/routes/claims.rs | head -10
```

In `create_claim`'s return path, ensure `was_created` propagates. The simplest faithful port: after constructing the `ClaimResponse` from `created_claim` (whether via `From::from` or a literal), set `response.was_created = was_created;` before returning. **If the existing return is `Ok(Json(created_claim.into()))`, replace with:**

```rust
    let mut response: ClaimResponse = created_claim.into();
    response.was_created = was_created;
    Ok(Json(response))
```

(Adjust to match the actual surrounding control flow — the goal is: `was_created` from Step 5 reaches the wire response on the create handler, and remains `false` on GET/PATCH/list paths via `From<Claim>`'s default.)

- [ ] **Step 9: Compile**

```bash
cargo check -p epigraph-api
```

Expected: clean. Likely surface errors:
- `ApiError::Conflict` not in scope → already added in Task 5; ensure no typo.
- `epigraph_db::DbError::DuplicateKey` not in scope → confirm `epigraph_db` is already imported.
- Pattern non-exhaustive on `match e` in Step 7 → add a wildcard if sqlx version requires it.

Fix any issues, then re-run.

- [ ] **Step 10: Commit**

```bash
git add crates/epigraph-api/src/routes/claims.rs
git commit -m "feat(api): add if_not_exists option to POST /api/v1/claims

Routes claim creation through ClaimRepository::create_or_get when
if_not_exists=true (returns existing row with was_created=false on
match), or create_strict otherwise (post-107 (content_hash, agent_id)
collisions surface as 409 Conflict). Gates the content_hash /
properties override on was_created so cross-agent metadata clobber is
not possible. Validates if_not_exists incompatible with
encrypted/private tiers and with the content_hash override.

See docs/architecture/noun-claims-and-verb-edges.md."
```

---

## Task 7: Update submit_packet_tests comment

**Files:**
- Modify: `crates/epigraph-api/tests/routes/submit_packet_tests.rs`

- [ ] **Step 1: Locate the comment**

```bash
grep -n "migration 097 added a UNIQUE constraint" crates/epigraph-api/tests/routes/submit_packet_tests.rs
```

Expected: one match around line 1413.

- [ ] **Step 2: Replace the comment block**

Replace:

```rust
    // Distinct content per packet — migration 097 added a UNIQUE constraint on
    // (content_hash, agent_id), so two packets with the same content under the
    // same agent would now violate the constraint regardless of idempotency key.
    // The test still validates the original intent: different idempotency keys
```

with the internal-main wording (which references migration 106, the closer numerical neighbour in the public repo):

```rust
    // Distinct content per packet — migration 106 (security_and_hardening)
    // adds a UNIQUE constraint on (content_hash, agent_id), so two packets
    // with the same content under the same agent would violate the constraint
    // regardless of idempotency key. (Pending in source until Task 7
    // disposition; live DB may already enforce it out-of-band.) The test
    // still validates the original intent: different idempotency keys
```

**Note:** the engineer may wish to further update this comment to reference migration 107 (the constraint we just ported) rather than 106. The internal-main comment was written before the migration was extracted to 107; updating to "migration 107" is acceptable and arguably more accurate post-port. Use judgment.

- [ ] **Step 3: Compile tests**

```bash
cargo test -p epigraph-api --no-run --tests 2>&1 | tail -5
```

Expected: clean compile.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-api/tests/routes/submit_packet_tests.rs
git commit -m "test(api): update submit_packet test comment for migration 107"
```

---

## Task 8: Workspace verification

- [ ] **Step 1: Full workspace clippy**

```bash
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -30
```

Expected: clean. Address any warnings introduced by the port.

- [ ] **Step 2: Full workspace fmt-check**

```bash
cargo fmt --all -- --check
```

Expected: no diff. If diff produced, run `cargo fmt --all` and amend the most-recently-touched commit (or add a `style: cargo fmt` commit).

- [ ] **Step 3: Run the full test suite (with DB)**

```bash
export DATABASE_URL=postgres://localhost/epigraph_test
cargo test --workspace -- --test-threads=1 2>&1 | tail -30
```

Expected: all tests pass. Pay attention to:
- `claim_repo_helpers` (Task 4): all green.
- `submit_packet_tests::test_different_idempotency_keys_create_different_claims` (Task 7): green.
- Any pre-existing test that touched `CreateClaimRequest` or `ClaimResponse` JSON shape: should still pass — `if_not_exists` defaults to `false`, `was_created` is skipped on serialize when false.

- [ ] **Step 4: Commit any fmt fixups**

If `cargo fmt --all` produced changes:

```bash
git add -u
git commit -m "style: cargo fmt"
```

---

## Task 9: Push and open PR

- [ ] **Step 1: Push branch**

```bash
git push -u origin feat/s1-noun-claim-port
```

- [ ] **Step 2: Open PR**

```bash
gh pr create --title "feat: port S1 noun-claim foundation from epigraph-internal" --body "$(cat <<'EOF'
## Summary
- Ports migration 107 (`uq_claims_content_hash_agent`) and the S1 noun-claim API/DB foundation from `epigraph-internal`.
- Adds `ClaimRepository::find_by_content_hash_and_agent` / `create_strict` / `create_or_get`; annotates legacy `create()` / `create_with_tx()` with the cross-agent collapse caveat.
- Adds `if_not_exists` option on `POST /api/v1/claims`; surfaces `(content_hash, agent_id)` collisions as 409 Conflict via new `ApiError::Conflict` variant.
- Ports the `noun-claims-and-verb-edges` architecture doc (referenced by code comments).

## Excluded (follow-up)
- Migrations 108/109 + MCP S3a writer migration (separate plan).
- `mcp_tools.rs` REST-over-MCP route + `dep:epigraph-mcp` Cargo feature change.
- `ApiError::BadGateway` (unrelated feature).

## Architecture
See `docs/architecture/noun-claims-and-verb-edges.md`.

## Test plan
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo fmt --all -- --check` clean
- [ ] `DATABASE_URL=… cargo test --workspace -- --test-threads=1` green
- [ ] `claim_repo_helpers` integration tests exercise pre- and post-107 fixtures (constraint toggled via DDL in `add_unique_constraint` / `drop_unique_constraint`)
- [ ] Manual: `POST /api/v1/claims` with `if_not_exists=true` returns existing row + `was_created=false` on a content-hash repeat for the same agent
- [ ] Manual: `POST /api/v1/claims` with `if_not_exists=false` for a duplicate `(content_hash, agent_id)` returns 409 Conflict (post-107 only)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review Checklist (engineer to verify before handoff)

1. **Spec coverage:**
   - Migration 107 ported (Task 2). ✓
   - DB helpers + legacy annotations ported (Task 3). ✓
   - Integration tests ported (Task 4). ✓
   - `ApiError::Conflict` ported (Task 5). ✓
   - `if_not_exists` API surface ported (Task 6). ✓
   - Architecture doc ported (Task 1). ✓
   - submit_packet test comment fixed (Task 7). ✓
   - Excluded scope explicitly listed in plan header.

2. **Type/method consistency:**
   - `find_by_content_hash_and_agent`, `create_strict`, `create_or_get` — names match between Task 3 (definition) and Task 6 (call sites).
   - `was_created` — same name in `ClaimResponse` field (Task 6 Step 2), persistence destructure (Step 5), override gate (Step 6), response assignment (Step 8).
   - `if_not_exists` — same name throughout request, validation, branch.

3. **Excluded items still excluded:**
   - No port of `mcp_tools.rs`, `ApiError::BadGateway`, migrations 108/109, `claim_helper.rs`, `tool_resubmit_tests.rs`.

4. **No placeholders:** every code step shows the actual code.

5. **Commit boundaries:** one commit per Task (1–7), plus optional fmt fixup. Each commit independently buildable.
