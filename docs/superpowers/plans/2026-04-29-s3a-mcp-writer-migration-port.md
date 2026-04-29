# S3a MCP Writer Migration Port — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the S3a `epigraph-mcp` writer migration from `epigraph-internal` into `epigraph`. Migrates the five MCP writer tools (`submit_claim`, `memorize`, `store_workflow`, `improve_workflow`, `ingest_paper`) to the noun-claim canonical pattern using `ClaimRepository::create_or_get` via a new `claim_helper::create_claim_idempotent` shim. Replaces `idx_edges_unique_triple` with the architecture doc's "verb-event" semantics so each submission emits a distinct AUTHORED (and other relationship) edge.

**Architecture:** Atomic migration. The schema change (drop `idx_edges_unique_triple`, replace with partial-then-no constraint) and the writer-tool rewrite must land together; with the migration alone, every existing `let _ = EdgeRepository::create(...)` callsite silently shifts from "dedup-by-constraint" to "accumulate" without the corresponding `was_created` edge property metadata that downstream consumers need to interpret the accumulation. Internal landed this as PR #8 for that reason; we mirror.

**Tech Stack:** Rust workspace · sqlx 0.7 · Postgres · `epigraph-mcp` (rmcp framework) · cargo. Tests use `DATABASE_URL`-gated integration harness and `tracing-test` for log capture (new dev-dep).

**Base branch:** `feat/s1-noun-claim-port` (PR #16). Slice 2 depends on `ClaimRepository::create_or_get` which lands in #16. Rebase onto `main` after #16 merges.

**Out of scope (defer to later plans):**
- `EpiGraphMcpFull::all_tools_json` / `list_mcp_tools` discovery additions in `crates/epigraph-mcp/src/lib.rs` and `src/server.rs` (lines after 53-63 of server.rs and the `pub fn list_tools` in lib.rs). Internal landed them inside PR #8 for timing; functionally they're tool-discovery, not writer-migration. Land with `routes/mcp_tools.rs` and `BadGateway` in a follow-up.
- API handler at `routes/claims.rs:565` AUTHORED emit alignment to the new accumulating semantics (spec backlog item #10 — internal explicitly leaves this for later).
- The internal *S3a plan* document (`docs/superpowers/plans/2026-04-26-s3a-epigraph-mcp-writer-migration.md`, 2706 lines) — internal artefact, not ported. The *design spec* (244 lines) IS ported because `claim_helper.rs` rustdoc references it.

**Source refs (paste-ready git show targets):**
- `internal-main:migrations/108_authored_edges_allow_multiple.sql`
- `internal-main:migrations/109_drop_edges_triple_unique_constraint.sql`
- `internal-main:crates/epigraph-mcp/src/claim_helper.rs`
- `internal-main:crates/epigraph-mcp/src/tools/claims.rs`
- `internal-main:crates/epigraph-mcp/src/tools/memory.rs`
- `internal-main:crates/epigraph-mcp/src/tools/workflows.rs`
- `internal-main:crates/epigraph-mcp/src/tools/ingestion.rs`
- `internal-main:crates/epigraph-mcp/Cargo.toml`
- `internal-main:crates/epigraph-mcp/tests/common/mod.rs`
- `internal-main:crates/epigraph-mcp/tests/claim_helper_tests.rs`
- `internal-main:crates/epigraph-mcp/tests/tool_resubmit_tests.rs`
- `internal-main:docs/superpowers/specs/2026-04-26-s3a-epigraph-mcp-writer-migration-design.md`

---

## File Structure

**Create:**
- `migrations/017_authored_edges_allow_multiple.sql` — port of internal `108_*`. Replaces `idx_edges_unique_triple` with a partial unique index excluding AUTHORED.
- `migrations/018_drop_edges_triple_unique_constraint.sql` — port of internal `109_*`. Drops the partial index entirely; all relationships accumulate.
- `crates/epigraph-mcp/src/claim_helper.rs` (61 lines) — `create_claim_idempotent` shim over `ClaimRepository::create_or_get` + AUTHORED verb-edge emission.
- `crates/epigraph-mcp/tests/common/mod.rs` (90 lines) — shared test fixtures (DB pool, test agent setup, etc.).
- `crates/epigraph-mcp/tests/claim_helper_tests.rs` (312 lines) — integration tests for the new helper.
- `crates/epigraph-mcp/tests/tool_resubmit_tests.rs` (694 lines) — end-to-end resubmit tests for all 5 migrated tools.
- `docs/superpowers/specs/2026-04-26-s3a-epigraph-mcp-writer-migration-design.md` (244 lines) — design spec referenced by `claim_helper.rs` rustdoc.

**Modify:**
- `crates/epigraph-mcp/Cargo.toml` — add `[dev-dependencies] tracing-test = { version = "0.2", features = ["no-env-filter"] }`.
- `crates/epigraph-mcp/src/lib.rs` — add `pub mod claim_helper;` (do **not** port `pub fn list_tools` — out of scope per header).
- `crates/epigraph-mcp/src/tools/claims.rs` — migrate `submit_claim` to noun-claim pattern.
- `crates/epigraph-mcp/src/tools/memory.rs` — migrate `memorize` to noun-claim pattern.
- `crates/epigraph-mcp/src/tools/workflows.rs` — migrate `store_workflow` and `improve_workflow`.
- `crates/epigraph-mcp/src/tools/ingestion.rs` — migrate `ingest_paper` (per-claim loop) to noun-claim pattern.

**Boundary rationale:** `claim_helper` is a single-responsibility module (idempotent create + AUTHORED emit). Each tool file owns its writer migration; the shared shim keeps tool files focused on tool semantics. Tests follow the cargo `tests/` convention with a shared `common/mod.rs` fixture.

---

## Pre-Task: Worktree setup

- [ ] **Step 1: Create isolated worktree off slice 1's branch**

```bash
cd /home/jeremy/epigraph
git fetch origin feat/s1-noun-claim-port
git worktree add -b feat/s3a-mcp-writer-port ../epigraph-wt-s3a-mcp /home/jeremy/epigraph-wt-s1-noun-claim
cd ../epigraph-wt-s3a-mcp
git log --oneline -1
```

Expected: tip is `56df3f02` (S1 plan commit) or whatever HEAD of `feat/s1-noun-claim-port` is.

- [ ] **Step 2: Sanity-check baseline build (slice 1 carries forward)**

```bash
cargo check -p epigraph-mcp -p epigraph-db -p epigraph-api
```

Expected: clean compile. The S1 helpers must be present — `grep -c "create_or_get" crates/epigraph-db/src/repos/claim.rs` should be `>= 2`.

---

## Task 1: Port S3a design spec

**Files:**
- Create: `docs/superpowers/specs/2026-04-26-s3a-epigraph-mcp-writer-migration-design.md`

- [ ] **Step 1: Copy spec verbatim**

```bash
mkdir -p docs/superpowers/specs
git show internal-main:docs/superpowers/specs/2026-04-26-s3a-epigraph-mcp-writer-migration-design.md > docs/superpowers/specs/2026-04-26-s3a-epigraph-mcp-writer-migration-design.md
wc -l docs/superpowers/specs/2026-04-26-s3a-epigraph-mcp-writer-migration-design.md
```

Expected: 244 lines.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-04-26-s3a-epigraph-mcp-writer-migration-design.md
git commit -m "docs(spec): port S3a MCP writer migration design

Cherry-picked from epigraph-internal:docs/superpowers/specs/. The
claim_helper module ported in subsequent commits references this spec
in its rustdoc — porting first prevents dangling links."
```

---

## Task 2: Port migrations 017 + 018

**Files:**
- Create: `migrations/017_authored_edges_allow_multiple.sql`
- Create: `migrations/018_drop_edges_triple_unique_constraint.sql`

- [ ] **Step 1: Copy migration 017 (was internal 108) and rewrite header comment to reference the public-repo predecessor**

```bash
git show internal-main:migrations/108_authored_edges_allow_multiple.sql > migrations/017_authored_edges_allow_multiple.sql
```

Then edit the file's header comment block: the body says "The original idx_edges_unique_triple (migration 030) prevented AUTHORED accumulation". In the public repo, `idx_edges_unique_triple` lives in `001_initial_schema.sql:2561`, not migration 030. Replace the comment text:

```
-- The original idx_edges_unique_triple (migration 030) prevented AUTHORED
-- accumulation: a second AUTHORED edge for the same (agent, claim) tripped
```

with:

```
-- The original idx_edges_unique_triple (defined in 001_initial_schema.sql)
-- prevented AUTHORED accumulation: a second AUTHORED edge for the same
-- (agent, claim) tripped
```

The DDL body (`DROP INDEX IF EXISTS idx_edges_unique_triple; CREATE UNIQUE INDEX idx_edges_unique_triple_non_authored ...`) is unchanged.

- [ ] **Step 2: Copy migration 018 (was internal 109) and rewrite "migration 108" / "migration 030" references**

```bash
git show internal-main:migrations/109_drop_edges_triple_unique_constraint.sql > migrations/018_drop_edges_triple_unique_constraint.sql
```

Edit the header comment: every literal "migration 108" → "migration 017", and "migration 030" → "001_initial_schema.sql". Use:

```bash
sed -i 's/migration 108/migration 017/g; s/migration 030/001_initial_schema.sql/g' migrations/018_drop_edges_triple_unique_constraint.sql
```

Verify:

```bash
grep -n "migration 017\|001_initial_schema" migrations/018_drop_edges_triple_unique_constraint.sql | head -5
```

Expected: at least one match for each.

The DDL body (`DROP INDEX IF EXISTS idx_edges_unique_triple_non_authored;`) is unchanged.

- [ ] **Step 3: Apply against the test DB**

```bash
export DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_s3a_port_test
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d postgres -c "DROP DATABASE IF EXISTS epigraph_s3a_port_test;"
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d postgres -c "CREATE DATABASE epigraph_s3a_port_test OWNER epigraph;"
sqlx migrate run --source migrations
```

Expected: `Applied 017/migrate authored edges allow multiple` and `Applied 018/migrate drop edges triple unique constraint`.

- [ ] **Step 4: Verify schema state**

```bash
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d epigraph_s3a_port_test -c "\d edges" | grep -i "unique_triple\|UNIQUE"
```

Expected: NO `idx_edges_unique_triple` and NO `idx_edges_unique_triple_non_authored`. Only `edges_pkey` should remain on edges.

- [ ] **Step 5: Commit**

```bash
git add migrations/017_authored_edges_allow_multiple.sql migrations/018_drop_edges_triple_unique_constraint.sql
git commit -m "feat(migrations): port 017/018 — verb-edge accumulation

Ports internal migrations 108 + 109. 017 replaces the
idx_edges_unique_triple constraint (defined in 001_initial_schema.sql)
with a partial index excluding AUTHORED; 018 drops that partial index
so every relationship accumulates per submission per the architecture
doc's verb-event semantics.

Application code is responsible for idempotency where a relationship
is semantically a noun-edge. The four pre-existing let-_-EdgeRepo
callsites (RELATES_TO in routes/edges.rs, span edges in routes/spans.rs,
PERSPECTIVE_OF in mcp/perspectives.rs, attribution edges in
routes/conventions.rs) shift from silent-dedup to silent-accumulate;
their semantics are filed for follow-up audit per the internal
migration 109 header comment.

See docs/architecture/noun-claims-and-verb-edges.md and
docs/superpowers/specs/2026-04-26-s3a-epigraph-mcp-writer-migration-design.md."
```

---

## Task 3: Add `tracing-test` dev-dependency

**Files:**
- Modify: `crates/epigraph-mcp/Cargo.toml`

- [ ] **Step 1: Locate the dependencies section**

```bash
grep -n "^\[dependencies\]\|^\[dev-dependencies\]\|^\[features\]" crates/epigraph-mcp/Cargo.toml
```

Expected: `[dependencies]` exists; `[dev-dependencies]` may or may not. `[features]` follows.

- [ ] **Step 2: Insert `[dev-dependencies]` block before `[features]`**

If `[dev-dependencies]` does not yet exist in the file, insert this block immediately before the `[features]` line:

```toml
[dev-dependencies]
# `no-env-filter` is REQUIRED for integration tests in tests/* to capture
# events emitted from src/ (different crate target). Without it, the macro's
# default env filter scopes capture to the test crate only.
tracing-test = { version = "0.2", features = ["no-env-filter"] }

```

If `[dev-dependencies]` already exists, append the `tracing-test = ...` line (with the comment block above it) inside it.

- [ ] **Step 3: Build to fetch the new dep**

```bash
cargo build -p epigraph-mcp --tests 2>&1 | tail -10
```

Expected: `Compiling tracing-test v0.2.x` then clean finish. The first build may take a minute as `tracing-test` has its own dep tree (tracing-subscriber etc., already in workspace).

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-mcp/Cargo.toml Cargo.lock
git commit -m "chore(mcp): add tracing-test dev-dep for tool resubmit tests

Required by tests/tool_resubmit_tests.rs to capture log events from
src/ via the no-env-filter feature; integration test crate target is
distinct from src crate target."
```

---

## Task 4: Port `claim_helper` module

**Files:**
- Create: `crates/epigraph-mcp/src/claim_helper.rs`
- Modify: `crates/epigraph-mcp/src/lib.rs`

- [ ] **Step 1: Copy `claim_helper.rs` verbatim**

```bash
git show internal-main:crates/epigraph-mcp/src/claim_helper.rs > crates/epigraph-mcp/src/claim_helper.rs
wc -l crates/epigraph-mcp/src/claim_helper.rs
```

Expected: 61 lines.

- [ ] **Step 2: Register the module in `lib.rs`**

Find the existing `pub mod` lines:

```bash
grep -n "^pub mod" crates/epigraph-mcp/src/lib.rs
```

Add `pub mod claim_helper;` to the list, alphabetically before `pub mod embed;`. Edit the existing block:

```rust
#![allow(clippy::doc_markdown)]

pub mod embed;
```

becomes:

```rust
#![allow(clippy::doc_markdown)]

pub mod claim_helper;
pub mod embed;
```

**Do NOT** port the `pub fn list_tools` and `pub use server::EpiGraphMcpFull` discovery additions from `internal-main:lib.rs` — those are out of scope per the plan header.

- [ ] **Step 3: Compile**

```bash
cargo check -p epigraph-mcp 2>&1 | tail -10
```

Expected: clean. Common failure: `epigraph-db` not in `[dependencies]` — verify `crates/epigraph-mcp/Cargo.toml` already lists `epigraph-db`. If not, add it (workspace-style) and re-check.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-mcp/src/claim_helper.rs crates/epigraph-mcp/src/lib.rs
git commit -m "feat(mcp): add claim_helper::create_claim_idempotent

Idempotent canonical claim creation + AUTHORED verb-edge emission for
MCP-layer writers. Composes ClaimRepository::create_or_get inside a
connection scope, then fire-and-forget AUTHORED on the pool. Mirrors
the API handler pattern at routes/claims.rs:444-576.

See docs/architecture/noun-claims-and-verb-edges.md and
docs/superpowers/specs/2026-04-26-s3a-epigraph-mcp-writer-migration-design.md."
```

---

## Task 5: Port test fixture `tests/common/mod.rs`

**Files:**
- Create: `crates/epigraph-mcp/tests/common/mod.rs`

- [ ] **Step 1: Copy verbatim**

```bash
mkdir -p crates/epigraph-mcp/tests/common
git show internal-main:crates/epigraph-mcp/tests/common/mod.rs > crates/epigraph-mcp/tests/common/mod.rs
wc -l crates/epigraph-mcp/tests/common/mod.rs
```

Expected: 90 lines.

- [ ] **Step 2: Compile (test target only)**

```bash
cargo test -p epigraph-mcp --no-run 2>&1 | tail -10
```

Expected: clean compile. The fixture is unused at this point; rustc may warn `dead_code`. Suppress only if the fixture file already has a `#[allow(dead_code)]` at the top (verbatim port — leave as is). If a hard error appears, the fixture's imports are out-of-sync — re-read both versions and reconcile.

- [ ] **Step 3: Commit**

```bash
git add crates/epigraph-mcp/tests/common/mod.rs
git commit -m "test(mcp): port shared test fixture for tool resubmit suite

Provides DB pool setup, test agent insertion, and edge-count helpers
shared between claim_helper_tests.rs and tool_resubmit_tests.rs."
```

---

## Task 6: Port `claim_helper_tests.rs`

**Files:**
- Create: `crates/epigraph-mcp/tests/claim_helper_tests.rs`

- [ ] **Step 1: Copy verbatim**

```bash
git show internal-main:crates/epigraph-mcp/tests/claim_helper_tests.rs > crates/epigraph-mcp/tests/claim_helper_tests.rs
wc -l crates/epigraph-mcp/tests/claim_helper_tests.rs
```

Expected: 312 lines.

- [ ] **Step 2: Compile**

```bash
cargo test -p epigraph-mcp --no-run 2>&1 | tail -10
```

Expected: clean compile.

- [ ] **Step 3: Run against test DB**

```bash
export DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_s3a_port_test
cargo test -p epigraph-mcp --test claim_helper_tests -- --test-threads=1
```

Expected: all tests pass. The fixture sets up a fresh test DB row state per test (truncates between tests if implemented that way — read `common/mod.rs` if you need to debug).

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-mcp/tests/claim_helper_tests.rs
git commit -m "test(mcp): port claim_helper integration tests

Exercises create_claim_idempotent: was_created branching, AUTHORED
edge emission per submission (post-018 accumulation), error
propagation from ClaimRepository::create_or_get, AUTHORED-failure
log-and-swallow behavior."
```

---

## Task 7: Migrate `submit_claim` (tools/claims.rs)

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/claims.rs`

This and Tasks 8–10 each rewrite a single tool's writer body. The diffs are large but mechanical: replace the legacy `ClaimRepository::create(&server.pool, &claim).await?` + manual edge emission with `crate::claim_helper::create_claim_idempotent(&server.pool, &claim, "<tool_name>").await?`, then emit the per-submission verb-edges (DERIVED_FROM, HAS_TRACE, etc.) on every branch with `was_created` recorded in edge properties.

- [ ] **Step 1: Apply the migration via cherry-pick equivalent**

The simplest faithful port is to write the file's new state directly from `internal-main`:

```bash
git show internal-main:crates/epigraph-mcp/src/tools/claims.rs > crates/epigraph-mcp/src/tools/claims.rs
```

**Caveat:** if `tools/claims.rs` has diverged on epigraph main since slice 1 (it shouldn't, but `git diff main internal-main -- crates/epigraph-mcp/src/tools/claims.rs` should be the only difference vs your worktree's pre-port state), this clobbers any in-tree changes. Verify before clobbering:

```bash
git diff origin/main -- crates/epigraph-mcp/src/tools/claims.rs | head -20
```

Expected: empty (no public-repo changes since fork point on this file). If non-empty, STOP — three-way merge required.

- [ ] **Step 2: Compile**

```bash
cargo check -p epigraph-mcp 2>&1 | tail -10
```

Expected: clean. Likely surface errors:
- `EdgeRepository` import added — already in the new file.
- `crate::claim_helper` path — registered in Task 4.
- Workflow / dataset return types — should match because `submit_claim`'s public signature is unchanged.

- [ ] **Step 3: Run any unit tests in the file**

```bash
cargo test -p epigraph-mcp --lib claims 2>&1 | tail -10
```

Expected: pass (or "no tests" — the migration is exercised end-to-end by `tool_resubmit_tests.rs` in Task 11).

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-mcp/src/tools/claims.rs
git commit -m "feat(mcp): migrate submit_claim to noun-claim canonical pattern

Replaces ClaimRepository::create with claim_helper::create_claim_idempotent.
Emits per-submission DERIVED_FROM and HAS_TRACE verb-edges on both
branches (post-018 accumulation), with was_created recorded in edge
properties. Trace and Evidence remain noun-claims with their own
UUIDs and signatures.

API handler at routes/claims.rs still follows the pre-S3a
skip-on-resubmit rule for these edges; alignment is spec backlog #10."
```

---

## Task 8: Migrate `memorize` (tools/memory.rs)

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/memory.rs`

- [ ] **Step 1: Pre-clobber check**

```bash
git diff origin/main -- crates/epigraph-mcp/src/tools/memory.rs | head -20
```

Expected: empty. If non-empty: STOP, three-way merge.

- [ ] **Step 2: Replace file with internal-main version**

```bash
git show internal-main:crates/epigraph-mcp/src/tools/memory.rs > crates/epigraph-mcp/src/tools/memory.rs
```

- [ ] **Step 3: Compile**

```bash
cargo check -p epigraph-mcp 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-mcp/src/tools/memory.rs
git commit -m "feat(mcp): migrate memorize to noun-claim canonical pattern

Routes memorize through claim_helper::create_claim_idempotent so
re-memorize calls return the existing canonical claim with
was_created=false instead of inserting a duplicate row (which
post-013 would 409 anyway). AUTHORED edge accumulates per call."
```

---

## Task 9: Migrate `store_workflow` and `improve_workflow` (tools/workflows.rs)

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/workflows.rs`

This is the largest tool diff (326 diff lines).

- [ ] **Step 1: Pre-clobber check**

```bash
git diff origin/main -- crates/epigraph-mcp/src/tools/workflows.rs | head -20
```

Expected: empty.

- [ ] **Step 2: Replace file**

```bash
git show internal-main:crates/epigraph-mcp/src/tools/workflows.rs > crates/epigraph-mcp/src/tools/workflows.rs
```

- [ ] **Step 3: Compile**

```bash
cargo check -p epigraph-mcp 2>&1 | tail -10
```

Expected: clean. `store_workflow` and `improve_workflow` both route through `create_claim_idempotent`. `improve_workflow` additionally has a `variant_of` edge that must be skipped on the `was_created=false` branch (the migrated code already does this — see internal commit `78fada9`).

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-mcp/src/tools/workflows.rs
git commit -m "feat(mcp): migrate store_workflow + improve_workflow to noun-claim canonical pattern

Both tools route through claim_helper::create_claim_idempotent.
improve_workflow skips its variant_of noun-edge emission on the
was_created=false branch (resubmit returns the existing canonical
workflow row; the variant_of edge already exists)."
```

---

## Task 10: Migrate `ingest_paper` (tools/ingestion.rs) — **MERGED PORT (not clobber)**

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/ingestion.rs`

**Discovered during execution 2026-04-29:** the public-repo `tools/ingestion.rs` contains an entire `ingest_document` / `do_ingest_document` block (plus DOI/arxiv resolution helpers) added by PR #14 (extract-claims pipeline) that is absent from `internal-main`. A clobber drops these functions and breaks `server.rs` wiring. The faithful port is a merge: take internal's writer-migration body for `ingest_paper` / `ingest_paper_url` / `do_ingest`, then append the public-only `ingest_document` block.

- [ ] **Step 1: Build merged file via shell helper**

```bash
WT=/home/jeremy/epigraph-wt-s3a-mcp
TARGET=$WT/crates/epigraph-mcp/src/tools/ingestion.rs
PUB_TMP=/tmp/ingestion_pub.rs
INT_TMP=/tmp/ingestion_int.rs

cd $WT
git show origin/main:crates/epigraph-mcp/src/tools/ingestion.rs > $PUB_TMP
git show internal-main:crates/epigraph-mcp/src/tools/ingestion.rs > $INT_TMP

# Public's import set (lines 1-25) is a superset of internal's; use it.
sed -n '1,25p' $PUB_TMP > $TARGET
echo "" >> $TARGET

# Internal's body from line 20 onward (everything after its imports).
sed -n '20,$p' $INT_TMP >> $TARGET

# Public's ingest_document block (line 307 onward).
sed -n '307,$p' $PUB_TMP >> $TARGET
```

Expected: ~786 lines total.

- [ ] **Step 2: Compile + verify single definitions**

```bash
cargo check -p epigraph-mcp 2>&1 | tail -10
grep -n "pub async fn ingest_document\b\|PIPELINE_VERSION\|pub async fn do_ingest_document" crates/epigraph-mcp/src/tools/ingestion.rs
```

Expected: clean compile. Single definitions of `ingest_document`, `do_ingest_document`, `PIPELINE_VERSION`. The merge boundary may leave a stray blank line that `cargo fmt --all` cleans up in Task 12.

- [ ] **Step 3: Run the public ingest_document_smoke test**

```bash
DATABASE_URL=… cargo test -p epigraph-mcp --test ingest_document_smoke -- --test-threads=1
```

Expected: 3 tests pass (`happy_path_ingests_full_hierarchy`, `re_ingest_hits_version_gate`, `cross_paper_atom_and_author_converge`). Confirms the merge preserved public's `ingest_document` semantics.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-mcp/src/tools/ingestion.rs
git commit -m "feat(mcp): migrate ingest_paper per-claim loop to noun-claim canonical pattern

Each extracted claim routes through claim_helper::create_claim_idempotent.
SUPPORTS edges between two canonical claims accumulate per submission
per migration 018 (this case is what motivated 018 — see migration
header). The ingest_document tool already used a different pattern
and is unaffected."
```

---

## Task 11: Port `tool_resubmit_tests.rs`

**Files:**
- Create: `crates/epigraph-mcp/tests/tool_resubmit_tests.rs`

- [ ] **Step 1: Copy verbatim**

```bash
git show internal-main:crates/epigraph-mcp/tests/tool_resubmit_tests.rs > crates/epigraph-mcp/tests/tool_resubmit_tests.rs
wc -l crates/epigraph-mcp/tests/tool_resubmit_tests.rs
```

Expected: 694 lines.

- [ ] **Step 2: Compile**

```bash
cargo test -p epigraph-mcp --no-run 2>&1 | tail -10
```

Expected: clean. The test file uses `tracing-test` (added in Task 3), `common::*` fixtures (Task 5), and the migrated tools (Tasks 7–10).

- [ ] **Step 3: Run against test DB**

```bash
export DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_s3a_port_test
cargo test -p epigraph-mcp --test tool_resubmit_tests -- --test-threads=1
```

Expected: all tests pass. The suite covers all 5 migrated tools: each tool's resubmit path returns `was_created=false` for repeat content, accumulates verb-edges per submission, persists Trace/Evidence, and logs AUTHORED-emit failures without aborting.

If a test fails on schema state (e.g., `idx_edges_unique_triple` lingering): drop and recreate the DB:

```bash
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d postgres -c "DROP DATABASE IF EXISTS epigraph_s3a_port_test;"
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d postgres -c "CREATE DATABASE epigraph_s3a_port_test OWNER epigraph;"
```

The fixture re-runs migrations on first connection.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-mcp/tests/tool_resubmit_tests.rs
git commit -m "test(mcp): port tool resubmit end-to-end suite

694-line integration suite covering all 5 migrated MCP writer tools
(submit_claim, memorize, store_workflow, improve_workflow,
ingest_paper). Verifies was_created branching, verb-edge
accumulation per submission, AUTHORED-emit log-and-swallow on
EdgeRepository failure."
```

---

## Task 12: Workspace verification

- [ ] **Step 1: Scoped clippy on touched crates (lib only — workspace tests have pre-existing baseline noise)**

```bash
cargo clippy -p epigraph-mcp -p epigraph-db --lib -- -D warnings
```

Expected: clean.

- [ ] **Step 2: fmt-check**

```bash
cargo fmt --all -- --check
```

Expected: no diff. If diff: `cargo fmt --all` and add a `style: cargo fmt` commit.

- [ ] **Step 3: Run touched-crate tests against test DB**

```bash
export DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_s3a_port_test
cargo test -p epigraph-mcp -p epigraph-db -- --test-threads=1 2>&1 | tail -30
```

Expected: all pass. Watch for:
- `claim_repo_helpers` (slice 1): still green (constraint name unchanged).
- `claim_helper_tests` (Task 6): green.
- `tool_resubmit_tests` (Task 11): green.
- Any pre-existing `epigraph-mcp` tests: green (the migrations don't break the existing test fixtures because all relationships still PRIMARY-KEY-unique on `edges.id`).

- [ ] **Step 4: Sanity-check the four flagged let-_-EdgeRepo callsites still compile (audit deferred)**

```bash
cargo check -p epigraph-api 2>&1 | tail -10
```

Expected: clean. The `routes/edges.rs`, `routes/spans.rs`, `mcp/perspectives.rs`, `routes/conventions.rs` callsites continue to use `let _ = EdgeRepository::create(...)` — now silent-accumulate instead of silent-dedup. Behavior shift documented in migration 018 header comment; full audit is the spec's `s3a-followup` backlog item.

---

## Task 13: Push and open PR

- [ ] **Step 1: Push**

```bash
git push -u origin feat/s3a-mcp-writer-port
```

- [ ] **Step 2: Open PR (depends on #16)**

```bash
gh pr create --title "feat: port S3a MCP writer migration from epigraph-internal" --base feat/s1-noun-claim-port --body "$(cat <<'EOF'
## Summary
- Ports the S3a MCP writer migration from `epigraph-internal` (PR #8 there).
- Adds migrations 017/018 to drop `idx_edges_unique_triple` so every relationship accumulates per submission per the architecture doc's verb-event semantics.
- Adds `claim_helper::create_claim_idempotent` shim over `ClaimRepository::create_or_get` (from #16) + AUTHORED verb-edge emission.
- Migrates 5 MCP writer tools: `submit_claim`, `memorize`, `store_workflow`, `improve_workflow`, `ingest_paper`.

## Depends on
- #16 (S1 noun-claim foundation) — provides `ClaimRepository::create_or_get`. **Rebase onto main after #16 merges.**

## Excluded (follow-up)
- `EpiGraphMcpFull::all_tools_json` / `list_mcp_tools` discovery additions in `lib.rs` and `server.rs` — bundled with `routes/mcp_tools.rs` follow-up, not writer-migration scope.
- API handler `routes/claims.rs:565` AUTHORED emit alignment — spec backlog #10.
- Audit of pre-existing `let _ = EdgeRepository::create(...)` callsites in `routes/edges.rs`, `routes/spans.rs`, `mcp/perspectives.rs`, `routes/conventions.rs` — flagged in migration 018 header comment.

## Coverage notes for reviewers
- `claim_helper_tests.rs` (312 lines) covers the new helper directly.
- `tool_resubmit_tests.rs` (694 lines) covers all 5 migrated tools end-to-end.
- The four pre-existing `let _ = EdgeRepository::create(...)` callsites shift from silent-dedup to silent-accumulate. No regression test is added for them in this PR; migration 018 header comment files the audit.

## Test plan
- [x] `cargo fmt --all -- --check` clean
- [x] `cargo clippy -p epigraph-mcp -p epigraph-db --lib -- -D warnings` clean
- [x] `DATABASE_URL=… cargo test -p epigraph-mcp -p epigraph-db -- --test-threads=1` — all green
- [ ] **Manual:** `submit_claim` MCP tool returns `was_created=false` on a content-hash repeat for the same agent
- [ ] **Manual:** Two `submit_claim` calls produce two distinct AUTHORED edges (post-018 accumulation)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review Checklist

1. **Scope coverage:** all 5 writer tools migrated ✓; helpers + tests ported ✓; design spec ported ✓; migrations 017/018 ported ✓; tracing-test dev-dep added ✓.

2. **Excluded scope held:** `list_mcp_tools` server.rs/lib.rs additions NOT ported ✓; `routes/claims.rs:565` API alignment NOT ported ✓; internal S3a *plan* (2706 lines) NOT ported ✓.

3. **Type/method consistency:**
   - `crate::claim_helper::create_claim_idempotent` — name matches Task 4 (definition) and Tasks 7–10 (call sites).
   - Migration filenames match the renumbering (017/018, not 108/109).
   - Constraint name `idx_edges_unique_triple` referenced consistently — defined in `001_initial_schema.sql`, dropped in 017, residual partial dropped in 018.

4. **Dependency on slice 1 explicit:** plan header states "Base branch: `feat/s1-noun-claim-port`"; PR command uses `--base feat/s1-noun-claim-port`.

5. **No placeholders:** every step has the exact `git show` command or sed line or commit message.

6. **Migration sed safety:** the sed in Task 2 Step 2 only rewrites in the new 018 file (which I created in step 1), not anywhere else. Verify by checking `migrations/` files only.
