# S5 DB Repo Port — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port two small, additions-only deltas in `crates/epigraph-db/src/repos/` from `epigraph-internal` into the public `epigraph` repo:

1. **`divergence.rs`** — adds a 7-day TTL filter to `get_latest` / `top_divergent`, sanitizes the `pignistic_prob` argument of `store` against NaN, infinities, negatives (including IEEE-754 `-0.0`), and values above 1.0, and adds 4 unit tests.
2. **`claim.rs`** — drops one line (`AND is_current = true`) from `find_claims_needing_embeddings` so superseded claims are also surfaced for embedding backfill.

**Architecture:** Two narrowly scoped commits. The divergence change is a faithful additions-only port; the claim change is a surgical filter relaxation. Other `is_current` references elsewhere in `claim.rs` (lineage code at line 969+) are **not** touched.

**Tech Stack:** Rust workspace · sqlx 0.7 · Postgres · `epigraph-db` crate.

**Base branch:** `main` (post-#16 merge — `25e221a4`). No dependency on the open S3a PR (#17) — slices are file-disjoint at the crate level (S3a touches `epigraph-mcp`, `migrations/`, and tests; S5 touches only `crates/epigraph-db/src/repos/divergence.rs` + `claim.rs`).

**Out of scope (do not touch):**
- `crates/epigraph-db/src/repos/edge.rs` — `git diff` shows it as deleted because internal-main lacks the public-only `EdgeRepository::create_if_not_exists` (added by PR #14 extract-claims). Keep public version.
- `crates/epigraph-db/src/repos/paper.rs` — same: public-only file from PR #14, used by `crates/epigraph-mcp/src/tools/ingestion.rs::do_ingest_document`. Keep.
- `crates/epigraph-db/src/repos/mod.rs` — keeps `pub mod paper;` (public-only registration). Do not delete.
- Any other `is_current` filter in `claim.rs` — only the one in `find_claims_needing_embeddings` (line 1420) is dropped.

**Source refs:**
- `internal-main:crates/epigraph-db/src/repos/divergence.rs`
- `internal-main:crates/epigraph-db/src/repos/claim.rs`

---

## File Structure

**Modify:**
- `crates/epigraph-db/src/repos/divergence.rs` — replace verbatim with internal-main version (the public version is line-for-line a strict subset, so a verbatim overwrite is the faithful port).
- `crates/epigraph-db/src/repos/claim.rs` — surgical 1-line edit: remove the `AND is_current = true` clause from the `find_claims_needing_embeddings` SELECT.

**Create:**
- `docs/superpowers/plans/2026-04-29-s5-db-repo-port.md` — this plan.

---

## Pre-Task: Worktree setup

- [x] **Step 1: Create isolated worktree off origin/main**

```bash
cd /home/jeremy/epigraph
git worktree add -b feat/s5-db-repo-port /home/jeremy/epigraph-wt-db-repo origin/main
cd /home/jeremy/epigraph-wt-db-repo
git log --oneline -1
```

Expected: tip is `25e221a4 feat: port S1 noun-claim foundation from epigraph-internal (#16)` (current origin/main HEAD post-#16 merge).

- [ ] **Step 2: Sanity-check baseline build**

```bash
cargo check -p epigraph-db 2>&1 | tail -5
```

Expected: clean compile.

---

## Task 0: Commit the plan

- [ ] **Step 1: Commit the plan file**

```bash
git add docs/superpowers/plans/2026-04-29-s5-db-repo-port.md
git commit -m "docs(plan): add S5 DB repo port plan

Captures the scope of the two additions-only db-repo deltas
(divergence TTL/NaN-safety + embedding-backfill filter relaxation)
for traceability."
```

---

## Task 1: Port `divergence.rs`

**Files:**
- Modify: `crates/epigraph-db/src/repos/divergence.rs`

- [ ] **Step 1: Pre-clobber check**

```bash
git diff origin/main -- crates/epigraph-db/src/repos/divergence.rs
```

Expected: empty (worktree was just created off origin/main; no unrelated drift).

- [ ] **Step 2: Replace file with internal-main version**

```bash
git show internal-main:crates/epigraph-db/src/repos/divergence.rs > crates/epigraph-db/src/repos/divergence.rs
wc -l crates/epigraph-db/src/repos/divergence.rs
```

Expected: 223 lines (vs. 139 in the public version pre-port — net +84, matching the diff stat ±a couple lines for end-of-file whitespace).

- [ ] **Step 3: Verify the diff matches the expected port**

```bash
git diff -- crates/epigraph-db/src/repos/divergence.rs | head -120
```

Expected to see:
- `use chrono::{DateTime, Duration, Utc};` (added `Duration`)
- `const DIVERGENCE_TTL_DAYS: i64 = 7;`
- `safe_betp` block in `store` using explicit comparisons (NOT `.clamp()` — the IEEE-754 `-0.0` reasoning in the inline comment is load-bearing).
- `WHERE ... AND computed_at >= $2` in `get_latest`; `WHERE computed_at >= $1` in `top_divergent`.
- 4 new unit tests in the `tests` module: `store_sanitizes_negative_zero_pignistic`, `store_sanitizes_nan_pignistic`, `store_sanitizes_negative_pignistic`, `store_sanitizes_pignistic_above_one`.

- [ ] **Step 4: Compile + clippy**

```bash
cargo check -p epigraph-db 2>&1 | tail -10
cargo clippy -p epigraph-db --lib -- -D warnings 2>&1 | tail -20
```

Expected: clean. **Risk:** `clippy::manual_clamp` may flag the `safe_betp` `if/else if/else` ladder. If so, do **not** rewrite using `.clamp()` — that defeats the bug fix (`-0.0.clamp(0.0, 1.0) == -0.0`). Instead, add `#[allow(clippy::manual_clamp)]` on the `store` function with an inline comment pointing at the `-0.0` reasoning the existing code-comment already documents. Re-run clippy to confirm clean.

- [ ] **Step 5: fmt-check**

```bash
cargo fmt --all -- --check
```

Expected: no diff. If diff, run `cargo fmt --all` and stage.

- [ ] **Step 6: Run db unit tests against the test DB**

```bash
export DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_db_repo_test
sqlx migrate run --source migrations
cargo test -p epigraph-db --lib divergence 2>&1 | tail -20
```

Expected: 5 tests pass (the existing `divergence_row_has_expected_fields` plus the 4 new sanitizer tests). They are pure-Rust unit tests, no DB needed, but running them under the migrated DB context catches any inadvertent fallout.

- [ ] **Step 7: Commit**

```bash
git add crates/epigraph-db/src/repos/divergence.rs
git commit -m "feat(db): port DivergenceRepository TTL + NaN-safe writes

Cherry-picked from epigraph-internal:crates/epigraph-db/src/repos/divergence.rs.

Three behavior changes:

1. store() now sanitizes pignistic_prob before insertion. NaN, +/-inf,
   and any value <= 0.0 (including IEEE-754 -0.0, which .clamp(0.0,1.0)
   preserves) become a fresh +0.0 literal; values >= 1.0 saturate to
   1.0. Prevents the cache from holding invalid probabilities.

2. get_latest() and top_divergent() now exclude rows older than
   DIVERGENCE_TTL_DAYS (= 7). Stale entries are invisible until new
   evidence triggers a fresh write. Callers in
   crates/epigraph-api/src/routes/belief.rs and
   crates/epigraph-mcp/src/tools/ds.rs see this as silent drop of
   stale rows — intentional per the TTL.

3. Adds 4 unit tests covering -0.0, NaN, sub-zero, and over-1
   pignistic inputs to lock the sanitizer behavior."
```

---

## Task 2: Drop `is_current` filter from `find_claims_needing_embeddings`

**Files:**
- Modify: `crates/epigraph-db/src/repos/claim.rs`

- [ ] **Step 1: Inspect the surrounding code (sanity)**

```bash
sed -n '1410,1435p' crates/epigraph-db/src/repos/claim.rs
```

Expected: the SELECT block from line 1416 with `AND is_current = true` on line 1420.

- [ ] **Step 2: Remove the single line**

Use the `Edit` tool to remove exactly the line `              AND is_current = true` (between `WHERE embedding IS NULL` and `              AND content NOT LIKE 'Agent sent message%'`).

- [ ] **Step 3: Verify only one line changed**

```bash
git diff -- crates/epigraph-db/src/repos/claim.rs
```

Expected: a single `-              AND is_current = true` deletion, nothing else. Verify other `is_current` references (lineage code at line 969+) are intact:

```bash
grep -c "is_current" crates/epigraph-db/src/repos/claim.rs
```

Expected: 6 (was 7 — exactly one occurrence dropped).

- [ ] **Step 4: Compile + clippy**

```bash
cargo check -p epigraph-db 2>&1 | tail -10
cargo clippy -p epigraph-db --lib -- -D warnings 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 5: Run the existing backfill test (which uses the schema default `is_current = true`, so removing the filter does not break the inclusion path)**

```bash
export DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_db_repo_test
cargo test -p epigraph-db --lib test_find_claims_needing_embeddings -- --test-threads=1 2>&1 | tail -10
```

Expected: pass. The test inserts a claim without explicitly setting `is_current`, so the schema default (TRUE per `migrations/001_initial_schema.sql:621`) keeps the inclusion-path assertion valid.

- [ ] **Step 6: Commit**

```bash
git add crates/epigraph-db/src/repos/claim.rs
git commit -m "fix(db): include superseded claims in embedding backfill candidates

Cherry-picked from epigraph-internal. Drops the AND is_current = true
filter from ClaimRepository::find_claims_needing_embeddings so
historical (superseded) claims with NULL embeddings also become
backfill targets — keeps embedding coverage uniform across claim
versions, which downstream similarity / recall pathways assume.

Other is_current references in claim.rs (lineage queries at
line 969+) are unchanged.

Existing test test_find_claims_needing_embeddings still passes
because the inserted fixture relies on the schema default
is_current = true (migrations/001_initial_schema.sql:621), so the
inclusion-path assertion is unaffected by the filter removal."
```

---

## Task 3: Workspace verification

- [ ] **Step 1: Scoped clippy**

```bash
cargo clippy -p epigraph-db --lib -- -D warnings 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 2: fmt-check**

```bash
cargo fmt --all -- --check
```

Expected: no diff.

- [ ] **Step 3: Full epigraph-db test suite against the test DB**

```bash
export DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_db_repo_test
cargo test -p epigraph-db -- --test-threads=1 2>&1 | tail -40
```

Expected: all green. Pay attention to:
- `divergence::tests` — 5 pass.
- `test_find_claims_needing_embeddings` — pass.
- Any lineage or version-related tests — pass (they touch `is_current` elsewhere; we did not modify those paths).

- [ ] **Step 4: Sanity-check downstream callers compile**

```bash
cargo check -p epigraph-api -p epigraph-mcp 2>&1 | tail -10
```

Expected: clean. The TTL change is invisible at compile time (signature unchanged); the embedding-backfill filter removal is invisible at compile time (same query shape).

---

## Task 4: Push and open PR

- [ ] **Step 1: Push**

```bash
git push -u origin feat/s5-db-repo-port
```

- [ ] **Step 2: Open PR (depends on nothing — base = main)**

```bash
gh pr create --title "feat: port DB repo deltas from epigraph-internal" --base main --body "$(cat <<'EOF'
## Summary
- Ports two narrowly scoped additions-only deltas in `crates/epigraph-db/src/repos/` from `epigraph-internal`.
- `divergence.rs`: adds 7-day TTL filter to `get_latest` / `top_divergent`, sanitizes the `pignistic_prob` argument of `store` (NaN, +/-inf, IEEE-754 `-0.0`, values outside [0,1]), adds 4 unit tests for the sanitizer.
- `claim.rs`: drops the `AND is_current = true` filter from `find_claims_needing_embeddings` so superseded claims also become embedding-backfill candidates.

## Behavior shifts visible to API/MCP callers
- `GET /belief/divergence/{claim_id}` (via `routes/belief.rs:2004`) and the MCP `query_divergence` tool (via `tools/ds.rs:434`) silently hide cached rows older than 7 days — intentional per the new TTL constant.
- `GET /belief/divergence/top` (via `routes/belief.rs:2027`) likewise filters stale rows.
- The MCP / API embedding-backfill endpoint now surfaces superseded claims with NULL embeddings, which previously were never backfilled.

## Out of scope
- `crates/epigraph-db/src/repos/edge.rs`, `paper.rs`, and the `pub mod paper;` registration in `repos/mod.rs` show as deletions in `git diff origin/main internal-main` because internal-main lacks the PR #14 extract-claims pipeline. They are kept as-is — slice 2 (PR #17) verified.
- Other `is_current` filters in `claim.rs` (lineage queries at line 969+) are unchanged.

## Test plan
- [x] `cargo fmt --all -- --check` clean
- [x] `cargo clippy -p epigraph-db --lib -- -D warnings` clean (workspace clippy has pre-existing baseline noise — not in scope)
- [x] `DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_db_repo_test cargo test -p epigraph-db -- --test-threads=1` — all green
- [x] `cargo check -p epigraph-api -p epigraph-mcp` — clean (downstream callers unaffected at compile time)

EOF
)"
```

---

## Self-Review Checklist

1. **Scope coverage:** divergence TTL + NaN-safe writes ported verbatim ✓; claim.rs single-line filter dropped ✓; 4 new sanitizer unit tests included ✓.

2. **Excluded scope held:** `repos/edge.rs`, `repos/paper.rs`, and `pub mod paper;` in `repos/mod.rs` NOT touched ✓; other `is_current` references in `claim.rs` NOT touched ✓.

3. **Faithful port:** verbatim `git show internal-main:` for `divergence.rs`; `Edit` tool for the single-line `claim.rs` change. The `safe_betp` ladder uses explicit `if/else if/else` comparisons (NOT `.clamp()`) to preserve the IEEE-754 `-0.0` fix.

4. **Verification:** clippy clean on `epigraph-db --lib`; full `epigraph-db` test suite green against the dedicated test DB; downstream `epigraph-api` and `epigraph-mcp` compile cleanly.

5. **PR body flags behavior shifts:** TTL hides stale rows from belief endpoints; embedding-backfill endpoint now surfaces superseded claims.
