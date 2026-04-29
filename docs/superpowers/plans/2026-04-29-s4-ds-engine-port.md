# S4 DS / Engine Deltas Port — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the Slice 4 DS / engine deltas from `epigraph-internal` into `epigraph`. Forward-ports DS-level NaN safety and BetP clamp fixes (`combination.rs`, `measures.rs`), the engine-level CDST belief-propagation damping rewrite (`cdst_bp.rs`), and a small live-integration test fixture comment update. Also removes two legacy `epigraph-engine` modules (`belief_query.rs`, `recall.rs`) that internal already deleted and which have zero external callers in the public repo. Because those modules were the only consumers of two crate dependencies, the dep list also contracts: `epigraph-db` and `epigraph-embeddings` are dropped from `[dependencies]`.

**Architecture:** Pure content cherry-pick. Histories between public `epigraph` and `epigraph-internal` are disjoint, so we read internal-main file states with `git show internal-main:<path>` and apply them in the worktree. Slice scope is exactly the eight files in `git diff origin/main internal-main --stat -- crates/epigraph-ds/ crates/epigraph-engine/`.

**Tech Stack:** Rust workspace · sqlx 0.7 · Postgres · `epigraph-ds`, `epigraph-engine` crates · cargo. Tests use `DATABASE_URL`-gated integration harness.

**Base branch:** `origin/main`. Branch `feat/graph-communities` in the original checkout is irrelevant.

**Out of scope (do NOT touch):**
- `crates/epigraph-db/src/repos/paper.rs` — public-only, used by extract-claims pipeline.
- `crates/epigraph-db/src/repos/edge.rs::create_if_not_exists` — public-only, used by extract-claims pipeline.
- These appear in raw `git diff origin/main internal-main` as deletions (public has them, internal does not), but they are load-bearing on the public side and slices are explicitly directed to leave them alone.
- Anything outside `crates/epigraph-ds/` and `crates/epigraph-engine/`.

**Source refs (paste-ready git show targets):**
- `internal-main:crates/epigraph-ds/src/combination.rs`
- `internal-main:crates/epigraph-ds/src/measures.rs`
- `internal-main:crates/epigraph-engine/src/cdst_bp.rs`
- `internal-main:crates/epigraph-engine/src/lib.rs`
- `internal-main:crates/epigraph-engine/Cargo.toml`
- `internal-main:crates/epigraph-engine/tests/integration_live.rs`

---

## File Structure

**Modify (replace verbatim with internal-main version):**
- `crates/epigraph-ds/src/combination.rs` (+104 LOC) — NaN safety + open-world adaptive selector reroute (YagerOpen → Inagaki(γ=1.0)).
- `crates/epigraph-ds/src/measures.rs` (+61 LOC) — clamps in pignistic_probability + BetP regression tests.
- `crates/epigraph-engine/src/cdst_bp.rs` (+123 LOC) — linear-interp damping replaces discount+combine, BP convergence flag, cycle path tracing.
- `crates/epigraph-engine/tests/integration_live.rs` (+2 LOC) — comment fixup on test claim INSERT.
- `crates/epigraph-engine/src/lib.rs` (−4 LOC) — drop `pub mod belief_query`, `pub mod recall`, and the corresponding `pub use` re-exports.
- `crates/epigraph-engine/Cargo.toml` (−2 LOC) — drop `epigraph-db` and `epigraph-embeddings` from `[dependencies]`. Dev-deps `proptest` and `sqlx` are already present on origin/main; no change needed there.

**Delete:**
- `crates/epigraph-engine/src/belief_query.rs` (171 LOC) — module already absent in internal-main; zero external callers in public repo.
- `crates/epigraph-engine/src/recall.rs` (195 LOC) — same.

**Boundary rationale:** Each commit corresponds to one logical change so reviewers can see DS fixes, engine BP rewrite, and the legacy-module removal independently. The deletes + lib.rs update + Cargo.toml dep contraction must land in the right order to keep every intermediate commit compiling.

---

## Pre-Task: Worktree setup

- [x] **Step 1: Create isolated worktree off `origin/main`**

```bash
cd /home/jeremy/epigraph
git worktree add -b feat/s4-ds-engine-port /home/jeremy/epigraph-wt-ds-engine origin/main
cd /home/jeremy/epigraph-wt-ds-engine
git log --oneline -1
```

Expected: tip is `25e221a4 feat: port S1 noun-claim foundation from epigraph-internal (#16)`.

- [ ] **Step 2: Sanity-check baseline build**

```bash
cargo check -p epigraph-ds -p epigraph-engine
```

Expected: clean compile against origin/main. Any error here is unrelated to the port and must be investigated before proceeding.

- [ ] **Step 3: Verify zero external callers of soon-to-be-deleted symbols**

```bash
grep -rn "epigraph_engine::recall\|epigraph_engine::get_belief\|epigraph_engine::belief_query\|epigraph_engine::BeliefInterval\|epigraph_engine::BeliefQueryError\|epigraph_engine::RecallError\|epigraph_engine::RecallResult" --include='*.rs' .
```

Expected: no matches. The pre-flight grep performed during planning returned no matches; this step is a re-check from inside the worktree to make sure nothing has been added between the planning grep and execution.

---

## Task 1: Port `combination.rs`

**Files:**
- Modify: `crates/epigraph-ds/src/combination.rs`

- [ ] **Step 1: Pre-clobber check (no public-only divergence)**

```bash
git diff origin/main -- crates/epigraph-ds/src/combination.rs
```

Expected: empty (we just created the worktree off origin/main; sanity check).

- [ ] **Step 2: Replace with internal-main version verbatim**

```bash
git show internal-main:crates/epigraph-ds/src/combination.rs > crates/epigraph-ds/src/combination.rs
wc -l crates/epigraph-ds/src/combination.rs
```

Expected: 1727 lines.

- [ ] **Step 3: Compile**

```bash
cargo check -p epigraph-ds 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-ds/src/combination.rs
git commit -m "feat(ds): port NaN-safe combination + adaptive open-world reroute

Internal-main forward-ports clamp/NaN guards across the Dempster,
Yager, and Inagaki combiners and reroutes the adaptive selector's
YagerOpen regime to Inagaki(gamma=1.0). Vacuous focal pass-through
in the Yager open-world rule was inflating Pl as contradicting
evidence accumulated (the plausibility one-way ratchet);
Inagaki(gamma=1.0) sends all conflict K to the missing element so Pl
contracts correctly.

Tests renamed: combine_multiple_open_world_uses_yager became
combine_multiple_open_world_uses_inagaki_full and was tightened to
the new 0.6/0.9 disagreement fixture."
```

---

## Task 2: Port `measures.rs`

**Files:**
- Modify: `crates/epigraph-ds/src/measures.rs`

- [ ] **Step 1: Pre-clobber check**

```bash
git diff origin/main -- crates/epigraph-ds/src/measures.rs
```

Expected: empty.

- [ ] **Step 2: Replace verbatim**

```bash
git show internal-main:crates/epigraph-ds/src/measures.rs > crates/epigraph-ds/src/measures.rs
wc -l crates/epigraph-ds/src/measures.rs
```

Expected: 968 lines.

- [ ] **Step 3: Compile + run unit tests in the file**

```bash
cargo test -p epigraph-ds --lib measures 2>&1 | tail -15
```

Expected: all tests pass, including the new BetP-clamp regression tests.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-ds/src/measures.rs
git commit -m "feat(ds): clamp pignistic_probability into [0, 1]

Floating-point combination can produce tiny negative values (e.g.
-0.0) when non_classical_mass is near 1.0 and sum underflows; the
result was being persisted into the divergence cache verbatim. Use
explicit is_nan/!is_finite/<= 0.0 guards (clamp() preserves IEEE 754
-0.0 sign so it is unsuitable here) plus an explicit upper-bound
clamp at 1.0. Adds regression tests for high-ignorance frames where
missing mass approaches 1.0."
```

---

## Task 3: Port `cdst_bp.rs`

**Files:**
- Modify: `crates/epigraph-engine/src/cdst_bp.rs`

- [ ] **Step 1: Pre-clobber check**

```bash
git diff origin/main -- crates/epigraph-engine/src/cdst_bp.rs
```

Expected: empty.

- [ ] **Step 2: Replace verbatim**

```bash
git show internal-main:crates/epigraph-engine/src/cdst_bp.rs > crates/epigraph-engine/src/cdst_bp.rs
wc -l crates/epigraph-engine/src/cdst_bp.rs
```

Expected: 682 lines.

- [ ] **Step 3: Compile**

```bash
cargo check -p epigraph-engine 2>&1 | tail -10
```

Expected: clean. The file is still self-contained — it only depends on `epigraph-ds` types (`MassFunction`, `FocalElement`) and existing engine-internal modules, neither of which was touched.

- [ ] **Step 4: Run unit tests in the file**

```bash
cargo test -p epigraph-engine --lib cdst_bp 2>&1 | tail -20
```

Expected: all tests pass. The new `damp` linear-interp helper is exercised by the existing iteration tests; convergence-flag and cycle-path-tracing tests were added in the same internal commit (`6affb77f`) and ride along with the verbatim port.

- [ ] **Step 5: Commit**

```bash
git add crates/epigraph-engine/src/cdst_bp.rs
git commit -m "feat(engine): port linear-interp damping + BP convergence/cycle tracing

Replaces discount+combine damping with linear interpolation on focal
masses: m(A) = (1-d)*m_new(A) + d*m_old(A). The previous formulation
injected monotonic Theta mass each iteration so beliefs degenerated
toward vacuous beyond ~25 iterations and BetP oscillated; the linear
formulation has the evidence-combined belief as a fixed point so
max_iterations can be raised safely.

Also adds a BP convergence flag on CdstBpResult and a cycle-path
tracing field for graphs where messages do not converge within
max_iterations. Internal commit: 6affb77f."
```

---

## Task 4: Drop legacy `belief_query` + `recall` modules

These two files have zero external callers (verified in pre-task Step 3) and are absent from internal-main. Removing them, the matching `lib.rs` declarations, and the `pub use` re-exports must land in a single commit so each intermediate commit still compiles.

**Files:**
- Delete: `crates/epigraph-engine/src/belief_query.rs`
- Delete: `crates/epigraph-engine/src/recall.rs`
- Modify: `crates/epigraph-engine/src/lib.rs`

- [ ] **Step 1: Replace `lib.rs` with internal-main version verbatim**

The slice spec directs us to match `internal-main:lib.rs` exactly. Since neither slice 1 nor slice 3a touched `epigraph-engine/src/lib.rs`, a verbatim replace is safe. Verify:

```bash
git diff origin/main -- crates/epigraph-engine/src/lib.rs
```

Expected: empty. Then:

```bash
git show internal-main:crates/epigraph-engine/src/lib.rs > crates/epigraph-engine/src/lib.rs
```

- [ ] **Step 2: Delete the two module files**

```bash
git rm crates/epigraph-engine/src/belief_query.rs crates/epigraph-engine/src/recall.rs
```

- [ ] **Step 3: Compile**

```bash
cargo check -p epigraph-engine 2>&1 | tail -10
```

Expected: clean. If a downstream consumer surfaces here (it should not — pre-task Step 3 confirmed no external callers), STOP and inspect the unresolved-import error.

- [ ] **Step 4: Workspace check (gate)**

```bash
cargo check --workspace 2>&1 | tail -20
```

Expected: clean. The slice spec calls out workspace breakage as a red flag; this is the load-bearing gate before continuing.

- [ ] **Step 5: Commit**

```bash
git add crates/epigraph-engine/src/lib.rs
git commit -m "chore(engine): remove legacy belief_query and recall modules

Both modules were lifted from epigraph-mcp tools so episcience and
similar callers could invoke them without spawning MCP-over-stdio.
internal-main has already deleted them (callers migrated to the
direct repository helpers); the public repo has no remaining users
(verified by repo-wide grep for epigraph_engine::recall and
epigraph_engine::get_belief).

Removes the corresponding pub mod and pub use lines from lib.rs to
match internal-main:crates/epigraph-engine/src/lib.rs verbatim. The
crate-level [dependencies] contraction follows in a separate commit."
```

---

## Task 5: Drop `epigraph-db` + `epigraph-embeddings` deps

After Task 4, neither `epigraph-db` nor `epigraph-embeddings` has any remaining consumer in `epigraph-engine`. Internal-main's `Cargo.toml` reflects this. The slice spec mentions only `epigraph-db`, but a `git diff origin/main internal-main -- crates/epigraph-engine/Cargo.toml` shows `epigraph-embeddings` is also removed (sole consumer was `recall.rs`). Match internal-main exactly.

**Files:**
- Modify: `crates/epigraph-engine/Cargo.toml`

- [ ] **Step 1: Pre-clobber check**

```bash
git diff origin/main -- crates/epigraph-engine/Cargo.toml
```

Expected: empty.

- [ ] **Step 2: Replace verbatim**

```bash
git show internal-main:crates/epigraph-engine/Cargo.toml > crates/epigraph-engine/Cargo.toml
```

Verify the resulting `[dependencies]` block has no `epigraph-db` or `epigraph-embeddings` line and the `[dev-dependencies]` block contains both `proptest = { workspace = true }` and `sqlx = { workspace = true }`:

```bash
grep -E "epigraph-db|epigraph-embeddings|^proptest|^sqlx" crates/epigraph-engine/Cargo.toml
```

Expected: only the two dev-dependency lines for `proptest` and `sqlx` (under `[dev-dependencies]`).

- [ ] **Step 3: Compile + lockfile update**

```bash
cargo check -p epigraph-engine 2>&1 | tail -10
```

Expected: clean. `Cargo.lock` may update if no other crate still pulls `epigraph-db` or `epigraph-embeddings`, but workspace-wide they are consumed elsewhere so the lock should be stable.

- [ ] **Step 4: Workspace gate**

```bash
cargo check --workspace 2>&1 | tail -20
```

Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/epigraph-engine/Cargo.toml Cargo.lock
git commit -m "chore(engine): drop epigraph-db and epigraph-embeddings deps

Sole consumers of these dependencies were the legacy belief_query
and recall modules removed in the previous commit. Match
internal-main:crates/epigraph-engine/Cargo.toml exactly. Dev-deps
proptest and sqlx are already present on origin/main and remain.

Note: the slice spec called out only epigraph-db; epigraph-embeddings
is the sole-consumer-of-recall dep that the diff also removes."
```

---

## Task 6: Update `integration_live.rs` test fixture

**Files:**
- Modify: `crates/epigraph-engine/tests/integration_live.rs`

- [ ] **Step 1: Pre-clobber check**

```bash
git diff origin/main -- crates/epigraph-engine/tests/integration_live.rs
```

Expected: empty.

- [ ] **Step 2: Replace verbatim**

```bash
git show internal-main:crates/epigraph-engine/tests/integration_live.rs > crates/epigraph-engine/tests/integration_live.rs
wc -l crates/epigraph-engine/tests/integration_live.rs
```

Expected: 447 lines.

The internal version comments "migration 106's UNIQUE(content_hash, agent_id)"; in the public repo this constraint actually lives in `migrations/013_code_review_hardening.sql`. The previous public state already had a misnumbered "migration 097" reference that landed unchanged with S1; preserving the verbatim port keeps consistency with that precedent. The comment is informational, not load-bearing.

- [ ] **Step 3: Compile (test target)**

```bash
cargo test -p epigraph-engine --no-run 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/epigraph-engine/tests/integration_live.rs
git commit -m "test(engine): port integration_live test fixture comment

Updates the create_test_claim header comment to reflect the latest
constraint disposition note from internal-main. Internal-numbered
migration reference (106) carries over from the existing 097
reference imported in S1; migration numbers diverge between the
internal and public repos and renumbering is out of scope for the
S4 port."
```

---

## Task 7: Workspace verification

- [ ] **Step 1: Scoped clippy on touched crates (lib only)**

Workspace clippy has pre-existing baseline noise (`BayesianUpdater` deprecation in `propagation_tests.rs` and a borrow lint at `claim.rs:1888`) per the slice spec. Constrain the gate to `--lib` on the touched crates:

```bash
cargo clippy -p epigraph-ds -p epigraph-engine --lib -- -D warnings
```

Expected: clean. Mention pre-existing workspace clippy noise in the PR body.

- [ ] **Step 2: fmt-check**

```bash
cargo fmt --all -- --check
```

Expected: no diff. If diff: `cargo fmt --all` and add a `style: cargo fmt` commit.

- [ ] **Step 3: Workspace check**

```bash
cargo check --workspace 2>&1 | tail -20
```

Expected: clean.

- [ ] **Step 4: Run touched-crate tests against the test DB**

```bash
PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d postgres -c "SELECT 1 FROM pg_database WHERE datname='epigraph_ds_engine_test'" | grep -q 1 || \
  PGPASSWORD=epigraph psql -h 127.0.0.1 -U epigraph -d postgres -c "CREATE DATABASE epigraph_ds_engine_test OWNER epigraph;"
export DATABASE_URL=postgres://epigraph:epigraph@127.0.0.1:5432/epigraph_ds_engine_test
sqlx migrate run --source migrations
cargo test -p epigraph-ds -p epigraph-engine -- --test-threads=1 2>&1 | tail -40
```

Expected: all green. Watch for:
- New BetP-clamp regression tests in `epigraph-ds::measures`: green.
- Renamed open-world combine test (`combine_multiple_open_world_uses_inagaki_full`) in `epigraph-ds::combination`: green.
- `cdst_bp` damping/convergence tests: green.
- `integration_live.rs`: green (DB-backed, uses migration-097-style content_hash sha256 trick).
- No unresolved imports for `epigraph_engine::recall` etc.

---

## Task 8: Push and open PR

- [ ] **Step 1: Push**

```bash
git push -u origin feat/s4-ds-engine-port
```

- [ ] **Step 2: Open PR (independent of #16/#17 — touches different crates)**

```bash
gh pr create --title "feat: port DS/engine deltas from epigraph-internal" --base main --body "$(cat <<'EOF'
## Summary
- Forward-ports the S4 DS / engine deltas from `epigraph-internal`. Pure content cherry-pick.
- DS: NaN safety + adaptive open-world reroute in `combination.rs`; pignistic-probability clamp in `measures.rs`.
- Engine: linear-interp damping replaces discount+combine in `cdst_bp.rs`; BP convergence flag + cycle path tracing.
- Removes two legacy engine modules (`belief_query`, `recall`) that internal already deleted and that have zero external callers in this repo.
- Drops `epigraph-db` and `epigraph-embeddings` from `[dependencies]` (their sole consumers were the deleted modules).
- Test fixture comment update in `tests/integration_live.rs`.

## Scope (additions + targeted deletes)
- Modified: `crates/epigraph-ds/src/{combination,measures}.rs`, `crates/epigraph-engine/src/{cdst_bp,lib}.rs`, `crates/epigraph-engine/Cargo.toml`, `crates/epigraph-engine/tests/integration_live.rs`.
- Deleted: `crates/epigraph-engine/src/{belief_query,recall}.rs`. Repo-wide grep for `epigraph_engine::recall`, `epigraph_engine::get_belief`, `epigraph_engine::belief_query`, `epigraph_engine::BeliefInterval`, `epigraph_engine::BeliefQueryError`, `epigraph_engine::RecallError`, `epigraph_engine::RecallResult` returned no matches; safe to drop.

## Excluded (intentionally not touched)
- `crates/epigraph-db/src/repos/paper.rs` — public-only, used by extract-claims.
- `crates/epigraph-db/src/repos/edge.rs::create_if_not_exists` — public-only, used by extract-claims.
- These appear in raw `git diff origin/main internal-main` as deletions because public has them and internal does not, but they are load-bearing on the public side.

## Note on Cargo.toml dep contraction
- The slice spec called out dropping `epigraph-db`. The `git diff origin/main internal-main -- crates/epigraph-engine/Cargo.toml` reality also drops `epigraph-embeddings` — its sole consumer was `recall.rs`. Both deps land in this PR.

## Test plan
- [x] `cargo clippy -p epigraph-ds -p epigraph-engine --lib -- -D warnings` clean (lint scoped to touched crates per slice spec; workspace-wide clippy has pre-existing baseline noise from the `BayesianUpdater` deprecation in `propagation_tests.rs` and a borrow lint at `claim.rs:1888`).
- [x] `cargo fmt --all -- --check` clean.
- [x] `cargo check --workspace` clean (no external consumers broken by the legacy-module removal).
- [x] `DATABASE_URL=… cargo test -p epigraph-ds -p epigraph-engine -- --test-threads=1` all green.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review Checklist

1. **Scope coverage:** all 8 files in `git diff origin/main internal-main --stat -- crates/epigraph-ds/ crates/epigraph-engine/` are addressed. Two are deletes, six are file-replace ports.

2. **Excluded scope held:** no edits to `crates/epigraph-db/src/repos/paper.rs` or `crates/epigraph-db/src/repos/edge.rs`. No edits outside `epigraph-ds` and `epigraph-engine`.

3. **Order safety:** Task 4 ships file-deletes + lib.rs update in one commit so each commit compiles. Task 5 (Cargo.toml dep drop) follows Task 4 because the deps are still referenced until then.

4. **Verbatim ports:** every modified file is replaced with `git show internal-main:<path>` rather than diff-merged. None of these files have public-only sections — confirmed by inspecting `git diff origin/main internal-main` for each.

5. **No placeholders:** every step has the exact `git show` command or shell line and the commit message body.

6. **Lint scope match:** clippy uses `-p epigraph-ds -p epigraph-engine --lib -- -D warnings` exactly as the slice spec dictates.
