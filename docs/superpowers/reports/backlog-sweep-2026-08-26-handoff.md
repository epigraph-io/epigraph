# Backlog sweep — handoff

**Session:** `aa3474ca-f068-42ea-bbb6-793e9c711028` · 2026-08-26/27
**Status at handoff:** loop halted by request after the fourth workflow round.
**Audience:** an agent system picking this up cold. Assume none of the originating context.

---

## 0. Read this first — three things that will waste your time otherwise

1. **`cargo` is not on `PATH`.** Every shell command must start with
   `export PATH="$HOME/.cargo/bin:$PATH"`. There is no `rustup`.
2. **There is no system PostgreSQL.** No `psql`, no `pg_isready`, no Homebrew, no Postgres.app.
   A database was stood up from a pip package — see §3. Without it, ~97 tests fail with an
   identical `DATABASE_URL must be set` panic, and that is *not* a regression.
3. **Another Claude session is working in this repo concurrently.** It owns the main working tree
   `/Users/jeremynano/Projects/epigraph` (branch `feat/multi-user-tenancy`) and a PostgreSQL
   instance on **port 55432**. Do not write to either. See §4.

---

## 1. Branches — what exists and what is at risk

| Branch | Worktree | Pushed? |
|---|---|---|
| `fix/backlog-sweep-2026-08-26` | `…/scratchpad/wt-backlog` | **NO** |
| `feat/blob-manifest-anchor` | `…/scratchpad/wt-blob` | **NO** |

**Durability status.** The *commits* are safe — worktrees share the object store in
`/Users/jeremynano/Projects/epigraph/.git`, which is not ephemeral. The *worktree directories*
are under `/private/tmp/claude-501/…/scratchpad/` and will be removed when the session's
temporary storage is reclaimed. When that happens the branches remain fully intact; the stale
worktree registrations are cleared with:

```bash
git -C /Users/jeremynano/Projects/epigraph worktree prune
```

**The one real risk: neither branch has a remote.** `git rev-parse origin/<branch>` fails for
both. If the local `.git` is lost, all of this work is lost with it. Pushing was deliberately not
done — it is an outward action that was never authorised. **This is the highest-value action for
whoever picks this up**, pending owner approval:

```bash
git -C /Users/jeremynano/Projects/epigraph push -u origin fix/backlog-sweep-2026-08-26
git -C /Users/jeremynano/Projects/epigraph push -u origin feat/blob-manifest-anchor
```

Both branches are based on `main` at `3948445`.

---

## 2. Rebuilding the toolchain

```bash
export PATH="$HOME/.cargo/bin:$PATH"        # cargo 1.98.0, clippy, cargo-sqlx all present
cd <worktree>
SQLX_OFFLINE=true cargo check --workspace --locked
SQLX_OFFLINE=true cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check                            # CI GATES ON THIS — see §5
```

`target/` is warm (~3.4 GB); incremental checks take seconds.

---

## 3. Rebuilding the database (it is ephemeral)

The cluster lives in `…/scratchpad/pgdata2` and does **not** survive session teardown. Recreate it:

```bash
# 1. self-contained PostgreSQL 16.2 binaries, no admin rights needed
python3 -m venv /tmp/pgvenv && /tmp/pgvenv/bin/pip install pgserver
PGB=/tmp/pgvenv/lib/python3.*/site-packages/pgserver/pginstall/bin
export PATH="$PGB:$PATH"

# 2. init and start on a port nothing else is using (NOT 55432 — see §4)
initdb -D /tmp/pgdata -U postgres --auth=trust
pg_ctl -D /tmp/pgdata -o "-p 55471 -h 127.0.0.1" -l /tmp/pg.log start

# 3. databases + extensions
createdb -h 127.0.0.1 -p 55471 -U postgres epigraph_db_repo_test
createdb -h 127.0.0.1 -p 55471 -U postgres epigraph_blob_test
psql -h 127.0.0.1 -p 55471 -U postgres -d epigraph_db_repo_test \
  -c 'CREATE EXTENSION IF NOT EXISTS vector;' \
  -c 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";' \
  -c 'CREATE EXTENSION IF NOT EXISTS pg_trgm;'

# 4. migrate
export DATABASE_URL="postgresql://postgres@127.0.0.1:55471/epigraph_db_repo_test"
export PATH="$HOME/.cargo/bin:$PATH"
SQLX_OFFLINE=true cargo run --bin epigraph-migrate
```

**Gotcha that costs an hour if you hit it blind.** The `pgserver` wheel ships only `plpgsql` and
`vector`. Migrations also need **`pg_trgm`** (`001_initial_schema.sql`, `020_workflows_table.sql`)
and **`uuid-ossp`**. If `CREATE EXTENSION pg_trgm` fails with *"extension is not available"*, copy
them from any fuller PG 16.2 install of the same platform:

```
cp <other>/share/postgresql/extension/pg_trgm*    <yours>/share/postgresql/extension/
cp <other>/lib/postgresql/pg_trgm.dylib           <yours>/lib/postgresql/
```

**Reference results with the DB up (branch `fix/backlog-sweep-2026-08-26`):**
`cargo test --workspace --lib --no-fail-fast` → **1859 passed, 0 failed**. Treat that as the
regression baseline. Without the DB the same command yields ~1757 passed / 97 failed, every
failure the same `DATABASE_URL` panic — environmental, not a code defect.

---

## 4. Standing hazards

**Port 55432 belongs to another session.** A second Claude session
(`6e343bd8-4322-4255-b803-c10131bb6624`) runs its own `pgserver` PostgreSQL there with the schema
fully migrated. `#[sqlx::test]` creates and drops databases as it runs — pointing `DATABASE_URL`
at 55432 would operate inside another agent's workspace. Always confirm before connecting:

```bash
lsof -nP -iTCP:<port> -sTCP:LISTEN
```

This nearly happened: a cluster started on 55432 bound only to IPv6 because the peer already held
IPv4, so `127.0.0.1` silently reached *their* server.

**Do not write to `/Users/jeremynano/Projects/epigraph`.** It is the peer session's working tree,
on `feat/multi-user-tenancy`. Read-only access is fine; use a `git worktree` for any edits.

**`recompute_beliefs` is unsafe on edge targets** until backlog `696d3a1c` is fixed. It discards
belief contributed by epistemic edges and silently reverts `contradicts`/`refutes` propagation,
returning `errors=[]`. Workaround: do not call it on any claim set containing `link_epistemic`
targets; rely on `classification` and `recall(exclude_contested=true)` instead. **14 epistemic
edges written by this session are affected.**

**No MCP write tool was called against the production graph during any implementation round.**
The graph is unmutated by the code work. The only graph writes this session made were the
deliberate backlog filings described in §5.

---

## 5. CI gates — the exact set

`.github/workflows/ci.yml` runs `cargo fmt --check` as a **blocking** step (line ~155). One round
of this sweep shipped a branch that was green on check/clippy/tests and still could not merge
because of 9 rustfmt hunks. Run all four, always:

```bash
SQLX_OFFLINE=true cargo check --workspace --locked
SQLX_OFFLINE=true cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo test --workspace --lib --no-fail-fast
```

Plus **offline parity**, which is the most likely way to break CI after touching SQL:

```bash
env -u DATABASE_URL SQLX_OFFLINE=true cargo check --workspace --locked
```

If you add or edit any `sqlx::query!` / `query_as!` macro you must run
`cargo sqlx prepare --workspace -- --tests` and commit `.sqlx/`.

---

## 6. Repo conventions that bite

From `CLAUDE.md`, learned the hard way during this sweep:

- All SQL lives in `crates/epigraph-db/src/repos/`. Routes and MCP tools call the repo layer.
- Do not widen `claim_from_row`'s signature — extend the caller's `SELECT` and post-fix the `Claim`.
- A new MCP tool must be added to the `#[tool_router]` impl in `epigraph-mcp/src/server.rs`
  **and** to `SCOPE_MAP` in `scope_map.rs`; a coverage test fails until both are done.
- Backlog retirement uses `resolve_backlog_item(original_id, resolution_content)` — never a
  free-text "Resolves &lt;uuid&gt;" claim alone, and never raw `update_labels` to add `resolved`.
- Commits follow the Epistemic Commit Protocol: `<type>(<scope>): <claim>` plus
  `**Evidence:**` / `**Reasoning:**` / `**Verification:**`.

---

## 7. Two failure modes this sweep produced — check for them in review

Both were caught by adversarial verification, not by the implementer, and both are easy to repeat.

**Inert code.** `1a79c4d9` added a per-type hash domain tag whose only caller was the trait's own
default. Every persisted digest still went through the untagged path, so the feature shipped with
zero live effect — while *also* changing digests in `epigraph-harvester`, which is in the Cargo
`exclude` list and therefore never compile-checked by CI. **Before accepting any new capability,
grep for its callers and confirm it is reachable on a live path.**

**Disabled by default.** `5e54282f` gated its whole code path on an embedder that returns `Err`
whenever the API key is absent or `"mock"` — which is how every DB-backed test constructs the
server. The logic was unreachable in 100% of existing tests, and the implementer recommended
setting the threshold to disable it on first deploy. **Confirm the tests exercise the ON path.**

A third pattern worth naming: **tautological tests**. Round 1's `9a0bd3e2` shipped four tests that
would have passed against the unfixed code. Later rounds required red-then-green proof — stash the
source hunk, observe the failure, restore, observe the pass.

---

## 8. Item ledger

**Graph index claim: `0e4b4b96-ffdf-4566-8b6e-ccf163d4c69a`** — the single durable, queryable record
of what landed where, with commit shas. Read it first.

**New defect found during the sweep: `152d9af6`** (priority-high). `belief_query::get_belief` with no
`frame_id` never reads the DS cache; it returns `cached_from_truth(truth_value)`, and both the tool
schema and the doc comment say otherwise. This is distinct from `696d3a1c` and the two mask each
other — fixing only `696d3a1c` will look like it did not work.

### RETIREMENT IS OUTSTANDING — action required

Nothing was retired. `resolve_backlog_item` failed with:

> claim is owned by agent `427aa492-…`; caller principal `149ea918-…` cannot retire it
> (requires claims:admin scope or ownership)

The MCP principal changed mid-session. Free-text "Resolves &lt;uuid&gt;" claims were deliberately NOT
filed as a substitute — per §6 those leave the original open in every backlog query forever. **An
owning agent or an admin must retire the completed items listed in `0e4b4b96`.**

### Verified SOUND — `fix/backlog-sweep-2026-08-26` (31 commits, 1873 tests, offline-clean)

| Item | What landed | Commit |
|---|---|---|
| `696d3a1c` | recompute_beliefs frame-name-ordered clobber | `22c1c7e1` |
| `cdd8d097` | get_neighborhood/traverse blind to non-claim nodes | `63e4ddd4` |
| `a85ee585` | query_claims `is_current` fabrication at two layers | `b1dd73e7` |
| `52eff3ab` | `shifted_to` edge — re-rank only, never moves belief | `eec703be` (mig 060) |
| `e09986c2` | additive `canonical_hash`, wire contract intact | `7b569f86` (mig 061) |
| `9a0bd3e2` | symmetric contradicts dedup | round 1 + 2 |
| `31c10a5a` | get_provenance depth/node caps | round 1 + 2 |
| `6ed02d04` | write-time contradiction staging | round 1 + 2 |
| `d4f1e8fa` | closure_basis as justifies edges | round 1 |
| `0a2ed32d` | `get_step_deviations` | round 1 |
| `dae795f8` | edge-writer inventory + drift guard | round 1 |

### Verified SOUND — `feat/blob-manifest-anchor` (7 commits, 1783 tests, offline-clean)

| Item | What landed | Migration / tools |
|---|---|---|
| — | blob store ported from episcience | `070`, `attach_blob` |
| `6e2364b8` | Merkle manifests over an immutable per-row subset | `071`, `export_subgraph_manifest`, `verify_manifest` |
| `94e62824` | mock-first anchoring of manifest roots | `072`, `anchor_manifest`, `verify_anchor` |
| `4b48ffb5` | obligation MVP — flagged as needing elaboration | `073`, `check_obligation` |

### NOT done

- **`7c909c49` essence binding.** Complete feasible design, skipped by an orchestration bug (the
  design agent returned track id `essence-binding`; the driver's order array looked up `essence`).
  Recorded verbatim in `backlog-sweep-2026-08-26-essence-design.md`. Decisions 17 and 18 are stale.

### Landed but NOT trustworthy — review before trusting

- **`1a79c4d9`** shipped **inert** — no caller outside the trait's own default, so every persisted
  digest still takes the untagged path. It also moves digests *and signature preimages* in
  `epigraph-harvester`, which is in the Cargo `exclude` list and therefore never compile-checked.
- **`5e54282f`** shipped **disabled** — gated on an embedder that returns `Err` whenever the API key
  is absent or `"mock"`, which is how every DB-backed test builds the server.

Both are revert-or-wire-up decisions, not retirements.

### Open non-blocking defects from round 4 verifiers (unfixed by the halt)

- blob: `mime_type` is validated only for emptiness yet echoed into responses — the unguarded twin
  of the filename bug the same commit fixed.
- manifest: `ManifestRepository::list_for_row` has zero production callers (dead code).
- anchor: `service.rs` mislabels `trust_basis` when the process backend differs from the row's.
- obligation: `declared_total` above `i32::MAX` truncates on store (no verdict is ever wrong).

The authoritative record is the graph itself. Query open items with:

```python
mcp__epigraph__query_claims_by_label(
    labels=["backlog"], exclude_labels=["resolved"], current_only=True,
)
```

Items filed by this session carry `epigraph-improvement`; the Ada-derived subset also carries
`ada-review-2026-08`.
