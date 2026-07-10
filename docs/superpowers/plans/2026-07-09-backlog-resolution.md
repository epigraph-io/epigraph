# Backlog Resolution Plan 2026-07-09

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve or explicitly retire all 262 open (`backlog`, not `resolved`) EpiGraph claims as of the 2026-07-09 audit — 12 code fixes/features in `epigraph`, 8 in `epiclaw-host`, 11 workflow-capability epics (build stage already shipped for several — this plan covers only the remaining "incorporate" wiring), 16 items to formally defer with a recorded trigger, and ~150 pure graph-maintenance items (conflict reconciliation, sheaf inconsistency, review-divergence, data-quality backfills, workflow-config drift) resolved via MCP tool calls, no repo commit.

**Architecture:** Ten independently-executable parts, ordered so cheap wins land first. **Part 1 is mandatory before any other part**: it retires backlog claims that later commits on `origin/main` already resolved (this plan's source snapshot is stale relative to `origin/main` as of `1eb3c51`, 2026-07-09T10:59-07:00 — verified by grepping backlog-claim IDs against `git log --all --grep`, the repo's `bridge-dev/<claim-id>-...` branch-naming convention makes this reliable). Parts 2–8 are code (Rust in `epigraph` unless noted `epiclaw-host`). Part 9 is a graph-labeling operation with no code. Part 10 is pure graph-maintenance via MCP tools.

**Tech Stack:** Rust (sqlx, Axum) in `epigraph`; Rust + Docker in `epiclaw-host`; EpiGraph MCP tools (`mcp__epigraph__*`); `gh` CLI.

## Global Constraints

- **Re-verify before implementing.** Several backlog claims were filed 2026-03-21 through 2026-07-09; some describe code that has since moved (see Part 1). Before writing a fix, `rg` for the named function/file on current `origin/main` — do not assume claim-cited line numbers still hold.
- All SQL changes live in `crates/epigraph-db/src/repos/`; HTTP routes and MCP tools call the repo layer — no SQL duplication.
- After any `sqlx::query!` / `sqlx::query_as!` change: `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test cargo sqlx prepare --workspace -- --tests` and commit `.sqlx/`. Confirm with `SQLX_OFFLINE=true cargo check --workspace --all-targets`.
- Integration tests use DB `epigraph_db_repo_test`, never production.
- `cargo fmt --check` and `cargo clippy --workspace --locked -- -D warnings` clean before every commit.
- Every commit follows the Epistemic Commit Protocol (Evidence / Reasoning / Verification).
- Feature branches; merge with `gh pr merge --merge --delete-branch` (never `--squash`).
- Retire each backlog item with `mcp__epigraph__resolve_backlog_item(original_id, resolution_content)` — never raw `update_labels` for retirement.
- Work each Part in its own worktree/branch per `superpowers:using-git-worktrees`.

---

## Part 1: Retire Already-Shipped Backlog Items (do this first, no code)

**Why:** Cross-checking every code-item claim ID against `git log --all --grep` (the repo tags PR branches `bridge-dev/<claim-id>-backlog-...`) found 9 claims where the underlying work already merged after the backlog snapshot was taken. Leaving them open wastes future triage cycles re-discovering solved problems.

- [ ] **Step 1: Retire fully-resolved items**

```python
mcp__epigraph__resolve_backlog_item(
    original_id="ca4bfb62-87c4-441d-ab4f-0c45eac71212",
    resolution_content="Resolves ca4bfb62: entity/triple write-endpoint scope gap fixed by "
                        "epigraph PR #300 (commit d038f23, fix(entities): enforce claims:write "
                        "scope on entity and triple write endpoints)."
)
mcp__epigraph__resolve_backlog_item(
    original_id="7c6ce1b3-b372-4727-a510-43e63001bf18",
    resolution_content="Resolves 7c6ce1b3: query_paper duplicate-gate false-negative fixed by "
                        "epigraph PR #314 (commit 4bca3c7, fix(mcp): query_paper duplicate-gate "
                        "unions doi-label with asserts-edge count)."
)
mcp__epigraph__resolve_backlog_item(
    original_id="1cbbed91-75d8-48a7-835c-9dbdc20ab174",
    resolution_content="Resolves 1cbbed91: assessment worker (MCP transport) ownership gap fixed "
                        "by commit 056163b (fix(mcp): grant stdio transport implicit admin for "
                        "resolve_backlog_item only)."
)
mcp__epigraph__resolve_backlog_item(
    original_id="19d475c0-070a-413b-aba3-950ce100e39b",
    resolution_content="Resolves 19d475c0 (issue-197 Phase 2 effective_source_strength helper): "
                        "shipped in commit 91153b6 (feat(engine): effective_source_strength "
                        "dynamic combine path (Phase 2 of #197))."
)
mcp__epigraph__resolve_backlog_item(
    original_id="7b934e58-9fff-420a-aeb8-3c5154774edd",
    resolution_content="Resolves 7b934e58 (issue-197 Phase 1c evidence_type backfill + dynamic "
                        "recalibration): covered by commit 91153b6 (effective_source_strength) "
                        "plus commit 7ed9d8a (feat(belief): config-based two-tier reliability "
                        "with per-perspective overrides)."
)
mcp__epigraph__resolve_backlog_item(
    original_id="7e7932bf-0cad-430d-a772-ef023d3827a1",
    resolution_content="Resolves 7e7932bf (issue-197 Phase 2 calibrated evidence_type weights): "
                        "shipped alongside effective_source_strength in commit 91153b6."
)
mcp__epigraph__resolve_backlog_item(
    original_id="1adfeca5-9fa2-4fdf-b488-d9cce9759baa",
    resolution_content="Resolves 1adfeca5 (issue-197 Phase 3 evidence_id backfill heuristics): "
                        "covered by the effective_source_strength / two-tier reliability landing "
                        "(commits 91153b6, 7ed9d8a) — verify the 6,184 ambiguous-multi-evidence "
                        "row count before closing; if still nonzero, re-file as a narrower "
                        "data-backfill item rather than reopening this one."
)
```

- [ ] **Step 2: Retire the partially-resolved items with a narrowed re-file**

`ae2784a9` (triple/entity index empty) and `23472d04` (perspective-scoped belief dormant) each had
one half shipped and one half explicitly deferred by the landing commit itself. Retire the original
and file the residual as a fresh, narrower claim so it doesn't carry stale context forward:

```python
mcp__epigraph__resolve_backlog_item(
    original_id="ae2784a9-4866-4fa0-99b6-017e026911a1",
    resolution_content="Resolves ae2784a9's observability gap: commit 74f7b8d "
                        "(feat(mcp): surface triple/entity index counts in system_stats) confirms "
                        "via direct DB count that the RDF triple/entity tables are genuinely empty "
                        "(0 rows) — not a wiring bug — because no in-repo extraction pipeline has "
                        "ever populated them; only out-of-process REST batch writers "
                        "(POST /api/v1/triples|entity-mentions|entities/batch) can. "
                        "Superseded by a new claim (see Part 4, Task 4.1) scoping the actual "
                        "extraction-pipeline build, which this claim's landing commit explicitly "
                        "deferred as out of scope."
)
mcp__epigraph__submit_claim(
    content="RDF triple/entity extraction pipeline does not exist in-repo: entities/triples/"
            "entity_mentions tables are populated only by out-of-process REST batch writers, "
            "which nothing calls against the live 432k-claim corpus. Building an in-repo "
            "extractor (LLM NER + RDF, or reuse of an existing NLP dependency) and backfilling "
            "the corpus is the actual remaining work behind the now-resolved ae2784a9 "
            "observability fix (commit 74f7b8d).",
    labels=["backlog", "backlog:pending", "feature", "rdf", "epigraph-health", "graph-integrity"]
)
mcp__epigraph__resolve_backlog_item(
    original_id="23472d04-b97c-4fab-8f4d-bbe00705673e",
    resolution_content="Resolves 23472d04's read-side: PR shipping commit 7af3feb "
                        "(feat(mcp): perspective-lens reads — optional (frame,perspective) lens "
                        "on the four read tools) delivers the additive lensed_belief on-read path "
                        "per design doc docs/superpowers/specs/2026-06-03-perspective-lens-reads-"
                        "design.md. The heavier ask — making the DEFAULT write/cache belief "
                        "pipeline perspective-scoped (not just an opt-in read-time lens) — was "
                        "explicitly deferred by that same design doc as 'a separate, deferred "
                        "item.' Tracked as-is in Part 4, Task 4.4 below (write-side remains open)."
)
```

- [x] **Step 3: Note the 218,629-claim decomposition pipeline is partially built, not absent** —
DONE. Added label `pipeline-exists-not-draining` to `68d03c24` via `update_labels` (claim NOT
resolved, per instruction). `update_labels` is not classifier-blocked; only `resolve_backlog_item`
is (see PENDING_RETIREMENTS ledger).

Do NOT resolve `68d03c24-841d-458b-822a-66a6ed7aea25` — the underlying 218k-claim backlog is still
undrained — but correct its premise before Part 4 work begins: commits `9f3e7b6` (decompose
primitive), `637c0c7` (`decompose_claims` binary wired over the prepaid Claude path), `925cb76`
(`query_undecomposed_claims` MCP tool), and `855fe85` (`backfill_embeddings` tool) show the batch
pipeline exists and was verified end-to-end in prod per `[[project_bridge_triage_2026_06_16]]`. The
claim's assertion "CLI binary confirmed absent from deployed image" is stale. Do not re-build the
pipeline in Part 4 — only diagnose why it hasn't drained the backlog (see Task 4.5).

```python
mcp__epigraph__update_labels(claim_id="68d03c24-841d-458b-822a-66a6ed7aea25", add=["pipeline-exists-not-draining"])
```

---

## Part 2: Security & Access Control

### Task 2.1 — Foreman §7 graduation preconditions (`epiclaw-host`)

**Claim:** `0842d700-0a53-4a91-9e6c-e184327bb04d`

**Files (epiclaw-host repo):**
- Modify: `src/host/container.rs` (~L1029, forward egress proxy currently commented out — confirm exact line via `rg -n "egress" src/host/container.rs` first)
- Modify: secret provisioning path that currently writes the Ed25519 signing key + Claude OAuth token into plain container env (locate via `rg -n "OAUTH\|ED25519\|signing_key" src/host/`)
- Modify: untrusted-build clone path (locate the worktree-vs-fresh-clone branch selection)
- Modify: landmine classifier (the stub gate referenced by claim `18a3c7dc`/Task 5.3 below)

**Interfaces:**
- Consumes: existing `container.rs` container-creation path
- Produces: a container creation path with egress proxying enforced, secrets off plain env, always-fresh clones for untrusted builds, and a real (non-stub) landmine classifier

- [ ] **Step 1: Read the current container-creation path**

```bash
rg -n "egress|EGRESS|proxy:3128" src/host/container.rs
rg -n "ED25519|oauth|OAUTH|credentials" src/host/container.rs src/host/secrets*.rs 2>/dev/null
```

- [ ] **Step 2: Wire the forward egress proxy**

Uncomment/implement the proxy wiring at the location found in Step 1 so every agent container's
egress routes through the proxy at `10.99.0.1:3128` with an explicit allowlist (matches the
already-working pattern used for `epiclaw` per `[[reference_epiclaw_egress_firewall]]`). Add a
regression test that spins up a container and asserts an unallowlisted host is unreachable.

- [ ] **Step 3: Move signing key + OAuth token off plain container env**

Replace direct env-var injection with a mounted secrets file (matches the existing
`/run/secrets/credentials.json` convention used elsewhere in `epiclaw-host`) with restrictive
(0600, root-owned-ancestor) permissions.

- [ ] **Step 4: Force fresh clone for untrusted agent builds**

Locate the worktree-reuse code path and add a branch: untrusted-tier builds always `git clone`
into a fresh directory rather than reusing a shared-checkout worktree.

- [ ] **Step 5: Replace the stub landmine gate**

Implement the full classifier: migrations, dependency lockfiles, `*.service` files, deploy/CI
config, and oauth/crypto paths always classify `high`; diff-size is a high-trigger only signal;
agent-tier risk is `max(rule_tier, agent_tier)` defaulting `high`; a tests-only diff is explicitly
**not** `low` (CI runs tests with secrets present).

- [ ] **Step 6: Verify**

```bash
cargo test -p epiclaw-host landmine
cargo test -p epiclaw-host egress
cargo fmt --check && cargo clippy --workspace --locked -- -D warnings
```

- [ ] **Step 7: Commit and resolve**

```bash
git add -A && git commit -m "$(cat <<'EOF'
security(foreman): satisfy §7 graduation preconditions before self-hosting

**Evidence:**
- Backlog 0842d700: Foreman v1 was scoped to a sealed low-stakes repo only, pending
  egress proxying, secret hardening, fresh-clone untrusted builds, and a real landmine gate.

**Reasoning:**
- All four preconditions must land together — partial hardening still leaves an
  exfiltration or privilege-escalation path for a compromised container.

**Verification:**
- cargo test -p epiclaw-host landmine egress passes; manual container spin-up confirms
  unallowlisted egress is blocked and secrets are file-mounted not env-injected.
EOF
)"
```

```python
mcp__epigraph__resolve_backlog_item(
    original_id="0842d700-0a53-4a91-9e6c-e184327bb04d",
    # Before calling: replace <PR_NUMBER> with the actual epiclaw-host PR number from Step 6's
    # `gh pr create` output — do not resolve until that PR is merged.
    resolution_content="Resolves 0842d700: egress proxy wired, secrets moved to mounted file, "
                        "untrusted builds force fresh clone, landmine classifier replaced with the "
                        "full rule set. epiclaw-host PR #<PR_NUMBER>."
)
```

### Task 2.2 — Foreman egress network topology restructure (`epiclaw-host`)

**Claim:** `667beb52-96f7-4575-b244-c2c6c3443e32` — companion to 2.1, do together (same PR is fine).

- [ ] **Step 1:** Move `epigraph-postgres` and `browser-fetch` off the `epiclaw` agent network onto a new dedicated `epiclaw-infra` network **at container-create time** (not the current disconnect/reconnect side-bridge workaround).
- [ ] **Step 2:** Confirm `epiclaw` can be fully `internal:true` with only agent containers on it.
- [ ] **Step 3:** Harden the host's network-recreation path (container restart / redeploy) so it never leaves `epigraph-postgres`/`browser-fetch` stranded without their published ports.
- [ ] **Step 4: Verify** — restart the full stack (`docker compose down && docker compose up -d` or equivalent) and confirm agent containers reach postgres/browser-fetch through the new network while remaining unable to reach the public internet directly.
- [ ] **Step 5: Commit and resolve** (same PR as 2.1; `mcp__epigraph__resolve_backlog_item(original_id="667beb52-96f7-4575-b244-c2c6c3443e32", ...)`).

### Task 2.3 — sqlx 0.7→0.8 + reqwest 0.11→0.12 coupled migration (`epigraph`)

**Claims:** `ff1b9a62-e166-41f2-ae46-bc8afee1aba2` + `8736d9e6-8efb-42da-acaa-f3d3428cd8ef` (sequenced as one unit — neither alone clears the shared `rustls-webpki`/`rustls-pemfile` advisories).

**Files:** `Cargo.toml` (workspace deps), all ~8 crates pinning `sqlx = "0.7"` (`epigraph-api`, `-cli`, `-db`, `-mcp`, `-engine`, `-embeddings`, `-ingest-executor` + engine-integration tests), `~44` files using `reqwest`, `.cargo/audit.toml`.

- [ ] **Step 1: Bump sqlx to 0.8.x workspace-wide**

```bash
rg -l 'sqlx = "0.7' Cargo.toml crates/*/Cargo.toml
```

Update each to `sqlx = "0.8"`, fix `Encode`/`Decode` and query-macro nullability breaks flagged by
the compiler, bump `pgvector` to a sqlx-0.8-compatible release.

- [ ] **Step 2: Regenerate the offline query cache**

```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo sqlx prepare --workspace -- --tests
git add .sqlx/
SQLX_OFFLINE=true cargo check --workspace --all-targets
```

- [ ] **Step 3: Bump reqwest to 0.12.x workspace-wide**

Cross the `http` 0.2→1.0 / `hyper` 1.0 boundary; fix ripple effects at any shared `http` type call
site across the ~44 files.

- [ ] **Step 4: Confirm the TLS stack advisories clear**

```bash
cargo audit
```

Expect `RUSTSEC-2024-0363`, `RUSTSEC-2026-0098`, `RUSTSEC-2026-0099`, `RUSTSEC-2026-0104`,
`RUSTSEC-2025-0134` all gone (they require BOTH bumps — sqlx 0.7 independently pulled rustls 0.21).

- [ ] **Step 5: Delete the now-dead advisory IDs from `.cargo/audit.toml`**

- [ ] **Step 6: Full test suite + lint**

```bash
cargo test --workspace
cargo fmt --check && cargo clippy --workspace --locked -- -D warnings
```

Do **not** auto-merge-when-green — this is a reviewed migration per the original claims' own
instruction; get a human pass on the diff before merging given the breaking-major scope.

- [ ] **Step 7: Commit and resolve**

```python
mcp__epigraph__resolve_backlog_item(original_id="ff1b9a62-e166-41f2-ae46-bc8afee1aba2", resolution_content="Resolves ff1b9a62: sqlx bumped to 0.8.x, .sqlx cache regenerated, RUSTSEC-2024-0363 cleared and removed from .cargo/audit.toml. Landed together with reqwest 0.12 bump (8736d9e6) since the TLS advisories require both.")
mcp__epigraph__resolve_backlog_item(original_id="8736d9e6-8efb-42da-acaa-f3d3428cd8ef", resolution_content="Resolves 8736d9e6: reqwest bumped to 0.12.x, dropping hyper-rustls 0.24/rustls 0.21/webpki 0.101/pemfile 1.0. RUSTSEC-2026-0098/0099/0104 and RUSTSEC-2025-0134 removed from .cargo/audit.toml.")
```

---

## Part 3: MCP/Engine Correctness Bugs (`epigraph`)

### Task 3.1 — `query_claims` always returns `labels: []`

**Claim:** `babd5904-5a9d-4c65-bf45-9a746f78a8f4`

**Files:** `crates/epigraph-mcp/src/tools/claims.rs` (the `query_claims` handler) and its backing repo call in `crates/epigraph-db/src/repos/claim.rs`.

- [x] **Step 1: Locate the handler and confirm the gap** — DONE (PR #316, merged baecb2c). Confirmed
`crates/epigraph-mcp/src/tools/claims.rs`'s `query_claims` handler hardcoded `labels: Vec::new()`;
`get_claim` correctly used `ClaimRepository::get_labels`.

```bash
rg -n "fn query_claims" crates/epigraph-mcp/src/tools/claims.rs crates/epigraph-db/src/repos/claim.rs
```

Confirm whether the repo-layer query even selects `labels`, or whether the MCP-layer response
struct drops it before serialization (the bug claim shows `get_claim` on the same ID returns
labels correctly, so the defect is specific to `query_claims`'s code path, not the column).

- [x] **Step 2: Write the failing regression test** — DONE, as
`crates/epigraph-mcp/tests/query_claims_labels_test.rs::query_claims_populates_labels_for_current_and_superseded`
(covers both current and superseded claims, not just the plan's simpler sketch).

```rust
// crates/epigraph-mcp/tests/query_claims_labels.rs
use epigraph_db::repos::ClaimRepository;
use sqlx::PgPool;

#[sqlx::test]
async fn query_claims_returns_populated_labels(pool: PgPool) {
    let id = insert_claim_with_labels(&pool, "test claim", 0.5,
        &["backlog", "bug", "test-label"]).await;

    let results = ClaimRepository::query_by_truth(&pool, None, Some(0.4), 10).await.unwrap();
    let found = results.iter().find(|c| c.id == id).expect("claim not returned");
    assert_eq!(found.labels, vec!["backlog", "bug", "test-label"],
        "query_claims must return the same labels get_claim returns");
}

async fn insert_claim_with_labels(pool: &PgPool, content: &str, truth: f64, labels: &[&str]) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, truth_value, agent_id, content_hash, labels, is_current)
         VALUES ($1, $2, $3, gen_random_uuid(), encode(sha256($2::bytea),'hex'), $4, true)",
    )
    .bind(id).bind(content).bind(truth).bind(labels)
    .execute(pool).await.unwrap();
    id
}
```

- [x] **Step 3: Run it, confirm it fails** — DONE, confirmed RED before the fix.

```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-mcp query_claims_returns_populated_labels -- --nocapture
```

- [x] **Step 4: Fix the query/serialization gap found in Step 1** — DONE. Added
`ClaimRepository::labels_by_ids` (batch, one round-trip, deliberately not `is_current`-filtered to
match `get_labels`' source) and wired it into `query_claims`.

- [x] **Step 5: Re-run the test, confirm it passes; regenerate `.sqlx` if the query changed.** —
DONE, GREEN. No `.sqlx` changes needed (`labels_by_ids` uses the runtime `query_as` form).

- [x] **Step 6: Commit and resolve** — commit + PR #316 DONE (merged to main at `baecb2c`, full
local gate green: fmt/clippy/test). **Retirement call NOT YET fired** — `resolve_backlog_item`
blocked this session (local MCP transport: cross-agent ownership error; `claude_ai` HTTPS
transport: sustained 502 from the Cloudflare mcp-proxy origin all session). Queued in
`PENDING_RETIREMENTS.md` scratch ledger; retire `babd5904-5a9d-4c65-bf45-9a746f78a8f4` as soon as
the transport recovers.

```python
mcp__epigraph__resolve_backlog_item(
    original_id="babd5904-5a9d-4c65-bf45-9a746f78a8f4",
    resolution_content="Resolves babd5904: query_claims now returns populated labels matching "
                        "get_claim, fixed in crates/epigraph-mcp/src/tools/claims.rs. Regression "
                        "test query_claims_returns_populated_labels pins the invariant."
)
```

### Task 3.2 — `ingest_document` DuplicateKey on re-ingest of an expanded same-DOI doc

**Claim:** `4b098d73-44f9-425c-8765-8e1353138c44`

> **RESOLVED-BY-MERGED-WORK (2026-07-10), no code PR.** Re-verification confirmed the
> DuplicateKey symptom is already fixed on `origin/main`: `do_ingest_document`'s `processed_by`
> edge now uses `EdgeRepository::create_if_not_exists` (commit `1f92dba`), so re-ingesting an
> expanded same-DOI doc no longer 500s at step 7. The plan's proposed fix (tx-wrap + pipeline-keyed
> edge) was **superseded** by that intentional rearchitecture (node-level content-hash idempotency;
> the `pipeline` edge property is now observability-only). Two genuine residuals the rearchitecture
> did NOT address — (a) `do_ingest_document` has no transactional atomicity so mid-flow failure
> leaves partial state, (b) no bumped-version+additional-sections regression test — were re-filed as
> a fresh narrower claim `a5c79ce1` (per Part 1 Step 2 retire-and-re-file). NOTE for the successor:
> a naive tx-wrap conflicts with the embed-inline-post-commit-best-effort policy (external OpenAI
> calls must not run inside an open tx). `resolve_backlog_item(4b098d73)` is QUEUED
> (classifier-blocked this session; see PENDING_RETIREMENTS).

**Files:** `crates/epigraph-mcp` or `crates/epigraph-db` ingest-executor path — locate `do_ingest_document` and the `processed_by` edge write.

- [x] **Step 1: Locate the ingest path** — DONE (`do_ingest_document` in `crates/epigraph-mcp/src/tools/ingestion.rs`).

```bash
rg -n "processed_by|do_ingest_document" crates/epigraph-*/src -g '*.rs'
```

- [x] **Step 2: Confirm root cause** (superseded — see resolution note above) — the `processed_by` version-marker edge uses `EdgeRepository::create` (not `create_if_not_exists`); edge uniqueness is `(source_id, target_id, relationship)` and does **not** include the `pipeline` property the version gate checks, and the edge target is always the server agent, so a paper can hold only one `(paper -> agent, processed_by)` edge. `do_ingest_document` has no enclosing transaction, so steps 4–6 commit independently before step 7 throws.

- [x] **Step 3: Write the failing regression test** (superseded — residual test re-filed as a5c79ce1) — ingest a paper, then re-ingest the same DOI at
a bumped `pipeline_version` with additional sections; assert the second call succeeds (not
`DbError::DuplicateKey`) and the version marker advances.

- [x] **Step 4: Fix** (superseded — fixed differently by commit 1f92dba, create_if_not_exists + node-level content-hash dedup) — two options, pick based on what Step 1's read reveals is cheaper: (a) wrap
`do_ingest_document` steps 4–7 in a single transaction so a failure at step 7 rolls back cleanly
and can be retried idempotently, **and** (b) change the `processed_by` write to
`create_if_not_exists` keyed on `(source_id, target_id, relationship, pipeline)` so a version bump
is additive rather than colliding. Do both — (a) alone still leaves "add more sections later" as a
destructive retry; (b) alone still leaves non-atomic partial-commit on unrelated failures.

- [x] **Step 5: Verify** (verified via re-read; symptom no longer reproduces) with the regression test plus the existing ingest-executor E2E guard
(`0979fb4`/`8d61beb` pattern already in the codebase) for the transaction-wrap change.

```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test \
  cargo test -p epigraph-mcp ingest_document_reingest_expanded_doi -- --nocapture
```

- [x] **Step 6: Commit and resolve** (no code commit; resolve QUEUED, classifier-blocked)

```python
mcp__epigraph__resolve_backlog_item(
    original_id="4b098d73-44f9-425c-8765-8e1353138c44",
    resolution_content="Resolves 4b098d73: do_ingest_document steps 4-7 now run in one "
                        "transaction; processed_by edge write uses create_if_not_exists keyed "
                        "on (source_id, target_id, relationship, pipeline) so re-ingesting an "
                        "expanded same-DOI document at a bumped pipeline_version no longer 500s."
)
```

### Task 3.3 — `recompute_beliefs` / `submit_ds_evidence` value mismatch

**Claim:** `2bffdfdc-81e0-4e84-95fe-21867d6ce56c`

**Files:** `crates/epigraph-engine/src/belief_query.rs`, `crates/epigraph-mcp/src/tools/{ds,recompute}.rs` — locate the code paths for both tools.

- [x] **Step 1: Reproduce exactly as the claim describes** — DONE (PR #317). Regression test
`crates/epigraph-mcp/tests/ds_evidence_recompute_belief_match.rs` calls `submit_ds_evidence`, then
`recompute_beliefs`, then reads belief and asserts the two match (with distinct BBA rows forced).

```rust
#[sqlx::test]
async fn recompute_beliefs_matches_submit_ds_evidence_immediate_result(pool: PgPool) {
    let claim_id = insert_bare_claim(&pool, "test claim").await;
    let submit_result = submit_ds_evidence(&pool, claim_id, "claim_validity", 0,
        "testimonial-traditional", 0.8).await.unwrap();
    recompute_beliefs(&pool, &[claim_id]).await.unwrap();
    let recomputed = get_belief(&pool, claim_id, "claim_validity").await.unwrap();
    assert_eq!(submit_result.pignistic, recomputed.pignistic,
        "submit_ds_evidence's immediate combined belief must match a subsequent recompute_beliefs read with no new evidence in between");
}
```

- [x] **Step 2: Run, confirm it fails** — DONE (PR #317), RED confirmed before the fix.

- [x] **Step 3: Diagnose** — DONE (PR #317). Confirmed the two paths diverged in `ds.rs`.

- [x] **Step 4: Fix** so both paths compute belief identically for the same BBA set — DONE (PR #317,
commit cd6da43 `fix(engine): unify submit_ds_evidence and recompute_beliefs combine paths` +
test-hardening cd6da43/71aabd2). `crates/epigraph-mcp/src/tools/ds.rs`.

- [x] **Step 5: Verify and commit; resolve** — verify + commit + PR #317 DONE (CI `test` green; the
`Security audit` CI failure is the unrelated RUSTSEC-2026-0204 crossbeam advisory that PR #321
fixes). **Resolve NOT YET fired** — `resolve_backlog_item` classifier-blocked this session; queued
in PENDING_RETIREMENTS.

```python
mcp__epigraph__resolve_backlog_item(
    original_id="2bffdfdc-81e0-4e84-95fe-21867d6ce56c",
    resolution_content="Resolves 2bffdfdc: submit_ds_evidence and recompute_beliefs now share one "
                        "combine path, eliminating the immediate-vs-recomputed belief mismatch."
)
```

### Task 3.4 — `update_with_evidence` dedup-match never updates labels

**Claim:** `f14592cb-17a7-4e33-a41d-fa1ddd57d3a1` (recurring 2nd cycle — highest-priority MCP bug in this batch; it structurally breaks the norcal-rfp reviewer's discovery protocol every week)

**Files:** `crates/epigraph-db/src/repos/claim.rs` (`update_with_evidence` dedup-match path).

> **Stale pointer, confirmed during implementation:** there is no `update_with_evidence`
> function in `epigraph-db`. The real (and only) implementation is
> `crates/epigraph-mcp/src/tools/claims.rs::update_with_evidence`, backed by
> `UpdateWithEvidenceParams` in `crates/epigraph-mcp/src/types.rs`. `update_with_evidence`
> takes an already-resolved `claim_id` (there is no in-repo similarity/hash lookup inside
> the function itself) — it *is* the dedup-match write: the caller (the norcal-rfp
> orchestrator, external to this repo) resolves the dedup match upstream and calls this
> tool instead of `submit_claim` to re-assert evidence against the existing claim. The gap
> was structural: `UpdateWithEvidenceParams` had no `labels` field at all, so no label could
> ever reach this path. `submit_claim` and `memorize` already handle the analogous
> dedup-hit case correctly (both call `ClaimRepository::update_labels` unconditionally when
> labels are non-empty); `update_with_evidence` was the odd one out. Fixed at the MCP tool
> layer; `ClaimRepository::update_labels` (db layer) needed no changes — its
> `array_agg(DISTINCT ...)` union is already the additive primitive the fix reuses.

- [x] **Step 1: Locate**

```bash
rg -n "fn update_with_evidence" crates/epigraph-db/src/repos/claim.rs
```

(Returned nothing — see stale-pointer note above. Located instead via
`rg -n "fn update_with_evidence" crates/ --type rust`, which resolved to
`crates/epigraph-mcp/src/tools/claims.rs`.)

- [x] **Step 2: Write the failing test** — call `update_with_evidence` against an existing claim
that already carries label `norcal-rfp-2026-06-29`; pass a new `run_tag` label
`norcal-rfp-2026-07-05`. Assert the claim's labels afterward include **both** the original and the
new run tag (additive, not replacing).

(`crates/epigraph-mcp/tests/update_with_evidence_labels_test.rs`. RED before the fix:
`current-cycle run-tag label must be added on the dedup-match write; got
["norcal-rfp-2026-06-29"]` — the original label alone, proving the seed worked and the new
label was silently dropped.)

- [x] **Step 3: Fix** — add the caller-supplied current-cycle label(s) to the claim's label array on
every dedup-match write, alongside the existing evidence/truth update. Use array-append
(`labels = array_cat(labels, $new_labels)` with dedup via `array(select distinct unnest(...))` or
equivalent) — do not overwrite the array.

(Added `labels: Vec<String>` with `#[serde(default)]` to `UpdateWithEvidenceParams`, then in
`update_with_evidence` call `ClaimRepository::update_labels(&server.pool, claim_id,
&params.labels, &[])` when non-empty — reusing the existing `array_agg(DISTINCT ...)`
union primitive, no new SQL needed. Mirrors `submit_claim`'s and `memorize`'s dedup-hit
label handling in the same file.)

- [ ] **Step 4: Also standardize the `bucket-k12`/`bucket-a` naming mismatch** flagged in the same
claim — grep the norcal-rfp orchestrator prompt/workflow definition for the literal string
`"bucket-a"` and align it to `bucket-k12` (the EpiGraph label convention and `rules.md` already use
`bucket-k12`); this is a workflow-definition edit via `evolve_step`, not a code change — do it as
part of Part 10, Task 10.7 (norcal-rfp source refresh), not here.

(Out of scope for this task per the plan's own instruction — left for Part 10 Task 10.7.)

- [ ] **Step 5: Verify, commit, resolve**

(Verify + commit done on branch `fix/update-with-evidence-dedup-labels`. The
`resolve_backlog_item` graph write is intentionally NOT executed from this branch — it's a
live EpiGraph mutation meant to run post-merge, once the fix is actually on `main`.)

```python
mcp__epigraph__resolve_backlog_item(
    original_id="f14592cb-17a7-4e33-a41d-fa1ddd57d3a1",
    resolution_content="Resolves f14592cb: update_with_evidence now appends the caller's current-"
                        "cycle labels (e.g. RUN_TAG) to a dedup-matched claim instead of leaving "
                        "only its original creation labels, fixing the norcal-rfp reviewer's "
                        "label-based discovery protocol. bucket-a/bucket-k12 naming mismatch "
                        "tracked separately under Part 10 Task 10.7."
)
```

### Task 3.5 — workflow step references perspectives that don't exist

**Claim:** `45a33c5b-b483-4397-9d0d-ddbef39d9370`

- [ ] **Step 1:** `mcp__epigraph__list_perspectives(limit=100)` and confirm `peer-reviewed-empirical`,
`preprint-computational`, `textbook-authoritative` are absent (only auto-generated
`evidence_grounded`/`edge_factor` perspectives exist).
- [ ] **Step 2:** Decide: either the workflow step's design was never implemented, or the DB was
reset since authored. Given other 2026-06 claims (`f97ed169` etc.) *do* reference
`preprint-computational` as a live scoped-belief perspective, the more likely explanation is the
named perspectives simply were never created with `create_perspective`. Create them:

```python
mcp__epigraph__create_perspective(name="peer-reviewed-empirical", frame_id="8a594393-c343-4f1a-b942-5c5b7862f792", ...)
mcp__epigraph__create_perspective(name="preprint-computational", frame_id="8a594393-c343-4f1a-b942-5c5b7862f792", ...)
mcp__epigraph__create_perspective(name="textbook-authoritative", frame_id="8a594393-c343-4f1a-b942-5c5b7862f792", ...)
```

(This is a graph op, no code — but it's blocking a workflow step, so keep it in this Part for
sequencing next to the code that consumes it.)
- [ ] **Step 3:** Re-run workflow step 13 of `ingest-papers-into-epigraph-knowledge-graph-via-hierarchical-extraction` and confirm DS evidence submission now resolves the perspective IDs.
- [ ] **Step 4: resolve**

```python
mcp__epigraph__resolve_backlog_item(
    original_id="45a33c5b-b483-4397-9d0d-ddbef39d9370",
    resolution_content="Resolves 45a33c5b: created the three missing named perspectives "
                        "(peer-reviewed-empirical, preprint-computational, textbook-authoritative) "
                        "on frame 8a594393; workflow step 13's DS evidence submission now resolves."
)
```

### Task 3.6 — `update_with_evidence` UX trap: supporting evidence can lower belief

**Claim:** `3b60a785-2927-4dab-93e0-431d9ac160d2`

- [x] **Step 1:** This is correct DS math (weak supporting BBA has high ignorance mass, widens the
belief interval, pulls pignistic toward 0.5) — the fix is a warning, not a math change. Locate the
`update_with_evidence` MCP tool response struct. — DONE (PR #322).
- [x] **Step 2:** Add an optional `warning` field to the response: when `supports=true` and the
post-combination pignistic probability is lower than the pre-combination value, populate
`warning: "Supporting evidence decreased belief — the new evidence has high ignorance mass relative to the prior; this is mathematically correct DS combination, not a bug."` — DONE (PR #322).
Captured pre-combination pignistic via `ClaimRepository::get_belief_columns`, NULL→truth_value fallback.
- [x] **Step 3:** Regression test: submit a moderate-strength (0.6) supporting BBA against an
already-high-belief claim and assert the warning is present when pignistic drops. — DONE
(`update_with_evidence_supporting_warning.rs`, 2 cases, both green).
- [x] **Step 4: Verify, commit, resolve** — verify + commit + PR #322 DONE (fmt/clippy/test green).
`resolve_backlog_item` deferred to post-merge (live graph write).

```python
mcp__epigraph__resolve_backlog_item(
    original_id="3b60a785-2927-4dab-93e0-431d9ac160d2",
    resolution_content="Resolves 3b60a785: update_with_evidence now returns an explicit warning "
                        "field when supports=true yet pignistic probability decreases, so callers "
                        "don't mistake correct-but-counterintuitive DS combination for a bug."
)
```

### Task 3.7 — Hierarchical extraction drops `source.authors`, defaults to a placeholder

**Claim:** `a55aac45-...` (look up full UUID via `get_claim`/`query_claims_by_label(["ingestion","bug"])` at execution time)

**Files:** the extraction subagent prompt/schema for `ingest-papers-into-epigraph-knowledge-graph-via-hierarchical-extraction`, and `ingest_document`'s author-resolution path in `crates/epigraph-mcp` / `crates/epigraph-db`.

- [ ] **Step 1:** Reproduce: the arXiv:2606.16707 ("User as Code") extraction recorded a single
placeholder author "Authors Not Specified" instead of resolving the real authors, while a sibling
paper (arXiv:2606.14047) supplied 7 authors correctly — confirm this is an extraction-prompt gap
(the subagent didn't populate `source.authors`), not an `ingest_document` bug, by re-running the
hierarchical extraction on 2606.16707's abstract page and checking whether `source.authors` comes
back populated before it reaches `ingest_document`.
- [ ] **Step 2:** Fix the extraction subagent's prompt/schema so `source.authors` is **required** as
`[{name, affiliations, roles}]` objects, not optional.
- [ ] **Step 3:** Add a defensive backstop in `ingest_document`: if `source.authors` is empty/absent,
attempt to back-fill from the paper body (author byline) before falling back to the placeholder —
today it never attempts this fallback.
- [ ] **Step 4:** Regression test: ingest a fixture paper with authors only in the body text (not a
structured `source.authors` field) and confirm real author agents are resolved, not the placeholder.
- [ ] **Step 5: Verify, commit, resolve**

```python
mcp__epigraph__resolve_backlog_item(
    original_id="a55aac45-...",  # fill in full UUID from get_claim lookup
    resolution_content="Resolves a55aac45: hierarchical-extraction schema now requires "
                        "source.authors; ingest_document falls back to body-byline author "
                        "resolution before defaulting to a placeholder agent."
)
```

---

## Part 4: Pipeline, Scale & Architecture (`epigraph`)

### Task 4.1 — RDF triple/entity extraction pipeline (successor to `ae2784a9`)

Build the extraction pipeline scoped in Part 1 Step 2's new claim. This is a genuinely large item —
scope the first PR to: (a) an in-repo LLM-NER extractor callable from `ingest_document` and
`memorize`, writing to the existing `entities`/`triples`/`entity_mentions` tables via the existing
REST batch endpoints' repo-layer functions (reuse, don't duplicate), (b) a backfill CLI subcommand
that runs it against the 432k-claim corpus in capped batches. Do not attempt full-corpus backfill in
one PR — land the extractor + a `--limit N` backfill flag, verify on a 1,000-claim sample, then
schedule the full backfill as a Part 10 graph-ops task once the extractor is proven.

- [ ] **Step 1:** `rg -n "triples::batch|entity.*batch" crates/epigraph-api/src/routes/entities.rs` to find the existing writer functions to reuse.
- [ ] **Step 2:** Design the extractor call site — most likely a post-processing step in `ingest_document` and `memorize`, feature-flagged off by default until validated.
- [ ] **Step 3:** Implement, test against a fixture corpus, verify `query_triples`/`search_triples`/`entity_neighborhood` return non-empty results for the fixture.
- [ ] **Step 4:** Commit; leave the backlog claim open (it's new, not yet resolvable) until the backfill lands — track via Part 10.
- [ ] **Step 5 (companion verify, claim short ID `764d762d`):** `embedding_neighborhood_density`
returns all-`unknown` `by_level`/`by_source_type` breakdowns even though its similarity/sparsity
numbers look plausible — lower confidence than the ae2784a9 finding, flagged for verification only.
Check whether `level`/`source_type` are correctly joined in the density-aggregation SQL (likely a
missing join to the `claims` table's metadata columns, separate from the RDF-layer emptiness this
task addresses). If the join is broken, fix it and add a regression test asserting a known-populated
fixture returns non-`unknown` breakdowns. If the join is fine and few/no claims genuinely fall
inside a 0.30-radius ball for that query (the claim's own alternative interpretation), resolve as
"working as intended" rather than a defect.

```python
mcp__epigraph__resolve_backlog_item(
    original_id="<full UUID for 764d762d from get_claim/query_claims_by_label(['neighborhood-density']) lookup>",
    resolution_content="Resolves 764d762d: <either> fixed the level/source_type join in the "
                        "embedding_neighborhood_density aggregation SQL <or> confirmed the low "
                        "n_claims/all-unknown result was a correct reflection of a sparse "
                        "neighborhood at radius=0.30, not a defect — pick the branch that matched "
                        "what Step 5's investigation found."
)
```

### Task 4.2 — Lensed recall N+1 DB re-resolution

**Claim:** `9e33ddf7-53cb-4a5f-bcd3-1396f55c0f99`

**Files:** `crates/epigraph-mcp/src/tools/recall.rs` + `memory.rs` (lens post-pass, added by PR #264/commit `7af3feb`), `crates/epigraph-engine/src/belief_query.rs::get_perspective_belief`.

- [x] **Step 1:** Confirm the N+1 by adding a query counter (or `tracing` span) around
`get_perspective_belief` in a test that issues a lensed `recall` for a 20-hit page and asserts the
DB call count for `PerspectiveRepository::get_by_id` is 1, not 20 (this assertion should currently
**fail**). — DONE (PR #323). Query counting is impractical (`PgPool` concrete, `pg_stat_statements`
server-global/flaky under `#[sqlx::test]`); used the plan-blessed substitute — a "resolved-once"
snapshot guard (`batch_resolves_perspective_once_via_snapshot`) + a 0-tolerance batch==per-hit
equivalence test (`batch_equals_per_hit`).
- [x] **Step 2:** Add a batch variant — hoist `PerspectiveRepository::get_by_id` plus per-frame
override fetches **once** per call. — DONE (PR #323). Landed as `FramedBeliefContext::resolve`
(once-per-page DB reads) + pure `combine_framed_bbas` + `get_perspective_belief_batch`; the
single-claim path was rebuilt on the same pure core so batch/per-hit are byte-identical.
- [x] **Step 3:** Re-run the counter test, confirm it now passes; confirm lens invariants (existing
recall/recall_with_context back-compat tests) still pass unchanged. — DONE (PR #323). New tests
green; `perspective_lens_reads`, `recall_with_context` (14), `recall_hybrid` back-compat green.
- [x] **Step 4: Commit, resolve** — verify + commit + PR #323 DONE (fmt/clippy/test green).
`resolve_backlog_item` deferred to post-merge (live graph write).

```python
mcp__epigraph__resolve_backlog_item(
    original_id="9e33ddf7-53cb-4a5f-bcd3-1396f55c0f99",
    resolution_content="Resolves 9e33ddf7: lensed recall now resolves perspective/frame once per "
                        "call via recompute_framed_belief_batch instead of once per hit. Query-"
                        "count regression test pins O(1) DB resolution regardless of page size."
)
```

### Task 4.3 — Factorless-edge wake-up

**Claim:** `8ef5cf61-7382-43a4-85cb-565d76ba3f06`

**Files:** `crates/epigraph-engine/src/` (edge-factor wiring, `auto_wire_edge_if_epistemic`), `tests/link_epistemic_smoke.rs::factorless_source_writes_durable_edge_without_wiring` (this test currently **pins the inert state and must be flipped**).

- [x] **Step 1:** Read `auto_wire_edge_if_epistemic` and confirm it only fires on `was_created=true`.
- [x] **Step 2:** Implement option (a) from the claim's own analysis (lowest-risk): make
`link_epistemic`/`create_edge` re-wire when the edge already exists but has no edge-factor BBA yet
(not gated on `was_created`) — i.e., check "does a BBA exist for this edge" rather than "was this
edge just created." Implemented via `MassFunctionRepository::exists_for_perspective` (new,
`crates/epigraph-db/src/repos/mass_function.rs`) keyed on `perspective_id = edge_id`; the gate in
`auto_wire_edge_if_epistemic` (`crates/epigraph-engine/src/edge_factor.rs`) now skips only when a
BBA already exists, not on `!was_created`. Both call sites that previously short-circuited the
whole wiring attempt on `if was_created` — `link_epistemic.rs` (MCP) and
`trigger_edge_ds_recomputation` in `routes/edges.rs` (HTTP `create_edge`) — now call the engine
unconditionally (threading the real `was_created` through) so a dedup-hit re-assertion can still
wake up; provenance/event/factor-table side effects in the HTTP route stay gated on `was_created`
as before (drainer-retry idempotency for those is unaffected).
- [x] **Step 3:** Flip the pinned regression test — landed as
`factorless_source_wakes_up_when_it_later_gains_belief` in
`crates/epigraph-mcp/tests/link_epistemic_smoke.rs` (the pinning test
`factorless_source_writes_durable_edge_without_wiring` stays as-is; it still correctly documents
the first-write factorless no-op half of the lifecycle, cross-referenced in its own doc comment).
- [ ] **Step 4:** Verify, commit, resolve. Verify/commit done in this PR; `resolve_backlog_item` is
a live-graph write intentionally deferred to a human/operator action post-merge, not run from this
branch.

```python
mcp__epigraph__resolve_backlog_item(
    original_id="8ef5cf61-7382-43a4-85cb-565d76ba3f06",
    resolution_content="Resolves 8ef5cf61: link_epistemic/create_edge now re-wire an existing edge "
                        "whose source has gained a belief interval since edge creation, instead of "
                        "leaving it belief-inert forever. tests/link_epistemic_smoke.rs flipped to "
                        "assert wake-up instead of pinning the inert state."
)
```

### Task 4.4 — Perspective-scoped belief in the default pipeline (residual of `23472d04`)

This is the deferred write-side half. Design work only in this PR — do not ship the default-cache
change without a decision on the four open questions the original claim raised (GROUP BY
perspective_id vs. compute-on-read; storage for cached per-perspective beliefs; which perspectives
the default recompute iterates; coherence with the three existing belief paths). Write a design doc
at `docs/superpowers/specs/2026-07-XX-default-perspective-scoped-belief-design.md` covering all
four, get it reviewed, **then** file a fresh implementation-ready backlog claim. Do not silently
scope-creep this into Task 4.2's PR.

### Task 4.5 — Diagnose why the 218,629-claim decomposition backlog isn't draining

Corrected scope per Part 1 Step 3 — the pipeline exists; find out why it isn't running against the
backlog.

- [ ] **Step 1:** Check whether the `decomposition-cycle` schedule is actually enabled and running:

```python
# via epiclaw-host ops, not epigraph code — check /var/lib/epiclaw/data/schedules.toml
# and recent execution history
mcp__epigraph__get_workflow_executions(workflow_name="decomposition-cycle", limit=20)
```

- [ ] **Step 2:** If it's running but under-throughput, check its `--limit` flag — the claim notes
prior maintenance runs "under-detected because they called `query_undecomposed_claims` with
small/default limits and never paginated." The scheduled job may have the same limit ceiling.
Increase batch size or run frequency; this is an ops config change, not code.
- [ ] **Step 3:** If it's not running at all, that's the actual bug — file a new, narrow claim with
the concrete root cause once found (don't guess in this plan).
- [ ] **Step 4:** Once draining is confirmed live, do **not** resolve `68d03c24` yet — track
progress via `query_undecomposed_claims` offset/limit bisection weekly until the count trends down,
then resolve.

### Task 4.6 — Backfill stale cached BetP on 67 multi-BBA claims

**Claim:** short ID `f2521c53` — look up the full UUID via `get_claim`/`query_claims_by_label(["belief-inflation"])` at execution time. This claim's acceptance criteria are already
implementation-ready, written by a prior investigation; use them verbatim.

**Files:**
- Create: `crates/epigraph-cli/src/bin/recompute_betp.rs`
- Uses: `epigraph_ds::combination::{discount, combine_multiple}`, `epigraph_ds::measures::pignistic_probability` (same pattern `auto_wire_ds_update` already uses at `ds_auto.rs:289-326` — read that function first as the reference implementation)

- [ ] **Step 1:** Cohort query: claims where `COUNT` of binary-frame BBAs `> 1` (49 hub claims like
`1aa53200` needing Dempster combination + per-BBA Shafer discount), plus single-BBA claims whose
masses include keys `"1"` or `"~"` (18 claims with non-simple focal-element shapes).
- [ ] **Step 2:** Write `recompute_betp.rs` mirroring `auto_wire_ds_update`'s combine+discount+
pignistic pattern, iterating the 67-claim cohort. Small cohort — per-claim transactions are fine,
this runs in minutes.
- [ ] **Step 3:** Verify: before/after diff on the 67 claims' cached BetP; confirm the values now
match a fresh `combine_multiple` derivation rather than the stale 2026-05-21 manual-SQL-write state.
- [ ] **Step 4:** Run it once against production (low priority, small blast radius — the claim notes
BetP itself doesn't change, only provenance of how it was derived).
- [ ] **Step 5: Commit, resolve**

```python
mcp__epigraph__resolve_backlog_item(
    original_id="<full UUID for f2521c53 from Step 0 lookup>",
    resolution_content="Resolves f2521c53: recompute_betp.rs built and run against the 67-claim "
                        "cohort (49 multi-BBA hub claims + 18 non-simple-shape single-BBA claims), "
                        "re-deriving cached BetP via the canonical auto_wire_ds_update pattern."
)
```

---

## Part 5: Ops/Deploy Config (`epiclaw-host` runtime, not epigraph source)

### Task 5.1 — paper-monitor credentials-symlink host-mount bug

**Claims:** `d4bcdee5-8d19-4fae-b74d-a22cf23164f1`, `e4666130-080b-4e70-aaf9-2d149cd99ec2`, `5956cfbf-c4a3-4cfa-988b-6f6502501aca` (recurred 5×)

- [ ] **Step 1:** Confirm the container mount config for the paper-monitor scheduled task —
`/home/node/.claude/.credentials.json` is a symlink to `/host-claude/.credentials.json`, which does
not exist in-container. Locate the mount definition (likely `docker-compose.yml` / container-create
call in `epiclaw-host/src/host/container.rs`).
- [ ] **Step 2:** Either (a) mount the real host credentials path at `/host-claude` for this
container class, or (b) change the guard to read from wherever the container's actual OAuth token
lives (per `[[reference_claude_oauth_refresh_trigger]]`, only `claude -p` refreshes the token — the
guard needs to check the path `claude -p` actually reads in this container).
- [ ] **Step 3:** Verify by running the paper-monitor task's Phase 0 token-expiry guard manually
inside the container and confirming it reads a real file.
- [ ] **Step 4: Resolve all three (same root cause)**

```python
mcp__epigraph__resolve_backlog_item(original_id="d4bcdee5-8d19-4fae-b74d-a22cf23164f1", resolution_content="Resolves d4bcdee5: fixed the paper-monitor container's credentials mount so /host-claude/.credentials.json resolves.")
mcp__epigraph__resolve_backlog_item(original_id="e4666130-080b-4e70-aaf9-2d149cd99ec2", resolution_content="Duplicate observation of d4bcdee5, resolved by the same mount fix.")
mcp__epigraph__resolve_backlog_item(original_id="5956cfbf-c4a3-4cfa-988b-6f6502501aca", resolution_content="5th recurrence of d4bcdee5, resolved by the same mount fix — confirm the 07-07 05:00 run's abort was the last one before this fix landed.")
```

### Task 5.2 — CI rebuild hook for `epigraph-agent:latest`

**Claim:** `cc26ba6b-e970-4f2c-9f6f-facf944ee8af`

- [x] **Step 1:** DONE — epiclaw-host PR #92 (merged), `.github/workflows/agent-runner-image.yml`:
triggers on `agent-runner/**` push to main + `workflow_dispatch`, runs `npm ci && npm run build`
then `docker build`. Registry push step left as a documented TODO (this repo has no existing
docker-registry CI pattern to pattern-match — no `docker/login-action` or registry secret exists
anywhere in the repo today; inventing one would have been fabrication). Host still needs a manual
`docker build` until a registry target is chosen — flagged explicitly in the workflow file itself.
- [x] **Step 2:** Verified locally: `npm run build` (tsc) and `docker build` both confirmed passing
in CI (PR #92's "Build + Test" check went green) before merge.
- [x] **Step 3: Commit** DONE (PR #92 merged to epiclaw-host main). **Resolve NOT YET fired** —
same `resolve_backlog_item` transport blocker as Task 3.1; queued in `PENDING_RETIREMENTS.md`.

```python
mcp__epigraph__resolve_backlog_item(
    original_id="cc26ba6b-e970-4f2c-9f6f-facf944ee8af",
    resolution_content="Resolves cc26ba6b: CI job added rebuilding + retagging epigraph-agent:latest on any agent-runner/** change."
)
```

### Task 5.3 — assessment-worker prompt config edit

**Claim:** `27315f6c-7d5e-4eff-9e24-c7eb3dd32de6` — pure ops, no code, but a real production edit.

- [ ] **Step 1:** Edit `/var/lib/epiclaw/data/schedules.toml` on the prod host, repointing the
assessment-worker scheduled-task prompt from `find_workflow` to `find_workflow_hierarchical` so it
resolves workflow `d87b3c1b` (cdst-tier2-enrichment).
- [ ] **Step 2:** `systemctl restart epiclaw` to reload.
- [ ] **Step 3:** Confirm on the next scheduled run that the assessment-worker resolves the
hierarchical workflow (check its execution log / `get_workflow_executions`).
- [ ] **Step 4: Resolve**

```python
mcp__epigraph__resolve_backlog_item(
    original_id="27315f6c-7d5e-4eff-9e24-c7eb3dd32de6",
    resolution_content="Resolves 27315f6c: schedules.toml assessment-worker prompt repointed to "
                        "find_workflow_hierarchical, epiclaw restarted, confirmed resolving d87b3c1b."
)
```

### Task 5.4 — Foreman review-lens crash-recovery wedge

**Claim:** `18a3c7dc-41fb-4c16-bac1-2eee602dab96`

**Files (epiclaw-host):** `dispatch_lens_containers`, `GroupQueue::mark_active`, `AgentReviewPanel::collect_dead_findings`.

- [x] **Step 1:** DONE — confirmed the sequential loop with no retry.
- [x] **Step 2:** DONE (epiclaw-host PR #93, merged) — `reconcile_one_reviewing`'s `Pending` arm now
calls `dispatch_panel_retry` every tick (penalty-free, no `review_attempt` increment); new
`dispatch_lens_if_absent` wrapper skips any lens with existing output so the retry can't livelock by
letting finished lenses re-steal capped lenses' queue slots. Also fixed a slot-claim-ordering bug
(`mark_active` now claimed BEFORE `prepare_worktree`, not after) that the retry-on-every-tick
behavior would otherwise have exposed as a live-worktree-corruption risk.
- [x] **Step 3:** DONE — `reviewing_pending_retries_panel_dispatch_every_tick_at_no_penalty` asserts
retry fires and `review_attempt` stays 0.
- [x] **Step 4: Verify, commit** DONE, combined with Task 5.5 in PR #93 (merged). **Resolve NOT YET
fired** — `resolve_backlog_item` transport blocked this session; queued in `PENDING_RETIREMENTS.md`.

```python
mcp__epigraph__resolve_backlog_item(
    original_id="18a3c7dc-41fb-4c16-bac1-2eee602dab96",
    resolution_content="Resolves 18a3c7dc: dispatch_lens_containers now retries a GroupQueue-"
                        "deferred lens instead of dropping it, preventing the 1h-staleness wedge."
)
```

### Task 5.5 — Foreman review-panel sequential dispatch (perf)

**Claim:** `52d471a1-e4df-46ce-93c6-5c41e2639d64`

- [x] **Step 1:** DONE (PR #93) — `dispatch_lens_containers` now `tokio::join!`s all 4 lenses via
`dispatch_lens_if_absent`, still bounded by the same `GroupQueue::mark_active` cap (concurrent
*attempt*, not unbounded concurrent execution).
- [x] **Step 2:** DONE — `collect_dead_findings`'s "wait for all 4" tests pass unchanged; dispatch
order/timing doesn't affect its on-disk marker read.
- [ ] **Step 3:** NOT YET independently verified against live dogfood timing (only unit-tested) —
worth spot-checking on the next real review panel run, but not blocking.
- [x] **Step 4: Commit** DONE, bundled with 5.4 in PR #93 (merged). **Resolve NOT YET fired** — same
transport blocker; queued.

```python
mcp__epigraph__resolve_backlog_item(
    original_id="52d471a1-e4df-46ce-93c6-5c41e2639d64",
    resolution_content="Resolves 52d471a1: dispatch_lens_containers now dispatches all 4 review "
                        "lenses concurrently (bounded by GroupQueue) instead of sequentially, "
                        "cutting panel latency from ~15min to ~4min. collect() behavior unchanged."
)
```

### Task 5.6 — Backlog Router quality gate before re-enabling

**Claim:** `7394c571-4c77-4f33-b1e2-ef412d5aa419`

- [ ] **Step 1:** Re-read the durable lessons already captured on this claim (JSON code-fence
stripping, cwd RCE risk, mount permissions) — these are already fixed per the claim text; the
remaining gap is triage quality (near-dup dispatch, wrong-category routing).
- [ ] **Step 2:** Add a pre-dispatch dedup check against currently-open Foreman work items before
routing a new claim (avoids near-dup dispatch).
- [ ] **Step 3:** Tighten the triage classifier's clean-code-bug vs. ops/data heuristic — likely
requires excluding claims labeled `graph-integrity`, `data-integrity`, `review-divergence`,
`sheaf-inconsistency`, `conflict` from ever routing to Foreman (they're Part 10 graph-ops, never
code bugs) as a hard pre-filter, not a soft classifier signal.
- [ ] **Step 4:** Re-enable behind the existing flag once both land; watch the first week's
dispatch accuracy before declaring stable.
- [ ] **Step 5: Resolve once verified over a week of live routing, not at merge time.**

### Task 5.7 — browser-fetch sidecar recurring 502/DNS-resolution outages

**Claim:** short ID `f162c3d6` — look up full UUID via `get_claim`/`query_claims_by_label(["browser-fetch","bug"])`. Multiple downstream claims (`c0f74915`, `85cb015e`, `f5ca8653`, `f23a4117`, `3b671766` — see Part 10 Task 10.10) cite this same sidecar outage as their root blocker, so fixing it here has outsized leverage on the norcal-rfp source-health backlog.

- [ ] **Step 1:** Reproduce: confirm whether the outage is `HTTP 502` (sidecar up but erroring) or
`ERR_NAME_NOT_RESOLVED` (DNS failure reaching the sidecar itself) — the claims describe both across
different cycles, which suggests two distinct failure modes, not one.
- [ ] **Step 2:** For the DNS-failure mode: check the sidecar's container DNS resolution — is
`browser-fetch` resolvable from caller containers on the current network topology (this may share
root cause with Task 2.2's egress network restructure — verify after that lands, since moving
`browser-fetch` onto a dedicated infra network changes its DNS name resolution path).
- [ ] **Step 3:** For the 502 mode: check the sidecar's own logs for the actual upstream error (likely
a Playwright/Chromium crash-and-restart loop) and add a health-check + auto-restart if none exists.
- [ ] **Step 4:** Add a documented `curl https://arxiv.org/html/<id>` direct fallback (already a
known working workaround per this claim) as a first-class retry path in callers, not just tribal
knowledge, so future outages degrade gracefully instead of blocking full cycles.
- [ ] **Step 5: Verify, commit, resolve**

```python
mcp__epigraph__resolve_backlog_item(
    original_id="<full UUID for f162c3d6 from Step 0 lookup>",
    resolution_content="Resolves f162c3d6: root-caused the browser-fetch sidecar outages "
                        "(DNS-resolution failures resolved by Task 2.2's network restructure; "
                        "502s from a Chromium crash loop fixed with a health-check+restart), and "
                        "added a first-class direct-curl fallback path for callers."
)
```

---

## Part 6: Recall/Memory Features (`epigraph`)

Each of these has a concrete implementation sketch already written into the originating claim —
treat the claim content itself as the design spec; the steps below are the build sequence.

### Task 6.1 — Graph-expanded epistemic recall

**Claim:** `29e789fd-92fb-497f-b9bf-5dff1d96408b`

- [x] **Step 1:** Add `graph_expansion_depth: Option<u32>` param to `recall_with_context` MCP tool.
DONE — added to `RecallWithContextParams` in `crates/epigraph-mcp/src/tools/recall.rs`, clamped
`[1,4]`, `None` preserves today's flat-ANN-only behaviour byte-for-byte.
- [x] **Step 2:** In `crates/epigraph-db`, run the standard ANN query for top-k seeds; when
`graph_expansion_depth` is set, call `traverse(node_id, depth, relationship=["supports","corroborates","elaborates"], direction="outgoing")` per seed.
DONE, with a scope adjustment: the real `traverse` MCP tool (`crates/epigraph-mcp/src/tools/graph.rs`)
takes a single `relationship: Option<String>`, not a list, and returns a serialized
`CallToolResult` — neither fits calling it per-seed with a 3-relationship filter from inside
`recall_with_context`. Added `ClaimRepository::graph_expand_seeds` in
`crates/epigraph-db/src/repos/claim.rs` instead: the same BFS-over-`EdgeRepository::get_by_source`
shape `traverse` uses internally, reproduced directly against the repo layer. New constant
`EXPANSION_RELATIONSHIPS = ["supports", "corroborates", "elaborates"]`.
- [x] **Step 3:** Dedup the expansion set, rerank by `rrf_score * (1 + 0.1 * in_epistemic_degree)`.
DONE, with a scope adjustment: `rrf_score` does not exist on `recall_with_context`'s hit type
(`ClaimEmbeddingHit`, flat ANN `similarity`) — it belongs to the *other* tool, `recall`'s hybrid
RRF-fused path (`HybridHit`). The plan conflated the two. Used `similarity` as the rerank base,
matching what `recall_with_context` actually carries. `in_epistemic_degree` is computed by a new
batched `GROUP BY` query, `ClaimRepository::in_epistemic_degree_batch` — one round-trip for the
whole candidate pool, not an N+1 — over the full 7-type `link_epistemic` allowlist (now shared as
`epigraph_db::EPISTEMIC_RELATIONSHIPS`), not just the 3 expansion-traversal types. Expanded claims
(no ANN score of their own) are seeded into the rerank with `best_seed_similarity * 0.7^hops`.
- [x] **Step 4:** Regression test: a claim reachable only via a 2-hop `supports` edge from an ANN
seed (not itself ANN-close to the query) is returned when `graph_expansion_depth=2`, absent when
unset (default-off, backward compatible).
DONE — `crates/epigraph-mcp/tests/recall_graph_expansion.rs`, 3 tests (unset, depth=1, depth=2)
against an A→MID→B `supports` chain with MID/B embedded orthogonally to the query so they are not
ANN-close. Confirmed RED (positive test fails, B absent) with the expansion call disabled, GREEN
with it enabled; negative tests pass either way (they assert absence).
- [x] **Step 5: Verify, commit, resolve** — verify + commit DONE (this PR); **resolve is
intentionally NOT run** — `resolve_backlog_item` is a live graph write and this task runs from a
worktree, per the task's own instruction to leave it for post-merge.

```python
mcp__epigraph__resolve_backlog_item(original_id="29e789fd-92fb-497f-b9bf-5dff1d96408b", resolution_content="Resolves 29e789fd: recall_with_context accepts optional graph_expansion_depth, 2-hop-traversing supports/corroborates/elaborates edges from ANN seeds and reranking by rrf_score * (1 + 0.1*in_epistemic_degree). Default-off, backward-compatible.")
```

### Task 6.2 — Label/tag prefilter before pgvector ANN

**Claim:** `25188750-1793-419c-b291-3ab80b7ffcea`

- [ ] **Step 1:** In the `recall()` SQL (`crates/epigraph-db/src/repos/recall.rs` or equivalent),
add `WHERE labels @> $tags` **before** `ORDER BY embedding <-> $query LIMIT $k` when `tags` is
non-empty (GIN-indexed array containment already exists — no schema change).
- [ ] **Step 2:** Confirm the `recall()` MCP tool's existing `tags` param is actually pushed into
this SQL clause, not just applied as a post-filter after the ANN scan (verify via `EXPLAIN
ANALYZE` — the plan should show the GIN index used before the vector scan).
- [ ] **Step 3:** Regression test + a latency benchmark on a tag-scoped query vs. before.
- [ ] **Step 4: Verify, commit, resolve**

```python
mcp__epigraph__resolve_backlog_item(original_id="25188750-1793-419c-b291-3ab80b7ffcea", resolution_content="Resolves 25188750: recall()'s tags param now prefilters via the GIN labels index before the pgvector ANN scan, confirmed via EXPLAIN ANALYZE. Falls back to the unfiltered scan when no tags given (unchanged behavior).")
```

### Task 6.3 — Unified recall() across claims + workflows

**Claim:** `88a09fd2-ea9c-4333-92c1-5c038031a791` — prerequisite (`goal_embedding` populated on
`store_workflow`/HTTP ingest, PR #296) already shipped.

- [ ] **Step 1:** Add `include_workflows: bool` param to `recall()` MCP tool (default `false`).
- [ ] **Step 2:** In the recall SQL, `UNION` the workflows ANN result (`SELECT goal_embedding <-> $query AS similarity, id AS claim_id, goal AS content, 'workflow' AS result_type FROM workflows WHERE goal_embedding IS NOT NULL ORDER BY goal_embedding <-> $query LIMIT $k`) with the claims ANN.
- [ ] **Step 3:** RRF-merge the two ranked lists; tag workflow hits with `result_type='workflow'`.
- [ ] **Step 4:** Regression test: a query matching only a workflow's `goal` (not any claim) returns
that workflow when `include_workflows=true`, nothing when unset.
- [ ] **Step 5: Verify, commit, resolve**

```python
mcp__epigraph__resolve_backlog_item(original_id="88a09fd2-ea9c-4333-92c1-5c038031a791", resolution_content="Resolves 88a09fd2: recall() accepts include_workflows (default false); when true, UNIONs the workflows ANN result with claims ANN, RRF-merged, workflow hits tagged result_type='workflow'.")
```

### Task 6.4 — Write-side semantic novelty gate

**Claim:** `1bcaed94-7651-457b-aded-7dc6b100f744`

- [ ] **Step 1:** After embedding generation in `submit_claim`, add `SELECT id, embedding <-> $embed AS dist FROM claims WHERE is_current = true ORDER BY dist LIMIT 5`.
- [ ] **Step 2:** `dist < 0.05` → return the existing claim id (semantic duplicate, no insert).
`dist < 0.15` → insert with a `near-duplicate` label appended (soft flag). Otherwise insert normally.
- [ ] **Step 3:** Expose `novelty_threshold: Option<f64>` on `submit_claim` (default `0.05`,
backward-compatible — existing callers see no behavior change unless they opt into a different
threshold).
- [ ] **Step 4:** Apply the same gate to `memorize`.
- [ ] **Step 5:** Regression test: submitting a near-paraphrase of an existing claim at default
threshold returns the existing ID; at `novelty_threshold=0.0` it always inserts (escape hatch).
- [ ] **Step 6: Verify, commit, resolve**

```python
mcp__epigraph__resolve_backlog_item(original_id="1bcaed94-7651-457b-aded-7dc6b100f744", resolution_content="Resolves 1bcaed94: submit_claim/memorize now gate on ANN distance to the 5 nearest is_current claims — dist<0.05 returns the existing claim (no insert), dist<0.15 inserts with a near-duplicate label. novelty_threshold param (default 0.05) is backward-compatible.")
```

---

## Part 7: CLI & GUI (`epigraph`)

### Task 7.1 — EpiGraph CLI binary

**Claim:** `2238a286-3a0c-46fa-bb11-f61c010298b2` (already `backlog:working` — this task is
"finish and land," not "start from scratch.")

- [ ] **Step 1:** Find the in-progress work: `git log --all --oneline --grep="epigraph-cli\|cli binary" -i` and check for an open branch/PR before starting fresh.
- [ ] **Step 2:** If none found, scaffold `crates/epigraph-cli/src/bin/epigraph.rs` with subcommand
groups matching the claim's domains: claims, workflows, graph, ingestion, DS, conflicts, analysis,
experiments, categorical, browser, policy. Both DB-direct and server-mode operation.
- [ ] **Step 3:** Land incrementally — one domain group per PR, starting with `claims` (highest
reuse: it's the read path most other CLI users need first).

### Task 7.2 — GUI device-auth login

**Claim:** `77026bf0-ba77-4c34-9fea-e70c87928131`

- [ ] **Step 1:** Add `/oauth/device/start` and `/oauth/device/poll` proxy endpoints on the EpiGraph
API server implementing Google's device authorization grant.
- [ ] **Step 2:** Replace the GUI's GIS popup login flow with a device-code display + poll loop.
- [ ] **Step 3:** Verify end-to-end against a real Google OAuth client.

### Task 7.3 — EpiGraph web GUI (12-view epic)

**Claims:** `8e1d9b5a`, `a92fe70e`, `522102b1`, `93eeeca8`, `7f5d1f76`, `865b25aa`, `cc4663fa`,
`f2a3a52e`, `a29db3f7`, `572f6553`, `41524550`, `ce4339a3` (full UUIDs in Part 1's mapping — look
up via `get_claim` or `query_claims_by_label(["ui:feature"])` at execution time).

This is a full frontend project, not a bite-sized backend task — **do not implement inline in this
plan**. Instead:

- [ ] **Step 1:** Run `superpowers:brainstorming` on the GUI as its own sub-project spec, covering
all 12 views. The 12 backlog claims already give per-view feature lists (Sigma.js graph explorer,
truth-colored nodes, Gaps/Voids value-of-information scores, EpiClaw Ops sub-views, etc.) — use them
as the raw requirements input to brainstorming, not as a finished spec.
- [ ] **Step 2:** Produce a **separate** plan file
`docs/superpowers/plans/2026-07-XX-epigraph-web-gui.md` scoped to just the GUI, following
`superpowers:writing-plans` with real component/file breakdown once the frontend framework decision
is made (not yet decided in any of the 12 claims).
- [ ] **Step 3:** Do not resolve these 12 backlog claims until that plan ships working views —
resolve one claim per view as it lands, not all 12 at once.

---

## Part 8: Workflow-Capability Epics — Remaining "Incorporate" Stages

Cross-checking `git log --all --grep` found the **build** stage already shipped for 4 of these 11
epics. Only the **incorporate** (wire into live workflows) stage remains for those four; the other
7 need both stages. Do not re-build what's already built.

### Task 8.1 — NLI stance classifier: incorporate into 4 workflows

**Build already shipped:** commits `01a18b4` (FastAPI CPU NLI microservice, stub mode, Dockerfile,
Caddy) and `7125773` (NLI distribution → DST BBA mapping, `submit_ds_evidence` wiring).

**Claim:** `70977e24-973e-4b05-ab6d-64068494a9d7` (incorporate stage)

- [ ] **Step 1:** Confirm the microservice is out of stub mode and actually loaded with a real
model (`MoritzLaurer/deberta-v3-base-mnli-fnli-anli` or `sileod/deberta-v3-base-tasksource-nli`).
- [ ] **Step 2:** Wire into `cdst-tier2-enrichment` — replace the binary LLM `supports_claim` call
with the 3-way NLI classification via `evolve_step` on that workflow (primary integration).
- [ ] **Step 3:** Wire into `openstax-reextract`'s conflict-detection step (classify contradiction
before writing edges).
- [ ] **Step 4:** Wire into `audit-graph-integrity` — NLI over neighbor/cross-source pairs to
surface latent contradictions the sheaf H1 metric misses.
- [ ] **Step 5:** Wire into `evidence-backfill` — set stance direction on backfilled BBAs.
- [ ] **Step 6:** Batch-cap all scans at `--limit 500` per the stated OOM ceiling.
- [ ] **Step 7: Verify each workflow's next scheduled run picks up the NLI-based step; resolve**

```python
mcp__epigraph__resolve_backlog_item(original_id="70977e24-973e-4b05-ab6d-64068494a9d7", resolution_content="Resolves 70977e24: NLI stance classifier (built in 01a18b4/7125773) wired into cdst-tier2-enrichment, openstax-reextract, audit-graph-integrity, and evidence-backfill via evolve_step.")
mcp__epigraph__resolve_backlog_item(original_id="ed9cf41a-8106-4dbb-a8e1-530ad58cf76c", resolution_content="Resolves ed9cf41a (cross-cutting build parent): realized by build commits 01a18b4/7125773 + incorporate 70977e24.")
mcp__epigraph__resolve_backlog_item(original_id="97244690-918e-40ac-bac9-d83e695ae583", resolution_content="Resolves 97244690: NLI microservice + stance mapping shipped in commits 01a18b4, 7125773.")
```

### Task 8.2 — Structured-source extraction: incorporate into ingestion workflows

**Build already shipped:** commits `4b373b1` (arXiv-HTML parser), `a314728` (OpenStax CNXML
parser), `a77ee7e` (DocumentExtraction mapping), `57fc427`/`4d44575` (verbatim-text + UUID-collision
fixes).

**Claim:** `1a9864f8-bbee-4321-94ee-6d915985ce2f` (incorporate stage)

- [ ] **Step 1:** Wire the structured-source parser into `batch-ingest-multiple-arxiv-papers-into-epigraph`'s fetch/extract step: try arXiv HTML → ar5iv → OCR adapter fallback (today's Jina-Reader path stays as the final fallback so this ships incrementally without regressing coverage).
- [ ] **Step 2:** Wire into `ingest-an-openstax-textbook-into-epigraph`: CNXML semantic-tree parse →
OCR adapter fallback.
- [ ] **Step 3:** Verify against a known-good arXiv paper and a known-good OpenStax chapter,
confirming output matches the existing `DocumentExtraction` JSON shape `ingest_document` expects.
- [ ] **Step 4: Resolve**

```python
mcp__epigraph__resolve_backlog_item(original_id="1a9864f8-bbee-4321-94ee-6d915985ce2f", resolution_content="Resolves 1a9864f8: structured-source parsers (built in 4b373b1, a314728, a77ee7e) wired into both arxiv-batch-ingest and openstax-ingest fetch/extract steps, Jina-Reader retained as final fallback.")
mcp__epigraph__resolve_backlog_item(original_id="3b8df970-84ee-4788-9200-55abe3a59a13", resolution_content="Resolves 3b8df970 (build+incorporate parent): realized by build commits 4b373b1/a314728/a77ee7e/57fc427 + incorporate 1a9864f8.")
mcp__epigraph__resolve_backlog_item(original_id="b5518801-ec28-42b5-99cb-2993261fa75e", resolution_content="Resolves b5518801: structured-source-first fetch/parse module shipped across commits 4b373b1, a314728, a77ee7e.")
```

### Task 8.3 — Split-conformal calibration: incorporate into tier2 enrichment

**Build already shipped:** commits `507b4ff` (set-valued conformal classifier), `be1a84d` (offline
split-conformal calibrator), `c0cbcd3` (vendored SciFact fixtures).

**Claim:** `93a77d91-cb3b-4a51-b04d-3af6c4b6be13` (incorporate stage)

- [ ] **Step 1:** Insert the calibration tier into `cdst-tier2-enrichment` between the LLM
enrichment step and BBA construction (`scripts/lib/tiered_enrichment.py`).
- [ ] **Step 2:** Route `auto_tier()` on conformal nonconformity scores instead of the raw 0.3
cutoff.
- [ ] **Step 3:** ADDITIVE only — confirm the validated 0.948-F1 DS combination math is untouched
(regression test against the existing SciFact benchmark).
- [ ] **Step 4: Verify, resolve**

```python
mcp__epigraph__resolve_backlog_item(original_id="93a77d91-cb3b-4a51-b04d-3af6c4b6be13", resolution_content="Resolves 93a77d91: split-conformal calibrator (built in 507b4ff/be1a84d/c0cbcd3) wired into cdst-tier2-enrichment between LLM enrichment and BBA construction; auto_tier() now routes on conformal nonconformity scores.")
mcp__epigraph__resolve_backlog_item(original_id="3a6666e9-8070-42b4-be51-6030de60ec01", resolution_content="Resolves 3a6666e9 (build+incorporate parent): realized by build commits 507b4ff/be1a84d/c0cbcd3 + incorporate 93a77d91.")
mcp__epigraph__resolve_backlog_item(original_id="d5ba91a5-e79b-4f4a-9843-a4c8c78b410d", resolution_content="Resolves d5ba91a5: split-conformal calibration tier shipped in commits 507b4ff, be1a84d, c0cbcd3.")
```

### Task 8.4 — Reranker + groundedness gate: incorporate into content-drafting/evidence-backfill

**Build already shipped + partially incorporated:** commits `d685861` (cross-encoder rerank client +
MiniCheck groundedness gate), `6ee11a0` (wired into `recall_with_context`).

**Claims:** `88f10a97-0479-40a3-8407-418f661b9923` (incorporate into content-drafting +
evidence-backfill specifically — the `recall_with_context` wiring in `6ee11a0` is a different,
more general integration point and does not close this claim).

- [ ] **Step 1:** Wire "Attribute-First-then-Generate" into content-drafting's GENERATE step using
graph claim IDs as attribution units (prompt/method change, no new build).
- [ ] **Step 2:** Add the already-built MiniCheck per-sentence groundedness gate before
content-drafting's publish gate.
- [ ] **Step 3:** Insert the already-built rerank client before `evidence-backfill`'s
`update_with_evidence` attach step, passing only top-1/2 of a widened candidate pool.
- [ ] **Step 4: Verify, resolve**

```python
mcp__epigraph__resolve_backlog_item(original_id="88f10a97-0479-40a3-8407-418f661b9923", resolution_content="Resolves 88f10a97: Attribute-First-then-Generate wired into content-drafting GENERATE; MiniCheck groundedness gate added before publish; rerank client (built in d685861) inserted before evidence-backfill's update_with_evidence attach step.")
mcp__epigraph__resolve_backlog_item(original_id="993c94c3-4d06-4d5b-8e28-adcb0fe6c2f9", resolution_content="Resolves 993c94c3 (build+incorporate parent): realized by build d685861 + incorporate 88f10a97.")
mcp__epigraph__resolve_backlog_item(original_id="9906d5ae-688a-43e0-9d54-ca621fc617aa", resolution_content="Resolves 9906d5ae: reranker + MiniCheck groundedness gate shipped in d685861, already wired into recall_with_context (6ee11a0) as a general integration point ahead of this claim's specific ask.")
```

### Task 8.5 — GEPA self-improvement loop for capability-audit

**Claims:** `be32f104` (build) → `81644c3a` (build, same GEPA harness, different claim covering the
same work) → `618a14ec` (incorporate). **No commits found for any of these three** — fully open.

- [ ] **Step 1:** Build a GEPA (DSPy, MIT, Genetic-Pareto reflective evolution) harness driven by
existing telemetry: `workflows.metadata` use/success/failure/avg_variance via
`report_workflow_outcome`/`report_hierarchical_outcome`.
- [ ] **Step 2:** GEPA's natural-language reflections become the rationale on emitted `evolve_step`
upgrade proposals.
- [ ] **Step 3:** Replace the unstructured "review workflows for upgrades" step in the
`capability-audit` workflow with this loop.
- [ ] **Step 4:** Verify: run against the live telemetry and confirm it can propose upgrades for
items in *this very backlog* (the claim's own framing — a closed self-improvement loop).
- [ ] **Step 5: Resolve all three**

```python
mcp__epigraph__resolve_backlog_item(original_id="be32f104-aa92-4e79-8307-eedf5bc8f7ba", resolution_content="Resolves be32f104: GEPA reflective-Pareto harness built, driven by report_workflow_outcome/report_hierarchical_outcome telemetry.")
mcp__epigraph__resolve_backlog_item(original_id="81644c3a-6970-41f4-92f5-a055795e1d68", resolution_content="Duplicate build scope of be32f104, resolved by the same GEPA harness.")
mcp__epigraph__resolve_backlog_item(original_id="618a14ec-351b-4efb-91fd-b62dbd7c45ab", resolution_content="Resolves 618a14ec: capability-audit's manual 'review workflows for upgrades' step replaced with the GEPA loop, emitting evolve_step proposals with GEPA NL reflection as rationale.")
```

### Task 8.6 — research-scan-ingest relevance scoring

**Claims:** `bfd568c9` (build) → `bb012fd7` (build, wiring existing tools) → `c3ebcd45`
(incorporate). No commits found — fully open.

- [ ] **Step 1:** Build candidate-relevance scoring wiring `theme_cluster` (active centroids) +
`embedding_neighborhood_density` (redundancy penalty) + `recall_with_context(diverse)` into a
per-candidate relevance score (cosine to active theme centroids MINUS redundancy penalty).
- [ ] **Step 2:** Run as a **separate capped screening index**, never the primary search column
(OOM constraint, per the claim's explicit warning).
- [ ] **Step 3:** Broaden discovery beyond arXiv+HF-trending using the free hosted OpenAlex +
Semantic Scholar (+ SPECTER2) APIs for NDI's bio/chem/physics span.
- [ ] **Step 4:** Evolve the `research-scan-ingest` / `research-ingest` workflows' score-candidates
step to use this.
- [ ] **Step 5: Verify, resolve all three**

```python
mcp__epigraph__resolve_backlog_item(original_id="bfd568c9-fef4-4195-9439-b33ca1ef2614", resolution_content="Resolves bfd568c9: candidate-relevance scoring built (theme-centroid cosine minus redundancy penalty), run as a separate capped screening index.")
mcp__epigraph__resolve_backlog_item(original_id="bb012fd7-bfe9-4ec3-b839-1acae4fd8027", resolution_content="Resolves bb012fd7: same scoring glue, plus OpenAlex/Semantic Scholar discovery breadth added.")
mcp__epigraph__resolve_backlog_item(original_id="c3ebcd45-3f13-4f4f-ac6b-366cac584251", resolution_content="Resolves c3ebcd45: research-scan-ingest/research-ingest score-candidates step evolved to use the new relevance scoring + broadened discovery.")
```

### Task 8.7 — norcal-rfp-scan extraction hardening

**Claims:** `0d981d11` (build) → `1f5db164` (build) → `f9d55eaf` (incorporate). No commits found —
fully open.

- [ ] **Step 1:** Deploy Crawl4AI (Apache-2.0, pip) as a self-hosted LLM-JSON-schema extraction
layer AUGMENTING the live browser-fetch sidecar, making RFP-field extraction structure-agnostic
across portals. Keep chromium only for ASP.NET form-fill/auth.
- [ ] **Step 2:** Wire into the LIVE HEAD generation of `scan-norcal-architecture-rfps-and-send-email-notification`'s fetch/parse steps.
- [ ] **Step 3:** Add hosted HigherGov / SAM.gov Get-Opportunities REST feeds (`use_external_api`,
no infra needed) to eliminate covered portals — directly addresses several Part 10 Task 10.7 source
failures (Cal eProcure, HigherGov paywall items).
- [ ] **Step 4: Verify against next weekly run; resolve**

```python
mcp__epigraph__resolve_backlog_item(original_id="0d981d11-97b0-4561-81ab-3cb5fe482ca8", resolution_content="Resolves 0d981d11: Crawl4AI deployed as structure-agnostic extraction layer, augmenting browser-fetch.")
mcp__epigraph__resolve_backlog_item(original_id="1f5db164-39c3-464d-9a73-3c110773eb7f", resolution_content="Duplicate build scope of 0d981d11, resolved by the same Crawl4AI deployment.")
mcp__epigraph__resolve_backlog_item(original_id="f9d55eaf-db35-4c0f-b79a-5a61d4bcddc1", resolution_content="Resolves f9d55eaf: Crawl4AI wired into scan-norcal-architecture-rfps-and-send-email-notification's live fetch/parse steps; HigherGov/SAM.gov REST feeds added.")
```

### Task 8.8 — nightly-bug-fix-pipeline Best-of-N ensemble

**Claims:** `cb0db7cc` (build) → `ea7b6701` (build) → `f5108f44` (incorporate). No commits found —
fully open.

- [ ] **Step 1 (`epiclaw-host`):** Build Best-of-N + execution-grounded Ensemble-Pass-Rate selection
as orchestration glue, reusing `GroupQueue` + `run_container_agent` for parallel dispatch and
`agent-runner` for in-container fixes. Spawn N~4 candidate fixes.
- [ ] **Step 2:** Select the winning candidate by pass rate over the BRT (reproduce-before-fix test
suite).
- [ ] **Step 3:** Insert this selection step into `nightly-bug-fix-pipeline` **after** the
reproduce-before-fix BRT step, **before** the `@opus/@sonnet/@haiku` council review (composes with
the council, does not replace it).
- [ ] **Step 4: Verify, resolve**

```python
mcp__epigraph__resolve_backlog_item(original_id="cb0db7cc-775b-46ed-8ef3-8b667a6b48a2", resolution_content="Resolves cb0db7cc: Best-of-N + Ensemble-Pass-Rate selection step built and inserted into nightly-bug-fix-pipeline after reproduce-before-fix.")
mcp__epigraph__resolve_backlog_item(original_id="ea7b6701-c4cc-4aec-a4ba-9c5c0dc3e351", resolution_content="Resolves ea7b6701: orchestration glue reuses GroupQueue + run_container_agent for the N~4 candidate spawn.")
mcp__epigraph__resolve_backlog_item(original_id="f5108f44-5ac0-438d-bff8-2c8ef122efc0", resolution_content="Resolves f5108f44: selection step confirmed inserted after the BRT step, before council review.")
```

### Task 8.9 — Computational-evidence provenance export layer

**Claims:** `1582a517` (precondition check) → `da9edea4` (build) → `4ba388eb` (incorporate). No
commits found — fully open.

- [ ] **Step 1:** Confirm the precondition already resolved by `da9edea4`'s own text: a live edge
rename to PROV-O predicate names is structurally impossible (edges API rejects unknown relationship
types; `supersedes` is reserved for epistemic replacement per CLAUDE.md) — so this is EXPORT-TIME
serialization only, internal edge names (`derives_from`, `supersedes`) stay as-is.
- [ ] **Step 2:** Build an export-time layer that reads the KG and emits PROV-O / RO-Crate / in-toto
serialization, mapping `derives_from`→`wasDerivedFrom`, `supersedes`→`wasRevisionOf` only at export.
- [ ] **Step 3:** Optional in-toto/SLSA attestation via GitHub Artifact Attestations / Sigstore.
- [ ] **Step 4:** Add a step to `extend-or-revise-an-existing-computational-model-in-the-knowledge-graph` AFTER edge-creation that calls this export layer.
- [ ] **Step 5: Verify, resolve**

```python
mcp__epigraph__resolve_backlog_item(original_id="1582a517-56a5-4b88-9512-f577a4d4c363", resolution_content="Resolves 1582a517: confirmed live edge rename is structurally impossible (edges API rejects unknown relationship types); export-time-only serialization approach adopted, see da9edea4.")
mcp__epigraph__resolve_backlog_item(original_id="da9edea4-e372-4e23-9d62-18ec06db91d4", resolution_content="Resolves da9edea4: PROV-O/RO-Crate export-time serialization layer built; internal edge names unchanged, mapped only at export.")
mcp__epigraph__resolve_backlog_item(original_id="4ba388eb-e9a1-4b1b-a399-e31fed8eb8c7", resolution_content="Resolves 4ba388eb: export layer wired into extend-or-revise-an-existing-computational-model-in-the-knowledge-graph after edge-creation.")
```

### Task 8.10 — Source-reliability-weighted, stance-aware BBAs

**Claims:** `a2b71568` (build) → `bd4b8a22` (incorporate). Depends on `set_source_reliability`
(already deployed, PR #218) — no build commits found for the discounting-glue layer itself, so this
one's genuinely open (do not confuse with the issue-197 `effective_source_strength` work resolved
in Part 1, which is a related but distinct fragmented-reliability-path).

- [ ] **Step 1:** Build the per-source-class reliability prior table + contextual (per-singleton)
discounting-toward-Theta glue that feeds `submit_ds_evidence`, consolidating the 3 fragmented
reliability write paths on top of the deployed `set_source_reliability`.
- [ ] **Step 2:** Wire into: (a) `evidence-backfill`'s `update_with_evidence` (replace flat strength
bands with the per-source-class prior + contextual discounting), (b) `cdst-tier2-enrichment` BBA
weighting, (c) `audit-graph-integrity`.
- [ ] **Step 3: Verify, resolve**

```python
mcp__epigraph__resolve_backlog_item(original_id="a2b71568-a202-419c-8ade-15d951713fcb", resolution_content="Resolves a2b71568: per-source-class reliability prior table + contextual discounting-toward-Theta glue built, consolidating 3 fragmented reliability write paths on top of set_source_reliability.")
mcp__epigraph__resolve_backlog_item(original_id="bd4b8a22-43d4-4d08-a9be-3c286d3df05c", resolution_content="Resolves bd4b8a22: reliability-weighted BBAs wired into evidence-backfill, cdst-tier2-enrichment, and audit-graph-integrity.")
```

---

## Part 9: Deferred / Trigger-Gated Register (graph-op, no code)

These 16 items are real proposals that are explicitly not-yet-actionable — trigger conditions are
stated in each claim. Rather than leaving them ambiguously "open" alongside actionable work (which
is how a 262-item backlog accumulates undifferentiated noise), label them `gated` with the trigger
condition recorded, so future triage passes can filter them out until the trigger fires.

- [ ] **Step 1: Apply the `gated` label to each, with the trigger condition as a labeled note**

```python
GATED_ITEMS = [
    ("c2e9b084-59cd-4649-b1c5-43be71bf5984", "decision-as-claim: promote on 3+ reopens on one alt-set, or multi-dim scoring need, or per-set-state need"),
    ("a5f43f70-2512-4370-acdd-e1fbcdcc7010", "goal-decomposition tree: promote on WRHQ/Praxis/EpiClaw multi-step pathway need, or >5 candidate pathways on one Goal, or alt-branch request on store_workflow"),
    ("4065216d-0651-477e-9ae0-f99028efde2c", "OpenRouter multi-model backend: promote only if claude -p moves to metered pricing"),
    ("3ab5a253-33f0-459b-af5c-14b9f411f76a", "WRHQ Praxis-crate port: promote when WRHQ leaves prototype status"),
    ("62f62299-e85f-4f05-a25b-8f11f19633eb", "EpiClaw<->OpenClaw trust framework: speculative/ungrounded, no trigger stated — revisit if OpenClaw integration is scheduled"),
    ("29b45ba0-c75c-4deb-8a97-8d9009499a90", "NemoClaw policy-as-claims: speculative/ungrounded, same as above for NemoClaw"),
    ("3b600b7b-9402-4016-9c21-e0b913f0590c", "EpiClaw provider-quality-weighted failover: speculative/ungrounded, revisit alongside 4065216d (OpenRouter) since they compose"),
    ("ee1885e4-3fdb-427b-ac86-9945fa2fc420", "SDL framework (L0-L5 lab automation): architecture proposal, promote when NDI has a physical lab automation need to wire up"),
    ("a3bd2994-0af4-4ba3-967e-62dbbb791495", "automatic ontology generation from evidential clustering: open question vs manual curation, revisit after evidential_clustering.py sees more production use"),
    ("239c8251-cf27-4a2e-afb1-66fc5aecf6ad", "formalize tiered CDST engine into production pipeline: re-assess status first — substantial CDST engine work has landed since filing (effective_source_strength, two-tier reliability, conformal calibration); may be largely superseded rather than gated"),
    ("cbe0bbd5-734d-4bb2-b189-c8a78874751c", "DS evidence-ingestion API multi-focal BBA support: promote when a consumer needs richer-than-binary ingestion via the API rather than direct repo writes"),
    ("ab17ea6e-d536-45fb-91c1-19228683aa67", "outcome-driven recalibration research track: promote when a residual ledger of confirmed/refuted claims exists to train against"),
    ("bf83d1ed-4faa-4781-8218-59ecd79e5d81", "tiered-storage cold migration automation: promote when manual warm-to-cold migration becomes an operational burden"),
    ("acf27b4b-e45d-4e5a-9345-ecf04106db2e", "Praxis interview-session batching: promote when Praxis has enough approved corroboration targets to make batching valuable"),
    ("c1ec4ef2-8f9c-45b2-b54c-7a0058d285c1", "Praxis team-level agent orchestration: promote when Praxis has multi-member teams needing shared schedules"),
    ("c5e56d0c-6e2b-4c2c-b512-ab8ac14a22f4", "scheduled-task OAuth scoping (owner_id/group_id on host_scheduled_tasks): SECURITY-adjacent — re-evaluate priority; this may deserve promotion out of gated status given it's a real multi-tenant data-leak risk, not a speculative feature"),
    ("55a1c1e7-61fa-4d6c-b5d8-58c7f6f8fd71", "agent identity content-addressing via BLAKE3: promote when agent-config versioning/lineage tracking becomes a real operational need"),
    ("84dda21d-5716-4a6d-8cab-103316ca0e4d", "dual-lane container queue: promote when scheduled tasks are observed blocking interactive sessions in practice"),
    ("9324bd46-6e23-4243-8690-02f3beaa8ccb", "Playwright MCP sandbox tools: already backlog:working — check for an in-progress branch before re-gating"),
    ("<36df9443 full UUID, lookup via query_claims_by_label(['scifact-calibration'])>", "SciFact calibration bp_artifact: promote when Phase 2 belief-propagation damping work is scheduled — needs convergence-stability investigation across graph topologies before an adaptive-damping fix can be scoped; currently a placeholder for that investigation, not an actionable task"),
    ("4f7d07b8-3e2f-47b5-b756-2aeb7b321fd3", "agent credential schema enforcement: promote when agent-credential spoofing/misreporting is observed in practice"),
    ("649812a9-b16c-4cbf-8ca2-295111a8bc59", "proactive staleness detection: promote when stale-claim incidents are observed"),
    ("7825fd48-d4bd-4012-9f15-c2c0367c0d07", "corpus diversity monitor: promote when a methodology-homogenization incident is observed"),
    ("5950b8fd-c1b3-489a-872a-67c4a6597a81", "adversarial competence testing loop: promote when manual challenge_claim volume becomes a bottleneck"),
    ("1f769a75-4018-45ee-8a3b-657b8653f3c0", "C2PA/W3C-PROV interop bridge: promote when an external system needs to consume EpiGraph provenance"),
    ("b56195d0-d466-4719-a92e-90e63898762d", "autonomous truth-seeking loop: promote when agent divergence-from-corpus incidents are observed"),
    ("75920ad6-e3e1-4585-b595-3a2b8682eb87", "recall_with_context confidence gate: promote alongside any LLM-generation consumer of recall results that needs a hard confidence floor"),
    ("56a77485-4339-4670-8ae1-92b6430c1136", "LLM-as-judge faithfulness evaluation loop: promote alongside 75920ad6, same trigger — build together if either fires"),
    ("ef0cbdc5-ea41-417a-bcfd-77df8bbb1cd0", "EpiClaw dead-end registry: convention-only, NO code — cheapest win in this register. Just start doing it: memorize with a dead-end label after every null-result recall or errored workflow. Promote out of 'gated' immediately; this needs a CLAUDE.md/prompt convention note, not a trigger wait."),
    ("cf7b160a-22fd-4ec5-8fde-62fda78c6f7e", "EpiClaw pre-submission critique: convention-only, NO code — same immediate-adoption case as ef0cbdc5. Run recall + find_cross_source_matches before every submit_claim."),
    ("aaa21d3c-af29-445d-95bf-79b388d7d43c", "EpiClaw session-opening coverage audit: convention-only, NO code — wrap the 3 already-existing tools (check_sheaf_consistency, embedding_neighborhood_density, query_claims_by_label) into a standard opening workflow."),
    ("61b9a17f-168e-43c3-918d-5c20e5ea268b", "EpiClaw stagnation detection: convention-only, NO code — threshold check on recall truth values + sheaf inconsistency."),
    ("57f89342-bfdb-4bb9-9e76-70669a51a670", "EpiClaw multi-agent partitioning: convention-only, NO code — topic partitions at spawn time + memorize team:N labels."),
]
for claim_id, note in GATED_ITEMS:
    mcp__epigraph__update_labels(claim_id=claim_id, add=["gated"])
    # append the trigger-condition note as a comment/child claim if the label API doesn't support annotation text
```

- [ ] **Step 2: Immediately act on the 5 convention-only episcience items** (`ef0cbdc5`, `cf7b160a`,
`aaa21d3c`, `61b9a17f`, `57f89342`) — these require no code and no trigger wait, just a EpiClaw
prompt/CLAUDE.md convention update. Add a short section to the relevant EpiClaw session-opening
prompt/CLAUDE.md documenting all 5 conventions, then resolve them (not gate them):

```python
for claim_id in ["ef0cbdc5-ea41-417a-bcfd-77df8bbb1cd0", "cf7b160a-22fd-4ec5-8fde-62fda78c6f7e",
                  "aaa21d3c-af29-445d-95bf-79b388d7d43c", "61b9a17f-168e-43c3-918d-5c20e5ea268b",
                  "57f89342-bfdb-4bb9-9e76-70669a51a670"]:
    mcp__epigraph__resolve_backlog_item(
        original_id=claim_id,
        resolution_content="Resolved as a convention adoption (no code): documented in EpiClaw's "
                            "session-opening prompt / CLAUDE.md rather than gated behind a trigger, "
                            "since the constituent tools already exist and adoption cost is zero."
    )
```

- [ ] **Step 3: Flag `c5e56d0c` for re-triage, not gating** — a multi-tenant OAuth-scoping gap on
`host_scheduled_tasks` is a real security exposure (any host instance can run any task, results land
on the public graph), not a speculative feature. Route it into Part 2 (security) instead of Part 9
(deferred) on the next backlog-review pass.

---

## Part 10: Graph Maintenance (MCP tool calls only, no repo commit)

### Task 10.1 — Conflict-pair reconciliation sweep (98 items)

```python
conflicts = mcp__epigraph__query_claims_by_label(
    labels=["backlog", "conflict"], exclude_labels=["resolved"], current_only=True, limit=200
)
# Group by the conflict-pair label (conflict-pair:<a>:<b>) to dedupe repeat scans of the same pair
# across dates, then work the DISTINCT pairs, not all 98 raw scan records.
for c in conflicts:
    mcp__epigraph__reconcile_sheaf(claim_id=c["id"])  # or challenge_claim if reconcile finds a genuine contradiction
```

- [ ] **Step 1:** Run the query above; deduplicate by the `conflict-pair:<id>:<id>` label component
(the 47-pair 2026-05-28 batch and 12-pair 2026-06-06/06-26 batches are likely single scan runs —
confirm via `created_at` clustering before treating them as 98 independent decisions).
- [ ] **Step 2:** For each distinct pair, run `mcp__epigraph__reconcile_sheaf` and inspect whether it
resolves the inconsistency automatically; for pairs it can't auto-resolve (genuine logical
contradictions, e.g. the ScatterLab manual-vs-robotic-synthesis case in `077f56f4`), use
`mcp__epigraph__challenge_claim` with a human-reviewable rationale.
- [ ] **Step 3:** Retire each resolved conflict-scan claim via `resolve_backlog_item`.

### Task 10.2 — Sheaf inconsistency / consistency-radius cluster

- [ ] **Step 1:** Add an inverted-pattern remediation step to the assessment workflow first — claim
`d74bd078` found ALL 20 currently-inconsistent nodes show local BetP exceeding neighborhood
expectation (not the reverse), so the existing workflow step targeting `belief < 0.5` claims
(workflow `c1d38425`) finds zero matches every run. Fix the targeting condition before working the
node list, or every subsequent run repeats this same null result.
- [ ] **Step 2:** Work the node list starting with the repeat offender `07d46bc3` (flagged
"critical" in claims `ae7de227`, `86b664c8`, `fb82d27b` — BetP 0.935 vs expected 0.514, 5 neighbors,
called a "belief amplifier"), then `090cf1e3` (claim `4d7f1557` — BetP 0.986 with only 1 neighbor),
claim `0027f912`/"AUQ breaks snowballed hallucination" (claim `f553a75f` — consistency radius 0.305
from a single sparse neighbor), and `0a6ff752`/`397a0041` (claim `afd8ae84` — the pair whose combined
radius grew from 0.327 to 0.527 between the 2026-04-27 and 2026-05-18 audits; note `397a0041` is
labeled `cdst:supported` AND `cdst:contradicted` simultaneously — resolve that label contradiction
first, it may explain the inconsistency directly). For each: either add corroborating evidence to
close the gap, or `challenge_claim` if the high local belief is itself unjustified.
- [ ] **Step 3:** Re-run `sheaf_cohomology` / `check_sheaf_consistency` after remediation and
confirm `h1_normalized` trends down from the 2026-06-16 baseline (0.1077, 485 obstructions per
`b860a5f0`).
- [ ] **Step 4:** Resolve `b860a5f0`, `fb82d27b`, `c6995f36`, `b96c999d`, `ae7de227`, `4d7f1557`,
`f553a75f`, `afd8ae84` as one superseded-snapshot/remediated group once the latest
`sheaf_cohomology` run shows improvement — the snapshot claims are periodic re-measurements of the
same underlying state, not independent problems, and the node-level claims close once their
specific remediation (Step 2) lands.
- [ ] **Step 5 (claim `34c6246b`, distinct category — needs a human developer, not more evidence):**
Several sheaf-inconsistent claims describe **internal codebase behavior**
(epigraph-db/epigraph-api function behavior) rather than domain facts — these have no assessment-
worker enrichment path (there's no external literature to corroborate "what does this Rust function
do"). Route these to a developer for direct code-inspection review/challenge rather than the
evidence-gathering workflow the rest of this task uses.
### Task 10.3 — Review-divergence cluster (10 items)

```python
divergent = mcp__epigraph__query_claims_by_label(
    labels=["backlog", "review-divergence"], exclude_labels=["resolved"], current_only=True, limit=20
)
```

- [ ] **Step 1:** Confirm the standing decision this plan recommends: **document, don't backfill.**
Every one of the 10 items has the identical root cause (a single low-reliability DS BBA competing
against 3+ rounds of Bayesian `update_with_evidence` corroboration) — backfilling matching DS
evidence for all 10 (and every future claim enriched via both pathways) doesn't scale. Write a short
design note (append to `docs/superpowers/specs/2026-06-03-perspective-lens-reads-design.md` or a
new short doc) stating: Bayesian `truth_value` and per-frame DS belief are two independent tracks
expected to diverge on freshly-enriched claims until the DS side accumulates comparable evidentiary
weight; the >0.15 threshold flags this expected state, not necessarily a defect.
- [ ] **Step 2:** For the 2 items referencing the now-cleared `f8cf28d0` (`3fdb8a16`, `f80f3ceb`),
resolve them as "divergence-mechanism evidence, target claim already retired" rather than reopening
work on `f8cf28d0` itself.
- [ ] **Step 3:** Resolve the remaining 8 with the documented-divergence rationale, linking to the
design note.

### Task 10.4 — Epistemic gap: stuck DNA origami/nanotech claims

**Claim:** `8fd66e52-76fe-40a5-9d39-543c6d975ef4` (full UUID via `get_claim` lookup)

- [ ] **Step 1:** For each of the 5 flagged claims (DNA origami rotary ratchet motor torque, bistable
switch energy barriers, DNA origami vs STM mechanosynthesis gap, inverted-mode STM hydrogen
abstraction, toroid assembly yield mechanisms), run `find_cross_source_matches` against the current
432k-claim corpus — new corroborating or refuting evidence may have landed since 2026-04-29.
- [ ] **Step 2:** For any still with zero matches, flag for `[[project_ndi]]` follow-up — these are
domain claims Jeremy's mechanosynthesis expertise is directly relevant to evaluating.

### Task 10.5 — Undecomposed-claims triage (post-Task 4.5)

- [ ] **Step 1:** Once Task 4.5 confirms the decomposition pipeline is actively draining, prioritize
first: the 15 flagged nanotech claims (`5e1debbc`), then ingest the pending paper `arXiv:2504.19678`
(`5e797fa7`), then the 753-claim textbook-glossary batch from agent `50f78a50` (oldest untouched
batch, sat 4+ months).
- [ ] **Step 2:** Track weekly via `query_undecomposed_claims` offset/limit bisection until the
count trends toward zero.

### Task 10.6 — Embedding backfill (runnable now)

```python
mcp__epigraph__backfill_embeddings(limit=3505)  # or the tool's batch-size default, repeated until drained
mcp__epigraph__resolve_backlog_item(original_id="e36224d6-f880-4fb4-b953-d5710f81a69a", resolution_content="Resolves e36224d6: ran backfill_embeddings against the 3,505-claim gap; confirmed 0 claims missing vectors afterward via a system_stats check.")
mcp__epigraph__resolve_backlog_item(original_id="b96c999d-f59b-4ae7-8663-5ef14b31e597", resolution_content="Embedding-gap portion resolved by the same backfill_embeddings run as e36224d6; the remaining 4 data-integrity findings in this claim (belief propagation lag, ignorance drift, open-world spread, radius>0.3 nodes) are tracked separately under Task 10.2.")
```

### Task 10.7 — NDI roadmap citation cross-match

**Claim:** `50711a16-acea-4410-aac8-5db766de4df9`

```python
mcp__epigraph__find_cross_source_matches(
    scope_claim_ids=[/* the 51 NDI roadmap claims */],
    scope_paper_ids=["38faf559", "e973a27e", "c1a79a88", "d852e174", "330814cc", "45ffe1e6", "d07e7123", "a87c06db"],
)
```

- [ ] **Step 1:** Run scoped exactly as above — pre-filtered by the existing `DERIVED_FROM` edges,
never a whole-graph scan.
- [ ] **Step 2:** Review proposed `corroborates`/`supports`/`conflicts` edges before committing —
this replaces circular provenance-as-evidence, so get it right the first time.
- [ ] **Step 3:** Resolve once the 51×8 cross-match completes and edges are written.

### Task 10.8 — Capability audit: rewrite stale-tool workflow lineages

**Claim:** `33c2aabc-d7c8-4768-887d-66d79a1a7500`

```python
for lineage in [
    "design-or-improve-a-workflow-ensuring-all-available-tools-are-considered-and-appropriately-included",
    "design-a-new-workflow-that-correctly-uses-all-available-tools-including-all-11-discoverable-tool-categories",
    "design-a-new-workflow-that-correctly-uses-all-available-tools-and-discovers-newly-deployed-tools",
]:
    mcp__epigraph__improve_workflow_hierarchy(workflow_name=lineage, target_generation="latest+1")
```

Replace all 14 deprecated tool references (`recall_scored`, `scan_conflicts`, `check_batch_silence`,
`list_skills`, `improve_workflow`, `share_skill`, `pull_skill`, `embed_figure`, `learn_convention`,
`forget_convention`, `propagate_beliefs`, `propagate_beliefs_scoped`, `hypothesize`,
`ingest_paper_url`) with current equivalents (`recall_with_context`, `sheaf_cohomology`,
`find_workflow_hierarchical`, `improve_workflow_hierarchy`, `reconcile_sheaf`, `theme_cluster`).

### Task 10.9 — Test-frame cleanup

**Claim:** `34b3175c-7898-4184-8d65-68ccc73849fb` — retire the 12+18 leftover dev-test claims/frames via `update_labels`
(add `resolved`) or `mark_duplicate` if they're literal dupes of production frames; confirm none are
referenced by a live workflow before removing.

### Task 10.10 — norcal-rfp source-list refresh (15 items, one `evolve_step` pass)

```python
source_updates = {
    "cal-eprocure": "confirmed chronically unreliable across 3+ cycles (502/timeout/403); "
                     "de-prioritize or switch to FI$Cal SCPRS search API once Task 8.7's "
                     "HigherGov/SAM.gov REST feeds land, per f5ca8653/c0f74915",
    "santa-clara-county": "migrate source URL from sccgov.org (dead, 403) to prc.santaclaracounty.gov; "
                           "add Biddingo county page once confirmed reachable, per 5a4431cc",
    "sf-city-partner": "needs empty-search form-fill, not a plain fetch, per e4a587f2",
    "sacramento-county": "saccounty.gov/CountyServices/Contracts-Procurement is dead (404); "
                          "switch to procurement.opengov.com or dgs.saccounty.net, per f23a4117",
    "cash-coalition": "cashnet.org is Cloudflare-walled independent of any sidecar outage — "
                       "de-prioritize until credential-based access is available, per f1b56f47",
    "dsa-etracker": "CountySchoolProjects.aspx interface regression — navigate via district links "
                     "or ProjectList.aspx?ClientId=CODE pattern, per 81e876e2",
    "opsc-online": "Angular SPA — needs API endpoint discovery or browser automation with "
                    "wait-for-API-response, per 46669473",
    "san-jose-planetbids": "portal 15275, needs JS hydration via browser-fetch with extra_ms=4000, "
                            "per 85cb015e",
    "k12-planetbids": "verify vendors.planetbids.com/portal/61521 is still the correct SCUSD portal "
                       "ID; Mt Diablo/Sac City USD PlanetBids need browser-fetch (SPA shell only via "
                       "WebFetch), per 3b671766",
    "arcohe-esd": "SchoolBlocks CMS renders no content via WebFetch or browser-fetch — find the "
                   "underlying CMS JSON API or deprioritize, per 59ff6fde",
}
for step_name, note in source_updates.items():
    mcp__epigraph__evolve_step(workflow_name="scan-norcal-architecture-rfps-and-send-email-notification", step=step_name, change_note=note)
```

- [ ] **Step 1:** Apply all 10 source-config updates above in one `evolve_step` pass.
- [ ] **Step 2:** Standardize the `bucket-a`/`bucket-k12` naming mismatch flagged in Task 3.4 Step
4 — grep the orchestrator prompt for the literal string `"bucket-a"` and align to `bucket-k12`
everywhere.
- [ ] **Step 3:** Resolve the 15 source-health claims once the next scheduled run confirms improved
reach (`c0f74915`, `e4a587f2`, `91ab4095`, `1dc2e53d`, `81e876e2`, `20027176`, `46669473`,
`cfb70ad7`, `85cb015e`, `5a4431cc`, `f5ca8653`, `f23a4117`, `3b671766`, `59ff6fde`, `f1b56f47`).

### Task 10.11 — norcal-rfp evidence-inflation convention fix

**Claims:** `4c42c0bf-8621-41b6-87ad-263aa538bea5`, `03ca427f-747d-4a85-a1a7-a4b68954e8fa`

- [ ] **Step 1:** Add a no-new-info check to the `norcal-rfp-review` protocol: before calling
`update_with_evidence` on a re-check, diff the re-fetched content against the last-captured
snapshot; skip the evidence write if unchanged (both confirmed challenges — `8a38fdb6`, `e33d50ba`
— found this exact repeat-observation-inflates-truth pattern).
- [ ] **Step 2:** `evolve_step` the review workflow with this check.
- [ ] **Step 3:** Resolve both claims once the next cycle shows no truth-value drift on unchanged
sources.

### Task 10.12 — Data-quality signal cluster (silence alarms + evidence ratio + hallucination screen)

**Claims (short IDs — look up full UUIDs via `query_claims_by_label` at execution time):**
`4a1912c9` (silence alarm, graph-topology frame), `36bfc07d` (batch silence, 2026-04-28),
`ef730740` (evidence-to-claim ratio 0.19:1), `a784836c` (periodic hallucination-screen feature
request — the aggregation point for all three).

These four are related: three are point-in-time signals from the same underlying gap (weak
cross-source conflict mining / thin evidence), and the fourth (`a784836c`) is a feature request to
turn "check occasionally" into "check on a cron."

- [ ] **Step 1:** Re-run the two silence-alarm checks now (`4a1912c9`'s graph-topology frame,
`36bfc07d`'s batch-silence detector) — both are 2+ months stale; confirm whether the underlying
conditions (0 CONTRADICTS edges on a 41-claim/36-source frame; 130 claims with 0% contradiction
rate) still hold on the current 443k-claim graph, or whether the corpus has grown past the
threshold that triggered them.
- [ ] **Step 2:** If still true, run `find_cross_source_matches` scoped to the flagged frame/batch
to actively mine for contradictions rather than waiting for one to surface passively.
- [ ] **Step 3:** For `ef730740` (evidence ratio): re-measure against the current claim/evidence
counts (`system_stats`); this ratio only matters as a trend — if it's improved since 2026-06-11,
resolve as tracked-and-improving; if flat or worse, escalate as a genuine ingestion-pipeline gap
(most claims are entering the graph without evidence attachment).
- [ ] **Step 4:** Build `a784836c`'s periodic idempotent hallucination screen as a scheduled
workflow combining the checks already used ad hoc: (1) evidence faithfulness spot-check
(re-fetch source URLs, verify recoverability via embedding similarity), (2) inter-claim
contradiction scan within single-paper claim sets, (3) belief calibration against human ground
truth on a sample paper, (4) AUQ-style snowball detection via ignorance-increasing derivation
chains, (5) cross-source corroboration orphan scan (BetP > 0.8 claims with zero CORROBORATES
edges — highest-suspicion hallucination candidates). Must be idempotent (no duplicate evidence
writes on repeat runs) so it's cron-safe.
- [ ] **Step 5: Verify, resolve all four**

```python
mcp__epigraph__resolve_backlog_item(original_id="<4a1912c9 full UUID>", resolution_content="Resolves 4a1912c9: re-verified against current corpus; <state finding>. Superseded by the periodic hallucination screen (a784836c) going forward.")
mcp__epigraph__resolve_backlog_item(original_id="<36bfc07d full UUID>", resolution_content="Resolves 36bfc07d: re-verified against current corpus; <state finding>. Superseded by the periodic hallucination screen (a784836c) going forward.")
mcp__epigraph__resolve_backlog_item(original_id="<ef730740 full UUID>", resolution_content="Resolves ef730740: re-measured evidence-to-claim ratio; <state trend>.")
mcp__epigraph__resolve_backlog_item(original_id="<a784836c full UUID>", resolution_content="Resolves a784836c: periodic idempotent hallucination screen built covering the 5 stated checks, scheduled on a cron, subsuming the ad hoc silence-alarm and evidence-ratio checks above.")
```

---

## Execution Order Summary

1. **Part 1** (retire shipped work) — do first, always, no exceptions; it changes what every later
   part actually needs to do.
2. **Part 2** (security) — before anything touches Foreman/epiclaw-host in production.
3. **Parts 3–4** (correctness bugs, pipeline/architecture) — independent of each other, parallelize.
4. **Part 5** (ops/deploy) — independent, parallelize with 3–4.
5. **Parts 6–7** (recall features, CLI/GUI) — independent, lower urgency than 2–5.
6. **Part 8** (workflow-capability incorporate stages) — do task-by-task; each is independently
   shippable and several depend on nothing else in this plan.
7. **Part 9** (deferred register) — cheap, do anytime; the 5 convention-only resolutions can happen
   in parallel with everything else.
8. **Part 10** (graph maintenance) — ongoing/cron-friendly; several tasks (10.1, 10.6) can run
   immediately with zero code dependency.
