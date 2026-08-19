# PRE-REGISTRATION — Proposal J: temporal recall (`created_at` + `since:`)

**Governance artifact. Written BEFORE any implementation exists.**

| | |
|---|---|
| Proposal | EpiGraph backlog claim `03bb1479-ec73-43fb-b5f3-2b991d3efa91` |
| Brief | "temporal recall: `created_at` in RecallRow + optional `since:` param" |
| Branch | `feat/recall-temporal-since` (worktree `/home/jeremy/epigraph-wt-J`) |
| Base | `origin/main` @ `7cd5eeef` |
| Author role | Governance agent (Ada three-gate discipline) |
| Date | 2026-08-17 |
| Status | **Answer key fixed. No implementation code written by this agent.** |

This document exists so that the implementer cannot move the goalposts after seeing
results. Every criterion below has a pass condition, a refute condition, and a command
that decides it. A criterion that cannot be decided by running something is not a
criterion and is not in this file.

---

## 0. Surface inventory (established by reading the code, not by assumption)

Naming follows the repo convention `path::function` + grep-able fragment; no line
numbers.

### 0.1 The two tools in scope

| Tool | Handler | Params type | Response hit type |
|---|---|---|---|
| `recall` | `epigraph-mcp/src/tools/memory.rs::recall` → `recall_post_embed` | `epigraph-mcp/src/types.rs::RecallParams` | `epigraph-mcp/src/types.rs::RecallResult` |
| `recall_with_context` | `epigraph-mcp/src/tools/recall.rs::recall_with_context` → `recall_with_context_post_embed` | `tools/recall.rs::RecallWithContextParams` | `tools/recall.rs::RecallHit` |

The brief's "RecallRow" is not a real type in this workspace. It maps onto **two**
distinct response structs (`RecallResult` and `RecallHit`). Both must change, or the
feature is half-delivered.

### 0.2 Candidate-producing surfaces (the leak inventory)

A `since` window is only honoured if it is honoured at **every** surface that can put a
row into the top-level `results` array. There are **seven**:

| # | Surface | Reached by | Notes |
|---|---|---|---|
| S1 | `epigraph-db/src/repos/claim.rs::search_hybrid_scoped` — **dense CTE** (`WITH dense AS ... ORDER BY c.embedding <=> $1::vector LIMIT $3`) | `recall` (embedder up) | |
| S2 | same function — **lex CTE** (`FROM claims c, websearch_to_tsquery('english', $2) q`) | `recall` (embedder up) | fused by `FULL OUTER JOIN` |
| S3 | `claim.rs::search_lexical_scoped` | `recall` (embedder **down**) | the degrade path `recall_hybrid.rs` pins |
| S4 | `epigraph-db/src/repos/workflow.rs::search_by_goal_embedding` | `recall` with `include_workflows=true` | rows are **workflows, not claims** — no `claims.created_at` |
| S5 | `claim.rs::search_by_embedding` (`WHERE (c.properties->>'level')::int = 2`) | `recall_with_context` flat path **and** the diverse-empty fallback | |
| S6 | `epigraph-engine::diverse_retrieval::run_diverse_pipeline` → `candidates_in_themes_at_dim` → the real SQL, `epigraph-db/src/repos/claim_theme.rs::claims_in_themes_at_dim` (`WHERE c.theme_id = ANY($1)`) | `recall_with_context` with `diverse=true` | **also called by `epigraph-api/src/routes/search.rs`** (`/api/v1/search/semantic?diverse=true`) — a required new parameter here breaks that route; use `Option` and pass `None` |
| S7 | `tools/recall.rs::apply_graph_expansion` | `recall_with_context` with `graph_expansion_depth` | folds **edge-reachable** claims into `raw_hits`, i.e. into top-level results |

### 0.2b Explicitly OUT of scope (named because the brief points at them)

The brief says the `since` clause follows "the same pattern as the existing `tags`
prefilter". That prefilter lives in
`epigraph-db/src/repos/claim.rs::search_by_embedding_scoped`
(`AND ($3::text[] IS NULL OR c.labels @> $3::text[])`), which is the first function an
implementer will open — **and it is not S1–S7.** Neither MCP tool in scope reaches it.
Its callers are `epigraph-mcp/src/embed.rs`, `epigraph-mcp/src/tools/workflows.rs`, and
`search_by_embedding_current`, which is what `epigraph_engine::recall::recall` uses.

Per the scoping instruction ("scope J to `recall()`/`recall_with_context()` only"):

- `ClaimRepository::search_by_embedding_scoped` — **unchanged**
- `ClaimRepository::search_by_embedding_current` — **unchanged**
- `epigraph_engine::recall::recall`'s retrieval behaviour — **unchanged** (only its
  five-argument signature is protected, see **G2**)
- `epigraph-mcp/src/embed.rs`, `tools/workflows.rs`, `epigraph-api/src/routes/search.rs`
  — **unchanged**

Widening any of those to carry `since` is scope creep that eight passing criteria would
otherwise have hidden. It is a refute condition under **G8.1**. If a follow-up decides the
engine path should get the window too, it is a separate claim with its own
pre-registration and its own no-leak test — not a quiet rider on this one.

### 0.3 Facts verified by reading, which the criteria depend on

- **`Claim::created_at` already exists** (`epigraph-core/src/domain/claim.rs::Claim`), and
  `memory.rs::recall_post_embed` already does `ClaimRepository::get_by_id` per hit. On the
  `recall` path the response field is therefore *free* — no SQL change needed.
- **`recall_with_context` has no such luxury.** `ClaimEmbeddingHit` carries only
  `claim_id` + `similarity`, and paragraph metadata comes from
  `tools/recall.rs::fetch_batched_context` step 1, which is the **compile-time macro**
  `sqlx::query!("SELECT id, content, truth_value FROM claims WHERE id = ANY($1)")`
  populating `ParagraphCore`. Widening that SELECT invalidates `.sqlx` and requires
  `cargo sqlx prepare`.
- **`updated_at` is not a creation time.** `claim.rs::batch_update_truth_values`
  (`END, updated_at = NOW() WHERE id IN (`) bumps `updated_at` on every belief
  recomputation without touching content. `recompute_beliefs` therefore rewrites
  `updated_at` corpus-wide. Any `since` implemented against `updated_at` is wrong.
- **`RecallParams` does not use `serde(deny_unknown_fields)`.** A `since` key sent today
  is silently ignored — so a JSON-deserialisation test is *not* a red test; only a
  behavioural test is.
- **All seven candidate surfaces use runtime queries, not compile-time macros** — S1–S5
  are `sqlx::query_as::<_, T>(...)`, S6 is `sqlx::query(&sql)` in
  `claim_theme.rs::claims_in_themes_at_dim`, S7 composes S1–S6 output. No `.sqlx` churn is
  expected from the filter work itself; the only expected `.sqlx` delta is from
  `fetch_batched_context`. **G8.3** catches this either way.
- **`epigraph_engine::recall::recall(pool, embedder, query, limit, min_truth)`** is
  documented in its own module header as the entry point episcience calls
  out-of-workspace.

---

## 1. Gate 1 — Reasoning Freedom

### Verdict: **POSITIVE**

**Reasoning.**

The proposal is, in its stated form, two purely additive things:

1. an **optional** `since: DateTime` parameter, defaulting to "no window"; and
2. an **additive** `created_at` field on the response.

It adds no prohibition, removes no existing parameter, and forbids no query a caller can
make today. It strictly *expands* the action space: a caller who previously could only
ask "what is semantically nearest?" can now also ask "what is semantically nearest
*among things created since T*?" and can perform temporal arbitration client-side on
`created_at` even without using `since`. This is the textbook capability form — a
resource offered, not a rule imposed. Contrast the CONSTRAINED form the proposal
carefully does *not* take: "recall must exclude claims older than N days" or
"`since` is required". Neither is proposed.

Gate 1 judges the **proposal**, and the proposal is POSITIVE. But three *implementation
choices* would convert it to CONSTRAINED, and because Gate 1 is a hard blocker they are
pre-registered here as refute conditions rather than left to review discretion:

- **CT-1 (the real tripwire).** Adding a sixth **positional, required** parameter to
  `epigraph_engine::recall::recall`. Its module doc states episcience calls it with
  `(pool, embedder, query, limit, min_truth)`. A required sixth argument narrows what an
  existing out-of-workspace caller may do — it does not merely inconvenience them, it
  removes the call they currently have. That variant is **CONSTRAINED → REJECT**. The
  passing forms are: a sibling `recall_since(...)`, an options struct, or
  `since: Option<_>` added with a five-argument `recall` retained as a delegating
  wrapper. See **G2**.
- **CT-2.** Making `since` required (non-`Option`, or `Option` without a working
  missing-field default) on either MCP params struct. See **G1**.
- **CT-3.** Changing default behaviour — e.g. defaulting `since` to "last 30 days", or
  re-ranking by recency when `since` is absent. That silently removes the caller's
  ability to reach old material and is a prohibition wearing a default's clothes.
  See **G1**.

### Gate 2 — Autonomy Preservation: **PASS**

No new mandatory confirmation checkpoint, no new approval step, no new failure mode that
halts a caller. The audit-log addition (**G8**) is a fire-and-forget write that already
degrades to a `tracing::warn!` on failure (`spawn_recall_audit`), so it cannot block a
retrieval.

### Gate 3 — Learning Rate: **MEDIUM–HIGH**

Enables the "changed-since" modality that the cited MemSyco-Bench / LongMemEval-V2
evidence identifies as the frontier failure (systems retrieve both the old and the
updated memory and cannot arbitrate). It does not *solve* arbitration; it supplies the
signal an agent needs to arbitrate. Honest framing: this is the enabling primitive, not
the fix. Evidence class is **TYPE-C** (literature) plus a **TYPE-B**-adjacent internal
observation (the `is_current` / `sweep_semantic_duplicates` gap named in the brief).

### Scope boundary (pre-registered, so it cannot drift)

Claim `24caecaa` (a general created_at-window MCP tool over claims/evidence) is
**explicitly out of scope**. Proposal J touches `recall` and `recall_with_context` only.
No new MCP tool. See **G8**.

---

## 2. Criterion gates

Fixed now. Each is decided by the named command. `WT=/home/jeremy/epigraph-wt-J`.

> **Database rule for every command below.** The production `epigraph` database on
> container `epigraph-postgres` is off limits — no connections, no migrations, ever.
> `#[sqlx::test(migrations = "../../migrations")]` provisions a fresh throwaway database
> per test from `DATABASE_URL`, so the URL must be set or the commands below error out
> before deciding anything. Every `cargo test` / `cargo sqlx prepare` invocation in this
> document is to be run with:
>
> ```
> export TESTDB=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test
> ```
>
> and prefixed `DATABASE_URL=$TESTDB`. Any other disposable database is fine; the
> `epigraph` database is not.

---

### G1 — `since` is optional and default behaviour is unchanged

**Statement.** `since` is an optional parameter on both `RecallParams` and
`RecallWithContextParams`; a request that omits it produces the same result set, in the
same order, as `origin/main`, and no default window is applied.

**Pass.** (a) Both fields are `Option<DateTime<Utc>>` (or `Option<String>` parsed
explicitly) carrying `#[serde(default)]`; (b) a new test
`since_absent_is_baseline_behaviour` seeds claims spanning two `created_at` epochs, calls
each tool with no `since`, and asserts the returned id list **and order** are identical
to the baseline. The baseline is **not** an inline vector the implementer writes from
memory: it is captured by running that same test file in the `origin/main` worktree stood
up for **G4** and recording its printed id list. (c) every pre-existing test in
`recall_hybrid.rs`, `recall_with_context.rs`, `recall_workflows.rs`,
`recall_graph_expansion.rs`, `recall_audit_wiring.rs`, `perspective_lens_reads.rs`
passes with its **assertions unmodified** (mechanical struct-literal field additions are
permitted; changed expectations are not).

**Refute.** `since` is non-`Option`; or a missing `since` deserialises to anything other
than "no window"; or a default window/recency re-rank is applied when `since` is absent;
or any pre-existing recall assertion had to be weakened or changed.

**How checked.**
```
git -C $WT diff origin/main -- crates/epigraph-mcp/tests/ | grep -E '^-\s+assert'   # must be empty
DATABASE_URL=$TESTDB SQLX_OFFLINE=true cargo test -p epigraph-mcp --tests
```
plus `git -C $WT diff origin/main -- crates/epigraph-mcp/src/types.rs` review for
`Option` + `serde(default)`.

---

### G2 — Out-of-workspace callers of the engine entry point keep their call

**Statement.** `epigraph_engine::recall::recall` remains callable with exactly its
current five arguments `(pool, embedder, query, limit, min_truth)`.

**Pass.** A five-argument call compiles. Any temporal capability is exposed as a sibling
function, an options struct, or a defaulted variant, with the five-arg form retained as a
delegating wrapper.

**Refute.** The signature gains a sixth required positional parameter (Gate 1
**CONSTRAINED → automatic REJECT of the change**, not merely a failed criterion).

**How checked.**
```
grep -n "pub async fn recall(" -A 8 $WT/crates/epigraph-engine/src/recall.rs
DATABASE_URL=$TESTDB SQLX_OFFLINE=true cargo test -p epigraph-engine \
  --test recall_audit_test --test recall_claims_embedding_test
```
(`recall_audit_test.rs` already contains a literal five-arg call
`recall(&pool, &provider, "grendlewick", 10, 0.0)`; it must still compile **unedited**.)

---

### G3 — `created_at` is the creation time, and is never fabricated

**Statement.** The response field is sourced from `claims.created_at`; it is not
`updated_at`, not `NOW()`, and not synthesised for rows that have no `claims` row.

**Pass.** (a) A test seeds a claim with an explicit past `created_at`, calls
`ClaimRepository::batch_update_truth_values` on it (which sets `updated_at = NOW()`), then
asserts the recalled `created_at` still equals the seeded value; (b) a workflow-origin hit
(`include_workflows=true`, `result_type == "workflow"`) either omits `created_at`
entirely — `Option<_>` + `skip_serializing_if`, matching the existing `result_type` /
`lensed_belief` / `dispute_count` pattern — or carries the genuine `workflows.created_at`
fetched from the workflows table; it never carries a fabricated timestamp.

**Refute.** `created_at` tracks `updated_at`; or a workflow hit reports
`Utc::now()`/the request time/the claim-hit timestamp; or the field is `unwrap_or_default`-ed
to the Unix epoch.

**How checked.**
```
DATABASE_URL=$TESTDB SQLX_OFFLINE=true cargo test -p epigraph-mcp \
  --test recall_temporal created_at_is_creation_not_update
```
New test `created_at_is_creation_not_update` in
`crates/epigraph-mcp/tests/recall_temporal.rs`, plus
`grep -n "Utc::now()\|unwrap_or_default" $WT/crates/epigraph-mcp/src/tools/memory.rs
$WT/crates/epigraph-mcp/src/tools/recall.rs` reviewed for any new occurrence on the
`created_at` path.

---

### G4 — At least one criterion is decided by a test that FAILS on current code

**Statement.** A behavioural test exists that is red on `origin/main` and green after the
change.

**Pass.** `crates/epigraph-mcp/tests/recall_temporal.rs::since_excludes_older_claims_and_reports_created_at`
seeds one old claim and one recent claim that both match the query, calls `recall` with
`since` set between them **via `serde_json::from_value::<RecallParams>(json!({...}))`**
(not a struct literal, so it compiles against `origin/main`), and asserts (i) only the
recent id is returned and (ii) `results[0]["created_at"]` parses as RFC3339. Running this
test on a `git stash`-ed / `git worktree` checkout of `origin/main` **fails**; on the
branch it **passes**.

**Refute.** The test passes on `origin/main` (it is then tautological — `since` is
currently an ignored unknown field, so a passing run proves the assertions are vacuous),
or it fails to compile on `origin/main` (a compile error is not a red test; it proves
nothing about behaviour).

**How checked.**
```
export TESTDB=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test
BASE=/tmp/claude-1001/-home-jeremy/pre-j-base
# red, against base
git -C $WT worktree add $BASE origin/main
cp $WT/crates/epigraph-mcp/tests/recall_temporal.rs $BASE/crates/epigraph-mcp/tests/
DATABASE_URL=$TESTDB SQLX_OFFLINE=true cargo test --manifest-path $BASE/Cargo.toml \
  -p epigraph-mcp --test recall_temporal        # MUST FAIL (assertion, not compile error)
# green, on branch
DATABASE_URL=$TESTDB SQLX_OFFLINE=true cargo test -p epigraph-mcp --test recall_temporal   # MUST PASS
```
The same `$BASE` worktree supplies **G1(b)**'s baseline id list. Remove it with
`git -C $WT worktree remove $BASE` when done.

---

### G5 — `since` is pushed down into the candidate pool, not applied after it

**Statement.** The window is a SQL predicate **inside** each candidate CTE/query, before
its `LIMIT`, not a post-filter on the fused/returned rows and not a Rust `.retain()`
after the repository call.

**Pass.** A test `since_survives_candidate_pool_saturation` seeds ~120 old claims with
high similarity to the query plus one recent claim with lower similarity, sets `since`
above the old ones, and asserts the recent claim **is returned**. Additionally,
`search_hybrid_scoped`'s SQL shows the new predicate inside **both** the `dense` and `lex`
CTEs, above their `LIMIT $3`.

**Refute.** The test returns zero rows (the naive post-filter signature: the entire
`HYBRID_CANDIDATE_POOL` was consumed by pre-window claims and then discarded, so an
empty answer is served for a question that has a real answer); or the diff shows a
`.retain(|h| ...)` / `.filter(...)` on the returned `Vec<HybridHit>` / `Vec<ClaimEmbeddingHit>`
instead of a WHERE clause.

**How checked.**
```
DATABASE_URL=$TESTDB SQLX_OFFLINE=true cargo test -p epigraph-mcp \
  --test recall_temporal since_survives_candidate_pool_saturation      # decides the criterion
git -C $WT diff origin/main -- crates/epigraph-db/src/repos/claim.rs | grep -n "created_at"
```
The first command is the decider. The `claim.rs` diff must show `created_at` inside the
`dense` and `lex` WHERE clauses. As a **review prompt, not a hard gate** (it would false-
refute on an unrelated helper), scan the non-test recall paths for a Rust-side filter:
```
git -C $WT diff origin/main -- crates/epigraph-mcp/src/tools/memory.rs \
    crates/epigraph-mcp/src/tools/recall.rs crates/epigraph-db/src/repos/ \
  | grep -nE "retain\(|\.filter\(.*created_at"
```

---

### G6 — No leak: every top-level hit satisfies the window, on every surface

**Statement.** Universal form — *for every element of the response `results` array, when
`since` is set, that element's `created_at >= since`.* Coverage form — the predicate
reaches all seven surfaces S1–S7 in §0.2.

**Pass.** A parameterised test asserts the universal property across, at minimum: S1+S2
(`recall`, embedder up), S3 (`recall`, mock embedder — the `recall_hybrid.rs` pattern),
S4 (`include_workflows=true`), S5 (`recall_with_context` flat), S6
(`recall_with_context` `diverse=true` with a seeded theme), S7 (`recall_with_context`
`graph_expansion_depth=2`, with a pre-window claim reachable by a `supports` edge from an
in-window seed — it must NOT appear as a top-level hit). A surface that cannot honour the
window must be **documented and gated**: either it rejects `since` with an
`invalid_params` error naming the incompatible combination, or it is proven unreachable.
Silently ignoring `since` on any surface is a refute, not a documented limitation.

**Refute.** Any of the six exercised surfaces returns a top-level hit with
`created_at < since`; or a surface silently drops the filter (the existing
`paper_doi_filter`-on-diverse `TODO(diverse-recall)` is precedent for exactly this bug
class — do not add a second one).

**How checked.**
```
DATABASE_URL=$TESTDB SQLX_OFFLINE=true cargo test -p epigraph-mcp --test recall_temporal
```
with one `#[sqlx::test]` per surface, each named `no_leak_s1_dense` …
`no_leak_s7_graph_expansion`. Each such test asserts the **disjunction** the criterion
allows: *either* every top-level hit satisfies `created_at >= since`, *or* the call
returned an `invalid_params` error whose message names both `since` and the incompatible
option (e.g. `diverse`). It must not assert only the filtering branch — that would fail an
implementer who legitimately took the documented-and-gated branch. What neither branch
permits is a successful call that silently ignores `since`.

---

### G7 — Context enrichment is exempt, and the exemption is written down

**Statement.** The window constrains **top-level hits only**. The context sub-objects on
`RecallHit` — `atoms`, `siblings`, `corroborates`, `neighbor_paragraphs`, `section`,
`paper` — are NOT filtered by `since`. A two-year-old supporting paragraph is legitimate
context for a claim created yesterday; filtering it would delete the caller's ability to
see why a recent claim is believed, which is the CONSTRAINED direction.

**Pass.** A test seeds a recent paragraph hit whose sibling/corroborates/atom context is
older than `since` and asserts the hit is returned **with its context intact and
non-empty**; and a doc comment on the `since` field states the hits/context boundary
explicitly.

**Refute.** Context arrays come back empty or truncated because the window was applied
inside `fetch_batched_context`; or the boundary is undocumented (an undocumented boundary
is one an implementer silently reverses next quarter).

**How checked.**
```
DATABASE_URL=$TESTDB SQLX_OFFLINE=true cargo test -p epigraph-mcp \
  --test recall_temporal context_is_exempt_from_since
git -C $WT diff origin/main -- crates/epigraph-mcp/src/tools/recall.rs | grep -n "since"
```
(review that `fetch_batched_context` gained `created_at` in its SELECT but **no** `since`
predicate).

---

### G8 — Scope held, retrieval auditable, full CI gate green

**Statement.** Three sub-conditions, each decidable:

1. **Scope.** No new MCP tool; `crates/epigraph-mcp/src/scope_map.rs` and the
   `#[tool_router]` block in `server.rs` are untouched (claim `24caecaa` stays out). **And**
   the §0.2b out-of-scope list holds: `ClaimRepository::search_by_embedding_scoped` and
   `search_by_embedding_current` keep their current signatures, and
   `epigraph-mcp/src/embed.rs`, `tools/workflows.rs`, `epigraph-api/src/routes/search.rs`
   are unmodified.
2. **Auditability.** When `since` is supplied, it appears in `NewRecallEvent.params` for
   **both** tools — the `serde_json::json!({...})` literal in `memory.rs::recall_post_embed`
   and the one passed to `tools/recall.rs::spawn_recall_audit`. A retrieval whose window
   cannot be reconstructed from its audit row is an unauditable retrieval.
3. **CI gate + sqlx.** `cargo fmt --all -- --check`, then
   `cargo clippy --all-targets -- -D warnings`, then the test suites, all green; and
   `SQLX_OFFLINE=true cargo check --workspace` passes — proving that if
   `fetch_batched_context`'s `sqlx::query!` SELECT was widened, `.sqlx/` was regenerated
   against a **throwaway** database and committed.

**Pass.** All three hold.

**Refute.** A new tool or `SCOPE_MAP` entry appears; or an audit row for a windowed
recall has no `since` in `params`; or the offline check fails / `.sqlx` is stale; or
`clippy -D warnings` reports anything.

**How checked.**
```
git -C $WT diff --stat origin/main -- \
  crates/epigraph-mcp/src/scope_map.rs crates/epigraph-mcp/src/server.rs \
  crates/epigraph-mcp/src/embed.rs crates/epigraph-mcp/src/tools/workflows.rs \
  crates/epigraph-api/src/routes/search.rs                       # must be empty
grep -n "pub async fn search_by_embedding_scoped" -A 8 $WT/crates/epigraph-db/src/repos/claim.rs
SQLX_OFFLINE=true cargo check --workspace
cargo fmt --all -- --check
SQLX_OFFLINE=true cargo clippy --all-targets -- -D warnings
DATABASE_URL=$TESTDB SQLX_OFFLINE=true cargo test -p epigraph-db -p epigraph-engine -p epigraph-mcp
```
plus a test extending `recall_audit_wiring.rs` asserting
`params->>'since'` is present on a windowed call.

---

## 3. BCH regression challenges

Adversarial cases where a plausible naive implementation is **confidently wrong**.
Format follows `/home/jeremy/Ada/benchmark_challenges/`.

```yaml
id: BCH-J01
title: "Temporal recall — post-filtering a saturated candidate pool returns an empty set"
tier: hard
domain: software_retrieval
ground_truth_tier: CONFIRMED

scenario: >
  `recall` fuses two CTEs in `ClaimRepository::search_hybrid_scoped`: a dense ANN leg and
  a lexical leg, EACH capped at `HYBRID_CANDIDATE_POOL` (LIMIT $3) before the
  FULL OUTER JOIN. An implementer adds `since` by filtering the Vec<HybridHit> the
  function returns. A corpus has 120 older claims that are the nearest neighbours of the
  query, plus one claim created yesterday that is a weaker but real match. A caller asks
  "what changed in the last 7 days about X?" The tool returns []. Is the implementation
  correct?

ground_truth: >
  No. The post-filter is applied AFTER each leg's LIMIT, so the pool is consumed entirely
  by pre-window claims and the recent claim never enters it. The correct answer exists in
  the database and is not returned. Worse, the failure is silent and inverted: an empty
  result reads to the caller as "nothing changed", which is the exact opposite of the
  truth — this is the confidently-wrong answer, not a mere miss.
  Correct implementation: push `AND ($n::timestamptz IS NULL OR c.created_at >= $n)` into
  BOTH the `dense` and `lex` CTE WHERE clauses, above their LIMIT, following the existing
  `($6::text[] IS NULL OR c.labels @> $6::text[])` tag-prefilter idiom in the same query.
  The same reasoning applies to `search_lexical_scoped` and to
  `search_by_embedding`'s ANN WHERE clause.
  Diagnostic: an empty result for a window that provably contains matching rows is proof
  of post-filtering, not of an empty window.

pass_criteria:
  - criterion: C1
    description: "Identifies that the filter must precede the candidate LIMIT"
    weight: 45
    detection_keywords: ["push down", "WHERE", "before LIMIT", "candidate pool", "CTE", "post-filter"]
  - criterion: C2
    description: "Names the empty-set-reads-as-nothing-changed inversion as the harm"
    weight: 30
    detection_keywords: ["empty", "silent", "nothing changed", "false negative", "inverted"]
  - criterion: C3
    description: "Applies the fix to BOTH legs / all candidate surfaces, not just the dense one"
    weight: 25
    detection_keywords: ["lexical", "both", "lex CTE", "search_lexical_scoped", "every surface"]

score_history:
  - {version: pre-J, score: 0, date: "2026-08-17", notes: "baseline — no since param exists"}
```

```yaml
id: BCH-J02
title: "Temporal recall — `updated_at` is not a creation time"
tier: medium
domain: software_retrieval
ground_truth_tier: CONFIRMED

scenario: >
  An implementer reasons "recency is what the caller wants, and `updated_at` is the more
  recent of the two columns, so filter and report on `updated_at`". A nightly
  `recompute_beliefs` job has just run over the corpus. A caller asks for everything
  created in the last 24 hours. What comes back, and is it right?

ground_truth: >
  Wrong. `ClaimRepository::batch_update_truth_values` executes
  `... END, updated_at = NOW() WHERE id IN (...)`, so a belief recomputation bumps
  `updated_at` on every touched claim WITHOUT changing its content. Filtering on
  `updated_at` therefore returns the entire recomputed corpus as "new in the last 24
  hours" — a confidently wrong answer that is maximally misleading precisely for the
  temporal-arbitration use case the feature exists to serve (the agent concludes hundreds
  of facts changed when none did).
  The proposal says `created_at`, the claim's immutable creation instant, and that is what
  both the `since` predicate and the response field must use. `updated_at` semantics
  ("belief last touched") are a legitimate SEPARATE capability and may be added as an
  additional optional field later — never as a substitute.

pass_criteria:
  - criterion: C1
    description: "States that created_at and updated_at are semantically different columns"
    weight: 40
    detection_keywords: ["created_at", "updated_at", "immutable", "creation", "not the same"]
  - criterion: C2
    description: "Names belief recomputation as the concrete corruption path"
    weight: 35
    detection_keywords: ["recompute_beliefs", "batch_update_truth_values", "NOW()", "truth_value", "nightly"]
  - criterion: C3
    description: "Keeps updated_at available as an additive capability rather than banning it"
    weight: 25
    detection_keywords: ["separate field", "additional", "both", "later", "not instead"]

score_history:
  - {version: pre-J, score: 0, date: "2026-08-17", notes: "baseline"}
```

```yaml
id: BCH-J03
title: "Temporal recall — graph expansion smuggles pre-window claims into top-level hits"
tier: hard
domain: software_retrieval
ground_truth_tier: CONFIRMED

scenario: >
  `recall_with_context` with `graph_expansion_depth=2` runs `apply_graph_expansion`, which
  follows supports/corroborates/elaborates edges from the ANN seeds and FOLDS the reached
  claims into `raw_hits` — the same vector that becomes the top-level `results`. An
  implementer adds `since` to `ClaimRepository::search_by_embedding` only, reasoning
  "that's the ANN SELECT the proposal names". A caller sets `since` to yesterday and
  `graph_expansion_depth=2`. Three of the eight returned hits were created in 2024. Bug or
  intended?

ground_truth: >
  Bug. Graph expansion is a CANDIDATE-PRODUCING surface, not a context surface: its output
  lands in `results`, so every row it contributes must satisfy the window. Filtering only
  the ANN seed is insufficient — the same reasoning covers
  `diverse_retrieval::run_diverse_pipeline` (which bypasses `search_by_embedding`
  entirely) and `WorkflowRepository::search_by_goal_embedding`. There are seven such
  surfaces; a green test over one of them is not coverage.
  The distinction that resolves this cleanly: filter everything that can become a
  top-level HIT; exempt everything that is CONTEXT hanging off a hit (`siblings`,
  `corroborates`, `atoms`, `neighbor_paragraphs`, `section`, `paper`). Old supporting
  evidence for a new claim is exactly what the caller needs to see; old claims presented
  as "what changed" are not.
  Precedent in this codebase: `paper_doi_filter` is silently ignored on the diverse path
  (`TODO(diverse-recall)`). Repeating that pattern for `since` would be a second silent
  scope bypass.

pass_criteria:
  - criterion: C1
    description: "Enumerates candidate surfaces beyond the flat ANN (graph expansion, diverse, workflows, lexical)"
    weight: 40
    detection_keywords: ["apply_graph_expansion", "diverse", "run_diverse_pipeline", "workflows", "lexical", "every surface"]
  - criterion: C2
    description: "Draws the hits-vs-context boundary and exempts context deliberately"
    weight: 35
    detection_keywords: ["context", "siblings", "corroborates", "neighbor", "exempt", "top-level"]
  - criterion: C3
    description: "Rejects silently ignoring the filter on any surface; requires filter-or-error"
    weight: 25
    detection_keywords: ["silently", "ignored", "paper_doi_filter", "TODO", "reject", "invalid_params"]

score_history:
  - {version: pre-J, score: 0, date: "2026-08-17", notes: "baseline"}
```

```yaml
id: BCH-J04
title: "Temporal recall — fabricating created_at for workflow-origin results"
tier: medium
domain: software_retrieval
ground_truth_tier: CONFIRMED

scenario: >
  `recall` with `include_workflows=true` merges `WorkflowGoalEmbeddingHit`s
  (`workflow_id`, `content`, `truth_value`, `similarity` — no timestamp) into the same
  `RecallResult` array as claim hits. The implementer makes `created_at` a required
  `DateTime<Utc>` on `RecallResult`; the compiler then demands a value in the workflow
  branch, and they write `created_at: Utc::now()`. It compiles, tests pass, output looks
  clean. What is wrong?

ground_truth: >
  Every workflow result now reports itself as created at query time, so it is newer than
  every claim in the corpus and sorts first under any recency preference — a fabricated
  fact injected into an epistemic graph whose entire purpose is provenance. It is also
  self-consistent and therefore invisible to a reviewer reading the output.
  `Utc::now()`, `DateTime::default()` (Unix epoch) and `unwrap_or_default()` are all the
  same error: inventing a timestamp to satisfy a type.
  Correct: `created_at: Option<DateTime<Utc>>` with
  `#[serde(skip_serializing_if = "Option::is_none")]` — the pattern `RecallResult`
  already uses for `result_type`, `lensed_belief` and `dispute_count`. Claim hits carry a
  real `claims.created_at`; workflow hits omit the key (absent, not null), so the caller
  can see the value is unknown rather than being handed a lie. If workflow timestamps are
  wanted, SELECT the genuine `workflows.created_at`. Corollary: with `since` set,
  timestamp-less rows must be excluded from the window, not admitted by default —
  "unknown" is not "in range".

pass_criteria:
  - criterion: C1
    description: "Identifies the fabricated timestamp as invented provenance, not a formatting detail"
    weight: 40
    detection_keywords: ["Utc::now", "fabricat", "invent", "provenance", "lie", "unknown"]
  - criterion: C2
    description: "Prescribes Option + skip_serializing_if, matching the existing struct's pattern"
    weight: 35
    detection_keywords: ["Option", "skip_serializing_if", "omit", "absent", "not null", "result_type"]
  - criterion: C3
    description: "States that unknown-timestamp rows are excluded by a since window, not admitted"
    weight: 25
    detection_keywords: ["exclude", "unknown", "not in range", "since", "default"]

score_history:
  - {version: pre-J, score: 0, date: "2026-08-17", notes: "baseline"}
```

```yaml
id: BCH-J05
title: "Temporal recall — the sixth positional parameter that breaks episcience"
tier: medium
domain: governance_evaluation
ground_truth_tier: CONFIRMED

scenario: >
  `epigraph_engine::recall::recall(pool, embedder, query, limit, min_truth)` is documented
  in its own module header as the entry point episcience (a separate repository) calls so
  it need not spawn MCP-over-stdio. To thread the window through, an implementer changes
  it to `recall(pool, embedder, query, limit, min_truth, since)` with `since:
  Option<DateTime<Utc>>`. "It's an Option — callers just pass None." The EpiGraph
  workspace compiles and all tests pass. Governance verdict?

ground_truth: >
  REJECT as CONSTRAINED at Gate 1, notwithstanding the green workspace build. `Option`
  makes the VALUE optional; it does not make the ARGUMENT optional. Rust has no default
  arguments, so every existing caller's expression is now a compile error. The
  in-workspace suite is silent about this because the affected caller lives in another
  repository — a green suite over unmodified code proves nothing about code it never
  compiled. This is a change that removes a call an existing caller currently has: the
  action space narrowed, which is the automatic-reject condition.
  Passing forms, all of which ADD capability without removing any: (a) a sibling
  `recall_since(pool, embedder, query, limit, min_truth, since)` with the five-arg
  `recall` retained as a delegating wrapper; (b) an options/params struct with `Default`,
  introduced alongside the existing function; (c) a builder. Test that decides it:
  `crates/epigraph-engine/tests/recall_audit_test.rs` contains a literal five-argument
  call and must still compile UNEDITED.
  General rule this instantiates: judge backward compatibility at the widest caller
  boundary the symbol is published across, not at the edge of the workspace you can build.

pass_criteria:
  - criterion: C1
    description: "Verdict is CONSTRAINED / reject, on action-space-narrowing grounds"
    weight: 40
    detection_keywords: ["CONSTRAINED", "reject", "Gate 1", "narrow", "action space", "breaking"]
  - criterion: C2
    description: "Distinguishes optional value (Option) from optional argument (no default args in Rust)"
    weight: 30
    detection_keywords: ["Option", "not optional", "default argument", "positional", "every caller"]
  - criterion: C3
    description: "Offers a capability-framed passing alternative and names the deciding test"
    weight: 30
    detection_keywords: ["recall_since", "wrapper", "options struct", "delegat", "recall_audit_test", "unedited"]

score_history:
  - {version: pre-J, score: 0, date: "2026-08-17", notes: "baseline"}
```

```yaml
id: BCH-J06
title: "Temporal recall — a default window is a prohibition wearing a default's clothes"
tier: medium
domain: governance_evaluation
ground_truth_tier: PROVISIONAL

scenario: >
  During review someone proposes: "agents keep surfacing stale memories; since we're
  adding `since` anyway, let's default it to 90 days — callers who want the whole corpus
  can pass `since: null`." The change is small, well-intentioned, and directly targets the
  stale-memory problem in the proposal's evidence base. Gate 1 verdict?

ground_truth: >
  CONSTRAINED — reject. It converts an offered resource into an imposed rule. Concretely:
  every existing caller's results change without their code changing; recall of anything
  older than a quarter silently disappears; and the failure mode is invisible, because a
  short, plausible, wrong answer looks exactly like a short, plausible, right one. That
  the null escape hatch exists does not save it — the agent must now know about a
  restriction in order to undo it, which is the definition of a narrowed default action
  space. It also breaks G1's "absent `since` reproduces base behaviour".
  Same reasoning applies to the sibling proposals "re-rank by recency when since is
  absent" and "drop hits older than the newest hit's supersede date": both change the
  default answer to a question the caller did not ask.
  The capability-framed alternative that carries the SAME knowledge: return `created_at`
  on every hit (which this proposal already does), document that temporal arbitration is a
  known frontier failure mode with a pointer to the MemSyco-Bench / LongMemEval-V2
  evidence, and let the caller apply the window it wants. Knowledge offered, choice
  preserved.

pass_criteria:
  - criterion: C1
    description: "Verdict CONSTRAINED despite the escape hatch and the good intention"
    weight: 40
    detection_keywords: ["CONSTRAINED", "reject", "default", "escape hatch", "still restricts"]
  - criterion: C2
    description: "Names silent behaviour change for existing callers as the concrete harm"
    weight: 30
    detection_keywords: ["existing callers", "silent", "invisible", "disappears", "without their code changing"]
  - criterion: C3
    description: "Supplies the capability-framed alternative carrying the same knowledge"
    weight: 30
    detection_keywords: ["created_at on every hit", "document", "caller decides", "resource", "preserve choice"]

score_history:
  - {version: pre-J, score: 0, date: "2026-08-17", notes: "baseline"}
```

---

## 4. Summary for the implementer

Do these and the gates fall out:

- `since: Option<DateTime<Utc>>` + `#[serde(default)]` on **both** params structs; no
  default window; no recency re-rank.
- Push `AND ($n::timestamptz IS NULL OR c.created_at >= $n)` into every candidate query's
  WHERE, above its LIMIT — all seven surfaces of §0.2, mirroring the existing
  `($6::text[] IS NULL OR c.labels @> $6::text[])` idiom. Do **not** touch the §0.2b
  out-of-scope functions, even though `search_by_embedding_scoped` is where that idiom
  lives. New parameters on shared repo functions (notably S6's
  `claims_in_themes_at_dim`, also called by the REST search route) must be `Option` with
  existing callers passing `None`.
- `created_at: Option<DateTime<Utc>>` + `skip_serializing_if` on **both** `RecallResult`
  and `RecallHit`; real `claims.created_at`, never `updated_at`, never `Utc::now()`.
- Context sub-objects stay unfiltered, and say so in the doc comment.
- Keep `epigraph_engine::recall::recall`'s five-argument form callable.
- Record `since` in both audit `params` JSON literals.
- `fetch_batched_context`'s `sqlx::query!` is the only compile-time macro in the blast
  radius: widening it means `cargo sqlx prepare` **against a throwaway DB** and a
  committed `.sqlx/` delta.
- Never touch the `epigraph` database on `epigraph-postgres`.

---

## Adjudication

**Written AFTER implementation and after three independent adversarial reviews.**
Recorded per gate: PASS or REFUTE, with the evidence that decided it. Gates that
did not pass are recorded as REFUTE and not renegotiated.

| | |
|---|---|
| Adjudicated | 2026-08-17 |
| Branch HEAD at adjudication | `feat/recall-temporal-since` |
| Base | `origin/main` @ `7cd5eeef` |
| Test DB | `postgres://epigraph:epigraph@localhost/epigraph_db_repo_test` (throwaway; the prod `epigraph` DB on `epigraph-postgres` was never contacted) |
| Toolchain | `cargo 1.96.0` / `clippy 0.1.96` (no `rust-toolchain.toml` in the repo) |

### Summary

| Gate | Verdict |
|---|---|
| G1 — `since` optional, default behaviour unchanged | **PASS** |
| G2 — engine entry point keeps its five-argument call | **PASS** |
| G3 — `created_at` is creation time, never fabricated | **PASS** (test strengthened during adjudication) |
| G4 — a test that is red on `origin/main` | **PASS** |
| G5 — window pushed down before the candidate `LIMIT` | **PASS** |
| G6 — no leak on any of the seven surfaces | **PASS**, with one documented completeness limitation |
| G7 — context enrichment exempt, exemption written down | **PASS** |
| G8.1 — scope held | **PASS** |
| G8.2 — `since` in the audit `params` of BOTH tools | **PASS** (was **REFUTE** at review time; fixed) |
| G8.3 — full CI gate + sqlx offline | **REFUTE** — see below. `fmt`, `cargo check --workspace` and the test suites are green; workspace-wide `clippy --all-targets -- -D warnings` fails on **pre-existing** lints in files this branch does not touch, reproduced on an `origin/main` worktree. The criterion as written ("or `clippy -D warnings` reports anything") is therefore not met. |

---

### G1 — `since` is optional and default behaviour is unchanged — **PASS**

- (a) `types.rs::RecallParams::since` and `tools/recall.rs::RecallWithContextParams::since`
  are both `Option<chrono::DateTime<chrono::Utc>>` carrying `#[serde(default)]`.
- (b) `recall_temporal.rs::since_absent_is_baseline_behaviour` passes on the branch.
  The pinned baseline is **verified against base, not asserted from memory**: when the
  whole file was copied into an `origin/main` worktree, this test's
  `assert_eq!(ids, vec![a, b, c], …)` did **not** fire — the run panicked later, at
  `created_at_of` (the `created_at`-presence block), proving the id list AND order
  assertion is satisfied by `origin/main` behaviour.
- (c) `git diff origin/main -- crates/epigraph-mcp/tests/ | grep -E '^-\s+assert'` → empty.
  No pre-existing recall assertion was removed or weakened.
- Adjudication addition: the test now also asserts every unwindowed hit carries its real
  `created_at`. Mutation proof this is live — `memory.rs`
  `created_at: Some(claim.created_at)` → `params.since.map(|_| claim.created_at)` turns
  `since_absent_is_baseline_behaviour` **FAILED**. Before the addition that mutant survived.

### G2 — out-of-workspace callers keep their five-argument call — **PASS**

```
$ grep -n "pub async fn recall(" -A 8 crates/epigraph-engine/src/recall.rs
78:pub async fn recall(pool, embedder, query, limit, min_truth) -> Result<Vec<RecallResult>, RecallError>
$ git diff --stat origin/main -- crates/epigraph-engine/tests/recall_audit_test.rs   # empty
$ cargo test -p epigraph-engine    # all targets green (see G8.3)
```
No sixth positional parameter. BCH-J05's CT-1 tripwire was not tripped.

### G3 — `created_at` is the creation time, and is never fabricated — **PASS**

- (a) `created_at_is_creation_not_update` part (a): after
  `batch_update_truth_values` moves `updated_at` to `NOW()`, the recalled `created_at`
  is still `epoch_old()`.
- (b) **This half was repaired during adjudication.** As written, part (b) used
  `since = Utc::now() + 1s`, which is past BOTH `created_at` and `updated_at`, so it
  could not tell the two columns apart — mutating both hybrid CTE predicates to
  `c.updated_at >= $8` left it **green**. It now uses the discriminating fixture
  `created_at < since <= updated_at` (`created_at` = 2024-01-15, `updated_at` ≈ now,
  `since` = `epoch_cut()` = 2025-06-01), with the ordering asserted as an explicit
  precondition. Mutation proof:

  ```
  # both CTE predicates -> c.updated_at >= $8
  test created_at_is_creation_not_update ... FAILED
    "a claim whose updated_at is inside the window but whose created_at is not must be
     excluded; filtering on updated_at returns [00000000-…-0301]"
  ```
- Boundary semantics are now pinned too. `since` is documented as "at or after this
  instant"; a claim seeded at exactly `epoch_cut()` is asserted to be RETURNED.
  Mutation proof: `created_at >= $8` → `created_at > $8` (both CTEs) turns
  `since_excludes_older_claims_and_reports_created_at` **FAILED**. Before this fixture
  that mutant survived all 11 tests.
- (b′) Workflow-origin hits carry the genuine `workflows.created_at`
  (`workflow.rs::search_by_goal_embedding_since` selects it). No `Utc::now()` /
  `unwrap_or_default` was added on any `created_at` path — the only new occurrence of
  the string `Utc::now()` in the diff is inside a comment explaining why it is wrong.

### G4 — at least one criterion is decided by a test that FAILS on current code — **PASS**

The complete `recall_temporal.rs` (including every assertion added during adjudication)
was copied into a detached `origin/main` worktree and run:

```
$ cargo test -p epigraph-mcp --test recall_temporal        # in the origin/main worktree
running 11 tests
test result: FAILED. 0 passed; 11 failed; 0 ignored
  since_excludes_older_claims_and_reports_created_at:
    "the pre-window claim must be excluded; got [..0100, ..0101, ..0102]"
  since_survives_candidate_pool_saturation:
    "the only in-window claim was not returned … the window was applied AFTER the LIMIT"
```

It **compiled** and failed on assertions, not on compilation — which is what the
criterion requires. On the branch: `11 passed; 0 failed`. The base worktree was removed
with `git worktree remove`.

*Constraint this imposed on the adjudication:* the branch-only symbol
`graph_expand_seeds_since` must NOT be named in `recall_temporal.rs`, or the file stops
compiling on base and G4's own check dies. The graph-expansion regression test was
therefore placed in `crates/epigraph-db/tests/graph_expand_seeds_window.rs`.

### G5 — `since` is pushed down into the candidate pool — **PASS**

`claim.rs::search_hybrid_scoped_since` carries
`AND ($8::timestamptz IS NULL OR c.created_at >= $8::timestamptz)` inside **both** the
`dense` and the `lex` CTE, above their `LIMIT $3`; `search_by_embedding_since` and
`search_lexical_scoped_since` likewise. `since_survives_candidate_pool_saturation`
passes on the branch and fails on base with exactly the empty-set inversion BCH-J01
predicts. The review-prompt grep for a Rust-side post-filter
(`retain(|…)` / `.filter(… created_at)`) over the returned vectors finds nothing.

### G6 — no leak on any of the seven surfaces — **PASS**, with one documented limitation

All six `no_leak_s*` tests pass, and each is a live discriminator: an earlier review
neutered each surface's predicate in turn and each time exactly its own test went red
(`workflow.rs` → `no_leak_s4_workflows`; `claim_theme.rs` → `no_leak_s6_diverse_themes`;
`graph_expand_seeds` destination filter → `no_leak_s7_graph_expansion`).

**Defect found and fixed during adjudication (S7).** `graph_expand_seeds` walked the
graph, inserted **every** reachable claim into the discovery map, stopped at
`MAX_EXPANSION_NODES` (200), and only then applied the window. Out-of-window claims
therefore consumed the emission budget, so a windowed expansion could return `[]` while
in-window reachable destinations existed — BCH-J01's "empty reads as nothing changed"
inversion, reproduced on the graph surface. The doc comment asserted the opposite
("nothing in-window was displaced … the way it would be under a `LIMIT`").

Fix: two budgets. `MAX_EXPANSION_NODES` (200) now caps only what is **emitted**;
`MAX_EXPANSION_VISITS` (1 000) caps what is **walked**, and applies only when a window
is set. Membership is resolved per BFS level in one batched query, filtering `level_new`
in its own order so truncation stays deterministic. Unwindowed the emission cap is the
only bound that can bind, so behaviour is unchanged. The walk is still not pruned — an
out-of-window claim remains a legitimate bridge.

Regression test `crates/epigraph-db/tests/graph_expand_seeds_window.rs`:

```
$ cargo test -p epigraph-db --test graph_expand_seeds_window
test an_out_of_window_claim_still_bridges_to_an_in_window_one ... ok
test in_window_destination_survives_a_pre_window_fanout ... ok

# with the two budgets collapsed back into one (the pre-fix shape):
test in_window_destination_survives_a_pre_window_fanout ... FAILED
  "the in-window destination … was starved by the expansion budget: 250 pre-window
   neighbours consumed it and the call returned []"
```

The unwindowed control (`graph_expand_seeds(&pool, &[seed], 2).len() == 200`) is asserted
in the same test, so the fix cannot silently change the pre-existing truncation.

**Documented limitation (completeness, not a leak).**
`diverse_retrieval::run_diverse_pipeline` selects its `max_themes` themes by centroid
similarity **before** `since` is consulted (`find_similar_themes_at_dim` takes no
window). A theme holding only pre-window claims still consumes a slot, so a windowed
`diverse=true` page can be SHORT. No pre-window row can reach the caller — the window
still binds on `claims_in_themes_at_dim_since` — so this is a shortfall, not the silent
scope bypass G6 forbids. S6's pre-registered surface inventory named
`claims_in_themes_at_dim` only; windowing theme selection needs a new `claim_themes`
query outside that inventory and is deliberately deferred rather than half-done. It is
now written down at both doc sites — `DiverseRetrievalConfig::since` and the
caller-facing `RecallWithContextParams::since` schemars text, which previously
overstated the guarantee for the pipeline as a whole.

**Gating branch hardened.** The `Outcome::Gated` arm of `assert_window_honoured` is dead
in every current run (the implementation filters rather than gates, which is the branch
the pre-registration preferred). Its acceptance bar was `msg.contains("since")`, which an
unrelated internal error could satisfy. It now also requires the incompatible option
name and an `invalid_params` code. This is intent-hardening for a future implementation;
**no runtime evidence supports it, because the branch is never taken.**

### G7 — context enrichment is exempt, and the exemption is written down — **PASS**

`context_is_exempt_from_since` passes. `fetch_batched_context` gained `created_at` in its
`SELECT` and **no** `since` predicate — the only occurrence of "since" inside that
function is the comment explaining the omission. The hits-vs-context boundary is stated
explicitly on `RecallWithContextParams::since`.

### G8.1 — scope held — **PASS**

```
$ git diff --stat origin/main -- crates/epigraph-mcp/src/scope_map.rs \
    crates/epigraph-mcp/src/server.rs crates/epigraph-mcp/src/embed.rs \
    crates/epigraph-mcp/src/tools/workflows.rs crates/epigraph-api/src/routes/search.rs
(empty)
```
`ClaimRepository::search_by_embedding_scoped` (5 args) and `search_by_embedding_current`
(3 args) are unchanged. No new MCP tool; claim `24caecaa` stays out.

**BCH-J05 compatibility decision, recorded rather than left implicit.** Five symbols were
given `_since` siblings with the original arity retained as a delegating wrapper. Two more
were fixed during adjudication for consistency at the widest published boundary:
`ClaimRepository::graph_expand_seeds` (3 args) and
`WorkflowRepository::search_by_goal_embedding` (3 args) are now wrappers over
`…_since`. Two remaining breaks are **struct fields**, for which no wrapper form exists;
both are judged acceptable and the judgement is written into the code:

- `WorkflowGoalEmbeddingHit.created_at` — a `sqlx::FromRow` result row, never constructed
  by hand (`grep -rn "WorkflowGoalEmbeddingHit {"` finds only the definition).
- `DiverseRetrievalConfig.since` — deliberately **not** given `#[derive(Default)]`: a
  defaulted `centroid_dim: 0` is rejected at runtime by `centroid_columns_for_dim`, so
  deriving `Default` would trade a compile error for a runtime `InvalidData`.

### G8.2 — retrieval auditable for BOTH tools — **PASS** (was REFUTE at review time)

At review time this was **REFUTE**: `recall_audit_wiring.rs::since_is_recorded_in_recall_audit_params`
queries `WHERE tool = 'recall'`, so deleting **both** `"since": params.since` literals from
`tools/recall.rs::recall_with_context_post_embed` left the entire suite green (verified by
a reviewer, and re-verified here).

Two sibling tests now cover the other half:
`since_is_recorded_in_recall_with_context_audit_params` (main path, with a
non-empty-page precondition) and
`since_is_recorded_on_the_empty_recall_with_context_audit_row` (the empty-result early
return, driven by a claim that only the window excludes, asserting `empty: true`
alongside the window). Mutation proof:

```
# both `"since": params.since,` literals removed from tools/recall.rs
test since_is_recorded_in_recall_with_context_audit_params ... FAILED
test since_is_recorded_on_the_empty_recall_with_context_audit_row ... FAILED
test result: FAILED. 3 passed; 2 failed
```

### G8.3 — full CI gate + sqlx — **REFUTE**

Three of the four sub-conditions hold; the clippy one does not, for reasons entirely
outside this branch. Recorded as REFUTE because the criterion's refute condition is
literal ("or `clippy -D warnings` reports anything").

```
$ SQLX_OFFLINE=true cargo fmt --all -- --check
(clean)

$ SQLX_OFFLINE=true cargo check --workspace
Finished `dev` profile … in 56.22s          # .sqlx/ is current; the fetch_batched_context
                                            # delta was regenerated against the throwaway DB

$ DATABASE_URL=$TESTDB SQLX_OFFLINE=true cargo test -p epigraph-db      # 41 targets, 0 failed
$ DATABASE_URL=$TESTDB SQLX_OFFLINE=true cargo test -p epigraph-engine  # 40 targets, 0 failed
$ DATABASE_URL=$TESTDB SQLX_OFFLINE=true cargo test -p epigraph-mcp     # 73 test targets
                                                                        # + lib (134) + bins (11),
                                                                        # run in three batches, 0 failed

$ SQLX_OFFLINE=true cargo clippy --all-targets -- -D warnings
error: could not compile `epigraph-tools` (example "table_graph") due to 5 previous errors
```

Every `-D warnings` diagnostic is in a file this branch does not touch:

```
crates/epigraph-tools/examples/table_graph/{discover,dossier,ingest,llm,types}.rs
crates/epigraph-engine/tests/{blocker_compound_nbhd,perspectival_demo_t2}.rs
crates/epigraph-db/tests/{match_candidate_repo,last_match_scan_column}.rs
crates/epigraph-db/src/repos/claim.rs::max_agent_claims_constant_is_positive  (pre-existing test fn)
```

Reproduced on base, so it is not caused by this change:

```
$ git worktree add --detach /home/jeremy/pre-j-base origin/main
$ cd /home/jeremy/pre-j-base && SQLX_OFFLINE=true cargo clippy -p epigraph-tools --all-targets -- -D warnings
error: function `scan_crates` is never used
… EXIT=101
```

**Environment note (recorded because it is a deviation from a plain `cargo test`).**
The host filesystem was at 100% during adjudication. The test suites above were run
with `CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_DEV_DEBUG=0` so the ~40 MB test binaries
fit; debug info does not affect test outcomes. `epigraph-mcp`'s 73 test targets were run
in three batches to stay inside the shell timeout. One intermediate batch reported
`recall_temporal: 8 passed; 3 failed` — that run coincided with the disk filling
completely, and PostgreSQL's data directory is on the same volume; re-run with 7 GB free
the same target reports `11 passed; 0 failed`, as does the whole recall family
(`graph_expand_seeds_window` 2, `perspective_lens_reads` 10, `recall_audit_wiring` 5,
`recall_dispute_awareness` 3, `recall_graph_expansion` 3, `recall_hybrid` 1,
`recall_temporal` 11, `recall_with_context` 16, `recall_workflows` 2 — 53 tests, 0 failed).
The transient failure is recorded rather than omitted, with the evidence that it was the
environment and not the change.

`epigraph-tools` depends only on `epigraph-core`, which this branch does not modify, so
the failure is also structurally independent of it. The branch's own blast radius is
clippy-clean, but the gate as pre-registered is workspace-wide and it does not pass.
**Recorded as REFUTE, not renegotiated.** Remediation belongs in a separate change that
fixes the pre-existing lints (or pins the toolchain CI uses).

### BCH challenge outcomes

| Challenge | Outcome |
|---|---|
| BCH-J01 (post-filter empties a saturated pool) | Avoided on the ANN legs from the start; **hit on the graph surface** (S7) and fixed during adjudication, with a red-then-green regression test. |
| BCH-J02 (`updated_at` is not a creation time) | Implementation correct throughout; the *test* did not discriminate the two columns and now does. |
| BCH-J03 (graph expansion smuggles pre-window claims) | Destination filter present from the start; the budget-starvation variant was the residual and is fixed. |
| BCH-J04 (fabricated `created_at` for workflow hits) | Avoided — real `workflows.created_at`, `Option` + `skip_serializing_if`. |
| BCH-J05 (sixth positional parameter) | Avoided on the engine entry point; two further arity breaks closed during adjudication, two struct-field breaks recorded as explicit decisions. |
| BCH-J06 (a default window) | Avoided — no default window, no recency re-rank. |
