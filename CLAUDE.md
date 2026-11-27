# EpiGraph — Claude / Agent Conventions

This file is loaded into any Claude Code / agent session opened in this repo.
Project-wide rules below; module-specific rules live next to their code.

## Adding MCP tools — the two extension points

There is no in-process tool trait or registry to implement. `epigraph-mcp` has
no extension trait — zero `pub trait` declarations, and a compile-time
`#[tool_router]` impl block. Its router and `scope_map` are a closed set by
design: a tool reaches the MCP server either as a kernel tool or as a
downstream product's federated tool.

- **Kernel tool** → add it to the `#[tool_router] impl` in
  `epigraph-mcp/src/server.rs` *and* to `SCOPE_MAP` in `scope_map.rs` (a
  coverage test fails until you do).
- **Downstream product** → run a separate `rmcp` server on loopback
  streamable-HTTP and mount it via `EPIGRAPH_MCP_EXTENSIONS`. See
  `epigraph-mcp/src/federation/` and
  `docs/superpowers/specs/2026-07-23-mcp-federation-gateway-design.md`.
  `episcience` is the reference implementation. Do **not** add federated tools
  to `SCOPE_MAP` — they are gated by the `scope=` in the env var instead.
- **A mounted extension is trusted with every caller's bearer.** Today the
  gateway forwards the caller's own kernel access token, verbatim, on every
  federated `tools/call` (`federation/client.rs::invoke_once`). The extension
  therefore receives a token whose audience is the kernel, and anything it
  does with that token (log it, replay it against `epigraph-api` or
  `epigraph-mcp`, hand it to another service) acts as the caller with the
  caller's full scopes until the token expires. That is the confused-deputy
  shape the MCP authorization spec forbids ("token passthrough").
  It is accepted for now because the only extension that validates these
  tokens does so with `epigraph_auth::JwtConfig`, which means it already
  holds `EPIGRAPH_JWT_SECRET` and could mint any kernel token itself:
  forwarding the bearer gives it no authority it does not already have. The
  rule that follows: **mount only an extension you operate and would trust
  with the kernel's signing secret**, and never mount a third-party one.
  Backlog `7b834860` adds the asymmetric path: with
  `EPIGRAPH_JWT_SIGNING_KEY` the kernel signs EdDSA and serves
  `/.well-known/jwks.json`, and an extension built on
  `JwtConfig::verifier_from_jwks` verifies without being able to mint. The
  caveat holds until a deployment has set the key and removed
  `EPIGRAPH_JWT_SECRET` from every extension (`docs/deploy.md`, "Token
  signing keys").
  The fix (backlog `c9b82fae`; design
  `docs/superpowers/specs/2026-09-26-episcience-operator-authority-design.md`
  section 2 and section 6 item 6) is an RFC 8693 token-exchange grant at
  `/oauth/token`: the gateway exchanges the caller's token for a short-lived
  token whose `aud` names the extension, forwards only that, and the kernel
  refuses an extension-audience token on its own routes.

## Adding HTTP routes from a downstream product

The MCP surface is extended by federation (above). The REST surface is
extended in-process: an embedder that runs `epigraph-api` as a library passes
`RouterExtension`s to `create_router_with_extensions`, and each is mounted at
`/api/v1/ext/<name>` inside the authenticated router (bearer, per-access
recorder, body limit, rate limit). The recorder logs an extension access
under its raw request path, not a route template (`nest_service` leaves no
`MatchedPath`). The recorder refuses an elevated token by method only
(anything but GET, HEAD and OPTIONS), so an extension handler must never write
on GET, HEAD or OPTIONS, including in `.fallback()` and `any()`. Scope checks
and tenancy are the extension's own job; see
`crates/epigraph-api/src/routes/extensions.rs`.
Never register a first-party route under `/api/v1/ext`
(`tests/router_extension_seam_lint.rs` fails if you do).

## Retiring backlog items

When you complete or refute a claim labelled `backlog`, **always use
`mcp__epigraph__resolve_backlog_item(original_id, resolution_content)`**.
It creates a resolution claim (labelled `["resolved"]`, prose prefixed
`"Resolves <id>: "`) AND patches the original's labels with `add=["resolved"]`
in a single call. Free-text "Resolves <UUID>" alone leaves the original
looking open in every backlog query forever.

Do NOT:
- File a free-text "Resolves <UUID>" claim alone without patching the
  original's labels.
- Use `supersedes`/`is_current` for status. Those are reserved for
  *epistemic* claim replacement (one claim refining another's factual
  content), not operational status.
- Reach for raw `update_labels` to add `["resolved"]` to a backlog item —
  that bypasses the canonical resolution-claim trail.

**Enforcement (issue #374).** `resolved` is the one label with retirement
semantics, so `update_labels`, `patch_claim` and `update_with_evidence`'s
`labels` merge (drain U004) apply `resolve_backlog_item`'s
`require_owner_or_admin` check when a call adds or removes it, on EVERY
transport (the stdio half closed in batch H-b). Ownership is the claim's
author, or an agent linked to the same operator as the author (stdio;
migration 107's operator arms, which is what makes a model-bumped fleet agent
able to retire its predecessor's items), an agent live-linked to the author
itself (its delegate, operator ruling R-183: one hop, a retired link grants
nothing; stdio, or over HTTP a live delegated run token), or the author's
operator (HTTP).
Over HTTP a `claims:admin` token also passes; its write into a group the admin
cannot write goes through the audited admin path (batch H-b, D2) on
`update_labels` / `patch_claim`; `update_with_evidence` has no admin path and
refuses such a label merge instead. Over HTTP the
WHOLE label mutation needs that ownership, whatever the labels (as
`patch_claim` and `PATCH /api/v1/claims/:id/labels` do); on stdio every other
label stays ungated. A stdio agent that shares no operator with the claim's
author, and is not its delegate, is now refused, including through the agent fleet's
`update_labels(original_id, add=["resolved"])` retirement procedure, and so is a stdio
server with no declared signer (`--agent-key` or the separate signing key) on any claim it
did not author. The deploy preconditions this sets for the fleet are in
`scripts/e2e/README.md` ("Deploy preconditions").

**Querying open backlog:**

```python
mcp__epigraph__query_claims_by_label(
    labels=["backlog"],
    exclude_labels=["resolved"],
    current_only=True,
)
```

A daily reconciler (`scripts/reconcile_backlog_labels.py`) catches free-text
"Resolves <UUID>" claims filed without `resolve_backlog_item` and back-fills
the label patch. Ambiguous matches go to `docs/superpowers/reports/reconciler-needs-review.log`.

Full spec: `docs/conventions/backlog-retirement.md`.

## Schema, migrations, claim mechanics

- All SQL stays in `crates/epigraph-db/src/repos/`. HTTP routes
  (`crates/epigraph-api/src/routes/`) and MCP tools
  (`crates/epigraph-mcp/src/tools/`) both call the repo layer; do not
  duplicate SQL between them.
  Neither is at zero yet, so two exact-count ratchet tests pin the residue:
  `crates/epigraph-mcp/tests/no_inline_sql_in_tools.rs` (MCP tools) and
  `crates/epigraph-api/tests/no_inline_sql_in_routes.rs` (HTTP routes); the
  HTTP count can only fall, by moving a statement into the repo layer.
- After adding or modifying a `sqlx::query!` / `sqlx::query_as!` macro
  call, run `DATABASE_URL=... cargo sqlx prepare --workspace -- --tests`
  and commit `.sqlx/` so `SQLX_OFFLINE=true cargo check --workspace`
  passes in CI. Removing a macro call leaves its `.sqlx/` entry orphaned;
  delete it.
- Most repo SQL is runtime, not macro-checked (under one in ten statements
  use the macros; `crates/epigraph-db/README.md`, "Setup"). Prefer the macro
  only for a static statement that no `Viewer::splice` / `splice_write`
  marker will ever need to reach, since a macro cannot take a spliced
  literal. Otherwise decode a runtime query through `query_as` into a
  `FromRow` struct, never `Row::get`, which panics on a missing column or a
  type mismatch.
- `claim_from_row` has ~20 callers in `crates/epigraph-db/src/repos/claim.rs`.
  Do not widen its signature — extend the relevant `SELECT` in the caller
  and post-fix the returned `Claim` (see `list_by_labels` and `get_by_id`
  for the pattern).

## Status claims bypass the novelty gate

MCP `submit_claim` / `memorize` / `batch_submit_claims` run a write-side
semantic novelty gate (`epigraph-mcp/src/tools/novelty_gate.rs`): a new claim
within `novelty_threshold` (default 0.05) cosine distance of an existing
`is_current` claim is SUPPRESSED and the existing claim's id is returned
instead. Recurring reports are templated (only numbers and dates move), so
each run used to collapse into the prior run's claim and the time series was
lost (backlog `a3e63a12`, `0a97ba24`).

A claim carrying any label in `novelty_gate::STATUS_CLAIM_LABELS` (`telemetry`,
the scheduled writers' `norcal-rfp-*-status` / `grant-*-status` labels,
`journal-status` for the daily journal's dated summary, and the older bare
`gen-status`, `generator-summary`, `review-status`, `revise-status`,
`research-scan`) is exempt: `novelty_gate::decide` pins its
effective threshold to 0.0. Suppression only; the fixed 0.15 `near-duplicate`
soft-flag still applies.

- Writing a recurring reporter? **Label its per-run summary claim** with a
  status label, and add a new label to `STATUS_CLAIM_LABELS` (exact match).
  Do not rely on passing `novelty_threshold=0` on every call.
- Keep the list to *shape* labels. Topic labels (`graph-integrity`,
  `maintenance`, `rfp`, `daily-journal`) stay out: exempting a topic disables dedup for genuine
  content on that topic.
- Adding a gated write path? `decide` takes `labels` as a required argument.
  Pass the caller's real labels, never `&[]` as a placeholder.

## Test database

Integration tests against the live `epigraph` DB fan out for 30+ minutes
and pollute production claim state. Never point them at it, and never reuse
a SHARED test database either: one that was not migrated `001 -> head` from
empty (left at a pre-tenancy version, or provisioned outside the public
migration series) cannot be migrated forward in place (060 fails closed on
its pre-060 tables) and turns a full `cargo test -p epigraph-api` run into
hundreds of failures that look like a code regression. Do what CI does:
create a FRESH database whose name ends in `_test` and migrate it from empty.

```bash
createdb -U epigraph <name>_test
EPIGRAPH_MIGRATE_GRANT_SEED_TO_SELF=1 \
MIGRATION_DATABASE_URL=postgres://epigraph:epigraph@localhost/<name>_test \
  cargo run -p epigraph-api --bin epigraph-migrate
DATABASE_URL=postgres://epigraph:epigraph@localhost/<name>_test cargo test ...
```

`EPIGRAPH_MIGRATE_GRANT_SEED_TO_SELF=1` grants `epigraph_seed` to the migrating
login (migration 216: the tenancy seed escape hatch the fixtures rely on needs
an explicit grant, a superuser no longer counts). The grant is cluster-wide, so
it also covers `#[sqlx::test]` databases. Never set it for a deployed login.

`#[sqlx::test]` suites are unaffected (each test gets its own database, migrated
from empty); this matters for the suites that read `DATABASE_URL` directly. The
shared fixtures stop with that procedure instead of failing obscurely:
`spawn_app*` in `crates/epigraph-api/tests/common/mod.rs` refuses a database
below this tree's head, and `try_test_pool` in
`crates/epigraph-mcp/tests/common/mod.rs` panics when its database will not
migrate to head (it used to skip silently).

## Workflow

- Feature branches, never land 3+ commits directly on `main`.
- **Reach `main` through a staging PR, not one feature PR at a time.** Every
  merge to `main` starts a full CI run on `main` and moves the base under
  every other open PR, so a backlog merged one by one (dozens of open PRs)
  queues dozens of full runs. Epiclaw's nightly staging run already works
  this way on `integration/<YYYYMMDD>` branches; an ad-hoc batch from a
  session does the same on `staging/<YYYYMMDD>-<tag>`. Use one of those two
  prefixes: CI runs only the affected shards on other PR heads, only lint and
  a fixed set of cross-crate ratchets on the burndown's `fix/triage-*` heads
  (the light plan, `.github/scripts/test-shard.py` `LIGHT_TARGETS`; the
  `ci:full` label overrides it), and the full plan on `integration/**` and
  `staging/**`, which is what makes the staging PR the full-suite gate on the
  combined tree:
  1. Cut the staging branch from current `main`.
  2. Bring in each candidate that is green at its head with
     `git merge --no-ff <head>`, subject `merge(staging): #NNN <its claim>`
     and an epistemic body (no squash, no rebase). Leave the feature PRs
     based on `main`: GitHub marks each one merged when its head reaches
     `main`.
  3. Open ONE draft PR from the staging branch to `main`. Its body carries a
     table with one row per included PR (number, one-line claim, result on
     the combined tree), the excluded PRs with the reason for each, and the
     combined-tree verification with the head sha it ran on. A body that
     only lists PR numbers is not enough: the staging PR is the merge record
     on `main`.
  4. Merge it with `--merge` once CI on the combined tree is green.
  5. Keep the number of open staging PRs to the minimum, one per batch. Do
     not push to a staging branch another session created; put late work in
     the next batch.
- `gh pr merge --merge --delete-branch` by default; never `--squash`
  unless explicitly told.

## Embedding policy

**Invariant:** every **non-telemetry** claim with `is_current = true` should
have an embedding; every claim with `is_current = false` should have
`embedding = NULL` AND `embedding_3072 = NULL` (enforced by
`chk_deprecated_no_embedding`, migrations 052 and 144). Semantic recall
(`recall()`, `recall_with_context()`, the UMAP theme pipeline, `find_workflow`'s
semantic path) reads from `embedding`, so violations either hide live claims
or surface stale ones.

**Telemetry exception:** host-provenance claims (epiclaw-host's
`ProvenanceRecorder` — container/task lifecycle, agent output, messages) are
intentionally NOT embedded (no semantic value, one OpenAI call each). They carry
the `telemetry` label and a `properties->>'event'` marker, and dominate the
is_current embedding gap. The write path already skips embedding them
(`submit.rs` `is_host_telemetry`), and `find_claims_needing_embeddings` excludes
them. Do NOT treat them as `live_missing`. (backlog a4aaa487)

**Declared opt-out:** `ingest_workflow` (MCP) and `POST /api/v1/workflows/ingest`
take `embed: false`, which sends no claim or goal text to the embedding
provider and stores no vector. Those claims are current and unembedded BY
REQUEST (typically group-private workflow plans, which pinned resolution never
searches), so they show up in the `live_missing` audit below; that count is not
a write-path defect for them. The opt-out is NOT recorded on the row: a later
backfill (`find_claims_needing_embeddings`, e.g. `embed_backfill`) does not
know it and will embed them. A declared-tenancy (`tenancy`) ingest that does
embed stores through the claims' known author
(`workflow_ingest::store_ingest_embedding`), because the embedder's
public-reader path cannot resolve a group-private claim's author.

### Write paths (must embed on insert)

When adding a new code path that inserts a claim, embed inline post-commit,
best-effort (warn on failure, never block the write). Current call-sites:

- **MCP `submit_claim`** — `crates/epigraph-mcp/src/tools/claims.rs::finish_submission` (phase 3 of `submit_claim`, after COMMIT), through `claim_helper::embed_claim_author_stamped`
- **MCP `memorize`** — `crates/epigraph-mcp/src/tools/memory.rs::memorize`, through `claim_helper::embed_claim_author_stamped`
- **MCP `batch_submit_claims`** — delegates to `submit_claim`
- **MCP `submit_bug_report`** — `crates/epigraph-mcp/src/tools/bug_report.rs::submit_bug_report`. The one exception to post-commit: the vector is computed best-effort BEFORE the transaction and stored by migration 207's definer in the same statement sequence as the row, because the reporter cannot update an intake-owned claim after commit (row security hides it from them). The embed runs only after `epigraph_bug_report_preflight` passes, so a caller the write would refuse for who it is or its limit (not configured, system agent, unbound, a role's agent whose role its own human does not hold, over its limit) costs no provider call. The theme scripts never turn an intake-owned claim's text, or any non-public claim's, into a label (`scripts/theme_lib.py::public_label_source`)
- **MCP `ingest_document`** — `crates/epigraph-mcp/src/tools/ingestion.rs::do_ingest_document_reporting` (the `embed_queue` drained through `embed_and_store` after the write)
- **MCP `ingest_document_spine`** — `do_ingest_document_spine` in the same file; phase-1 of the two-phase flow, embeds spine claims (thesis + sections + paragraphs) post-write
- **MCP `workflow_ingest`** — embeds executor output; `crates/epigraph-mcp/src/tools/workflow_ingest.rs`
- **MCP `store_workflow`** — embeds executor output via `execute_workflow_ingest_with_inserted`; `crates/epigraph-mcp/src/tools/workflows.rs::store_workflow`
- **MCP `improve_workflow_hierarchy`** — embeds executor output (claims) AND calls `set_goal_embedding` for the new `workflows` row; `crates/epigraph-mcp/src/tools/workflow_ingest.rs`
- **MCP `add_step`** and **HTTP `POST /api/v1/workflows/steps`** — embed when `AddStepResult::inserted_content` is `Some` (a new step, or a reused one revived from a workflow deprecation)
- **HTTP `POST /api/v1/claims`** — `crates/epigraph-api/src/routes/claims.rs` (after `tx.commit()` in `create_claim`)
- **HTTP `POST /api/v1/claims/batch`** — delegates each item to `create_claim_core` in `crates/epigraph-api/src/routes/claims.rs`
- **HTTP `POST /api/v1/conventions`** — embeds the convention claim after `tx.commit()` on the caller's stamp (`AppState::embed_claim_as`); the claim and everything attached to it are written on that caller's stamped transaction; `crates/epigraph-api/src/routes/conventions.rs::learn_convention`
- **HTTP `POST /api/v1/skills/share`** — embeds the shared-copy claim after the handler's last write, stored through `ClaimRepository::store_embedding` on the raw pool the handler writes the claim on; `crates/epigraph-api/src/routes/conventions.rs::embed_created_claim`
- **HTTP `POST /api/v1/policy-challenges`** — embeds a NEW challenge after `tx.commit()` on the caller's stamp (`AppState::store_claim_embedding_as`); a repeat request creates nothing and embeds nothing; `crates/epigraph-api/src/routes/policies.rs::embed_new_challenge`
- **HTTP `POST /api/v1/submit/packet`** — `crates/epigraph-api/src/routes/submit.rs::submit_packet` (the `if !was_duplicate` block; stored through `AppState::store_claim_embedding_as`)
- **HTTP `POST /api/v1/workflows/ingest`** (both callsites) — `crates/epigraph-api/src/routes/workflows.rs`
- **MCP `unmark_duplicate`** and **HTTP `POST /api/v1/claims/:id/undedup`** — not an insert, but they make a marked duplicate CURRENT again, so they re-embed it post-commit the same way (`tools/supersede.rs::unmark_duplicate`, `routes/versioning.rs::unmark_duplicate`; stored through `store_embedding_if_unsealed`)
- **MCP `supersede_claim`** and **HTTP `POST /api/v1/claims/:id/supersede`** — the act inserts a current replacement with new text and copies no vector, so the replacement is embedded post-commit: MCP on the stamp of the principal whose transaction inserted it (`actor`), not the inherited author, who may not write the claim's group (`tools/supersede.rs::supersede_claim`, `embed_claim_author_stamped`), HTTP on the caller's stamp (`routes/versioning.rs::supersede_claim`, `AppState::embed_claim_as`)
- **MCP `evolve_step`** and **HTTP `POST /api/v1/workflows/steps/:id/evolve`** — the new step, `supersedes` or `revises`, embedded post-commit through the caller that authored it (`tools/evolve_step.rs`, `embed_created_workflow_claims`; `routes/workflows.rs::evolve_step`, `embed_inserted_workflow_claims`)
- **CLI `unmark_duplicate`** — the operator's un-mark on the maintenance DSN (request servers refuse one under D9); re-embeds each restored claim post-commit through `store_embedding_if_unsealed`, best-effort (`crates/epigraph-cli/src/bin/unmark_duplicate.rs::embed_restored`)
- **CLI `epigraph-operator custodial-supersede`** — the custodian's revision of a platform-owned claim inserts a current successor with new text; after the act commits (`--apply`) it embeds the successor on the same maintenance session through `store_embedding_if_unsealed`, best-effort, and prints `embedded=` (`crates/epigraph-cli/src/operator/custodian.rs::embed_successor`)
- **CLI `hypothesis`** — `crates/epigraph-cli/src/bin/hypothesis.rs` (embedding included directly in INSERT; canonical CLI pattern — acquire embedder via `epigraph_cli::embedding_service()`, format the vector with `epigraph_db::pgvector_literal` (the one helper; `embedding_stack_ratchet` refuses a hand-written `[v,v,...]`), bind as `$N::vector`)
- **CLI `method_search`** — `crates/epigraph-cli/src/bin/method_search.rs` (embedding included directly in INSERT, matches `hypothesis` pattern)

`epigraph-ingest-executor` is pure-DB and does **not** embed itself; it returns
`WorkflowIngestExecutionResult::claims_to_embed()` (the claims it `inserted`
plus the ones it `revived` from a workflow deprecation) /
`AddStepResult::inserted_content` so each caller embeds with its own configured
embedder.

### Cleanup paths (must null on `is_current = false`)

When superseding or otherwise flipping `is_current` to false, null BOTH
`embedding` and `embedding_3072` in the SAME statement that sets
`is_current = false`. `chk_deprecated_no_embedding` (`CHECK (is_current OR
(embedding IS NULL AND embedding_3072 IS NULL))`) is checked per statement, so a
separate `UPDATE ... SET embedding = NULL` afterwards is refused with 23514.
`embedding_3072` matters as much as `embedding`: it is a second live ANN
column. Recall at centroid_dim=3072 (`ClaimRepository::search_by_embedding_since`)
has stated `is_current` itself since backlog 7720cb7a, as do the diverse
theme reads in `claim_theme.rs`, so the CHECK and the read now both keep a
retired claim out of recall; neither replaces the other.

The retirement paths, all in `crates/epigraph-db/src/repos/claim.rs`:

- **`ClaimRepository::supersede_act_conn`** — `"UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL"`
- **`ClaimRepository::evolve_step_conn`** — same statement, under `if edge_type == "supersedes"`
- **`ClaimRepository::deprecate_claim`** — `SET truth_value = 0.05, is_current = false, embedding = NULL,`
- **`ClaimRepository::retire_for_workflow_deprecation`** — the same `SET` list plus a `workflow_deprecation_retired` marker in `properties` (the hierarchical `deprecate_workflow`); `revive_workflow_deprecation_retired` undoes a marked retirement when a later generation or `add_step` reuses the claim, and the caller re-embeds it
- **`ClaimRepository::consolidate_act_conn`** — `SET supersedes = $1, is_current = false, embedding = NULL, embedding_3072 = NULL` (mode `merge` only: `abstract` retires nothing, and `identity` goes through `mark_duplicate_act` below)
- **`mark_duplicate_act`** (free fn behind `ClaimRepository::mark_duplicate_act_conn` / `mark_duplicate_with_repair_conn`) — `SET supersedes = $1, is_current = false, embedding = NULL,`

`scripts/fuzzy_dedup_claims.py` marks through `POST /api/v1/claims/:id/dedup`
(the act above, with its identity edge and cascade) and only reads the
database. Duplicates it marked before 2026-10 with its own `claims` UPDATE have
no `same_as` identity edge until an operator runs
`backfill_dedup_identity_edges --apply` (epigraph-cli, dry run by default).
Once backfilled they are ordinary dedup records and `unmark_duplicate` makes
them current again; that script kept no repair record, so the un-mark puts
nothing back and says so (`legacy_mark`). A legacy mark the backfill cannot
reconstruct is refused with the reason. On the re-embed side,
`crates/epigraph-cli/src/reembed.rs::fetch_batch` selects only current claims
(`ReembedTarget::eligible_predicate`), so `epigraph-cli reembed` never writes a
3072 vector back onto a retired claim.

If you add another path that flips `is_current = false`, null both columns in
that same statement and add it to this list.

### Auditing the gap

```sql
SELECT COUNT(*) FILTER (WHERE is_current AND embedding IS NULL
         AND NOT ('telemetry' = ANY(labels)) AND (properties->>'event') IS NULL
         -- A SEALED claim is not an embedding gap. Keyed on `claim_encryption`,
         -- never on `visibility`: a restricted claim keeps its embedding on
         -- purpose, and keying on visibility would hide every group-private row.
         AND NOT EXISTS (SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = claims.id)
         -- Nor is an unseal in flight. BOUNDED, deliberately: `unseal-commit`
         -- enqueues one embedding_generation job per restored claim.
         --
         -- THE BOUND STAYS AT 24h, AND IT IS NOW A DEPLOYMENT QUESTION RATHER
         -- THAN A MISSING-CODE ONE. A handler for that job type is registered,
         -- by `jobs_drain::build_job_runner` (crates/epigraph-api), which only
         -- the `drain_jobs` timer binary runs: since D9 `bin/server.rs` runs no
         -- job runner at all, so an instance whose drain timer is not installed
         -- drains nothing whatever its provider. The registration is
         -- CONDITIONAL: only the provider that OWNS this
         -- column may write it. That is stricter than "not a mock" -- a real
         -- provider embedding into a different vector space is refused too, and
         -- refused deliberately, because one ANN column holding two spaces
         -- degrades recall with no error. So an instance on the development
         -- fallback embedder AND an instance on any other real provider both
         -- register nothing, and their queues still never drain. Removing the
         -- bound would therefore hide an unsealed claim from `live_missing`
         -- forever on exactly the instances that most need to see it. A
         -- non-zero count of jobs older than the bound now means "this
         -- instance's embedding provider is not the one that owns this
         -- column, or its `drain_jobs` timer is not running", which is a
         -- deployment signal rather than a missing-handler one; the warning
         -- in `drain_jobs`'s log (not the server's boot log) says which
         -- provider was selected.
         -- Recovery there is `embed_backfill` with the owning provider (it
         -- writes `embedding`); `epigraph-cli reembed` does NOT restore this
         -- column, it writes `embedding_3072`. Such jobs keep `drain_jobs` at
         -- exit 4 until `drain_jobs --cancel-pending embedding_generation`.
         --
         -- Restoration is HALF: the job writes `embedding`, which is the column
         -- this clause reads. `embedding_3072` is nulled by the same seal and
         -- is NOT restored by it -- `epigraph-cli reembed` writes that one.
         --
         -- THE PAYLOAD PATH IS `#>> '{EmbeddingGeneration,claim_id}'`, NOT
         -- `->>'claim_id'`. `EpiGraphJob` is an externally tagged serde enum, so
         -- the row reads {"EmbeddingGeneration": {"claim_id": "…"}}; the flat
         -- spelling matches nothing and turns this clause into a no-op.
         AND NOT EXISTS (SELECT 1 FROM jobs j
                          WHERE j.job_type = 'embedding_generation'
                            AND j.state IN ('pending','running')
                            AND j.created_at > now() - interval '24 hours'
                            AND j.payload #>> '{EmbeddingGeneration,claim_id}'
                                = claims.id::text)
       ) AS live_missing,
       -- BOTH vector columns, for the same reason as `sealed_with_embedding`
       -- below: a clause naming only `embedding` reports zero while a retired
       -- claim still carries an `embedding_3072` recall at 3072 can return.
       COUNT(*) FILTER (WHERE NOT is_current
         AND (embedding IS NOT NULL OR embedding_3072 IS NOT NULL)) AS stale_present,
       -- A sealed claim that still carries a plaintext-derived vector is a
       -- CONFIDENTIALITY VIOLATION, not an embedding gap. Must be zero.
       -- BOTH vector columns: `embedding_3072` (migration 027) is a second live
       -- ANN column, written by `epigraph-cli reembed` and read by recall at
       -- centroid_dim=3072. A clause naming only `embedding` reports zero while
       -- the other column still holds a vector derived from the sealed text.
       COUNT(*) FILTER (WHERE (embedding IS NOT NULL OR embedding_3072 IS NOT NULL)
         AND EXISTS (SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = claims.id)
       ) AS sealed_with_embedding
FROM claims;

-- AND THE SAME CLAUSE OVER `evidence`, which the audit above cannot see.
-- Evidence carries its own `embedding` and `embedding_3072`, and an audit
-- scoped to `claims` alone reports zero while a sealed claim's evidence keeps a
-- plaintext-derived vector. Must be 0.
-- Keyed on the ROW's own ciphertext (`evidence_encryption`), not on its
-- claim's: a seal covers only the evidence its claim's owner holds, so a
-- sealed claim can keep another group's plaintext row, whose vector is
-- legitimate. Same predicate as `epigraph-cli reembed`'s sealed filter.
SELECT COUNT(*) FROM evidence e
 WHERE (e.embedding IS NOT NULL OR e.embedding_3072 IS NOT NULL)
   AND EXISTS (SELECT 1 FROM evidence_encryption ee WHERE ee.evidence_id = e.id);
```

`live_missing` and `stale_present` should trend toward zero. `live_missing`
growing means a write path is bypassing the embedder; `stale_present` growing
means a cleanup path is missing the null. Track via `system_stats` if exposed;
otherwise spot-check.

**`sealed_with_embedding > 0` on either table is a page-the-on-call condition,
not a backlog item.** It means a row whose content is ciphertext still carries a
vector computed from the plaintext.

<!-- BEGIN epistemic-commit-protocol (managed block — keep these markers; edit the source at ~/.epistemic-commit-protocol.md and re-run the propagator) -->

## The Epistemic Commit Protocol

Treat version control as an **Epistemic Ledger**: every commit is a node in the project's
knowledge graph, parseable into a claim with evidence, reasoning, and verification. Write each
commit so a future reader — or an automated git-log ingester — can reconstruct *what* decision
was made, *why*, and *how we know it is correct*.

### Forbidden commit messages

Never write "Fixed bug", "Updated code", "WIP", "Misc changes", or "Refactored stuff". They
destroy provenance: future developers (and future you) cannot reconstruct the *why*.

### Atomic discipline

One commit = one logical decision. **If the Reasoning section needs multiple unrelated
paragraphs, split the commit.**

| Too small | Just right | Too large |
|-----------|------------|-----------|
| "Add newline" | "Define Claim struct with validation" | "Implement the whole module" |
| "Fix typo" | "Add BLAKE3 content hasher" | "Add all crypto functions" |

### Message schema

```
<type>(<scope>): <claim — imperative summary of the single decision>

**Evidence:**
- <the raw error, issue ID, metric, or requirement that triggered this>

**Reasoning:**
- <why this solution over the alternatives>

**Verification:**
- <proof the claim holds — tests, checks, measurements>
```

`<scope>` is the module / subsystem / package the change touches (e.g. `api`, `db`, `loader`);
keep scopes consistent within a repo. Omit `(<scope>)` only when the change is genuinely global.

### Types

| Type | Use |
|------|-----|
| `feat` | new feature or capability |
| `fix` | bug fix |
| `refactor` | change that neither fixes a bug nor adds behaviour |
| `perf` | performance improvement |
| `test` | adding or updating tests |
| `docs` | documentation only |
| `chore` | build, CI, dependencies |
| `security` | security fix or hardening |

### Example

```
security(crypto): use constant-time comparison in signature verification

**Evidence:**
- Audit flagged `==` on signature bytes in the verify path (timing side-channel)

**Reasoning:**
- Replaced `==` with `subtle::ConstantTimeEq`; short-circuit comparison leaks timing
  on cryptographic material, and there is no correctness cost

**Verification:**
- cargo test passes; manual review confirms no early returns in the verify path
```

<!-- END epistemic-commit-protocol -->

## Commit-message lint (this repository)

CI (`.github/scripts/commit-message-lint.py`, job `Commit message lint`) reads
only the non-merge commits a change adds. It refuses:

- **E1** an e-mail address outside a trailer (placeholder domains and
  `noreply@anthropic.com` excepted; `role@<IPv4>` in a connection string is not
  an address);
- **E2** a home-directory path (`/home/<name>/`, `/Users/<name>/`) whose name is
  not generic (`user`, `runner`, `dev`, `you`, `me`, `USER`);
- **E3** a wildcard-DNS host that encodes an address, or a bare public IPv4
  outside the documentation, loopback and private ranges;
- **E4** a Verification section that says "Not run", "CI to confirm" or "to be
  run" when the message has no line starting `Unverified:` (a list item,
  `- Unverified: ...`, counts). Record what was not run on such a line; that is
  the only thing that clears E4;
- **E5** a change inside a `SECURITY DEFINER` function (any `*.sql` hunk inside a
  `CREATE FUNCTION` statement that carries the attribute) whose Verification
  records no run, or which has no Verification section. `Unverified:` does NOT
  clear E5: a later commit in the same change that names the first commit's sha
  (7+ characters) next to the test result does;
- **E6** a term from the private deny-list (customer and deployment names). The
  list lives in the repository secret `COMMIT_LINT_DENY_TERMS` (one term per
  line) and, locally, in a file named by `COMMIT_LINT_DENY_FILE`; it is never
  committed, because a public deny-list would publish the names it protects.

It only warns about a subject outside `<type>(<scope>): <text>` (W2) and a
message with none of the three sections (W3). Output is redacted, never the
offending value.

**Pull request title and body.** The `PR text lint` workflow
(`.github/workflows/pr-text-lint.yml`, `commit-message-lint.py --pr-text`)
applies E1, E2, E3 and E6 to the PR's title and body on every open, edit and
push, and fails on a finding. Every line is read, trailer-shaped lines included
(a PR body has no git attribution to protect). A finding names the rule and
`title` or `body line <n>`, never the text. It checks new and edited PR text
only; it does not rewrite PR bodies that were already published.

**Citing commits.** Cite a commit by sha only once it is on `main`, or when it
is an earlier commit of the same change. Cite anything else (a commit on
another open PR's branch, or one a rebase will rewrite) by **PR number and
subject**, e.g. `#1234 "fix(db): ..."`: a branch sha stops resolving once the
branch is rebased or squashed, and the citation is then a dead link for every
later reader. After each merge, the `Cited sha check` workflow
(`.github/workflows/cited-sha-check.yml`, `commit-message-lint.py --cited-shas`)
warns (W4) about each cited sha that names no commit reachable from `main`.
Write a sha so the check can read it: **at least 9 hex characters** (git's
default abbreviation here, as `git log --oneline` prints it), or a 7-8 hex short
sha right after `commit`, `commit hash`, `sha`, `revert(s|ed)` or
`cherry-pick(ed)` (also through a list: "commits a, b and c"). A bare 7-8 hex
token is not checked, because it cannot be told from an 8-hex backlog or
claim-id prefix. A sha-like token is lowercase hex holding a digit and a letter,
not part of a UUID or a longer hex run, not right after `@`, not 32 long and not
labelled as a `sha256`/`blake3`/`md5`/`hash` digest. W4 is a warning only and
does not run on pull requests.
