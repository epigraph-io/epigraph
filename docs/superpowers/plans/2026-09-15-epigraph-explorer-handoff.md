# Handoff — EpiGraph Explorer (web UI + Notion integration)

**Date:** 2026-09-15
**Status:** spec written, nothing implemented
**Spec:** `docs/superpowers/specs/2026-09-15-epigraph-explorer-ui-design.md`
**Origin:** a Claude Code web session that could not push (see §1). Everything
below was verified in-session against this tree and production; re-verify
anything marked *unverified* before acting on it.

---

## 1. Why this document exists

The session that produced the spec had **no GitHub write access**:

```
remote: Claude doesn't have GitHub access to epigraph-io/epigraph for your organization.
fatal: unable to access 'https://github.com/epigraph-io/epigraph/': 403
```

The GitHub MCP tools returned `Resource not accessible by integration` on ref
creation, so both push paths were closed. The work was handed over as a git
bundle instead. Remedy, if the next agent hits the same wall: an org admin
installs the Claude GitHub App
(`https://github.com/apps/claude/installations/select_target`), or the user
reconnects GitHub from claude.ai connector settings.

**Note on the branch:** `origin/claude/ecstatic-keller-phnje6` exists remotely at
`e4f9d74`, which is *not* an ancestor of `origin/main` (`9fdcc0d`). The bundle is
based on `e4f9d74` for that reason.

---

## 2. The request being served

Two asks from the user, in order of arrival:

1. An "EpiGraph explorer function in Notion", and auto-ingest of specific Notion
   pages into EpiGraph.
2. Then, correctly, a push-back: *"Sure we can't just put a webUI onto the
   epigraph API and use notion as a visualizer? I'd love a good graph visualizer
   where clicking a link takes you to a page with automatic outlinks."*

(2) supersedes (1) for the read path. The spec reflects that: **a web UI is
primary, Notion gets an embed and OpenGraph unfurls, and no claims are copied
into Notion.** The auto-ingest half (Notion → EpiGraph) survives unchanged and is
specified at a lower level of detail — it needs its own spec before implementation.

The third ask was the parity audit: *"Make sure the MCP tooling has API versions
available. (Consider consolidating, making the MCP system call the API instead of
running directly to avoid interface drift, though that may be a backlog item.)"*
That is §8–§9 of the spec, and the recommendation is **no** to the HTTP hop —
read §9 before re-opening it.

---

## 3. Verified facts — do not re-derive

Each of these cost real investigation. All are `file:line` in this tree unless
noted.

### Corpus (production, via `system_stats`, 2026-09-15)

`claims 476,006 · edges 1,061,399 · embeddings 343,370 · evidence 122,876 ·
agents 5,461 · frames 126 · workflows 157`

These numbers kill two designs: a global graph render, and any projection of
claims into Notion. Re-measure before quoting them as current.

### Source findings

| Finding | Location |
|---|---|
| `expand` resolves neighborhoods only against the **latest** `graph_cluster_runs` row; 404s otherwise. Neighborhood IDs are therefore not permalink-safe | `crates/epigraph-api/src/routes/graph_neighborhood.rs:133` |
| `atomic_response` is **fully implemented** — the file header comment calling it "an empty placeholder" is stale. One-line doc fix available | `routes/graph_neighborhood.rs:354` (comment at line 9) |
| `claim_neighborhood` caps `depth` at 3 and takes an optional auth context | `routes/edges.rs:1519` |
| `synthetic_document_key` hashes `source.external_id` **alone**, so a title edit converges on the same node. This is the mechanism for keying Notion pages as `notion:<page_id>` | `crates/epigraph-mcp/src/tools/ingestion.rs:842` |
| `effective_pipeline_version` appends `:ch{n}` for chunked ingests — the pattern to copy for a Notion content-revision stamp | `tools/ingestion.rs:141` |
| `ingest_document` / `_inline` `tokio::spawn` a **detached** task and return `"queued"`. No completion signal; callers must poll `check_already_ingested` | `tools/ingestion.rs:153,195` |
| `query_paper` returns paper **plus claims** plus an asserted-vs-labelled discrepancy probe that catches partial ingests | `tools/paper_queries.rs:52-77` |
| `GET /api/v1/papers?doi=` returns **metadata only** — no claims, no probe | `routes/papers.rs:50,185` |
| `stage_claims` (MCP) is a pure **validator** — no DB write. Real staging is `POST /api/v1/staging/*` | `tools/batch.rs:78` |
| MCP `recall` params: `min_truth`, `tags`, `agent_id`, `frame_id`+`perspective_id` | `crates/epigraph-mcp/src/types.rs:444` |
| API `/search/semantic` params: `min_similarity`, `claim_type`, date range, `diverse`, `max_themes`, `diversity_weight`, `candidate_pool`, `centroid_dim` | `routes/search.rs:430` |
| Raw-SQL leakage: 12/38 files in `epigraph-mcp/src/tools/`, 33/64 in `epigraph-api/src/routes/` | `grep -rl "sqlx::query"` |
| No frontend exists anywhere — no `package.json` in-tree, no GUI repo among those reachable | verified by `find` + repo listing |

### Tenancy state (from `docs/tenancy/COMPLETION-PLAN.md` on `integration/tenancy`)

- `integration/tenancy` is 188 commits ahead of `main`; production is at
  migration 59 with the whole 060–091 series unapplied. **Tenancy is not in force
  anywhere.**
- Deploy is gated on: the 391-site conversion tail, FORCE preconditions, step
  11d, the `epigraph-tenancy-backfill` verify-at-zero, and a **not-yet-specified**
  end-to-end suite. §6.3 (decided 2026-09-14) says nothing merges to `main` until
  e2e passes on the integration branch.
- Locked decisions that matter here: **D1** ownership required and declared;
  **D2** legacy rows backfill to explicit `public`; **D3** `public` means any
  authenticated agent, anonymous callers get nothing.
- The enforcement boundary is **Rust, not Postgres** (§1 of that plan).
- Relevant open findings: `D-PR16-recall-events-are-instance-wide` (every agent's
  recall history is readable — gate any `get_recall_events` route behind
  tenancy); `D-PR16-claim-authorship-is-not-a-credential` (nothing checks a
  caller may author as the `agent_id` in the body — matters before pointing an
  always-on Notion writer at prod); `D-PR19-webhook-secret-at-rest` (webhook
  secrets stored plaintext).

### Notion-side state

The workspace (**Astera**) already has a working EpiGraph↔Notion contract, in the
**NanoDynamics Purchase Order System**: properties `EpiGraph Ingestion Status`,
`EpiGraph Claim ID`, `Provenance / Notion Page ID`, `Ingested By`,
`Record Schema Version`, with an idempotent round trip
(`check_already_ingested` → stage/batch_submit; supersede/patch keyed on the
stored Claim ID). **Generalize that contract rather than inventing one.** That
system also holds vendor TINs, bank-verification state and related-party flags —
i.e. exactly the content that must not be ingested as `public`.

---

## 4. Confidence bounds on the parity audit

The audit (spec §8) matched 86 `SCOPE_MAP` tools against 200 route paths at
**path/name level**, with a targeted grep per suspected gap.

- The ~15 tools listed in §8.2 are **verified absent** from `routes/`.
- Everything else is **verified present by path only**. Its semantics are
  *unverified* — and §8.3 (`recall` vs `/search/semantic`) demonstrates that a
  path-level match can hide two different features.

If the next agent needs a trustworthy full-parity matrix, budget for reading both
implementations per tool. Do not present the current audit as more than it is.

---

## 5. What to do next, in order

1. **Get the bundle onto a branch and open a draft PR.** Nothing else is
   reviewable until it is.
2. **Decide the two blocking questions in §7** — they change the work.
3. **Phase 1 of the spec: the reader.** `/`, `/search`, `/claim/:id` with
   outlinks, OG tags, BFF with OAuth. No graph canvas. The claim page is two
   calls and a loop; do not over-build it.
4. **File the parity backlog item** (spec §9, items 1–3). Use
   `mcp__epigraph__submit_claim` with label `backlog` — and when it is later
   retired, `resolve_backlog_item`, never a free-text "Resolves <UUID>"
   (CLAUDE.md is explicit and there is a daily reconciler that catches the
   mistake).
5. **Close the §8.2 gaps that Phase 2/3 need**: `get_provenance_chain` and
   `check_already_ingested` first. `get_recall_events` is deliberately deferred.
6. **Write the Notion auto-ingest spec separately.** It is sketched in the
   conversation but not specified: registry database, content-hash pipeline
   version, reconciler cron on the `git_ingest_reconciler.py` pattern, and the
   deleted-paragraph policy (§7 below).

---

## 6. Traps found in this session

- **The pipeline-version gate silently no-ops on edited pages.** Papers are
  immutable, Notion pages are not. Re-ingesting an edited page short-circuits on
  the `processed_by` edge and does nothing. Fix by stamping a content revision
  into the pipeline version (`…:notion:<blake3(markdown)[..12]>`), copying the
  `:ch{n}` pattern. **Hash the rendered content, not `last_edited_time`** —
  Notion bumps that timestamp on no-op and property-only edits.
- **Detached ingest tasks.** See §3. A reconciler that writes
  `EpiGraph Ingestion Status` back to Notion must poll, not assume.
- **Bundling a UI around neighborhood IDs will break weekly.** See §3.
- **Declassification runs both ways.** Notion → EpiGraph: private pages becoming
  `public` claims (worsened by D2's backfill-to-`public`, so anything ingested
  before tenancy deploys is workspace-readable by default). EpiGraph → Notion: a
  projected claim is protected by *Notion's* ACLs, and `claims_block_widening`
  cannot catch a widening that happens outside the database. The web-UI design
  removes the second direction entirely; the first is still live.
- **Section cross-references in the spec were renumbered late.** They were fixed
  in the amend; if you edit section order, re-check them.

---

## 7. Open decisions — need the operator, not an agent

1. **Deleted-paragraph policy.** When a paragraph disappears from an ingested
   Notion page, what happens to its claim? Recommendation was a `stale` label
   plus manual retire, *not* auto-supersede. Unresolved. Decide before the first
   sensitive page flows — it gets much more expensive later.
2. **Group ↔ teamspace pairing.** Which EpiGraph group owns claims from which
   Notion teamspace, and at what visibility. Required by D1 once tenancy lands;
   worth recording now so the columns are populated correctly rather than
   backfilled to `public` by D2.
3. **BFF language** — Rust/axum matches the team; Node/TS gets a better graph-canvas
   ecosystem. `services/` precedent is Python (`nli`), so either is in keeping.
4. **Does `get_recall_events` get an API route at all?** See §3, tenancy findings.
5. **Who owns the parity backlog item** — it spans both surfaces and belongs to
   neither.

---

## 8. Conventions the next agent must follow

From `CLAUDE.md`, the ones this work will touch:

- **Do not add tools to `epigraph-tools`.** It is not the extension point. A
  kernel tool goes in the `#[tool_router]` impl **and** `SCOPE_MAP` (a coverage
  test fails until it does). A downstream product — **which the Notion service
  is** — runs a separate `rmcp` server on loopback and mounts via
  `EPIGRAPH_MCP_EXTENSIONS`; `episcience` is the reference. Federated tools do
  **not** go in `SCOPE_MAP`.
- **All SQL in `crates/epigraph-db/src/repos/`.** Adding a route for a §8.2 gap
  means extending the repo layer, not writing SQL in the handler — notwithstanding
  that 33/64 route files already break this.
- After touching a `sqlx::query!` macro, run
  `cargo sqlx prepare --workspace -- --tests` and commit `.sqlx/`.
- **Do not widen `claim_from_row`'s signature** (~20 callers). Extend the caller's
  `SELECT` and post-fix the returned `Claim`.
- **Test against `epigraph_db_repo_test`**, never the live `epigraph` DB —
  integration tests there fan out for 30+ minutes and pollute production claim
  state.
- **Every new claim write path must embed inline post-commit**, best-effort;
  every path flipping `is_current = false` must null the embedding in the same
  transaction. The Notion ingest path inherits this.
- **Commits follow the Epistemic Commit Protocol** — Evidence / Reasoning /
  Verification, one logical decision per commit.
- Feature branches; `gh pr merge --merge --delete-branch`, never `--squash`
  unless told.
