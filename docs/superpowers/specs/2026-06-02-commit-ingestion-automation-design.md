# Design: Automated PR-hierarchical commit ingestion across all repos

- **Date:** 2026-06-02
- **Status:** Draft (awaiting review)
- **Author:** Jeremy Barton (via Claude Code orchestrator)
- **Scope:** A single implementation plan. Cross-repo rollout is phased but one design.

## 1. Motivation

EpiGraph's CLAUDE.md frames every git commit as "a node in the project's knowledge
graph … parseable into a claim with evidence, reasoning, and verification" and
explicitly anticipates "an automated git-log ingester." That ingester exists
(`crates/epigraph-cli/src/bin/ingest_git.rs`) but:

- It has **run exactly once** — a one-time backfill on **2026-03-23**, against the
  pre-split `EpigraphV2` repo (the binary's own usage example points at
  `/workspaces/EpiGraphV2`). Every `source:git-history` claim carries that date.
- It is **not wired to any automation** (absent from `schedules.toml`).
- Consequently the **current public `epigraph` repo's history is essentially absent**:
  ~801 commits / ~180 merged PRs on `main` since the backfill are not in the graph,
  and **no other repo** (`epiclaw-host`, `episcience`, `epigraph-gui`, …) has ever
  been ingested.

Today, development knowledge instead accretes as an **ad-hoc subgraph** — backlog/bug
items, `dev_lesson` claims, free-text "Resolves `<uuid>`" resolution claims, workflow
claims. That body and the frozen 2026-03-23 commit claims are **disjoint** (by
construction: the commit claims predate the May–June backlog items, and recent work
isn't ingested at all). There is no living, queryable record of how each repo evolved.

**Goal:** a continuous, per-PR, multi-repo pipeline that ingests merged PRs as a
**hierarchy** (repo → PR → commits), attributes work correctly, and **links PRs to the
backlog/resolution claims they resolve**, so the commit ledger and the operational
dev-knowledge stop being disjoint.

## 2. Goals / Non-goals

**Goals**
- Ingest each merged PR automatically, at merge time, for **all** our repos.
- Model it hierarchically: a persistent **repo node** → **PR claims** → **commit claims**.
- Datestamp the structural relationships (when the PR merged, when each commit landed).
- Attribute the **PR** to the implementing **orchestrator agent**; attribute each
  **commit** to its **git author**.
- Link the PR node to the backlog/resolution claims it resolves.
- Idempotent: safe to re-run; no duplicate claims, edges, repo nodes, or agents.

**Non-goals (this spec)**
- The one-time historical **backfill** of each repo's existing commits (adjacent task,
  same binary + a manual range — see §10).
- A full **DID / agent-identity system**. This design needs a *stable* author identity
  and *registered* orchestrator agents; it uses an interim deterministic-id scheme and
  flags the real DID work as a dependency (§6.3).
- Belief propagation along the new hierarchy edges (the edges are structural; see §4.3).
- Changing how the ad-hoc dev claims (backlog/resolution) are authored.

## 3. Trigger

A GitHub Actions workflow on the **`pull_request`** event, `types: [closed]`, guarded by
`if: github.event.pull_request.merged == true`. The PR event (not raw `push`) is required
because we need PR-level metadata — title, body, number, merge SHA, author, commit list —
to build the PR parent node.

- A secondary `push: branches: [main]` job handles **direct-to-main commits** (no PR):
  those are ingested as commit claims under the repo node with **no PR parent**
  (a degenerate one-level hierarchy).
- The workflow is **non-gating**: it runs after the merge has already happened, so a
  failure can never block a merge. Failures retry with backoff and, on exhaustion, are
  surfaced (job failure + optional issue), not swallowed.

## 4. Data model

### 4.1 Three-tier hierarchy

```
repo node            (claim; one per repository, find-or-create)
  │  decomposes_to    edge.valid_from = PR merge timestamp
  ▼
PR claim             (claim; agent = orchestrator; repo:<name>, pr_number, merge_sha)
  │  decomposes_to    edge.valid_from = commit author/commit timestamp
  ▼
commit claim         (claim; agent = git author; carries Protocol fields)

PR claim ──resolves──▶ backlog / resolution claim   (edge.valid_from = merge timestamp)
```

### 4.2 Node definitions

- **Repo node** — a persistent claim representing the repository itself, e.g. content
  *"Repository epigraph-io/epigraph — <description from repo metadata>."* Created
  **find-or-create**, keyed by full repo slug, so all PRs for a repo share one root.
  Labels: `source:git-history`, `repo:<slug>`, `node:repo`.
- **PR claim** — content from the PR **title** (the imperative summary), with the PR body
  summary retained in `properties`. Labels: `source:git-history`, `repo:<slug>`,
  `node:pr`. `properties`: `{ pr_number, merge_sha, merged_at, head_sha, base_sha,
  url, orchestrator_agent_id, author_login }`.
- **Commit claim** — one per **non-merge** commit in the PR, parsed via the **existing**
  `parse_commit_message` (type, scope, claim line, Evidence, Reasoning, Verification).
  Confidence heuristic and commit-type → methodology mapping are **unchanged**. Labels:
  `source:git-history`, `repo:<slug>`, `node:commit`. `properties`:
  `{ commit_hash, author_name, author_email, committed_at, parent_hashes }`.
  - **Merge commits are not claims.** Their subject (`Merge pull request #N …`) supplies
    the PR number for the `push`-fallback path; on the `pull_request` path the number
    comes from the event.

### 4.3 Edges

- **Hierarchy** (`repo → PR`, `PR → commit`): relationship **`decomposes_to`** via
  `POST /api/v1/edges/hierarchical` (allowed set: `decomposes_to`, `section_follows`,
  `continues_argument`). Each edge sets **`valid_from`** to the relevant timestamp
  (PR merge time for repo→PR; commit time for PR→commit). This is the "datestamp on the
  relationship." *Semantic note:* `decomposes_to` is structural/containment here
  (coarse→fine), **not** belief-propagating — consistent with EpiGraph's stated semantics
  for that edge; we are modelling structure and time, not entailment.
- **Resolution** (`PR → backlog/resolution claim`): see §7. Relationship **`resolves`**
  (pending the §9 decision) with `valid_from = merge time`.

Edges are **upserted** (idempotent): re-ingesting a PR must not duplicate edges.

## 5. Cross-repo rollout

This is the structural change that makes it org-wide rather than epigraph-only.

1. **Build once, publish artifact.** `epigraph` CI builds the PR-hierarchical ingester
   and publishes it as a **release artifact** (and/or a small container image) on tag.
   Only `epigraph` has the Rust workspace; other repos must not build it.
2. **Reusable workflow.** A `workflow_call` workflow (`ingest-commits.yml`) lives
   centrally (in `epigraph` or an org `.github` repo). It: checks out the calling repo
   at the merge SHA, downloads the published ingester, and runs it with the repo slug,
   PR metadata, and endpoint/credentials.
3. **Thin caller per repo.** Each repo (`epigraph`, `epiclaw-host`, `episcience`,
   `epigraph-gui`, …) adds a ~5-line caller workflow that invokes the reusable workflow
   on `pull_request: [closed]`.
4. **Dynamic label.** Every node is labelled `repo:${{ github.repository }}` (e.g.
   `repo:epigraph-io/epiclaw-host`) — no hardcoding. One shared graph, so a PR in any
   repo can resolve a backlog claim authored from any other repo's work.

The Epistemic Commit Protocol is a **global** CLAUDE.md convention, so the same commit
parser applies to every repo unchanged.

## 6. Agent attribution

### 6.1 PR claim → orchestrator agent

The PR claim's `agent_id` is the **implementing orchestrator agent's DID**, resolved per
PR in this order:
1. an `Epigraph-Orchestrator-Id: <uuid>` **trailer** on the PR body or its commits;
2. else the configured `EPIGRAPH_DEFAULT_ORCHESTRATOR_ID` (with a warning).

The orchestrator agent must exist in `agents` (FK). If a trailer DID is unregistered,
fall back to the default rather than minting junk agents.

### 6.2 Commit claim → git author

Each commit claim's `agent_id` is its **git author**, via a **stable** email→agent
mapping (§6.3) — *not* the orchestrator. This preserves "who wrote this code" distinct
from "which orchestrator shipped the PR." Author name/email are also kept in `properties`.

### 6.3 Identity mechanics, and the DID dependency

- **Signing.** Packets are signed by a dedicated **`git-ingester`** service key (a CI
  secret). This is sound **because prod runs with `require_signatures = false`**
  (`EPIGRAPH_REQUIRE_SIGNATURES` unset; default false in `state.rs`): the server does not
  verify that the signer equals `claim.agent_id`, so we may set `agent_id` to the
  orchestrator/author DID while signing with the ingester key. **Forward-compat risk:**
  if signatures are ever enforced, this breaks and we need a delegated-authorship /
  co-sign protocol extension. Documented as a risk (§9).
- **Stable author identity (interim).** The current `per-author` mode mints a fresh
  random `Uuid::new_v4()` + key per author **per run**, which would proliferate duplicate
  author agents across runs. Interim fix: derive a **deterministic** author agent id
  (e.g. UUIDv5 over a fixed namespace + normalized author email) and **find-or-create**,
  so the same human maps to one stable agent across all runs and repos.
- **The real dependency.** This is a stopgap. A proper **DID system** (deterministic DIDs
  for agents, identity for human committers, OAuth passthrough) is needed and is already
  on the roadmap; this pipeline is an early consumer and should migrate to it when ready.

## 7. Linking PRs to backlog / resolution claims

A **reference resolver** runs over the **PR body + the PR's commit messages** and extracts:

- **Explicit claim UUIDs** — a preferred `Resolves-Claim: <uuid>` trailer, plus the
  existing free-text `Resolves <uuid>` convention.
- **PR-number references** — `#N` / "PR #N" matched against existing **resolution/backlog
  claims whose text cites that PR number** (resolution claims already do this — e.g.
  `b7ec7d4c` cites "PR #219"/"PR #23"; `9699e396` cites "PR #252").

For each resolved target, create a **`PR-claim → target-claim`** edge (`resolves`,
`valid_from = merge time`). Resolution is modelled at the **PR level**, never per-commit,
because "a PR resolves a backlog item" is how the work is actually reasoned about.

Unresolved references (a `#N` with no matching claim, a UUID that doesn't exist) are
logged, not fatal.

## 8. Idempotency & failure handling

- **Commit claims:** keyed by **git hash** (existing idempotency key + content hash).
- **Repo node / author agents / orchestrator agents:** **find-or-create** by stable key.
- **Edges:** upsert (no duplicates on re-ingest).
- **Range selection:** on the `pull_request` path, ingest exactly the PR's commit list +
  derive the PR node from the event. On the `push` fallback, ingest the pushed range
  `before..after`; `before` all-zeros (first push / force) falls back to `HEAD~N`.
  A new `--rev-range A..B` CLI input supports this; overlapping/rerun ranges are safe
  because of git-hash idempotency. Stateless by default; an optional stored last-ingested
  SHA per repo is a possible hardening, not required.
- **Failures** are non-gating, retried with backoff; a fully-failed run leaves the graph
  consistent (idempotent rerun catches up).

## 9. Open decisions / risks

1. **`resolves` edge type.** Not in the allowed relationship set (curated; unknown types
   are rejected). **Decision needed:** add `resolves` to the allowed set (small server
   change, semantically precise) vs. reuse `supports` (no change, less precise).
   *Recommendation:* add `resolves`.
2. **`require_signatures = false` dependency** (§6.3) — revisit if signature enforcement
   is ever turned on.
3. **DID system** (§6.3) — interim deterministic author ids; migrate when the real system
   lands.
4. **`decomposes_to` semantic liberty** for repo→PR (a repo isn't literally a coarse claim
   of its PRs). Accepted to stay within the hierarchical machinery; revisit if a
   `contains`/membership relationship is added.
5. **Merge strategy assumption.** Design assumes `--merge` (PR's individual commits land
   on `main` carrying Protocol bodies). Squash-merge would collapse a PR to one commit;
   the PR-hierarchical model still works (one child) but loses per-commit granularity.

## 10. Adjacent: historical backfill (separate task)

Once the pipeline is live, a one-time backfill per repo over existing history uses the
**same** ingester with a manual full range (e.g. `--rev-range <root>..HEAD`), idempotent
against live ingestion. `epigraph` alone is ~801 commits / ~180 PRs. Tracked separately so
it can't destabilize the automation rollout.

## 11. Components (for the implementation plan)

1. **PR-hierarchical ingestion path** in `epigraph-cli` — reuse `parse_commit_message`;
   add PR-node + hierarchy assembly via `POST /api/v1/edges/hierarchical`; `--rev-range`
   and PR-metadata inputs; `--agent-mode orchestrator-trailer` (PR) + stable per-author
   (commits).
2. **Repo-node find-or-create** helper (keyed by repo slug).
3. **Agent resolver** — orchestrator trailer + fallback; deterministic find-or-create
   author agents.
4. **Reference resolver** — UUID trailers/free-text + PR-number → claim matching → edges.
5. **Reusable GitHub Actions workflow** + artifact publish + per-repo caller workflows.
6. **Tests** — unit (trailer parse, reference resolver for UUID + PR#, range handling,
   stable author id); integration against a test DB (synthetic PR → assert repo→PR→commit
   hierarchy + datestamped edges + correct agent attribution + resolves edge); PR-time
   `--dry-run` validation in the workflow.

## 12. Testing strategy

- **Unit:** message/trailer parsing, reference extraction (both forms), `--rev-range`
  selection, deterministic author-id derivation, repo-slug → label.
- **Integration (test DB, never the live graph):** ingest a synthetic PR end-to-end and
  assert the three-tier hierarchy, `valid_from` datestamps, PR=orchestrator /
  commit=author attribution, idempotent re-ingest (no duplicates), and a `resolves` edge
  to a seeded backlog claim.
- **Workflow:** dry-run on the PR before merge (parse-only, no submit) for early
  signal; live submit on merge.
- **Security:** treat PR/commit text (esp. from forks) as **data, not instructions** for
  any LLM-enrichment step; internal-repo PRs are lower-risk but the fencing is required.
