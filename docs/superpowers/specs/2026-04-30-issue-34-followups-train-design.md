# issue-34 Followups Train — Design

**Branch:** `feat/issue-34-followups` (origin)
**Issues closed:** [#43](https://github.com/epigraph-io/epigraph/issues/43), [#44](https://github.com/epigraph-io/epigraph/issues/44), [#49](https://github.com/epigraph-io/epigraph/issues/49), [#51](https://github.com/epigraph-io/epigraph/issues/51)
**Issue partially closed:** [#48](https://github.com/epigraph-io/epigraph/issues/48) (part 1 only)
**Followup issue to file:** complete #48 — 3072d centroids, build-from-bridges, diverse=true dim hint, scheduled rebuild

**Date:** 2026-04-30
**Author:** brainstorming with the user, captured here

## Problem

Five issues from the #34 hierarchical-workflow review have implementations sitting on `origin/feat/issue-34-followups` but no PR exists. Local `main` is in sync with `origin/main` (0 ahead, 0 behind). Recent merges (#56 cascade-trigger, #57 edge-validation) closed adjacent work but left this train idle.

The branch is 32 commits ahead of `main` and 57 behind. Of the 32: only 5 commits are net-new. The other 27 are #34 commits already on `main` via PR #55, plus migrations 019–023 already on `main`. A rebase will collapse the train to its 5 atomic commits cleanly, with no predicted conflicts (the new commits touch ingest-executor, workflow_ingest tools, theme routes, and `crud.rs`; recent main additions touch DB triggers and `validate_edge_reference` — disjoint surface).

## Goals

- Ship the five completed-but-unmerged fixes and refactors without bundling unrelated work
- Preserve atomic per-issue provenance so any single issue can be reverted in isolation post-merge (`git revert <sha>`)
- Make the partial close on #48 unambiguous by filing a followup issue covering parts A/B/C/D before merging
- Each commit conforms to the EpiGraph Epistemic Commit Protocol (atomic, with evidence/reasoning/verification)

## Non-goals (deferred)

- The `recall_with_context` chain (#35, #45, #46, #52) — separate train; #35 needs porting from `internal-main`
- #36 (regenerate migrated flat workflows hierarchically) — backlog item, separate scope
- #53 (cross-component bridge sweep) — net-new feature, separate design
- #54 root-cause fix (automated startup migration runner) — needs its own design; the local-only `hotfix/graph-overview-themes` branch addresses one symptom but is out of scope here
- Completing #48 parts A/B/C/D — filed as a new followup issue instead

---

## Architecture: the splittable monolith

One PR mechanically; five atomic commits epistemically. The unit of merge is the PR; the unit of provenance is the commit.

Each of the five commits:

- Is the entire change for exactly one issue (no entanglement)
- Is independently revertable: `git revert <sha>` rolls back exactly that issue
- Is independently cherry-pickable to other branches (e.g., a security-patch backport)
- Carries an Evidence / Reasoning / Verification body per the Epistemic Commit Protocol

Splitting an issue post-merge is mechanical: revert the commit, open a new PR. No diff archaeology required.

## Commit topology (post-rebase)

In topological order on `feat/issue-34-followups` after `git rebase origin/main`:

| # | Commit (current sha) | Issue | Resolution |
|---|---|---|---|
| 1 | `02b5fe5d` fix(api,mcp): variant_of edge on hierarchical workflow ingest | #51 | Closes |
| 2 | `3f6be243` refactor(ingest): hoist shared helpers + workflow edge-case tests | #43 | Closes |
| 3 | `8adb97f2` refactor(ingest): hoist workflow-ingest core into epigraph-ingest-executor | #44 | Closes (layers on #43) |
| 4 | `1dfc0160` feat(api): POST /api/v1/themes/build-from-corpus | #48 | Partial — Refs |
| 5 | `13c46a02` feat(api): expose theme_id + cluster_id on /search/semantic results | #49 | Closes |

Commit shas may renumber after rebase; the topology is what's load-bearing.

The existing commit messages already follow the Epistemic Commit Protocol in spirit (atomic, with stated reasoning and tests-as-verification). No reword pass required for content; the only PR-time touch-up is to ensure each message ends with a `Closes #N` (or `Refs #48` for commit 4) trailer so GitHub auto-closes on merge. If interactive rebase is restricted in this environment, the trailers can live in the PR body's `Closes:` line instead — GitHub auto-closes from PR body equally well.

## Rebase plan

Operate from a fresh worktree (per project worktree convention; multiple Claude sessions share this repo):

```bash
cd /home/jeremy/epigraph
git worktree add ../epigraph-wt-issue-34-followups origin/feat/issue-34-followups
cd /home/jeremy/epigraph-wt-issue-34-followups
git fetch origin
git rebase origin/main
```

Expected outcome: 27 redundant #34 commits drop, 5 atomic commits remain. Migrations 019–023 reconcile to no-ops because identical files already exist on `main`.

If conflicts arise (not predicted): stop and re-evaluate. Do not force through. Fallback option below.

## Verification gates (do not proceed past failure)

| Gate | Command | Pass criterion |
|---|---|---|
| A — Rebase clean | `git rebase origin/main` | 5 commits remain, no conflicts |
| B — Per-commit build | Loop `git checkout $sha && cargo build --workspace --quiet` | Every commit builds (catches mid-rebase regressions early) |
| C — Workspace tests | `cargo test --workspace` | Green on tip of branch |
| D — Lint clean | `cargo clippy --workspace -- -D warnings` | No warnings |
| E — Smoke | Manual `POST /api/v1/themes/build-from-corpus` on staging; manual `POST /api/v1/workflows/ingest` with parent set, then assert `variant_of` edge in `edges` table | Both succeed |

Gate B is non-obvious but valuable: it catches the case where rebase preserves the tip but breaks an intermediate commit, which would silently break `git revert` later.

## Followup issue (file before opening PR)

```
Title: Feature: complete #48 — 3072d centroids, build-from-bridges, diverse=true dim hint, scheduled rebuild

Body:
#48 part 1 (POST /api/v1/themes/build-from-corpus) shipped in commit 1dfc0160.

Remaining parts (each a separable sub-task):
- A. centroid_3072 vector(3072) columns on claim_themes and cluster_centroids
     (requires re-embedding corpus through OpenAI API + rebuilding HNSW indexes
     where applicable — pgvector HNSW caps at 2000 dims, so 3072d centroids stay
     sequential-scan only, fine for typical theme/cluster counts)
- B. POST /api/v1/clusters/build-from-bridges (Louvain over decomposes_to bridges
     where two paragraphs share ≥1 atom child)
- C. centroid_dim hint on /search/semantic?diverse=true (default to whichever
     centroid column has data when both don't)
- D. Scheduled theme_cluster_rebuild job in epigraph-jobs::JobRunner
     (sibling to existing cluster_graph job; backed off when corpus unchanged)

Refs #48.
```

## PR shape

**Title:** `issue-34 followups: variant_of fix + ingest hoist + theme bootstrap`

**Body:**

```markdown
## Summary
Five atomic commits, one per issue. Each commit is independently revertable.

## Commit ↔ Issue map
| Commit | Issue | Resolution |
|---|---|---|
| <sha1> | #51 | Closes |
| <sha2> | #43 | Closes |
| <sha3> | #44 | Closes |
| <sha4> | #48 | Partial — see #NEW |
| <sha5> | #49 | Closes |

## Splitting policy
If any single issue regresses or needs to be reverted post-merge,
`git revert <sha>` rolls back exactly that issue with no entanglement.

## Out of scope
- hotfix/graph-overview-themes (local, unpushed) — addresses #54 symptom; #54's
  real fix is an automated startup migration runner, separate design.
- recall_with_context chain (#35, #45, #46, #52) — separate train.
- #36 flat→hierarchical workflow regeneration — backlog.
- #53 cross-component bridge sweep — separate design.

## Test plan
- [ ] cargo build --workspace
- [ ] cargo test --workspace
- [ ] cargo clippy --workspace -- -D warnings
- [ ] Manual: POST /api/v1/themes/build-from-corpus on staging
- [ ] Manual: POST /api/v1/workflows/ingest with parent → assert variant_of edge

Closes #43, #44, #49, #51.
Refs #48 (#NEW).
```

## Fallbacks

| Failure | Response |
|---|---|
| Rebase conflicts non-trivial | Switch to A2 split-PRs for the conflicting subset only; merge #51 standalone first, then rebase the rest |
| Migration ordering disputed (not predicted — files identical to main) | `git rm` the migrations from the rebase resolution |
| Test we don't own breaks | Surface to user; do not silently skip with `--no-verify` |
| `git rebase -i` needed but unavailable | Use PR-body `Closes:` trailers instead of per-commit message edits |

## Open considerations (not blockers)

- The local-only `hotfix/graph-overview-themes` is one commit (`cabe869a`) that fixes one #54 symptom (`graph/overview` reads `claim_themes`). Not in this train, but worth pushing as a separate small PR or noting in `MEMORY.md` so it doesn't get lost. Recommend handling as a separate one-commit PR after this train merges.

- The PR-body `Closes:` trailer approach (vs per-commit message edits) trades a small amount of provenance fidelity (the commit itself doesn't say which issue) for not needing interactive rebase. Acceptable because the PR-body map and the original issue-numbered subject lines together carry the provenance.
