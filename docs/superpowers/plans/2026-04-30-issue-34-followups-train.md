# issue-34 Followups Train Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the 5 atomic commits on `origin/feat/issue-34-followups` as a single PR, closing #43, #44, #49, #51 and partially closing #48 (with a followup issue filed for #48's remaining parts).

**Architecture:** A1 + Epistemic Commit Architecture — one PR mechanically, five atomic commits epistemically. Rebase the branch onto current main (drops 27 redundant commits), verify per-commit build + workspace tests + clippy, file the #48 followup issue, push (force-with-lease), open PR.

**Tech Stack:** git worktrees, cargo workspace, gh CLI / GitHub MCP, Rust toolchain.

**Spec:** `docs/superpowers/specs/2026-04-30-issue-34-followups-train-design.md`

---

## File Structure

This is a release plan — no source files are created or modified. The artifacts produced are:

| Artifact | Where |
|---|---|
| Worktree (temporary) | `/home/jeremy/epigraph-wt-issue-34-followups` |
| Rebased branch | `feat/issue-34-followups` (force-pushed to origin) |
| Followup issue | `epigraph-io/epigraph` issue tracker (new issue) |
| Pull request | `epigraph-io/epigraph` PRs |

**Path discipline:** Every command in this plan uses absolute paths. Per the project's "subagent worktree path discipline" memory, any subagent executing this MUST prefix `cd /home/jeremy/epigraph-wt-issue-34-followups &&` to every Bash block (or use absolute paths in every command). Drift to `/home/jeremy/epigraph` is the failure mode.

---

## Phase 1: Worktree setup

### Task 1: Create the rebase worktree

**Files:** none (creates worktree only)

- [ ] **Step 1: Verify no stale worktree exists at the target path**

Run:
```bash
ls /home/jeremy/epigraph-wt-issue-34-followups 2>&1
```

Expected: `ls: cannot access ...: No such file or directory`

If the path exists, stop and ask the user — there may be in-progress work.

- [ ] **Step 2: Fetch origin and create the worktree**

Run:
```bash
cd /home/jeremy/epigraph
git fetch origin
git worktree add /home/jeremy/epigraph-wt-issue-34-followups origin/feat/issue-34-followups
```

Expected output ends with: `HEAD is now at 13c46a02 feat(api): expose theme_id + cluster_id on /search/semantic results (#49)`

- [ ] **Step 3: Confirm starting state**

Run:
```bash
cd /home/jeremy/epigraph-wt-issue-34-followups && git log --oneline -1 && git rev-list --left-right --count origin/main...HEAD
```

Expected: tip is `13c46a02 feat(api): expose theme_id + cluster_id ...`; counts are `57	32` (57 commits on origin/main not on branch; 32 on branch not on origin/main).

---

## Phase 2: Rebase + verification gates

### Task 2: Rebase onto origin/main (Gate A)

**Files:** none (history rewrite only)

- [ ] **Step 1: Run the rebase**

Run:
```bash
cd /home/jeremy/epigraph-wt-issue-34-followups && git rebase origin/main
```

Expected: rebase completes silently with no conflict prompts. Final message: `Successfully rebased and updated refs/heads/feat/issue-34-followups.`

If conflicts arise: stop, do NOT force through with `git rebase --skip` or `--theirs`. Surface to the user with the conflicting paths. Fallback per the spec's Fallbacks table: switch to A2 (split-PRs) for the conflicting subset.

- [ ] **Step 2: Verify the train collapsed to 5 commits**

Run:
```bash
cd /home/jeremy/epigraph-wt-issue-34-followups && git log --oneline origin/main..HEAD
```

Expected output (5 lines, in this order from tip to base):
```
<sha> feat(api): expose theme_id + cluster_id on /search/semantic results (#49)
<sha> feat(api): POST /api/v1/themes/build-from-corpus (#48)
<sha> refactor(ingest): hoist workflow-ingest core into epigraph-ingest-executor (#44)
<sha> refactor(ingest): hoist shared helpers + workflow edge-case tests (#43)
<sha> fix(api,mcp): write variant_of edge on hierarchical workflow ingest (#51)
```

If the count is not 5, stop. Either the rebase didn't drop the redundant commits (unexpected — maybe migrations diverged) or it dropped too many. Surface to the user.

- [ ] **Step 3: Capture the new SHAs for the PR body**

Run:
```bash
cd /home/jeremy/epigraph-wt-issue-34-followups && git log --oneline origin/main..HEAD --reverse > /tmp/issue-34-followups-shas.txt && cat /tmp/issue-34-followups-shas.txt
```

Save the output — these SHAs go into the PR body's commit↔issue map (Task 9).

### Task 3: Per-commit build verification (Gate B)

**Files:** none (compile-only check)

- [ ] **Step 1: Loop build across each commit**

Run:
```bash
cd /home/jeremy/epigraph-wt-issue-34-followups
for sha in $(git log --reverse --format=%H origin/main..feat/issue-34-followups); do
  echo "=== $sha ==="
  git checkout --quiet "$sha"
  cargo build --workspace --quiet 2>&1 | tail -5
  if [ ${PIPESTATUS[0]} -ne 0 ]; then echo "BREAK at $sha"; break; fi
done
git checkout --quiet feat/issue-34-followups
```

Expected: 5 `=== <sha> ===` blocks, no `BREAK` line, final `git checkout` returns to branch tip silently.

If any commit fails to build: that commit is broken in isolation. This breaks `git revert <sha>` for that commit later. Stop and surface to the user — likely needs `git rebase -i --edit <sha>` to repair, but interactive rebase is restricted in this environment, so the user must do it manually.

- [ ] **Step 2: Confirm we returned to the branch tip**

Run:
```bash
cd /home/jeremy/epigraph-wt-issue-34-followups && git log --oneline -1
```

Expected: same SHA as Task 2 Step 2's first line (the #49 commit).

### Task 4: Workspace test suite (Gate C)

**Files:** none

- [ ] **Step 1: Run the full test suite**

Run:
```bash
cd /home/jeremy/epigraph-wt-issue-34-followups && cargo test --workspace 2>&1 | tee /tmp/issue-34-followups-test.log | tail -30
```

Expected final summary line for each crate: `test result: ok. N passed; 0 failed; 0 ignored; ...`. The tail will show the last test crate's summary.

If any crate reports `FAILED` or `0 passed`: capture the failing test name from `/tmp/issue-34-followups-test.log` and surface to the user. Per the spec, we don't silently skip with `--no-verify`.

- [ ] **Step 2: Confirm all crates passed**

Run:
```bash
grep -E "^test result:" /tmp/issue-34-followups-test.log | grep -v "ok\." | head
```

Expected: empty output (no non-ok results).

### Task 5: Workspace clippy lint (Gate D)

**Files:** none

- [ ] **Step 1: Run clippy with warnings-as-errors**

Run:
```bash
cd /home/jeremy/epigraph-wt-issue-34-followups && cargo clippy --workspace -- -D warnings 2>&1 | tee /tmp/issue-34-followups-clippy.log | tail -20
```

Expected: `Finished` line at the end with no `error` or `warning:` lines preceding it.

If warnings/errors: surface the specific ones from `/tmp/issue-34-followups-clippy.log`. Don't bypass.

### Task 6 (manual gate, requires user): Smoke tests (Gate E)

**Files:** none

This task requires a running staging API + DB. Surface to the user rather than attempt automation.

- [ ] **Step 1: Ask the user to run the two smoke tests**

Send to user:
> Gate E (smoke) needs your hands. Two tests on staging:
>
> 1. `POST /api/v1/themes/build-from-corpus` returns 200 and creates `claim_themes` rows.
> 2. `POST /api/v1/workflows/ingest` with `parent_canonical_name` set: confirm a `variant_of` row appears in `edges` table.
>
> Ack when both pass (or paste the failure).

- [ ] **Step 2: Wait for ack**

Do not proceed to Phase 3 without user confirmation. If user says "skip smoke for now, push to staging via the PR's CI": that's their call; record the decision in the PR body's test plan as `[ ] Manual smoke — deferred to staging post-merge`.

---

## Phase 3: File followup issue, push, open PR

### Task 7: File the #NEW followup issue for #48 residuals

**Files:** none (creates an issue on github.com)

- [ ] **Step 1: Create the followup issue**

Use the GitHub MCP tool `mcp__plugin_github_github__issue_write` with:
- owner: `epigraph-io`
- repo: `epigraph`
- title: `Feature: complete #48 — 3072d centroids, build-from-bridges, diverse=true dim hint, scheduled rebuild`
- body:
```markdown
#48 part 1 (POST /api/v1/themes/build-from-corpus) shipped in commit <sha-of-#48-commit-from-task-2-step-3>.

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

If `issue_write` schema needs `action: create` or similar parameter, fetch the schema with `ToolSearch query="select:mcp__plugin_github_github__issue_write"` first.

- [ ] **Step 2: Capture the new issue number**

Save the issue number returned (e.g., `#58`) for use in Task 9's PR body.

### Task 8: Push the rebased branch (force-with-lease)

**Files:** none (updates remote ref)

- [ ] **Step 1: Force-push with lease**

Run:
```bash
cd /home/jeremy/epigraph-wt-issue-34-followups && git push --force-with-lease origin feat/issue-34-followups
```

Expected: `+ <old-sha>...<new-sha> feat/issue-34-followups -> feat/issue-34-followups (forced update)`

`--force-with-lease` (not `--force`) protects against the case where someone else pushed to the branch since our last fetch — the push will refuse if origin has moved.

If the push refuses with "stale info" or similar: someone updated the branch on origin since Task 1. Stop and re-evaluate (likely re-fetch + re-rebase the new tip).

This force-push is to a feature branch (not main), and is the standard outcome of any rebase. It does NOT violate the project's no-force-push-to-main rule.

- [ ] **Step 2: Verify origin matches local**

Run:
```bash
cd /home/jeremy/epigraph-wt-issue-34-followups && git fetch origin && git rev-list --left-right --count HEAD...origin/feat/issue-34-followups
```

Expected: `0	0`

### Task 9: Open the pull request

**Files:** none (creates a PR on github.com)

- [ ] **Step 1: Compose the PR body**

Substitute the SHAs captured in Task 2 Step 3 and the followup issue number from Task 7 Step 2 into this template:

```markdown
## Summary
Five atomic commits, one per issue. Each commit is independently revertable.

## Commit ↔ Issue map
| Commit | Issue | Resolution |
|---|---|---|
| <sha-of-#51> | #51 | Closes |
| <sha-of-#43> | #43 | Closes |
| <sha-of-#44> | #44 | Closes |
| <sha-of-#48> | #48 | Partial — see #<followup-number> |
| <sha-of-#49> | #49 | Closes |

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
- [x] cargo build --workspace (verified per-commit and on tip)
- [x] cargo test --workspace
- [x] cargo clippy --workspace -- -D warnings
- [x] Manual: POST /api/v1/themes/build-from-corpus on staging
- [x] Manual: POST /api/v1/workflows/ingest with parent → assert variant_of edge

Closes #43, #44, #49, #51.
Refs #48 (#<followup-number>).
```

If user deferred Gate E in Task 6: change the two `[x] Manual:` lines to `[ ] Manual: ... (deferred to staging post-merge)`.

- [ ] **Step 2: Open the PR via gh CLI**

Run:
```bash
cd /home/jeremy/epigraph-wt-issue-34-followups && gh pr create \
  --title "issue-34 followups: variant_of fix + ingest hoist + theme bootstrap" \
  --body "$(cat /tmp/issue-34-followups-pr-body.md)" \
  --base main \
  --head feat/issue-34-followups
```

(Write the composed body from Step 1 to `/tmp/issue-34-followups-pr-body.md` first.)

Expected: prints the new PR URL on stdout, e.g., `https://github.com/epigraph-io/epigraph/pull/58`

- [ ] **Step 3: Surface the PR URL to the user**

Send to user:
> PR opened: <URL>. Five atomic commits per the spec. Smoke tests <ack/deferred>. Closes #43, #44, #49, #51; refs #48 via the new followup issue #<num>.

---

## Phase 4: Cleanup

### Task 10: Remove the worktree (only after PR merges)

**Files:** none (removes worktree)

This task is **deferred** — do not execute as part of the initial implementation. Run only after the PR has been merged and CI is green on `main`.

- [ ] **Step 1: Confirm PR is merged**

Verify via gh CLI: `gh pr view <PR-number> --json state -q .state` returns `"MERGED"`.

- [ ] **Step 2: Remove the worktree**

Run:
```bash
cd /home/jeremy/epigraph && git worktree remove /home/jeremy/epigraph-wt-issue-34-followups
```

Expected: silent success.

If worktree has uncommitted changes (shouldn't, but possible if someone touched it): surface to the user before removing.

- [ ] **Step 3: Clean up the rebased remote branch (optional)**

If GitHub auto-deleted the branch on merge: nothing to do.

If not: `git push origin --delete feat/issue-34-followups`. Confirm with the user before deleting.

---

## Self-Review Notes

**Spec coverage check** — every spec section maps to a task:
- "Architecture: the splittable monolith" → Task 2 (rebase preserves 5 atomic commits)
- "Commit topology" → Task 2 Step 2 (verify exactly 5 commits in expected order)
- "Rebase plan" → Task 1 + Task 2
- "Verification gates A–E" → Tasks 2–6 (one per gate, in order)
- "Followup issue (file before opening PR)" → Task 7
- "PR shape" → Task 9
- "Fallbacks" → embedded in Task 2 Step 1 (rebase conflicts), Task 3 Step 1 (per-commit build break), Task 4 Step 1 (test failure)
- "Open considerations: hotfix/graph-overview-themes" → noted in PR body's Out-of-scope section (Task 9)
- "Open considerations: PR-body trailers vs per-commit edits" → resolved by using PR body `Closes:` line (Task 9 Step 1), no per-commit edits attempted

**Placeholder scan** — no `TBD`, no "appropriate", no "etc". The `<sha>` and `<followup-number>` placeholders are intentional substitution points captured in Task 2 Step 3 and Task 7 Step 2 respectively, with explicit instructions for what fills them.

**Type/name consistency** — file paths and commands use the same worktree path throughout (`/home/jeremy/epigraph-wt-issue-34-followups`). Branch name `feat/issue-34-followups` consistent. Gate labels A–E match the spec's verification gates table.
