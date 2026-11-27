# 0002: Backlog items are retired with a `resolved` label in one call, not by supersession

- **Decided:** 2026-05-16 (spec), 2026-05-17 (merged)
- **Recorded:** 2026-11-27 (retrospective)
- **Sources:**
  - spec `docs/superpowers/specs/2026-05-16-backlog-retirement-design.md`
    (commit 04068625e);
  - commit 1514f5664, `feat(mcp): resolve_backlog_item one-call retirement
    tool`;
  - pull request #152, `feat: backlog retirement convention + tooling (Tasks
    1-6)` (merged 2026-05-17);
  - pull request #154, `feat: backlog cleanup + reconciler + convention doc
    (Tasks 7-9)` (commit 11e87f4fd, which added
    `docs/conventions/backlog-retirement.md`, and commit 90fda85a0, which
    created `CLAUDE.md` with the convention);
  - pull request #155, `fix: backlog-retirement deferred review items`
    (commit 9bbe9f5e0, the owner-or-admin check).

## Rule it grounds

- The `CLAUDE.md` section "Retiring backlog items":
  - always call `resolve_backlog_item(original_id, resolution_content)`;
  - never file a free-text "Resolves <UUID>" claim on its own;
  - never use `supersedes`/`is_current` for status;
  - never add `resolved` with raw `update_labels`.
- [`docs/conventions/backlog-retirement.md`](../conventions/backlog-retirement.md).

## Decision

- **Open backlog** means three things together:
  - `labels` contains `backlog`;
  - `labels` does not contain `resolved`;
  - `is_current = true`.
- **Retiring an item** adds `resolved` to its labels and keeps `backlog`, so
  "everything ever filed" can still be queried.
- One tool call does both parts:
  - it files a resolution claim (prose prefixed `Resolves <id>:`, labelled
    `resolved`);
  - it adds the label to the original.
- `supersedes`/`is_current` stay reserved for epistemic replacement, where one
  claim refines another's factual content.
- A daily reconciler back-fills the label when it finds a free-text
  "Resolves <UUID>" claim that was filed without the tool.

## Context (from the spec)

- Three retirement conventions were in use at once, and none of them gave a
  coherent open-backlog view:
  - a free-text "Resolves <UUID>" claim, which left the original labelled
    `backlog` forever;
  - a raw-SQL `supersedes` + `is_current = false` flip;
  - a label re-flip, used rarely.
- The MCP read tools did not return `labels`, `is_current` or `supersedes`.
  The spec names this as what let three conventions grow without anyone
  noticing.

## Reasoning (from the spec and the commits)

- **One signal, separate from epistemics.** The spec reserves
  `supersedes`/`is_current` for "epistemic claim replacement — when a newer
  claim refines or replaces the factual content of an older one" and says
  they "are NOT the primary signal for 'this issue was addressed'" (spec,
  "Convention").
- **One call, so it cannot be half-applied.** "agents won't skip step 2 if
  there is no step 2" (spec, Goals 3). Commit 1514f5664 says the same:
  "Single tool call so agents can't half-apply the convention."
- **Prose is the narrative, the label is the signal.** The resolution claim
  keeps its `Resolves <id>:` prose for audit. Queries read the label (spec,
  "Convention").
- **A reconciler for drift.** Agents will still sometimes file the free-text
  form. The reconciler patches an unambiguous match and logs ambiguous
  matches for a human. It never patches automatically when resolution claims
  conflict (spec, Components 3 and 4).
- **Only the owner may retire.** Commit 9bbe9f5e0: the first handler
  patched labels directly and skipped the HTTP route's owner-or-admin check,
  and "A claims:write MCP token could retire any user-authored claim."

## Not recorded

- Why a label rather than a separate status column or table? The spec lists
  "changing the `claims` schema" as a non-goal, but gives no reason for it.

## Later changes

- Issue #374 put the owner-or-admin check on every path that adds or
  removes `resolved` (`update_labels`, `patch_claim`, `update_with_evidence`),
  on every transport. `CLAUDE.md` ("Enforcement (issue #374)") has the
  current ownership rules.
- Commit e8e802e0b (2026-05-27) passed the `claims:admin` scope through to
  the tool's ownership check.
