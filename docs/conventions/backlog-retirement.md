# Backlog Retirement Convention

**Authoritative source:** `docs/superpowers/specs/2026-05-16-backlog-retirement-design.md`

## Filing a backlog item

Use `submit_claim` (or `memorize`) with `labels=["backlog"]` and a self-contained
description of the issue. Include enough context that a future agent or human can
act on it without the original conversation.

## Filing backlog items: evidence tier

A backlog item says something is wrong. How that was established decides
whether anyone should plan work on it yet.

- **`backlog-candidate`.** Label an item `backlog-candidate` (alongside
  `backlog`) when its only support is static reading (a code trace nobody
  executed) or testimony (someone reported it). The item is open and visible
  like any other; it is just not ready to plan until it is re-measured.
- **Re-measured** means the defect was confirmed on the current ref, with the
  evidence cited:
  - *Structural* claims (dead code, doc drift, a duplicated constant):
    `git grep` / `git show` on the current `main` is enough.
  - *Behavioural* claims (a wrong result, a race, a refusal) need an executed
    test, a reproduced call, or a read of the deployed system.
- **The re-measurer removes `backlog-candidate`**, citing the evidence (what
  was run, and on which ref) in the label patch. The ownership rules under
  "Who may retire an item" apply to that patch as to any other, and it never
  touches `resolved`.
- **A candidate is never closed for being unmeasured.** An item nobody has
  re-measured stays open as a candidate; it is not resolved, refuted or
  dropped for that reason. `backlog-candidate` is never a substitute for
  `resolved`: retiring a candidate still goes through `resolve_backlog_item`.
- **Backlog items only.** The tier governs backlog promotion. General claims
  are unaffected: their admission and belief do not change (ruling
  `6e7a6c69`).

To list only the items ready to plan, add `backlog-candidate` to
`exclude_labels` in the open-backlog query below (`exclude_labels` drops a
claim carrying any of the listed labels).

## Retiring a backlog item

**ALWAYS use `mcp__epigraph__resolve_backlog_item`.** This single tool call both
creates a resolution claim (labelled `["resolved"]`, prefixed with `"Resolves
<id>: "`) AND patches the original claim's labels with `add=["resolved"]`.

Do NOT:
- File a free-text "Resolves <UUID>" claim alone. The original keeps the
  `[backlog]` label and stays visible in every backlog query forever.
- Use `supersedes`/`is_current` for status. Those are reserved for *epistemic*
  claim replacement (one claim refining another's factual content), not
  operational status.

If you find yourself reaching for raw SQL or `update_labels` after a resolution,
that's a sign you should be using `resolve_backlog_item` instead.

The `resolved` label is the backlog's own retirement mechanism. How every
other table retires a row (`is_current`, `retracted_at`, `valid_to`, `retired`,
the workflow sentinel), and the filter each reader must apply, is in
`docs/conventions/no-longer-in-force.md`.

## Who may retire an item

`resolved` is the one label with retirement semantics, so it is gated on every
transport (issue #374). `resolve_backlog_item` requires ownership of the
original claim, and `update_labels`, `patch_claim` and `update_with_evidence`'s
`labels` merge apply the same check whenever a call adds or removes `resolved`.

An owner is:

- the claim's author;
- on stdio, an agent linked to the same operator as the author (this is what
  lets an agent whose model was bumped retire its predecessor's items), or an
  agent live-linked to the author itself (its delegate: one hop, and a retired
  link grants nothing);
- over HTTP, the author's operator, or a live delegated run token. A
  `claims:admin` token also passes.

Refused: a stdio agent that shares no operator with the author and is not its
delegate, and a stdio server with no declared signer (`--agent-key` or the
separate signing key) on any claim it did not author. Over HTTP the whole label
mutation needs that ownership, whatever the labels; on stdio every other label
stays ungated.

A refusal is not a reason to file a free-text "Resolves <UUID>" claim. Have an
owner retire the item. The rule's implementation and its reasoning are in
`crates/epigraph-mcp/src/tools/claims.rs` (`require_owner_or_admin`,
`gate_retirement_label`).

## Querying open backlog

```python
mcp__epigraph__query_claims_by_label(
    labels=["backlog"],
    exclude_labels=["resolved"],
    current_only=True,
)
```

This returns claims labelled `backlog` that are not also labelled `resolved`
and have not been epistemically superseded. The result is the live, actionable
backlog — not the historical "everything ever filed" view.

## Drift safety net

A daily reconciler (`scripts/reconcile_backlog_labels.py`) scans for cases
where someone filed a free-text "Resolves <UUID>" claim without using
`resolve_backlog_item`, and back-fills the label patch. Ambiguous matches
(multiple resolution claims referencing the same backlog UUID, or 8-char
prefix collisions among open backlog UUIDs) are logged for human triage at
`docs/superpowers/reports/reconciler-needs-review.log`.

It is a dry run unless passed `--apply`. A dry run prints one
`WOULD-PATCH <backlog_id> via <resolved_claim_id>` line per unambiguous match
and counts them in the summary's `patched=N`; under `--apply`, `patched=N`
counts successful PATCHes and the run exits 1 if any PATCH failed (HTTP
error or transport error). Both modes append ambiguous matches to the
needs-review log; only `--apply` sends label PATCHes.
