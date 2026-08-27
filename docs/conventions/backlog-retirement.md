# Backlog Retirement Convention

**Authoritative source:** `docs/superpowers/specs/2026-05-16-backlog-retirement-design.md`

## Filing a backlog item

Use `submit_claim` (or `memorize`) with `labels=["backlog"]` and a self-contained
description of the issue. Include enough context that a future agent or human can
act on it without the original conversation.

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

## Recording the closure basis

The retirement above records *that* an item was closed but not *why* it could
be. Pass `closure_basis` with the claim ids the closure actually rests on — the
test result, the benchmark, the commit claim, the refuting observation:

```python
mcp__epigraph__resolve_backlog_item(
    original_id="<backlog uuid>",
    resolution_content="Fixed by replacing the index with a GIN BTREE.",
    closure_basis=["<benchmark claim uuid>", "<commit claim uuid>"],
)
```

Each id produces two records:

- a `justifies` edge, **basis -> resolution claim** — read as "basis justifies
  resolution", following the repo's `source -> target` = "source RELATIONSHIP
  target" convention;
- an entry in the resolution claim's `properties->'closure_basis'` array, which
  is direction-free and queryable without a graph traversal.

`justifies` is **belief-inert by design**: it has no `edge_to_factor_type`
mapping, so it creates no Dempster-Shafer factor and moves no claim's
confidence. It is operational provenance, not evidence. Do not give it a factor
mapping and do not add it to `EPISTEMIC_RELATIONSHIPS` — that would
retroactively animate every historical closure edge.

Constraints and caveats:

- Max 16 ids. Every id must be an existing claim, and none may be `original_id`
  (an item is not evidence for its own closure). Either violation rejects the
  whole call before anything is written.
- Basis recording runs **after** the item is already retired and is
  best-effort: if a write fails, the call still succeeds and reports the
  failure in `warnings`. Check that key. Failing instead would leave the item
  labelled `resolved` and tempt a retry that files a duplicate resolution.
- `submit_claim` dedups on content hash, so re-running with identical
  `resolution_content` patches the *same* resolution claim. The property is
  replaced (last writer wins) while earlier edges remain, so a second call with
  a shorter basis list leaves the property narrower than the edges.

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
