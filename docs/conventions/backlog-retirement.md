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
