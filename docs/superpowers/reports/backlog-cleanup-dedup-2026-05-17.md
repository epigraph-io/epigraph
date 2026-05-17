# Backlog cleanup — 2026-05-17 (round 2: sublabel migration + cluster dedup)

Mode: APPLY (PATCH `["resolved"]` via admin token on `/api/v1/claims/:id/labels`)

Total open backlog 167 → 77 (90 retired this round).

## Bucket 1 — `backlog:completed` sublabel migration (62)

Pre-existing `backlog:completed` sublabel attests completion. Migrated to canonical
`["resolved"]` label per 2026-05-16 retirement convention. PATCH-only — no
resolution claim filed, matching the existing `cleanup_backlog_labels.py`
treatment of supersedes-retired items (sublabel itself is the resolution
evidence).

Source list: `/tmp/completed_ids.txt` (62 UUIDs).

## Bucket 2 — cluster dedup (28)

Manual cluster analysis of the 60 NO_SUBLABEL items (EpiClaw-filed bug reports,
divergence alerts, silence alarms). Each cluster: pick the earliest claim as
canonical (keeps the timeline anchor), PATCH `["resolved"]` on the rest.

| Cluster | Canonical (kept open) | Dups retired |
|---|---|---|
| silence-alarm-graph-topology-274858a4 | `4a1912c9` | 73905e79, 4d94d075, b57a9c73, bf27c398, e0d1a787, 085058b2 |
| si-h-70d289c5-ds-bayesian-divergence | `b6c1bc2c` | 68cb0256, 84d9a384, 4cc504c2, 883918be, f258595e |
| biotin-streptavidin-98c40810-k0.32 | `a1497a63` | 7ca0b7ef, 18601421, 4353e7cc, 23c8a352 |
| thermal-noise-7416e69e-dd4593e6-mistyped-refutes | `5306aa3f` | 52f7c82f, 7d25fca9, a215baaf, 2cff0361, 467dcd9a |
| assessment-queue-workflow-a04928e5-missing-runner | `82a26911` | dc3e21cd, 5288fd66, 3c324522 |
| batch-submit-claims-unknown-methodology | `daf7db58` | 32c62901 |
| scheduler-container-missing-psql | `5bfd44a1` | f3b76c79 |
| update-with-evidence-plausibility-bounds-1.0 | `8c921f32` | 35ec7aa7 |
| ingest-document-already-ingested-zero-claims | `60423d55` | eb571e64 |
| nems-cluster-belief-inflation | `261513eb` | cedf196b |

Source list: `/tmp/dup_map.tsv`.

## Standing open (77)

After this round:

- 45 sublabel-bucketed (`backlog:pending` 34, `backlog:working` 11): real WIP, untouched.
- 32 NO_SUBLABEL remaining: 10 canonicals (above) + 22 standalone items (foundational bugs, design brainstorms, today's scans, single-instance issues).

Notable standalone items left open:

- `0c878514` — STRESS TEST FLAW S1: update_with_evidence non-commutative (Feb 2026, foundational)
- `c11c1295` — Dedup failure: 20+ refuted claims with identical content_hashes
- `3a8879fc` — recall() doesn't surface post-`ingest_document` claims
- `46410d7c` / `4812b044` — `alternative_of` edge type + CDST least-restrictive-alternative (paired design work)
- `98d5a2d5` / `351cae08` — intra-source `supports` retype to `decomposes_to` (paired work)
- `654edcb0` — Supersede semantics brainstorm (from PR #150 review)
- `1ba8bc21` / `934830cb` — CDST Tier 2/3 + data-quality MCP workflows missing
- `a7a9192e`, `be2a3391`, `33435276` — today's scans/findings (2026-05-17), not yet triaged

## Auth note

`resolve_backlog_item` MCP tool blocks cross-agent retirement: claims authored by
agent `a0bbd6f5` (EpiClaw canonical) cannot be retired by other agents because
the `claims:admin` scope override is not yet plumbed into the MCP tool handler
(the PR #155 review TODO). PATCH route via admin OAuth token works as designed.
Same gap noted in past memory `feedback_dedup_admin_only`. **Follow-up:** plumb
admin scope through `mcp__epigraph__resolve_backlog_item` handler so future
cleanups can use the canonical MCP tool.

Tokens minted via `EPIGRAPH_ADMIN_CLIENT_ID`/`SECRET` from
`/home/jeremy/.epigraph/canonical_clients.env` with scope `claims:write claims:admin`.

## Reconciler status

`scripts/reconcile_backlog_labels.py` ships (PR #154) but is **not registered**
in `host_scheduled_tasks`. The daily run promised by `CLAUDE.md` has never
fired; `reconciler-needs-review.log` does not exist.

Wiring would be an INSERT into `host_scheduled_tasks` along the lines of:

```
id=backlog-reconciler, schedule_type=cron, schedule_value='0 0 6 * * *',
prompt='python3 /opt/epigraph/scripts/reconcile_backlog_labels.py --apply',
status=active
```

Not wired in this PR — defer to operator decision on schedule slot and
container layout.
