# No Longer In Force: How Each Table Retires a Row

EpiGraph has no single "deleted" flag. Each table that keeps retired rows has
its own mechanism, and a reader that forgets that table's filter sees retired
rows as live. This page names the mechanism per table, the migration that
defines it, and the canonical reader filter (backlog `64eeca4e`).

Before you add a reader of one of these tables, apply its filter. Before you
add a new retirement mechanism, add a row here.

| Table | A row stops being in force when | Defined by | Canonical reader filter | Coming back |
|---|---|---|---|---|
| `claims` | `is_current = false`, with `supersedes` naming the replacement (or the duplicate's survivor). Set by the supersede, consolidate and dedup acts and by `deprecate_claim`, with both embeddings nulled in the same statement (CLAUDE.md, "Cleanup paths"). Reserved for *epistemic* replacement, never for operational status. | `migrations/001_initial_schema.sql` (`claims.is_current`, and `claims.supersedes`) | `current_only` in `crates/epigraph-db/src/repos/claim.rs`: `ClaimRepository::list_by_labels` keeps `is_current = true` rows only. A read without that parameter states `is_current = true` in its own SQL. | `unmark_duplicate` makes a marked duplicate current again and re-embeds it. A superseded claim stays superseded. |
| `claims` labelled `backlog` | The item carries the `resolved` label, added by `resolve_backlog_item` together with a `"Resolves <id>: "` resolution claim. Gated on ownership on every transport. | `migrations/001_initial_schema.sql` (`claims.labels`) | `exclude_labels` in `crates/epigraph-db/src/repos/claim.rs`: query with `labels=["backlog"]`, `exclude_labels=["resolved"]`, `current_only=True` (`docs/conventions/backlog-retirement.md`). | Removing `resolved` is the same gated label mutation. `backlog-candidate` is NOT a retirement: an unmeasured item stays open. |
| `mass_functions` | `retracted_at` is set (with `retracted_by` and `retract_reason`) by `epigraph_retract_mass_function`, behind `retract_bba` (MCP) and `POST /api/v1/mass-functions/:id/retract`. The row is kept and excluded from every fold. | `migrations/184_mass_function_retract.sql` (`mass_functions.retracted_at`) | `not_retracted_predicate` in `crates/epigraph-db/src/repos/mass_function.rs`: `retracted_at IS NULL`, required on every BBA read by `crates/epigraph-db/tests/bba_retract_read_lint.rs`. | Only through the audited un-retract, `epigraph_unretract_mass_function` (migration 184, section 2b; `unretract_bba` over MCP, `POST /api/v1/mass-functions/:id/unretract` over HTTP), which writes a `security_events` row. A retracted row keeps its key: a new write to the same claim, frame, source agent and perspective is refused (RT07), never a revival. |
| `edges` | `valid_to` is set to a time not after now. `MatchCandidateRepo::retire` and the dedup act retract edges this way rather than deleting them. | `migrations/001_initial_schema.sql` (`edges.valid_to`) | `EDGE_IN_FORCE` in `crates/epigraph-db/src/repos/edge.rs`: `(valid_to IS NULL OR valid_to > now())` (`EDGE_IN_FORCE_UNALIASED` without the alias). | A retracted edge is not reopened; a new edge is written instead. |
| `operator_links` | `retired = true`, written by `epigraph_link_retired_agent` for an agent identity that will never run again (e.g. a job's identity before a model bump). The operator still owns what that identity authored, but the link grants no write authority: it is never an actor link and never a delegation. | `migrations/107_operator_link.sql` (`operator_links.retired`) | `epigraph_operator_actor` in `migrations/107_operator_link.sql`: the actor read requires `NOT l.retired`; later bindings (migration 122) read a LIVE link as `retired = false`. | Never promoted: `epigraph_link_operator` on a retired agent inserts no membership and reports `link_retired = true`, and the row is recorded once (`ON CONFLICT (agent_id) DO NOTHING`). |
| `workflows` | **Transitional:** the `truth_value = 0.05` sentinel is being replaced by `status` / `retired_at` per `99f6dd92`, whose change updates this row when it lands. Today `truth_value` drops to `0.05`: `deprecate_workflow` mirrors its claim deprecation onto the hierarchical row through `WorkflowRepository::set_truth_value(…, 0.05)` (`crates/epigraph-api/src/routes/workflows.rs`), and `delete_step` soft-deletes a step claim with the same value (`crates/epigraph-ingest-executor/src/workflow_steps.rs`). | `migrations/033_workflows_truth_value.sql` (`workflows.truth_value`) | `search_hierarchical_by_text` in `crates/epigraph-db/src/repos/workflow.rs`: `truth_value >= min_truth`, where `GET /api/v1/workflows/hierarchical/search` defaults `min_truth` to 0.3. The deprecated workflow's claims also go `is_current = false`, so the `claims` filter applies to them. | A claim a workflow deprecation retired is revived when a later generation or `add_step` reuses it (`revive_workflow_deprecation_retired`). |

## Rules that hold across tables

- **Retire, do not delete.** Each mechanism above keeps the row so an audit
  can read it. Derived materializations (`factors`, `bp_messages`, stored
  scoped beliefs) are deleted instead, because they regenerate from live rows.
- **Use the named filter.** Where a table has a named predicate or parameter
  (`EDGE_IN_FORCE`, `not_retracted_predicate`, `current_only`,
  `exclude_labels`), use it rather than re-typing the condition, so a ratchet
  can find every reader.
- **Status is not epistemic replacement.** `supersedes` / `is_current` record
  that one claim replaced another's content. Operational status (done,
  refuted, deprecated) uses the table's own mechanism: the `resolved` label
  for backlog items, the sentinel (for now) for workflows.
