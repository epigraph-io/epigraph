# No Longer In Force: How Each Table Retires a Row

EpiGraph has no single "deleted" flag. Each table that keeps retired rows has
its own mechanism, and a reader that forgets that table's filter sees retired
rows as live. This page names the mechanism per table, the migration that
defines it, and the canonical reader filter (backlog `64eeca4e`).

Before you add a reader of one of these tables, apply its filter. Before you
add a new retirement mechanism, add a row here.

| Table | A row stops being in force when | Defined by | Canonical reader filter | Coming back |
|---|---|---|---|---|
| `claims` | `is_current = false`. The supersede, consolidate and dedup acts also set `supersedes` to the replacement (or the duplicate's canonical); `deprecate_claim` (workflow deprecation) retires a claim with no replacement. Every path nulls both embeddings in the same statement (CLAUDE.md, "Cleanup paths"). A backlog item's status never goes here: it is the `resolved` label (next row). | `migrations/001_initial_schema.sql` (`claims.is_current`, and `claims.supersedes`) | `current_only` in `crates/epigraph-db/src/repos/claim.rs`: `ClaimRepository::list_by_labels` keeps `is_current = true` rows only. A read without that parameter states `is_current = true` in its own SQL. | `unmark_duplicate` (`ClaimRepository::unmark_duplicate_act_authorized_conn`) makes a marked duplicate current again, clearing `supersedes`, and re-embeds it; `revive_workflow_deprecation_retired` revives a claim a workflow deprecation retired when a later generation or `add_step` reuses it. No other path makes a retired claim current again. |
| `claims` labelled `backlog` | The item carries the `resolved` label, added by `resolve_backlog_item` together with a `"Resolves <id>: "` resolution claim. Gated on ownership on every transport. | `migrations/001_initial_schema.sql` (`claims.labels`) | `exclude_labels` in `crates/epigraph-db/src/repos/claim.rs`: query with `labels=["backlog"]`, `exclude_labels=["resolved"]`, `current_only=True` (`docs/conventions/backlog-retirement.md`). | Removing `resolved` is the same gated label mutation. `backlog-candidate` is NOT a retirement: an unmeasured item stays open. |
| `mass_functions` | `retracted_at` is set (with `retracted_by` and `retract_reason`) by `epigraph_retract_mass_function`, behind `retract_bba` (MCP) and `POST /api/v1/mass-functions/:id/retract`. The row is kept and excluded from every fold. Exception: an edge-slot BBA (`slot_kind = 'edge'`) is DELETED, not retracted, when its edge is retired or withdrawn (see "Rules that hold across tables"). | `migrations/184_mass_function_retract.sql` (`mass_functions.retracted_at`) | `not_retracted_predicate` in `crates/epigraph-db/src/repos/mass_function.rs`: `retracted_at IS NULL`, required on every BBA read by `crates/epigraph-db/tests/bba_retract_read_lint.rs`. | Only through the audited un-retract, `epigraph_unretract_mass_function` (migration 184, section 2b; `unretract_bba` over MCP, `POST /api/v1/mass-functions/:id/unretract` over HTTP), which writes a `security_events` row. A retracted row keeps its key: a new write to the same claim, frame, source agent and perspective is refused (RT07), never a revival. |
| `edges` | `valid_to` is set to a time not after now. `MatchCandidateRepo::retire` and the dedup act retract edges this way rather than deleting them. | `migrations/001_initial_schema.sql` (`edges.valid_to`) | `EDGE_IN_FORCE` in `crates/epigraph-db/src/repos/edge.rs`: `(valid_to IS NULL OR valid_to > now())` (`EDGE_IN_FORCE_UNALIASED` without the alias). | The dedup un-mark reopens (`valid_to = NULL`) only the edges its own repair retracted, matched on that exact retraction stamp (`reverse_marked_duplicate` in `crates/epigraph-db/src/repos/claim.rs`). Any other retracted edge stays closed; write a new edge instead. |
| `operator_links` | `retired = true`, written by `epigraph_link_retired_agent` for an agent identity that will never run again (e.g. a job's identity before a model bump). The operator still owns what that identity authored, but the link grants no write authority: it is never an actor link and never a delegation. | `migrations/107_operator_link.sql` (`operator_links.retired`) | `epigraph_operator_actor` in `migrations/107_operator_link.sql`: the actor read requires `NOT l.retired`; later bindings (migration 122) read a LIVE link as `retired = false`. | Never promoted: `epigraph_link_operator` on a retired agent inserts no membership and reports `link_retired = true`, and the row is recorded once (`ON CONFLICT (agent_id) DO NOTHING`). |
| `workflows` | **Transitional:** the `truth_value = 0.05` sentinel is being replaced by `status` / `retired_at` per `99f6dd92`, whose change updates this row when it lands. Today `truth_value` drops to `0.05`: `deprecate_workflow` mirrors its claim deprecation onto the hierarchical row through `WorkflowRepository::set_truth_value(…, 0.05)`, over HTTP (`crates/epigraph-api/src/routes/workflows.rs`) and over MCP, for every workflow child its cascade reaches (`crates/epigraph-mcp/src/tools/workflows.rs`); and `delete_step` soft-deletes a step claim with the same value (`crates/epigraph-ingest-executor/src/workflow_steps.rs`). | `migrations/033_workflows_truth_value.sql` (`workflows.truth_value`) | `search_hierarchical_by_text` in `crates/epigraph-db/src/repos/workflow.rs`: `truth_value >= min_truth`, where `GET /api/v1/workflows/hierarchical/search` defaults `min_truth` to 0.3. The deprecated workflow's claims also go `is_current = false`, so the `claims` filter applies to them. | A claim a workflow deprecation retired is revived when a later generation or `add_step` reuses it (`revive_workflow_deprecation_retired`). |

## Rules that hold across tables

- **Retire, do not delete.** Each mechanism above keeps the row so an audit
  can read it. Derived materializations (`factors`, `bp_messages`, stored
  scoped beliefs) are deleted instead, because they regenerate from live rows.
- **Edge-slot BBAs are deleted with their edge's derived records.** A
  `mass_functions` row keyed to an edge (`slot_kind = 'edge'`) is deleted,
  not retracted, when that edge is retired or withdrawn:
  `MatchCandidateRepo::retire` (through `delete_edge_bbas` in
  `crates/epigraph-db/src/repos/mass_function.rs`), the edge-BBA withdrawal
  in `crates/epigraph-db/src/repos/edge.rs`, the dedup repair and its
  reversal in `crates/epigraph-db/src/repos/claim.rs`, the engine's
  `retraction_cascade`, and the `backfill_factors` CLI's edge repair. Such a row has no `retracted_at`, so
  `unretract_bba` cannot bring it back. Two other paths delete a BBA
  outright: `delete_for_claim` (`mass_function.rs`) and
  `retire_promoted_hypothesis_bba` (`crates/epigraph-db/src/repos/experiment.rs`).
- **Use the named filter.** Where a table has a named predicate or parameter
  (`EDGE_IN_FORCE`, `not_retracted_predicate`, `current_only`,
  `exclude_labels`), use it rather than re-typing the condition, so a ratchet
  can find every reader.
- **Backlog status is not epistemic replacement.** `supersedes` records that
  one claim replaced another's content. A backlog item's status (done,
  refuted) is the `resolved` label, never `supersedes` / `is_current`.
  Workflow deprecation is the one operational status that flips
  `is_current`, through `deprecate_claim` and without a `supersedes`,
  alongside the workflows sentinel.
