# 0004: Workflows are hierarchical claim graphs whose steps share ids with document atoms

- **Decided:** 2026-04-30
- **Recorded:** 2026-11-27 (retrospective)
- **Sources:**
  - issue #34, "Feature: hierarchical workflow primitive — workflows as a
    claim graph (steps as first-class claims) isomorphic to
    DocumentExtraction";
  - spec `docs/superpowers/specs/2026-04-30-hierarchical-workflow-primitive-design.md`
    (commits d5a975bb2, 12aa005a2);
  - pull request #55, `feat: hierarchical workflows + DB-drift fixes (closes
    #34, #38, #42, #47)` (merged 2026-04-30). It includes:
    - commit 94bd0b11b, the `workflows` table;
    - commit af69fc737, the `WorkflowExtraction` schema and walker;
    - commit e1faa612e, the `ingest_workflow` tool;
    - commit e2a90fd12, the cross-source convergence test.
  - pull request #58, `feat(mcp): expose hierarchical workflow tools
    (ingest/search/outcome)`.

## Rule it grounds

- `crates/epigraph-ingest/src/workflow/builder.rs`: an operation atom's id is
  `uuid_v5(ATOM_NAMESPACE, blake3(text))`, "the SAME namespace documents use"
  (`crates/epigraph-ingest/src/common/ids.rs`).
- A workflow root's id comes from `WORKFLOW_NAMESPACE` and
  `canonical_name:generation`.
- `CLAUDE.md` "Embedding policy" has two rules that exist because steps are
  shared claim nodes:
  - the workflow-ingest write paths in "Write paths" (`ingest_workflow`,
    `store_workflow`, `improve_workflow_hierarchy`, `add_step`) embed the
    claims the executor inserted or revived;
  - in "Cleanup paths", `retire_for_workflow_deprecation` and
    `revive_workflow_deprecation_retired` mark a retirement and undo it when
    a later generation or `add_step` reuses the claim.

## Decision

- A workflow is ingested the way a document is. It has these levels, joined
  by `decomposes_to` and the same ordering edges:
  - a thesis;
  - phases;
  - step descriptions;
  - atomic operations.
- It has its own `workflows` table, parallel to `papers`.
- The `workflow` row links to its step claims with `executes` edges, where a
  paper uses `asserts`.
- Operation atoms use the document atoms' namespace. The same text is
  therefore the same claim node, whether it came from a workflow or a
  document.

## Context (from issue #34 and the spec)

- Before this, `store_workflow` wrote one claim whose content was a JSON
  object of `goal` and `steps`. A step was an element of a JSON array, not a
  node.
- Documents were already decomposed into a four-level hierarchy, with
  deterministic atom ids that converge identical text across documents.
  Workflows got none of that.

## Reasoning (from the sources)

- **Cross-workflow reuse.** "The same operational step ... used in two
  workflows can't share a claim node, can't accumulate `paper --asserts-->
  claim` edges from multiple workflows, and can't be queried for 'what
  workflows reference this step?'. Documents got this; workflows didn't."
  (issue #34)
- **One graph, same queries.** Steps as claim nodes "participate in the same
  graph queries (semantic search, neighborhoods, sheaf consistency) as
  document atoms", and operations "dedup *across* workflows and across
  documents — same text means same node, regardless of source artifact
  type." (spec, Goals)
- **Lineage by deterministic root id.** A root id derived from
  `canonical_name + generation` makes variants into a lineage and makes
  identical canonical names converge. The `(canonical_name, generation)`
  unique constraint is "belt-and-suspenders against deterministic-ID drift".
  (spec, Architecture and Data model)
- **Additive rollout.** The spec's goal was "nothing existing breaks": the
  flat tools would stay, and a one-shot migration would move existing flat
  workflows across. (spec, Goals)

## Not recorded

- Why a separate `workflows` table rather than `papers` rows of a workflow
  kind? The spec says "parallel to `papers`" but does not weigh the
  alternative.

## Later changes

- The migration CLI was written and then retired:
  - commit 630d94471 (in #55) added `migrate-flat-workflows`;
  - commit 4602cfaab (2026-05-12) removed it once the one-shot migration was
    done.
  - The spec's status header (commit 30be832ca, 2026-11-14) says the CLI
    "was never written". That is right about the tree today but not about
    the history.
- The flat and hierarchical tools were bridged rather than kept apart.
  - `store_workflow` now runs the hierarchical ingest.
  - `find_workflow` and `report_workflow_outcome` serve both stores.
  - The spec's status header lists these deviations.
