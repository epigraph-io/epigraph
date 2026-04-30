# Hierarchical Workflow Primitive — Design

**Issue:** [#34](https://github.com/epigraph-io/epigraph/issues/34) — Workflows as a claim graph (steps as first-class claims) isomorphic to `DocumentExtraction`.
**Follow-up:** [#36](https://github.com/epigraph-io/epigraph/issues/36) — Re-author migrated flat workflows into true hierarchical form.

**Date:** 2026-04-30
**Author:** brainstorming with the user, captured here

## Problem

Workflows are currently stored as flat-JSON claims: `store_workflow` writes one claim with content `{"goal":"…","steps":["…"]}`, and the steps are JSON array elements rather than first-class claim nodes. Documents, by contrast, get a four-level decomposition (thesis → sections → paragraphs → atoms) via `epigraph_ingest::DocumentExtraction` and `mcp__epigraph__ingest_document`, with `decomposes_to`/`section_follows`/`continues_argument` edges and deterministic UUIDv5 atom IDs that converge identical text across documents.

The asymmetry costs cross-workflow value capture. The same operational step — `"Use uuid_v5(ATOM_NAMESPACE, blake3(text)) for atom IDs to enable cross-source convergence"` — used in two workflows can't share a claim node, can't accumulate `paper —asserts→ claim` edges from multiple workflows, and can't be queried for "what workflows reference this step?". Documents got this; workflows didn't.

## Goals

- Workflow operational steps are first-class claim nodes that participate in the same graph queries (semantic search, neighborhoods, sheaf consistency) as document atoms.
- Operations at the lowest level dedup *across* workflows and across documents — same text means same node, regardless of source artifact type.
- Add the new path additively: nothing existing breaks. Old `store_workflow` and `find_workflow` keep working unchanged.
- Provide a one-shot migration tool that brings existing flat-JSON workflows into the hierarchical tables without losing them or their accumulated stats.

## Non-goals (deferred)

- Unifying `find_paper` and `find_workflow` into a single `find_hierarchical_artifact` tool. Tracked separately; out of scope for this PR.
- Re-authoring migrated flat workflows into substantively-multi-phase decompositions. Tracked as [#36](https://github.com/epigraph-io/epigraph/issues/36).
- Backfilling `behavioral_executions` rows that reference old flat-root claim IDs to point at the new hierarchical roots.
- The "workflows authoring workflows" provenance model gestured at in #34's authorship section. Authorship in this PR is human/LLM agents only, same as papers.

---

## Architecture

A workflow becomes a hierarchical artifact mirroring `DocumentExtraction`, with a dedicated `workflows` table parallel to `papers`. The `epigraph-ingest` crate gets extended with a `workflow` module that shares the existing hierarchy walker; only the source-node type and a small set of paper-specific properties differ. Workflows are addressed by a deterministic root ID derived from `canonical_name + generation`, so variants form a lineage and identical canonical names converge across instances.

Atomic operations at level 3 use the *existing* `ATOM_NAMESPACE` UUIDv5 derivation from `epigraph-ingest`, so a step like `"Use uuid_v5(ATOM_NAMESPACE, blake3(...)) for atom IDs"` shares the same claim node whether it appears in a workflow extraction or a document extraction. That's the cross-source convergence the issue is asking for.

The flat-JSON `store_workflow` path stays untouched. The new hierarchical path is additive: a new MCP tool `ingest_workflow`, a new HTTP endpoint `POST /api/v1/workflows/ingest`, and a one-shot migration CLI that re-ingests existing flat-JSON workflows hierarchically. After migration, existing flat-JSON claims carry both `'workflow'` and `'legacy_flat'` labels, and a `supersedes` edge points from the new hierarchical root to the old claim. `find_workflow` continues to read the flat side; a new `find_workflow_hierarchical` reads the `workflows` table.

---

## Data model

### New table

```sql
CREATE TABLE workflows (
    id              uuid PRIMARY KEY,                    -- deterministic, derived from canonical_name + generation
    canonical_name  text NOT NULL,                       -- slug, e.g. "cross-source-matching-pipeline"
    generation      integer NOT NULL DEFAULT 0,
    goal            text NOT NULL,                       -- free text, indexed for trigram search
    parent_id       uuid REFERENCES workflows(id),       -- variant_of in lineage form
    metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,  -- tags, expected_outcome, change_rationale, accumulated stats
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (canonical_name, generation)
);
CREATE INDEX workflows_canonical_name_idx ON workflows (canonical_name);
CREATE INDEX workflows_goal_trgm_idx ON workflows USING gin (goal gin_trgm_ops);
```

Root ID derivation: `uuid_v5(WORKFLOW_NAMESPACE, blake3(canonical_name || ":" || generation))`. The `(canonical_name, generation)` UNIQUE constraint is belt-and-suspenders against deterministic-ID drift.

The same migration **must also** expand the existing `edges_entity_types_valid` CHECK constraint and the `validate_edge_reference` trigger function to recognize `'workflow'` as a valid entity type. Today `migrations/005_task_event_edge_types.sql` enumerates allowed source/target types as a closed list (`'claim', 'agent', 'evidence', 'trace', 'node', 'activity', 'paper', 'perspective', 'community', 'context', 'frame', 'analysis', 'source_artifact', 'span', 'entity', 'task', 'event'`) — `'workflow'` is not in it, so any `INSERT INTO edges (source_type='workflow', ...)` fails the CHECK before reaching the workflows table. Steps for the new migration:

1. `ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid; ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid CHECK (... ARRAY[..., 'workflow'] ...)` — append `'workflow'` to both the `source_type` and `target_type` ARRAYs, preserving the existing entries verbatim.
2. `CREATE OR REPLACE FUNCTION validate_edge_reference(entity_type TEXT, entity_id UUID) ...` — add a `WHEN 'workflow' THEN EXISTS (SELECT 1 FROM workflows WHERE id = entity_id)` branch. Both overloads (`(text, uuid)` and `(uuid, varchar)`) must be updated; the trigger calls the second.

This sequencing matters: the migration creates the `workflows` table first, then expands the constraints and trigger function (the trigger references `workflows`, which must exist first).

### Claim labels

| Level | Content | Labels |
|------|---------|--------|
| 0 | Workflow thesis (one-sentence statement) | `['workflow_thesis']` |
| 1 | Phase summary | `['workflow_step']` |
| 2 | Step description (compound) | `['workflow_step']` |
| 3 | Atomic operation | `['workflow_step', 'workflow_atom']` |
| — | Legacy flat-JSON workflow root (post-migration only) | `['workflow', 'legacy_flat']` |

`'workflow_step'` is intentionally applied to levels 1–3 — a query `WHERE 'workflow_step' = ANY(labels)` returns phases, step descriptions, and operations together (the full hierarchical content of all workflows). `'workflow_atom'` narrows to just level-3 operation atoms — the cross-workflow-convergent ones — for queries like "which atoms are referenced by more than one workflow?".

`find_workflow`'s existing `WHERE 'workflow' = ANY(labels)` filter is unchanged → it keeps reading flat-JSON workflows. New label values (`workflow_thesis`, `workflow_step`, `workflow_atom`) avoid collision with the existing `'workflow'` label that flat-JSON roots carry; if we used `'workflow'` for both, every existing `find_workflow` query would suddenly start returning level-3 atomic operations.

### Edges

No schema change to the `edges` table. New relationship strings:

- `workflow —executes→ claim` — for every claim in a workflow's hierarchy (`source_type='workflow', target_type='claim'`).
- `claim —decomposes_to→ claim` — same as documents.
- `claim —phase_follows→ claim` — sequential phase ordering at level 1 (analog of `section_follows`).
- `claim —step_follows→ claim` — sequential step ordering within a phase at level 2 (analog of `continues_argument`).
- `workflow —supersedes→ claim` — post-migration: new hierarchical root supersedes old flat-JSON root.
- `workflow —variant_of→ workflow` — workflow lineage. Replaces the existing claim-level `variant_of` for hierarchical workflows. The `parent_id` FK on `workflows` provides cheap recursive lineage; the edge makes variants visible to graph-traversal queries that don't know about `workflows`. (Same redundancy pattern as `claims.derived_from` + `derived_from` edges.)

### Behavioral-executions extension

```sql
ALTER TABLE behavioral_executions
    ADD COLUMN step_claim_id uuid REFERENCES claims(id);  -- nullable for back-compat
```

Each row becomes per-(execution, step). An execution with N steps writes N rows, with execution-level fields (`goal_text`, `success`, `tool_pattern`) denormalized across them. Existing rows have NULL `step_claim_id`.

**Aggregation semantics under mixed rows.** Old rows are 1:1 with executions; new rows are N:1 with executions. So `SELECT COUNT(*) FROM behavioral_executions WHERE workflow_id = $1` is no longer "execution count" once any hierarchical workflow is written — it's an over-count. Queries that need per-execution counts must `COUNT(DISTINCT (workflow_id, created_at))` (or some equivalent execution-key tuple). Queries that aggregate by `(workflow_id, success)` continue to work for legacy-flat workflows because `step_claim_id` is NULL and `created_at` is unique per row. New per-step analytics use `WHERE step_claim_id IS NOT NULL` to scope to hierarchical executions only. Existing `behavioral_affinity_lineage` and `rolling_success_rate` query paths in `epigraph-db` will be reviewed at writing-plans time and updated to use the DISTINCT-tuple pattern where they need execution-count semantics.

---

## Code structure

### Crate layout (extending `epigraph-ingest`)

```
crates/epigraph-ingest/src/
├── lib.rs              (pub mod document; pub mod workflow; pub mod common;
│                       re-exports for back-compat)
├── common/
│   ├── walker.rs       (parameterized hierarchy walker — extracted from current builder.rs)
│   ├── ids.rs          (ATOM_NAMESPACE, COMPOUND_NAMESPACE, content_hash, compound_claim_id)
│   ├── plan.rs         (PlannedClaim, PlannedEdge, IngestPlan — unchanged)
│   └── schema.rs       (AuthorEntry, ClaimRelationship, ThesisDerivation — shared)
├── document/
│   ├── schema.rs       (DocumentExtraction, Section, Paragraph, DocumentSource, SourceType)
│   └── builder.rs      (calls common::walker with paper-specific WalkerConfig)
├── workflow/
│   ├── schema.rs       (WorkflowExtraction, Phase, Step, WorkflowSource)
│   └── builder.rs      (calls common::walker with workflow-specific WalkerConfig)
├── builder.rs          (re-exports `pub use document::builder::*` for back-compat)
└── schema.rs           (re-exports `pub use document::schema::*` for back-compat)
```

The walker takes a small `WalkerConfig`: a new `WORKFLOW_NAMESPACE`, `ATOM_NAMESPACE` (shared with documents), label values per level, source-node type name (`"paper"` vs `"workflow"`), relationship-string overrides, and a closure for deriving the compound-namespace seed (`doc_title` for documents, `canonical_name` for workflows). Everything else — content hashing, compound ID generation, atom ID generation, decompose-edge generation, cross-reference resolution, sequential-link generation — is shared.

### MCP tool

- New module `crates/epigraph-mcp/src/tools/workflow_ingest.rs` adds tool `ingest_workflow`. Mirrors `ingest_document` exactly: takes a `WorkflowExtraction` JSON, runs `epigraph_ingest::workflow::build_ingest_plan`, persists claims and edges, plus inserts the `workflows` row and the `workflow —executes→ claim` edges for every claim in the plan.
- Existing `crates/epigraph-mcp/src/tools/workflows.rs` (which holds `store_workflow`, `find_workflow`, `improve_workflow`, etc.) is untouched.

### HTTP endpoints

- New handler `ingest_workflow` registered at `POST /api/v1/workflows/ingest` in `crates/epigraph-api/src/routes/workflows.rs`.
- New handler `report_hierarchical_outcome` registered at `POST /api/v1/workflows/hierarchical/:id/outcome`. The existing `report_outcome` (flat-JSON path) looks up `claims WHERE id=$1 AND 'workflow' = ANY(labels)` and 404s on hierarchical roots; rather than overload it with table-dispatch logic, the hierarchical path gets its own endpoint. The new handler resolves `:id` against the `workflows` table, updates `workflows.metadata` counters (`use_count`, `success_count`, `failure_count`, `avg_variance`) the same way `report_outcome` updates `claims.properties` today, and writes per-step `behavioral_executions` rows with `step_claim_id` populated for each step in the request's `step_executions` array (using the workflow's `executes` edges to resolve step indices to claim IDs). Returns the same response shape as `report_outcome` so callers can switch endpoints with minimal changes.
- New handler `find_workflow_hierarchical` registered at `GET /api/v1/workflows/hierarchical/search` (used in tests; future unification work will fold it into a single tool).
- All existing handlers in `workflows.rs` are untouched.

### Migration CLI

A new bin: `crates/epigraph-mcp/src/bin/migrate-flat-workflows.rs`.

```bash
cargo run --bin migrate-flat-workflows -- \
  --database-url "$DATABASE_URL" \
  [--dry-run] \
  [--limit N] \
  [--canonical-from goal-slug | tag] \
  [--workflow-id <uuid>]
```

Idempotent (re-runs filter out already-migrated rows by their `'legacy_flat'` label). Algorithm in detail under "Migration tool" below.

### Back-compat re-exports

The `epigraph_ingest::DocumentExtraction` and `epigraph_ingest::build_ingest_plan` paths used by `do_ingest_document` and several tests keep working without code changes — `lib.rs` re-exports both names from the new `document::` module. Costs two `pub use` lines and avoids touching dozens of call sites for no reader benefit.

The migration is shipped as a stand-alone bin rather than an MCP tool because it's a one-shot ops task, not a recurring agent capability. Keeps the MCP tool surface clean.

---

## `WorkflowExtraction` schema

```rust
// crates/epigraph-ingest/src/workflow/schema.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExtraction {
    pub source: WorkflowSource,
    #[serde(default)]
    pub thesis: Option<String>,            // one-sentence statement of what this workflow does
    #[serde(default)]
    pub thesis_derivation: ThesisDerivation,
    #[serde(default)]
    pub phases: Vec<Phase>,
    #[serde(default)]
    pub relationships: Vec<ClaimRelationship>,  // reused from common::schema
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowSource {
    pub canonical_name: String,            // REQUIRED — slug, drives root ID
    pub goal: String,                       // free text, embedded for find_workflow_hierarchical
    #[serde(default)]
    pub generation: u32,                    // 0 for first version; increments via improve
    #[serde(default)]
    pub parent_canonical_name: Option<String>,  // for variant_of lineage
    #[serde(default)]
    pub authors: Vec<AuthorEntry>,          // reused from common::schema (humans, LLMs)
    #[serde(default)]
    pub expected_outcome: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase {
    pub title: String,                       // e.g. "Source Decomposition"
    #[serde(default)]
    pub summary: String,                     // phase thesis (level 1 claim content)
    #[serde(default)]
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub compound: String,                    // step description (level 2 claim content)
    #[serde(default)]
    pub rationale: String,                   // why this step exists; level 2 supporting_text
    #[serde(default)]
    pub operations: Vec<String>,             // atomic operations (level 3 claims)
    #[serde(default)]
    pub generality: Vec<i32>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
}
```

### Key differences from `DocumentExtraction`

- `source` requires `canonical_name` (drives deterministic root ID; mirrors `papers.doi`).
- `source.generation` and `source.parent_canonical_name` model variants without forking off a separate type.
- `Phase` replaces `Section`. Same structural shape, renamed field `paragraphs → steps`.
- `Step` replaces `Paragraph`. Drops paper-specific fields: `methodology`, `evidence_type`, `page`, `instruments_used`, `reagents_involved`, `conditions`. Renames `supporting_text → rationale` (semantically: why-this-step, not where-the-evidence-came-from). Renames `atoms → operations`.
- `relationships` and `ClaimRelationship` are shared via `common::schema` — workflow steps can support / contradict / refute each other across phases just like document atoms can.

### Walker config (sketch)

```rust
WalkerConfig {
    source_node_type: "workflow",
    levels: [
        Level { kind: "thesis",    labels: vec!["workflow_thesis"] },
        Level { kind: "phase",     labels: vec!["workflow_step"] },
        Level { kind: "step",      labels: vec!["workflow_step"] },
        Level { kind: "operation", labels: vec!["workflow_step", "workflow_atom"] },
    ],
    sequential_relationships: SequentialRels {
        level_1: "phase_follows",
        level_2: "step_follows",
    },
    decompose_relationship: "decomposes_to",
    atom_namespace: ATOM_NAMESPACE,            // shared with documents → cross-source convergence
    compound_namespace_seed: |source| source.canonical_name.clone(),
}
```

### Cross-source convergence — the headline property

Operations at level 3 use the *same* `ATOM_NAMESPACE` as document atoms. A statement like `"Use uuid_v5(ATOM_NAMESPACE, blake3(...)) for atom IDs"` written in a workflow's operations list and the same statement appearing as an atom in some paper extraction both produce `Uuid::new_v5(ATOM_NAMESPACE, blake3(text))` — same UUID, same node, accumulating `paper —asserts→` *and* `workflow —executes→` edges from both sides. That's the convergence the issue is asking for.

Compound nodes (thesis, phase, step) are scoped by `canonical_name` instead of `doc_title` — same canonical_name means same compound node; different canonical_name means a different node even if the text is identical. Phases and steps are workflow-specific concepts and shouldn't accidentally converge across workflows.

---

## Migration tool

**Binary:** `crates/epigraph-mcp/src/bin/migrate-flat-workflows.rs`

**Algorithm:**

1. Query: `SELECT id, content, properties, truth_value, created_at FROM claims WHERE 'workflow' = ANY(labels) AND NOT 'legacy_flat' = ANY(labels) ORDER BY created_at ASC [LIMIT N]`.
2. For each row, parse `content` as `{goal, steps, prerequisites?, expected_outcome?, tags?}`. Skip with a warning if it doesn't parse — flat-JSON shape isn't guaranteed across the corpus.
3. Build `WorkflowExtraction`:
   - `source.canonical_name`: by default, `slugify(goal)`. With `--canonical-from tag`, use the first tag if present (fallback to slugified goal). Collisions (two flat workflows with the same canonical_name) are resolved by appending generation: the first-seen becomes generation=0, subsequent ones become generation=1, 2, … with `parent_canonical_name` pointing to the first.
   - `source.goal`: copied verbatim.
   - `source.generation`: read from old `properties.generation`, default 0; collision-incremented if needed.
   - `source.parent_canonical_name`: derived from old `properties.parent_id` if present. Migration tool reads `properties.parent_id` (a claim UUID set by the existing `improve_workflow` handler at `crates/epigraph-api/src/routes/workflows.rs:666`), looks up that claim's content, slugifies its `goal`, and uses the result as `parent_canonical_name`. After `ingest_workflow` runs, the new `workflows.parent_id` FK is populated by resolving `parent_canonical_name + (parent_generation := 0)` to a `workflows.id`. If the parent claim itself isn't yet migrated when the child runs, the migration tool processes the parent first (sort by `properties.generation ASC` within a canonical_name group). Lineage chains are reconstructed in topological order.
   - `source.authors`: empty (old flat-JSON has no author info beyond `agent_id`).
   - `source.expected_outcome`, `source.tags`: copied.
   - `thesis`: `Some(goal.clone())`.
   - `phases`: one phase titled `"Body"` with one `Step` per old `steps[i]`, where each `Step.compound` is the step text and `Step.operations = vec![step_text.clone()]` (the operation atom *is* the step, by necessity — flat-JSON has no further decomposition). The structurally-weak nature of this mapping is intentional and tracked separately as #36.
   - `relationships`: empty.
4. Call the in-process `ingest_workflow` builder + persister against the same DB pool.
5. After successful ingest, in one transaction:
   - `UPDATE claims SET labels = array_append(labels, 'legacy_flat') WHERE id = $old_claim_id`.
   - `INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) VALUES ($new_workflow_root_id, 'workflow', $old_claim_id, 'claim', 'supersedes', '{}'::jsonb)`.
   - Copy old `properties.use_count`, `success_count`, `failure_count`, `avg_variance` into the new `workflows.metadata` so success metrics carry over.
6. Log: `migrated <old_id> -> <new_id> (canonical_name=foo-bar, gen=0)`.
7. On parse or ingest failure for any single workflow, rollback that workflow's transaction and continue. Final summary: `migrated N, skipped M (parse), failed K (ingest)`.

**Idempotence:** the `WHERE NOT 'legacy_flat' = ANY(labels)` filter at step 1 makes re-runs safe.

**Step-claim convergence during migration:** because operation atoms use the global `ATOM_NAMESPACE`, two old workflows whose `steps[i]` text is identical produce the same `Uuid::new_v5(&ATOM_NAMESPACE, &blake3(text))` and share one operation claim after migration. The migrate-pass realizes the cross-workflow convergence retroactively. Claim writes use `INSERT ... ON CONFLICT (id) DO NOTHING` (the existing primary-key constraint on `claims.id`); the deterministic UUIDs from `epigraph-ingest` make this idempotent across concurrent migrations and re-runs without a separate UNIQUE on `content_hash`.

---

## Coexistence and deprecation

The PR is purely additive. Nothing existing breaks.

**Day-0 state after the PR merges:**
- Old: `store_workflow`, `find_workflow`, `improve_workflow`, `report_outcome`, `record_behavioral_execution` keep working unchanged. Existing flat-JSON claims in `claims WHERE 'workflow' = ANY(labels)` still serve `find_workflow`.
- New: `ingest_workflow` MCP tool + `POST /api/v1/workflows/ingest` are available. New ingests can go through this path. Hierarchical workflows live in the `workflows` table + carry workflow-step labels on their constituent claims.

**Day-1 (or whenever, separate operation):**
- Run the migration CLI. For each existing flat-JSON claim, a parallel hierarchical workflow is created. The flat-JSON claim picks up a `'legacy_flat'` label and a `workflow —supersedes→ claim` edge points at it from the new hierarchical root.
- After migration, `find_workflow` *still* returns flat-JSON results — those claims still carry `'workflow'`. A new `find_workflow_hierarchical` (or the future unified `find_hierarchical_artifact`, deferred) reads from the `workflows` table.

**Deprecation horizon (out of scope for this PR; trajectory only):**
- Once every active caller of `find_workflow` has been moved to the hierarchical path, the old `'workflow'` label becomes redundant on legacy_flat claims and the old `find_workflow` / `store_workflow` MCP tools can be removed in a follow-up.
- Issue #36 tracks the re-authoring work that makes the hierarchical results substantively better than the migrated-flat versions; once that's far enough along, `find_workflow_hierarchical` is the better answer for everyone and the old path can retire.
- No deprecation deadline in this PR.

**Risk: divergent stats between old flat-JSON and new hierarchical roots during the coexistence window.** Callers reporting outcomes via `report_outcome(old_id)` accrue stats on the old claim's properties. New hierarchical workflows accrue stats via per-step `behavioral_executions(step_claim_id, …)` rows. The `workflow —supersedes→ claim` edge is the join point if anyone wants to roll up "all stats for this workflow regardless of which path was used." Not built in this PR — flagged as a future query if needed.

---

## Testing

### Unit tests (in `crates/epigraph-ingest/`)

- `workflow::schema` parses minimal `WorkflowExtraction` round-trip via serde.
- `workflow::schema` parses `parent_canonical_name` lineage marker + `generation > 0`.
- `workflow::builder::build_ingest_plan` produces the expected `(claims, edges, path_index)` counts for a 2-phase × 2-step × 2-operation extraction. Exact assertion: 1 + 2 + 4 + 8 = 15 claims; `decomposes_to` count = 14; `phase_follows` count = 1; `step_follows` count = 2 within each phase.
- **Cross-source convergence (regression test for the headline property).** Build an ingest plan from a `DocumentExtraction` whose atom text is `"Use uuid_v5 for atom IDs."`, then a separate plan from a `WorkflowExtraction` whose operation text is the same string. Assert the two atoms have the *same* `Uuid` (from `ATOM_NAMESPACE` + `blake3`).
- Walker-config invariant: workflow plans never use `section_follows`/`continues_argument`; document plans never use `phase_follows`/`step_follows`. Catches accidental cross-wiring of the parameterized walker.
- Determinism: same `WorkflowExtraction` built twice produces identical claim IDs and identical edge lists (modulo ordering).

### Integration tests (in `crates/epigraph-mcp/tests/` and `crates/epigraph-api/`)

- `ingest_workflow_end_to_end`: spawn test server, call `ingest_workflow` with a 2-phase extraction, assert (a) one row in `workflows` with the expected `(canonical_name, generation)` UNIQUE, (b) N claims with `'workflow_thesis'` / `'workflow_step'` / `'workflow_atom'` labels, (c) `workflow —executes→ claim` edge count == claim count, (d) `phase_follows` and `step_follows` edges as expected.
- `ingest_workflow_idempotent`: ingest the same extraction twice. Second call is a no-op (root already exists, claims already exist via `ON CONFLICT DO NOTHING`, edges deduped via `EdgeRepository::create_if_not_exists`). Post-state row counts equal first-call's.
- `ingest_workflow_variant_lineage`: ingest workflow X (generation=0). Then ingest a "v2" with `parent_canonical_name=X.canonical_name, generation=1`. Assert `workflows.parent_id` FK is set, plus a `workflow —variant_of→ workflow` edge exists.
- `ingest_workflow_does_not_disturb_old_path`: pre-seed a flat-JSON workflow via `store_workflow`. Ingest a hierarchical workflow with the same `goal`. Assert `find_workflow` (old path) still returns the flat one; `find_workflow_hierarchical` returns the new one. Both are independent.
- `behavioral_execution_with_step_claim_id`: write a `behavioral_executions` row with a populated `step_claim_id`. Assert it persists and is queryable. Verify a backward-compatible NULL row also persists. Verify existing `behavioral_affinity_lineage` aggregation queries still return the same shape on a mix of NULL and populated rows.
- `report_hierarchical_outcome_updates_workflows_metadata`: `POST /api/v1/workflows/hierarchical/:id/outcome` with `{success: true, step_executions: [...]}` against a hierarchical workflow. Assert (a) `workflows.metadata.use_count` incremented, (b) one `behavioral_executions` row written per step with the matching `step_claim_id`, (c) the response shape matches the existing `report_outcome` shape so callers can swap.
- `report_hierarchical_outcome_404s_on_flat_id`: same endpoint with a flat-JSON `claim.id` returns 404 (the flat path is on the original endpoint).
- `edges_constraint_admits_workflow_source_type`: after the new migration runs, `INSERT INTO edges (source_type, target_type, ...) VALUES ('workflow', 'claim', ...)` succeeds. A pre-migration rollback (or against an unmigrated DB) would fail with `edges_entity_types_valid` — this test guards against the migration being merged without the constraint expansion.
- **Cross-source convergence DB test.** Ingest a `DocumentExtraction` with one atom `"text-embedding-3-large produces 3072-dimensional vectors"`. Ingest a `WorkflowExtraction` whose operation list contains the same string. Query `claims WHERE id = $deterministic_uuid_v5`. Assert exactly one row. Assert it has both a `paper —asserts→` (or `author_placeholder` resolved) edge AND a `workflow —executes→` edge pointing at it.

### Migration tool tests (in the bin's own test module)

- `migrate_one_flat_workflow_with_two_steps`: seed via `store_workflow`, run migration with `--dry-run`, assert no DB writes. Run without `--dry-run`, assert (a) old claim now has `'legacy_flat'` label, (b) one `workflows` row created, (c) one `workflow —supersedes→ claim` edge points at the old claim, (d) the operation atoms are reachable from the new root via `executes` edges.
- `migrate_idempotent_on_already_migrated`: run migration twice. Second run is a no-op (skipped by `'legacy_flat'` filter).
- `migrate_canonical_name_collision`: seed two flat workflows whose goals slugify to the same canonical_name. Assert one becomes generation=0 and the other generation=1 with `parent_canonical_name` set to the first's canonical_name.
- `migrate_handles_unparseable_content`: seed a claim with `'workflow'` label whose `content` doesn't parse. Assert migration logs a warning, leaves the claim untouched (no `'legacy_flat'`), and continues.

### Manual smoke test (documented for ops)

After deploy, run `migrate-flat-workflows --dry-run --limit 5` against the dev DB. Inspect logs for plausibility. Run again without `--dry-run --limit 5` for a small batch. Verify `SELECT count(*) FROM workflows` and `SELECT count(*) FROM claims WHERE 'legacy_flat' = ANY(labels)` match. Verify a sample workflow round-trips through `find_workflow_hierarchical`.

---

## Open questions deferred to writing-plans

These are mechanical / implementation-detail items the plan will resolve. Not design decisions:

- Exact migration filename / number — depends on the latest migration in main when this lands.
- Slugification rules for `--canonical-from goal-slug` (lowercase, hyphenate, strip non-alnum — exact regex is implementation detail).
- Whether the migration bin lives in `crates/epigraph-mcp` or gets its own `crates/epigraph-migrations-cli` — depends on dependency-tree convenience at implementation time.

Decisions explicitly *not* open:

- `find_workflow_hierarchical` ships as an HTTP endpoint only (`GET /api/v1/workflows/hierarchical/search?...`). No MCP tool variant in this PR. The future deferred unification work will produce the canonical MCP tool surface; adding a hierarchical-only MCP tool now would create a tool that gets renamed or removed when unification lands.
- The `workflow —executes→ claim` edge is emitted for *every* claim in the workflow's hierarchy (thesis, phases, steps, operations) — not just the top-level thesis. Slight edge-table growth in exchange for trivial graph-traversal queries answering "what are all the claims for this workflow?".
