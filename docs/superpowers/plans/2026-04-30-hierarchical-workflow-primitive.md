# Hierarchical Workflow Primitive Implementation Plan (#34)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land issue #34 — hierarchical workflows isomorphic to `DocumentExtraction`, with a dedicated `workflows` table, parameterized hierarchy walker shared with documents, atomic operations that converge across workflows and documents at level 3, and a one-shot migration tool that brings existing flat-JSON workflows into the new tables without disturbing the old `find_workflow` / `store_workflow` paths.

**Architecture:** Eight phases inside one feature branch. Phase 1 lands the schema (workflows table + edges constraint expansion + validate_edge_reference trigger update). Phase 2 refactors `epigraph-ingest` from a monolithic builder to `common`/`document`/`workflow` modules with a parameterized walker, preserving back-compat for all current `ingest_document` callers. Phase 3 adds `WorkflowExtraction` and the workflow walker config. Phase 4 ships `ingest_workflow` (MCP tool + HTTP endpoint). Phase 5 ALTERs `behavioral_executions` and adds `report_hierarchical_outcome`. Phase 6 adds `find_workflow_hierarchical` HTTP search. Phase 7 ships the migration CLI. Phase 8 runs the full workspace test suite + manual smoke. Each phase ends in a commit and can be reviewed/cherry-picked independently.

**Tech Stack:** Rust 1.75+, Axum, sqlx, PostgreSQL 16, blake3, uuid (v5).

**Spec:** [`docs/superpowers/specs/2026-04-30-hierarchical-workflow-primitive-design.md`](../specs/2026-04-30-hierarchical-workflow-primitive-design.md).

---

## Pre-flight

- [ ] **Step 0.1: Confirm worktree state**

```bash
cd /home/jeremy/epigraph-wt-issue-34
git log --oneline -3
```

Expected: `4caac2bf` (review-driven spec edits) at HEAD, `7ca19e3c` immediately before, `171fdd6f` (origin/main) third.

- [ ] **Step 0.2: Confirm toolchain compiles**

```bash
cargo build -p epigraph-api -p epigraph-mcp -p epigraph-db -p epigraph-ingest --features db 2>&1 | tail -5
```

Expected: clean build (or sqlx-offline metadata regeneration prompt — if so, run `cargo sqlx prepare --workspace` against a live dev DB before continuing).

- [ ] **Step 0.3: Confirm dev DB reachable**

```bash
psql "$DATABASE_URL" -c '\dt claims edges papers behavioral_executions' | head -10
```

Expected: four rows, one per table.

- [ ] **Step 0.4: Confirm latest migration is 018**

```bash
ls /home/jeremy/epigraph-wt-issue-34/migrations/ | grep -E '^[0-9]' | tail -3
```

Expected: ends in `018_drop_edges_triple_unique_constraint.sql`. New migrations in this plan are 019 and 020.

- [ ] **Step 0.5: Run existing `epigraph-ingest` tests as baseline**

```bash
cargo test -p epigraph-ingest 2>&1 | tail -5
```

Expected: all pass. This baseline is what the Phase 2 refactor must preserve.

---

## Phase 1 — Migration: `workflows` table + edges constraint + trigger

**Why first:** Every later phase that inserts a `workflow —executes→ claim` edge or queries the `workflows` table assumes this migration has run. Land the schema, expand the edges constraint to admit `'workflow'` as a valid `source_type`/`target_type`, and update both `validate_edge_reference` overloads to verify FKs against the new table. Without all three, the `EdgeRepository::create` path fails the CHECK before reaching any workflow-aware code.

### Task 1.1: Write migration `019_workflows_table.sql`

**Files:**
- Create: `migrations/019_workflows_table.sql`

- [ ] **Step 1.1.1: Write the migration**

Create `migrations/019_workflows_table.sql` with this exact content:

```sql
-- Migration 019: workflows table + edges constraint expansion + trigger update for #34
-- Adds the `workflows` source-node type as the metadata anchor for hierarchical
-- workflows. Expands the edges_entity_types_valid CHECK and validate_edge_reference
-- overloads so workflow→claim edges (executes, supersedes, variant_of) can be inserted.

-- Step 1: workflows table (parallel to papers)
CREATE TABLE workflows (
    id              uuid PRIMARY KEY,
    canonical_name  text NOT NULL,
    generation      integer NOT NULL DEFAULT 0,
    goal            text NOT NULL,
    parent_id       uuid REFERENCES workflows(id),
    metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (canonical_name, generation)
);
CREATE INDEX workflows_canonical_name_idx ON workflows (canonical_name);
CREATE INDEX workflows_goal_trgm_idx ON workflows USING gin (goal gin_trgm_ops);

-- Step 2: expand edges_entity_types_valid CHECK to include 'workflow'
ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_entity_types_valid;
ALTER TABLE edges ADD CONSTRAINT edges_entity_types_valid CHECK (
    (source_type::text = ANY (ARRAY[
        'claim', 'agent', 'evidence', 'trace', 'node', 'activity', 'paper',
        'perspective', 'community', 'context', 'frame', 'analysis',
        'source_artifact', 'span', 'entity', 'task', 'event', 'workflow'
    ]))
    AND
    (target_type::text = ANY (ARRAY[
        'claim', 'agent', 'evidence', 'trace', 'node', 'activity', 'paper',
        'perspective', 'community', 'context', 'frame', 'analysis',
        'source_artifact', 'span', 'entity', 'task', 'event', 'workflow'
    ]))
);

-- Step 3: replace BOTH overloads of validate_edge_reference to recognize 'workflow'
CREATE OR REPLACE FUNCTION validate_edge_reference(entity_type TEXT, entity_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN CASE entity_type
        WHEN 'claim'                 THEN EXISTS (SELECT 1 FROM claims WHERE id = entity_id)
        WHEN 'agent'                 THEN EXISTS (SELECT 1 FROM agents WHERE id = entity_id)
        WHEN 'evidence'              THEN EXISTS (SELECT 1 FROM evidence WHERE id = entity_id)
        WHEN 'trace'                 THEN EXISTS (SELECT 1 FROM reasoning_traces WHERE id = entity_id)
        WHEN 'paper'                 THEN EXISTS (SELECT 1 FROM papers WHERE id = entity_id)
        WHEN 'analysis'              THEN EXISTS (SELECT 1 FROM analyses WHERE id = entity_id)
        WHEN 'activity'              THEN EXISTS (SELECT 1 FROM activities WHERE id = entity_id)
        WHEN 'source_artifact'       THEN EXISTS (SELECT 1 FROM source_artifacts WHERE id = entity_id)
        WHEN 'span'                  THEN EXISTS (SELECT 1 FROM agent_spans WHERE id = entity_id)
        WHEN 'entity'                THEN EXISTS (SELECT 1 FROM entities WHERE id = entity_id)
        WHEN 'task'                  THEN EXISTS (SELECT 1 FROM tasks WHERE id = entity_id)
        WHEN 'event'                 THEN EXISTS (SELECT 1 FROM events WHERE id = entity_id)
        WHEN 'workflow'              THEN EXISTS (SELECT 1 FROM workflows WHERE id = entity_id)
        WHEN 'node'                  THEN TRUE
        ELSE FALSE
    END;
END;
$$;

CREATE OR REPLACE FUNCTION validate_edge_reference(entity_id UUID, entity_type CHARACTER VARYING)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN CASE entity_type
        WHEN 'claim'                 THEN EXISTS (SELECT 1 FROM claims WHERE id = entity_id)
        WHEN 'agent'                 THEN EXISTS (SELECT 1 FROM agents WHERE id = entity_id)
        WHEN 'evidence'              THEN EXISTS (SELECT 1 FROM evidence WHERE id = entity_id)
        WHEN 'trace'                 THEN EXISTS (SELECT 1 FROM reasoning_traces WHERE id = entity_id)
        WHEN 'paper'                 THEN EXISTS (SELECT 1 FROM papers WHERE id = entity_id)
        WHEN 'analysis'              THEN EXISTS (SELECT 1 FROM analyses WHERE id = entity_id)
        WHEN 'activity'              THEN EXISTS (SELECT 1 FROM activities WHERE id = entity_id)
        WHEN 'source_artifact'       THEN EXISTS (SELECT 1 FROM source_artifacts WHERE id = entity_id)
        WHEN 'span'                  THEN EXISTS (SELECT 1 FROM agent_spans WHERE id = entity_id)
        WHEN 'entity'                THEN EXISTS (SELECT 1 FROM entities WHERE id = entity_id)
        WHEN 'task'                  THEN EXISTS (SELECT 1 FROM tasks WHERE id = entity_id)
        WHEN 'event'                 THEN EXISTS (SELECT 1 FROM events WHERE id = entity_id)
        WHEN 'workflow'              THEN EXISTS (SELECT 1 FROM workflows WHERE id = entity_id)
        WHEN 'node'                  THEN TRUE
        ELSE FALSE
    END;
END;
$$;
```

- [ ] **Step 1.1.2: Apply the migration to the dev DB**

```bash
psql "$DATABASE_URL" -f migrations/019_workflows_table.sql 2>&1 | tail -10
```

Expected: `CREATE TABLE`, `CREATE INDEX`, `CREATE INDEX`, `ALTER TABLE`, `ALTER TABLE`, `CREATE FUNCTION`, `CREATE FUNCTION`. No errors.

- [ ] **Step 1.1.3: Verify the table was created**

```bash
psql "$DATABASE_URL" -c '\d workflows' | head -15
```

Expected: shows columns `id, canonical_name, generation, goal, parent_id, metadata, created_at` with the right types.

- [ ] **Step 1.1.4: Verify the edges constraint admits 'workflow'**

```bash
psql "$DATABASE_URL" -c "INSERT INTO workflows (id, canonical_name, goal) VALUES (gen_random_uuid(), 'constraint-smoke-test', 'smoke') RETURNING id;" \
  | tee /tmp/wfid.txt
WFID=$(grep -oE '[a-f0-9-]{36}' /tmp/wfid.txt | head -1)
CLAIMID=$(psql "$DATABASE_URL" -tAc "SELECT id FROM claims LIMIT 1")
psql "$DATABASE_URL" -c "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) VALUES ('$WFID', 'workflow', '$CLAIMID', 'claim', 'executes');"
psql "$DATABASE_URL" -c "DELETE FROM edges WHERE source_id = '$WFID'; DELETE FROM workflows WHERE id = '$WFID';"
```

Expected: the INSERT into `edges` succeeds (no `edges_entity_types_valid` violation, no `validate_edge_reference` trigger violation). Cleanup deletes succeed. If the INSERT fails with a CHECK or trigger violation, the migration is incomplete — re-read step 1.1.1.

- [ ] **Step 1.1.5: Commit**

```bash
git add migrations/019_workflows_table.sql
git commit -m "feat(db): workflows table + edges constraint expansion + trigger update (#34)"
```

---

## Phase 2 — Refactor `epigraph-ingest` into `common`/`document`/`workflow` modules

**Why second:** Phases 3, 4, 7 depend on a parameterized walker. The current `crates/epigraph-ingest/src/builder.rs` is a single 360-line `build_ingest_plan(&DocumentExtraction)` function with hard-coded paper-specific logic. Extract the reusable parts into `common::`, leave document-specific logic in `document::`, and prepare an empty `workflow::` namespace for Phase 3.

**Approach:** Move types and helpers, add re-exports so existing call sites continue to compile without changes. Run the full `epigraph-ingest` test suite after each move to catch regressions.

### Task 2.1: Extract shared types to `common::plan`

**Files:**
- Create: `crates/epigraph-ingest/src/common/mod.rs`
- Create: `crates/epigraph-ingest/src/common/plan.rs`
- Modify: `crates/epigraph-ingest/src/lib.rs`

- [ ] **Step 2.1.1: Create `common/plan.rs` with the shared plan types**

Create `crates/epigraph-ingest/src/common/plan.rs`:

```rust
//! Shared plan types for hierarchical artifact ingest. Used by both
//! `document::` (papers) and `workflow::` (workflows).

use std::collections::HashMap;
use uuid::Uuid;

/// A planned claim to be persisted.
#[derive(Debug, Clone)]
pub struct PlannedClaim {
    pub id: Uuid,
    pub content: String,
    pub level: u8, // 0=thesis, 1=section/phase, 2=paragraph/step, 3=atom/operation
    pub properties: serde_json::Value,
    pub content_hash: [u8; 32], // BLAKE3
    pub confidence: f64,
    pub methodology: Option<String>,
    pub evidence_type: Option<String>,
    pub supporting_text: Option<String>,
    pub enrichment: serde_json::Value,
}

/// A planned edge to be persisted.
#[derive(Debug, Clone)]
pub struct PlannedEdge {
    pub source_id: Uuid,
    pub source_type: String,
    pub target_id: Uuid,
    pub target_type: String,
    pub relationship: String,
    pub properties: serde_json::Value,
}

/// Complete plan of operations for ingesting a hierarchical artifact (paper
/// or workflow). The walker that produced this plan is the same in both cases;
/// only the source-node type, namespace seed, and label/relationship strings
/// differ between artifact kinds.
#[derive(Debug)]
pub struct IngestPlan {
    pub claims: Vec<PlannedClaim>,
    pub edges: Vec<PlannedEdge>,
    pub path_index: HashMap<String, Uuid>,
}
```

- [ ] **Step 2.1.2: Create `common/mod.rs`**

Create `crates/epigraph-ingest/src/common/mod.rs`:

```rust
//! Shared infrastructure for hierarchical artifact ingest. The hierarchy
//! walker, ID derivation namespaces, and plan types live here. Document-
//! and workflow-specific schemas wrap them in `document::` and `workflow::`.

pub mod ids;
pub mod plan;
pub mod schema;
pub mod walker;
```

(`ids`, `schema`, `walker` will be created in subsequent tasks; placeholder mod entries are OK because their files will exist before any consumer needs them.)

- [ ] **Step 2.1.3: Update `lib.rs` to declare the new module tree**

Edit `crates/epigraph-ingest/src/lib.rs`. Replace the existing content:

```rust
pub mod builder;
pub mod errors;
pub mod schema;

#[cfg(test)]
mod tests {
    // ... existing tests ...
}
```

with:

```rust
pub mod builder;
pub mod common;
pub mod errors;
pub mod schema;

#[cfg(test)]
mod tests {
    // ... existing tests unchanged ...
}
```

(Leave the `#[cfg(test)] mod tests` block exactly as-is; it imports from `crate::builder::*` and `crate::schema::*` which we'll keep working via re-exports.)

- [ ] **Step 2.1.4: Confirm it still compiles**

```bash
cargo check -p epigraph-ingest 2>&1 | tail -5
```

Expected: `error[E0583]: file not found for module ids` (or similar). The `common/mod.rs` declares `ids`/`schema`/`walker` modules whose files don't yet exist. That's the correct intermediate state — the next tasks create them.

### Task 2.2: Extract ID-derivation helpers to `common::ids`

**Files:**
- Create: `crates/epigraph-ingest/src/common/ids.rs`

- [ ] **Step 2.2.1: Create `common/ids.rs` with the namespace constants and helpers**

Create `crates/epigraph-ingest/src/common/ids.rs`:

```rust
//! Deterministic ID derivation for hierarchical artifact ingest.
//!
//! Atoms (level 3) use a global namespace so that identical text across
//! different documents AND different workflows converges on the same claim
//! node. Compound nodes (thesis, section/phase, paragraph/step) are scoped by
//! a per-artifact seed (the document title, or the workflow's canonical_name)
//! so they do NOT converge across artifacts even when their text matches.

use uuid::Uuid;

/// EpiGraph atom content namespace for deterministic UUIDv5 generation.
/// Atoms with identical text across different documents and workflows
/// intentionally get the same UUID — this is how cross-source matching works.
pub const ATOM_NAMESPACE: Uuid = Uuid::from_bytes([
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x47, 0x89, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
]);

/// Namespace for compound claims (thesis, section/phase, paragraph/step).
/// Compound claims are scoped by their host artifact (document title or
/// workflow canonical_name) so the same summary text in two different
/// papers gets two different UUIDs.
pub const COMPOUND_NAMESPACE: Uuid = Uuid::from_bytes([
    0xc0, 0x4d, 0x90, 0xd1, 0xe2, 0xf3, 0x44, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0xa5,
]);

/// Namespace for workflow root nodes. Used by `workflow::builder` to derive
/// `workflows.id` from `(canonical_name, generation)`.
pub const WORKFLOW_NAMESPACE: Uuid = Uuid::from_bytes([
    0xf1, 0x0e, 0x55, 0xa5, 0x37, 0x42, 0x4b, 0xc0, 0x9d, 0x21, 0x8e, 0xa6, 0xf3, 0x12, 0x6c, 0x88,
]);

/// BLAKE3-32 of `content` as a fixed-size array.
#[must_use]
pub fn content_hash(content: &str) -> [u8; 32] {
    *blake3::hash(content.as_bytes()).as_bytes()
}

/// Generate a deterministic UUID for a compound claim (thesis/section/phase/
/// paragraph/step) scoped to its host artifact. Same content + same artifact
/// seed → same UUID.
#[must_use]
pub fn compound_claim_id(content_hash: &[u8; 32], artifact_seed: &str) -> Uuid {
    let mut material = Vec::with_capacity(32 + artifact_seed.len());
    material.extend_from_slice(content_hash);
    material.extend_from_slice(artifact_seed.as_bytes());
    Uuid::new_v5(&COMPOUND_NAMESPACE, &material)
}

/// Generate a deterministic UUID for an atomic claim (level 3) from its
/// content hash. Globally unique to the text — converges across artifacts.
#[must_use]
pub fn atom_id(content_hash: &[u8; 32]) -> Uuid {
    Uuid::new_v5(&ATOM_NAMESPACE, content_hash)
}

/// Generate a deterministic UUID for a workflow root node from canonical_name
/// and generation. Variants share `canonical_name`; their root IDs differ by
/// the appended generation tag.
#[must_use]
pub fn workflow_root_id(canonical_name: &str, generation: u32) -> Uuid {
    let material = format!("{canonical_name}:{generation}");
    let hash = blake3::hash(material.as_bytes());
    Uuid::new_v5(&WORKFLOW_NAMESPACE, hash.as_bytes())
}
```

- [ ] **Step 2.2.2: Confirm `cargo check` advances past `ids`**

```bash
cargo check -p epigraph-ingest 2>&1 | tail -5
```

Expected: a different error — now `error[E0583]: file not found for module schema` (the next missing file). If `ids` errors, re-read step 2.2.1.

### Task 2.3: Extract shared schema types to `common::schema`

**Files:**
- Create: `crates/epigraph-ingest/src/common/schema.rs`
- Modify: `crates/epigraph-ingest/src/schema.rs` (later, in Task 2.5 — for now keep as-is)

- [ ] **Step 2.3.1: Create `common/schema.rs` with `AuthorEntry`, `ClaimRelationship`, `ThesisDerivation`**

Create `crates/epigraph-ingest/src/common/schema.rs`:

```rust
//! Schema types shared across `document::` and `workflow::` artifact kinds.

use serde::{Deserialize, Serialize};

/// An author with affiliations and roles. Workflows can be authored by humans,
/// LLMs, or external systems — same shape as document authors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorEntry {
    pub name: String,
    #[serde(default)]
    pub affiliations: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

/// A relationship between two claims identified by path. Workflow steps can
/// support / contradict / refute each other across phases just like document
/// atoms can across paragraphs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRelationship {
    pub source_path: String,
    pub target_path: String,
    pub relationship: String,
    #[serde(default)]
    pub rationale: Option<String>,
    #[serde(default)]
    pub strength: Option<f64>,
}

/// Whether the thesis was derived top-down or bottom-up.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThesisDerivation {
    #[default]
    TopDown,
    BottomUp,
}
```

- [ ] **Step 2.3.2: Confirm `cargo check` advances**

```bash
cargo check -p epigraph-ingest 2>&1 | tail -5
```

Expected: `error[E0583]: file not found for module walker`. Now we have `ids` and `schema` working; only `walker` is missing.

### Task 2.4: Define the `Walker` trait + `WalkerConfig` in `common::walker`

**Files:**
- Create: `crates/epigraph-ingest/src/common/walker.rs`

The walker is the hierarchy-walking algorithm extracted from `build_ingest_plan`. Rather than abstract it as a free-function with a 10-parameter config, model the per-kind variation as a `Walker` trait that document/workflow each implement.

- [ ] **Step 2.4.1: Create `common/walker.rs` with the `Walker` trait**

Create `crates/epigraph-ingest/src/common/walker.rs`:

```rust
//! Parameterized hierarchy walker. Document and workflow ingestion both
//! implement `Walker` to produce an `IngestPlan` from their respective
//! extraction shapes.
//!
//! The walker contract is intentionally minimal: kind-specific schemas walk
//! their own data, but use shared `common::ids` helpers and emit
//! `common::plan::IngestPlan`. There is no single generic walk function —
//! each kind's `build_ingest_plan` reads naturally with its own field names.
//! This trait exists to define the *interface* both kinds expose.

use crate::common::plan::IngestPlan;

/// Implemented by `document::DocumentExtraction` and `workflow::WorkflowExtraction`.
/// Building a plan is the only operation that varies by kind.
pub trait Walker {
    /// Walk the artifact's hierarchy and produce a complete ingest plan.
    fn build_ingest_plan(&self) -> IngestPlan;
}
```

- [ ] **Step 2.4.2: Confirm `cargo check` succeeds for `common`**

```bash
cargo check -p epigraph-ingest 2>&1 | tail -5
```

Expected: now the error shifts to `unresolved import` somewhere in `lib.rs` or `builder.rs` — because the existing `builder.rs` still uses local `ATOM_NAMESPACE`, `compound_claim_id`, etc. that we haven't yet redirected. That's the next task.

### Task 2.5: Move `DocumentExtraction` to `document::schema`, builder to `document::builder`

**Files:**
- Create: `crates/epigraph-ingest/src/document/mod.rs`
- Create: `crates/epigraph-ingest/src/document/schema.rs`
- Create: `crates/epigraph-ingest/src/document/builder.rs`
- Modify: `crates/epigraph-ingest/src/schema.rs` (replace contents with re-export)
- Modify: `crates/epigraph-ingest/src/builder.rs` (replace contents with re-export)
- Modify: `crates/epigraph-ingest/src/lib.rs` (add `pub mod document;`)

- [ ] **Step 2.5.1: Create `document/mod.rs`**

Create `crates/epigraph-ingest/src/document/mod.rs`:

```rust
//! Document-specific (paper / textbook / report / …) extraction and ingest.

pub mod builder;
pub mod schema;

pub use builder::build_ingest_plan;
pub use schema::*;
```

- [ ] **Step 2.5.2: Move `DocumentExtraction` and friends into `document/schema.rs`**

Create `crates/epigraph-ingest/src/document/schema.rs` with the **document-specific** schema types — `DocumentExtraction`, `DocumentSource`, `SourceType`, `Section`, `Paragraph`. Use `common::schema::{AuthorEntry, ClaimRelationship, ThesisDerivation}` for the shared bits:

```rust
//! Schema types for document (paper) extraction.

use serde::{Deserialize, Serialize};

use crate::common::schema::{AuthorEntry, ClaimRelationship, ThesisDerivation};

/// Top-level extraction result from a document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentExtraction {
    pub source: DocumentSource,
    #[serde(default)]
    pub thesis: Option<String>,
    #[serde(default)]
    pub thesis_derivation: ThesisDerivation,
    #[serde(default)]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub relationships: Vec<ClaimRelationship>,
}

/// Metadata about the source document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSource {
    pub title: String,
    #[serde(default)]
    pub doi: Option<String>,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub source_type: SourceType,
    #[serde(default)]
    pub authors: Vec<AuthorEntry>,
    #[serde(default)]
    pub journal: Option<String>,
    #[serde(default)]
    pub year: Option<u32>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// The type of source document.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceType {
    #[default]
    Paper,
    Textbook,
    InternalDocument,
    Report,
    Transcript,
    Legal,
    Tabular,
}

/// A section within the document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub paragraphs: Vec<Paragraph>,
}

/// A paragraph containing atomic claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paragraph {
    pub compound: String,
    #[serde(default)]
    pub supporting_text: String,
    #[serde(default)]
    pub atoms: Vec<String>,
    #[serde(default)]
    pub generality: Vec<i32>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default)]
    pub methodology: Option<String>,
    #[serde(default)]
    pub evidence_type: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub instruments_used: Vec<String>,
    #[serde(default)]
    pub reagents_involved: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<String>,
}

#[must_use]
pub fn default_confidence() -> f64 {
    0.8
}
```

- [ ] **Step 2.5.3: Move `build_ingest_plan` into `document/builder.rs`**

Create `crates/epigraph-ingest/src/document/builder.rs` by **moving** the contents of `crates/epigraph-ingest/src/builder.rs` into it, with these textual edits:

1. Replace the local `ATOM_NAMESPACE`, `COMPOUND_NAMESPACE`, `compound_claim_id`, `content_hash` constants/functions with `use crate::common::ids::{atom_id, compound_claim_id, content_hash};` at the top.
2. Replace the local `PlannedClaim`, `PlannedEdge`, `IngestPlan` types with `use crate::common::plan::{IngestPlan, PlannedClaim, PlannedEdge};`.
3. Replace the local `normalize_claim_path` helper — keep it as-is, it's document-specific (sections/paragraphs/atoms paths).
4. Replace the call site `let atom_id = Uuid::new_v5(&ATOM_NAMESPACE, &atom_hash);` with `let atom_id = atom_id(&atom_hash);` (using the helper from `common::ids`).
5. Replace the call site `let id = compound_claim_id(&hash, doc_title);` — already matches the new helper signature, keep as-is.
6. Add `use crate::document::schema::*;` to bring `DocumentExtraction` etc. into scope.
7. Add `impl crate::common::walker::Walker for DocumentExtraction { fn build_ingest_plan(&self) -> IngestPlan { build_ingest_plan(self) } }` at the bottom.
8. Strip the `enrichment_from_paragraph` helper if it's still local — leave it in place (it's document-specific).

The fully edited file (use this as the canonical version — do not partially edit; copy this into `document/builder.rs` verbatim then proceed):

```rust
//! Document hierarchy walker. Reads a `DocumentExtraction` and produces an
//! `IngestPlan` of claims + edges + path index.

use std::collections::HashMap;

use uuid::Uuid;

use crate::common::ids::{atom_id, compound_claim_id, content_hash};
use crate::common::plan::{IngestPlan, PlannedClaim, PlannedEdge};
use crate::common::schema::ThesisDerivation;
use crate::document::schema::{DocumentExtraction, Paragraph, SourceType};

/// Convert slash-delimited paths from extraction ("sections/0/paragraphs/1/atoms/2")
/// to the bracket-dot notation used by path_index ("sections[0].paragraphs[1].atoms[2]").
/// Passes through paths that are already in bracket-dot format unchanged.
#[must_use]
pub fn normalize_claim_path(path: &str) -> String {
    if path.contains('[') {
        return path.to_string();
    }
    let parts: Vec<&str> = path.split('/').collect();
    let mut result = String::new();
    let mut i = 0;
    while i < parts.len() {
        if i > 0 {
            result.push('.');
        }
        result.push_str(parts[i]);
        if i + 1 < parts.len() && parts[i + 1].parse::<usize>().is_ok() {
            result.push('[');
            result.push_str(parts[i + 1]);
            result.push(']');
            i += 2;
            continue;
        }
        i += 1;
    }
    result
}

const fn source_type_str(st: &SourceType) -> &'static str {
    match st {
        SourceType::Paper => "Paper",
        SourceType::Textbook => "Textbook",
        SourceType::InternalDocument => "InternalDocument",
        SourceType::Report => "Report",
        SourceType::Transcript => "Transcript",
        SourceType::Legal => "Legal",
        SourceType::Tabular => "Tabular",
    }
}

const fn thesis_derivation_str(td: &ThesisDerivation) -> &'static str {
    match td {
        ThesisDerivation::TopDown => "TopDown",
        ThesisDerivation::BottomUp => "BottomUp",
    }
}

fn decomposes_edge(source_id: Uuid, target_id: Uuid) -> PlannedEdge {
    PlannedEdge {
        source_id,
        source_type: "claim".to_string(),
        target_id,
        target_type: "claim".to_string(),
        relationship: "decomposes_to".to_string(),
        properties: serde_json::json!({}),
    }
}

fn enrichment_from_paragraph(paragraph: &Paragraph) -> serde_json::Value {
    serde_json::json!({
        "instruments_used": paragraph.instruments_used,
        "reagents_involved": paragraph.reagents_involved,
        "conditions": paragraph.conditions,
    })
}

/// Walk a `DocumentExtraction` tree and produce a flat list of operations.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build_ingest_plan(extraction: &DocumentExtraction) -> IngestPlan {
    let mut claims = Vec::new();
    let mut edges = Vec::new();
    let mut path_index = HashMap::new();

    let source_type = source_type_str(&extraction.source.source_type);
    let doc_title = &extraction.source.title;

    // Step 1: Thesis (level 0)
    #[allow(clippy::option_if_let_else)]
    let thesis_id = if let Some(ref thesis_text) = extraction.thesis {
        let hash = content_hash(thesis_text);
        let id = compound_claim_id(&hash, doc_title);
        path_index.insert("thesis".to_string(), id);

        claims.push(PlannedClaim {
            id,
            content: thesis_text.clone(),
            level: 0,
            properties: serde_json::json!({
                "level": 0,
                "source_type": source_type,
                "thesis_derivation": thesis_derivation_str(&extraction.thesis_derivation),
            }),
            content_hash: hash,
            confidence: 1.0,
            methodology: None,
            evidence_type: None,
            supporting_text: None,
            enrichment: serde_json::json!({}),
        });
        Some(id)
    } else {
        None
    };

    let mut section_ids: Vec<Uuid> = Vec::new();

    for (si, section) in extraction.sections.iter().enumerate() {
        let section_path = format!("sections[{si}]");
        let section_hash = content_hash(&section.summary);
        let section_id = compound_claim_id(&section_hash, doc_title);
        section_ids.push(section_id);
        path_index.insert(section_path.clone(), section_id);

        claims.push(PlannedClaim {
            id: section_id,
            content: section.summary.clone(),
            level: 1,
            properties: serde_json::json!({
                "level": 1,
                "source_type": source_type,
                "section": section.title,
            }),
            content_hash: section_hash,
            confidence: 1.0,
            methodology: None,
            evidence_type: None,
            supporting_text: None,
            enrichment: serde_json::json!({}),
        });

        if let Some(tid) = thesis_id {
            edges.push(decomposes_edge(tid, section_id));
        }

        let mut para_ids: Vec<Uuid> = Vec::new();

        for (pi, paragraph) in section.paragraphs.iter().enumerate() {
            let para_path = format!("{section_path}.paragraphs[{pi}]");
            let para_hash = content_hash(&paragraph.compound);
            let para_id = compound_claim_id(&para_hash, doc_title);
            para_ids.push(para_id);
            path_index.insert(para_path.clone(), para_id);

            let enrichment = enrichment_from_paragraph(paragraph);

            claims.push(PlannedClaim {
                id: para_id,
                content: paragraph.compound.clone(),
                level: 2,
                properties: serde_json::json!({
                    "level": 2,
                    "source_type": source_type,
                    "section": section.title,
                    "supporting_text": paragraph.supporting_text,
                }),
                content_hash: para_hash,
                confidence: paragraph.confidence,
                methodology: paragraph.methodology.clone(),
                evidence_type: paragraph.evidence_type.clone(),
                supporting_text: Some(paragraph.supporting_text.clone()),
                enrichment: enrichment.clone(),
            });

            edges.push(decomposes_edge(section_id, para_id));

            for (ai, atom_text) in paragraph.atoms.iter().enumerate() {
                let atom_hash = content_hash(atom_text);
                let aid = atom_id(&atom_hash);
                let atom_path = format!("{para_path}.atoms[{ai}]");
                path_index.insert(atom_path, aid);

                let generality = paragraph.generality.get(ai).copied().filter(|&g| g >= 0);

                let mut props = serde_json::json!({
                    "level": 3,
                    "source_type": source_type,
                    "section": section.title,
                });
                if let Some(g) = generality {
                    props["generality"] = serde_json::json!(g);
                }

                claims.push(PlannedClaim {
                    id: aid,
                    content: atom_text.clone(),
                    level: 3,
                    properties: props,
                    content_hash: atom_hash,
                    confidence: paragraph.confidence,
                    methodology: paragraph.methodology.clone(),
                    evidence_type: paragraph.evidence_type.clone(),
                    supporting_text: Some(paragraph.supporting_text.clone()),
                    enrichment: enrichment.clone(),
                });

                edges.push(decomposes_edge(para_id, aid));
            }
        }

        for w in para_ids.windows(2) {
            edges.push(PlannedEdge {
                source_id: w[0],
                source_type: "claim".to_string(),
                target_id: w[1],
                target_type: "claim".to_string(),
                relationship: "continues_argument".to_string(),
                properties: serde_json::json!({}),
            });
        }
    }

    for w in section_ids.windows(2) {
        edges.push(PlannedEdge {
            source_id: w[0],
            source_type: "claim".to_string(),
            target_id: w[1],
            target_type: "claim".to_string(),
            relationship: "section_follows".to_string(),
            properties: serde_json::json!({}),
        });
    }

    for rel in &extraction.relationships {
        let src_path = normalize_claim_path(&rel.source_path);
        let tgt_path = normalize_claim_path(&rel.target_path);

        let source_id = match path_index.get(&src_path) {
            Some(id) => *id,
            None => continue,
        };
        let target_id = match path_index.get(&tgt_path) {
            Some(id) => *id,
            None => continue,
        };

        let mut props = serde_json::json!({});
        if let Some(ref rationale) = rel.rationale {
            props["rationale"] = serde_json::json!(rationale);
        }
        if let Some(strength) = rel.strength {
            props["strength"] = serde_json::json!(strength);
        }

        edges.push(PlannedEdge {
            source_id,
            source_type: "claim".to_string(),
            target_id,
            target_type: "claim".to_string(),
            relationship: rel.relationship.clone(),
            properties: props,
        });
    }

    for (author_idx, _author) in extraction.source.authors.iter().enumerate() {
        for planned_claim in &claims {
            edges.push(PlannedEdge {
                source_id: Uuid::nil(),
                source_type: "author_placeholder".to_string(),
                target_id: planned_claim.id,
                target_type: "claim".to_string(),
                relationship: "asserts".to_string(),
                properties: serde_json::json!({
                    "author_index": author_idx,
                    "role": "author",
                    "source": "document_attribution",
                }),
            });
        }
    }

    IngestPlan {
        claims,
        edges,
        path_index,
    }
}

impl crate::common::walker::Walker for DocumentExtraction {
    fn build_ingest_plan(&self) -> IngestPlan {
        build_ingest_plan(self)
    }
}
```

- [ ] **Step 2.5.4: Replace `crates/epigraph-ingest/src/schema.rs` with a re-export shim**

Open `crates/epigraph-ingest/src/schema.rs` and **replace its entire contents** with:

```rust
//! Back-compat shim. Document schema lives in `document::schema` now; workflow
//! schema lives in `workflow::schema`. Re-exports here keep existing
//! `epigraph_ingest::DocumentExtraction` etc. callers compiling.

pub use crate::common::schema::{AuthorEntry, ClaimRelationship, ThesisDerivation};
pub use crate::document::schema::{
    default_confidence, DocumentExtraction, DocumentSource, Paragraph, Section, SourceType,
};
```

- [ ] **Step 2.5.5: Replace `crates/epigraph-ingest/src/builder.rs` with a re-export shim**

Open `crates/epigraph-ingest/src/builder.rs` and **replace its entire contents** with:

```rust
//! Back-compat shim. Document builder lives in `document::builder` now; workflow
//! builder lives in `workflow::builder`. Re-exports here keep existing
//! `epigraph_ingest::build_ingest_plan` callers compiling.

pub use crate::common::plan::{IngestPlan, PlannedClaim, PlannedEdge};
pub use crate::document::builder::{build_ingest_plan, normalize_claim_path};
```

- [ ] **Step 2.5.6: Update `lib.rs` to register `document` and re-exports**

Edit `crates/epigraph-ingest/src/lib.rs`. Replace its declaration block with:

```rust
pub mod builder;
pub mod common;
pub mod document;
pub mod errors;
pub mod schema;

#[cfg(test)]
mod tests {
    // ... existing tests, unchanged ...
}
```

(The existing `mod tests` block uses `crate::builder::*` and `crate::schema::*` — both shims still expose the names it needs, so the tests don't need to change.)

- [ ] **Step 2.5.7: Run `cargo check` to confirm clean compile**

```bash
cargo check -p epigraph-ingest 2>&1 | tail -10
```

Expected: clean check with no errors. If `unresolved import` errors remain, the most likely cause is a missing `pub use` in either `document/mod.rs`, `schema.rs` shim, or `builder.rs` shim.

- [ ] **Step 2.5.8: Run the full `epigraph-ingest` test suite — no regressions allowed**

```bash
cargo test -p epigraph-ingest 2>&1 | tail -10
```

Expected: every test passes. Specifically `test_parse_minimal_document_extraction`, `test_build_plan_counts`, `test_atom_deterministic_ids`, `test_compound_claim_ids_deterministic`, and the relationship/path tests must all green.

- [ ] **Step 2.5.9: Commit the refactor as one atomic change**

```bash
git add crates/epigraph-ingest/
git commit -m "refactor(ingest): extract common/document modules; add Walker trait (#34)"
```

---

## Phase 3 — `WorkflowExtraction` schema and walker

**Why third:** Now that `common::` exposes the shared infrastructure, the workflow walker is a small additive module. No existing behavior changes.

### Task 3.1: Add `workflow/schema.rs`

**Files:**
- Create: `crates/epigraph-ingest/src/workflow/mod.rs`
- Create: `crates/epigraph-ingest/src/workflow/schema.rs`
- Modify: `crates/epigraph-ingest/src/lib.rs`

- [ ] **Step 3.1.1: Create `workflow/mod.rs`**

Create `crates/epigraph-ingest/src/workflow/mod.rs`:

```rust
//! Workflow-specific extraction and ingest. Mirrors `document::` for hierarchical
//! workflows; uses the same `common::` infrastructure (Walker, IngestPlan,
//! ID derivation, ATOM_NAMESPACE for cross-source convergence).

pub mod builder;
pub mod schema;

pub use builder::build_ingest_plan;
pub use schema::*;
```

- [ ] **Step 3.1.2: Create `workflow/schema.rs`**

Create `crates/epigraph-ingest/src/workflow/schema.rs`:

```rust
//! Schema types for hierarchical workflow extraction. Isomorphic to
//! `document::schema::DocumentExtraction` but with workflow-native field
//! names (phases/steps/operations) and workflow-specific source metadata
//! (canonical_name, generation, parent_canonical_name).

use serde::{Deserialize, Serialize};

use crate::common::schema::{AuthorEntry, ClaimRelationship, ThesisDerivation};
use crate::document::schema::default_confidence;

/// Top-level extraction result from a workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExtraction {
    pub source: WorkflowSource,
    #[serde(default)]
    pub thesis: Option<String>,
    #[serde(default)]
    pub thesis_derivation: ThesisDerivation,
    #[serde(default)]
    pub phases: Vec<Phase>,
    #[serde(default)]
    pub relationships: Vec<ClaimRelationship>,
}

/// Metadata about the workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowSource {
    /// Required slug; drives the deterministic root ID.
    pub canonical_name: String,
    /// Free-text statement of the workflow's goal.
    pub goal: String,
    #[serde(default)]
    pub generation: u32,
    #[serde(default)]
    pub parent_canonical_name: Option<String>,
    #[serde(default)]
    pub authors: Vec<AuthorEntry>,
    #[serde(default)]
    pub expected_outcome: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// A phase within a workflow (analog of `document::schema::Section`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase {
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub steps: Vec<Step>,
}

/// A step within a phase (analog of `document::schema::Paragraph`).
/// Paper-specific fields (methodology, evidence_type, page, instruments_used,
/// reagents_involved, conditions) are intentionally absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub compound: String,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub generality: Vec<i32>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
}
```

- [ ] **Step 3.1.3: Register `workflow` module in `lib.rs`**

Edit `crates/epigraph-ingest/src/lib.rs` and add `pub mod workflow;` between `errors` and `schema`:

```rust
pub mod builder;
pub mod common;
pub mod document;
pub mod errors;
pub mod schema;
pub mod workflow;
```

- [ ] **Step 3.1.4: Confirm compile**

```bash
cargo check -p epigraph-ingest 2>&1 | tail -5
```

Expected: now `error[E0583]: file not found for module builder` *inside* `workflow/mod.rs` — the next task creates it.

### Task 3.2: Implement `workflow::builder::build_ingest_plan`

**Files:**
- Create: `crates/epigraph-ingest/src/workflow/builder.rs`

- [ ] **Step 3.2.1: Write the failing unit test**

Edit `crates/epigraph-ingest/src/lib.rs`'s `#[cfg(test)] mod tests` block and append, below the existing tests:

```rust
    // ── WorkflowExtraction ingest tests ──

    use crate::workflow::schema as wf_schema;

    fn make_workflow(json: &str) -> wf_schema::WorkflowExtraction {
        serde_json::from_str(json).expect("test workflow JSON should parse")
    }

    fn minimal_workflow_json() -> &'static str {
        r#"{
            "source": {
                "canonical_name": "deploy-canary",
                "goal": "Deploy a canary release safely.",
                "generation": 0,
                "authors": []
            },
            "thesis": "Workflow for canary deployment with monitoring.",
            "phases": [{
                "title": "Pre-flight",
                "summary": "Verify prerequisites.",
                "steps": [{
                    "compound": "Confirm CI passing.",
                    "operations": ["Run `gh pr checks`."],
                    "generality": [1],
                    "confidence": 0.9
                }]
            }],
            "relationships": []
        }"#
    }

    #[test]
    fn test_workflow_build_plan_counts() {
        let wf = make_workflow(minimal_workflow_json());
        let plan = crate::workflow::build_ingest_plan(&wf);

        // 1 thesis + 1 phase + 1 step + 1 operation
        assert_eq!(plan.claims.len(), 4);

        let level_counts: Vec<usize> = (0..=3)
            .map(|l| plan.claims.iter().filter(|c| c.level == l).count())
            .collect();
        assert_eq!(level_counts, vec![1, 1, 1, 1]);

        let decompose_count = plan
            .edges
            .iter()
            .filter(|e| e.relationship == "decomposes_to")
            .count();
        assert_eq!(decompose_count, 3, "thesis->phase, phase->step, step->op");
    }

    #[test]
    fn test_workflow_uses_phase_follows_not_section_follows() {
        let json = r#"{
            "source": {"canonical_name": "two-phase", "goal": "G", "authors": []},
            "thesis": "T",
            "phases": [
                {"title": "P1", "summary": "S1", "steps": []},
                {"title": "P2", "summary": "S2", "steps": []}
            ],
            "relationships": []
        }"#;
        let plan = crate::workflow::build_ingest_plan(&make_workflow(json));
        assert!(
            plan.edges.iter().any(|e| e.relationship == "phase_follows"),
            "must emit phase_follows for adjacent phases"
        );
        assert!(
            plan.edges.iter().all(|e| e.relationship != "section_follows"),
            "must NOT emit section_follows in workflow plans"
        );
    }

    #[test]
    fn test_workflow_step_follows_within_phase() {
        let json = r#"{
            "source": {"canonical_name": "two-step", "goal": "G", "authors": []},
            "thesis": "T",
            "phases": [{
                "title": "P1", "summary": "S1",
                "steps": [
                    {"compound": "Step1", "operations": ["op1"], "generality": [1], "confidence": 0.8},
                    {"compound": "Step2", "operations": ["op2"], "generality": [1], "confidence": 0.8}
                ]
            }],
            "relationships": []
        }"#;
        let plan = crate::workflow::build_ingest_plan(&make_workflow(json));
        let step_follows: Vec<_> = plan.edges.iter().filter(|e| e.relationship == "step_follows").collect();
        assert_eq!(step_follows.len(), 1, "exactly one step_follows between two adjacent steps");
        assert!(
            plan.edges.iter().all(|e| e.relationship != "continues_argument"),
            "must NOT emit continues_argument in workflow plans"
        );
    }

    #[test]
    fn test_workflow_atom_converges_with_document_atom() {
        let doc_json = r#"{
            "source": {"title": "P", "source_type": "Paper", "authors": []},
            "sections": [{
                "title": "Body", "summary": "S",
                "paragraphs": [{
                    "compound": "C",
                    "atoms": ["text-embedding-3-large produces 3072-dimensional vectors."],
                    "generality": [1], "confidence": 0.9
                }]
            }]
        }"#;
        let wf_json = r#"{
            "source": {"canonical_name": "embed-pipeline", "goal": "G", "authors": []},
            "thesis": "T",
            "phases": [{
                "title": "Embed", "summary": "Embed step",
                "steps": [{
                    "compound": "Run embedding.",
                    "operations": ["text-embedding-3-large produces 3072-dimensional vectors."],
                    "generality": [1], "confidence": 0.9
                }]
            }]
        }"#;
        let doc: crate::document::schema::DocumentExtraction =
            serde_json::from_str(doc_json).unwrap();
        let wf: wf_schema::WorkflowExtraction = serde_json::from_str(wf_json).unwrap();

        let doc_plan = crate::document::build_ingest_plan(&doc);
        let wf_plan = crate::workflow::build_ingest_plan(&wf);

        let doc_atom = doc_plan.claims.iter().find(|c| c.level == 3).expect("doc has atom");
        let wf_op = wf_plan.claims.iter().find(|c| c.level == 3).expect("wf has operation");

        assert_eq!(
            doc_atom.id, wf_op.id,
            "operation atom in workflow must converge with document atom of same text (ATOM_NAMESPACE shared)"
        );
    }

    #[test]
    fn test_workflow_compound_ids_scoped_by_canonical_name() {
        let json_a = r#"{
            "source": {"canonical_name": "wf-a", "goal": "G", "authors": []},
            "thesis": "Same thesis text",
            "phases": [],
            "relationships": []
        }"#;
        let json_b = r#"{
            "source": {"canonical_name": "wf-b", "goal": "G", "authors": []},
            "thesis": "Same thesis text",
            "phases": [],
            "relationships": []
        }"#;
        let plan_a = crate::workflow::build_ingest_plan(&make_workflow(json_a));
        let plan_b = crate::workflow::build_ingest_plan(&make_workflow(json_b));
        let thesis_a = plan_a.claims.iter().find(|c| c.level == 0).unwrap();
        let thesis_b = plan_b.claims.iter().find(|c| c.level == 0).unwrap();
        assert_ne!(
            thesis_a.id, thesis_b.id,
            "compound nodes must NOT converge across workflows with different canonical_name"
        );
    }
```

- [ ] **Step 3.2.2: Run the tests to confirm they fail**

```bash
cargo test -p epigraph-ingest test_workflow_ 2>&1 | tail -10
```

Expected: every `test_workflow_*` fails with `unresolved import` or "no function named build_ingest_plan in workflow" — the module file doesn't exist yet.

- [ ] **Step 3.2.3: Implement `workflow/builder.rs`**

Create `crates/epigraph-ingest/src/workflow/builder.rs`:

```rust
//! Workflow hierarchy walker. Reads a `WorkflowExtraction` and produces an
//! `IngestPlan` of claims + edges + path index. Compound nodes are scoped by
//! `canonical_name`; operation atoms use the global `ATOM_NAMESPACE` (shared
//! with documents) for cross-source convergence.

use std::collections::HashMap;

use uuid::Uuid;

use crate::common::ids::{atom_id, compound_claim_id, content_hash, workflow_root_id};
use crate::common::plan::{IngestPlan, PlannedClaim, PlannedEdge};
use crate::common::schema::ThesisDerivation;
use crate::document::builder::normalize_claim_path;
use crate::workflow::schema::WorkflowExtraction;

const fn thesis_derivation_str(td: &ThesisDerivation) -> &'static str {
    match td {
        ThesisDerivation::TopDown => "TopDown",
        ThesisDerivation::BottomUp => "BottomUp",
    }
}

fn decomposes_edge(source_id: Uuid, target_id: Uuid) -> PlannedEdge {
    PlannedEdge {
        source_id,
        source_type: "claim".to_string(),
        target_id,
        target_type: "claim".to_string(),
        relationship: "decomposes_to".to_string(),
        properties: serde_json::json!({}),
    }
}

/// Walk a `WorkflowExtraction` tree and produce a flat list of operations.
///
/// The result includes a `workflow` source-node id (deterministic from
/// `canonical_name + generation`) but does NOT include the `workflow —executes→`
/// edges — those are emitted by `epigraph-mcp::tools::workflow_ingest::do_ingest_workflow`
/// once the workflow row is created. The plan returns claims + intra-claim
/// edges + path index, identical in shape to the document plan.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build_ingest_plan(extraction: &WorkflowExtraction) -> IngestPlan {
    let mut claims = Vec::new();
    let mut edges = Vec::new();
    let mut path_index = HashMap::new();

    let canonical_name = &extraction.source.canonical_name;
    let source_type = "workflow";

    // Step 1: Thesis (level 0)
    let thesis_id = if let Some(ref thesis_text) = extraction.thesis {
        let hash = content_hash(thesis_text);
        let id = compound_claim_id(&hash, canonical_name);
        path_index.insert("thesis".to_string(), id);

        claims.push(PlannedClaim {
            id,
            content: thesis_text.clone(),
            level: 0,
            properties: serde_json::json!({
                "level": 0,
                "source_type": source_type,
                "thesis_derivation": thesis_derivation_str(&extraction.thesis_derivation),
                "kind": "workflow_thesis",
            }),
            content_hash: hash,
            confidence: 1.0,
            methodology: None,
            evidence_type: None,
            supporting_text: None,
            enrichment: serde_json::json!({}),
        });
        Some(id)
    } else {
        None
    };

    let mut phase_ids: Vec<Uuid> = Vec::new();

    for (pi, phase) in extraction.phases.iter().enumerate() {
        let phase_path = format!("phases[{pi}]");
        let phase_hash = content_hash(&phase.summary);
        let phase_id = compound_claim_id(&phase_hash, canonical_name);
        phase_ids.push(phase_id);
        path_index.insert(phase_path.clone(), phase_id);

        claims.push(PlannedClaim {
            id: phase_id,
            content: phase.summary.clone(),
            level: 1,
            properties: serde_json::json!({
                "level": 1,
                "source_type": source_type,
                "phase": phase.title,
                "kind": "workflow_step",
            }),
            content_hash: phase_hash,
            confidence: 1.0,
            methodology: None,
            evidence_type: None,
            supporting_text: None,
            enrichment: serde_json::json!({}),
        });

        if let Some(tid) = thesis_id {
            edges.push(decomposes_edge(tid, phase_id));
        }

        let mut step_ids: Vec<Uuid> = Vec::new();

        for (si, step) in phase.steps.iter().enumerate() {
            let step_path = format!("{phase_path}.steps[{si}]");
            let step_hash = content_hash(&step.compound);
            let step_id = compound_claim_id(&step_hash, canonical_name);
            step_ids.push(step_id);
            path_index.insert(step_path.clone(), step_id);

            claims.push(PlannedClaim {
                id: step_id,
                content: step.compound.clone(),
                level: 2,
                properties: serde_json::json!({
                    "level": 2,
                    "source_type": source_type,
                    "phase": phase.title,
                    "rationale": step.rationale,
                    "kind": "workflow_step",
                }),
                content_hash: step_hash,
                confidence: step.confidence,
                methodology: None,
                evidence_type: None,
                supporting_text: Some(step.rationale.clone()),
                enrichment: serde_json::json!({}),
            });

            edges.push(decomposes_edge(phase_id, step_id));

            for (oi, op_text) in step.operations.iter().enumerate() {
                let op_hash = content_hash(op_text);
                // ATOM_NAMESPACE is the SAME namespace documents use → cross-source convergence.
                let oid = atom_id(&op_hash);
                let op_path = format!("{step_path}.operations[{oi}]");
                path_index.insert(op_path, oid);

                let generality = step.generality.get(oi).copied().filter(|&g| g >= 0);

                let mut props = serde_json::json!({
                    "level": 3,
                    "source_type": source_type,
                    "phase": phase.title,
                    "kind": "workflow_atom",
                });
                if let Some(g) = generality {
                    props["generality"] = serde_json::json!(g);
                }

                claims.push(PlannedClaim {
                    id: oid,
                    content: op_text.clone(),
                    level: 3,
                    properties: props,
                    content_hash: op_hash,
                    confidence: step.confidence,
                    methodology: None,
                    evidence_type: None,
                    supporting_text: Some(step.rationale.clone()),
                    enrichment: serde_json::json!({}),
                });

                edges.push(decomposes_edge(step_id, oid));
            }
        }

        // step_follows within the phase
        for w in step_ids.windows(2) {
            edges.push(PlannedEdge {
                source_id: w[0],
                source_type: "claim".to_string(),
                target_id: w[1],
                target_type: "claim".to_string(),
                relationship: "step_follows".to_string(),
                properties: serde_json::json!({}),
            });
        }
    }

    // phase_follows between phases
    for w in phase_ids.windows(2) {
        edges.push(PlannedEdge {
            source_id: w[0],
            source_type: "claim".to_string(),
            target_id: w[1],
            target_type: "claim".to_string(),
            relationship: "phase_follows".to_string(),
            properties: serde_json::json!({}),
        });
    }

    // Cross-references from extraction.relationships
    for rel in &extraction.relationships {
        let src_path = normalize_claim_path(&rel.source_path);
        let tgt_path = normalize_claim_path(&rel.target_path);
        let source_id = match path_index.get(&src_path) {
            Some(id) => *id,
            None => continue,
        };
        let target_id = match path_index.get(&tgt_path) {
            Some(id) => *id,
            None => continue,
        };
        let mut props = serde_json::json!({});
        if let Some(ref rationale) = rel.rationale {
            props["rationale"] = serde_json::json!(rationale);
        }
        if let Some(strength) = rel.strength {
            props["strength"] = serde_json::json!(strength);
        }
        edges.push(PlannedEdge {
            source_id,
            source_type: "claim".to_string(),
            target_id,
            target_type: "claim".to_string(),
            relationship: rel.relationship.clone(),
            properties: props,
        });
    }

    // Author → claim edges (same as documents; resolved by MCP layer to real agent UUIDs)
    for (author_idx, _author) in extraction.source.authors.iter().enumerate() {
        for planned_claim in &claims {
            edges.push(PlannedEdge {
                source_id: Uuid::nil(),
                source_type: "author_placeholder".to_string(),
                target_id: planned_claim.id,
                target_type: "claim".to_string(),
                relationship: "asserts".to_string(),
                properties: serde_json::json!({
                    "author_index": author_idx,
                    "role": "author",
                    "source": "workflow_attribution",
                }),
            });
        }
    }

    IngestPlan {
        claims,
        edges,
        path_index,
    }
}

/// Compute the deterministic `workflows.id` for an extraction's source.
#[must_use]
pub fn root_workflow_id(extraction: &WorkflowExtraction) -> Uuid {
    workflow_root_id(
        &extraction.source.canonical_name,
        extraction.source.generation,
    )
}

impl crate::common::walker::Walker for WorkflowExtraction {
    fn build_ingest_plan(&self) -> IngestPlan {
        build_ingest_plan(self)
    }
}
```

- [ ] **Step 3.2.4: Run the tests to confirm they pass**

```bash
cargo test -p epigraph-ingest test_workflow_ 2>&1 | tail -15
```

Expected: all five new `test_workflow_*` tests pass. If `test_workflow_atom_converges_with_document_atom` fails specifically, double-check that `workflow::builder::build_ingest_plan` calls `atom_id(&op_hash)` from `common::ids` and not a local namespace.

- [ ] **Step 3.2.5: Run the full ingest test suite to confirm no regression**

```bash
cargo test -p epigraph-ingest 2>&1 | tail -5
```

Expected: every test passes including the original document-side ones.

- [ ] **Step 3.2.6: Commit**

```bash
git add crates/epigraph-ingest/
git commit -m "feat(ingest): add WorkflowExtraction schema + walker (#34)"
```

---

## Phase 4 — `ingest_workflow` MCP tool + HTTP endpoint

**Why fourth:** Phase 3 produces a plan; this phase persists it. The persistence layer adds the `workflows` row, runs the existing claim/edge writers from `do_ingest_document`, and emits `workflow —executes→ claim` edges for every claim in the plan.

### Task 4.1: Add `WorkflowRepository::insert_root` to `epigraph-db`

**Files:**
- Modify: `crates/epigraph-db/src/repos/workflow.rs` (add method to `impl WorkflowRepository`)
- Test: same file

- [ ] **Step 4.1.1: Write the failing repo test**

Append to `crates/epigraph-db/src/repos/workflow.rs` test module (find or create `#[cfg(test)] mod tests`). If no test module exists in this file, add one at the bottom following the pattern in `crates/epigraph-db/src/repos/claim.rs::tests`:

```rust
    #[sqlx::test]
    async fn insert_root_creates_workflows_row(pool: sqlx::PgPool) {
        let id = uuid::Uuid::new_v4();
        WorkflowRepository::insert_root(
            &pool,
            id,
            "deploy-canary",
            0,
            "Deploy a canary release safely.",
            None,
            serde_json::json!({"tags": ["deploy"]}),
        )
        .await
        .unwrap();

        let row: (String, i32, String, serde_json::Value) = sqlx::query_as(
            "SELECT canonical_name, generation, goal, metadata FROM workflows WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "deploy-canary");
        assert_eq!(row.1, 0);
        assert_eq!(row.2, "Deploy a canary release safely.");
        assert_eq!(row.3["tags"][0], "deploy");
    }
```

- [ ] **Step 4.1.2: Run the test to confirm it fails**

```bash
cargo test -p epigraph-db --features db insert_root_creates_workflows_row 2>&1 | tail -10
```

Expected: FAIL — `no function or associated item named insert_root`.

- [ ] **Step 4.1.3: Implement `WorkflowRepository::insert_root`**

In `crates/epigraph-db/src/repos/workflow.rs`, add this method to `impl WorkflowRepository` (place it near the top of the impl block, before `find_by_embedding`):

```rust
    /// Insert a row into the new `workflows` table (added in migration 019).
    /// Used by `epigraph-mcp::tools::workflow_ingest::do_ingest_workflow`.
    /// Idempotent on `(canonical_name, generation)` UNIQUE — repeated inserts
    /// of the same identity are silently ignored.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails for reasons other
    /// than a duplicate-key conflict on the UNIQUE constraint.
    pub async fn insert_root(
        pool: &PgPool,
        id: Uuid,
        canonical_name: &str,
        generation: i32,
        goal: &str,
        parent_id: Option<Uuid>,
        metadata: serde_json::Value,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO workflows (id, canonical_name, generation, goal, parent_id, metadata) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (canonical_name, generation) DO NOTHING",
        )
        .bind(id)
        .bind(canonical_name)
        .bind(generation)
        .bind(goal)
        .bind(parent_id)
        .bind(metadata)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Look up a workflow root by `(canonical_name, generation)`.
    pub async fn find_root_by_canonical(
        pool: &PgPool,
        canonical_name: &str,
        generation: i32,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM workflows WHERE canonical_name = $1 AND generation = $2",
        )
        .bind(canonical_name)
        .bind(generation)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|(id,)| id))
    }
```

- [ ] **Step 4.1.4: Run test to confirm pass**

```bash
cargo test -p epigraph-db --features db insert_root_creates_workflows_row 2>&1 | tail -5
```

Expected: PASS.

- [ ] **Step 4.1.5: Commit**

```bash
git add crates/epigraph-db/src/repos/workflow.rs
git commit -m "feat(db): WorkflowRepository::insert_root + find_root_by_canonical (#34)"
```

### Task 4.1b: Confirm or add `ClaimRepository::create_with_id_if_absent`

**Files:**
- Modify (or confirm-only): `crates/epigraph-db/src/repos/claim.rs`

`do_ingest_workflow` (next task) needs an idempotent insert keyed on the deterministic claim ID — `INSERT ... ON CONFLICT (id) DO NOTHING RETURNING (xmax = 0)` semantics. Verify whether the repo already exposes this, and if not, add it.

- [ ] **Step 4.1b.1: Search for an existing equivalent**

```bash
grep -nE 'create_with_id_if_absent|create.*absent|ON CONFLICT.*DO NOTHING' /home/jeremy/epigraph-wt-issue-34/crates/epigraph-db/src/repos/claim.rs | head -10
```

If a method already exists with the contract `(pool, id, content, content_hash, agent_id, truth, labels) -> Result<bool>` returning whether the row was newly inserted, **skip to Task 4.2** and adapt the call sites in Task 4.2's code to the actual name.

If the existing `create` method does not return a "was new" flag, add the new method as below.

- [ ] **Step 4.1b.2: Add the method**

In `crates/epigraph-db/src/repos/claim.rs`, in `impl ClaimRepository`:

```rust
    /// Insert a claim with a caller-supplied id. Returns `true` if the row
    /// was newly inserted, `false` if the id already existed (silently
    /// skipped via `ON CONFLICT (id) DO NOTHING`). Used by ingest paths that
    /// generate deterministic UUIDs and rely on idempotent re-runs.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` for non-conflict failures.
    #[instrument(skip(pool, content, content_hash, labels))]
    pub async fn create_with_id_if_absent(
        pool: &PgPool,
        id: Uuid,
        content: &str,
        content_hash: &[u8; 32],
        agent_id: Uuid,
        truth: TruthValue,
        labels: &[String],
    ) -> Result<bool, DbError> {
        let row: Option<(bool,)> = sqlx::query_as(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, labels) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (id) DO NOTHING \
             RETURNING (xmax = 0) AS was_inserted",
        )
        .bind(id)
        .bind(content)
        .bind(content_hash.as_slice())
        .bind(agent_id)
        .bind(truth.value())
        .bind(labels)
        .fetch_optional(pool)
        .await?;
        // RETURNING is empty when the conflict path is taken, so None == not new.
        Ok(row.map(|(b,)| b).unwrap_or(false))
    }
```

- [ ] **Step 4.1b.3: Test it**

Append to the `claim.rs` test module:

```rust
    #[sqlx::test]
    async fn create_with_id_if_absent_is_idempotent(pool: sqlx::PgPool) {
        let agent = epigraph_test_support::seed_agent(&pool).await;
        let id = uuid::Uuid::new_v4();
        let hash = blake3::hash(b"x");
        let was_new1 = ClaimRepository::create_with_id_if_absent(
            &pool,
            id,
            "x",
            hash.as_bytes(),
            agent.id.into(),
            TruthValue::clamped(0.5),
            &["test".to_string()],
        )
        .await
        .unwrap();
        let was_new2 = ClaimRepository::create_with_id_if_absent(
            &pool,
            id,
            "x",
            hash.as_bytes(),
            agent.id.into(),
            TruthValue::clamped(0.5),
            &["test".to_string()],
        )
        .await
        .unwrap();
        assert!(was_new1);
        assert!(!was_new2);
    }
```

If `epigraph_test_support::seed_agent` does not exist, copy the agent-insertion pattern from any existing test in `claim.rs`.

- [ ] **Step 4.1b.4: Run + commit**

```bash
cargo test -p epigraph-db --features db create_with_id_if_absent_is_idempotent 2>&1 | tail -5
git add crates/epigraph-db/src/repos/claim.rs
git commit -m "feat(db): ClaimRepository::create_with_id_if_absent for ingest idempotence (#34)"
```

### Task 4.2: Add `do_ingest_workflow` in `epigraph-mcp`

**Files:**
- Create: `crates/epigraph-mcp/src/tools/workflow_ingest.rs`
- Modify: `crates/epigraph-mcp/src/tools/mod.rs` (register module)

- [ ] **Step 4.2.1: Write the failing integration test**

Add a test to `crates/epigraph-mcp/src/tools/workflow_ingest.rs` (created in next step). For now, plan to write this test:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::spawn_test_server;
    use epigraph_ingest::workflow::WorkflowExtraction;

    #[sqlx::test]
    async fn ingest_workflow_creates_root_and_executes_edges(pool: sqlx::PgPool) {
        let server = spawn_test_server(pool.clone()).await;
        let extraction: WorkflowExtraction = serde_json::from_str(
            r#"{
                "source": {
                    "canonical_name": "ingest-test",
                    "goal": "Test ingest_workflow round-trip.",
                    "generation": 0,
                    "authors": []
                },
                "thesis": "Test thesis.",
                "phases": [{
                    "title": "P1", "summary": "S1",
                    "steps": [{
                        "compound": "Step1",
                        "operations": ["op1"],
                        "generality": [1], "confidence": 0.8
                    }]
                }],
                "relationships": []
            }"#,
        )
        .unwrap();

        let result = do_ingest_workflow(&server, &extraction).await.unwrap();

        // workflows row exists
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = $1")
                .bind("ingest-test")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1);

        // claims persisted
        let claim_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM claims WHERE 'workflow_step' = ANY(labels) OR 'workflow_thesis' = ANY(labels)")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(claim_count >= 4); // thesis + phase + step + op

        // executes edges from workflow → claim, one per claim
        let exec_edges: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE source_id = $1 AND source_type = 'workflow' AND relationship = 'executes'",
        )
        .bind(result.workflow_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(exec_edges >= 4);
    }

    #[sqlx::test]
    async fn ingest_workflow_idempotent(pool: sqlx::PgPool) {
        let server = spawn_test_server(pool.clone()).await;
        let extraction: WorkflowExtraction = serde_json::from_str(
            r#"{
                "source": {"canonical_name": "idempo", "goal": "G", "generation": 0, "authors": []},
                "thesis": "T",
                "phases": [{"title": "P", "summary": "S", "steps": [{"compound": "C", "operations": ["o"], "generality": [1], "confidence": 0.8}]}],
                "relationships": []
            }"#,
        )
        .unwrap();

        let r1 = do_ingest_workflow(&server, &extraction).await.unwrap();
        let r2 = do_ingest_workflow(&server, &extraction).await.unwrap();
        assert_eq!(r1.workflow_id, r2.workflow_id, "second ingest must return same root");

        let workflow_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = 'idempo'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(workflow_count, 1);

        // edges count must not double
        let exec_edges: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'executes'",
        )
        .bind(r1.workflow_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let one_run_edge_count = 4_i64; // thesis + phase + step + op
        assert_eq!(exec_edges, one_run_edge_count);
    }

    #[sqlx::test]
    async fn ingest_workflow_atom_converges_with_document_atom(pool: sqlx::PgPool) {
        // Ingest a doc and a workflow whose atomic content is identical.
        let server = spawn_test_server(pool.clone()).await;

        let doc_extraction: epigraph_ingest::document::DocumentExtraction = serde_json::from_str(
            r#"{
                "source": {"title": "Test Paper", "source_type": "Paper", "authors": []},
                "thesis": "Doc thesis",
                "sections": [{
                    "title": "Body", "summary": "Body summary",
                    "paragraphs": [{
                        "compound": "P1",
                        "atoms": ["text-embedding-3-large produces 3072-dimensional vectors."],
                        "generality": [1], "confidence": 0.9
                    }]
                }],
                "relationships": []
            }"#,
        )
        .unwrap();
        crate::tools::ingestion::do_ingest_document(&server, &doc_extraction)
            .await
            .unwrap();

        let wf_extraction: WorkflowExtraction = serde_json::from_str(
            r#"{
                "source": {"canonical_name": "embed-pipeline", "goal": "G", "generation": 0, "authors": []},
                "thesis": "Workflow thesis",
                "phases": [{
                    "title": "Embed", "summary": "Embed step",
                    "steps": [{
                        "compound": "Run embedding",
                        "operations": ["text-embedding-3-large produces 3072-dimensional vectors."],
                        "generality": [1], "confidence": 0.9
                    }]
                }]
            }"#,
        )
        .unwrap();
        let wf_result = do_ingest_workflow(&server, &wf_extraction).await.unwrap();

        // The atom UUID is deterministic from ATOM_NAMESPACE + blake3(text). Compute it.
        let atom_text = "text-embedding-3-large produces 3072-dimensional vectors.";
        let hash = blake3::hash(atom_text.as_bytes());
        let expected_atom_id =
            uuid::Uuid::new_v5(&epigraph_ingest::common::ids::ATOM_NAMESPACE, hash.as_bytes());

        // Exactly one row in claims with this id
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
            .bind(expected_atom_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "atom must converge to one claim node");

        // Workflow has executes edge to the atom
        let wf_edge: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2 AND relationship = 'executes'",
        )
        .bind(wf_result.workflow_id)
        .bind(expected_atom_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(wf_edge, 1);

        // Doc author_placeholder asserts edge was resolved by do_ingest_document; check via either author edge or paper-asserts-claim. The exact edge depends on ingestion's author-resolution path; check that *some* document-side edge points at the atom.
        let doc_edge_to_atom: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE target_id = $1 AND relationship IN ('asserts', 'authored', 'AUTHORED')",
        )
        .bind(expected_atom_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(doc_edge_to_atom >= 1, "document-side attribution edge should exist");
    }
}
```

- [ ] **Step 4.2.2: Implement `do_ingest_workflow`**

Create `crates/epigraph-mcp/src/tools/workflow_ingest.rs`. The structure mirrors `do_ingest_document` (in `crates/epigraph-mcp/src/tools/ingestion.rs`); the differences are:
1. Insert a row into `workflows` first (using `WorkflowRepository::insert_root`).
2. Persist all claims from the `IngestPlan` (using existing claim/edge writers).
3. Emit a `workflow —executes→ claim` edge for every claim in the plan.
4. Emit a `workflow —variant_of→ workflow` edge if `parent_canonical_name` resolves.

```rust
//! `ingest_workflow` MCP tool and HTTP handler shared logic.
//!
//! Flow (mirrors `do_ingest_document` for the claim/edge persistence path,
//! adds workflows-table writes + executes edges):
//!
//! 1. Insert (or look up existing) `workflows` row by `(canonical_name, generation)`.
//! 2. If parent_canonical_name is set, look up parent root and emit `variant_of` edge.
//! 3. Run `epigraph_ingest::workflow::build_ingest_plan` to produce claims + edges.
//! 4. Persist each claim via `ClaimRepository::create` (ON CONFLICT (id) DO NOTHING),
//!    then `set_properties` to attach hierarchy metadata (level, phase, kind).
//! 5. Persist each edge via `EdgeRepository::create_if_not_exists`.
//! 6. Emit one `workflow —executes→ claim` edge per claim in the plan.
//! 7. Resolve author_placeholder edges to real agent UUIDs (same as documents).

use std::sync::Arc;

use epigraph_core::{Agent, ClaimId, TruthValue};
use epigraph_db::{
    AgentRepository, ClaimRepository, EdgeRepository, EventRepository, WorkflowRepository,
};
use epigraph_ingest::workflow::{build_ingest_plan, root_workflow_id, WorkflowExtraction};
use uuid::Uuid;

use crate::errors::McpError;
use crate::server::McpServer;

#[derive(Debug)]
pub struct IngestWorkflowResult {
    pub workflow_id: Uuid,
    pub claims_created: usize,
    pub edges_created: usize,
}

pub async fn do_ingest_workflow(
    server: &Arc<McpServer>,
    extraction: &WorkflowExtraction,
) -> Result<IngestWorkflowResult, McpError> {
    let pool = server.db_pool();

    let workflow_id = root_workflow_id(extraction);
    let canonical_name = &extraction.source.canonical_name;
    let generation = extraction.source.generation as i32;

    let metadata = serde_json::json!({
        "tags": extraction.source.tags,
        "expected_outcome": extraction.source.expected_outcome,
        "use_count": 0,
        "success_count": 0,
        "failure_count": 0,
        "avg_variance": 0.0,
        "raw_metadata": extraction.source.metadata,
    });

    // Step 1: insert (or no-op on conflict) the workflows row
    let parent_id = if let Some(ref parent_canonical) = extraction.source.parent_canonical_name {
        WorkflowRepository::find_root_by_canonical(pool, parent_canonical, 0)
            .await
            .map_err(|e| McpError::Internal(format!("parent lookup failed: {e}")))?
    } else {
        None
    };

    WorkflowRepository::insert_root(
        pool,
        workflow_id,
        canonical_name,
        generation,
        &extraction.source.goal,
        parent_id,
        metadata,
    )
    .await
    .map_err(|e| McpError::Internal(format!("workflows insert failed: {e}")))?;

    // Step 2: variant_of edge if parent exists
    if let Some(pid) = parent_id {
        let _ = EdgeRepository::create_if_not_exists(
            pool,
            workflow_id,
            "workflow",
            pid,
            "workflow",
            "variant_of",
            None,
            None,
            None,
        )
        .await;
    }

    // Step 3: build the plan
    let plan = build_ingest_plan(extraction);

    // Step 4: ensure system agent exists for unauthored claims
    let sys_agent_id = get_or_create_system_agent(pool).await?;

    let mut claims_created = 0_usize;
    for planned in &plan.claims {
        let truth = TruthValue::clamped(0.5);
        let labels = labels_for_level(planned.level);
        // ON CONFLICT (id) DO NOTHING happens inside ClaimRepository::create_with_id
        let was_new = ClaimRepository::create_with_id_if_absent(
            pool,
            planned.id,
            &planned.content,
            &planned.content_hash,
            sys_agent_id,
            truth,
            &labels,
        )
        .await
        .map_err(|e| McpError::Internal(format!("claim insert failed: {e}")))?;
        if was_new {
            claims_created += 1;
        }
        // Always (re)set properties for this claim — the plan is the source of truth.
        ClaimRepository::set_properties(
            pool,
            ClaimId::from_uuid(planned.id),
            planned.properties.clone(),
        )
        .await
        .map_err(|e| McpError::Internal(format!("claim set_properties failed: {e}")))?;
    }

    // Step 5: persist intra-claim edges (decomposes_to, phase_follows, step_follows, cross-rels)
    let mut edges_created = 0_usize;
    for planned in &plan.edges {
        if planned.source_type == "author_placeholder" {
            // Skip — resolved below after author-table inserts (mirrors document path).
            continue;
        }
        let was_new = EdgeRepository::create_if_not_exists(
            pool,
            planned.source_id,
            &planned.source_type,
            planned.target_id,
            &planned.target_type,
            &planned.relationship,
            Some(&planned.properties),
            None,
            None,
        )
        .await
        .map_err(|e| McpError::Internal(format!("edge insert failed: {e}")))?;
        if was_new {
            edges_created += 1;
        }
    }

    // Step 6: workflow —executes→ claim, one per claim
    for planned in &plan.claims {
        let was_new = EdgeRepository::create_if_not_exists(
            pool,
            workflow_id,
            "workflow",
            planned.id,
            "claim",
            "executes",
            None,
            None,
            None,
        )
        .await
        .map_err(|e| McpError::Internal(format!("executes edge insert failed: {e}")))?;
        if was_new {
            edges_created += 1;
        }
    }

    // Step 7: resolve author edges (same path as document — see do_ingest_document)
    resolve_author_edges(pool, &plan.edges, &extraction.source.authors).await?;

    // Step 8: emit event
    let _ = EventRepository::insert(
        pool,
        "workflow.ingested",
        None,
        &serde_json::json!({
            "workflow_id": workflow_id,
            "canonical_name": canonical_name,
            "generation": generation,
            "claims_created": claims_created,
            "edges_created": edges_created,
        }),
    )
    .await;

    Ok(IngestWorkflowResult {
        workflow_id,
        claims_created,
        edges_created,
    })
}

fn labels_for_level(level: u8) -> Vec<String> {
    match level {
        0 => vec!["workflow_thesis".to_string()],
        1 | 2 => vec!["workflow_step".to_string()],
        3 => vec!["workflow_step".to_string(), "workflow_atom".to_string()],
        _ => vec![],
    }
}

async fn get_or_create_system_agent(pool: &sqlx::PgPool) -> Result<Uuid, McpError> {
    let pub_key = [0u8; 32];
    if let Some(a) = AgentRepository::get_by_public_key(pool, &pub_key)
        .await
        .map_err(|e| McpError::Internal(e.to_string()))?
    {
        Ok(a.id.as_uuid())
    } else {
        let agent = Agent::new(pub_key, Some("workflow-ingest-system".to_string()));
        let created = AgentRepository::create(pool, &agent)
            .await
            .map_err(|e| McpError::Internal(e.to_string()))?;
        Ok(created.id.as_uuid())
    }
}

async fn resolve_author_edges(
    pool: &sqlx::PgPool,
    plan_edges: &[epigraph_ingest::common::plan::PlannedEdge],
    authors: &[epigraph_ingest::common::schema::AuthorEntry],
) -> Result<(), McpError> {
    if authors.is_empty() {
        return Ok(());
    }
    // For each author, ensure an agent row exists keyed by name.
    let mut author_agent_ids: Vec<Uuid> = Vec::with_capacity(authors.len());
    for author in authors {
        let key = format!("workflow-author:{}", author.name);
        let pub_key = blake3::hash(key.as_bytes());
        let pub_key_arr: [u8; 32] = *pub_key.as_bytes();
        let agent_id = if let Some(a) = AgentRepository::get_by_public_key(pool, &pub_key_arr)
            .await
            .map_err(|e| McpError::Internal(e.to_string()))?
        {
            a.id.as_uuid()
        } else {
            let agent = Agent::new(pub_key_arr, Some(author.name.clone()));
            let created = AgentRepository::create(pool, &agent)
                .await
                .map_err(|e| McpError::Internal(e.to_string()))?;
            created.id.as_uuid()
        };
        author_agent_ids.push(agent_id);
    }

    // Replace each `author_placeholder` edge with `agent --asserts--> claim`.
    for planned in plan_edges {
        if planned.source_type != "author_placeholder" {
            continue;
        }
        let author_idx = planned
            .properties
            .get("author_index")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let Some(&agent_id) = author_agent_ids.get(author_idx) else {
            continue;
        };
        let _ = EdgeRepository::create_if_not_exists(
            pool,
            agent_id,
            "agent",
            planned.target_id,
            "claim",
            "asserts",
            Some(&planned.properties),
            None,
            None,
        )
        .await;
    }
    Ok(())
}
```

> **Note:** This step assumes `ClaimRepository::create_with_id_if_absent` exists and returns `Result<bool, _>` indicating whether a new row was created. If the actual repo does not have this signature, find the closest equivalent (likely `create` returning the row, with internal `ON CONFLICT DO NOTHING`) and adapt — the key invariant is that re-runs are idempotent. If neither exists, add a thin `create_with_id_if_absent` to `claim.rs` matching the signature used here, doing `INSERT ... ON CONFLICT (id) DO NOTHING RETURNING (xmax = 0) AS was_inserted` and returning the boolean.

- [ ] **Step 4.2.3: Register module in `tools/mod.rs`**

Edit `crates/epigraph-mcp/src/tools/mod.rs` and add `pub mod workflow_ingest;` next to the existing `pub mod ingestion;` and `pub mod workflows;` declarations.

- [ ] **Step 4.2.4: Run the new tests to confirm they pass**

```bash
cargo test -p epigraph-mcp --features db ingest_workflow_ 2>&1 | tail -20
```

Expected: all three new tests pass.

- [ ] **Step 4.2.5: Commit**

```bash
git add crates/epigraph-mcp/src/tools/
git commit -m "feat(mcp): ingest_workflow tool — workflows-row + executes edges (#34)"
```

### Task 4.3: HTTP endpoint `POST /api/v1/workflows/ingest`

**Files:**
- Modify: `crates/epigraph-api/src/routes/workflows.rs` (add handler)
- Modify: `crates/epigraph-api/src/routes/mod.rs` (register route)

- [ ] **Step 4.3.1: Write the failing handler test**

Append to `crates/epigraph-api/src/routes/workflows.rs` test module:

```rust
    #[tokio::test]
    async fn ingest_workflow_http_returns_workflow_id() {
        let state = test_state().await;
        let body = serde_json::json!({
            "source": {
                "canonical_name": "http-ingest-test",
                "goal": "G",
                "generation": 0,
                "authors": []
            },
            "thesis": "T",
            "phases": [{
                "title": "P", "summary": "S",
                "steps": [{"compound": "C", "operations": ["o"], "generality": [1], "confidence": 0.8}]
            }],
            "relationships": []
        });

        let router = workflow_router(state.clone());
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/workflows/ingest")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = parse_body(response).await;
        assert!(body["workflow_id"].is_string());
        assert!(body["claims_created"].as_u64().unwrap_or(0) >= 4);
    }
```

- [ ] **Step 4.3.2: Implement the HTTP handler**

In `crates/epigraph-api/src/routes/workflows.rs`, add this handler after `store_workflow` (around line 205):

```rust
/// POST /api/v1/workflows/ingest - Ingest a hierarchical workflow.
///
/// Mirrors `ingest_document` for workflows. Persists the `workflows` row,
/// the constituent claims (thesis/phase/step/operation), and the
/// `workflow —executes→ claim` edges.
#[cfg(feature = "db")]
pub async fn ingest_workflow(
    State(state): State<AppState>,
    Json(extraction): Json<epigraph_ingest::workflow::WorkflowExtraction>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = epigraph_mcp::tools::workflow_ingest::do_ingest_workflow_via_pool(
        &state.db_pool,
        state.embedding_service(),
        &extraction,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("ingest_workflow failed: {e}"),
    })?;

    Ok(Json(serde_json::json!({
        "workflow_id": result.workflow_id,
        "claims_created": result.claims_created,
        "edges_created": result.edges_created,
    })))
}
```

> The handler calls a `do_ingest_workflow_via_pool` variant that takes a `&PgPool` directly (the `&Arc<McpServer>` form is used in the MCP context). Add this thin wrapper in `crates/epigraph-mcp/src/tools/workflow_ingest.rs`:
>
> ```rust
> /// HTTP-friendly variant: same flow as `do_ingest_workflow` but takes a `&PgPool`
> /// directly instead of an `&Arc<McpServer>`. Used by the
> /// `POST /api/v1/workflows/ingest` route.
> pub async fn do_ingest_workflow_via_pool(
>     pool: &sqlx::PgPool,
>     _embedder: Option<std::sync::Arc<dyn epigraph_embeddings::EmbeddingService>>,
>     extraction: &WorkflowExtraction,
> ) -> Result<IngestWorkflowResult, McpError> {
>     // Delegate to the shared core: refactor `do_ingest_workflow` to use a `&PgPool`
>     // internally, with a thin `do_ingest_workflow(server, ...)` wrapper that
>     // calls into the pool variant.
>     ...
> }
> ```
>
> Implementation detail: the cleanest refactor is to extract the body of `do_ingest_workflow` into a `_pool_inner(pool, embedder, extraction)` and have both `do_ingest_workflow(server, ...)` and `do_ingest_workflow_via_pool(pool, ...)` call it.

- [ ] **Step 4.3.3: Register the route**

In `crates/epigraph-api/src/routes/mod.rs`, find the workflow route block (search for `"/api/v1/workflows"` to locate it) and add:

```rust
        .route("/api/v1/workflows/ingest", post(workflows::ingest_workflow))
```

before the `:id`-suffixed routes so axum's path matcher prefers the more specific path.

- [ ] **Step 4.3.4: Run the test**

```bash
cargo test -p epigraph-api --features db ingest_workflow_http 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 4.3.5: Commit**

```bash
git add crates/epigraph-api/ crates/epigraph-mcp/
git commit -m "feat(api): POST /api/v1/workflows/ingest (#34)"
```

---

## Phase 5 — `behavioral_executions` ALTER + `report_hierarchical_outcome`

**Why fifth:** Phase 4 ingests workflows but doesn't yet record executions for them. The existing `report_outcome` looks up flat-JSON workflows by `claims WHERE 'workflow' = ANY(labels)` and 404s on hierarchical roots — they live in `workflows`, not `claims`. Add `step_claim_id` to `behavioral_executions` and a sibling endpoint that resolves `:id` against `workflows`.

### Task 5.1: Migration `020_behavioral_executions_step_claim_id.sql`

**Files:**
- Create: `migrations/020_behavioral_executions_step_claim_id.sql`

- [ ] **Step 5.1.1: Write the migration**

Create `migrations/020_behavioral_executions_step_claim_id.sql`:

```sql
-- Migration 020: per-(execution, step) granularity for behavioral_executions (#34).
-- Adds nullable step_claim_id; existing rows stay NULL (one row per execution).
-- New hierarchical-workflow callers write N rows per execution where N=step count.
-- See spec section "Behavioral-executions extension".

ALTER TABLE behavioral_executions
    ADD COLUMN step_claim_id uuid REFERENCES claims(id);

CREATE INDEX behavioral_executions_step_claim_id_idx
    ON behavioral_executions (step_claim_id)
    WHERE step_claim_id IS NOT NULL;
```

- [ ] **Step 5.1.2: Apply and verify**

```bash
psql "$DATABASE_URL" -f migrations/020_behavioral_executions_step_claim_id.sql
psql "$DATABASE_URL" -c '\d behavioral_executions' | grep step_claim_id
```

Expected: column shows in the `\d` output as `uuid`, nullable, FK to claims(id).

- [ ] **Step 5.1.3: Commit**

```bash
git add migrations/020_behavioral_executions_step_claim_id.sql
git commit -m "feat(db): step_claim_id column on behavioral_executions (#34)"
```

### Task 5.2: Update `BehavioralExecutionRow` + repo

**Files:**
- Modify: `crates/epigraph-db/src/repos/behavioral_execution.rs` (add field + plumb through writes)

- [ ] **Step 5.2.1: Add `step_claim_id` to the row struct**

In `crates/epigraph-db/src/repos/behavioral_execution.rs`, find `BehavioralExecutionRow` (likely a `#[derive(sqlx::FromRow)]` struct around line 20-50) and add:

```rust
    pub step_claim_id: Option<uuid::Uuid>,
```

right after the existing fields. Also update any `INSERT INTO behavioral_executions ...` statements in the file to include `step_claim_id` in their column list and `$N` placeholders. Existing call sites that don't supply it should bind `Option::<Uuid>::None`.

- [ ] **Step 5.2.2: Run existing behavioral_executions tests to confirm no regression**

```bash
cargo test -p epigraph-db --features db behavioral 2>&1 | tail -10
```

Expected: all existing tests pass; new column is silently included as NULL.

- [ ] **Step 5.2.3: Add a positive test for step_claim_id**

Append to the test module in `behavioral_execution.rs`:

```rust
    #[sqlx::test]
    async fn behavioral_execution_persists_step_claim_id(pool: sqlx::PgPool) {
        let agent = epigraph_test_support::seed_agent(&pool).await;
        let claim_id = epigraph_test_support::seed_claim(&pool, &agent).await;
        let workflow_root_id = epigraph_test_support::seed_claim(&pool, &agent).await; // stand-in
        let row = BehavioralExecutionRow {
            id: uuid::Uuid::new_v4(),
            workflow_id: workflow_root_id,
            goal_text: "test".into(),
            success: true,
            step_beliefs: serde_json::json!({}),
            tool_pattern: vec!["t1".into()],
            quality: Some(0.9),
            deviation_count: 0,
            total_steps: 1,
            created_at: chrono::Utc::now(),
            step_claim_id: Some(claim_id.into()),
        };
        BehavioralExecutionRepository::create(&pool, row, None)
            .await
            .unwrap();

        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM behavioral_executions WHERE step_claim_id IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(count >= 1);
    }
```

- [ ] **Step 5.2.4: Run**

```bash
cargo test -p epigraph-db --features db behavioral_execution_persists_step_claim_id 2>&1 | tail -5
```

Expected: PASS.

- [ ] **Step 5.2.5: Commit**

```bash
git add crates/epigraph-db/src/repos/behavioral_execution.rs
git commit -m "feat(db): plumb step_claim_id through BehavioralExecutionRow (#34)"
```

### Task 5.3: `POST /api/v1/workflows/hierarchical/:id/outcome`

**Files:**
- Modify: `crates/epigraph-api/src/routes/workflows.rs` (add handler)
- Modify: `crates/epigraph-api/src/routes/mod.rs` (register route)

- [ ] **Step 5.3.1: Write the failing tests**

Append to `crates/epigraph-api/src/routes/workflows.rs` test module:

```rust
    #[tokio::test]
    async fn report_hierarchical_outcome_updates_workflow_metadata() {
        let state = test_state().await;
        let workflow_id = seed_test_hierarchical_workflow(&state, "metadata-test").await;

        let body = serde_json::json!({
            "success": true,
            "outcome_details": "ok",
            "step_executions": [
                {"step_index": 0, "planned": "step1", "actual": "step1", "deviated": false}
            ]
        });

        let router = workflow_router(state.clone());
        let response = router
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/workflows/hierarchical/{workflow_id}/outcome"))
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let metadata: serde_json::Value = sqlx::query_scalar(
            "SELECT metadata FROM workflows WHERE id = $1",
        )
        .bind(workflow_id)
        .fetch_one(&state.db_pool)
        .await
        .unwrap();
        assert_eq!(metadata["use_count"], 1);
        assert_eq!(metadata["success_count"], 1);
    }

    #[tokio::test]
    async fn report_hierarchical_outcome_404s_on_flat_id() {
        let state = test_state().await;
        let flat_claim_id = seed_flat_workflow(&state, "flat-only", &["s1"]).await;

        let body = serde_json::json!({
            "success": true, "outcome_details": "ok"
        });

        let router = workflow_router(state.clone());
        let response = router
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/v1/workflows/hierarchical/{flat_claim_id}/outcome"))
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
```

If `seed_test_hierarchical_workflow` and `seed_flat_workflow` helpers don't yet exist, add them to the test module:

```rust
    async fn seed_test_hierarchical_workflow(state: &AppState, canonical: &str) -> Uuid {
        let extraction: epigraph_ingest::workflow::WorkflowExtraction = serde_json::from_str(
            &format!(
                r#"{{
                    "source": {{"canonical_name": "{canonical}", "goal": "G", "generation": 0, "authors": []}},
                    "thesis": "T",
                    "phases": [{{
                        "title": "P", "summary": "S",
                        "steps": [{{"compound": "C", "operations": ["o"], "generality": [1], "confidence": 0.8}}]
                    }}]
                }}"#
            ),
        )
        .unwrap();
        let result = epigraph_mcp::tools::workflow_ingest::do_ingest_workflow_via_pool(
            &state.db_pool,
            state.embedding_service(),
            &extraction,
        )
        .await
        .unwrap();
        result.workflow_id
    }

    async fn seed_flat_workflow(state: &AppState, _canonical: &str, steps: &[&str]) -> Uuid {
        let body = StoreWorkflowRequest {
            goal: "Flat test".into(),
            steps: steps.iter().map(|s| (*s).to_string()).collect(),
            prerequisites: None,
            expected_outcome: None,
            confidence: Some(0.8),
            tags: None,
        };
        let response = store_workflow(State(state.clone()), Json(body)).await.unwrap();
        let v = response.0;
        v["workflow_id"].as_str().unwrap().parse().unwrap()
    }
```

- [ ] **Step 5.3.2: Implement `report_hierarchical_outcome`**

Add to `crates/epigraph-api/src/routes/workflows.rs`:

```rust
/// POST /api/v1/workflows/hierarchical/:id/outcome - Report execution outcome
/// for a hierarchical workflow (one whose root lives in the `workflows` table).
///
/// Updates `workflows.metadata` counters (use_count, success_count, failure_count,
/// avg_variance) and writes per-step `behavioral_executions` rows with
/// `step_claim_id` populated for each step in `step_executions`.
///
/// Returns 404 if the id does not correspond to a `workflows` row. Use
/// `POST /api/v1/workflows/:id/outcome` for flat-JSON workflows.
#[cfg(feature = "db")]
pub async fn report_hierarchical_outcome(
    State(state): State<AppState>,
    Path(workflow_id): Path<Uuid>,
    Json(request): Json<ReportOutcomeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // 1. Confirm this is a hierarchical workflow root
    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT metadata FROM workflows WHERE id = $1")
            .bind(workflow_id)
            .fetch_optional(&state.db_pool)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("workflows lookup failed: {e}"),
            })?;
    let mut metadata = match row {
        Some((m,)) => m,
        None => {
            return Err(ApiError::NotFound {
                entity: "hierarchical workflow".into(),
                id: workflow_id.to_string(),
            });
        }
    };

    // 2. Compute deltas
    let success = request.success;
    let variance = request.step_executions.as_ref().map_or(0.0, |steps| {
        if steps.is_empty() {
            0.0
        } else {
            let dev = steps.iter().filter(|s| s.deviated).count();
            dev as f64 / steps.len() as f64
        }
    });
    let quality = request.quality.unwrap_or(if success { 1.0 } else { 0.0 });

    // 3. Update metadata counters
    let use_count = metadata.get("use_count").and_then(|v| v.as_i64()).unwrap_or(0) + 1;
    let success_count = metadata
        .get("success_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        + i64::from(success);
    let failure_count = metadata
        .get("failure_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        + i64::from(!success);
    let prev_avg_var = metadata
        .get("avg_variance")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let avg_variance = if use_count > 0 {
        (prev_avg_var * (use_count - 1) as f64 + variance) / use_count as f64
    } else {
        variance
    };
    metadata["use_count"] = serde_json::json!(use_count);
    metadata["success_count"] = serde_json::json!(success_count);
    metadata["failure_count"] = serde_json::json!(failure_count);
    metadata["avg_variance"] = serde_json::json!(avg_variance);

    sqlx::query("UPDATE workflows SET metadata = $1 WHERE id = $2")
        .bind(&metadata)
        .bind(workflow_id)
        .execute(&state.db_pool)
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("metadata update failed: {e}"),
        })?;

    // 4. Resolve step_index → step_claim_id via the workflow's executes edges,
    //    sorted by claim level=2 (steps), in plan order. Plan order is the
    //    insertion order of `executes` edges; we use edges.created_at as proxy.
    let step_claims: Vec<(i32, Uuid)> = sqlx::query_as(
        "SELECT (c.properties->>'level')::int AS level, c.id \
         FROM edges e \
         JOIN claims c ON c.id = e.target_id \
         WHERE e.source_id = $1 AND e.relationship = 'executes' AND (c.properties->>'level')::int = 2 \
         ORDER BY e.created_at ASC, c.id ASC",
    )
    .bind(workflow_id)
    .fetch_all(&state.db_pool)
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("step lookup failed: {e}"),
    })?;
    let step_claim_ids: Vec<Uuid> = step_claims.into_iter().map(|(_, id)| id).collect();

    // 5. Write per-step behavioral_executions rows
    if let Some(ref step_execs) = request.step_executions {
        for step_exec in step_execs {
            let step_claim_id = step_claim_ids.get(step_exec.step_index).copied();
            let step_beliefs = serde_json::json!({
                "deviated": step_exec.deviated,
                "deviation_reason": step_exec.deviation_reason,
            });
            let row = epigraph_db::BehavioralExecutionRow {
                id: Uuid::new_v4(),
                workflow_id,
                goal_text: request
                    .goal_text
                    .clone()
                    .unwrap_or_else(|| String::from("hierarchical")),
                success,
                step_beliefs,
                tool_pattern: vec![step_exec.planned.clone()],
                quality: Some(quality),
                deviation_count: i32::from(step_exec.deviated),
                total_steps: 1,
                created_at: chrono::Utc::now(),
                step_claim_id,
            };
            let _ = epigraph_db::BehavioralExecutionRepository::create(&state.db_pool, row, None)
                .await;
        }
    }

    Ok(Json(serde_json::json!({
        "workflow_id": workflow_id,
        "use_count": use_count,
        "success_count": success_count,
        "failure_count": failure_count,
        "variance": variance,
    })))
}
```

- [ ] **Step 5.3.3: Register the route**

In `crates/epigraph-api/src/routes/mod.rs`, add:

```rust
        .route(
            "/api/v1/workflows/hierarchical/:id/outcome",
            post(workflows::report_hierarchical_outcome),
        )
```

before the existing `/api/v1/workflows/:id/outcome` route (more-specific paths first).

- [ ] **Step 5.3.4: Run tests**

```bash
cargo test -p epigraph-api --features db report_hierarchical_outcome 2>&1 | tail -10
```

Expected: both tests pass.

- [ ] **Step 5.3.5: Commit**

```bash
git add crates/epigraph-api/
git commit -m "feat(api): POST /api/v1/workflows/hierarchical/:id/outcome (#34)"
```

---

## Phase 6 — Hierarchical search endpoint

**Why sixth:** Need a way to *find* hierarchical workflows. `find_workflow` reads the flat-JSON path; this adds a parallel hierarchical search returning rows from `workflows`.

### Task 6.1: `WorkflowRepository::search_hierarchical_by_text`

**Files:**
- Modify: `crates/epigraph-db/src/repos/workflow.rs`

- [ ] **Step 6.1.1: Write the test**

Append to the test module:

```rust
    #[sqlx::test]
    async fn search_hierarchical_by_text_returns_matches(pool: sqlx::PgPool) {
        WorkflowRepository::insert_root(
            &pool,
            uuid::Uuid::new_v4(),
            "data-pipeline-v1",
            0,
            "Process incoming sensor data and write to warehouse.",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();
        WorkflowRepository::insert_root(
            &pool,
            uuid::Uuid::new_v4(),
            "deploy-canary",
            0,
            "Deploy a canary release safely.",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();

        let hits = WorkflowRepository::search_hierarchical_by_text(&pool, "sensor", 10)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].canonical_name, "data-pipeline-v1");
    }
```

- [ ] **Step 6.1.2: Implement**

Add to `crates/epigraph-db/src/repos/workflow.rs`:

```rust
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HierarchicalWorkflowRow {
    pub id: Uuid,
    pub canonical_name: String,
    pub generation: i32,
    pub goal: String,
    pub parent_id: Option<Uuid>,
    pub metadata: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl WorkflowRepository {
    pub async fn search_hierarchical_by_text(
        pool: &PgPool,
        query: &str,
        limit: i64,
    ) -> Result<Vec<HierarchicalWorkflowRow>, sqlx::Error> {
        let pattern = format!("%{query}%");
        sqlx::query_as::<_, HierarchicalWorkflowRow>(
            "SELECT id, canonical_name, generation, goal, parent_id, metadata, created_at \
             FROM workflows \
             WHERE goal ILIKE $1 OR canonical_name ILIKE $1 \
             ORDER BY created_at DESC \
             LIMIT $2",
        )
        .bind(&pattern)
        .bind(limit)
        .fetch_all(pool)
        .await
    }
}
```

- [ ] **Step 6.1.3: Run + commit**

```bash
cargo test -p epigraph-db --features db search_hierarchical_by_text_returns_matches 2>&1 | tail -5
git add crates/epigraph-db/src/repos/workflow.rs
git commit -m "feat(db): WorkflowRepository::search_hierarchical_by_text (#34)"
```

### Task 6.2: `GET /api/v1/workflows/hierarchical/search`

**Files:**
- Modify: `crates/epigraph-api/src/routes/workflows.rs`
- Modify: `crates/epigraph-api/src/routes/mod.rs`

- [ ] **Step 6.2.1: Test + handler + route**

Append the handler in `workflows.rs`:

```rust
#[cfg(feature = "db")]
#[derive(Debug, Deserialize)]
pub struct HierarchicalSearchQuery {
    pub q: String,
    pub limit: Option<i64>,
}

#[cfg(feature = "db")]
pub async fn find_workflow_hierarchical(
    State(state): State<AppState>,
    Query(params): Query<HierarchicalSearchQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);
    let rows = epigraph_db::WorkflowRepository::search_hierarchical_by_text(
        &state.db_pool,
        &params.q,
        limit,
    )
    .await
    .map_err(|e| ApiError::InternalError {
        message: format!("hierarchical search failed: {e}"),
    })?;
    let workflows: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "workflow_id": r.id,
                "canonical_name": r.canonical_name,
                "generation": r.generation,
                "goal": r.goal,
                "parent_id": r.parent_id,
                "metadata": r.metadata,
                "created_at": r.created_at,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "workflows": workflows,
        "total": workflows.len(),
    })))
}
```

Test (in same file):

```rust
    #[tokio::test]
    async fn find_workflow_hierarchical_returns_match() {
        let state = test_state().await;
        seed_test_hierarchical_workflow(&state, "search-test-canonical").await;

        let router = workflow_router(state.clone());
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/workflows/hierarchical/search?q=search-test-canonical")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = parse_body(response).await;
        assert_eq!(body["workflows"][0]["canonical_name"], "search-test-canonical");
    }
```

Route in `routes/mod.rs`:

```rust
        .route(
            "/api/v1/workflows/hierarchical/search",
            get(workflows::find_workflow_hierarchical),
        )
```

(Place before any catch-all route that might steal it.)

- [ ] **Step 6.2.2: Run + commit**

```bash
cargo test -p epigraph-api --features db find_workflow_hierarchical 2>&1 | tail -5
git add crates/epigraph-api/
git commit -m "feat(api): GET /api/v1/workflows/hierarchical/search (#34)"
```

---

## Phase 7 — Migration CLI: `migrate-flat-workflows`

**Why seventh:** Existing flat-JSON workflows need to enter the hierarchical tables to participate in `find_workflow_hierarchical` and accumulate cross-workflow operation atoms. One-shot CLI, idempotent, processes oldest first.

### Task 7.1: Add the bin

**Files:**
- Create: `crates/epigraph-mcp/src/bin/migrate_flat_workflows.rs`
- Modify: `crates/epigraph-mcp/Cargo.toml` (add `[[bin]]` entry)
- Modify: `crates/epigraph-mcp/src/lib.rs` (export helpers if needed)

- [ ] **Step 7.1.1: Write the bin**

Create `crates/epigraph-mcp/src/bin/migrate_flat_workflows.rs`:

```rust
//! Migration CLI for issue #34. Re-ingests existing flat-JSON workflows
//! (claims labeled `'workflow'`) into the new hierarchical `workflows` table.
//! Idempotent: skips claims already labeled `'legacy_flat'`.

use std::collections::HashMap;

use clap::Parser;
use epigraph_ingest::common::schema::ThesisDerivation;
use epigraph_ingest::workflow::{Phase, Step, WorkflowExtraction, WorkflowSource};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(version, about = "Migrate flat-JSON workflows to hierarchical form (#34)")]
struct Args {
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    #[arg(long, default_value_t = false)]
    dry_run: bool,
    #[arg(long)]
    limit: Option<i64>,
    #[arg(long, value_enum, default_value_t = CanonicalFrom::GoalSlug)]
    canonical_from: CanonicalFrom,
    #[arg(long)]
    workflow_id: Option<Uuid>,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum CanonicalFrom {
    GoalSlug,
    Tag,
}

#[derive(Debug, Deserialize)]
struct FlatContent {
    goal: String,
    #[serde(default)]
    steps: Vec<String>,
    #[serde(default)]
    prerequisites: Vec<String>,
    #[serde(default)]
    expected_outcome: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct FlatRow {
    id: Uuid,
    content: String,
    properties: serde_json::Value,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let pool = PgPool::connect(&args.database_url).await?;

    let rows = fetch_unmigrated(&pool, args.limit, args.workflow_id).await?;
    println!(
        "Found {} flat-JSON workflow{} to migrate{}",
        rows.len(),
        if rows.len() == 1 { "" } else { "s" },
        if args.dry_run { " (DRY RUN)" } else { "" }
    );

    let mut by_canonical: HashMap<String, Vec<&FlatRow>> = HashMap::new();
    let mut canonical_for_row: HashMap<Uuid, String> = HashMap::new();
    let mut row_canonical_pairs: Vec<(&FlatRow, FlatContent, String)> = Vec::with_capacity(rows.len());

    // First pass: parse + group by canonical name
    for row in &rows {
        let parsed: FlatContent = match serde_json::from_str(&row.content) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("SKIP claim {} — content does not parse: {e}", row.id);
                continue;
            }
        };
        let canonical = match args.canonical_from {
            CanonicalFrom::Tag => parsed.tags.first().cloned().unwrap_or_else(|| slugify(&parsed.goal)),
            CanonicalFrom::GoalSlug => slugify(&parsed.goal),
        };
        canonical_for_row.insert(row.id, canonical.clone());
        row_canonical_pairs.push((row, parsed, canonical.clone()));
    }
    for (row, _parsed, canonical) in &row_canonical_pairs {
        by_canonical.entry(canonical.clone()).or_default().push(*row);
    }

    let mut migrated = 0_usize;
    let mut failed = 0_usize;
    for (row, parsed, canonical) in &row_canonical_pairs {
        // Determine generation: position within group (0-indexed by created_at, which equals fetch order).
        let group = by_canonical.get(canonical).unwrap();
        let generation = group.iter().position(|r| r.id == row.id).unwrap_or(0) as u32;
        let parent_canonical = if generation > 0 {
            // Look up the previous claim (generation - 1) in this group; its canonical is the same.
            None // For migration, all migrated claims share the canonical; parent_canonical_name resolves to the same canonical at gen=0.
        } else {
            // For original flat workflows, properties.parent_id (if set) names the parent claim's id.
            row.properties
                .get("parent_id")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Uuid>().ok())
                .and_then(|pid| canonical_for_row.get(&pid).cloned())
        };

        let extraction = build_extraction(parsed, canonical.clone(), generation, parent_canonical);

        if args.dry_run {
            println!(
                "DRY RUN: would migrate {} → canonical={canonical} gen={generation}",
                row.id
            );
            migrated += 1;
            continue;
        }

        match epigraph_mcp::tools::workflow_ingest::do_ingest_workflow_via_pool(
            &pool, None, &extraction,
        )
        .await
        {
            Ok(result) => {
                if let Err(e) = mark_legacy_and_supersede(&pool, row.id, result.workflow_id).await {
                    eprintln!("FAIL post-migration markup for {}: {e}", row.id);
                    failed += 1;
                } else {
                    println!(
                        "migrated {} → {} (canonical={canonical}, gen={generation})",
                        row.id, result.workflow_id
                    );
                    migrated += 1;
                }
            }
            Err(e) => {
                eprintln!("FAIL ingest for {}: {e}", row.id);
                failed += 1;
            }
        }
    }
    println!("Done. migrated={migrated}, failed={failed}");
    Ok(())
}

async fn fetch_unmigrated(
    pool: &PgPool,
    limit: Option<i64>,
    only_id: Option<Uuid>,
) -> Result<Vec<FlatRow>, sqlx::Error> {
    let lim = limit.unwrap_or(i64::MAX);
    if let Some(id) = only_id {
        sqlx::query_as::<_, FlatRow>(
            "SELECT id, content, properties FROM claims \
             WHERE id = $1 AND 'workflow' = ANY(labels) AND NOT 'legacy_flat' = ANY(labels)",
        )
        .bind(id)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, FlatRow>(
            "SELECT id, content, properties FROM claims \
             WHERE 'workflow' = ANY(labels) AND NOT 'legacy_flat' = ANY(labels) \
             ORDER BY (properties->>'generation')::int NULLS FIRST, created_at ASC \
             LIMIT $1",
        )
        .bind(lim)
        .fetch_all(pool)
        .await
    }
}

fn build_extraction(
    parsed: &FlatContent,
    canonical_name: String,
    generation: u32,
    parent_canonical_name: Option<String>,
) -> WorkflowExtraction {
    let phases = if parsed.steps.is_empty() {
        vec![]
    } else {
        vec![Phase {
            title: "Body".to_string(),
            summary: parsed.goal.clone(),
            steps: parsed
                .steps
                .iter()
                .map(|step_text| Step {
                    compound: step_text.clone(),
                    rationale: String::new(),
                    operations: vec![step_text.clone()],
                    generality: vec![1],
                    confidence: 0.8,
                })
                .collect(),
        }]
    };

    WorkflowExtraction {
        source: WorkflowSource {
            canonical_name,
            goal: parsed.goal.clone(),
            generation,
            parent_canonical_name,
            authors: vec![],
            expected_outcome: parsed.expected_outcome.clone(),
            tags: parsed.tags.clone(),
            metadata: serde_json::json!({
                "prerequisites": parsed.prerequisites,
            }),
        },
        thesis: Some(parsed.goal.clone()),
        thesis_derivation: ThesisDerivation::default(),
        phases,
        relationships: vec![],
    }
}

async fn mark_legacy_and_supersede(
    pool: &PgPool,
    old_claim_id: Uuid,
    new_workflow_id: Uuid,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE claims SET labels = array_append(labels, 'legacy_flat') WHERE id = $1 AND NOT 'legacy_flat' = ANY(labels)",
    )
    .bind(old_claim_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, 'workflow', $2, 'claim', 'supersedes', '{}'::jsonb) \
         ON CONFLICT DO NOTHING",
    )
    .bind(new_workflow_id)
    .bind(old_claim_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

fn slugify(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}
```

- [ ] **Step 7.1.2: Add bin entry to `Cargo.toml`**

Edit `crates/epigraph-mcp/Cargo.toml`. After the `[lib]` section (or at the bottom), add:

```toml
[[bin]]
name = "migrate-flat-workflows"
path = "src/bin/migrate_flat_workflows.rs"
required-features = ["db"]
```

If `clap` isn't already a dep, add `clap = { version = "4", features = ["derive", "env"] }` to `[dependencies]`.

- [ ] **Step 7.1.3: Compile-check**

```bash
cargo check -p epigraph-mcp --features db --bin migrate-flat-workflows 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 7.1.4: Write a test script that exercises the bin against a seeded DB**

Add `crates/epigraph-mcp/tests/migration_tool_smoke.rs`:

```rust
//! End-to-end smoke for the migrate-flat-workflows bin against a real DB pool.

#[sqlx::test]
async fn migrate_one_flat_workflow(pool: sqlx::PgPool) {
    use epigraph_mcp::tools::workflow_ingest;

    // Seed a flat-JSON workflow via raw SQL (avoids HTTP test setup overhead).
    // Ensure a system agent exists.
    let sys_pub_key = [0u8; 32];
    let sys_agent_id: uuid::Uuid = match sqlx::query_scalar::<_, uuid::Uuid>(
        "SELECT id FROM agents WHERE public_key = $1",
    )
    .bind(sys_pub_key.as_slice())
    .fetch_optional(&pool)
    .await
    .unwrap()
    {
        Some(id) => id,
        None => sqlx::query_scalar(
            "INSERT INTO agents (public_key, name) VALUES ($1, $2) RETURNING id",
        )
        .bind(sys_pub_key.as_slice())
        .bind("test-sys")
        .fetch_one(&pool)
        .await
        .unwrap(),
    };
    let claim_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties) \
         VALUES ($1, $2, $3, 0.5, ARRAY['workflow'], '{}'::jsonb) \
         RETURNING id",
    )
    .bind(serde_json::json!({"goal": "Test", "steps": ["s1", "s2"], "tags": ["test"]}).to_string())
    .bind(blake3::hash(b"test").as_bytes())
    .bind(sys_agent_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Drive the migration as the bin would: build_extraction + do_ingest_workflow_via_pool + mark_legacy_and_supersede.
    // (We don't shell out to the bin in tests; we exercise its core logic which lives in workflow_ingest helpers.)

    // ... port the build_extraction logic from the bin or extract it into a public module ...
    // For a first cut, drive the test by calling do_ingest_workflow_via_pool with a hand-built extraction:

    let extraction = epigraph_ingest::workflow::WorkflowExtraction {
        source: epigraph_ingest::workflow::WorkflowSource {
            canonical_name: "test".into(),
            goal: "Test".into(),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec!["test".into()],
            metadata: serde_json::json!({}),
        },
        thesis: Some("Test".into()),
        thesis_derivation: Default::default(),
        phases: vec![epigraph_ingest::workflow::Phase {
            title: "Body".into(),
            summary: "Test".into(),
            steps: vec![
                epigraph_ingest::workflow::Step {
                    compound: "s1".into(),
                    rationale: "".into(),
                    operations: vec!["s1".into()],
                    generality: vec![1],
                    confidence: 0.8,
                },
            ],
        }],
        relationships: vec![],
    };

    let result = workflow_ingest::do_ingest_workflow_via_pool(&pool, None, &extraction)
        .await
        .unwrap();
    assert!(result.claims_created >= 4);

    // Now mark legacy + supersede
    sqlx::query(
        "UPDATE claims SET labels = array_append(labels, 'legacy_flat') WHERE id = $1",
    )
    .bind(claim_id)
    .execute(&pool)
    .await
    .unwrap();

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM claims WHERE id = $1 AND 'legacy_flat' = ANY(labels)",
    )
    .bind(claim_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}
```

> The test deliberately exercises the same shared core (`do_ingest_workflow_via_pool`) that the bin uses. To make the bin's `build_extraction` reachable from tests, **extract** it into `crates/epigraph-mcp/src/migrate_flat.rs` and have the bin import it. Add `pub mod migrate_flat;` in `crates/epigraph-mcp/src/lib.rs`. Then the test imports `epigraph_mcp::migrate_flat::build_extraction` and calls it.

- [ ] **Step 7.1.5: Run the smoke test**

```bash
cargo test -p epigraph-mcp --features db --test migration_tool_smoke 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 7.1.6: Commit**

```bash
git add crates/epigraph-mcp/
git commit -m "feat(mcp): migrate-flat-workflows CLI for #34 hierarchical migration"
```

### Task 7.2: Add idempotence + canonical-collision tests

**Files:**
- Modify: `crates/epigraph-mcp/tests/migration_tool_smoke.rs`

- [ ] **Step 7.2.1: Add test for idempotence**

Append:

```rust
#[sqlx::test]
async fn migrate_idempotent_re_run_is_noop(pool: sqlx::PgPool) {
    // Ingest the same workflow twice.
    let extraction = epigraph_ingest::workflow::WorkflowExtraction {
        source: epigraph_ingest::workflow::WorkflowSource {
            canonical_name: "idempo-mig".into(),
            goal: "G".into(),
            generation: 0,
            parent_canonical_name: None,
            authors: vec![],
            expected_outcome: None,
            tags: vec![],
            metadata: serde_json::json!({}),
        },
        thesis: Some("T".into()),
        thesis_derivation: Default::default(),
        phases: vec![epigraph_ingest::workflow::Phase {
            title: "P".into(), summary: "S".into(),
            steps: vec![epigraph_ingest::workflow::Step {
                compound: "C".into(), rationale: "".into(),
                operations: vec!["o".into()], generality: vec![1], confidence: 0.8,
            }],
        }],
        relationships: vec![],
    };

    let r1 = epigraph_mcp::tools::workflow_ingest::do_ingest_workflow_via_pool(&pool, None, &extraction).await.unwrap();
    let r2 = epigraph_mcp::tools::workflow_ingest::do_ingest_workflow_via_pool(&pool, None, &extraction).await.unwrap();
    assert_eq!(r1.workflow_id, r2.workflow_id);

    // No duplicate workflows row
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = 'idempo-mig'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
}
```

- [ ] **Step 7.2.2: Run + commit**

```bash
cargo test -p epigraph-mcp --features db --test migration_tool_smoke 2>&1 | tail -10
git add crates/epigraph-mcp/tests/migration_tool_smoke.rs
git commit -m "test(mcp): idempotence test for migrate-flat-workflows (#34)"
```

---

## Phase 8 — Workspace tests + manual smoke + final commit

### Task 8.1: Run the full workspace test suite

- [ ] **Step 8.1.1: cargo test --workspace --features db**

```bash
cargo test --workspace --features db 2>&1 | tail -20
```

Expected: every test passes. If any test fails, treat it as a regression and fix before declaring done. Common failure modes:
- `sqlx::query!` macro expects compile-time-checked queries: run `cargo sqlx prepare --workspace --check` to update the offline metadata if you added new sqlx queries.
- Existing `do_ingest_document` tests fail: confirm Phase 2 re-exports are exhaustive.
- A test assumes `'workflow'` label on claims that a Phase 4 hierarchical ingest now creates: check whether the test queries by label or by `kind`.

### Task 8.2: Manual smoke against the dev DB

- [ ] **Step 8.2.1: Apply both new migrations to dev DB if not already**

```bash
psql "$DATABASE_URL" -f migrations/019_workflows_table.sql
psql "$DATABASE_URL" -f migrations/020_behavioral_executions_step_claim_id.sql
```

(Both should be no-ops if already applied during phase development; the `IF EXISTS`/`IF NOT EXISTS` guards in the SQL handle this.)

- [ ] **Step 8.2.2: Spin up the API**

```bash
cargo run -p epigraph-api --features db -- --port 8080 &
sleep 5
```

- [ ] **Step 8.2.3: Round-trip a hierarchical workflow over HTTP**

```bash
WORKFLOW_RESP=$(curl -s -X POST http://localhost:8080/api/v1/workflows/ingest \
    -H "content-type: application/json" \
    -d '{
        "source": {
            "canonical_name": "smoke-test",
            "goal": "End-to-end smoke",
            "generation": 0,
            "authors": []
        },
        "thesis": "Smoke thesis",
        "phases": [{
            "title": "P", "summary": "S",
            "steps": [{"compound": "C", "operations": ["op1", "op2"], "generality": [1, 1], "confidence": 0.8}]
        }],
        "relationships": []
    }')
echo "$WORKFLOW_RESP"
WF_ID=$(echo "$WORKFLOW_RESP" | jq -r '.workflow_id')

curl -s "http://localhost:8080/api/v1/workflows/hierarchical/search?q=smoke-test" | jq '.'

curl -s -X POST "http://localhost:8080/api/v1/workflows/hierarchical/$WF_ID/outcome" \
    -H "content-type: application/json" \
    -d '{"success": true, "outcome_details": "ok", "step_executions": [{"step_index": 0, "planned": "C", "actual": "C", "deviated": false}]}'
```

Expected: ingest returns a JSON with `workflow_id`, `claims_created` (≥4), `edges_created` (≥7). Search returns the row. Outcome returns updated counters.

- [ ] **Step 8.2.4: Run the migration tool against a flat workflow**

```bash
# Seed a flat-JSON workflow first via the existing endpoint
curl -s -X POST http://localhost:8080/api/v1/workflows \
    -H "content-type: application/json" \
    -d '{"goal":"Migrate me","steps":["step a","step b"],"confidence":0.8,"tags":["migrate"]}'

# Run the migration tool in dry-run mode
cargo run -p epigraph-mcp --features db --bin migrate-flat-workflows -- --dry-run --limit 5

# Real run
cargo run -p epigraph-mcp --features db --bin migrate-flat-workflows -- --limit 5
```

Expected: dry-run prints what would happen; real run produces `migrated N` lines and post-condition queries:

```bash
psql "$DATABASE_URL" -c "SELECT canonical_name, generation FROM workflows ORDER BY created_at DESC LIMIT 5"
psql "$DATABASE_URL" -c "SELECT count(*) FROM claims WHERE 'legacy_flat' = ANY(labels)"
psql "$DATABASE_URL" -c "SELECT count(*) FROM edges WHERE source_type = 'workflow' AND relationship = 'supersedes'"
```

The first two counts should match.

- [ ] **Step 8.2.5: Stop the API**

```bash
kill %1
```

### Task 8.3: Final lint + clippy pass

- [ ] **Step 8.3.1: Run clippy with the same warnings policy as CI**

```bash
cargo clippy --workspace --features db --all-targets -- -D warnings 2>&1 | tail -20
```

Expected: clean. Address any new warnings introduced by this work; do not blanket-allow.

- [ ] **Step 8.3.2: Run `cargo fmt --check`**

```bash
cargo fmt --check
```

Expected: clean. If not, run `cargo fmt` and commit the formatting.

### Task 8.4: Push and open PR

- [ ] **Step 8.4.1: Confirm git log is clean and ready**

```bash
git log --oneline origin/main..HEAD
```

Expected: a tidy linear sequence of commits, one per phase task, all with `(#34)` suffix on their subject lines.

- [ ] **Step 8.4.2: Push the branch**

```bash
git push -u origin feat/issue-34-hierarchical-workflow
```

- [ ] **Step 8.4.3: Open the PR**

```bash
gh pr create --repo epigraph-io/epigraph \
    --title "feat: hierarchical workflow primitive (#34)" \
    --body "$(cat <<'EOF'
## Summary
- Adds hierarchical workflows isomorphic to `DocumentExtraction`, with a dedicated `workflows` table parallel to `papers`.
- Refactors `epigraph-ingest` into `common`/`document`/`workflow` modules sharing a parameterized walker. Operation atoms at level 3 use the same `ATOM_NAMESPACE` as document atoms — cross-source convergence works for free.
- Adds `ingest_workflow` MCP tool + `POST /api/v1/workflows/ingest`.
- Adds `POST /api/v1/workflows/hierarchical/:id/outcome` and `GET /api/v1/workflows/hierarchical/search`.
- Adds `migrate-flat-workflows` CLI to bring existing flat-JSON workflows into hierarchical form (idempotent, single-Body-phase mapping per design).
- Existing `store_workflow` / `find_workflow` / `improve_workflow` / `report_outcome` paths are untouched.

Spec: docs/superpowers/specs/2026-04-30-hierarchical-workflow-primitive-design.md
Plan: docs/superpowers/plans/2026-04-30-hierarchical-workflow-primitive.md
Follow-up: #36 (re-author migrated flat workflows into substantively-multi-phase form)

## Test plan
- [x] cargo test --workspace --features db
- [x] cargo clippy --workspace --features db --all-targets -- -D warnings
- [x] Manual smoke: ingest → search → outcome → migrate
- [x] Cross-source convergence test (workflow operation atom == document atom UUID)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 8.4.4: Done.**

Plan complete. The hierarchical workflow primitive is in.
