# Design: Five Memory-Architecture Backlog Features

Implementation design for the five open `backlog`+`epigraph-improvement` proposals:

| # | Backlog claim | Feature | Size |
|---|---------------|---------|------|
| F1 | `44b19521` | `consolidate_claims` — N→1 merge via supersedes | L |
| F2 | `3216b086` | `get_provenance_chain` — topological derivation traversal | M |
| F3 | `34d3400d` | Dispute-awareness in `recall()` responses | S |
| F4 | `e3732d16` | `sweep_semantic_duplicates` — batch dedup sweep | M |
| F5 | `8cbffa0e` | Recall audit logging (`recall_events`) | M |

All SQL lands in `crates/epigraph-db/src/repos/` (house rule); MCP tools in
`crates/epigraph-mcp/src/tools/` call the repo layer. Each feature is one
feature branch / one PR, epistemic commit protocol, `cargo sqlx prepare`
committed per PR.

Suggested landing order: **F3 → F2 → F5 → F1 → F4** (smallest first; F4's
merge mode consumes F1).

---

## F1 — `consolidate_claims`: N→1 merge via supersedes

### Semantics

Merge 2..=20 `is_current` source claims into one new merged claim. The
**caller** (agent) supplies the synthesized `merged_content` — the server
never calls an LLM (same division of labor as `epigraph-ingest-executor`:
agent-side synthesis, server-side storage).

### The `supersedes` column problem

`claims.supersedes` is a single UUID, and the codebase uses it in two
directions today:

- `ClaimRepository::supersede` (claim.rs:1967): **new** row's `supersedes`
  = old id ("this replaces that").
- `ClaimRepository::mark_duplicate` (claim.rs:2788): **retired** row's
  `supersedes` = canonical id (forwarding pointer, "go here now").

An N→1 merge cannot use the `supersede` convention (one column, N parents).
Decision: use the **mark_duplicate convention** — each retired source gets
`supersedes = merged_id` as a forwarding pointer. This also makes
`mark_duplicate`'s existing "already superseded; refusing to overwrite"
guard protect merged sources for free. The merged row's own `supersedes`
column stays NULL; the reverse fan-out is carried by:

1. N `supersedes` **edges** `merged → source_i`, `properties =
   {reason, mode, merged_at}` (mirrors supersede()'s edge insert).
2. `merged.properties.merge = { mode, merged_from: [source_ids],
   merged_at: <ISO-8601>, reason }` — the merge date + lineage metadata
   requested in the design brief, queryable via
   `properties->'merge'->>'merged_at'`.

### Repo: `ClaimRepository::consolidate` (claim.rs)

```rust
pub async fn consolidate(
    pool: &PgPool,
    source_ids: &[ClaimId],        // 2..=20, distinct
    merged_content: &str,
    merged_truth: TruthValue,
    mode: ConsolidateMode,         // Merge | Abstract | Rewrite
    reason: &str,
    acting_agent_id: Uuid,
) -> Result<ConsolidateResult, DbError>  // { merged_id, superseded: Vec<Uuid> }
```

Single transaction:

1. `SELECT ... FOR UPDATE` all sources; verify each exists, `is_current`,
   and `supersedes IS NULL` (not already forwarded). Refuse self-set dups.
2. Union + dedupe `labels` across sources (same label-carry rationale as
   supersede()); **properties are NOT carried** (same rule as supersede() —
   blanket copy propagates the bug a merge may be fixing), except the new
   `properties.merge` object.
3. Retire sources: `UPDATE claims SET supersedes = $merged, is_current =
   false, embedding = NULL, updated_at = NOW() WHERE id = ANY($sources)` —
   one statement, per the `chk_deprecated_no_embedding` (migration 052)
   per-statement CHECK requirement documented at claim.rs:2013.
4. Insert merged claim (`is_current = true`, `agent_id = acting_agent_id`
   — see Decisions).
5. **Edge migration** — recreate all relationships of the merged nodes on
   the merged claim. Same two guard classes as `mark_duplicate`
   (claim.rs:2844, `docs/architecture/audit-edge-collision-mark-duplicate.md`),
   plus one new class:
   - *Self-loops*: edges among `{sources ∪ merged}` would collapse to
     `merged→merged`; filter them out (they are interior to the merge).
   - *Diamond duplicates*: third claim T with same-relationship edges to
     both a source and the merged/another source → pre-delete redundant
     copies (keep lowest `created_at`) before the `UPDATE`, so the partial
     unique triple index isn't tripped. AUTHORED excluded (allowed to
     accumulate, migration 017).
   - *Cross-source duplicates* (new): T→[REL]→s1 **and** T→[REL]→s2 both
     migrate to T→[REL]→merged. Handled by the same pre-delete pass run
     over `ANY($sources)` collectively rather than per-source.
   `supersedes` edges are excluded from migration (as in supersede()).
6. Insert the N `supersedes` edges `merged → source_i`.
7. Commit. Post-commit, best-effort (warn, never block — CLAUDE.md write
   path invariant): embed the merged claim. Add the call-site to CLAUDE.md's
   write-path list.

Not migrated: `mass_functions` rows stay attached to retired sources
(parity with supersede(), which also doesn't migrate them). The merged
claim starts from `merged_truth`; callers wanting DS-grounded belief run
`update_with_evidence` / `recompute_beliefs` after. Follow-up candidate,
out of scope here.

### MCP: `consolidate_claims` (new `tools/consolidate.rs`)

```
consolidate_claims(
  source_claim_ids: Vec<Uuid>,   // 2..=20
  merged_content: String,
  mode: "merge" | "abstract" | "rewrite",
  reason: String,
  confidence: Option<f64>,       // default max(source truths) * 0.95
)
```

Response: `{ merged_claim_id, superseded_ids, edges_migrated,
edges_deduped, embedded }`. Agent identity from the PR #361 deterministic
LLM-agent auth context.

### Decisions (settled 2026-07-27)

- **agent_id of the merged claim**: sources may span agents (the dedup
  corpus is cross-agent). Inheriting is ill-defined for N>1 ⇒ merged claim
  belongs to the **acting agent**, with source agents recoverable via the
  supersedes edges / `merged_from`. Intentionally differs from
  supersede()'s inheritance — approved.
- Post-107 `(content_hash, agent_id)` unique constraint applies to the
  merged insert; a content-identical merged claim by the same agent
  surfaces as `DuplicateKey` — return the existing id (novelty-gate style)
  rather than erroring.

---

## F2 — `get_provenance_chain`

Read-only. Answers "what derivation supports this conclusion" in one call
instead of the current recall → get_neighborhood → get_claim round-trips.

### Repo: `ClaimRepository::provenance_chain` (or `repos/provenance.rs`)

Recursive CTE from the target claim, walking derivation edges backwards:

```sql
WITH RECURSIVE chain AS (
    SELECT e.source_id, e.target_id, e.relationship, 1 AS depth,
           ARRAY[e.target_id, e.source_id] AS path
    FROM edges e
    WHERE e.target_id = $1
      AND e.source_type = 'claim' AND e.target_type = 'claim'
      AND e.relationship = ANY($2)
  UNION ALL
    SELECT e.source_id, e.target_id, e.relationship, c.depth + 1,
           c.path || e.source_id
    FROM edges e
    JOIN chain c ON e.target_id = c.source_id
    WHERE e.relationship = ANY($2)
      AND c.depth < $3
      AND NOT (e.source_id = ANY(c.path))   -- cycle guard
)
SELECT DISTINCT ON (source_id, target_id, relationship) ...
```

Then one batched join against `claims` for `content, truth_value, labels,
is_current, created_at`, and a **Kahn topological sort in Rust** over the
collected edge set (evidence first, conclusion last) — depth is not a
valid topo key when a node is reachable at multiple depths.

- `relationships` default: `['supports','corroborates','elaborates',
  'decomposes_to','supersedes']`. (`inferred_from` from the backlog
  sketch does not exist as a relationship in this codebase — dropped.)
  Per-relationship traversal direction is a **constant table**, not a
  parameter (decided 2026-07-27):
  - `supports` / `corroborates` / `elaborates`: **incoming**
    (evidence→claim).
  - `decomposes_to`: **incoming** — ingestion writes paragraph→atom
    (owner-confirmed; matches the compound-paragraph/atom self-loop
    guard in `tools/ingestion.rs:610`), so an atom's incoming edge
    yields its parent paragraph.
  - `supersedes`: **outgoing** — `supersede()` writes new→old
    (claim.rs:2046), so a claim's predecessor sits behind its outgoing
    edge.
  The CTE therefore joins a mixed-direction frontier:
  `(e.target_id = c.node AND e.relationship = ANY($incoming)) OR
  (e.source_id = c.node AND e.relationship = ANY($outgoing))`.
- `max_depth`: 1..=8, default 4. Node cap 500 ⇒ `truncated: true`.
- Cycles detected (path-array hits) reported as `cycles: [[ids]]`, not an
  error.
- Include non-current nodes (marked `is_current: false`) — derivation
  history legitimately crosses superseded claims; that's the point of the
  supersedes hop.

### MCP: `get_provenance_chain` (new `tools/provenance_chain.rs`)

```
get_provenance_chain(claim_id, max_depth = 4, relationships = <default set>)
→ { root: claim_id, nodes: [topo-ordered {id, content, truth_value,
    labels, is_current, depth}], edges: [{source, target, relationship}],
    truncated, cycles }
```

No schema change. No `claim_from_row` widening (house rule) — dedicated
row struct.

---

## F3 — Dispute-awareness in `recall()` / `recall_with_context()`

Smallest change, ships first.

### Approach: post-fix batch query, not ANN-SQL surgery

Rather than a LATERAL join inside `search_hybrid_scoped`'s fused CTE
(claim.rs:768) — which risks the HNSW plan — run **one batched follow-up
query** over the returned ids (the same post-fix pattern as
`list_by_labels` / `get_by_id` documented in CLAUDE.md):

```sql
SELECT e.target_id,
       count(*)::int AS dispute_count,
       (array_agg(e.source_id ORDER BY src.truth_value DESC))[1:3]
           AS contesting_claim_ids
FROM edges e
JOIN claims src ON src.id = e.source_id AND src.is_current
WHERE e.target_id = ANY($1)
  AND e.relationship IN ('contradicts','refutes')
GROUP BY e.target_id
```

One extra round-trip per recall (≤ limit ids, index on
`edges(target_id)`), zero perf risk to the retrieval path.

### Surface

New fields on the recall hit structs (`RecallHit` in
`tools/recall.rs`, and the engine `recall` row in
`epigraph-engine/src/recall.rs`):

- `dispute_count: u32` (absent/0 when uncontested)
- `is_contested: bool`
- `contesting_claim_ids: Vec<Uuid>` (top-3 by contesting truth_value)

New optional param `exclude_contested: bool = false` (post-filter after
RRF; simpler than the backlog's `min_dispute_count` and covers the stated
use-case "only uncontested memories"). Ranking is unchanged — the signal
informs, it does not re-rank (per MemSyco-Bench: the failure is missing
signal, not ordering).

Applies to `recall`, `recall_with_context`, and the lensed variants —
same post-fix helper for all.

---

## F4 — `sweep_semantic_duplicates`

Retroactive sweep for the pre-novelty-gate duplicate corpus. Builds on
two shipped pieces: `pairwise_cosine_distance` (claim.rs:2615, ≤1000 ids)
and `mark_duplicate`'s guarded edge migration; F1 adds a merge option for
non-identical near-duplicates.

### Repo additions

- `nearest_neighbors_of_claim(pool, claim_id, k)` — per-claim ANN
  self-join (`ORDER BY c2.embedding <=> (SELECT embedding FROM claims
  WHERE id=$1) LIMIT k`, `is_current`, `id != $1`). Mirrors
  `nearest_by_embedding` (claim.rs:738) but seeds from a stored row.
- `enumerate_current_embedded(pool, offset, limit)` — paging cursor,
  `created_at ASC`.

### MCP: `sweep_semantic_duplicates` (new `tools/dedup_sweep.rs`)

```
sweep_semantic_duplicates(
  similarity_threshold: f64 = 0.10,   // cosine distance, <=>
  agent_scope: Option<Vec<Uuid>>,     // default None = cross-agent sweep
                                      // (decided 2026-07-27; the 68.4%
                                      // duplicate corpus spans 20+ agents)
  labels_scope: Option<Vec<String>>,
  dry_run: bool = true,
  limit: usize = 500,                 // claims scanned this call
  offset: usize = 0,                  // resumable paging
)
```

Per call: enumerate a page → per-claim ANN top-5 → collect pairs with
`distance < threshold` → **union-find** into clusters → per cluster pick
survivor = highest `truth_value`, tie-break earliest `created_at`.

- Exclusions: `telemetry`-labeled claims (no embeddings by policy),
  claims with `properties->>'level'` (workflow/spine structure), any claim
  whose `supersedes` is already set.
- `dry_run = true` (default): return
  `{ clusters: [{survivor, duplicates, distances}], merge_candidates }`
  with **no mutation**. `merge_candidates` = clusters whose members are
  near but not content-identical — suggested inputs for F1's
  `consolidate_claims` (agent reviews, synthesizes, merges).
- `dry_run = false`: `mark_duplicate(dup, survivor)` per pair —
  transactional per pair so one collision failure doesn't roll back the
  sweep; failures collected and returned, not fatal.
- Every execute run logs to `behavioral_executions` (pairs marked,
  failures, page window) for auditability and resumability.

Sweeping 450k claims is many calls by design — the reconciler-style daily
cron drives it with advancing `offset`, keeping each call bounded and the
blast radius reviewable.

---

## F5 — Recall audit logging (`recall_events`)

### Migration `058_recall_events.sql`

```sql
CREATE TABLE recall_events (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id             UUID,                 -- nullable: unauthenticated paths
    tool                 TEXT NOT NULL,        -- 'recall' | 'recall_with_context' | ...
    query_text           TEXT NOT NULL,
    query_embedding_hash BYTEA,                -- BLAKE3 of the pgvector literal
    params               JSONB NOT NULL DEFAULT '{}'::jsonb,
    returned_claim_ids   UUID[] NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_recall_events_agent_time ON recall_events (agent_id, created_at DESC);
CREATE INDEX idx_recall_events_time       ON recall_events (created_at DESC);
CREATE INDEX idx_recall_events_claims     ON recall_events USING GIN (returned_claim_ids);
```

`query_embedding_hash` (BLAKE3, via existing `ContentHasher` /
epigraph-crypto) is what makes MOSS-style reproducibility auditing
possible: identical query text + identical hash but different
`returned_claim_ids` ⟹ the corpus changed; same text, different hash ⟹
the **embedder** changed. Raw vectors are not stored (16× the row size
for no additional audit power).

### Write path

`RecallEventRepository::log()` called via `tokio::spawn` **after** the
recall response is built — fire-and-forget, `warn!` on failure, never
blocks or fails the recall (same best-effort contract as post-commit
embedding). Agent id from the PR #361 identity context. The recall
response gains optional `recall_event_id` so agents can cite which
retrieval fed a decision (composes with F1's `reason` and the PROV-O
layer from PR #334).

### Read path

MCP `get_recall_events(agent_id?, claim_id?, since?, until?, limit=50,
offset=0)` — `claim_id` filter uses the GIN index
(`returned_claim_ids @> ARRAY[$claim_id]`): "which queries ever surfaced
this claim."

### Retention (settled 2026-07-27)

Recall volume ≫ claim volume; unbounded growth is real. 90-day retention
via the existing daily-reconciler cron (`DELETE ... WHERE created_at <
NOW() - INTERVAL '90 days'`), configurable env
`RECALL_EVENTS_RETENTION_DAYS`. Approved.

---

## Cross-cutting

- **Tests**: each PR against `epigraph_db_repo_test` (never live DB).
  F1 needs the collision-class tests mirroring
  `audit-edge-collision-mark-duplicate.md`'s matrix plus the new
  cross-source class; F2 needs a cycle fixture; F4's execute path tested
  only in dry-run + single-pair execute.
- **sqlx**: `cargo sqlx prepare --workspace -- --tests` + commit `.sqlx/`
  per PR.
- **Backlog retirement**: on merge of each PR,
  `resolve_backlog_item(<claim-id>, <resolution>)` — never bare
  free-text resolves.
