---
title: Cross-Source Matching
date: 2026-05-21
status: draft
authors: [Jeremy Barton]
---

# Cross-Source Matching

## Problem

The same underlying fact, finding, or assertion enters EpiGraph through many doors:
a hierarchically-ingested paper, an EpiClaw-memorized note about that paper, a
workflow run that cites it, a textbook chapter covering the same topic, a
re-ingestion after the source was updated. Today, each of these arrives as an
independent claim with no link to its cross-source peers. Belief propagation
sees them as unrelated evidence, search lists them as separate near-identical
results, and the graph has no way to express "these are the same thing, told
twice."

The primary use case is **provenance bridging (D)**: detect when claims from
*independent* provenance assert the same thing, and emit a typed link. Two
downstream use cases ride on this: **DST evidence aggregation (C)** — bridged
peers pool their masses under Dempster's rule with discounting — and **dedup
(A)** — destructive merge via the existing admin-only `mark_duplicate` path.

## Relationship to Existing Work

Phase 7 (ratified 2026-05-06, spec `2026-05-05-cross-component-bridge-sweep-design.md`)
ships a **component-level bridge sweep**: union-find over the compound graph,
find disconnected components, HNSW kNN from each small component into the
giant, LLM rerank via `rerank_bridges::rerank_candidates_table`, write edges.

That work is the substrate this spec builds on. It does **not** solve cross-source
matching by itself because:

1. Its filter is **structural** (component pair), not **provenance** (paper /
   agent / ingestion). Two atoms in the same component can still be from
   independent sources that should be bridged; two atoms across components
   can be same-source noise (e.g., one agent's notes about two papers in
   different components).
2. Its blocker is **embedding ANN only**. Strong cross-source signals like
   shared triple `(subject, predicate)`, theme co-membership, and
   compound-neighborhood overlap go unused.
3. Its candidate persistence is **per-run temp tables** (locked-in
   commitment 5.4). There's no durable store to support a review queue, a
   DST aggregation hook, or cross-run dedup of candidates.

This spec adds the source-aware layer on top: a **source-key filter**, a
**multi-signal blocker**, a **durable `match_candidates` store**, and an
**MCP/API review queue**. It reuses what already exists:

| Reused                                                  | This spec adds                          |
| ------------------------------------------------------- | --------------------------------------- |
| `rerank_bridges::rerank_candidates_table` (LLM verifier) | Source-key filter                       |
| HNSW index from migration 030                           | Multi-signal blocker (beyond ANN)       |
| `epigraph_engine::reconciliation::UnionFind`            | Durable `match_candidates` + state mach |
| Edge types `CORROBORATES`, `same_as`, `same_source`     | DST evidence-pool wiring on `CORROBORATES` |
| `mark_duplicate` admin path                             | MCP/API review surface                  |

No new edge type is introduced. Matches with provenance-distinct claims and
high confidence are written as `CORROBORATES` (the existing "cross-source
corroboration" relationship per `edges.rs:88`); same-text dedup remains
`same_as`; intra-source structural links remain `same_source`.

## Goals

1. Source-agnostic detection of cross-source claim ≈ claim matches.
2. Output is *match candidates with confidence*, not destructive merges.
3. A separate policy layer turns candidates into `BRIDGES` edges, DST inputs,
   or human-reviewed dedup decisions.
4. Calibrated on SciFact; precision ≥ 0.95 in the auto-promote band.

## Non-Goals (out of scope for this spec)

- Entity ↔ Entity matching (people, orgs, concepts). Adjacent; deferred.
- Methodology ↔ Methodology, workflow-run ↔ workflow-run. Specialized; deferred.
- Paper ↔ Paper dedup. Already handled by `papers_doi_unique_constraint` (migration 097).
- Real-time on-ingest hook. Designed as Phase 2; this spec covers batch + MCP.
- A learned classifier. Deferred until the review queue accumulates labels.

## Architecture

Pipeline shape:

```
   blocker  →  scorer  →  band?  →  policy  →  output
```

- **blocker** generates O(M) candidate pairs from O(N²) possible pairs.
- **scorer** is a pure function producing features + a [0,1] score per pair.
- **band** classifies score into `high | mid | low`; `mid` invokes LLM verifier.
- **policy** writes a `match_candidate` row and optionally a `BRIDGES` edge.

All four are independent, testable units. Three drivers call this pipeline:
batch sweep, MCP tool, and (Phase 2) ingest-event subscriber.

### Components

#### 1. `source_key(claim) → SourceKey`

Defines what counts as "same source" for filtering. A pair is filtered out
(not scored) when their `SourceKey`s **share any non-null component**.

```rust
struct SourceKey {
    paper_id:        Option<Uuid>,    // claims.paper_id
    agent_id:        Uuid,            // authorship via AUTHORED edge
    ingestion_run:   Option<Uuid>,    // claims.ingestion_run_id (new column)
    derivation_root: Option<Uuid>,    // chase derived_from chain to root
}
```

Filter rule: pair `(a, b)` is **same-source** iff
`a.paper_id == b.paper_id (both non-null)` OR
`a.ingestion_run == b.ingestion_run (both non-null)` OR
`a.derivation_root == b.derivation_root (both non-null)`.

These three components define **provenance-of-the-claim** (where it came
from in the ingestion graph). Same-source pairs are dropped entirely.

**Open choice: should `agent_id` equality also count as same-source?**
Including it makes the matcher stricter (e.g., two papers by the same
author asserting the same finding would be filtered out — even though
those are exactly the cross-source corroborations one would want to
find). Excluding it admits some same-author cross-paper matches. The
default in this spec is **excluded** (provenance-only, not authorship);
exposed as a configurable flag `matcher.filter.include_agent_id` for
operators who want the stricter rule. Defer the calibration of which
default to use to the SciFact tuning run.

#### 2. Blocker

Pluggable strategies, results unioned and source-filtered:

| Strategy                  | Recall | Cost  | Backed by                          |
| ------------------------- | ------ | ----- | ---------------------------------- |
| Embedding ANN (top-K=50)  | High   | Low   | `embeddings` table + pgvector      |
| Theme cluster co-member   | Med    | Tiny  | `theme_clusters` (migration ~090)  |
| Compound nbhd co-member   | Med    | Tiny  | `graph_neighborhoods` (mig 026)    |
| Shared triple (subj,pred) | Low-Med| Low   | `entity_triples` (mig 091)         |
| Content-hash prefix       | Low    | Tiny  | `claims.content_hash` (mig 107)    |

Each strategy yields candidate pairs `(claim_a_id, claim_b_id)` in canonical
order (`claim_a_id < claim_b_id`). Union with dedup. Apply source filter.

#### 3. Scorer

Pure function `score(a: Claim, b: Claim) → MatchFeatures` where:

```rust
struct MatchFeatures {
    embed_cosine:      f32,   // 0..1
    triple_overlap:    f32,   // Jaccard of (subject,predicate) sets
    entity_jaccard:    f32,   // Jaccard of extracted named entities
    method_match:      bool,
    nbhd_overlap:      f32,   // Jaccard of compound-neighborhood node sets
    citation_overlap:  f32,   // Jaccard of cited papers
    temporal_dist_days: i32,
    score:             f32,   // weighted combiner, 0..1
}
```

Combiner is a hand-tuned weighted sum, weights in `calibration.toml`:

```toml
[matcher.weights]
embed_cosine     = 0.40
triple_overlap   = 0.20
entity_jaccard   = 0.15
method_match     = 0.10
nbhd_overlap     = 0.10
citation_overlap = 0.05
# temporal_dist_days used as soft penalty; not a positive signal

[matcher.bands]
high = 0.85   # auto-promote
mid  = 0.60   # send to LLM verifier
# below mid → drop

[matcher.embedding]
model_version = "v1"
```

Calibrated on SciFact; embedding model version recorded so a model swap
forces recalibration.

#### 4. LLM Verifier (mid band only) — Reuse `rerank_bridges`

The mid band invokes the `rerank_bridges::rerank_candidates_table` library
entry-point. **This is a Phase 7 deliverable** (spec §2.2, plan task 2 —
refactoring the existing 1206-line CLI into a library + thin CLI shell);
verify it has shipped before starting this spec's implementation. If
Phase 7 has not yet landed the refactor, this spec depends on it and
should not be planned independently.

The candidate-pair table our matcher produces conforms to that function's
expected schema
(`source_id uuid, target_id uuid`, plus optional metadata columns), so
verification is one library call:

```rust
let report = rerank_bridges::rerank_candidates_table(
    &pool,
    &candidate_table_name,
    RerankArgs { dry_run: !auto_apply, /* … */ },
)?;
```

Notes:

- Provider follows the host repo's convention (`claude-cli` in internal,
  Anthropic SDK in public) per the existing `rerank_bridges` divergence —
  not our concern here.
- The reranker writes its own edges with LLM-chosen relationships when
  `--apply` is passed. We disable that path (`dry_run: true`) and consume
  the returned verdicts ourselves, writing into `match_candidates` and (for
  the high band) emitting `CORROBORATES` edges via the policy layer.
- Verdict mapping from the reranker's relationship vocabulary
  (`refines | supports | elaborates | derives_from | contradicts | analogous`):
  - `supports` or `elaborates` → `same` for matcher purposes
  - `analogous` → `paraphrase`
  - `refines` → `overlapping_but_distinct`
  - `contradicts` → `distinct` (and surfaces a contradiction signal — see §Failure Modes)
  - `derives_from` → `distinct` (related-but-not-same)
- Verdict and rationale stored on the match-candidate row; never re-asked.
- Cost-bounded: only invoked for pairs in the mid band.

#### 5. `match_candidates` table (new migration)

```sql
CREATE TABLE match_candidates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_a         UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    claim_b         UUID NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    score           REAL NOT NULL,
    features        JSONB NOT NULL,
    verifier_verdict TEXT,           -- same|paraphrase|overlapping|distinct|null
    verifier_rationale TEXT,
    status          TEXT NOT NULL,   -- see state machine below
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at      TIMESTAMPTZ,
    decided_by      UUID,            -- agent who promoted/rejected
    CONSTRAINT canonical_order CHECK (claim_a < claim_b),
    CONSTRAINT unique_pair UNIQUE (claim_a, claim_b)
);

CREATE INDEX match_candidates_status_idx ON match_candidates(status);
CREATE INDEX match_candidates_claim_a_idx ON match_candidates(claim_a);
CREATE INDEX match_candidates_claim_b_idx ON match_candidates(claim_b);
```

#### 6. State Machine

```
                  blocker emits pair
                         ↓
                    source-filter?
                  ┌──────┴──────┐
                same           cross
                  ↓              ↓
              [dropped]       scorer
                                 ↓
                              band?
                   ┌─────────────┼─────────────┐
                  high          mid           low
                   ↓             ↓             ↓
              auto-promote   LLM verifier   [dropped]
                   ↓          ┌──┴──┐
              BRIDGES edge   same  distinct
              status=promoted  ↓     ↓
                          auto-promote rejected
```

States: `pending | promoted | rejected | stale`.
A candidate becomes `stale` when either claim is superseded (mig 068) or
duplicate-marked.

#### 7. `CORROBORATES` Edges (existing vocabulary)

The `edges` table already accepts `CORROBORATES` (per
`crates/epigraph-api/src/routes/edges.rs:88` — "claim → claim (cross-source
corroboration)"). High-band auto-promoted matches and admin-approved mid-band
matches are written as `CORROBORATES`:

```text
edges(source_id=claim_a, target_id=claim_b, relationship='CORROBORATES',
      properties = jsonb {
          matcher_run_id,
          score,
          features,
          candidate_id,
          verifier_verdict?,
      })
```

Stored once with canonical ordering (`claim_a < claim_b`); semantics are
undirected.

**DST aggregation is a new deliverable of this spec, not existing behavior.**
Grep confirms `epigraph-engine/src/cdst_bp.rs` does not currently special-case
`CORROBORATES`; `search.rs` only includes it in result-set joins. Wiring
`CORROBORATES` into the CDST BP loop as a discounted evidence-pool operator
— masses from corroborating peers combined via Dempster's rule with discount
`1 - properties.score`, bounded by the fan-out cap — is added work that this
spec owns. Implementation lands as a new propagation step in
`epigraph-engine`, called from the existing BP run. Marked explicitly so
the plan task list reflects it.

When the verifier instead returns a contradiction (`contradicts`), we
write a `contradicts` edge (already in the edges-table vocabulary) rather
than `CORROBORATES`; the match candidate is still recorded with
`status=promoted` because the matcher's *job* — surfacing the cross-source
relationship — succeeded.

### Drivers

1. **Batch sweep** (Phase 1) — cron-scheduled job that iterates claims with
   `last_match_scan_at < watermark`. For each, runs blocker → scorer →
   verifier, writes match_candidate rows, auto-promotes high band. Bound by
   per-run cap on claims processed. Records new `last_match_scan_at`.

2. **MCP tool** `find_cross_source_matches` (Phase 1) — admin-facing tool.
   Args: `claim_id?`, `theme_id?`, `paper_id?` (at least one required), plus
   `min_score?`, `include_low_band?`. Scoped pipeline run; returns candidate
   list without writing edges (read-only by default, with a `commit=true`
   option to persist).

3. **Ingest hook** (Phase 2) — subscribes to `claim.ingested` events via
   existing event bus; pushes `(claim_id, created_at)` onto `match_queue`.
   A separate worker drains rate-limited, calling the same pipeline.

### MCP / API Surface

| Tool / Route                                | Caller    | Purpose                                  |
| ------------------------------------------- | --------- | ---------------------------------------- |
| MCP `find_cross_source_matches`             | agents    | On-demand, scoped match query            |
| MCP `list_match_candidates`                 | admin     | Review queue (status=pending)            |
| MCP `decide_match_candidate(id, verdict)`   | admin     | Promote → BRIDGES, or reject             |
| GET `/api/v1/claims/:id/cross_source_matches` | API     | Read candidates + BRIDGES for a claim    |

`list_match_candidates` and `decide_match_candidate` follow the existing
admin-only pattern (`claims:admin` scope, per
`feedback_dedup_admin_only`).

### Calibration

- **Dataset**: SciFact (1.4K labeled claim–evidence pairs).
- **Positive pairs**: SciFact claims that share supporting evidence on the
  same fact.
- **Hard negatives**: claims on the same topic but different facts.
- **Easy negatives**: random pairs.
- **Targets**:
  - High band (auto-promote): precision ≥ 0.95
  - Mid band (LLM verifier): precision after verification ≥ 0.90
  - Recall at mid threshold: track but no hard target in Phase 1.
- **Per-band metrics persisted** with each calibration run; weights and
  thresholds versioned in `calibration.toml`.

### Crate / Module Placement

Extend `epigraph-engine` with a new `matching` module — sibling of the
existing `reasoning` and `reconciliation` (UnionFind lives there) modules.
The pipeline lives there; drivers are thin:

- Batch sweep: binary in `epigraph-cli`, sibling of `bridge_sweep.rs`. May
  share helpers with `crates/epigraph-cli/src/bridge/` introduced in Phase 7.
- MCP tool: handler in `epigraph-mcp/src/tools/`.
- API route: route in `epigraph-api/src/routes/`.

## Failure Modes & Guards

| Risk                              | Mitigation                                           |
| --------------------------------- | ---------------------------------------------------- |
| Same-source slip-through          | Unit-test `source_key` across all source-type pairs  |
| Embedding model drift             | `embedding.model_version` in calibration.toml; mismatch forces re-calib |
| Adversarial paraphrase / negation | LLM verifier; adversarial test corpus with negations |
| Transitive runaway (A↔B, B↔C → ?) | No transitive auto-promote; cap fan-out per claim    |
| Quadratic explosion in blocker    | ANN top-K cap; per-claim candidate budget            |
| Stale candidates                  | Candidates marked `stale` on supersede / mark_duplicate |
| Council-of-critics on tests       | Adversarial test review (per `feedback_council_of_critics`) |

## Testing

- **Unit**: `source_key` exhaustive cross-product; blocker recall on synthetic
  gold; scorer feature determinism with fixed embedding.
- **Integration**: SciFact subset; per-band F1 / precision; bands recorded.
- **Adversarial**: hand-curated set of negation flips, scope-flips, and
  near-duplicates with crucial differences.
- **Live**: small-DB integration tests against `epigraph_db_repo_test`
  (per `feedback_cluster_graph_test_db`).
- **Council of critics**: every new test reviewed for tautology, mock-shape,
  happy-path-only, trivial round-trips.

## Migrations

1. New: `match_candidates` table (canonical ordering, unique pair).
2. New: `match_queue` table (Phase 2; defer until ingest-hook driver).
3. New column: `claims.last_match_scan_at TIMESTAMPTZ NULL`.
4. New column: `claims.ingestion_run_id UUID NULL` (if not already present —
   verify before writing migration; if absent, derive from `authored` /
   `derived_from` chain instead and skip the column).
5. No edges-table change: `CORROBORATES`, `same_as`, `same_source`, and
   `contradicts` are all already accepted relationships (per `edges.rs:85-88`).
6. No new HNSW index: reuse migration 030 from Phase 7.

### Tension with Phase 7 commitment 5.4 ("temp tables")

Phase 7's locked-in commitment 5.4 is that candidate persistence stays in
temp tables (`bridge_sweep_run_<uuid>_candidates`). That commitment is
scoped to the **per-run input** to the reranker, and this spec does not
break it — our matcher still uses a temp table as the reranker's input.

The new durable `match_candidates` table serves a **different concern**:
the cross-run review queue + DST aggregation hook + state machine for
human-promotion of mid-band candidates. These need durability that a temp
table can't provide. The two structures coexist; 5.4 stays intact.

## Dependencies & Sequencing

Hard dependencies that must land before this spec's implementation starts:

1. **Phase 7 `rerank_bridges` library refactor** — `rerank_candidates_table`
   exposed as a library entry-point (plan task 2). If still a CLI-only
   binary, this spec cannot consume it cleanly.
2. **Migration 030 (partial HNSW on level=3 atoms)** — required for the
   embedding-ANN blocker. Phase 7 deliverable.
3. **`epigraph_engine::reconciliation::UnionFind`** — already exists; just
   verify it's reachable from the new `matching` module.

Internal deliverables this spec owns:

- The `matching` module in `epigraph-engine` (blocker, scorer, source-key).
- The `match_candidates` table + migration.
- The `CORROBORATES`-aware DST aggregation step in the BP loop.
- The MCP tools + API route.
- The batch-sweep binary in `epigraph-cli`.

## Phased Rollout

- **Phase 1** (this spec): scorer + blocker + verifier + match_candidates
  table + batch sweep + MCP tools + API route. Calibrate on SciFact. Run
  manually on dev DB, validate. A feature flag (`matcher.auto_promote`,
  default `false`) gates whether high-band candidates auto-write `BRIDGES`
  edges; flip to `true` once SciFact precision ≥ 0.95 is reproduced on the
  prod DB.
- **Phase 2** (follow-on spec): ingest-event hook + `match_queue` + worker;
  A/B compare against batch.
- **Phase 3** (follow-on spec): generalize to entity-level (B) and
  finding-level (c) matching; learned classifier when review queue has
  ≥1k labels.

## Open Questions for Implementation

- Exact LLM prompt template + few-shot examples — TBD during implementation.
- Per-claim candidate fan-out cap value — tune during calibration.
- Whether `BRIDGES` should auto-fan to DST aggregator immediately or via a
  separate sweep job — leaning immediate; revisit if propagation cost
  spikes.
