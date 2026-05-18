# Cross-Source Anchor: Linking Paper Claims to Textbook Concepts

**Date:** 2026-05-18
**Status:** Design — awaiting review
**Author:** Jeremy Barton (with Claude)

## Problem

EpiGraph holds two large hierarchical extractions that have nothing connecting them today:

- **Textbooks** — 22,007 claims across L0–L3 (114 documents, 781 sections, 3,773 paragraphs, 17,339 atoms). Pedagogical, definitional, slow-moving, vetted.
- **Papers** — 3,437 claims across L0–L3 (25 documents, 222 sections, 841 paragraphs, 2,349 atoms). Empirical, specific, frontier.

Paper atoms and textbook atoms generally do **not** cosine-match. The textbook says *"Bernoulli's equation handles the general case in which pressure, velocity, and height all change between two points on a streamline"*; a paper says *"growth at 500 °C minimized poor growth regions by increasing adatom mobility."* These live in adjacent conceptual territory but share almost no surface vocabulary. As a result:

1. Frontier paper claims have no conceptual context — a user reading a paper atom cannot navigate up to "what concept is this an instance of?"
2. Papers that share a conceptual anchor but no surface vocabulary (e.g., two thin-film deposition papers using different temperature regimes) cannot find each other via embedding similarity.
3. The existing `claim_themes` layer is one abandoned k-means pass: 16 themes, all labeled `auto-00` … `auto-15`, only 500 of 420K claims assigned, no human-meaningful concept structure.

A prior pure-embedding attempt (call it approach A) failed to bridge papers to textbooks because the wording gap is too wide. The workaround at the time was to ingest **review papers** as intermediate bridges (review papers share vocabulary with both frontier papers and textbooks). That's not just an embedding crutch — review papers carry the field's *interpretation* of which findings instantiate which concept, which is epistemically distinct from both empirical specifics and canonical pedagogy.

## Goals

1. **Conceptually anchor each paper claim** to the textbook concept(s) it instantiates.
2. **Use shared conceptual anchors as bridges** between papers that share no surface vocabulary.
3. **Reuse and complete existing theme infrastructure** — populate `claim_themes` with meaningful labels and restore the missing tooling that the nightly maintenance workflow already assumes exists.
4. **Preserve the natural three-tier knowledge structure** (textbook concept ← review paper integrative claim ← frontier paper empirical claim) without forcing every frontier claim through a review-paper bridge.

Non-goals (this spec):

- New GUI for browsing anchors. Existing diverse-search and bridge-sweep readers consume `claim_themes.label`; readable labels are the immediate win.
- Replacing or merging duplicate claims across sources. Cross-source matching is a relation, not a merge — `mark_duplicate` and the dedup scripts stay separate concerns.
- New belief-propagation semantics. `INSTANTIATES` is descriptive ("X is an instance of Y"), not corroborative ("X supports Y"). Wiring it into CDST is a follow-up.

## State of the art (verified 2026-05-18)

### What exists in `epigraph` (public)

- **`claim_themes` table** with `label`, `description`, `centroid vector(1536)`, `centroid_3072 vector(3072)`, `claim_count`. HNSW index on both centroid dims. FK from `claims.theme_id` (single-valued).
- **`theme_kmeans.rs`** (engine): linfa-based elbow-search k-means. Drives `POST /api/v1/themes/build-from-corpus` and the `theme_cluster_rebuild` cron job in `epigraph-jobs`. Has only ever been run once on this corpus → produced the 16 `auto-NN` themes.
- **`theme_cluster.rs`** (engine): xMemory-inspired k-means with sparsity score `N²/(K·Σnₖ²)`. Lower-level companion to `theme_kmeans.rs`; helpers for cosine sim, centroid mean, nearest-centroid assignment.
- **`diverse_select.rs`** (engine): xMemory submodular diverse selection (coverage + relevance, alpha-weighted).
- **`/api/v1/search/semantic?diverse=true`** (`routes/search.rs:539`): query → top-K themes → submodular per-theme coverage selection. Already consumes `claim_themes.label` — readable labels improve this path for free.
- **`/api/v1/clusters/build-from-bridges`** (`routes/clusters.rs`): Louvain over `decomposes_to` paragraph bridges. Separate cluster artefact (`graph_clusters`, `claim_cluster_membership`); not the same as themes.
- **`/api/v1/graph/neighborhoods/:id/expand`** (`routes/graph_neighborhood.rs`): expands a graph neighborhood; compound + atomic modes. Edge-graph centric, not embedding-distance centric.
- **`bridge/spine.rs`** (`epigraph-cli`): cross-component candidate sweep, aggregates by `claim_themes.label` as "umbrella" — today shows `auto-08`; will show meaningful section names once seeded.
- **`hypothesize()`** (`routes/experiments.rs:78`): takes `(statement, search_radius)`, embeds the statement, returns the 50 nearest claims and a similarity-weighted prior belief. No clustering despite what the nightly workflow text claims.

### What the nightly workflow assumes — but does not exist

The stored "Run k-means theme maintenance on knowledge graph claims" workflow (claim `10ed2ff2`) has steps that reference two capabilities not present in code:

- **`embedding_neighborhood_density(query=...)`** — referenced as "measure cluster density"; absent from every codebase searched. Likely lost in the EpiGraphV2 migration (no V2 archive on disk).
- **`hypothesize(statement, cluster_count=8, search_radius=0.25)`** — `cluster_count` is undocumented on the endpoint and unused by the handler. The workflow describes "trigger k-means landscape clustering over all claims," which the current handler does not do.

Both must be (re)built. The cross-source anchor pass can use them as diagnostics (which textbook sections are paper-dense, which embedding neighborhoods are uniform vs. clumpy).

### What's NOT a problem

- `epigraph-internal` is a smaller/older slice of public `epigraph`; the engine files we care about (`theme_cluster.rs`, `belief_gate.rs`, `diverse_select.rs`, `experiments.rs`) are byte-identical between repos. There is nothing to "port from internal." The split is real but doesn't affect this work.

## Decisions

| # | Decision | Choice | Why |
|---|---|---|---|
| 1 | What kind of match? | Conceptual anchoring (paper → textbook concept), then derived paper-paper bridges via shared anchor | User intent. Atomic claims layer is the primary vehicle. |
| 2 | Matching mechanism | HNSW embedding shortlist → LLM "is-instance-of" judge that also emits a short named anchor concept | Pure cosine misses empirical↔pedagogical wording gap; LLM produces confidence and interpretable label. |
| 3 | Review-paper handling | Parallel anchor layers — frontier→review AND frontier→textbook edges both allowed | Better coverage; review-paper edges retain the field's interpretation when it exists. |
| 4 | Concept-node data model | Reuse `claim_themes`. Seed themes from the textbook hierarchy; LLM emits labels. | Existing infra: HNSW centroid index, diverse-search top-K navigation, bridge-sweep umbrella aggregation. All three consume `claim_themes.label`. |
| 5 | Theme grain | Textbook **L1 sections** (~781 themes), with optional LLM-driven sub-splits guided by density signal | One coherent concept per section; section titles seed labels well; ~781 is healthy for diverse-search top-K. Density tool lets us subdivide hot sections. |
| 6 | Multi-anchor | Primary `theme_id` (existing FK) + `INSTANTIATES` edges for secondaries | Existing diverse search reads only `theme_id` — keeps working out of the box. Multi-concept atoms get edges. No junction-table migration. |
| 7 | Paper-paper bridges | Query-time SQL only (no materialized `CO_ANCHORED` edges initially) | `bridge/spine.rs` already aggregates by `theme_id`. Materializing N² intra-theme edges adds rows without solving a known latency problem. |
| 8 | Review/frontier classification | One-shot LLM batch over the 25 paper L0 rows → set `properties.document_type ∈ {review, frontier}` | Cheap. Run before anchor pass so `INSTANTIATES` edges carry the layer-correct target. |
| 9 | Missing tools | Build `embedding_neighborhood_density` and extend `hypothesize` with `cluster_count` as part of this work | Nightly maintenance workflow already references both; building them makes the loop runnable end-to-end and gives the anchor pass real diagnostics. |
| 10 | Existing auto-NN themes | Drop on textbook-seed run; pause `theme_cluster_rebuild` cron until we decide its long-term role | 16 unlabeled themes with no semantic meaning; their 500 assignments are noise. Cron stays disabled, not deleted — k-means may regain a fallback role for non-textbook claims. |

## Architecture

Seven components, each shippable independently.

### Component 0: Restore `embedding_neighborhood_density` + extend `hypothesize`

**Goal:** make the nightly maintenance workflow's stored steps actually executable, and give the anchor pass real diagnostics.

**0a. `embedding_neighborhood_density`** — new endpoint and MCP tool.

- **Endpoint:** `POST /api/v1/embeddings/neighborhood-density`.
- **Request:** `{ query: string, radius: float (default 0.30), max_sample: int (default 500) }`.
- **Logic:**
  1. Embed `query` via the existing embedding service.
  2. Single SQL: `SELECT COUNT(*) AS n, AVG(1 - (embedding <=> $1::vector)) AS mean_sim, percentile_cont(0.5) WITHIN GROUP (ORDER BY 1 - (embedding <=> $1::vector)) AS median_sim FROM claims WHERE embedding IS NOT NULL AND 1 - (embedding <=> $1::vector) >= $2`. HNSW-backed; fast.
  3. Optionally sample top-`max_sample` claims for downstream summary stats (level distribution, source_type distribution).
- **Response:** `{ n_claims: int, mean_similarity: float, median_similarity: float, sparsity: float, by_level: {0:n, 1:n, 2:n, 3:n}, by_source_type: {Textbook:n, Paper:n, ...} }`. `sparsity = 1 / (1 + n_claims / target_n)` or similar squashing — actual formula TBD but bounded [0, 1].
- **MCP tool:** wrap as `mcp__epigraph__embedding_neighborhood_density(query, radius=0.30, max_sample=500)`. Returns the same JSON.
- **Files:** `crates/epigraph-api/src/routes/embeddings.rs` (new), `crates/epigraph-mcp/src/tools/embeddings.rs` (new or add to existing tools module).

**0b. Extend `hypothesize` with `cluster_count`**

- **Request schema:** add `cluster_count: Option<u32>` (default `None`).
- **Behaviour when `cluster_count = Some(k)`:**
  1. Run existing similar-claim retrieval (top-N where N = max(50, k·10)).
  2. Run mini k-means on those embeddings with `k` clusters (use existing `theme_cluster::cluster_embeddings`).
  3. Return additional response field `clusters: [{ centroid_summary: text (LLM-emitted), claim_ids: [uuid], mean_prior_belief: float }, ...]`.
  4. `centroid_summary` requires an LLM call per cluster (≤ k calls); call asks "summarise these N claims in one phrase."
- **Behaviour when `cluster_count = None`:** unchanged from today.
- **File:** `crates/epigraph-api/src/routes/experiments.rs`.

### Component 1: Paper document-type classifier

**Goal:** label each paper L0 row as `review` or `frontier` so the anchor pass routes correctly.

- **Input:** 25 paper L0 claims (`properties->>'source_type' = 'Paper' AND properties->>'level' = '0'`).
- **Logic:** LLM call per paper with `(title, abstract or first L1 child content)`. Prompt returns `{ document_type: "review" | "frontier", confidence: float }`.
- **Output:** PATCH `properties.document_type` and `properties.document_type_confidence` on the L0 row. Descendants inherit at query time via `decomposes_to` walk (no denormalisation).
- **Form:** `scripts/classify_paper_document_type.py`. Idempotent. ~25 LLM calls, seconds.

### Component 2: Textbook-seeded theme rebuild

**Goal:** replace the 16 abandoned `auto-NN` themes with ~781 textbook-L1-seeded themes carrying meaningful labels.

- **Input:** all current textbook L1 claims.
- **Per-L1 logic:**
  1. Pull the L1 claim and its `decomposes_to` descendants.
  2. Call `embedding_neighborhood_density(query=L1_content)` to gauge how paper-dense this concept's neighborhood already is. If `n_claims` in radius 0.30 is very high (>200) AND mostly paper rather than textbook, flag for LLM sub-splitting (next bullet).
  3. **Sub-split decision:** when flagged, call `hypothesize(statement=L1_content, cluster_count=3)` over the dense neighborhood; if the returned clusters are clearly distinct (centroid summaries differ semantically per LLM judge), emit 2–3 themes for this L1 instead of 1.
  4. Compute theme centroid as the mean of the L1 + descendant embeddings (both 1536 and 3072 dims in one pass).
  5. Call LLM to emit `label` (≤ 60 chars, e.g., *"Bernoulli's Equation — Streamline Form"*) and `description` (≤ 250 chars).
  6. INSERT `claim_themes` row.
  7. Backfill `claims.theme_id` on the L1 claim and its `decomposes_to`-descendants.
- **Theme metadata:** store originating textbook claim ID in `claim_themes.properties.source_textbook_claim_id`. Requires adding a `properties JSONB DEFAULT '{}'` column to `claim_themes` (small migration).
- **Existing 16 `auto-NN` themes:** delete after textbook seed completes, freeing their 500 claim assignments to be re-assigned by Component 3. Capture the audit trail (count, dump) before deletion.
- **Form:** `scripts/seed_themes_from_textbooks.py`. Idempotent — skip themes whose source L1 already has a `theme_id`. Resumable via `--resume-from-textbook-id`.
- **Cost:** ~781 LLM calls for labels + a smaller number for sub-split decisions. Minutes, < $2 at Haiku.

### Component 3: Paper-claim anchor pass

**Goal:** for each paper atom (L3), assign a primary `theme_id` and emit `INSTANTIATES` edges for additional anchors.

- **Input:** all paper L3 claims with embeddings (~2,349 atoms); ~841 L2 paragraphs are an optional second pass.
- **Per-claim logic:**
  1. HNSW lookup against `claim_themes.centroid` — top-K candidate themes (K = 8).
  2. Filter by similarity threshold (default 0.45 cosine; calibrate against a 50-claim hand-labeled sample first).
  3. For each surviving candidate, LLM "is-instance-of" judge: `(paper claim content, theme label, theme description) → { verdict: yes|maybe|no, confidence: float, refined_anchor_label: text }`.
  4. Keep verdicts ≥ `yes`. Fall back to top `maybe` if its confidence ≥ 0.6. Otherwise leave claim unanchored.
  5. **Primary anchor:** highest-confidence verdict → `claims.theme_id`.
  6. **Secondary anchors:** every other surviving verdict → INSERT `INSTANTIATES` edge from paper claim → textbook L1 claim (theme's source). Properties: `confidence`, `anchor_label`, `judge_model`, `created_at`.
- **Layer routing:**
  - **Frontier paper atom:** anchor pass runs twice — once against textbook themes (Component 2's output), once against review-paper L2 paragraph embeddings (Component 4's index).
  - **Review paper atom:** anchor only to textbook themes.
- **Unanchored claims:** keep a small report. They may indicate textbook gaps (the corpus has no concept covering this claim). Don't invent anchors.
- **Form:** `scripts/anchor_papers_to_themes.py`. Batch, resumable. Flags: `--limit`, `--threshold`, `--top-k`, `--layer={textbook,review,both}`.
- **Cost:** ~2,349 atoms × top-8 candidates × 1 LLM call ≈ 19K calls for textbook pass. At Haiku ~$3. Review-pass adds a smaller chunk.

### Component 4: Review-paper bridge layer

**Goal:** materialize frontier→review `INSTANTIATES` edges.

- **Pre-condition:** Component 1 has labeled papers as review vs. frontier.
- **Per frontier paper atom:** HNSW lookup over **review-paper L2 paragraph embeddings** (a smaller index than the theme centroids); LLM judge confirms instantiation; emit edge.
- **No new theme rows** for review papers. Review paragraphs are anchor *targets* via `INSTANTIATES` edges only. (Themes stay textbook-only for now. Revisit if review papers prove to need their own centroid layer.)
- **Form:** subroutine of `anchor_papers_to_themes.py` triggered when `document_type=frontier` and `--layer` includes `review`.

### Component 5: Paper-paper bridge query (no new storage)

**Goal:** answer "which papers share a conceptual anchor with paper X?"

- **No new edges materialized.** Two SQL queries cover the question:
  1. **Same primary theme:** `SELECT c2.id FROM claims c1 JOIN claims c2 USING (theme_id) WHERE c1.id = $X AND c2.id <> c1.id AND ...`.
  2. **Shared `INSTANTIATES` target:** `SELECT e2.source_id FROM edges e1 JOIN edges e2 ON e1.target_id = e2.target_id WHERE e1.relationship = 'INSTANTIATES' AND e2.relationship = 'INSTANTIATES' AND e1.source_id = $X AND e2.source_id <> e1.source_id`.
- **Existing consumer:** `bridge/spine.rs::compute_spine_destination` already aggregates by `claim_themes.label`. With Component 2 done, its output stops showing `auto-08` and starts showing *"Bernoulli's Equation — Streamline Form."* No code change required for that win.
- **Future:** materialize `CO_ANCHORED` edges via a periodic job if query latency demands. Defer until measured.

### Component 6: Wire into nightly maintenance workflow

**Goal:** make the stored "Run k-means theme maintenance" workflow runnable and useful after this work.

- The workflow's existing steps will work once Component 0 lands (`embedding_neighborhood_density` and `hypothesize(cluster_count=N)` become real tools).
- Update the stored workflow body (via `evolve_step` on each affected step claim) to reflect the new anchor-aware behaviour:
  - Replace "trigger k-means landscape clustering over all claims" with "diagnose dense embedding neighborhoods that lack textbook anchors; surface them as candidates for new textbook ingest or theme sub-splits."
  - Add a step: re-run anchor pass for paper claims that newly fell below threshold after belief propagation.
- **The `theme_cluster_rebuild` cron stays paused** for the curated-theme era. If we later want a discover-new-themes pass for non-textbook claims, namespace its label_prefix away from textbook themes (e.g., `discovered-NNN`) and run on `theme_id IS NULL` only.
- **Form:** no new code; one Python script `scripts/update_theme_workflow_steps.py` that uses MCP `evolve_step` calls. ≤ 20 lines.

### New edge relation: `INSTANTIATES`

- **Direction:** `source_id` = paper or review claim; `target_id` = more-general/canonical claim (textbook L1 for direct frontier→textbook; review L2 for frontier→review).
- **`source_type` / `target_type`:** `claim` for both. Layer distinction lives in `properties.source_type` / `properties.document_type` on each side, not in the edge.
- **`edges.properties`:** `confidence` (float), `anchor_label` (text), `judge_model` (string), `created_at` (timestamptz).
- **No migration:** existing `edges` table accepts arbitrary `relationship` strings and JSONB `properties`.
- **Optional partial index** (defer): `CREATE INDEX idx_edges_instantiates ON edges (source_id, target_id) WHERE relationship = 'INSTANTIATES'`.

## Data model summary

**Schema changes are minimal:**

1. **Add `properties JSONB DEFAULT '{}'` to `claim_themes`** (small migration). Used to store `source_textbook_claim_id` and future metadata.
2. **`claim_themes` populated** with ~781 textbook-seeded rows; 16 `auto-NN` rows deleted with audit log.
3. **`edges`** gains `relationship = 'INSTANTIATES'` rows — no schema change.
4. **`claims.theme_id`** set on every textbook claim and every successfully-anchored paper claim.

**No new tables.**

## Pipeline

One-shot bootstrap (order matters):

```
1. Migration: claim_themes.properties JSONB column        (seconds)
2. Build Component 0 (density + clustering hypothesize)   (Rust; build/deploy)
3. classify_paper_document_type.py                        (~25 LLM calls, seconds)
4. seed_themes_from_textbooks.py                          (~1500 LLM calls, ~10 min, ~$2)
5. anchor_papers_to_themes.py --layer=textbook            (~19K LLM calls, ~30 min, ~$3)
6. anchor_papers_to_themes.py --layer=review              (frontier-only pass, smaller)
7. update_theme_workflow_steps.py                         (seconds)
```

Each script is idempotent and resumable. Total wall time: < 1 hour. Total LLM cost: < $10 at Haiku rates.

**Incremental ingest (future work, not in this spec):**

- Hook into `ingest_document` so new paper claims trigger an anchor pass at their L3 atoms.
- Hook into textbook ingest so new L1 sections create new themes.
- Defer until the one-shot bootstrap proves the model.

## Open questions

1. **Threshold calibration.** The 0.45 cosine cutoff and `confidence ≥ 0.6` `maybe` fallback are starting guesses. Calibrate against a 50-claim hand-labeled sample before running at scale.
2. **Density formula.** `sparsity = 1 / (1 + n_claims / target_n)` is a placeholder. Pick a formula that's interpretable to LLM consumers (probably normalised against per-textbook-section baselines).
3. **L2 sub-themes scope.** Component 2 sub-splits an L1 only when the density signal says "dense and paper-heavy." Tune this trigger after first run.
4. **`theme_cluster_rebuild` cron long-term role.** Leave paused; revisit once we see how much of the corpus stays unanchored.
5. **Review-paper inventory.** We don't yet know how many of the 25 papers are reviews. If the answer is ≤ 2, Component 4 yields little value on this corpus — deprioritize.
6. **Embedding dim.** Default 1536D (currently populated). 3072D path stays compatible; textbook-seed script populates both columns when `embedding_3072` is set on the source claim.

## Out of scope (intentionally)

- Replacing the existing `theme_cluster_rebuild` cron job. Paused for now; not deleted.
- Cross-source dedup or merge (use `mark_duplicate` separately).
- Belief propagation through anchor edges. `INSTANTIATES` is descriptive, not corroborative. Wiring it into CDST is a separate design.
- GUI changes. Existing diverse-search and bridge-sweep readers consume `claim_themes.label` already; they upgrade for free.
