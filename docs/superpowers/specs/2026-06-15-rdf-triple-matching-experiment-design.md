# RDF Triple Substrate → Cross-Source Matching: Experiment Design

**Date:** 2026-06-15
**Status:** Design — pending user review, then implementation plan
**Branch:** `exp/rdf-triple-matching` (worktree `/home/jeremy/epigraph-wt-triples-exp`, off `origin/main`)
**Scope:** Contained experiment — populate the empty entity/triple substrate on a 4,034-claim slice and measure whether triple/entity signals move cross-source claim matching. Not a production rollout.

---

## 1. Problem & current state (measured, not assumed)

The cross-source matcher already wires two structural features — `triple_overlap` (weight 0.15) and
`entity_jaccard` (weight 0.10) — as features #2 and #3 of its 9-feature scorer
(`crates/epigraph-engine/src/matching/scorer.rs`). `SharedTripleBlocker` is also instantiated in
`run_pipeline`. **But the data substrate is empty**, so both features are inert.

Measured against the live `epigraph` DB (2026-06-15):

| Table | Rows |
|-------|------|
| `claims` (is_current) | 436,027 |
| `entities` (canonical) | **0** |
| `triples` | **0** |
| `entity_mentions` | **0** |
| `match_candidates` | 12,442 |

All 12,442 stored candidates have `triple_overlap = 0` and `entity_jaccard = 0` in their `features`
JSON. The matching code is fully wired; it is **starved of data**. The missing piece is an
**extraction pipeline** turning claim text → entities + triples. That code does not exist in this
repo, but a complete implementation and an approved design **do** exist in EpigraphV2 and were never
ported into the collapsed `epigraph` repo:

- `EpigraphV2/scripts/extract_triples.py`, `scripts/lib/{spacy_extractor,llm_extractor,triple_extractor}.py` (~1,150 LOC)
- `EpigraphV2/docs/superpowers/specs/2026-04-08-rdf-triple-ner-knowledge-graph-design.md` (full schema + ontology + extractor protocol + dedup design)

The triple/entity tables (`entities`, `entity_mentions`, `triples`, `entity_merge_candidates`)
already exist in this repo's migration `001_initial_schema.sql`. **No new schema migration is
required.**

## 2. Hypothesis (refined by the data)

> Extracting and canonicalizing entities/triples for the 4,034 claims in the candidate set will make
> `triple_overlap` and `entity_jaccard` carry **discriminative signal** for true cross-source
> matches, and `SharedTripleBlocker` will surface true pairs that embedding-blocking missed.

The naive framing — "re-score the 12,442 candidates and watch the score go up" — is **wrong**, for
two evidence-based reasons (Sections 6 and 7). The honest hypothesis splits into a **signal-validity**
claim (weight-independent) and a **recall** claim (the blocker probe), with fixed-weight re-ranking
as a secondary, caveated measurement.

## 3. Scope & non-goals

**In scope:**
- Port V2's two extractors (`spacy`, `llm`/Claude-OAuth) behind the `TripleExtractor` protocol.
- Benchmark both against a hand-annotated gold set, pick the winner.
- Populate entities + entity_mentions + triples for the 4,034 candidate claims (via API).
- Entity canonicalization (link-then-merge) — **on the critical path** (Section 4).
- Re-score the 12,442 candidate pairs and run the measurement suite (Section 6).

**Out of scope (deferred):**
- Dempster–Shafer / belief integration (V2 design defers it; matcher is a query/discovery layer).
- Full 436K backfill.
- Matcher weight/band recalibration (`calibrate_matcher`) — confounds with the in-flight #239
  precision sweep; kept as a *downstream recommendation*, not part of this measurement.
- Any write to the production `epigraph` DB.

## 4. Critical-path insight: entity canonicalization is mandatory

`triple_overlap` is `Jaccard` over `(subject_id, predicate)` **sets of canonical entity IDs**
(`scorer.rs`, SQL Query 2). If claim A mentions "DNA origami" and claim B mentions "DNA-origami" and
they receive **distinct** entity rows, `subject_id` never matches and the feature stays 0 *even with
triples present*. Therefore entity canonicalization (embedding-NN within `type_top` + name/Levenshtein,
per-type thresholds, non-destructive merge per V2 §4) is **required for the matching signal to fire
across sources** — it is not an optional add-on. This is the single biggest correctness risk in the
experiment.

## 5. Isolation ("experimental branch and database")

- **Git:** worktree `/home/jeremy/epigraph-wt-triples-exp`, branch `exp/rdf-triple-matching`, off
  `origin/main` (per the worktree + branch-from-public conventions).
- **DB:** **full clone** of prod `epigraph` (12 GB; 46 GB free on `/`) → `epigraph_triples_exp`.
  Full clone, not a 4,034-claim subset, because `graph_overlap` (Adamic–Adar) reads the **whole edge
  neighborhood**; a subset clone would silently corrupt that feature. All required tables already
  exist; only `triples`/`entities`/`entity_mentions` get populated.
- **API:** an isolated `crates/epigraph-api/src/bin/server.rs` instance on a staging port bound to
  `epigraph_triples_exp`. Extraction writes go through the API batch endpoints (the no-raw-SQL
  mutation rule); reads use a read-only psql connection. Production API/DB untouched.

## 6. Measurement (evidence-grounded, honest ordering)

Ground-truth reality (measured): of the 12,442 candidates, only **~76 carry real LLM adjudications**
(`same`=10, `paraphrase`=29, `overlapping`=34, `contradicts`=3). The other **12,366 "distinct"
verdicts are placeholders** — their rationale is literally `"count-only run; verifier skipped"`. So
the **negative class is effectively unlabeled**, and the ~76 real positives all sit at `score ≥ 0.80`
and `embed_cosine ≥ 0.746` (embedding already separates them). Consequences drive the ordering below.

### 6a. Signal validity — PRIMARY, weight-independent
The real scientific question: once populated, do `triple_overlap` / `entity_jaccard` discriminate true
matches from non-matches, independent of the scorer's weights?
- For the ~76 real positives vs. a **freshly verifier-labeled negative sample** (we generate labels —
  see 6e), compare raw feature-value distributions and compute per-feature AUC / PR.
- Reported per feature alone, so the renormalization confound (6c) cannot mask it.

### 6b. Blocker-recall probe — PRIMARY
The candidate pool was generated **while the triple blocker was dead**, so 100% of candidates are
embedding/theme/content-hash selected. Re-scoring them therefore measures **re-ranking only** and
*structurally cannot* measure recall — triples' biggest value. Probe it directly:
- After population, run `SharedTripleBlocker` over the 4,034 claims and collect `(subject_id,
  predicate)`-sharing pairs **not already in the 12,442**.
- Verify a stratified sample with the LLM verifier; count true matches that embedding-blocking missed.
- **Honest scope limit (state in the report):** extraction covers only the 4,034 claims, so this
  probes **intra-set** recall. Full recall measurement requires the broader backfill deferred in §3.

### 6c. Fixed-weight re-ranking lift — SECONDARY, caveated
`renormalized_score` excludes `None` features. Today, with no triples, `triple_overlap` is `None`
(empty Jaccard → SQL NULL) and is **excluded** entirely (the stored `features.triple_overlap = 0.0`
is just an `unwrap_or(0.0)` display default). After population:
- A pair whose claims have triples **but no shared** `(subject, predicate)` gets `Some(0.0)` → now
  **included** as 0 with weight 0.15 → **dilutes** the score (it drops).
- A pair that **does** share raises the score **iff** the Jaccard exceeds the pair's current weighted
  average (`(N+wv)/(D+w) > N/D ⟺ v > N/D`); a modest overlap on an embed-dominated pair can still
  dilute.

So fixed-weight lift is **non-monotonic** and likely ~null on this embed-easy labeled set. We report
it with this caveat. If signal validity (6a) is positive but fixed-weight lift is not, the conclusion
is concrete and actionable: *triples are informative; the scorer's renormalization/weights must change
to exploit them* (a downstream `calibrate_matcher` task, out of scope here).

### 6d. Extractor scorecard
spaCy vs LLM on the gold set: entity precision/recall, triple precision/recall, cost, latency.
Winner runs over all 4,034.

### 6e. Ground-truth strategy
Because stored negatives are unlabeled, the **LLM verifier is the labeling oracle**. We hand-annotate
a ~60–80 claim **extraction gold set** (stratified from the 4,034: entity-dense / predicate-dense /
cross-source-overlap / edge cases, sampling the *scientific* claims and skipping `"Body"`-type
garbage) for the extractor benchmark (6d), and we use the verifier to label match pairs of interest
for 6a/6b.

## 7. Data realities & caveats (so the report doesn't over-claim)

- **4,034 distinct claims** are touched by the 12,442 candidate pairs — a small, cheap extraction
  target (LLM pass is trivial on prepaid OAuth).
- **Negatives are unlabeled** ("count-only; verifier skipped"); only ~76 positives are real and they
  are embed-easy. → Cannot compute trustworthy precision/recall from stored verdicts; must generate
  labels (6e).
- **Corpus is mixed:** genuine science (MEMS/NEMS resonators, ¹³C NMR, magnetic flux vortices,
  mode-locked OPO lasers, multi-agent-debate LLM work — all triple-friendly) **plus** operational
  noise (`workflow_step` ×495, `graph-integrity`, `backlog`, `daily-journal`, empty `"Body"` rows).
  The ~76 existing positives skew operational/self-referential (graph-integrity audits, sheaf-cohomology
  runs) — part of *why* embedding alone already separates them. Gold-set stratification targets the
  scientific subset; the extractor skips garbage.
- **Selection bias** (restated): re-ranking conclusions apply only to embedding-selected candidates;
  the recall probe (6b) is the only venue where embedding-missed matches can appear.

## 8. Success criteria (go / no-go)

The experiment **succeeds as an experiment** if it returns a defensible verdict, positive or negative,
on each:
1. **Signal:** do `triple_overlap`/`entity_jaccard` separate verifier-confirmed matches from negatives
   (AUC materially > 0.5)?
2. **Recall:** does `SharedTripleBlocker` surface ≥1 verifier-confirmed true match absent from the
   12,442 (existence proof of recall value), and at what rate?
3. **Extractor:** which extractor wins on precision/recall/cost, and is its triple yield high enough
   to matter (non-trivial fraction of the 4,034 produce ≥1 canonicalizable triple)?

A null result on (1)+(2) — *with* the caveats controlled — is a valid, useful outcome: it says the
triple layer does not earn its extraction cost **on this slice/corpus**, and bounds where it might
(scientific-dense backfill).

## 9. Risks

| Risk | Mitigation |
|------|------------|
| Entity canonicalization too weak → IDs don't unify → signal can't fire | Port V2 link-then-merge with per-type thresholds; validate on gold cross-source entity links before trusting re-score |
| Renormalization dilution masks real signal | Lead with weight-independent signal validity (6a); report fixed-weight lift only as caveated secondary |
| Selection bias hides recall | Dedicated blocker-recall probe (6b) with explicit intra-set scope limit |
| Operational/noise claims pollute extraction | Gold set + extraction skip garbage; report yield on scientific subset separately |
| Tiny positive set (~76) → low statistical power | Generate additional labels via verifier oracle (6e); report confidence intervals; treat as existence proofs not rates where N small |
| Full-DB clone disk/time | 12 GB into 46 GB free is safe; clone once, reuse |

## 10. Sequence of work (high level — detailed plan via writing-plans)

1. Clone prod `epigraph` → `epigraph_triples_exp`; stand up isolated API on staging port.
2. Port V2 extractors behind `TripleExtractor` protocol (spaCy + LLM).
3. Build extraction gold set (~60–80 stratified scientific claims); annotate.
4. Run both extractors on gold; score; pick winner (6d).
5. Run winner over all 4,034 candidate claims → entities/mentions/triples via API.
6. Canonicalize entities (link-then-merge); validate against gold cross-source links.
7. Re-score the 12,442 with `cross_source_sweep --dry-run` against the experimental DB.
8. Run measurement suite: signal validity (6a), blocker-recall probe (6b), fixed-weight lift (6c).
9. Write go/no-go report; recommend (or not) weight recalibration + scientific-dense backfill.

## 11. Deliverables

- Reusable extractor port (if it earns its cost).
- Go/no-go report answering the three success criteria with controlled caveats.
- Recommendation on downstream work (weight recalibration, broader backfill).
