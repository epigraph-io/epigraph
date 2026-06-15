# RDF Triple Substrate → Cross-Source Matching: Experiment Design

**Date:** 2026-06-15
**Status:** Design — pending user review, then implementation plan
**Branch:** `exp/rdf-triple-matching` (worktree `/home/jeremy/epigraph-wt-triples-exp`, off `origin/main`)
**Scope:** Contained experiment — populate the empty entity/triple substrate on a **scientific-dense
DNA-origami/nanomachine slice** and measure whether triple/entity signals carry discriminative power
and recover cross-source matches embedding-blocking misses. Not a production rollout.

> **Revision note (supersedes the first committed draft).** The corpus venue changed from the
> 12,442-candidate slice to a scientific-dense slice, and the primary metric from fixed-weight
> re-ranking to **signal-validity + recall probe**, after evidence showed the candidate slice's
> before/after baseline mostly doesn't exist (negatives are unlabeled placeholders; the ~76 real
> positives are embed-easy operational self-matches). See §6/§7.

---

## 1. Problem & current state (measured, not assumed)

The cross-source matcher already wires two structural features — `triple_overlap` (weight 0.15) and
`entity_jaccard` (weight 0.10) — as features #2/#3 of its 9-feature scorer
(`crates/epigraph-engine/src/matching/scorer.rs`), and `SharedTripleBlocker` is instantiated in
`run_pipeline`. **But the data substrate is empty:** the live `epigraph` DB has 436,027 current
claims and **0 entities / 0 triples / 0 entity_mentions**. All 12,442 stored `match_candidates`
carry `triple_overlap = 0` and `entity_jaccard = 0`. The matching code is wired but **starved**.

The missing piece is an **extraction pipeline** (claim text → entities + triples). It does not exist
in this repo, but a complete implementation and an approved design exist in EpigraphV2 and were never
ported into the collapsed `epigraph` repo:

- `EpigraphV2/scripts/extract_triples.py`, `scripts/lib/{spacy_extractor,llm_extractor,triple_extractor}.py` (~1,150 LOC)
- `EpigraphV2/docs/superpowers/specs/2026-04-08-rdf-triple-ner-knowledge-graph-design.md`

The triple/entity tables (`entities`, `entity_mentions`, `triples`, `entity_merge_candidates`) already
exist in this repo's migration `001_initial_schema.sql`. **No new schema migration is required.**

## 2. Hypothesis

> On an entity-dense scientific slice, extracted-and-canonicalized triples will (a) make
> `triple_overlap` / `entity_jaccard` **discriminate** verifier-confirmed cross-source matches from
> non-matches, weight-independently, and (b) let `SharedTripleBlocker` **recover** true cross-source
> matches that embedding-blocking misses.

We measure (a) signal validity and (b) recall — not fixed-weight re-ranking lift, which is unsound on
this matcher for reasons in §6c.

## 3. Corpus: the scientific-dense slice (measured)

Selected from the live corpus by topic: the **DNA-origami / nanomachine / de-novo-protein** cluster.

- **58 papers, 1,590 claims** (`claims.properties->>'source_doi'` ∈ the slice's DOIs; filtered by
  paper-title topic match on origami / DNA-nano / molecular-motor / nanoengine / nanopore /
  self-assembly / quantum-emitter / protein-nanomaterial / RFdiffusion).
- Entity-dense in exactly the V2 ontology's target types (Material, Molecule, Method, Instrument,
  Property) — DNA origami, staple strands, scaffold, MgCl₂, thermal annealing, nanopore, quantum
  emitter, etc.
- **Ground-truth positives are built in:** ~8 papers appear as **same-title / different-source DOIs**
  (journal + preprint), e.g.:
  - "realizing mechanical frustration at the nanoscale using DNA" — 3 DOIs (NatComm + bioRxiv + `10.1038/s41467-025-60492-z`)
  - "spring-loaded DNA origami arrays …" — sciRobotics + bioRxiv
  - "from Brownian to deterministic motor movement in a DNA-based …" — NanoLett + bioRxiv
  - "reconfigurable multi-component nanostructures built from DNA" — sciRobotics + bioRxiv
  - "deterministic nanofabrication of quantum-dot circular Bragg …" — arXiv + Nature
  - "a hybrid graphene-siliconnitride nanomembrane …" — arXiv + journal
  - "recent advances in DNA-origami-engineered nanomaterials" — arXiv + ChemRev
  - "DNA origami nano-mechanics" — 2 DOIs

  Claims describing the same finding across the two sources **should** cross-source match,
  **independent of embedding** — the gold positives the candidate slice never had.

The exact curated DOI list is produced in the implementation plan (regex seed above, then manual
trim to drop near-misses).

## 4. Critical-path insight: entity canonicalization is mandatory

`triple_overlap` is `Jaccard` over `(subject_id, predicate)` **sets of canonical entity IDs**. If the
journal claim mentions "DNA origami" and the preprint claim mentions "DNA-origami" and they receive
**distinct** entity rows, `subject_id` never matches and the feature stays 0 *even with triples
present*. Entity canonicalization (embedding-NN within `type_top` + name/Levenshtein, per-type
thresholds, non-destructive merge per V2 §4) is therefore **required for the signal to fire across
sources** — not optional. This is the single biggest correctness risk; the Phase-0 spike (§6e) checks
it first.

## 5. Isolation ("experimental branch and database")

- **Git:** worktree `/home/jeremy/epigraph-wt-triples-exp`, branch `exp/rdf-triple-matching`, off
  `origin/main`.
- **DB:** **full clone** of prod `epigraph` (12 GB; 46 GB free on `/`) → `epigraph_triples_exp`.
  Full clone, not a 1,590-claim subset, because `graph_overlap` (Adamic–Adar) reads the **whole edge
  neighborhood**; a subset would silently corrupt that feature during scoring. Only
  `triples`/`entities`/`entity_mentions` get populated (for the slice's claims).
- **API:** an isolated `crates/epigraph-api/src/bin/server.rs` instance on a staging port bound to
  `epigraph_triples_exp`. Extraction writes go through the API batch endpoints (no-raw-SQL mutation
  rule); reads use a read-only psql connection. Production API/DB untouched.

## 6. Measurement

### 6a. Signal validity — PRIMARY, weight-independent
Do `triple_overlap` / `entity_jaccard` separate true matches from non-matches regardless of scorer
weights?
- **Positives:** (P1) same-paper cross-source claim pairs from the duplicate-DOI papers (§3),
  aligned within a pair; (P2) cross-paper pairs the LLM verifier confirms as `same`/`paraphrase`.
- **Negatives:** sampled claim pairs from topically-distinct papers in the slice + verifier-labeled
  `distinct`.
- **Report:** per-feature value distributions (positives vs negatives) and per-feature AUC / PR for
  `triple_overlap` and `entity_jaccard` *alone*. P1 gives positives independent of embedding, so the
  embed confound that crippled the candidate slice does not apply here.

### 6b. Recall probe — PRIMARY
The value triples add that embedding can't: surfacing matches embedding-blocking misses.
- Run all five blockers over the 1,590 slice claims. Compute, per blocker, the set of candidate pairs.
- **Key number:** true matches (P1 + verifier-confirmed) generated by `SharedTripleBlocker` but
  **absent from `EmbeddingAnnBlocker`'s output** — i.e., recovered *only* via shared triples.
- The duplicate-paper twins are known positives, so recall against them is directly measurable
  (did the triple blocker surface each twin pair?).

### 6c. Fixed-weight re-ranking — SECONDARY, caveated (not a success criterion)
`renormalized_score` excludes `None` features; an empty-triple claim yields `triple_overlap = None`
(excluded). After population, an added `Some(0.0)` is **included** as 0 and **dilutes** the score; an
added `Some(v)` raises it **iff** `v > current weighted average` (`(N+wv)/(D+w) > N/D ⟺ v > N/D`). So
fixed-weight lift is **non-monotonic**. Reported for completeness only; not used to judge success.
If 6a is positive but 6c is not, the actionable conclusion is "signal is real; weights/renormalization
must change to exploit it" — a downstream `calibrate_matcher` task, **out of scope** (avoids
confounding the in-flight #239 precision sweep).

### 6d. Extractor scorecard
spaCy vs LLM (Claude OAuth), benchmarked against a hand-annotated **extraction gold set** of ~60–80
claims stratified from the 1,590 (entity-dense / predicate-dense / cross-source-overlap / edge cases).
Metrics: entity P/R, triple P/R, cost, latency. Winner runs over all 1,590.

### 6e. Phase-0 premise spike — KILL-SWITCH before the heavy build
Before porting two extractors and hand-annotating gold, validate the premise cheaply on **one**
duplicate-paper pair (e.g. "mechanical frustration DNA origami": bioRxiv + NatComm, ~180 claims):
1. Extract triples with the LLM extractor on both versions.
2. Canonicalize entities across the two sources.
3. Check two numbers: **(i)** do entities merge across sources (e.g. "DNA origami" from both → one
   canonical id; report merge rate), and **(ii)** do the known-twin claim pairs get
   `triple_overlap > 0`?
If entities don't merge or twins stay at 0 overlap, the premise is dead on this corpus — stop and
report, having spent ~1% of the effort. This spike also serves as the **canonicalization validity
gate** for 6b: an empty recall probe is only informative if merge rate and triple density are
non-floor.

### 6f. Ground-truth strategy
Stored `match_candidates` verdicts are not reused (negatives are `"count-only run; verifier skipped"`
placeholders). Ground truth here = the duplicate-paper twins (structural positives) + the LLM verifier
as labeling oracle for cross-paper pairs and negatives.

## 7. Data realities & caveats

- **1,590 claims** across 58 papers — cheap to extract (LLM pass trivial on prepaid OAuth).
- **Built-in positives** from ~8 duplicate-DOI paper pairs — real cross-source matches independent of
  embedding. This is the key advantage over the candidate slice.
- **Honest recall scope:** extraction covers only the slice, so the recall probe measures
  **intra-slice** recall (matches among these 58 papers). Full-corpus recall needs the deferred 436K
  backfill.
- **Slice still contains some noise** (empty `"Body"` rows, section-fragment claims); the extractor
  skips garbage and the gold set targets substantive scientific claims.
- **Twin-pair alignment isn't free:** journal and preprint versions are not claim-for-claim identical;
  aligning which preprint claim corresponds to which journal claim (for P1) is itself done by
  embedding+verifier and should be reported with its own confidence, not assumed perfect.

## 8. Success criteria (go / no-go)

The experiment **succeeds as an experiment** if it returns a defensible verdict on each:
1. **Signal:** `triple_overlap`/`entity_jaccard` AUC materially > 0.5 separating confirmed matches
   from negatives (6a).
2. **Recall:** `SharedTripleBlocker` surfaces ≥1 true cross-source pair absent from the embedding
   blocker's output, and recovers the known twin pairs at a measurable rate (6b).
3. **Extractor + substrate:** a winning extractor with acceptable P/R, and a non-floor triple density
   / entity-merge rate on the slice (6d, 6e).

A null result *with caveats controlled* (especially the §6e gate passing, so the null isn't just "no
triples/merges") is a valid, useful outcome: triples don't earn their cost even on a favorable
scientific slice.

## 9. Risks

| Risk | Mitigation |
|------|------------|
| Entity canonicalization too weak → IDs don't unify → signal can't fire | Port V2 link-then-merge; Phase-0 spike (§6e) validates merge across a known twin pair before the heavy build |
| Recall probe empty *and* uninformative | §6e gate: require non-floor merge rate + triple density before interpreting an empty probe |
| Renormalization dilution masks signal | Lead with weight-independent 6a; 6c is caveated, non-criterion |
| Twin-pair alignment noise inflates/deflates P1 | Align via embedding+verifier, report alignment confidence; lean on verifier-confirmed P2 as backup positives |
| Slice noise (garbage/fragment claims) | Extractor skips garbage; gold set targets substantive claims |
| Full-DB clone disk/time | 12 GB into 46 GB free is safe; clone once, reuse |

## 10. Sequence of work (high level — detailed plan via writing-plans)

0. **Phase-0 spike (§6e):** clone DB → `epigraph_triples_exp`, stand up isolated API, LLM-extract +
   canonicalize one duplicate-paper pair, check merge rate + twin `triple_overlap`. **Gate:** proceed
   only if premise holds.
1. Port V2 extractors behind the `TripleExtractor` protocol (spaCy + LLM).
2. Build extraction gold set (~60–80 stratified scientific claims); annotate.
3. Run both extractors on gold; score; pick winner (6d).
4. Run winner over all 1,590 slice claims → entities/mentions/triples via API.
5. Canonicalize entities (link-then-merge); validate against known twin entity links.
6. Build evaluation pairs: P1 (twin alignment), P2 (verifier-labeled cross-paper), negatives.
7. Signal validity (6a) + recall probe (6b); fixed-weight re-ranking reported as caveated secondary (6c).
8. Go/no-go report; recommend (or not) weight recalibration + scientific-dense backfill.

## 11. Deliverables

- Reusable extractor port (if it earns its cost).
- Go/no-go report answering the three success criteria with controlled caveats.
- Recommendation on downstream work (weight recalibration, broader backfill).
