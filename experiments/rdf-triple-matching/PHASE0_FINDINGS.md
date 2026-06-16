# Phase-0 Spike Findings (2026-06-16)

**Twin pair:** Mechanical Frustration DNA Origami — bioRxiv preprint (91 claims) + NatComm journal (20 claims) = 111 claims.
**Extractor:** LLM (`claude -p` OAuth), with retry + 300s timeout (box runs concurrent EpiClaw `claude -p` load).
**Canonicalization tested:** exact `(lower(name), type)` vs normalized `(alnum-only, type)`.

## Gate: PASS (weak)

Premise holds at the floor: entities merge across sources and ≥1 cross-source pair gets `triple_overlap>0`. But the signal is sparse and the result reshapes the experiment.

| Metric | Value |
|---|---|
| Claims with entities / triples | 111 / 111 |
| Canonical entities (exact / normalized) | 327 / 325 |
| **Cross-source entity merges** | **30** (same under exact & normalized) |
| Cross-source pairs evaluated | 1,820 (20×91) |
| **Pairs with `triple_overlap` > 0** | **3** (1 embed-hard) |
| **Pairs with `entity_jaccard` > 0** | **146** |
| Max `triple_overlap` | 0.5 |

## Key findings

1. **`entity_jaccard` is the workhorse, not `triple_overlap`** — 146 vs 3 firing pairs (~50×). The matcher weights them 0.10 vs 0.15, i.e. it *underweights* the signal that actually fires.
2. **Predicate variance bottlenecks `triple_overlap`.** It needs subject AND predicate to match; LLM predicates are free-text snake_case that vary across rewordings (`exhibits`/`exhibited`/`shows`), so even when two cross-source claims share a subject entity, the predicate usually differs → no `(subject,predicate)` match. This points at **predicate canonicalization/clustering** (V2 §2.3) as the lever to make `triple_overlap` useful.
3. **Name normalization barely helps here** (30→30 cross-source entities). Exact name match already captures the mergeable entities on this pair; the bottleneck is predicates, not entity name variants. (Embedding-based entity merge may still help on other pairs — untested.)
4. **The marginal-value case exists but is thin:** one embed-hard pair (embed=0.653, below match threshold) linked by shared entity `dna metastructure` — embedding misses it, the entity signal catches it. Exactly the recall mechanism the experiment targets, but N=1 on this pair.

## Implication for the full experiment

- Promote **`entity_jaccard`** (and raw shared-entity counts) to the primary measured signal; treat `triple_overlap` as secondary and test whether **predicate canonicalization** rescues it.
- The recall probe (`SharedTripleBlocker` uses `(subject_id, predicate)`) will be weak as-is; an **entity-overlap blocker** (shared canonical entity, no predicate) is the more promising recall lever and should be added.

Raw data: `spike_results.json`.

---

## Phase-0b: DISCRIMINATION check (the real gate) — NEGATIVE

Firing rate ≠ signal. Re-ran on the same twin, this time measuring whether the structural
features *separate* verifier-confirmed matches from non-matches in the embed-MID band
(0.50–0.80, where embedding is ambiguous — the only band a structural signal can help).
Ground truth = LLM verifier per pair (not embed_cosine; same-paper twins are near-duplicate
text, so labeling-by-embedding would be circular).

**Mechanism** (143 entity-sharing pairs): 143 share any entity → **53** share a *subject* →
**8** share a `(subject,predicate)`. `triple_overlap` loses signal at both stages: shared
entities are often objects/modifiers (143→53), and shared subjects usually differ in predicate
(53→8). Predicate canonicalization could at best lift 8→53; the subject-role constraint caps it.

**Discrimination** (embed-mid band, n=50 labeled: 11 match / 39 non-match):

| Feature | mean(match) | mean(non-match) | AUC |
|---|---|---|---|
| `entity_jaccard` | 0.073 | 0.059 | **0.573** |
| `subject_jaccard` | 0.018 | 0.067 | **0.409** (anti-signal) |
| `triple_overlap` | 0.000 | 0.000 | **0.500** (dead in-band) |
| `embed_cosine` | 0.666 | 0.576 | **0.776** |

**Verdict: NEGATIVE.** In the band where embedding is ambiguous, the RDF triple/entity
structural features add no discriminative value over embedding (entity AUC 0.573 ≈ chance,
subject AUC 0.409 below chance, triple AUC 0.500 dead; embedding AUC 0.776 carries it). The
earlier "entity overlap is the workhorse" read was the firing-rate fallacy — entity_jaccard
fires often (146 pairs) but those firings are mostly non-matches sharing generic entities.

**Caveats:** one twin pair; n=50 labeled with only 11 matches → wide AUC confidence intervals;
single extractor (LLM, generic predicates). But the point estimates are uniformly weak/inverted
and embedding dominates, so tightening is unlikely to flip the conclusion to a strong positive.

**Recommendation: do NOT proceed to the 58-paper build for cross-source *matching*.** The
cheap gate says the triple layer won't earn its extraction+canonicalization cost on this corpus
for the matching objective. Triples' value, if any, lies in the *query/discovery* use case
(`query_triples`, `entity_neighborhood`) — a different objective the user did not pick.

Raw data: `discriminate_results.json`, `extractions_cache.json`.
