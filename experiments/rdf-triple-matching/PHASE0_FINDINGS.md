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

**Discrimination** (embed-mid band, n=50 labeled: 11 match / 39 non-match). AUC SE at n_pos=11
is ~0.10, so the ~95% CI on each AUC is roughly ±0.20:

| Feature | mean(match) | mean(non-match) | AUC | reading |
|---|---|---|---|---|
| `entity_jaccard` | 0.073 | 0.059 | 0.573 | within ~1 SE of chance (CI ≈ 0.40–0.74) |
| `subject_jaccard` | 0.018 | 0.067 | 0.409 | ~0.9 SE under chance → indistinguishable from 0.5 (noise, **not** anti-signal) |
| `triple_overlap` | 0.000 | 0.000 | 0.500 | **unevaluable** — fired 0/50 in-band (8/1820 overall); never tested, not "failed" |
| `embed_cosine` | 0.666 | 0.576 | 0.776 | clearly separates matches |

**Human audit of the labels (50 pairs read by hand, 0 claude calls):** the verifier's matches are
**real reworded corroborations**, not text-overlap rubber-stamps — e.g. P18 (both "actual ~15 pN,
max ~57 pN"), P21 (both: adaptable mode = steep single free-energy minimum), P17 (both: edge ~28 nm
2HB). So the labels carry signal. But the strongest matches (P17/P18/P21) have `ej≈0.08–0.13, sj=0,
to=0`, while the *highest*-`ej` pairs (P02 0.29, P08 0.20, P13 0.22) are topically-related
**non-matches**. The real cross-source matches are numeric/content corroborations embedding captures
and structural Jaccard cannot single out.

**Verdict: underpowered null — enough to refuse the build, not to refute triples.** At this sample
size no structural feature is distinguishable from chance; embedding (0.776) is. This does **not**
prove "triples don't help matching": it tested the LLM extractor with raw predicates on **one
same-paper twin**, and skipped three levers the full design leaned on — predicate canonicalization
(53 shared-subject pairs collapse to 8 shared-(subject,predicate); canon could recover much of that),
the spaCy-vs-LLM benchmark, and cross-paper P2. What still kills the *matching* build regardless:
`entity_jaccard` is predicate-independent and also indistinguishable from chance here, and the human
audit shows the real matches don't share subjects/predicates at all — so the predicate lever wouldn't
rescue the matching objective even if it fired more triples.

**Recommendation: do NOT fund the 58-paper extract+canonicalize+score build for cross-source
*matching*** on this evidence. Options for the user: (a) stop & document; (b) one cheap follow-up
(predicate-canon on the 53 shared-subject pairs, or +2 twin pairs to tighten N); (c) pivot to the
*query/discovery* use case (`query_triples`, `entity_neighborhood`) — a different objective not
picked here, where structured triples may still pay off independent of matching.

Raw data: `discriminate_results.json`, `extractions_cache.json`; auditable pairs via `recover_pairs.py`.
