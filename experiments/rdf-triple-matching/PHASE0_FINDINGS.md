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
