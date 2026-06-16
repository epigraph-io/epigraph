# RDF Triple / Entity Machinery — Experiment Conclusion

**Date:** 2026-06-16 · **Branch:** `exp/rdf-triple-matching` · **Status:** complete (negative, cheaply)

## The question
The epigraph repos carry a dormant RDF triple + entity layer (tables, MCP/HTTP tools,
`SharedTripleBlocker`, and `triple_overlap`/`entity_jaccard` features already wired into the
cross-source matcher) — but the substrate is empty (0 entities / 0 triples over 436k claims; no
extraction pipeline). The user asked whether to turn it on for **entity matching** and **cross-source
claim matching**. We ran cheap, kill-switch-gated checks before any heavy build.

## Bottom line: NOT worth turning on for these objectives, on this corpus.

| Objective | Cheap gate | Result |
|---|---|---|
| **Cross-source matching** | Does the structural signal discriminate verifier-confirmed matches where embedding is ambiguous? (n=50, hand-audited) | **No** — `entity_jaccard` AUC 0.573 (≈chance), `subject_jaccard` 0.409 (noise), `triple_overlap` unevaluable (0/50 fired); `embed_cosine` 0.776 carries it. The real matches are numeric/content corroborations with ~zero structural overlap. |
| **Entity-centric retrieval / query** | Does the entity layer beat the binding **lexical** baseline (grep/BM25)? Surface-variant census. | **No** — 88.2% of mentions are literal substrings; non-literal wedge 11.8% and mostly morphological; cross-claim wedge 8.0% with high-value entities at zero. |

Both halves fail at the cheapest possible gate. Total spend: ~2 LLM extraction passes + ~50 verifier
calls + in-memory analysis. No 58-paper build, no production changes.

## Why (mechanism, not just metrics)
1. **Embedding already does cross-source matching well** — which is exactly why the matcher's 12,442
   existing candidates are embedding-selected and the triple features sit at zero.
2. **`triple_overlap` is doubly brittle**: it needs a shared *subject* (143 entity-sharing pairs →
   53 subject-sharing) and a shared *predicate* (53 → 8); LLM predicates vary across rewordings.
3. **The entity layer doesn't beat lexical** because the LLM extracts near-literal names from clean
   scientific prose — there's little synonym/coreference gap for it to bridge.

## Honest scope (what this does NOT claim)
- One scientific twin-paper corpus (clean prose). Messier corpora (abbreviation/OCR/coreference-heavy)
  could change the entity-retrieval verdict.
- Skipped (deliberately, once the gate fired): predicate canonicalization, the spaCy-vs-LLM extractor
  benchmark, cross-paper P2, the full 58-paper build. The human audit shows real matches share no
  subjects/predicates, so predicate canonicalization wouldn't rescue *matching*.
- `entity_neighborhood` aggregation ("everything about X") is a genuinely unique capability, but it
  rides on the noisy predicates and was not separately validated.

## What was built and is reusable
- Working OAuth `claude -p` triple/entity extractor (ported from EpigraphV2; retry + 300s timeout for
  concurrent load): `discriminate.py` / `extractions_cache.json`.
- Discrimination + census harnesses: `spike_triple_premise.py`, `discriminate.py`,
  `recover_pairs.py`, `census_surface_variants.py`.
- Experimental DB clone `epigraph_triples_exp` (12 GB; 3 large claims HNSW indexes unbuilt — `/dev/shm`
  limit). **Droppable** — nothing here depends on it persisting.

## Recommendation
Leave the triple/entity machinery dormant for matching and entity retrieval. If revisited, the only
promising direction is a corpus with genuine surface variation (where the census wedge would be large)
or the aggregation/`entity_neighborhood` capability *after* predicate quality is fixed — neither
justified by the user's current corpus or objectives.
