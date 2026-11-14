# Cross-source verifier adjudication protocol, v1

Status: **DRAFT.** §3 (the decision rule) is **PROPOSED**. The operator must
ratify its thresholds before any precision sweep runs. A sweep run before
ratification does not count toward this protocol.

## 0. Why this exists

The LLM verifier is the precision gate of the cross-source matcher.
`calibration.toml` sets `[matcher.bands] high = 1.01`, so no score
auto-promotes and every candidate at or above `mid` goes to the verifier
(`crates/epigraph-engine/src/matching/pipeline.rs::run_pipeline`). A precision
figure for that verifier means something only if the following hold:

- the prompt under test is fixed before scoring (§1);
- the decision rule is fixed before the results are seen (§3);
- the people producing the reference labels cannot see provenance, scores, or
  the verifier's answer (§4);
- pairs that already have a verdict are excluded from the headline figure (§5).

This file fixes all four before the sweep. Changing any of them requires a new
version (`prompts_v2.md`), not an edit to this one.

## 1. The verifier under test

Call path: `cross_source_sweep` → `epigraph_cli::matching_client::RerankBridgesClient`
→ `epigraph_cli::rerank::core` → `epigraph_cli::rerank::prompt::build_validation_prompt`.
Record the model named by `ENRICHMENT_MODEL` at run time in the sweep report.

The prompt text is pinned below. `{pairs_text}` is the per-batch block, one
entry per pair in this form:
`Pair {i} (cosine similarity: {sim:.4}):\n  Source [{doi}]: "{content≤300}"\n  Target [{doi}]: "{content≤300}"`.
A unit test (`rerank::prompt::tests::adjudication_protocol_pins_the_live_prompt`)
fails if the live prompt drifts from this text. Drift means a new protocol
version, not a silent re-run.

```text
You are a scientific relationship validator for an epistemic knowledge graph.
You evaluate whether pairs of scientific claims have a genuine scientific
relationship, or if their high embedding similarity is merely vocabulary overlap.

## CRITICAL DISTINCTION

GENUINE relationship: Claim A's truth or methodology meaningfully bears on Claim B.
One claim provides evidence, theoretical basis, or specific application of the other.

FALSE POSITIVE (reject): Both claims use the same terms (e.g., "octahedral",
"geometry", "lattice") but in unrelated scientific contexts. Example:
Crystal Field Theory (d-orbital splitting in transition metal complexes) vs
DNA origami (octahedral nanostructure shape) — shared word "octahedral", zero mechanistic link.

## Candidate Pairs

{pairs_text}
## Relationship Types

- supports: A provides evidence or theoretical basis for B
- contradicts: A provides evidence undermining B
- derives_from: A is a logical consequence or application of B
- refines: A adds precision or qualifies B
- analogous: genuinely parallel phenomena in related domains

## Rules

1. REJECT pairs where the ONLY connection is shared vocabulary in different contexts
2. A relationship must be defensible in a peer-reviewed context
3. If uncertain, REJECT — false negatives are preferable to false positives
4. Strength range: 0.3 to 1.0 (for accepted pairs)
5. Rationale must name the SPECIFIC scientific mechanism connecting the claims

## Output

Return a JSON array with one object per pair:
- pair_index: integer (0-based)
- valid: boolean
- relationship: string or null (supports/contradicts/derives_from/refines/analogous)
- strength: number or null (0.3 to 1.0)
- rationale: string (explain the specific scientific connection or why it's a false positive)

Return ONLY the JSON array. Include an entry for EVERY pair.
```

How verdicts map to outcomes (`epigraph_engine::matching::verifier::map_relationship`):

| Verifier relationship     | Match verdict | Pipeline action |
|---------------------------|---------------|-----------------|
| `supports`, `elaborates`  | Same          | promote (CORROBORATES) |
| `analogous`               | Paraphrase    | promote (CORROBORATES) |
| `contradicts`             | Contradicts   | write `contradicts` |
| `refines`, `derives_from` | Overlapping   | reject |
| anything else / `valid=false` | Distinct  | reject |
| no answer (`None`)        | none          | skipped; not scored |

**Known deviation, which the operator rules on before the sweep:** the live
prompt shows each claim's DOI to the verifier. The verifier therefore sees
provenance, which §4 hides from the adjudicators. v1 evaluates the verifier as
it is deployed, DOIs included. If the operator wants a DOI-blind verifier
measured, that is a v2 prompt and a separate run.

## 2. Sample frame

1. Draw the sweep's seed window exactly as `cross_source_sweep` does
   (`--dry-run`, so no edges are written). Record the git sha, the
   `calibration.toml` hash, and the seed count.
2. Take every pair the pipeline routes to the verifier (`mid_band`). Pairs the
   verifier did not answer (`skipped_no_verdict`) are reported, but they are
   not part of the precision denominator.
3. Before scoring, write the contamination ledger (§5) and split the pairs into
   **clean** and **contaminated**.
4. Draw the adjudication sample from the clean pairs: all verifier-accepted
   pairs (Same, Paraphrase, Contradicts), plus a random sample of
   verifier-rejected pairs of size `N_REJECT_AUDIT` (§3), so that missed
   matches are also measured. The sampling seed is recorded in the ledger
   header before any pair is drawn.

## 3. Decision rule: PROPOSED, operator ratifies

Every number below is a placeholder until the operator fills it in and signs
off. Once the sweep's results have been seen, these values cannot be changed.

- **Headline metric:** precision of verifier-accepted pairs on the clean set:
  the fraction of accepted pairs whose adjudicated class equals the
  verifier's class family. The families are {corroborates: Same or
  Paraphrase} and {contradicts}. Report it overall and separately per family,
  with a 95% Wilson interval.
- **Supports deployment of `--apply`:** the lower bound of the overall interval
  is at least `T_SUPPORT` = `<operator>`, **and** contradicts-family precision
  is at least `T_CONTRA` = `<operator>`, over at least `N_MIN` = `<operator>`
  accepted clean pairs.
- **Refutes it (verifier stays advisory, `--dry-run` only):** the upper bound of
  the overall interval is below `T_REFUTE` = `<operator>`.
- **Inconclusive:** anything else. Record the result, enlarge the sample, and do
  not move the thresholds.
- **Miss-rate audit:** across the `N_REJECT_AUDIT` = `<operator>` sampled
  rejections, report the fraction the adjudicators class as a match. This is
  reported only and does not gate the decision.
- **Contaminated pairs:** report their count and their verifier-agreement
  separately. They are never part of the headline figure.

## 4. Blinding and randomised artifact ids

- Before any adjudicator sees a pair, each sampled pair is given an opaque id:
  8 random hex characters from a CSPRNG, unique within the run. The mapping
  from id to claim pair is written to a sealed file that adjudicators do not
  read until §6.
- The adjudicator packet shows, per id, only the two claim texts (untruncated)
  in random A/B order. It does not show claim uuids, DOIs, paper titles,
  agents, the matcher score, features, the band, the verifier's verdict or
  rationale, or which side is the seed.
- Adjudicators label each pair independently, with no access to other
  adjudicators' labels. If there are two or more adjudicators, disagreements
  are settled by a third adjudicator who sees the same blind packet.

## 5. Contamination ledger

A pair is **contaminated** if its `match_candidates` row has a
`verifier_verdict`, a `decided_at`, or status `promoted`/`rejected`. Its
verdict already exists, so scoring it again measures agreement with that
earlier verdict, not the verifier. Produce the ledger **before** scoring:

```sh
calibrate_matcher --contamination-ledger <out>/contamination_ledger.json
```

The ledger is built by `epigraph_engine::matching::contamination::contamination_ledger`
and is corpus-wide (it uses the maintenance DSN). Split the sweep's pairs with
`partition_by_ledger`, which matches pairs whatever their orientation. Commit
the ledger, or archive it next to the results, with the run's sha.

## 6. Withheld rubric (adjudicators only)

The verifier never sees this rubric. It is the reference standard the
adjudicators apply to each blind pair. Pick exactly one label:

- **corroborates**: both claims assert the same finding, or one is a faithful
  restatement of the other. A reader who accepts one would accept the other
  for the same reason. Different wording, units or precision is fine. A
  difference in scope (population, regime, conditions) is **not** fine; see
  overlapping.
- **contradicts**: the claims make incompatible assertions about the same
  quantity, mechanism or entity under the same conditions. Both cannot be true
  as stated.
- **overlapping**: same topic, and one bears on the other, but neither
  restates nor refutes it (refinement, special case, consequence, different
  conditions).
- **distinct**: the only connection is shared vocabulary or a shared field.
- **unjudgeable**: the claim text alone is not enough to decide. Excluded from
  the denominator, and the count is reported.

Unseal the id mapping only after every label is final. Then compute §3
exactly as written.

## 7. Report

The report records:

- the git sha, `ENRICHMENT_MODEL`, the calibration hash, and the sampling seed;
- the stage counts from the sweep's JSON;
- the clean and contaminated counts;
- per-family confusion tables and the §3 outcome.

Archive the adjudicator packet, the labels and the sealed mapping alongside
the report.
