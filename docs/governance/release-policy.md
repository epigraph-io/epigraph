# Release gate policy

**Status: a policy note. Nothing in this repository evaluates it.** No Rust
code, script, CI workflow or release step reads these thresholds or blocks a
release on them. They are applied by a person reading the query result below.

**Authoritative source:** the policy claim in the EpiGraph graph. This note is
a convenience copy of it. No mechanism keeps the two in sync; if they differ,
the graph claim wins.

## Thresholds

The gate is expressed over the belief (pignistic probability, BetP) of the
contract claims labelled `contract` and `repo-split`.

| Threshold | Value | Meaning |
|---|---|---|
| `open_kernel_contract_min_belief` | 0.85 | Minimum BetP every open kernel contract must reach to gate a 1.0 release. Depends on the DS combination scheme, the number of independent implementations, and the open-world discount applied to single-source evidence. |
| `enterprise_contract_min_belief` | 0.90 | Higher bar for enterprise contracts, which carry commercial SLA expectations. |
| `open_world_discount_factor` | 0.15 | Discount applied when only a single implementation provides evidence, so that one passing test suite cannot produce overconfident belief. |

## Changing a threshold

Submit a design-decision claim to EpiGraph first, with rationale and evidence,
then update this note to match.

## Reading gate status

Run against a read-only connection to the graph database:

```sql
SELECT content, pignistic_prob
  FROM claims
 WHERE labels @> ARRAY['contract', 'repo-split']
   AND is_current
 ORDER BY pignistic_prob;
```

Compare each contract's `pignistic_prob` with the threshold for its class.

## History

These values lived in `release-policy.toml` at the repository root until
2026-11. That file was read by nothing, so it was replaced by this note
(backlog `601b7829`).
