# Duplicates vs index hygiene: `mark_duplicate`, `same_as`, label dedup

Three things can look like "dedup":

- retiring a claim that restates another;
- linking two claims that stay current;
- keeping an operational index clean.

They have different tools, and choosing the wrong one either loses knowledge
or hides it. Use this page to decide.

## Which tool

| You have | Use | What happens |
|---|---|---|
| A claim that restates another claim, and only one should stay current | `mark_duplicate(claim_id, canonical_id)` | The duplicate becomes non-current and `supersedes` the canonical. A `same_as` identity edge records who marked it, how and why. Other claims' edges to it, and its mass functions, move onto the canonical; its evidence stays with it. `unmark_duplicate` undoes all of it. |
| Many exact restatements across the corpus | `sweep_semantic_duplicates` (the operator CLI on the maintenance connection; a request-serving MCP server refuses it) | The same act as `mark_duplicate`, one pair at a time, with rule `exact_restatement` on the identity edge. |
| Several claims that should become ONE new, merged claim | `consolidate_claims` | A new claim is written, and the inputs supersede into it. There is no identity edge and no un-mark. |
| A claim whose content is wrong or out of date | `supersede_claim` | A new version replaces it. |
| Two claims that say the same thing but should BOTH stay current (two sources, two scopes, two owners) | an `EQUIVALENT_TO` edge (HTTP `POST /api/v1/edges`), or `link_epistemic` with `corroborates` when one should support the other's belief | Nothing is retired. `EQUIVALENT_TO` moves no belief; `corroborates` does. |
| Items of an operational index family (a lead list, a tracker): duplicates, past-due items, partial retirements | `plan_label_dedup`, then `apply_label_dedup` | Duplicates are marked through `mark_duplicate`'s act, and the rest is label bookkeeping. `revert_label_dedup` undoes one apply. See [label-dedup.md](label-dedup.md). |

## Rules

- **A duplicate is a graph fact, not a label.**
  - Mark it; never tag it `duplicate-of:<id>`.
  - Readers find a duplicate by its non-current state and its `same_as`
    identity edge. Label dedup itself writes no loser label.
- **`properties.dedup` is reserved.**
  - Only the dedup act writes a `same_as` edge carrying it. The edge routes and
    `patch_edge` refuse it.
  - A plain `same_as` edge, without that key, is an assertion and nothing
    more. It retires nothing, and neither the index view nor an un-mark
    follows it.
- **Label dedup is for index families only.**
  - Every family a profile names must declare `family_kind: "index"`, and the
    operator must allowlist it (`EPIGRAPH_LABEL_DEDUP_INDEX_FAMILIES`).
  - Duplicates of knowledge claims are marked one at a time, with
    `mark_duplicate`, by someone with write authority over both claims.
- **Never mark across owners automatically.**
  - Label dedup refuses any cluster whose members have more than one owner,
    whatever the caller's grant, and lists it in `review`.
  - A human who decides the pair is a duplicate marks it with
    `mark_duplicate`, which needs write authority over both claims.
- **A marked duplicate keeps what it knew.**
  - Its fields (a later deadline, an extra id) stay on its own claim.
  - Index readers get them through the canonical: `label_dedup_index_view`
    (MCP), or the planner's own reads.
  - Do not copy them onto the canonical as labels.
- **Prefer marking to deleting or relabelling.**
  - A mark keeps evidence, provenance and belief.
  - It is reversible: `unmark_duplicate` for one claim, `revert_label_dedup`
    for a whole label-dedup apply.

## Picking the canonical

- Keep the claim with the most evidence and the best content, not the oldest
  or the newest by default.
- A canonical that is itself a marked duplicate makes a chain. An un-mark must
  then go newest link first: `unmark_duplicate` refuses a duplicate whose
  canonical is still retired.
- The caller must write both claims' owning groups (or hold `claims:admin`
  for `mark_duplicate`). The dedup moves other writers' edges and mass
  functions onto the canonical, into its owner's group.
