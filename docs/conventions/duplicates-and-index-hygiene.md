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
| A claim that restates another claim, and only one should stay current | `mark_duplicate(claim_id, canonical_id, reason)` | The duplicate becomes non-current, `supersedes` the canonical, and loses its embeddings (it leaves semantic recall). A `same_as` identity edge records the tool, the rule, who marked it, and your `reason` when you give one. The dedup cascade then re-points the duplicate's edges (see [What a mark moves](#what-a-mark-moves)). |
| Many identical restatements across the corpus | `sweep_semantic_duplicates`, an operator job (the CLI on the maintenance connection; a request-serving MCP server refuses it) | Dry-run by default. It collapses only claims with identical content (the same hash), across tenants, onto the survivor it picks (highest truth value, then earliest), through the same act as `mark_duplicate`, with rule `exact_restatement`. Near-duplicates come back as merge candidates for `consolidate_claims`. |
| 2 to 20 claims that should become ONE new, merged claim | `consolidate_claims` | A new claim is written, and the sources supersede into it. Their edges move to it, but their belief inputs do not (no belief cascade follows). There is no identity edge and no un-mark. Sources spanning two owner groups are refused. |
| A claim whose content is wrong or out of date | `supersede_claim` | A new version replaces it. |
| Two claims that say the same thing but should BOTH stay current (two sources, two scopes, two owners) | An `EQUIVALENT_TO` edge (HTTP `POST /api/v1/edges`, scope `edges:write`, that exact casing; no MCP tool writes it). Or `link_epistemic` with `corroborates` when one should support the other's belief. | Nothing is retired. `EQUIVALENT_TO` moves no belief. `corroborates` does. |
| Items of an operational index family (a lead list, a tracker): duplicates, past-due items, partial retirements | `plan_label_dedup`, then `apply_label_dedup` | Duplicates are marked through `mark_duplicate`'s act, and the rest is label bookkeeping. See [label-dedup.md](label-dedup.md). |

## A mark is one-way on a request server today

An un-mark (`unmark_duplicate`, HTTP `POST /api/v1/claims/:id/undedup`, and
`revert_label_dedup` for a label-dedup apply) runs the dedup's reversal on
the server's administrative (maintenance) connection. It has no deferred form.

Request-serving MCP and HTTP servers hold no maintenance connection, so there
these calls are refused with nothing written. No shipped surface runs the
reversal anywhere else either: unlike the sweep, there is no operator CLI for
an un-mark. Treat a mark as one-way.

Where an un-mark does run, it puts back only rows that are still where the
dedup left them. A row a later write has changed is left alone and reported
as `drifted`.

By contrast, a label write can always be undone with `update_labels`. Mark
only what you are sure of.

## What a mark moves

The dedup's repair runs after the mark. On a request-serving server it is
deferred, and the replay timer applies it.

- **Edges.** The duplicate's edges, incoming and outgoing, are re-pointed onto
  the canonical. An edge whose triple the canonical already has is retracted
  instead. The identity edge itself is never moved. A non-public duplicate
  keeps its `executes` edges.
- **Belief inputs (mass functions).** They follow the edges and pool onto the
  canonical, except:
  - copies of a source the canonical already holds;
  - `attributed_v1` rows;
  - every row, when the canonical is a compound (an in-force `decomposes_to`
    out-edge).
- **Ownership of what moves.**
  - On a group-private canonical, moved rows take its owner's group.
  - On a public canonical, each keeps its writer's group.
- **Evidence.** It stays with the duplicate.

## Rules

- **A duplicate is a graph fact, not a label.**
  - Mark it; never tag it `duplicate-of:<id>`.
  - Readers find a duplicate by its non-current state and its `same_as`
    identity edge. Label dedup writes no loser label.
- **`properties.dedup` is reserved for the dedup act.**
  - The application edge routes (create, patch) and `patch_edge` refuse it.
  - A plain `same_as` edge, without that key, retires nothing, and neither
    the index view nor an un-mark follows it.
  - A plain `same_as` is NOT belief-neutral: between two current claims it
    creates a belief-propagation evidential-support factor (strength 0.95).
    Use `EQUIVALENT_TO` for a neutral equivalence link.
- **Label dedup is for index families only.**
  - Every family a profile names must declare `family_kind: "index"`, and the
    operator must allowlist it (`EPIGRAPH_LABEL_DEDUP_INDEX_FAMILIES`).
  - Duplicates of knowledge claims are marked with `mark_duplicate`, by a
    caller with write authority over both claims.
- **Label dedup never marks across owners.**
  - It refuses any cluster whose members have more than one owner, whatever
    the caller's grant, and lists it in `review`.
  - A human who decides the pair is a duplicate marks it with
    `mark_duplicate`.
- **A marked duplicate keeps what it knew.**
  - Its fields (a later deadline, an extra id) stay on its own claim.
  - Index readers get them through the canonical: `label_dedup_index_view`
    (MCP), or the planner's own reads.
  - Do not copy them onto the canonical as labels.

## Picking the canonical

- Keep the claim with the most evidence and the best content, not the oldest
  or the newest by default.
- Pick a CURRENT canonical. `mark_duplicate` refuses a mark onto a retired
  claim (nothing is written); a chain is built only by marking a claim that
  already has duplicates onto a current canonical.
- Un-mark a chain from the canonical end: first the duplicate whose canonical
  is current. `unmark_duplicate` refuses a duplicate whose canonical is itself
  still a marked duplicate (un-mark that one first).
- A canonical superseded or consolidated after the mark is followed to its
  current replacement, and the duplicate is restored against that one
  (`current_canonical_id`); you need the same write authority over every claim
  of that chain as over the canonical.
- A duplicate the pre-2026-10 raw-SQL `fuzzy_dedup_claims` marked is
  un-markable once `backfill_dedup_identity_edges --apply` has written its
  identity edge. That script kept no repair record, so nothing is put back
  (`legacy_mark`); a legacy mark the backfill cannot reconstruct is refused
  with the reason.
- A compound canonical takes none of the duplicate's belief inputs.
- Write authority:
  - you must write the groups that own both claims, or hold `claims:admin`;
  - without `claims:admin`, a duplicate bound FALSE on `binary_truth` cannot
    be marked onto a canonical you cannot write that has no such binding
    (FA07).
