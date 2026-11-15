# Atlas: nested groups down to a force-directed subgraph view

Status: for the operator's approval (questions answered 2026-11-12). It extends
`2026-11-04-epigraph-explorer-atlas-design.md` (the Atlas). It replaces that design's
"neighbourhood level" (§4.2, phase P3e) and the inside-a-theme claim placement.

## 1. Intent

Today a theme opens straight onto its claims, placed in a spiral by similarity rank to
the theme. That shows *what is near what in meaning*. It does not show *how the
knowledge is built*. The operator wants to zoom all the way into a theme and see the
actual subgraph: the atomic claims, the agents that asserted them, and the evidence
behind them, with belief shown as flows.

A theme can hold thousands of claims, so the map needs nested groups between the theme
and that graph, each small enough to read, each with a name.

## 2. What the operator decided

- **Theme cap.** No theme holds more than about 2,000 claims. A theme over the cap is
  split, using UMAP of its members' embeddings and then clustering.
  - Today: 210 themes, 55 of them over 2,000 claims; the largest is 7,959, the median 1,104.
  - Existing splitters do not meet this. `scripts/maintain_themes.py` k-means-splits only
    high-variance themes over 2,000. `scripts/split_theme.py` k-means-splits one theme in
    two. `scripts/theme_pipeline.py grow` caps at 8,000.
- **Deepest level: a force-directed subgraph of at most 100 nodes.** Nodes are claims,
  agents and evidence, counted together.
- **Belief as flow.** Support visibly moves from evidence through claims toward the
  conclusions they back. Each edge's thickness, or animated particles along it, shows how
  much that link contributes to the belief of the claim it feeds. Contradicting and
  refuting links are drawn in the opposing style, so the drag on a claim is visible.
- **Nested groups between the theme and the subgraph, with two switchable groupings.**
  - **By meaning:** groups of claims with similar embeddings.
  - **By links:** communities in the graph itself (densely interlinked claims: one
    argument, one paper's chain of reasoning, one debate).
  - The viewer flips between them with a switch. Both hierarchies are precomputed.
  - Every group at every level is named by an LLM assessment of the group's claims.
- **Freshness.** The layout is refreshed nightly; new claims appear the next day.
- **Whose graph (operator, Q&A 2026-11-12): one layout per team.** Each team group (the
  science team, platform operations, the consultancy team, and the rest) gets its own
  hierarchy and leaf layouts. Each is built from that team's claims plus public claims and
  shown to its members. A viewer in several teams flips between their teams' maps. Public
  viewers get the public-only map (today's rule A1).
- **The nightly (operator): incremental, built as part of this work.**
  - Each night it assigns new claims to the existing themes and groups, splits only a theme
    or group that went over its cap, and re-lays out and renames only the groups whose
    membership changed.
  - Ids and positions stay stable across nights.
  - A full UMAP rebuild stays an occasional, operator-run step. This keeps the theme-v2
    runbook's rule that UMAP never runs nightly on the host.
  - The nightly job replaces the paused `theme-maintenance` task (paused since it wiped the
    themes on 2026-08-18). Its runbook step "rewire the nightly" is part of this work.
- **Flow meaning (operator): a labelled proxy.**
  - Evidence-to-claim edges show their exact stored mass (`mass_functions.evidence_id`).
  - Claim-to-claim edges (supports, contradicts, refutes, …) show a proxy: link strength ×
    sign only, with no belief factor, so a served weight can never be turned back into a
    claim's belief. The view labels it as an estimate. (Operator, 2026-11-13; this replaces
    an earlier "strength × the source claim's BetP".)
  - No leave-one-out recomputation.
- **Private data off the host (operator): embeddings and structure only.**
  - The heavy maths (UMAP, community detection, force layout) may run on the remote build
    hosts or lanes, given claim ids, embeddings and edge structure only.
  - Claim text never leaves the prod box.
  - LLM naming runs from prod through the existing Claude CLI path.
- **Anti-goal: latency.** Zooming and switching must feel instant. A version that works
  but lags has failed.

## 2a. Operator rulings during the build (2026-11-13)

- **No belief values on leaf claims.** Leaf claim nodes carry no BetP. A later contract
  version may add one after the evidence-edge backfill (below) lands; `truth_value` stays
  as the colour value, as on the region and theme levels.
- **Stored evidence edges only.** A leaf draws only evidence-to-claim edges stored in the
  edges table; the view never synthesises one. Every evidence write path must name at
  least one claim and write that edge, and existing evidence gets an operator-run backfill
  (most evidence rows had no such edge).
- **Co-owned edges.** The database's rule stands: an edge co-owned by two teams is readable
  only by people in both. A map draws an edge only when both endpoints are drawable on it
  and the map's whole audience may read the edge, so a co-owned edge is never baked into a
  single-team map, and the public map draws public edges only. A joint per-viewer view for
  people in both teams is future work. (This replaces an earlier ruling that drew it on both
  teams' maps.)
- **Proxy weights.** Claim-to-claim flow weight is link strength × sign only (§2).

## 3. Goals

1. Every theme ≤ ~2,000 claims after the nightly refresh.
2. Two precomputed hierarchies under each theme (meaning, links). Each hierarchy nests
   until every leaf group holds ≤ 100 nodes (claims + agents + evidence).
3. An LLM name for every group at every level, in both hierarchies.
4. A force-directed leaf view with belief flows. Its positions are precomputed, so the
   browser draws and does not simulate.
5. Links that leave a group are shown at every level, aggregated to that level, as the
   Atlas already does between themes and regions. Clicking one flies to its target.
6. A latency budget the build is tested against (§6).

## 4. Non-goals

- **A live view.** A separate editor window where people hand-craft and edit graphs
  (in the style of Graphileon) is a future project, not this one.
- **Changing regions or themes.** Regions, theme placement and the region/theme levels
  of the Atlas are unchanged, except that oversized themes are split.
- **New belief maths.** Flows show stored evidence mass and link strength as they stand,
  not a live re-propagation.

## 5. Constraints

- **Visibility.** Per-team layouts (above).
  - A team's map is built only from rows that team can read: its group's claims plus public
    ones.
  - It is served only to that team's members. The serving path still filters by the viewer
    (RLS), so a member never sees a row their own session cannot read.
  - The corpus is overwhelmingly team-private (about 366,000 current claims against 8,600
    public), which is why per-team maps are needed.
- **No leak through names or shape.** An LLM name is generated only from text every viewer
  of that map can read: the team's claims plus public claims for a team map, public claims
  only for the public map. The existing theme names have this leak today, since
  `label_themes_llm.py` samples team-private text (backlog D-PR16). Per-team maps get
  per-team theme names, and the public map's theme names are regenerated from public text.
- **Invalidation.** Migration 197's `atlas_layout_epoch` bumps only when a public row
  narrows. A team map must also go stale when a claim moves into or out of the team, so it
  needs a per-team epoch or an equivalent trigger.
- **The prod host is small:** 4 CPUs, and a disk shared with Postgres. Heavy compute
  (UMAP, community detection, force layout, LLM naming) runs in the nightly build. Use
  the remote build hosts or a lane if it is too heavy for the host. The serving path
  only reads precomputed rows.
- **Existing stack.** Build on what exists:
  - `atlas_layout` (Rust, `crates/epigraph-cli/src/atlas_layout`) and the
    `atlas_layout_*` tables (migration 197, with the visibility epoch);
  - the theme scripts in `scripts/` (`theme_pipeline.py`, `split_theme.py`,
    `label_themes_llm.py`, `theme_lib.py`);
  - the Explorer BFF routes `/bff/atlas/*` (`services/explorer/src/bff/atlas.rs`) and
    the d3 canvas front end (`services/explorer/static/atlas.js`).

## 6. Latency budget

These are the builder's targets. The operator set the principle; the numbers are this
document's call.

- Zooming into a group or flipping the switch: the next level is on screen within
  **200 ms at p95** from a warm cache, and **500 ms** cold.
- Each level's payload is ≤ **150 KB** compressed. A leaf payload carries ≤ 100 nodes
  with their positions, the edges among them, and the outgoing cross-group links,
  aggregated.
- **No client-side force simulation** beyond an optional ≤ 300 ms settle, for nodes the
  viewer can see but the shared layout does not hold.
- Children are prefetched when their parent fills about a third of the view, as the
  Atlas already does.

## 7. How (the builder's to finalize)

**Nightly build order, after the theme refresh:**
1. Split themes over the cap.
2. Build both hierarchies per theme.
3. Collect each leaf's node set:
   - its claims;
   - the agents that assert or author them;
   - the evidence attached to them.

   If that takes a leaf past 100, split it again.
4. Compute the leaf force layouts. Make them deterministic: seeded, and stable across
   nights for unchanged leaves.
5. Compute the flow weights per edge: an evidence-to-claim edge's exact stored mass, and a
   claim-to-claim edge's strength × sign (§2, §2a).
6. Name the groups.
7. Write one new layout run, keyed like today's `atlas_layout_runs`.

**Calls this document made, not the operator** (check them):
- **Theme ids:** themes stay global (`claim_themes`). A team map shows each theme with that
  team's claims and its own per-team name and layout. The cap counts the claims the team's
  map draws.
- **The 100-node cap:** counts what the team's map draws.
- **"By links" edges:** epistemic links (supports, refutes, contradicts, cites, elaborates,
  corroborates) plus `decomposes_to`, so a paper's chain of reasoning holds together. A
  claim with no such link inside its theme falls back to its "by meaning" group, not to one
  leftover bucket.
- **Flow direction:** flows follow the current belief model. If the held atom-level
  belief-direction work lands, the flow direction along `decomposes_to` follows it.

**Choices left to the builder:**
- Graph community detection: Leiden or Louvain.
- UMAP parameters, and the clustering after UMAP.
- How agents and evidence count toward the 100-node limit when one agent touches many
  claims. One option is to show a high-degree agent once per leaf.
- The storage shape: new tables beside 197's, or a JSON blob per group. It must serve
  the §6 budget with one indexed read per level.
- LLM naming cost control: only renaming groups whose membership changed.
- The visual encoding details: particles versus thickness, and the colour of
  contradiction.

## 8. Open questions

None; the operator answered them on 2026-11-12 (§2).

## 9. Future

- A live, editable graph window (Graphileon-style), separate from the nightly map.
