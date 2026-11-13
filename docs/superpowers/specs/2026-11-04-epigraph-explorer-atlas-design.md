# EpiGraph Explorer: Atlas (zoomable map, sources, timeline)

**Date:** 2026-11-04
**Status:** spec
**Repo:** `epigraph` (public)
**Builds on:** `2026-09-15-epigraph-explorer-ui-design.md` (the Explorer: BFF, auth,
claim pages, graph canvas) and `../plans/2026-09-15-epigraph-explorer-impl-plan.md`.
Where the two disagree, this spec replaces §7 (Notion) and §11 Phase 3 of the
2026-09-15 spec. Everything else there stands.
**Rulings:** owner rulings A1-A7 (claims `7b8f47a7`, `19e64a7b`), summarised in §2.
**Backlog:** 17 items labelled `explorer-atlas`, indexed in §12.

---

## 1. What this adds

The Explorer answers "click a claim, see what it links to". The Atlas answers
"where am I in the corpus, who said this, and how did we get here". It is a
zoomable canvas in the style of a Prezi: one camera that flies between nested
levels, with three views over the same claims.

- **Topics.** Regions, then themes, then claims, then the claims a claim links to.
- **Sources.** Who said what: papers with their authors, web sources, and the
  people behind the agents that file claims directly.
- **Timeline.** Claims at the date they were filed, with cites, supports and
  contradicts drawn as arcs from the earlier claim to the later one.

Around the views: provenance when you click a claim, search that flies to the
result, guided tours, and deep links that embed in Notion.

A prototype built all three views from a static snapshot taken over MCP on
2026-11-04 (private artifact "EpiGraph Atlas"; ask the owner for access). It is a
design reference, not an implementation. Production reads go through the HTTP API
via the Explorer BFF, with each viewer's own bearer, exactly as the 2026-09-15 spec
§6 requires. Every place the prototype depended on MCP-only behaviour is a backlog
item in §12.

### Non-goals

- **Notion-to-EpiGraph ingest.** Notion paragraphs do not become claims (A3).
- **A global node-link render.** Still never (2026-09-15 §2). The Atlas draws
  containment and aggregates; node-link drawing stays local to one claim.
- **Writes.** The Atlas is read-only. Writes remain Phase 4 of the Explorer spec.
- **Data cleanup.** Data is shown as stored (A6, §9).

---

## 2. Rulings and defaults

| | Ruling (2026-11-04) |
|---|---|
| A1 | Every viewer sees the graph they can read. Layout positions are computed once, from public claims, and shared. Each viewer sees only the regions, themes, claims, links and counts they can read, at those positions, on the assumption that the visible structure is similar. |
| A2 | Inside a Notion embed the Explorer fetches with the signed-in user's own token. Guests, including Notion's link-card fetcher, get the public graph only. |
| A3 | No Notion-to-EpiGraph ingest. The auto-ingest reconciler of the 2026-09-15 spec is dropped; handoff §7 items 1-2 (deleted-paragraph policy, group-teamspace pairing) are moot. |
| A4 | Tours are stored in Notion. |
| A5 | Who said what shows the human behind each agent, with the agent's model and system prompt as a side note. A paper shows its authors, plus the human who ingested it and the model used. |
| A6 | No data cleanup yet. |
| A7 | The model name and prompt snapshot id are shown to anyone who can read the claim. System prompt text stays behind design D4: only the agent's linked human and admins can read it. |

Defaults taken on recommendation, recorded with A1-A6:

- The Atlas is built into `services/explorer` (this PR), not `epigraph-gui`.
- This PR is rebased on `main` and split into a kernel PR and an Explorer PR before
  Atlas work lands.
- Every overview route is capped and cursor-paged from the start.
- Deep links carry claim ids, resolved through `/claims/:id/placement`, never theme
  or neighbourhood ids alone.
- Tours live in a Notion database, read with the viewer's own Notion connection.
- `get_recall_events` gets no Explorer route until tenancy covers it.

---

## 3. What the corpus looks like (measured 2026-11-04)

- **210 themes, flat.** LLM-named and readable. Nothing groups them, and nothing
  positions them (backlog `f9b4a488`, `2b5bd83e`).
- **Theme sizes are wrong in the overview.** `/graph/themes/overview` reads
  `claim_themes.claim_count`, which assignment writers do not maintain: one theme
  shows 5,071 stored against 3,230 live, another 7,959 against 77 (backlog
  `57917c13`).
- **Neighbourhoods have machine labels** (`neighborhood-N`, a frame UUID, or
  `synthetic`) and ids that change every clustering run (backlog `01e0b839`).
- **The visible corpus depends on who asks.** Since the 2026-10-26 deploy, claim
  counts range from about 43k to 489k by identity (backlog `5d604be4`). The
  snapshot identity saw 46,227. The Atlas is per viewer by construction (A1).
- **Links are mostly document structure.** `decomposes_to` dominates. Supports,
  contradicts and cites are dense in a few design-heavy themes and rare elsewhere,
  so most timeline lanes will be dots without arcs. That reflects the graph.
- **Provenance is mostly there.** In a 250-claim sample: 85 paper or document
  sources, 7 web domains, 16 agents filing directly. DOIs live in `doi:` labels and
  evidence URLs. Some authors are placeholders (`author:<name>`) and some documents
  carry `urn:epigraph:doc:` keys instead of DOIs. Both are shown as stored (A6).

---

## 4. Views

### 4.1 One camera, semantic zoom

- Every item is a circle nested in its parent (lanes in the timeline). The camera is
  `(x, y, k)`. Flights use van Wijk and Nuij smooth zoom (`d3.interpolateZoom`); with
  `prefers-reduced-motion` they jump.
- Level of detail follows on-screen size. A level's labels fade in as it grows and
  fade out as its children take over. Children are fetched when their parent fills
  about a third of the view.
- **Colour means belief and nothing else.** One sequential ramp, stepped separately
  for light and dark. A contested claim gets a dashed ring in the critical colour.
  Regions and themes are told apart by their names, as on an atlas.
- Bubble area is the number of claims the viewer can read.
- After free zooming, the breadcrumb follows the deepest item that fills the view.

### 4.2 Topics

Region, theme, neighbourhood (once named), claim, claim ring.

- **Positions mean something.** Regions and themes come from the layout route:
  related themes sit near each other (backlog `f9b4a488`, `2b5bd83e`). Positions are
  computed per clustering run from theme centroids in the centroid-distance frame of
  `scripts/cluster_claims.py`, from public claims only, and shared by every viewer
  (A1). A short collision pass in the client removes overlaps while staying near the
  targets.
- **Inside a theme, distance from the centre is closeness to the theme's core.**
  Claims are ranked by similarity to the theme (search with a theme filter, backlog
  `7f359a86`) and placed by rank; angle only spreads them out. The map says so in
  the theme bubble.
- **Neighbourhood level.** It goes between theme and claims once neighbourhoods have
  names (backlog `01e0b839`). Until then a theme opens straight onto its claims: the
  closest N, with "show more" paging.
- **Claim ring.** The claim is at the centre. The inner ring holds its parent
  passage, its parts and its epistemic neighbours; the outer ring holds sibling
  passages (backlog `cadfc550`). Edge style follows the relationship: supports in
  the accent colour, contradicts dashed in the critical colour, structure muted.

#### Links that cross themes and regions

Containment shows what belongs together. Links that cross a boundary are often the
most informative part of the map, since cross-source and cross-topic links are the
hard ones to find. They are drawn at every level, always aggregated to the level
the viewer is at:

- **Overview.** One bundle between each pair of regions that share links, its width
  scaled to the link count. A dashed segment inside the bundle shows the share of
  contradicts and refutes. Links inside a region are not drawn at this level.
- **Inside a region.** Bundles between its themes. Links from a theme to another
  region leave as a stub towards that region, labelled with its name and count;
  clicking the stub flies there.
- **Inside a theme.** A claim with links outside the theme gets a small mark on its
  rim pointing towards the other theme's position on the map.
- **Claim ring.** A linked claim from another theme carries that theme's name, and
  clicking it flies across the map to the claim in its own theme. This replaces the
  prototype's rings, which kept every linked claim inside the current bubble.
- **What counts.** By default only epistemic links (supports, refutes,
  contradicts, cites, elaborates, corroborates). `decomposes_to` and other
  structure links are one toggle away; a paper's parts often spread across themes,
  and counting them would drown the rest.
- **Clicking a bundle** opens the claims behind it in the panel, grouped by
  relationship, strongest first (backlog `4321ae80`).
- **Visibility.** Bundle widths come from the shared public layout (A1), so they
  are the same for everyone. The panel list behind a bundle is the viewer's own and
  can include links that only they can read.
- **Timeline and Sources.** Arcs in the timeline already cross lanes, which are
  themes. In Sources, links between two sources (one paper citing another, an agent
  contradicting a paper) use the same bundle rule.

### 4.3 Sources: who said what (A5, A7)

- **Groups.** Papers and documents; web sources; people. A person is the human
  behind the agents that filed claims directly (`epigraph_human_of`). Agents with no
  linked human are shown as themselves.
- **A paper** shows title, authors and DOI. A side note reads "ingested by
  *human* using *model* on *date*" (backlog `b7354adc`).
- **A person** shows the human. For each claim, a side note gives the agent's
  display name, model and prompt snapshot id (backlog `48421526`). The prompt text is
  linked only for callers the D4 gate admits (A7).
- **Inside a source**, claims sit with the earliest at the centre.
- **Scope** is the whole visible corpus or one theme (backlog `da4a8bc1`).

### 4.4 Timeline

- One lane per theme (or per source, as an option). The x axis is `created_at`.
  Tick size follows the zoom: years, quarters, months, weeks, days.
- Dots take the belief colour. A hollow dot is a linked claim from outside the lane.
- Arcs join claims that cite, support or contradict each other, running from the
  earlier claim to the later one. The selected claim's arcs are drawn strong and the
  rest are dimmed.
- Selecting a claim frames the claim together with every claim it links to, so the
  whole exchange is on screen.
- Claim text appears beside a dot only when the lane is tall enough and the next dot
  leaves room. Lane names stay pinned to the left edge.
- Version history (`/claims/:id/history`, on `main`) appears in the claim panel as a
  supersede chain. Drawing chains as joined dots is a later step.
- Data: the claims timeline route (backlog `ea26d7aa`), batch reads (backlog
  `864368a8`) and claim context (backlog `cadfc550`).

### 4.5 Claim panel and provenance

Clicking a claim in any view opens the same panel:

- content; belief, with the authored truth value marked on the same bar; a
  contested flag
- **Provenance:** when it was filed and whether it is current; paper with authors
  and a doi.org link; other source URLs; who filed it (the human, then the agent,
  model and prompt snapshot id); classification; labels
- linked claims with the relationship in words ("cites this claim", "a part of
  this claim", "from the same passage"), or the dated links in the timeline view
- version history
- buttons to show the same claim in the other two views
- the embed link for this exact view

Upstream: `GET /claims/:id`, `/claims/:id/context` (backlog `cadfc550`),
`/papers?doi=` with authors (backlog `fe75ef36`), the `authored_by` block (backlog
`48421526`), `/claims/:id/history`, and `/claims/:id/provenance-chain` (this PR).

### 4.6 Search, deep links, tours

- **Search** uses `POST /search/semantic` (with the theme filter) and
  `/claims/by-labels`. `/` focuses it; arrow keys and Enter pick a result, which
  flies to the item in the current view, or switches to Topics if the item is not in
  that view.
- **Deep links** are a `#name` for one item: `t-<id8>` for a theme, `c-<id8>` for a
  claim, `x…` keys in Sources, `tc-<id8>` in the Timeline, `tour-<id>-<n>` for a
  tour stop. The BFF resolves claim keys through `/claims/:id/placement`, so links
  survive re-clustering. Theme ids alone are not durable: themes were rebuilt on
  2026-10-07 after a probe wiped them (backlog `5abe23de`). A link holds only an id,
  never claim text.
- **Tours (A4)** are a Notion database with one row per stop: tour, order, Explorer
  link, caption. The BFF reads it with the viewer's own Notion connection, so Notion's
  sharing decides who sees a tour. A stop the viewer cannot read in EpiGraph is
  skipped with a note. Tours are never stored in EpiGraph.

---

## 5. Visibility and auth (A1, A2, A7)

- **Signed-in viewers.** Every BFF call forwards the viewer's bearer, unchanged from
  2026-09-15 §6. The Viewer predicate decides what comes back; counts and names are
  per viewer.
- **Shared layout.** Positions are computed per run from public claims and served to
  everyone. A region or theme is drawn for a viewer only if they can read at least
  one member. A theme with no public members has no shared position; the client
  places it inside its region for the viewers who can see it. Positions therefore
  carry nothing private.
- **Guests** get the public graph through an anonymous, read-only, public-only
  surface (backlog `1deb9dbf`). Since `8c70e5af` (2026-08-27) the anonymous allowlist
  holds no claim or graph reads, so this surface is new. A non-public id is answered
  exactly as an absent one.
- **Inside a Notion embed**, the Explorer's popup sign-in and partitioned cookie
  (already in this PR) give the viewer their own token.
- **Pasted links** in Notion unfurl from the page's OpenGraph tags, fetched without
  any user token, so the cards are guest reads. Notion no longer lets new developers
  create custom Link Preview connections ("Custom Link Preview connections are no
  longer available for new developers to create", developers.notion.com), so
  per-user link cards are not an option.
- **Prompt text** is served only through the D4 gate (A7).
- **Caching** of viewer-filtered responses is keyed per viewer. Only the public
  layout may be cached across viewers.

---

## 6. BFF surface

New enumerated, read-only endpoints in `services/explorer`, following 2026-09-15 §6
(no generic passthrough):

| BFF endpoint | Composes |
|---|---|
| `GET /atlas` | HTML shell: canvas, panel, tour bar |
| `GET /bff/atlas/layout` | layout route with regions; nodes and counts filtered for the viewer |
| `GET /bff/atlas/theme/:id/claims?after=` | search with theme filter, then a batch read |
| `GET /bff/atlas/links?from=&to=&rel=&after=` | the claims behind a bundle between two themes or regions |
| `GET /bff/atlas/claim/:id` | claim, context, `authored_by`, history |
| `GET /bff/atlas/sources?theme_id=&after=` | sources overview |
| `GET /bff/atlas/timeline?theme_id=&from=&to=&after=` | claims timeline plus links among the page |
| `GET /bff/atlas/search?q=` | semantic search |
| `GET /bff/atlas/tour/:id` | Notion database rows, read with the viewer's Notion token |
| `GET /bff/atlas/resolve/:key` | deep-link key to node, via placement |

Rules:

- **Caps.** At most about 2 MB and 200 items per response, cursor-paged. The
  communities overview already returns about 74 MB (backlog `cc21d1fe`).
- **Caching.** ETag on the layout by `run_id`; short TTLs on overviews; per-viewer
  keys for anything viewer-filtered.
- **Degradation.** Each panel section and each zoom level fails on its own; a failed
  fetch shows an inline retry, never a blank map.

---

## 7. Front end

- **Where.** `services/explorer`: `templates/atlas.html` and `static/atlas.js`, a
  canvas renderer. The d3 modules it needs (zoom interpolation, hierarchy pack,
  force, time scales and formats) are vendored into `static/`, because the CSP is
  `script-src 'self'`. No CDN.
- **Layout.** One screen: header with view tabs, search and breadcrumb; the map;
  the panel on the right (a sheet below the map on phones); the tour bar over the
  bottom of the map.
- **Accessibility.** Every map item is reachable from the panel's lists and from
  search. Keys: `/` search, Esc out, arrow keys between tour stops. The panel is an
  `aria-live` region. Reduced motion is respected. The canvas is not the only way in.
- **Performance.** Cull off-screen items, cache text wrapping, and draw no more than
  about 2,000 items per frame. Children load lazily.
- **Theme.** Colour tokens with light and dark values; the belief ramp is validated
  for both.
- **`epigraph-gui`** (backlog `dee9f733`) does not host the Atlas. Its graph page can
  link to Atlas deep links.

---

## 8. Notion surface (replaces 2026-09-15 §7)

1. **An `/embed` block** of `/atlas` or any deep link. Signed-in viewers browse with
   their own token.
2. **Pasted claim links** unfurl from OpenGraph tags as guest reads. A public claim
   shows its text and belief. Anything else shows a generic "EpiGraph claim" card
   with no text.
3. **Tours**: the Notion database of §4.6.

No claims are copied into Notion, and no Notion content is copied into EpiGraph (A3).
The Notion ingest half of the 2026-09-15 spec, its reconciler, and the dependency on
an HTTP `check_already_ingested` route for that purpose are dropped.

---

## 9. Data quality as found (A6)

Shown as stored; no cleanup in this work:

- stale stored theme counts (filed as a bug, backlog `57917c13`, because the overview
  route reads them)
- placeholder author names and `urn:epigraph:doc:` document keys
- theme members that look off-topic
- MCP `traverse` reporting authored truth as `belief_score` (backlog `1574d9b4`);
  the Atlas reads belief from the HTTP API, which does not share this defect

---

## 10. Phasing

| Phase | Delivers | Needs |
|---|---|---|
| P3a | Topics: regions, themes, claims, claim rings, cross-theme bundles, search, deep links | backlog `f9b4a488`, `2b5bd83e`, `4321ae80`, `57917c13`, `7f359a86`, `cadfc550`, `864368a8` |
| P3b | Provenance panel and Sources view | backlog `fe75ef36`, `da4a8bc1`, `48421526`, `b7354adc` |
| P3c | Timeline | backlog `ea26d7aa`; history route already on `main` |
| P3d | Notion: guest surface, link cards, tours | backlog `1deb9dbf`; a Notion OAuth client for the Explorer |
| P3e | Neighbourhood level | backlog `01e0b839` |

P3a can start before the layout route exists by packing themes by size, as the
prototype first did, and switch once positions ship.

**Prerequisites.** This PR rebased on `main` and split into kernel and Explorer
PRs. The OAuth hardening it was blocked on is resolved (backlog `3ae14c11`).

---

## 11. Risks

- **Different viewers, different maps.** A shared link or tour can show different
  content to different viewers. Unreadable tour stops are skipped with a note, never
  shown as errors that reveal they exist.
- **Public-only positions** can misplace a theme whose public members are atypical.
  Accepted under A1.
- **Per-viewer caching** costs more than the shared caching the 2026-09-15 spec
  assumed for overviews.
- **MCP and HTTP keep drifting.** Backlog `7f359a86`, `fe75ef36`, `8b29593c` and
  `0720d208` are parity fixes. The shared request and response types of 2026-09-15
  §9 are still the real cure.
- **A second identity.** Tours need a Notion OAuth connection alongside the EpiGraph
  session. When it is missing or fails, the tour bar says so and the map still works.

---

## 12. Backlog and ruling index

All labelled `explorer-atlas`, filed 2026-11-04.

| Id | Kind | Item |
|---|---|---|
| `f9b4a488` | feature-gap | `GET /graph/themes/layout`: theme positions per run and theme-to-theme links, from public claims |
| `2b5bd83e` | feature-gap | region level above themes |
| `4321ae80` | feature-gap | links across themes and regions: per-relationship counts and `GET /graph/links` drill-down |
| `57917c13` | bug | themes overview reports a stale `claim_count` |
| `7f359a86` | parity | `theme_id` filter on `POST /search/semantic` |
| `cadfc550` | feature-gap | `GET /claims/:id/context`: paper, section, parts, siblings, epistemic edges |
| `fe75ef36` | parity | authors and claim count in `GET /papers` |
| `da4a8bc1` | feature-gap | `GET /sources/overview` |
| `ea26d7aa` | feature-gap | claims list by theme and date window, ordered by `created_at` |
| `01e0b839` | feature-gap | readable neighbourhood labels |
| `864368a8` | feature-gap | `POST /claims/batch-get` |
| `1deb9dbf` | feature-gap | anonymous public-only reads for guests and link cards |
| `48421526` | feature-gap | `authored_by` on claims: human, agent, model, prompt snapshot (A7) |
| `b7354adc` | feature-gap | paper ingestion provenance: human, model, date (A7) |
| `1574d9b4` | bug (MCP) | `traverse` reports authored truth as `belief_score` |
| `8b29593c` | parity (MCP) | `get_agent` tool |
| `0720d208` | feature-gap (MCP) | claim context by id |
| `7b8f47a7` | ruling | owner rulings A1-A6 and defaults |
| `19e64a7b` | ruling | owner ruling A7 |
