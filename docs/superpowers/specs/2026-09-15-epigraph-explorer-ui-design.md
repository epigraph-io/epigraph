# EpiGraph Explorer — Web UI, BFF, and MCP/API parity

**Date:** 2026-09-15
**Status:** spec
**Repo:** `epigraph` (public)
**Related:** `2026-07-23-mcp-federation-gateway-design.md` (extension point),
`2026-06-03-plan-3-git-ingest-reconciler-design.md` (the reconciler pattern the
Notion ingest half reuses)

---

## 1. Motivation

There is no EpiGraph frontend. Not in this repo (no `package.json` anywhere),
not in a sibling repo. Every read of the corpus today goes through an MCP client
or `curl`. The corpus is at **476,006 claims / 1,061,399 edges** and growing;
the thing people actually ask for is "click a claim, see what it links to, click
that."

That is a hyperlinked web app, and the API already has the endpoints for it. This
spec defines the UI route table, the endpoint mapping, and the BFF that fronts
them — plus an audit of where the MCP tool surface and the HTTP API have drifted
apart, because the UI is the first consumer that makes the drift expensive.

### Non-goals

- Notion as a data store. A projection of claims into Notion databases is
  explicitly rejected in §7.
- A global graph render. See §2.
- Write flows beyond the minimum. v1 is a reader; §11 phases writes in later.

---

## 2. Corpus facts that constrain the design

Measured via `system_stats` against production, 2026-09-15:

| metric | value |
|---|---|
| claims | 476,006 |
| edges | 1,061,399 |
| embeddings | 343,370 |
| evidence | 122,876 |
| agents | 5,461 |
| frames | 126 |
| workflows | 157 |

Three consequences, each load-bearing:

1. **Never render the global graph.** Every graph view is ego-centric: one claim,
   expanded k=1, click to expand further. `claim_neighborhood`
   (`routes/edges.rs:1519`) already caps `depth` at 3; the UI caps node degree on
   top of that.
2. **Never materialise the corpus anywhere else.** At Notion's ~3 req/s write
   limit a full projection is ~44 hours of API calls for the initial load alone,
   and Notion's UI degrades long before 476k rows.
3. **Pagination is mandatory on every list surface.** `list_papers` clamps to 100;
   assume the same everywhere and design the UI around cursors, not counts.

---

## 3. UI routes

Served by the BFF (§6). Every route is a real URL — that is the whole point.

| Route | Purpose |
|---|---|
| `/` | Landing: search box, theme overview, community overview, corpus stats |
| `/search?q=&mode=` | Results. `mode` ∈ `semantic` (default), `label`, `evidence` |
| `/claim/:id` | **The core route.** Content, belief, labels, provenance summary, evidence, challenges, and outlinks grouped by `relationship` |
| `/claim/:id/graph` | Ego-graph centred on the claim |
| `/claim/:id/history` | Version history and genealogy |
| `/theme/:id` | Theme expansion |
| `/community/:id` | Community expansion |
| `/neighborhood/:id` | Precomputed cluster view, compound/atomic toggle. **Not a permalink** — see §5 |
| `/frame/:id` | Frame definition and its claims |
| `/agent/:id` | Agent profile, authored claims, epistemic profile |
| `/document/:key` | Document spine: thesis → sections → paragraphs. Where an auto-ingested Notion page lands |
| `/workflow/:id` | Workflow, steps, executions |
| `/evidence/:id` | Evidence detail |

### The outlink page, concretely

`/claim/:id` is two calls and a loop:

```
GET /api/v1/claims/:id
GET /api/v1/claims/:id/neighborhood?depth=1
  → group neighbours by `relationship`
  → render each as <a href="/claim/:target_id">
```

The neighborhood query is undirected, so inbound edges render alongside outbound
ones and backlinks come free. No backlink index to build or maintain.

---

## 4. Route → endpoint mapping

| UI route | API calls |
|---|---|
| `/` | `GET /api/v1/graph/themes/overview`<br>`GET /api/v1/graph/communities/overview`<br>`GET /api/v1/admin/stats` |
| `/search` semantic | `POST /api/v1/search/semantic` |
| `/search` label | `GET /api/v1/claims/by-labels` |
| `/search` evidence | `GET /api/v1/search/evidence` |
| `/claim/:id` | `GET /api/v1/claims/:id`<br>`GET /api/v1/claims/:id/neighborhood?depth=1`<br>`GET /api/v1/claims/:id/belief`<br>`GET /api/v1/claims/:id/evidence`<br>`GET /api/v1/claims/:id/challenges`<br>`GET /api/v1/claims/:id/provenance` |
| `/claim/:id/graph` | `GET /api/v1/claims/:id/neighborhood?depth=2`<br>or `GET /api/v1/claims/:id/compound_neighborhood` |
| `/claim/:id/history` | `GET /api/v1/claims/:id/history`<br>`GET /api/v1/claims/:id/genealogy` |
| `/theme/:id` | `GET /api/v1/graph/themes/:theme_id/expand` |
| `/community/:id` | `GET /api/v1/graph/communities/:id/expand` |
| `/neighborhood/:id` | `GET /api/v1/graph/neighborhoods/:id/expand?mode=compound\|atomic` |
| `/frame/:id` | `GET /api/v1/frames/:id`<br>`GET /api/v1/frames/:id/claims` |
| `/agent/:id` | `GET /api/v1/agents/:id`<br>`GET /api/v1/agents/:id/claims`<br>`GET /api/v1/agents/:id/epistemic-profile` |
| `/document/:key` | `GET /api/v1/papers?doi=<key>`<br>`GET /api/v1/claims/by-labels?labels=doi:<key>` |
| `/workflow/:id` | `GET /api/v1/workflows/:id`<br>`GET /api/v1/workflows/:id/behavioral-executions` |
| `/evidence/:id` | `GET /api/v1/evidence/:id` |

`/document/:key` is the one route that reassembles by hand what MCP hands over
composed — see §8.3.

---

## 5. Graph visualizer

`GET /api/v1/graph/neighborhoods/:id/expand` already returns a force-graph
payload with no transformation: nodes carry `label`, `pignistic_prob`,
`frame_id`, and (compound mode) `atom_count`; edges carry `relationship`.

- **Belief → node fill.** `pignistic_prob` on a sequential ramp.
- **Frame → hue family.** `frame_id` groups visually; 126 frames means a hashed
  palette, not a legend.
- **`atom_count` → radius** in compound mode.
- **`relationship` → edge style.** Supports/refutes/decomposes read differently.

### Two gotchas, both verified in source

**Bookmark claim IDs, never neighborhood IDs.** `expand` resolves
`neighborhood_id` only against the latest `graph_cluster_runs` row and 404s
otherwise (`routes/graph_neighborhood.rs:133`). Any URL carrying a neighborhood
ID breaks on the next clustering run. `/neighborhood/:id` is therefore a
navigational view, never a shared link; the share button on that view copies the
centre claim's URL.

**Compound is the default; atomic works.** Compound mode collapses
`decomposes_to` hierarchies, which is what a reader wants. The file's header
comment says atomic "returns an empty placeholder" — that comment is **stale**;
`atomic_response` (`routes/graph_neighborhood.rs:354`) is fully implemented.
Fixing the comment is a one-line cleanup worth doing alongside this work.

---

## 6. BFF shape

### Why a BFF rather than browser → API

Four reasons, in order of force:

1. **Ingress.** Production sits behind the VPC firewall with Caddy-only ingress.
   The API is not browser-reachable and should not become so.
2. **Token custody.** The browser must never hold an API bearer. The BFF keeps it
   server-side and exposes a session cookie instead.
3. **Composition.** `/claim/:id` is six API calls. Doing that from the browser is
   six round trips over the public internet; doing it in the BFF is six calls on
   the loopback/VPC side and one response to the browser.
4. **OpenGraph.** Notion (and Slack, and everything else) unfurls pasted URLs by
   fetching server-rendered `<meta>` tags. That requires server-side HTML.

### Placement

`services/explorer/`, following the `services/nli/` precedent: a self-contained
service with its own `Dockerfile` and a `Caddyfile.snippet` appended into the VM
Caddyfile. It is **not** a workspace crate and the kernel does not depend on it.

```
services/explorer/
  Caddyfile.snippet     # handle_path /explorer* { reverse_proxy 127.0.0.1:8090 }
  Dockerfile
  README.md
  src/                  # server-rendered pages + JSON endpoints
```

### Browser-facing endpoints

The BFF exposes composed views, not a proxy of the API:

| BFF endpoint | Composes |
|---|---|
| `GET /claim/:id` | Server-rendered HTML incl. OG tags |
| `GET /bff/claim/:id` | The six `/claims/:id/*` calls as one JSON object |
| `GET /bff/search?q=&mode=` | One of the three search endpoints |
| `GET /bff/graph/ego/:id?depth=` | Neighborhood, degree-capped |
| `GET /bff/themes`, `/bff/communities` | Overview endpoints |
| `GET /healthz` | Liveness |

**Deliberately not a generic passthrough.** A `/bff/*` route that forwards
arbitrary API paths would re-expose the whole write surface to the browser. Every
BFF endpoint is enumerated and read-only in v1.

### Auth

- OAuth authorization-code + PKCE against the existing IdP.
- The BFF holds tokens server-side; the browser gets an `httpOnly`, `Secure`,
  `SameSite=Lax` session cookie.
- **Every upstream call forwards the end user's own bearer**, not a service
  token. Pre-tenancy this changes nothing; post-tenancy it is what makes the
  `Viewer` predicate apply per user. Building it the other way would require
  rewriting the BFF the week tenancy deploys.
- Inside a Notion embed the page is third-party context, so third-party cookies
  are unreliable: sign-in is an OAuth **popup** (`window.open`), never an in-frame
  redirect, and **never a token in the embed URL** — embed URLs are visible to
  everyone who can see the Notion page and get copied around.

### Caching and limits

- `ETag` on `/bff/claim/:id` derived from the claim's `updated_at`.
- Short TTL (30–60s) on overview endpoints; they are expensive and rarely change.
- Depth and degree caps enforced **in the BFF**, not only in the UI — the BFF is
  the only publicly reachable component and is therefore the DoS boundary.

---

## 7. The Notion surface

Notion gets two things, both cheap, neither involving copying claims:

1. **One `/embed` block** pointing at the explorer, on an "EpiGraph" page.
2. **OpenGraph tags on `/claim/:id`.** Any claim URL pasted into any Notion page
   unfurls into a card showing the claim text and belief. This is how the graph
   reaches into people's writing without materialising anything.

A projection of claims into Notion databases is rejected: it is infeasible at
476k rows (§2), and it re-exports the corpus under **Notion's** ACLs rather than
EpiGraph's, which silently widens any `group`-visibility claim placed in a
teamspace with broader membership — a widening `claims_block_widening` cannot
catch, because it happens outside the database.

---

## 8. MCP ↔ API parity audit

### 8.1 Method and confidence

86 tools extracted from `SCOPE_MAP` (the authoritative closed set) against 200
route paths in `routes/mod.rs`. Matching is **path- and name-level**, with a
targeted grep across `routes/` for each suspected gap. Read this as: the gaps in
§8.2 are verified absent; the remainder are verified *present by path* and their
**semantics are unverified** — §8.3 shows why that caveat is not pedantry.

### 8.2 Confirmed gaps — MCP tool with no API equivalent

| MCP tool | Notes |
|---|---|
| `memorize` | No route. Distinct write path from `submit_claim` |
| `recall` | See §8.3 — `/search/semantic` is *not* this operation |
| `get_recall_events` | No route |
| `get_provenance_chain` | No route (`/claims/:id/provenance` is the single-hop view) |
| `query_undecomposed_claims` | No route |
| `check_already_ingested` | No route. Blocks any HTTP-side idempotent ingest |
| `ingest_document` / `_inline` / `_spine` | `/ingest/paper` and `/ingest/paper-url` are different operations |
| `structure_source` | No route. Pure function, trivially exposable |
| `verify_claim`, `update_with_evidence` | No route |
| `consolidate_claims`, `sweep_semantic_duplicates` | No route |
| `suggest_alternative_sets`, `update_partition` | No route |
| `resolve_backlog_item` | No route (composite; low priority) |

For this UI, `get_provenance_chain` and `check_already_ingested` are the ones
that bite: the first is a claim-page feature we would have to drop, the second
blocks the Notion ingest half from being driven over HTTP.

### 8.3 The drift is already real — `recall` vs `/search/semantic`

These are not one operation with two skins. Compare parameters:

| MCP `recall` (`types.rs:444`) | API `POST /search/semantic` (`routes/search.rs:430`) |
|---|---|
| `query`, `limit` | `query`, `limit` |
| `min_truth` (belief threshold) | `min_similarity` (vector distance) |
| `tags`, `agent_id` | `claim_type`, `created_after`, `created_before` |
| **`frame_id` + `perspective_id` → lensed belief** | — |
| — | **`diverse`, `max_themes`, `diversity_weight`, `candidate_pool`, `centroid_dim`** |

So today: an **agent** using MCP gets lens-aware recall and no diversity; a **UI**
built on the API gets theme-diverse retrieval and no lenses. Same corpus, same
pgvector index, two divergent retrieval features — and the divergence is
invisible until someone tries to build both surfaces at once, which is what this
spec does.

`query_paper` is the same story in miniature: MCP returns the paper *with* its
claims and a deliberate asserted-vs-labelled discrepancy probe that catches
partial ingests (`tools/paper_queries.rs:71-77`). `GET /api/v1/papers?doi=` returns
metadata only, so `/document/:key` reassembles it from a second label query and
**loses the probe**.

### 8.4 Why it drifted — measured

CLAUDE.md says all SQL lives in `crates/epigraph-db/src/repos/`. Neither surface
holds to it:

| | files with raw `sqlx::query` | total |
|---|---|---|
| `epigraph-mcp/src/tools/` | 12 | 38 |
| `epigraph-api/src/routes/` | 33 | 64 |

Half the API's route files reach past the repo layer. That is the mechanism: two
surfaces writing their own SQL against the same tables will diverge, and the
convention that was supposed to prevent it is not being enforced by anything.

---

## 9. Should MCP call the API?

**Recommendation: no — and the framing should change.**

Routing MCP through HTTP costs a network hop and a serialisation round trip on
every tool call, forfeits transactional composition (several tools do multi-step
writes that must not interleave), and doubles the auth surface (the MCP server
would hold a service credential *and* forward user bearers). It also inverts the
documented architecture, where both surfaces are peers over the repo layer.

The drift in §8.3 is not SQL drift. It is **contract drift** — parameter names,
defaults, filter semantics, and which features exist at all. An HTTP hop does not
fix that; it just relocates it.

What does fix it, in increasing order of cost:

1. **Close the §8.2 gaps.** Every MCP tool gets a route. Mechanical, unblocks the
   BFF, and needs no architectural change. Do this one.
2. **Shared request/response types.** Extract the parameter structs and response
   DTOs into a shared crate that both `#[tool_router]` and the axum handlers
   depend on. A field added on one side then fails to compile on the other. This
   is the actual fix for §8.3.
3. **Enforce the repo-layer rule.** A ratchet test counting raw `sqlx::query` in
   `routes/` and `tools/`, stepping down, in the style the tenancy series used for
   `no_unscoped_pool.rs`. Stops the bleeding without a big-bang refactor.
4. **A shared service layer** between repos and both surfaces. The real endgame,
   and much too large to attach to this UI work.

**Proposed backlog item:** *"MCP and HTTP API have drifted into divergent
contracts over the same corpus; share the request/response types and ratchet raw
SQL out of both surfaces."* Items 1–3 above, with §8.2 and §8.3 as evidence. Item
1 is a prerequisite for this spec's Phase 2; items 2–4 are not, and should not
block the UI.

---

## 10. Tenancy interaction

`integration/tenancy` is 188 commits ahead of `main`; production is at migration
59 with the 060–091 series unapplied. Per `docs/tenancy/COMPLETION-PLAN.md` the
deploy is gated behind the conversion tail, FORCE preconditions, step 11d, the
backfill, and an end-to-end suite. **Do not block this UI on it** — but build for
it:

- The BFF forwards the end user's bearer from day one (§6). That is the whole
  tenancy integration on the read path; the `Viewer` predicate does the rest.
- A web UI is strictly better than any Notion projection here, because a
  projection necessarily reads as one service identity and then re-exports under
  a different permission system (§7).
- `D-PR16-recall-events-are-instance-wide` means `get_recall_events` is currently
  readable by everyone. If it gets an API route (§8.2) and the UI surfaces it,
  that widens the blast radius of an already-known finding. **Gate that one route
  behind tenancy** rather than shipping it in Phase 1.

---

## 11. Phasing

**Phase 1 — the reader.** `/`, `/search`, `/claim/:id` with outlinks, OG tags,
BFF with OAuth. No graph canvas. This is the smallest thing that delivers the
"click a link, get a page with outlinks" experience, and it is roughly a week.

**Phase 2 — the graph.** `/claim/:id/graph`, `/theme/:id`, `/community/:id`,
`/neighborhood/:id`. Needs §9 item 1 for the claim-page gaps.

**Phase 3 — documents and Notion.** `/document/:key`, the Notion embed, the
auto-ingest reconciler. Depends on `check_already_ingested` having a route.

**Phase 4 — writes.** Challenge, label, supersede from the UI. Only after
tenancy, because a write surface without ownership enforcement is the one thing
here that is genuinely unsafe.

---

## 12. Open decisions

1. **BFF language.** Rust/axum matches the team and the repo; a Node/TS BFF gets
   server-rendered React and a better component ecosystem for the graph canvas.
   The `services/` precedent (`nli` is Python) means either is in keeping.
2. **Graph library.** Force-directed at ~100 visible nodes is undemanding; the
   choice matters less than the degree cap.
3. **Does `get_recall_events` ship at all?** See §10.
4. **Who owns the parity backlog item** — it spans both surfaces and belongs to
   neither.
