# EpiGraph Explorer — implementation plan (Phases 1+2)

**Date:** 2026-09-15
**Spec:** `docs/superpowers/specs/2026-09-15-epigraph-explorer-ui-design.md`
**Handoff:** `docs/superpowers/plans/2026-09-15-epigraph-explorer-handoff.md`
**Status:** in progress

This plan is the contract every implementation agent codes against. Where it
disagrees with the spec, **this plan wins** — each disagreement below was
verified in source during a mapping pass (six readers + a cross-checking critic)
and is cited.

## 0. Decisions taken

| Decision | Choice | Why |
|---|---|---|
| BFF language | Rust / axum 0.8 | Matches team + CI; graph canvas is client-side JS either way |
| Templates | `askama` (auto-escaping) | Claim text is untrusted and lands in HTML and OG attributes; the tree has no templating precedent, and hand-rolled `format!` escaping does not scale |
| Graph canvas | Hand-written SVG force layout in vanilla JS, served from `/static/` | Ego graphs are ≤ ~100 nodes; zero third-party JS keeps CSP at `script-src 'self'` |
| Scope | Spec Phases 1+2 | Phase 3 needs the Notion decisions (handoff §7); Phase 4 is tenancy-gated |
| Port | `8096` | 8080 API, 8000 nli, **8090 is episcience** (spec's 8090 collides), 8093/8094 federation |
| Health path | `/health` | Repo convention (API, nli, rate-limit bypass list); spec's `/healthz` does not match |
| Workspace | `services/explorer/` with its own empty `[workspace]` table | `workspace = true` cannot resolve outside the workspace (the harvester is broken this way today) |

## 1. Spec corrections (verified)

1. **`/claim/:id` is not "two calls and a loop".** `/claims/:id/neighborhood`
   returns edge rows + UUIDs only (`routes/edges.rs:439-490`); rendering link text
   is an N+1 against a 10-connection pool with no statement/HTTP timeout
   (`bin/server.rs:207-209`). → new kernel route `GET /claims/:id/ego` (§2.2).
2. **Neighborhood truncation drops backlinks.** Outgoing rows are collected first
   and the set is cut at 500 (`edges.rs:1538-1595`). The ego route balances
   in/out.
3. **`/claims/:id/genealogy` is political propagation**, not version history
   (`political.rs:556-560`). History = `/claims/:id/history` only.
4. **`/claims/:id/provenance` is not "the single-hop view" of
   `get_provenance_chain`** — it walks claim → trace → evidence; the chain walks
   claim → claim. Both are shown, as separate sections.
5. **Graph overview/expand routes are on the protected router**
   (`routes/mod.rs:464-475`) and need a bearer even pre-tenancy.
6. **`/api/v1/admin/stats` is process diagnostics**, not corpus counts
   (`admin.rs:29-104`). → new kernel route `GET /api/v1/stats` (§2.4).
7. **No route maps a claim to its theme/cluster/neighborhood.** → new kernel
   route `GET /claims/:id/placement` (§2.3). Theme and community ids are also
   regenerated per run, so none of `/theme/:id`, `/community/:id`,
   `/neighborhood/:id` are permalinks.
8. **Caddy `handle_path /explorer*` strips the prefix** — the BFF takes a
   configured base path and generates every link, redirect, `og:url` and cookie
   `Path` from it.
9. **The API is its own OAuth AS, federating only to Google** behind an email
   allowlist; `/oauth/*` must stay browser-reachable. The BFF cannot
   self-register (`oauth/register.rs:85-95` allows only claude.ai/claude.com
   redirect URIs) → operator inserts the client row by SQL (README).
10. **Several read routes return unredacted content** that `GET /claims/:id`
    redacts, and `check_content_access` **fails open** on a DB error
    (`epigraph-db/src/access_control.rs:58-68`). → kernel fixes (§2.5, §2.6).

## 2. Kernel changes (`crates/epigraph-api`, `crates/epigraph-db`)

All new SQL in `crates/epigraph-db/src/repos/` (or `access_control.rs`). All new
read routes on the **db `public` router** with `optional_bearer_auth_middleware`,
the `Option<axum::Extension<AuthContext>>` extractor, and
`requester = ctx.agent_id.or(Some(ctx.client_id))` — the `get_claim` pattern.
New handlers live in `#[cfg(feature = "db")]` modules registered **once**, in the
db router only (no `not(db)` stub needed). Tests use `#[sqlx::test]` against the
local server; route tests are top-level files in `crates/epigraph-api/tests/`.

Local DB: `postgres://postgres@127.0.0.1:55432/epigraph_db_repo_test`
(pgserver, TCP only). Never the live `epigraph` DB.

### 2.1 `GET /api/v1/claims/:id/provenance-chain`

Query: `max_depth` (`u32`, default 4, clamped to `1..=8`), `relationships`
(comma-separated; empty ⇒ default set). Calls
`ProvenanceChainRepository::chain` unchanged. **404** when the root is absent from
`nodes` (the repo returns empty success today). Per-node redaction.

```json
{ "root": "uuid",
  "nodes": [{ "id": "uuid", "content": "string", "truth_value": 0.5,
              "labels": ["..."], "is_current": true, "depth": 0, "redacted": false }],
  "edges": [{ "source": "uuid", "target": "uuid", "relationship": "supports" }],
  "truncated": false,
  "cycles": [["uuid", "..."]] }
```

Avoid the name clash with `routes/edges.rs:2164 pub struct ProvenanceChain`.

### 2.2 `GET /api/v1/claims/:id/ego`

Depth-1, hydrated, degree-capped neighbourhood — the outlink page and the graph
canvas both read this. Query: `max_degree` (default 40, clamp `1..=200`),
`relationships` (optional comma-separated filter).

- Excludes retracted edges (`valid_to` set and `<= now()`).
- Balanced cap: up to ⌈max/2⌉ inbound and ⌈max/2⌉ outbound, each newest-first;
  unused budget on one side goes to the other.
- Hydrates neighbours in one query per entity table (claims, agents, evidence,
  frames, papers where hydratable); unknown types get `label = entity_type`.
- Redaction via the batch access check (§2.5). Mirrors `claim_neighborhood`:
  edges touching a redacted *neighbour* claim are dropped; a redacted *centre*
  returns the centre with `redacted: true` and no edges.
- `total_edges` is **redaction-aware**: the repository counts the degree in the
  database, and the route subtracts the edges it then dropped for redaction
  before serialising. Reporting the raw degree beside a redacted edge list
  would state exactly how many neighbours the viewer may not see — the same
  metadata the redacted-centre case already withholds. With the cap not in
  play the number is therefore exactly `edges.len()`.
- `truncated` means the **degree cap** cut the list, and only that; redaction
  never sets it. So the pair is readable as "there is more to see, and this is
  how much of it you are allowed to know about", which is what the Explorer's
  "connection limit cut the list" notice relies on (it renders `total_edges`
  verbatim and trusts `truncated` alone — see
  `services/explorer/src/pages/core/relationships.rs::group_outlinks`).
- **404** when the centre claim does not exist.

```json
{ "center": EgoNode,
  "nodes": [EgoNode],
  "edges": [{ "id": "uuid", "source_id": "uuid", "target_id": "uuid",
              "source_type": "claim", "target_type": "agent",
              "relationship": "supports", "direction": "out" }],
  "total_edges": 123,
  "truncated": true }
```

`EgoNode`: `id`, `entity_type`, `label` (≤ 160 chars, cut on a char boundary),
and for claims `content`, `truth_value`, `pignistic_prob?`, `labels`,
`is_current`; `redacted: bool` on every node. `direction` is relative to the
centre (`"out"` = centre is source).

### 2.3 `GET /api/v1/claims/:id/placement`

```json
{ "claim_id": "uuid", "theme_id": "uuid|null", "cluster_run_id": "uuid|null",
  "cluster_id": "uuid|null", "neighborhood_id": "uuid|null",
  "run_completed_at": "rfc3339|null" }
```

Resolves the cluster run with **the same lookup** the expand routes use, so a
returned id is one `expand` will accept at that moment. 404 when the claim does
not exist; all-null is a normal answer (clustering is operator-triggered and
only leaf claims get neighbourhoods).

### 2.4 `GET /api/v1/stats`

Corpus counts for the landing page. Move the SQL behind MCP `system_stats`
(`epigraph-mcp/src/tools/batch.rs:122-189`) into a repo function that **both**
surfaces call.

```json
{ "claims": 0, "edges": 0, "evidence": 0, "embeddings": 0, "agents": 0,
  "frames": 0, "workflows": 0, "computed_at": "rfc3339" }
```

### 2.5 Access-control fixes

- `check_content_access` **fails closed**: a lookup error yields `Redacted`, not
  `Full`.
- A set-based `batch_content_access(pool, ids, requester) -> HashMap<Uuid,
  ContentAccess>` with the exact semantics of `check_content_access`, proven by
  an equivalence test over public / private-owner / private-other /
  community-member / community-other / no-ownership-row fixtures. Fails closed.

### 2.6 Redaction sweep

Apply the batch check to every read the Explorer renders claim text from that
does not redact today: `POST /search/semantic`, `GET /claims/by-labels`,
`GET /claims/:id/history`, `GET /agents/:id/claims`, `GET /frames/:id/claims`,
and the three graph `expand` routes (labels are claim content). Redacted ⇒
`"[REDACTED]"`, the existing convention.

### 2.7 Small fixes

- `/claims/:id/provenance` byte-slices at 57 and panics on multi-byte UTF-8
  (`edges.rs:2215-2216`); with no `CatchPanicLayer` the connection drops. Cut on a
  char boundary.
- `/claims/:id/history` has no cycle guard (`versioning.rs:536-605`) and
  `mark_duplicate` can create cycles. Add a visited set.
- Stale header comment in `routes/graph_neighborhood.rs:9-10` (atomic mode is
  implemented).
- Consent page hard-codes "Authorize Claude" (`oauth/authorize.rs:271-273`):
  name the requesting client (escaped).

## 3. The Explorer service (`services/explorer/`)

### 3.1 Layout

```
services/explorer/
  Cargo.toml  Cargo.lock  .gitignore  .dockerignore
  Dockerfile  Caddyfile.snippet  README.md  explorer.example.toml
  src/
    main.rs            # config → state → router → serve
    config.rs          # env parsing + validation
    state.rs           # AppState
    error.rs           # AppError → HTML/JSON responses
    security.rs        # headers middleware (CSP etc.)
    links.rs           # base-path-aware URL builders
    upstream/          # typed client for epigraph-api
      mod.rs           # client: bearer, semaphore, timeout, 401→refresh→retry
      types.rs         # shared DTOs (claim, belief, ego, …)
    auth/              # OAuth code+PKCE, sessions, cookies, embed handoff
    pages/             # server-rendered routes
      core.rs          # /, /search, /claim/:id
      entities.rs      # /claim/:id/history, /claim/:id/provenance, /agent, /frame, /evidence
      graph.rs         # /claim/:id/graph, /theme, /community, /neighborhood
    bff.rs             # /bff/* JSON
  templates/           # askama
  static/              # app.css, graph.js, embed.js
  tests/               # wiremock-backed upstream
```

### 3.2 Configuration (env)

| Var | Default | Notes |
|---|---|---|
| `EPIGRAPH_API_URL` | `http://127.0.0.1:8080` | repo-standard name |
| `EPIGRAPH_EXPLORER_PORT` | `8096` | bind `127.0.0.1` |
| `EPIGRAPH_EXPLORER_PUBLIC_BASE_URL` | **required** | absolute origin + base path, e.g. `https://explorer.example.com/explorer`; used for OG, redirects, `redirect_uri` |
| `EPIGRAPH_OAUTH_BASE_URL` | = API URL | browser-facing OAuth AS origin (`/oauth/authorize`) |
| `EPIGRAPH_EXPLORER_CLIENT_ID` | required for login | pre-registered client (README SQL) |
| `EPIGRAPH_EXPLORER_PUBLIC_UNFURL` | `false` | when true, anonymous `/claim/:id` renders OG text from an anonymous upstream read; else a generic card |
| `EPIGRAPH_EXPLORER_FRAME_ANCESTORS` | `https://www.notion.so https://*.notion.so https://*.notion.site` | CSP `frame-ancestors` |
| `EPIGRAPH_EXPLORER_UPSTREAM_CONCURRENCY` | `6` | global semaphore, well under the API's pool of 10 |
| `EPIGRAPH_EXPLORER_UPSTREAM_TIMEOUT_MS` | `8000` | per call |
| `EPIGRAPH_EXPLORER_INSECURE_COOKIES` | `false` | drop `Secure` for plain-http local dev |
| `EPIGRAPH_EXPLORER_DEV_BEARER` | unset | **dev only**: refused at startup unless the public base URL host is `localhost`/`127.0.0.1` |

No real hostnames or IPs in source, docs or examples — RFC 2606 names only
(`explorer.example.com`); the `no_deployment_host_literals` test scans
`rs md toml yml yaml sql json sh`.

### 3.3 Auth

- Authorization code + PKCE (S256, mandatory upstream) against
  `{EPIGRAPH_OAUTH_BASE_URL}/oauth/authorize`, `scope=claims:read`. Public client,
  no secret. `redirect_uri = {PUBLIC_BASE_URL}/auth/callback` (exact match
  upstream). Code TTL is 60 s — redeem immediately.
- Token endpoint takes form bodies; errors are `{error, message, details}`, not
  RFC 6749 — hand-written client, no `oauth2` crate.
- Session store in memory: random 256-bit session id → `{access, refresh,
  expires_at}`. Restart ⇒ re-login (documented). Refresh **single-flight per
  session**; rotate and store the new refresh token every time. Refresh
  proactively 60 s before expiry and once after any upstream 401; a second 401
  ends the session.
- Upstream quirk: a present-but-invalid bearer gets 401 even on public routes;
  never send a stale token.
- Session cookie `epx_session`: `HttpOnly`, `Secure`, `SameSite=Lax`,
  `Path={base_path}`.
- **Embed sign-in** (Notion iframe is third-party): login opens a popup
  (`mode=popup`); the callback page `postMessage`s a single-use 60 s handoff code
  to `window.opener` with `targetOrigin` = own origin; the iframe `POST`s it to
  `/auth/redeem`, which sets the cookie `SameSite=None; Secure; Partitioned`. No
  token ever appears in a URL.
- Logout: `POST /auth/logout` (Origin-checked) → revoke refresh token upstream
  (JSON body), drop the session.
- Every HTML page except `/health`, `/auth/*`, `/static/*` requires a session.
  Anonymous `/claim/:id` returns **200** with a sign-in prompt and OG tags (a
  redirect would unfurl as a login page); OG text only when
  `PUBLIC_UNFURL=true` and the anonymous upstream read is not redacted.

### 3.4 Routes

| Route | Upstream |
|---|---|
| `GET /` | `/api/v1/stats`, `/graph/themes/overview`, `/graph/communities/overview` |
| `GET /search?q=&mode=semantic\|label\|evidence&page=` | `POST /search/semantic` · `GET /claims/by-labels` · `GET /search/evidence` |
| `GET /claim/:id` | `/claims/:id`, `/claims/:id/ego`, `/claims/:id/belief`, `/claims/:id/evidence`, `/claims/:id/supporting-evidence`, `/claims/:id/contradicting-evidence`, `/claims/:id/challenges`, `/claims/:id/provenance`, `/claims/:id/placement` |
| `GET /claim/:id/provenance` | `/claims/:id/provenance-chain` |
| `GET /claim/:id/history` | `/claims/:id/history` |
| `GET /claim/:id/graph` | page shell; data from `/bff/graph/ego/:id` |
| `GET /theme/:id` | `/graph/themes/:id/expand` |
| `GET /community/:id` | `/graph/communities/:id/expand` |
| `GET /neighborhood/:id?mode=` | `/graph/neighborhoods/:id/expand` |
| `GET /agent/:id` | `/agents/:id`, `/agents/:id/claims` ("attributed claims"), `/agents/:id/epistemic-profile` |
| `GET /frame/:id` | `/frames/:id`, `/frames/:id/claims` |
| `GET /evidence/:id` | `/evidence/:id` |
| `GET /bff/claim/:id` | composed JSON of `/claim/:id` |
| `GET /bff/search` | as `/search` |
| `GET /bff/graph/ego/:id?max_degree=` | `/claims/:id/ego` |
| `GET /bff/themes`, `/bff/communities` | overviews (60 s cache, keyed per user) |
| `GET /health` | liveness |
| `GET /auth/login`, `/auth/callback`, `POST /auth/logout`, `POST /auth/redeem` | auth |

- **Rules for rendering.** If `GET /claims/:id` returns content `"[REDACTED]"`,
  skip every other content-bearing sub-call and keep the text out of OG.
- **Degraded sections.** A failed or timed-out sub-call renders that section as
  unavailable; the page still renders.
- **Outlink grouping.** Mirror `GRAPH_VIEW_RELATIONSHIPS` (`routes/graph.rs:29-66`)
  with case-folding and alias merging; everything else goes under "Other".
- **Entity links.** `claim`, `agent`, `evidence` and `frame` link to pages. Other
  entity types render as plain text.
- **Evidence type vocabularies** differ per endpoint. Normalise them for display.
  A DOI in `source_url` becomes `https://doi.org/<doi>`.
- **History.** Label versions reached through `mark_duplicate` as "duplicate of".
- **Theme expand.** A synthetic theme-expand entry (`label == "synthetic" && size
  == 0`) and a 404 from expand both render "view expired — clustering has
  re-run".
- **Sharing.** Share buttons on theme/community/neighbourhood views copy the
  centre claim's URL.
- **Deserialization.** Upstream omits optional fields rather than sending
  `null`, so use `#[serde(default)]` and `Option` everywhere. Bad-UUID rejections
  are `text/plain`, not JSON.

### 3.5 Limits, caching, headers

- Upstream calls go through a global semaphore with a per-call timeout. Page
  sub-calls run concurrently under it.
- Caps are enforced in the BFF: `max_degree ≤ 80`, search `limit ≤ 50`, and theme
  and community expand budgets are clamped.
- `/bff/claim/:id` carries a weak ETag over the composed body. `updated_at` does
  not move when edges are added, so it cannot be the ETag.
- Security headers:
  - CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'
    data:; connect-src 'self'; form-action 'self'; base-uri 'none';
    frame-ancestors <configured>`.
  - `X-Content-Type-Options: nosniff`.
  - `Referrer-Policy: same-origin`.
- Output is escaped by askama everywhere. Text is only truncated on char
  boundaries.

### 3.6 Graph canvas (`static/graph.js`)

- SVG force layout: velocity-Verlet with charge, links and centring. Pan, zoom
  and drag.
- Single click selects a node and shows its detail. Double click or "expand"
  fetches `/bff/graph/ego/:id` and merges the result. The link opens the node's
  page.
- Node fill is a sequential ramp on `pignistic_prob`, falling back to
  `truth_value`. Hue comes from a hashed `frame_id` or entity type. Radius comes
  from `atom_count` where present.
- Edge style is set by relationship family: support (solid), refute (dashed,
  warm) and structural (thin grey).
- A visible node cap of 150, with a "truncated" notice. The layout works in light
  and dark themes (`prefers-color-scheme`).

### 3.7 Ops

- `.github/workflows/explorer.yml` runs from `working-directory: services/explorer`
  with the same pinned action SHAs as `ci.yml`. It runs `fmt --check`, `clippy
  --all-targets --locked -D warnings`, and `test --locked`, plus an advisory
  `cargo audit --file Cargo.lock`. `scripts/verify.sh` gains an explorer step.
- The binary and package are named `epigraph-explorer`. Never `server`: the
  deploy host shares one target dir.
- The Caddy snippet uses `handle_path /explorer*` and `reverse_proxy
  127.0.0.1:8096`. The BFF's configured base path handles the stripped prefix.
- `README.md` covers the operator SQL for the OAuth client row, the Google
  allowlist note, env vars, local dev, the in-memory session caveat, and the
  post-tenancy OG caveat.

## 4. Deferred (backlog, not this PR)

- MCP `get_provenance_chain` does not redact. The new route does, so this is a
  live MCP-side leak.
- Configurable `register.rs` redirect-origin allowlist.
- API pool size and `statement_timeout` configuration. A `CatchPanicLayer`.
- `POST /search/hybrid` wrapping `search_hybrid_scoped_since`. This closes part
  of the `recall` drift (spec §8.3) and gives an indexed keyword mode.
- The latest-run lookup lacks an `algo='louvain'` filter.
- Post-tenancy OG unfurls. Under D3, anonymous callers get nothing, so this needs
  a design.
- The parity backlog item (spec §9).
