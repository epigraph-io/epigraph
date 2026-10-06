# epigraph-explorer — web UI and BFF for EpiGraph

The EpiGraph Explorer lets people browse the EpiGraph knowledge graph in a
browser. It renders pages on the server for claims, their evidence, belief,
history and provenance, and for agents, frames and evidence records. It also
shows search results and graph views (ego graph, themes, communities,
neighbourhoods). For the operator it adds four read-only pages: open
backlog items, the security events the viewer may read, what a configured
list of agents did, and pending cross-source match candidates. A small JSON
surface under `/bff/*` feeds the client-side graph canvas and the audit page.

The Explorer only reads. Resolving backlog items, deciding match candidates,
challenging, labelling and superseding stay on MCP and the CLI.

It is a **backend-for-frontend**. It holds no data. Every read goes to
`epigraph-api` with the signed-in viewer's own bearer token, so the API's
per-viewer visibility decides what each viewer sees: a row the viewer may not
read is **absent** from the response, never blanked. The Explorer never uses a
service token of its own.

- Crate and binary: `epigraph-explorer` (Rust, axum 0.8, askama templates).
- Standalone crate: it has its own empty `[workspace]`, its own `Cargo.lock`
  and its own `target/`. It is not a member of the kernel workspace, so root
  `cargo … --workspace` commands never build it. CI:
  [`.github/workflows/explorer.yml`](../../.github/workflows/explorer.yml).
  Local gate: `scripts/verify.sh`.
- Default port: `8096`. It binds `127.0.0.1` only. The other loopback ports
  are taken: 8080 is the API, 8000 nli, 8090 episcience, and 8093/8094 the
  federation extensions.
- Design contract: `docs/superpowers/plans/2026-09-15-epigraph-explorer-impl-plan.md`
  (this overrides the spec where they disagree). The spec is
  `docs/superpowers/specs/2026-09-15-epigraph-explorer-ui-design.md`.

## Architecture

```
                      https://explorer.example.com/   (its own host, served at the root)
  browser ─────────────────────▶ Caddy (public edge)
     │                             │
     │                             │ explorer.example.com { reverse_proxy … }
     │                             ▼
     │                   epigraph-explorer  127.0.0.1:8096
     │                     • askama pages + /bff JSON + /static (compiled in)
     │                     • in-memory sessions (access + refresh token)
     │                     • one global upstream semaphore, a per-viewer
     │                       in-flight cap, per-call timeout
     │                             │  Authorization: Bearer <viewer's token>
     │                             │  /oauth/token, /oauth/revoke,
     │                             │  /oauth/introspect (no bearer)
     │                             │  EPIGRAPH_API_URL (loopback)
     │                             ▼
     │   /oauth/authorize  epigraph-api  :8080   (systemd: epigraph-api.service)
     └─────────────────────▶   /api/v1/*  ── reads, filtered per viewer
        (top-level              /oauth/*   ── authorization server
         navigation to the API's          │
         own host,                        │
         EPIGRAPH_OAUTH_BASE_URL)         │
                                     ▼
                              Google OIDC (email allowlist)
```

- **Pages** are server-rendered HTML. Each page makes several upstream calls
  concurrently. A failed optional sub-call shows up as an "unavailable"
  section, and the rest of the page still renders.
- **`/bff/*`** returns the same data as JSON for the graph canvas
  (`static/graph.js`, a hand-written SVG force layout). No third-party
  JavaScript is loaded.
- **Assets.** Everything is compiled into the binary: templates at compile
  time, and every file under `static/` through `build.rs`. Asset URLs carry a
  content hash and are served as immutable. The deployable artifact is the
  binary alone.

### Routes

Deploy the Explorer at the root of its own host (see Deploy). It still
supports a base path, for local testing: it then serves every route both at
the root and under the base path, so it works behind a proxy that strips the
prefix or one that does not, and every link it generates includes the base
path. A base path costs the `__Host-` cookie prefix (see Security model).

| Route | What it shows |
|---|---|
| `GET /` | Corpus counts, theme overview, community overview |
| `GET /search?q=&mode=semantic\|label\|evidence&page=` | Search results |
| `GET /claim/{id}` | A claim: belief, evidence, challenges, provenance, grouped outlinks, placement |
| `GET /claim/{id}/history` · `/provenance` · `/graph` | Version history · derivation chain · graph canvas |
| `GET /theme/{id}` · `/community/{id}` · `/neighborhood/{id}?mode=` | Clustering views (not permalinks; see Caveats) |
| `GET /agent/{id}` · `/frame/{id}` · `/evidence/{id}` | Entity pages |
| `GET /backlog?label=&page=` | Open backlog items, newest first (see Operator pages) |
| `GET /audit?since=&until=&type=&failures=1` | Security events the viewer may read, counted by type, with a drill-down (see Operator pages) |
| `GET /activity?since=` | The watched agents' newest claims, and an events tail (see Operator pages) |
| `GET /candidates?status=` | Cross-source match candidates as side-by-side pairs (see Operator pages) |
| `GET /acts` | Reserved for the viewer's own admin acts. It is not built yet: it answers 501 "not yet available", makes no upstream call, and has no navigation link |
| `GET /bff/claim/{id}` · `/bff/search` · `/bff/graph/ego/{id}?max_degree=` · `/bff/themes` · `/bff/communities` · `/bff/neighborhood/{id}` | JSON for the canvas |
| `GET /bff/audit?since=&until=&type=&failures=1` | The audit page's counted window as JSON |
| `GET /auth/login` · `GET /auth/callback` · `POST /auth/logout` · `POST /auth/redeem` | Sign-in (see Security model) |
| `GET /health` | Liveness: `{"status":"ok","version":"…"}` |
| `GET /static/{path}` | Compiled-in CSS/JS |

Every HTML page except `/health`, `/auth/*` and `/static/*` needs a session.
An anonymous page request gets a 303 to `/auth/login?return_to=…`, and an
anonymous `/bff/*` request gets a JSON `401 {"error":"unauthorized"}`. The one
exception is `/claim/{id}`. For an anonymous visitor it returns **200** with a
sign-in prompt and OpenGraph tags, because a redirect would unfurl in chat
apps as a login page.

### Operator pages

Each page is read-only, needs a session, and reads with the viewer's own
token. An empty answer and a failed one render differently: "no … that you
can read" is a real empty result, and "unavailable" means the API call
failed. A query value the page will not send (a bad time, status or label)
is explained on the page, and the API is not called.
Times are UTC; `since` and `until` take RFC 3339, `YYYY-MM-DDTHH:MM[:SS]` or a
bare date, and `since` defaults to 24 hours ago.

- **`/backlog`** lists current claims labelled `backlog` and not labelled
  `resolved`, newest first, a page at a time. `label=` narrows the list to
  one more label (a comma is refused, because the API would AND the labels).
  With `EPIGRAPH_EXPLORER_KANBAN_URL` set, each row also has an
  "Open in kanban" link. It opens the board, not the item: the board has no
  per-item address.
- **`/audit`** counts the security events of the window by `event_type`,
  with each type's failures. `failures=1` keeps failures only, and `type=`
  drills down to that type's newest 200 rows (the counts still cover the
  whole window). The page reads the API in pages of 1 000 rows, moving an
  `until` cursor back, up to `EPIGRAPH_EXPLORER_AUDIT_ROW_CEILING` rows:
  - a window holding more than the ceiling is marked **capped**: narrow it;
  - a page that fails after the first keeps the counts read so far under an
    **incomplete** banner, and so does a window it cannot page past (more
    than 1 000 events at one timestamp);
  - a first page that fails leaves the section **unavailable**, never a 500.

  It needs the `audit:read` scope **granted to the signing-in user's own
  per-user client** (see Operator setup §1). The Explorer requests it, and
  the API silently drops a scope the user was not granted. When the token's
  scope lacks it, the page explains that and does not call the API; an API
  403 gets the same answer.

  Which events a viewer may read is the API's decision. The page says "you
  see only your own security events" unless the rows it read show more (an
  event with no agent, or events of two agents), and then says this account
  reads more than its own events. It also says, on every view, that it shows
  only events the viewer may read, and that refresh-token volume and
  liveness are not in this trail.
- **`/activity`** shows, for each agent in `EPIGRAPH_EXPLORER_WATCH_AGENTS`,
  its newest 20 claims created since `since`, each linked to its claim page,
  and marks a list the API counted more rows for as capped. One agent's
  failed call leaves only that agent "unavailable". Below that is an **events
  tail**: one read of the API's recent events since `since`, kept only where
  a watched agent is the actor, newest first, at most 100 rows. The API's
  event list cannot be filtered by agent and holds only a window of its
  newest events, so the tail is labelled as corpus-wide and filtered here,
  and it is **not a complete record** of the watched agents since `since`.
  With no watch list, the page explains how to set one and calls nothing.
- **`/candidates`** lists cross-source match candidates of one status
  (`pending` by default; `promoted`, `rejected` and `stale` by the
  switcher), highest score first, at most the top 100 per status with a
  "there may be more" marker. Each candidate is a side-by-side pair of claim
  excerpts, each linked to its own claim page, with score, verifier verdict
  and rationale. Only pairs whose **both** claims the viewer may read are
  listed. There are no decide controls: deciding stays on MCP and the CLI.

## Configuration

All configuration comes from environment variables, read once at startup
(`src/config.rs`). The Explorer reads no config file. An empty or
whitespace-only value counts as unset. The one exception is
`EPIGRAPH_EXPLORER_FRAME_ANCESTORS`, described in the table. Invalid
configuration makes the process print the problem to stderr and exit with
code **2**.

| Variable | Default | Notes |
|---|---|---|
| `EPIGRAPH_EXPLORER_PUBLIC_BASE_URL` | **required** | The absolute public URL. In production it is the root of the Explorer's own host, `https://explorer.example.com`, with an **empty path** (see Deploy); a base path such as `http://localhost:8096/explorer` is for local testing. Every link, redirect, `og:url` and cookie `Path`, and the OAuth `redirect_uri` (`{this}/auth/callback`), are built from it. It must be `http(s)`. It may not contain a query, a fragment or credentials. Path segments are limited to letters, digits and `-` `_` `.` `~`. A trailing `/` is ignored. Its **first** segment may not be one of the Explorer's own top-level routes (`activity`, `acts`, `agent`, `audit`, `auth`, `backlog`, `bff`, `candidates`, `claim`, `community`, `evidence`, `frame`, `health`, `neighborhood`, `search`, `static`, `theme`): the routes are mounted both under the base path and at the root, so such a base path would make two handlers claim the same URL. The process refuses to start (exit 2) and names the offending segment. |
| `EPIGRAPH_API_URL` | `http://127.0.0.1:8080` | The `epigraph-api` origin, called server to server. This is the repo-standard variable name. |
| `EPIGRAPH_EXPLORER_PORT` | `8096` | Port to bind, always on `127.0.0.1`. Must be 1–65535. |
| `EPIGRAPH_OAUTH_BASE_URL` | same as `EPIGRAPH_API_URL` | The **browser-facing** origin of the API's OAuth server, and only that: the browser is sent to `{this}/oauth/authorize`. In production it is the API's public origin (e.g. `https://api.example.com`), never loopback. The Explorer itself never calls this origin — the server-to-server `/oauth/token`, `/oauth/revoke` and `/oauth/introspect` calls go to `EPIGRAPH_API_URL` (the same process, over loopback), which keeps the authorization code, the refresh token and the client id off the public edge. |
| `EPIGRAPH_EXPLORER_CLIENT_ID` | unset | The `client_id` of the pre-registered OAuth client (see Operator setup). If it is unset, sign-in is disabled and a warning is logged at startup. Whitespace is rejected. |
| `EPIGRAPH_EXPLORER_FRAME_ANCESTORS` | `https://www.notion.so https://*.notion.so https://*.notion.site` | The CSP `frame-ancestors` source list, space-separated. `;`, `,`, control characters and non-ASCII are rejected. Setting it **explicitly empty** means `'none'` (no framing at all). |
| `EPIGRAPH_EXPLORER_UPSTREAM_CONCURRENCY` | `6` | Size of the global semaphore on upstream calls, clamped to 1–8. The API's database pool has 10 connections, shared with every other client. A clamped value is logged. |
| `EPIGRAPH_EXPLORER_SESSION_CONCURRENCY` | `3` | Upstream calls one viewer may have in flight at once, enforced in front of the global semaphore so one viewer cannot hold every permit. Clamped to 1–8. Keep it **below** `EPIGRAPH_EXPLORER_UPSTREAM_CONCURRENCY`; a value that is not below it is logged as a warning, because it then protects nobody. |
| `EPIGRAPH_EXPLORER_UPSTREAM_TIMEOUT_MS` | `8000` | Timeout for each upstream call, clamped to 250–60000. The time spent waiting for the semaphore counts against it. |
| `EPIGRAPH_EXPLORER_TOKEN_TIMEOUT_MS` | `20000` | Timeout for `POST /oauth/token` (the code exchange and every refresh), separate from and longer than the data timeout, clamped to 250–60000. A refresh whose answer is lost ends the session (see Security model), so the token call gets more room than a data call, which only degrades a section. |
| `EPIGRAPH_EXPLORER_INSECURE_COOKIES` | `false` | Drops `Secure` from the session and login-binding cookies, and with it the `__Host-` prefix. **Only for plain-http local development**: the process refuses to start (exit 2) when it is set and `EPIGRAPH_EXPLORER_PUBLIC_BASE_URL` is `https`. Logged as a warning. The embed cookie stays `Secure` regardless. |
| `EPIGRAPH_EXPLORER_DEV_BEARER` | unset | **Development only.** A bearer token used for every request that has no session. The process refuses to start with it unless the host of `EPIGRAPH_EXPLORER_PUBLIC_BASE_URL` is exactly `localhost` or `127.0.0.1`. Logged as a warning and redacted from logs. It must be a token minted by the **current** `/oauth/token`, because the API rejects a token that carries no `agent_id`; there is no refresh on this path, so it dies at its TTL (see Local development). |
| `EPIGRAPH_EXPLORER_KANBAN_URL` | unset | The kanban board's **base URL**, e.g. `https://kanban.example.com/`. When set, each `/backlog` row links to it; unset, no kanban link renders. The viewer's browser opens it, so it must be reachable from there. It must be `http(s)` and may not carry a query string or fragment: never paste the board's pairing link, which carries a single-use code in its fragment (the process refuses to start). The link opens the board, not the item. |
| `EPIGRAPH_EXPLORER_AUDIT_ROW_CEILING` | `10000` | Most security events `/audit` reads for one window (in pages of 1 000), clamped to 1000–50000. A window holding more is shown as capped. The page keeps every row of the window in memory while it counts, so at the 50 000 ceiling a window of detail-heavy rows costs tens of MB per request; the default is far below that. A clamped value is logged. |
| `EPIGRAPH_EXPLORER_WATCH_AGENTS` | unset | The agents `/activity` shows: a comma-separated list of agent ids (uuids), shown in the order given, duplicates dropped, at most 20 (each is one upstream call per page view). A value that is not a uuid, or more than 20, stops the process at startup (exit 2). Unset, the page explains how to set it. Use the ids of your own agents; the repository names none. |
| `RUST_LOG` | `info` | A `tracing-subscriber` filter, e.g. `info,epigraph_explorer=debug`. |

Fixed limits, which are not configurable:

- request bodies are capped at 64 KiB and upstream bodies at 8 MiB;
- the API may not redirect the Explorer (redirects are refused, so a bearer
  is never replayed to another host);
- `max_degree` is at most 80 (default 40), provenance depth 1–8, and a search
  page at most 50 results;
- a session lasts at most 30 days, the lifetime of an upstream refresh token.

Here is an example environment file for production (`/etc/epigraph/explorer.env`):

```sh
EPIGRAPH_EXPLORER_PUBLIC_BASE_URL=https://explorer.example.com
EPIGRAPH_API_URL=http://127.0.0.1:8080
EPIGRAPH_OAUTH_BASE_URL=https://api.example.com
EPIGRAPH_EXPLORER_CLIENT_ID=epigraph_explorer
# Optional:
# EPIGRAPH_EXPLORER_KANBAN_URL=https://kanban.example.com/
# EPIGRAPH_EXPLORER_WATCH_AGENTS=00000000-0000-0000-0000-000000000000   (comma-separated)
# EPIGRAPH_EXPLORER_AUDIT_ROW_CEILING=10000
# RUST_LOG=info
```

Use only RFC 2606 names (`example.com`) in anything committed. Real hosts
belong in the environment on the deploy host, never in the repository.

## Local development

You need `epigraph-api` running on `127.0.0.1:8080` against a **development**
database (never the live `epigraph` one).

```sh
cd services/explorer

# Run the Explorer at the root of localhost, over plain http.
EPIGRAPH_EXPLORER_PUBLIC_BASE_URL=http://localhost:8096 \
EPIGRAPH_EXPLORER_INSECURE_COOKIES=true \
cargo run
# → open http://localhost:8096/
```

To exercise a base path, set
`EPIGRAPH_EXPLORER_PUBLIC_BASE_URL=http://localhost:8096/explorer` and open
`http://localhost:8096/explorer/`. Under a base path the cookies keep their
plain names, scoped to that path, and the startup log says
"base path set: `__Host-` cookie prefix unavailable". That is expected here
and wrong in production.

**Without Google sign-in (`EPIGRAPH_EXPLORER_DEV_BEARER`).** Local sign-in
through the API needs real Google credentials, a `providers.toml`, and a
registered redirect. For most UI work it is easier to give the Explorer a
fixed token. The Explorer then treats every visitor as signed in with that
token.

```sh
# Once per dev DB: create the canonical service clients (prints each secret once).
cargo run --bin bootstrap_clients -- \
    --legal-entity-name "Dev" --legal-contact-email "dev@example.com"
# Mint a read-only access token (a service token lives 1 hour; the Explorer
# never refreshes a dev bearer).
curl -s -X POST http://127.0.0.1:8080/oauth/token \
    -d grant_type=client_credentials -d client_id=epigraph-ro -d client_secret=<secret>

EPIGRAPH_EXPLORER_PUBLIC_BASE_URL=http://localhost:8096 \
EPIGRAPH_EXPLORER_INSECURE_COOKIES=true \
EPIGRAPH_EXPLORER_DEV_BEARER=<access_token> \
cargo run
```

Run `bootstrap_clients` from the repo root with `DATABASE_URL` pointing at the
dev database. This is the only place a service-style token touches the
Explorer, and the startup check keeps it on localhost.

**The dev bearer has no refresh, and it must carry a principal.** A
`RequestAuth::DevBearer` is deliberately excluded from the refresh-and-retry
path (`src/upstream/mod.rs`), so there is no recovery when the API rejects it:
every page renders "Sign in to see this." Two ways to land there, and both
look identical from the browser:

- the token expired (1 h for `client_credentials`), or
- the token carries no `agent_id`, so the API's `ViewerExtractor` 401s it with
  *"token carries no agent_id; re-authenticate to obtain a token bound to a
  principal"*. Every grant on the current `/oauth/token` populates it, so this
  only happens with a token minted before tenancy, or pasted from an old note.

The Explorer logs the API's own reason on each upstream 401
(`upstream_reason=…`), so `RUST_LOG=info` tells the two apart. The fix for
both is the same: mint a fresh token and restart.

**With real sign-in.** Insert an `oauth_clients` row whose `redirect_uris`
contains `http://localhost:8096/auth/callback` into the **dev** database (the
SQL is in Operator setup below). Set `EPIGRAPH_EXPLORER_CLIENT_ID`. The API
needs a Google provider configured, with your email on its allowlist.

**Tests.** Run `cargo test --locked`. The tests stub the API with `wiremock`
and need no database and no network. The repo root's `.cargo/config.toml`
sets `RUST_TEST_THREADS=1`, and cargo applies it here too. Before committing,
run the same gate CI runs:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release --locked
```

`scripts/verify.sh` runs these after the kernel checks.

## Operator setup

### 1. Register the Explorer as an OAuth client (SQL)

The Explorer cannot register itself. `POST /oauth/register` only accepts
`redirect_uri`s under `https://claude.ai/` or `https://claude.com/`, and no
admin route edits redirect URIs. An operator inserts the client row directly
into the API's database:

```sql
INSERT INTO oauth_clients
    (client_id, client_name, client_type, allowed_scopes, granted_scopes, status, redirect_uris)
VALUES
    ('epigraph_explorer', 'EpiGraph Explorer', 'human', '{}', '{}', 'active',
     ARRAY['https://explorer.example.com/auth/callback'])
RETURNING id, client_id, client_type, status, redirect_uris;
```

**Untested since migration 122.** This statement has not been run against a
database migrated to `122_operator_binding.sql` or later. Reading the
migration, 122 adds no NOT NULL column and no INSERT trigger on
`oauth_clients` (its one new trigger there fires `BEFORE UPDATE OF status`),
so the row should still insert as written. Run it inside a transaction the
first time, and check the `RETURNING` row before committing.

The row has to meet these constraints:

- **`client_id`** must be at most 64 characters (`varchar(64)`) and unique,
  and must not contain `:`. The token endpoint treats a colon as marking an
  external `google:<sub>` client. The value is not secret, because it appears
  in the authorize URL. Put the same value in `EPIGRAPH_EXPLORER_CLIENT_ID`.
- **`client_type`** must be `'human'`. A human client needs no owner and no
  legal entity. **`status`** must be `'active'`, because `/oauth/authorize`
  rejects any other status with `invalid_client`.
- **`redirect_uris`** is compared with a **plain string match**, with no
  normalisation. The entry must equal
  `EPIGRAPH_EXPLORER_PUBLIC_BASE_URL + "/auth/callback"` byte for byte. At
  the root of the Explorer's own host that is
  `https://explorer.example.com/auth/callback`. There is no trailing slash.
- **No secret.** The Explorer is a public client using PKCE S256, and the
  authorization-code grant never checks a secret.
- **Empty scopes are correct.** The scopes a token carries come from the
  signing-in user's own per-user client (`google:<sub>`), not from this row.
  The Explorer requests `claims:read audit:read`, and the API grants the
  intersection with that per-user client's granted scopes, silently dropping
  the rest. So sign-in works either way, but `/audit` shows events only to a
  user whose own per-user client is granted `audit:read`; everyone else gets
  its "not granted" explanation.
- **No `agent_id` column, on purpose.** The token endpoint materialises the
  principal at **mint** time and links it write-once
  (`principal_agent_id` → `AgentRepository::ensure_for_client`;
  `OAuthClientRepository::set_agent_id` guards with `AND agent_id IS NULL`),
  so clients that predate tenancy acquire theirs on their next token. Do not
  add the column to this INSERT.
- **Do not give this row group memberships.** The same rule that decides the
  scopes decides the tenancy principal: a signed-in user's principal is their
  **own** `google:<sub>` client's agent, never `epigraph_explorer`'s. Granting
  this row groups does nothing today, and it is the obvious wrong fix for a
  user who sees an empty result set — the right fix is that user's own group
  membership.

To move the Explorer to a new public URL, update the row:

```sql
UPDATE oauth_clients
   SET redirect_uris = ARRAY['https://explorer.example.com/auth/callback'],
       updated_at = now()
 WHERE client_id = 'epigraph_explorer';
```

On the deploy host the API database is the `epigraph-postgres` container, so
`docker exec -i epigraph-postgres psql -U epigraph -d epigraph` gives you a
shell. Take a `pg_dump` first, as `docs/deploy.md` recommends for any manual
change.

### 2. Allowlist the users (Google)

The API's authorization server signs people in **only through Google**, and
**only emails on the provider allowlist** get through: `allowed_emails` /
`allowed_domains` in the `[[provider]] name = "google"` section of the API's
`providers.toml`. That file is gitignored; the template is
`providers.toml.example`.

- A user who is not on the allowlist gets a `403` JSON page on the API's
  origin at `/oauth/callback`. For embed sign-in, that page appears inside
  the popup, and the Explorer never learns why sign-in stopped.
- The allowlist is checked again when a token is refreshed, so removing an
  email cuts that user off within about an hour. That is the access-token
  lifetime.
- An **empty** allowlist (no `allowed_emails` and no `allowed_domains`) lets
  **nobody** in: the API refuses to provision any identity through that
  provider and refuses every refresh for its users, unless the API runs with
  `EPIGRAPH_ALLOW_ALL_IDENTITIES=true`, which admits every identity Google
  authenticates. With `auto_provision` on and no allowlist, the API does not
  even boot unless that variable is `true` or `EPIGRAPH_ENV` names a
  non-production environment. Populate the allowlist; do not use the
  allow-all switch for the Explorer.
- Restart `epigraph-api.service` after editing the file.

### 3. The consent page

After Google, the API shows its own consent page, and the user must press
**Allow** on every sign-in (consent is not stored). The page names the
requesting client from `oauth_clients.client_name` (plan §2.7, landed in
`fix(oauth): name the requesting client on the consent page`), so whatever you
put in `client_name` above is what your users read there. Older API builds
hard-code "Authorize Claude"; if that is what the page says, the API is behind
this tree.

### 4. Keep `/oauth/*` browser-reachable

Sign-in uses top-level browser navigation to the API itself:

- `GET /oauth/authorize`
- `GET /oauth/callback` (Google redirects there)
- the consent form's `POST /oauth/authorize/consent`

These routes live at the root of the API's own `EPIGRAPH_PUBLIC_BASE_URL`, and
the claude.ai connector already relies on them. They stay on the API's host:
the Explorer's host proxies only to the Explorer, never `/oauth/*` or
`/api/v1/*`. `/api/v1/*` can stay private, because the Explorer reaches it over
loopback. `EPIGRAPH_OAUTH_BASE_URL` must be that public API origin.

### 5. Deploy

Build the release binary from `services/explorer`:

```sh
cargo build --release --locked
# → target/release/epigraph-explorer, or $CARGO_TARGET_DIR/release/epigraph-explorer
```

The binary is named `epigraph-explorer`, never `server`. The deploy host
shares one cargo target directory, and the API's binary there is already
`release/server`.

**systemd (recommended).** `epigraph-api` is itself a systemd service on the
host, so the simplest deployment runs the Explorer the same way. Use
[`epigraph-explorer.service.example`](epigraph-explorer.service.example):

```sh
sudo install -m 0755 <target-dir>/release/epigraph-explorer /usr/local/bin/epigraph-explorer
sudo install -m 0644 epigraph-explorer.service.example /etc/systemd/system/epigraph-explorer.service
sudo install -d -m 0755 /etc/epigraph
sudo install -m 0600 /dev/null /etc/epigraph/explorer.env   # fill in from the example above
sudo systemctl daemon-reload && sudo systemctl enable --now epigraph-explorer
```

The unit runs as a `DynamicUser` with a strict sandbox. It is ordered after
the API but does not require it: when the API is down, the Explorer shows
degraded pages and recovers on its own. The unit does not restart on exit
code 2, a configuration error, so check `journalctl -u epigraph-explorer`.

**Docker (alternative).** Use the [`Dockerfile`](Dockerfile): a multi-stage
build ending in `debian:bookworm-slim` with a non-root uid of 10001. The
binary binds loopback only and the API is on host loopback, so the container
**must** use host networking. A bridge network with `-p 8096:8096` cannot
reach it.

```sh
docker build -t epigraph-explorer services/explorer
docker run -d --name epigraph-explorer --network host \
    --env-file /etc/epigraph/explorer.env epigraph-explorer
```

**Caddy: a dedicated host, served at the root.** Add
[`Caddyfile.snippet`](Caddyfile.snippet) as a site block of its own
(`explorer.example.com { reverse_proxy 127.0.0.1:8096 }`), not as a stanza in
the API's site block, then reload Caddy. Set
`EPIGRAPH_EXPLORER_PUBLIC_BASE_URL` to that host's root, with an empty path.
Why its own host:

- **Origin isolation.** Under a path of the API's site, the Explorer would
  share one origin with the API's HTML pages (the consent page, and any
  passkey ceremony page). An HTML-injection bug on either side would then
  reach the other, and the Explorer's Origin check on `POST /auth/logout` and
  `POST /auth/redeem` would accept requests from any API page. A cookie
  `Path` is no boundary inside one origin.
- **`__Host-` cookies.** Only at the root of a secure origin can the session
  and login-binding cookies carry the `__Host-` prefix, which stops any other
  host (a sibling under the same parent domain included) from setting or
  shadowing them. That closes login CSRF by cookie tossing even when the
  parent domain is not a public suffix.

If the API's site block still routes `/explorer*` from an earlier deploy,
remove that stanza: serving the Explorer on both origins keeps the exposure.
If the API serves WebAuthn (passkey) ceremonies, its relying-party id must be
the API's **exact host**, never a registrable parent domain that the
Explorer's host also sits under. Do not add `X-Frame-Options` on the
Explorer's host: the Explorer's CSP `frame-ancestors` controls framing.

### 6. Smoke test

```sh
curl -fsS http://127.0.0.1:8096/health          # {"status":"ok","version":"0.1.0"}
curl -sI https://explorer.example.com/          # 303 → /auth/login?return_to=…
curl -sI https://explorer.example.com/auth/login # Set-Cookie: __Host-epx_login=…; Path=/; Secure
```

Then sign in through the browser and open a claim. The deploy is right only
if the login response's cookie starts `__Host-` and the startup log
(`journalctl -u epigraph-explorer`) has **no**
"base path set: `__Host-` cookie prefix unavailable" line.

## Security model

- **Bearer forwarding, and no service token.** Every upstream call carries the
  viewer's own access token, and anonymous calls carry none. The API's
  per-viewer visibility filtering is what protects content; the Explorer adds
  no privileges of its own. It never sends a token it knows is stale, because
  the API returns 401 for a present-but-invalid bearer even on the two
  allowlisted routes.
  It refreshes a token 60 s before expiry. After an upstream 401 it refreshes
  and retries once, and a second 401 ends the session. Refresh runs one
  at a time per session, and the rotated refresh token is stored every time.
  **A refresh that fails ends the session**, whatever the cause. When
  upstream refused it (`invalid_grant`, a revoked token), the token is dead
  anyway. When there was no usable answer (a timeout, a 5xx, an API restart,
  a connection failure), upstream may already have rotated the token before
  the answer was lost, and presenting it again would be read as reuse and
  revoke the whole token family. So the Explorer ends the session at once,
  under the session's refresh lock so no queued request replays the token,
  and revokes the refresh token it held, best effort. The viewer is sent to
  sign in again. The cost: a viewer whose refresh falls inside an API
  restart is signed out rather than shown a degraded page. The token call
  has its own, longer timeout (`EPIGRAPH_EXPLORER_TOKEN_TIMEOUT_MS`) to make
  a lost answer rarer.
- **Absence, not blanking.** A row the viewer may not read is **absent** from
  the API's response — omitted from a list, or a 404 that is byte-identical to
  the one a nonexistent id gets. It is never returned blanked as
  `"[REDACTED]"`; the kernel deleted that mechanism (`68b8a8b1`). The Explorer
  follows the same rule, and it is a rule about *this* UI as much as the API:
  there is **no "hidden claim" page**. `/claim/{id}`, `/claim/{id}/graph`,
  `/claim/{id}/history` and `/claim/{id}/provenance` for a claim this viewer
  may not read all render the ordinary not-found page, because a distinct "you
  may not have access" page would rebuild in the UI exactly the existence
  oracle the API removed. Two places where an id could still leak are closed
  here rather than upstream: an edge whose endpoint is not among the nodes the
  response carried is **dropped**, not rendered as a linked "Claim
  <short-id>"; and `/community/{id}` no longer prints the cluster's
  `total_size`, because that metadata is not viewer-filtered and the
  difference against the filtered list is a count of what the viewer cannot
  see.
- **Counts are per-viewer.** `/api/v1/stats` is filtered like every other
  read, so the landing page's numbers are "rows you can see", not the size of
  the corpus, and two signed-in readers get different ones. The page says so.
- **Sign-in** uses the authorization-code flow with mandatory PKCE S256
  against the API's own authorization server, with
  `scope=claims:read audit:read` (intersected upstream with the user's own
  grant; see Operator setup §1). The
  code lives 60 s upstream and is redeemed immediately. No token ever appears
  in a URL.
- **Identity strip.** Every signed-in page header shows a short principal
  id, the scopes the current token **actually** carries, the minutes left
  until it expires, and a Sign out button. Scope and expiry come from the
  token response itself. The principal comes from **one**
  `POST /oauth/introspect` per access token, made when the token is minted or
  refreshed (never per page), server to server on `EPIGRAPH_API_URL`, with
  the token in a JSON body and no bearer. If that call fails, the strip says
  "principal unavailable" until the next token, and the page still renders.
  A token wider than the scopes requested is shown as neutral information,
  "wider than requested": the API's refresh currently issues the user's full
  granted scopes (see Caveats), so expect it on most sessions after the first
  refresh. The strip **cannot** say which sign-in application a session uses:
  introspection reports a `client_id` equal to the subject. The strip is
  display only; no authorization decision reads it.
- **Session cookie.** At the root of a secure origin (the production
  topology, see Deploy) the session cookie is `__Host-epx_session` with
  `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, no `Domain` and a 30-day
  `Max-Age`; the login binding is `__Host-epx_login` (`Path=/`, 10 minutes).
  The prefix makes the browser refuse any version of these cookies set by
  another host, a sibling under the same parent domain included, which is
  what closes login CSRF and session swapping by cookie tossing. Under a
  base path, or with `EPIGRAPH_EXPLORER_INSECURE_COOKIES` on plain http, the
  prefix is impossible and the plain names `epx_session` (`Path={base path}`)
  and `epx_login` (`Path={base path}/auth`) are used; with a base path the
  startup log warns "base path set: `__Host-` cookie prefix unavailable".
  Each mode reads only its own names. The session cookie holds only a random
  256-bit session id; the tokens stay server-side in memory.
- **Duplicated cookies are refused.** A request that carries the session
  cookie twice is treated as signed out, and the response clears both the
  first-party and the embed cookie. A callback that carries the login binding
  twice is refused, and the next `/auth/login` starts over. This is defence in
  depth behind the `__Host-` prefix: on its own it cannot remove a cookie
  another host set with `Domain=`.
- **Logout** is a `POST /auth/logout`, checked against Origin. It revokes the
  refresh token upstream and drops the session. An already-issued access token
  stays valid upstream until it expires (at most 1 hour), because the API's
  access-token revocation is in-memory in one process.
- **Headers.** Every response carries:

  ```
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';
    img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none';
    frame-ancestors <EPIGRAPH_EXPLORER_FRAME_ANCESTORS>
  X-Content-Type-Options: nosniff
  Referrer-Policy: same-origin
  ```

  A response that sets no cache policy of its own (every page, and
  `/bff/audit`) also carries `Cache-Control: private, no-store` and
  `Vary: Cookie`: a page shows what one viewer may read, so neither the
  browser's history cache nor a shared cache may keep it. Static assets and
  the `/bff` routes that use ETags keep their own policy.

  There are no inline scripts or styles, so no nonces are needed. There is
  deliberately no `X-Frame-Options`, because `frame-ancestors` governs
  framing. askama escapes all output, and upstream text is never marked safe.
  Text is only ever truncated on character boundaries.
- **Request logs carry the path only.** Each request's tracing span records
  the path, never the query string, so the OAuth `code` and `state` on
  `/auth/callback` and search terms stay out of the logs.
- **Notion embed sign-in.** Inside a Notion page the Explorer is a
  third-party iframe, so it cannot see a first-party `SameSite=Lax` cookie.
  Sign-in there works through a popup:
  1. The iframe opens `/auth/login?mode=popup` in a popup, which runs the
     normal OAuth flow first-party.
  2. The popup's callback page `postMessage`s a **single-use, 60-second
     handoff code** to `window.opener`, with `targetOrigin` set to the
     Explorer's own origin.
  3. The iframe `POST`s the code to `/auth/redeem`, checked against Origin.
     Only then is the session created, and the response sets the session
     cookie with `SameSite=None; Secure; Partitioned` (CHIPS), under the
     same name as the first-party one. That cookie lives in the iframe's
     partitioned jar.

  Until the redeem, the handoff holds the token set. A handoff never redeemed
  leaves no session: once its 60-second code expires, the next housekeeping
  pass (every minute) revokes the refresh token it held. Sessions are also
  dropped 30 days after sign-in, and their refresh tokens are revoked then.

  **Which sites may frame the Explorer** is `EPIGRAPH_EXPLORER_FRAME_ANCESTORS`.
  Its default, `https://www.notion.so https://*.notion.so https://*.notion.site`,
  keeps the embed working out of the box, and so it lets **any** published
  Notion site (`*.notion.site` is open to every Notion customer) frame the
  Explorer. At deploy, narrow it to the origins your own workspace uses, for
  example `https://www.notion.so` for the Notion app plus your own
  `https://<workspace>.notion.site` if you publish there. Set it explicitly
  empty to forbid framing altogether, which turns the embed off.
- **Loopback bind.** The process listens on `127.0.0.1` only, so Caddy is the
  only way in.

## Caveats

- **Theme, community and neighbourhood ids are not permalinks.** They are
  regenerated every time clustering re-runs, which an operator triggers.
  When an id has gone stale, its view says "view expired — clustering has
  re-run". The share buttons on those views copy the centre **claim's** URL,
  which is stable. Share claim links, not cluster links.
- **OpenGraph unfurls never contain claim text.** Unfurl bots have no
  session, and there is no anonymous claim read to fall back on: the API's
  public allowlist is exactly `/health`, `/api/v1/openapi.json` and the OAuth
  paths, pinned by a lint (`crates/epigraph-api/tests/public_router_allowlist.rs`).
  An anonymous `/claim/{id}` is therefore a sign-in prompt with a generic card
  ("A claim in EpiGraph"), and it makes **no upstream call at all**. The
  `EPIGRAPH_EXPLORER_PUBLIC_UNFURL` knob that used to switch this is gone: it
  could only ever buy a request that 401s. Setting the variable now does
  nothing. Real previews need a public-share design in the kernel — a signed
  per-claim share token, or an explicit `visibility = 'public'` read on the
  allowlist — and the Explorer will not use a service token to get around
  that.
- **The session store is credential storage.** When a token is refreshed,
  the API issues it with the user's **full** granted scopes, whatever was
  requested at sign-in. Those scopes include write scopes such as
  `claims:write` and `edges:write`. Every session therefore holds a
  write-capable 30-day refresh credential, even though the Explorer only
  reads. Sessions live **only in process memory**: they are never written to
  disk and never logged (`Debug` output redacts them). Treat core dumps and
  memory access to this process as sensitive.
- **Sessions are in memory, so a restart signs everyone out.** The refresh
  tokens those sessions held are **not** revoked upstream at a restart: they
  are simply lost, and stay valid at the API until they expire (30 days).
  Sessions are also not shared between processes, so run **one** instance. A
  second instance behind a load balancer would sign users out at random.
- **Every page needs sign-in.** Every API read needs a viewer, so anonymous
  visitors get the sign-in redirect everywhere except `/health`, `/auth/*`,
  `/static/*` and `/claim/{id}`, which answers 200 with a sign-in prompt so
  that a shared link does not unfurl as the login page.
- **Who can sign in** is decided by the API's Google allowlist, not by the
  Explorer (Operator setup §2).
- **A token minted before tenancy carries no `agent_id`,** and the API
  returns 401 for it — deliberately a 401 and not a 403, because the remedy is
  to re-mint it. For a session this is invisible: the Explorer's
  refresh-and-retry-once gets a fresh token, and every grant on the current
  `/oauth/token` populates `agent_id`, so the retry succeeds. Users whose
  refresh *also* fails are asked to sign in again. `EPIGRAPH_EXPLORER_DEV_BEARER`
  has no refresh and does not recover (see Local development).
