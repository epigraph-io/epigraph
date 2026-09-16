# epigraph-explorer — web UI and BFF for EpiGraph

The EpiGraph Explorer lets people browse the EpiGraph knowledge graph in a
browser. It renders pages on the server for claims, their evidence, belief,
history and provenance, and for agents, frames and evidence records. It also
shows search results and graph views (ego graph, themes, communities,
neighbourhoods). A small JSON surface under `/bff/*` feeds the client-side
graph canvas.

It is a **backend-for-frontend**. It holds no data. Every read goes to
`epigraph-api` with the signed-in viewer's own bearer token, so the API's
access control and redaction decide what each viewer sees. The Explorer never
uses a service token of its own.

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
                      https://explorer.example.com
  browser ─────────────────────▶ Caddy (public edge)
     │                             │
     │   /explorer/*               │ handle_path /explorer*  (prefix stripped)
     │                             ▼
     │                   epigraph-explorer  127.0.0.1:8096
     │                     • askama pages + /bff JSON + /static (compiled in)
     │                     • in-memory sessions (access + refresh token)
     │                     • one global upstream semaphore, per-call timeout
     │                             │  Authorization: Bearer <viewer's token>
     │                             │  /oauth/token, /oauth/revoke (no bearer)
     │                             │  EPIGRAPH_API_URL (loopback)
     │                             ▼
     │   /oauth/authorize  epigraph-api  :8080   (systemd: epigraph-api.service)
     └─────────────────────▶   /api/v1/*  ── reads, with redaction per viewer
        (top-level              /oauth/*   ── authorization server
         navigation, to                   │
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

The Explorer serves every route both at the root and under the configured
base path, so it works behind either `handle_path` or `handle`. Every link it
generates includes the base path.

| Route | What it shows |
|---|---|
| `GET /` | Corpus counts, theme overview, community overview |
| `GET /search?q=&mode=semantic\|label\|evidence&page=` | Search results |
| `GET /claim/{id}` | A claim: belief, evidence, challenges, provenance, grouped outlinks, placement |
| `GET /claim/{id}/history` · `/provenance` · `/graph` | Version history · derivation chain · graph canvas |
| `GET /theme/{id}` · `/community/{id}` · `/neighborhood/{id}?mode=` | Clustering views (not permalinks; see Caveats) |
| `GET /agent/{id}` · `/frame/{id}` · `/evidence/{id}` | Entity pages |
| `GET /bff/claim/{id}` · `/bff/search` · `/bff/graph/ego/{id}?max_degree=` · `/bff/themes` · `/bff/communities` · `/bff/neighborhood/{id}` | JSON for the canvas |
| `GET /auth/login` · `GET /auth/callback` · `POST /auth/logout` · `POST /auth/redeem` | Sign-in (see Security model) |
| `GET /health` | Liveness: `{"status":"ok","version":"…"}` |
| `GET /static/{path}` | Compiled-in CSS/JS |

Every HTML page except `/health`, `/auth/*` and `/static/*` needs a session.
An anonymous page request gets a 303 to `/auth/login?return_to=…`, and an
anonymous `/bff/*` request gets a JSON `401 {"error":"unauthorized"}`. The one
exception is `/claim/{id}`. For an anonymous visitor it returns **200** with a
sign-in prompt and OpenGraph tags, because a redirect would unfurl in chat
apps as a login page.

## Configuration

All configuration comes from environment variables, read once at startup
(`src/config.rs`). The Explorer reads no config file. An empty or
whitespace-only value counts as unset. The one exception is
`EPIGRAPH_EXPLORER_FRAME_ANCESTORS`, described in the table. Invalid
configuration makes the process print the problem to stderr and exit with
code **2**.

| Variable | Default | Notes |
|---|---|---|
| `EPIGRAPH_EXPLORER_PUBLIC_BASE_URL` | **required** | The absolute public URL including the base path, e.g. `https://explorer.example.com/explorer`. Every link, redirect, `og:url` and cookie `Path`, and the OAuth `redirect_uri` (`{this}/auth/callback`), are built from it. It must be `http(s)`. It may not contain a query, a fragment or credentials. Path segments are limited to letters, digits and `-` `_` `.` `~`. A trailing `/` is ignored. Its **first** segment may not be one of the Explorer's own top-level routes (`agent`, `auth`, `bff`, `claim`, `community`, `evidence`, `frame`, `health`, `neighborhood`, `search`, `static`, `theme`): the routes are mounted both under the base path and at the root, so such a base path would make two handlers claim the same URL. The process refuses to start (exit 2) and names the offending segment. |
| `EPIGRAPH_API_URL` | `http://127.0.0.1:8080` | The `epigraph-api` origin, called server to server. This is the repo-standard variable name. |
| `EPIGRAPH_EXPLORER_PORT` | `8096` | Port to bind, always on `127.0.0.1`. Must be 1–65535. |
| `EPIGRAPH_OAUTH_BASE_URL` | same as `EPIGRAPH_API_URL` | The **browser-facing** origin of the API's OAuth server, and only that: the browser is sent to `{this}/oauth/authorize`. In production it is the API's public origin (e.g. `https://api.example.com`), never loopback. The Explorer itself never calls this origin — the server-to-server `/oauth/token` and `/oauth/revoke` calls go to `EPIGRAPH_API_URL` (the same process, over loopback), which keeps the authorization code, the refresh token and the client id off the public edge. |
| `EPIGRAPH_EXPLORER_CLIENT_ID` | unset | The `client_id` of the pre-registered OAuth client (see Operator setup). If it is unset, sign-in is disabled and a warning is logged at startup. Whitespace is rejected. |
| `EPIGRAPH_EXPLORER_PUBLIC_UNFURL` | `false` | If `true`, an anonymous `/claim/{id}` renders OpenGraph text from an anonymous upstream read, unless that read is redacted. Otherwise it shows a generic card. Accepts `true/false/1/0/yes/no/on/off`. |
| `EPIGRAPH_EXPLORER_FRAME_ANCESTORS` | `https://www.notion.so https://*.notion.so https://*.notion.site` | The CSP `frame-ancestors` source list, space-separated. `;`, `,`, control characters and non-ASCII are rejected. Setting it **explicitly empty** means `'none'` (no framing at all). |
| `EPIGRAPH_EXPLORER_UPSTREAM_CONCURRENCY` | `6` | Size of the global semaphore on upstream calls, clamped to 1–8. The API's database pool has 10 connections, shared with every other client. A clamped value is logged. |
| `EPIGRAPH_EXPLORER_UPSTREAM_TIMEOUT_MS` | `8000` | Timeout for each upstream call, clamped to 250–60000. The time spent waiting for the semaphore counts against it. |
| `EPIGRAPH_EXPLORER_INSECURE_COOKIES` | `false` | Drops `Secure` from the first-party session cookie. **Only for plain-http local development.** Logged as a warning. |
| `EPIGRAPH_EXPLORER_DEV_BEARER` | unset | **Development only.** A bearer token used for every request that has no session. The process refuses to start with it unless the host of `EPIGRAPH_EXPLORER_PUBLIC_BASE_URL` is exactly `localhost` or `127.0.0.1`. Logged as a warning and redacted from logs. |
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
EPIGRAPH_EXPLORER_PUBLIC_BASE_URL=https://explorer.example.com/explorer
EPIGRAPH_API_URL=http://127.0.0.1:8080
EPIGRAPH_OAUTH_BASE_URL=https://api.example.com
EPIGRAPH_EXPLORER_CLIENT_ID=epigraph_explorer
# EPIGRAPH_EXPLORER_PUBLIC_UNFURL=false
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

To exercise the base path the way Caddy serves it, set
`EPIGRAPH_EXPLORER_PUBLIC_BASE_URL=http://localhost:8096/explorer` and open
`http://localhost:8096/explorer/`.

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
Explorer, and the startup check keeps it on localhost. When the token expires
the API returns 401 and pages redirect to sign-in; mint a new one and restart.

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
     ARRAY['https://explorer.example.com/explorer/auth/callback'])
RETURNING id, client_id, client_type, status, redirect_uris;
```

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
  `EPIGRAPH_EXPLORER_PUBLIC_BASE_URL + "/auth/callback"` byte for byte,
  including the `/explorer` prefix that Caddy strips. There is no trailing
  slash.
- **No secret.** The Explorer is a public client using PKCE S256, and the
  authorization-code grant never checks a secret.
- **Empty scopes are correct.** The scopes a token carries come from the
  signing-in user's own per-user client (`google:<sub>`), not from this row.

To move the Explorer to a new public URL, update the row:

```sql
UPDATE oauth_clients
   SET redirect_uris = ARRAY['https://explorer.example.com/explorer/auth/callback'],
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
- On `main`, an empty allowlist lets **everyone** in (the API logs a
  warning). Populate it before exposing the Explorer.
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
the claude.ai connector already relies on them. Only `/api/v1/*` can stay
hidden behind the Explorer. `EPIGRAPH_OAUTH_BASE_URL` must be that public API
origin.

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

**Caddy.** Add [`Caddyfile.snippet`](Caddyfile.snippet)
(`handle_path /explorer* { reverse_proxy 127.0.0.1:8096 }`) to the public site
block, then reload Caddy. `handle_path` strips `/explorer`, which is why the
public base URL has to carry it. Do not add `X-Frame-Options` for this path:
the Explorer's CSP `frame-ancestors` controls framing.

### 6. Smoke test

```sh
curl -fsS http://127.0.0.1:8096/health          # {"status":"ok","version":"0.1.0"}
curl -sI https://explorer.example.com/explorer/  # 303 → /explorer/auth/login?return_to=…
```

Then sign in through the browser and open a claim.

## Security model

- **Bearer forwarding, and no service token.** Every upstream call carries the
  viewer's own access token, and anonymous calls carry none. The API's
  per-viewer redaction is what protects content; the Explorer adds no
  privileges of its own. It never sends a token it knows is stale, because
  the API returns 401 for a present-but-invalid bearer even on public routes.
  It refreshes a token 60 s before expiry. After an upstream 401 it refreshes
  and retries once, and a second 401 ends the session. Refresh runs one
  at a time per session, and the rotated refresh token is stored every time.
  A refresh that *fails* ends the session only when upstream refused it
  (`invalid_grant`, a revoked token, no such session). A refresh that could
  not reach `/oauth/token` at all — a restart, a timeout, a 5xx — keeps the
  session and reports the ordinary "API unavailable" failure, so an API
  restart does not sign every user out.
- **Redaction short-circuit.** Several upstream read routes do not yet redact
  what `GET /claims/{id}` redacts (plan §2.6). If `GET /claims/{id}` returns
  the content `"[REDACTED]"`, the Explorer skips every other content-bearing
  call for that page, and the text never reaches OpenGraph tags.
- **Sign-in** uses the authorization-code flow with mandatory PKCE S256
  against the API's own authorization server, with `scope=claims:read`. The
  code lives 60 s upstream and is redeemed immediately. No token ever appears
  in a URL.
- **Session cookie** `epx_session` has `HttpOnly`, `Secure`, `SameSite=Lax`,
  `Path={base path}` and a 30-day `Max-Age`. It holds only a random 256-bit
  session id. The tokens stay server-side in memory.
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

  There are no inline scripts or styles, so no nonces are needed. There is
  deliberately no `X-Frame-Options`, because `frame-ancestors` governs
  framing. askama escapes all output, and upstream text is never marked safe.
  Text is only ever truncated on character boundaries.
- **Notion embed sign-in.** Inside a Notion page the Explorer is a
  third-party iframe, so it cannot see a first-party `SameSite=Lax` cookie.
  Sign-in there works through a popup:
  1. The iframe opens `/auth/login?mode=popup` in a popup, which runs the
     normal OAuth flow first-party.
  2. The popup's callback page `postMessage`s a **single-use, 60-second
     handoff code** to `window.opener`, with `targetOrigin` set to the
     Explorer's own origin.
  3. The iframe `POST`s the code to `/auth/redeem`, which sets the session
     cookie with `SameSite=None; Secure; Partitioned` (CHIPS). That cookie
     lives in the iframe's partitioned jar.

  The embedding origins must be listed in `EPIGRAPH_EXPLORER_FRAME_ANCESTORS`,
  which defaults to Notion's.
- **Loopback bind.** The process listens on `127.0.0.1` only, so Caddy is the
  only way in.

## Caveats

- **Theme, community and neighbourhood ids are not permalinks.** They are
  regenerated every time clustering re-runs, which an operator triggers.
  When an id has gone stale, its view says "view expired — clustering has
  re-run". The share buttons on those views copy the centre **claim's** URL,
  which is stable. Share claim links, not cluster links.
- **OpenGraph unfurls stop working after tenancy.** Unfurl bots have no
  session. Today, anonymous claim reads work on `main`, so
  `EPIGRAPH_EXPLORER_PUBLIC_UNFURL=true` can put claim text in link previews.
  Once the tenancy work deploys, anonymous callers get nothing, and the
  Explorer will not use a service token to get around that. Previews will
  fall back to a generic card until a public-share design exists (plan §4).
- **The session store is credential storage.** When a token is refreshed,
  the API issues it with the user's **full** granted scopes, whatever was
  requested at sign-in. Those scopes include write scopes such as
  `claims:write` and `edges:write`. Every session therefore holds a
  write-capable 30-day refresh credential, even though the Explorer only
  reads. Sessions live **only in process memory**: they are never written to
  disk and never logged (`Debug` output redacts them). Treat core dumps and
  memory access to this process as sensitive.
- **Sessions are in memory, so a restart signs everyone out.** They are also
  not shared between processes, so run **one** instance. A second instance
  behind a load balancer would sign users out at random.
- **Pages need sign-in even before tenancy.** The graph overview and expand
  routes are on the API's protected router. Anonymous visitors therefore get
  the sign-in redirect everywhere except `/claim/{id}`.
- **Who can sign in** is decided by the API's Google allowlist, not by the
  Explorer (Operator setup §2).
- **After tenancy deploys,** tokens minted before it carry no `agent_id`,
  and the API returns 401 for them. The Explorer's refresh-and-retry-once
  gets a fresh token for them. Users whose refresh also fails are asked to
  sign in again.
