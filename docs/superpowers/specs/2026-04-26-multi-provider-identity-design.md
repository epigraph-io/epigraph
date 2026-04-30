# Multi-Provider External Identity Design

> **Origin:** Ported from `epigraph-internal` (private dev repo) as historical
> design context. The implementation landed on this repo as **#24**. Branch /
> PR-number references below point to the original `epigraph-internal` artifacts.

**Date:** 2026-04-26
**Branch:** to be created at plan time (likely `feat/multi-provider-identity`, forked off `main`)
**Status:** Draft for user review (post-brainstorm)

---

## Why this design exists

EpiGraph's "human" OAuth path is hardwired to Google. Google-specific code is inlined in three places:

- `crates/epigraph-api/src/oauth/device.rs` — browser auth-code flow at `/oauth/google/auth-url` and `/oauth/google/exchange`. `accounts.google.com` and `oauth2.googleapis.com/token` appear as string literals.
- `crates/epigraph-api/src/oauth/token.rs` — `grant_type=google_id_token` handler with hardcoded JWKS URL `https://www.googleapis.com/oauth2/v3/certs`, hardcoded issuer allowlist, and a Google-specific claim struct `GoogleIdTokenClaims`.
- `crates/epigraph-api/src/oauth/token.rs::provision_google_user` — synthesizes `oauth_clients.client_id = "google:{sub}"` and grants a fixed default scope set on first sight.

A deployment that wants to put EpiGraph behind Cloudflare Access today has no clean integration point — it would have to fork and patch this code. We want deployments to plug in additional identity sources (Cloudflare Access first, others later) by configuration, not by patching `epigraph-internal`.

This design generalizes the path from "external assertion arrives" to "EpiGraph JWT issued" behind a small trait registry. Google becomes one provider implementation; Cloudflare Access becomes a second. New providers are a single struct + a `providers.toml` entry.

The bearer middleware, AuthContext, scope checking, EpiGraph JWT signing, agent/service auth, and the database schema are unchanged.

## Goals and non-goals

**This design ships:**

- A trait abstraction (`ExternalIdentityProvider` + optional `OidcRedirectFlow`) over external identity sources.
- A `ProviderRegistry` owned by `AppState`, populated from `providers.toml` at startup.
- Two concrete implementations: `GoogleProvider` (redirect + assertion) and `CloudflareAccessProvider` (assertion-only).
- A shared `JwksCache` so JWKS is no longer fetched on every assertion validation.
- A generic `provision_external_user` helper replacing the current `provision_google_user`.
- Provider-parameterized routes: `POST /oauth/{provider}/auth-url`, `POST /oauth/{provider}/exchange` (verbs match the existing Google routes). The existing `/oauth/google/...` paths keep working unchanged (because the provider's `name` is `"google"`).
- Per-provider grant types in `POST /oauth/token`. `google_id_token` continues to work; `cloudflare_access_jwt` is added.
- Tests covering both providers via mocked JWKS fixtures.

**This design explicitly does NOT ship:**

- **No identity stitching.** Each `(provider, external_subject)` pair remains its own `oauth_clients` row. A future spec may introduce a `external_identities` join table; out of scope here.
- **No schema migration.** `oauth_clients` table is untouched.
- **No new crate.** Everything lives inside `crates/epigraph-api`.
- **No hot reload.** Config changes require a server restart.
- **No changes to bearer middleware, AuthContext, scope checking, or EpiGraph JWT issuance/validation.**
- **No changes to agent (Ed25519) or service (`client_secret`) auth paths.**
- **No deployment-side sidecar.** The deployment owns whatever local glue (Caddy snippet, small adapter service, etc.) translates Cloudflare Access's `Cf-Access-Jwt-Assertion` header into a `POST /oauth/token` call. EpiGraph exposes the generalized API; the deployment builds against it.

## Architecture

### Module layout

```
crates/epigraph-api/src/oauth/
├── mod.rs                  (re-exports)
├── jwt.rs                  (unchanged — EpiGraph's own JWT signing)
├── token.rs                (modified — generic provider dispatch)
├── device.rs               (modified — generic redirect flow, no longer Google-only)
├── register.rs             (unchanged)
├── revoke.rs               (unchanged)
├── introspect.rs           (unchanged)
└── providers/              (NEW)
    ├── mod.rs              (trait defs + ProviderRegistry + provision_external_user)
    ├── config.rs           (TOML structs + env interpolation + load fn)
    ├── jwks.rs             (cached JWKS fetcher — shared by all providers)
    ├── google.rs           (GoogleProvider: ExternalIdentityProvider + OidcRedirectFlow)
    └── cloudflare_access.rs (CloudflareAccessProvider: ExternalIdentityProvider only)
```

`AppState` gains one field: `pub providers: Arc<ProviderRegistry>`. Built once at startup from `providers.toml`. Immutable for process lifetime. Follows the existing "shared trait-object" pattern already used for `encryption_provider: SharedEncryptionProvider` in `state.rs`.

The `/oauth/{provider}/auth-url` and `/oauth/{provider}/exchange` routes must be registered in **both** OAuth router blocks in `routes/mod.rs` (the `db` build at ~`:670–683` and the second build at ~`:1024–1036`). Both currently register `/oauth/google/auth-url` and `/oauth/google/exchange` as POST; the new generic routes replace them in both places.

### Core types

```rust
/// Identity extracted from a validated external assertion.
pub struct ExternalIdentity {
    pub subject: String,        // becomes the suffix in client_id = "{provider}:{subject}"
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub raw_claims: serde_json::Value,  // full claims for audit/debug
}

#[async_trait]
pub trait ExternalIdentityProvider: Send + Sync {
    /// Stable identifier — used as the prefix in client_id and the path segment in /oauth/{name}/...
    /// Must match `[a-z0-9-]+`. Unique within the registry.
    fn name(&self) -> &str;

    /// The grant_type string this provider responds to in POST /oauth/token.
    /// Unique within the registry.
    fn grant_type(&self) -> &str;

    /// Validate the inbound assertion (a JWT) and extract identity.
    async fn validate(&self, assertion: &str) -> Result<ExternalIdentity, ProviderError>;

    fn auto_provision(&self) -> bool;
    fn default_scopes(&self) -> &[String];
}

/// Optional capability — only providers that initiate a browser auth-code flow.
#[async_trait]
pub trait OidcRedirectFlow: Send + Sync {
    fn build_auth_url(&self, state: &str, pkce_challenge: &str, redirect_uri: &str) -> String;
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        pkce_verifier: &str,
    ) -> Result<String /* id_token JWT */, ProviderError>;
}

pub struct ProviderRegistry {
    by_name: HashMap<String, Arc<dyn ExternalIdentityProvider>>,
    by_grant_type: HashMap<String, Arc<dyn ExternalIdentityProvider>>,
    redirect_flows: HashMap<String, Arc<dyn OidcRedirectFlow>>,
}

impl ProviderRegistry {
    pub fn from_config(cfg: ProvidersConfig) -> Result<Self, ProviderConfigError>;
    pub fn by_name(&self, name: &str) -> Option<Arc<dyn ExternalIdentityProvider>>;
    pub fn by_grant_type(&self, gt: &str) -> Option<Arc<dyn ExternalIdentityProvider>>;
    pub fn redirect_flow(&self, name: &str) -> Option<Arc<dyn OidcRedirectFlow>>;
}

pub enum ProviderError {
    InvalidAssertion(String),  // bad signature, expired, wrong issuer, wrong audience
    JwksFetch(String),         // upstream JWKS unreachable
    Config(String),            // misconfigured at startup
    Upstream(String),          // e.g., Google's token endpoint returned 5xx during redirect-flow exchange
}
```

### Provisioning helper

```rust
/// Provider-agnostic version of today's provision_google_user.
/// Synthesizes client_id = "{provider.name()}:{identity.subject}", auto-creates if missing
/// (when provider.auto_provision()), grants provider.default_scopes(), issues EpiGraph tokens.
pub async fn provision_external_user(
    state: &AppState,
    provider: &dyn ExternalIdentityProvider,
    identity: &ExternalIdentity,
    requested_scope: Option<&str>,
) -> Result<(StatusCode, Json<TokenResponse>), ApiError>;
```

The current `provision_google_user` is deleted; its logic moves wholesale into `provision_external_user`. The shape is the same — `client_id` synthesis, find-or-create, scope intersection, access+refresh token issuance — only the inputs become provider-supplied rather than Google-hardcoded.

`provision_google_user` has **two** call sites that must both migrate in the same PR:
- `token.rs:687` — the `grant_type=google_id_token` token-grant handler.
- `device.rs:250` — the redirect-flow exchange handler (after Google's token endpoint returns the `id_token`).

Errors from `provision_external_user` (e.g. `auto_provision=false` for an unknown subject, DB write failures) are **not** `ProviderError` — they are mapped to HTTP responses inside the helper itself (see §Error handling). `ProviderError` is reserved for assertion-validation and config errors raised by the trait implementations.

### JWKS caching

`providers/jwks.rs` exposes a `JwksCache` keyed by JWKS URL.

- TTL: 1 hour.
- Stale-grace: serve cached values for an additional 5 minutes if upstream is unreachable during a refresh (avoids hard outages when Google or Cloudflare's JWKS endpoint flaps).
- Kid-not-found: triggers a single forced refetch. If the kid is still missing post-refetch, the validation fails. No further retries.
- Concurrent fetches for the same URL are coalesced (single in-flight request via `tokio::sync::Mutex` or a similar coalescer) so a thundering herd of validations doesn't issue N upstream calls.

This replaces the per-validation `reqwest::get(jwks_url)` calls inline in `device.rs:200-226` and `token.rs:633-660`.

## Configuration

### TOML schema

Path: `providers.toml` at repo root. Overridable via `EPIGRAPH_PROVIDERS_CONFIG` env var.

```toml
[[provider]]
name              = "google"
flow              = "redirect"                          # provider runs a browser auth-code dance
grant_type        = "google_id_token"
issuer            = "https://accounts.google.com"
extra_issuers     = ["accounts.google.com"]             # legacy non-https form Google still emits
jwks_url          = "https://www.googleapis.com/oauth2/v3/certs"
audience_env      = "GOOGLE_CLIENT_ID"
client_id_env     = "GOOGLE_CLIENT_ID"
client_secret_env = "GOOGLE_CLIENT_SECRET"
auth_endpoint     = "https://accounts.google.com/o/oauth2/v2/auth"
token_endpoint    = "https://oauth2.googleapis.com/token"
redirect_uri_env  = "EPIGRAPH_REDIRECT_URI"             # optional; caller-supplied wins, this is the fallback
auto_provision    = true
default_scopes = [
  "claims:read", "claims:write", "claims:challenge",
  "evidence:read", "evidence:submit",
  "edges:read", "edges:write",
  "agents:read", "agents:write",
  "groups:read", "groups:manage",
  "analysis:belief", "analysis:propagation", "analysis:reasoning",
  "analysis:gaps", "analysis:structural", "analysis:hypothesis",
  "analysis:political",
  "clients:register",
]

[[provider]]
name           = "cloudflare-access"
flow           = "assertion"                            # validate-only, no redirect dance
grant_type     = "cloudflare_access_jwt"
issuer         = "https://your-team.cloudflareaccess.com"
jwks_url       = "https://your-team.cloudflareaccess.com/cdn-cgi/access/certs"
audience_env   = "CF_ACCESS_AUD"                        # the AUD tag of the CF Access app
auto_provision = true
default_scopes = ["claims:read", "claims:write", "evidence:read", "evidence:submit"]
```

### Schema rules

- `flow = "redirect"` requires `auth_endpoint`, `token_endpoint`, `client_id_env`, `client_secret_env`. May optionally specify `redirect_uri` (literal) or `redirect_uri_env`. Provider impls both `ExternalIdentityProvider` and `OidcRedirectFlow`.
- `flow = "assertion"` requires only `issuer`, `jwks_url`, `audience_env` (or literal `audience`). Provider impls `ExternalIdentityProvider` only.
- `*_env` fields name an environment variable read at startup. **Secrets are never written into TOML.** A missing referenced env var is a startup error.
- `audience` may be a literal in TOML instead of `audience_env` if the value is non-secret.
- `name` must be unique, lowercase, `[a-z0-9-]+`. Becomes the `client_id` prefix and the URL path segment.
- `grant_type` must be unique across providers.

### Precedence

- **`providers.toml` present:** TOML is authoritative. Environment variables are read only where TOML references them via `*_env` fields.
- **`providers.toml` absent AND `GOOGLE_CLIENT_ID` set:** legacy mode. Server synthesizes a single `google` provider from environment variables (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`) matching the current behavior. Logged as a warning at startup; slated for removal in a follow-up.
- **`providers.toml` absent AND no `GOOGLE_CLIENT_ID`:** server starts with an empty provider registry. EpiGraph's own JWT-bearer auth still works (existing tokens, agent assertions, service `client_secret`). Any `POST /oauth/token` with an external grant type returns `400 unsupported_grant_type`.

### Startup validation

- Parse TOML. On any error: log + exit non-zero.
- Resolve referenced env vars. Missing env var → exit non-zero.
- Reject: duplicate `name`, duplicate `grant_type`, invalid `name` format, missing required field for declared `flow`.
- Probe each `jwks_url` once (HEAD or GET). Warn on unreachable; do not exit (network may flap; cache will retry on first real validation).
- Build `ProviderRegistry`, inject into `AppState`.

### Redirect URI resolution

The redirect URI was previously a single server-wide env var (`EPIGRAPH_REDIRECT_URI`) read inline at `device.rs:94` and `device.rs:140`. Multi-provider needs per-provider control without breaking existing callers, who do **not** send a redirect URI today.

Resolution order, used by both `/oauth/{provider}/auth-url` and `/oauth/{provider}/exchange`:

1. If the request body includes `redirect_uri`, use it.
2. Else, if the provider config (TOML) supplies `redirect_uri` (literal) or `redirect_uri_env` (env var name), use that.
3. Else, in **legacy mode only** (synthesized `google` provider, see Precedence below), fall back to `EPIGRAPH_REDIRECT_URI`, defaulting to `http://127.0.0.1:1` if unset — matches today's behavior.

Existing callers that send neither field continue to work via step 3. New deployments configure step 2 in `providers.toml`. The inline `std::env::var("EPIGRAPH_REDIRECT_URI")` calls move into the legacy-mode synthesizer; no other code path reads the env var directly.

## Data flow

### Token-grant path (used by both Google and Cloudflare Access)

```
1. Caller (sidecar or browser): POST /oauth/token
                                grant_type=cloudflare_access_jwt   (or google_id_token)
                                assertion=<JWT>
                                scope="claims:read claims:write"   (optional)
2. token::handle_token() reads grant_type
3. registry.by_grant_type(grant_type) → Arc<dyn ExternalIdentityProvider>
4. provider.validate(assertion):
     a. JwksCache.get(provider.jwks_url) → cached or fetched JWKS
     b. decode_header → kid
     c. find key by kid (refetch JWKS once if miss)
     d. jsonwebtoken::decode with provider's issuer + audience set in Validation
     e. extract ExternalIdentity { subject, email, email_verified, name, raw_claims }
5. provision_external_user(state, &provider, &identity, requested_scope):
     a. client_id_synth = format!("{}:{}", provider.name(), identity.subject)
     b. OAuthClientRepository::get_by_client_id(client_id_synth)
     c. if missing && provider.auto_provision(): create with provider.default_scopes()
     d. effective_scopes = intersection(client.granted_scopes, requested_scope or all)
     e. issue EpiGraph access JWT (HS256, claims.client_type="human")
     f. issue refresh token (32B random, blake3 hashed, stored)
6. Return TokenResponse { access_token, token_type, expires_in, refresh_token, scope }
```

### Redirect path (Google today; any future OIDC provider)

Wire shape matches today's `/oauth/google/auth-url` and `/oauth/google/exchange`: same verb (POST), same field names. New fields are additive and optional.

```
1. Caller:   POST /oauth/{provider}/auth-url
              body: { redirect_uri?: string }       // optional; falls back to provider config or EPIGRAPH_REDIRECT_URI
2. Handler verifies registry.redirect_flow(provider) → Some(...) ; if None (e.g. flow="assertion"), returns 400.
3. flow.build_auth_url(state, pkce_challenge, redirect_uri) → consent URL
4. Server returns { auth_url, code_verifier } to caller   // existing field name; unchanged
5. Browser hits IdP, returns to redirect_uri with ?code=...
6. Caller:   POST /oauth/{provider}/exchange
              body: { code, code_verifier, redirect_uri? }    // existing field names; redirect_uri optional and falls back as in step 1
7. flow.exchange_code(code, redirect_uri, code_verifier) → id_token (IdP-signed JWT)
8. provider.validate(id_token) → ExternalIdentity   (same path as token-grant)
9. provision_external_user(...) → TokenResponse
```

Note on routing for `flow="assertion"` providers: the `/oauth/{provider}/auth-url` and `/exchange` routes are registered uniformly for all providers, but the handler must check `registry.redirect_flow(name)` first and return 400 when the provider does not implement `OidcRedirectFlow`. The 404 case (unknown provider name) takes precedence over the 400 case.

Steps 8–9 reuse the exact same code path as the token-grant flow. The redirect flow's only job is "exchange code for assertion JWT, then hand to validate."

### Cloudflare Access deployment shape (illustrative)

Cloudflare Access already gatekeeps the route at the edge and injects `Cf-Access-Jwt-Assertion` on every request to EpiGraph. The deployment runs a small adapter (Caddy snippet, tiny Go service, lambda — whatever's idiomatic). On a fresh session it:

1. Reads the CF assertion header from the inbound request.
2. POSTs to EpiGraph: `grant_type=cloudflare_access_jwt`, `assertion=<the CF JWT>`.
3. Stores the returned EpiGraph access+refresh tokens in a session cookie (signed) or sidecar memory.
4. On subsequent requests, replaces the CF assertion with `Authorization: Bearer <epigraph-access-token>`.
5. When the EpiGraph access token expires, uses the refresh token (or just re-exchanges the current CF assertion).

EpiGraph itself sees only `Authorization: Bearer ...` for non-token requests — exactly as today.

## Error handling, observability, security

### HTTP responses (`POST /oauth/token`)

| Failure | Status | OAuth2 error code |
|---|---|---|
| Unknown `grant_type` (no provider registered) | 400 | `unsupported_grant_type` |
| Missing `assertion` field | 400 | `invalid_request` |
| Bad signature / wrong issuer / wrong audience / expired | 401 | `invalid_grant` |
| JWKS fetch fails (upstream unreachable, cache cold) | 503 | `temporarily_unavailable` |
| Provider has `auto_provision=false` and user not found | 403 | `access_denied` |
| DB write fails during provisioning | 500 | `server_error` |

### Redirect flow (`/oauth/{provider}/auth-url`, `/oauth/{provider}/exchange`)

| Failure | Status |
|---|---|
| Unknown provider name in path | 404 |
| Provider exists but `flow != "redirect"` | 400 |
| Upstream token endpoint 5xx during exchange | 502 |
| PKCE verifier mismatch | 400 |

### Logging rules

- Never log full assertions or ID tokens. Log: `provider=cloudflare-access subject=<sub> email=<email> outcome=success|invalid_grant reason=<short>`.
- Validation failures emit a `security_event` row (existing table) with `event_type="oauth_assertion_rejected"`, `provider`, and reason. Reuses the existing audit pipeline.
- Successful first-time provisioning emits `event_type="oauth_human_provisioned"`, provider, client_id.

### Replay / freshness

- Each provider validates `exp` strictly.
- `iat` skew tolerance ±60s.
- No nonce check for `flow="assertion"` providers (no nonce was bound at issuance — we did not initiate the IdP request).
- For `flow="redirect"`, the `state` parameter and PKCE verifier already bind initiation to exchange.

### Provider name as trust boundary

`client_id = "{provider_name}:{subject}"` is the identity key. Two providers can both authenticate the same external `subject` value, but they create *different* `oauth_clients` rows because the prefix differs. A misconfigured or duplicated `provider.name` would silently merge identities — the `from_config` validator enforces unique names, lowercase format, and `[a-z0-9-]+` charset.

## Testing

### Test infrastructure (new)

`crates/epigraph-api/tests/oauth_providers/fixtures.rs` provides:

- An RSA keypair generated at test setup, exposed as a JWKS via `wiremock` HTTP fixtures.
- A `sign_id_token(claims)` helper producing a JWT signed by that key with a matching `kid`.
- Per-test `ProviderRegistry` builders pointing providers at the wiremock URL.

Same fixture serves both Google and Cloudflare Access test flows; only issuer/audience differ.

**New dev-dependencies** to add to `crates/epigraph-api/Cargo.toml`:
- `wiremock` (HTTP mocking for JWKS + Google token endpoint).
- RSA key generation: `rsa` + `rand` (already a workspace dep).

`async-trait`, `jsonwebtoken`, `serde_json`, and `tokio` are already present.

### Unit tests per provider

For `providers/google.rs::tests` and `providers/cloudflare_access.rs::tests`:

- Valid signed assertion → returns expected `ExternalIdentity`.
- Wrong `iss` → `InvalidAssertion`.
- Wrong `aud` → `InvalidAssertion`.
- Expired (`exp` < now) → `InvalidAssertion`.
- Future `iat` beyond skew tolerance → `InvalidAssertion`.
- Missing `kid` in header → `InvalidAssertion`.
- Unknown `kid` triggers JWKS refetch; if still missing → `InvalidAssertion`.

### JwksCache unit tests

In `providers/jwks.rs::tests`:

- N concurrent `get(url)` calls during cache miss issue exactly one upstream fetch.
- TTL expiry triggers refetch.
- Kid-not-found triggers single refetch then fails if still missing.
- Upstream 5xx during refresh: returns last cached result if still within stale-grace window; otherwise error.

### Integration tests (token endpoint)

In `crates/epigraph-api/tests/oauth_token_grant.rs` (new file — no oauth integration test exists today):

- `grant_type=google_id_token` end-to-end: mocked JWT → 200 with EpiGraph tokens → use access token to hit a protected route → 200.
- `grant_type=cloudflare_access_jwt` end-to-end: same shape.
- Unknown `grant_type` → 400 `unsupported_grant_type`.
- Invalid assertion → 401 `invalid_grant`.
- Provider with `auto_provision=false` + unknown subject → 403 `access_denied`.
- Provider with `auto_provision=true` + new subject → `oauth_clients` row created with correct `client_id` prefix, `name`, `email`; second call with same subject finds the existing row (no duplicate insert).

### Integration test — redirect flow

In `crates/epigraph-api/tests/oauth_redirect_flow.rs` (new file):

- GET `/oauth/google/auth-url` returns auth URL containing `state` + PKCE challenge.
- POST `/oauth/google/exchange` with mocked Google token endpoint (wiremock) returns EpiGraph tokens.
- Provider with `flow="assertion"` rejects redirect-flow paths: GET `/oauth/cloudflare-access/auth-url` → 400.
- Unknown provider: GET `/oauth/nonexistent/auth-url` → 404.

### Config loading tests

In `providers/config.rs::tests`:

- Valid TOML round-trips.
- Missing referenced env var → startup error.
- Duplicate `name` / duplicate `grant_type` → startup error.
- Invalid `name` format (uppercase, special chars) → startup error.
- `flow="redirect"` without `auth_endpoint` → startup error.
- Legacy mode: no TOML + `GOOGLE_CLIENT_ID` set → registry contains exactly one google provider matching today's behavior.
- Empty mode: no TOML + no `GOOGLE_CLIENT_ID` → registry empty; server starts; external grant types return 400.

### Tests that must be updated, not deleted

Any current test calling `provision_google_user` directly is updated to call `provision_external_user` with a `google` provider built from a test config. Existing assertions on response shape and `oauth_clients` row contents stay the same (the synthesized `client_id` is identical: `google:{sub}`).

## Backwards compatibility

The default-named `google` provider preserves today's wire contract end-to-end:

- **HTTP verbs unchanged.** `/oauth/google/auth-url` and `/oauth/google/exchange` remain `POST` (matches `routes/mod.rs:677–682` and `:1030–1035` today).
- **Request/response field names unchanged.** `ExchangeRequest { code, code_verifier }` and `AuthUrlResponse { auth_url, code_verifier }` keep their existing names. The new optional `redirect_uri` field on the request is additive — callers that omit it fall through to provider config and ultimately to `EPIGRAPH_REDIRECT_URI` (legacy mode), matching today's server-side resolution.
- **`grant_type=google_id_token` unchanged.** Existing token-grant calls keep working with `id_token` field as before.
- **`oauth_clients.client_id` format unchanged.** Existing rows (`google:{sub}`) match the new synthesizer's output exactly.
- **Legacy env-var-only mode preserved.** Deployments without `providers.toml` synthesize a single `google` provider from `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `EPIGRAPH_REDIRECT_URI` and behave exactly as today, with a deprecation warning at startup.

Net effect: a deployment running today, with no config changes, sees identical behavior on the next restart.

## Implementation notes (for the plan, not part of the abstraction)

These were flagged during design review and should be checked when implementing:

1. **Cloudflare Access `aud` is an array, not a string.** Real Cloudflare Access JWTs emit `aud: ["abc123..."]` (a one-element array). `jsonwebtoken::Validation::set_audience(&[configured_aud])` handles both string and array claim values, but the test fixture for `cloudflare_access` should explicitly use the array form to verify.
2. **Existing in-memory token revocation set in `AppState.revoked_tokens` is unaffected.** It tracks EpiGraph-issued JWTs, not provider-issued assertions. No change needed.
3. **The `register.rs` "first active human as agent owner" lookup is unaffected.** `register.rs:148–156` runs `SELECT id FROM oauth_clients WHERE client_type = 'human' AND status = 'active' ORDER BY created_at LIMIT 1` to populate `owner_id` when an agent registers. (Note: there is no separate "first-human admin-approval" code path — humans auto-provisioned via any external provider land directly as `status='active'` inside `provision_external_user`, same as today's `provision_google_user`.) Across multiple providers, "first active human" still means whoever signed in earliest by any path; semantics unchanged.
4. **`jsonwebtoken::Validation::set_required_spec_claims` should include `["exp", "iss", "aud"]` for all providers.** The current Google validation does this implicitly via the validation struct defaults; make it explicit so a future provider implementation doesn't accidentally drop a required claim.

## Open questions for the implementation plan

- **Branch base:** off `main` or off the current S3a branch? S3a is unrelated; cleaner to fork from `main`.
- **PR scoping:** single PR for the full refactor, or split (1) extract abstraction with Google-only, (2) add Cloudflare Access provider? Single is simpler to review since the abstraction without a second consumer can't be evaluated for fitness.
- **Hot-reload deferral:** confirmed out of scope. Restart on config change.
