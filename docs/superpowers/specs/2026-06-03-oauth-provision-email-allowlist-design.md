# OAuth external-provisioning email allowlist

**Date:** 2026-06-03
**Branch:** `security/oauth-provision-allowlist`
**Type:** `security` (access-control hardening)

## Problem

EpiGraph's OAuth layer auto-provisions a per-user `human` OAuth client for any
identity an external IdP (currently Google OIDC) authenticates, when the
provider has `auto_provision = true`. The default Google provider in
`providers.toml` grants a wide scope set including **write** scopes
(`claims:write`, `edges:write`, `groups:manage`, `clients:register`,
`agents:write`, …).

Net effect: **any Google account that completes the OIDC flow receives a
write-capable client on the knowledge graph.** Authentication is not
authorization — Google proves *who* you are, not that you are *permitted*.

This is the latent exposure recorded in memory
`reference_mcp_manifest_not_scope_filtered` ("providers.toml
auto_provision=true + write scopes → any Google acct gets graph write").

### Current blast radius (verified against prod `epigraph` DB, 2026-06-03)

Exactly one external client is provisioned:
`google:107485523387294236292` = `jeremy.barton@gmail.com`, `status=active`,
full scope set. That is the legitimate owner. **No rogue clients exist**, so no
revocation/cleanup migration is required — the fix is purely preventive.

## Goal

Restrict external auto-provisioning to an operator-controlled **email
allowlist** (exact addresses and/or whole domains), enforced on every path that
mints a token for or creates an external client. Preserve backward
compatibility: an empty allowlist means allow-all (opt-in gate).

## Design

### 1. Config surface (`providers.toml` / `ProviderConfig`)

Two new optional, serde-default-empty fields per provider:

- `allowed_emails: Vec<String>` — exact addresses.
- `allowed_domains: Vec<String>` — match on the substring after the last `@`.

Semantics, implemented by the pure predicate `email_is_allowed(email,
allowed_emails, allowed_domains) -> bool`:

- **Both lists empty ⇒ `true`** (allow-all; backward compatible).
- Otherwise `true` iff trimmed/lowercased email exactly matches an
  `allowed_emails` entry (case-insensitive, entries trimmed too) **or** its
  domain matches an `allowed_domains` entry.
- **Empty email while an allowlist is configured ⇒ `false`** (deny). Guards
  against `unwrap_or_default()` producing `""`.
- Domain split uses the **last** `@` (quoted-local-part / plus-address safety);
  suffix attacks (`evilbaros.associates`, `baros.associates.attacker.com`) are
  rejected because comparison is whole-label equality, not suffix.

Initial prod config: `allowed_emails = ["jeremy.barton@gmail.com"]`.

### 2. Provision-time gate (`provision.rs::provision_external_user_client`)

A gate at the **top** of the find-or-create path, *before* `get_by_client_id`,
so it covers both the new-provision and existing-client branches, and all
callers of this inner fn:

- `authorize.rs` (consent screen, calls the inner fn directly),
- `token.rs::handle_external_grant` → `provision_external_user` (token mint),
- `device.rs` → `provision_external_user` (device flow).

When an allowlist is configured the gate additionally requires
`identity.email_verified` (Google may assert an unverified address;
CloudflareAccess hardcodes `email_verified = true`). On denial: emit an
`oauth_provision_denied` security-audit row and return **HTTP 403**.

### 3. Refresh-time re-check (`token.rs::handle_refresh_token`) — NEW

The provision gate does **not** cover the `refresh_token` grant: that handler
looks up the client by refresh token and re-mints using
`client.granted_scopes`, checking only `status == "active"`. So an identity
provisioned *then later removed* from the allowlist keeps a working, write-
capable token for up to the 30-day refresh-token lifetime.

To make de-listing take effect within the access-token TTL (≤1 h) we add a
re-check in `handle_refresh_token`:

1. Derive the provider name from the client_id prefix (`"{provider}:{subject}"`
   — split on the first `:`).
2. `state.providers.by_name(prefix)`. **If `None`** (the client is not an
   external IdP-provisioned client — e.g. a directly-registered agent/service
   client), **skip** the re-check entirely. This is what keeps non-external
   clients unaffected.
3. If the matched provider has an allowlist configured, evaluate
   `email_is_allowed(client.legal_contact_email.unwrap_or_default(), …)` (the
   provisioned email is persisted in `legal_contact_email`). On failure: emit an
   `oauth_refresh_denied` audit row and return **HTTP 403**.

This is defense-in-depth: it does not replace the provision gate; it closes the
refresh window. No new SQL — operates on the already-fetched client row, so no
`.sqlx/` regeneration.

### 4. Load-time guardrail (`mod.rs::build_registry`)

When a provider has `auto_provision = true` but **no** allowlist configured, log
a `tracing::warn!` at registry build so an operator who forgot to populate the
allowlist sees it.

## Out of scope

- Revocation of existing rows — none exist that need it (verified).
- Dynamic client registration (`register.rs`) — issues agent/service clients
  under a different trust model, not external IdP provisioning.
- Per-scope authorization policy / role mapping — the allowlist is binary
  (provision or not); scope shaping is a separate concern.

## Verification plan

- Unit tests on `email_is_allowed` (case-insensitivity, last-`@` split, suffix
  rejection, empty-email-deny-when-configured, allow-all-when-empty) — present
  in WIP.
- New unit/handler test: a de-listed external client's refresh is rejected;
  a non-external (no provider prefix) client's refresh is unaffected; an
  allowlisted client's refresh still succeeds.
- Adversarial completeness audit (workflow): enumerate *every* path that mints a
  token or creates a human/external client and confirm each is gated.
- CI gate before commit: `cargo fmt --check`, `cargo clippy --workspace
  --locked -- -D warnings`, `cargo test` (oauth provider + token modules).

## Provenance

Resolves backlog claim (filed 2026-06-03). PR off `origin/main` on branch
`security/oauth-provision-allowlist`.
