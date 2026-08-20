# Decision: the `epigraph-api` no-`db` build variant is unsupported

**Status:** accepted, 2026-08-20
**Supersedes the open question left by:** PR #343, `docs/architecture/audit-cross-source-cfg-gating.md`
(that doc landed on `origin/dev`, not `origin/main`, and ends "No code changes in this step; the fix
is left for a follow-up"). This is that follow-up.
**Backlog claim:** `cedf2a3b` — "epigraph-api will not build without the db feature".

## The reported defect

```
$ SQLX_OFFLINE=true cargo check -p epigraph-api --no-default-features
error: could not compile `epigraph-api` (lib) due to 28 previous errors; 21 warnings emitted
```

28 errors across 8 files (`access_control.rs`, `openapi.rs`, `oauth/providers/mod.rs`,
`routes/{versioning,edges,spans,challenge,cross_source,mod}.rs`) — name-resolution failures for
`sqlx`, `epigraph_db`, `EpiGraphEvent`, `ClaimId`/`AgentId`, `graph_neighborhood`, and
`AppState::db_pool`.

## Decision

Make the failure **explicit and intentional**: `crates/epigraph-api/src/lib.rs` now raises a
`compile_error!` under `#[cfg(not(feature = "db"))]`. The no-`db` variant is not repaired.

## Evidence

### 1. Nothing builds `epigraph-api` without `db`

Four independent surfaces, all checked against `origin/main` (39484459):

| Surface | Invocation | Features |
|---|---|---|
| CI | `.github/workflows/ci.yml` — `cargo build --workspace --locked`, `cargo clippy --workspace --all-targets` | defaults (`db` on); `grep -n features ci.yml` returns nothing |
| Local gate | `scripts/verify.sh` — `cargo build --workspace --locked` | defaults; `grep -n features scripts/verify.sh` returns nothing |
| Production | epiclaw-host `src/host/container.rs` — `cargo build --release -p epigraph-api` | defaults |
| README quickstart | `cargo build --release -p epigraph-api -p epigraph-mcp` | defaults |

The only workspace dependent is `epigraph-cli` (`epigraph-api = { workspace = true }`) — default
features on. `grep -rn "no-default-features"` over the repo matches only `sqlx-cli` install
instructions in docs. No `wasm32` or `no_std` target exists anywhere in the tree. The `genai`
feature already declares `db` as a dependency; `tls`, `otel`, `integration`, `enterprise`, and
`episcience` are never enabled standalone by any build. So `compile_error!` cannot break a real
build, and **it does not change what production compiles**.

### 2. The variant is structurally untestable, not merely untested

`crates/epigraph-api/Cargo.toml` `[dev-dependencies]` lists `epigraph-db` and `sqlx` as
**non-optional**. `cargo test -p epigraph-api --no-default-features` therefore links Postgres
regardless of the feature flag. A "lightweight/mock mode without a PostgreSQL dependency" — the
stated rationale in the old `routes/mod.rs` header — cannot be exercised by the crate's own test
suite as the manifest stands.

### 3. It has been broken for ~3.5 months, undetected

`git blame` on the breaking lines:

- `routes/versioning.rs::supersede_claim` — `7b6b8bdb`, **2026-05-08**, "fix(api): require
  claims:write scope on supersede_claim"
- `openapi.rs` workflow-schema import — `e86ed466`, **2026-05-09**, "feat(api): typed OpenAPI
  schemas for 4 workflow endpoints"
- `access_control.rs` re-export — `f50ac854`, 2026-05-30
- `oauth/providers/mod.rs` re-export — `5f02e3c3`, 2026-06-02

The `routes/mod.rs` header asserting the variant works was dated "Audited 2026-03-28" — i.e. the
assertion was already false for three months when PR #343 re-audited the gating in July 2026 and
still did not build the configuration.

### 4. Repair is mechanically cheap, but the cheap repair breaks the variant's own contract

A throwaway probe gated the errors mechanically and re-checked each round:

| Round | Errors | What the round revealed |
|---|---|---|
| 0 | 28 | resolution failures in 8 files |
| 1 | 27 | 12 **new** errors in `openapi.rs` (the `ApiDoc` derive needs the workflow schemas) |
| 2 | 6 | `versioning::{supersede_claim, claim_history}` have no non-`db` stub at all |
| 3 | 4 | `utoipa` doc-stub `__path_*` types |
| 4 | **0** | compiles, with **55** `cargo clippy --no-default-features` warnings |

So repair converges in ~30 lines — the cascade argument does *not* hold, and is deliberately not
used to justify this decision. What the probe actually showed is worse:

- It compiled by **deleting** `/api/v1/claims/:id/supersede`, `/api/v1/claims/:id/history`, and
  `/api/v1/claims/:id/compound_neighborhood` from the non-`db` router, plus three OpenAPI paths.
  Those routes then return **404**, not the 501 the variant's documented contract promises. The
  minimal repair does not restore the variant; it silently produces a different, quieter one.
- A contract-honoring repair means hand-writing 501 stubs for three handlers that never had one,
  and deciding what a no-`db` OpenAPI document claims about four workflow endpoints it cannot
  serve — inventing API surface for a configuration with no consumer and no test.
- The 55 dead-code warnings mean the CI job that would prevent re-rot cannot be added with
  `-D warnings` until they are all cleaned or blanket-`allow`ed.

Repairing without adding that CI job just resets the rot clock; adding it means paying for a
configuration nobody runs on a runner whose `ci.yml` already carries "No space left on device"
mitigations.

## What was deliberately not done

- **The 171 `cfg(not(feature = "db"))` stubs across 42 files are left in place.** Reaping them is a
  separate logical decision and an unreviewable diff. `compile_error!` makes them unreachable; the
  `routes/mod.rs` header now says so and forbids adding more. Follow-up backlog item.
- **`default = ["db"]` was not touched**, and `db` was not folded into the other features. The
  feature graph and the production build output are byte-identical to before this change.

## What the failure looks like now

`compile_error!` is expanded during macro expansion, before name resolution, so it is the **first**
diagnostic rustc emits:

```
$ SQLX_OFFLINE=true cargo check -p epigraph-api --no-default-features
error: epigraph-api requires the `db` feature. The no-db build variant is unsupported: ...
  --> crates/epigraph-api/src/lib.rs:16:1
...
error: could not compile `epigraph-api` (lib) due to 29 previous errors
```

The 28 pre-existing rot diagnostics still follow it — `compile_error!` does not abort the
compilation pass. That is accepted: the developer reads the explanation first, and the residual
errors are now *explained* rather than mysterious. A `build.rs` panic would collapse the output to
a single line, but it would add a build-script node to the production build graph purely for
cosmetics, which is a worse trade.

## Reversing this

If a genuine no-`db` consumer appears, the reversal is: delete the `compile_error!`, apply the
five-round gating (recorded above), hand-write the three missing 501 stubs, clean the 55 clippy
warnings, and — this is the load-bearing part — add
`cargo check -p epigraph-api --no-default-features` to `.github/workflows/ci.yml`. Without that
last step the variant will rot again within weeks, exactly as it did between 2026-05-08 and now.
