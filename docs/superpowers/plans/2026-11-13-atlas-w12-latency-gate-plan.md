# Atlas W12: the latency budget as a gate

Backlog W12 824ac5ac (epic 8fa0282d). Stacked on `feat/atlas-w10` (#813), which
carries W11 through `atlas/wave4-base`. Design:
`docs/superpowers/specs/2026-11-12-atlas-nested-groups-and-subgraph-view-design.md`
§6. No migration, and no change to a route's behaviour.

## The budget (design §6) and how it is split

| Budget | Total | Client allowance | Server share |
|---|---|---|---|
| Level transition or switch flip, warm, p95 | 200 ms | 50 ms (draw the level) | 150 ms |
| The same, cold, p95 | 500 ms | 50 ms | 450 ms |
| Level payload | 150 KB gzip | | checked per body by `check_level_body` (W10a), on the kernel route and the BFF path (W10) |
| Client force simulation | ≤ 300 ms settle | | checked statically by W11's tests |

The server share is spent by two processes. The per-PR gate measures each one
apart, because the Explorer is its own Cargo workspace and cannot link the
kernel:

| Process | Warm p95 | Cold p95 | Where it is measured |
|---|---|---|---|
| Kernel (route, DB read, decode, validate, `for_viewer`, encode) | 120 ms | 420 ms | `crates/epigraph-api/tests/atlas_latency_gate.rs` |
| Explorer BFF (proxy, mirror decode, digest, compression) | 30 ms | 30 ms | `services/explorer/tests/atlas_latency.rs` |

Network round-trip time between the browser and the server is not modelled:
every measurement is on loopback. The client allowance is the room for it and
for drawing.

The page-load routes (`/maps`, `/maps/:map/themes`) are not level transitions.
They are recorded and gated at the cold server share (450 ms), since they run
once per `/atlas` load. Claim-to-leaf is a navigation (search, then fly), gated
like a level: 120 ms warm, 420 ms cold.

## Files

| File | What |
|---|---|
| `crates/epigraph-atlas-contract/src/scale.rs` (feature `check`) | `theme_levels`: one theme's level documents in both hierarchies from real claim, agent and evidence ids, built with the W10a generator (`leaf_level`), with twin switches and outside targets that resolve inside the set |
| `crates/epigraph-api/tests/atlas_latency_gate.rs` | the kernel harness, the pure verdict, and the red-on-regression test |
| `services/explorer/tests/atlas_latency.rs` | the BFF harness (wiremock kernel) and its red-on-regression test |
| `services/explorer/static/atlas.js` | one hook: after the frame that first draws a newly attached level, `data-atlas-drawn-level` on the stage and a `performance.mark` |
| `scripts/e2e/probe-atlas-latency.sh`, `scripts/e2e/atlas-latency-browser.mjs`, `scripts/e2e/README.md` | the staging run (full scale) and the opt-in browser check |

## The seeded map (`ATLAS_LATENCY_SCALE`)

A team map built through W2's storage (`AtlasMapRepository::write_run`,
`put_level`, `finish_run`) on a fresh `#[sqlx::test]` database:

- **Themes:** 1,743 claims each (366k / 210). `small` (the default, the per-PR
  run) is 24 themes, about 42k claims and 1,584 levels: large enough that a
  read whose cost grows with the whole run rather than one theme shows in the
  per-PR gate. `full` (the staging run) is 210 themes, about 366k claims and
  13,860 levels; an integer sets the theme count.
- **Claims:** real `claims` rows, inserted in batches, with `theme_id` set. One
  in five is the team's (`group`), the rest public: the team map's readable
  set is mostly public claims. A pool of 32 agents authors them. Evidence rows
  hang off one claim in eight.
- **Levels:** `scale::theme_levels` per theme. Leaves of 64 claims, 8 agents
  and 16 evidence nodes (88 nodes, 4 claim links per claim), grouped 8 to a
  group under the theme root. 1,743 claims give 28 leaves, 4 groups and a
  root per hierarchy, so a run holds 66 documents per theme and 13,860 at
  full scale. The links hierarchy partitions the claims in another order,
  so a claim's two leaves differ, as on a real map.
- **Viewer:** a reader of the team.

## What is measured

Every request is a real HTTP round trip to `create_router` served by
`axum::serve` on a loopback listener, with a `reqwest` client and the viewer's
bearer. Each timed sample also asserts status 200 and the level id asked for,
so a regression that answers a fast 404 cannot read as green.
`check_level_body` runs once per distinct level, outside the timer.

| Type | Request |
|---|---|
| `root` | a theme's level-0 group |
| `group` | a group below the root |
| `leaf` | a leaf (the `for_viewer` path) |
| `switch` | the twin, in the other hierarchy, of a level just fetched |
| `claim_leaf` | `/claims/:id/leaf` for a claim of the map |
| `themes` | `/maps/:map/themes` |
| `maps` | `/maps` |

- **Warm:** a pooled client and server after one untimed request of each type.
  Samples cycle over distinct levels.
- **Cold:** a fresh `ScopedPool`, `AppState`, listener and client per sample
  (no pooled connection, no statement cache), and a level not asked for
  before. A fresh PROCESS is not part of the per-PR run; the staging script's
  separate `--release` invocation is the closest it comes, and that is stated
  as a gap.

The report (`ATLAS_LATENCY_REPORT`, a path) is JSON: scale, build profile,
seed and request counts, and n, p50, p95 and max per type and warm/cold, plus
the verdict. It is written before any assertion, so a red run still leaves its
numbers. A table goes to stderr either way.

The BFF harness measures, for the largest committed leaf fixture
(`team_leaf_dense`) and the theme root: 200 with gzip, 200 with br, and 304
(`If-None-Match`), warm; asserts `Content-Encoding` on every compressed
sample; and records the gzip and br sizes of the body. Its report path is
`ATLAS_LATENCY_BFF_REPORT`.

## The verdict

`verdict(samples, budgets) -> Vec<Breach>` is pure: p95 (nearest rank) of each
(type, warm/cold) against its budget. Unit tests on synthetic samples: a p95
over budget is a breach, a p50 under budget with a p95 over is still a breach
(p95, not p50, is the gate), an empty sample set is a breach (a type that
measured nothing cannot be green).

## Red on regression

- **Kernel:** `a_deliberately_slow_route_turns_the_gate_red`. A test-only
  `axum` middleware, layered outside `create_router`'s router, sleeps on leaf
  level paths only. A control run with no delay is green; the run with a delay
  of twice the warm budget is red, and only `leaf` is in breach (attribution).
  No change under `src/`.
- **BFF:** `a_slow_kernel_turns_the_bff_gate_red`: wiremock's `set_delay` on
  the level route.

## Staging wiring

`scripts/e2e/probe-atlas-latency.sh` runs both harnesses at
`ATLAS_LATENCY_SCALE=full` in `--release` and writes both reports to a
directory it is given. It refuses a `DATABASE_URL` the way `dsn-guard.sh`
refuses a DSN (no port, or the production port). The README's script table
lists it, so "the scripts/e2e probes that apply" in a staging run include it.

The client check (`atlas-latency-browser.mjs`, Playwright, opt-in like
`elevation-no-authenticator.mjs`) times click to drawn for a group, a leaf and
a switch flip against the Explorer's `--atlas-fixture-preview` server. CI has
no browser (ci.yml and explorer.yml install none), so it is not in the per-PR
gate.

## "Done when" (backlog 824ac5ac)

| Criterion | Proof |
|---|---|
| The harness runs in the per-PR gate (small scale) | `atlas_latency_gate.rs` is an `epigraph-api` integration test, run by ci.yml's `cargo test -p epigraph-api`; `atlas_latency.rs` by explorer.yml's `cargo test`. No ci.yml change |
| It runs in staging (full scale) | `scripts/e2e/probe-atlas-latency.sh` and its README row |
| It reports p50 and p95 per level type | the JSON report; `the_kernel_meets_the_latency_budget` writes it |
| A deliberately slow route turns it red | `a_deliberately_slow_route_turns_the_gate_red`, `a_slow_kernel_turns_the_bff_gate_red` |

## Fail-on-old proofs (each run red, then restored)

- The verdict compares p50 instead of p95: the verdict unit test goes red.
- The level route answers 404: the harness's per-sample status check goes red.
- The delay layer is removed: the red test's "treated run is red" goes red.
- The BFF's compression layer is removed: the BFF harness's `Content-Encoding`
  check goes red.

## Needs prod measurement

The numbers are synthetic. What this cannot see: prod's TOAST and buffer-cache
state, its concurrent load, real leaf sizes once W9 assembles leaves, and the
network between the browser and the server.
