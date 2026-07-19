# Audit: `#[cfg(feature = "db")]` Gating Gaps — `cross_source::list_candidates` / `decide_candidate`

## Scope

Covers `crates/epigraph-api/src/routes/cross_source.rs` as introduced by the
`feat/nightly-xsm-rest-routes` branch (commits `0f51bfb`, `458166f`,
`9439f02`), merged to `origin/main` at `a983921` (PR #342, "Add REST
endpoints for cross-source match candidate review"). This audit is
read-only: no code in this step is changed.

**Branch-state note:** at the time of this audit, `dev` (and this task's
base branch) is at `b2c5bf1` and does **not** yet contain
`feat/nightly-xsm-rest-routes` — `cross_source.rs` on `dev` still has only
`get_cross_source_matches`. `origin/main` is ahead and already has the
`list_candidates` / `decide_candidate` handlers this audit covers. The
findings below are taken from `cross_source.rs` as it exists on
`origin/main` (`a983921`), since that is the only place the handlers in
question currently exist. A follow-up step must port/merge this feature
into `dev` before the fix identified here can land there.

---

## Existing pattern (baseline)

`get_cross_source_matches` at the top of the file establishes the file's
convention:

```rust
#[cfg(feature = "db")]
pub async fn get_cross_source_matches(...) -> Result<Json<CrossSourceMatchesResponse>, ApiError> {
    // uses state.db_pool, sqlx::query_as, epigraph_db::... — real query
}

#[cfg(not(feature = "db"))]
pub async fn get_cross_source_matches(
    State(_state): State<AppState>,
    Path(claim_id): Path<Uuid>,
) -> Result<Json<CrossSourceMatchesResponse>, ApiError> {
    Ok(Json(CrossSourceMatchesResponse { claim_id: claim_id.to_string(), corroborates: Vec::new(), pending: Vec::new() }))
}
```

Every handler that touches `state.db_pool`, an `epigraph_db::*` type, or a
`sqlx::*` macro/type must have a matching `#[cfg(not(feature = "db"))]`
counterpart, because:

- `epigraph-api/Cargo.toml` makes both `epigraph-db` and `sqlx` **optional**
  deps, pulled in only by `db = ["dep:epigraph-db", "dep:sqlx", ...]`. Outside
  a `#[cfg(feature = "db")]` block, those crates are not in scope at all in a
  non-`db` build.
- `AppState::db_pool` (`crates/epigraph-api/src/state.rs`) is itself declared
  `#[cfg(feature = "db")] pub db_pool: PgPool` — the field doesn't exist on
  `AppState` in a non-`db` build.
- `routes/mod.rs::create_router` is a single, non-cfg-gated function that
  registers every route unconditionally (`pub mod cross_source;` is also not
  cfg-gated). So any handler it references must compile in **both** feature
  configurations, which is only possible if every db-touching function has a
  `#[cfg(not(feature = "db"))]` stub with the same route signature.

---

## Inventory of items referencing sqlx / epigraph_db / state.db_pool / ClaimId / AgentId

| Item | References `sqlx`/`epigraph_db`/`state.db_pool`? | Currently gated `#[cfg(feature = "db")]`? | Has `#[cfg(not(feature = "db"))]` stub? | Status |
|---|---|---|---|---|
| `get_cross_source_matches` | Yes (both, baseline) | Yes | Yes | OK — reference pattern |
| `map_sqlx<T>` helper | Signature is `Result<T, sqlx::Error>` — references `sqlx::Error` type | **No** | N/A | See note below |
| `ListCandidatesQuery` struct | No — plain `Deserialize` (`status: Option<String>`, `limit: i64`) | No | N/A | OK — feature-agnostic, no gating needed |
| `PendingCandidateOut` struct | No — plain `Serialize` | No | N/A | OK — no gating needed |
| `excerpt()` fn | No — pure string helper | No | N/A | OK — no gating needed |
| `list_candidates` (real impl) | Yes — `epigraph_db::MatchCandidateRepo`, `sqlx::query_as`, `state.db_pool` | Yes | Yes (returns `Ok(Json(Vec::new()))`) | OK — already correctly gated both sides |
| `DecideCandidateRequest` struct | No — plain `Deserialize` (`verdict: String`) | No | N/A | OK — no gating needed |
| `decide_candidate` (real impl) | Yes — `epigraph_db::MatchCandidateRepo`, `epigraph_db::ClaimRepository::are_all_current`, `epigraph_db::EdgeRepository::create_symmetric_if_absent`, `state.db_pool`, `AuthContext`/`auth.agent_id` | Yes (`#[cfg(feature = "db")]` present on the fn) | **No** | **GAP — must add stub** |

`ClaimId`/`AgentId` newtypes (`epigraph-core/src/domain/ids.rs`) are **not**
used anywhere in `cross_source.rs`; both `list_candidates` and
`decide_candidate` operate on raw `Uuid` (via `Path<Uuid>`,
`row.claim_a: Uuid`, `auth.agent_id: Option<Uuid>` from `epigraph-auth`).
No additional gating concern from those types.

`map_sqlx<T>(r: Result<T, sqlx::Error>) -> Result<T, ApiError>` is a
free function whose *signature* names `sqlx::Error` unconditionally and is
**not** itself wrapped in `#[cfg(feature = "db")]`. It is only ever called
from inside `#[cfg(feature = "db")]` bodies today, but as written it will
fail to compile in a non-`db` build regardless of whether it's called,
because `sqlx` is not a dependency in that configuration and the function
signature alone requires the type to resolve. This is a pre-existing issue
on the `get_cross_source_matches`/baseline code, not something introduced
by `list_candidates`/`decide_candidate`, but it sits in the same file and
blocks a clean non-`db` build today. Flagging it here since it's in scope
of "references sqlx query macros/types ... not gated behind
`#[cfg(feature = "db")]`."

---

## Confirmed compile-time gap

`decide_candidate` is the one handler introduced by this feature that is
gated on the `db`-feature side but has **no** `#[cfg(not(feature = "db"))]`
counterpart. `routes/mod.rs::create_router` references
`cross_source::decide_candidate` unconditionally:

```rust
.route(
    "/api/v1/match_candidates/:id/decide",
    post(cross_source::decide_candidate),
);
```

Building the `epigraph-api` crate without the `db` feature will fail to
resolve `cross_source::decide_candidate`, since the only definition of that
symbol is behind `#[cfg(feature = "db")]`.

---

## Fix summary (not implemented here)

Two items for the next step, once this feature is ported onto `dev`:

1. Add a `#[cfg(not(feature = "db"))]` stub for `decide_candidate`,
   following the `delete_edge` precedent in `routes/edges.rs` (returns
   `ApiError::ServiceUnavailable` rather than fabricating a success body,
   since `decide_candidate` is a write/side-effecting endpoint — unlike
   `list_candidates`'/`get_cross_source_matches`'s empty-read stubs):

   ```rust
   #[cfg(not(feature = "db"))]
   pub async fn decide_candidate(
       State(_state): State<AppState>,
       Path(_id): Path<Uuid>,
       Json(_req): Json<DecideCandidateRequest>,
   ) -> Result<Json<serde_json::Value>, ApiError> {
       Err(ApiError::ServiceUnavailable {
           service: "Cross-source match candidate review requires database".to_string(),
       })
   }
   ```

2. Either gate `map_sqlx` behind `#[cfg(feature = "db")]` (it's only called
   from `db`-gated bodies) or move it inside each `#[cfg(feature = "db")]`
   block that uses it, so the file compiles cleanly with `--no-default-features`.
