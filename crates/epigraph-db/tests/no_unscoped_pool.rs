//! The request path must stop reaching for the raw application pool.
//!
//! # What this ratchet is for
//!
//! `docs/tenancy/progress.json` records the open decision
//! `D-PR17-request-path-never-stamps-session-gucs`: `ScopedPool::acquire_as`
//! and `::begin_as` had **zero** non-test call sites, so everything migrations
//! 077/078/079 armed was inert, and §9.2 step 11d — repointing `DATABASE_URL`
//! at `epigraph_app` — was a total read/write outage waiting to happen. Every
//! `state.db_pool` site in a handler is one instance of that: the in-query `$V`
//! predicate is filtered correctly, the connection carries no tenancy GUCs at
//! all, and under FORCE the two disagree. Rows go invisible to their own
//! owners, with a 200 and no log line.
//!
//! # Why it is SEEDED rather than asserted at zero
//!
//! PR-17 deliberately declined to ship this file, for a stated reason: *"the
//! lint would fail on day one"*. It would — there were 391 unconverted sites
//! when this file landed, and a lint that fails on day one is a lint someone
//! deletes in week two. (303 today; the assertions below measure the tree and
//! are what a reader should trust over any integer in this prose.)
//!
//! Seeding fixes that without weakening it. The table below is the measured
//! per-file site count, so the lint **passes today** and can only shrink. Each
//! conversion shard lowers its own entries, and the exactness of the assertion
//! is what forces the shard to say so in its diff.
//!
//! # The rule for shard authors
//!
//! * Counts are asserted **exactly**, in both directions, for BOTH tables. A
//!   shard that converts sites must lower its number here in the same commit; a
//!   number that is too high is as much a failure as one that is too low,
//!   because a register nobody prunes is folklore rather than a ratchet.
//!   [`HIGH_WATER`] additionally makes growth structural rather than a matter
//!   of a reviewer noticing an edited literal.
//! * A file driven to zero must have its key **REMOVED**, not set to `0`. The
//!   scanner only ever produces non-zero entries, so a `0` row can never be
//!   satisfied — the same rule `epigraph-api/tests/viewer_route_table_lint.rs`
//!   documents on its removed `webhooks.rs` entry.
//! * **Reads** convert onto `AppState::read_as`, which dispatches on
//!   `SessionGucMode` and refuses when no `ScopedPool` was built. Do **not**
//!   convert a site to a literal `acquire_as`: it hard-refuses
//!   `EPIGRAPH_SESSION_GUC_MODE=transaction`, the pooler fallback
//!   `bin/server.rs` advertises to operators, so a site converted that way is
//!   unservable in a configuration this project supports.
//! * **Writes are NOT `read_as`'s job and there is deliberately no
//!   `AppState::begin_as`.** Their target is `ScopedPool::begin_as`, reached
//!   through `AppState.scoped`. `read_as` is documented read-only for a
//!   substantive reason — in `SessionGucMode::Session` its arm is a bare
//!   connection, so a multi-statement write through it is not atomic, while the
//!   identical code in `Transaction` mode is; atomicity that depends on an
//!   environment variable is a data-integrity landmine. A write-side
//!   `AppState` twin was deliberately NOT added here: a second entry point with
//!   zero production callers is the very defect `read_as`'s own doc argues
//!   against, and the write-side predicate is 16b's, not this PR's. Measured on
//!   this tree with a same-line name needle (create / insert / update / delete
//!   / upsert / supersede / revoke / mark_ / record_ / append): **30** of the
//!   sites below were visibly write-shaped when that sweep ran against 355 of
//!   them; the sweep was not re-run for shard 6, which converted reads only and
//!   left every write-shaped site counted. Led by
//!   `routes/experiment_loop.rs` (5), `routes/tasks.rs` (4) and
//!   `routes/crud.rs`, `routes/claims.rs`, `routes/workflows.rs`,
//!   `routes/webhooks.rs` (3 each). That is a LOWER bound — the needle only
//!   sees a write whose verb appears on the same line as the pool access — so
//!   a shard must classify its own sites rather than trusting this figure.
//! * **Two files below must still NOT be converted, and the reason has
//!   changed — read this before assuming it is stale.** `routes/webhooks.rs`
//!   and `routes/events.rs` both suppress on
//!   `ClaimRepository::hidden_claim_ids`, whose two arms need *different*
//!   authority and got the same authority once RLS was FORCEd on an
//!   application role. That was the reason not to convert them: converting
//!   would have turned this ratchet green over a control that had stopped
//!   working. **PR-24 repaired the probe itself** — migration 086 moves both
//!   arms into a `SECURITY DEFINER` frame, so the answer no longer depends on
//!   the connection's session GUCs at all, and
//!   `F-PR23-existence-probe-collapses-under-force` is closed.
//!
//!   **DO NOT convert `routes/webhooks.rs` or `routes/events.rs`. Closing the
//!   probes did not make them safe to convert, and a shard must not read it that
//!   way.** As of PR-25 the prohibition stands on reason (2) ALONE — reason (1)
//!   is closed and is kept, not deleted, because the hazard it names is general.
//!   `docs/tenancy/progress.json`'s `prs.next` is worded to match — if the two
//!   ever disagree about the FORCE of this rule, that disagreement is itself the
//!   finding:
//!
//!   1. **CLOSED BY PR-25, recorded rather than removed.**
//!      `F-PR24-event-list-existence-arm-collapses-under-force` was the SQL twin
//!      of the repaired probe — `EventRepository::list`'s suppression predicate,
//!      which serves the *persisted* half of `GET /api/v1/events`, all of
//!      `GET /api/v1/graph/snapshot/:version`, and all of MCP `list_events`. It
//!      read `claims` directly on both arms and collapsed the same way. PR-25
//!      moved both arms into 086's `SECURITY DEFINER` frame; no migration was
//!      needed. This reason no longer holds the prohibition up — reason (2)
//!      does, on its own — but the sentence stays, because the hazard is not
//!      specific to that finding: converting a file whose suppression control
//!      has stopped working turns this ratchet green over nothing, and the next
//!      shard must check the control before it checks the counter. **The
//!      separate hold on `crates/epigraph-mcp/src/tools/events.rs` is NOT
//!      lifted and never was about conversion**: it calls
//!      `EventRepository::list` with no Rust backstop at all, and this ratchet
//!      cannot see it, because its scan root is `crates/epigraph-api/src` and
//!      `epigraph-mcp` appears only in the Known-limits section above. No
//!      counter protects that file, so this sentence is still the only control
//!      on it.
//!   2. `D-PR17-request-path-never-stamps-session-gucs`, which still blocks
//!      §9.2 step 11d with 303 unconverted sites. **This alone is sufficient for
//!      the prohibition above.** PR-24 discharged one precondition and PR-25 a
//!      second; PR-26 converted the first shard's seven sites, PR-28 the
//!      second shard's five, PR-29 — the first MULTI-FILE shard — the third
//!      shard's eleven, across `routes/search.rs`, `routes/voids.rs` and
//!      `routes/methods.rs`, and shard 4 nineteen more across
//!      `routes/belief.rs` (14) and `routes/computation.rs` (5), and shard 5
//!      seventeen more across `routes/political.rs` (7), `routes/context.rs`
//!      (4), `routes/perspective.rs` (3), `routes/graph_neighborhood.rs` (2)
//!      and `routes/structural.rs` (1), and shard 6 twenty-five more across
//!      `routes/edges.rs` (7), `routes/hypothesis.rs` (6), `routes/agents.rs`
//!      (5), `routes/experiments.rs` (3), `routes/community.rs` (2) and
//!      `routes/rag.rs` (2), and shard 7 — the LAST read shard — twenty-seven
//!      more across `routes/workflows.rs` (10), `routes/entities.rs` (5),
//!      `routes/claims.rs` (4), `routes/crud.rs` (4), and one each in
//!      `routes/versioning.rs`, `routes/conventions.rs`, `routes/graph.rs` and
//!      `routes/challenge.rs`. None
//!      discharged the gate — 303 is not 0 — and no shard in the series may be
//!      read as unblocking step 11d. A SMALLER number is not a discharged
//!      decision: 113 of the 416 sites the series began with are converted, and
//!      303 are not.
//!
//!      **What remains is NOT read-shard work, and that is the closing
//!      measurement of the read programme rather than a to-do list.** Shard 7
//!      exhausted the sites PR #460 classified `A` that any shard may take: of
//!      the 26 it was sized for, 24 landed, 2 were declined at SITE level (an
//!      authorization read in `routes/claims.rs`, argued at the site), and 3
//!      more landed that the classification filed `C` on a rule that does not
//!      match reachability. The residue is ~39 category `B`, behind an open
//!      operator decision, and ~265 category `C`, every one blocked by its
//!      HANDLER — overwhelmingly because the handler WRITES, which
//!      `AppState::read_as` is documented not to serve.
//!
//!      **Shard 4 is also the first shard to end with rows it did not empty,
//!      and that is the honest outcome rather than a shortfall.** It was sized
//!      from a read/write classification that put all 40 of its sites in three
//!      files at "read"; re-measured from the tree, 7 of the 40 write and 9 more
//!      are in handlers that hold no `Viewer` at all. So `routes/belief.rs`
//!      keeps 3 and `routes/computation.rs` 10, `routes/papers.rs` is unchanged
//!      at 8, and [`HIGH_WATER_FILES`] does not move. A shard lowers its rows to
//!      what it converted; it does not delete a row it did not empty, and it
//!      does not convert a site to make a planning figure land.
//!
//!   And independently of both, the conversion is unargued: each file takes a
//!   raw `&PgPool` as a *parameter* (from `state.db_pool` and from the
//!   webhook-dispatcher handoff in the EXEMPT `bin/server.rs`), so a conversion
//!   is a signature change across a process-lifetime task boundary rather than a
//!   `read_as` swap — and BOTH probes (the Rust `hidden_claim_ids` and, since
//!   PR-25, the SQL `EventRepository::list`) are now correct on an unstamped
//!   connection, so stamping buys nothing *for those controls*. See
//!   `hidden_claim_ids`' and `EventRepository::list`'s own doc comments for the
//!   mechanism.
//! * **The repo layer did not serve this at scale. PR-27 fixed the REPO-LAYER
//!   HALF, for the 188 single-statement viewer-taking reads, and nothing else.**
//!   Measured under `crates/epigraph-db/src/repos/` before PR-27: 206
//!   `pub async fn` took both a `pool: &PgPool` and a `Viewer`, and only 14
//!   `*_conn` siblings existed at all — of which exactly 5 took a `Viewer`
//!   (`ClaimRepository::{get_by_id_conn, list_conn, count_conn}` and, from
//!   PR-26, `LineageRepository::{get_lineage_conn, get_descendants_conn}`).
//!   The pilot worked only because one of those happened to exist. PR-27
//!   re-measured that set and found 188 of the 206 run exactly one statement on
//!   the pool parameter and reference it exactly once, so they need no sibling
//!   at all: their parameter is now `<'e, E: sqlx::PgExecutor<'e>>`, and one
//!   body serves a pool and a connection alike. A shard that reaches one of
//!   those 188 no longer has to author a duplicate form for it.
//!
//!   **Read that scope literally, because most of the register is NOT reached by
//!   it.** `prs.next` measures the site distribution as a long tail: 74 of the
//!   registered sites are `let pool = &state.db_pool` aliases and roughly 70 are
//!   raw inline `sqlx` written directly in the handler. Neither class routes
//!   through a repo function at all, so a widened repo-layer bound does nothing
//!   for either, and both remain each shard's own work. PR-27 converts ZERO
//!   sites and moves neither constant below.
//!
//!   Of the remaining 18, 12 are hard exclusions and 6 are deferred wrappers.
//!   The exclusion mechanisms, each derived by counting executions of and
//!   references to the parameter rather than by reading the body narratively:
//!   a body that runs several statements on it (6 — a by-value `E: PgExecutor`
//!   is MOVED by its first use, which is why the compiler, not a reviewer,
//!   enforces this criterion); a body that runs one statement AND then passes
//!   the parameter on to another repo call (2, `claim.rs::graph_expand_seeds_since`
//!   and `workflow.rs::resolve_steps_to_heads`); a wrapper that calls
//!   `Pool::acquire`, which is a `Pool` API a `PgExecutor` does not have (2,
//!   `LineageRepository::{get_lineage, get_descendants}`); and a wrapper whose
//!   callee is ITSELF excluded (2, `claim.rs::graph_expand_seeds` and
//!   `workflow.rs::resolve_step_claim`). The other 6 forward, directly or
//!   through one further wrapper, to a callee that DID convert — the two-hop
//!   case is `ClaimThemeRepository::claims_in_themes`, whose callee
//!   `claims_in_themes_at_dim` is itself an unconverted wrapper over the
//!   converted `claims_in_themes_at_dim_since` — so they are convertible
//!   whenever a shard wants them and are deferred only to keep this pass to one
//!   rule.
//!
//!   Do not read the count of unconverted functions as a count of blockers: the
//!   paragraph this replaced did exactly that. Calling
//!   `read_as` once per statement remains the wrong answer either way: in
//!   `Session` mode it would produce N separately-stamped checkouts with no
//!   transaction tying them, against a pool whose `ScopedPoolOptions::default()`
//!   is 10 connections. Two lints police the two connection-taking shapes:
//!   `visibility_lint.rs::every_conn_taking_repo_fn_takes_a_viewer_or_is_exempt`
//!   stops a shard writing a `_conn` sibling *without* a viewer, and — since
//!   PR-27, because that rule keys on the NAME and so cannot see a generic
//!   function —
//!   `visibility_lint.rs::every_executor_taking_repo_fn_takes_a_viewer_or_is_exempt`
//!   applies the same rule to the `PgExecutor` shape this paragraph recommends.
//!
//!   **PR-26 established the shape, and it is NOT a copy-pasted twin.** The
//!   connection-taking form is the PRIMITIVE and the pool-taking form is a thin
//!   wrapper that acquires and delegates. Two copies of the same SQL is what
//!   produced `get_by_id_conn`'s seven-vs-nine projection drift, which no gate
//!   could see because a dropped column defaults to a plausible value rather
//!   than erroring. One body cannot drift from itself, the wrapper keeps every
//!   existing caller (`epigraph-mcp`, ~20 assertions in
//!   `epigraph-db/tests/lineage_tests.rs`) compiling unedited, and
//!   `visibility_lint.rs` has one SQL text to police instead of two. Note that
//!   `every_viewer_taking_repo_fn_that_runs_sql_spends_the_viewer` already
//!   anticipates the wrapper: a body with no `sqlx::query` is skipped as a
//!   delegating wrapper, because the callee is subject to the same lint.
//!   **Cost metric for sizing later shards: 2 new connection-taking repo forms
//!   for 7 converted sites.** PR-28 then measured ZERO new forms for 5 sites,
//!   and PR-29 TWO new forms for 11 sites across three files — so the cost is
//!   driven by how many distinct callees a shard reaches, not by its site count.
//!   Both of PR-29's are single-statement generic widenings of functions that
//!   take no `Viewer` at all, a category PR-27's pass excluded by construction.
//!
//!   **PR-27 adds a third shape for the single-statement majority, and this
//!   paragraph should be read with that scope attached — it does NOT supersede
//!   PR-26's, and PR-26 did not pay for an overstatement.** Measured on the
//!   shipped tree: `get_lineage_conn` and `get_descendants_conn` run FIVE
//!   statements each on one connection, so they are outside the class PR-27
//!   serves and would have been authored identically had PR-27 landed first.
//!   Nor are they duplicated bodies — `get_lineage` is 16 lines and
//!   `get_descendants` 13, each acquiring and delegating, so what exists is one
//!   primitive plus a thin wrapper and no ~180-line SQL body appears twice
//!   anywhere in the tree. Acquire-and-delegate remains correct wherever several
//!   statements must share one connection, which is exactly what
//!   `LineageRepository`'s walk does and why its two wrappers were left
//!   untouched.
//!
//!   Where a body runs exactly ONE statement there is a third and better shape:
//!   no wrapper, no primitive, one generic body. That form cannot drift from
//!   itself either, and it costs zero new entry points. The duplicate-body
//!   hazard this series keeps naming is demonstrated here by the case PR-27
//!   actually deleted — `ClaimRepository::count_conn`, a genuinely copy-pasted
//!   body that had already drifted from `count` in whitespace, now rewritten to
//!   delegate, so the pool-taking and connection-taking counts share a single
//!   SQL text rather than two copies.
//! * **Handler-side sizing, re-derived from the router** (the recon's 113/113
//!   was flagged by its own author as a regex artifact and is not what the code
//!   says). Enumerating handler idents from every `.route(…)` registration
//!   across the 17 files that contain one, then resolving each ident's
//!   declaration: **233** distinct registered handlers, **108** already take a
//!   `ViewerExtractor`, **125** do not, 0 unresolved. So the split is
//!   materially asymmetric, not symmetric, and roughly half the handler
//!   population needs a `ViewerExtractor` added — a real change, not a
//!   mechanical one. Most of the 125 are write handlers (`create_*`, `add_*`,
//!   `batch_*`) or the pre-auth OAuth surface, i.e. 16b/exempt territory rather
//!   than read-conversion territory.
//!
//! # Two places, or it is not a control
//!
//! Following `visibility_lint.rs` and `no_unmaintained_dsn.rs`: an exemption
//! needs both an in-file `UNSCOPED-POOL-EXEMPT:` marker at the top of the file
//! and an entry in [`EXEMPT`] carrying the reason and the measured site count.
//! The set is asserted in both directions, so a file that gets converted but is
//! left in the table fails too.
//!
//! **The table is authoritative; the in-file marker is a pointer to it.** The
//! test asserts the marker is PRESENT, not that its wording matches the
//! table's — several markers are deliberately abbreviated. Do not read a
//! divergence between the two texts as the table being out of date.
//!
//! # Known limits, so nobody over-claims
//!
//! * **Exemption is per FILE, not per site**, exactly as in
//!   `no_unmaintained_dsn.rs`. That is expressible today because every exempt
//!   file measured here is *wholly* exempt — each one is pre-authentication,
//!   boot/observability, or a detached task, in all of its sites. If a future
//!   file is genuinely MIXED, this rule cannot express it and the scanner will
//!   need a per-site marker pass. It does not have one now, and that is stated
//!   rather than assumed. **`state.rs` is where that limit will break first**,
//!   because it is both file-exempt on boot/observability grounds AND the home
//!   of `AppState::read_as` / `maintenance_viewer` — i.e. the natural place a
//!   shard will want to add a request-path accessor. The exemption there is
//!   enumerated method-by-method and pinned at a site count for that reason;
//!   the next shard that adds an `AppState` request-path accessor must
//!   introduce the per-site marker pass rather than extend the file exemption.
//! * **The needle is `.db_pool`, so this measures a FIELD ACCESS, not a
//!   query.** It is the right key for `epigraph-api` because `AppState.db_pool`
//!   is the only raw pool a handler can reach *through the state*. It is blind
//!   to a function that receives a `&PgPool` as a PARAMETER — and that blind
//!   spot is **not** confined to other crates, which an earlier draft of this
//!   list wrongly implied. Measured inside this very scan root, excluding
//!   `#[cfg(test)]` helpers: production functions across a dozen-odd files take
//!   a `&PgPool` parameter, and the register above sees none of them. This
//!   sentence used to carry the integers "22 production functions across 14
//!   files". Conversion shard 5 falsified them by taking
//!   `routes/graph_neighborhood.rs::{compound_response, atomic_response}` from
//!   `&PgPool` to `&mut PgConnection`, so both are struck from the list below
//!   and that file leaves it entirely — a real reduction in the blind spot, and
//!   for the right reason: the two helpers left because their SIGNATURE
//!   changed, not because the needle learned to see a parameter.
//!
//!   **The integers are deliberately NOT restated, because shard 5 could not
//!   reproduce the old ones and will not replace a number it did not measure
//!   with a number it derived by subtraction.** The enumeration below is a
//!   22-name list against a stated count of 22 only if `tenancy_gauge.rs`'s
//!   second `&PgPool`-taking function is read as part of `sample`; nothing
//!   here pins either reading, and no test asserts the count. Re-deriving the
//!   list properly needs a scanner that can tell a `&PgPool` PARAMETER from a
//!   `let pool: &PgPool = ...` local and a production function from a
//!   `#[cfg(test)]` seeder — which is exactly the follow-up lint named at the
//!   end of this bullet, and is where the count belongs. Shard 5 corrected
//!   only what it falsified.
//!
//!   **Conversion shard 7 struck a second name for the same reason, and no
//!   integer moves here either.** `routes/graph.rs::fetch_subgraph_edges` took
//!   a `&PgPool` PARAMETER and now takes a `&mut PgConnection`, because its
//!   only caller — `routes/graph.rs::expand`, verified as the only one
//!   workspace-wide — is converted. It left the list below because its
//!   SIGNATURE changed, not because the needle learned to see a parameter, and
//!   shard 7 likewise replaces no number it did not measure. Note what did NOT
//!   happen: it was changed IN PLACE rather than split into a `_conn` primitive
//!   with a `&PgPool` wrapper, which is what shard 6 had to do for
//!   `graph_query_utils::load_subgraph`. A wrapper here would have had zero
//!   call sites, and the `_conn` shape would have added a route-layer
//!   connection primitive that `visibility_lint.rs`'s two connection rules
//!   cannot see, because their scan root is `crates/epigraph-db/src/repos`.
//!   Enumerated so no shard author mistakes this table for complete —
//!   `middleware/group_authz.rs::require_group_admin`,
//!   `middleware/provenance.rs::record_provenance`,
//!   `oauth/providers/provision.rs::emit_oauth_audit`,
//!   `routes/clusters.rs::{persist_bridge_run, gc_bridge_runs}`,
//!   `routes/computation.rs::extract_neighborhood`,
//!   `routes/edges.rs::{trigger_edge_ds_recomputation, propagate_to_dependents,
//!   recompute_claim_belief}`, `routes/events.rs::retain_visible_events`,
//!   `routes/graph_query_utils.rs::load_subgraph`,
//!   `routes/independence.rs::analyze_independence`,
//!   `routes/provenance.rs::{find_or_create_author_agent, find_or_create_org_agent}`,
//!   `routes/webhooks.rs::{retain_visible_subscriptions, agent_principal_exists,
//!   agent_may_receive, deliver_event}`,
//!   `routes/workflows.rs::{get_or_create_system_agent,
//!   auto_wire_inserted_edges}`, `tenancy_gauge.rs::sample`. The webhook
//!   fan-out is the one that matters most and the one this register cannot
//!   see at all: its pool is handed over once in the EXEMPT `bin/server.rs` and
//!   then travels as a parameter, and `agent_may_receive` resolves a real
//!   `Viewer` on it. A second lint keyed on the parameter is a follow-up, not
//!   part of this PR.
//!
//!   **Shard 6 added one name to that enumeration and one shape to the blind
//!   spot, and records both rather than letting the list read as re-derived.**
//!   `routes/graph_query_utils.rs::load_subgraph` was a live instance the list
//!   never named — it takes `pool: &PgPool` as a PARAMETER and ran five
//!   statements on it — and is added above. Shard 6 gave it a
//!   `load_subgraph_conn(&mut PgConnection, …)` primitive so
//!   `routes/edges.rs::graph_full` could stamp, keeping the `&PgPool` spelling
//!   for `routes/graph_query.rs`, which is outside that shard and stays counted.
//!   That primitive is a ROUTE-LAYER `_conn` function, and no lint in this
//!   workspace reaches it: `visibility_lint.rs`'s two connection rules scan
//!   `crates/epigraph-db/src/repos` only, and this register's needle sees
//!   `AppState.db_pool`, not a connection parameter. Its own doc says the caller
//!   owns the stamping and that it cannot verify it, which is documentation
//!   standing in for a control — the same follow-up lint named above is what
//!   would replace it.
//! * **Sibling crates are also invisible, for the same parameter reason** —
//!   `epigraph-engine`, `epigraph-jobs` and `epigraph-ingest-executor` (12, 12
//!   and 7 viewer-less SQL functions respectively), and **`epigraph-mcp`**,
//!   which an earlier draft of this list omitted and which is the more
//!   important of the four: it is the *other* per-principal serving surface,
//!   live in production, with Viewer-taking tools, no `after_release` scrub and
//!   no `acquire_as` path at all. Measured: 534 occurrences of `pool` and 51
//!   `PgPool` mentions under `crates/epigraph-mcp/src`, keyed on
//!   `EpiGraphServer`'s own field rather than on `AppState`. It needs its own
//!   lint and its own workstream. A green run HERE means "no unexempted
//!   `epigraph-api` handler reaches the raw pool through `AppState`", not "no
//!   unscoped read exists in the workspace".
//! * `#[cfg(test)]` is **not** cut, because it does not need to be: measured on
//!   this tree, zero `.db_pool` occurrences live inside a `#[cfg(test)]` item
//!   (verified by brace-matching every such region, not by grep). On THIS tree
//!   a raw `grep -o` finds 465 and this scanner finds 461; the gap of 4 is
//!   whole-line comments alone. (An earlier draft quoted "466 vs 461", which
//!   mixed trees: 466 was the pre-pilot figure.)
//! * **The recon's headline 448 is not this scanner's 461, and neither is
//!   wrong** — they are different needles. `state.db_pool` alone measures 445
//!   here (447 before the pilot, which is the recon's ~448); adding the
//!   `self.db_pool` sites inside `state.rs` (the count [`EXEMPT`] records —
//!   quoted here as 9 when this was written, and authoritative THERE, not
//!   here) and the lines carrying more than one occurrence gives 461. This
//!   scanner's needle is the more complete one and is the right key for the
//!   question it asks.
//!
//!   **These four totals are a measurement of the tree ON THE DAY THIS LINT WAS
//!   WRITTEN and are not re-derived on every change.** Conversions have landed
//!   since; the assertions above measure the tree directly and are what a
//!   reader should trust. The prose is kept for the *relationship* between the
//!   needles, which does not go stale, not for the integers.
//! * Whole-line comments are skipped by prefix, so a `.db_pool` appended after
//!   code on the same line as a trailing comment is still counted (correctly),
//!   while a commented-out call is not.
//! * This proves a handler does not reach the raw pool. It does not prove the
//!   handler acquired the *right* viewer — that is `viewer_route_table_lint.rs`
//!   and `visibility_lint.rs`'s job.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The field access that denotes "a statement about to run on the raw,
/// untenanted application pool".
const NEEDLE: &str = ".db_pool";

const MARKER: &str = "UNSCOPED-POOL-EXEMPT:";

/// The one tree scanned. See "Known limits" for why this needle does not
/// transfer to the crates that take a `&PgPool` parameter instead.
const SCAN_ROOT: &str = "crates/epigraph-api/src";

/// Files whose every `NEEDLE` site is legitimately unscoped, with the measured
/// site count and the reason. Asserted as an exact set AND at an exact count,
/// in both directions.
///
/// # Why the count is here and not only in [`UNCONVERTED`]
///
/// Membership alone is not enough. Without the count, an exempt file could grow
/// from 13 sites to 50 with every test still green — and these are precisely
/// the surfaces where a new unscoped statement is most dangerous:
/// pre-authentication endpoints and detached tasks, where "no Viewer can exist
/// here" is a file-level argument that a newly added site would silently
/// inherit. A new site now forces its author to re-state that the reason covers
/// it.
///
/// Three classes are represented, and they are different arguments:
/// pre-authentication (no principal exists yet — establishing one is the
/// endpoint's purpose), boot/observability (no request exists), and detached
/// long-lived tasks (the request that spawned them is gone). One entry —
/// `bin/server.rs` — is deliberately a MIXED argument and says so.
const EXEMPT: &[(&str, usize, &str)] = &[
    (
        "bin/server.rs",
        3,
        "Boot and spawned long-lived tasks — in TWO different senses, and the second is a \
         STANDING exemption as of PR-24, no longer exempt-until-a-follow-up. (a) The \
         webhook-subscription load at startup and the metrics-sampler handoff: no principal \
         exists at process start or inside the sampler, so there is nothing to stamp a \
         connection from. (b) The webhook-dispatcher handoff is NOT of that kind, and an earlier \
         draft of this reason was factually wrong to say so: the dispatcher resolves a real \
         Viewer per subscription three files away (routes/webhooks.rs::agent_may_receive), so a \
         Viewer IS constructible there. The follow-up it was waiting on has LANDED — migration \
         086 repaired ClaimRepository::hidden_claim_ids by putting both arms of its set \
         difference inside a SECURITY DEFINER frame — and the exemption does not dissolve with \
         it: the pool is handed over ONCE at process start and travels as a &PgPool parameter \
         into a detached task, so the site is a process-lifetime handoff rather than a request \
         whose viewer could stamp it, and the probe it feeds is now correct on an unstamped \
         connection anyway. Converting it is a separate decision with its own evidence, not a \
         consequence of 086 — see that function's doc.",
    ),
    (
        "middleware/bearer.rs",
        1,
        "STRUCTURALLY non-exemptable, not merely unconverted. The single site is Viewer::resolve, \
         which BUILDS the viewer every scoped acquire needs; ScopedPool::acquire_as takes the very \
         Viewer this call constructs, so stamping the connection first is circular. Recorded as \
         D-PR17-live-memberships-is-parameterised-not-principal-bound. A shard that 'converts' \
         this deadlocks the bootstrap rather than fixing a leak.",
    ),
    (
        "middleware/rate_limit.rs",
        1,
        "One db_pool.clone() handed to a detached task that records security events. It runs after \
         the rate-limit decision and outside any request's viewer scope, and rate limiting \
         precedes authentication, so the request may have no principal to scope to at all.",
    ),
    (
        "oauth/authorize.rs",
        7,
        "Pre-authentication by definition. The authorize/callback/consent endpoints sit on the \
         anonymous OAuth router — the surface public_router_allowlist.rs pins — and run before any \
         principal exists. Establishing one is what they are for. REVIEWED, NOT RUBBER-STAMPED: \
         this is the one entry whose argument is contingent rather than definitional, because the \
         consent POST (AuthorizeSessionRepository::take) runs after a provider identity has been \
         resolved. It is still pre-authentication in the sense that matters here — no EpiGraph \
         principal has been minted, so there is no agent id a Viewer could resolve from — but a \
         shard should re-read this entry rather than assume it, and it is the first exemption to \
         revisit if the consent step ever mints early. \
         \
         6 -> 7: the Explorer branch's consent-page fix adds one \
         OAuthClientRepository::get_by_client_id in callback_endpoint, so the page can name the \
         REQUESTING client instead of a hard-coded product name. The file-level reason covers it \
         and was re-read rather than assumed: it is the same repo method this file already calls \
         at /oauth/authorize, on the same anonymous router, strictly BEFORE the provider exchange \
         and before any principal is provisioned. `oauth_clients` additionally carries no tenancy \
         columns at all and is in none of migration 077's protected arrays — 077 says in its own \
         comment that a policy there would make the token mint's UPDATE match zero rows — so there \
         is no predicate a Viewer could have been spent on even if one existed.",
    ),
    (
        "oauth/device.rs",
        1,
        "Pre-authentication. The device/redirect exchange endpoint runs on the anonymous OAuth \
         router, before a principal exists, and its whole job is to turn a provider assertion into \
         one.",
    ),
    (
        "oauth/providers/provision.rs",
        7,
        "Pre-authentication provisioning: synthesizes a client and issues its first tokens. It \
         runs before the identity it creates exists, so there is no Viewer it could be scoped to.",
    ),
    (
        "oauth/register.rs",
        3,
        "Pre-authentication. RFC 7591 dynamic client registration CREATES the client; no principal \
         exists until it succeeds, so there is nothing to stamp the connection from.",
    ),
    (
        "oauth/revoke.rs",
        2,
        "Pre-authentication. RFC 7009 revocation authenticates the token being revoked rather than \
         a session principal, and is reachable on the anonymous OAuth router.",
    ),
    (
        "oauth/token.rs",
        13,
        "Pre-authentication by definition, and the largest such site. Token issuance is the step \
         that MINTS the principal every later request is scoped to; a Viewer cannot precede it.",
    ),
    (
        "state.rs",
        10,
        "Boot and observability, including the session-GUC probe itself. ENUMERATED rather than \
         waved at, because this is the one file where the needle is an indirection layer: a \
         `pub async fn` on AppState that reads self.db_pool is exempt-by-file no matter who calls \
         it, and a ViewerExtractor grep cannot detect the mixed case (AppState methods take &self; \
         the Viewer lives in the calling handler). The ten sites are exactly \
         load_entity_type_cache (1), assert_tenancy_triggers_armed (3), probe_rls_posture (3), \
         rls_canary_visible (2) and warn_on_privileged_connection (1). The third site in \
         assert_tenancy_triggers_armed is migration 089's marker probe, added with \
         TENANCY_TRIGGERS_089: it reads pg_proc, which carries no tenancy columns and no rows a \
         Viewer could filter. VERIFIED BY CALL GRAPH, not \
         by grep: every caller outside state.rs is bin/server.rs at boot, tenancy_gauge.rs (itself \
         exempt), or a #[cfg(all(test, feature = \"db\"))] module in routes/admin.rs and \
         routes/edges.rs. Scoping the probe to a Viewer would make it prove a property of that \
         viewer instead of the pool. The count is pinned so a tenth site cannot inherit this \
         reason silently — see the `state.rs` note in the module's Known limits.",
    ),
    (
        "tenancy_gauge.rs",
        1,
        "Observability. It counts rows across the whole corpus to measure tenancy coverage; a \
         viewer-scoped gauge would report one tenant's coverage and label it the fleet's.",
    ),
];

/// The never-to-be-raised ceilings, so growth fails STRUCTURALLY rather than by
/// a reviewer noticing an edited literal.
///
/// [`UNCONVERTED`] is an exact-equality table, which fails identically on growth
/// and on shrink — useful friction, but nothing in it encodes monotonicity, and
/// a future author could raise a row and its total together. These two are the
/// ratchet proper: a shard lowering entries touches only its own rows and never
/// these, and any net growth fails here as well.
const HIGH_WATER: usize = 303;
/// Companion ceiling on the file count. See [`HIGH_WATER`].
///
/// Shard 4 converted 19 sites and did NOT move this: none of its three files
/// reached zero, so no key was deleted. A shard whose site count falls without
/// this moving is the ordinary case, not a sign it forgot to lower something.
///
/// Conversion shard 5 is the first to move it since PR-29: `routes/structural.rs`
/// and `routes/graph_neighborhood.rs` both reached zero and their keys were
/// DELETED, so 46 -> 44. Both integers here are what `measure()` reported on the
/// converted tree, read off `the_scanner_is_not_vacuous`'s own failure, rather
/// than 372 and 46 less the sites this shard believed it had converted.
///
/// Conversion shard 6 did NOT move it, and that is the expected outcome rather
/// than an omission: none of its six files reached zero, so no key was deleted.
/// Its 25 sites came off `HIGH_WATER` alone, 355 -> 330 — again read off
/// `the_scanner_is_not_vacuous`'s own failure on the converted tree, not derived
/// by subtracting the count the shard believed it had converted.
///
/// Conversion shard 7 did not move it either, for the same reason: its eight
/// files all retain sites, the smallest residual being `routes/challenge.rs` at
/// 2. Its 27 sites came off `HIGH_WATER` alone, 330 -> 303, and BOTH integers
/// were read off `measure()`'s own failure output with these two constants
/// temporarily set to 1 — never by subtracting the count the shard believed it
/// had converted, which is the method every shard since 5 has used and the one
/// that catches a miscount.
const HIGH_WATER_FILES: usize = 44;

/// The seeded ratchet: per-file counts of sites still reaching the raw pool.
///
/// 303 sites across 44 files as of this commit. Lower an entry when a shard
/// converts sites; delete the key when it reaches zero.
const UNCONVERTED: &[(&str, usize)] = &[
    ("routes/activities.rs", 3),
    ("routes/admin.rs", 4),
    ("routes/agent_keys.rs", 6),
    ("routes/agents.rs", 10),
    ("routes/assess.rs", 1),
    ("routes/audit.rs", 1),
    // 17 before this PR. Shard 4 converted the FOURTEEN read-only handlers onto
    // `AppState::read_as`. The row SURVIVES at 3 rather than being deleted, and
    // the remainder is a class rather than a leftover: `create_frame`,
    // `submit_evidence` and `refine_frame` each WRITE through their alias. Every
    // site in this file is one handler-level `let pool = &state.db_pool;`, so
    // those three cannot be split off the reads beside them without splitting
    // the handler, and `read_as` is documented read-only — see that file's
    // module doc for why routing a write through it compiles and then discards
    // the write. Their owner is `ScopedPool::begin_as` plus 16b's write gate.
    ("routes/belief.rs", 3),
    // 3 before conversion shard 7, which moved `list_challenges` onto
    // `AppState::read_as`. The two that remain are `submit_challenge`, which
    // WRITES and holds no `Viewer` at all; its owner is
    // `D-PR16-claim-authorship-is-not-a-credential`, an open operator decision.
    ("routes/challenge.rs", 2),
    // 25 before conversion shard 7, which moved `get_claim`, `list_claims`,
    // `list_claim_evidence` and `list_by_labels` onto
    // `AppState::read_as`. FOUR, not six: `get_claim` and `list_claims` each
    // hold a SECOND site that is declined at SITE level rather than handler
    // level — a `GroupMembershipRepository::is_member` authorization gate that
    // completes before any content read begins. The argument is written at the
    // site in that file, and it is the first decline in this series whose
    // blocker is the site and not the handler. The remaining NINETEEN sit in
    // write handlers — `create_claim` (9), `update_claim` (6), `patch_claim`
    // (2), `update_labels` (2) — which with those two gates is 21, the row
    // below. (An earlier draft of this comment said "seventeen" and did not
    // close the arithmetic against the row it annotates.)
    ("routes/claims.rs", 21),
    // `routes/claims_query.rs` was 5 and is GONE, not zeroed: PR-28, conversion
    // shard 2, moved all five onto `AppState::read_as`. Same rule as
    // `routes/lineage.rs` below — `measure()` only ever emits non-zero entries,
    // so a `0` row could never be satisfied.
    ("routes/clusters.rs", 1),
    ("routes/community.rs", 3),
    // 15 before this PR. Shard 4 converted the five sites belonging to its four
    // read-only handlers (`sheaf_consistency`, `sheaf_cohomology`,
    // `sheaf_reconcile`, `belief_at_time`). Unlike `routes/belief.rs` the sites
    // here are PER-STATEMENT, so a partially-converted handler is expressible;
    // the shard declined to produce one. Of the ten that remain, seven are
    // `propagate_beliefs`, which writes through two of them, and three are
    // `compose_subgraphs`. Both are named in that file's module doc.
    ("routes/computation.rs", 10),
    // 12 before this PR. `classify_conflict` is the pilot conversion onto
    // `AppState::read_as`; see `epigraph-api/tests/scoped_read_is_fail_closed.rs`.
    ("routes/conflicts.rs", 10),
    // 5 before conversion shard 5, which moved `list_contexts`, `get_context`,
    // `list_active_contexts` and `frame_contexts` onto `AppState::read_as`. The
    // one that remains is `create_context`, which WRITES through its alias:
    // `read_as` is documented read-only, `ScopedRead::commit` is not called by
    // `Drop`, and under `SessionGucMode::Transaction` a write routed through it
    // is rolled back while still type-checking. Its owner is
    // `ScopedPool::begin_as` plus `Viewer::splice_write`, and
    // `ContextRepository::create` takes no `Viewer` at all.
    ("routes/context.rs", 1),
    // 4 before conversion shard 7, which moved `list_skills` onto
    // `AppState::read_as` through the same `WorkflowRepository::list` widening
    // that serves `routes/workflows.rs::list_workflows` — one signature change
    // for two converted sites in two files. The three that remain
    // (`learn_convention`, `forget_convention`, `share_skill`) all WRITE.
    ("routes/conventions.rs", 3),
    // UNCHANGED at 7, and that is a measurement rather than an omission.
    // Conversion shard 5 was sized to include this file (4 of its 7 sites were
    // classified as convertible reads) and then measured it site by site. Three
    // of the seven construct `MatchCandidateRepo::new(state.db_pool.clone())`,
    // which takes an OWNED `PgPool` and stores it; `read_as` yields a borrowed
    // `ScopedRead<'_>` that cannot be cloned into one, and giving that repo a
    // connection-taking form is a cross-crate signature change reaching
    // `epigraph-mcp`, `epigraph-engine`'s matching pipeline and an
    // `epigraph-cli` binary -- not an executor swap. One of those three is also
    // WRITE-BEARING (`set_status`, and a `retire` that opens its own
    // transaction). The remaining four sites are individually swappable, but
    // each shares a handler with one that is not, so converting them would
    // produce a handler whose statements run on two different connections: the
    // `read_as` doc's own stated hazard, and the disposition shard 4 already
    // took when `routes/computation.rs` offered the same choice. Whole handlers
    // or nothing.
    ("routes/cross_source.rs", 7),
    // 40 before conversion shard 7, which moved the four read-only
    // `ClaimThemeRepository` handlers (`get_boundary_claims`,
    // `get_split_candidates`, `get_distant_claims`, `get_theme_embeddings`) onto
    // `AppState::read_as`. Every one of the thirty-six that remain sits in a
    // WRITE handler; this is the densest write-blocked file in the series.
    ("routes/crud.rs", 36),
    ("routes/edges.rs", 10),
    ("routes/embeddings.rs", 2),
    // 8 before conversion shard 7, and the largest single-file drop in that
    // shard. `entity_neighborhood` (2 sites) is category A. `query_triples`
    // (3 sites) is NOT: PR #460 filed it C because its classification computes
    // `write verb OR no Viewer OR unrouted` from the HANDLER, and the verb is a
    // property of the route table rather than of the statement. Measured here:
    // it is a POST that holds a `ViewerExtractor`, runs three SELECTs, opens no
    // transaction and writes nothing — the same "true of the rule, false of the
    // reachability" shape shard 6 found in `edges.rs::evidence_by_relationship`.
    // The three that remain are `create_entity`, `batch_create_mentions` and
    // `batch_create_triples`, all writes.
    ("routes/entities.rs", 3),
    ("routes/events.rs", 6),
    ("routes/experiment_loop.rs", 20),
    ("routes/experiments.rs", 8),
    ("routes/gaps.rs", 5),
    // 4 before conversion shard 7, which moved `expand` onto
    // `AppState::read_as`. ONE register site spending its alias on FOUR
    // statements: two inline run/cluster-metadata probes, the viewer-spliced
    // `GraphViewRepository::expand_cluster_nodes`, and the private helper
    // `fetch_subgraph_edges`, whose signature changed to `&mut PgConnection` in
    // place — it has exactly one caller workspace-wide, so no pool-shaped
    // wrapper was created and this file leaves the `&PgPool`-PARAMETER blind
    // spot enumerated in the Known limits above. The three that remain
    // (`overview`, `themes_overview`, `themes_expand`) are routed GETs that hold
    // NO `Viewer`; their owner is `D-PR16-theme-cluster-viewer-scope`.
    ("routes/graph.rs", 3),
    // `routes/graph_neighborhood.rs` was 2 and is GONE, not zeroed: conversion
    // shard 5 moved `expand` and `claim_compound_neighborhood` onto
    // `AppState::read_as`. It is one of TWO rows that shard deleted; see
    // `routes/structural.rs` below.
    //
    // Two things this deletion does NOT mean, stated so the row's absence is
    // not over-read. (1) `expand`'s first statement probes
    // `graph_neighborhoods` / `graph_cluster_runs`; measured at migration head
    // 92, row-level security is OFF on both and neither carries a policy, so
    // stamping that connection narrows nothing. The stamp is for the `claims` /
    // `edges` / `claim_neighborhood_membership` reads that follow. (2) The seven
    // inline edge/membership aggregates in this file remain viewer-less in the
    // statement; `F-edges-unfiltered` owns that and conversion neither closes
    // nor worsens it. What DID change beyond the counter is that
    // `compound_response` and `atomic_response` moved from `pool: &PgPool` to
    // `&mut PgConnection`, so they also leave the `&PgPool`-parameter blind-spot
    // enumeration in this file's module doc.
    ("routes/graph_query.rs", 1),
    ("routes/groups.rs", 12),
    ("routes/hypothesis.rs", 11),
    ("routes/isomorphism.rs", 3),
    // `routes/lineage.rs` was 7 and is GONE, not zeroed: PR-26, the first
    // conversion shard, moved all seven onto `AppState::read_as`. `measure()`
    // only ever emits non-zero entries, so a `0` row could never be satisfied.
    //
    // `routes/methods.rs` was 2 and is GONE, not zeroed: PR-29, conversion shard
    // 3, moved both onto `AppState::read_as`. It is one of THREE rows that shard
    // deleted — see `routes/search.rs` and `routes/voids.rs` below — which is
    // what makes it the first multi-file shard in the series.
    //
    // `routes/papers.rs` is UNCHANGED at 8, deliberately. Shard 4 was sized to
    // include this file and then measured it: two of the eight sites write,
    // neither handler holds a `Viewer`, and adding one to both `#[cfg]` arms is
    // a callable behaviour change. A schema measurement taken in the same pass
    // is registered as `F-SHARD4-A3` and is not restated here; its operational
    // conclusion is that converting the remaining six would move this counter
    // and change no row the endpoint returns. That file's module doc carries
    // the reasoning. This row is the series' example of a file that is COUNTED
    // and not convertible.
    ("routes/papers.rs", 8),
    // 5 before conversion shard 5, which moved `list_perspectives`,
    // `get_perspective` and `agent_perspectives` onto `AppState::read_as`. The
    // two that remain both WRITE -- `create_perspective` (which also creates a
    // PERSPECTIVE_OF edge) and `set_source_reliability` (an `UPDATE`) -- and
    // neither `PerspectiveRepository::create` nor `::set_source_reliability`
    // takes a `Viewer`. Same owner as `context.rs`'s residue.
    ("routes/perspective.rs", 2),
    ("routes/policies.rs", 9),
    // 12 before conversion shard 5, which moved all seven read-only
    // viewer-holding handlers onto `AppState::read_as`: `epistemic_profile`,
    // `compare_agents`, `position_timeline`, `claim_genealogy`,
    // `originated_claims`, `inflation_index` and `claim_techniques`. The five
    // that remain hold NO `Viewer` at all -- `inflation_leaderboard`
    // (which is also the site
    // `viewer_route_table_lint.rs::UNCOMPENSATED_INLINE_READS` records as
    // `("political.rs", 1)`, so it must not be relocated to lower that
    // register), `list_techniques`, `list_coalitions`, and the two `create_*`
    // handlers, which write. This file's module doc carries the reasoning.
    ("routes/political.rs", 5),
    ("routes/provenance.rs", 1),
    ("routes/rag.rs", 2),
    ("routes/reasoning.rs", 1),
    ("routes/revoke_signature.rs", 1),
    // `routes/search.rs` was 6 and is GONE, not zeroed: PR-29, conversion shard
    // 3. Two of the six were inline `sqlx::query*` statements in the handler
    // rather than repo calls; both kept their SQL where it was and changed only
    // the executor, so `viewer_route_table_lint.rs::UNCOMPENSATED_INLINE_READS`
    // still records `("search.rs", 1)` and must not be lowered.
    ("routes/spans.rs", 6),
    // `routes/structural.rs` was 1 and is GONE, not zeroed: conversion shard 5
    // moved `get_structural_features`'s single alias -- which fanned into NINE
    // sequential `StructuralRepository` round-trips -- onto `AppState::read_as`.
    // It is one of TWO rows that shard deleted; see `routes/graph_neighborhood.rs`
    // above, whose two sites also reached zero, and which additionally left the
    // `&PgPool`-parameter blind-spot list in this file's module doc.
    ("routes/submit.rs", 4),
    ("routes/tasks.rs", 15),
    ("routes/timeline.rs", 2),
    // 9 before conversion shard 7, which moved `claim_history` onto
    // `AppState::read_as`. Of the eight that remain, six are `supersede_claim`
    // and two `mark_duplicate` — both write. One of the six is additionally
    // blocked at SITE level: `let pool = state.db_pool.clone()` is moved into a
    // detached `tokio::spawn`, which a `ScopedRead<'_>` borrowed from
    // `AppState` cannot outlive.
    ("routes/versioning.rs", 8),
    // `routes/voids.rs` was 3 and is GONE, not zeroed: PR-29, conversion shard 3,
    // moved all three onto `AppState::read_as` across its two handlers.
    // NOT exempt, and the decision is deliberate: a webhook subscription is
    // owned by the principal that registered it, so these three are ordinary
    // authenticated CRUD, not a pre-auth receiver.
    ("routes/webhooks.rs", 3),
    // 40 before conversion shard 7, which moved `search_workflows` (6 sites),
    // `find_workflow_hierarchical` (3) and `list_workflows` (1) onto
    // `AppState::read_as` — the densest conversion in that shard. Of the thirty
    // that remain, twenty-eight sit in WRITE handlers (`store_workflow`,
    // `report_outcome`, `deprecate_workflow`, `report_hierarchical_outcome`,
    // `ingest_workflow`, `record_behavioral_execution`, `evolve_step`,
    // `add_step`, `delete_step`) and two in `get_workflow`, a routed GET that
    // holds no `Viewer` at all — the same no-Viewer class shard 6 declined in
    // `routes/agents.rs`.
    ("routes/workflows.rs", 30),
];

/// Repo root. `CARGO_MANIFEST_DIR` is `crates/epigraph-db`; two parents up is
/// the workspace root. Same derivation as `no_unmaintained_dsn.rs`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/epigraph-db has two ancestors")
        .to_path_buf()
}

fn collect(root: &Path, out: &mut Vec<PathBuf>) {
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Lines that are not whole-line comments.
fn code_lines(src: &str) -> impl Iterator<Item = (usize, &str)> {
    src.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
}

/// Sites in `src` that reach the raw pool, ignoring commented-out ones.
fn count_sites(src: &str) -> usize {
    code_lines(src)
        .map(|(_, l)| l.matches(NEEDLE).count())
        .sum()
}

/// Every scanned file, keyed repo-relative to [`SCAN_ROOT`], with its site
/// count. Only non-zero entries, which is why a `0` in [`UNCONVERTED`] can
/// never be satisfied.
fn measure() -> BTreeMap<String, usize> {
    let root = repo_root().join(SCAN_ROOT);
    let mut files = Vec::new();
    collect(&root, &mut files);
    files.sort();

    let mut out = BTreeMap::new();
    for path in &files {
        let src = std::fs::read_to_string(path).expect("read source");
        let n = count_sites(&src);
        if n > 0 {
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, n);
        }
    }
    out
}

fn exempt_names() -> BTreeSet<&'static str> {
    EXEMPT.iter().map(|(f, _, _)| *f).collect()
}

/// The scan must actually read the tree it claims to. A silently-empty scan is
/// how a ratchet certifies a codebase it never opened.
#[test]
fn the_scan_root_resolves_and_is_not_empty() {
    let root = repo_root().join(SCAN_ROOT);
    assert!(
        root.is_dir(),
        "scan root {SCAN_ROOT} does not exist at {}",
        root.display()
    );
    let mut files = Vec::new();
    collect(&root, &mut files);
    assert!(
        files.len() > 80,
        "expected >80 .rs files under {SCAN_ROOT}; found {}",
        files.len()
    );
    let measured = measure();
    assert!(
        measured.len() > 40,
        "expected >40 files to carry at least one {NEEDLE} site; found {}. \
         A scanner that suddenly finds almost nothing has broken, not been fixed.",
        measured.len()
    );
}

/// The ratchet proper: every file's remaining site count is exactly what was
/// recorded, and no unexempted file has appeared.
#[test]
fn the_unconverted_register_is_exactly_what_was_measured() {
    let measured = measure();
    let exempt = exempt_names();
    let expected: BTreeMap<&str, usize> = UNCONVERTED.iter().copied().collect();

    let actual: BTreeMap<&str, usize> = measured
        .iter()
        .filter(|(f, _)| !exempt.contains(f.as_str()))
        .map(|(f, n)| (f.as_str(), *n))
        .collect();

    let mut findings = Vec::new();

    for (file, n) in &actual {
        match expected.get(file) {
            None => findings.push(format!(
                "  {file}: {n} site(s) reaching the raw pool, and the file is in NEITHER register.\n    \
                 Convert them onto `AppState::read_as`, or — if the file is genuinely \
                 pre-authentication, boot/observability, or a detached task — add an \
                 `{MARKER} <reason>` comment at the top of the file AND an entry with the same \
                 reason in EXEMPT."
            )),
            Some(e) if e != n => findings.push(format!(
                "  {file}: recorded {e}, measured {n}.\n    {}",
                if n < e {
                    "FEWER than recorded — a conversion landed without lowering this table. \
                     Lower it in the same commit (and REMOVE the key if it reached zero); the \
                     table is how a reviewer sees what the shard actually converted."
                } else {
                    "MORE than recorded — a new unscoped read was added to a file that was \
                     already being converted. That is the regression this ratchet exists to stop."
                }
            )),
            Some(_) => {}
        }
    }

    for (file, e) in &expected {
        if !actual.contains_key(file) {
            findings.push(format!(
                "  {file}: recorded {e} site(s), measured NONE.\n    \
                 The file is fully converted — DELETE the key rather than setting it to 0. \
                 `measure()` only ever emits non-zero entries, so a 0 row can never be satisfied."
            ));
        }
    }

    assert!(
        findings.is_empty(),
        "the unscoped-pool register is out of date. {} finding(s):\n{}",
        findings.len(),
        findings.join("\n")
    );
}

/// The exemption set is exactly what was reviewed — in both directions.
#[test]
fn the_exemption_set_is_exactly_what_was_reviewed() {
    let root = repo_root().join(SCAN_ROOT);
    let measured = measure();

    for (name, recorded, reason) in EXEMPT {
        let path = root.join(name);
        assert!(
            path.exists(),
            "EXEMPT names {name}, which does not exist under {SCAN_ROOT}"
        );
        assert!(
            reason.len() > 80,
            "the exemption for {name} is {} chars. A REASON is required, not a label: state what \
             the sites do and why no Viewer can exist there.",
            reason.len()
        );
        let src = std::fs::read_to_string(&path).expect("read exempt file");
        assert!(
            src.contains(MARKER),
            "{name} is in EXEMPT but carries no `{MARKER}` comment. The table records the \
             decision; the marker is what a reader of the code finds. Both are required. (The \
             table is authoritative for the WORDING; the marker is a pointer to it.)"
        );

        // And it must still NEED the exemption.
        let measured_here = measured.get(*name).copied().unwrap_or(0);
        assert!(
            measured_here > 0,
            "{name} is listed in EXEMPT but no longer reaches the raw pool. Delete the entry and \
             the `{MARKER}` comment: an exemption list that outlives its subjects stops being a \
             list of decisions and becomes a list of nobody-checked."
        );

        // ...at exactly the reviewed size. Membership alone would let an exempt
        // file grow without limit, and these are the surfaces where a new
        // unscoped statement is most dangerous.
        assert_eq!(
            measured_here,
            *recorded,
            "{name} is exempt at {recorded} site(s) but measures {measured_here}. {}",
            if measured_here > *recorded {
                "A NEW unscoped site was added to an exempt file. The file-level reason does not \
                 automatically cover it: re-read the reason, confirm it still holds for the new \
                 site, and raise the count in the same commit."
            } else {
                "Sites were REMOVED from an exempt file. Lower the count here in the same commit — \
                 and if it reached zero, delete the entry and the marker."
            }
        );
    }

    // The reverse direction: a file carrying the marker must be in the table,
    // or the marker becomes a comment anyone can type to silence the lint.
    let mut files = Vec::new();
    collect(&root, &mut files);
    let exempt = exempt_names();
    for path in &files {
        let src = std::fs::read_to_string(path).expect("read source");
        if !src.contains(MARKER) {
            continue;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        assert!(
            exempt.contains(rel.as_str()),
            "{rel} carries an `{MARKER}` comment but has no entry in EXEMPT. An in-file marker \
             alone must not exempt anything, or the lint is self-service."
        );
    }
}

/// Calibration. A green run must mean "there is nothing", not "the scanner
/// found nothing".
#[test]
fn the_scanner_is_not_vacuous() {
    // It fires on the real spellings.
    for sample in [
        "    let c = Repo::get(&state.db_pool, id).await?;",
        "        .fetch_one(&state.db_pool)",
        "    let pool = state.db_pool.clone();",
        "        Repo::list(&self.db_pool).await",
    ] {
        assert_eq!(count_sites(sample), 1, "the scanner must detect: {sample}");
    }

    // Two on one line are two sites, or a compound expression would under-count.
    assert_eq!(
        count_sites("    f(&state.db_pool, &state.db_pool);"),
        2,
        "each occurrence on a line is its own site"
    );

    // It ignores whole-line comments, or every doc reference would be a finding.
    for commented in [
        "    // let c = Repo::get(&state.db_pool, id).await?;",
        "//! reads `state.db_pool` directly",
    ] {
        assert_eq!(
            count_sites(commented),
            0,
            "a whole-line comment must not be scanned: {commented}"
        );
    }

    // The exemption marker is not itself a site, and does not suppress one on
    // another line — file-level exemption is what suppresses (see module doc).
    assert_eq!(
        count_sites(&format!("// {MARKER} pre-auth by definition")),
        0
    );

    // And the totals are the ones the module doc quotes, so the prose cannot
    // drift from the tables.
    let recorded: usize = UNCONVERTED.iter().map(|(_, n)| n).sum();
    assert_eq!(
        recorded, HIGH_WATER,
        "the seeded total changed; update the module documentation too"
    );
    assert_eq!(
        UNCONVERTED.len(),
        HIGH_WATER_FILES,
        "the seeded file count changed; update the module documentation too"
    );
}

/// The ratchet may only turn one way.
///
/// [`the_unconverted_register_is_exactly_what_was_measured`] asserts exact
/// equality, which fails identically on growth and on shrink and is therefore
/// accuracy rather than monotonicity: a future author could raise a row and its
/// total together and stay green. This test measures the tree directly and
/// refuses any total above the ceiling, so growth cannot be absorbed by editing
/// the table.
#[test]
fn the_register_can_only_shrink() {
    let exempt = exempt_names();
    let measured = measure();
    let total: usize = measured
        .iter()
        .filter(|(f, _)| !exempt.contains(f.as_str()))
        .map(|(_, n)| *n)
        .sum();
    let files = measured
        .keys()
        .filter(|f| !exempt.contains(f.as_str()))
        .count();

    assert!(
        total <= HIGH_WATER,
        "{total} unexempted sites reach the raw pool, above the high-water mark of {HIGH_WATER}. \
         This constant is never to be raised: the conversion is meant to shrink this number, and \
         a shard that needs a new unscoped read needs an exemption with a reason, not a bigger \
         ceiling."
    );
    assert!(
        files <= HIGH_WATER_FILES,
        "{files} unexempted files reach the raw pool, above the high-water mark of \
         {HIGH_WATER_FILES}. A NEW file reaching the raw pool is a new surface, not a bigger \
         number — convert it or exempt it with a reason."
    );
}
