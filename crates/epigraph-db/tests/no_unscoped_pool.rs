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
//! lint would fail on day one"*. It would — there are 391 unconverted sites as
//! of this commit, and a lint that fails on day one is a lint someone deletes
//! in week two.
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
//!   391 sites below are visibly write-shaped, led by
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
//!      §9.2 step 11d with 391 unconverted sites. **This alone is sufficient for
//!      the prohibition above.** PR-24 discharged one precondition and PR-25 a
//!      second; PR-26 converted the first shard's seven sites, PR-28 the
//!      second shard's five, and PR-29 — the first MULTI-FILE shard — the third
//!      shard's eleven, across `routes/search.rs`, `routes/voids.rs` and
//!      `routes/methods.rs`. None discharged the gate — 391 is not 0 — and
//!      neither PR-25 nor PR-26 nor PR-28 nor PR-29 may be read as unblocking
//!      step 11d. A SMALLER number is not a discharged decision: 25 of the 416
//!      sites the series began with are converted, and 391 are not.
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
//!   `#[cfg(test)]` helpers: **22 production functions across 14 files** take a
//!   `&PgPool` parameter, and the register above sees none of them.
//!   Enumerated so no shard author mistakes this table for complete —
//!   `middleware/group_authz.rs::require_group_admin`,
//!   `middleware/provenance.rs::record_provenance`,
//!   `oauth/providers/provision.rs::emit_oauth_audit`,
//!   `routes/clusters.rs::{persist_bridge_run, gc_bridge_runs}`,
//!   `routes/computation.rs::extract_neighborhood`,
//!   `routes/edges.rs::{trigger_edge_ds_recomputation, propagate_to_dependents,
//!   recompute_claim_belief}`, `routes/events.rs::retain_visible_events`,
//!   `routes/graph.rs::fetch_subgraph_edges`,
//!   `routes/graph_neighborhood.rs::{compound_response, atomic_response}`,
//!   `routes/independence.rs::analyze_independence`,
//!   `routes/provenance.rs::{find_or_create_author_agent, find_or_create_org_agent}`,
//!   `routes/webhooks.rs::{retain_visible_subscriptions, agent_may_receive,
//!   deliver_event}`, `routes/workflows.rs::{get_or_create_system_agent,
//!   auto_wire_inserted_edges}`, `tenancy_gauge.rs::sample`. The webhook
//!   fan-out is the one that matters most and the one this register cannot
//!   see at all: its pool is handed over once in the EXEMPT `bin/server.rs` and
//!   then travels as a parameter, and `agent_may_receive` resolves a real
//!   `Viewer` on it. A second lint keyed on the parameter is a follow-up, not
//!   part of this PR.
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
//!   here (447 before the pilot, which is the recon's ~448); adding the 9
//!   `self.db_pool` sites inside `state.rs` and the lines carrying more than
//!   one occurrence gives 461. This scanner's needle is the more complete one
//!   and is the right key for the question it asks.
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
        6,
        "Pre-authentication by definition. The authorize/callback/consent endpoints sit on the \
         anonymous OAuth router — the surface public_router_allowlist.rs pins — and run before any \
         principal exists. Establishing one is what they are for. REVIEWED, NOT RUBBER-STAMPED: \
         this is the one entry whose argument is contingent rather than definitional, because the \
         consent POST (AuthorizeSessionRepository::take) runs after a provider identity has been \
         resolved. It is still pre-authentication in the sense that matters here — no EpiGraph \
         principal has been minted, so there is no agent id a Viewer could resolve from — but a \
         shard should re-read this entry rather than assume it, and it is the first exemption to \
         revisit if the consent step ever mints early.",
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
        9,
        "Boot and observability, including the session-GUC probe itself. ENUMERATED rather than \
         waved at, because this is the one file where the needle is an indirection layer: a \
         `pub async fn` on AppState that reads self.db_pool is exempt-by-file no matter who calls \
         it, and a ViewerExtractor grep cannot detect the mixed case (AppState methods take &self; \
         the Viewer lives in the calling handler). The nine sites are exactly \
         load_entity_type_cache (1), assert_tenancy_triggers_armed (2), probe_rls_posture (3), \
         rls_canary_visible (2) and warn_on_privileged_connection (1). VERIFIED BY CALL GRAPH, not \
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
const HIGH_WATER: usize = 391;
/// Companion ceiling on the file count. See [`HIGH_WATER`].
const HIGH_WATER_FILES: usize = 46;

/// The seeded ratchet: per-file counts of sites still reaching the raw pool.
///
/// 391 sites across 46 files as of this commit. Lower an entry when a shard
/// converts sites; delete the key when it reaches zero.
const UNCONVERTED: &[(&str, usize)] = &[
    ("routes/activities.rs", 3),
    ("routes/admin.rs", 4),
    ("routes/agent_keys.rs", 6),
    ("routes/agents.rs", 15),
    ("routes/assess.rs", 1),
    ("routes/audit.rs", 1),
    ("routes/belief.rs", 17),
    ("routes/challenge.rs", 3),
    ("routes/claims.rs", 25),
    // `routes/claims_query.rs` was 5 and is GONE, not zeroed: PR-28, conversion
    // shard 2, moved all five onto `AppState::read_as`. Same rule as
    // `routes/lineage.rs` below — `measure()` only ever emits non-zero entries,
    // so a `0` row could never be satisfied.
    ("routes/clusters.rs", 1),
    ("routes/community.rs", 5),
    ("routes/computation.rs", 15),
    // 12 before this PR. `classify_conflict` is the pilot conversion onto
    // `AppState::read_as`; see `epigraph-api/tests/scoped_read_is_fail_closed.rs`.
    ("routes/conflicts.rs", 10),
    ("routes/context.rs", 5),
    ("routes/conventions.rs", 4),
    ("routes/cross_source.rs", 7),
    ("routes/crud.rs", 40),
    ("routes/edges.rs", 17),
    ("routes/embeddings.rs", 2),
    ("routes/entities.rs", 8),
    ("routes/events.rs", 6),
    ("routes/experiment_loop.rs", 20),
    ("routes/experiments.rs", 11),
    ("routes/gaps.rs", 5),
    ("routes/graph.rs", 4),
    ("routes/graph_neighborhood.rs", 2),
    ("routes/graph_query.rs", 1),
    ("routes/groups.rs", 12),
    ("routes/hypothesis.rs", 17),
    ("routes/isomorphism.rs", 3),
    // `routes/lineage.rs` was 7 and is GONE, not zeroed: PR-26, the first
    // conversion shard, moved all seven onto `AppState::read_as`. `measure()`
    // only ever emits non-zero entries, so a `0` row could never be satisfied.
    //
    // `routes/methods.rs` was 2 and is GONE, not zeroed: PR-29, conversion shard
    // 3, moved both onto `AppState::read_as`. It is one of THREE rows that shard
    // deleted — see `routes/search.rs` and `routes/voids.rs` below — which is
    // what makes it the first multi-file shard in the series.
    ("routes/papers.rs", 8),
    ("routes/perspective.rs", 5),
    ("routes/policies.rs", 9),
    ("routes/political.rs", 12),
    ("routes/provenance.rs", 1),
    ("routes/rag.rs", 4),
    ("routes/reasoning.rs", 1),
    ("routes/revoke_signature.rs", 1),
    // `routes/search.rs` was 6 and is GONE, not zeroed: PR-29, conversion shard
    // 3. Two of the six were inline `sqlx::query*` statements in the handler
    // rather than repo calls; both kept their SQL where it was and changed only
    // the executor, so `viewer_route_table_lint.rs::UNCOMPENSATED_INLINE_READS`
    // still records `("search.rs", 1)` and must not be lowered.
    ("routes/spans.rs", 6),
    ("routes/structural.rs", 1),
    ("routes/submit.rs", 4),
    ("routes/tasks.rs", 15),
    ("routes/timeline.rs", 2),
    ("routes/versioning.rs", 9),
    // `routes/voids.rs` was 3 and is GONE, not zeroed: PR-29, conversion shard 3,
    // moved all three onto `AppState::read_as` across its two handlers.
    // NOT exempt, and the decision is deliberate: a webhook subscription is
    // owned by the principal that registered it, so these three are ordinary
    // authenticated CRUD, not a pre-auth receiver.
    ("routes/webhooks.rs", 3),
    ("routes/workflows.rs", 40),
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
