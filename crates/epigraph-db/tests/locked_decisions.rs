//! The locked decisions, checkable from one file (plan §0.2).
//!
//! # THIS FILE GROWS EACH PR
//!
//! Plan §0.2 fixes four decisions that the rest of the design rests on. They are
//! *locked*: a later PR does not get to relitigate one by quietly editing the
//! code it constrains. This file is where each becomes a machine-checked
//! predicate, and it is deliberately one file rather than four, so a reviewer can
//! read the whole contract in one screen.
//!
//! **A PR that changes an RLS policy, a route split, or a tenancy column and does
//! not touch this file is rejected in review.** If a change is genuinely outside
//! the four decisions, say so in the commit body; do not leave the reviewer to
//! infer it from an untouched test file.
//!
//! ## Status at PR-14
//!
//! **PR-14 DOES change a route split, so this file is touched deliberately
//! rather than left to be read as an oversight.** Plan §0.2's rejection trigger
//! is "a PR that changes a policy, a route split, or a tenancy column and does
//! not touch `locked_decisions.rs`", and PR-14 removes four registrations from
//! **both** `create_router` variants: `POST /api/v1/ownership`,
//! `PUT /api/v1/ownership/:node_id`, `GET /api/v1/ownership/:node_id` and
//! `GET /api/v1/agents/:id/owned-nodes`.
//!
//! **Every assertion below is unchanged, and that is the correct outcome.**
//! The split D3 constrains is `public` vs `protected`, and
//! [`d3_anonymous_route_surface_is_the_allowlist`] reads `routes/mod.rs` to
//! check that the anonymous surface is exactly `/health` +
//! `/api/v1/openapi.json`. All four deleted routes were on `protected` (PR-03
//! moved `/api/v1/ownership/:node_id` there; the inversion comment in
//! `routes/mod.rs` still names it as one of the routes that motivated the
//! inversion). Deleting a `protected` route shrinks the authenticated surface
//! and cannot grow the anonymous one, so the allowlist is untouched in both
//! variants. Callers of those paths now get 404, not 401 — they stopped
//! existing, they did not stop requiring a credential.
//!
//! PR-14 is otherwise a read-path deletion: it removes the post-fetch redaction
//! pass (`check_content_access` / `redact_claim_content` / the MCP
//! `redact_content`), moves four `epigraph-api/src/routes/edges.rs` statements
//! into `crates/epigraph-db/src/repos/` behind `Viewer` predicates, and deletes
//! the legacy `ownership` read/declassify surface. **No migration** —
//! `migrations/README.md` reserves PR-14 no number. **No RLS policy.** **No
//! tenancy column.** **No write-side predicate.** (PR-16 correction to this
//! sentence, which used to read "`viewer.writable_bind()` remains PR-16's
//! mechanism": `Viewer::writable_bind` has been public since PR-04 and is
//! already consumed by `pool.rs::apply_session_gucs`. What is missing is the
//! SQL half — the write-side predicate and `WITH CHECK` — and PR-16a does not
//! add it either.)
//!
//! One D1-adjacent consequence is worth recording where a future reader will
//! find it. `access_control.rs`'s `None => ContentAccess::Full` was cited in
//! this file and in `epigraph-interfaces/src/policy.rs` as the canonical D1
//! defect — "public by absence". PR-12 made it unreachable; PR-14 deletes it.
//! Those citations are kept in the past tense on purpose: the archetype is why
//! D1 is worded as it is, and losing the example would leave the rule without
//! its evidence.
//!
//! **What PR-14 leaves dormant, stated because a passing test can be read as
//! coverage when it is not.** PR-11's four `PolicyGate::authorize` call sites
//! were the two HTTP ownership handlers and the two MCP ownership tools. All
//! four are deleted here, along with both `require_declassify_authority`
//! helpers, so `authorize` has **zero production callers** until PR-16 wires the
//! write-side predicate. `GroupPolicyGate` is still constructed at all six
//! `AppState` and both `EpiGraphMcpFull` sites, and D1's floor is still real —
//! but the assertions that survive are constructor- and type-level, and none of
//! them exercises a live decision. The three call-site lints that would have
//! noticed the gate never coming back
//! (`write_gate_call_sites.rs`, `write_gate_denies_at_the_route.rs`,
//! `write_gate_denies_at_the_tool.rs`) were deleted rather than emptied: the
//! first hard-asserts a symbol with no definitions left in the tree. The
//! obligation to restore them is
//! `D-PR16-reestablish-the-write-gate-call-site-lint` in
//! `docs/tenancy/progress.json`. PR-14 adds one residual in exchange:
//! `epigraph-mcp/src/server.rs::the_default_gate_is_installed_at_both_mcp_constructors`,
//! which is the MCP half of the constructor count that `state.rs` only ever
//! pinned for the six API sites — see the D1 bullet below, which asserted those
//! two in prose alone.
//!
//! ## Status at PR-13
//!
//! **PR-13 DOES touch a locked decision.** It adds a tenancy column —
//! `edges.co_owner_group_id` (migration 072). "A tenancy column" is one of the
//! three things named above that make extending this file mandatory, so this
//! section is not optional.
//!
//! * **D1 (nothing is public by absence, omission, or default-on-error)** —
//!   preserved, and the *shape* of the new column is where it bites.
//!   `co_owner_group_id` is nullable **with no `DEFAULT`**, and NULL means
//!   "single owner", not "unknown". That reads like the implicit-public D1
//!   forbids, and it is not: the column is never the sole carrier of an
//!   authorization decision. `owner_group_id` (NOT NULL, CHECKed, stamped by a
//!   trigger) decides visibility; `co_owner_group_id` can only NARROW it.
//!   A NULL therefore fails toward the pre-072 behaviour, which is the
//!   single-owner predicate — never toward public. Pinned by
//!   [`d1_the_co_owner_column_has_no_default_and_cannot_widen`].
//! * **D3 (`public` = any authenticated agent; no anonymous shape)** —
//!   unchanged. PR-13 adds `Viewer::edge_predicate_fragment`, a second *method*
//!   on the existing type; it adds no shape, no constructor, no `SystemReason`,
//!   and `no_anonymous_viewer.rs`'s source lint over `visibility.rs` is
//!   unchanged and still passes.
//! * **No route moved**, and `public_router_allowlist.rs` is untouched.
//! * **No RLS policy, no `WITH CHECK`, no write-side SQL predicate.** Migration
//!   072 `CREATE OR REPLACE`s two *stamping* trigger arms and creates no policy.
//!   It also REMOVES a write-side membership test — arm (b)'s
//!   `sg = ANY(epigraph_session_groups()) AND tg = ANY(...)` hatch — and that
//!   direction is the one this bullet permits: it moves write authorization
//!   OUT of a stamping trigger and leaves it to PR-16, rather than pre-empting
//!   PR-16 by adding some. The hatch was unsatisfiable in production anyway
//!   (personal groups admit no principal in two of them, and every edge writer
//!   reaches the trigger on a bare `&PgPool` with no session GUCs), so nothing
//!   that ever fired was removed. Pinned by
//!   `tenancy_triggers.rs::arm_b_no_longer_raises_on_a_cross_group_edge`.
//! * **No `VALIDATE CONSTRAINT`, no `DROP DEFAULT`.** Both 072 constraints ship
//!   `NOT VALID`; validation is PR-16's 075/076.
//!   [`d1_the_stamping_trigger_is_still_the_transition_form`] still passes,
//!   i.e. `claims.owner_group_id` keeps its `column_default`.
//! * **No `FAIL_OPEN_SCOPE_SITES` row moved.**
//! * **The trigger inventory count is unchanged at 21.** 072 replaces two
//!   function BODIES with `CREATE OR REPLACE`, which does not re-create a
//!   trigger — [`d1_tenancy_stamping_triggers_are_armed`] would catch a
//!   replacement that silently dropped one.
//!
//! ## Status at PR-11
//!
//! **PR-11 DOES touch a locked decision.** It changes the kernel's *write*
//! authorization posture from allow-all to deny-by-default, which is D1 — not a
//! route split, not a tenancy column, not a migration (PR-11 adds none;
//! `migrations/README.md` reserves it no number), but the first of the four,
//! read on the write side.
//!
//! * **D1 (nothing is public by absence, omission, or default-on-error)** —
//!   extended from reads to writes. Three mechanisms, all in
//!   `crates/epigraph-interfaces/src/policy.rs` and
//!   `crates/epigraph-authz/src/lib.rs`:
//!   - The kernel's type-level floor is `DenyAllPolicyGate`. It replaces
//!     `NoOpPolicyGate`, whose `check()` returned `Ok(true)` unconditionally —
//!     *public by default*, one layer up from `access_control.rs:68`.
//!     **Say "floor", not "the default a deployment gets":**
//!     `DenyAllPolicyGate` has zero production install sites. All six
//!     `AppState` constructors and both `EpiGraphMcpFull` constructors install
//!     `epigraph_authz::GroupPolicyGate`, and the tests that pin *that* are
//!     `epigraph-api/src/state.rs::the_default_gate_is_installed_at_every_constructor`
//!     (the six) and, since PR-14,
//!     `epigraph-mcp/src/server.rs::the_default_gate_is_installed_at_both_mcp_constructors`
//!     (the two — asserted in this comment alone until then).
//!     [`d1_the_kernel_write_gate_is_not_an_allow_all`] below is a source scan
//!     over `policy.rs`; it proves no allow-all is reachable in a production
//!     build, which is a weaker and different claim than "a running process
//!     denies by default". Both are needed; neither substitutes for the other.
//!   - `PolicyGate::authorize` maps `Err(_)` to `Decision::Deny` inside the
//!     trait, so no call site can spell *default-on-error*. This is the direct
//!     analogue of PR-10's three-branch `retain_visible_subscriptions`.
//!   - `GroupPolicyGate` denies a `ResourceRef` that names neither an owning
//!     group nor an owning agent — *absence* is a denial, not a pass.
//!
//!   Asserted by [`d1_the_kernel_write_gate_is_not_an_allow_all`].
//! * **D3 (`public` means any authenticated agent; no anonymous shape)** —
//!   unchanged. PR-11 adds no `Viewer` constructor and no `SystemReason`. Its
//!   two HTTP call sites take `middleware::bearer::ViewerExtractor`, which is
//!   the one production path, and its two MCP call sites take
//!   `tools::viewer::request_viewer`, which is the other. Neither invents a
//!   principal: a viewer with no principal is refused, not defaulted.
//! * **No route moved** between the `public` and `protected` chains, and no
//!   route was added or removed. `public_router_allowlist.rs` is untouched.
//! * **No RLS policy, no `WITH CHECK`, no write-side SQL predicate.** That half
//!   is PR-16/PR-17's and PR-11 deliberately does not pre-empt it — see the
//!   `-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate`
//!   markers in `repos/claim.rs`, which are unchanged.
//! * **No `FAIL_OPEN_SCOPE_SITES` row moved.** Locked decision Q7 assigns those
//!   35 sites to PR-16 and PR-11 spends its mechanism elsewhere.
//!
//! ## Status at PR-10
//!
//! **PR-10 adds a migration and does NOT touch any of the four.** Said
//! explicitly, because it adds one (085, `webhook_subscriptions`) and the
//! rejection trigger above is written to catch exactly the PR that adds a
//! migration and leaves this file alone.
//!
//! * **D1 (nothing is public by absence, omission, or default-on-error)** —
//!   reinforced, not changed. The new fan-out filter in
//!   `epigraph-api/src/routes/webhooks.rs::retain_visible_subscriptions` has
//!   three failure branches (no `agent_id`, `Viewer::resolve` errors,
//!   `hidden_claim_ids` errors) and all three DROP the delivery. A database
//!   outage stops webhooks; it does not broadcast every tenant's claims.
//! * **D3 (`public` means any authenticated agent; no anonymous shape)** —
//!   unchanged. PR-10 adds no `Viewer` constructor and no `SystemReason`. Its
//!   viewers come from `Viewer::resolve` over a subscription's `agent_id`,
//!   which is the one production path. `list_webhooks` / `get_webhook` gained
//!   `middleware::bearer::RequirePrincipal`, which enforces D3's two 401
//!   branches (no `AuthContext`, then no `agent_id`) and deliberately does NOT
//!   hand out a `Viewer` — there is no visibility predicate on a subscription
//!   row for one to be spent on, and an unspent viewer is a fail-open dressed
//!   as diligence.
//! * **Migration 085 is not a tenancy column change.** `webhook_subscriptions`
//!   has no `claim_id` and no foreign key onto `claims`, so it is outside the
//!   §2.4 protected set under both of `tenancy_coverage.rs::protected_set`'s
//!   generators, carries neither `visibility` nor `owner_group_id`, and gets no
//!   `tenancy_exempt` row (the registry is for relations the generators DO
//!   find; `migration_068_and_069_apply_twice` pins its cardinality at 12).
//! * **No route moved between the `public` and `protected` chains.** The four
//!   webhook routes were already on `protected` in both `create_router`
//!   variants and still are; `public_router_allowlist.rs` is untouched.
//! * **No RLS policy.** None existed at PR-10 (PR-17 owns 077/079; see the
//!   PR-17 status block below, which is where that stopped being true).
//! * **No write-side tenancy predicate.** `register_webhook` now writes a row,
//!   which is disclosed on the handler itself, but it spends no
//!   `writable_bind()` and adds no `WITH CHECK` and no policy. (PR-16
//!   correction: this used to say the mechanism "does not exist".
//!   `Viewer::writable_bind` has existed since PR-04; what does not exist is
//!   the SQL half that consumes it, and PR-16a does not add that either.)
//!   Refusing when `AuthContext` is absent (`delete_webhook`) is
//!   authentication, not the PR-16 control.
//!
//! ## Status at PR-09
//!
//! **PR-09 DOES touch a locked decision, and this file grows accordingly.**
//! It changes how an MCP caller obtains read authority, which is D3 — not a
//! route split, not a tenancy column, but the third of the four. Two changes,
//! both in the direction D3 points:
//!
//! * `crates/epigraph-mcp/src/tools/viewer.rs::request_viewer` no longer
//!   flattens `agent_id.or(owner_id).unwrap_or(client_id)`. `owner_id` and
//!   `client_id` are `oauth_clients.id` values; feeding either to
//!   `Viewer::resolve` was a type confusion that produced the D3-correct answer
//!   (public only) *by accident*, because the membership lookup happened never
//!   to match. An HTTP `AuthContext` with no `agent_id` is now refused.
//!   Asserted by [`d3_mcp_viewer_acquisition_does_not_flatten_a_client_id`].
//! * `crates/epigraph-mcp/src/auth.rs::unauthenticated_context` now carries the
//!   server's own `agents.id`, so the `--allow-unauthenticated-http` listener
//!   resolves the server's viewer rather than a nil principal's. This is a
//!   **widening** of that listener's read authority, and it is the change plan
//!   §4.12 assigns to PR-09. It does not create an anonymous *shape* — there is
//!   still exactly one `Viewer::resolve` and it still requires a principal — so
//!   [`d3_viewer_has_no_infallible_constructor`] is unchanged and correct.
//!
//! Nothing else in PR-09 is one of the four: the rest is read-path filtering
//! (viewer predicates spliced into repo functions and into `recall.rs`'s
//! `sqlx::query!` macros), inline SQL moved to `crates/epigraph-db/src/repos/`,
//! and three new test files. No migration; no RLS policy; no route moved
//! between the `public` and `protected` chains.
//!
//! ## Status at PR-08
//!
//! PR-06, PR-07 and PR-08 leave every assertion below unchanged, and that is the
//! correct outcome rather than an omission: none changes an RLS policy, a
//! route split, or a tenancy column. PR-07 is a read-path refactor — it moves
//! statements from `crates/epigraph-api/src/routes/` into
//! `crates/epigraph-db/src/repos/` and splices `Viewer` predicates into them —
//! and it adds no migration. Recorded here explicitly because the rejection
//! trigger above asks for it to be said, not inferred.
//!
//! **PR-08 in particular does not move a route.** Its plan entry says
//! `/api/v1/structural-features/:owner_id` is registered on the `public` router
//! and must move to `protected`; it already is on `protected`, in BOTH
//! `create_router` variants. Which PR moved it is NOT attributable from the
//! history — an earlier revision of this comment credited PR-03, which is not
//! evidenced: `git log -S/-G 'structural-features' -- routes/mod.rs` returns
//! only the initial public release, because the registration line itself never
//! changed and only the enclosing `public`/`protected` block boundary moved.
//! `routes/mod.rs` is untouched by PR-08 and the anonymous→401 acceptance
//! criterion is *tested*
//! (`crates/epigraph-api/tests/structural_features_authz.rs::anonymous_is_401`)
//! rather than implemented. The rest of PR-08 — nine statements into
//! `repos/structural.rs` with spliced predicates, an `epsilon` default of 1.0
//! that is also the unprivileged ceiling, and a `claims:admin` gate on exact
//! counts — is a read path and a scope check, neither of which is one of the
//! four decisions.
//!
//! * **D3 — no anonymous read authority.** Asserted below, in full.
//! * **D1 — tenancy is declared, never defaulted.** *Half asserted.* PR-05's
//!   migration 069 adds `entity_types.tenancy_tier`, and — unusually for this
//!   series — drops its DEFAULT **in the same migration**, because a type that
//!   does not exist yet has no live table to widen metadata-only and therefore
//!   needs no transition DEFAULT at all. That makes one column, today, the first
//!   place D1 is a machine-checkable predicate rather than an intention:
//!   `d1_tenancy_tier_is_declared_never_defaulted` below.
//!
//!   The OTHER half — the tier-A `visibility` / `owner_group_id` DEFAULTs
//!   migration 062 ships on purpose — is still not assertable, and stays a
//!   comment in the D1 section until migration 074 drops them in PR-16.
//! * **D4 — privatization is an explicit, audited administrative act.** Nothing
//!   to assert until the D4 surface exists. See the placeholder in the D4
//!   section.
//!
//! The remaining placeholders are *comments*, not `#[ignore]`d tests: an ignored
//! test is a red herring in `cargo test` output, and a parked `panic!` body is a
//! trap for whoever runs the suite with `--include-ignored`. PR-03 used the
//! parked-test form for one specific obligation with a silent failure mode;
//! these have no such mode, so a comment naming the owning PR is the honest
//! shape.
//!
//! ## Relationship to the other lint files
//!
//! `d3_viewer_has_no_infallible_constructor` overlaps
//! `crates/epigraph-db/tests/no_anonymous_viewer.rs`, and
//! `d3_anonymous_route_surface_is_the_allowlist` overlaps
//! `crates/epigraph-api/tests/public_router_allowlist.rs`. **That overlap is the
//! design**, not an oversight: §0.2 wants the locked decisions readable in one
//! place. The other two files remain **authoritative** — `public_router_allowlist.rs`
//! in particular also boots the app and proves every protected route really 401s,
//! and documents why axum 0.7.9 makes a runtime walk of "both variants"
//! impossible. What is here is the cheaper, structural half.

//! ## Status at PR-17
//!
//! **PR-17 changes an RLS policy, so this file grows.** It is the first PR in
//! the series that does — until 077 there was no policy in `pg_policy` at all.
//!
//! * **D4 gains a subject.** `migrations/077_rls_policies.sql` installs the
//!   policy set and `079_rls_force.sql` FORCEs the 35 relations it names. It is
//!   NOT the only source of [`FORCE_PROTECTED_SET`] — see the next bullet and
//!   that constant's own doc comment. The per-command coverage table D4 asks for
//!   lives in `crates/epigraph-db/tests/rls_enforcement.rs`, enumerated from
//!   `pg_policy.polcmd` and never from the migration text, with an exact
//!   `DELIBERATELY_UNCOVERED` register.
//! * **The locked array is 062's `tier_a` (25) ∪ the ten group/identity/
//!   encryption control tables ∪ the four privatization tables (PR-18a)**,
//!   asserted by [`d4_the_force_array_is_tier_a_plus_the_control_tables`]. The
//!   first two terms are 079's array; the four privatization tables are NOT in
//!   it and must never be added to it — 079 is applied and immutable, and
//!   `080`–`083` FORCE themselves at creation on 078's `rls_canary` precedent.
//!   The plan says
//!   this array equals "the generated protected set ∪ the group/encryption/
//!   admin tables"; **that formulation is not literally satisfiable** — the
//!   generated set (`tenancy_coverage.rs::protected_set`) contains two VIEWs and
//!   nine `tenancy_exempt` relations and OMITS the five non-claim-keyed roots
//!   (`frames`, `contexts`, `perspectives`, `communities`, `recall_events`).
//!   062's array is the honest referent and is what 079 transcribes.
//! * **`security_invoker` on the two view exemptions.** 077 sets it on
//!   `alternative_set` and `alt_set_decisions` and rewrites their
//!   `tenancy_exempt` residuals; `tenancy_coverage.rs::
//!   the_two_view_exemptions_are_security_invoker` is the inverted assertion.
//! * **No route moved between the `public` and `protected` chains**, and no
//!   tenancy column changed. `public_router_allowlist.rs` is untouched.
//! * **A write-side predicate now exists at the database layer**, which is a
//!   correction to the PR-10 note above: every `FOR ALL` policy 077 installs
//!   carries an explicit `WITH CHECK`. The RUST write gate is still absent —
//!   PR-16 landed as 16a only and the call-site gate is unnumbered 16b — so
//!   `Viewer::writable_bind` remains unspent in the repo layer. What changed is
//!   that the database no longer accepts a write into a group the session
//!   cannot write to, whatever the Rust does.

//! ## Status at PR-24
//!
//! **PR-24 adds a migration (086) and does NOT touch any of the four.** Said
//! explicitly, following PR-10's precedent, because the rejection trigger above
//! is written to catch exactly the PR that adds a migration and leaves this file
//! alone.
//!
//! * **No RLS policy, and this is checkable rather than narrated.** 086 creates
//!   one `SECURITY DEFINER` function plus a `REVOKE` and a role-guarded
//!   `OWNER TO` / `GRANT EXECUTE`. It issues no `CREATE POLICY`, no
//!   `DROP POLICY`, no `ALTER TABLE … ROW LEVEL SECURITY` and no
//!   `ALTER TABLE … FORCE`, so it adds, removes and edits **zero** `pg_policy`
//!   rows. Asserted from the migration source by
//!   [`d4_migration_086_installs_no_policy`] rather than left to review.
//! * **D1 (nothing is public by absence, omission, or default-on-error)** —
//!   reinforced, and the residual is stated in the direction it actually runs,
//!   because an earlier draft of this bullet had it BACKWARDS. The defect 086
//!   closes was an existence probe that returned EMPTY for every input once RLS
//!   was FORCEd on an application role, which both callers read as *"nothing is
//!   hidden"* — a mechanism that failed toward **delivering**. 086 removes that
//!   for the intended configuration. It does **not** invert the failure
//!   direction, and this file must not claim it does:
//!
//!   - **Degraded definer AUTHORITY is still fail-OPEN.** Both arms of the set
//!     difference now draw from the SAME CTE, fed by one call to
//!     `epigraph_claim_tenancy_by_ids`. If that frame loses its authority — a
//!     silently no-opped `ALTER FUNCTION … OWNER TO`, so
//!     `epigraph_definer_bypass()` is false inside it, or `epigraph_maintenance`
//!     losing `SELECT` on `claims` — the CTE shrinks to the rows the policy
//!     admits. A public row survives in BOTH arms (it satisfies
//!     `visibility = 'public'`), the difference empties, and the callers read
//!     empty as *"nothing is hidden"* and DELIVER. That is the original
//!     collapse, reached by a different route. **Measured, not deduced:**
//!     re-owning the function to `epigraph_app` and re-running
//!     `rls_enforcement.rs::hidden_claim_ids_still_classifies_on_the_app_role_under_force`
//!     fails it on property 1 — "an existing row the viewer cannot read must
//!     come back HIDDEN" — i.e. the probe reports NOTHING, not everything.
//!     **What upholds D1 here is the instrument, not the shape**: the deferred
//!     entry in
//!     `epigraph-cli/src/bin/tenancy_backfill.rs::DEFERRED_DEFINER_FUNCTIONS`,
//!     checked by `verify` — whose exit code is the week-11c deploy pre-flight —
//!     is the only thing standing behind the frame's authority. It gates on the
//!     function's presence in `pg_proc`, not on `_sqlx_migrations`, so a
//!     database that lost its bookkeeping row cannot silently skip it.
//!   - **A missing `EXECUTE` grant IS fail-closed.** It raises `42501`, the call
//!     returns `Err`, and the PR-10 trio pinned above (`agent_id == None`,
//!     `Viewer::resolve` errors, `hidden_claim_ids` errors → all DROP) turns
//!     that into a DROP. That trio is untouched.
//! * **D3 (`public` means any authenticated agent; no anonymous shape)** —
//!   unchanged. PR-24 adds no `Viewer` shape, no constructor, and no
//!   `SystemReason`; `Viewer::bypass_bind` is not consulted and no
//!   `Viewer::system(` appears in the diff. The repaired statement keeps its
//!   `Viewer::splice` marker — over the definer function's output rather than
//!   over `claims` — so the viewer is spent in SQL exactly as
//!   `visibility_lint.rs` requires, and **no new `VISIBILITY-EXEMPT:` entry is
//!   taken**. That was a factoring decision, not a coincidence: the shape that
//!   would have needed one puts the group array inside the definer frame, and
//!   `EXPECTED_EXEMPTIONS`' own doc says a new exemption on a READ path is
//!   almost certainly a leak being annotated rather than fixed.
//! * **No tenancy column.** 086 adds no column to any relation, adds no table,
//!   and therefore no `tenancy_exempt` row — `tenancy_coverage.rs`'s
//!   cardinality-12 pin is untouched.
//! * **No route moved** between the `public` and `protected` chains, and no
//!   route was added or removed. `public_router_allowlist.rs` and
//!   `viewer_route_table_lint.rs` are untouched; PR-24 changes no handler
//!   signature.
//! * **No write-side predicate.** 086's function is `STABLE` and its body is a
//!   `SELECT`. The `-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side
//!   predicate` markers in `repos/claim.rs` are unchanged, and no
//!   `FAIL_OPEN_SCOPE_SITES` row moved.
//! * **The `no_unscoped_pool.rs` counters do not move.** PR-24 converts
//!   nothing: `UNCONVERTED` keeps `routes/events.rs` at 6 and
//!   `routes/webhooks.rs` at 3, `HIGH_WATER` stays 414 and `HIGH_WATER_FILES`
//!   51, and `bin/server.rs` stays in `EXEMPT` at 3. Only the prose reasons
//!   change, because the follow-up they pointed at is this PR.

//! ## Status at PR-25
//!
//! **PR-25 adds NO migration and does NOT touch any of the four.** Stated
//! explicitly, following PR-10's and PR-24's precedent. §0.2's rejection trigger
//! fires on *"a PR that changes an RLS policy, a route split, or a tenancy
//! column and does not touch this file"* — PR-25 changes none of the three, so
//! the trigger does not fire and this block is convention rather than
//! obligation. It is written because the D1 residual PR-24 recorded now applies
//! to a second function, on strictly worse terms.
//!
//! PR-25 repairs `epigraph-db/src/repos/event.rs::EventRepository::list` — the
//! SQL twin of `hidden_claim_ids`, and the only tenancy control over the event
//! ROWS returned by the persisted half of `GET /api/v1/events`, by
//! `GET /api/v1/graph/snapshot/:version`, and by all of MCP `list_events`. Read
//! "only tenancy control" as a statement about AUTHORITY, not COVERAGE: the
//! predicate classifies payload uuids against `claims` alone, so a payload
//! naming a row in another tenanted table is not classified at all, and
//! `graph_snapshot`'s `current_version` comes from the deliberately viewer-less
//! `EventRepository::get_latest_version` rather than through this predicate.
//! Both limits are recorded — the first as the open finding
//! `F-PR25-event-suppression-is-claims-keyed-only`, the second in that
//! function's own doc. It routes **both** arms of that predicate
//! through 086's existing `epigraph_claim_tenancy_by_ids(uuid[])`. No new
//! migration; no new database object; `d4_migration_086_installs_no_policy`
//! below is unaffected, and it reads the migration source, not the tree.
//!
//! * **No RLS policy, no route split, no tenancy column.** One SQL string
//!   literal in one repo function, plus one new test and doc corrections. Zero
//!   `pg_policy` rows read, added, removed or edited; no handler signature
//!   changes; `public_router_allowlist.rs` and `viewer_route_table_lint.rs` are
//!   untouched; `tenancy_coverage.rs`' cardinality-12 pin is untouched.
//! * **D1 — the residual is UNCHANGED IN KIND and WIDER IN BLAST RADIUS.**
//!   Degraded definer authority is still fail-OPEN, and here it is worse than it
//!   is for `hidden_claim_ids`. The mechanism is the same: if the frame loses
//!   its authority (a silently no-opped `ALTER FUNCTION … OWNER TO`, or
//!   `epigraph_maintenance` losing `SELECT` on `claims`) both arms shrink to the
//!   rows the policy admits, the existence arm stops finding the row, the
//!   conjunction is unsatisfiable, and **every** event is returned. What is
//!   worse is the reach: `routes/events.rs::list_events` at least has a second,
//!   independent Rust control on its ring-buffer half, whereas `graph_snapshot`
//!   and MCP `list_events` have **no Rust backstop at all**, and `events`
//!   carries no RLS of its own. So the `DEFERRED_DEFINER_FUNCTIONS` entry in
//!   `epigraph-cli/src/bin/tenancy_backfill.rs`, checked by `verify`, is now the
//!   only thing standing behind three read surfaces instead of two. PR-25 adds
//!   no new entry there — the function is already registered, and the *same*
//!   function is what backs both probes — but the stake it carries is larger.
//!   **AMENDED by `tenancy/fix-coverage-hygiene` (2026-09-17); the three
//!   sentences that stood here are now false and are corrected rather than left
//!   to be read as current.** They said that the constant's own doc still named
//!   only `hidden_claim_ids`, that editing any `epigraph-cli` file would make
//!   the `genai` feature gate owed, and that THIS block was the current
//!   statement of the stake. All three have been superseded: that batch updated
//!   the constant's doc at both of its sites — the `DEFERRED_DEFINER_FUNCTIONS`
//!   preamble and `verify_definer_ownership`'s 086 bullet — so the wider stake
//!   is now stated where an operator reads it; the `genai` reason was
//!   re-measured and did not survive, because the `epigraph-tenancy-backfill`
//!   `[[bin]]` carries `required-features = ["db"]` and `db` IS default, so that
//!   file is already inside the standard gate and gates no `genai` target; and
//!   the deferred obligation `D-PR25-deferred-definer-doc-understates-its-stake`
//!   is dispositioned CLOSED in `docs/tenancy/progress.json` on that basis. This
//!   block is kept as the PR-25-era record of how the residual widened, not as
//!   the live statement of the stake.
//!   `schema_contract.rs::migration_086_read_definer_is_revoked_from_public` is
//!   likewise untouched and likewise load-bearing for more surfaces.
//! * **D1 — a missing `EXECUTE` grant is still fail-CLOSED here, but the
//!   symptom differs from `hidden_claim_ids`' and must not be transcribed from
//!   it.** There, `42501` becomes a DROP via the PR-10 error trio. Here it
//!   becomes an `Err` out of `EventRepository::list`, i.e. a 500 on
//!   `GET /api/v1/events` and on `graph_snapshot` and an error from MCP
//!   `list_events` — a total outage of the surfaces the predicate protects, not
//!   a silent leak. The same is true of a `42883` on a pre-086 database.
//! * **D3 (`public` means any authenticated agent; no anonymous shape)** —
//!   unchanged. No `Viewer` shape, constructor or `SystemReason` is added;
//!   `Viewer::system(` and `Viewer::bypass_bind` appear nowhere in the diff. All
//!   three callers are on the `protected` chain and none moves. The repaired
//!   statement keeps its `Viewer::splice` marker — over the definer function's
//!   output rather than over `claims` — so the viewer is spent in SQL exactly as
//!   `visibility_lint.rs` requires, the bind index stays 4 (the array literal is
//!   inline, so no positional parameter is added), the guarded
//!   `if let Some(g) = viewer.group_bind()` bind is preserved, and **no new
//!   `VISIBILITY-EXEMPT:` entry is taken.** That last is a decision, not luck:
//!   this is a READ path, which matches none of `EXPECTED_EXEMPTIONS`' three
//!   categories, and that set's own doc says an exemption on a read path is
//!   almost always a leak being annotated rather than fixed.
//! * **No write-side predicate.** 086's function is `STABLE` and its body is a
//!   `SELECT`; PR-25 adds no SQL of any other kind. `EventRepository::{insert,
//!   publish_or_log, publish_or_log_conn}` are untouched and PR-16 still owns
//!   the write-side predicate, including the `create_event` / `publish_event`
//!   attribution surface. No `FAIL_OPEN_SCOPE_SITES` row moved.
//! * **The `no_unscoped_pool.rs` counters do not move.** PR-25 converts nothing
//!   and is explicitly not a conversion shard: `UNCONVERTED` keeps
//!   `routes/events.rs` at 6 and `routes/webhooks.rs` at 3, `HIGH_WATER` stays
//!   414, `HIGH_WATER_FILES` 51, `bin/server.rs` stays in `EXEMPT` at 3. Only
//!   the prose changes, and the do-not-convert rule stays IMPERATIVE — it now
//!   rests on `D-PR17-request-path-never-stamps-session-gucs` alone, which PR-25
//!   does not discharge. **§9.2 step 11d remains blocked.**

//! ## Status at PR-22
//!
//! **PR-22 ADDS A MIGRATION (084) and touches none of the four locked
//! decisions.** This block is therefore an OBLIGATION, not a convention: §0.2's
//! rejection trigger fires on *"a PR that changes an RLS policy, a route split,
//! or a tenancy column and does not touch this file"*, and the `Status at PR-10`
//! block above records that it was written *"explicitly, because it adds one
//! (085, `webhook_subscriptions`) and the rejection trigger above is written to
//! catch exactly the PR that adds a migration and leaves this file alone."*
//!
//! PR-22 retires the legacy `ownership` table. Migration 084 drops the relation,
//! its `ownership_key_id_quarantine` VIEW, both its triggers and 071's
//! `public.epigraph_ownership_transcribe()` definer body, behind two `DO $$`
//! pre-flights that `RAISE EXCEPTION`. The Rust half deletes
//! `repos/ownership.rs` and its two re-exports, retires
//! `tenancy_backfill`'s `transcribe_legacy_ownership` pass and its two
//! `ownership` `verify` checks, and rewrites the eight `ownership`-joining
//! statements in `repos/structural.rs`.
//!
//! * **No RLS policy.** `ownership` was never in migration 077's policy set and
//!   never in 079's FORCE array — measured: `relrowsecurity = false`,
//!   `relforcerowsecurity = false`, zero `pg_policy` rows. So the drop removes
//!   no policy, and `rls_enforcement.rs`'s `PROTECTED` and
//!   `DELIBERATELY_UNCOVERED` registers need no edit and get none.
//! * **No route split.** PR-14 already deleted the four HTTP routes and the
//!   three MCP tools; there is nothing left to move.
//!   `public_router_allowlist.rs` and `viewer_route_table_lint.rs` are
//!   untouched, and no `FAIL_OPEN_SCOPE_SITES` row moves.
//! * **No tenancy column.** `ownership` carried none — it is not in migration
//!   062's `tier_a`, has no `claim_id` and no FK to `claims`, so it is in
//!   neither §2.4 generator and needs no `tenancy_exempt` row. That registry's
//!   cardinality-12 pin in `tenancy_coverage.rs` is untouched.
//!   `schema_contract.rs` never referenced `ownership`; the three shapes it pins
//!   (062's `tenancy_transcription_log`, `tenancy_backfill_progress`,
//!   `tenancy_undeclared_writes`) all SURVIVE 084.
//! * **The trigger inventory moves 21 → 20, and the name comes OUT of both
//!   queries.** `ownership_transcribe` goes with its table.
//!   [`d1_tenancy_stamping_triggers_are_armed`] and
//!   `tenancy_triggers.rs::every_tenancy_trigger_is_enabled` are edited in the
//!   same commit as the DDL. The name is removed from the `IN` lists rather than
//!   only the count being lowered: leaving it would make the vacuity guard look
//!   for a trigger that cannot exist, which is a self-fulfilling assertion.
//! * **D1 — nothing becomes public by absence.** This is the decision the drop
//!   is closest to, and the answer is that it strictly REDUCES the ways a node
//!   can be undeclared. Before 084 a node's tenancy could be asserted in two
//!   places — its own columns and an `ownership` row — and 071's shim existed
//!   solely to stop them diverging. After 084 there is one place. Pre-flight (2)
//!   is what makes that safe rather than merely tidy: it refuses the drop while
//!   any non-public row lacks a `tenancy_transcription_log` entry **recording
//!   the partition that row currently holds**. Say what the guard proves and no
//!   more: the ledger is `node_id PRIMARY KEY`, overwritten on each firing and
//!   written for every `partition_type` including `'public'`, so a
//!   presence-only check would be satisfied by a stale entry and would NOT
//!   establish that the row's *current* declaration ever reached a column. The
//!   `from_partition` conjunct is what closes the difference. Dropping a row
//!   whose non-public declaration lives nowhere else would silently widen its
//!   node, which is precisely a D1 violation, and the migration refuses
//!   instead. `retire_ownership_preflight.rs` asserts BOTH refusals — the
//!   missing entry and the stale one — against manufactured failing states, and
//!   pairs each with a passing control.
//! * **D3 — no `Viewer` shape, constructor or `SystemReason` is added.**
//!   `Viewer::system(` and `Viewer::bypass_bind` appear nowhere in the diff. The
//!   eight rewritten `repos/structural.rs` statements each still take a
//!   `&Viewer` and still spend it through `Viewer::splice`; every marker in the
//!   new owned-node union is the canonical `/* {VISIBILITY:<alias>} */` or
//!   `/* {EDGE_VISIBILITY:<alias>} */` spelling, the guarded
//!   `if let Some(g) = viewer.group_bind()` bind is preserved at every site, and
//!   the bind indices are unchanged (2, and 3 for `edge_counts`). **No new
//!   `VISIBILITY-EXEMPT:` entry is taken**, and that is a decision rather than
//!   luck: the obvious shortcut for a statement whose owner relation had just
//!   been deleted would have been to annotate it, which
//!   `visibility_lint.rs::EXPECTED_EXEMPTIONS` calls "a leak being annotated
//!   rather than fixed" on a read path. The union filters both of its arms
//!   instead. Deleting `repos/ownership.rs` removes SIX viewer-taking functions
//!   from that lint's population and no exemption from its register.
//! * **No write-side predicate.** PR-22 adds no `WITH CHECK`, no RLS policy and
//!   no write-side SQL predicate, and no `PolicyGate::authorize` call site. The
//!   `-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate`
//!   markers in `repos/claim.rs` are unchanged. What PR-22 deletes is write
//!   CODE that cannot survive its table — `OwnershipRepository` and
//!   `transcribe_legacy_ownership` — which is a removal, not a gate.
//! * **`no_unscoped_pool.rs` is untouched.** It scans
//!   `crates/epigraph-api/src`; nothing in this diff is under that root, so
//!   `UNCONVERTED`, `HIGH_WATER` and `HIGH_WATER_FILES` do not move.
//! * **One deliberate UN-PINNING, said out loud.**
//!   `tenancy_coverage.rs::ownership_key_id_quarantine_is_a_view` pinned two
//!   properties of the quarantine view — that it was a VIEW rather than a
//!   snapshot, and that it carried `security_invoker = true` — and
//!   `migrations/README.md` named it as the pin for both. 084 drops the view, so
//!   the test goes with it. The RULE it exemplified ("any VIEW added in the
//!   060-090 range must set `security_invoker`") stands, is restated in README,
//!   and is still ratcheted on the two view exemptions by
//!   `tenancy_coverage.rs::the_two_view_exemptions_are_security_invoker`.
//!
//! ## Status at migration 092
//!
//! **092 CHANGES AN RLS POLICY, so this file is touched deliberately.** §0.2's
//! rejection trigger fires on *"a PR that changes an RLS policy … and does not
//! touch this file"*, and the discharge here is an assertion rather than a
//! sentence — see
//! [`d4_the_group_creation_bootstrap_arm_is_bounded_by_the_roster`].
//!
//! 092 bounds migration 077's group-creation bootstrap arm to the group's
//! roster, closing `D-PR17-creator-arm-outlives-membership`. The arm is carried
//! by three policies — `groups_tenancy`, `group_memberships_tenancy` and
//! `group_key_epochs_tenancy` — in two different spellings, an inline column
//! comparison on `groups` and the shared `epigraph_is_group_creator()` helper on
//! the other two, so a single-site fix is incomplete by construction and would
//! still pass a proof written against whichever spelling it chose.
//!
//! * **D4 — the policies stay FORCEd and keep full command coverage.** 092
//!   amends `groups_tenancy` with `ALTER POLICY` rather than DROP + CREATE, so
//!   `pg_policy.polcmd` stays `*` (`FOR ALL`) and the grantee list is preserved
//!   by construction; the other two policies are not re-issued at all, only the
//!   function their arms call. No table is added to or removed from the FORCEd
//!   set, so `FORCE_PROTECTED_SET`, `CONTROL_TABLES`, `PRIVATIZATION_TABLES`,
//!   `rls_enforcement.rs::PROTECTED` and `DELIBERATELY_UNCOVERED` need no edit
//!   and get none.
//! * **D1 — no tenancy column.** `groups`, `group_memberships` and
//!   `group_key_epochs` carry neither `visibility` nor `owner_group_id`; they are
//!   not in 062's `tier_a` set, and 092 adds no column anywhere.
//! * **D3 — no `Viewer` shape, constructor or `SystemReason` is added**, and no
//!   route is added, moved or removed. 092 is SQL only; the Rust half of this
//!   batch is tests and the ledger.
//! * **The arm is still session-keyed in the shape
//!   `rls_enforcement.rs::no_policy_arm_is_session_independent` requires.** That
//!   test splits each policy expression on the literal `" OR "` and demands every
//!   fragment name a session helper. The narrowing is written INSIDE the existing
//!   disjunct as an `AND`, not as a new top-level `OR`, so the fragment still
//!   reads `created_by_agent_id = ( SELECT epigraph_principal_id() …) AND …` —
//!   measured against `pg_get_expr`, not assumed. A narrowing spelled as a
//!   sibling disjunct would have been reported as an unconditional grant, which
//!   misdescribes the change and sends a reviewer the wrong way. The roster
//!   helper is ALSO added to that test's `SESSION_HELPERS` list, so recognition
//!   rests on the helper's own session binding rather than on the adjacent
//!   `epigraph_principal_id()` happening to be the substring the match finds —
//!   the incidental shape the list's own 083 entry criticises.
//! * **No `ROW_ONLY_BY_DESIGN` entry goes stale.** None of the four needles
//!   (`true`, `key_kind`, `privatization_apply`, `agent_id IS NULL`) matches an
//!   arm 092 rewrites, and that register is exact in both directions.

use sqlx::PgPool;
use std::collections::BTreeSet;

// ===========================================================================
// D3 — there is no anonymous read authority
// ===========================================================================

const VISIBILITY_RS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/visibility.rs");

/// Cross-crate source read. `locked_decisions.rs` lives in `epigraph-db` because
/// that is where §0.2 fixes its path, but D3's route half is a fact about
/// `epigraph-api`. Both crates are in this workspace and the path is stable.
const ROUTES_MOD_RS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../epigraph-api/src/routes/mod.rs"
);

/// D3's MCP half (PR-09). `crates/epigraph-mcp/src/tools/viewer.rs` is where a
/// tool call turns an `AuthContext` into read authority — the MCP counterpart of
/// `epigraph-api`'s `ViewerExtractor`, and therefore the other place D3 can be
/// violated. Same cross-crate rationale as [`ROUTES_MOD_RS`].
const MCP_VIEWER_RS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../epigraph-mcp/src/tools/viewer.rs"
);

/// D1's write half (PR-11). `crates/epigraph-interfaces/src/policy.rs` is
/// where the kernel decides what an unconfigured deployment permits. Same
/// cross-crate rationale as [`ROUTES_MOD_RS`].
const INTERFACES_POLICY_RS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../epigraph-interfaces/src/policy.rs"
);

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

/// Strip `//`-style comments so the prose explaining *why* a construct is banned
/// does not itself trip the ban. Block comments are not stripped; do not write
/// one containing a banned needle.
///
/// **This truncates at the first `//` on a line, including one inside a string
/// literal** — a URL in a doc example would silently delete the rest of that
/// line. Harmless in today's `visibility.rs`, which has none, but it matters
/// here in a way it would not in a normal linter: every assertion below is that
/// a needle is ABSENT, so over-deleting makes the lint quieter, never louder.
/// If a banned construct ever hides behind a `//` in a string, this scanner is
/// where to look.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|line| match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// D3, half one: read authority cannot be materialised out of nothing.
///
/// Every needle below is a way to obtain a `Viewer` without proving who the
/// caller is. They are *absences*, so a text scan is the right instrument —
/// there is no type to assert against when the point is that the impl must not
/// exist.
#[test]
fn d3_viewer_has_no_infallible_constructor() {
    let code = strip_line_comments(&read(VISIBILITY_RS));

    const BANNED: &[(&str, &str)] = &[
        (
            "Anonymous",
            "D3 removes the anonymous shape entirely. A viewer that 'matches \
             nothing' is invisible to a test suite written as 'assert a stranger \
             CANNOT read': it passes every case while returning empty results \
             forever.",
        ),
        ("anonymous(", "the same, in constructor form"),
        (
            "impl Default for Viewer",
            "reachable by `..Default::default()` in a struct literal nobody reads",
        ),
        (
            "From<Option<Uuid>> for Viewer",
            "the anonymous shape wearing a different hat: `None` would have to \
             mean something, and every meaning is wrong",
        ),
        (
            "From<&AuthContext> for Viewer",
            "an infallible conversion cannot perform the membership round trip, \
             so it would have to invent a group set",
        ),
        (
            "fn unrestricted(",
            "the unrestricted shape must cost a MaintenanceLease",
        ),
    ];

    let violations: Vec<String> = BANNED
        .iter()
        .filter(|(needle, _)| code.contains(needle))
        .map(|(needle, why)| format!("  `{needle}` — {why}"))
        .collect();

    assert!(
        violations.is_empty(),
        "D3 is violated in src/visibility.rs:\n{}",
        violations.join("\n\n")
    );
}

/// D3, MCP half: read authority comes from an `agents.id` or it does not come
/// at all (PR-09).
///
/// `epigraph-api`'s side of this is the `ViewerExtractor`, which 401s a
/// principal-less token. MCP has no extractor — `tools/viewer.rs::request_viewer`
/// is the whole of it — and until PR-09 it flattened
/// `agent_id.or(owner_id).unwrap_or(client_id)` and resolved whatever came out.
///
/// Why that mattered even though the outcome was correct: `owner_id` and
/// `client_id` are `oauth_clients.id` values, so `Viewer::resolve` looked up
/// `group_memberships.agent_id = <a client id>`, matched nothing, and returned a
/// public-only viewer. Right answer, wrong reason — and a reason that stops
/// holding the moment those id spaces overlap, at which point the flatten is a
/// silent authority grant with no error and no metric. Plan §4.12 says so
/// directly, prescribing `None => Err(unauthorized(...))`.
///
/// This is a source-text assertion for the same reason
/// [`d3_viewer_has_no_infallible_constructor`] is: the property is "this
/// spelling does not appear", which no runtime test can establish.
#[test]
fn d3_mcp_viewer_acquisition_does_not_flatten_a_client_id() {
    let code = strip_line_comments(&read(MCP_VIEWER_RS));

    assert!(
        !code.contains("unwrap_or(a.client_id)") && !code.contains("or(a.owner_id)"),
        "D3 is violated in epigraph-mcp/src/tools/viewer.rs: request_viewer is \
         flattening an oauth_clients.id into an agents.id position again. A \
         token with no agent principal has no read authority; refuse it."
    );
    assert!(
        code.contains("a.agent_id.ok_or_else("),
        "request_viewer must refuse an AuthContext carrying no agent_id, not \
         substitute another id for it. If the refusal moved or changed shape, \
         update this assertion deliberately — it is the only mechanical record \
         that MCP's read authority is agent-derived."
    );
    assert!(
        code.contains("Viewer::resolve"),
        "request_viewer must still go through Viewer::resolve — the one \
         constructor a request path can reach. A second acquisition path is a \
         second place D3 can be violated."
    );
}

/// D3, half two: the one unrestricted shape costs a lease, and the lease is
/// unforgeable outside this crate.
#[test]
fn d3_the_only_unrestricted_shape_costs_a_lease() {
    let code = strip_line_comments(&read(VISIBILITY_RS));

    assert!(
        code.contains("pub struct MaintenanceLease(pub(crate) ())"),
        "MaintenanceLease's field must stay `pub(crate)`. If it becomes `pub`, \
         any crate constructs one with `MaintenanceLease(())` and `Viewer::system` \
         stops being a type-level guarantee."
    );
    assert!(
        code.contains("pub const fn system(_lease: &MaintenanceLease, reason: SystemReason)")
            || code.contains("pub fn system(_lease: &MaintenanceLease, reason: SystemReason)"),
        "Viewer::system must take a `&MaintenanceLease`. Without the lease \
         parameter, 'unrestricted viewer' and 'maintenance connection' come apart \
         — and under FORCEd RLS that combination returns ZERO rows, not all rows."
    );
    assert!(
        !code.contains("pub const fn new() -> Self") || code.contains("pub(crate) const fn new()"),
        "MaintenanceLease::new must stay crate-private."
    );

    // There is deliberately no behavioural half here. Constructing a lease from
    // an integration test is IMPOSSIBLE — `MaintenanceLease::new` is
    // `pub(crate)` and this file links `epigraph-db` from outside — and that
    // impossibility IS the decision. The behaviour of a bypass viewer once it
    // exists is asserted in `qual_guc_coherence.rs`, which obtains its lease the
    // only way anything can: from `ScopedPool::unscoped_for_maintenance`.
}

/// D3, half three: the set of routes reachable with no `Authorization` header is
/// an allowlist of exactly two application routes, in **both** `create_router`
/// variants.
///
/// The `#[cfg(not(feature = "db"))]` variant is not built in any buildable
/// configuration, so a source lint is the only mechanism that covers it at all.
#[test]
fn d3_anonymous_route_surface_is_the_allowlist() {
    let src = read(ROUTES_MOD_RS);
    let expected: BTreeSet<&str> = ["/health", "/api/v1/openapi.json"].into_iter().collect();

    let chains: Vec<&str> = statement_starts(&src, "let public = Router::new()")
        .into_iter()
        .map(|start| statement_at(&src, start))
        .collect();

    assert_eq!(
        chains.len(),
        2,
        "expected exactly two `let public = Router::new()` chains — one per \
         create_router variant. Found {}. If a variant was added or removed, \
         this test must be updated deliberately.",
        chains.len()
    );

    for (i, chain) in chains.iter().enumerate() {
        let routes: BTreeSet<&str> = route_literals(chain).into_iter().collect();
        assert_eq!(
            routes, expected,
            "create_router variant #{i}: the anonymous surface is not the \
             allowlist. Registering a route on the `public` chain puts it back \
             on the unauthenticated internet — which under D3 is a decision that \
             belongs in review, not in a diff hunk. \
             (The authoritative, richer check, including the live 401 assertions, \
             is crates/epigraph-api/tests/public_router_allowlist.rs.)"
        );
    }
}

// ---------------------------------------------------------------------------
// A minimal, depth-aware Rust statement scanner.
//
// Line-based scanning has a silent-truncation mode: a `;` inside a route
// closure ends the scan early, and a truncation falling after the last expected
// route but before a newly added one passes the assertion while missing the new
// route. So `;` only terminates at depth zero.
// ---------------------------------------------------------------------------

fn statement_starts(src: &str, needle: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(needle) {
        out.push(from + rel);
        from += rel + needle.len();
    }
    out
}

fn statement_at(src: &str, start: usize) -> &str {
    let bytes = src.as_bytes();
    let mut depth = 0i32;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b';' if depth == 0 => return &src[start..=i],
            b'"' => {
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' => i += 1,
                        b'"' => break,
                        _ => {}
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("unterminated statement starting at byte {start} of routes/mod.rs");
}

/// Every `.route("<path>"` literal in a chain.
fn route_literals(chain: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = chain[from..].find(".route(") {
        let after = from + rel + ".route(".len();
        let rest = chain[after..].trim_start();
        let offset = after + (chain[after..].len() - rest.len());
        if let Some(stripped) = rest.strip_prefix('"') {
            if let Some(end) = stripped.find('"') {
                out.push(&chain[offset + 1..offset + 1 + end]);
            }
        }
        from = after;
    }
    out
}

// ===========================================================================
// D1 — tenancy is declared on write, never defaulted
// ===========================================================================
//
// THE PLACEHOLDER IS DISCHARGED. PR-05 left a hook here reading: "PR-16: after
// migration 074 drops the DEFAULTs, assert here that no tier-A table has a
// `column_default` on `visibility` or `owner_group_id`, and that
// `count(*) FROM claims WHERE owner_group_id = <world>` is 0." That is plan
// §8.2's A1 and A4, and migration 074 has now landed, so it is asserted below
// in `d1_no_tier_a_tenancy_column_carries_a_default`.
//
// PR-05's reason for deferring is worth keeping, because it is what a future
// reader will want when they wonder why 062 shipped defaults at all: migration
// 062 ships `DEFAULT 'public'` and `DEFAULT '00000000-…-000000000000'::uuid`
// deliberately — they are what makes `ADD COLUMN` metadata-only on a live
// `claims` table. Dropping them was always stage two, and an assertion written
// at PR-05 would have failed by construction and been silenced rather than
// fixed.
//
// The FULL acceptance suite for 074 is `crates/epigraph-db/tests/tenancy_required.rs`.
// What lives here is only the part that pins the DECISION: a PR that reinstates
// a default relitigates D1, and this is where that is caught.

/// D1, the half that is live: **a tenancy column with no absence value.**
///
/// PR-05's migration 069 adds `entity_types.tenancy_tier` and drops its DEFAULT
/// in the same file. It can, where 062 could not: `entity_types` holds 23 rows,
/// not a live `claims` table, so there is no metadata-only widening to protect
/// and no two-stage rollout to sequence. The 23 existing rows are classified by
/// the migration itself and the DEFAULT is then removed, which is exactly the
/// end-state 074 will bring the tier-A columns to.
///
/// Two things together are what make D1 true here, and BOTH are asserted:
///
/// 1. **No DEFAULT.** An `INSERT` that omits the column raises 23502 rather than
///    silently landing on a value nobody chose. This is what makes
///    `EntityTypeRepository::upsert_non_core`'s `tenancy_tier` parameter
///    load-bearing rather than cosmetic.
/// 2. **No absence value inside the vocabulary.** `entity_types_no_unclassified`
///    forbids `'unclassified'` at rest, so "I did not decide" cannot be
///    laundered into a stored value. Without this, dropping the DEFAULT would
///    only move the silence from the schema into the caller.
///
/// A PR that reinstates either — a convenience DEFAULT, or dropping the CHECK so
/// a registration can park at `'unclassified'` — relitigates D1, and this is
/// where it is caught.
#[sqlx::test(migrations = "../../migrations")]
async fn d1_tenancy_tier_is_declared_never_defaulted(pool: PgPool) {
    // (1) No DEFAULT, read from the catalog rather than inferred from an error.
    let default: Option<String> = sqlx::query_scalar(
        "SELECT column_default FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'entity_types' \
            AND column_name = 'tenancy_tier'",
    )
    .fetch_one(&pool)
    .await
    .expect("column_default probe");
    assert_eq!(
        default, None,
        "entity_types.tenancy_tier must have NO column_default. A DEFAULT here is \
         D1 being relitigated: it would let a registration omit the field and land \
         on a tier nobody declared."
    );

    // And it is still NOT NULL, so "no default" means "you must say", not
    // "it can be blank".
    let nullable: String = sqlx::query_scalar(
        "SELECT is_nullable FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'entity_types' \
            AND column_name = 'tenancy_tier'",
    )
    .fetch_one(&pool)
    .await
    .expect("is_nullable probe");
    assert_eq!(
        nullable, "NO",
        "dropping the DEFAULT only declares tenancy if the column is also NOT NULL"
    );

    // (2) The absence value is not storable.
    let constraint_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_constraint \
                        WHERE conrelid = 'public.entity_types'::regclass \
                          AND conname = 'entity_types_no_unclassified')",
    )
    .fetch_one(&pool)
    .await
    .expect("constraint probe");
    assert!(
        constraint_exists,
        "entity_types_no_unclassified must exist. Without it, 'unclassified' is a \
         storable absence value and dropping the DEFAULT merely moves the silence \
         from the schema to the caller."
    );

    // CONRELID-QUALIFIED above on purpose: `pg_constraint.conname` is unique per
    // RELATION, not per database, so a bare name lookup would be satisfied by a
    // same-named constraint on any other table — the exact blind spot migration
    // 062's own comments call out.

    // And no row is parked at the absence value.
    let unclassified: i64 = sqlx::query_scalar(
        "SELECT count(*)::bigint FROM entity_types WHERE tenancy_tier = 'unclassified'",
    )
    .fetch_one(&pool)
    .await
    .expect("unclassified count");
    assert_eq!(unclassified, 0);
}

// ===========================================================================
// D4 — privatization is an explicit, audited administrative act
// ===========================================================================
//
// PR-18a discharges the SECOND and THIRD of the three obligations this slot
// reserved — `privatization_audit` is append-only, and the D4 write surface is
// admin-only — because 080–083 create the objects both are about.
//
// The FIRST — every non-public row reachable through a privatization plan has a
// `tenancy_transcription_log` entry — stays reserved and belongs to 18c. It is a
// property of the APPLY, and PR-18a ships no apply: no job handler, no route,
// and `privatization_plan_items` with no write policy. An assertion over an
// empty table would be vacuous, which is the failure mode this whole file
// exists to refuse.

/// **D4, locked.** `privatization_audit` and `security_events` are append-only
/// by a control that also binds the TABLE OWNER.
///
/// RLS is not that control and cannot be. `ENABLE` exempts the owner outright,
/// `FORCE` does not defeat `BYPASSRLS`, and a superuser holds `BYPASSRLS`
/// implicitly — so a policy-only answer to "append-only" is satisfied by a
/// database on which the owner can rewrite the audit trail at will. Migration
/// 082's `BEFORE UPDATE OR DELETE … FOR EACH ROW` trigger is what binds every
/// role including the owner, and this asserts the trigger is there and ARMED
/// rather than merely defined.
///
/// `tgenabled` is checked because `ALTER TABLE … DISABLE TRIGGER` is a one-line,
/// no-migration way to remove the control that leaves the catalog otherwise
/// unchanged — the same reason `tenancy_triggers.rs` checks it for 070's
/// stamping triggers.
///
/// STATED LIMIT, so a reader does not over-read this: a row-level trigger does
/// not fire on `TRUNCATE`. `TRUNCATE` requires table ownership, which
/// `epigraph_app` does not have, so the app role cannot reach it; an owner or
/// maintenance connection can, and no assertion here would say so. 082's header
/// carries the same statement.
#[sqlx::test(migrations = "../../migrations")]
async fn d4_the_audit_tables_are_append_only_by_a_trigger_not_only_by_a_policy(pool: PgPool) {
    // (table, trigger, function, tgtype, tgenabled)
    let rows: Vec<(String, String, String, i16, String)> = sqlx::query_as(
        "SELECT c.relname::text, t.tgname::text, p.proname::text, t.tgtype, t.tgenabled::text \
           FROM pg_trigger t \
           JOIN pg_class c ON c.oid = t.tgrelid \
           JOIN pg_proc p ON p.oid = t.tgfoid \
          WHERE NOT t.tgisinternal \
            AND c.relnamespace = 'public'::regnamespace \
            AND t.tgname IN ('privatization_audit_no_mutate', 'security_events_no_mutate') \
          ORDER BY c.relname",
    )
    .fetch_all(&pool)
    .await
    .expect("audit trigger catalog probe");

    assert_eq!(
        rows.len(),
        2,
        "migration 082 must install an immutability trigger on BOTH audit tables; got {rows:?}"
    );

    for (table, trigger, func, tgtype, tgenabled) in &rows {
        assert_eq!(
            func, "epigraph_audit_immutable",
            "{table}.{trigger} must run 082's shared immutability body; a second body is a \
             second thing to keep in step"
        );
        assert_eq!(
            tgenabled, "O",
            "{table}.{trigger} is not tgenabled='O'. ALTER TABLE ... DISABLE TRIGGER removes \
             the control with no migration and no other catalog change."
        );
        // pg_trigger.tgtype bits: 1 = ROW, 2 = BEFORE, 4 = INSERT, 8 = DELETE,
        // 16 = UPDATE. Asserted by bit rather than by equality so a later
        // migration that ALSO covers INSERT does not fail this for being
        // stricter than it was.
        assert_eq!(*tgtype & 1, 1, "{table}.{trigger} must be FOR EACH ROW");
        assert_eq!(*tgtype & 2, 2, "{table}.{trigger} must be BEFORE");
        assert_eq!(
            *tgtype & 8,
            8,
            "{table}.{trigger} must cover DELETE — an actor erasing its own audit trail is the \
             whole threat"
        );
        assert_eq!(*tgtype & 16, 16, "{table}.{trigger} must cover UPDATE");
    }
}

/// **D4, locked.** A plan's STATE MACHINE is writable on a bypass connection and
/// on nothing else.
///
/// # The decision this locks
///
/// FINAL-PLAN §0.2 requires that a PR which changes a policy extends this file,
/// and migration 088 changes two. It gives `privatization_plans` and
/// `privatization_plan_items` their UPDATE policies, which is what makes
/// `approve`, `apply`, `abort` and `revert` possible at all — under `FORCE` a
/// command with no policy is denied to every role, `epigraph_maintenance`
/// included, because `epigraph_bypass()` is a function evaluated INSIDE a policy
/// expression and with no policy there is nothing to evaluate.
///
/// What is locked is that the widening stops there. The read policies (087) let
/// an instance admin who administers the target group SELECT; the UPDATE
/// policies deliberately do NOT mirror that conjunction, because the batch that
/// advances `privatization_plan_items.state` has just rewritten `claims` in the
/// same transaction and must be able to write both. So a state transition is
/// reachable only from the connection the job handler runs on, and the
/// authorization for it is FINAL-PLAN §6.5.5's re-validation rather than this
/// policy.
///
/// # Read from `pg_policy`, never from the migration text
///
/// §0.2's D4 predicate says so in those words. A migration that was edited, or
/// one whose `CREATE POLICY` was shadowed by a later `DROP`, is invisible to a
/// source scan and visible here.
///
/// # DELETE stays uncovered on both tables and that is asserted too
///
/// The inverse direction is the half that rots. "088 added an UPDATE policy" is
/// satisfied by a migration that also added `FOR ALL`, which would silently make
/// a plan deletable — and a plan is the record that a privatization was
/// attempted. `rls_enforcement.rs::DELIBERATELY_UNCOVERED` still carries both
/// DELETE rows; this is the catalog-side statement of the same fact.
#[sqlx::test(migrations = "../../migrations")]
async fn d4_the_plan_state_machine_is_writable_only_on_a_bypass_connection(pool: PgPool) {
    for table in ["privatization_plans", "privatization_plan_items"] {
        let rows: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT p.polname::text, p.polcmd::text, \
                    pg_get_expr(p.polqual, p.polrelid), \
                    pg_get_expr(p.polwithcheck, p.polrelid) \
               FROM pg_policy p \
              WHERE p.polrelid = ($1 || '')::regclass \
              ORDER BY p.polname",
        )
        .bind(format!("public.{table}"))
        .fetch_all(&pool)
        .await
        .expect("policy catalog probe");

        let cmds: BTreeSet<String> = rows.iter().map(|(_, c, _, _)| c.clone()).collect();
        // `polcmd` is one character: 'r' SELECT, 'a' INSERT, 'w' UPDATE,
        // 'd' DELETE, '*' ALL.
        assert!(
            cmds.contains("w"),
            "{table} has no UPDATE policy. Under FORCE that denies every state transition to \
             every role including the maintenance connection, so approve/apply/abort/revert \
             cannot exist. Migration 088 is what installs it; policies present: {rows:?}"
        );
        assert!(
            !cmds.contains("d"),
            "{table} has acquired a DELETE policy. A plan is the record that a privatization was \
             attempted and is never deleted; items cascade with their plan. \
             rls_enforcement.rs::DELIBERATELY_UNCOVERED still records the pair as uncovered, and \
             that register is exact in both directions."
        );
        assert!(
            !cmds.contains("*"),
            "{table} has acquired a FOR ALL policy. Every write policy on this surface stops \
             short of FOR ALL on purpose (083's instance_admins pair is the template), so a \
             command nobody has asked for stays denied rather than arriving as a side effect."
        );

        let update = rows
            .iter()
            .find(|(_, c, _, _)| c == "w")
            .expect("checked above");
        let (name, _, qual, with_check) = update;
        let qual = qual.as_deref().unwrap_or_default();
        let with_check = with_check.as_deref().unwrap_or_default();
        assert!(
            !qual.is_empty() && !with_check.is_empty(),
            "{table}.{name} must spell USING and WITH CHECK explicitly. They answer different \
             questions — which rows are candidates, and whether the row produced is legal — and a \
             reader who has to derive one from the other cannot tell an intentional asymmetry \
             from an omission."
        );
        for (clause, expr) in [("USING", qual), ("WITH CHECK", with_check)] {
            assert!(
                expr.contains("epigraph_bypass"),
                "{table}.{name}'s {clause} does not name epigraph_bypass(). A write arm on this \
                 surface that admits a non-bypass session is a state transition issued from the \
                 request path, which is the split migration 088's header refuses. Got: {expr}"
            );
            for forbidden in ["epigraph_is_instance_admin", "epigraph_is_group_admin"] {
                assert!(
                    !expr.contains(forbidden),
                    "{table}.{name}'s {clause} names {forbidden}. That is 087's READ conjunction, \
                     and mirroring it here would let a state transition be issued on a connection \
                     that cannot also write `claims` in the same transaction — which makes a \
                     partially applied batch reachable. Got: {expr}"
                );
            }
        }
    }
}

/// **D4, locked.** The D4 write surface is admin-only because there is NO
/// request-path write surface at all.
///
/// **PR-18 (18b).** The request path reaches D4 selection only through the
/// composed entry point, so a handler can never hold a bare selection-pass id.
///
/// # The decision this locks
///
/// FINAL-PLAN §6.5.2 records a previous revision of this design that shipped a
/// cross-tenant read oracle: selection must run UNFILTERED to be correct, and
/// the previous revision then serialised the ids and content it selected.
/// `repos/privatization.rs` closes that with a two-pass split, and the split is
/// now expressed as a TYPE — `UnfilteredSelection` wraps the selection pass's
/// output with a private field, and every exit that can carry an entity id
/// either takes the ACTOR's `Viewer` or writes into a `FORCE`-protected table.
///
/// Rust visibility cannot finish the job. The selection primitives must stay
/// `pub` because four integration-test binaries in another crate exercise them
/// directly, and `UnfilteredSelection` needs an unguarded constructor and
/// accessor for the same reason. So the request path is held off them here, by
/// the same instrument
/// [`d4_no_request_path_writes_the_instance_admin_table`] uses.
///
/// # Why a source lint is the right shape, stated plainly
///
/// It is an exact-substring scan after whitespace collapse, so an aliased import
/// walks past it. What makes it worth its weight is that the thing it catches —
/// a handler calling `select_closure` and serialising the result — is a diff, at
/// review time, with no runtime signature at all: the oracle returns `200` and
/// every test passes. There is no behavioural assertion that can stand in for
/// it, because the defect is "the handler answered with MORE than it should
/// have", and a test written against the wrong shape returns more, not less.
///
/// `RESTRICTED` names selection-pass entry points and the two test-only
/// constructors on the wrapper. It deliberately does NOT name the composed entry
/// point `PrivatizationRepository::select`, nor the rendering functions
/// (`visible_previews`, `visible_boundary_edges`, `count_visible`) — those take
/// the actor's own viewer and refuse a bypass one at runtime, so a route calling
/// them is the intended shape.
#[test]
fn d4_the_request_path_reaches_privatization_only_through_the_composed_entry_point() {
    // Raw, not comment-stripped, for the reason the sibling lint gives: these
    // are the names a doc comment explaining the rule would want to spell, and
    // the false positive is cheaper than a call hidden behind a `//` that a
    // later edit reinstates. Consequence for a future author: say "the selection
    // pass" rather than naming the function.
    const RESTRICTED: &[&str] = &[
        "PrivatizationRepository::select_closure",
        "PrivatizationRepository::select_content_lineage_hull",
        "PrivatizationRepository::count_selected",
        // BOTH UFCS SPELLINGS. The method-call needles below only catch
        // `sel.into_selected()`; `UnfilteredSelection::into_selected(sel)` is
        // the same call and walked straight past an earlier revision of this
        // list, which named the `from_selected` UFCS form and not this one.
        "UnfilteredSelection::from_selected",
        "UnfilteredSelection::into_selected",
        ".into_selected(",
        ".from_selected(",
    ];
    // The two REQUEST-PATH crates. `epigraph-mcp/src/tools` has no privatization
    // tool today and is scanned ANYWAY: the six MCP tools FINAL-PLAN §6.5.7 names
    // are the next slice's, they answer the same requests over a different
    // transport, and a rule that arrived with them would be a rule written by the
    // code it is meant to constrain.
    //
    // `epigraph-jobs/src` is deliberately absent for the opposite reason: 18c is
    // chartered to add an apply handler there, it runs on the maintenance pool,
    // and reaching the selection primitives directly is its job. Banning a call
    // the next slice must make would be a rule written ahead of the decision that
    // owns it.
    let roots = [
        concat!(env!("CARGO_MANIFEST_DIR"), "/../epigraph-api/src/routes"),
        concat!(env!("CARGO_MANIFEST_DIR"), "/../epigraph-mcp/src/tools"),
    ];

    let mut offenders: Vec<String> = Vec::new();
    for root in roots {
        let sources = rust_sources(std::path::Path::new(root));
        // VACUITY GUARD. `rust_sources` returns an empty `Vec` when `read_dir`
        // fails, so a moved directory would turn this into
        // `assert!(vec![].is_empty())`.
        assert!(
            !sources.is_empty(),
            "scan root {root} yielded no .rs files; the lint would pass vacuously"
        );
        for path in sources {
            let display = path.display().to_string();
            let src = read(path.to_str().expect("utf-8 path"));
            let flat = src.split_whitespace().collect::<Vec<_>>().join(" ");
            for needle in RESTRICTED {
                if flat.contains(needle) {
                    offenders.push(format!("{display}: {needle}"));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a handler or MCP tool reaches the D4 SELECTION pass directly. WHAT THIS MEASURES: exact \
         substrings after whitespace collapse over epigraph-api/src/routes and \
         epigraph-mcp/src/tools — an aliased import walks past it, and the real control is that \
         `UnfilteredSelection`'s field is private and its id-bearing exits take the actor's own \
         Viewer. WHY THE RULE: the selection pass runs unfiltered by necessity, so a value it \
         produced is not safe to serialise; `PrivatizationRepository::select` returns it wrapped \
         precisely so a handler cannot get a bare Uuid out of it, and the restricted names are \
         the ways around that wrapper. If a request path genuinely needs the raw selection, that \
         is a design change and this test is where it is argued. Offenders: {offenders:?}"
    );
}

/// `instance_admins` is the authority behind every privatization, and PR-18a's
/// acceptance clause is that it is empty after migration and stays empty until
/// an operator grants. That clause is only true while the request path cannot
/// write the table. Two independent controls hold it — migration 083's `REVOKE
/// INSERT, UPDATE, DELETE … FROM epigraph_app`, and a write policy pair whose
/// only disjunct is `epigraph_bypass()`, which reads `session_user` and is false
/// on an app connection — and this is the third: a SOURCE lint that no handler
/// or MCP tool calls the write repository at all.
///
/// A source lint rather than a behavioural one on purpose. The behavioural half
/// lives in `privatization_boundary.rs` / `privatization_authz.rs` and needs a
/// non-owner role to be non-vacuous; this catches the case that matters
/// EARLIEST — a future PR wiring `grant` into a route — at the point where it is
/// still a diff, and it keeps holding if the grants are ever loosened.
#[test]
fn d4_no_request_path_writes_the_instance_admin_table() {
    // THE SCAN IS RAW, NOT COMMENT-STRIPPED, AND THAT IS A CHOICE. `code_lines`
    // exists in this file because prose explaining why a construct is banned
    // would otherwise trip the ban — but the needles below are the very names a
    // route's doc comment would want to use to state the rule. Stripping would
    // let `// SAFETY: we call InstanceAdminRepository::grant only from ...` sit
    // one edit away from being uncommented, and this is the one lint where the
    // false positive (a comment naming the call) is cheaper than the false
    // negative (a call hidden behind a `//` that a later edit reinstates).
    // Consequence for a future author: say "the operator CLI's grant path"
    // rather than spelling the symbol.
    const BANNED: &[&str] = &[
        "InstanceAdminRepository::grant",
        "InstanceAdminRepository::revoke",
        "INSERT INTO instance_admins",
        "UPDATE instance_admins",
        "DELETE FROM instance_admins",
    ];
    // THE READ HALF, AND WHY ITS ROOT SET IS SMALLER THAN THE WRITE HALF'S.
    //
    // `InstanceAdminRepository::list` is `pub`, re-exported from
    // `epigraph-db/src/lib.rs`, takes a bare `&PgPool` and carries no `Viewer`,
    // so `visibility_lint.rs` never inspects it. On a STAMPED app pool
    // `instance_admins_self_or_definer` narrows it to the caller's own row — but
    // on the maintenance or superuser pool, which is the posture until plan §9.2
    // step 11d, it returns the whole roster plus `granted_by` and `note`. A
    // future `GET /api/v1/admin/instance-admins` calling `list(&state.db_pool,
    // true)` would pass fmt, clippy, the whole suite and the write half of this
    // lint. The roster is the authority list every privatization is checked
    // against, so enumerating it is a target-selection read even though it
    // mutates nothing.
    //
    // Only the two REQUEST-PATH crates are scanned. `epigraph-cli/src/bin` is
    // forced onto the maintenance pool by `no_unmaintained_dsn.rs` and reading
    // the roster there IS the operator CLI's job, and `epigraph-jobs/src` is
    // 18c's chartered surface — banning a read it may legitimately need would be
    // a rule written ahead of the decision that owns it. The write half scans
    // all four because a grant is never legitimate outside the operator CLI.
    const BANNED_READS: &[&str] = &["InstanceAdminRepository::list", "FROM instance_admins"];
    const READ_ROOTS: usize = 2;
    // THE ROOT SET IS THE FINDING, NOT THE NEEDLE LIST. An earlier revision
    // scanned `epigraph-api/src` and `epigraph-mcp/src` only — the two APP-POOL
    // crates, where 083's REVOKE and its `epigraph_bypass()`-only write policies
    // deny the write with `42501` no matter what the source says. The lint was
    // redundant exactly where it looked and absent everywhere it would have
    // bitten: `epigraph-jobs/src` runs on the MAINTENANCE pool (`bin/server.rs`
    // builds `job_pool` from `maintenance_url`, and the tree's own `jobs_app`
    // ROW_ONLY_BY_DESIGN note says so), and `no_unmaintained_dsn.rs` actively
    // FORCES every `epigraph-cli/src/bin` target onto it. On those pools
    // `epigraph_bypass()` is true and the grant SUCCEEDS.
    //
    // The realistic shape of the threat this lint's own failure message names is
    // a route that ENQUEUES a job with the grant in the handler — and 18c is
    // chartered to add `epigraph-jobs/src/privatization.rs`. So both pools are
    // scanned, with one exact allowance for the single intended writer.
    let roots = [
        concat!(env!("CARGO_MANIFEST_DIR"), "/../epigraph-api/src"),
        concat!(env!("CARGO_MANIFEST_DIR"), "/../epigraph-mcp/src"),
        concat!(env!("CARGO_MANIFEST_DIR"), "/../epigraph-jobs/src"),
        concat!(env!("CARGO_MANIFEST_DIR"), "/../epigraph-cli/src"),
    ];
    // The operator CLI: the one intended writer. The allowance is a path suffix
    // rather than a file name so a second `instance_admin.rs` elsewhere in the
    // scanned tree does not inherit it.
    const ALLOWED: &str = "epigraph-cli/src/bin/instance_admin.rs";

    let mut offenders: Vec<String> = Vec::new();
    for (idx, root) in roots.into_iter().enumerate() {
        // `roots` is ordered api, mcp, jobs, cli; the first `READ_ROOTS` are the
        // request-path crates that the read half applies to. Pinned rather than
        // matched on the path string so reordering `roots` cannot silently move
        // the read ban onto the operator CLI.
        let reads_banned = idx < READ_ROOTS;
        let sources = rust_sources(std::path::Path::new(root));
        // VACUITY GUARD. `rust_sources` returns an empty `Vec` when `read_dir`
        // fails, so a crate rename or a moved `src` would silently turn this
        // whole test into `assert!(vec![].is_empty())` — in the one file whose
        // stated purpose is refusing vacuous assertions. Every other lint here
        // goes through `read`, which panics on a missing path and therefore
        // cannot go quiet.
        assert!(
            !sources.is_empty(),
            "scan root {root} yielded no .rs files; the lint would pass vacuously"
        );
        for path in sources {
            let display = path.display().to_string();
            if display.replace('\\', "/").contains(ALLOWED) {
                continue;
            }
            // Collapse runs of whitespace before matching. The needles are exact
            // substrings, so a raw SQL literal wrapped as `INSERT INTO\n
            // instance_admins` would evade every one of them; the module's
            // `code_lines` convention already concedes these scanners are
            // textual approximations, and here the approximation and the root
            // set were failing in the same direction.
            let src = read(path.to_str().expect("utf-8 path"));
            let flat = src.split_whitespace().collect::<Vec<_>>().join(" ");
            let applicable = BANNED
                .iter()
                .chain(if reads_banned { BANNED_READS } else { &[] });
            for needle in applicable {
                if flat.contains(needle) {
                    offenders.push(format!("{display}: {needle}"));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a literal-source scan over epigraph-api/src, epigraph-mcp/src, epigraph-jobs/src and \
         epigraph-cli/src found a banned instance_admins reference. WHAT THIS MEASURES: exact \
         substrings, after whitespace collapse, with one path allowance for the operator CLI — \
         so an aliased import (`use … as Admins; Admins::grant`) or a `format!`-built table name \
         walks past it, and the DATABASE controls are the real boundary (083's REVOKE plus \
         write policies whose only disjunct is epigraph_bypass(), asserted behaviourally in \
         privatization_authz.rs). WHY THE RULE: granting the D4 authority is an operator action \
         taken out of band, over epigraph_maintenance, through the epigraph-instance-admin CLI — \
         a route that could grant it would let a token escalate itself into the authority the \
         token is checked against, and a job handler on the maintenance pool is the same \
         escalation with one hop of indirection. The read ban covers the two request-path crates \
         only: on the maintenance pool `list` returns the entire roster, which is the authority \
         list every privatization is checked against. Offenders: {offenders:?}"
    );
}

/// Every `.rs` file under `dir`, recursively. `read` below takes a path string,
/// so this yields owned paths rather than borrowing an iterator's temporary.
fn rust_sources(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

// Nothing to assert at PR-04: none of those objects exists yet. Migration 062
// creates `tenancy_transcription_log` as an empty ledger; `tenancy_migration_shape.rs`
// pins its shape.

// ===========================================================================
// D1 — nothing is authorized by absence, omission, or default-on-error
// ===========================================================================

/// D1, write half: the kernel's default write gate is a **denial**, and the
/// allow-all is not compiled into a production binary.
///
/// Before PR-11 the default was `NoOpPolicyGate`, whose `check()` returned
/// `Ok(true)` for every `(agent, action, resource)`. That is "public by
/// omission" for writes — the same defect D1 names at `access_control.rs:68`,
/// one layer up — and it went unnoticed for as long as it did precisely because
/// nothing ever called it, so no test could observe the verdict.
///
/// A text scan is the right instrument for the same reason as
/// [`d3_viewer_has_no_infallible_constructor`]: the assertions are about what
/// must be ABSENT, and there is no type to name when the point is that a
/// production build must not contain one.
#[test]
fn d1_the_kernel_write_gate_is_not_an_allow_all() {
    let raw = read(INTERFACES_POLICY_RS);
    let code = strip_line_comments(&raw);

    assert!(
        code.contains("pub struct DenyAllPolicyGate"),
        "the kernel default write gate must be a deny-all; if it was renamed, \
         update this assertion in the same commit and say in the PR body which \
         way the default now falls"
    );
    assert!(
        !code.contains("pub struct NoOpPolicyGate"),
        "`NoOpPolicyGate` returned Ok(true) unconditionally and was the \
         kernel default. It must not come back under that name or any other \
         un-cfg'd allow-all."
    );

    // The allow-all survives, and is reachable only under a cfg. The assertion
    // is on the ATTRIBUTE immediately preceding the definition, not merely on
    // the presence of the string somewhere in the file.
    let at = code
        .find("pub struct AllowAllPolicyGate")
        .expect("AllowAllPolicyGate must still exist — plan §2.7 keeps it for tests");
    let preceding = &code[..at];
    assert!(
        preceding
            .rfind("#[cfg(any(test, feature = \"insecure-allow-all\"))]")
            .is_some_and(|c| preceding[c..].matches('\n').count() <= 3),
        "`AllowAllPolicyGate` must be immediately preceded by \
         #[cfg(any(test, feature = \"insecure-allow-all\"))]"
    );

    // Nothing in the workspace may turn that feature on. A cargo feature CAN be
    // enabled from a dependent crate's build graph — the hazard
    // `Viewer::test_scoped` avoids by using `#[cfg(test)]` on its definition —
    // so the cfg alone is not the control; this is.
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let mut enablers = Vec::new();
    for entry in walk_manifests(std::path::Path::new(root)) {
        let text = read(entry.to_str().expect("utf-8 path"));
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            // The declaration in epigraph-interfaces' own [features] table is
            // the definition, not an enablement.
            if line.starts_with("insecure-allow-all = ") {
                continue;
            }
            if line.contains("insecure-allow-all") {
                enablers.push(format!("{}: {line}", entry.display()));
            }
        }
    }
    assert!(
        enablers.is_empty(),
        "\n\nA manifest in this workspace enables `insecure-allow-all`, which \
         compiles an allow-everything write gate:\n{}\n",
        enablers.join("\n")
    );
}

/// Every `Cargo.toml` under the workspace root, skipping `target/`.
fn walk_manifests(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if name == "target" || name == ".git" || name.starts_with('.') {
                    continue;
                }
                stack.push(path);
            } else if name == "Cargo.toml" {
                out.push(path);
            }
        }
    }
    out.sort();
    assert!(
        out.len() > 10,
        "expected to find the workspace's manifests, found {}",
        out.len()
    );
    out
}

// =============================================================================
// D1 / D2 — PR-12: the stamping triggers are armed, and the transition form is
// still the transition form.
//
// Plan §0.2 requires every PR that touches a locked decision to extend this
// file. PR-12 arms the write-side stamping D1 depends on and performs the D2
// backfill, so both are locked here.
// =============================================================================

/// D1 — plan §8.2 acceptance **A5**: every tenancy trigger is `tgenabled = 'O'`.
///
/// D1 is "nothing is public by absence, omission, or default-on-error", and
/// after PR-12 the mechanism enforcing it on the write side is a set of
/// triggers. `ALTER TABLE … DISABLE TRIGGER` is a one-line, in-band way to
/// revert that whole decision with no diff and no migration — precisely the
/// shape this file exists to catch. A disabled stamping trigger is
/// indistinguishable from an absent one at the row level.
///
/// The count is pinned, not just the enabled-ness: an assertion that "no
/// tenancy trigger is disabled" passes vacuously on a database that has none.
#[sqlx::test(migrations = "../../migrations")]
async fn d1_tenancy_stamping_triggers_are_armed(pool: PgPool) {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT t.tgname, t.tgenabled::text FROM pg_trigger t \
          WHERE NOT t.tgisinternal \
            AND (t.tgname IN ('claims_require_tenancy', 'edges_tenancy', \
                              'claims_propagate_tenancy') \
                 OR t.tgname LIKE '%\\_inherit\\_tenancy') \
          ORDER BY t.tgname",
    )
    .fetch_all(&pool)
    .await
    .expect("read pg_trigger");

    // 20 SINCE PR-22, NOT 21, AND THE FOURTH NAME IS GONE FROM THE IN-LIST.
    //
    // `ownership_transcribe` (migration 071) was the fourth named trigger.
    // Migration 084 drops `public.ownership`, which drops the trigger with it,
    // so the number had to move. It is stated here rather than merely edited
    // because that is exactly the "silent edit" this assertion's own message
    // warns about: the count changed for a REASON, and the reason is that the
    // relation the trigger guarded no longer exists — not that arm (c)'s table
    // set moved. The name is removed from the IN-list as well, so the query no
    // longer looks for a trigger that cannot exist; leaving it would have made
    // the count self-fulfilling.
    //
    // 21 SINCE MIGRATION 089, AND ARM (c)'s TABLE SET DID NOT MOVE.
    //
    // This assertion's message demands a decision rather than a silent edit, so
    // here is the decision. Arm (c) still covers exactly the 17 tier-A tables
    // carrying a `claim_id`; `harvester_fragments` has none and still cannot be
    // one of them. What 089 adds is a SECOND AFTER INSERT trigger on
    // `harvester_claim_provenance` — which already has arm (c)'s — stamping the
    // `harvester_fragments` row that provenance row points at, from the same
    // claim. That is the one write moment neither arm (c) (no `claim_id` to key
    // on) nor arm (d) (fires only when a claim's tenancy CHANGES) could reach,
    // and a fragment written before its provenance row was consequently stamped
    // by nothing.
    //
    // It is a D1 change in the direction D1 wants: strictly fewer ways for a row
    // to end up carrying no real owner, and it adds no way for one to become
    // public. That last clause is MEASURED and it is narrower than it looks: 062's
    // visibility CHECKs restrict claims and harvester_fragments alike to exactly
    // {public, group}, and harvester_fragments_group_needs_real_group makes a
    // sentinel-owned fragment necessarily public, so a stamp can only move a
    // fragment public -> public or public -> group. It is NOT the wider claim that
    // the stamp's effect is independent of who writes the provenance row; that is
    // a separate question, recorded as finding F-089-F in
    // docs/tenancy/progress.json with its location and owner.
    assert_eq!(
        rows.len(),
        21,
        "expected 21 tenancy triggers — 3 named (claims_require_tenancy, \
         edges_tenancy, claims_propagate_tenancy) plus one \
         *_inherit_tenancy per claim-derived tier-A table (17), plus migration \
         089's harvester_claim_provenance_fragment_inherit_tenancy. Found {}: \
         {rows:?}. A different count means migration 070 arm (c)'s table set \
         moved or 089's trigger is gone, which is a D1 change and needs a \
         decision, not a silent edit.",
        rows.len()
    );

    // PR-16. The query above cannot see migration 074's additions: its LIKE
    // pattern is `%_inherit_tenancy` and its IN list is 070's four names, so
    // the 23 new `<table>_require_tenancy` triggers and `claims_block_widening`
    // fall through both. Counted separately rather than by widening the pattern
    // above, so PR-12's number stays a statement about PR-12's trigger set and
    // this one about PR-16's — a single merged count would go green on the
    // wrong 24 as easily as the right one.
    let pr16: Vec<(String, String)> = sqlx::query_as(
        "SELECT t.tgname, t.tgenabled::text FROM pg_trigger t \
          WHERE NOT t.tgisinternal \
            AND (t.tgname LIKE '%\\_require\\_tenancy' \
                 OR t.tgname = 'claims_block_widening') \
          ORDER BY t.tgname",
    )
    .fetch_all(&pool)
    .await
    .expect("read pg_trigger for the PR-16 set");
    assert_eq!(
        pr16.len(),
        25,
        "expected 25 after migration 074: 24 *_require_tenancy (claims, the 17 \
         claim-derived tables, the 6 parentless roots) plus claims_block_widening. \
         Found {}: {pr16:?}",
        pr16.len()
    );
    let pr16_disabled: Vec<&(String, String)> = pr16.iter().filter(|(_, e)| e != "O").collect();
    assert!(
        pr16_disabled.is_empty(),
        "plan §8.2 A5 extends to migration 074's triggers: {pr16_disabled:?}"
    );

    let disabled: Vec<&(String, String)> = rows.iter().filter(|(_, e)| e != "O").collect();
    assert!(
        disabled.is_empty(),
        "plan §8.2 A5: every tenancy trigger must be ENABLED (tgenabled = 'O'). \
         These are not: {disabled:?}"
    );
}

/// **INVERTED BY PR-16.** This asserted, for PR-12, that migration 070 had
/// shipped the TRANSITION form and that `claims.owner_group_id` still carried
/// its DEFAULT. Migration 074 makes both false by design, and the assertion is
/// replaced by its end-state twin rather than deleted — the staging strategy is
/// the decision, and a decision that stops being pinned when it completes is a
/// decision nobody can later show was made.
///
/// What PR-12's version was protecting: shipping the final form early would
/// have turned thirteen production `INSERT INTO claims` call sites and ~180
/// test statements into hard `23502`s on the day PR-12 landed, months before
/// PR-16's rollout. That risk is discharged, in this order:
/// the call sites were patched, `tenancy_undeclared_writes` was watched flat at
/// zero for 24 hours (plan §9.2 week 11b), and only then did 074 apply.
///
/// Read from `pg_proc.prosrc` and the catalog rather than from the file, so a
/// database whose functions were replaced out of band also fails.
#[sqlx::test(migrations = "../../migrations")]
async fn d1_the_stamping_trigger_is_the_final_form(pool: PgPool) {
    let src: String = sqlx::query_scalar(
        "SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
          WHERE n.nspname = 'public' AND p.proname = 'epigraph_claims_require_tenancy'",
    )
    .fetch_one(&pool)
    .await
    .expect("epigraph_claims_require_tenancy must exist after migration 070");

    assert!(
        !src.contains("RAISE WARNING"),
        "after migration 074 the undeclared arm must RAISE, not warn. A surviving \
         `RAISE WARNING` means 074's CREATE OR REPLACE did not take — the DEFAULTs \
         are gone but the trigger still expects them, so `NEW.visibility` is NULL, \
         no arm matches, and every undeclared write dies on a bare NOT NULL \
         violation with no diagnosis instead of on the tenancy message."
    );
    assert!(
        src.contains("23502") && src.contains("docs/tenancy.md"),
        "the final form's terminal arm must raise 23502 and HINT at \
         docs/tenancy.md#declaring-visibility-on-write. The SQLSTATE is what keeps \
         the failure classified as a CLIENT error; the hint is what makes it \
         actionable."
    );
    assert!(
        src.contains("epigraph_seed"),
        "arm 4 (the seed escape hatch) must survive. Without it every undeclared \
         test fixture in the workspace raises."
    );

    // Ordering, read structurally: the predecessor arm must appear BEFORE the
    // "fully declared" short-circuit. Plan §3's body has them the other way
    // round, and with that order an INSERT binding `supersedes` to a private
    // claim AND declaring ('public', world) is accepted — a one-statement
    // declassification. `tenancy_required.rs::
    // an_explicitly_public_successor_over_a_private_predecessor_is_refused`
    // asserts the behaviour; this asserts the structure that produces it, so a
    // reordering is caught even if that test is ever weakened.
    let supersedes_at = src
        .find("NEW.supersedes IS NOT NULL")
        .expect("the predecessor arm must exist");
    let declared_at = src
        .find("NEW.visibility IS NOT NULL AND NEW.owner_group_id IS NOT NULL")
        .expect("the fully-declared arm must exist");
    assert!(
        supersedes_at < declared_at,
        "the `supersedes` arm must run BEFORE the fully-declared arm. Reversed, a \
         writer escapes the no-widening check simply by naming both columns."
    );
}

/// D1, the half PR-05 could not assert: **no tier-A tenancy column carries a
/// default, and no claim is world-owned.**
///
/// This is the hook PR-05 left in the comment block above, and it is plan
/// §8.2's A1 and A4. It is duplicated from `tenancy_required.rs` on purpose:
/// that file is PR-16's acceptance suite and could reasonably be deleted once
/// the release ships; this file is the ledger of locked decisions and may not.
/// A `DEFAULT` reinstated on a tier-A tenancy column is D1 being relitigated in
/// `pg_attrdef`, where no code review would see it.
#[sqlx::test(migrations = "../../migrations")]
async fn d1_no_tier_a_tenancy_column_carries_a_default(pool: PgPool) {
    let offenders: Vec<(String, String, Option<String>, String)> = sqlx::query_as(
        "SELECT table_name, column_name, column_default, is_nullable \
           FROM information_schema.columns \
          WHERE table_schema = 'public' \
            AND column_name IN ('visibility','owner_group_id') \
            AND (column_default IS NOT NULL OR is_nullable = 'YES') \
          ORDER BY table_name, column_name",
    )
    .fetch_all(&pool)
    .await
    .expect("A1 probe");
    assert!(
        offenders.is_empty(),
        "plan §8.2 A1 / decision D1: a tier-A tenancy column regained a DEFAULT or \
         became nullable. That is 'public by omission' one layer below the code — \
         the exact defect D1 names — and it makes the require-tenancy triggers \
         unreachable, because the column is never NULL inside a BEFORE trigger. \
         Offenders: {offenders:?}"
    );

    let world: uuid::Uuid = sqlx::query_scalar("SELECT id FROM groups WHERE kind = 'world'")
        .fetch_one(&pool)
        .await
        .expect("the world group is seeded by migration 062");
    let world_owned: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM claims WHERE owner_group_id = $1")
            .bind(world)
            .fetch_one(&pool)
            .await
            .expect("A4 probe");
    assert_eq!(
        world_owned, 0,
        "plan §8.2 A4: no claim may be owned by the world group. The world group is \
         memberless by design, so a world-owned claim has no owner any \
         privatization plan or RLS policy can act on. Migration 074 arm 4 stamps the \
         SEED group for exactly this reason."
    );
}

/// D2 — the backfill's target is the author's personal group, and the seed
/// group is NOT it.
///
/// Both nil-flavoured groups must exist and must remain memberless, because
/// that is what makes `('group', world)` and `('group', seed)` black holes and
/// what migration 062's `<table>_group_needs_real_group` CHECK is protecting.
/// A PR that gives seed memberships changes what PR-16's migration 074 arm 4
/// means, and this is where that is caught.
#[sqlx::test(migrations = "../../migrations")]
async fn d2_world_and_seed_remain_memberless(pool: PgPool) {
    for kind in ["world", "seed"] {
        let group: uuid::Uuid = sqlx::query_scalar("SELECT id FROM groups WHERE kind = $1")
            .bind(kind)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("migration 062 seeds the {kind} group: {e}"));

        let members: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM group_memberships WHERE group_id = $1 AND revoked_at IS NULL",
        )
        .bind(group)
        .fetch_one(&pool)
        .await
        .expect("count memberships");

        assert_eq!(
            members, 0,
            "the {kind} group must stay memberless by design. It is a SHAPE \
             CONSTANT, not an owner; giving it members would make ('group', \
             {kind}) look readable and quietly relitigate D2's choice of the \
             author's personal group as the backfill target."
        );
    }
}

// =============================================================================
// D1 — PR-13: the co-ownership column narrows, and can never widen.
//
// Plan §0.2 requires every PR that adds a tenancy column to extend this file.
// `edges.co_owner_group_id` (migration 072) is one.
// =============================================================================

/// D1 — `edges.co_owner_group_id` has NO `DEFAULT`, and NULL cannot widen.
///
/// The nullable column is the part of PR-13 that most resembles the thing D1
/// forbids: "nothing is public by absence, by omission, or by
/// default-on-error". Three catalog facts are what make it not that, and all
/// three are one edit away from being untrue:
///
/// 1. **No `column_default`.** 062's DEFAULTs on `owner_group_id` /
///    `visibility` are the transition form PR-16's 074 removes; adding one here
///    would be a NEW implicit declaration, arriving after the decision to stop
///    making them. There is also nothing a default could sensibly say — a
///    co-owner is derived from two endpoints, never assumed.
/// 2. **`owner_group_id` is still NOT NULL.** Co-ownership adds a SECOND owner;
///    it never replaces the first. A row whose only ownership signal were a
///    nullable column would be exactly the absence-means-public shape.
/// 3. **`edges_co_owner_shape` requires `visibility = 'group'`.** A co-owner on
///    a `visibility = 'public'` row is rejected, so the column cannot be read as
///    a restriction on an otherwise-public edge — the read fragment's leading
///    `visibility = 'public'` disjunct short-circuits before the co-owner test,
///    and this CHECK is what stops those two facts from disagreeing.
///
/// Together: a NULL co-owner degrades to the pre-072 single-owner predicate,
/// which is strictly narrower than public. The behavioural half of this lives
/// in `privatization_boundary.rs`; this is the catalog half, which survives a
/// database whose column was altered out of band.
#[sqlx::test(migrations = "../../migrations")]
async fn d1_the_co_owner_column_has_no_default_and_cannot_widen(pool: PgPool) {
    let (nullable, default): (String, Option<String>) = sqlx::query_as(
        "SELECT is_nullable, column_default FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'edges' \
            AND column_name = 'co_owner_group_id'",
    )
    .fetch_one(&pool)
    .await
    .expect("edges.co_owner_group_id must exist after migration 072");

    assert_eq!(
        nullable, "YES",
        "NULL is the single-owner case and must stay expressible; NOT NULL here \
         would force every edge to name a second group it does not have"
    );
    assert_eq!(
        default, None,
        "a DEFAULT on co_owner_group_id would be a new implicit tenancy \
         declaration, which is the D1 shape migration 074 exists to remove"
    );

    let owner_nullable: String = sqlx::query_scalar(
        "SELECT is_nullable FROM information_schema.columns \
          WHERE table_schema = 'public' AND table_name = 'edges' \
            AND column_name = 'owner_group_id'",
    )
    .fetch_one(&pool)
    .await
    .expect("edges.owner_group_id");
    assert_eq!(
        owner_nullable, "NO",
        "the FIRST owner stays NOT NULL: co-ownership adds an owner, it does \
         not make ownership optional"
    );

    // The shape CHECK exists, is now VALIDATED (PR-16's migration 076), and
    // still names both conjuncts.
    let (src, validated): (String, bool) = sqlx::query_as(
        "SELECT pg_get_constraintdef(oid), convalidated FROM pg_constraint \
          WHERE conrelid = 'public.edges'::regclass AND conname = 'edges_co_owner_shape'",
    )
    .fetch_one(&pool)
    .await
    .expect("edges_co_owner_shape must exist after migration 072");

    // INVERTED BY PR-16. PR-13 asserted this stayed NOT VALID, with the reason
    // that `VALIDATE CONSTRAINT` takes a full-table scan migration 072 did not
    // advertise. That reason named PR-16's 075/076 as where the scan belongs,
    // and 076 is now that file — so the assertion turns over rather than being
    // deleted, and the decision (validate LATE, in its own deploy step, never
    // inside the migration that adds the column) stays pinned by both halves.
    assert!(
        validated,
        "edges_co_owner_shape is still NOT VALID after migration 076. NOT VALID \
         constraints ARE enforced on new rows, so this is not an open write hole \
         — what it leaves unchecked is the EXISTING corpus, where a co-owned edge \
         with a malformed owner/co-owner pair would survive into RLS."
    );
    assert!(
        src.contains("co_owner_group_id IS NULL"),
        "the single-owner case must be permitted: {src}"
    );
    assert!(
        src.contains("visibility)::text = 'group'::text") || src.contains("visibility = 'group'"),
        "a co-owner is only meaningful on a group-visible row; without this \
         conjunct a public edge could carry a co-owner the read fragment never \
         checks: {src}"
    );
    assert!(
        src.contains("co_owner_group_id <> owner_group_id"),
        "co_owner = owner is not co-ownership; permitting it would make the \
         read fragment test one group's membership twice: {src}"
    );
}

// ===========================================================================
// D4 — the FORCE array (PR-17)
// ===========================================================================

/// Every relation the migrations FORCE, transcribed.
///
/// A test that read the array back out of the catalog would agree with the
/// migration by construction, including when the migration is wrong. This is
/// the third independent copy — the other two are `docs/runbooks/079-undo.sql`
/// and `epigraph_api::state::FORCE_PROTECTED_SET` — and the assertion below
/// pins all of them to 062's `tier_a` plus a named ten plus a named four.
///
/// # This stopped being "migration 079's array" at PR-18a
///
/// It was that until 080–083 landed. It is not any single migration's array
/// now, and the rename is not cosmetic: the third assertion below compares this
/// constant to **every** `relforcerowsecurity` relation in `public`, so the
/// referent has to be the catalog's set rather than one file's transcription.
///
/// 079 is applied and therefore frozen — `migrations/README.md` states the rule
/// and the checksum failure editing it causes — so the four privatization tables
/// could not be added to it. They FORCE themselves at creation instead, which is
/// the instrument 078 established for `rls_canary` and which 079's own header
/// names. A table added from 080 onward belongs in ITS OWN migration and here,
/// never in 079.
const FORCE_PROTECTED_SET: &[&str] = &[
    "claims",
    "evidence",
    "edges",
    "triples",
    "entity_mentions",
    "claim_versions",
    "mass_functions",
    "ds_combined_beliefs",
    "ds_bayesian_divergence",
    "claim_frames",
    "harvester_claim_provenance",
    "challenges",
    "reasoning_traces",
    "experiment_triples",
    "experiment_entity_mentions",
    "claim_clusters",
    "claim_cluster_membership",
    "claim_neighborhood_membership",
    "claim_signature_revocations",
    "harvester_fragments",
    "frames",
    "contexts",
    "perspectives",
    "communities",
    "recall_events",
    "groups",
    "group_memberships",
    "group_key_epochs",
    "agents",
    "jobs",
    "security_events",
    "claim_encryption",
    "claim_version_encryption",
    "evidence_encryption",
    "edge_encryption",
    "privatization_plans",
    "privatization_plan_items",
    "privatization_audit",
    "instance_admins",
    "operator_links",
];

/// The ten non-`tier_a` members 079 FORCEs, named so the arithmetic below is
/// checkable.
const CONTROL_TABLES: &[&str] = &[
    "groups",
    "group_memberships",
    "group_key_epochs",
    "agents",
    "jobs",
    "security_events",
    "claim_encryption",
    "claim_version_encryption",
    "evidence_encryption",
    "edge_encryption",
];

/// The four D4 tables 080, 082 and 083 create and FORCE (PR-18a).
///
/// A THIRD TERM RATHER THAN FOUR MORE `CONTROL_TABLES`. Folding them in would
/// make "the ten" fourteen and that constant's own doc comment false, and it
/// would erase the one fact worth keeping visible: these tables are FORCEd by a
/// DIFFERENT MECHANISM. 079 flips its thirty-five in one applied, frozen file;
/// these three migrations each flip the table they create. A reader who cannot
/// see that distinction goes looking for them in 079's array, does not find
/// them, and concludes the array is wrong.
///
/// None of the four joins `tier_a`: the catalog probe below recovers `tier_a` as
/// the relations carrying columns spelled exactly `visibility` and
/// `owner_group_id`, and these tables spell theirs `before_visibility` /
/// `after_visibility` / `before_owner_group_id` / `after_owner_group_id`,
/// because they RECORD a tenancy transition rather than carry one. `tier_a`
/// stays 25 and the assertion below still measures what it did before.
const PRIVATIZATION_TABLES: &[&str] = &[
    "privatization_plans",
    "privatization_plan_items",
    "privatization_audit",
    "instance_admins",
];

/// The operator-link record migration 102 creates and FORCEs.
///
/// A FOURTH TERM, for the reason [`PRIVATIZATION_TABLES`] is a third: it is
/// FORCEd by the migration that creates it, not by 079, and it is neither a
/// 079 control table nor a D4 privatization table. It carries no `visibility`
/// / `owner_group_id` columns, so it does not join `tier_a` either.
const OPERATOR_TABLES: &[&str] = &["operator_links"];

/// **D4, locked.** The FORCEd set is exactly 062's `tier_a` ∪ the control
/// tables ∪ the privatization tables, and it is exactly what the catalog
/// reports.
///
/// A table added to 062's generators and not to the arrays fails here, which is
/// the property the plan asks `locked_decisions.rs` to hold.
///
/// `tier_a` is recovered from the CATALOG — the relations carrying both tenancy
/// columns — rather than by parsing 062, because that is the same set 062's loop
/// produces and it cannot drift from what the database actually has.
///
/// # Why the third assertion stayed TOTAL at PR-18a
///
/// The catalog probe below excludes exactly one relation, `rls_canary`, and it
/// was tempting to exclude the four privatization tables the same way and leave
/// `declared` at thirty-five. That would have converted a total invariant — the
/// catalog's FORCEd set IS the declared set — into a partial one, and the next
/// self-FORCEing table declared nowhere would then pass silently. `rls_canary`
/// is excluded because it must stay FORCEd through the kill switch, which is a
/// property of the ROLLBACK and not an exemption from declaration; these four
/// have no such property. So the set grew instead.
#[sqlx::test(migrations = "../../migrations")]
async fn d4_the_force_array_is_tier_a_plus_the_control_tables(pool: PgPool) {
    let tier_a: BTreeSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = 'public' AND c.relkind IN ('r','p') \
            AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid \
                          AND a.attname = 'visibility' AND NOT a.attisdropped) \
            AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid \
                          AND a.attname = 'owner_group_id' AND NOT a.attisdropped)",
    )
    .fetch_all(&pool)
    .await
    .expect("tier_a probe")
    .into_iter()
    .collect();
    assert_eq!(
        tier_a.len(),
        25,
        "migration 062's tier_a is 25 relations; got {}: {tier_a:?}",
        tier_a.len()
    );

    let expected: BTreeSet<String> = tier_a
        .iter()
        .cloned()
        .chain(CONTROL_TABLES.iter().map(|s| (*s).to_string()))
        .chain(PRIVATIZATION_TABLES.iter().map(|s| (*s).to_string()))
        .chain(OPERATOR_TABLES.iter().map(|s| (*s).to_string()))
        .collect();
    let declared: BTreeSet<String> = FORCE_PROTECTED_SET
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(
        declared, expected,
        "the FORCEd set must be 062's tier_a union the ten control tables union the four \
         privatization tables union the operator-link table. If a table was ADDED to the generators: FORCE it IN ITS OWN \
         MIGRATION — 079_rls_force.sql is APPLIED and editing it changes its checksum, which \
         makes the next `sqlx migrate run` refuse to start; 078 set the precedent by FORCEing \
         rls_canary at creation and 080/082/083 followed it. Then add the name to \
         docs/runbooks/079-undo.sql, epigraph_api::state::FORCE_PROTECTED_SET, \
         rls_enforcement.rs::PROTECTED (with a DELIBERATELY_UNCOVERED row per uncovered \
         command) and this constant — all four, in the same commit as the migration."
    );

    let forced: BTreeSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
          WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND c.relforcerowsecurity \
            AND c.relname <> 'rls_canary'",
    )
    .fetch_all(&pool)
    .await
    .expect("forced probe")
    .into_iter()
    .collect();
    assert_eq!(
        forced, declared,
        "the catalog and the DECLARED FORCEd set disagree. The declared set is 062's tier_a \
         union the ten control tables union the four privatization tables union the \
         operator-link table — NOT migration \
         079's array, which names only the first two terms and is APPLIED and immutable. A \
         relation that appears here and nowhere in the declaration is a table that FORCEs \
         itself at creation without being declared; add it to PRIVATIZATION_TABLES (or to \
         CONTROL_TABLES, whichever it is) and to the three editable copies named in the \
         assertion above — never to 079. `rls_canary` is excluded on purpose: 078 FORCEs it at \
         creation and 079's array omits it, which is the precedent 080-083 follow."
    );
}

/// The kill switch and the migration loop the SAME array.
///
/// `AppState::assert_rls_posture` refuses to boot on a PARTIALLY FORCEd set, so
/// a `079-undo.sql` that missed a table would leave the cluster un-bootable —
/// turning the documented sub-minute rollback into an outage. This is a source
/// lint because the undo script is a runbook, never executed by the suite.
#[test]
fn d4_the_kill_switch_covers_the_same_relations_as_the_flip() {
    let raw = read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/runbooks/079-undo.sql"
    ));
    // Strip `--` comments before matching. The file's VERIFY section quotes the
    // relation names inside comments, including `rls_canary`, and a scanner
    // that read prose would find whatever the prose happened to mention.
    let undo: String = raw
        .lines()
        .map(|l| match l.find("--") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        undo.contains("NO FORCE ROW LEVEL SECURITY"),
        "079-undo.sql must pull the documented kill switch"
    );
    let missing: Vec<&str> = FORCE_PROTECTED_SET
        .iter()
        .copied()
        .filter(|t| !undo.contains(&format!("'{t}'")))
        .collect();
    assert!(
        missing.is_empty(),
        "docs/runbooks/079-undo.sql does not name these FORCEd relations: {missing:?}. A \
         partial undo leaves a strict subset FORCEd, which is the state the boot assertion \
         refuses on — the rollback would not come back up."
    );
    assert!(
        !undo.contains("'rls_canary'"),
        "079-undo.sql must NOT un-FORCE rls_canary: the canary would become visible to the \
         owner and the boot probe would report a false alarm during the rollback itself"
    );
}

// ===========================================================================
// D4 — PR-24's claim that migration 086 installs no policy
// ===========================================================================

/// Migration 086 adds a `SECURITY DEFINER` read helper and touches no policy.
///
/// The `## Status at PR-24` block above states this as fact. §0.2's rejection
/// trigger fires on *"a PR that changes an RLS policy … and does not touch this
/// file"*, so the honest discharge is an assertion, not a sentence: a later
/// edit that slipped a `CREATE POLICY` or an `ALTER TABLE … FORCE` into 086
/// would make that block false while every other test stayed green, and 086 is
/// applied by all ~1000 `#[sqlx::test(migrations = "../../migrations")]`
/// attributes in this workspace, so its blast radius is the whole suite.
///
/// Read from the migration SOURCE, not from `pg_policy`: a catalog read would
/// agree with the migration by construction, and it could not distinguish
/// "086 installs no policy" from "086 installs one that 079 already installed".
///
/// `--` comments are stripped first, for the same reason
/// [`strip_line_comments`] does it for Rust — 086's header discusses
/// `claims_tenancy` and its `USING` clause at length, and a scanner that read
/// prose would find whatever the prose happened to mention. Note that
/// [`strip_line_comments`] itself keys on `//` and is therefore the WRONG tool
/// on a `.sql` file; this is the same inline `--` strip
/// [`d4_the_kill_switch_covers_the_same_relations_as_the_flip`] uses.
#[test]
fn d4_migration_086_installs_no_policy() {
    let raw = include_str!("../../../migrations/086_claim_tenancy_definer.sql");
    let sql = raw
        .lines()
        .map(|l| match l.find("--") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
        .to_uppercase();

    for banned in [
        "CREATE POLICY",
        "DROP POLICY",
        "ALTER POLICY",
        "ROW LEVEL SECURITY",
        "ALTER TABLE",
        "ADD COLUMN",
    ] {
        assert!(
            !sql.contains(banned),
            "migration 086 contains `{banned}`. The `Status at PR-24` block in this file's \
             module doc asserts that it adds no policy, no FORCE flip and no tenancy column, \
             and that claim is now false. Either revert the statement or rewrite the block — \
             do not delete this assertion."
        );
    }

    // Inverted half: the assertion must not pass because the file moved or emptied.
    assert!(
        sql.contains("CREATE OR REPLACE FUNCTION PUBLIC.EPIGRAPH_CLAIM_TENANCY_BY_IDS")
            && sql.contains("SECURITY DEFINER")
            && sql.contains("REVOKE EXECUTE ON FUNCTION"),
        "086 must still be the definer helper it is documented to be, or the negative \
         assertions above are vacuous"
    );
    // The three parts of 077's idiom that are load-bearing rather than stylistic:
    // the frame's authority comes from its OWNER, and the app role cannot call
    // it without an explicit grant (`grant_app_privileges` covers tables only).
    assert!(
        sql.contains("OWNER TO EPIGRAPH_MAINTENANCE")
            && sql.contains("GRANT EXECUTE ON FUNCTION")
            && sql.contains("SET SEARCH_PATH = PUBLIC, PG_TEMP"),
        "086 must keep the guarded OWNER TO, the GRANT EXECUTE and the pinned search_path. \
         The owner is what makes epigraph_definer_bypass() true inside the frame — it is the \
         MECHANISM, not hardening — and without the grant the app role gets 42501."
    );
}

// ===========================================================================
// D4 — migration 092's narrowing of the group-creation bootstrap arm
// ===========================================================================

/// **D4, locked.** The bootstrap arm is bounded by the roster in BOTH of its
/// spellings, and the three policies that carry it still cover every command.
///
/// This is the catalog half of 092. The behavioural half lives in
/// `rls_enforcement.rs::the_creator_arm_ends_with_the_creators_own_membership`
/// and its positive sibling; a catalog check proves the predicate is INSTALLED,
/// never that it FILTERS, which is why both exist (see this file's header and
/// `rls_enforcement.rs`'s "three classes").
///
/// Read from `pg_get_expr` and `pg_proc.prosrc` rather than from the migration
/// text: 092 is one of ~1000 `#[sqlx::test(migrations = "../../migrations")]`
/// replays, and what matters is the predicate the database ENDED UP WITH after
/// 077 and 092 both ran — a later migration that reverted either spelling would
/// leave the migration text saying the right thing and the catalog saying the
/// wrong one.
///
/// **WHAT THIS TEST DELIBERATELY DOES NOT PIN: `proowner` and `proacl`.** It
/// greps `prosrc` for a predicate name, which survives any ownership change — so
/// it cannot see the one degradation that reverts 092 silently, a roster
/// predicate whose definer frame is not admitted by `epigraph_definer_bypass()`
/// and whose `NOT EXISTS` therefore admits every group. That pin is
/// `schema_contract.rs::migration_092_roster_definer_is_revoked_from_public`, on
/// the template 086 and 089 each established, and the deploy-time half is
/// `tenancy_backfill.rs::DEFERRED_DEFINER_FUNCTIONS`. Named here because a
/// reader who finds only this test would reasonably conclude 092 is fully
/// ratcheted by it.
///
/// **The `polcmd` assertion is not decoration.** `groups_tenancy` is a single
/// `FOR ALL` policy, so a narrowing written as DROP POLICY + CREATE POLICY that
/// forgot `FOR ALL` would silently drop INSERT/UPDATE/DELETE coverage while the
/// USING clause still read correctly. 092 uses `ALTER POLICY`, which cannot lose
/// it; this pins the outcome so a future re-issue cannot.
#[sqlx::test(migrations = "../../migrations")]
async fn d4_the_group_creation_bootstrap_arm_is_bounded_by_the_roster(pool: PgPool) {
    const ROSTER_PREDICATE: &str = "epigraph_group_roster_admits_principal";

    // Spelling one: the inline column comparison on `groups`.
    let (polcmd, using): (String, String) = sqlx::query_as(
        "SELECT p.polcmd::text, pg_get_expr(p.polqual, p.polrelid) \
           FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid \
          WHERE c.relname = 'groups' AND p.polname = 'groups_tenancy'",
    )
    .fetch_one(&pool)
    .await
    .expect("groups_tenancy must exist — 077 creates it and 092 amends it");

    assert_eq!(
        polcmd, "*",
        "groups_tenancy must still be FOR ALL. A re-issue that lost it would leave \
         INSERT/UPDATE/DELETE uncovered while the USING clause still read correctly, and \
         `rls_enforcement.rs::every_protected_relation_covers_every_command_or_records_why` \
         would then need a DELIBERATELY_UNCOVERED row that nobody wrote."
    );
    let creator_arm = using
        .split(" OR ")
        .find(|a| a.contains("created_by_agent_id"))
        .unwrap_or_else(|| {
            panic!(
                "groups_tenancy's USING clause no longer has a created_by_agent_id arm at all. \
                 Deleting it is NOT the fix: measured on 16.13, `INSERT … RETURNING` consults \
                 the USING clause, and `GroupRepository::create_with_admin` writes exactly \
                 that — group creation would be a total outage. USING was:\n{using}"
            )
        });
    assert!(
        creator_arm.contains(ROSTER_PREDICATE),
        "groups_tenancy's bootstrap arm is not bounded by the roster. \
         `groups.created_by_agent_id` is never rewritten, so an unbounded arm has no end and \
         outlives the creator's own membership — `D-PR17-creator-arm-outlives-membership`, \
         closed by migration 092. Arm was:\n{creator_arm}"
    );
    assert!(
        creator_arm.contains("epigraph_principal_id"),
        "the arm must still name a session helper in the SAME \" OR \"-delimited fragment, or \
         `rls_enforcement.rs::no_policy_arm_is_session_independent` reports it as an \
         unconditional grant. Write the bound as an AND inside the existing disjunct, never as \
         a sibling one. Arm was:\n{creator_arm}"
    );

    // Spelling two: the shared helper, which is what `group_memberships_tenancy`
    // and `group_key_epochs_tenancy` call. Narrowing only the policy above would
    // leave both of those exactly as 077 wrote them.
    let body: String = sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
          WHERE n.nspname = 'public' AND p.proname = 'epigraph_is_group_creator'",
    )
    .fetch_one(&pool)
    .await
    .expect("epigraph_is_group_creator must exist");
    assert!(
        body.contains(ROSTER_PREDICATE),
        "epigraph_is_group_creator is not bounded by the roster. It is the arm's OTHER \
         spelling: `group_memberships_tenancy` and `group_key_epochs_tenancy` reach the same \
         permission through it, in USING and in WITH CHECK, so a fix applied only to \
         groups_tenancy covers one of three tables and still passes a proof written against \
         that one. Body was:\n{body}"
    );

    // Vacuity guard, in both directions: the helper the two assertions above key
    // on must exist, be session-bound, and read `group_memberships` rather than
    // `groups` — reading `groups` is what makes it unusable in `groups_tenancy`'s
    // USING clause, because a STABLE function cannot see the row an
    // `INSERT … RETURNING` is inserting.
    let roster: (String, bool, String) = sqlx::query_as(
        "SELECT p.prosrc, p.prosecdef, p.provolatile::text \
           FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
          WHERE n.nspname = 'public' AND p.proname = $1",
    )
    .bind(ROSTER_PREDICATE)
    .fetch_one(&pool)
    .await
    .expect("the roster predicate must exist, or both assertions above are vacuous");
    assert!(
        roster.1 && roster.2 == "s",
        "{ROSTER_PREDICATE} must be STABLE SECURITY DEFINER: it reads group_memberships, which \
         is itself under RLS, and an invoker-rights body would make groups_tenancy depend on \
         group_memberships_tenancy, which calls back into groups. VOLATILE would say it writes."
    );
    assert!(
        roster.0.contains("group_memberships") && !roster.0.contains("FROM public.groups"),
        "{ROSTER_PREDICATE} must read group_memberships and NOT groups. The asymmetry is the \
         whole reason it is safe in a clause where epigraph_is_group_creator is not."
    );
    assert!(
        roster.0.contains("epigraph_principal_id"),
        "{ROSTER_PREDICATE} must bind its subject to the calling principal. Parameterised by \
         group and unbound to the session, it would admit any group with an empty roster to \
         anybody."
    );
}
