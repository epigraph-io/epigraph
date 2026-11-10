# Claim visibility controls: team by default, private and public on request, publish later

Status: built, 2026-11-05. Branch `feat/claim-visibility-controls`. Owner decisions D-V1..D-V5 are
recorded at the end (section 6), and the build follows them. Migration 206; `epigraph-db`
`repos/claim_visibility.rs`; MCP `tools/visibility.rs`; HTTP `routes/claim_visibility.rs`.

## 1. Problem

Every caller-facing claim write lands `('public', <author's personal group>)`:

* MCP `submit_claim`, `memorize`, `batch_submit_claims` reach
  `claim_helper::create_claim_idempotent`, which calls
  `ClaimRepository::default_decl_for_author`.
* MCP `ingest_document*` resolves the same declaration in `tools/ingestion.rs`.
* REST `POST /api/v1/submit` (`routes/submit.rs`) and the plain tier of `POST /api/v1/claims`
  (`routes/claims.rs`) do the same. `/claims` has an encrypted tier (`privacy_tier` + `group_id`)
  and nothing in between.

The owner wants agents and API callers to write to their **team** by default, with `private`
and `public` as explicit options. Owners must also be able to **publish** team work later.
Today no user-facing path can widen `group` → `public`. Migration 074's
`claims_block_widening` refuses it unless `epigraph.allow_declassify = 'yes'`. Only the
privatization revert and the operator CLI `restrict --reverse` set that GUC, and both run on
maintenance connections. Under D9 no request-serving process holds a maintenance connection.

## 2. Vocabulary

`Visibility` stays `Public | Group`. The three user-facing choices map onto
`(visibility, owner_group_id)`:

| choice    | visibility | owner_group_id                                                         |
|-----------|------------|------------------------------------------------------------------------|
| `team`    | `group`    | a team group the author writes (named by `group_id`, or the default)   |
| `private` | `group`    | the author's **home group**: its own personal group, or for an operated agent its operator's personal group (what `default_decl_for_author` resolves today) |
| `public`  | `public`   | the home group (today's behaviour, unchanged)                          |

A **team group** is an active group of kind `team` or `community` that the author may write:
the author holds a live `writer`/`admin` membership itself, or its live human does (D-V3). This
is migration 206's `epigraph_writable_teams(agent)`, and its `via` column says which. Role-derived
memberships (165/179) count. Personal, world and seed groups never do, so the home group is never
a team.

## 3. Part A: write-time visibility

### 3.1 Surface

New optional parameters on every caller-facing claim writer:

* `visibility`: `"team" | "private" | "public"`, optional.
* `group_id`: uuid, optional. Only meaningful with `team` (or with `visibility` omitted, when it
  implies `team`). Combining it with `private` or `public` is refused (`invalid_params` / 400).

Added to:

* MCP `submit_claim`, `memorize`, and `batch_submit_claims`. For the batch it is per entry:
  `tests/batch_submit_claims_parity.rs` requires an entry to accept every `submit_claim` field.
* MCP `ingest_document`, `ingest_document_inline` and `ingest_document_spine`. The setting applies
  to every claim the ingest creates. Claims it converges onto keep their own tenancy.
  `do_ingest_document` / `do_ingest_document_spine` keep writing public. They are the operator
  CLI's and the test harness's entry points (section 3.5). The tools call the
  `*_with_visibility` variants.
* REST `POST /api/v1/submit`, as top-level `visibility` / `group_id` packet fields. They are
  **outside** `signable_bytes`: a routing choice of the authenticated caller, so existing
  signatures still verify. A team must also be writable by the caller's own stamp.
* REST `POST /api/v1/claims`, on the plain tier only. There `group_id` names the team. The
  `fully_private` tier refuses `visibility`, because its `group_id` is the sealing group. A
  `derived_from` claim with no visibility named stays **public**: its parent must be public, and
  `decompose_claims` posts its atoms that way. A non-public `derived_from` is refused as before.

`submit_claim`, `memorize`, the batch entries, `POST /submit` and `POST /claims` responses gain
`visibility` (`team` / `private` / `public`), `owner_group_id`, and `visibility_note`. The note is
set when a default was resolved in a way the caller should know about (D-V1), or when an existing
claim was returned (D-V4). Ingest responses are unchanged.

### 3.2 Resolution (one function, every surface)

`ClaimRepository::resolve_write_decl(conn, author, VisibilityChoice)` in `epigraph-db`.
`VisibilityChoice` (`Default | Team(Option<Uuid>) | Private | Public`) lives in
`epigraph-core::tenancy`, next to `TenancyDecl`, so `epigraph-api --no-default-features` still
builds. The function first calls `default_decl_for_author`, so every existing refusal (OPL01,
OPL02, `MembershipRevoked`) still fires first, in the same order. That yields the home group `H`.
`resolve_visibility_choice` then answers the rest with pure definer reads, which also run on an
unstamped connection. The document ingest calls it directly, because its `owner_decl` resolves
`H` read-only.

* `Public` → `TenancyDecl::public(H)`, byte for byte today's answer.
* `Private` → `TenancyDecl::group(H)`.
* `Team(Some(g))` → `g` must be one of `epigraph_writable_teams(author)`. Then the result is
  `TenancyDecl::group(g)`. Otherwise the call is refused (`Authority`) with nothing written. The
  refusal says a reader membership does not admit writes, and does not say whether `g` exists.
* `Team(None)` / `Default` → D-V1. An explicit `Team(None)` that finds no single team is refused
  (`Input`), because the caller asked for a team. `Default` falls back to private, with a note.

Resolution runs **before** the author-stamped transaction opens. When the author writes the team
only through its human (`via = 'operator'`, D-V3), the result carries a `TeamWriteGrant`. Only
this function mints one. `claim_helper::begin_author_stamped_tx_for` then stamps the transaction
with `Viewer::with_team_write_grant`, which adds the team to the writable set and the read set.
The same widened viewer serves that one write's reads (the DS wiring, the read-backs). That way
077's `WITH CHECK` admits exactly what the claims trigger's writer scope
(`epigraph_require_writer_scope` → `epigraph_operator_writes_group`) already admits. No new GUC
and no new privilege.

### 3.3 Derived rows

These are unchanged and inherit from the claim. Evidence and reasoning traces get their tenancy
from 070 arm (c). The AUTHORED edge and every claim-to-claim edge take the endpoint meet
(070/072/120). An edge from a team claim to a public claim is therefore `('group', team)`.
Pinned evidence (110) is untouched.

`supersede_claim` keeps the original's tenancy (`TenancyDecl::inherited()`, as today). It takes
no `visibility` parameter: re-scoping a lineage is `publicize_claims` / `share_claims_with_team`
(below), not a side effect of a supersede.

`resolve_backlog_item` writes its resolution claim with the ORIGINAL's visibility: public stays
public, private stays private, and a team item gets a team resolution. A public item resolved
into a team would read as resolved to everyone, while only the team could read why.

### 3.4 Duplicates

`create_or_get` keys on `(content_hash, agent_id)`. A resubmission whose existing row has a
different tenancy from the one requested follows D-V4 (`ClaimRepository::write_tenancy_report`).
The novelty gate's "existing claim" answer reports no visibility. The dedup probes in
`tools/claims.rs` and `tools/memory.rs` are being changed by the "MCP dedup probes, raw-pool
writes and lint" session (worktree `fix/mcp-raw-pool-residuals`, uncommitted on 2026-11-05). This
branch does not touch those hunks. It resolves visibility just before them and threads the
declaration into `create_claim_idempotent`.

### 3.5 What does not change

These keep `default_decl_for_author` (public over the home group):

* the system-agent and registry writers: workflow ingest, which already has its own `tenancy`
  parameter; conventions; policies and challenges; hypothesis; and the CLI binaries, including
  the operator `ingest_document` CLI through `do_ingest_document`;
* `TenancyDecl` and the `Visibility` vocabulary;
* the database's widening, sealed and owner-immutability guards.

### 3.6 What changes for existing callers

Measured by the legacy suites on 2026-11-05. Every caller that names no `visibility` now writes
team-or-private, where it used to write public:

* **A writer that is not a team member now writes PRIVATE.** A test or client that writes as one
  agent and reads the claim as another (or as the public viewer) must send `"visibility":
  "public"`. About 80 legacy test sites now do, in `epigraph-mcp` and `epigraph-api`.
* **`POST /api/v1/submit/packet` from a delegated host** (token principal ≠ packet author, e.g.
  epiclaw-host's service client writing for its recorder agent into the human's group HG). The
  packet now lands private in HG. Where the host holds a writer membership in HG this works
  as before, except that the row is private. Where it holds none and a deployment still carries
  the legacy `*_privacy` policies, the insert is **refused**: those policies admitted it only
  because it was public. Owner ruling (2026-11-05): keep the private default. The host must
  send `visibility` or get a membership before this deploys
  (`host_writer_packets_armed.rs` Q0 pins the refusal). The same holds for the egress
  REVOKE: an admin client's standing `claims:admin` token with no HG membership gets 404 on
  a private approval (R1). An approval that must stay revocable that way has to be sent
  `public`.
* The `ingest_git` / `ingest_literature` CLIs post to `/submit`, so they now default to
  team/private too.
* **`create_claim_core`'s structural edges** (AUTHORED, HAS_TRACE, DERIVED_FROM) used to be
  written after the commit on the unstamped pool, best-effort. A group-visible claim is
  invisible there, so the edge's reference check refused them silently. For a group-visible
  claim they are now written on a viewer-stamped transaction, one per edge (still
  best-effort). Public claims keep the old path.
* A home group minted mid-request (an author's first write) is not in the viewer resolved at
  request start. `create_claim_core`, `persist_packet` and MCP `claim_helper::write_viewer`
  re-resolve the viewer once in that case, so the dedup find and the DS wiring see the row.

## 4. Part B: publish later (and share private work with a team)

### 4.1 Why a definer

Three guards stand between an application session and the publish act. Each is right for every
other path, so none is relaxed:

1. 074 `claims_block_widening` refuses `group → public` without `allow_declassify`, and refuses
   a sealed claim **unconditionally**.
2. 115 `<table>_owner_immutable` refuses any non-privileged change of `owner_group_id`. That is
   what `private → team` is.
3. 072/110/120 propagation copies the claim's new tenancy onto derived rows, but **never widens
   an edge** (`AND NOT (e.visibility = 'group' AND m.v = 'public')`). An edge between two claims
   that are now public would stay group-only. The privatization revert handles this with
   `recompute_boundary_meet_conn` on a maintenance connection, which request processes do not
   hold (D9).

So migration **206** adds five `SECURITY DEFINER` functions, all owned by
`epigraph_maintenance`, `SET search_path = pg_catalog, pg_temp` with every public object
schema-qualified (migration 190's ratchet), EXECUTE revoked from PUBLIC and granted to
`epigraph_app`:

* two reads, `epigraph_writable_teams(agent)` and `epigraph_default_group(agent)`, which must
  answer the same on an unstamped `epigraph_app` connection, where the membership and group
  policies hide every row;
* three writes, `epigraph_set_default_group(group)`, `epigraph_publicize_claims` (§4.2) and
  `epigraph_share_claims_with_team` (§4.3).

The three writes' `UPDATE`s open
a transaction-local "write window" (`search_path = public, pg_temp`) and close it straight
after, because the legacy invoker triggers they fire (`trigger_validate_edge_refs` →
`validate_edge_reference`) call unqualified functions and inherit the caller's path.
The pattern is the same as the existing definers (`epigraph_record_cascade_deferral`,
`epigraph_team_group_add_member`). Per `docs/tenancy.md#epigraph.allow_declassify`, the GUC is
an interlock and not an authorization. **The authorization is the function body.** It runs as
the session principal (`epigraph_principal_id()`), reads live memberships through
`epigraph_live_memberships`, and does not trust a caller-supplied identity.

The bodies keep their working set (the per-claim classification) in local variables and arrays,
never in a temporary table. A temporary table belongs to the calling session, not to the
function's owner, so a caller could create one of the same name first and have the body use it
with the owner's privileges. The same holds for an INVOKER function or trigger a definer runs,
since it runs as the definer's owner (the write window's `trigger_validate_edge_refs` →
`validate_edge_reference`). `definer_search_path_ratchet.rs`
(`no_function_keeps_state_in_a_session_temporary_relation`) refuses any such body that creates
or names a temporary relation: it scans every function outside the system schemas and
extensions, definer or not.

### 4.2 `epigraph_publicize_claims(p_claim_ids uuid[], p_reason text)`

For each claim, in one transaction and all-or-nothing:

The claims it may act on (the group-visible rows the session reads) are locked first, `FOR NO
KEY UPDATE` in id order. A row another session is changing is waited for, and the
classification then reads what that session committed, so an owner or visibility change cannot
slip in between the decision and the write.

Every id is classified first, in this order, and nothing changes unless every id comes out
`publicize` or `already_public`:

1. The row must exist and be readable by the session. Otherwise it is answered as `not_found`;
   existence of an unreadable claim is never disclosed.
2. It must be `visibility = 'group'`. An already-public claim is a no-op, `already_public`.
3. The caller must be authorized under **D-V2**, else `refused_not_admin`.
4. It must not be sealed (`claim_encryption` row), else `refused_sealed`. This is a returned
   outcome, not a raised error, and it is checked before anything changes. The 074 trigger is
   the backstop.

Then, for the `publicize` claims:

5. `set_config('epigraph.allow_declassify','yes', true)`, then `UPDATE claims SET
   visibility='public'` with the owner unchanged, then reset the GUC to `''` in the same body.
   The UPDATE moves a claim only while it is still `group` and still owned by the group it was
   classified under. If fewer claims move than were classified (a claim that was not locked
   because it became readable only after the lock, then changed), the call raises `VIS04`
   (SQLSTATE 40001) and nothing is changed; the repo maps it to a `State` refusal (409 over
   REST), and a retry classifies the new state. Propagation copies `public` onto the 17 derived
   tables. Pinned evidence stays `group`, and its owner never moves.
6. Recompute the edge meet for every edge incident to the claims, **widening allowed**. This is
   the same CASE as `recompute_boundary_meet_conn`: both endpoints public and in writer scope →
   `('public', writer_group_id)`, otherwise world. One endpoint still private → the private
   side's group. An edge explicitly declared `('group', G)` between public endpoints is kept,
   as 120 does on INSERT. That declaration is not recorded, so the rule is narrowed: only edges
   whose current owner equals the meet that the old tenancy produces get rewritten. Anything
   else was a declaration and is left alone.
7. Insert one `security_events` row, `event_type = 'claim.publicized'`, with `agent_id` set to
   the principal and details `{claim_ids, owner_group_ids, reason, edges_widened,
   evidence_kept_private, migration, session_user}`.

It returns per-claim `(claim_id, outcome)` where outcome is `publicized | already_public |
not_found | refused_not_admin | refused_sealed`. If any id is `not_found` or `refused_*`,
nothing is changed and the classification is returned as it stands. The repo wrapper
(`ClaimRepository::publicize_conn`) answers `not_found` as a missing claim and any refusal as a
designed refusal, so a caller never sees a partial act.

### 4.3 `epigraph_share_claims_with_team(p_claim_ids uuid[], p_group_id uuid, p_reason text)`

This handles `private → team`. Each claim must be `('group', H)`, where `H` is the caller's home
group (its own personal group, or its operator's for an operated caller). The caller must be the
claim's author (`claims.agent_id`), **or** a live admin of `H`. The second arm lets the human
whose personal group it is share what its agents wrote there; it is the share-side counterpart
of D-V2's note that the human is admin of its own personal group. `p_group_id` must be in
`epigraph_writable_teams(caller)` and must not be `H`.

Every id is classified first, in this order, all or nothing as in §4.2:

| Outcome | When |
|---|---|
| `not_found` | no such claim, or the session cannot read it |
| `refused_not_private` | the claim is public, or owned by a group other than `H` |
| `refused_not_author` | the caller neither wrote it nor is a live admin of `H` |
| `refused_sealed` | it has a `claim_encryption` row (its key material is bound to its group) |
| `refused_not_team_writer` | the target group is not writable by the caller, or is `H` |
| `share` | to be moved; returned as `shared` once moved |

The rows are locked before they are classified, as in §4.2. If every id is `share`, the
function runs `UPDATE claims SET owner_group_id = p_group_id` on the claims still owned by `H`
and still `group`, and raises `VIS04` (nothing changed) if fewer move than were classified, so
it never answers `shared` or writes the audit row for a claim it did not move. Visibility stays
`group`, so this is not a widening and the GUC is not armed. Propagation re-owns the derived
rows. Pinned evidence keeps its pin owner. Edges take the meet as usual, since narrowing and
group-to-group moves are not blocked. One `security_events` row, `claim.shared_with_team`, is
written. There is no `team → private` and no `team → other team`. Those are privatization's
job (another session), not this one.

### 4.4 Surfaces

* MCP `publicize_claims {claim_ids: [..≤500], reason}`, `share_claims_with_team {claim_ids,
  group_id, reason}` and `set_default_group {group_id?}`. All need `claims:write`
  (`scope_map.rs`). Each runs on the caller's own stamped transaction (`begin_author_stamped_tx`)
  and calls the definer.
* REST `POST /api/v1/claims/publicize`, `POST /api/v1/claims/share-with-team` and
  `PUT /api/v1/agents/me/default-group`, with the same bodies and the `claims:write` scope, on
  `AppState::write_as`. Refusals map by kind: 400 input, 403 authority, 409 state. A claim the
  caller cannot read is 404, exactly as a missing one.

Repo wrappers: `ClaimRepository::publicize_conn`, `share_with_team_conn` and
`set_default_group_conn`.

## 5. Tests (app role, `ScopedPool::connect_downgraded_for_tests(.., "epigraph_app")`)

`crates/epigraph-mcp/tests/claim_visibility_controls_app_role.rs` (12 tests):

* A member writes with no `visibility`. The claim lands `('group', team)`. Another team member
  reads it, and a non-member gets not-found. Derived evidence and trace rows match the claim.
* `private` lands `('group', home)`, which the teammate cannot read. `public` lands
  `('public', home)`, which the non-member can read.
* `team` with `group_id` naming a group where the author is a `reader` is refused, and nothing is
  written. A group the author is not in is also refused.
* D-V1: several teams and no default → private with a note; `set_default_group` then makes
  the next write land in the default team.
* D-V3: an operated agent writes into its live human's team.
* D-V4: a resubmit under another visibility returns the existing claim, unchanged, with a
  `visibility_note`.
* `publicize_claims` by a team admin (D-V2) works. The claim and the edge to a public claim
  become public, a pinned evidence row stays group, and the `claim.publicized` row exists. A
  writer is refused and nothing changes. A non-member is answered as not-found.
* A sealed claim is refused by `publicize_claims`, and a direct `UPDATE` by the app role is still
  refused by 074.
* `share_claims_with_team` moves a private claim to the team, after which the teammate reads it.
* A caller session that plants same-named temporary tables (with rows and a trigger that would
  rewrite a classification) before calling either act changes nothing: both answer with their
  own refusal, no claim moves, the trigger never runs and the planted rows stay as planted.
* A privileged session changes a claim's owner and has not committed when `publicize_claims`
  (or `share_claims_with_team`) is called on it. The call waits, then decides against the
  committed owner: the admin of the old owner is refused as a non-admin of the new one (the
  author's no-longer-private claim is refused as not private), the claim stays where the other
  session put it, and nothing is audited.

`crates/epigraph-api/tests/claim_visibility_http.rs` (3 tests): the REST write surfaces
(`/claims`, `/submit/packet`) honour `visibility`, the three REST acts answer as MCP does, and a
REST resubmit that matches the caller's existing private claim reports its stored tenancy and
the "NOT re-scoped" note.

`crates/epigraph-db/tests/definer_search_path_ratchet.rs`
(`no_function_keeps_state_in_a_session_temporary_relation`): no function body a definer can run
(definer or INVOKER, so its helpers and triggers too) creates or names a temporary relation.

`crates/epigraph-core/src/tenancy.rs`: `VisibilityChoice::parse` unit tests (bad pairs refused).

Legacy pins changed by the new default (§3.6): `host_writer_packets_armed.rs` (P1 private;
Q0 refusal, Q1/Q2 with explicit `public`), `claim_routes_bind_the_caller.rs` (the batch control
now measures the stamped structural edges), and the explicit-`public` fixtures.

## 6. Decisions (owner, 2026-11-05)

* **D-V1 default team.** If `agents.default_group_id` is set and still a team the author may
  write, it is used. Otherwise the author's own human's `default_group_id` is used under the
  same condition. Otherwise the single team the author may write. Otherwise the write is
  **private**, and the response carries a `visibility_note` saying why: no team, or several and
  no default. A default write **never** falls back to public. `default_group_id` (062) was
  unused. Migration 206 adds `epigraph_set_default_group`, served as MCP `set_default_group`
  and REST `PUT /api/v1/agents/me/default-group`, validated against the same team list and
  audited (`agent.default_group_set`).
* **D-V2 who may publicize: team admins only.** It takes the caller's **own** live `admin`
  membership of the claim's owning group. An operated agent does not inherit its human's admin
  role for this act. There is no second approver, and every publicize writes a
  `claim.publicized` `security_events` row. A private claim can be publicized too, because its
  owner is the human's personal group, where the human is admin.
* **D-V3 readers and crew agents: the operator's membership counts for writes.** A `reader`
  membership never admits a team write. An agent may write a claim into team T if it holds
  `writer`/`admin` in T itself, or if its **live human** (`epigraph_human_of(agent, true)`)
  writes T. That is the claims trigger's own writer-scope rule (`epigraph_require_writer_scope`
  → `epigraph_operator_writes_group`). The author-stamped transaction then carries T in its
  writable set for that one write (`Viewer::with_team_write_grant`, admitted only from
  `epigraph_writable_teams`), so 077's `WITH CHECK` agrees with the trigger.
* **D-V4 duplicates across visibilities: return the existing claim, flagged.** When
  `create_or_get` returns an existing claim whose `(visibility, owner_group_id)` differs from
  the request, the claim is returned unchanged. The response carries its real visibility and a
  `visibility_note` naming the difference and the tool that widens it. Nothing is silently
  re-scoped and no second row is created. As before, an exact resubmit still writes its
  evidence and trace onto the existing claim, and they inherit that claim's tenancy.
* **D-V5 callers that must now pass `public`: none.** Every caller-facing claim write defaults
  to team. Work that should be public is published later with `publicize_claims`. The
  system-agent and registry writers in §3.5 are unchanged. Confirmed for delegated packets on
  2026-11-05: an epiclaw-host packet that names no `visibility` lands private in the human's
  group, and is refused where the host has no membership and only the legacy policies
  admitted it (§3.6). The host changes, not the default.
