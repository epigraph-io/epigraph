# Share with team: moving private work into a team, and later to public

Status: design only, nothing is built. Operator request 2026-11-12: "We're going to need a
'publicise to team' function for workflows, subgraphs, and any private table." Measured against
`main` at `55b524f37`. Code is cited as `path::function` plus a fragment you can grep for, never by
line number.

Related documents: [claim-visibility-controls.md](claim-visibility-controls.md) (migration 206,
PR #784, decisions D-V1..D-V5), [papers-tenancy-followup.md](papers-tenancy-followup.md), and
`docs/deploy.md` (operator CLI runbook).

## 0. Summary

* **Why this is needed.** A ruling on 2026-11-12 says an epiclaw agent's writes default to its
  operator's **private** personal group. The operator then picks which work moves into a team
  group, and later which team work becomes public.
* **What exists today.** Migration 206 does this for **claims only**, one call at a time:
  * `epigraph_share_claims_with_team`: private → team;
  * `epigraph_publicize_claims`: group → public.

  Neither has a dry run, an undo, a team → team move, or any unit larger than a list of claim
  ids. The operator CLI (`reown-*`, `restrict-claims`, `regroup-claims`, `reown-workflows`,
  `reown-reverse`) covers more ground, but only on a maintenance connection.
* **What this spec proposes.**
  * **One act, four units of sharing:** a claim set, a workflow lineage, a subgraph selection,
    and a root row of any registered table.
  * **Three transitions:** private → team, team → team, and group → public.
  * **Preview, then apply.** A frozen selection, a plan digest, and a database-held manifest that
    makes every act reversible by compare-and-swap.
* **The rules that do the safety work:**
  * The database already makes every claim-derived row follow its claim (070 arm (d)).
  * An edge whose other endpoint stays private becomes **co-owned**, so the team cannot read it.
  * Pinned evidence, writer-owned rows and outsiders' challenges **never** move with the claim.
  * Sealed rows are refused.
  * Anything that removes a current reader is a **narrowing**, and is maintenance-only (R2).
* **Operator rulings 2026-11-12** (section 0.1) settle five of the original questions: a
  human is required, team → team is allowed but narrowing is maintenance-only, a publicize can
  be undone in the app for a configurable window, attached rows stay in the team, and boundary
  edges are included at their most private meet.
* **Phases:** seven implementable PRs (section 7.1). **Open
  questions:** numbered in section 8.

### 0.1 Operator rulings 2026-11-12

The operator's words are quoted. Each is followed by how this spec applies it, and the sections
that implement it.

* **R1 (question 1): "Yes, requires me."**
  * Every share, move and publicize needs the **human**. The session principal must satisfy
    `epigraph_is_human_operator` (122): a live registry row and its recorded human OAuth client
    still active. `regroup-claims` already applies this test.
  * An **operated agent** (an epiclaw or stdio agent with an operator link) may not share,
    move or publicize on its own authority, whatever memberships it holds or inherits. Neither
    D-V3's `via = 'operator'` arm nor 206's author arm counts.
  * A human's delegated run token does not count as the human either. A delegated session is
    refused, as `server.rs::enforce_federated_scope` already refuses one.
  * The deployed 206 acts let an operated agent do this today, so the gate goes into **P1**.
  * Sections 4.2 and 7.1.
* **R2 (question 2): "team-to-team sharing is allowable, reducing visibility is maintenance
  only."**
  * Team A → team B is app-callable, by a human who is a live admin of A **and** writes B.
  * Any **narrowing** is maintenance-only. That covers public → team, team → private, and any
    act that removes a current reader.
  * **How this spec reads it.** A move in which some reader of A cannot read B (`readers_losing
    > 0`) removes an audience. The app therefore refuses it with `SHR11 narrowing:
    maintenance only` and points to `regroup-claims`. The app performs a move only when
    `readers_losing = 0`. Open question 17 asks whether that is the intent.
  * Sections 4.1, 4.2 and 4.5.
* **R3 (question 3): "Undoing publicise is viable for, say, 48 hours (configurable), then
  maintenance only."**
  * An app-level undo of a publicize is allowed inside a window that defaults to **48 hours**.
    The window is measured from the publicize's audit row (`share.publicized`, or 206's
    `claim.publicized`).
  * The window is held in a maintenance-written settings row (`share_settings.publicize_undo_window`),
    in the shape of 207's `bug_report_intake_settings`. Nothing is hard-coded.
  * Who may run it: the authority that may publicize, which is a human live admin of the owning
    group (D-V2 plus R1).
  * After the window, the undo is maintenance-only (`reown-reverse`).
  * Sections 4.8 and 7.1 (P2).
* **R4 (question 4): "Kept in the team."**
  * When a share or move is undone, any claim that teammates attached rows to after the share
    **stays in the team**, together with those rows. Attached rows are evidence, BBAs, traces
    and edges. The undo neither pulls them back nor refuses.
  * The undo reverts only the claims nobody attached anything to, and reports the ones it kept.
  * Undoing a share is itself a narrowing (it removes the team as an audience). Under R2 it is
    therefore maintenance-only: `reown-reverse` on the plan. Open question 18 asks whether R3's
    window should also apply to undoing a share.
  * Section 4.8.
* **R5 (question 6): "include it in the most private permission set."**
  * A boundary edge whose other end stays private is **included** in the plan. It is recorded
    in the plan's items and manifest, and set to the **most restrictive meet** of its endpoints:
    `('group', owner)` with a co-owner when the endpoints are in two groups.
  * That meet is readable only by principals who can read **both** ends. It is never widened,
    and the endpoint itself is not pulled in.
  * This is the 072 intersection, which arm (d) already computes. The act also applies it to
    evidence-endpoint edges, which arm (d) misses.
  * Section 3.3.

## 1. Where we are

* **The 2026-11-12 default is not in the code yet.** At `55b524f37`, a default write follows
  D-V1: the agent's default team, else its human's, else the single writable team, else private
  with a `visibility_note`.
  * The function to change is
    `crates/epigraph-db/src/repos/claim_visibility.rs::resolve_visibility_choice`, in the
    `VisibilityChoice::Team(None) | VisibilityChoice::Default` arm.
  * This spec assumes the ruling lands. That makes "private" the common starting state, and
    makes this feature the main way work reaches a team.
* **App-callable acts (206).**
  * The definer `epigraph_share_claims_with_team(ids, group, reason)` is served as MCP
    `share_claims_with_team` and REST `POST /api/v1/claims/share-with-team`.
  * The definer `epigraph_publicize_claims(ids, reason)` is served as MCP `publicize_claims` and
    REST `POST /api/v1/claims/publicize`.
  * Both acts:
    * take 1 to 500 ids;
    * lock the rows, classify every id, and change nothing if any id is refused;
    * write one `security_events` row (`claim.shared_with_team` / `claim.publicized`).
* **Operator CLI acts** (`crates/epigraph-cli/src/operator/`). All run on the maintenance DSN,
  default to a dry run, and record a JSONL manifest that `reown-reverse` can replay.

  | verb | move | notes |
  |---|---|---|
  | `reown-claims` / `reown-linked` | public → the operator's personal group, still public | eligible only when every attached row is public |
  | `restrict-claims` | public → `('group', T)` | the admin privatization act |
  | `regroup-claims` (PR #794) | `('group', S)` → `('group', T)` | holds on `sealed`, `sealed-evidence`, `pinned`, `public-row`, `third-group`, `edge-would-widen`, `changed` |
  | `reown-workflows` (PR #783) | whole workflow lineages | `--visibility keep\|group`, `--catch-up`; holds plans that hand off a non-public row |
  | `hide-evidence` | evidence → the operator's personal group, pinned (110) | undone only by `reown-reverse` on its manifest |
* **Admin privatization pipeline.** `routes/privatization.rs` with the 080–082 plans, items and
  audit tables: preview, `plan_digest`, approve, apply, revert. Its plan shape is the model for
  section 4.8.
* **Gaps this spec closes:**
  * No app path shares a workflow, a subgraph, or any table other than `claims`.
  * No app path moves team → team.
  * Nothing previews or undoes a share. `docs/runbooks/206-undo.sql` drops 206's functions and
    says in as many words that a share or publicize stays done.
  * There are two edge gaps (section 4.6):
    * an edge whose endpoint is a moved claim's **evidence** row is not re-met, by arm (d) or by
      206;
    * `harvester_sources` does not follow its fragments when a claim moves.
  * **A leak (section 4.6).** Neither 206 act recomputes the moved claim's cached DS belief. A
    value folded from sources the new audience cannot read is served to that audience. For a
    publicize, that audience is everyone.

## 2. Inventory of tenancy-bearing tables at `55b524f37`

**Counting rule.**
* A table is **tenancy-bearing** if any of these holds:
  * it carries `owner_group_id` (with or without `visibility`);
  * it carries a `group_id` that an RLS policy compares with the session's groups;
  * it carries an `agent_id` that an RLS policy compares with the session's principal.
* Separately listed:
  * tables with **no** tenancy that hang off a tenancy-bearing row (the leak surface);
  * the control plane, which is never shared.
* Counted from `CREATE TABLE` across `migrations/`, minus the two real `DROP TABLE`s:
  `edges_to_cull` (012) and `ownership` (084). That leaves **120 tables and 2 views**.

**Notation for the policy column:**
* "077 tier-A":
  * `<t>_tenancy` FOR ALL. Read: `epigraph_bypass()` ∨ `epigraph_definer_bypass()` ∨
    `visibility = 'public'` ∨ `owner_group_id = ANY(epigraph_session_groups())`. Write:
    `owner_group_id = ANY(epigraph_writable_groups())`.
  * Plus 115's RESTRICTIVE `<t>_delete_owner`, plus 126's elevated-session arms.
* "079 FORCE": row security binds the table owner too.
* "115 immutable": `<t>_owner_immutable`, `epigraph_owner_immutable_guard`. Only a privileged
  writer (a maintenance session or a definer it owns) may change `owner_group_id`.

**Notation for the share-behaviour column:** what happens to the row when a share moves its
root.
* **root:** the act moves it directly.
* **follows claim:** 070 arm (d), `epigraph_propagate_tenancy`; latest body in 168.
* **follows fragment:** 173's trigger.
* **meet:** the endpoint meet (070/072/120).
* **stays:** never moves with the claim.
* **never:** the act must refuse it.

### 2.1 Tables carrying `(owner_group_id, visibility)`: 28

There are 25 from 062's `tier_a`, plus `harvester_sources` and `harvester_audit_reports` (173),
plus `workflows` (183).

| # | table | how a row gets its owner today | RLS | share behaviour | dependencies |
|---|---|---|---|---|---|
| 1 | `claims` | Declared by the writer: `ClaimRepository::default_decl_for_author` / `resolve_write_decl`. A successor inherits from `supersedes` or `step_lineage_id` (`epigraph_claims_require_tenancy`, 070 → 074). | 077 tier-A, 079 FORCE, 115 immutable, 074 `claims_block_widening` (group → public needs `epigraph.allow_declassify`; a sealed claim never goes public) | **root** | every row below; edges; `claim_themes.theme_id`; labels and embeddings are columns on the row |
| 2 | `evidence` | 070 arm (c) `epigraph_inherit_tenancy_stmt` from the claim. 114 `evidence_attach_writer`: writer-owned on a public claim the writer cannot write. 110: a pin keeps the owner fixed. | 077 tier-A, FORCE, writer-owner guard | follows claim, **except** writer-owned on a public claim (stays) and pinned (stays, section 4.6) | edges with an evidence endpoint; `evidence_encryption`; `evidence_visibility_pins` |
| 3 | `edges` | `epigraph_edges_tenancy` (070 → 072 → 120) on INSERT. The meet of the endpoints: public–public epistemic gets `writer_group_id` (D8); public–public structural gets `('public', world)`; one private side gets that side's group; two groups get owner plus `co_owner_group_id`. A declared `('group', G)` is kept. | 077 bespoke (co-owner INTERSECTION on read, world arm on write), 115 `edges_delete_owner`, 117 `edges_update_owner`, immutable owner/co-owner/`writer_group_id` | **meet**: re-met by arm (d) only when the new meet is non-public; widened only by 206 publicize, and only for edges that equalled their meet | `edge_encryption`; BBAs keyed on edges (`mass_functions`) |
| 4–19 | `triples`, `entity_mentions`, `claim_versions`, `ds_combined_beliefs`, `ds_bayesian_divergence`, `claim_frames`, `harvester_claim_provenance`, `experiment_triples`, `experiment_entity_mentions`, `claim_clusters`, `claim_cluster_membership`, `claim_neighborhood_membership`, `claim_signature_revocations` (13); plus `mass_functions`, `reasoning_traces`, `challenges` (3) | Arm (c): stamped from `claim_id` after every INSERT, over any declaration (074 `*_require_tenancy`). `mass_functions` and `reasoning_traces` are 114 writer-owned on a public claim. `challenges` is 168 writer-owned for an outsider. | 077 tier-A, FORCE, 115 immutable (not on the writer-owned three, which have 114's writer-owner guard) | follows claim; writer-owned rows stay while the claim is public; an outsider's challenge always stays | `claim_versions` → `claim_version_encryption`; `claim_cluster_membership` → `graph_clusters` (untenanted); `claim_neighborhood_membership` → `graph_neighborhoods` (untenanted); `mass_functions` → `frames` |
| 20 | `harvester_fragments` | Declared at harvest (root trigger). Re-stamped by arm (d) through `harvester_claim_provenance`. | 077 tier-A, FORCE, 115 immutable | follows claim **through provenance**. A fragment shared with a claim that is not moving is a shared node; `restrict.rs::TABLE_ROLES` calls it `SharedNode` and puts it back. | `harvester_audit_reports`, `harvester_sources` |
| 21 | `harvester_audit_reports` | 173 `epigraph_audit_report_inherit_tenancy`: the fragment's pair. | 173 (077 shape), FORCE, immutable; the app role holds SELECT only (118) | **follows fragment** (`epigraph_fragment_audit_reports_follow`) | — |
| 22 | `harvester_sources` | 173 root trigger (`epigraph_root_require_tenancy`): declared. | as row 21 | root. **Does not follow its fragments.** | `harvester_fragments.source_id` |
| 23 | `workflows` | 183: declared by the ingest (`epigraph_root_require_tenancy`); backfilled from the plan's level 0–2 `executes` targets. | 183 `workflows_read/insert/update/delete_owner`, FORCE, `workflows_owner_immutable` and `workflows_visibility_immutable` (maintenance only), 126 refusal-only arms | root. **Not propagated to:** `epigraph_node_tenancy` treats a workflow endpoint as tenancy-less, so `executes` edges take their claim's tenancy | `executes` edges → plan claims; `behavioral_executions`, `workflow_executions`, `tasks` (untenanted); 202 `epigraph_workflow_name_has_hidden_rows` |
| 24–27 | `frames`, `contexts`, `perspectives`, `communities` | Instance-wide registries: `TenancyDecl::instance_wide()` = `('public', world)`; group ownership is admitted. | 077 registry variant (world arm on write), FORCE, 115 immutable, 117 `<t>_update_owner` | root, rarely private | `mass_functions.frame_id`, `claim_frames`, `ds_*` |
| 28 | `recall_events` | Carries 062's columns, but the policy is **principal-keyed** (`agent_id = epigraph_principal_id()`). | 077 bespoke | **never**: one agent's search text and returned ids | — |

### 2.2 Tables keyed on `group_id`: 4

`claim_encryption`, `claim_version_encryption`, `evidence_encryption`, `edge_encryption`.
* They hold wrapped key material per `(group, epoch)`.
* Policy: 077 `<t>_tenancy`. Read is session groups; write is writable groups. Plus 115's
  RESTRICTIVE delete.
* Share behaviour: **never**. A sealed row's key is bound to its group, and moving it means
  re-wrapping under the target's epoch.
* Every act refuses or holds a sealed claim, sealed evidence, or a sealed edge (section 4.4).

### 2.3 Side tables that steer or record tenancy

| table | role | RLS | relevance |
|---|---|---|---|
| `evidence_visibility_pins` | a pin: arm (c) and arm (d) never widen the evidence row or move its owner | ENABLE+FORCE; read by bypass or definer; INSERT/DELETE by maintenance only | pinned evidence **stays** (section 4.6) |
| `privatization_plans`, `privatization_plan_items`, `privatization_audit` | frozen selection, `plan_digest`, four-eyes approval, revert | FORCE, policies 087/088 | the shape section 4.8 reuses |
| `security_events` | the audit sink for every act | 077 append and read policies; prefix reservations (117 `cascade.`, 123 `platform.`, 207 `bug_report.`) | new acts get a reserved prefix (section 4.7) |
| `tenancy_backfill_progress`, `tenancy_undeclared_writes`, `tenancy_transcription_log`, `tenancy_exempt` | ledgers | the app role holds no write (118) | `tenancy_exempt` is the registry the ratchet in section 7.2 extends |
| `atlas_layout_epoch`, `atlas_layout_runs`, `atlas_layout_regions`, `atlas_layout_themes`, `atlas_layout_theme_links` | public-only theme layout (197) | none: aggregates of public rows, served only while `visibility_epoch = atlas_layout_epoch.n` | section 6.1 |


### 2.4 Registered exemptions: `tenancy_exempt`, 12 rows seeded by 069

These rows carry no tenancy columns. Each was argued and reviewed. 173's `DELETE` names two
harvester tables that 069 never seeded, so it is a no-op on a fresh database. The registry stays
at the 12 rows pinned by `tenancy_coverage.rs::REGISTRY`.

| table | residual (069, as amended) | consequence for a share |
|---|---|---|
| `claim_themes` | centroid and `claim_count` span tenants | a shared claim's `theme_id` keeps pointing at a corpus-wide theme; no move needed, and the residual is unchanged |
| `agents`, `jobs`, `claim_encryption`, `claim_version_encryption` | identity, queue, sealed keys | not content |
| `experiments` | `protocol` discloses the design for a private hypothesis | **does not follow** a shared hypothesis claim; under-sharing, not a leak |
| `counterfactual_scenarios`, `learning_events`, `match_candidates` | free text about two claims | do not follow. `match_candidates` is a near-duplicate oracle and stays exempt. |
| `behavioral_executions` | a private step's `goal_text` and `goal_embedding` | a workflow share moves nothing here (section 3.2) |
| `alternative_set`, `alt_set_decisions` (views) | closed by 077 (`security_invoker = true`) | follow `edges` and `claims` |

### 2.5 Untenanted dependencies

These rows have no tenancy columns and no RLS, and they reference tenancy-bearing rows. A share
neither moves them nor needs to. Each one is either a leak that already exists whatever a share
does, or a stale aggregate.

| table(s) | references | note |
|---|---|---|
| `papers` | `asserts` / `authored` / `processed_by` edges | [papers-tenancy-followup.md](papers-tenancy-followup.md): a private ingest's paper row is world-readable today. Sharing does not make this worse. Publicizing makes it moot for that paper. |
| `entities`, `experiment_entities`, `entity_merge_candidates` | `entity_mentions`, `experiment_entity_mentions` | the entity registry is instance-wide; mentions carry the tenancy |
| `graph_cluster_runs`, `graph_clusters`, `cluster_centroids`, `cluster_edges`, `cluster_labels`, `graph_neighborhoods`, `neighborhood_edges` | `claim_cluster_membership`, `claim_neighborhood_membership` | aggregates; section 6.2 |
| `workflow_executions`, `tasks` | `workflows` (by `workflow_id`, no FK) | execution telemetry; section 3.2 |
| `events`, `webhook_subscriptions` | event payloads name claim ids | `webhook_subscriptions` is agent-keyed: `routes/webhooks.rs::deliver_event` drops events naming a claim the subscriber cannot read (`ClaimRepository::hidden_claim_ids`); section 6.4 |
| `provenance_log`, `factors`, `bp_messages`, `trace_parents`, `source_artifacts`, `harvester_enriched_concepts`, `experiment_results`, `analyses`, `gap_analyses`, `edges_staging` | various | not reached by any share unit; listed so that the ratchet's "no columns" set is explicit |

### 2.6 Control plane: never shared (21 tables with RLS, plus credentials)

The 21 tables with RLS:
* `groups`, `group_memberships`, `group_key_epochs`, `group_role_bindings`
* `agents`, `agent_prompt_blobs`, `agent_prompt_snapshots`, `agent_succession`
* `operator_links`, `instance_admins`, `platform_roles`, `role_assignments`, `role_agents`
* `person_authenticators`, `passkey_enrollments`
* `elevation_tickets`, `elevation_sessions`, `elevated_access`, `pending_admin_acts`
* `jobs`, `rls_canary`

The credential and OAuth tables locked down by 118 are also never shared. The generic primitive
(section 3.4) refuses every one of these by name.

**Totals.**
* 28 tables carry `(owner_group_id, visibility)`; one of them, `recall_events`, is
  principal-keyed.
* 4 tables are keyed on `group_id`.
* So **32 tables** carry a tenancy column, and **27 of them can ever be moved by a share** (the
  28, minus `recall_events`).
* Of those 27, **7 are roots**: `claims`, `workflows`, `harvester_sources`, and the four
  registries.

## 3. Units of sharing

Every unit resolves to the same thing: a **frozen item set** of root rows in one source group,
plus the closure rules below. The act then moves the roots, and the database moves the rest
(arm (d)) or the act's own body does (edges, fragments, sources). The rest of the spec states
everything in terms of that set.

### 3.1 Claim set

* **Input:** up to 500 claim ids per call. That is 206's cap, which bounds the lock set of one
  transaction.
* **Items:**
  * each id, after the visibility check (an unreadable id is `not_found`, never "exists but
    forbidden");
  * plus the **lineage hull**, unless the caller opts out (open question 5).
* **The lineage hull.** `epigraph_content_lineage_hull` (080) walks the `supersedes` chain in both
  directions, plus `step_lineage_id` siblings at one hop.
  * The problem it solves: share a successor and leave its predecessor private, and every team
    member reads a `supersedes` UUID that resolves to nothing. That is an existence oracle on
    the private corpus.
  * Hull members that are not in the source group, or are sealed, are **held** (refused with a
    reason). They are not silently dropped.
  * The hull's depth cap of 64 is a truncation. For a widening that is fail-safe: a truncated
    hull shares less. For an undo it is not, so the undo replays the manifest (section 4.8) and
    never re-walks the hull.

### 3.2 Workflow

* **Input:** a `canonical_name`.
* **Items:**
  * **every generation** of that name (all `workflows` rows);
  * the level 0–2 plan claims each generation `executes`: thesis, phase, step;
  * the `step_lineage_id` siblings that `evolve_step` created;
  * every plan edge between those claims.
* **Why all generations.** After a partial share, 202's
  `epigraph_workflow_name_has_hidden_rows` returns true for every teammate. Teammates' `add_step`,
  `delete_step` and `ingest_workflow` on the name are then refused, and `find_workflow` resolves
  the head to the latest generation *they* can read, not the real one. A head-only share would
  break the lineage for the very team it was shared with. (Open question 7 asks whether to allow
  it anyway, with a refusal.)
* **Level-3 operation atoms** are content-addressed (`atom_id`) in the namespace every document
  shares, so they are not the plan's own.
  * An atom whose tenancy is the source group **and** that only this lineage references follows
    the plan.
  * Any other atom is held as `shared-atom`. This is reown-workflows' "claims shared with other
    plans" hold, kept as is.
* **Executions.** `behavioral_executions`, `workflow_executions` and `tasks` carry no tenancy, so
  there is nothing to move.
  * `behavioral_executions.goal_text` was readable before the share and still is (its 069
    residual).
  * Outcome counters live in `workflows.metadata` and move with the row.
* **Catch-up.** A generation ingested into the source group after the share. 202 already refuses
  a teammate's write to a lineage with a hidden row, so the lineage cannot fork silently.
  * The plan records the name, and `share_workflow --catch-up <plan>` moves the new generation
    under the same manifest. This is reown-workflows' `--catch-up --after-manifest`.
* **Why it needs a new definer.** The `workflows` row cannot be moved by arm (d), and 183's two
  immutability triggers refuse every non-privileged change. A definer owned by
  `epigraph_maintenance` is admitted, which is how 206 gets past 115.

### 3.3 Subgraph

* **Definition.** A subgraph is the closure of a **selection**:

  ```
  selection := { seeds: claim ids                       -- or
                 label: { all_of: [..], any_of: [..] }  -- or
                 root: claim id,
                 traverse: { relationships: [..], direction: out|in|both, max_depth: 1..8 } }
  ```

* **Evaluation.**
  * The selection is evaluated **on the caller's stamped connection**, so it can only reach
    rows the caller can read. It is then filtered to rows owned by the source group.
  * Relationship names are case-normalized, as 080's closure must be: 011 documents 36,791
    `DERIVED_FROM` rows next to `derived_from`.
  * The result goes through the lineage hull (3.1) and is frozen as plan items with a digest
    (4.8).
  * **Why a frozen set.** A label query re-evaluated at apply time is a different set: the 080
    header calls the alternative "too racy to evaluate once at preview and again at apply".
* **Boundary edges (R5).** These are edges with exactly one endpoint in the item set.
  * They are **included**: each one is a plan item, with its before-image in the manifest.
  * Each is set to the most restrictive meet of its endpoints, and never widened.
  * The preview reports them by class, and nothing is decided silently.

  | other endpoint | after the move (arm (d) or the act's body) | team reads it? |
  |---|---|---|
  | public node | `('group', team)` | yes, and it already could read the public end |
  | private in the **source** group, staying | co-owned (072 meet): the owner is the group of the edge's `source_id` endpoint and the co-owner is the group of its `target_id` endpoint; one is the home group, the other the team | **no**: co-ownership is an intersection, and the team is not in the source group |
  | private in a **third** group | co-owned by the third group and the team | only principals in both |
  | sealed | the claim is held | n/a |

  There is no `on_boundary` option. The private endpoint is not pulled in. A caller who wants
  it shared selects it, which makes the edge an interior edge.
* **Evidence-endpoint edges.** These are edges whose endpoint is a moved claim's evidence row,
  not the claim. Arm (d) joins only on claim endpoints (`JOIN changed ch ON x.source_id = ch.id
  AND x.source_type = 'claim'`), so it leaves them at the old meet.
  * `operator/restrict.rs` documents this gap and re-meets them itself; 206 does not.
  * For a share, the stale edge stays `('group', home)`, which fails closed: the team misses an
    edge.
  * For an undo, which narrows, a stale edge would be a leak. So the act's body re-meets them
    in both directions, at the most restrictive meet (R5; phase P1).

### 3.4 Any private table: the generic primitive

* **Roots only.** A derived row moved directly does not stay moved: the next INSERT for the same
  claim fires arm (c), and `epigraph_inherit_tenancy_stmt` re-stamps every row of that claim back
  to the claim's tenancy.
* **The registry.** The primitive is a migration-owned table, `tenancy_share_registry`, which the
  app role reads only. One row per tenancy-bearing table:

  ```
  table_name text PK, behaviour text CHECK (behaviour IN
    ('root','follows_claim','follows_fragment','meet','writer_owned','pinned',
     'principal_keyed','group_keyed','registry','never')),
  unit_resolver text,   -- the definer that expands a root into items, NULL if not a root
  reason text NOT NULL
  ```

* **What may be shared:**
  * Only `behaviour = 'root'` tables can be named:
    * `claims`, through 3.1 and 3.3;
    * `workflows`, through 3.2;
    * `harvester_sources`, which moves its fragments' claims through 3.1, then the source;
    * `frames` / `contexts` / `perspectives` / `communities`, only when group-owned (open
      question 14).
  * Every other table is refused with `SHR10 not a root: shares follow <root>`.
* **A ratchet** keeps the registry complete (section 7.2): any table with `owner_group_id` and
  no registry row fails CI. A table added later cannot fall outside the feature by omission.

## 4. Semantics

### 4.1 Transitions

| from → to | act | narrowing? | status today |
|---|---|---|---|
| private (home) → team | `share` | no, for practical purposes: readers go from the home group to the team (section 4.5) | claims: 206. Others: new. |
| team A → team B | `move` | only if some reader of A cannot read B (`readers_losing > 0`); then maintenance-only (R2) | CLI `regroup-claims` / `reown-workflows` only. **R2:** app-callable when nothing narrows. |
| team → public, private → public | `publicize` | no | claims: 206 (D-V2). Others: new. |
| public → group, team → private | privatization | yes | **Maintenance-only (R2)**: CLI `restrict-claims`, admin privatization pipeline. Out of scope except as the undo of this feature's own acts (4.8). The one app exception is R3's publicize-undo window. |

### 4.2 Who may do it

The roles:
* **author:** `claims.agent_id`, or the workflow's ingesting principal.
* **operator:** the live human of the authoring agent, `epigraph_human_of(agent, true)`.
* **operated agent:** an agent acting under an operator link.
* **source admin / target writer:** live memberships, read through `epigraph_live_memberships`.

| act | rule (this spec) | today (206) |
|---|---|---|
| share private → team | a **human** (R1) who is a live admin of the home group (in practice, the human whose personal group it is) and who writes the target by **own** membership (`via = 'own'`) | author **or** home admin; the target is any team in `epigraph_writable_teams(caller)`, including `via = 'operator'`. **An operated agent passes today.** |
| move A → B | a **human** (R1) with its own live admin membership of A and writer membership of B; refused when `readers_losing > 0` (R2) | not app-callable |
| publicize | a **human** (R1) with its own live admin membership of the owning group (D-V2) | D-V2 without the human test |
| undo a publicize | inside the R3 window: a **human** live admin of the owning group. After it: maintenance only. | none |
| undo a share or move | maintenance only (R2): `reown-reverse` on the plan; attached claims stay (R4) | none |

* **Operated agents (verified at `55b524f37`).** 206's classification together with
  `epigraph_writable_teams`'s `operator` arm lets an operated epiclaw agent move work it authored
  from its operator's personal group into **any team its operator writes**. The two pieces are:
  * `WHEN c.agent_id IS DISTINCT FROM v_principal AND NOT v_home_admin THEN 'refused_not_author'`
    passes for the author;
  * the `via = 'operator'` row admits the team.

  This matches D-V3: the agent could have written into that team in the first place. It does
  not match the premise of 2026-11-12, that the **operator** chooses what leaves private.
* **R1 closes it.** P1 changes both 206 definers:
  * each refuses, with a new outcome `refused_not_human`, unless
    `epigraph_is_human_operator(epigraph_principal_id())` holds;
  * the author arm is dropped from share;
  * the target team must be writable by the caller's own membership.

  D-V3 is untouched for **writes**: an operated agent still writes into its human's teams. R1
  removes it only from the acts that move existing work.

### 4.3 All or nothing

* **One call or one batch is atomic,** in 206's pattern:
  1. lock the rows `FOR NO KEY UPDATE` in id order;
  2. classify every item;
  3. if any item is refused, return the classification and change nothing;
  4. otherwise update, re-checking the classified owner. A short count raises `VIS04` (40001).
* **A plan larger than 500 roots** is applied in batches, each one atomic. Plan state
  (`pending → applying → applied | failed`) and a cursor make a partial apply **visible and
  resumable**, never silent. This is privatization's `cursor_kind` / `cursor_id`.
* **`on_conflict`:**
  * `abort` (the default) holds the whole plan if any item is held at preview or at apply;
  * `skip` drops held items from the plan, recomputes the digest, and needs a fresh preview.
  * There is no `reassign` (privatization has one). A share never picks a different owner than
    the one the caller named.

### 4.4 Sealed rows

* **Refused, as in 206 and `regroup-claims`.** Classes:
  * `refused_sealed` (claim);
  * `held: sealed-evidence` (`evidence_encryption`);
  * `held: sealed-edge` (`edge_encryption`);
  * `held: sealed-version` (`claim_version_encryption`).
* **Why.** The ciphertext is wrapped for the source group's key epoch. Moving the row without
  re-wrapping makes it unreadable to its new owner (a black hole), or leaves the old group
  holding the key.
* **Sharing sealed content is a separate act:** unseal, share, then re-seal under the target's
  epoch. It is not in this spec.
* **For publicize**, 074's `claims_block_widening` stays the backstop: a sealed claim cannot go
  public by any path.

### 4.5 Widening and narrowing

* **Rule:** an act is a **narrowing** if any principal who reads a row before the act cannot
  read it after.
* **The preview computes `readers_losing`**: the count of live readers of the source group who
  are not readers of the target.
* **R2: an app session never narrows.** A nonzero `readers_losing` refuses with `SHR11
  narrowing: maintenance only` and names the CLI verb that does the move. There is no
  acknowledgement flag in the app. A maintenance verb (`regroup-claims`, `restrict-claims`,
  `reown-reverse`) may narrow, and it still prints the count and requires
  `--acknowledge-readers-losing`, which is privatization's `acknowledge_author_loss` applied
  to readers.
* **Private → team** is a narrowing only for readers of the home group who are not in the team.
  A personal group's readers are the human and its role-attached agents. The human must write
  the target (R1), so the set is normally empty. When it is not, R2 applies, and open question
  17 asks whether the human's own agents should count.
* **Team → team** is always computed this way. Under R2 the app performs it only when the
  target's readers include every reader of the source.
* **Publicize** never narrows.
* **The one app exception is R3:** undoing a publicize inside the window (4.8).

### 4.6 How dependent rows follow

| dependent | on share / move (group → group) | on publicize (group → public) | why |
|---|---|---|---|
| the 16 claim-derived tables of 2.1 rows 4–19 | follow (arm (d)) | follow | the database already does it; the act adds nothing |
| writer-owned `evidence` / `mass_functions` / `reasoning_traces` | none exist on a private claim (arm (d) cleared the flag when the claim left public) | stay the writer's, public | 114: an attachment to a public claim belongs to its writer |
| an outsider's `challenges` row (168) | stays the outsider's, public | stays | R-CH1: privatizing or re-owning a claim never drags an outsider's challenge into the claim's group |
| **pinned evidence** (110) | **stays** `('group', pin owner)` | **stays group** (206 reports `evidence_kept_private`) | see below |
| edges incident to a moved claim | re-met by arm (d) (non-public meets only) | 206 recomputes, widening allowed, **only** for edges whose tuple equalled their meet beforehand; a declared `('group', G)` edge is kept | 072/120: visibility never widens by accident |
| edges incident to a moved claim's **evidence** | **re-met by the act's body (new)** | likewise | the arm (d) gap, section 3.3 |
| `harvester_fragments` | follow through provenance; a fragment also feeding a claim that is not moving is **held** (`shared-fragment`) | same | otherwise the other claim's fragment changes owner under it |
| `harvester_audit_reports` | follow the fragment (173) | follow | — |
| `harvester_sources` | **moved by the act's body (new)** when all its fragments now agree, using 173's derivation rule; otherwise held (`source-mixed`) and reported | same | otherwise a harvested source stays private while all its claims are public |
| cached belief on the moved claim (`claims.belief` / `plausibility` / `pignistic_prob`, `ds_combined_beliefs`, `ds_bayesian_divergence`) | **recomputed by the act (new)** | **recomputed by the act (new)** | see "The DS cache" below |
| `papers`, structural `authored` / `processed_by` edges | untouched | untouched | untenanted (2.5) |
| `experiments`, `counterfactual_scenarios`, `learning_events`, `match_candidates` | untouched | untouched | exempt (2.4) |

**Why pinned evidence stays group in #784, and must stay group here.**
* A pin is how `epigraph-operator hide-evidence` keeps a chosen evidence row hidden while its
  claim stays as it is.
* 110's header (section 2, "WHY THE OWNER DOES NOT FOLLOW THE CLAIM") records the measurement
  that rejected the alternative:
  * letting the pinned owner follow the claim kept `visibility = 'group'` in the column;
  * but the set of **readers** changed: after a move, the operator read 0 of its hidden rows and
    the new owner read 1;
  * that is "a widening in everything but the column name".
* So the owner is fixed at the hide, and only an explicit unhide (`reown-reverse` on the hide
  manifest) moves it.
* A share is exactly the claim-owner change that analysis covers. The team gets the claim and
  not the hidden evidence, which is what the hide asked for. The preview lists the count.

**The DS cache: a leak that 206 leaves open today.**
* **The rule it breaks.** A BBA may enter a claim's *cached* belief only if every source of it is
  at least as widely readable as the claim. That means public, or (for a non-public claim) owned
  by the claim's own group, and never a co-owned edge. The rule is
  `crates/epigraph-db/src/repos/derivation_scope.rs::CACHE_ADMISSIBLE_SQL` ("is at least as
  widely readable as the claim"), applied when the cache is written by
  `crates/epigraph-engine/src/derivation_scope.rs::retain_for_cache`.
* **What 206 does.** Neither act recomputes the cache, so the value folded under the old tenancy
  is served under the new one:
  * **publicize:** a value folded while the claim was `('group', G)` can include BBAs from
    pinned evidence and edge-factor BBAs from G-private sources. It becomes readable by
    everyone.
  * **share:** sources left in the home group (pinned evidence, and private claims whose edges
    are now co-owned) stop being admissible, but the old value moves to the team.
  * `ds_combined_beliefs` and `ds_bayesian_divergence` rows follow the claim (arm (d)) with
    their values already folded.
* **The fix.** Every act recomputes the cache of each moved claim in the same transaction, after
  the move. Using `edge_factor::recompute_claim_cached_belief`, or vacating where
  `derivation_scope::must_vacate_cache` says so (R-80). It also drops or recomputes that
  claim's `ds_combined_beliefs` / `ds_bayesian_divergence` rows.
  * The combination runs in Rust, so this is a step in the repository call that wraps the
    definer. It is not part of the definer body: 114 records why a definer takes cache values
    from the caller rather than computing them.
  * The act is not reported done until the recompute has committed, in the same transaction.
* **Residual: raw BBA rows.** A `mass_functions` row keyed on a pinned evidence row follows the
  claim, so the team reads its masses but not the hidden evidence text. Hiding is per evidence
  row, so this residual already exists for every pin. The preview counts these rows
  (`bba_on_pinned_evidence`) so the caller sees it.

### 4.7 Audit

* **One `security_events` row per applied batch**, with a reserved prefix `share.`. Like 117's
  `cascade.` and 207's `bug_report.`, the prefix is enforced by a RESTRICTIVE INSERT policy, so
  that only the definers can write it.
* **Event types:**
  * `share.claims_shared`, `share.workflow_shared`, `share.selection_shared`, `share.moved`,
    `share.publicized`, `share.reversed`;
  * plus 206's existing `claim.shared_with_team` and `claim.publicized`, kept for the one-shot
    tools.
* **`details`:**
  * `plan_id`, `plan_digest`, `batch`, `from_group_id`, `to_group_id`, `reason`;
  * counts per dependent class: moved, held, `evidence_kept_private`, `edges_rewritten`,
    `boundary_cut`;
  * `readers_losing`, `session_user`, `migration`.
* **No ids beyond the roots.** The manifest (4.8) holds the per-row before-images; the audit row
  points at it.

### 4.8 Dry run, manifest and undo

* **Preview** is a definer call that resolves the unit, freezes the items into `share_plan_items`
  and returns:
  * the classification;
  * the dependent counts per table, from section 4.6;
  * the boundary report (3.3);
  * `readers_losing`;
  * a `plan_digest`: BLAKE3 over the sorted `(kind, id)`, as in 080.
* Preview writes only the plan, never content.
* **Apply** echoes the digest, re-classifies under lock, and refuses (`SHR04`) if anything
  changed.
* **Every MCP and REST surface previews by default.** `apply` is a separate call naming the
  plan.
* **The manifest.** The CLI's JSONL manifest is the model. App callers have no filesystem, so the
  manifest lives in the database: `share_plan_rows`, ENABLE+FORCE, readable by the plan's actor
  and the admins of either group.
  * It stores the **before-image** of every row the act touched:
    `(table, pk, owner_group_id, visibility, co_owner_group_id, writer_owned, pinned)`.
  * Rows that arm (d) moved are captured too, by diffing the dependent tables inside the same
    transaction (the census that `operator/reown.rs` takes with `pg_stat_xact_user_tables`).
  * The `security_events` details are **not** enough for this: they do not record the
    before-state of pinned, writer-owned or co-owned rows.
* **Undo** (`reverse_share(plan_id)`) replays the before-images newest-first, compare-and-swap
  per row: a row whose current tuple is not the plan's after-image is **held**, exactly as in
  `reown-reverse`.
* **Undoing a share or a move is a narrowing,** so under R2 it is **maintenance-only**:
  `epigraph-operator reown-reverse` gains a dispatch for `share_plan` manifests read from the
  database.
  * **R4: attached claims stay in the team.** A claim is "attached" if, since the share, a
    principal other than the plan's actor added any row stamped with the team. That means
    evidence, BBAs or traces (stamped by arm (c)), or an edge whose meet includes the team.
  * Such a claim is not reverted. It keeps its tenancy, its derived rows and its edges, and is
    listed in the undo's report as `kept_attached`.
  * Only claims nobody attached anything to are restored to their before-images. The hull and
    workflow rules still apply. A kept claim keeps its hull members in the team as well, so no
    `supersedes` or lineage reference dangles.
* **Undoing a publicize (R3).**
  * **Inside the window**, default 48 h from the publicize's audit row and configurable in
    `share_settings`, a human live admin of the owning group may undo it from the app. The act
    is the definer `epigraph_share_unpublicize(plan_id, reason)`, owned by
    `epigraph_maintenance` like 206's acts. The window is decided in the body, against the audit
    row's `created_at` and the settings row, both read live.
  * The undo restores the manifest's before-images. The claim goes back to `('group', owner)`.
    Arm (d) re-meets the incident edges, and `claims_atlas_layout_narrowed` bumps the layout
    epoch (section 6.1).
  * **Rows written since the publicize by principals outside the owning group** are the R4
    case on a public claim:
    * outsiders' writer-owned evidence, BBAs and traces (114);
    * challenges (168);
    * D8 writer-owned edges (120).

    Arm (d) would hand the writer-owned rows to the owning group when the claim narrows, and an
    outsider's edge would become unreadable to its writer. The in-window undo therefore
    **keeps** any such claim public, lists it as `kept_attached`, and reverts the rest. This is
    R4's rule ("kept") applied to the public audience. Open question 19 asks whether the
    operator would rather refuse here.
  * **After the window** the undo is maintenance-only: `reown-reverse` on the plan, which is
    today's `restrict-claims --allow-non-world-owner` in effect.
  * Events and webhooks already delivered during the window cannot be recalled (section 6.4).
    The response says so.

## 5. Surfaces

The same rules apply on all three surfaces:
* **Preview first.** A dry run is the default, and nothing is written without a second call
  that names the plan and echoes its digest.
* **One code path.** Every surface calls the same repository wrapper, which calls the same
  definer. No SQL is duplicated between routes and tools (repository rule).
* **Stamped as the caller.** Every surface runs on the caller's own stamped transaction:
  `begin_author_stamped_tx` for MCP, `AppState::write_as` for REST.

### 5.1 MCP (kernel tools: `server.rs` `#[tool_router]` and `scope_map.rs`)

| tool | arguments | scope | notes |
|---|---|---|---|
| `share_preview` | `unit: {claims: [..]} \| {workflow: name} \| {selection: ..} \| {root: {table, id}}`, `to_group_id`, `act: share\|move\|publicize`, `hull?` | `claims:write` | returns `plan_id`, `plan_digest`, the classification, dependent counts, the boundary report and `readers_losing`; writes only the plan. A non-human caller gets `refused_not_human` (R1). |
| `share_apply` | `plan_id`, `plan_digest`, `reason` | `claims:write` | human only (R1); applies batch by batch; resumable by calling it again; refuses `readers_losing > 0` with `SHR11` (R2) |
| `share_status` | `plan_id` | `claims:read` | the plan's state, cursor and per-batch outcomes; readable by the actor and by admins of either group |
| `share_unpublicize` | `plan_id`, `reason` | `claims:write` | R3: a human live admin of the owning group, inside the window. Outside the window it answers `SHR12 window closed: maintenance only`. Returns `reverted` and `kept_attached`. |
| `share_claims_with_team`, `publicize_claims` (206) | unchanged, plus `dry_run: bool`, **default true** after P1 | `claims:write` | human only after P1 (R1); kept for one-shot use of up to 500 ids; internally a one-batch plan, so a publicize gets the R3 undo too |

There is no app tool that reverses a share or a move: that narrows, and R2 makes it
maintenance-only (section 5.3).

### 5.2 REST

| route | maps to |
|---|---|
| `POST /api/v1/shares/preview` | `share_preview` |
| `POST /api/v1/shares/{plan_id}/apply` | `share_apply` |
| `GET /api/v1/shares/{plan_id}` | `share_status` |
| `POST /api/v1/shares/{plan_id}/unpublicize` | `share_unpublicize` |
| `POST /api/v1/claims/share-with-team`, `POST /api/v1/claims/publicize` (206) | unchanged, plus `?dry_run=` |

* Refusals map as in 206: input → 400, authority → 403, state (held, digest mismatch,
  `VIS04` / `SHR04`) → 409.
* A plan or claim the caller cannot read answers 404, exactly as a missing one.

### 5.3 Operator CLI (`epigraph-operator`, maintenance DSN)

* **New verbs:**
  * `share-claims`, `share-workflow`, `share-selection`, `publicize`;
  * `--plan <id>`, which applies a plan an app user previewed. This lets the operator apply on
    the user's behalf, with `--operator` named as the actor and the plan's digest checked.
* **Conventions, as for every verb:**
  * dry run unless `--apply`;
  * `--ruling` and `--reason` required to apply;
  * exit codes 0, 1, 2, 3;
  * a JSONL manifest opened `create_new` and fsynced before the write.
* **`reown-reverse`** gains a dispatch for `share_plan` manifests, which it reads from the
  database by plan id. It is the only undo of a share or a move (R2), and the only undo of a
  publicize once R3's window has closed. It keeps attached claims (R4), as the app undo does.
* **Existing verbs stay** as the maintenance-side tools for the same moves:
  * `regroup-claims` for team → team;
  * `reown-workflows` for workflows;
  * `restrict-claims` for public → group.

  P7 checks that the CLI and app paths hold on the same classes. A test runs both previews on
  one fixture and compares the hold sets.

## 6. Interactions

### 6.1 The Atlas layout epoch (197)

* **How it works.** The layout is built only from public current claims and public in-force
  edges. `epigraph_atlas_layout_narrowed` bumps `atlas_layout_epoch.n` in the same transaction
  as any `claims` or `edges` UPDATE that takes a row from `'public'` to non-public, and a run is
  served only while `visibility_epoch = n`.
* **Share and move** never touch a public row, so there is no effect.
* **Publicize** only widens. The layout simply lacks the new claims until the next
  `atlas_layout` run. That is stale, but nothing leaks. Open question 15 asks whether apply
  should queue a rebuild.
* **Undo of a publicize** (R3's app window, or `reown-reverse`) narrows, so the trigger fires and the layout stops being served until
  a rebuild. The trigger keys on the `visibility` change itself, not on any caller, so a
  maintenance replay is covered. A test pins this (7.2).

### 6.2 Embeddings, recall, clusters and caches

* **Embeddings and ANN indexes.** These are `claims.embedding` with `idx_claims_embedding_hnsw`,
  plus `embedding_3072`. Vectors do not depend on tenancy, and every search filters at query
  time (`ClaimRepository::search_by_embedding_scoped`, `/* {VISIBILITY:c} */`), so a share
  needs no refresh.
* **`recall_events`.** These rows are keyed on the principal. Ids a querier was once shown stay
  in its own rows after an undo. They carry ids, not content, and the reads of those ids are
  filtered.
* **In-process caches:**
  * `crates/epigraph-mcp/src/tools/recall.rs::CentroidPopulationCache` (300 s) holds a fraction,
    not ids, so it leaks nothing.
  * `crates/epigraph-embeddings/src/cache.rs::EmbeddingCache` is keyed on text.
  * Memberships are read live: the bearer middleware notes "No cache", and 206 calls
    `epigraph_live_memberships`.
  * The Explorer's `services/explorer/src/ttl.rs::ResponseCache` is keyed per session, with
    `OVERVIEW_TTL` and `LANDING_CACHE_TTL` of 60 s and `ATLAS_LAYOUT_TTL` of 30 s. After an
    **undo**, which narrows, a session can keep seeing withdrawn theme counts for up to 60 s.
    The undo surface states this bound in its response, and P2 decides between accepting it
    and adding a process-wide generation counter that the cache keys on.
* **Clusters and themes.**
  * `graph_clusters`, `cluster_edges`, `graph_neighborhoods`, `neighborhood_edges`,
    `cluster_labels` and `claim_themes` (centroid, label, `claim_count`) are corpus-wide
    aggregates. They are built without a visibility filter
    (`crates/epigraph-jobs/src/cluster_graph/runner.rs::run_clustering`, the theme scripts).
  * A share changes none of that residual, which is registered in 069 for `claim_themes`.
  * The membership rows (`claim_cluster_membership`, `claim_neighborhood_membership`) follow the
    claim.
  * Region labels in the Atlas come from `claim_themes.label`, which samples members with no
    visibility predicate. This is an existing residual, not changed here.
* **The DS cache** is the one structure that a share makes wrong. See section 4.6.

### 6.3 Federation (episcience)

* **How the gateway works.** `crates/epigraph-mcp/src/federation/` mounts episcience over
  loopback TCP. `client.rs::invoke_once` forwards the caller's own bearer for each call, so the
  downstream sees the real principal.
* **What episcience does with it** (not verifiable from this repository, whose episcience
  checkout is absent):
  * `docs/superpowers/specs/2026-09-26-episcience-operator-authority-design.md` records that
    episcience is pinned to a pre-tenancy revision, with no `ScopedPool` and no `Viewer`;
  * `add_observation` inserts claims undeclared;
  * episcience keeps syntheses in its own schema, outside epigraph's RLS and propagation.
* **Consequences:**
  * A share or publicize changes nothing on the episcience side.
  * An episcience synthesis that already quoted a private claim keeps the quote.
  * Synthesis nodes in `edges` contribute `'public'` to the meet (`epigraph_node_tenancy`
    returns public/world for any type other than claim or evidence), so an `edges` row between
    a synthesis and a moved claim takes the claim's tenancy, which is correct.
* **What this spec requires.** The share tools are **not** exported through federation, and an
  episcience tool cannot call them: they are epigraph-native, under `claims:write`, and
  `server.rs::enforce_federated_scope` already refuses delegated run tokens. The preview names
  any `edges` row from a synthesis node to an item, so the operator sees the episcience
  dependency.
* **No cross-instance publishing.** No code ships public claims to another epigraph instance,
  so "public" here means public on this instance only.

### 6.4 Events and webhooks

* **No event today.** `events` carries ids and numbers, not content, and 206 writes no `events`
  row, only `security_events`.
* **Filtering is already live.** Readers filter events against current visibility
  (`routes/events.rs::list_events`, which drops an event whose payload names a hidden claim via
  `ClaimRepository::hidden_claim_ids`), and so does webhook delivery
  (`routes/webhooks.rs::deliver_event`, against the subscriber's viewer). After a share, older
  events about the claim therefore become listable by the team. That is correct, because the
  team can now read the claim.
* **After an undo,** webhooks already delivered cannot be recalled. This is the same residual
  privatization has.
* **What the spec adds:** one `events` row per applied batch, `share.applied`, with `{plan_id,
  to_group_id, root_count}` and no claim ids. A subscriber who can read the plan can then fetch
  the items, and nobody else learns which claims moved. Open question 11 asks whether to fan
  out per claim instead.

## 7. Phasing and tests

### 7.1 Phases

Each phase is one PR, base `main`, with its own migration where noted, a
`docs/runbooks/<n>-undo.sql` (the 206 pattern, with a catalog round-trip test), and the
registrations listed after the table.

| phase | content | migration |
|---|---|---|
| **P1: claim-set hardening** | **R1's human-only gate on both 206 acts** (`refused_not_human`; drop share's author arm; the target writable by own membership); **recompute or vacate the DS cache of every moved claim (the leak in 4.6)**; `preview` mode on the two 206 acts (classification and dependent counts, no write); re-meet of evidence-endpoint edges in share and publicize; `harvester_sources` follow; `shared-fragment` hold; the lineage hull as an option (default per open question 5); the missing HTTP test for `share-with-team` | yes: `CREATE OR REPLACE` of the 206 definers with a new signature, keeping the old one as a wrapper |
| **P2: share plans and the publicize undo** | `share_plans`, `share_plan_items`, `share_plan_rows` (FORCE RLS); `share_settings` (maintenance-written, `publicize_undo_window` default 48 h); definers `epigraph_share_preview`, `epigraph_share_apply`, `epigraph_share_unpublicize` (R3, keeping attached claims); the `share.` prefix policy; MCP and REST surfaces; claim-set unit on plans; boundary edges included at the most restrictive meet (R5) | yes |
| **P3: workflow unit** | `epigraph_share_workflow_preview/apply`: every generation, level 0–2 claims, siblings, plan edges, exclusive atoms; catch-up; interaction with 202 tested | yes (definers) |
| **P4: subgraph selection** | the selection grammar, evaluated on the caller's connection, frozen; boundary report (edges included per R5) | yes (one STABLE invoker function; no new table) |
| **P5: move team → team** | human admin of the source who writes the target (R1, R2); `readers_losing` computed and any narrowing refused with `SHR11` (R2); the app counterpart of `regroup-claims`, with the same holds | yes (definer) |
| **P6: generic registry and ratchet** | `tenancy_share_registry`, seeded from section 2; the catalog ratchet; registries and `harvester_sources` as roots | yes |
| **P7: operator CLI parity** | `epigraph-operator share-{claims,workflow,selection}`, `publicize-*`, dry run by default, `--apply`, JSONL manifest; `reown-reverse` dispatches `share_plan` manifests: the undo of a share or a move (R2), and of a publicize after the window (R3), keeping attached claims (R4) | no |

**Order:** P1 first, then P2, which every later phase builds on. P3, P4 and P5 are independent
of each other. P6 can land any time after P2. P7 can land after P2.

**Every phase that adds a definer or a CLI verb also updates:**
* `definer_search_path_ratchet.rs` (pinned `pg_catalog, pg_temp`, no temporary relation);
* `tenancy_backfill.rs::DEFERRED_DEFINER_FUNCTIONS` (an owner that does not bypass makes the
  guard fail open);
* `elevation_arms_census.rs`;
* `maintenance_surface_register.rs`;
* `scope_map.rs` (`claims:write` for the acts, including `share_unpublicize`).

### 7.2 Test strategy

Adversarial, in the "council of critics" sense: every test must be able to fail on a plausible
wrong implementation. A test that only round-trips a happy path does not count.

1. **Run as the app role.** Every behavioural test runs on
   `ScopedPool::connect_downgraded_for_tests(.., "epigraph_app")`. CI's default connection is a
   BYPASSRLS superuser, so a leak is invisible on it (077's header records the same trap for
   `frames`).
2. **A leak test per dependent table.**
   * Fixture: a claim in the home group, with one row in **each** table of 2.1 rows 2–22 that
     can hang off a claim, one pinned evidence row, one writer-owned row, one outsider
     challenge, and one boundary edge of each class in 3.3.
   * After each act (share, move, publicize, and each undo), three principals read every table:
     a teammate, a non-member, and a member of the source group who is not in the team.
   * Expected readable sets are written out **per table**. They are not derived from the code
     under test.
   * One test per (act × table) pair, generated from the registry, so a table added later gets
     its test or fails the ratchet.
3. **Existence oracles.**
   * For each surface, an unreadable id must answer exactly as a missing id: same outcome,
     same HTTP status, same error text.
   * A shared successor of a private predecessor must not resolve `supersedes`, unless the hull
     moved the predecessor.
   * A teammate must not learn that a co-owned boundary edge exists, through
     `get_neighborhood`, `traverse`, counts, or `alternative_set`.
4. **Ratchets.**
   * Catalog-driven, in `tenancy_coverage.rs`'s pattern: every relation with `owner_group_id`
     or a group-keyed policy has a `tenancy_share_registry` row.
   * Every `root` has a `unit_resolver` that exists.
   * The `derived text[]` literal in `epigraph_propagate_tenancy` (read with
     `operator/tables.rs::parse_derived_array`) equals the registry's `follows_claim` set.
5. **Concurrency.**
   * A privileged session changes an owner and holds the transaction. The act waits, decides on
     the committed state, and either refuses or raises `VIS04`/`SHR04`. Nothing is partly
     written.
   * The same test runs for apply against a plan whose items changed after preview (a digest
     mismatch).
6. **Definer hardening.** The 206 temp-table planting test, repeated for every new definer.
   * The planted relations and triggers must not run.
   * The `search_path` write window must be closed again on every exit path, including the
     refusal path.
7. **Undo.**
   * Share then `reown-reverse` returns every untouched row to its exact before-image:
     byte-equal tuples, including `co_owner_group_id`, `writer_owned` and pins.
   * R4: a claim that a teammate attached evidence, a BBA, a trace or an edge to in between
     stays in the team. The teammate's row stays readable to the teammate, the claim is reported
     as `kept_attached`, and its hull members stay with it. The test fails if the row moves to
     the home group, or if the whole undo is refused.
   * A row changed by a third party is held, not overwritten.
   * Reversing twice changes nothing.
   * R2: the app has no undo for a share or a move. A test enumerates the MCP router and the
     REST route table and asserts that no app surface reaches `share_plan` reversal for those
     acts.
   * R3: inside the window, a human admin's `share_unpublicize` restores the before-images. At
     window + 1 s it answers `SHR12` and changes nothing. The test shrinks the window through
     `share_settings` and does not sleep. Changing the settings row on the app role is refused.
     A writer (not admin) is refused, and so is an operated agent of the admin. An outsider's
     evidence attached during the window keeps that claim public and listed `kept_attached`.
8. **Workflow-specific.**
   * After a share, a teammate's `add_step` on the lineage succeeds and `find_workflow` resolves
     the true head.
   * After a forced head-only share (if open question 7 allows one), the teammate's write is
     refused by 202 and not silently forked.
9. **DS cache.**
   * Fixture: a claim in the home group whose cached belief folds three things: a pinned
     evidence BBA, an edge-factor BBA from a home-private source, and a public source.
   * After a publicize, the anonymous reader's `belief` must equal the value recomputed from the
     public source alone. After a share, the teammate's must equal the value from the sources
     admissible in the team.
   * The test asserts the numbers, not the fact that a recompute ran. Against 206 as built, it
     fails.
10. **Atlas.** Undoing a publicize bumps `atlas_layout_epoch.n` exactly once per transaction, and
   a pre-undo run is no longer served.
11. **Sealed.** Each sealed class in 4.4 is held. A direct app-role UPDATE is still refused by 074
    and 115.
12. **R1, the human gate.** On every act (share, move, publicize, unpublicize, and the 206 tools
    after P1), each of these callers is refused with `refused_not_human` and changes nothing:
    * an operated epiclaw agent whose human is an admin of every group involved;
    * a stdio agent with an operator link;
    * an agent that itself holds an admin membership;
    * a human's delegated run token.

    The same human, calling directly, succeeds. The fixture gives the agent every membership,
    so the test fails if any membership arm, rather than the human test, admits it.
13. **R2, narrowing refused in the app.** A move from A to B, where one reader of A is not in B,
    answers `SHR11` with nothing written. Adding that reader to B makes the same plan apply. A
    private → team share where a non-human reader of the home group would lose read follows
    the open question 17 ruling.
14. **R5, boundary edges.** For each class in 3.3, the edge is in the plan's items and manifest
    after apply. Its tuple equals the most restrictive meet, and it is read by exactly the
    principals in both endpoint groups. This covers a teammate who is not in the home group, a
    home member who is not in the team, and a principal in both. A test also asserts that no
    act ever sets a boundary edge `public`.

## 8. Open questions for the operator

Questions 1–4 and 6 were ruled on 2026-11-12 (section 0.1). They keep their numbers so that
earlier references stay valid.

1. *Resolved by R1:* every act needs the human.
2. *Resolved by R2:* team → team is allowed in the app; narrowing is maintenance-only.
3. *Resolved by R3:* app undo within a configurable window, default 48 h; maintenance-only
   after it.
4. *Resolved by R4:* attached rows, and their claims, stay in the team.
5. **Lineage hull for a claim-set share.** Include the `supersedes` chain and `step_lineage`
   siblings by default (the safe choice), or only on request?
6. *Resolved by R5:* included, at the most restrictive meet of the endpoints.
7. **Workflow generations.** Always share every generation of a `canonical_name` (the
   recommendation, because of 202), or allow a head-only share that teammates cannot then
   extend?
8. **Level-3 atoms** that only this plan references and that are private in the source group:
   move them with the plan, or hold?
9. **Papers.** Should sharing or publicizing claims from an ingested document be refused until
   `papers` has tenancy (papers-tenancy-followup option 2)? Or should the existing residual be
   accepted and named in the preview?
10. **`harvester_sources` with mixed fragments.** Hold the whole share, or move the claims and
    leave the source behind, reported?
11. **Webhook fan-out.** Should a share emit an event that newly admitted subscribers receive?
    (See section 6.4.)
12. **Size.** Keep 500 roots per batch? Is there a cap on a whole plan (privatization's are
    unbounded but cursor-driven)?
13. **Large publicizes.** D-V2 says there is no second approver. Should that still hold above a
    size threshold (privatization's four-eyes applies only to narrowing)?
14. **Group-owned registry rows** (`frames`, `contexts`, `perspectives`, `communities`). Should
    they be shareable roots, or only ever instance-wide?
15. **Atlas after a publicize.** `atlas_layout` is a manual operator binary with no schedule.
    Should apply queue a rebuild, or should the layout stay stale until the next manual run?
16. **The DS cache fix for claims already shared or publicized under 206.** Should P1 include a
    one-off recompute of every claim named in a `claim.publicized` or `claim.shared_with_team`
    row, run on the maintenance connection?
17. **R2's scope.** This spec reads "reducing visibility is maintenance only" as covering any
    move that leaves a reader of the source unable to read the target. In that reading the app
    moves team → team only when the target's readers include all of the source's, which may be
    rare between two real teams. Is that the intent? And should the human's own role-attached
    agents count as readers lost when the human shares out of their personal group?
18. **Undoing a share in the app.** R3 gives a publicize a 48 h app-side undo, but a share undo
    narrows too, and R2 makes it maintenance-only. Should the same window apply to undoing a
    share or a move?
19. **Outsiders' attachments during a publicize window.** The in-window undo keeps public any
    claim that a principal outside the owning group attached a row to (R4 applied to the
    public). Would the operator rather the undo refuse entirely in that case?
