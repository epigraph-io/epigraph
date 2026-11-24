# Human identity visibility, and real names at provisioning

Status: design for implementation on `feat/human-identity-visibility`, mapped against
`origin/main` at `ffeb7bb3a` (head migration 271). Every surface below was re-read on that
head; the PR must re-verify each one again at commit time (§7 says how).

Section 16 lists every decision in this spec that the operator did not make directly. Each
one is marked either **[ORCHESTRATOR'S CALL]** or **[SPEC AUTHOR'S CALL]**. Items marked
**[OPEN]** need a ruling before or during implementation.

## 1. Intent

A human who signs in today becomes an `agents` row named `oauth:<client row id>`. That row is
world-readable (077 §9, `agents_identity ... USING (true)`), and every surface that names an
agent shows it to every caller. This change does two things:

1. A human principal gets their real name at provisioning, never an email address.
2. A human's name and identity are shown only to the callers the operator's rule admits (§4).
   Everyone else sees an agent indistinguishable from a nameless non-human one (§5). The id
   is still shown, so every claim stays traceable to its human.

## 2. Operator rulings (verbatim where quoted)

1. "Fix the codes so agent names go in like this": at provisioning, a human OAuth principal's
   `agents.display_name` is the person's real name, not `oauth:<client_row_id>`.
2. "A humans agent card is only public if they have made public claims. Otherwise they are
   visible only to their team members unless they chose to make themselves publically
   visible."
3. "Yes, a hidden human is just an unnamed agent id. Humans can't be hidden from team members.
   If a humans agents have made a claim that is public, then they should be tracable to that
   claim. No anonymous claims. The human might be a fake sock puppet, but it's still an
   accountability channel."
4. "make that privacy change as you described": the rule in §4 is the one the operator
   approved.
5. No backfill of existing display names in this PR (operator ruling). Only the provisioning
   path changes.

## 3. Terms

**Human principal (H).** An agent with structural, status-free evidence that it is a person:

```
EXISTS (oauth_clients c WHERE c.agent_id = H AND c.client_type = 'human')   -- any status
OR EXISTS (human_operators h WHERE h.agent_id = H)                          -- any state
```

`agents.agent_type` is not evidence: the legacy create path defaulted every row to `'human'`,
as `agent_lookup.rs` (module doc, "`kind`: derived from EVIDENCE") already records. No status
is read, so a suspension or a revocation can never flip a human between named and unnamed.
Flipping on status would let a reader watch the status change. Every non-human agent is
NAMED to everyone, as today. **[SPEC AUTHOR'S CALL]** (§16.B1).

This definition includes the agents of dynamic-registration (DCR) clients. `register.rs`
maps a DCR request and an explicit `client_type: "human"` registration to `client_type =
'human'` (`oauth/register.rs::register_endpoint`, `None => "human"`). Those agents keep the
`oauth:` placeholder name (§9), so hiding them costs nothing.

**Bound agents of H, B(H).** H itself, plus every agent ever bound to H:

- `operator_links` rows with `operator_id = H`, retired rows included (107; 161's succession
  inheritance writes its links here too), and
- `author_binding_clients` rows with `operator_id = H`, revoked rows included (149).

On HEAD nothing else binds an agent to a human. `role_agents` (166) binds an agent to a
ROLE, not to a person, so it is not in B(H) **[SPEC AUTHOR'S CALL]** (§16.B2). Delegated run
tokens act as an agent its delegator already operates through one of the two tables above.

## 4. The rule

H is **NAMED** to viewer V when any arm below holds. Otherwise H is **UNNAMED**.

| Arm | Condition | Source |
|---|---|---|
| self | V is H | approved rule |
| privileged | V is a maintenance Bypass viewer (`epigraph_bypass()`), or a live Elevated viewer (`epigraph_is_elevated()`) | approved rule |
| team | V's live group set (the stamped `epigraph.group_ids`: direct, role-derived and the 234 operator-readable teams, i.e. what `Viewer::resolve` yields) contains a group G such that G has `kind IN ('team','community')`, `status = 'active'`, and G is among H's live memberships (`epigraph_live_memberships_unbound(H)`: direct, 165 role-derived, 164 lapse, 235 allowance lapse). Personal, world and seed groups never count. | approved rule |
| opt-in | `agents.profile_visibility = 'public'` on H, set by H through the self-service definer (§8). Migration resets every human principal to `'group'` and new human principals are created as `'group'` (§10), so the value is evidence of consent. | approved rule |
| public claim | some agent in B(H) is `claims.agent_id` of a claim with `visibility = 'public'`, current or superseded (`is_current` is not read). This is sticky across binding changes: retiring a link or revoking an allowance never re-hides H. | approved rule ("No anonymous claims") |
| readable claim | V can read some claim whose `agent_id` is in B(H): `visibility = 'group' AND owner_group_id = ANY(V's groups)`. Whoever can read a claim can trace it to its human. | **[ORCHESTRATOR'S CALL]** (§16.A1) |

Consequences that follow directly from the rule and that the PR must state in its text:

- **A claim's filer, and the filer's human, are always NAMED to anyone who can read the
  claim.** Reading the claim satisfies the public-claim arm or the readable-claim arm. So the
  `authored_by` block's `agent` and `human` (§7, rows D1-D2) change only in name-only corner
  cases. The visible change is for `ingesters` that did not file the claim, and for paper
  authors.
- **No third party can make H NAMED by its own act alone**, with one exception that is
  recorded as a residual (§15.R2):
  - A stranger's ingest that names H as a pending author writes an `authored` edge, not a
    claim.
  - An `OPERATED_BY` edge any edge writer adds is not a binding.
  - Bindings are written only by maintenance or by H's own link flow.
  - Claims carry the filing principal's id.
- **The decision for "a member of only H's personal group"** **[SPEC AUTHOR'S CALL]**
  (§16.B3). Co-membership of H's personal group confers nothing: personal groups are
  excluded by the approved rule. The only agents in H's personal group are H's own live-linked
  agents and its allowlisted agents. Such an agent therefore reads H exactly as an outsider
  does until another arm holds. In practice another arm holds early: per 234 it reads H's
  teams, and once it has filed any claim it can read, the readable-claim arm holds. Both
  states are tested (§12.T4). The existing test name
  `an_operated_agent_sees_its_human_exactly_as_an_outsider_does` stays true.

## 5. The indistinguishability contract

For an UNNAMED human, every surface yields exactly what it yields for **N**: a nameless,
non-human agent with no human evidence, whose profile is `'group'` and has no ORCID or ROR.
The test fixture for N is a derived-key OAuth service principal with the same labels
(`oauth-principal`). Concretely:

- `display_name` is null. Where a surface substitutes a fallback label (ego `short_id`, graph
  `id[..8]`, papers `""`), it substitutes the same fallback it uses for N.
- `kind` is `unknown`, and `kind_evidence` holds none of `registered_human_operator`,
  `holds_disclosed_role` or `operator_of_bound_agent`.
- `roles` is `[]`: non-elevating assignments are hidden too. `role_attachments` is `[]`.
- `orcid` and `ror_id` are null, and so are `properties` and `profile_visibility` in
  `get_public_profile` (§7, row B1).
- H is never found by name, prefix, trigram, ORCID or ROR, and never listed as a same-name
  candidate. Not being found is what happens for N, which has no name to match.
- There is no "hidden" marker, no distinguishable 404, and no absence. The **id is never
  withheld**:
  - `operator_human` on a bound LLM agent's card becomes `{id: H, display_name: null}`;
  - `authored_by.*.human` becomes `{id, display_name: null}`;
  - `GET /api/v1/agents/:id` still answers 200.
- Every output is computed from the redacted value. For example, `derived_key_evidence` is
  fed the redacted name, so no output depends on the hidden name.

"Byte-identical" in the tests means equal after replacing H's and N's `id`, `public_key` and
`created_at` with placeholders. Viewer-scoped counts are data, not identity: N's fixture is
given the same edges when a test compares counts.

**Known trade-off, recorded and NOT changed (operator-approved behaviour).** The approved rule
keeps three things:

1. `operator_human: {id, display_name: null}` still tells an outsider "this id is some
   human".
2. The bound LLM agent's `kind_evidence` still contains `bound_to_visible_human`.
3. An unnamed H's own card reads `kind: unknown`.

The card set is therefore internally inconsistent for an outsider who looks at both cards.
The approved rule accepts this.

## 6. The single shared predicate

### 6.1 SQL (one core, two session wrappers)

All three functions are `SECURITY DEFINER` and owned by `epigraph_maintenance`. They use
172's form: `SET search_path = pg_catalog, pg_temp`, and every object is schema-qualified.
Every `CREATE` is followed by `REVOKE ALL ... FROM PUBLIC`.

```sql
-- THE rule. Audience passed explicitly. Maintenance-only EXECUTE: never granted to
-- epigraph_app, so no application session can ask about an arbitrary audience.
public.epigraph_agent_disclosure_for(
    p_target uuid, p_principal uuid, p_groups uuid[], p_privileged boolean)
  RETURNS TABLE (named boolean, details boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER COST 1000

-- The caller's session as the audience. Granted to epigraph_app.
public.epigraph_agent_disclosure(p_target uuid)
  RETURNS TABLE (named boolean, details boolean)
  -- = epigraph_agent_disclosure_for(p_target, epigraph_principal_id(),
  --       epigraph_session_groups(), epigraph_bypass() OR epigraph_is_elevated())

-- Name-only convenience. Granted to epigraph_app.
public.epigraph_human_named_to_viewer(p_target uuid) RETURNS boolean
  -- = COALESCE((SELECT named FROM epigraph_agent_disclosure(p_target)), false)
```

The core's body, in order (the decision is made in SQL; the Rust side only redacts):

1. `v_details_rule`: today's details rule, unchanged for every agent. It holds when any of
   these holds:
   - `p_privileged`;
   - `p_target = p_principal`;
   - `profile_visibility = 'public'`;
   - a live direct `group_memberships` row of `p_target` with `group_id = ANY(p_groups)`.

   This text replaces the four copies that exist today (§7, rows A1, A2, B1, B2; the brief
   said three, but `profile_details_visible` is a fourth).
2. If `p_target` is not a human principal (§3), return `(true, v_details_rule)`.
3. Otherwise evaluate `named` arm by arm, cheapest first: privileged, self, opt-in, team,
   public claim, readable claim. Return `(named, named AND v_details_rule)`.

`details` for a human is therefore never wider than today. A human NAMED only by a public
claim still has its ORCID hidden from outsiders, because its profile is `'group'`.
**[SPEC AUTHOR'S CALL]** (§16.B4).

The two claim arms are written as two `EXISTS`, so each one is an index probe (§11):

```sql
WITH b AS (SELECT p_target AS agent_id
           UNION SELECT l.agent_id FROM public.operator_links l WHERE l.operator_id = p_target
           UNION SELECT r.agent_id FROM public.author_binding_clients r
                  WHERE r.operator_id = p_target)
SELECT EXISTS (SELECT 1 FROM b WHERE EXISTS (SELECT 1 FROM public.claims c
                WHERE c.agent_id = b.agent_id AND c.visibility = 'public'))
    OR (pg_catalog.cardinality(p_groups) > 0 AND EXISTS (SELECT 1 FROM public.claims c
                WHERE c.visibility <> 'public' AND c.owner_group_id = ANY (p_groups)
                  AND c.agent_id IN (SELECT agent_id FROM b)))
```

Reads inside the core:

- `operator_links`, `claims` and `group_memberships` are FORCE RLS. They admit the core
  through `epigraph_definer_bypass()` because the owner is maintenance, the same mechanism 269
  relies on.
- Under a non-member owner, those reads return no rows and the human is UNNAMED: the core
  fails CLOSED. Its `tenancy_backfill` re-own register reports a silent no-op of the owner
  block.
- Re-verify that `epigraph_is_elevated()` (125, a maintenance-owned definer) answers correctly
  when it is called from inside another definer frame. It must read the SESSION's elevation
  pair, not `current_user`.

**One read fails OPEN, so it is pinned.** The human-evidence check (§3) decides whether the
rule applies at all: if it ever read empty, H would be treated as non-human and NAMED. It must
therefore key on `oauth_clients` (`client_type = 'human'`), which carries no row policy (077)
and which the maintenance owner reads under any owner state, and never on `human_operators`
alone (revoked from PUBLIC, readable only by its grantees). Every human principal has such a
client row by construction (`ensure_for_client` provisions humans only from a human client).
T10 asserts that a human stays human, and UNNAMED to an outsider, when the guarded owner block
is a no-op.

`COST 1000` makes the planner evaluate the call after every cheaper qual. This matters in
`match_ranked`, which scans every agent (§7, row A1).

The wrappers read the session settings that `ScopedPool::acquire_as` / `begin_as` stamp from a
resolved `Viewer`. On an UNSTAMPED connection the audience is the anonymous outsider, so the
fail direction is closed: teammates would see an unnamed human. Every surface in §7 must
therefore run on a stamped connection. The table marks the ones that do not today.

**Why the session wrappers read settings rather than taking binds** **[SPEC AUTHOR'S CALL]**
(§16.B5). An application-callable form with explicit audience arguments would answer "is H
named to a member of group X?" for any X. That is a membership oracle without even stamping.
The session form gives the answer 236 and 269 already accept: a holder of the application
DSN who self-stamps can probe, the same trust class as every principal-keyed policy (§15.R9).
The explicit-audience core exists only for the maintenance-run Atlas builder (§7, row H3),
whose documents are served to a whole map audience rather than to the builder.

### 6.2 Rust (one helper module)

Add `crates/epigraph-db/src/repos/agent_disclosure.rs`, re-exported from `epigraph_db`:

- `pub struct Disclosure { pub named: bool, pub details: bool }`.
- `AgentDisclosureRepository::disclosure(conn, ids) -> HashMap<Uuid, Disclosure>`: one
  statement over `unnest($1)` that calls `epigraph_agent_disclosure`. It replaces
  `AgentRepository::profile_details_visible`.
- `AgentDisclosureRepository::names(conn, ids) -> HashMap<Uuid, Option<String>>`:
  `CASE WHEN d.named THEN a.display_name END`. It is the ONE reader of another agent's
  `display_name` for output, and it replaces `authored_by.rs::display_names`, the human-name
  read in `cards_inner`, and the inline name reads in ego, graph and atlas.
- `AgentDisclosureRepository::names_for_audience(conn, ids, MapAudience)`: maintenance
  connections only. It calls the core with the map's audience:
  - the public map: `(NULL, '{}', false)`;
  - a team map: `(NULL, ARRAY[team], false)`.
- `pub fn redact_agent(agent: &mut Agent, d: Disclosure)`: nulls `display_name` when not named,
  and `orcid` / `ror_id` when not `details`. It is used by every route that serializes an
  `Agent` row.
- `pub fn disclosure_lateral_sql(alias) -> String`:
  `CROSS JOIN LATERAL public.epigraph_agent_disclosure({alias}.id) d_{alias}`, for the
  statements that decide in SQL (`cards_inner`, `match_ranked`, `get_public_profile`).

A new static lint (§14) refuses any other output read of `agents.display_name`, `orcid` or
`ror_id`.

## 7. Surface table

Columns: **site** (`path::function`), **today** (current behaviour on HEAD), **change**. Paths
are relative to `crates/`.

### A. Agent lookup (`epigraph-db/src/repos/agent_lookup.rs`)

| # | Site | Today | Change |
|---|---|---|---|
| A1 | `AgentLookupRepository::match_ranked` (MCP `find_agent`, REST `GET /api/v1/agents/search`, and `match_by_name` for the ingest author path) | Matches `fold_sql("a.display_name")` for every agent. The ORCID and ROR tiers use a copy of the details rule (`details_ok`, "`$4::bool OR a.profile_visibility = 'public'`"). | Match on the raw columns first. Then call `epigraph_agent_disclosure` once per MATCHED candidate (bounded by the match set, not by the table). Drop a candidate whose name tier is not `named`, or whose identifier tier is not `details`. An unnamed human is never found. The `details_ok` copy is deleted. |
| A2 | `AgentLookupRepository::cards_inner` (`card`, `cards`, `find`) | Raw `a.display_name`. `details_ok` copy for ORCID, ROR and `llm_model_visible`. Arms `holds_disclosed_role` and `operator_of_bound_agent` shown to every reader. Roles from 198 shown to every reader. | Uses the `disclosure_lateral_sql("a")` lateral. `display_name` becomes `CASE WHEN d.named`, and ORCID, ROR and llm_model use `d.details`. When not named: `operates_bound_agent`, roles and attachments are emptied, so `kind` falls to `unknown`. `kind_evidence` and `derived_key_evidence` are computed from the redacted name. |
| A3 | `cards_inner` step 3 ("The bound humans' names", `SELECT id, display_name FROM agents`) | `operator_human.display_name` shown to every reader. | `AgentDisclosureRepository::names`. The `operator_human.id` is unchanged. |
| A4 | `AgentLookupRepository::exact_name_candidates` (MCP ingest `candidates`) | Folded-equal names, viewer-free ("nothing here depends on the caller's viewer"). | Adds `AND public.epigraph_human_named_to_viewer(c.id)` after the `fname` join, so it is evaluated only for matches. The doc text changes: the result now depends on the caller's stamped session (the ingest transaction is stamped). |
| A5 | `AgentLookupRepository::author_nodes` (ingest report `display_name` of an explicit author) | Raw `a.display_name`. | The name returned for output goes through `names`. The internal checks (role node, system, reserved key, public key) are unchanged. |

### B. Agent repository (`epigraph-db/src/repos/agent.rs`)

| # | Site | Today | Change |
|---|---|---|---|
| B1 | `AgentRepository::get_public_profile` (no production caller; tests only) | Third copy of the rule. Returns raw `display_name` and `profile_visibility`. | Uses the lateral. `display_name` is gated by `named`. `properties`, `orcid` and `ror_id` are gated by `details`, and `profile_visibility` becomes `Option<String>`, shown only when `details`, so it is never a marker. |
| B2 | `AgentRepository::profile_details_visible` (`get_agent`, `list_agents`) | Fourth copy of the rule. | Deleted. Its callers use `AgentDisclosureRepository::disclosure`. |
| B3 | `AgentRepository::ensure_for_client` | `format!("oauth:{client_row_id}")` for every client type. | §9. |
| B4 | `epigraph_provision_oauth_agent` (077 definer) | Inserts using the column default `profile_visibility = 'public'`. | Re-stated (§10) to insert `'group'` when `p_agent_type = 'human'`. |

### C. REST agent routes (`epigraph-api/src/routes/agents.rs`)

| # | Site | Today | Change |
|---|---|---|---|
| C1 | `get_agent` (`/agents/:id`, `/api/v1/agents/:id`) | Raw name. ORCID and ROR redacted by B2. | `disclosure` and `redact_agent` on the existing `read_as` connection. |
| C2 | `list_agents` (pages, `?label=`, `?public_key=`) | Rows from `db_pool`; redaction on `read_as`. | Same as C1, per row (at most 100 rows a page). The ordering is unchanged and does not depend on names. |
| C3 | `get_agent_reputation` | `display_name: agent.display_name`. | `redact_agent`. |
| C4 | `create_agent` find-hit (posting a public key that `GET /api/v1/agents` serves returns that row) | Returns the existing row's `display_name`. Has no viewer, so ORCID and ROR are redacted for non-self, non-admin callers. | Add `ViewerExtractor`. On a find-hit, apply `disclosure` on a `read_as` connection. A newly created row echoes the caller's own input, as today. |
| C5 | `update_agent` (`PUT /api/v1/agents/:id`) | Writes through `AgentRepository::update` on `db_pool`. The application role holds no `UPDATE` on `agents` since 118, so re-verify that the route works at all (§15.R8). | New optional body field `profile_visibility`, applied through §8's definer on a `ScopedPool::begin_as(viewer)` transaction. It is accepted only when `:id` is the caller's principal, and refused 403 otherwise, `claims:admin` included. The response may carry `profile_visibility` only on the caller's own record. |
| C6 | `search_agents` | Through A1 and A2. | None beyond A1 and A2. |

### D. Claim and paper provenance (`epigraph-db/src/repos/authored_by.rs`)

| # | Site | Today | Change |
|---|---|---|---|
| D1 | `AuthoredByRepository::for_claim` (REST `GET /api/v1/claims/:id`, MCP `get_claim`; the guest card keeps only DOIs and titles, see `routes/guest.rs::sources_of`) | `display_names` raw for `agent`, `human`, ingesters, `named_by`, `added_by`. | `display_names` is replaced by `AgentDisclosureRepository::names` on the same `ScopedRead`. The filer and its human stay named (§4 consequence). |
| D2 | `AuthoredByRepository::for_paper_ingests` (REST `GET /api/v1/papers` ingests) | Raw names. | Same as D1. |

### E. Paper author listings (`epigraph-db/src/repos/paper.rs`)

| # | Site | Today | Change |
|---|---|---|---|
| E1 | `PaperRepository::author_listing` / `list_authors` / `list_authors_bounded` (`author_listing_columns`: "`a.id, a.display_name, ...`"), feeding MCP `query_paper` (`tools/paper_queries.rs`), REST papers (`routes/papers.rs`, `name: a.display_name.unwrap_or_default()`), D1, and the sources paper kind | Raw `a.display_name`. | `author_listing_columns` becomes `CASE WHEN public.epigraph_human_named_to_viewer(a.id) THEN a.display_name END`. Affiliations, position and role are the ingester's edge data, shown as for N. |
| E2 | **Explicit `authored` edge property `author_name`** (`paper.rs::AUTHORED_NAME_KEY`, written by `epigraph-mcp/src/tools/ingest_authors.rs`, `props[epigraph_db::AUTHORED_NAME_KEY] = ...author.name`) | The extraction's spelling of the author's name sits on an edge whose source is H's id. Agent-endpoint edges are `('public', world)` (120), so every edge reader that returns `properties` links the name to H. | **[OPEN]** (§16.C1). This is the largest scope risk. Proposed: redact `author_name` from `properties` of `authored` edges whose agent endpoint is not `named`, in the shared edge-row projection used by the edge read surfaces (REST edges, MCP neighbourhood/traverse, `agent_claims` `attribution`). The writer keeps writing it, because a later name-only ingest needs it to find the explicit author. Alternative: a follow-up PR with the residual recorded. |

### F. Political surfaces

| # | Site | Today | Change |
|---|---|---|---|
| F1 | `epigraph-api/src/routes/political.rs::epistemic_profile` | `display_name: agent.display_name`. | `redact_agent` on its `read_as` connection. |
| F2 | `routes/political.rs::compare_agents` | Same as F1, per agent. | Same as F1. |
| F3 | `epigraph-db/src/repos/political.rs::get_claim_genealogy` (`a.display_name AS agent_name` over `ORIGINATED_BY` / `AMPLIFIED_BY` edges) | Raw name. The edge target can be any agent. | `CASE WHEN public.epigraph_human_named_to_viewer(a.id) ...`. |
| F4 | `repos/political.rs::get_inflation_leaderboard` | Raw name, grouped by `a.display_name`. | Group by `c.agent_id` only, and project the name through the predicate. Every listed agent has a visible claim, so it is named; it is gated anyway so the rule is uniform. |

The other political handlers (`position_timeline`, `originated_claims`, `inflation_index`) read
`get_by_id` only as an existence check and expose no name: no change.

### G. Export

| # | Site | Today | Change |
|---|---|---|---|
| G1 | `epigraph-engine/src/export/prov.rs::export_provenance_prov_o` (MCP `export_provenance_prov_o`; CLI `bin/export_provenance.rs` under a maintenance bypass viewer) | `"display_name": agent.display_name` for each readable claim's filer. | Names go through `names` on the caller's connection. The MCP filers are named by construction (§4). The CLI is a privileged operator act, so everyone is named, as the rule says. |

### H. Graph, Atlas, sources

| # | Site | Today | Change |
|---|---|---|---|
| H1 | `epigraph-db/src/repos/ego.rs::EgoRepository::hydrate` (REST ego route, `read_as`) | `SELECT id, display_name FROM agents`; label falls back to `short_id`. | `names`. An unnamed human gets N's fallback label. |
| H2 | `epigraph-api/src/routes/graph_query_utils.rs::load_subgraph_conn` (`edges.rs::graph_full`, `graph_query.rs`, both stamped) | Inline `SELECT id, display_name FROM agents` in a route file. | Moves to `names`; the fallback label is `id[..8]` as for N. The unstamped `load_subgraph` wrapper has no caller on HEAD. Delete it, or keep it, knowing that its result would fail closed. |
| H3 | `epigraph-db/src/repos/atlas_leaf.rs::node_labels`, called by `epigraph-cli/src/atlas_nightly/build.rs` on a MAINTENANCE session (`bin/atlas_nightly.rs`: `MaintenancePool ... .viewer(SystemReason::ThemeClustering)`) | Raw `a.display_name` baked into stored leaf documents that are served to the map's whole audience. | `names_for_audience(conn, ids, map.audience())` with the map's audience (§6.2). A bypass viewer must NOT be the audience: it would name everyone in a public document. Deploy note: rebuild the stored leaf levels after deploy (§17). |
| H4 | `atlas_leaf.rs::read_leaf_rows` | Selects `c.id, a.id` and agent ids only. | None (ids only). It is listed because the brief named it. |
| H5 | `epigraph-db/src/repos/sources.rs::SourceOverviewRepository::agents` (agent kind) and the paper kind's authors (through E1) | `left(a.display_name, ...)`, grouped by the name. | Group by `a.id` only, and project the name through the predicate. Paging keys on `a.id::text`, so the name never orders anything. |

### I. MCP surface text and new tool (`epigraph-mcp`)

| # | Site | Today | Change |
|---|---|---|---|
| I1 | `server.rs` descriptions of `find_agent`, `get_agent`, `get_claim` | They say `operator_human` is "shown to every reader", and describe the `kind=human` arms. | Re-word: the id is always shown, the name is shown only under §4, and an unnamed human cannot be found by name. |
| I2 | New tool `set_profile_visibility` (§8) and its `scope_map.rs` row | None. | Added. |

### J. Re-verified: no change

| Site | Why no change |
|---|---|
| `epigraph-api/src/routes/guest.rs` | The card carries no `agent_id` and no `authored_by` (module doc "Who filed it"). `sources_of` keeps DOI and title only. Confirmed. |
| `claim.rs::get_by_id` (`LEFT JOIN agents s ON s.id = c.signer_id`) | Signer `public_key` only. |
| `agent_key.rs::attested_keys_for_claim` | Keys only. |
| `routes/crud.rs`, `routes/claims.rs` (`get_by_id ... public_key`), `submit.rs`, `webhooks.rs::agent_principal_exists`, `agent_prompt_history.rs` | Existence or key only. |
| `routes/belief.rs` (`SELECT properties FROM agents` for `competence_scopes`) | Internal computation; not returned. |
| `person_team_group.rs` / `routes/team_groups.rs` / `tools/team_groups.rs` | Group names and `invited_by` as an id only (see §15.R6). |
| CLI operator tools (`operator/system_agent.rs`, `bin/dekg.rs`, `bin/analyze_graph.rs`, `cache_owner_audit.rs`, `mass_function.rs::untyped_provenance_page` via `evidence_type_backfill`) | Maintenance, operator-facing: the privileged arm. |
| Events `actor_id`; world-readable `OCCUPIES` edges | Out of scope by ruling (§15). |

**Count: 30 production sites need a change (A1-A5, B1-B4, C1-C6, D1-D2, E1-E2, F1-F4, G1,
H1-H3, H5, I1-I2).** They span about 15 source files, plus the migrations. E2 is OPEN. H4 and
section J are re-verified as needing no change.

## 8. Opt-in surface

The opt-in is modelled on 209's `epigraph_set_agent_default_group`, the current successor of
206's self-service setter.

```sql
public.epigraph_set_profile_visibility(p_visibility text) RETURNS text
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
```

- **Who.** `epigraph_principal_id()` only, and never an argument, so the target is the
  principal. There is no operator arm, and no admin arm: "set BY H".
- **Refusals.** All of them change nothing:
  - `PVS01` (42501): no principal.
  - `PVS02` (22023): the value is not `'public'` or `'group'`. The existing CHECK admits
    only those two.
  - `PVS03` (42501): no `agents` row for the principal.
  - `PVS04` (55000): the UPDATE did not move exactly one row.
- **Write.** Lock the row (`FOR UPDATE`) and read the previous value. Open 206's write window
  (`set_config('search_path', 'public, pg_temp', true)`), run the UPDATE, close the window.
- **Audit.** One `security_events` row, `agent.profile_visibility_set`, with
  `agent_id = principal` and details `{previous, profile_visibility, migration, session_user}`.
- **Grants.** Owner `epigraph_maintenance`; EXECUTE revoked from PUBLIC and granted to
  `epigraph_app`.
- **Registration.** The new codes are registered in `epigraph-db/src/refusal_codes.rs` and
  mapped to caller errors.

Rust: `AgentRepository::set_profile_visibility_conn(tx, ProfileVisibility)`.

- **MCP.** `set_profile_visibility { visibility: "public" | "group" }` on the stamped
  transaction pattern `set_default_group` uses (`claim_helper::begin_author_stamped_tx`). The
  target is the stamped principal. Re-verify that for a human's own connector session this is
  the human's provider-client principal and not a signing agent.
- **Scope.** The MCP tool takes `claims:write`, matching `set_default_group`. The REST route
  keeps `agents:write` (C5). **[SPEC AUTHOR'S CALL]** (§16.B14); the brief is silent on scope, so
  this needs confirmation.
- **Description text.** "public: your name is shown to everyone; group: only to people who
  share a team or community with you, and to anyone who can read a claim you or your agents
  filed. Your id is always shown, and every claim stays traceable to you."

## 9. Real names at provisioning

### 9.1 The premise error in the brief

The brief says to use the provider-asserted name "for client_type 'human'". On HEAD that is
wrong. `register.rs` maps both a DCR request and an explicit human registration to
`client_type = 'human'`, with a client-chosen `client_name` (`oauth/register.rs`:
`None => "human"`, `"human" => ("pending", ...)`). Copying `client_name` for every human client
would let any registrant choose the display name of a "human". The discriminator must
identify PROVIDER provisioning.

### 9.2 The discriminator

**[SPEC AUTHOR'S CALL]** (§16.B6). `oauth/providers/provision.rs::provision_external_user_client`
is the only creator whose client ids have the form `<provider>:<subject>`
(`format!("{}:{}", provider.name(), identity.subject)`). Every other creator generates an id
with no `:` in it:

- `register.rs`, DCR and legacy human/service registration: `epigraph_<32 hex>`;
- `bootstrap.rs` service clients: `epigraph_<32 hex>`;
- agent clients: the 64-hex public key, and their type is `agent` anyway.

So `ensure_for_client` uses a pure function, unit-tested in `epigraph-db`:

```rust
fn provider_asserted_person_name(client_type: &str, client_id: &str,
                                 client_name: &str, legal_contact_email: Option<&str>)
    -> Option<String>
```

It returns `Some(name)` only when ALL of these hold:

- `client_type == "human"`;
- `client_id` contains `':'`;
- the name, trimmed and with whitespace collapsed:
  - is non-empty, at most 255 characters (`agents.display_name` is `varchar(255)`, and 001's
    `agents_display_name_not_empty` CHECK applies), and has no control characters;
  - **contains no `'@'`**;
  - **is not equal, case-insensitively, to `legal_contact_email`**.

The email guard exists because `provision.rs` stores
`identity.name.unwrap_or_else(|| email.clone())` as `client_name`, and `Some(&email)` as
`legal_contact_email`. An email must never become `display_name`. Otherwise the result is
`None` and the placeholder `oauth:<client_row_id>` stays. Non-human clients keep today's
behaviour exactly, including adopting the real signer row for agent clients.

A test per creator (§12.T7) pins that no non-provider creator mints an id containing `:`. If a
future creator does, that test fails, so the discriminator cannot drift silently.

### 9.3 Where the name is read

`epigraph_oauth_client_lock_for_link` returns `(agent_id, client_id, client_type)`. It gains
`client_name` and `legal_contact_email` (DROP + CREATE, §10.M2), so the name is read from the
same LOCKED row as `client_type`. That keeps today's property: "`client_type` is read from the
locked row ... so this site can no longer disagree with what is stored" (`oauth/token.rs::
materialise_principal_agent`).

Rejected alternative **[SPEC AUTHOR'S CALL]** (§16.B7): a plain `SELECT client_name, ...` in
the same transaction after the lock. The application role reads `oauth_clients`: it has no
policy (077) and keeps SELECT (118). That would avoid the DROP + CREATE, but it splits one
locked read into two statements.

### 9.4 What is not changed

- No backfill of existing rows (operator ruling 5). A client whose agent already exists keeps
  it: `ensure_for_client` returns early on a linked client.
- `provision.rs` still stores the email as `client_name` when the provider sends no name. That
  field is shown on consent and admin screens. Carrying the name separately is a follow-up
  (§15.F5).

## 10. Migrations

Numbers: the head is 271. 270 is a gap; do not fill it, because sqlx would apply a version
below the applied maximum. 265 is held by open PR #1028. Use the next free numbers above 271
**at commit time**, one file per decision:

- **M1 `272_human_identity_visibility.sql`** (transactional, `SET LOCAL lock_timeout = '3s'`,
  with the header sections WHY / RULE / SHAPE / WHAT IT TRUSTS / UNDO in 269's style):
  1. CREATE the three disclosure functions (§6.1) and `epigraph_set_profile_visibility` (§8).
     Each gets `REVOKE ALL ... FROM PUBLIC`. Then a guarded `DO` block:
     - `ALTER FUNCTION ... OWNER TO epigraph_maintenance` for all four;
     - `GRANT EXECUTE ... TO epigraph_app` for the two wrappers and the setter only.

     Each ALTER and GRANT names its function literally: `tenancy_backfill.rs`'s static
     re-own scan reads those statements.
  2. `CREATE OR REPLACE public.epigraph_provision_oauth_agent(bytea, text, text)`, which keeps
     owner and ACL. It inserts `profile_visibility = CASE WHEN p_agent_type = 'human' THEN
     'group' ELSE 'public' END`, and the ON CONFLICT re-find is unchanged.

     It moves to 172's form (`pg_catalog, pg_temp`, `pg_catalog.now()`), which shrinks the
     `PUBLIC_PATH_REGISTER` by one **[SPEC AUTHOR'S CALL]** (§16.B8). If
     `definer_search_path_ratchet`'s probes object, restate its existing `public, pg_temp`
     path verbatim instead.
  3. Reset every human principal (§3 predicate) with `profile_visibility <> 'group'` to
     `'group'`. Write one summary `security_events` row: `agent.profile_visibility_reset`,
     details `{migration, rows}`. No per-row audit.
  4. Precondition guard in 224's style: refuse (55000) if `epigraph_provision_oauth_agent`'s
     body is not 077's (md5), so a later re-body is never overwritten blind.
- **M2 `273_oauth_lock_for_link_client_name.sql`**: replace the lock function.
  - Precondition: the current body is 224's (md5), the same check 224 runs.
  - `DROP FUNCTION public.epigraph_oauth_client_lock_for_link(uuid)`, then CREATE it from
    224's body with the two extra columns (`c.client_name::text`,
    `c.legal_contact_email::text`), `SET search_path = pg_catalog, pg_temp`, `FOR UPDATE`
    kept.
  - A recreated function gets PUBLIC EXECUTE by default, so `REVOKE ALL ... FROM PUBLIC`.
  - Guarded re-own to `epigraph_maintenance` and re-GRANT EXECUTE to `epigraph_app`.
  - Old binaries keep working: they select three named columns. The new binary needs M2, and
    applies it at boot.
- **M3 `274_idx_claims_public_by_agent.sql`** (`-- no-transaction`, exactly one statement):
  `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_claims_public_by_agent ON public.claims
  (agent_id) WHERE visibility = 'public'`.
- **M4 `275_idx_claims_group_by_agent.sql`** (`-- no-transaction`, exactly one statement):
  `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_claims_group_by_agent ON public.claims
  (owner_group_id, agent_id) WHERE visibility <> 'public'`. It covers the minority partition,
  as 063 does.

Undo runbooks: `docs/runbooks/272-undo.sql` and `273-undo.sql` (269's convention):

- restore 077's provision body and 224's lock body, re-owned and re-granted;
- DROP the four new functions;
- the index undo is `DROP INDEX CONCURRENTLY IF EXISTS`.

The reset is NOT reversed by the undo. Its pre-state cannot be recovered, and it is the
privacy-safe value.

Registrations the PR must make (re-measure each list on HEAD):

- `epigraph-cli/src/bin/tenancy_backfill.rs`:
  - `DEFERRED_DEFINER_FUNCTIONS`: add the four new functions at 272. Move
    `("epigraph_oauth_client_lock_for_link", 118)` to 273, its latest re-own.
  - `OPERATOR_FUNCTION_GRANTS`, complete from 161: the three app grants at 272, and the lock
    function's re-grant at 273.
  - `epigraph_provision_oauth_agent` is in `PRE_REGISTER_DEFINERS`. M1 does not re-own it, so
    no entry moves. If the implementation does re-own it, move it out as 164 moved
    `epigraph_live_memberships`.
- `epigraph-db/tests/definer_search_path_ratchet.rs`:
  - new definers are on 172's form;
  - `PUBLIC_PATH_REGISTER` and `HIGH_WATER` shrink if M1.2 moves the path;
  - the lock function stays in `OAUTH_FAMILY_224` (same signature);
  - `the_oauth_family_resolves_in_pg_catalog_only` reads the new body at head, so qualify
    every builtin.
- `epigraph-db/tests/function_search_path_pg_temp_ratchet.rs` (271): `pg_temp` last
  everywhere.
- `epigraph-db/tests/app_role_table_lockdown.rs`: the lock function's grant list entry stays.
  Add the new app-executable definers wherever that test enumerates them.
- `tenancy_migration_shape.rs`: M3 and M4 are single-statement `-- no-transaction` files.

## 11. Performance plan

- **Non-human target, which is most evaluations.** The core does two index probes (the
  human-client check through `idx_oauth_clients_agent_id`, and the `human_operators` primary
  key) plus today's details rule. That is one function call per row where today there is an
  inline expression.
- **Human target.**
  - B(H) comes from `idx_operator_links_operator` and a scan of `author_binding_clients`, a
    small table.
  - The public-claim arm is one `idx_claims_public_by_agent` probe per bound agent, stopping
    at the first hit.
  - The readable arm is one `idx_claims_group_by_agent` scan per group in V's set, with
    `agent_id IN (b)`.
  - Without M3, a fleet agent with many group-only claims and no public one would make the
    probe walk all of its claims through `idx_claims_agent_id` with heap checks.
- **Bounded call sites.**
  - Cards: at most 200 per read (`CANDIDATE_POOL`).
  - List pages: at most 100.
  - `authored_by`: at most `1 + MAX_PAPERS` papers × `MAX_PAPER_AUTHORS` names plus the
    ingesters.
  - `match_ranked` and `exact_name_candidates`: evaluate after the name match (`COST 1000` and
    statement shape), so the cost scales with matches, not with the table.
- **Measurement before merge**, on a throwaway test database only.
  - Shape: a synthetic human with O(10³) bound agents (1,500), O(10⁵) claims (150k), mostly
    group-visibility, plus a control with zero public claims. The viewer has about 5 groups.
  - Run `EXPLAIN (ANALYZE, BUFFERS)` on:
    1. one core evaluation, no public claim (the worst case);
    2. the same with one public claim;
    3. a 200-card read;
    4. `find_agent` with a 2-character prefix.
  - Pass condition:
    - the plans use M3 and M4 and show no sequential scan of `claims`;
    - recorded p50 and max per evaluation are in the PR text.
  - Budget: worst case under 10 ms per human evaluation; non-human under 0.2 ms. Missing the
    budget blocks merge; it is not waived.
  - The test lives as an `#[ignore]`d measurement test,
    `epigraph-db/tests/human_identity_visibility_perf.rs`, run on the DB host.

## 12. Test plan

All new tests go in `epigraph-db/tests/human_identity_visibility.rs`, plus route and tool tests
in `epigraph-api/tests/` and `epigraph-mcp/tests/`. Each surface test builds:

- H: a human principal, `'group'`, no teams, no claims;
- N: the §5 control;
- an outsider O;
- a teammate T;
- the anonymous guest viewer `Viewer::public_only` where the surface admits one.

Each test also carries a CALIBRATION assertion that H is named to T, so a test cannot pass
by redacting everyone.

- **T1. Indistinguishability, per surface.** O's output for H equals O's output for N, modulo
  id, public key and created_at. Surfaces:
  - A1: H's exact name, prefix and ORCID all return no H;
  - A2, A3, A4, A5, B1;
  - C1-C4, at the HTTP level;
  - D1: an ingester that is H, on a claim filed by another agent;
  - D2, E1 (REST, MCP and `authored_by`), F1-F3, G1, H1, H2, H5;
  - H3, with the public and team audiences;
  - MCP `get_agent`, `find_agent`, `get_claim`, `query_paper` and `export_provenance_prov_o`.
- **T2. Accountability through a retired binding.**
  - Setup: bound agent A files exactly one public claim, then A's link is retired (107
    retire).
  - Assert: the guest viewer and O both see H named on H's card, on the claim's
    `authored_by.human` (199's bound-at names H at `created_at`), and in `find_agent`.
  - Assert: `operator_human` on A's card is null (retired), as today.
  - Repeat with a revoked 149 allowance instead of a link.
- **T3. Role-derived teammate.**
  - V holds role X; role X is bound to team G (165 `group_role_bindings`); H is a direct
    member of G. V sees H named.
  - The mirror case: H is in G through a role binding and V directly.
  - Exclusions, each with H unnamed: a suspended G; a revoked membership; V sharing only the
    world group, a seed group, or H's personal group.
- **T4. Personal group (§4 decision).**
  - H's live-linked bot, with no claims, and with H in no team: the bot's view of H equals
    O's.
  - After the bot files one claim it can read: H is named to the bot.
  - The same pair for an allowlisted (235) agent.
- **T5. Opt-in.**
  - H sets `'public'` through the definer: O and the guest viewer see H named. H sets
    `'group'`: H is unnamed again when no other arm holds.
  - Refused, with no row changed: O setting H's value (impossible by signature: it sets O's
    own); H's operated bot; a `claims:admin` caller on `PUT /api/v1/agents/:H`; a NULL
    principal; the value `'team'`.
  - The audit row exists, with the previous value.
  - MCP `set_profile_visibility` round trip.
- **T6. Superseded public claim.** A bound agent's only public claim is superseded, so it has
  `is_current = false` and its successor is group-only. H is still named to O.
- **T7. Provisioning names, one test per `oauth_clients` creator.** Through
  `ensure_for_client`:
  - provider client with a name gives the name;
  - provider client with email only (`client_name` = the email) gives the placeholder;
  - provider client with empty email and no name (`client_name = ''`) gives the placeholder;
  - provider name that equals `legal_contact_email` in another letter case gives the
    placeholder;
  - DCR human client named `"Ada Example"` gives the placeholder;
  - legacy `client_type: "human"` registration gives the placeholder;
  - service and agent clients behave as today.

  Also: a new human principal is `profile_visibility = 'group'`, and a new non-human one is
  `'public'`. And a pinning test that every creator's generated `client_id` has no `:` except
  the provider path. Plus unit tests of `provider_asserted_person_name`: control characters,
  257 characters, whitespace collapse, `@` anywhere.
- **T8. A stranger cannot unhide H.**
  - A stranger's ingest names H as a pending author on a public paper: H stays unnamed.
  - A stranger's `OPERATED_BY` edge from its agent to H: unnamed.
  - A stranger's public claim that mentions H's id in its content: unnamed.
- **T9. Privileged arms.** A maintenance bypass session and an elevated viewer see H named.
- **T10. Migrations.**
  - M1 reset, in production migration order (271's ratchet pattern): a human that is
    `'public'` before 272 is `'group'` after; a non-human is untouched; one summary audit row.
  - Definer pin tests in the style of `migration_269_definers_are_pinned_owned_and_granted`:
    owners, paths and ACLs. `epigraph_app` cannot EXECUTE the core, and can EXECUTE the
    wrappers and the setter. PUBLIC has no EXECUTE on any of them, nor on the recreated lock
    function.
  - M2's lock function returns the five columns and still takes the row lock.
  - Under a database where the guarded owner block no-ops (core owned by the migrating role
    rather than maintenance), a human principal still reads as human and UNNAMED to an
    outsider: the human-evidence check must not fail open (§6.1).
- **T11. Decide-alike.** For non-human targets, `disclosure().details` equals today's rule
  over a matrix of profile, self, shared-group and admin cases. This replaces
  `the_three_copies_of_the_profile_rule_decide_alike`.
- **T12. Static lint** (§14).

Every new test goes through the council-of-critics review: reject tautologies, mock-shaped
tests, happy-path-only tests and trivial round trips.

## 13. Existing tests that change, and why

Each one is updated deliberately; none is deleted to go green. The commit that touches each
one says why.

- **Fixture: `epigraph-db/tests/viewer_fixture.rs::make_human_operator`** (also used through
  `seed_human_operator`). It now also sets `profile_visibility = 'group'`, mirroring
  production provisioning **[SPEC AUTHOR'S CALL]** (§16.B9). A fixture human left at `'public'`
  would count as opted in and make every human test vacuous. Ripple, re-count at
  implementation time: `legacy_fleet_parent.rs`, `claim_authored_by.rs`,
  `author_binding_allowlist.rs`, `agent_lookup.rs`, `agent_identity_lineage.rs`,
  `shared_signer_retire.rs`, `epigraph-cli/tests/operator_link_identity_pubkey.rs`,
  `epigraph-api/tests/claim_authored_by_route.rs`, and in `epigraph-mcp/tests/`:
  `operator_http_signer_runtime_guard.rs`, `operator_startup_gate_test.rs`,
  `operator_ownership.rs`, `ingest_author_resolution.rs`, `get_claim_authored_by_app_role.rs`,
  `agent_lookup_tools.rs`. Each test that asserted a human's name, ORCID or kind to a
  non-teammate is updated, or names the arm that admits it.
- `agent_lookup.rs::the_operator_human_is_shown_to_every_reader`: the id is still shown to
  every reader, and the name is now shown only under §4. Rename it to say so. Assert an
  outsider gets `display_name: null` and a teammate gets the name.
- `agent_lookup.rs::an_operated_agent_sees_its_human_exactly_as_an_outsider_does`: the
  bot-equals-outsider equality stays. The expected result changes: the search for the
  humans' shared name returns no human for either viewer. T4 adds the after-a-claim case.
- `agent_lookup.rs::human_operator_status_is_shown_only_to_those_who_may_know_it`: to an
  outsider, the human with a bound agent becomes `unknown`, because `operator_of_bound_agent`
  is suppressed when unnamed. The self arm is unchanged.
- `agent_lookup.rs::a_human_some_agent_is_bound_to_reads_as_human_to_every_reader`: becomes
  "... to every reader it is named to". To an outsider it is `unknown`.
- `agent_lookup.rs::a_private_orcid_never_matches_and_is_never_shown`: for a human target, the
  ORCID tier now also needs `named`.
- `agent_lookup.rs::the_operator_human_does_not_move_with_client_or_registration_status`: still
  holds, because the rule is status-free. Its expected card content changes with the name
  rule. Re-assert that it is byte-identical before and after each event.
- `agent_lookup.rs` disclosed-role tests that read a `named_human` holder as an outsider
  (`roles_show_disclosed_assignments_and_never_the_admin_roster`,
  `the_auditor_roster_is_not_disclosed`,
  `a_disclosed_role_does_not_move_with_client_or_registration_status`): read the holder as a
  teammate or an opted-in holder, and add an outsider assertion of `roles == []`.
- `agent_lookup.rs::the_three_copies_of_the_profile_rule_decide_alike`: replaced by T11.
- `visibility_lint.rs::PROFILE_RULE_SITES` and `the_agent_profile_rule_is_one_text_at_every_site`:
  replaced by "every site calls `epigraph_agent_disclosure`, and no statement carries the
  profile predicate text".
- `agent_public_profile.rs`: human targets and the `Option` `profile_visibility`.
- `epigraph-mcp/tests/agent_lookup_tools.rs::every_reader_sees_the_operator_human_through_both_tools`:
  `operator_human.display_name` is null for an outsider; the id is unchanged.
- `epigraph-mcp/tests/ingest_author_resolution.rs` tests that find a registered human by name as
  a stranger (for example
  `an_explicit_agent_id_found_by_find_agent_is_the_author_and_a_stranger_cannot_make_it_assert`):
  the finder must be a teammate, or the human must opt in.
- `definer_search_path_ratchet.rs` (`PUBLIC_PATH_REGISTER`, `HIGH_WATER`) and the
  `tenancy_backfill.rs` registers, per §10.

## 14. Lints and ratchets the change touches

| Lint | Why it is touched |
|---|---|
| `no_unscoped_pool` | C4 and C5 gain stamped connections; no new unscoped site. |
| `cargo check -p epigraph-api --no-default-features` | The new route fields sit behind `db`. |
| `viewer_spend_lint` | New `&Viewer` parameters are spent. |
| `visibility_lint` | `PROFILE_RULE_SITES` is replaced. `EXPECTED_EXEMPTIONS` gains nothing: the new reads take no viewer, and `agents` is not `tier_a`. |
| `definer_search_path_ratchet` | See §10. |
| `app_role_table_lockdown` | See §10. |
| `edge_writer_signing_ratchet` | Unaffected: no edge writer changes. If E2 lands as proposed, it changes only an edge READ projection. |

**New static lint, `epigraph-db/tests/agent_name_disclosure_lint.rs`.** It refuses any SQL
literal that selects `display_name`, `orcid` or `ror_id` from an `agents` alias for output,
outside an allowlist:

- `agent_disclosure.rs`;
- writers;
- `ensure_for_client`;
- the internal checks in `author_nodes`;
- the operator CLI files in §7.J.

A missed or future surface fails CI, not review. This answers "enumerate all surfaces".

## 15. Residuals and out-of-scope follow-ups (recorded, not built)

- **R1. `OCCUPIES` edges** that role grants project (123) are world-readable. They say "this id
  holds role X", not a name. The operator question is still open. Out of scope by ruling.
- **R2. A keyed-team admin can add H directly, with no consent step** (`routes/groups.rs::
  add_member`; 263 §1 says the keyed routes "add members directly"). That makes H named to
  that group's members. Follow-up: count only memberships H accepted, or 164/263-made groups.
- **R3. A public DOI plus an author position re-identifies an unnamed author.** The paper text
  names its authors. An authorship edge is not a claim, so it does not name H. For a
  countersigned authorship (H's own act), whether it should count as a claim needs a ruling.
- **R4. Privatizing a public claim un-names H**, because the arm reads current `visibility`.
  Stickiness was ruled for binding changes only.
- **R5.** The team arm inherits 164's lapse and the group's `status`. A group's suspension
  changes named-ness only for that group's own members.
- **R6.** Invitations now need the invitee's id passed out of band, because `find_agent`
  cannot find an unnamed human. The invitee sees the inviter's id only.
- **R7. The approved `operator_human` trade-off** (§5).
- **R8. `PUT /api/v1/agents/:id` writes on a pool that has held no UPDATE on `agents` since
  118.** Verify whether it works at all. The opt-in goes through the definer on a stamped
  transaction regardless.
- **R9. Trust boundary.** `agents` stays world-readable to the application role (077 §9). A
  holder of the application DSN reads names directly, and can self-stamp to probe the session
  wrapper. This is the trust class of 236 and 269. The rule is enforced at every application
  surface, not as a database read boundary.
- **R10.** Events `actor_id` is out of scope by ruling. Guest routes were confirmed to drop
  agent identity (§7.J).
- **F1.** Author nodes from ingested literature and git authors are not human principals.
  Their names are public-source names, and they stay named.
- **F2.** Stored Atlas leaf documents built before deploy still carry names (§17).
- **F3.** Explorer UI copy should say "unnamed agent" neutrally. It must not say "hidden".
- **F4.** A row that gains human evidence AFTER creation keeps its earlier `'public'`.
  Through supported paths this cannot happen: a human client links only to a freshly
  provisioned derived row. Only abuse of the app-callable link definer could cause it (R9
  class). Hardening option: a consent timestamp column written only by the setter.
- **F5.** Have `provision.rs` stop storing an email as `client_name`, and carry the asserted
  name explicitly.
- **F6.** If E2 is deferred, it becomes a follow-up PR with the leak recorded.

## 16. Decisions not made by the operator (clearly marked)

### A. Orchestrator's call (recorded in the brief as such)

- **A1.** The readable-claim arm: V can read any claim attributed to B(H), so H is named to V.

Not a call by anyone below the operator, recorded here so it is not mistaken for one: the
`operator_human` trade-off (§5) is operator-approved behaviour, kept as approved and not
silently changed.

### B. Spec author's calls

- **B1.** The human-principal definition is structural and status-free (§3). It includes DCR
  human clients.
- **B2.** `role_agents` is not a human binding, so it is excluded from B(H).
- **B3.** H's personal-group co-membership confers nothing (§4). It is tested both before and
  after the bot's first claim.
- **B4.** A human's `details` = `named AND` today's details rule (§6.1).
- **B5.** The session wrappers read session settings. The explicit-audience core is
  maintenance-only (§6.1).
- **B6.** The provider-form `client_id` (`:`) discriminator, plus the email guard (§9.2).
- **B7.** DROP + CREATE of the lock function, rather than a second SELECT in the same
  transaction (§9.3).
- **B8.** The provision function moves to 172's path. The fallback is to restate its path
  verbatim.
- **B9.** `make_human_operator` sets `'group'`, with the ripple accepted (§13).
- **B10.** `get_public_profile.profile_visibility` becomes `Option`, and N's control profile is
  `'group'` (§5).
- **B11.** Two partial indexes rather than one composite. A summary audit row for the reset.
  `COST 1000`.
- **B12.** `PUT /api/v1/agents/:id` with `profile_visibility` is self-only, even for
  `claims:admin`.
- **B13.** Privatization of a public claim un-names H (R4): current visibility is read.
- **B14.** The opt-in tool's scope: `claims:write` on MCP (parity with `set_default_group`),
  `agents:write` on REST (the existing PUT scope). The brief is silent on scope; this needs
  confirmation.

### C. Open, needs a ruling

- **C1.** E2, the `author_name` edge property: redact it in this PR, or defer it to a
  follow-up with the residual recorded.
- **C2.** R3: whether a countersigned authorship of a readable paper should name H as a claim
  does.

## 17. Deploy notes

- Migrations apply at API boot. M3 and M4 build concurrently.
- After deploy, rebuild the Atlas leaf levels: run the Atlas nightly builder once, outside its
  schedule. Previously stored documents carry names built under a bypass viewer.
- MCP stdio clients pin their binary. Restart them so that the find_agent and get_agent text,
  and the new tool, are served.
