# Human identity visibility, and real names at provisioning

Status: design for implementation on `feat/human-identity-visibility`, mapped against
`origin/main` at `ffeb7bb3a` (head migration 271). Every surface below was re-read on that
head; the PR must re-verify each one again at commit time (§7 says how).

Section 16 lists every decision in this spec that the operator did not make directly. Each
one is marked either **[ORCHESTRATOR'S CALL]** or **[SPEC AUTHOR'S CALL]**. Items marked
**[OPEN]** need a ruling before or during implementation.

**Revision 2.** Two adversarial reviews (a leak hunt, findings L1-L15, and an
accountability / migration-safety / performance review, findings 1-20) were resolved into
this text. Section 18 maps every finding to where it is resolved, or says why it is rejected
or left open. Implementation is split: **part A** (migrations, the predicate, provisioning
names, the opt-in surfaces) and **part B** (every read surface in §7). Section 18 marks
which part each change lands in.

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
as `agent_lookup.rs` (module doc, "`kind`: derived from EVIDENCE") already records. Every
non-human agent is NAMED to everyone, as today. **[SPEC AUTHOR'S CALL]** (§16.B1).

The evidence is one function, `public.epigraph_is_human_principal(agent)` (§6.1). The rule,
the migration reset (§10) and the setter's non-human refusal (§8) all call it, so they
cannot disagree about who is human.

**Status.** The evidence reads no status, so a suspension or a revocation never turns a
human into a non-human. The rule as a whole is status-free **except for the team arm**, which
inherits two status reads from `epigraph_live_memberships_unbound` (236): a verb-made team
(`did:epigraph:group:%`, 164/263) counts only while `epigraph_is_human_operator(
epigraph_human_of(H, true))` holds (registration live, client `active`), and 235's allowance
lapse. The team arm also reads `groups.status = 'active'`. So suspending H's client makes H
UNNAMED to a teammate whose only arm was a 164/263 team. That is a status change a teammate
can watch. It is recorded in §15.R5 and pinned by §12.T3. The V side (`Viewer::resolve`) does
not filter `groups.status`, so V keeps reading a suspended group's claims, and the
readable-claim arm keeps H named wherever B(H) filed in that group.

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

**Why B(H) is sticky (verified on HEAD).** Each fact is a table invariant, not a convention:

- `operator_links` is keyed `agent_id PRIMARY KEY` (107), and its `operator_id` cannot change:
  191's and 257's guards reject `NEW.operator_id IS DISTINCT FROM OLD.operator_id`.
- `operator_links` rows are never deleted: the FKs are `ON DELETE RESTRICT`, there is no
  deleter, and the application role holds SELECT only.
- `author_binding_clients` refuses DELETE (149, `epigraph_author_binding_clients_refuse_delete`)
  and guards UPDATE.
- 161's succession writes an `operator_links` row for the successor. 180's
  `parent_agent_id` binds nothing. 166's `role_agents` confers nothing. There is no delegation
  table.

§12.T13 re-asserts these after a retire, so a new binding table, or a guard that is
loosened, fails a test.

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
- **A stranger's own writes cannot make H NAMED:**
  - A stranger's ingest that names H as a pending author writes an `authored` edge, not a
    claim.
  - An `OPERATED_BY` edge any edge writer adds is not a binding.
  - Bindings are written only by maintenance or by H's own link flow.
  - Claims carry the filing principal's id, so a stranger's claim that mentions H names
    nobody but the stranger.
- **Holders of group-admin authority CAN make H NAMED without H's consent.** Revision 1
  said only one exception existed; there are four (§15.R2, ruling **[OPEN] C3**):
  1. A holder of `groups:write` creates a keyed team (`routes/groups.rs::create_group`,
     `GroupRepository::create_with_admin_conn` inserts `kind = 'team'`). With `groups:admin`
     it then adds H directly (`routes/groups.rs::add_member`; 077's `group_memberships_tenancy`
     WITH CHECK admits `epigraph_is_group_admin(group_id)` for any `agent_id`). H's row is a
     live direct membership of an active team, so the team arm holds for every member of that
     team. `groups:admin` is in `canonical_scopes.rs::ADMIN_ONLY_SCOPES`, so this is an
     admin-tier act, not any team admin's.
  2. A live member of a community who holds `groups:admin` adds H to it
     (`repos/community.rs`, "adding requires the acting agent to hold a LIVE membership").
     The team arm counts communities.
  3. Any group admin's INSERT into `group_memberships` through the same 077 WITH CHECK.
  4. An admin of the team that owns a group claim filed by B(H) publicizes it
     (`epigraph_publicize_claims`, 242, refuses only non-humans and non-admins). The
     public-claim arm then names H to everyone. This one is accountability-positive (the
     claim is now public, so it must be traceable) and is ruled separately (**[OPEN] C4**).

  §12.T8 pins each of the four with the behaviour implemented now: the approved rule read
  literally ("team members"), option (a) of C3.
- **"Ever bound" is wider than `authored_by`'s attribution** (brief-literal, recorded, not
  changed). B(H) ignores the binding window, while `authored_by.human` uses 199's
  `epigraph_operator_bound_at(agent, created_at)`. So:
  - a claim an agent filed before H's link or allowance existed names H;
  - after a 149 allowance is revoked and the agent's other client is allowed for a second
    human, the agent's later public claims (made for the second human) still name H;
  - 123's `epigraph_link_legacy_authors` writes retired links in bulk for unlinked legacy
    authors, so the receiving human is named by every legacy public claim.

  The rejected alternative is an arm keyed on `bound_at(c.agent_id, c.created_at) = H`. It
  is exact, but it is a per-claim function call, so it cannot be an index probe, and it
  narrows the approved text "any agent ever bound to H". Narrowing approved rule text needs
  the operator (**[OPEN] C5**).
- **Only `claims.agent_id` counts** **[SPEC AUTHOR'S CALL]** (§16.B15). Ingest records
  (`paper --ingested_claim--> claim`, property `ingested_by`), evidence, challenges and
  BBAs filed by B(H) do not name H. Whether "no anonymous claims" covers a public ingest
  record is **[OPEN] C6**. If it does, the extra arm is an EXISTS on `edges`
  (`relationship = 'ingested_claim'`, `visibility = 'public'`,
  `properties->>'ingested_by' = ANY(B)`), which needs an expression index and must be
  budgeted under §11 before it is agreed.
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

**The null name is itself a marker on a real instance (findings L1 and 20; [OPEN] C7).**
`ensure_for_client` names every non-human OAuth principal `oauth:<client row id>`, never
null. A null-named agent exists in production only when `POST /api/v1/agents` omits the
name. So an `oauth-principal` agent with a null name and `kind: unknown` is, in practice, a
hidden human, and `GET /api/v1/agents?label=oauth-principal` enumerates them with no search.
`labels` (returned by `AgentResponse`) and `properties` can also differ from N's. The two
options put to the operator:

- (a) the redacted name is the placeholder a service principal shows,
  `oauth:<row id of H's provisioning client>`, which is what H's row held before ruling 1.
  An unnamed H is then byte-identical to a real service principal.
- (b) keep `display_name: null`, as the brief says, and record the marker and the
  list-by-label enumeration as known.

Part B implements (b), the brief's literal text, until the operator rules, and must not
switch silently. The main session (not a subagent) measures how many nameless derived
non-human agents exist on the instance and puts the number to the operator with C7.
Whichever is ruled, T1's N is built **production-shaped**: through `ensure_for_client` with
a `service` client, then given whatever name the ruling assigns (null under (b), the
placeholder under (a)). The comparison includes `labels`, and `properties` on B1.

Concretely:

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

`operator_human` is **not** the only id-level human signal. The others are recorded in §15
(R7, R11 the TGP03 invite oracle, R12 world-readable `OPERATED_BY` edges,
R13 timing, R14 assessment-slot BBAs). The pending-papers count (L11) is served as
computed to every reader, for H as for N (§7 row A2). Revision 2 zeroed it for an unnamed
H on the premise that "a pending explicit attachment exists only for a registered person";
that premise is false (`ingest_authors.rs::check_explicit_author_ids` has no human gate,
so an ingester may name any non-system, non-role agent), and zeroing it for unnamed humans
only made `0` a hidden-human marker (review findings leaks#2, correctness#2).

## 6. The single shared predicate

### 6.1 SQL (one evidence helper, one core, two session wrappers)

All four functions are `SECURITY DEFINER` and owned by `epigraph_maintenance`. They use
172's form: `SET search_path = pg_catalog, pg_temp`, and every object is schema-qualified.
Every `CREATE` is followed by `REVOKE ALL ... FROM PUBLIC`. They land in migration 272 (§10).

```sql
-- Human evidence (§3). Maintenance-only EXECUTE: definers call it as their owner.
public.epigraph_is_human_principal(p_agent uuid) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER

-- THE rule. Audience passed explicitly. Maintenance-only EXECUTE: never granted to
-- epigraph_app, so no application session can ask about an arbitrary audience.
public.epigraph_agent_disclosure_for(
    p_target uuid, p_principal uuid, p_groups uuid[], p_privileged boolean)
  RETURNS TABLE (named boolean, details boolean)
  LANGUAGE plpgsql STABLE SECURITY DEFINER COST 1000

-- The caller's session as the audience. Granted to epigraph_app. COST 1000.
public.epigraph_agent_disclosure(p_target uuid)
  RETURNS TABLE (named boolean, details boolean)
  -- = epigraph_agent_disclosure_for(p_target, epigraph_principal_id(),
  --       epigraph_session_groups(), epigraph_bypass() OR epigraph_is_elevated())

-- Name-only convenience. Granted to epigraph_app. COST 1000.
public.epigraph_human_named_to_viewer(p_target uuid) RETURNS boolean
  -- = COALESCE((SELECT named FROM epigraph_agent_disclosure(p_target)), false)
```

**Cost.** `COST 1000` is declared on the core AND on both wrappers. A SECURITY DEFINER
function with a `SET` clause is never inlined, so the planner orders quals by the cost of
the function the statement calls, which is a wrapper. Cost ordering applies only among quals
of one plan node, so it is a hint, not the guarantee: the guarantee is the statement shape
(§7 rows A1, A4: the predicate is a qual of the level after the name match).

The core always returns exactly one row (an unknown `p_target` reads as a non-human with no
profile), so a `CROSS JOIN LATERAL` over it never drops the outer row.

The core's body, in order (the decision is made in SQL; the Rust side only redacts):

1. `v_details_rule`: today's details rule, unchanged for every agent. It holds when any of
   these holds:
   - `p_privileged`;
   - `p_target = p_principal`;
   - `profile_visibility = 'public'`;
   - a live direct `group_memberships` row of `p_target` with `group_id = ANY(p_groups)`.

   This text replaces the four copies that exist today (§7, rows A1, A2, B1, B2; the brief
   said three, but `profile_details_visible` is a fourth). Part A creates the core; part B
   moves the four sites onto it.
2. If `p_target` is not a human principal (`epigraph_is_human_principal`), return
   `(true, v_details_rule)`.
3. Otherwise evaluate `named` arm by arm, cheapest first, returning at the first that holds:
   privileged, self, opt-in, team, public claim, readable claim. Return
   `(named, named AND v_details_rule)`.

`details` for a human is therefore never wider than today. A human NAMED only by a public
claim still has its ORCID hidden from outsiders, because its profile is `'group'`.
**[SPEC AUTHOR'S CALL]** (§16.B4).

**The claim arms are forced per-row probes** (finding 2). B(H) is materialised into an
array first; each arm is then a `LATERAL ... LIMIT 1` probe per bound agent, so the planner
has no join method to choose and cannot pick a hash semi-join over a whole partition:

```sql
v_bound := ARRAY[p_target]
        || ARRAY(SELECT l.agent_id FROM public.operator_links l WHERE l.operator_id = p_target)
        || ARRAY(SELECT r.agent_id FROM public.author_binding_clients r
                  WHERE r.operator_id = p_target);
-- public claim
EXISTS (SELECT 1 FROM pg_catalog.unnest(v_bound) b(agent_id)
        CROSS JOIN LATERAL (SELECT 1 FROM public.claims c
                             WHERE c.agent_id = b.agent_id AND c.visibility = 'public'
                             LIMIT 1) x)
-- readable claim (only when p_groups is non-empty)
EXISTS (SELECT 1 FROM pg_catalog.unnest(v_bound) b(agent_id)
        CROSS JOIN LATERAL (SELECT 1 FROM public.claims c
                             WHERE c.agent_id = b.agent_id AND c.visibility <> 'public'
                               AND c.owner_group_id = ANY (p_groups)
                             LIMIT 1) x)
```

The probes use `idx_claims_public_by_agent (agent_id) WHERE visibility = 'public'` and
`idx_claims_group_by_agent (agent_id, owner_group_id) WHERE visibility <> 'public'`
(§10, M4/M5). B(H)'s `author_binding_clients` read uses a new
`idx_author_binding_clients_operator (operator_id)` (finding 16; 149 created only the
primary key and the one-live-per-agent index).

Reads inside the core:

- `operator_links`, `claims` and `group_memberships` are FORCE RLS. They admit the core
  through `epigraph_definer_bypass()` because the owner is maintenance, the same mechanism 269
  relies on. Maintenance holds SELECT on `operator_links` (107), `author_binding_clients`
  (149) and `human_operators` (122).
- **Owner states** (finding 10b corrects revision 1). Under a superuser owner the core works
  unchanged: a superuser bypasses row security, so the reads succeed. The sqlx test runner,
  and the production migration runner per 212/238's headers, are superusers, so the guarded
  owner block's no-op is invisible there. Only under a non-member, NOSUPERUSER, NOBYPASSRLS
  owner do the FORCEd reads return no rows; then the claim and team arms never hold and the
  human is UNNAMED: the core fails CLOSED. `tenancy_backfill`'s re-own register reports the
  no-op. §12.T10 builds that owner explicitly.
- `epigraph_is_elevated()` (125) reads only session settings and `elevation_sessions` in its
  own definer frame; `epigraph_bypass()` reads `session_user`. Both answer for the SESSION
  inside the core's frame (verified on HEAD; finding 5).

**One read fails OPEN, so it is pinned** (finding 10a). The human-evidence check decides
whether the rule applies at all: if it ever read empty, H would be treated as non-human and
NAMED. It keys on `oauth_clients` (`client_type = 'human'`), which carries no row policy
(077), and on `human_operators`. For a provider-provisioned human who is not a registered
operator, the `oauth_clients` row is the only evidence, and `human_operators.client_id ON
DELETE RESTRICT` does not protect it. Migration 272 therefore adds a trigger,
`epigraph_oauth_clients_human_evidence_guard`, that refuses (SQLSTATE 55000, code `HEV01`)
a DELETE of a `client_type = 'human'` row that is linked to an agent, and an UPDATE that
changes `client_type` away from `'human'` on such a row. On HEAD no code deletes such a row
or updates `client_type` (re-verified by grep). The application role can INSERT
`oauth_clients` (122's header), which is the R9-class route to FORGING human evidence; a
forged row only ever hides an agent, never names one.

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
| A1 | `AgentLookupRepository::match_ranked` (MCP `find_agent`, REST `GET /api/v1/agents/search`, and `match_by_name` for the ingest author path) | Matches `fold_sql("a.display_name")` for every agent. The ORCID and ROR tiers use a copy of the details rule (`details_ok`, "`$4::bool OR a.profile_visibility = 'public'`"). | **Normative placement** (findings L6, 3): the disclosure predicate is a `WHERE` qual of the `ranked` level, after the raw name and identifier match quals (never in `cand`, which scans every agent), so it is evaluated before `ORDER BY ... LIMIT $6`. A candidate whose name tier is not `named`, or whose identifier tier is not `details`, never takes a pool slot, never shifts a rank, and is never counted: `find`'s `candidates_truncated` (`matches.len() > pool`) counts survivors only. Dropping after the fetch (in `find` or `cards_inner`) is forbidden: 200 decoy agents named like H would otherwise flip the flag. The `details_ok` copy is deleted. |
| A2 | `AgentLookupRepository::cards_inner` (`card`, `cards`, `find`) | Raw `a.display_name`. `details_ok` copy for ORCID, ROR and `llm_model_visible`. Arms `holds_disclosed_role` and `operator_of_bound_agent` shown to every reader. Roles from 198 shown to every reader. | Uses the `disclosure_lateral_sql("a")` lateral. `display_name` becomes `CASE WHEN d.named`, and ORCID, ROR and llm_model use `d.details`. When not named: `operates_bound_agent`, roles and attachments are emptied, so `kind` falls to `unknown`. `counts.pending_authored_papers` is served as computed, to every reader (finding L11 re-decided after review: an ingester can name ANY agent pending, so the count is not human evidence, and hiding it for unnamed humans only was itself the marker; review findings leaks#2, correctness#2). `kind_evidence` and `derived_key_evidence` are computed from the redacted name. |
| A3 | `cards_inner` step 3 ("The bound humans' names", `SELECT id, display_name FROM agents`) | `operator_human.display_name` shown to every reader. | `AgentDisclosureRepository::names`. The `operator_human.id` is unchanged. |
| A4 | `AgentLookupRepository::exact_name_candidates` (MCP ingest `candidates`) | Folded-equal names, viewer-free ("nothing here depends on the caller's viewer"). | Adds `AND public.epigraph_human_named_to_viewer(c.id)` as a qual of `m`'s `WHERE`, after the `fname` join, so it is evaluated only for matches. There `pg_catalog.count(*) OVER (PARTITION BY q.ord)` counts only survivors, so the ingest's `candidates_truncated` is safe (finding L16). The doc text changes: the result now depends on the caller's stamped session (the ingest transaction is stamped). |
| A5 | `AgentLookupRepository::author_nodes` (ingest report `display_name` of an explicit author) | Raw `a.display_name`. | The name returned for output goes through `names`. The internal checks (role node, system, reserved key, public key) are unchanged. |
| A6 | `epigraph-mcp/src/tools/ingest_authors.rs::resolve_document_authors`, the `same_spelling` matcher (`e.explicit && e.author_name.as_deref() == Some(a.name.as_str())`) feeding `declined` and then `also_at_position` (finding L3) | Matches the hidden spelling on another ingester's explicit `authored` edge and reports that edge's agent id: a name-to-id oracle. | Only the `declined` half is gated. When the edge's writer is not the caller, `same_spelling` may match it only if its agent is `named` to the caller (`epigraph_human_named_to_viewer`, on the ingest's stamped transaction); otherwise the edge does not reach `also_at_position`. The `at_position` half (every agent at the same extraction position, whatever the spelling) is the DOI-plus-position exposure §15.R3 already accepts, and is unchanged. |

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
| C5 | `update_agent` (`PUT /api/v1/agents/:id`) | Writes `display_name`, `labels`, `orcid`, `ror_id` through `AgentRepository::update` on `db_pool`. 118 grants the application role `UPDATE (display_name, labels, orcid, ror_id, properties, updated_at)` on `agents`, and `agents_self_update` admits only bypass, definer bypass or `id = principal`, so on the unstamped pool the profile write moves no row (§15.R8). `profile_visibility` is NOT in 118's column grant. | **Part A.** New optional body field `profile_visibility`, applied through §8's definer on `AppState::write_as(viewer)`. It is accepted only when `:id` is the caller's principal, and refused 403 otherwise, `claims:admin` included. A non-human caller is refused by the definer (PVS05, 403). The response is the caller's own record. **After review (correctness#7):** a body that mixes `profile_visibility` with any other field is refused 400 before anything is written (the edit and the opt-in run on different connections, so a mixed body could half-commit), and every response is redacted through `AgentDisclosureRepository::disclosure` on the caller's stamped read, so a `claims:admin` edit of another agent never echoes a withheld name even once R8 is fixed. |
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
| E2 | **Explicit `authored` edge properties `author_name` and `replaces`** (`paper.rs::AUTHORED_NAME_KEY` / `AUTHORED_REPLACES_KEY`, written by `epigraph-mcp/src/tools/ingest_authors.rs::authored_edge_properties`) | The extraction's spelling of the author's name sits on an edge whose source is H's id. `replaces` names the retracted name-derived node, whose `display_name` is the name and whose key is `name_key(name)`, so it links H's id to a public agent carrying H's name. Agent-endpoint edges are `('public', world)` (120). | **Resolved in this PR (part B), not deferred** (finding L2; C1 closed). In the shared edge-row projection, `author_name` AND `replaces` are removed from `properties` of `authored` edges whose agent endpoint is not `named` to the viewer. Whether `affiliations` is identity is **[OPEN] C8**; until ruled it is shown as for N (the ingester's edge data). The writer keeps writing all three, because a later name-only ingest needs them (row A6 gates that matcher). Every surface that returns edge `properties` gets a row of its own: E3. |
| E3 | Edge read surfaces that return `properties`: `routes/edges.rs` (list, get, `graph_full`), `routes/graph_neighborhood.rs`, MCP `get_neighborhood` / `traverse` / `entity_neighborhood`, `routes/agents.rs::agent_claims` (`attribution`). Part B re-greps `properties` in each and adds any other. | Raw `properties`. | Each goes through the E2 projection. Each gets a T1 row. |

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
| H6 | `epigraph-api/src/routes/graph_query.rs::execute_graph_query` (`"agent" \| "agents" => GqlNodeTable::Agents`, `GqlColumn::Property`) and `epigraph-db/src/repos/graph_view.rs::graph_query_node_ids` (`format!("properties->>'{name}'")`; `anchor_marker` is empty for agents because `table.tenanted()` is false) (finding L5) | `MATCH (a:agent) WHERE a.full_name = "..."` (or `email`, with `<` / `>` for a binary search) returns the ids whose `properties` match: a matcher on a details-gated field. Also `display_name` matches. | Each agent anchor row is gated before the `LIMIT`: a predicate on `properties` requires `(SELECT details FROM public.epigraph_agent_disclosure(n.id))`, and one on `display_name` requires `named`. A GQL predicate on H's `full_name` or name returns no H (T1). `graph_view.rs` joins the `agent_name_disclosure_lint` scope. |

### I. MCP surface text and new tool (`epigraph-mcp`)

| # | Site | Today | Change |
|---|---|---|---|
| I1 | `server.rs` descriptions of `find_agent`, `get_agent`, `get_claim` | They say `operator_human` is "shown to every reader", and describe the `kind=human` arms. | Re-word: the id is always shown, the name is shown only under §4, and an unnamed human cannot be found by name. |
| I2 | New tool `set_profile_visibility` (§8) and its `scope_map.rs` row | None. | **Part A.** Added. |
| I3 | `epigraph-mcp/src/errors.rs::db_caller_error` (`OperatorScopeRefused { .. } ... message: Cow::from(e.to_string())`), fed by 122's `epigraph_require_attributable` (`'OPL02: agent % writes a claim attributed to %, which belongs to human operator %, ...'`) (finding L8) | MCP forwards the raw database text, which names "belongs to human operator <id>". REST already maps it to fixed text (`epigraph-api/src/errors.rs`). | Map OPL01 and OPL02 in MCP to the same fixed text REST uses; keep the ids in the log. **PLAUSIBLE:** which MCP tool lets a caller choose `claims.agent_id` other than the writer (the supersede and attribution paths are the candidates) is re-verified in part B; if none can, the row becomes a §15 entry. |

### K. Role-holding projection edges (operator ruling 2026-11-24, after review)

Operator: "Make the OCCUPIES role edges team-only too." Moved here from §15.R1 and §7.J.

| # | Site | Today | Change |
|---|---|---|---|
| K1 | `migrations/130_pending_admin_acts.sql::epigraph_role_assignments_audit` (the only `OCCUPIES` writer on HEAD; 123's body re-stated by 130), its revoke/expiry arm, `group_role_bindings` changes, and every existing row | `holder -OCCUPIES-> role node` written `('public', world)` with `properties.role`: an outsider reads "this id holds role X" on `list_edges`, `get_neighborhood` / `traverse`, graph query and `graph_full`, while the card shows `roles: []`. | Migration 278 (§10 M7): owner = the role's single live binding's group when it is an active team/community, else the holder's personal group **[ORCHESTRATOR'S CALL, §16.A2]**; the personal group is minted by 105's function when absent **[FIX AGENT'S CALL, §16.A3]**; a bind/unbind re-owns the role's edges; every existing row is backfilled. Read surfaces are unchanged (edge row security already filters a `group` edge). The ego view and PROV export cannot reach an agent-to-agent edge (claim-centred / claim-rooted). |

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
| Events `actor_id` | Out of scope by ruling (§15). The `OCCUPIES` edges were here until the operator's 2026-11-24 ruling; they are now row K1. |
| `epigraph-db/src/repos/agent.rs` create tail (`"agent.registered", Some(id), &serde_json::json!({"agent_id": id, "display_name": display_name,`) | Human principals are created by `epigraph_provision_oauth_agent`, which emits no event, so no real name reaches `events` (no row policy) today. Pinned by §12.T7 (provisioning a provider human writes no `events` row containing the name) and by the lint (§14). |
| `services/explorer/src/ttl.rs::ResponseCache` | 60 s per-session cache keyed by `RequestAuth::cache_key`: delays an opt-out by up to 60 s, never crosses sessions. Note only. |
| `scripts/label_themes_llm.py` (`COALESCE(a.display_name, 'unknown') AS agent`) | Samples public claims only, whose filers the public-claim arm names, so it is consistent today. Part B drops the cosmetic agent column (finding L13); stored labels are a stale derivative (§15.F2). |

**Count: 34 production sites need a change (A1-A6, B1-B4, C1-C6, D1-D2, E1-E3, F1-F4, G1,
H1-H3, H5-H6, I1-I3).** They span about 20 source files, plus the migrations. Part A changes
B3, B4, C5 and I2; part B changes the rest. H4 and section J are re-verified as needing no
change.

## 8. Opt-in surface

The opt-in is modelled on 209's `epigraph_set_agent_default_group`, the current successor of
206's self-service setter. It lands in migration 273 (§10).

```sql
public.epigraph_set_profile_visibility(p_visibility text)
  RETURNS TABLE (previous text, profile_visibility text, named_to_everyone boolean)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
```

- **Who.** `epigraph_principal_id()` only, and never an argument, so the target is the
  principal. There is no operator arm, and no admin arm: "set BY H".
- **Refusals.** All of them change nothing:
  - `PVS01` (42501): no principal.
  - `PVS02` (22023): the value is not `'public'` or `'group'`. The existing CHECK admits
    only those two.
  - `PVS05` (42501): the principal is not a human principal (`epigraph_is_human_principal`,
    §3). Without it, an operated LLM agent or a service principal calling the tool would
    "succeed" by setting its own, irrelevant row (finding 17).
  - `PVS04` (55000): the UPDATE did not move exactly one row.

  Revision 1's `PVS03` (no `agents` row) is dropped: a human principal has an `agents` row
  by its evidence's foreign keys.
- **Write.** Lock the row (`FOR UPDATE`) and read the previous value, then UPDATE. No
  search_path write window: 206's window existed because invoker triggers on `agents`
  resolved unqualified names through the definer's path, and 271 pinned every trigger
  function's own path, so the body stays on `pg_catalog, pg_temp` throughout.
- **Return.** The previous value, the new value, and `named_to_everyone`: whether an
  anonymous outsider sees H named after the write (`epigraph_agent_disclosure_for(principal,
  NULL, '{}', false)`). Setting `'group'` while a public claim of B(H) exists therefore
  answers `named_to_everyone = true`, so the caller is told the truth.
- **Audit.** One `security_events` row, `agent.profile_visibility_set`, with
  `agent_id = principal` and details `{previous, profile_visibility, migration, session_user}`.
- **Grants.** Owner `epigraph_maintenance`; EXECUTE revoked from PUBLIC and granted to
  `epigraph_app`.
- **Refusal mapping.** Revision 1 said the codes are registered in
  `epigraph-db/src/refusal_codes.rs`. That is wrong: `CALLER_REFUSAL_CODES` is pinned to
  exactly migration 176's set by `caller_refusal_codes_restatement.rs`. The PVS codes are
  mapped the way the VIS codes are, by a local mapper beside the repo function
  (`claim_visibility.rs::map_vis_error` is the model) to `DbError::Refused { kind }`:
  PVS01 and PVS05 `Authority`, PVS02 `Input`, PVS04 `State`.

Rust: `AgentRepository::set_profile_visibility_conn(conn, ProfileVisibility) ->
ProfileVisibilitySet { previous, profile_visibility, named_to_everyone }`.

- **MCP.** `set_profile_visibility { visibility: "public" | "group" }` on the stamped
  transaction pattern `set_default_group` uses (`claim_helper::begin_author_stamped_tx`).
  The target is the stamped principal. Over HTTP that is `auth.agent_id`, the human's own
  provider-client principal for a human's token (`EpiGraphMcpFull::write_identity`). On
  stdio it is the server's own agent, which PVS05 refuses: the correct fail direction.
- **Scope.** The MCP tool takes `claims:write`, matching `set_default_group`. The REST route
  keeps `agents:write` (C5). **[SPEC AUTHOR'S CALL]** (§16.B14); the brief is silent on scope, so
  this needs confirmation.
- **Description text** (finding 17: it must be truthful). "public: your name is shown to
  everyone. group: your name is shown only to people who share a team or community with you,
  and to anyone who can read a claim you or one of your agents filed. If you, or any agent
  ever bound to you, filed a PUBLIC claim, your name is shown to everyone whatever this
  setting says (named_to_everyone in the answer). Your id is always shown, and every claim
  stays traceable to you."
- **Residual (finding 17).** An LLM driving H's own connector session (stamped as H) can call
  the MCP tool, for example under prompt injection. Recorded as §15.R15. The REST route is
  the deliberate path; the brief asks for the MCP tool.

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
    `agents_display_name_not_empty` CHECK applies);
  - has no control characters (Unicode `Cc`) and no format characters (`Cf`: bidi
    overrides such as U+202E, zero-width joiners and spaces, the BOM). A display name is
    spoofable, so a name carrying one is not used at all (finding 18);
  - **contains no `'@'`**;
  - **is not equal, case-insensitively, to `legal_contact_email`**.

The email guard exists because `provision.rs` stores
`identity.name.unwrap_or_else(|| email.clone())` as `client_name`, and `Some(&email)` as
`legal_contact_email`. An email must never become `display_name`. Otherwise the result is
`None` and the placeholder `oauth:<client_row_id>` stays. Non-human clients keep today's
behaviour exactly, including adopting the real signer row for agent clients.

A test per creator (§12.T7) pins that no non-provider creator mints an id containing `:`. If a
future creator does, that test fails, so the discriminator cannot drift silently.

What the guard does not catch, recorded (finding 18):

- A provider name equal to the email's local part (`ada.example` for
  `ada.example@...`) is not detected. It is the user's own choice at the provider; an
  operator follow-up (§15.F5) carries the asserted name separately.
- The `:` discriminator trusts the `oauth_clients` row, which a holder of the application
  DSN can INSERT (§15.R9 class). Such a holder could plant a provider-shaped human client
  with a chosen name; it gains nothing it could not do by writing `display_name` directly.

### 9.3 Where the name is read

**Revision 2 reverses B7** (finding 13). `ensure_for_client` keeps locking the row with
`SELECT agent_id, client_id, client_type FROM public.epigraph_oauth_client_lock_for_link($1)`
(`FOR UPDATE` inside the definer, held to the end of the caller's transaction), and then, only
for a human client, reads `SELECT client_name, legal_contact_email FROM public.oauth_clients
WHERE id = $1` in the same transaction. That reads the same locked row version: no concurrent
writer can commit a change to the row between the two statements, and the application role
keeps SELECT on `oauth_clients` (118). So the property "`client_type` is read from the locked
row" (`oauth/token.rs::materialise_principal_agent`) still holds, and so does "the name is
read from the row as locked".

Revision 1's DROP + CREATE of the lock function (its M2) is dropped. It would have added a re-own
and a re-grant, the PUBLIC re-grant hazard of a recreated function, moves in the
`tenancy_backfill` registers, and a rollout-order failure: a new binary running before the
migration fails every human first-mint with 42703. None of that buys any correctness.

### 9.4 What is not changed

- No backfill of existing rows (operator ruling 5). A client whose agent already exists keeps
  it: `ensure_for_client` returns early on a linked client.
- `provision.rs` still stores the email as `client_name` when the provider sends no name. That
  field is shown on consent and admin screens. Carrying the name separately is a follow-up
  (§15.F5).

## 10. Migrations

Numbers: the head is 271. 270 is a gap; do not fill it, because sqlx would apply a version
below the applied maximum. 265 is held by open PR #1028. Use the next free numbers above 271
**at commit time**, one file per decision (finding 11 split revision 1's M1). Each
transactional file has `SET LOCAL lock_timeout = '3s'` and the header sections WHY / RULE /
SHAPE / WHAT IT TRUSTS / UNDO in 269's style.

- **M1 `272_human_identity_disclosure.sql`** (transactional): the predicate.
  1. CREATE `epigraph_is_human_principal`, `epigraph_agent_disclosure_for`,
     `epigraph_agent_disclosure` and `epigraph_human_named_to_viewer` (§6.1). Each gets
     `REVOKE ALL ... FROM PUBLIC`. Then a guarded `DO` block:
     `ALTER FUNCTION ... OWNER TO epigraph_maintenance` for all four, and
     `GRANT EXECUTE ... TO epigraph_app` for the two wrappers only. Each ALTER and GRANT
     names its function literally: `tenancy_backfill.rs`'s static re-own scan reads those
     statements.
  2. `CREATE INDEX IF NOT EXISTS idx_author_binding_clients_operator ON
     public.author_binding_clients (operator_id)`. Non-concurrent on purpose: the table holds
     one row per allowance (an operator act), so the SHARE lock is momentary, and
     `lock_timeout` bounds it.
  3. The human-evidence guard trigger on `oauth_clients` (§6.1, `HEV01`), an INVOKER
     trigger function on `pg_catalog, public, pg_temp` per 271.
- **M2 `273_profile_visibility_setter.sql`** (transactional): `epigraph_set_profile_visibility`
  (§8), owner maintenance, EXECUTE to `epigraph_app` only.
- **M3 `274_human_profile_visibility_group.sql`** (transactional): provisioning and the reset.
  1. Precondition guard in 224's style: refuse (55000) if `epigraph_provision_oauth_agent`'s
     `prosrc` is not 077's (md5). 271 changed proconfig only, so 077's md5 still holds.
  2. `CREATE OR REPLACE public.epigraph_provision_oauth_agent(bytea, text, text)`, which keeps
     owner and ACL. It inserts `profile_visibility = CASE WHEN p_agent_type = 'human' THEN
     'group' ELSE 'public' END`, and the ON CONFLICT re-find is unchanged. It moves to 172's
     form (`pg_catalog, pg_temp`, `pg_catalog.now()`), which shrinks
     `PUBLIC_PATH_REGISTER` and `HIGH_WATER` by one **[SPEC AUTHOR'S CALL]** (§16.B8). If
     `definer_search_path_ratchet`'s scan objects, restate its `public, pg_temp` path
     verbatim instead.
  3. Reset every human principal (`epigraph_is_human_principal`) with
     `profile_visibility <> 'group'` to `'group'`.
  4. **Post-condition** (finding 11): `agents` is FORCE RLS (079) and `agents_self_update`
     admits only bypass, definer bypass or `id = principal`, so a non-superuser,
     non-maintenance runner's UPDATE moves 0 rows with no error, which leaves every existing
     human reading as consented. The file therefore re-counts and RAISEs (55000) if any human
     principal still has `profile_visibility <> 'group'`.
  5. One summary `security_events` row: `agent.profile_visibility_reset`, details
     `{migration, before, rows, after}` (pre-count, rows moved, post-count). No per-row audit.

  `lock_timeout = '3s'` also bounds the row locks of the reset: a long `ensure_for_client`
  transaction holding a human row makes the boot migration fail, and the API restarts and
  retries (§17).
- **M4 `275_idx_claims_public_by_agent.sql`** (`-- no-transaction`, exactly one statement):
  `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_claims_public_by_agent ON public.claims
  (agent_id) WHERE visibility = 'public'`.
- **M5 `276_idx_claims_group_by_agent.sql`** (`-- no-transaction`, exactly one statement):
  `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_claims_group_by_agent ON public.claims
  (agent_id, owner_group_id) WHERE visibility <> 'public'`. Key order (finding 15):
  `agent_id` first matches the forced per-bound-agent probe of §6.1 (one descent per agent,
  `owner_group_id = ANY(...)` as array keys), and cannot be mistaken for a group-partition
  scan. It covers the minority partition, as 063 does.

- **M6 `277_disclosure_team_arm_without_the_twin.sql`** (part B, transactional): re-states
  the core with the same answers after the section 11.1 measurement (team arm per viewer
  group, role derivation only for a bound group, public-claim arm first, readable probe
  per agent x group). Undo: `docs/runbooks/277-undo.sql`.

- **M7 `278_role_edges_team_only.sql`** (after review, operator ruling 2026-11-24,
  transactional): md5 precondition `OCC01` on 130's audit body; NEW
  `epigraph_role_edge_owner(text, uuid)` (172's path, maintenance-owned, not
  application-callable); `epigraph_role_assignments_audit` re-stated with the projection
  `('group', owner)` (its `public, pg_temp` path kept, so `PUBLIC_PATH_REGISTER` is
  unchanged); NEW AFTER trigger `group_role_bindings_reown_role_edges` (bind/unbind re-owns);
  backfill of every existing row with the declaration columns written, a
  `security_events` summary `edges.role_edges_team_only` {migration, before, rows, after},
  and post-condition `OCC02` (FORCE RLS would make a non-privileged runner move 0 rows).
  Registers: `edge_writer_signing_ratchet` DB site moves 130 -> 278; `tenancy_backfill.rs`
  DEFERRED (both new functions at 278), OPERATOR_FUNCTION_GRANTS (owner rule, `false`),
  GRANT_EXEMPT_TRIGGERS (the re-own trigger); `custodian_role.rs`'s catalog ratchet admits
  the re-own trigger as a second projection maintainer. Undo:
  `docs/runbooks/278-undo.sql` (130's body back; the backfill is not reversed).

- **M8 `279_disclosure_role_derived_arm_last.sql`** (after review, correctness#3,
  transactional): md5 precondition `DAO01` on 277's core body; the core re-stated with the
  readable-claim arm before the role-derived arm, and the role-derived arm's cheap probe
  (§11.1, after review). Same signature, owner, ACL, COST and path. Undo:
  `docs/runbooks/279-undo.sql` (277's body).

- **M9 `280_human_evidence_guard_agent_id.sql`** (after review, correctness#5,
  transactional): HEV01 also refuses re-pointing or unlinking a LINKED human client's
  `agent_id` (the trigger watches `UPDATE OF client_type, agent_id`); the first link of an
  unlinked client stays allowed. Undo: `docs/runbooks/280-undo.sql`.

Write amplification: M4 and M5 add two partial indexes to the hottest write table, beside
HEAD's `idx_claims_agent_id`, `idx_claims_agent_created` and `idx_claims_group_current`. The
§11 run measures insert cost.

**The invalid-index trap** (finding 15). `CREATE INDEX CONCURRENTLY IF NOT EXISTS` after a
cancelled or failed build leaves an INVALID index of that name, and a re-run skips it
silently; the arms would then fall back to `idx_claims_agent_id` with heap checks. Both
indexes are added to `tenancy_migration_shape.rs::INDEX_MIGRATIONS` (which checks
`indisvalid` on test databases), and §17 carries the post-deploy check and the runbook line.

Undo runbooks (269's convention): `docs/runbooks/272-undo.sql`, `273-undo.sql` and
`274-undo.sql`:

- restore 077's provision body, re-owned and re-granted;
- DROP the setter, the four disclosure functions, the guard trigger and its function;
- the index undo is `DROP INDEX CONCURRENTLY IF EXISTS`.

The undo is paired with a binary rollback: a binary that calls the dropped functions fails
(§17). The reset is NOT reversed by the undo. Its pre-state cannot be recovered, and it is the
privacy-safe value.

Registrations the PR must make (re-measure each list on HEAD):

- `epigraph-cli/src/bin/tenancy_backfill.rs`:
  - `DEFERRED_DEFINER_FUNCTIONS`: the four disclosure functions at 272, the setter at 273.
  - `OPERATOR_FUNCTION_GRANTS`: the two wrappers at 272 (application EXECUTE), the core and
    the evidence helper with `false`, the setter at 273.
  - `epigraph_provision_oauth_agent` is in `PRE_REGISTER_DEFINERS`. M3 does not re-own it,
    so no entry moves.
- `epigraph-db/tests/definer_search_path_ratchet.rs`: new definers are on 172's form;
  `PUBLIC_PATH_REGISTER` and `HIGH_WATER` shrink by one for the provision function.
- `epigraph-db/tests/function_search_path_pg_temp_ratchet.rs` (271): `pg_temp` last
  everywhere, and the new trigger function is pinned.
- `epigraph-db/tests/app_role_table_lockdown.rs`: `profile_visibility` joins
  `agents_identity_columns_are_not_app_updatable` beside `default_group_id` /
  `default_private` (finding 12), so a later column grant cannot open a path around the
  audited setter.
- `tenancy_migration_shape.rs`: M4 and M5 in `INDEX_MIGRATIONS`.

## 11. Performance plan

- **Non-human target, which is most evaluations.** The core does two index probes (the
  human-client check through `idx_oauth_clients_agent_id`, and the `human_operators` primary
  key) plus today's details rule. That is one function call per row where today there is an
  inline expression.
- **Human target.**
  - B(H) comes from `idx_operator_links_operator` and the new
    `idx_author_binding_clients_operator`.
  - The public-claim arm is one `idx_claims_public_by_agent` probe per bound agent (forced
    `LATERAL ... LIMIT 1`, §6.1), stopping at the first hit.
  - The readable arm is one `idx_claims_group_by_agent` descent per bound agent, with
    `owner_group_id = ANY(p_groups)` as array keys.
  - Without M4, a fleet agent with many group-only claims and no public one would make the
    probe walk all of its claims through `idx_claims_agent_id` with heap checks.
  - Worst case with no hit (an ESTIMATE, finding 16): about |B(H)| public probes plus
    |B(H)| × |groups| group-key descents. With 1,500 agents and 5 to 30 groups that is about
    9k to 46k btree descents, roughly 10 to 60 ms, which is at or over the budget below.
- **Bounded call sites.**
  - Cards: at most 200 per read (`CANDIDATE_POOL`).
  - List pages: at most 100.
  - `authored_by`: at most `1 + MAX_PAPERS` papers × `MAX_PAPER_AUTHORS` names plus the
    ingesters.
  - `match_ranked` and `exact_name_candidates`: the predicate is a qual of the level after
    the name match (§7 rows A1, A4), so the cost scales with matches, not with the table.
- **Measurement before merge**, on a throwaway test database only (finding 2).
  - `EXPLAIN (ANALYZE, BUFFERS)` of `SELECT epigraph_agent_disclosure(...)` shows only a
    function scan: plpgsql hides the plans of its body statements, and switches to a generic
    plan after five executions. So the plans are captured with `auto_explain`
    (`log_nested_statements = on`, `log_analyze = on`, `log_buffers = on`) after at least six
    calls in one session, or by `PREPARE`-ing each body statement under
    `SET plan_cache_mode = force_generic_plan`. Those plans go in the PR text.
  - Shapes:
    - a synthetic human with 1,500 bound agents and 150k claims, mostly group-visibility,
      plus a control with zero public claims;
    - (a) the viewer is in a group holding at least 1M non-public claims by OTHER agents;
    - (b) at least 1M public claims by other agents;
    - (c) skewed `operator_links` statistics: many operators with one link, plus one with
      1,500;
    - (d) a viewer group set of about 30 (role-derived memberships plus 234's operator teams).
  - Run: one core evaluation with no public claim (the worst case); the same with one public
    claim; a 200-card read; `find_agent` with a 2-character prefix, measuring the A1
    placement (the predicate runs per match, not per page); and the insert cost on `claims`
    with M4 and M5 present.
  - Call counts: `SET track_functions = 'all'` and `pg_stat_user_functions.calls`, so the PR
    proves "once per matched candidate" and "once per card".
  - Pass condition: the generic plans probe M4 and M5 per bound agent and show no scan of a
    whole `claims` partition (not merely "no sequential scan": a full index scan of a group
    partition is as bad); recorded p50 and max per evaluation are in the PR text.
  - Budget: worst case under 10 ms per human evaluation; non-human under 0.2 ms. Missing the
    budget blocks merge; it is not waived.
  - The test lives as an `#[ignore]`d measurement test,
    `epigraph-db/tests/human_identity_visibility_perf.rs`, run on the DB host.
- **Fallback if the budget is missed** (finding 16), listed now so a miss does not stall the
  PR: a sticky marker table `human_public_claim_marks(human_id)` maintained by triggers on
  `claims` (visibility becomes `'public'`) and on binding inserts, which makes the public arm
  one primary-key probe. It changes R4 / B13 (privatizing would no longer un-name H), so it
  needs the operator's ruling (**[OPEN] C9**) before it is built.

### 11.1 Measured (part B)

Run with `cargo test -p epigraph-db --test human_identity_visibility_perf -- --ignored
--nocapture` on a throwaway test database on a shared CI host, so wall times are noisy
(the same read varied up to 4x between runs); figures are ranges over the runs made.
Shape: one human H (provider-client evidence, profile `'group'`) with 1,500 operator-linked
agents that filed 150,000 group claims in a group the viewer does not read, no public
claim; (a) 1,000,000 group claims by another agent in the viewer's group; (b) 1,000,000
public claims by another agent; (c) 10,000 operators with one link each; (d) the viewer
in 30 groups. `ANALYZE`d after a `session_replication_role = replica` bulk load.

Generic plans of the core's body statements (`plan_cache_mode = force_generic_plan`, six
executions, under `SET ROLE epigraph_maintenance` so the FORCEd policies apply as in the
definer frame):

| Statement | Plan | Time |
|---|---|---|
| B(H) | `idx_operator_links_operator` (1,500 rows); `author_binding_clients` seq scan (empty table) | 0.2-0.3 ms |
| public-claim arm | nested loop over `unnest(B)`, `Index Only Scan using idx_claims_public_by_agent`, 1,501 loops, 4.5k buffers | 0.8-1.2 ms |
| readable-claim arm, 272 form (`owner_group_id = ANY`) | UNSTABLE: `idx_claims_group_by_agent` in some runs (18 ms, 135k buffers), `idx_claims_agent_id` + filter in others (52-74 ms) | 18-74 ms |
| readable-claim arm, 277 form (per agent x group) | `Index Scan using idx_claims_group_by_agent`, Index Cond `agent_id = b.agent_id AND owner_group_id = vg.group_id`, 45,030 loops, 135k buffers | 30-43 ms |
| team arm, 272 form (236's twin) | `Function Scan on epigraph_live_memberships_unbound`; nearly all of it is 249's `epigraph_role_derived_memberships` (575-585 ms with no `group_role_bindings` row) | 583-816 ms |

No plan scans `claims` sequentially. Whole-core wall time (one local round trip
included), 25 evaluations each:

| Case | 272 | 277 |
|---|---|---|
| human, no arm holds (worst case) | p50 623-635 ms | p50 20-38 ms, max 26-129 ms |
| human, one public claim by the LAST bound agent | p50 596-658 ms | p50 1.2-1.5 ms |
| non-human target | p50 0.4 ms | p50 0.2-0.4 ms, max 1.5-4 ms |

Call counts (`track_functions = 'all'`, `pg_stat_xact_user_functions`, application role,
stamped as the viewer): a 200-card read calls `epigraph_agent_disclosure` 201 times (once
per card, once for the operator human's name); a two-character prefix search (`'pe'`)
calls it once per raw name match (1,502 matches, 1,502 calls; one run 1,703) over 21,506
agents, never once per agent (A1's MATERIALIZED fence). Wall time: 200-card read 0.5-2.4
s, prefix search 0.3-0.6 s, both dominated by per-card / per-match work that exists
without this change only partly; the prefix search pays one predicate call per match by
design (the filter must precede the pool LIMIT).

Insert cost of 275 / 276: 20,000 group claims took 754-970 ms with both partial indexes
and 600-662 ms without (triggers off, so the difference is the indexes): +15-60 %.

**Verdict against the budget (blocking, reported, not waived).**

- Non-human: within the 0.2 ms p50 target at the low end of the range.
- Human, a public claim exists: 1.2-1.5 ms, within 10 ms.
- Human, worst case: 20-38 ms p50 after 277, OVER the 10 ms budget. The cost is the
  readable-claim arm, |B(H)| x |viewer groups| index descents (45,030 here). Migration
  277 removed the 600 ms team-arm cost and the plan instability, and cannot remove this
  one without changing the data model: **[OPEN] C12** below.

`human_identity_visibility_perf.rs` asserts only what it can state exactly (no `claims`
sequential scan; calls per match well under the table); it prints the rest. It is an
`#[ignore]`d measurement harness, not a regression gate (review tests#7): the performance
claims here rest on the recorded runs.

**After review (correctness#3, migration 279): a viewer group carries a role binding.**
The production shape (a role bound to a team) was not measured before review. Same shape,
plus one `group_role_bindings` row on the viewer's first group:

| Case | 277 (before 279) | 279 |
|---|---|---|
| H holds no bound role (a miss) | 617 ms p50, 657 ms max | 28.0 ms p50, 30.5 ms max |
| H holds the role bound to a viewer group (role-derived names) | 645 ms p50, 742 ms max | 27.9 ms p50, 33.3 ms max |
| worst case, no binding (unchanged) | 27.1 ms p50 | 27.2 ms p50 |

277 called 249's `epigraph_role_derived_memberships` (about 0.56 s on its own here) for
every evaluation once any viewer group carried a binding. 279 runs that arm last and,
for a target linked as nobody's agent and holding no allowance (where 249's candidate set
is the target alone), replaces the call with one binding probe per viewer group, pinned
equal to 249 by `human_identity_visibility.rs::the_cheap_role_probe_answers_as_249_does`.
A human principal that is also some human's agent, or holds an allowance, still pays the
249 call; the remaining worst case is C12's readable-claim arm.

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
  id, public key and created_at; `labels`, and `properties` on B1, are compared too. N is
  production-shaped (§5). Surfaces:
  - A1: H's exact name, prefix and ORCID all return no H;
  - A1 truncation (findings L6, 3): 200 decoy agents an attacker registers with H's exact
    name, plus H: `candidates_truncated` is false and the decoy page is identical to the page
    without H; a query matched by exactly `CANDIDATE_POOL` visible agents plus H gives
    `candidates_truncated: false`;
  - A6: a stranger's name-only re-ingest with H's exact spelling reports nothing about H in
    `also_at_position`;
  - E2, E3: every edge surface returns no `author_name` or `replaces` on H's explicit
    `authored` edge;
  - H6: a GQL predicate on H's `full_name`, email or name returns no H;
  - I3: an MCP OPL02 refusal carries the fixed text and no human id;
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
  - Status (finding 8): H's client suspended, so a teammate whose only shared group is a
    164/263 verb-made team no longer sees H, unless another arm holds; with a claim of B(H)
    the teammate reads in that group, H stays named.
- **T4. Personal group (§4 decision).**
  - H's live-linked bot, with no claims, and with H in no team: the bot's view of H equals
    O's.
  - After the bot files one claim it can read: H is named to the bot.
  - The same pair for an allowlisted (235) agent.
- **T5. Opt-in.**
  - H sets `'public'` through the definer: O and the guest viewer see H named. H sets
    `'group'`: H is unnamed again when no other arm holds.
  - Refused, with no row changed: O setting H's value (impossible by signature: it sets O's
    own); H's operated bot (PVS05); a service principal (PVS05); a `claims:admin` caller on
    `PUT /api/v1/agents/:H` (403); a NULL principal (PVS01); the value `'team'` (PVS02).
  - The audit row exists, with the previous value.
  - `named_to_everyone` is true after setting `'group'` when B(H) has a public claim, false
    when nothing else names H.
  - MCP `set_profile_visibility` round trip, as the human's own token.
  - REST `PUT /api/v1/agents/:id` with `profile_visibility` alone, as the human.
- **T6. Superseded public claim.** A bound agent's only public claim is superseded, so it has
  `is_current = false` and its successor is group-only. H is still named to O. The successor
  is written with EXPLICIT tenancy: a successor without declared tenancy inherits its
  predecessor's visibility (070, re-stated by 074), so the fixture could not be built
  otherwise.
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
  `'public'`. Provisioning a provider human writes no `events` row whose payload contains the
  name (finding L14). And a pinning test that every creator's generated `client_id` has no
  `:` except the provider path. Plus unit tests of `provider_asserted_person_name`: control
  (`Cc`) and format (`Cf`, U+202E, U+200B, U+FEFF) characters, 256 characters, whitespace
  collapse, `@` anywhere, the email in another letter case.
- **T8. A stranger cannot unhide H; an admin can (pinned as ruled).**
  - A stranger's ingest names H as a pending author on a public paper: H stays unnamed.
  - A stranger's `OPERATED_BY` edge from its agent to H: unnamed.
  - A stranger's public claim that mentions H's id in its content: unnamed.
  - The four admin paths of §4 (keyed team plus direct add, community add, a group admin's
    INSERT, publicize of a B(H) group claim), each pinned with the behaviour C3 / C4 rule;
    until ruled, the literal reading: H is named to that group's members (and to everyone
    after the publicize).
- **T9. Privileged arms.** A maintenance bypass session and an elevated viewer see H named.
- **T10. Migrations.**
  - M3 reset, in production migration order (271's ratchet pattern): a human that is
    `'public'` before 274 is `'group'` after; a non-human is untouched; one summary audit row
    carrying the pre-count, rows and post-count.
  - M3's post-condition: replayed with the reset neutralized, the file refuses (55000).
  - M3's precondition: a provision function with another body refuses (55000).
  - Definer pin tests in the style of `migration_269_definers_are_pinned_owned_and_granted`:
    owners, paths and ACLs. `epigraph_app` cannot EXECUTE the core or the evidence helper,
    and can EXECUTE the wrappers and the setter. PUBLIC has no EXECUTE on any of them.
  - Finding 10b: the test creates a uniquely named `NOSUPERUSER NOBYPASSRLS` role (roles are
    cluster-wide, so a fixed name collides between parallel tests), `ALTER FUNCTION ... OWNER
    TO` it for the core, and asserts that a human with a public claim is UNNAMED to an
    outsider (the FORCEd claim read sees nothing: fail closed) and still named to itself (the
    self arm reads no table).
  - The evidence guard refuses a DELETE of a linked human client and an UPDATE of its
    `client_type` (HEV01), and admits both on an unlinked or non-human client.
  - The exact set of catalog functions whose body inserts into `public.agents` is pinned
    (finding 14), so a new human-creating insert path cannot default to `'public'` unseen.
- **T11. Decide-alike.** For non-human targets, `disclosure().details` equals today's rule
  over a matrix of profile, self, shared-group and admin cases. This replaces
  `the_three_copies_of_the_profile_rule_decide_alike`.
- **T12. Static lint** (§14).
- **T13. The accountability property** (finding 5). Over a viewer × claim matrix (outsider,
  guest, teammate, bot, elevated; public, group-in-V, group-not-in-V; current, superseded;
  live, retired, revoked binding): "V can read claim c (as the claims read policy decides,
  on V's stamped session) ⇒ c.agent_id is named to V, and
  `epigraph_operator_bound_at(c.agent_id, c.created_at)` is named to V". Also: for every
  (agent, t) where `bound_at` names H, the agent is in B(H). And §3's stickiness invariants
  (finding 9): after a retire, an `operator_id` change is refused and H is still named. This
  is the guard for "anything newer on main that binds an agent to a human": a read-policy
  widening, a new `bound_at` branch or a new binding table fails it. Part A runs it against
  the predicate directly; part B adds the surfaces.

Every new test goes through the council-of-critics review: reject tautologies, mock-shaped
tests, happy-path-only tests and trivial round trips.

## 13. Existing tests that change, and why

Each one is updated deliberately; none is deleted to go green. The commit that touches each
one says why.

- **Fixture: `epigraph-db/tests/viewer_fixture.rs::make_human_operator`** (also used through
  `seed_human_operator`). **Part B.** Part A changes no read surface, so no test reads the
  fixture's profile through the rule yet; the fixture changes with the surfaces. It then also
  sets `profile_visibility = 'group'`, mirroring
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
| `visibility_lint` | `PROFILE_RULE_SITES` is replaced (part B). `EXPECTED_EXEMPTIONS` gains nothing: the new reads take no viewer, and `agents` is not `tier_a`. `CONN_WITHOUT_VIEWER` gains `agent.rs::set_profile_visibility_conn` (part A): a write through 273's definer on a stamped transaction, as `set_agent_default_conn` is. |
| `definer_search_path_ratchet` | See §10. |
| `app_role_table_lockdown` | See §10. |
| `edge_writer_signing_ratchet` | Unaffected: no edge writer changes. E2 changes the edge READ projection (part B), which this ratchet does not cover; E3's tests do. |
| `tenancy_migration_shape` | M4 and M5 join `INDEX_MIGRATIONS`. |
| `function_search_path_pg_temp_ratchet` | The new trigger function pins its path. |

**New static lint, `epigraph-db/tests/agent_name_disclosure_lint.rs`** (part B). It refuses any
SQL literal that selects or matches `display_name`, `orcid`, `ror_id` or `properties` from an
`agents` alias (findings L5: `properties` is details-gated, and a matcher on it is an
oracle), and any `events` payload builder that writes a `display_name` key (finding L14),
outside an allowlist:

- `agent_disclosure.rs`;
- writers;
- `ensure_for_client`;
- the internal checks in `author_nodes`;
- the operator CLI files in §7.J;
- `AgentRepository`'s create tail (its `agent.registered` payload), which no human
  principal reaches (§7.J).

`graph_view.rs` (row H6) is in scope, not allowlisted.

A missed or future surface fails CI, not review. This answers "enumerate all surfaces".

## 15. Residuals and out-of-scope follow-ups (recorded, not built)

- **R1. (Closed by the operator's 2026-11-24 ruling; now §7 row K1, migration 278.)** The
  `OCCUPIES` edges role grants project are team-only. Residual: a later change of a bound
  group's `status` or `kind` does not re-own its edges (a suspended team's members stop
  reading through it anyway; a group's kind does not change after creation, 108).
- **R2. Group-admin authority can unhide H with no consent step** (findings 1, L15). The four
  paths are listed in §4: a keyed team created on demand plus a direct add (admin-tier:
  `groups:admin` is in `ADMIN_ONLY_SCOPES`), a community add by any live member holding
  `groups:admin` (`routes/community.rs` writes the same `group_memberships` row under the
  weaker "live member" rule), any group admin's INSERT through 077's WITH CHECK, and a
  publicize of a B(H) group claim. Neither is a stranger-level leak. Options for **[OPEN] C3**:
  (a) accept literal "team members" and record that `groups:admin` can unhide anyone (what
  is implemented now); (b) count H-side team memberships only when H consented or a
  maintenance act wrote them (164 verbs, a 263 accepted invite), which needs a provenance
  column on `group_memberships` or a `security_events` join, i.e. a schema change; (c)
  exclude keyed (`did:key:`) groups and communities from the H side. The publicize path is
  **[OPEN] C4**, ruled separately because it is accountability-positive.
- **R3. A public DOI plus an author position re-identifies an unnamed author.** The paper text
  names its authors. An authorship edge is not a claim, so it does not name H. For a
  countersigned authorship (H's own act), whether it should count as a claim needs a ruling.
- **R4. Privatizing a public claim un-names H**, because the arm reads current `visibility`.
  Stickiness was ruled for binding changes only.
- **R5.** The team arm inherits 164's lapse (registration live and client `active`), 235's
  allowance lapse, and the group's `status` (§3, finding 8). A group's suspension, or H's
  client suspension for a 164/263 team, changes named-ness only for that group's own
  members, and only where no other arm holds.
- **R6.** Invitations now need the invitee's id passed out of band, because `find_agent`
  cannot find an unnamed human. The invitee sees the inviter's id only.
- **R7. The approved `operator_human` trade-off** (§5).
- **R8. `PUT /api/v1/agents/:id` writes its profile columns on the unstamped pool**
  (finding 12 corrects revision 1's premise). 118 grants the application role `UPDATE
  (display_name, labels, orcid, ror_id, properties, updated_at)` on `agents`, so the grant
  exists; but `agents_self_update` admits only bypass, definer bypass or `id = principal`, and
  the route writes on `state.db_pool`, so whether the row moves depends on the connection's
  stamp. Fixing the route's profile write is out of scope. The opt-in field goes through the
  definer on a stamped transaction (`AppState::write_as`) and does not depend on it.
- **R9. Trust boundary.** `agents` stays world-readable to the application role (077 §9). A
  holder of the application DSN reads names directly, and can self-stamp to probe the session
  wrapper. This is the trust class of 236 and 269. The rule is enforced at every application
  surface, not as a database read boundary. Where the real name is stored is **[OPEN] C13**.
  After review (correctness#8): the same holder can stamp `epigraph.principal_id` and call
  273's setter for ANY human, which persists an opt-in and names that person to everyone.
  It amplifies an exposure the holder already has (it can read the name) rather than
  creating one. The setter's audit row records only `session_user` (always the application
  login through the API), and HEAD has no request-correlation GUC to add (the only stamped
  ids are the principal, the groups, and an elevated session's `elevation_id` /
  `family_id`), so **an opt-in is not attributable below the API**: a forged one cannot be
  told apart from a real one afterwards. Adding a correlation stamp (OAuth client id or
  token jti) to every stamped connection is a follow-up, not built here.
- **R10.** Events `actor_id` is out of scope by ruling. Guest routes were confirmed to drop
  agent identity (§7.J). Event PAYLOADS are covered (§7.J, §14).
- **R11. `invite_to_group` answers "is this id a registered human?"** (finding L4).
  263's `epigraph_invite_to_team_group` raises `TGP03: agent % is not a registered human
  operator` for a non-human invitee, and the text reaches REST and MCP. TGP01 requires the
  caller to be a registered human operator, so the attacker is an onboarded insider, but the
  oracle classifies humans who share no team with the attacker and who have no bound agent,
  which the `operator_human` trade-off does not cover. **[OPEN] C10**: (a) accept any
  non-role, non-system invitee and refuse a non-human only at accept time, which no non-human
  can reach; (b) keep it as an explicit residual with the operator's sign-off. Unchanged
  until ruled.
- **R12. World-readable `OPERATED_BY` edges** (finding L7): 107's `epigraph_link_operator`,
  `epigraph_link_retired_agent`, 116's shared-signer retire, and
  `epigraph-mcp/src/server.rs::record_auth_lineage`. They persist after a retire (when the
  card shows `operator_human: null`), so they still say "this id is an operator", and the
  MCP auth-lineage edges from the server agent list every principal that used it. Id-level
  markers, out of scope pending a ruling (R1, the role edges, was ruled team-only).
- **R13. Timing** (findings L10, 19). A human evaluation costs up to the 10 ms budget, a
  non-human about 0.2 ms, so an outsider who times `GET /api/v1/agents/:id` can separate
  human ids from others, unbound humans included, even when the output is byte-identical.
  The cheap arms run first; equalizing the cost is not realistic.
- **R14. Assessment-slot BBAs** (finding L12). `routes/assess.rs` keys a bound agent's BBA
  slot to `AgentRepository::human_of(agent, true)`, and
  `mass_function.rs::assessment_slot_perspective` hashes `epigraph/assess-slot/v1/{owner}`, so
  anyone can compute the slot from an id and learn that X is the live human of the writing
  agent. Id-level and live-only, the trade-off's class; recorded with R12.
- **R15. An LLM driving H's own session can call `set_profile_visibility`** (finding 17), for
  example under prompt injection, and publish H's name. The REST route is the deliberate
  path; the MCP tool exists because the brief asks for it. The setter is audited.
- **F1.** Author nodes from ingested literature and git authors are not human principals.
  Their names are public-source names, and they stay named.
- **F2.** Stale derivatives (finding L13): stored Atlas leaf documents built before deploy
  still carry names (§17), and so can theme and neighbourhood labels written by
  `scripts/label_themes_llm.py` (consistent today, since it samples public claims, but
  stale after R4 or an opt-out). Part B drops that script's agent column; rebuild both after
  deploy.
- **F3.** Explorer UI copy should say "unnamed agent" neutrally. It must not say "hidden".
- **F4.** A row that gains human evidence AFTER creation keeps its earlier `'public'`, and the
  column default stays `'public'`, so any FUTURE human-creating insert path defaults to
  "consented" (finding 14). Through supported paths this cannot happen today: a human client
  links only to a freshly provisioned derived row. Only abuse of the app-callable link
  definer could cause it (R9 class). The guard: §12.T10 pins the exact set of catalog
  functions whose body inserts into `public.agents`, so a new insert path is a visible test
  change. The alternative, a `profile_public_consented_at` column written only by the
  setter (opt-in reads `'public' AND consented_at IS NOT NULL`), makes consent literal and
  the reset's completeness non-critical; it departs from the brief's prescribed reset, so it
  is **[OPEN] C11**.
- **F5.** Have `provision.rs` stop storing an email as `client_name`, and carry the asserted
  name explicitly.
- **F6.** (Revision 1: "if E2 is deferred".) Closed: E2 is resolved in this PR (part B).

## 16. Decisions not made by the operator (clearly marked)

### A. Orchestrator's call (recorded in the brief as such)

- **A1.** The readable-claim arm: V can read any claim attributed to B(H), so H is named to V.
- **A2.** (Brief addendum 2.) A role bound to no group, or to more than one live group, or
  whose one binding is not an active team/community, has its `OCCUPIES` edges owned by the
  HOLDER's personal group (visible to the holder, maintenance and elevated sessions only).
  No multi-owner edge is invented.
- **A3. (Fix agent's call, after review correctness#1.)** The review asked that a holder with
  NO personal group be refused (the grant and the backfill RAISE). Registration as a human
  operator does not guarantee a personal group, so a RAISE could fail a boot migration over
  a holder that simply never had one, which the main session cannot pre-measure from a
  subagent. 278 instead mints it through 105's `epigraph_ensure_personal_group` (found by
  its `did:epigraph:personal:` key): never the world group, and 105's RVK01 (only revoked
  personal rows) and RVK02 (a squatted key) still refuse with nothing written. Tested both
  ways (`role_edges_team_only.rs::a_missing_personal_group_is_minted_and_a_revoked_one_refuses`).

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
- **B7. (Reversed in revision 2, finding 13.)** A second SELECT of `client_name` and
  `legal_contact_email` in the same transaction, after the lock, rather than a DROP + CREATE
  of the lock function (§9.3).
- **B8.** The provision function moves to 172's path. The fallback is to restate its path
  verbatim.
- **B9.** `make_human_operator` sets `'group'`, with the ripple accepted (§13).
- **B10.** `get_public_profile.profile_visibility` becomes `Option`, and N's control profile is
  `'group'` (§5).
- **B11.** Two partial indexes rather than one composite, `agent_id` first. A summary audit
  row for the reset, with pre- and post-counts. `COST 1000` on the core and both wrappers.
- **B12.** `PUT /api/v1/agents/:id` with `profile_visibility` is self-only, even for
  `claims:admin`.
- **B13.** Privatization of a public claim un-names H (R4): current visibility is read.
- **B14.** The opt-in tool's scope: `claims:write` on MCP (parity with `set_default_group`),
  `agents:write` on REST (the existing PUT scope). The brief is silent on scope; this needs
  confirmation.
- **B15.** Only `claims.agent_id` counts for the public-claim and readable-claim arms; ingest
  records, evidence, challenges and BBAs filed by B(H) do not name H (§4; C6 is open).
- **B16. (Reversed after review, leaks#2 / correctness#2.)** An unnamed human's
  `pending_authored_papers` count is served as computed, as for N. Zeroing it rested on a
  false premise (only a registered person can be named pending) and created a marker.
- **B17.** The human-evidence row is pinned by a trigger (HEV01, §6.1) rather than only by a
  ratchet test. After review (correctness#5, migration 280) the pin covers `agent_id` too.
- **B18.** One evidence helper, `epigraph_is_human_principal`, shared by the rule, the reset
  and the setter.
- **B19.** The setter has no search_path write window (271 pinned every trigger's path) and
  returns `named_to_everyone`.
- **B20.** Part B implements the brief's literal `display_name: null` until C7 is ruled.

### C. Open, needs a ruling

Each item states the behaviour implemented until the operator rules.

- **C1. (Closed in revision 2.)** E2 is redacted in this PR, `replaces` included (finding L2).
- **C2.** R3: whether a countersigned authorship of a readable paper should name H as a claim
  does. Implemented: it does not.
- **C3.** Third-party unhide through group-admin authority (§4, R2): options (a) / (b) / (c).
  Implemented: (a), the literal reading.
- **C4.** Whether a team admin's publicize of a B(H) group claim may name H to everyone.
  Implemented: yes (the public-claim arm reads current visibility).
- **C5.** Key the public-claim arm on the binding window (`bound_at`) instead of "ever bound"
  (findings L9, 7). This narrows approved rule text, so only the operator can make it.
  Implemented: "ever bound".
- **C6.** Whether "no anonymous claims" covers public ingest records (finding 6).
  Implemented: no.
- **C7.** The null-name marker (findings L1, 20): redact to the `oauth:<client row id>`
  placeholder, or keep null. Implemented: null (the brief's text); the main session measures
  the nameless non-human population first.
- **C8.** Whether an explicit `authored` edge's `affiliations` is identity, to be redacted with
  `author_name`. Implemented: shown as for N.
- **C9.** The sticky public-claim marker table, only if the §11 budget is missed.
- **C10.** The TGP03 invite oracle (R11): accept-time refusal or a signed-off residual.
  Implemented: unchanged.
- **C11.** A `profile_public_consented_at` column in place of relying on the reset (F4,
  finding 14). Implemented: the brief's reset plus `'group'` at provisioning.
- **C12.** (Part B, measured.) The readable-claim arm's worst case is over the 10 ms
  budget (section 11.1: 20-38 ms p50 for a human with 1,500 bound agents and a viewer in
  30 groups). Options, each a data-model change: (a) a per-human marker of the groups
  B(H) has filed non-public claims in (`human_claim_groups(human_id, group_id)`,
  maintained by a trigger on `claims` and on binding inserts), making the arm one
  primary-key probe per viewer group (C9's mechanism, for groups); (b) cap the arm at
  the viewer's groups that are teams or communities (narrows the orchestrator's call A1);
  (c) accept the cost for this population size. Implemented: none (277 only made the
  plan stable; 279 removed the separate 0.6 s role-derived cost, §11.1); the operator
  rules.
- **C13. (After review: correctness#4, leaks#3, brief addendum.) Where the real name is
  stored.** Measured on HEAD: `oauth_clients.client_name` is NOT more restricted than
  `agents.display_name` for the database logins. 070 grants `SELECT` on every `public`
  table to the application and maintenance roles, 077 gives `oauth_clients` no row policy,
  no migration revokes `SELECT` on it (118 revokes only UPDATE / DELETE / TRUNCATE), and
  `agents_identity` is `FOR SELECT ... USING (true)`; `epigraph_app` and
  `epigraph_maintenance` are the only login roles the migrations provision, and
  `ensure_for_client` itself reads `client_name` on the application role. So every login
  that can read `agents.display_name` could already read the provider name. What widens is
  the number of code paths that read the column ungated: (a) the maintenance-DSN operator
  CLIs (`analyze_graph::main`, `dekg::handle_migrate`, `cache_owner_audit::audit_edges`,
  `backfill_markers::signers_statement`, `system_agent::identity`,
  `mass_function::untyped_provenance_page`: the lint's ALLOWED register); (b) the whole-row
  fetchers on the application role (`AgentRepository::get_by_id` / `get_by_public_key` /
  `list` / `list_by_label`, each serializing caller redacting; `update_agent` since review);
  (c) any holder of the application DSN, agent containers included (R9); (d) operator
  scripts (`scripts/evidential_clustering.py` filters on the column, serves nothing). No SQL
  function returns another agent's `display_name` to the application, and no tracing macro
  logs it. **Decision as built:** the real name lives in `agents.display_name`, gated at
  every application surface; the database layer is no wider than `oauth_clients` already
  is. **Alternative:** keep the `oauth:<client row id>` placeholder in `display_name` and
  resolve the name through the predicate from a restricted source; `oauth_clients` is not
  such a source today, so it would need its own row policy or a new maintenance-only table.
  Implemented: as built; the operator decides.


## 16a. Part B implementation notes (deviations and what was not covered)

Each deviation below is a choice made during part B, recorded so it is not mistaken for
the text above.

- **B9 deviated: the shared fixture is unchanged.** `viewer_fixture.rs::make_human_operator`
  is `#[path]`-included by 136 test files across four crates; changing its profile would
  have made every one a touched target. The tests that assert a human's visibility set
  `profile_visibility = 'group'` themselves (`agent_lookup.rs::named_human`,
  `human_identity_visibility.rs::human`, the MCP and authored-by tests that pin the rule),
  so none passes by the column default's "consent".
- **`AgentLookupRepository::match_by_name` lost its `&Viewer`.** The decision reads the
  stamped session; a viewer argument the statement no longer used would have been a
  second, unspent source of the audience. `find` and `cards` keep theirs (counts and the
  self/admin registration arm still read it).
- **The spend lint (`visibility_lint.rs`)** admits the stamped disclosure as a viewer
  spend only through an exact register, `DISCLOSURE_SITES` (today `cards_inner`), never as
  a free marker; `PROFILE_RULE_SITES` became `no_repo_statement_spells_the_agent_profile_rule`.
- **`agent_name_disclosure_lint.rs`** (section 14) scans every `crates/*/src` function's
  string-literal SQL for an identity column read off `agents` and pins GATED / ALLOWED;
  its PENDING register is empty. After review (leaks#4) it also scans a write that hands
  its row back (`UPDATE` / `INSERT INTO agents ... RETURNING` an identity column; four
  writers registered in ALLOWED) and treats `profile_visibility` as an identity column
  (after 274 its value is near-human evidence); `agent_type` stays out (read only for
  `= 'role'` checks today). Limits: it is textual, so a statement whose table is a
  format argument (`graph_view.rs::graph_query_node_ids`, H6) is guarded by its HTTP test,
  not by the lint; it does not scan `events` payload builders (L14 stays pinned by T7 only).
- **A bound agent reads its operator's teams (234)**, so once H has a team, H's own bot is
  NAMED H through the team arm; `an_operated_agent_sees_its_human_exactly_as_an_outsider_does`
  stays true only while H has no team (as that test builds it).
- **I3: only OPL02 is mapped to fixed text.** OPL01 names only the unbound agent (the
  caller's write identity or the author it named), never a human, and two MCP tests pin
  that the refusal names that agent for the caller's fix.
- **E3 surfaces re-verified on this head:** edge `properties` reach a caller through REST
  `list_edges` and `claim_neighborhood` (both redacted); MCP `get_neighborhood` / `traverse`
  return no properties; `graph_full` / graph query take only `strength` and `prov_type`;
  `agent_claims` serves `ATTRIBUTED_TO` edge properties (no name key is written there);
  `create_edge` / `patch_edge` echo the writer's own row.
- **C4 (`create_agent`)** now takes a `ViewerExtractor` (never `Option<..>`, per
  `middleware/bearer.rs`), so a token that names no principal is refused 401 on that route
  as on every viewer route.
- **G1** reads names through the rule; every exported filer filed a claim the caller reads,
  so no observable change is expected, and no new test beyond the export suite was added.

Not covered by part B (open):

- **L13** (`scripts/label_themes_llm.py`'s cosmetic `agent` column) is not dropped; it
  samples public claims only, whose filers the rule names.
- **T8's four admin paths** and **T13 over every surface** are pinned at the predicate
  (part A); part B adds T2 on the `authored_by` block, not a full viewer x claim matrix per
  surface.
- **C7** stays the brief's literal `display_name: null` (option (b)); the main session's
  measurement of nameless non-human agents is still owed to the operator.
- **C12** (above): the worst-case budget.

## 17. Deploy notes

- Migrations apply at API boot. M4 and M5 build concurrently.
- Rollout order: the API (which migrates) deploys before any binary that calls the new
  functions; part A's binaries call the setter only from the new routes and the new tool.
- M3's reset (274) evaluates `epigraph_is_human_principal` (a definer with a SET clause,
  never inlined: two index probes plus call overhead) for every agent whose profile is not
  'group', three times (before-count, UPDATE, after-count). Nearly every agent is 'public',
  so the boot migration's time scales with the whole `agents` table x3 (review
  correctness#6). It runs once; 274 is not edited (the standing rule), so a NEW migration
  could not improve it. Expect it on the deploy that applies 274.
- M3's reset takes row locks under `lock_timeout = '3s'`. A long `ensure_for_client`
  transaction holding a human row fails the boot migration; the API restarts and retries.
- After M4 and M5: `SELECT indexrelid::regclass FROM pg_index WHERE NOT indisvalid` must
  return nothing. An invalid index is recovered with `DROP INDEX CONCURRENTLY <name>`, then the
  migration is re-applied (finding 15).
- The undo runbooks are paired with a binary rollback: a binary that calls a dropped function
  fails.
- M7 (278) mints a personal group for any role holder that has none, and refuses the boot
  migration (RVK01 / RVK02) for a holder whose personal membership is only revoked or whose
  personal key is squatted. Pre-check on the maintenance DSN before deploy: every live or
  ended `role_assignments.holder_person_id` has a live row in the group whose `did_key` is
  `did:epigraph:personal:<holder>`, or no such group at all.
- After deploy, rebuild the Atlas leaf levels: run the Atlas nightly builder once, outside its
  schedule. Previously stored documents carry names built under a bypass viewer.
- MCP stdio clients pin their binary. Restart them so that the find_agent and get_agent text,
  and the new tool, are served.

## 18. Critique resolution (revision 2)

Every finding of the two reviews, with its disposition. "Accepted" points to where the text
now says it; "Part" is where the change is built.

| Finding | Disposition | Where | Part |
|---|---|---|---|
| L1 null name is a marker; `?label=oauth-principal` enumerates | **[OPEN] C7**, brief's null kept; N rebuilt production-shaped; labels and properties compared | §5, §12.T1 | B |
| L2 `author_name` and `replaces` on `authored` edges | Accepted: resolved now, not deferred (C1 closed) | §7 E2, E3 | B |
| L3 `same_spelling` name-to-id oracle | Accepted: the `declined` half is gated | §7 A6, §12.T1 | B |
| L4 TGP03 invite oracle | **[OPEN] C10**, recorded as a residual | §15.R11 | - |
| L5 GQL matches `properties` | Accepted: anchor rows gated before LIMIT; lint scope | §7 H6, §14 | B |
| L6 drop before LIMIT and truncation | Accepted: normative placement plus decoy test | §7 A1, A4, §12.T1 | B |
| L7 `OPERATED_BY` edges | Accepted as residual; §5 no longer says `operator_human` is the only signal | §5, §15.R12 | - |
| L8 MCP forwards OPL text | Accepted (reachability PLAUSIBLE, re-verified in part B) | §7 I3 | B |
| L9 binding window | **[OPEN] C5**: narrows approved text; consequence recorded | §4, §16.C5 | - |
| L10 timing | Accepted as residual | §15.R13 | - |
| L11 pending count | Accepted in revision 2 (zeroed when unnamed), REVERSED after review: the premise was false and the zero was a marker; served to all (B16) | §7 A2 | B |
| L12 assessment-slot BBAs | Accepted as residual | §15.R14 | - |
| L13 stored derivatives | Accepted: theme labeller added to F2; agent column dropped | §7.J, §15.F2 | B |
| L14 `agent.registered` payload | Accepted: T7 assertion; lint scope | §7.J, §12.T7, §14 | A (T7), B (lint) |
| L15 R2 narrower than written | Accepted, merged into R2 | §15.R2 | - |
| L16 re-verifications | Cited | §7 A4, §7.J | - |
| 1 third-party unhide paths | Accepted: §4 corrected, R2 widened, T8 pins; **[OPEN] C3**, C4 | §4, §15.R2, §12.T8 | B (T8) |
| 2 perf gate cannot be evaluated | Accepted: forced LATERAL probes; auto_explain / generic plans; four extra shapes; call counts | §6.1, §11 | A (SQL), B (measurement) |
| 3 A1/A4 filter in SQL | Accepted (same as L6) | §7 A1, A4 | B |
| 4 COST on the wrappers | Accepted | §6.1 | A |
| 5 accountability property | Accepted: T13 | §12.T13 | A (predicate), B (surfaces) |
| 6 non-claim assertions | Accepted as B15; **[OPEN] C6** | §4, §16 | - |
| 7 ever-bound over-discloses | Accepted: consequence stated; alternative rejected pending C5 | §4 | - |
| 8 status-free claim contradicted | Accepted: §3 corrected, R5 folded, T3 case | §3, §15.R5, §12.T3 | A |
| 9 B(H) completeness | Accepted: invariants cited and tested | §3, §12.T13 | A |
| 10a evidence row unprotected | Accepted: HEV01 trigger (B17); app INSERT route stated | §6.1, §10 M1 | A |
| 10b T10 vacuous under a superuser | Accepted: explicit NOSUPERUSER owner; wording fixed | §6.1, §12.T10 | A |
| 11 reset can move zero rows; split M1 | Accepted: post-condition, counts, lock note, split into M1-M3 | §10, §17 | A |
| 12 `profile_visibility` app-updatable; R8 premise | Accepted: lockdown test; R8 rewritten | §10, §15.R8, §7 C5 | A |
| 13 lock-function DROP + CREATE avoidable | Accepted: B7 reversed, revision 1's M2 dropped | §9.3, §16.B7 | A |
| 14 column default fails open | Partly: catalog insert-path pin accepted; consent column **[OPEN] C11** | §15.F4, §12.T10 | A |
| 15 index trap, registration, key order | Accepted | §10, §17 | A |
| 16 budget at risk; `author_binding_clients` index | Accepted: index added; fallback listed (C9) | §6.1, §10, §11 | A |
| 17 setter: non-humans, truthful text, LLM residual | Accepted: PVS05, `named_to_everyone`, description, R15 | §8, §15.R15 | A |
| 18 email guard hardening | Accepted: `Cf` rejected; local part and R9 recorded | §9.2 | A |
| 19 timing | Accepted (same as L10) | §15.R13 | - |
| 20 N may have no counterpart | **[OPEN] C7** (same as L1); measured by the main session | §5 | - |
| minor: T6 tenancy | Accepted | §12.T6 | B |
| minor: 206 write window | Re-verified: not needed after 271; omitted (B19) | §8 | A |
| minor: undo needs a binary rollback | Accepted | §10, §17 | - |

Rejected outright: none. Revision 1's `refusal_codes.rs` registration (§8) was wrong and is
replaced by a local mapper; that is a correction, not a finding.
