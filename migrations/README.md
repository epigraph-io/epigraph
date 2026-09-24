# EpiGraph Database Migrations

PostgreSQL schema migrations for the EpiGraph epistemic knowledge graph system.

## Migrations are append-only

Once a migration has been applied (in any environment), its file is **frozen**:
the SHA-384 checksum is recorded in `_sqlx_migrations.checksum` and verified on
every API startup. Editing an applied migration file — even whitespace, comments,
or a typo fix — will cause the next deploy to fail with a checksum mismatch and
refuse to start.

Add a NEW migration (`NNN+1_fix_typo.sql`) instead of editing an existing one.

## Known schema drift: `uq_claims_content_hash_agent` (013)

`_sqlx_migrations` recording a version as applied does **not** prove the
objects it created still exist. On the long-lived `epigraph` database,
migration 013 is recorded `success = true` while its
`uq_claims_content_hash_agent UNIQUE (content_hash, agent_id)` constraint is
absent from `claims`.

Cause: integration-test fixtures in
`crates/epigraph-db/tests/claim_repo_helpers.rs` and
`crates/epigraph-mcp/tests/common/mod.rs` deliberately drop that constraint to
exercise the pre-107 code path. Run with `DATABASE_URL` pointing at a live
database, they dropped it there and left it dropped. Those fixtures now refuse
to run against non-disposable databases (see `db_is_disposable` /
`EPIGRAPH_TEST_DESTRUCTIVE_DB`), so the drift cannot recur — but the existing
drift, and the ~169k duplicate rows that accumulated while `claims` was
unconstrained, still need reconciling.

**Do not "fix" this with a new migration that re-adds the constraint.** A bare
`ADD CONSTRAINT` fails on the duplicates, and per the append-only rule above a
failed migration panics the api binary on restart — turning silent drift into a
deploy outage. Audit first:

```bash
python3 scripts/audit_claims_content_hash_agent.py     # read-only
```

## Version range coordination with epigraph-internal

The private `epigraph-internal` repo also runs `sqlx::migrate!()` against the
same `_sqlx_migrations` table, so its versions and ours **did** share a number
space. As of 2026-09-02 that is no longer true in practice — see "The
epigraph-internal overlap" below — but the numbers it burned are still real and
still recorded here, because a database that ever ran internal carries them.

Current reservation:

- **001–034**: public
- **035–037**: `epigraph-internal` (`claim_supersession`, `challenges_and_events`,
  `analyses`) — applied to prod 2026-05-22. Public has since renumbered these
  same files in-tree to `036–038` (cross-source matching port).
- **038**: public `corroborates_factor_strength_from_score` (PR #173)
- **039–059**: public
- **060–090**: RESERVED — public multi-user tenancy series (epigraph-io/epigraph
  `feat/multi-user-tenancy`). `epigraph-internal` MUST NOT allocate in this range.

  | Version(s) | PR | What |
  |---|---|---|
  | **060** | PR-01 | group tenancy tables |
  | **061** | PR-02 | `agents.key_kind` |
  | **062** | PR-04 | tenancy columns, stage 1 — metadata-only, idempotent, transition DEFAULTs present |
  | **063–066** | PR-04 | tenancy indexes. `-- no-transaction`, **one `CREATE INDEX CONCURRENTLY` per file**. See the section below; this is not style. |
  | **067** | PR-04 | session / bypass functions (`epigraph_session_groups`, `epigraph_writable_groups`, `epigraph_principal_id`, `epigraph_bypass`, `epigraph_definer_bypass`) |
  | **068–084** | PR-05 … PR-22 | the remaining plan §3.1 migrations, shifted **+4** from the plan's printed numbering after 062 (plan 064 → 068, …, plan 080 → 084) |
  | **085** | PR-10 | `webhook_subscriptions` — **claimed 2026-09-03**, was headroom |
  | **086** | PR-24 | `epigraph_claim_tenancy_by_ids` `SECURITY DEFINER` read helper — **claimed 2026-09-06**, was headroom |
  | **087** | PR-18 (delivered as 18b) | SELECT + INSERT policies on `privatization_plans` and `privatization_plan_items` — **claimed 2026-09-08**, was headroom |
  | **088** | PR-18 (delivered as 18c) | UPDATE policies on `privatization_plans` and `privatization_plan_items` — **claimed 2026-09-08**, was headroom |
  | **089** | cleanup batch `tenancy/fix-harvester-fragment-stamp` (no plan section — all 22 are delivered) | `harvester_claim_provenance_fragment_inherit_tenancy` + `epigraph_inherit_fragment_tenancy_stmt`: an AFTER INSERT statement trigger that stamps a `harvester_fragments` row with its claim's tenancy when the provenance row linking them appears. Closes the one write moment migration 070 could not cover — `harvester_fragments` has no `claim_id`, so arm (c) cannot key on it, and arm (d) fires only when a claim's tenancy changes. Adds no table, so 070's `GRANT … ON ALL TABLES` note needs no re-issue. File: `089_harvester_fragment_provenance_stamp.sql`. **No undo runbook ships**, unlike 070/074/079/084: reversing this file is one `DROP TRIGGER IF EXISTS` plus one `DROP FUNCTION IF EXISTS` (both named in the file's own closing section), and the rows it stamped are deliberately NOT un-stamped — `docs/runbooks/070-undo.sql` takes the same stance, so an operator rolling back is left with a fail-closed residual rather than a hazard. Recorded here so the absence is a decision rather than an omission. **Claimed 2026-09-12**, was headroom. **Applied to a throwaway database only, NOT to any deployed database.** |
  | **090** | FORCE-precondition batch `tenancy/fix-force-preconditions` (no plan section — all 22 are delivered) | `edges_symmetric_relationship_uniq`: a partial UNIQUE index over `(LEAST(source_id,target_id), GREATEST(source_id,target_id), relationship)` for the two symmetric claim-claim relationships `EdgeRepository::create_symmetric_if_absent` writes (`CORROBORATES`, `contradicts`), keyed on the same `(pair + properties->>'source' = 'cross_source_matcher')` identity `MatchCandidateRepo::retire` already uses and restricted to in-force claim-claim rows, so an operator-authored edge over the same pair is unaffected — a broader predicate was written first and rejected when two existing tests caught it changing what `POST /edges` may write. `alternative_of` is deliberately excluded — migration 042's `edges_alternative_of_symmetric_uniq`, narrowed by 091, already covers it. Backs a read guard that is not atomic and that cannot see an edge whose ownership no longer follows its endpoints' (072 arm (d)'s no-widening rule); `D-PR17-read-guards-widen-under-rls`. File: `090_edges_symmetric_relationship_uniq.sql`. **No undo runbook ships**: reversing this file is one `DROP INDEX IF EXISTS edges_symmetric_relationship_uniq`, named in the file itself, and it creates no rows to un-create. **The file carries a DEPLOY PRECONDITION** — `CREATE UNIQUE INDEX` fails on pre-existing in-force duplicates, and the census query is in its header; measured zero on the throwaway, unknown on production, which is at migration 59. **Claimed 2026-09-15**, was headroom — this exhausts the reserved 060–090 range. **Applied to a throwaway database only, NOT to any deployed database.** |

  **060–090 is now fully allocated.** There is no headroom left inside this
  range. It is NOT the end of the tenancy series: the operator authorized a
  SECOND contiguous tenancy block, `092–099`, on 2026-09-15 — see its own entry
  below. Until that decision it was true, and is recorded here as history, that
  "a tenancy migration that needs a number after this one is a version-space
  decision for the operator, not a choice a PR may make". The decision was made;
  the rule that produced it stands for `100` and beyond.

  **The post-shift numbers, pinned.** THIS TABLE IS AUTHORITATIVE; plan §3.1's
  own columns are not, and neither is `docs/tenancy/FINAL-PLAN.md`. Derive
  nothing — a downstream comment that names a migration must name the number in
  this column. **PR-05 takes 068 and 069, not the plan's 065/066.**

  | Actual | PR | What |
  |---|---|---|
  | **068** | PR-05 | communities → groups; `encryption_key_id` de-overload |
  | **069** | PR-05 | `entity_types.tenancy_tier` + `tenancy_exempt` registry |
  | **070** | PR-12 | write-side stamping triggers (statement-level, transition form) — drafted PR-12; **validated on a throwaway DB only, NOT applied to any deployed database** (plan §9.2 puts that at week 11c) |
  | **071** | PR-12 | `ownership` compat shim — drafted PR-12; **validated on a throwaway DB only, NOT applied to any deployed database** |
  | **072** | PR-13 | `edges.co_owner_group_id` — column + FK + shape CHECK (both `NOT VALID`) and the `CREATE OR REPLACE` of 070's `epigraph_edges_tenancy` / `epigraph_propagate_tenancy`. **Drafted PR-13; validated on a throwaway DB only, NOT applied to any deployed database.** File: `072_edge_co_ownership.sql` |
  | **073** | PR-13 | edge co-owner index (`-- no-transaction`, one `CREATE INDEX CONCURRENTLY`). File: `073_idx_edges_co_owner.sql`. NOT the `edges_tenancy` RLS policy — the plan's PR-13 *Files* line says "pre-staged for 073" and means **077**; the clause itself is written out in 072's header. **Drafted PR-13; validated on a throwaway DB only, NOT applied to any deployed database.** |
  | **074** | PR-16 | tenancy REQUIRED: `DROP DEFAULT`, require-tenancy trigger, no-widening trigger |
  | **075** | PR-16 | validate tenancy constraints — `claims` only |
  | **076** | PR-16 | validate tenancy constraints — remaining tier-A tables |
  | **077** | PR-17 | RLS policies (`ENABLE` only) + `epigraph_app` GRANTs + `security_invoker=true` on the two view exemptions. File: `077_rls_policies.sql`. **Applied to a throwaway database only, NOT to any deployed database.** |
  | **078** | PR-17 | RLS canary table (`rls_canary`, FORCEd at creation and deliberately absent from 079's array). File: `078_rls_canary.sql`. **Throwaway only.** |
  | **079** | PR-17 | `FORCE ROW LEVEL SECURITY` over 062's `tier_a` ∪ the ten control tables. File: `079_rls_force.sql`; undo at `docs/runbooks/079-undo.sql`. **The plan's 079 array also names `privatization_plans`, `privatization_plan_items`, `privatization_audit` and `instance_admins`; they did not exist when 079 was written — they are PR-18a's 080–083 — and 079 RAISEs rather than silently skipping a missing table.** 079's header instructs PR-18 to add them to its own array; **that instruction cannot be followed and was not** — 079 is applied and frozen by the rule below, so 080/082/083 FORCE their own tables at creation instead, which is the instrument 078 established for `rls_canary`. **The undo script therefore loops a LONGER array than 079 does** (thirty-nine, not thirty-five), because the boot assertion counts the catalog and a partial un-FORCE is the state it refuses on. **Throwaway only.** |
  | **080** | PR-18a | `privatization_plans`, `privatization_plan_items`, `epigraph_content_lineage_hull`, `epigraph_privatization_closure`. Both tables ENABLE + FORCE with **no policy** — full default deny, registered pair-by-pair in `rls_enforcement.rs::DELIBERATELY_UNCOVERED`, because 18a ships no reader and no writer of either. File: `080_privatization_plans.sql`. **Throwaway only.** |
  | **081** | PR-18a | privatization guards: the plan guard (target-group maturity + admin plurality), the approver guard, and `claim_encryption_no_public_sealed`. No table, so nothing to FORCE. File: `081_privatization_guards.sql`. **Throwaway only.** |
  | **082** | PR-18a | `privatization_audit` (append-only) + the `security_events` hardening PR-17 deferred here: the shared `epigraph_audit_immutable` trigger on both tables and `REVOKE UPDATE, DELETE … FROM epigraph_app`. File: `082_privatization_audit.sql`. **Throwaway only.** |
  | **083** | PR-18a | `instance_admins` + `epigraph_is_instance_admin(uuid)`, plus the two policies 082 could not create before the function existed (`privatization_audit_read`, and `security_events_read`'s restored instance-admin disjunct). Seeds nothing. **Correction to the plan:** it prescribes no INSERT/UPDATE policy on `instance_admins`, which under `FORCE` denies the operator grant to every role; 083 ships a bypass-only INSERT and UPDATE pair instead, and stops short of `FOR ALL` so DELETE stays denied. File: `083_instance_admins.sql`. **Throwaway only.** |
  | **084** | PR-22 | retire `ownership`. `DROP TABLE public.ownership` plus, EXPLICITLY and in their own statements, the `ownership_key_id_quarantine` VIEW (068) and `public.epigraph_ownership_transcribe()` (071) — `DROP TABLE` removes the two triggers but not the SECURITY DEFINER body behind one of them, and a CASCADE would take the view pre-flight (1) inspects. Gated on **two `DO $$` blocks that RAISE EXCEPTION**: an empty quarantine, and zero non-public rows without a `tenancy_transcription_log` entry. Both are sliced out by their `-- >>> PRE-FLIGHT n` sentinels and executed against a manufactured failing state by `crates/epigraph-db/tests/retire_ownership_preflight.rs` — a `#[sqlx::test]` body cannot seed the table, because the migrator has already dropped it. **ONE-WAY DOOR**; undo at `docs/runbooks/084-undo.sql`, which recreates the empty shape and states which columns are recoverable from the surviving ledger and which are not. **Applied to a throwaway database only, NOT to any deployed database.** |
  | **085** | PR-10 | `webhook_subscriptions` (durable webhook registrations, `agent_id` FK) |
  | **087** | PR-18 (18b) | SELECT + INSERT policies on `privatization_plans` and `privatization_plan_items`. **The plan specifies no policy for either table** — fourteen `CREATE POLICY` blocks in `docs/tenancy/FINAL-PLAN.md`, none naming them — so this file designs them from 082/083's two templates and says so in its own header. Read is instance-admin **AND** group-admin-of-target (§6.5.2 point 2); write is bypass-only, matching 083's `instance_admins` shape, because 080 already REVOKEs DML from `epigraph_app`. **Side effect on a table it does not touch:** 083's `privatization_audit_read` entity arm resolves its sub-select over `privatization_plans` and therefore activates. UPDATE and DELETE stay uncovered and stay registered in `rls_enforcement.rs::DELIBERATELY_UNCOVERED`. File: `087_privatization_plan_policies.sql`. **Throwaway only.** |
  | **088** | PR-18 (18c) | UPDATE policies on `privatization_plans` and `privatization_plan_items`, bypass-only on both `USING` and `WITH CHECK`. **The plan assigns this slice migrations "076/077/078/079", which are PR-16's and PR-17's under the +4 shift and are applied and frozen** — so the number comes from this table's headroom instead. Every state transition in the apply/approve/abort/revert surface is an UPDATE of one of these two tables, and under `FORCE` an uncovered command is denied to every role including a bypass connection, so the whole surface is blocked without this file. DELETE stays uncovered on both tables and stays registered in `rls_enforcement.rs::DELIBERATELY_UNCOVERED`; the two UPDATE rows are deleted from that register in the same commit, because it is exact in both directions. File: `088_privatization_plan_state_policies.sql`. **Throwaway only.** |

  **PR-10 takes 085, NOT the 081 `docs/tenancy/FINAL-PLAN.md` names.** The
  plan's PR-10 note says its migration "takes the next unused number in the
  reserved 060–085 range (081 if nothing else has claimed it)". 081 *is*
  claimed — PR-18's privatization guards, two rows up. The plan was written
  against the pre-shift numbering, before PR-04's index migration became four
  files; that is the same staleness this table's "Derive nothing" rule exists
  to absorb. PR-10 landed ahead of PR-12…PR-22 in wall-clock order, which is
  exactly the case the headroom row was reserved for.

  **Non-table objects the reserved range introduces.** A number in the table
  above names a migration, not everything it creates. These are the objects
  inside 060–090 that a later `DROP` has to know about by name, because they are
  not tables and so do not appear in the Tombstones section below:

  | Object | `relkind` | Created by | Dropped by |
  |---|---|---|---|
  | `public.ownership_key_id_quarantine` | VIEW (`v`) | 068 | **084 — DONE.** Dropped explicitly, in its own statement, AFTER the pre-flight that reads it (`SELECT count(*) FROM ownership_key_id_quarantine`); a non-empty result is an operator action item, and `DROP TABLE ownership CASCADE` would have destroyed the object the check inspects. `retire_ownership_preflight.rs::the_migration_declares_both_pre_flights` asserts that 084 contains no `CASCADE` and drops the view by name. |
  | `public.tenancy_exempt` | TABLE (`r`) | 069 | **never** — it is the §2.4 exemption registry and outlives the series. Listed here so it is not mistaken for scaffolding. |

  A VIEW was deliberate for the quarantine (ops F20): a `CREATE TABLE AS`
  snapshot taken at 068 time cannot see a row that becomes unparseable
  afterwards, so 084's pre-flight would have passed over exactly the value it
  existed to catch. It was created `WITH (security_invoker = true)` — a view
  without that option executes as its OWNER and bypasses the invoker's policies
  once migration 079 FORCEs RLS, which is the open finding migration 069 files
  against `alternative_set` and `alt_set_decisions`. **THE RULE STANDS: any VIEW
  added in this range must set it.** Its example does not. PR-22 dropped the
  view and with it
  `crates/epigraph-db/tests/tenancy_coverage.rs::ownership_key_id_quarantine_is_a_view`,
  which pinned both properties — a deliberate un-pinning, recorded here because
  README named that test as the pin. The rule is still ratcheted, on the two
  view exemptions in `tenancy_exempt`, by that file's
  `the_two_view_exemptions_are_security_invoker`.

  **The app-role grant rule, from 077 onward.** Migration 077 grants
  `epigraph_app` SELECT/INSERT/UPDATE/DELETE `ON ALL TABLES IN SCHEMA public`.
  That binds only the tables that exist at version 077, so on a FRESH migrate
  (CI, a new cluster, a restore) every table created by a LATER migration is
  missed — while on the already-deployed database the same statement catches
  them, because there the later tables already exist. That divergence was real:
  `webhook_subscriptions` (085) was measured as the one relation in `public` for
  which `has_table_privilege('epigraph_app', …, 'SELECT')` was false at head.
  077 therefore ALSO issues `ALTER DEFAULT PRIVILEGES FOR ROLE epigraph … GRANT
  … TO epigraph_app`, which covers tables created afterwards **by the migration
  runner**. A table created by any other role is not covered and needs its own
  explicit grant, the way 078 grants `rls_canary`. Pinned by
  `rls_enforcement.rs::the_app_role_can_reach_every_public_table_without_the_test_fixture`,
  which deliberately does NOT call `viewer_fixture::grant_app_privileges` — that
  fixture re-issues the schema-wide grant at test time and would mask exactly
  this gap.

  Two comments in migrations already applied to a database still carry
  pre-shift numbers and **cannot be corrected**: editing an applied file changes
  its checksum and `sqlx migrate run` then refuses to start. They are
  `060_group_tenancy_tables.sql:110` ("070's seed arm" — now **074**) and
  nothing else. Read them against this table.

  **Why 060–085 became 060–090.** PR-04's index migration could not be one file
  (see below), so it became four, consuming three extra numbers and pushing the
  chain's end from 081 to 084. Against the old reservation that left exactly one
  free number for PR-10's webhook-persistence migration and no slack at all. The
  version space is shared with `epigraph-internal` against the same
  `_sqlx_migrations` table, and `run_migrations` sets `set_ignore_missing(true)`
  (`crates/epigraph-api/src/migrate.rs::embedded_migrator`), so a collision is **not** caught by the
  missing-version check — it panics the api binary on restart.

  **Why the +1 shift:** the plan assigns no migration to PR-02, yet PR-02's
  `AgentRepository::ensure_for_client` writes `agents.key_kind = 'derived'` for
  the blake3 placeholder key it materialises for every keyless OAuth principal,
  and `routes/submit.rs` must filter `key_kind = 'ed25519'` on the signature
  path. `key_kind` was scheduled inside PR-04's tenancy-columns migration, which
  would have retroactively stamped every PR-02 placeholder agent as a real
  Ed25519 verifier. PR-02 therefore claims 061 and everything after it moves up
  one. **Do not "correct" this back to the plan's numbering** — 061 is applied.
  PR-04's tenancy-columns file keeps its own guarded `ADD COLUMN IF NOT EXISTS
  key_kind` statements; against a database that has 061 they no-op.
- **091**: public `alternative_of_uniq_ignores_retracted` (PR #411) — the first
  allocation outside the reserved range. It was written as `060` and merged to
  `main` before this table existed there; see "Why 091 and not 060" below.
- **092–099**: RESERVED — public multi-user tenancy series, CONTINUED.
  `epigraph-internal` MUST NOT allocate in this range. `091` is NOT in it (see
  the entry above and "Why 091 and not 060"), which is why the block starts at
  `092` and is not contiguous with `060–090`.

  Authorized by the operator on **2026-09-15**, when `060–090` was exhausted and
  `D-PR17-creator-arm-outlives-membership` still needed a migration. Recorded
  here on the same terms as `060–090`, in the same commit as the first file that
  claims from it. The working record is `~/tenancy-pending-decisions.md`, outside
  this repository.

  | Version(s) | PR | What |
  |---|---|---|
  | **092** | obligation batch `tenancy/fix-force-tail-and-registers` (no plan section — all 22 are delivered) | `epigraph_group_roster_admits_principal` + a narrowed `epigraph_is_group_creator` + an `ALTER POLICY` on `groups_tenancy`: bounds migration 077's group-creation bootstrap arm to the group's roster, so it ends where the creator's own membership ends instead of never. Closes `D-PR17-creator-arm-outlives-membership` (COMPLETION-PLAN §2.2.5). The arm is carried by THREE policies in TWO spellings — an inline column comparison on `groups`, the shared `epigraph_is_group_creator()` helper on `group_memberships` and `group_key_epochs` — and both are narrowed, because a single-site fix is incomplete by construction. `ALTER POLICY`, not DROP + CREATE, so `pg_policy.polcmd` keeps `*` and no command coverage can be lost; pinned by `locked_decisions.rs::d4_the_group_creation_bootstrap_arm_is_bounded_by_the_roster`. The new definer body's OWNER is a correctness control rather than hygiene — see the file's section 5 — and is pinned in CI by `schema_contract.rs::migration_092_roster_definer_is_revoked_from_public` and at deploy by `tenancy_backfill.rs::DEFERRED_DEFINER_FUNCTIONS` (plan §9.2 step 11c). File: `092_group_creator_arm_roster_bound.sql`. **No undo runbook ships**, on the same ground as 089 and 090: reversing it is one `CREATE OR REPLACE FUNCTION public.epigraph_is_group_creator(uuid)` back to 077's body, one `ALTER POLICY groups_tenancy ON public.groups USING (…)` back to 077's text and one `DROP FUNCTION IF EXISTS public.epigraph_group_roster_admits_principal(uuid)` — the roster predicate is NEW in 092 and has no 077 body to be replaced back to, so it is dropped rather than replaced — all three named in the file's own closing section, and it creates no rows to un-create. **No deploy precondition**: it adds no constraint and no index, so there is no pre-existing state it can fail on. **Claimed 2026-09-16.** **Applied to a throwaway database only, NOT to any deployed database.** |
  | **093–099** | — | headroom |

- **100**: public `claims_belief_frame_id` (backlog 696d3a1c) — records WHICH frame
  the cached `claims.{belief, plausibility, mass_on_empty, pignistic_prob,
  mass_on_missing, open_world_mass}` scalars summarize. Nullable, additive, no
  backfill: NULL honestly means "written before this column existed".

  **Why 100 and not 093.** It was authored as `093` against `main`, whose README
  read "092+: public next" — the second reserved block `092–099` is recorded only
  on the tenancy line, so the public branch had no way to see it and CI could not
  catch it. The merge brought both files together cleanly and the contradiction
  surfaced only on reading. Renumbered here rather than on main because it has
  never been applied to a deployed database — production is at 59.

- **101**: public `seed_method_entity_type` (backlog 895a74e5) — seeds the
  `method` row in the `entity_types` registry, without which every edge whose
  `source_type`/`target_type` is `'method'` is refused by the FK migration 055
  installed.

  **Why 101 and not 094.** It was authored as `094` against a `main` whose
  README read "095+: public next", so neither the author nor CI could see that
  `092–099` had been reserved as the SECOND tenancy block on 2026-09-15 — the
  same blind spot that put `claims_belief_frame_id` at `093`, recorded one entry
  up. The renumber also dissolves a second collision the original entry had to
  document and live with: `epigraph-internal` carries a DIFFERENT
  `094_stop_truth_value_overwrite.sql`, and the two repos share a
  `_sqlx_migrations` table, so version 94 was a checksum collision waiting for
  the first database that saw both. At `101` there is nothing to check for
  before deploying. Renumbered here rather than on `main` for the same reason
  `100` was: it has never been applied to a deployed database — production is at
  59.

- **102–104**: HELD for the open branch `feat/operator-scoped-ownership`, which
  carries `102_operator_link.sql` and `103_groups_identity_immutable.sql` and
  may take `104`. Not allocated on this line; that branch records its own
  entries in the same commit as its files. Recorded here only so no other
  branch picks a colliding number.
- **105**: public `personal_group_no_revival` (batch F; backlog F2 `af7c58d9`,
  the root of F1 `da432f25`, #493 and #498's `system_agent_write_authority`
  finding). `CREATE OR REPLACE` of migration 077's
  `epigraph_ensure_personal_group(uuid) RETURNS uuid`, same signature: a LIVE
  personal membership is returned with its role kept and nothing written; only
  REVOKED rows (any epoch) RAISE SQLSTATE `RVK01`, which
  `epigraph-db/src/errors.rs` maps to `DbError::MembershipRevoked`; no row of
  any state provisions exactly as before. Before any of that, the group under
  the canonical did_key must be the agent's own (`kind = 'personal'` and
  `created_by_agent_id` = the agent), or it RAISEs SQLSTATE `RVK02`
  (`DbError::PersonalGroupNotOwned`): a group another agent created under that
  key is a squat, not a personal group. 077's body ended in `ON CONFLICT …
  DO UPDATE SET revoked_at = NULL, role = 'admin'`, so every call revived a
  revocation and promoted a demotion. Re-states 077's owner / `REVOKE … FROM
  PUBLIC` / `GRANT EXECUTE … TO epigraph_app` block (idempotent). Pinned by
  `epigraph-db/tests/personal_group_no_revival.rs` as `epigraph_app`. **No undo
  runbook ships**: reversing it is re-running 077's function body, which
  restores the defect; it creates and changes no rows. **No deploy
  precondition.** **Claimed 2026-09-24.** **Applied to a throwaway database
  only, NOT to any deployed database.**
- **106**: public `community_membership_integrity` (batch F follow-on; F4a
  `afb1cfaf`, F4b `7cdea6f1`). Two `SECURITY DEFINER` functions,
  `epigraph_community_add_member(uuid, uuid, uuid)` and
  `epigraph_community_remove_member(uuid, uuid, uuid)`, each of which takes the
  community group's roster lock, then its `groups` row lock (which serialises
  first joiners over an empty roster), decides under both, and writes — one
  statement for `CommunityRepository`. Rules: add needs a LIVE member, except a
  group that has NEVER had a membership row of any state (a group emptied by
  removals does not re-open); a revoked row is restored at the requested
  `reader` role, never its old one. Only a LIVE admin may restore a revoked
  row (`'denied_readmit'` otherwise), so a live reader cannot undo an
  eviction. Remove needs the perspective's owner
  (leaving) or a LIVE admin (evicting), and never removes the last live admin
  (`'last_admin'`, nothing written). The actor is `epigraph_principal_id()`
  unless `epigraph_bypass()`; a mismatched `p_actor` is DENIED. The
  `community_members` DELETE runs in the caller's statement, because
  `epigraph_maintenance` holds no DELETE (070). Owner `epigraph_maintenance`,
  `REVOKE … FROM PUBLIC`, `GRANT EXECUTE … TO epigraph_app`. Also `REVOKE
  DELETE ON group_memberships FROM epigraph_app`: the membership table is an
  append-and-revoke ledger, 105's and 106's rules both rest on rows never
  disappearing, and the FOR ALL policy let a stamped agent delete its own and
  its groups' rows (measured: a revoked agent re-provisioned as live admin, a
  reader deleted its admin's row, an emptied group re-bootstrapped). Pinned by
  `epigraph-db/tests/community_membership_integrity.rs` as `epigraph_app`.
  **No undo runbook ships**: reversing it is two `DROP FUNCTION IF EXISTS`
  (named in the file), `GRANT DELETE ON group_memberships TO epigraph_app`
  (which restores the hole), and the pre-batch-F `community.rs`; it creates no
  rows. **No deploy precondition in this repository**; deploy note: a consumer
  OUTSIDE this repository that deletes `group_memberships` rows as
  `epigraph_app` will get 42501 after this file (none exists in-tree; not
  verified for out-of-repo consumers). **Claimed 2026-09-24.** **Applied to a
  throwaway database only, NOT to any deployed database.**
- **107+**: public next

Next public migration **outside both reserved tenancy ranges** must be `107` or
later. Numbers inside 060–090 are allocated by §3.1 of the tenancy plan;
numbers inside 092–099 are allocated by the obligation batches that follow it.
Both are claimed one at a time, and a claim is recorded in the tables above **in
the same commit as the file**. Picking a colliding version (checksum mismatch on
a `_sqlx_migrations` row that's already applied) will panic the api binary on
restart.

## `-- no-transaction` migrations

Migration `063_idx_claims_group_current.sql` is the **first `-- no-transaction`
migration in this repo's history**. Before it, `013_code_review_hardening.sql:8-10`
and `030_atom_embedding_partial_index.sql:11` documented a manual DBA pre-step
for `CREATE INDEX CONCURRENTLY` because the team believed it impossible inside a
migration. It is not: sqlx-core 0.8.6 honours a leading `-- no-transaction` line
(`src/migrate/source.rs:127`) and sqlx-macros-core propagates the flag into the
compile-time `migrate!()` literal, so `epigraph-migrate` honours it too.

### THE RULE: one statement per `-- no-transaction` file

Not style. sqlx-postgres 0.8.6's `execute_migration` runs
`conn.execute(&*migration.sql)` (`src/migrate.rs:280`) — the **simple query
protocol over the whole file**. PostgreSQL wraps a multi-statement simple query
in an *implicit transaction block*, and `CREATE INDEX CONCURRENTLY` inside one
fails with SQLSTATE **25001**, `CREATE INDEX CONCURRENTLY cannot run inside a
transaction block`. Interleaving `COMMIT;` between statements does not help;
that was tested. The four index statements PR-04 needed are therefore four
files, 063–066.

`crates/epigraph-db/tests/tenancy_migration_shape.rs::no_transaction_files_contain_exactly_one_statement`
is the ratchet on this. Without it, the next person merges the files back
together and the whole workspace suite goes red at once, with an error naming
sqlx rather than the edit.

Two further constraints:

* `-- no-transaction` must be the **literal first bytes of the file** — no BOM,
  no blank line, no `-- <name>.sql` header above it (every other migration in
  this tree opens with one; these four must not).
* A `-- no-transaction` file's `_sqlx_migrations` bookkeeping is **not atomic**
  with its DDL (`sqlx-postgres/src/migrate.rs:214`). Keep such files to index
  statements only, all `IF NOT EXISTS`, so a failure can never strand a column.

### Recovery from a failed `CREATE INDEX CONCURRENTLY`

There is no transaction, so a failure leaves an **INVALID index** behind and no
`_sqlx_migrations` row. Re-running the migration is safe (`IF NOT EXISTS`) but
will *not* rebuild the invalid index — an operator must drop it first:

```sql
SELECT c.relname FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
 WHERE NOT i.indisvalid;
```

```sql
DROP INDEX CONCURRENTLY <name>;   -- then re-run the migration
```

### Production window

On a live cluster, `CREATE INDEX CONCURRENTLY` waits for every transaction older
than itself in the same database. `bin/server.rs` sets the background job pool's
`statement_timeout` to **2 700 000 ms (45 minutes)** by default, so a single
long clustering job can stall 063–066 for that long. `SET LOCAL lock_timeout` in
a `-- no-transaction` file is *legal* but useless: outside a transaction block it
is a silent no-op that emits only `WARNING: SET LOCAL can only be used in
transaction blocks`, and it would not bound this wait even if it applied. Run
these during a quiet window, or after confirming
`SELECT max(now() - xact_start) FROM pg_stat_activity WHERE state <> 'idle'` is
small.

### `scripts/prepare-engine-integration-db.sh`

That script applies every `migrations/*.sql` with `psql -v ON_ERROR_STOP=1 -f`
in autocommit and never writes `_sqlx_migrations`. `-- no-transaction` is an
inert comment to psql and autocommit makes `CREATE INDEX CONCURRENTLY` legal, so
063–066 survive that path unchanged. The pre-existing hazard is unaffected: a
database prepared this way then fails every `sqlx::migrate!`.

## Tombstones

Tables that exist in the field but have no owning code. Scheduled for an
explicit `DROP TABLE IF EXISTS` inside the reserved 060–090 range — not dropped
opportunistically, because on the databases where they exist they hold key
material.

- **`ownership`** — DROPPED by migration **084** (PR-22). The pre-tenancy ACL
  table: one row per node, naming an agent and a coarse partition. Migration 071
  demoted it to a write-through shim, PR-14 deleted its whole API surface, and
  084 removed the relation, its view, its two triggers and 071's definer body.
  Listed here so a `DROP TABLE ownership` in a later migration is recognised as a
  duplicate rather than written afresh. `tenancy_transcription_log` (062)
  survives and is the only record of what the dropped rows declared;
  `docs/runbooks/084-undo.sql` is honest about what that does and does not
  recover.

- **`embedding_shares`**, **`re_encryption_keys`** — created by
  `epigraph-enterprise/migrations/001_initial_schema.sql`, never created by any
  public migration (060 deliberately skips both). Their repositories
  (`EmbeddingShareRepository`, `ReEncryptionKeyRepository`) and the MPC/PRE code
  paths that used them were deleted in PR-01 of the tenancy series. On an
  enterprise-lineage database both survive with `ON DELETE CASCADE` FKs to
  `groups` and zero readers; PR-21's corpus-wide seal verification must not
  mistake the MPC share material for live ciphertext.

## Provisioning lineage

Migration `060_group_tenancy_tables.sql` opens with a **drift guard**: it
`RAISE`s if any of seven group-tenancy tables already exists in a shape it did
not create (`pattern_templates`, the eighth, is identical in both lineages and
carries no sentinel). This is deliberate. Seven of its eight tables also exist in the
`epigraph-enterprise` schema with different columns, CHECK constraints and
`ON DELETE` actions, and `CREATE TABLE IF NOT EXISTS` is silent about that — the
migration would report success while applying none of its guarantees. If you hit
that error, reconcile the tables to the 060 shape by hand and re-run; do not
hand-insert a `_sqlx_migrations` row.

### Why 091 and not 060

`alternative_of_uniq_ignores_retracted` was written as `060` and merged to
`main` in #411 while this table still ended at "039+: public next" — nothing
recorded that #408 had already claimed `060`. Git does not catch it: the two
files have different names, so they merge cleanly and the collision only
appears when sqlx sees version 60 already applied under a different checksum
and panics the api binary on startup.

It was renumbered to `091` rather than renumbering #408's 21 migrations,
because it was applied to **no** database at the time (prod `_sqlx_migrations`
max was 59) and because #408 reserved the range first. That window existed only
because #411 had not yet been deployed; had it shipped first, moving it would
itself have been the panic scenario and #408 would have had to shift instead.

**The lesson for this table:** a reservation that lives only on an unmerged
branch protects nothing. Record the range here, on `main`, when the branch is
opened — not when it lands.

### The epigraph-internal overlap

`epigraph-internal` allocated `060`–`112` (110 migration files, `060_prov_o_agent_typing`
onward) long before the tenancy series reserved `060`–`090`, so the two ranges
overlap outright. This is recorded rather than fixed, because internal no
longer shares prod's `_sqlx_migrations`:

```
prod `epigraph` DB, max applied version            : 59   (2026-09-02)
prod rows matching internal migration descriptions : 0
```

Verify both before assuming it still holds. If a database is ever found that
ran internal *and* is targeted by public migrations, `060`–`112` is a minefield
there and public must allocate above `112` for that database.

**The 092–099 tenancy block sits inside internal's 060–112, and that is a known
consequence of the reservation, not an oversight.** It rests on exactly the
measurement above and on nothing else. **The measurement was NOT re-run when 092
was claimed on 2026-09-16** — this batch is confined to a throwaway database and
has no read of any deployed cluster — so the two numbers quoted in the block
above are still the 2026-09-02 ones. Re-run them before the first deploy that
carries a migration in this block; if a database is found that ran internal, the
whole `092`–`099` reservation is void for that database and the rule in the
paragraph above applies instead.

Note also that `crates/epigraph-api/src/migrate.rs::embedded_migrator` sets
`migrator.set_ignore_missing(true)`, so a *gap* is tolerated but a *checksum
mismatch* is not. Prod's missing version 35 is the benign case: there is no
public `035_*.sql` at all, 035 belongs to internal, and prod's 036/037/038
descriptions match the public filenames.

Since issue #492 the flag no longer hides a database that is AHEAD of the
binary: `run_migrations` refuses, before applying anything, when
`_sqlx_migrations` holds a successful version above the binary's highest
embedded migration, unless `--allow-db-ahead` / `EPIGRAPH_MIGRATE_ALLOW_DB_AHEAD=1`
opts in to a rollback. A gap BELOW the head (the 035 case) is still tolerated.
A database that ever ran internal's `060`–`112` above public's head therefore
now trips that refusal — deliberately; see the paragraph above.

## Migration Order

Migrations must be applied in numerical order:

1. **001_create_extensions.sql** - Enable pgvector and uuid-ossp extensions
2. **002_create_agents.sql** - Create agents table (cryptographic identities)
3. **003_create_claims.sql** - Create claims table (epistemic assertions)
4. **004_create_evidence.sql** - Create evidence table (supporting materials)
5. **005_create_reasoning_traces.sql** - Create reasoning traces and DAG structure
6. **006_create_relationships.sql** - Add circular FKs and LPG edges table
7. **007_create_indexes.sql** - Create performance indexes (HNSW, composite, partial)

## Schema Overview

### Core Tables

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `agents` | Cryptographic identities | `id`, `public_key` (32 bytes Ed25519) |
| `claims` | Epistemic assertions | `id`, `content`, `truth_value` [0.0, 1.0], `embedding` vector(1536) |
| `evidence` | Supporting materials | `id`, `content_hash`, `evidence_type`, `signature` (64 bytes) |
| `reasoning_traces` | Reasoning provenance | `id`, `claim_id`, `reasoning_type`, `confidence` [0.0, 1.0] |
| `trace_parents` | DAG edges (reasoning dependencies) | `trace_id`, `parent_id` |
| `edges` | LPG-style relationships | `source_id`, `target_id`, `relationship` |

### Label Property Graph (LPG) Features

All core tables include:
- **labels** (`TEXT[]`) - Categorization tags (e.g., `['verified', 'scientific']`)
- **properties** (`JSONB`) - Flexible key-value metadata

### Key Design Decisions

#### 1. UUID Primary Keys
- Matches Rust `Uuid` type in `epigraph-core`
- Uses `gen_random_uuid()` from uuid-ossp extension
- Enables distributed ID generation without coordination

#### 2. Bounded Truth Values
- `truth_value DOUBLE PRECISION CHECK (>= 0.0 AND <= 1.0)`
- Matches `TruthValue` type in `crates/epigraph-core/src/truth.rs`
- 0.0 = definitely false, 0.5 = uncertain, 1.0 = definitely true

#### 3. Cryptographic Integrity
- `content_hash` BYTEA(32) - BLAKE3 hashes
- `public_key` BYTEA(32) - Ed25519 public keys
- `signature` BYTEA(64) - Ed25519 signatures
- CHECK constraints ensure correct byte lengths

#### 4. Vector Embeddings
- `embedding vector(1536)` - OpenAI text-embedding-3-small
- HNSW index for fast approximate nearest neighbor search
- Enables semantic search with cosine similarity

#### 5. DAG Structure for Reasoning
- `trace_parents` junction table represents reasoning dependencies
- Prevents circular reasoning (cycles detected at application layer)
- Enables lineage queries via recursive CTEs

#### 6. Circular FK Resolution
- `claims.trace_id` FK added in migration 006 (after both tables exist)
- Allows claims and traces to reference each other
- Uses `ON DELETE SET NULL` to prevent cascade issues

#### 7. LPG Edges Table
- Generic `edges` table for flexible graph relationships
- Complements fixed schema FKs
- Supports typed, property-decorated edges between any entities
- Example: claim "supports" claim, agent "endorses" claim

## Index Strategy

### Vector Similarity
- **HNSW** index on `claims.embedding` (fast for < 1M vectors)
- For larger datasets, consider migrating to IVFFlat with `lists = sqrt(num_rows)`

### GIN Indexes
- All `labels` columns (array containment queries)
- All `properties` columns (JSONB key/value queries)

### B-tree Indexes
- Primary keys (automatic)
- Foreign keys (forward and reverse lookups)
- `truth_value` (filtering and sorting)
- Composite indexes for common query patterns

### Partial Indexes
- High-truth claims (`truth_value >= 0.7`) for verified queries
- Low-truth claims (`truth_value <= 0.3`) for disputed queries
- Non-null embeddings for semantic search

## Running Migrations

### Using sqlx (Rust)

```bash
# Set DATABASE_URL in .env
export DATABASE_URL="postgres://user:pass@localhost:5432/epigraph"

# Run migrations
sqlx migrate run

# Revert last migration
sqlx migrate revert
```

### Using psql

```bash
# Apply all migrations in order
for file in migrations/*.sql; do
  psql $DATABASE_URL -f $file
done
```

## Schema Validation

### Critical Invariants

The following invariants MUST be maintained:

1. **Truth values bounded**: `0.0 <= truth_value <= 1.0`
2. **No cycles in reasoning DAG**: Application layer must validate before insert
3. **Hash lengths correct**: BLAKE3 = 32 bytes, Ed25519 keys = 32 bytes, Ed25519 sigs = 64 bytes
4. **Signatures require signers**: `signature IS NOT NULL` implies `signer_id IS NOT NULL`
5. **No self-referencing traces**: `trace_id != parent_id` in `trace_parents`

### Test Queries

```sql
-- Verify no truth values out of bounds
SELECT COUNT(*) FROM claims WHERE truth_value < 0.0 OR truth_value > 1.0;
-- Should return 0

-- Verify all signed evidence has a signer
SELECT COUNT(*) FROM evidence WHERE signature IS NOT NULL AND signer_id IS NULL;
-- Should return 0

-- Verify no self-referencing traces
SELECT COUNT(*) FROM trace_parents WHERE trace_id = parent_id;
-- Should return 0

-- Verify hash lengths
SELECT COUNT(*) FROM claims WHERE octet_length(content_hash) != 32;
SELECT COUNT(*) FROM evidence WHERE octet_length(content_hash) != 32;
-- Both should return 0
```

## Performance Monitoring

```sql
-- Index usage statistics
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan ASC;

-- Table sizes
SELECT
    tablename,
    pg_size_pretty(pg_total_relation_size('public.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size('public.'||tablename) DESC;

-- Vector index performance (claims)
EXPLAIN ANALYZE
SELECT id, statement, truth_value
FROM claims
WHERE embedding IS NOT NULL
ORDER BY embedding <=> '[0.1, 0.2, ...]'::vector
LIMIT 10;
```

## Future Considerations

### Partitioning
For very large datasets (> 100M claims), consider partitioning:
- `claims` by `created_at` (monthly or yearly)
- `evidence` by `claim_id` hash
- `edges` by `source_type`

### Archival
Low-activity claims can be archived to cold storage:
- Move claims with `truth_value < 0.1` and no recent updates
- Maintain lineage in archived state

### Replication
For high availability:
- PostgreSQL logical replication for read replicas
- pgvector indexes rebuild automatically on replicas

## References

- [pgvector Documentation](https://github.com/pgvector/pgvector)
- [HNSW Algorithm](https://arxiv.org/abs/1603.09320)
- [PostgreSQL GIN Indexes](https://www.postgresql.org/docs/current/gin.html)
- [EpiGraph Implementation Plan](/home/user/EpiGraphV2/IMPLEMENTATION_PLAN.md)
- [TruthValue Type](/home/user/EpiGraphV2/crates/epigraph-core/src/truth.rs)
