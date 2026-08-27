# EpiGraph Multi-User Tenancy — Implementation Plan (FINAL)

> **MIGRATION NUMBERING IN THIS DOCUMENT IS SUPERSEDED. Do not allocate from it.**
> Both number columns in §3.1 are pre-shift. PR-04's index migration could not be
> one file (sqlx sends a whole migration as one simple query, and `CREATE INDEX
> CONCURRENTLY` inside the resulting implicit transaction raises 25001), so it
> became four, consuming three numbers more than §3.1 allocated. Everything from
> the plan's printed 064 onward moved **+4**. The authoritative table — actual
> number, PR, contents, for every remaining migration through PR-22 — is the
> "post-shift numbers, pinned" table in `migrations/README.md`. Read §3.1 for
> *contents* and `migrations/README.md` for *numbers*. Nothing else in this
> document is superseded.

**Status:** ready for engineering. Every number, path, line reference and column name below was re-verified against `main` @ `3948445` (sqlx 0.8.6, migrations `001..059`) while writing this revision.
**Supersedes:** `DRAFT-PLAN.md` and `REVISED-PLAN.md`.
**Folds in:** the security critique (F1–F17) and the ops/migration critique (F1–F20), plus the earlier completeness pass. Findings that survived verification are adopted in the body; findings that did not are answered in §11.

**What changed from the previous revision, at a glance.**

1. **The FORCE-RLS / GUC contradiction is resolved** (sec F1). The previous revision shipped a deliberately transaction-free hot path *and* `FORCE ROW LEVEL SECURITY` over the tables that hot path reads. On a pooled statement with no session GUCs the policy reduces to `bypass() OR visibility='public'`, so every group-private row would have become invisible to its own owners the day PR-17 landed — silently, with no test in the suite able to see it. §0.5 picks a mechanism, §4.5 specifies it, §8.4 adds the missing *positive* test class.
2. **The protected-table set is generated, not hand-written** (sec F2). The eight-table list missed at least eight more claim-keyed tables, verified below. A registry + build-failing coverage test replaces the literal list.
3. **`seal` now actually seals** (sec F3). A named TCB column list; `claim_versions.content`, `evidence.raw_content`, `evidence.embedding` and the plaintext extractions are encrypted-or-deleted in the same transaction; the test is a corpus-wide nonce grep, not per-column assertions.
4. **One role name.** The previous revision created `epigraph_app` and then told ops to point `DATABASE_URL` at `epigraph_api` (sec F15). Every occurrence is now `epigraph_app`, with a boot assertion on `current_user`.
5. **Roles are created early and guarded** (ops F3/F4), so CI's eight `#[sqlx::test]` packages do not collide on `CREATE ROLE`, and migration 070's `pg_has_role` cannot raise `42704`.
6. **The job/CLI/script fleet gets a maintenance DSN before FORCE lands** (ops F5/F6), as its own PR (PR-15). Without it the privatization job cannot write and fourteen CLI binaries silently no-op.
7. **Thirteen production `INSERT INTO claims` statements, not twelve** (ops F1) — `ClaimRepository::consolidate` at `claim.rs:4653` was missed, and it is a `sqlx::query_scalar!`, so the `cargo sqlx prepare` list was short by one.
8. **Migration range is `060..080`** (21 migrations) and is **reserved in `migrations/README.md` by PR-01** (ops F2). **22 PRs.**

---

## 0. Resolved disagreements

### 0.1 The four locked decisions — settled, not open

These are inputs. Every section below is written to satisfy them. They are not re-litigated anywhere in this document, and §10 does not list them.

**D1 — Ownership is REQUIRED; `public` must be explicitly declared.**
The kernel today treats the absence of an `ownership` row as public. Verified at `crates/epigraph-db/src/access_control.rs:58-69`:

```rust
let ownership: Option<(String, Uuid, Option<String>)> = sqlx::query_as(
    "SELECT partition_type, owner_id, encryption_key_id FROM ownership WHERE node_id = $1",
).bind(node_id).fetch_optional(pool).await
.unwrap_or(None);                                  // :64  — ANY DB ERROR → None
let (partition, owner_id, encryption_key_id) = match ownership {
    Some(row) => row,
    None => return ContentAccess::Full,            // :68  — "No ownership → public"
};
```

That is forbidden from here on. Every node carries an explicit visibility/ownership declaration. Nothing is public by absence, by omission, or by default-on-error. Enforcement is at the **database** layer — `NOT NULL` + `CHECK` + **no `DEFAULT`** + a `BEFORE INSERT` trigger that `RAISE`s — so no write path can bypass it.

**D2 — Legacy backfill sets explicit `public`, owner derived from `claims.agent_id`.**
Pre-existing rows are backfilled to explicit `public`; the owner is the author's personal group. Those rows were already world-readable, so declaring it is a no-op rather than a new disclosure.

**D3 — `public` means ANY AUTHENTICATED AGENT. Anonymous callers get NOTHING.**
A request with `AuthContext.agent_id == None` receives zero claim content. There is no anonymous read path, so there is no `Viewer::Anonymous`, no anonymous ANN fast path, and no partial `WHERE visibility='public'` index justified by one.

**D4 — There must be an ADMIN SURFACE to take a subgraph private / enable subgraph encryption on it.**
The corpus starts public (D2) and admins selectively privatize regions of it. First-class feature: its own schema (`privatization_plans`, `privatization_plan_items`, `privatization_audit`, `instance_admins`), job handler, CLI, and PRs (PR-18, PR-21).

### 0.2 The three invariants, extracted as machine-checked predicates

The security critique's closing process note is correct and is adopted as a deliverable: of its seventeen findings, eight were **internal contradictions** — the document asserted a property in one section and defeated it in another. Prose review does not catch that at this size. So D1, D3 and D4 each become a test that reads the migration set and the route table, not a sentence:

```rust
// crates/epigraph-db/tests/locked_decisions.rs   (NEW — lands in PR-04, grows each PR)
//
// D1: no tier-A tenancy column has a DEFAULT or is NULLable, after migration 070.
// D1: every table in the generated protected set has BOTH columns NOT NULL
//     or an explicit row in `tenancy_exempt`.
// D3: the set of routes reachable with no Authorization header, over BOTH
//     create_router variants, equals ANONYMOUS_ALLOWLIST exactly.
// D3: `Viewer` has no infallible constructor (source assertion + no_anonymous_viewer.rs).
// D4: every table with `visibility` has an RLS policy for each of
//     SELECT/INSERT/UPDATE/DELETE, or a recorded exemption, enumerated from
//     pg_policy.polcmd — never from the migration text.
```

Each PR that touches a locked decision must extend this file. A PR that changes a policy, a route split, or a tenancy column and does not touch `locked_decisions.rs` is rejected in review.

### 0.3 Consequences that ripple, stated once

| Locked decision | What it invalidates | Where the replacement lives |
|---|---|---|
| D1 | permanent `DEFAULT 'public'` / `DEFAULT <world>`; inheritance keyed on "still equals the world default"; ungated `DROP TABLE ownership` | §3/070, §3/066, §7 PR-16, §7 PR-22 |
| D2 | "secure-by-default" as an open choice; the world-group-owns-public-rows pairing rule | §9.3, §3/061, §4.4 |
| D3 | `Viewer::Anonymous`; `idx_claims_embedding_hnsw_public`; `optional_bearer_auth_middleware` on 109 routes; the RAG public-access guarantee | §2.5, §3/062, §4.3, §4.7, §6.2, §8 |
| D4 | `PATCH /claims/:id/visibility` as the whole surface; a propagation list that misses `evidence`; a cross-group edge `RAISE` as the only answer | §3/076–079, §6.5, §7 PR-18/PR-21 |

### 0.4 Corrections to the judges and to the previous revision, retained

- **The security judge's "tenth live 500" is wrong.** `PatternTemplateRepository` *is* imported and called at `crates/epigraph-api/src/routes/isomorphism.rs:11,138,143,253`, so deleting `repos/pattern_template.rs` **does** break `cargo check -p epigraph-api` — but `/api/v1/isomorphism/patterns` is **not registered** (`routes/mod.rs:775` is a bare comment). Compiled dead code, not a live 500. We create `pattern_templates` for build correctness only.
- **`GroupKeyEpochRepository::retire_epoch` already exists** at `crates/epigraph-db/src/repos/group_key_epoch.rs:82`. All three design proposals claimed it was missing.
- **`CREATE INDEX CONCURRENTLY` inside a migration is supported.** sqlx 0.8.6 honours a `-- no-transaction` first line (`sqlx-core-0.8.6/src/migrate/source.rs:127`), and `sqlx-macros-core-0.8.6/src/migrate.rs:73` propagates `no_tx` into the `migrate!()` literal — so the property holds for the embedded macro this repo actually uses, not merely the runtime path. **Verified separately: no migration in this repo has ever used it** (`head -1 migrations/*.sql | grep -c no-transaction` → 0), and `013`/`030` document a DBA pre-step precisely because the team believed it impossible. **Migration 062 is the first live exercise; it ships alone, early, against a throwaway DB first** (ops F8).
- **`repeat('\x00',32)::bytea` and `'\x'::bytea || repeat('00',32)::bytea` are both wrong.** Where 32 zero bytes are needed use `decode(repeat('00',32),'hex')`. This plan avoids it via a `kind`-conditional CHECK and `''::bytea` for keyless groups.
- **Verified counts, from the tree, superseding every critique figure that conflicts:** `repos/claim.rs` has **24** macro call sites (**23** `sqlx::query!` + **1** `sqlx::query_scalar!` + **0** `sqlx::query_as!`); `.sqlx/` holds **117** files; `crates/epigraph-cli/src/bin` has **26** binaries, **14** of which read `DATABASE_URL`; `routes/mod.rs` has **379** `.route(` registrations; the fail-open `if let Some(axum::Extension(ref auth)) = auth_ctx` idiom appears **39** times under `routes/`; `mcp_requester` is called at **7** sites in `epigraph-mcp/src/server.rs`; **8** crates contain `#[sqlx::test]` (696 occurrences) and **15** call sites do `sqlx::migrate!("../../migrations")` directly.

### 0.5 The mechanism decision the previous revision left contradictory (sec F1)

The previous revision stated, in §0.3, that `begin_as` "is used **only** by paths that need the RLS session context — the RLS backstop, not the hot path," and justified `Viewer`-over-`ScopedPool` on "no transaction, no round-trip tax, works on a pooled single statement." It then `FORCE`d RLS on `claims`, `evidence`, `edges`, the derived tables, `frames`, `contexts`, `perspectives`, `communities`, `recall_events`.

Those are mutually exclusive. `epigraph_session_groups()` reads `current_setting('epigraph.group_ids', true)` and `COALESCE`s to `ARRAY[]::uuid[]`. On a pooled statement with no `SET`, `claims_tenancy` reduces to `bypass() OR visibility = 'public'`; `recall_events_tenancy` reduces to `agent_id IS NOT DISTINCT FROM NULL`, which makes every NULL-`agent_id` recall event readable by every session; and both `privatization_audit_admin_only` and `instance_admins_self_or_admin` evaluate `epigraph_is_instance_admin(NULL)` → false, so the D4 surface is unreadable through the app.

**Decision: the GUCs are set at connection checkout, in one round trip, and the boot sequence proves the connection is not behind a transaction pooler.**

```rust
// crates/epigraph-db/src/pool.rs
impl ScopedPool {
    /// PRIMARY mechanism. Acquires a connection and stamps the session GUCs from
    /// THIS viewer, in ONE statement. No transaction required, so a single
    /// pooled SELECT keeps working exactly as §4.3 describes.
    pub async fn acquire_as(&self, v: &Viewer) -> Result<ScopedConn<'_>, DbError>;

    /// Transactional variant, for writes and for anything that must be atomic.
    /// Issues the identical set_config triple with is_local = true.
    pub async fn begin_as(&self, v: &Viewer) -> Result<ScopedTx<'_>, DbError>;

    pub fn unscoped_for_maintenance(&self, r: SystemReason)
        -> Result<(MaintenanceConn<'_>, MaintenanceLease), DbError>;
}
```

Both paths emit the same single statement, which is what makes qual/GUC coherence (§4.5) testable:

```sql
SELECT set_config('epigraph.group_ids',          $1, $local),
       set_config('epigraph.writable_group_ids', $2, $local),
       set_config('epigraph.principal_id',       $3, $local);
```

Three properties make this safe, and each is a test, not a promise:

1. **Release scrubs.** The pool's `after_release` hook re-runs the triple with three empty strings and `is_local = false`. If the scrub fails the connection is **closed**, never returned. A leaked group set on a recycled connection is the one failure mode that would be a cross-tenant read, so it fails closed by construction.
2. **A transaction pooler in front would break the session-scoped form.** `AppState::with_db` runs a boot probe: acquire a connection, `set_config('epigraph.probe','1',false)`, `SELECT current_setting('epigraph.probe',true)` **as a second statement on the same handle** — must be `'1'`; then release, acquire again, and assert the value is empty. If the first check fails, the deployment is behind a transaction-mode pooler and the process **refuses to serve** with an explicit message telling the operator to set `EPIGRAPH_SESSION_GUC_MODE=transaction`, which switches every read to `begin_as`.
3. **`EPIGRAPH_SESSION_GUC_MODE=transaction` is a supported, costed fallback**, not a hypothetical: every read runs inside `begin_as`, at a measured cost of two extra round trips (BEGIN pipelined with the `set_config` triple, then COMMIT). §9.4's W10 gate records the delta under both modes so the choice is made on numbers.

**And the missing test class is added.** §8.4's suite is written entirely as *"assert a stranger CANNOT read"*, so a viewer that over-restricts passes every case. Every one of the 17 `claim.rs` read functions in §4.11 gains a **positive** assertion under `FORCE`: *a `Scoped` viewer retrieves its own group-private rows, at the expected cardinality.* That assertion, and only that assertion, would have failed on the previous revision's design.

### 0.6 The other original disagreements — resolutions retained

**FORCE RLS: mandatory, but terminal and gated.** RLS ships as PR-17, after the in-query predicate is live and shadow-verified, behind role separation, a boot-time canary and the §0.5 probe, with a one-statement kill switch (`ALTER TABLE … NO FORCE ROW LEVEL SECURITY`). Nothing else catches a query reaching the database outside the repo layer. The measured opt-in adoption of the existing model is **7 of 85** MCP tools; there is no version of this system where "the last defence is optional" survives that number. D4 sharpens it: privatization whose enforcement is repo-layer-only is a promise, not a control, which is why PR-18 hard-depends on PR-17.

**`ScopedPool` vs `Viewer`: split the mechanism.** `Viewer` as a required parameter carries the *read predicate* and gives the compiler one call site per conversion. `ScopedPool` is the newtype that owns connection acquisition (§0.5) and the maintenance escape hatch, so the bypass has a structural anchor with an asserted call-site count.

**`PolicyGate` survives, rewritten, as a write-side gate only.** `WITH CHECK` cannot cleanly express role semantics (`reader` must not write) across ~15 heterogeneous mutation paths. Reads are never gated by it.

---

## 1. Scope & non-goals

### In scope — "multi-user" means

1. **Every principal resolves to exactly one namespace** (`agents.id`), on every transport. A request that resolves to no principal is refused, not served the public corpus (D3).
2. **Every claim, evidence row, edge, and claim-derived row carries an explicit tenancy declaration**, refused by the database if absent (D1), inherited from a determinate parent where one exists, never defaulted.
3. **Read authorization is a predicate inside the retrieval SQL**, evaluated before `LIMIT`, so a non-visible row is *absent* — not redacted, not counted, not ranked, not paginated over.
4. **Group-private knowledge is fully usable**: embedded, tsv-indexed, recallable by its members. Private must not mean invisible-to-its-owner. Under `FORCE`, this is a tested property, not an intention (§0.5).
5. **Cross-group sharing is deliberate**: an explicit visibility change, gated by membership in both source and target.
6. **Admins can privatize regions of a public corpus** with preview, batching, audit, and revert (D4).
7. **Enforcement is provable at runtime**, not asserted in a code review.

### Explicit non-goals (deferred, with the stage that would deliver them)

| Deferred | Why | Stage |
|---|---|---|
| Encryption at rest for the whole corpus | Encrypting `content` while `content_tsv` is `GENERATED ALWAYS` from the same plaintext (migration 050) and `embedding` is derived from it is theatre for a corpus-wide default. Selective, admin-driven sealing is *in* scope. | PR-19/PR-21 |
| Key rotation with forward secrecy | `routes/groups.rs:162` calls `create_epoch(..., 0, None)`, so `group_key_epochs.wrapped_key` is always NULL. Blocked on key custody (§5.4). **Note the revocation semantics in §6.7 before reading rotation as revocation.** | PR-20 |
| Cross-group proxy re-encryption | `crates/epigraph-crypto/src/proxy_re.rs` is not PRE: `derive_wrap_key` (:148-159) is one `blake3::derive_key` over one input, so the "public key" **is** the decryption secret; `generate_re_key` (:199-206) emits `len‖source_private‖target_public` in cleartext. **Deleted, not deferred.** | never |
| MPC / secret-shared embeddings | `SimulatedMpc::cosine_similarity` reconstructs both embeddings in the clear (`ENT/crates/epigraph-privacy/src/mpc/similarity.rs:44-65`, whose own doc says "This is NOT real MPC"). Repo deleted. | never |
| `epigraph-policy` rule engine | 13 `Condition` variants, none mentioning group/owner/partition/resource; `gate.rs:94` discards `_resource_id`; `engine.rs:222` fails open. | never |
| `epigraph-orchestrator` | 953 LOC behind 2 tests asserting two UUIDs differ. | never |
| Per-node ACLs | Requires a grants table. Group-of-one is the v1 answer. | v2 |
| Aggregate-cardinality privacy | `system_stats` reveals corpus-wide write activity; before/after differencing reveals the size of a privatized region. Accepted permanently; §10.2 ledger. | never |
| Standing (re-evaluated) privatization rules | A saved query re-evaluated at apply time is a write-path trigger, not an admin action. Schema slot reserved; v1 returns `501`. | v2 |
| Retroactive privatization as an automatic migration | ~1,198 orphan agents make an automatic sweep unsafe. It is an **operator action through the D4 surface**. | PR-18 |
| Server-performed re-seal on member removal | The server holds no key (§6.5.6), so it *cannot* re-encrypt. What ships is a `reseal_required_at` marker, a metric, and an operator-initiated reseal plan mode (§6.7). | PR-21 |

---

## 2. Target architecture

### 2.1 The tenancy primitive — definitively: `groups`

- Every agent has exactly one **personal group** (`groups.kind='personal'`), auto-created, membership of one, role `admin`. This is what `partition_type='private'` becomes and, under D2, what every legacy public claim's `owner_group_id` resolves to.
- The **world group** (`00000000-0000-0000-0000-000000000000`, `kind='world'`) exists as a schema shape constant only. **It is not the owner of public content** (§2.3), and after PR-16 nothing is permitted to own anything with it (§3/070 arm 4 stamps a dedicated *seed group*, not world — sec F14).
- Every **community** projects to a `groups` row with `kind='community'` and `id` preserved; every `community_members ⋈ perspectives.owner_agent_id` pair projects to a `group_memberships` row. The feature survives; its role as an access-control backend is retired.
- Real multi-party groups are `kind='team'`. **`team` is the only keyed kind**; `personal`, `community`, `world` and `seed` hold no key material (`public_key = ''::bytea`), which is what makes the 32-byte CHECK conditional on `kind`.

### 2.2 Tenancy lives on the row, not beside it

`ownership` is a separate table with **no FK on `node_id`** (its only FK is `owner_id → agents(id)`, `migrations/001:3800-3804`) and `PRIMARY KEY (node_id)`. Three reasons it cannot carry D1:

1. **It cannot be pushed into an ANN query.** Dense retrieval is `ORDER BY c.embedding <=> $1 LIMIT $3` inside a CTE (`repos/claim.rs:928-931`). A predicate requiring a join to `ownership` cannot be pushed under the HNSW `LIMIT`; filtering after it silently shrinks pages and leaks the count of hidden neighbours.
2. **It cannot be made mandatory without a race or a rewrite.** With no FK on `node_id`, requiring the side-row needs either a `DEFERRABLE INITIALLY DEFERRED` constraint trigger on `claims` (fires at COMMIT — the row exists undeclared for the whole transaction) or an inverse FK from `claims` to `ownership`, which is circular.
3. **It can be deleted out from under its node.** `DELETE FROM ownership WHERE node_id = $1` is a **one-statement declassification**, with no cascade, no audit, no error. `UPDATE claims SET visibility = NULL` fails on `NOT NULL`.

And the decisive empirical argument: **this codebase has produced the absence-means-public bug twice, independently, and both times from a side table.** Kernel: `access_control.rs:68`. Enterprise: `ENT/migrations/001_initial_schema.sql:501-527`, where `epigraph_is_visible_to_group()` ends `RETURN NOT found;` — no `claim_encryption` row ⇒ visible — and that is the *RLS policy body* at `:530`.

A side-table predicate is *shaped* like `EXISTS(...)`, and `NOT EXISTS` reads as "unrestricted". A column predicate is shaped like `= 'public'`, and no value of the column reads as "unrestricted".

```
<table>.owner_group_id  uuid                  NOT NULL REFERENCES groups(id)  -- NO DEFAULT after 070
<table>.visibility      character varying(16) NOT NULL CHECK IN ('public','group')  -- NO DEFAULT after 070
```

### 2.3 Two columns, two different meanings

| Column | Meaning | Question it answers |
|---|---|---|
| `owner_group_id uuid NOT NULL REFERENCES groups(id) ON DELETE RESTRICT` | **Steward.** Which group governs this node — may write it, change its visibility, seal it. Independent of who may *read* it. | *Whose node is this?* (D1, D4) |
| `visibility character varying(16) NOT NULL CHECK (visibility IN ('public','group'))` | **Reach.** `public` = every **authenticated** agent (D3). `group` = live members of `owner_group_id`. | *Who may read it?* |

A public claim is `('public', <author's personal group>)`, **not** `('public', world)`. The read predicate is unchanged — `(c.visibility = 'public' OR c.owner_group_id = ANY($V::uuid[]))` — and this buys three things:

1. **D4 becomes a one-column UPDATE.** Under world-pinning, D4 must *invent* an owner at privatization time and, for the legacy corpus, there is no candidate.
2. **The write-side `WITH CHECK` becomes meaningful.** `owner_group_id = ANY(epigraph_writable_groups())` gates *all* writes, public ones included, so `reader` means something on the public path.
3. **D1's word "ownership" is honoured literally.** Every node names an owner.

Per-node owner *agent* identity is not lost: `claims.agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE RESTRICT` (`migrations/001:3468`, column at `001:606`) already carries it and is what D2 derives the group from. `ownership.node_type` is authorization-inert today: `check_content_access` selects `WHERE node_id = $1` with no `node_type` predicate; `node_type` is read only by `OwnershipRepository::get_for_owner`'s display filter (`repos/ownership.rs:166`).

### 2.4 The protected set is GENERATED, not enumerated (sec F2)

The previous revision hand-wrote a tier-A list of `claims`, `evidence`, `edges`, eight derived tables, plus `frames`/`contexts`/`perspectives`/`communities`. **That list is materially incomplete.** Verified against the migration set at `3948445` — every table below carries `claim_id uuid NOT NULL` (or claim-derived free text) and appeared in *none* of the previous revision's 061, `epigraph_propagate_tenancy`, `visibility_lint.rs::PROTECTED`, or the FORCE list:

| Table | Defined at | What survived privatization under the previous revision |
|---|---|---|
| `challenges` | `001:528` | `claim_id uuid NOT NULL` (`:530`), `explanation text NOT NULL`. Served by `challenge::list_challenges` on **both** routers (`routes/mod.rs:547`, `:1037`) and by MCP `list_challenges` at `claims:read` (`scope_map.rs:47`) |
| `reasoning_traces` | `001:1383` | `claim_id` (`:1385`), `explanation text NOT NULL` (`:1387`), plus `labels text[]` and `properties jsonb` |
| `experiment_triples` | `001:950` | `claim_id` (`:952`), `predicate text NOT NULL` — a second triples table `triples` does not cover |
| `experiment_entity_mentions` | `001:936` | `claim_id` (`:938`) |
| `claim_clusters` | `001:546` | `claim_id` (`:548`), cluster geometry derived from private embeddings |
| `claim_cluster_membership` | `015:22` | `claim_id UUID NOT NULL` |
| `claim_neighborhood_membership` | `026:28` | `claim_id UUID NOT NULL REFERENCES claims(id)` |
| `claim_signature_revocations` | `008:30` | `claim_id UUID NOT NULL REFERENCES claims(id)` |
| `harvester_fragments` | `001:1090` | `content_text text NOT NULL`, `context_window` — **the source text the claim was extracted from**. No `claim_id`; reachable via `harvester_claim_provenance`, which *is* covered, so the join survives |

So under the previous revision, "take this subgraph private" left the reasoning, the challenges, the experiment triples, the cluster geometry, the signature-revocation record and the source fragments readable by any `claims:read` holder, and the preview's `side_effects.defends_against: ["every API and MCP caller, incl. authenticated non-members"]` was false as written.

**The fix is not a longer list.** It is two generators plus a registry, checked at build time:

```sql
-- Generator A: every table with a claim_id column.
SELECT c.table_schema, c.table_name
  FROM information_schema.columns c
 WHERE c.table_schema = 'public' AND c.column_name = 'claim_id';

-- Generator B: every table with an FK whose referenced table is `claims`
-- (catches claim_neighborhood_membership-style rows and any future shape).
SELECT DISTINCT tc.table_schema, tc.table_name
  FROM information_schema.table_constraints tc
  JOIN information_schema.constraint_column_usage ccu
    ON ccu.constraint_name = tc.constraint_name
 WHERE tc.constraint_type = 'FOREIGN KEY' AND ccu.table_name = 'claims';
```

Generators A and B do **not** find `harvester_fragments` (no `claim_id`, no FK to `claims`) or `claim_themes` (an aggregate keyed on nothing). That gap is why the registry exists rather than the generators alone:

```sql
-- migration 065
CREATE TABLE public.tenancy_exempt (
    table_name  text PRIMARY KEY,
    reason      text NOT NULL,
    residual    text NOT NULL,   -- what an attacker still learns, stated out loud
    reviewed_by text NOT NULL,
    reviewed_at timestamptz NOT NULL DEFAULT now()
);
```

`crates/epigraph-db/tests/tenancy_coverage.rs` runs both generators against a live `epigraph_db_repo_test`, unions the manually-registered additions (`harvester_fragments`), and **fails the build** unless every member either carries `(visibility, owner_group_id)` as `NOT NULL` or has a `tenancy_exempt` row. Adding a table to `tenancy_exempt` is a visible diff with a named reviewer.

The v1 exemptions, with their residuals:

| Exempt | Reason | Residual (ledgered, §10.2) |
|---|---|---|
| `claim_themes` (`001:573`) | No `claim_id` and no per-claim key — it is a corpus-wide aggregate with `centroid vector(1536)` and `claim_count`. Adding `(visibility, owner_group_id)` to it is meaningless: a theme spans tenants by construction. | A theme centroid computed over a mixed public/private set reveals topical adjacency. Control is PR-09's viewer-scoped clustering, not a column. |
| `agents` (`001:421`) | Identity must render authorship on a public claim. | Governed instead by `profile_visibility` over `properties`/`orcid`/`ror_id` (§2.5 tier B). |
| `jobs` (`001:1141`) | Queue metadata, no claim content. | **But it gains a policy anyway** (sec F5): an unprivileged `INSERT INTO jobs` is a privilege-escalation path into the privatization handler. See §3/073. |

### 2.5 Tiers, and the runtime-extensible node universe

`ownership_node_type_check` (`001:1324`) admits `claim, agent, evidence, perspective, community, context, frame`. `migrations/054_entity_types_registry.sql:26-82` establishes `entity_types` as "the one source of truth", seeded with **23** types, and `055:36-46` replaced the static `edges_entity_types_valid` CHECK with FKs to it. It is extensible at runtime via `POST /api/v1/admin/entity-types` (`routes/mod.rs:423-427`, `entity-types:write`).

- **Tier A — carries viewer-authored content; gets `(visibility, owner_group_id)`:** the generated set from §2.4 — `claims`, `evidence`, `edges`, `triples`, `entity_mentions`, `claim_versions`, `mass_functions`, `ds_combined_beliefs`, `ds_bayesian_divergence`, `claim_frames`, `harvester_claim_provenance`, **plus** `challenges`, `reasoning_traces`, `experiment_triples`, `experiment_entity_mentions`, `claim_clusters`, `claim_cluster_membership`, `claim_neighborhood_membership`, `claim_signature_revocations`, `harvester_fragments`, **plus** `frames`, `contexts`, `perspectives`, `communities`, **plus** `recall_events` (keyed on the querying agent, not on a claim).
- **Tier B — identity, exempt by explicit declaration:** `agents`, governed by `profile_visibility character varying(16) NOT NULL CHECK (profile_visibility IN ('public','group'))` over `properties`/`orcid`/`ror_id` **only**; `id`/`display_name`/`public_key`/`key_kind` always readable.
- **Tier C — no independent content, tenancy derived from a Tier-A parent at read time:** `trace`, `paper`, `analysis`, `activity`, `source_artifact`, `span`, `entity`, `task`, `event`, `experiment`, `experiment_result`, `workflow`, `node`, `synthesis`, `coalition`, `propaganda_technique`.

**`tenancy_tier` becomes a precondition, not a promise (sec F16).** The previous revision asserted three times that read paths "must treat `unclassified` as DENY" and implemented it nowhere — the predicate is a per-table literal, so a newly registered type has no column, no policy and no FORCE, and is therefore public *by absence of a column*, which is the exact defect §2.2 uses to reject the side-table design. Replaced by two enforceable rules:

1. `POST /api/v1/admin/entity-types` **refuses** `tenancy_tier='columns'` unless the named table already has both `NOT NULL` columns, a policy for each of SELECT/INSERT/UPDATE/DELETE, and `pg_class.relforcerowsecurity = true` — checked in the handler against `information_schema` / `pg_class` / `pg_policy`, not in a test.
2. Migration 065 adds `CHECK (tenancy_tier <> 'unclassified')` **after** the seed classifies all 23 core types, so `unclassified` becomes un-registerable at runtime and a type with no tenancy decision cannot be created at all.

The three "read paths must treat `unclassified` as DENY" sentences are **deleted**; they no longer describe anything.

### 2.6 Two orthogonal axes, permanently separated

| Axis | Column | Values | Question | Enforced by |
|---|---|---|---|---|
| **Visibility** | `visibility` + `owner_group_id` | `public` \| `group` | *Who may read this row?* | SQL predicate + RLS |
| **Confidentiality** | `claim_encryption` row present/absent | `Plaintext` \| `Sealed` | *Are the content bytes ciphertext on disk?* | client-side crypto, PR-19/PR-21 |

Confidentiality is **never** consulted for authorization. `privacy_tier='encrypted_content'` is **deleted** — it stored the real plaintext in `claims.content` (`routes/claims.rs:410-415` overrides content only for `fully_private`), which then fed `content_tsv`, the GIN index, and the BLAKE3 hash.

| | `Plaintext` | `Sealed` |
|---|---|---|
| **`public`** | the corpus's starting state (D2) | **forbidden** — trigger-enforced in **both** directions (§3/077) |
| **`group`** | **`restrict` mode** — the D4 default, ~95 % of privatizations | **`seal` mode** — D4's "enable subgraph encryption" |

`fully_private` is redefined: `claims.content = '[sealed:' || claims.id::text || ']'`, `content_hash = BLAKE3(ciphertext)`. This fixes a live bug: today `fully_private` forces the constant `"[private]"`, so `content_hash` is identical for every such claim and the app-layer duplicate guard 409s the second one — **an agent can create at most one fully-private claim, ever** (`routes/claims.rs:410-415` + `:453-470`).

### 2.7 The three dead extension points — definitive disposition

`grep -rn '\.encryption_provider\|\.policy_gate\|\.orchestration_backend' --include='*.rs' crates | grep -v state.rs` → zero results.

| Trait | Disposition | Reason |
|---|---|---|
| `EncryptionProvider` | **DELETED.** Reborn PR-19 as `ContentSealer` in `epigraph-privacy`, called client-side. | `encrypt(plaintext, key_id: &str)` has nowhere to put an entity id, which is why the enterprise adapter passes `Uuid::nil()` (`ENT/…/provider.rs:112-116,:150-151`) and discards the transplant/replay binding `encryptor.rs:12-17` exists to provide. `PrivacyEncryptionProvider` holds every group's master key in `Arc<RwLock<HashMap<String, GroupKeyEntry>>>` (`ENT/provider.rs:65`), seeded only by `register_key` (`:86`), which both production constructors call with an empty vec — every `encrypt()` returns `KeyNotFound` in the shipped binary. `state.rs:219-223` advertises a slot promising per-group AES-256-GCM, so every reader concludes it exists and is merely unconfigured. |
| `OrchestrationBackend` | **DELETED**, field + builder + `NoOp` + `epigraph-core/tests/extensions.rs` cases. | Orthogonal; kernel already has durable DB-backed workflows. |
| `PolicyGate` | **KEPT, REWRITTEN, ACTUALLY CALLED** as a write-side gate. New `crates/epigraph-authz` supplies the fail-closed default. | Signature gains a real `ResourceRef`; default becomes `GroupPolicyGate` (fail-closed); `NoOpPolicyGate` renamed `AllowAllPolicyGate` behind `#[cfg(any(test, feature = "insecure-allow-all"))]`. |

`LlmProvider` is genuinely wired and untouched. Also deleted in the same sweep: `routes/mpc.rs` (203 LOC, imports `epigraph_privacy` which is not a dependency), the `enterprise` cargo feature (`epigraph-api/Cargo.toml:18` declared empty, dep commented at `:52`, `cargo check --features enterprise` fails at `mpc.rs:8`), `repos/embedding_share.rs`, `repos/re_encryption_key.rs`, `epigraph-crypto/src/proxy_re.rs`.

### 2.8 Component table (end state)

| Component | Path | Role |
|---|---|---|
| `Viewer` | `crates/epigraph-db/src/visibility.rs` | Read authority. No `Default`, no `From<Option<Uuid>>`, no `From<&AuthContext>`. **Two shapes: `Scoped{principal, group_ids, writable}`, `Bypass{reason: SystemReason}`.** No `Anonymous` (D3). |
| `Viewer::predicate_fragment()` | same | Two `&'static str` fragments, emitted inline. `Scoped` orders `visibility = 'public'` first, syntactically matching the RLS policy's leading disjunct (§4.5). |
| `SystemReason` | same | Closed `#[non_exhaustive]` enum of legitimate bypass reasons. Ratchet is `SystemReason::ALL.len()` + a `match`, not a regex. |
| `MaintenanceLease` | same | Unforgeable token, minted only by `ScopedPool::unscoped_for_maintenance(reason)`. |
| `ScopedPool` | `crates/epigraph-db/src/pool.rs` | `acquire_as(&Viewer)`, `begin_as(&Viewer)`, `unscoped_for_maintenance(reason)`. Owns the GUC stamping and the release scrub (§0.5). Ratcheted. |
| `ViewerExtractor` | `crates/epigraph-api/src/middleware/bearer.rs` | The only way an HTTP handler obtains a `Viewer`. 401s with an **RFC 6750 `WWW-Authenticate` challenge** (ops F15). Runs before any body extractor. |
| `epigraph_session_groups/principal_id/writable_groups/bypass()` | migration 063 | `STABLE`, GUC-reading, RLS-only. |
| `epigraph_require_tenancy()` | migration 070 | `BEFORE INSERT` on every tier-A table. Validates, inherits from a determinate parent, or `RAISE`s. **Never defaults.** |
| `visibility_lint.rs` | `crates/epigraph-db/tests/` | Build failure if repo SQL reads a protected table without the predicate or an inline `-- VISIBILITY-EXEMPT:` marker. `PROTECTED` is **generated at test time** from §2.4's generators, not a literal. |
| `locked_decisions.rs` | `crates/epigraph-db/tests/` | D1/D3/D4 as machine-checked predicates (§0.2). |
| RLS policies + `FORCE` | migrations 073/075 | Backstop for anything reaching the DB outside the repo layer. Per-command coverage asserted from `pg_policy.polcmd`. |
| RLS canary | migration 074 + `state.rs` | One integer, checked at boot and every 60 s. Its own table. |
| `GroupPolicyGate` | `crates/epigraph-authz/` | Fail-closed write gate. Enforces `GroupRole::can_write()`. |
| `instance_admins` + `epigraph_is_instance_admin()` | migration 079 | The D4 authority. Empty at first. |
| `privatization_plans` / `_plan_items` / `_audit` | migrations 076/078 | The D4 surface's persisted, resumable, auditable object. |
| `epigraph-privacy` | kernel workspace, PR-19 | `encryptor.rs`, `tier.rs`, `group.rs`, `errors.rs`, `rewrap.rs`. ~350 LOC. |
| `epigraph-group` / `epigraph-privatize` / `epigraph-instance-admin` CLIs | `crates/epigraph-cli/src/bin/` | Key ceremony; frontier selection + seal/unseal; `grant`/`revoke`/`list`. |

---

## 3. Schema plan

Kernel is at `059`. **Twenty-one** new migrations, `060..080`.

### 3.0 Rules applied throughout

- **Version-space reservation is PR-01's first act** (ops F2). `migrations/README.md` §"Version range coordination with epigraph-internal" says, verbatim, that `epigraph-internal` runs `sqlx::migrate!()` against the **same `_sqlx_migrations` table** and that *"Picking a colliding version (checksum mismatch on a `_sqlx_migrations` row that's already applied) will panic the api binary on restart."* Its reservation table stops at 038 and records a live unreconciled divergence (035–037 applied to prod by internal; public renumbered them 036–038; *"prod `_sqlx_migrations` rows must be renumbered +1 on next public deploy"*). `run_migrations` sets `set_ignore_missing(true)` (`crates/epigraph-api/src/lib.rs:54`), so a collision is **not** caught by the missing-version check. Dropping 21 migrations into that unannounced is the single cheapest self-inflicted outage available. PR-01 updates the README to **reserve 060–085** — the 21 migrations named in §3.1 occupy 060–080, and the headroom covers PR-10's webhook-persistence migration (which takes the next unused number at the time it lands) plus any follow-up — and the W0 gate adds `SELECT version, description, checksum FROM _sqlx_migrations ORDER BY version DESC LIMIT 25` against prod.
- **Every DDL migration opens with `SET LOCAL lock_timeout = '3s';`** (ops F7). The risk is not lock *duration* — `DROP DEFAULT` is catalog-only — it is lock *acquisition*: one in-flight `recall`, `embed_backfill` scan or belief recompute delays the `ALTER`, and the queued `ACCESS EXCLUSIVE` then blocks every query behind it. On a `claims` table the README implies is several hundred thousand rows minimum (~169k known duplicates alone), that is a write outage of unbounded length.
- **Every DDL migration is idempotent**, so a `lock_timeout` abort is retried by re-running the same file. sqlx records **no** `_sqlx_migrations` row for a failed migration, and `migrations/README.md` is explicit that a failed migration *"panics the api binary on restart"* — so a non-idempotent partial failure is a permanent deploy outage, not a retry. Concretely: `ADD COLUMN IF NOT EXISTS`; `ADD CONSTRAINT` wrapped in a `pg_constraint` existence check (PostgreSQL has no `ADD CONSTRAINT IF NOT EXISTS`); `DROP TRIGGER IF EXISTS` before `CREATE TRIGGER`; `CREATE OR REPLACE FUNCTION`; `INSERT … ON CONFLICT DO NOTHING`.
- **Index migrations begin with `-- no-transaction`** and use `CREATE INDEX CONCURRENTLY IF NOT EXISTS`. **A `-- no-transaction` migration contains index statements and nothing else** (ops F8) — the previous revision's 068 mixed `ALTER TABLE ADD COLUMN` (no `IF NOT EXISTS`) with a trailing `CREATE INDEX CONCURRENTLY` in one no-transaction file, so an index failure re-ran the whole file and died on `42701 column already exists`. Split into 068 (transactional DDL) + 069 (no-transaction index).
- `ADD COLUMN … NOT NULL DEFAULT <constant>` is metadata-only on PG 11+ (`pg_attribute.attmissingval`) — no rewrite of `claims`.
- Constraints land `NOT VALID`, validated later under a guard, **one `VALIDATE` group per migration** (ops F16).
- **Roles are created in 060, guarded** (ops F3/F4), never in the RLS migration.
- **Every `DEFAULT` on a tenancy column is a transition artifact** with a named migration that removes it (070). A `DEFAULT 'public'` is "public by omission" relocated into `pg_attrdef`.
- **Three checked-in undo scripts.** `ls migrations/ | grep -c '\.down\.sql'` → **0**: every migration in this repo is a *simple* (non-reversible) sqlx migration, so `sqlx migrate revert` is unavailable for all of 060–080. §7's PRs are revertible in Rust and **not** in schema. The three genuine one-way doors ship with a checked-in undo and a named executing role: `docs/runbooks/070-undo.sql`, `docs/runbooks/075-undo.sql`, `docs/runbooks/080-undo.sql`.

### 3.1 Migration → PR map

> **AMENDED BY PR-02 (as shipped). The whole chain below 060 is shifted +1.**
>
> This map assigned NO migration to PR-02 and put `agents.key_kind` inside
> PR-04's tenancy-columns file. That is a sequencing error: PR-02's
> `AgentRepository::ensure_for_client` writes `key_kind = 'derived'` for the
> BLAKE3 placeholder public key it materialises for every keyless OAuth
> principal, and `routes/submit.rs` must filter `key_kind = 'ed25519'` on the
> signature path. Without the discriminator, PR-02's required negative test is
> unwritable and PR-04's later `DEFAULT 'ed25519'` would retroactively stamp
> every PR-02 placeholder agent as a real Ed25519 verifier.
>
> `migrations/061_agents_key_kind.sql` therefore ships in PR-02 and **is
> applied**. It is a one-way door. The **Shipped** column below is authoritative;
> `migrations/README.md` in the repo carries the same map. PR-04's
> tenancy-columns file keeps its own guarded `ADD COLUMN IF NOT EXISTS key_kind`
> statements — against a database that has 061 they no-op.
>
> The runbook files named elsewhere in this plan move with their migrations:
> `docs/runbooks/070-undo.sql` → `071-undo.sql`, `075-undo.sql` → `076-undo.sql`,
> `080-undo.sql` → `081-undo.sql`. PR-10's webhook-persistence migration moves
> 081 → 082. Everything stays inside PR-01's reserved 060–085 range.

| Shipped | (Planned) | PR | Contents |
|---|---|---|---|
| 060 | 060 | PR-01 | group tenancy tables (fixes the live 500) **+ the three NOLOGIN roles, guarded** |
| **061** | — | **PR-02** | **`agents.key_kind` discriminator (`ed25519` \| `derived`), `NOT VALID` + guarded `VALIDATE`, shape drift guard** |
| 062 | 061 | PR-04 | tenancy columns, stage 1 (idempotent, metadata-only, defaults present) — **must also CREATE `agents.profile_visibility`**, which §3.1 never scheduled although §2.4 describes it as existing |
| 063 | 062 | PR-04 | tenancy indexes (`-- no-transaction`; **no public HNSW**) |
| 064 | 063 | PR-04 | session/bypass functions |
| 065 | 064 | PR-05 | communities → groups; `encryption_key_id` de-overload |
| 066 | 065 | PR-05 | `entity_types.tenancy_tier` + `tenancy_exempt` registry |
| 067 | 066 | PR-12 | write-side stamping triggers (transition form, **statement-level**) |
| 068 | 067 | PR-12 | `ownership` compat shim |
| 069 | 068 | PR-13 | `edges.co_owner_group_id` — column + constraints + the 067(b)/(d) replacements |
| 070 | 069 | PR-13 | edge co-owner index (`-- no-transaction`) |
| 071 | 070 | PR-16 | **tenancy REQUIRED**: `DROP DEFAULT`, require-tenancy trigger, no-widening trigger, seed group |
| 072 | 071 | PR-16 | validate tenancy constraints — `claims` only |
| 073 | 072 | PR-16 | validate tenancy constraints — remaining tier-A tables |
| 074 | 073 | PR-17 | RLS policies (`ENABLE` only), per-command, incl. `agents` write policy, `jobs`, `security_events` |
| 075 | 074 | PR-17 | RLS canary table |
| 076 | 075 | PR-17 | `FORCE ROW LEVEL SECURITY` |
| 077 | 076 | PR-18 | privatization plans, items, closure + **content-lineage** hull |
| 078 | 077 | PR-18 | privatization guards — `(public,Sealed)` forbidden **in both directions**; keyed-group check |
| 079 | 078 | PR-18 | privatization audit (append-only, RLS) + `security_events` hardening |
| 080 | 079 | PR-18 | `instance_admins` |
| 081 | 080 | PR-22 | retire `ownership` |

### 060_group_tenancy_tables.sql

Creates the **seven** tables the live kernel repos already query, plus the three roles.

```sql
-- 060_group_tenancy_tables.sql
--
-- LIVE INCIDENT FIXED HERE: crates/epigraph-api/src/routes/claims.rs:841
-- (get_claim) and :1000 (list_claims) call
-- ClaimEncryptionRepository::get_by_claim_id_conn UNCONDITIONALLY, so on a stock
-- kernel database GET /api/v1/claims/:id and GET /claims return HTTP 500 for
-- EVERY claim. The kernel's own harness documents this at
-- crates/epigraph-api/tests/common/mod.rs:372-380 and works around it with an
-- FK-less, CHECK-less stand-in at :390-405.
--
-- NOT created here, deliberately: embedding_shares and re_encryption_keys.
-- Their repos are DELETED in the same PR.
SET LOCAL lock_timeout = '3s';

-- ===================================================================
-- ROLES FIRST, AND GUARDED.
--
-- Roles are CLUSTER-scoped; databases are not. CI runs epigraph-migrate against
-- `epigraph`, then EIGHT crates' worth of #[sqlx::test] (696 occurrences),
-- each building a template DB per test binary and applying all migrations, plus
-- 15 call sites doing sqlx::migrate!("../../migrations") directly. The second
-- one to reach an unguarded CREATE ROLE gets 42710. Verified counts, not
-- estimates.
--
-- Roles are also created HERE, not in the RLS migration, because migration
-- 070's seed arm calls pg_has_role(session_user, 'epigraph_seed', 'MEMBER'),
-- and pg_has_role on a NONEXISTENT role RAISES 42704 — it does not return
-- false. With role creation in the RLS migration, every insert reaching that
-- arm between PR-16 and PR-17 would abort with an opaque 42704 instead of the
-- designed 23502, and every CI run on the PR-16 branch would fail on the first
-- fixture insert.
--
-- On managed Postgres the migration role has neither SUPERUSER nor CREATEROLE.
-- The DO block therefore CATCHES insufficient_privilege and raises a NOTICE:
-- the roles are provisioned out of band by the deploy system, and the boot
-- assertion in AppState::with_db (PR-17) is what makes their absence fatal in
-- production rather than at migration time.
-- ===================================================================
DO $$
DECLARE r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['epigraph_app','epigraph_maintenance','epigraph_seed'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            BEGIN
                EXECUTE format('CREATE ROLE %I NOLOGIN', r);
            EXCEPTION
                WHEN insufficient_privilege THEN
                    RAISE NOTICE 'Cannot CREATE ROLE %: provision it out of band '
                                 'before deploying PR-17.', r;
                WHEN duplicate_object THEN NULL;   -- lost a race with a parallel test DB
            END;
        END IF;
    END LOOP;
END $$;
-- Every GRANT/REVOKE anywhere in 060..080 is likewise wrapped:
--   IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='epigraph_app') THEN ... END IF;
-- because an unguarded GRANT to a missing role hard-fails the migration.

CREATE TABLE IF NOT EXISTS public.groups (
    id                  uuid DEFAULT gen_random_uuid() NOT NULL,
    display_name        character varying(255),
    did_key             text NOT NULL,
    public_key          bytea NOT NULL,
    pre_public_key      bytea,
    -- KERNEL ADDITION: routes/groups.rs:168-172 logs creator_agent_id and
    -- persists it nowhere, leaving no basis to reconstruct a bootstrap admin.
    created_by_agent_id uuid,
    -- KERNEL ADDITION: only kind='team' carries key material.
    kind                character varying(16) DEFAULT 'team' NOT NULL,
    status              character varying(16) DEFAULT 'active' NOT NULL,
    properties          jsonb DEFAULT '{}'::jsonb NOT NULL,   -- holds kms_key_ref (§6.5.6)
    reseal_required_at  timestamptz,                          -- §6.7
    created_at          timestamp with time zone DEFAULT now() NOT NULL,
    updated_at          timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT groups_pkey PRIMARY KEY (id),
    CONSTRAINT groups_did_key_key UNIQUE (did_key),
    CONSTRAINT groups_kind_check   CHECK (kind IN ('world','personal','community','team','seed')),
    CONSTRAINT groups_status_check CHECK (status IN ('active','suspended','deprovisioned')),
    CONSTRAINT groups_public_key_shape CHECK (
        (kind = 'team' AND octet_length(public_key) = 32)
     OR (kind <> 'team' AND octet_length(public_key) = 0)),
    CONSTRAINT groups_created_by_fkey FOREIGN KEY (created_by_agent_id)
        REFERENCES public.agents(id) ON DELETE SET NULL
);
DROP TRIGGER IF EXISTS groups_updated_at ON public.groups;
CREATE TRIGGER groups_updated_at BEFORE UPDATE ON public.groups
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- Deprovisioning is a status transition, never a DELETE. Every FK below
-- CASCADEs from groups (inherited from the enterprise schema), so one
-- DELETE FROM groups would hard-delete every membership, epoch and ciphertext.
CREATE OR REPLACE FUNCTION public.epigraph_block_group_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF COALESCE(current_setting('epigraph.allow_group_delete', true), '') <> 'yes' THEN
        RAISE EXCEPTION 'refusing DELETE FROM groups (id=%). Set groups.status '
                        '= ''deprovisioned''. To force: SET LOCAL '
                        'epigraph.allow_group_delete = ''yes''.', OLD.id;
    END IF;
    RETURN OLD;
END $$;
DROP TRIGGER IF EXISTS groups_block_delete ON public.groups;
CREATE TRIGGER groups_block_delete BEFORE DELETE ON public.groups
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_block_group_delete();

CREATE TABLE IF NOT EXISTS public.group_key_epochs (
    id          uuid DEFAULT gen_random_uuid() NOT NULL,
    group_id    uuid NOT NULL,
    epoch       integer NOT NULL,
    wrapped_key bytea,
    status      character varying(20) DEFAULT 'active' NOT NULL,
    created_at  timestamp with time zone DEFAULT now() NOT NULL,
    retired_at  timestamp with time zone,
    CONSTRAINT group_key_epochs_pkey PRIMARY KEY (id),
    CONSTRAINT group_key_epochs_group_id_epoch_key UNIQUE (group_id, epoch),
    CONSTRAINT group_key_epochs_status_check CHECK (status IN ('active','rotating','retired')),
    -- epoch is i32 in the repos but u32 in every crypto/response type; e.g.
    -- crates/epigraph-crypto/src/epoch.rs:10-15 does epoch.to_le_bytes() on u32.
    CONSTRAINT group_key_epochs_epoch_nonneg CHECK (epoch >= 0),
    CONSTRAINT group_key_epochs_group_id_fkey FOREIGN KEY (group_id)
        REFERENCES public.groups(id) ON DELETE CASCADE
);
-- Nothing enforced at-most-one active epoch, and create_epoch
-- (repos/group_key_epoch.rs:36-47) never retires its predecessor;
-- get_active_epoch masks duplicates with ORDER BY epoch DESC LIMIT 1.
CREATE UNIQUE INDEX IF NOT EXISTS group_key_epochs_one_active
    ON public.group_key_epochs (group_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_group_key_epochs_group_status
    ON public.group_key_epochs (group_id, status);

CREATE TABLE IF NOT EXISTS public.group_memberships (
    id                uuid DEFAULT gen_random_uuid() NOT NULL,
    group_id          uuid NOT NULL,
    agent_id          uuid NOT NULL,
    -- repos/group_membership.rs:14 binds Vec<u8>, not Option<Vec<u8>>.
    wrapped_key_share bytea NOT NULL,
    epoch             integer NOT NULL,
    -- ONE role vocabulary. Today there are FOUR: the enterprise CHECK
    -- (admin|writer|reader), the kernel route's valid_roles at
    -- routes/groups.rs:212 (admin|member|reader) whose DEFAULT 'member'
    -- (groups.rs:64-66) VIOLATES the CHECK, and middleware/group_authz.rs:32
    -- which honours only admin|creator ('creator' is UNSTORABLE under this
    -- CHECK, so that branch is dead code). PR-02 fixes the route and middleware
    -- in the SAME RELEASE WINDOW as this CHECK; landing the CHECK alone
    -- converts today's missing-table 500 into a 23514 CHECK-violation 500.
    role              character varying(20) DEFAULT 'reader' NOT NULL,
    joined_at         timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at        timestamp with time zone,
    CONSTRAINT group_memberships_pkey PRIMARY KEY (id),
    CONSTRAINT group_memberships_group_id_agent_id_epoch_key UNIQUE (group_id, agent_id, epoch),
    CONSTRAINT group_memberships_role_check  CHECK (role IN ('admin','writer','reader')),
    CONSTRAINT group_memberships_epoch_nonneg CHECK (epoch >= 0),
    CONSTRAINT group_memberships_group_id_fkey FOREIGN KEY (group_id)
        REFERENCES public.groups(id) ON DELETE CASCADE,
    CONSTRAINT group_memberships_agent_id_fkey FOREIGN KEY (agent_id)
        REFERENCES public.agents(id) ON DELETE CASCADE
);
-- get_member_role (repos/group_membership.rs:130-141) has NO ORDER BY. Once
-- rotation inserts a second row per agent at epoch N+1 (which the UNIQUE above
-- permits) admin authorization becomes nondeterministic.
CREATE UNIQUE INDEX IF NOT EXISTS group_memberships_one_live
    ON public.group_memberships (group_id, agent_id) WHERE revoked_at IS NULL;
-- The hot path: "which live groups is this agent in?" — one index-only scan
-- per request in Viewer::resolve.
CREATE INDEX IF NOT EXISTS idx_group_memberships_agent_live
    ON public.group_memberships (agent_id, group_id, role) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_group_memberships_group ON public.group_memberships (group_id);

CREATE TABLE IF NOT EXISTS public.claim_encryption (
    claim_id           uuid NOT NULL,
    group_id           uuid NOT NULL,
    epoch              integer NOT NULL,
    privacy_tier       character varying(20) NOT NULL,
    encrypted_content  bytea NOT NULL,
    encrypted_labels   bytea,
    encrypted_properties bytea,          -- §6.5.6 TCB: claims.properties
    created_at         timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT claim_encryption_pkey PRIMARY KEY (claim_id),
    -- 'encrypted_content' is NOT accepted: it stored the PLAINTEXT in
    -- claims.content next to the ciphertext (routes/claims.rs:410-415),
    -- feeding content_tsv (migration 050, GENERATED ALWAYS + GIN) and the
    -- BLAKE3 content_hash.
    CONSTRAINT claim_encryption_privacy_tier_check CHECK (privacy_tier = 'fully_private'),
    CONSTRAINT claim_encryption_epoch_nonneg CHECK (epoch >= 0),
    CONSTRAINT claim_encryption_claim_id_fkey FOREIGN KEY (claim_id)
        REFERENCES public.claims(id) ON DELETE CASCADE,
    -- RESTRICT, not the enterprise CASCADE: ciphertext must not evaporate.
    CONSTRAINT claim_encryption_group_id_fkey FOREIGN KEY (group_id)
        REFERENCES public.groups(id) ON DELETE RESTRICT,
    CONSTRAINT claim_encryption_epoch_fkey FOREIGN KEY (group_id, epoch)
        REFERENCES public.group_key_epochs (group_id, epoch)
);
CREATE INDEX IF NOT EXISTS idx_claim_encryption_group ON public.claim_encryption (group_id);

-- The §6.5.6 seal TCB needs two more ciphertext homes. Created here so the
-- schema_contract test covers them from day one and PR-21 adds no DDL.
CREATE TABLE IF NOT EXISTS public.claim_version_encryption (
    claim_version_id  uuid PRIMARY KEY,
    claim_id          uuid NOT NULL REFERENCES public.claims(id) ON DELETE CASCADE,
    group_id          uuid NOT NULL REFERENCES public.groups(id) ON DELETE RESTRICT,
    epoch             integer NOT NULL CHECK (epoch >= 0),
    encrypted_content bytea NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.evidence_encryption (
    evidence_id          uuid PRIMARY KEY REFERENCES public.evidence(id) ON DELETE CASCADE,
    group_id             uuid NOT NULL REFERENCES public.groups(id) ON DELETE RESTRICT,
    epoch                integer NOT NULL CHECK (epoch >= 0),
    encrypted_content    bytea NOT NULL,
    encrypted_properties bytea,
    created_at           timestamptz NOT NULL DEFAULT now()
);
-- edge_encryption: identical shape (PK edge_id, encrypted_labels +
-- encrypted_properties), same RESTRICT correction. Zero callers today; created
-- so repos/edge_encryption.rs stops being a runtime landmine.

-- pattern_templates: MUST be created. PatternTemplateRepository has live callers
-- at crates/epigraph-api/src/routes/isomorphism.rs:11,138,143,253, so deleting
-- the repo fails `cargo check -p epigraph-api`. NOTE: the route is NOT
-- registered (routes/mod.rs:775 is a bare comment).
CREATE TABLE IF NOT EXISTS public.pattern_templates (
    id             uuid DEFAULT gen_random_uuid() NOT NULL,
    name           character varying(255) NOT NULL,
    category       character varying(50) NOT NULL,
    description    text,
    skeleton       jsonb NOT NULL,
    min_confidence double precision DEFAULT 0.7 NOT NULL,
    created_at     timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT pattern_templates_pkey PRIMARY KEY (id),
    CONSTRAINT pattern_templates_name_key UNIQUE (name)
);
```

> **`cargo sqlx prepare`:** not required. All seven original repos use runtime `sqlx::query` / `query_as`. **This is also the trap:** their schema drift is invisible to `SQLX_OFFLINE=true cargo check`. PR-01 therefore ships `crates/epigraph-db/tests/schema_contract.rs`, asserting every table exists with the exact expected column set, type and nullability from `information_schema.columns`. That test is the only guard.

### 061_tenancy_columns.sql — stage 1, metadata-only, idempotent

```sql
-- 061_tenancy_columns.sql — metadata-only. Does NOT rewrite claims.
-- Idempotent end to end, so a lock_timeout abort is retried by re-running the
-- file (sqlx records no row for a failed migration; a non-idempotent partial
-- failure is a permanent deploy outage — migrations/README.md).
SET LOCAL lock_timeout = '3s';

-- STAGE 1 OF TWO. The DEFAULTs below exist ONLY so this migration is
-- metadata-only on a populated claims table and so no in-flight writer breaks
-- between here and PR-16. Migration 070 DROPs every one of them.

-- The world group. Nil UUID so it is unmistakable in a psql dump. It is a SHAPE
-- CONSTANT and nothing more -- it is NOT the owner of public content (§2.3),
-- and after 070 nothing may own anything with it. It has no group_memberships
-- rows, by design. kind='world' => the conditional public_key CHECK accepts a
-- zero-length bytea. (Do NOT write repeat('\x00',32)::bytea.)
INSERT INTO public.groups (id, display_name, did_key, public_key, kind)
VALUES ('00000000-0000-0000-0000-000000000000'::uuid,
        'world', 'did:epigraph:world', ''::bytea, 'world')
ON CONFLICT (id) DO NOTHING;
INSERT INTO public.group_key_epochs (group_id, epoch, wrapped_key, status)
VALUES ('00000000-0000-0000-0000-000000000000'::uuid, 0, NULL, 'active')
ON CONFLICT (group_id, epoch) DO NOTHING;

-- The SEED group. Migration 070 arm 4 stamps THIS, never world, so that
-- §8.2 A4 (`count(*) FROM claims WHERE owner_group_id = world` must be 0) and
-- the deferred strong CHECK (owner_group_id <> world) are both achievable on a
-- database where the test suite has run. Rows created by the seed role are
-- greppable by owner_group_id.
INSERT INTO public.groups (id, display_name, did_key, public_key, kind)
VALUES ('00000000-0000-0000-0000-0000000000se'::uuid,   -- see note below
        'seed', 'did:epigraph:seed', ''::bytea, 'seed')
ON CONFLICT (id) DO NOTHING;
-- NOTE: the literal above is illustrative; the shipped migration uses
-- '00000000-0000-0000-0000-00000000dead'::uuid. Any fixed non-nil UUID works;
-- what matters is that it is NOT the world group and IS a real groups row with
-- kind='seed', so the FK and the pairing CHECK both hold.
INSERT INTO public.group_key_epochs (group_id, epoch, wrapped_key, status)
VALUES ('00000000-0000-0000-0000-00000000dead'::uuid, 0, NULL, 'active')
ON CONFLICT (group_id, epoch) DO NOTHING;

-- ===================================================================
-- Tier-A widening, driven from the GENERATED set (§2.4) rather than a hand
-- list. The array below is the generator's output at 3948445, pinned into the
-- migration so the migration is deterministic; tenancy_coverage.rs re-runs the
-- generator at test time and fails the build if the two ever diverge.
-- ===================================================================
DO $$
DECLARE t text;
        tier_a text[] := ARRAY[
          -- roots
          'claims','evidence','edges',
          -- claim-derived, from Generator A (information_schema: column_name='claim_id')
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance',
          -- MISSED BY THE PREVIOUS REVISION (sec F2), all verified:
          'challenges',                      -- 001:528, claim_id :530, explanation NOT NULL
          'reasoning_traces',                -- 001:1383, claim_id :1385, explanation :1387
          'experiment_triples',              -- 001:950,  claim_id :952,  predicate NOT NULL
          'experiment_entity_mentions',      -- 001:936,  claim_id :938
          'claim_clusters',                  -- 001:546,  claim_id :548
          'claim_cluster_membership',        -- 015:22
          'claim_neighborhood_membership',   -- 026:28, FK -> claims(id)
          'claim_signature_revocations',     -- 008:30, FK -> claims(id)
          -- Generator B misses this one: no claim_id, no FK. Registered by hand.
          'harvester_fragments',             -- 001:1090, content_text NOT NULL
          -- D1 roots the previous revision added; kept
          'frames','contexts','perspectives','communities',
          -- keyed on the QUERYING agent, not on a claim
          'recall_events'
        ];
BEGIN
    FOREACH t IN ARRAY tier_a LOOP
        EXECUTE format(
          'ALTER TABLE public.%I
             ADD COLUMN IF NOT EXISTS owner_group_id uuid NOT NULL
               DEFAULT ''00000000-0000-0000-0000-000000000000''::uuid,
             ADD COLUMN IF NOT EXISTS visibility character varying(16)
               NOT NULL DEFAULT ''public''', t);
        -- ADD CONSTRAINT has no IF NOT EXISTS; guard on the catalog.
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conname = t || '_visibility_check') THEN
            EXECUTE format(
              'ALTER TABLE public.%I ADD CONSTRAINT %I
                 CHECK (visibility IN (''public'',''group'')) NOT VALID',
              t, t || '_visibility_check');
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conname = t || '_owner_group_fkey') THEN
            EXECUTE format(
              'ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (owner_group_id)
                 REFERENCES public.groups(id) ON DELETE RESTRICT NOT VALID',
              t, t || '_owner_group_fkey');
        END IF;
        -- THE PAIRING INVARIANT. A 'group'-visible row owned by the world group
        -- is a BLACK HOLE: the world group has no group_memberships rows by
        -- design, so `owner_group_id = ANY(<viewer groups>)` can never match and
        -- NOBODY, including the author, can read it back. This is a TABLE CHECK,
        -- not only an RLS WITH CHECK arm: an RLS WITH CHECK is inert for the
        -- table owner until 075's FORCE, and inert entirely for the maintenance
        -- role.
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                        WHERE conname = t || '_group_needs_real_group') THEN
            EXECUTE format(
              'ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (
                  visibility <> ''group''
                  OR owner_group_id <> ''00000000-0000-0000-0000-000000000000''::uuid
               ) NOT VALID', t, t || '_group_needs_real_group');
        END IF;
    END LOOP;
END $$;

-- TIER B (identity): agents stay readable so authorship renders on a public
-- claim, but agents.properties holds full_name / orcid / affiliations / email
-- (documented at 001:~453). Declare the exemption out loud rather than by
-- omission; that is what makes it D1-compliant.
ALTER TABLE public.agents
    ADD COLUMN IF NOT EXISTS profile_visibility character varying(16)
        NOT NULL DEFAULT 'public';
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='agents_profile_visibility_check')
    THEN ALTER TABLE public.agents ADD CONSTRAINT agents_profile_visibility_check
             CHECK (profile_visibility IN ('public','group')) NOT VALID; END IF;
END $$;

-- agents gains a default write target and a key discriminator so a human OAuth
-- principal can exist without an Ed25519 keypair. agents.public_key is
-- bytea NOT NULL CHECK (octet_length = 32) at migrations/001:423,:440.
ALTER TABLE public.agents
    ADD COLUMN IF NOT EXISTS default_group_id uuid
        REFERENCES public.groups(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS key_kind character varying(16) NOT NULL DEFAULT 'ed25519';
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='agents_key_kind_check')
    THEN ALTER TABLE public.agents ADD CONSTRAINT agents_key_kind_check
             CHECK (key_kind IN ('ed25519','derived')); END IF;
END $$;
COMMENT ON COLUMN public.agents.key_kind IS
  '''derived'' means public_key is blake3::derive_key("epigraph-oauth-client", '
  'client_uuid) — a 32-byte placeholder satisfying the NOT NULL/length CHECK for '
  'a keyless OAuth principal. It is NOT a signature verifier: every signature '
  'path MUST filter key_kind = ''ed25519''.';

-- Resumable backfill progress. DEMOTED TO OBSERVABILITY: migration 071's guard
-- is LIVE COUNTS, not this table's boolean, because a boolean `complete` flag
-- is hand-flippable by an on-call trying to unblock a deploy at 2 a.m.
CREATE TABLE IF NOT EXISTS public.tenancy_backfill_progress (
    entity     text PRIMARY KEY,
    last_id    uuid,
    rows_done  bigint NOT NULL DEFAULT 0,
    complete   boolean NOT NULL DEFAULT false,
    updated_at timestamp with time zone NOT NULL DEFAULT now()
);
-- Seeded from the SAME tier_a array above, plus 'personal_groups','communities'.

-- The undeclared-write counter (ops F10). Migration 066's transition trigger
-- bumps this instead of silently inheriting, and §9.2's deploy gate requires it
-- FLAT FOR 24 HOURS before migration 070 runs.
CREATE TABLE IF NOT EXISTS public.tenancy_undeclared_writes (
    table_name text NOT NULL,
    day        date NOT NULL DEFAULT current_date,
    n          bigint NOT NULL DEFAULT 0,
    last_seen  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (table_name, day)
);

-- Transcription ledger. Migration 080 REFUSES to DROP TABLE ownership unless
-- every non-public ownership row has a row here.
CREATE TABLE IF NOT EXISTS public.tenancy_transcription_log (
    node_id        uuid PRIMARY KEY,
    node_type      text NOT NULL,
    from_partition text NOT NULL,
    to_visibility  text NOT NULL,
    to_group_id    uuid NOT NULL,
    transcribed_at timestamp with time zone NOT NULL DEFAULT now()
);
```

> **On not splitting 061 one-table-per-migration** (ops F7's second half). Rejected on the ops critique's *own* other finding: the version space is shared with `epigraph-internal` (ops F2), and burning 24 version numbers on metadata-only `ADD COLUMN`s to buy a finer retry granularity is a bad trade. The retry problem is solved instead by making the file **idempotent** — every statement above is `IF NOT EXISTS` or catalog-guarded — so a `lock_timeout` abort is retried by re-running one file, with no partial state. **Migration 070 is a different case and *is* split** (070/071/072), because its `VALIDATE CONSTRAINT`s are full table scans holding `SHARE UPDATE EXCLUSIVE` and must not be redone as a group.

### 062_tenancy_indexes.sql

```sql
-- no-transaction
--
-- sqlx-core 0.8.6 honours a leading `-- no-transaction` line
-- (src/migrate/source.rs:127) and sqlx-macros-core 0.8.6 propagates no_tx into
-- the migrate!() literal (src/migrate.rs:73), so CREATE INDEX CONCURRENTLY is
-- legal inside a migration. This supersedes the DBA-pre-step workaround at
-- migrations/013_code_review_hardening.sql:8-10 and
-- migrations/030_atom_embedding_partial_index.sql:11.
--
-- THIS FILE CONTAINS INDEX STATEMENTS AND NOTHING ELSE. A -- no-transaction
-- migration that also does ALTER TABLE is not re-runnable: a failure in the
-- index leaves the column behind, and the next boot re-runs the whole file and
-- dies on 42701.
--
-- WARNING: because there is no transaction, a failure here leaves an INVALID
-- index behind. Re-running is safe (IF NOT EXISTS), but an operator must DROP
-- INDEX the leftover first. Detect with:
--   SELECT relname FROM pg_class c JOIN pg_index i ON i.indexrelid=c.oid
--    WHERE NOT i.indisvalid;
--
-- ===================================================================
-- DELETED: idx_claims_embedding_hnsw_public.
--
-- The draft created a partial HNSW index WHERE visibility = 'public' and
-- justified it as "the anonymous/public ANN fast path". Under D3 that caller
-- cannot exist, and the index is not merely unjustified -- it is UNREACHABLE.
-- PostgreSQL proves index-predicate implication from rel->baserestrictinfo.
-- After D3 the only app-emitted qual on claims is
--     embedding IS NOT NULL AND is_current
--       AND (visibility = 'public' OR owner_group_id = ANY($V))
-- and `A OR B` does not imply `A`. The proof cannot fire for any Scoped viewer,
-- and Bypass emits no visibility qual at all. The index would be built,
-- maintained on every insert (2x HNSW insert per write, 2x disk on the largest
-- table, a build migrations/030 records at 5-15 min on 150k rows for a SMALLER
-- index) and never used.
--
-- If a partial ANN index is ever justified by measurement it is the COMPLEMENT
-- (visibility <> 'public') plus a two-leg UNION rewrite -- see "062b" below and
-- the §9.4 W10 gate. The existing idx_claims_embedding_hnsw
-- (migrations/001:2375, WHERE embedding IS NOT NULL) remains the sole ANN index
-- on claims. Under D4 the corpus starts public and admins privatize regions of
-- it, so the full index IS approximately the public index.
-- ===================================================================

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_claims_owner_group
    ON public.claims (owner_group_id) WHERE visibility <> 'public';
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_evidence_owner_group
    ON public.evidence (owner_group_id) WHERE visibility <> 'public';
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_edges_owner_group
    ON public.edges (owner_group_id) WHERE visibility <> 'public';
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_claims_group_current
    ON public.claims (owner_group_id, is_current) WHERE visibility = 'group';

-- Migration 071's guard counts world-owned claims. idx_claims_owner_group is
-- partial WHERE visibility <> 'public' and every world-owned row is public, so
-- that index is STRUCTURALLY UNUSABLE for the guard (ops F16). The guard
-- therefore does not live in a migration at all -- it is
-- `epigraph-tenancy-backfill verify`'s exit code -- and this narrow index
-- exists so `verify` is not a seq scan on every run.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_claims_world_owned
    ON public.claims (id)
 WHERE owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid;
```

All indexes above cover the **minority** partition, so their disk and insert cost scales with how much of the graph admins have actually privatized (D4), not with the whole corpus.

#### The only design in which a partial ANN index earns its place — deferred `062b`

Not the public one, the **complement**, paired with a two-leg rewrite of the dense CTE:

```sql
dense_pub AS (            -- LEG 1: literal qual, provably implies
    SELECT c.id, c.embedding <=> $1::vector AS d   -- idx_claims_embedding_hnsw
    FROM claims c
    WHERE c.embedding IS NOT NULL AND c.is_current AND c.visibility = 'public'
    ORDER BY c.embedding <=> $1::vector LIMIT $3
),
dense_grp AS (            -- LEG 2: over the SMALL partition
    SELECT c.id, c.embedding <=> $1::vector AS d
    FROM claims c
    WHERE c.embedding IS NOT NULL AND c.is_current
      AND c.visibility = 'group' AND c.owner_group_id = ANY($V::uuid[])
    ORDER BY c.embedding <=> $1::vector LIMIT $3
),
dense AS (SELECT id, d FROM (SELECT * FROM dense_pub UNION ALL SELECT * FROM dense_grp) u
          ORDER BY d LIMIT $3)
```

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_claims_embedding_hnsw_group
    ON public.claims USING hnsw (embedding public.vector_cosine_ops)
    WITH (m='16', ef_construction='64')
    WHERE embedding IS NOT NULL AND is_current AND visibility <> 'public';
```

Both legs are pre-filtered; recall is strictly better than post-filtering. **Do not ship this in 062.** It costs a query rewrite in `search_hybrid_scoped_since` (`repos/claim.rs:910`), `search_lexical_scoped_since` (`:1004`) and `search_by_embedding_scoped` (`:782`), and it is gated on the §9.4 W10 measurement.

### 063_session_functions.sql

Only the four GUC/bypass functions survive. `epigraph_visible()` is **not created** — it bought readability at the cost of an inlining assumption and one more `SECURITY DEFINER`-adjacent surface to `REVOKE`. `epigraph_groups_for()` is **not created** — it is folded into `Viewer::resolve`'s single query.

```sql
SET LOCAL lock_timeout = '3s';

-- RLS-only. STABLE (fixed within a statement, varies across transactions).
-- Wrapped in (SELECT ...) at the policy site so the planner emits an InitPlan
-- evaluated ONCE per statement rather than once per row. Without the wrapper a
-- seq scan over 1e6 claims parses the GUC 1e6 times.
CREATE OR REPLACE FUNCTION public.epigraph_session_groups() RETURNS uuid[]
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT COALESCE(
      (SELECT array_agg(x::uuid) FROM unnest(string_to_array(
          NULLIF(current_setting('epigraph.group_ids', true), ''), ',')) AS x),
      ARRAY[]::uuid[]);
$$;

-- The WRITABLE subset (group_memberships.role IN ('admin','writer')). Used by
-- every WITH CHECK. The draft used this function and DEFINED IT NOWHERE.
CREATE OR REPLACE FUNCTION public.epigraph_writable_groups() RETURNS uuid[]
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT COALESCE(
      (SELECT array_agg(x::uuid) FROM unnest(string_to_array(
          NULLIF(current_setting('epigraph.writable_group_ids', true), ''), ',')) AS x),
      ARRAY[]::uuid[]);
$$;

CREATE OR REPLACE FUNCTION public.epigraph_principal_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT NULLIF(current_setting('epigraph.principal_id', true), '')::uuid;
$$;

-- The maintenance escape hatch is ROLE MEMBERSHIP, not the BYPASSRLS attribute.
-- A compromised application connection cannot SET its way into it; revoking it
-- is one GRANT and it is visible in pg_auth_members.
--
-- session_user, NOT current_user: inside a SECURITY DEFINER frame current_user
-- resolves to the FUNCTION OWNER, which is exactly the escalation the security
-- review flagged. The EXISTS guard means this is safe to call before the roles
-- exist (managed Postgres, see 060).
CREATE OR REPLACE FUNCTION public.epigraph_bypass() RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT COALESCE(
      (SELECT pg_has_role(session_user, 'epigraph_maintenance', 'MEMBER')
        WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')),
      false);
$$;

-- THE current_user VARIANT (sec F10). Used ONLY inside the two trigger bodies
-- that must write through their own tables' policies while running as the
-- function owner: epigraph_propagate_tenancy and epigraph_inherit_tenancy.
-- Safe because both are REVOKE EXECUTE ... FROM PUBLIC and neither is callable
-- from SQL the app can emit.
CREATE OR REPLACE FUNCTION public.epigraph_definer_bypass() RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT COALESCE(
      (SELECT pg_has_role(current_user, 'epigraph_maintenance', 'MEMBER')
        WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_maintenance')),
      false);
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_definer_bypass() FROM PUBLIC;
```

Marking `epigraph_bypass()` `LEAKPROOF` stays **declined**: it requires superuser and, with the duplicate HNSW index gone, buys nothing.

### 064_communities_to_groups.sql — the `encryption_key_id` de-overload

```sql
SET LOCAL lock_timeout = '3s';
-- Resolves the collision the audit flagged: ownership.encryption_key_id is a
-- text column whose NAME and whose intended consumer both mean "key id", but
-- which TODAY holds a stringified COMMUNITY UUID --
--   crates/epigraph-db/src/repos/ownership.rs:101
--     let encryption_key_id = community_id.map(|id| id.to_string());
--   crates/epigraph-db/src/access_control.rs:57, :78-80 (the reading comments)

ALTER TABLE public.ownership ADD COLUMN IF NOT EXISTS community_id uuid;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ownership_community_fkey')
  THEN ALTER TABLE public.ownership ADD CONSTRAINT ownership_community_fkey
           FOREIGN KEY (community_id) REFERENCES public.communities(id)
           ON DELETE SET NULL NOT VALID; END IF;
END $$;

-- 1. Drain the parseable values into a typed column.
UPDATE public.ownership
   SET community_id = encryption_key_id::uuid
 WHERE partition_type = 'community'
   AND encryption_key_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

-- 2. QUARANTINE anything left. A VIEW, NOT A CTAS SNAPSHOT (ops F20).
--    The draft materialised the unparseable set at 064 time — but
--    repos/ownership.rs:101 keeps WRITING encryption_key_id until PR-06, so a
--    row that becomes unparseable in between would never enter a snapshot, and
--    migration 080's pre-flight 1 would pass while the value was discarded.
--    A view is always current, and the CHECK below closes the window entirely.
CREATE OR REPLACE VIEW public.ownership_key_id_quarantine AS
    SELECT node_id, node_type, partition_type, owner_id, encryption_key_id
      FROM public.ownership
     WHERE encryption_key_id IS NOT NULL AND community_id IS NULL;
COMMENT ON VIEW public.ownership_key_id_quarantine IS
  'Rows whose ownership.encryption_key_id does not parse as a community UUID. '
  'Must be empty before migration 080 drops the table. Non-empty is an operator '
  'action item, not an error.';

-- Belt and braces: no NEW unparseable value can be written between here and
-- PR-06's removal of the writer.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ownership_key_id_is_uuid')
  THEN ALTER TABLE public.ownership ADD CONSTRAINT ownership_key_id_is_uuid
           CHECK (encryption_key_id IS NULL
                  OR encryption_key_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
           NOT VALID; END IF;
END $$;

-- 3. Project each community into a group, id-preserving so no mapping table is
--    needed. kind='community' => key-free => zero-length public_key is correct.
INSERT INTO public.groups (id, display_name, did_key, public_key, kind, created_at)
SELECT c.id, c.name, 'did:epigraph:community:' || c.id::text, ''::bytea,
       'community', c.created_at
  FROM public.communities c
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.group_key_epochs (group_id, epoch, wrapped_key, status)
SELECT c.id, 0, NULL, 'active' FROM public.communities c
ON CONFLICT (group_id, epoch) DO NOTHING;

-- 4. community_members ⋈ perspectives.owner_agent_id  →  group_memberships.
--    This is the 2-hop membership path from access_control.rs:99-113,
--    collapsed into one agent-level table with roles and revocation.
INSERT INTO public.group_memberships
    (group_id, agent_id, wrapped_key_share, epoch, role, joined_at)
SELECT DISTINCT ON (cm.community_id, p.owner_agent_id)
       cm.community_id, p.owner_agent_id, ''::bytea, 0, 'writer', now()
  FROM public.community_members cm
  JOIN public.perspectives p ON p.id = cm.perspective_id
 WHERE p.owner_agent_id IS NOT NULL
ON CONFLICT DO NOTHING;

COMMENT ON COLUMN public.ownership.encryption_key_id IS
  'DEPRECATED. Held stringified community UUIDs until migration 064. Read by '
  'nothing after PR-06. Dropped in migration 080.';
```

### 065_entity_types_tenancy_tier.sql — D1 for types that do not exist yet

```sql
SET LOCAL lock_timeout = '3s';

ALTER TABLE public.entity_types
    ADD COLUMN IF NOT EXISTS tenancy_tier text NOT NULL DEFAULT 'unclassified';
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='entity_types_tier_vocab')
  THEN ALTER TABLE public.entity_types ADD CONSTRAINT entity_types_tier_vocab
           CHECK (tenancy_tier IN ('unclassified','columns','derived','identity')); END IF;
END $$;

-- Seed the 23 known types explicitly. No row is left 'unclassified'.
UPDATE public.entity_types SET tenancy_tier = 'columns'
 WHERE type_name IN ('claim','evidence','frame','context','perspective','community');
UPDATE public.entity_types SET tenancy_tier = 'identity' WHERE type_name = 'agent';
UPDATE public.entity_types SET tenancy_tier = 'derived'
 WHERE tenancy_tier = 'unclassified';

-- AFTER the seed, 'unclassified' becomes UN-REGISTERABLE (sec F16). The
-- previous revision asserted three times that read paths must treat
-- 'unclassified' as DENY and implemented it nowhere. The honest fix is that a
-- type with no tenancy decision cannot be created at runtime at all.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='entity_types_no_unclassified')
  THEN ALTER TABLE public.entity_types ADD CONSTRAINT entity_types_no_unclassified
           CHECK (tenancy_tier <> 'unclassified'); END IF;
END $$;
ALTER TABLE public.entity_types ALTER COLUMN tenancy_tier DROP DEFAULT;

-- The exemption registry (§2.4). A table in the generated protected set that
-- carries no tenancy columns must have a row here, with a named reviewer and a
-- stated residual. Adding a row is a visible diff.
CREATE TABLE IF NOT EXISTS public.tenancy_exempt (
    table_name  text PRIMARY KEY,
    reason      text NOT NULL,
    residual    text NOT NULL,
    reviewed_by text NOT NULL,
    reviewed_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO public.tenancy_exempt (table_name, reason, residual, reviewed_by) VALUES
 ('claim_themes',
  'Corpus-wide aggregate: no claim_id, no per-claim key. centroid vector(1536) '
  'and claim_count span tenants by construction.',
  'A centroid computed over a mixed public/private set reveals topical '
  'adjacency. Control is PR-09 viewer-scoped clustering, not a column.',
  'PENDING'),
 ('agents',
  'Identity must render authorship on a public claim.',
  'display_name and public_key are always readable; profile_visibility governs '
  'properties/orcid/ror_id only (§2.5 tier B).',
  'PENDING'),
 ('jobs',
  'Queue metadata; carries no claim content.',
  'Payload jsonb can name a plan_id. Closed by the 073 policy + the handler '
  're-validation in §6.5.5, not by columns.',
  'PENDING')
ON CONFLICT (table_name) DO NOTHING;
```

**The registration handler is where `tenancy_tier` becomes enforceable.** `POST /api/v1/admin/entity-types` (`routes/mod.rs:423-427`) gains a required `tenancy_tier` field (400 without it) **and a precondition check**: `tenancy_tier='columns'` is refused unless the named table already has both columns `NOT NULL`, a policy for each of SELECT/INSERT/UPDATE/DELETE in `pg_policy`, and `pg_class.relforcerowsecurity = true`. Checked in the handler, not in a test.

`crates/epigraph-db/tests/tenancy_coverage.rs` then closes the loop from the other side:

```sql
-- (a) every 'columns'-tier registry row actually has both NOT NULL columns
SELECT et.type_name, et.table_name
  FROM public.entity_types et
 WHERE et.tenancy_tier = 'columns' AND et.table_name IS NOT NULL
   AND NOT (EXISTS (SELECT 1 FROM information_schema.columns c
                     WHERE c.table_schema = et.schema_name AND c.table_name = et.table_name
                       AND c.column_name = 'visibility' AND c.is_nullable = 'NO')
        AND EXISTS (SELECT 1 FROM information_schema.columns c
                     WHERE c.table_schema = et.schema_name AND c.table_name = et.table_name
                       AND c.column_name = 'owner_group_id' AND c.is_nullable = 'NO'));
-- must be empty

-- (b) every table found by Generator A or B (§2.4) either has both columns or a
--     tenancy_exempt row. THIS is the assertion the previous revision's
--     hand-written 8-table list could not make.
-- must be empty
```

### 066_tenancy_triggers.sql — write-side stamping (transition form, statement-level)

Thirteen production `INSERT INTO claims` statements exist (§4.6) plus 160 test statements. Patching them by hand is exactly the opt-in discipline that produced 7-of-85 MCP coverage, so inheritance is stamped by the database and covers paths that do not exist yet.

**This migration ships the transition form**, keyed on "still equals the world default", because 061's `DEFAULT`s are still present and `NEW.visibility` is therefore never NULL. Migration 070 `CREATE OR REPLACE`s the same functions with the final `IS NULL`-keyed, `RAISE`-terminated versions in the same migration that drops those defaults.

```sql
SET LOCAL lock_timeout = '3s';

-- (a) A successor claim INHERITS its predecessor's tenancy. Today
--     ClaimRepository::supersede (repos/claim.rs:2139-2216) inserts a new UUID
--     and carries labels forward (:2203-2216) but NOT ownership, so superseding
--     a private claim silently DECLASSIFIES it.
CREATE OR REPLACE FUNCTION public.epigraph_claims_require_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE g uuid; v character varying(16);
BEGIN
    -- TRANSITION FORM (066). While 061's DEFAULTs exist, "undeclared" reads as
    -- "still the world default". Migration 070 replaces this whole function.
    IF NEW.owner_group_id <> '00000000-0000-0000-0000-000000000000'::uuid
       THEN RETURN NEW; END IF;

    IF NEW.supersedes IS NOT NULL THEN
        SELECT c.owner_group_id, c.visibility INTO g, v
          FROM public.claims c WHERE c.id = NEW.supersedes;
        IF FOUND THEN NEW.owner_group_id := g; NEW.visibility := v; RETURN NEW; END IF;
    END IF;

    -- evolve_step (repos/claim.rs:2845-2910, VERIFIED) inserts a successor
    -- WITHOUT setting supersedes -- it links via step_lineage_id plus an edge.
    IF NEW.step_lineage_id IS NOT NULL THEN
        SELECT c.owner_group_id, c.visibility INTO g, v
          FROM public.claims c
         WHERE c.step_lineage_id = NEW.step_lineage_id AND c.id <> NEW.id
         ORDER BY c.created_at DESC LIMIT 1;
        IF FOUND THEN NEW.owner_group_id := g; NEW.visibility := v; RETURN NEW; END IF;
    END IF;

    -- THE DEPLOY-ORDERING INSTRUMENT (ops F10). An undeclared write that
    -- silently inherits the default is exactly what migration 070 will start
    -- REJECTING. Count it, loudly, so §9.2's gate has a number to be flat.
    INSERT INTO public.tenancy_undeclared_writes (table_name, day, n, last_seen)
    VALUES (TG_TABLE_NAME, current_date, 1, now())
    ON CONFLICT (table_name, day)
      DO UPDATE SET n = tenancy_undeclared_writes.n + 1, last_seen = now();
    RAISE WARNING 'epigraph tenancy: undeclared INSERT INTO % (id=%). This will '
                  'raise 23502 after migration 070. See docs/tenancy.md.',
                  TG_TABLE_NAME, NEW.id;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_claims_require_tenancy() FROM PUBLIC;
DROP TRIGGER IF EXISTS claims_require_tenancy ON public.claims;
CREATE TRIGGER claims_require_tenancy BEFORE INSERT ON public.claims
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_claims_require_tenancy();

-- (b) An edge is stamped with the MEET of its endpoints. Migration 068 relaxes
--     the cross-group RAISE to a co-ownership stamp once co_owner_group_id
--     exists; until then it raises, because silently picking one side leaks the
--     other.
CREATE OR REPLACE FUNCTION public.epigraph_node_tenancy(p_id uuid, p_type text)
RETURNS TABLE (g uuid, v character varying(16))
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF p_type = 'claim' THEN
        RETURN QUERY SELECT c.owner_group_id, c.visibility FROM public.claims c WHERE c.id = p_id;
    ELSIF p_type = 'evidence' THEN
        RETURN QUERY SELECT e.owner_group_id, e.visibility FROM public.evidence e WHERE e.id = p_id;
    END IF;
    -- An edge pointing at a frame/agent/paper/task (17 permitted source_type
    -- values per edges_entity_types_valid, 001:757) has no tenancy of its own,
    -- so it contributes 'public' to the meet and never BLOCKS privatization.
    IF NOT FOUND THEN
        RETURN QUERY SELECT '00000000-0000-0000-0000-000000000000'::uuid,
                            'public'::character varying(16);
    END IF;
END $$;
-- REVOKE, MISSING FROM THE PREVIOUS REVISION (ops F18). This is a directly
-- callable oracle returning any claim's (owner_group_id, visibility).
REVOKE EXECUTE ON FUNCTION public.epigraph_node_tenancy(uuid, text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.epigraph_edges_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE sg uuid; sv varchar(16); tg uuid; tv varchar(16);
BEGIN
    SELECT g, v INTO sg, sv FROM public.epigraph_node_tenancy(NEW.source_id, NEW.source_type);
    SELECT g, v INTO tg, tv FROM public.epigraph_node_tenancy(NEW.target_id, NEW.target_type);
    IF sv = 'public' AND tv = 'public' THEN
        NEW.owner_group_id := '00000000-0000-0000-0000-000000000000'::uuid;
        NEW.visibility := 'public';
    ELSIF sv = 'public' THEN NEW.owner_group_id := tg; NEW.visibility := 'group';
    ELSIF tv = 'public' THEN NEW.owner_group_id := sg; NEW.visibility := 'group';
    ELSIF sg = tg      THEN NEW.owner_group_id := sg; NEW.visibility := 'group';
    ELSE
        IF NOT (sg = ANY (public.epigraph_session_groups())
            AND tg = ANY (public.epigraph_session_groups())) THEN
            RAISE EXCEPTION 'epigraph tenancy: edge spans groups % and %; writer '
                            'is not a member of both', sg, tg;
        END IF;
        NEW.owner_group_id := sg; NEW.visibility := 'group';
    END IF;
    RETURN NEW;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_edges_tenancy() FROM PUBLIC;   -- ops F18
DROP TRIGGER IF EXISTS edges_tenancy ON public.edges;
CREATE TRIGGER edges_tenancy BEFORE INSERT OR UPDATE OF source_id, target_id
    ON public.edges FOR EACH ROW EXECUTE FUNCTION public.epigraph_edges_tenancy();

-- (c) Claim-derived rows inherit from their parent claim. Fails CLOSED.
--
-- STATIC, PER-TABLE, STATEMENT-LEVEL (ops F17). The previous revision used a
-- dynamic `EXECUTE format('SELECT ($1).%I', parent_col) INTO parent_id USING NEW`
-- plus a per-row SELECT on claims -- two queries per inserted row on the
-- highest-volume insert paths, where one 5,017-claim ingest inserts 18,400
-- triples and 22,119 entity_mentions. The TG_ARGV indirection bought nothing:
-- the parent column is `claim_id` on EVERY table in the generated set
-- (verified against 001, 008, 015, 026).
CREATE OR REPLACE FUNCTION public.epigraph_inherit_tenancy_stmt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE n_orphan bigint;
BEGIN
    EXECUTE format(
      'UPDATE %I t SET owner_group_id = c.owner_group_id, visibility = c.visibility
         FROM public.claims c
        WHERE c.id = t.claim_id AND t.ctid = ANY (SELECT ctid FROM newrows)
          AND (t.owner_group_id, t.visibility)
              IS DISTINCT FROM (c.owner_group_id, c.visibility)', TG_TABLE_NAME);
    -- Unresolvable parent => RAISE, never a default.
    EXECUTE 'SELECT count(*) FROM newrows n
              WHERE n.claim_id IS NOT NULL
                AND NOT EXISTS (SELECT 1 FROM public.claims c WHERE c.id = n.claim_id)'
      INTO n_orphan;
    IF n_orphan > 0 THEN
        RAISE EXCEPTION 'epigraph tenancy: % row(s) in % reference a nonexistent '
                        'parent claim', n_orphan, TG_TABLE_NAME
            USING ERRCODE = '23503';
    END IF;
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_inherit_tenancy_stmt() FROM PUBLIC;
-- One AFTER INSERT ... REFERENCING NEW TABLE AS newrows FOR EACH STATEMENT
-- trigger per member of the generated set that carries claim_id -- INCLUDING
-- `evidence`.
--
-- CORRECTION TO THE DRAFT: evidence.claim_id uuid NOT NULL (001:904) makes
-- evidence a strict claim derivative, and evidence.raw_content (001:903) plus
-- evidence.embedding vector(1536) (001:910) are a full second copy of
-- claim-derived text WITH ITS OWN ANN VECTOR, served at routes/claims.rs:1073.
-- The draft's (c) list omitted it and (b) covered only edges, so as drafted,
-- EVIDENCE OF A GROUP-PRIVATE CLAIM WAS STAMPED WORLD/PUBLIC.

-- (d) A visibility change on a claim propagates to its children in the SAME tx.
--
-- THREE CORRECTIONS relative to the previous revision:
--   1. STATEMENT-LEVEL, not FOR EACH ROW (ops F11). The row form issued ten
--      UPDATEs per claim -- 5,000 statements per 500-item batch.
--   2. EVERY arm carries IS DISTINCT FROM (ops F11). The previous revision
--      claimed "every UPDATE carries IS DISTINCT FROM, so re-running a batch is
--      a no-op"; only the evidence arm actually did. Idempotence is what makes
--      a kill -9 recoverable, so this is load-bearing.
--   3. ROW_COUNT IS CHECKED (sec F10). epigraph_bypass() keys on session_user,
--      which SECURITY DEFINER does not change, so it is FALSE for an app-role
--      caller -- while RLS itself evaluates against current_user (the function
--      owner), for whom FORCE applies. The UPDATEs were therefore silently
--      RLS-FILTERED with no row-count check and no error: propagation would
--      accidentally work for a first privatization and silently fail for every
--      re-privatization and every third-group conflict. Fixed by using
--      epigraph_definer_bypass() (§3/063) AND by raising on a count mismatch.
CREATE OR REPLACE FUNCTION public.epigraph_propagate_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE t text; expected bigint; actual bigint;
        derived text[] := ARRAY[
          'triples','entity_mentions','claim_versions','mass_functions',
          'ds_combined_beliefs','ds_bayesian_divergence','claim_frames',
          'harvester_claim_provenance','evidence',
          -- sec F2 additions
          'challenges','reasoning_traces','experiment_triples',
          'experiment_entity_mentions','claim_clusters','claim_cluster_membership',
          'claim_neighborhood_membership','claim_signature_revocations'];
BEGIN
    IF NOT public.epigraph_definer_bypass() THEN
        RAISE EXCEPTION 'epigraph tenancy: propagation requires a maintenance-role '
                        'owner; refusing to run RLS-filtered' USING ERRCODE = '42501';
    END IF;
    FOREACH t IN ARRAY derived LOOP
        EXECUTE format(
          'SELECT count(*) FROM %I d JOIN changed ch ON ch.id = d.claim_id
             WHERE (d.owner_group_id, d.visibility)
                   IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t)
          INTO expected;
        EXECUTE format(
          'UPDATE %I d SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
             FROM changed ch
            WHERE ch.id = d.claim_id
              AND (d.owner_group_id, d.visibility)
                  IS DISTINCT FROM (ch.owner_group_id, ch.visibility)', t);
        GET DIAGNOSTICS actual = ROW_COUNT;
        IF actual <> expected THEN
            RAISE EXCEPTION 'epigraph tenancy: propagation to % updated % of % rows '
                            '(RLS filtered?)', t, actual, expected;
        END IF;
    END LOOP;
    -- Harvester fragments hang off provenance, not off claim_id.
    UPDATE public.harvester_fragments f
       SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
      FROM public.harvester_claim_provenance p JOIN changed ch ON ch.id = p.claim_id
     WHERE f.id = p.fragment_id
       AND (f.owner_group_id, f.visibility)
           IS DISTINCT FROM (ch.owner_group_id, ch.visibility);
    -- Edges are the MEET of their (possibly changed) endpoints. Migration 068
    -- REPLACES this body with the three-CASE co-ownership form; see the note
    -- there -- the replacement is SQL in 068, not prose.
    UPDATE public.edges e SET owner_group_id = ch.owner_group_id, visibility = ch.visibility
      FROM changed ch
     WHERE ((e.source_id = ch.id AND e.source_type='claim')
         OR (e.target_id = ch.id AND e.target_type='claim'))
       AND (e.owner_group_id, e.visibility)
           IS DISTINCT FROM (ch.owner_group_id, ch.visibility);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION public.epigraph_propagate_tenancy() FROM PUBLIC;  -- ops F18
DROP TRIGGER IF EXISTS claims_propagate_tenancy ON public.claims;
CREATE TRIGGER claims_propagate_tenancy AFTER UPDATE OF owner_group_id, visibility
    ON public.claims REFERENCING NEW TABLE AS changed
    FOR EACH STATEMENT EXECUTE FUNCTION public.epigraph_propagate_tenancy();
```

> **The `supersedes` chain is deliberately NOT propagated by a trigger.** A predecessor is a *sibling* `claims` row, and an `AFTER UPDATE` walking the chain would recurse. Retroactive closure is done at **selection time** by the D4 surface (§3/076, `epigraph_content_lineage_hull`). Trigger (a) handles the *write* direction; the hull handles the *retroactive* direction.

> **The propagation trigger now requires the maintenance role.** That is the direct consequence of sec F10 and it forces one design change downstream: `PATCH /api/v1/claims/:id/visibility` can **no longer apply synchronously in the HTTP handler** on the app pool. It enqueues the same one-item plan job every other privatization uses (§6.5.7). The previous revision's stated goal — *"exactly one code path"* — is finally true.

### 067_ownership_compat_shim.sql

`ownership` is demoted to a write-through shim so `POST /api/v1/ownership` (`routes/ownership.rs:97`), MCP `assign_ownership` (`tools/perspectives.rs:196`) and the five test fixtures keep working through the rollout. An `AFTER INSERT OR UPDATE` trigger maps `partition_type` → `(claims.visibility, claims.owner_group_id)`: `public` → the author's personal group + `'public'` (**not** world — D2/§2.3); `private` → the owner's personal group + `'group'`; `community` → `community_id`'s group + `'group'`. Every mapping also writes a `tenancy_transcription_log` row, which is what migration 080's pre-flight reads.

**The shim runs on the ordinary write path, so it hits sec F10 head-on.** It is therefore `SECURITY DEFINER` **owned by `epigraph_maintenance`**, and its body opens with the same `epigraph_definer_bypass()` assertion as 066(d). Both writers are deleted in PR-14; the shim is dropped in 080.

### 068_edge_co_ownership.sql — making the endpoint meet expressible (transactional)

`edges.owner_group_id` is a single uuid. It can express *both endpoints public*, *one public + one in G*, and *both in G* — but **not** *endpoints in different groups G and H*. Migration 066(b) handles that at write time by rejecting the insert. **Privatization cannot reject:** the edge already exists, and refusing to privatize the claim because of it would let any writer veto privatization by planting one edge. Silently picking `G` grants group G read access to an edge whose other endpoint is H's. Silently deleting the edge destroys corpus data.

```sql
SET LOCAL lock_timeout = '3s';
ALTER TABLE public.edges
    ADD COLUMN IF NOT EXISTS co_owner_group_id uuid;   -- NULL = single-owner (common case)
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='edges_co_owner_fkey')
  THEN ALTER TABLE public.edges ADD CONSTRAINT edges_co_owner_fkey
           FOREIGN KEY (co_owner_group_id) REFERENCES public.groups(id)
           ON DELETE RESTRICT NOT VALID; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='edges_co_owner_shape')
  THEN ALTER TABLE public.edges ADD CONSTRAINT edges_co_owner_shape CHECK (
           co_owner_group_id IS NULL
           OR (visibility = 'group' AND co_owner_group_id <> owner_group_id)) NOT VALID;
  END IF;
END $$;

-- ===================================================================
-- THE BEHAVIOURAL CHANGE, AS SQL (ops F19).
--
-- The previous revision described in PROSE that 066(b)'s cross-group RAISE "is
-- then relaxed to a co-ownership stamp" and that 066(d)'s trailing edge UPDATE
-- "is replaced by the three-CASE meet recomputation" -- and then shipped a
-- migration body containing only ALTER TABLE, two ADD CONSTRAINTs and an index.
-- Between PR-13 and PR-18 the OLD 066(d) would have survived, overwriting
-- owner_group_id/visibility for every edge touching the claim with no meet.
-- Both function bodies are CREATE OR REPLACEd here.
-- ===================================================================
CREATE OR REPLACE FUNCTION public.epigraph_edges_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE sg uuid; sv varchar(16); tg uuid; tv varchar(16);
BEGIN
    SELECT g, v INTO sg, sv FROM public.epigraph_node_tenancy(NEW.source_id, NEW.source_type);
    SELECT g, v INTO tg, tv FROM public.epigraph_node_tenancy(NEW.target_id, NEW.target_type);
    IF sv = 'public' AND tv = 'public' THEN
        NEW.owner_group_id := '00000000-0000-0000-0000-000000000000'::uuid;
        NEW.visibility := 'public'; NEW.co_owner_group_id := NULL;
    ELSIF sv = 'public' THEN
        NEW.owner_group_id := tg; NEW.visibility := 'group'; NEW.co_owner_group_id := NULL;
    ELSIF tv = 'public' THEN
        NEW.owner_group_id := sg; NEW.visibility := 'group'; NEW.co_owner_group_id := NULL;
    ELSIF sg = tg THEN
        NEW.owner_group_id := sg; NEW.visibility := 'group'; NEW.co_owner_group_id := NULL;
    ELSE
        -- RELAXED: expressible now. Strictly better than the old exception.
        NEW.owner_group_id := sg; NEW.visibility := 'group'; NEW.co_owner_group_id := tg;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION public.epigraph_propagate_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
-- identical to 066(d) except the final edges UPDATE, which becomes the
-- three-CASE meet over BOTH endpoints, ordered by e.id (ops F12), with
-- IS DISTINCT FROM on the whole triple.
$$;
```

The edge visibility predicate becomes an **intersection**, not a union:

```sql
-- Viewer::edge_predicate_fragment, Scoped arm, alias `e`:
--   AND (e.visibility = 'public'
--        OR (e.owner_group_id = ANY($V::uuid[])
--            AND (e.co_owner_group_id IS NULL
--                 OR e.co_owner_group_id = ANY($V::uuid[]))))
--
-- The RLS policy body (073, edges_tenancy) gets the identical clause with
-- (SELECT public.epigraph_session_groups()) in place of $V.
```

A cross-group edge is visible only to a principal in **both** groups — exactly the meet, and exactly what the enterprise `edges_privacy` policy intends.

### 069_edge_co_owner_index.sql

```sql
-- no-transaction
-- Index statements only (ops F8). See 062's header for the INVALID-index
-- detection query and the DROP INDEX recovery step.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_edges_co_owner
    ON public.edges (co_owner_group_id) WHERE co_owner_group_id IS NOT NULL;
```

### 070_tenancy_required.sql — D1's teeth

Ships only after the backfill has completed (PR-12), every call site in §4.6 is patched, **and `tenancy_undeclared_writes` has been flat for 24 hours** (§9.2, ops F10).

```sql
SET LOCAL lock_timeout = '3s';
-- ===================================================================
-- D1: a DEFAULT is a form of implicit-public. Remove it.
--
-- DROP DEFAULT is a catalog-only change: instant, no rewrite. Rows already
-- written keep their attmissingval; only FUTURE inserts lose the fallback.
-- Idempotent: DROP DEFAULT on a column with no default is a no-op.
--
-- ONE-WAY DOOR. Undo script: docs/runbooks/070-undo.sql, executed as the table
-- OWNER (which the app role is not, after PR-16's role split).
-- ===================================================================
DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY <the same tier_a array as 061> LOOP
        EXECUTE format('ALTER TABLE public.%I ALTER COLUMN visibility DROP DEFAULT', t);
        EXECUTE format('ALTER TABLE public.%I ALTER COLUMN owner_group_id DROP DEFAULT', t);
    END LOOP;
END $$;
ALTER TABLE public.agents ALTER COLUMN profile_visibility DROP DEFAULT;
```

**Why `NOT NULL` alone is not enough, and what the trigger is for.** `NOT NULL` with no default already gives a fail-closed write path, but a bare `23502 null value in column "visibility"` is a terrible diagnostic, and it breaks the *legitimate* case where the row's tenancy is determinate from its parent.

| Case | Trigger action |
|---|---|
| Writer named both columns | validate the pair, pass through |
| Writer omitted them, row has a determinate parent (`supersedes`, `step_lineage_id`, `claim_id`, edge endpoints) | **inherit** — more D1-compliant than requiring restatement, because restating invites an accidental downgrade |
| Writer omitted them, no parent | **`RAISE EXCEPTION`** with a diagnosable message |

Ordering is what makes this work: **column defaults are materialised when the tuple is built (before `BEFORE INSERT` triggers), and `NOT NULL` is checked at heap-insert time (after them)**. With the default dropped, `NEW.visibility` is `NULL` inside the trigger, the trigger can fill it or raise, and `NOT NULL` remains as a backstop against a trigger bug.

```sql
CREATE OR REPLACE FUNCTION public.epigraph_claims_require_tenancy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE g uuid; v character varying(16);
BEGIN
    -- 1. Fully declared by the writer.
    IF NEW.visibility IS NOT NULL AND NEW.owner_group_id IS NOT NULL THEN
        RETURN NEW;
    END IF;

    -- 2. Determinate inheritance from a predecessor.
    IF NEW.supersedes IS NOT NULL THEN
        SELECT c.owner_group_id, c.visibility INTO g, v
          FROM public.claims c WHERE c.id = NEW.supersedes;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'epigraph tenancy: claims.supersedes=% does not exist',
                NEW.supersedes USING ERRCODE = '23503';
        END IF;
        NEW.owner_group_id := COALESCE(NEW.owner_group_id, g);
        NEW.visibility     := COALESCE(NEW.visibility,     v);
        IF v = 'group' AND NEW.visibility = 'public' THEN
            RAISE EXCEPTION 'epigraph tenancy: claim % supersedes group-private claim % '
                            'and may not be public', NEW.id, NEW.supersedes
                USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END IF;

    -- 3. Determinate inheritance within a step lineage (evolve_step,
    --    repos/claim.rs:2845-2910, VERIFIED: no supersedes, links via
    --    step_lineage_id + an edge).
    IF NEW.step_lineage_id IS NOT NULL THEN
        SELECT c.owner_group_id, c.visibility INTO g, v
          FROM public.claims c
         WHERE c.step_lineage_id = NEW.step_lineage_id AND c.id <> NEW.id
         ORDER BY c.created_at DESC LIMIT 1;
        IF FOUND THEN
            NEW.owner_group_id := COALESCE(NEW.owner_group_id, g);
            NEW.visibility     := COALESCE(NEW.visibility,     v);
            IF v = 'group' AND NEW.visibility = 'public' THEN
                RAISE EXCEPTION 'epigraph tenancy: claim % is in a group-private step '
                                'lineage and may not be public', NEW.id
                    USING ERRCODE = '42501';
            END IF;
            RETURN NEW;
        END IF;
    END IF;

    -- 4. Seed-role escape hatch. ROLE MEMBERSHIP, not a GUC an app can SET.
    --    session_user, NOT current_user (inside this SECURITY DEFINER frame
    --    current_user is the function owner). The EXISTS guard is required
    --    because pg_has_role on a nonexistent role RAISES 42704 (ops F4) --
    --    though after 060 the role exists in every environment the migration
    --    could run in, so this is belt and braces.
    --
    --    STAMPS THE SEED GROUP, NOT WORLD (sec F14). §8.2 A4 asserts
    --    `count(*) FROM claims WHERE owner_group_id = <world>` is 0, and the
    --    deferred strong CHECK (owner_group_id <> world) can never ship while
    --    this arm stamps world. A dedicated seed group makes both achievable
    --    AND makes seed-created rows greppable.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'epigraph_seed')
       AND pg_has_role(session_user, 'epigraph_seed', 'MEMBER') THEN
        NEW.owner_group_id := COALESCE(NEW.owner_group_id,
            '00000000-0000-0000-0000-00000000dead'::uuid);
        NEW.visibility := COALESCE(NEW.visibility, 'public');
        RETURN NEW;
    END IF;

    -- 5. Undeclared. D1: fail, never default.
    RAISE EXCEPTION
        'epigraph tenancy: INSERT INTO claims without an explicit (visibility, '
        'owner_group_id) declaration and no inheritable parent. Name both columns, '
        'or set claims.supersedes. id=%, agent_id=%', NEW.id, NEW.agent_id
        USING ERRCODE = '23502',
              HINT = 'See docs/tenancy.md#declaring-visibility-on-write';
END $$;

-- Widening is a separate, audited operation (D4's inverse).
CREATE OR REPLACE FUNCTION public.epigraph_claims_block_widening() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- (a) THE SEALED GUARD, UNCONDITIONAL AND WITH NO GUC OVERRIDE (sec F11).
    --     The previous revision said the (public, Sealed) ban was enforced by
    --     "a trigger on claim_encryption PLUS the reverse guard in
    --     epigraph_propagate_tenancy" -- and epigraph_propagate_tenancy
    --     contained no such guard, while the claim_encryption trigger was
    --     BEFORE INSERT OR UPDATE **OF claim_id** and could never fire on
    --     `UPDATE claims SET visibility='public'`. Result: seal, then
    --     declassify with epigraph.allow_declassify='yes' (which the admin
    --     declassification surface sets BY DESIGN) yields a PUBLIC row whose
    --     content is '[sealed:uuid]', embedding NULL, and ciphertext no reader
    --     is entitled to: a corpus-wide, permanently unreadable stub, and
    --     content_hash = BLAKE3(ciphertext) no longer agrees with content.
    IF NEW.visibility = 'public'
       AND EXISTS (SELECT 1 FROM public.claim_encryption WHERE claim_id = NEW.id) THEN
        RAISE EXCEPTION 'epigraph tenancy: claim % is SEALED and cannot be made '
                        'public. Unseal first, then declassify.', NEW.id
            USING ERRCODE = '42501';
    END IF;
    -- (b) Ordinary declassification guard.
    IF OLD.visibility = 'group' AND NEW.visibility = 'public'
       AND COALESCE(current_setting('epigraph.allow_declassify', true), '') <> 'yes' THEN
        RAISE EXCEPTION 'epigraph tenancy: refusing to declassify claim % from group to '
                        'public. Use the admin declassification surface.', OLD.id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS claims_block_widening ON public.claims;
CREATE TRIGGER claims_block_widening BEFORE UPDATE OF visibility ON public.claims
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_claims_block_widening();
```

Analogous `*_require_tenancy` triggers are created on every other tier-A table; on the derived tables arms 2/3 are replaced by the `claim_id` lookup from 066(c), so the only new behaviour is that an unresolvable parent raises `23502` instead of silently keeping a default.

> **`epigraph_seed` is the honest cost of this design.** Arm 4 exists so 160 test-fixture inserts (§4.6) do not have to be rewritten. It is a default-on-omission mechanism and therefore a D1 hazard. Four mitigations: (1) it is **role membership**, visible in `pg_auth_members`, revocable with one `REVOKE`; (2) `AppState::with_db` refuses to serve if `pg_has_role(session_user, 'epigraph_seed', 'MEMBER')`; (3) `tenancy_required.rs` asserts an `epigraph_app` insert with no declaration raises `23502`; (4) it stamps the **seed group**, so `SELECT count(*) FROM claims WHERE owner_group_id = '…dead'` is a one-line audit of exactly how much of the corpus took the escape hatch. **§10.1 Q3 asks the user whether to delete it and pay for the fixture edits.**

**What the trigger does not catch.** `COPY`, `INSERT ... SELECT` and logical-replication apply all fire row triggers, so they are covered. **`ALTER TABLE … DISABLE TRIGGER` and `SET session_replication_role = 'replica'` are not**, and both are available to the table owner. Same residual as `FORCE RLS`. Boot assertion:

```sql
SELECT tgenabled FROM pg_trigger WHERE tgname = 'claims_require_tenancy';  -- must be 'O'
```

### 071 / 072 — validate tenancy constraints, split and self-defending

**The guard moves out of the migration entirely** (ops F16). The previous revision put three `count(*)` queries and every `VALIDATE CONSTRAINT` in one transaction: the guard's `count(*) FROM claims WHERE owner_group_id = <world>` is a full seq scan (`idx_claims_owner_group` is partial `WHERE visibility <> 'public'` and every world-owned row is public, so that index is structurally unusable for it), and the same transaction then ran three `VALIDATE`s on `claims` plus one per tier-A table, holding `SHARE UPDATE EXCLUSIVE` throughout — autovacuum on `claims` blocked and the xmin horizon pinned for the duration.

- **The guard is `epigraph-tenancy-backfill verify`'s exit code**, run as a deploy step *before* 071. It runs the three live counts (world-owned claims, world-owned evidence, non-public `ownership` rows mapping to a public claim) using `idx_claims_world_owned` from 062, and prints the offending ids.
- **071 validates `claims` only.** Three `VALIDATE CONSTRAINT`s, `SET LOCAL lock_timeout = '3s'`.
- **072 validates every remaining tier-A table**, `agents`, `edges_co_owner_shape`, and `ownership_community_fkey` / `ownership_key_id_is_uuid`.
- Both are idempotent: `VALIDATE CONSTRAINT` on an already-validated constraint is a no-op.

> **The stronger variant, deferred and measurement-gated.** Since the D2 derivation is *total* (`claims.agent_id` is `NOT NULL` at `001:606`, every agent gets a personal group), no legitimate claim ever needs the world group. `CHECK (owner_group_id <> '00000000-…-0000')` unconditionally on `claims` is the end state. With arm 4 now stamping the **seed** group (sec F14), it is finally *reachable*. Ship the pairing CHECK during rollout; add the strong form once the count has been zero for a full release (§10.2 Q6).

### 073_rls_policies.sql — created, not yet forced; per-command, not FOR ALL by habit

Policies on the full generated tier-A set, `groups`, `group_memberships`, `group_key_epochs`, the three encryption tables, **`jobs`**, **`security_events`**, and (from 076/078/079) `privatization_plans`, `privatization_plan_items`, `privatization_audit`, `instance_admins`. `ENABLE` only — until 075 flips `FORCE`, the schema-owning role bypasses them, which is the shadow window.

```sql
SET LOCAL lock_timeout = '3s';

ALTER TABLE public.claims ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS claims_tenancy ON public.claims;
CREATE POLICY claims_tenancy ON public.claims FOR ALL TO PUBLIC
    -- (SELECT f()) → InitPlan, evaluated ONCE per statement, not once per row.
    --
    -- THE CONSTANT COMES FIRST, and it is the same disjunct, in the same order,
    -- that Viewer::predicate_fragment emits. That is what makes the app-emitted
    -- qual IMPLY the policy's disjunct, so the RLS filter can never reject a row
    -- the index returned (§4.5).
    USING (
        (SELECT public.epigraph_bypass())
        OR visibility = 'public'
        OR owner_group_id = ANY ((SELECT public.epigraph_session_groups())))
    -- WITH CHECK is written EXPLICITLY. `FOR ALL USING (...)` alone reuses USING
    -- as WITH CHECK, and the enterprise policies (ENT/migrations/001:530-545) do
    -- exactly that — which degenerates to a no-op for INSERT because their
    -- predicate looks up claim_encryption for a claim that has no encryption row
    -- yet.
    --
    -- The draft's third arm `OR (visibility='public' AND owner_group_id=<world>)`
    -- is DELETED: under §2.3 a public claim is owned by its author's group, so
    -- publishing publicly is an ORDINARY write into a group you can write to,
    -- and `reader` blocks it exactly as it blocks a group write.
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())));

-- edges carries the co-ownership INTERSECTION (migration 068).
ALTER TABLE public.edges ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS edges_tenancy ON public.edges;
CREATE POLICY edges_tenancy ON public.edges FOR ALL TO PUBLIC
    USING (
        (SELECT public.epigraph_bypass())
        OR visibility = 'public'
        OR (owner_group_id = ANY ((SELECT public.epigraph_session_groups()))
            AND (co_owner_group_id IS NULL
                 OR co_owner_group_id = ANY ((SELECT public.epigraph_session_groups())))))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        OR owner_group_id = ANY ((SELECT public.epigraph_writable_groups())));

-- group_memberships needs a SECURITY DEFINER helper, NOT an inline EXISTS over
-- itself: a policy ON group_memberships whose WITH CHECK selects FROM
-- group_memberships re-applies the policy to the inner scan and raises
-- `infinite recursion detected in policy for relation "group_memberships"`.
CREATE OR REPLACE FUNCTION public.epigraph_is_group_admin(p_group uuid, p_agent uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM public.group_memberships m
                    WHERE m.group_id = p_group AND m.agent_id = p_agent
                      AND m.role = 'admin' AND m.revoked_at IS NULL)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_is_group_admin(uuid, uuid) FROM PUBLIC;
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='epigraph_app') THEN
  GRANT EXECUTE ON FUNCTION public.epigraph_is_group_admin(uuid, uuid) TO epigraph_app;
END IF; END $$;

ALTER TABLE public.group_memberships ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS group_memberships_tenancy ON public.group_memberships;
CREATE POLICY group_memberships_tenancy ON public.group_memberships FOR ALL TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR group_id = ANY ((SELECT public.epigraph_session_groups()))
        OR agent_id = (SELECT public.epigraph_principal_id()))
    WITH CHECK ((SELECT public.epigraph_bypass())
        OR public.epigraph_is_group_admin(group_id, (SELECT public.epigraph_principal_id())));

-- recall_events is keyed on the QUERYING agent: today get_recall_events
-- (tools/recall_events.rs:51-98) hands any claims:read holder every other
-- agent's raw search text and returned claim ids.
--
-- NOTE the `IS NOT NULL` conjunct. Without it, an unset principal GUC makes the
-- predicate `agent_id IS NOT DISTINCT FROM NULL`, which is TRUE for every
-- NULL-agent_id row -- the inverse of the leak this policy closes (sec F1).
-- §0.5's checkout stamping means the GUC is always set, and this conjunct means
-- the policy is still correct if it ever is not.
ALTER TABLE public.recall_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recall_events_tenancy ON public.recall_events;
CREATE POLICY recall_events_tenancy ON public.recall_events FOR ALL TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR ((SELECT public.epigraph_principal_id()) IS NOT NULL
            AND agent_id IS NOT DISTINCT FROM (SELECT public.epigraph_principal_id())))
    WITH CHECK ((SELECT public.epigraph_bypass())
        OR ((SELECT public.epigraph_principal_id()) IS NOT NULL
            AND agent_id IS NOT DISTINCT FROM (SELECT public.epigraph_principal_id())));

-- ===================================================================
-- agents: THE FOR-SELECT-ONLY TRAP (sec F13).
--
-- `ENABLE ROW LEVEL SECURITY` already applies to non-owner roles, and
-- epigraph_app is a non-owner by construction after PR-16's role split. With
-- ONLY a FOR SELECT policy, PostgreSQL DEFAULT-DENIES INSERT and UPDATE -- so
-- AgentRepository::ensure_for_client, called at all three token-mint sites
-- (oauth/token.rs:416, :558, :739), is denied, and `UPDATE oauth_clients SET
-- agent_id` fails. EVERY AUTHENTICATION WOULD BREAK THE DAY 075 LANDS.
-- ===================================================================
ALTER TABLE public.agents ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agents_identity ON public.agents;
CREATE POLICY agents_identity ON public.agents FOR SELECT TO PUBLIC
    USING (true);   -- rows are readable; the PROJECTION is the control.
                    -- VISIBILITY-EXEMPT: agents.id/display_name/public_key must
                    -- render authorship on public claims. profile_visibility
                    -- governs the PII columns in the repo layer (§4.4).
DROP POLICY IF EXISTS agents_provision ON public.agents;
CREATE POLICY agents_provision ON public.agents FOR INSERT TO PUBLIC
    WITH CHECK (true);  -- ensure_for_client is idempotent and pre-authorized by
                        -- the token mint; the agents row IS the principal.
DROP POLICY IF EXISTS agents_self_update ON public.agents;
CREATE POLICY agents_self_update ON public.agents FOR UPDATE TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR id = (SELECT public.epigraph_principal_id()))
    WITH CHECK ((SELECT public.epigraph_bypass())
        OR id = (SELECT public.epigraph_principal_id()));
-- No DELETE policy: agents are never deleted through the app role. Recorded as
-- a deliberate uncovered command in rls_enforcement.rs's polcmd table.

-- ===================================================================
-- jobs: the privatization job handler runs with epigraph_bypass() TRUE, so
-- anything that can INSERT a jobs row can dispatch an unapproved plan with full
-- RLS bypass (sec F5). PostgresJobQueue::enqueue writes this table from the
-- ordinary app role (epigraph-jobs/src/lib.rs:3135), so it needs a policy.
-- ===================================================================
ALTER TABLE public.jobs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jobs_app ON public.jobs;
CREATE POLICY jobs_app ON public.jobs FOR ALL TO PUBLIC
    USING ((SELECT public.epigraph_bypass()))
    WITH CHECK (
        (SELECT public.epigraph_bypass())
        -- The app role may enqueue ordinary work, never privatization work.
        OR job_type NOT IN ('privatization_apply','privatization_revert','privatization_reseal'));
-- Reading the queue is a maintenance operation; the app enqueues and polls
-- through repo functions that run on the maintenance pool after PR-15.

-- ===================================================================
-- security_events: the previous revision routed privatization.seal_manifest --
-- "the only API call that hands plaintext to a caller who may not otherwise be
-- entitled to it" -- into a table with NO immutability trigger, NO policy, and
-- absent from the FORCE list, written on the ordinary app connection by
-- SecurityEventRepository::create (repos/security_event.rs:82). The
-- plaintext-egress record landed in a table the same role could DELETE FROM
-- (sec F17). Verified: security_events at 001:1415 has no such controls.
--
-- DISPOSITION: privatization_audit is the RECORD OF AUTHORITY for privatization
-- (§3/078). security_events remains the cross-cutting actor log and is hardened
-- to match, so neither is the weak copy of the other.
-- ===================================================================
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS security_events_append ON public.security_events;
CREATE POLICY security_events_append ON public.security_events FOR INSERT TO PUBLIC
    WITH CHECK (true);
DROP POLICY IF EXISTS security_events_read ON public.security_events;
CREATE POLICY security_events_read ON public.security_events FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR agent_id = (SELECT public.epigraph_principal_id())
        OR public.epigraph_is_instance_admin((SELECT public.epigraph_principal_id())));
-- No UPDATE/DELETE policy => default deny, plus the immutability trigger in 078.
```

**Per-command coverage is asserted, not assumed.** `crates/epigraph-db/tests/rls_enforcement.rs` enumerates `pg_policy.polcmd` for every table with `relrowsecurity = true` and fails the build unless each of SELECT/INSERT/UPDATE/DELETE is either covered by a policy or listed in an in-test `DELIBERATELY_UNCOVERED` table with a reason. **Enumerated from the catalog, never from the migration text** — that is what would have caught the `agents` trap.

### 074_rls_canary.sql — its own table, not a synthetic claim

```sql
-- The canary reduces the entire security posture to one integer, checked at
-- boot and every 60 s. There is no app-layer equivalent — you cannot assert at
-- runtime that 85 tools remembered to redact.
--
-- IT GETS ITS OWN TABLE. A synthetic row in `claims` is wrong regardless of
-- labelling: it counts in system_stats, needs an exclusion in
-- find_claims_needing_embeddings and in the CLAUDE.md audit SQL, and pollutes
-- an agent's authored set.
CREATE TABLE IF NOT EXISTS public.rls_canary (
    id         integer PRIMARY KEY,
    note       text NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);
INSERT INTO public.rls_canary (id, note) VALUES
    (1, 'Visible ONLY to a connection that bypasses row security. If an '
        'epigraph_app connection can SELECT this row, RLS is not in force.')
ON CONFLICT (id) DO NOTHING;

ALTER TABLE public.rls_canary ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rls_canary_bypass_only ON public.rls_canary;
CREATE POLICY rls_canary_bypass_only ON public.rls_canary FOR ALL TO PUBLIC
    USING ((SELECT public.epigraph_bypass()))
    WITH CHECK ((SELECT public.epigraph_bypass()));
ALTER TABLE public.rls_canary FORCE ROW LEVEL SECURITY;
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='epigraph_app') THEN
  GRANT SELECT ON public.rls_canary TO epigraph_app;
END IF; END $$;
```

### 075_rls_force.sql — the flip

```sql
SET LOCAL lock_timeout = '3s';
-- ENABLE does not apply to the table owner; only FORCE does. The entire
-- enterprise policy set is therefore INERT for the schema-owning role the app
-- connects as today (postgres://epigraph:epigraph@localhost/...): a grep for
-- `FORCE ROW LEVEL` across ENT/migrations returns nothing.
--
-- KILL SWITCH: ALTER TABLE ... NO FORCE ROW LEVEL SECURITY. Instant, no
-- rewrite, no data change. Paired with reverting DATABASE_URL to the owner role
-- this is a sub-minute rollback. Scripted at docs/runbooks/075-undo.sql.
--
-- PRECONDITIONS, checked by the deploy runbook BEFORE this runs:
--   * §0.5's session-GUC probe passes on the target cluster.
--   * PR-15 has landed: the job pool, the 14 DATABASE_URL CLI binaries, and
--     scripts/{theme_lib,fuzzy_dedup_claims}.py all use MAINTENANCE_DATABASE_URL.
--   * `current_user` on the API pool is exactly `epigraph_app`.
DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY <the tier_a array, PLUS groups, group_memberships,
                        group_key_epochs, claim_encryption, claim_version_encryption,
                        evidence_encryption, edge_encryption, agents, jobs,
                        security_events, privatization_plans,
                        privatization_plan_items, privatization_audit,
                        instance_admins> LOOP
        EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END $$;
```

`locked_decisions.rs` asserts that this array equals the generated protected set ∪ the group/encryption/admin tables, so a table added to §2.4's generators and not to 075 fails the build.

### 076_privatization_plans.sql — D4's persisted object

A 100k-node selection is too expensive to evaluate twice and too racy to evaluate once at preview and again at apply. **Selection is materialized once, into `privatization_plan_items`, and the apply operates on that frozen id set.** Preview returns a `plan_digest`; `apply` must echo it.

```sql
SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS public.privatization_plans (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    state             text NOT NULL DEFAULT 'draft',
    mode              text NOT NULL,                -- 'restrict' | 'seal'
    target_group_id   uuid NOT NULL REFERENCES public.groups(id) ON DELETE RESTRICT,
    selector          jsonb NOT NULL,               -- the request, verbatim
    on_conflict       text NOT NULL DEFAULT 'abort',-- 'abort'|'skip'|'reassign'
    pad_to            integer NOT NULL DEFAULT 256,
    plan_digest       bytea,                        -- BLAKE3 over sorted (kind,id)
    item_count        integer NOT NULL DEFAULT 0,
    authors_losing_count integer NOT NULL DEFAULT 0, -- drives dual control (§6.6)
    acknowledge_author_loss boolean NOT NULL DEFAULT false,
    created_by        uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    approved_by       uuid          REFERENCES public.agents(id) ON DELETE RESTRICT,
    approved_at       timestamptz,
    dispatched_by     uuid          REFERENCES public.agents(id) ON DELETE RESTRICT,
    cursor_kind       text, cursor_depth integer, cursor_id uuid,
    drift_ids         uuid[] NOT NULL DEFAULT ARRAY[]::uuid[],   -- §6.5.5 post-apply rescan
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pp_state_check CHECK (state IN
        ('draft','selecting','previewed','approved','applying','applied',
         'applied_with_drift','failed','reverting','reverted')),
    CONSTRAINT pp_mode_check  CHECK (mode IN ('restrict','seal')),
    CONSTRAINT pp_conflict_check CHECK (on_conflict IN ('abort','skip','reassign')),
    CONSTRAINT pp_pad_check   CHECK (pad_to IN (0,256,1024,4096)),
    CONSTRAINT pp_four_eyes  CHECK (approved_by IS NULL OR approved_by <> created_by),
    CONSTRAINT pp_seal_needs_pad CHECK (mode <> 'seal' OR pad_to > 0)
);

CREATE TABLE IF NOT EXISTS public.privatization_plan_items (
    plan_id     uuid NOT NULL REFERENCES public.privatization_plans(id) ON DELETE CASCADE,
    kind        text NOT NULL,     -- 'claim' | 'evidence'
    entity_id   uuid NOT NULL,
    depth       integer NOT NULL,  -- 0 = seed; hull members inherit their anchor's depth
    via         text,              -- 'seed'|'closure:<rel>'|'hull:supersedes'
                                   -- |'hull:step_lineage'|'hull:versions'|'hull:evidence'
    before_visibility     text NOT NULL,
    before_owner_group_id uuid NOT NULL,
    before_had_embedding  boolean NOT NULL,
    state       text NOT NULL DEFAULT 'pending',  -- pending|applied|skipped|failed|reverted
    error       text,
    applied_at  timestamptz,
    PRIMARY KEY (plan_id, kind, entity_id)
);
CREATE INDEX IF NOT EXISTS idx_ppi_work ON public.privatization_plan_items
    (plan_id, state, depth DESC, kind, entity_id);

-- Only one plan may be mid-flight against a given target group.
CREATE UNIQUE INDEX IF NOT EXISTS privatization_one_active_per_group
    ON public.privatization_plans (target_group_id)
 WHERE state IN ('selecting','applying','reverting');
```

**The mandatory hull.** Independently of any closure, every selected claim `C` drags in `claim_versions WHERE claim_id = C` (`content text NOT NULL`, `001:589-591`), `evidence WHERE claim_id = C` (`raw_content` + its own `embedding vector(1536)`, `001:903-910`), and **the whole content-lineage, transitively, in both directions**.

**Lineage is `supersedes` UNION `step_lineage_id` (sec F8).** The previous revision's `epigraph_supersede_hull` recursed on `claims.supersedes` only — while §3/069 arm 3 and §4.6 row 7 of that same document *correctly* stated that `evolve_step` (verified at `repos/claim.rs:2845-2910`) inserts a successor **without** setting `supersedes`, linking via `step_lineage_id` plus an edge, and called the draft's omission of that arm a bug. So privatizing one revision of a workflow step left every sibling revision in the same lineage public — successive drafts of the same content, exactly the restatement class the hull exists to close, and a public sibling shares the private claim's `step_lineage_id`, which is §8.5's dangling-reference oracle verbatim.

```sql
CREATE OR REPLACE FUNCTION public.epigraph_content_lineage_hull(p_seeds uuid[])
RETURNS TABLE (claim_id uuid, via text) LANGUAGE sql STABLE PARALLEL SAFE AS $$
    WITH RECURSIVE chain AS (
        SELECT c.id, c.supersedes, ARRAY[c.id] AS path, 'seed'::text AS via
          FROM public.claims c WHERE c.id = ANY(p_seeds)
        UNION ALL
        -- backwards: predecessors (older content, is_current = false, and NO
        -- trigger reaches them)
        SELECT p.id, p.supersedes, ch.path || p.id, 'hull:supersedes'
          FROM public.claims p JOIN chain ch ON p.id = ch.supersedes
         WHERE NOT p.id = ANY(ch.path) AND array_length(ch.path,1) < 64
        UNION ALL
        -- forwards: successors. A public successor pointing at a now-private
        -- predecessor is a DANGLING-REFERENCE EXISTENCE ORACLE (§8.5).
        SELECT s.id, s.supersedes, ch.path || s.id, 'hull:supersedes'
          FROM public.claims s JOIN chain ch ON s.supersedes = ch.id
         WHERE NOT s.id = ANY(ch.path) AND array_length(ch.path,1) < 64
    ),
    -- THE ARM THE PREVIOUS REVISION MISSED. evolve_step's siblings.
    lineage AS (
        SELECT l.id, 'hull:step_lineage'::text AS via
          FROM public.claims l
         WHERE l.step_lineage_id IN (
                 SELECT c.step_lineage_id FROM public.claims c
                  WHERE c.id IN (SELECT id FROM chain) AND c.step_lineage_id IS NOT NULL)
    )
    SELECT DISTINCT id, min(via) FROM (
        SELECT id, via FROM chain UNION ALL SELECT id, via FROM lineage
    ) u GROUP BY id
$$;
```

`privatization_hull.rs` asserts the `supersedes`, the `step_lineage_id`, the `claim_versions` and the `evidence` cases independently.

**Closure traversal.** Case-normalisation is mandatory, not cosmetic: `migrations/011` documents **36,791** rows with `relationship='DERIVED_FROM'` (paraphrase → source atom) alongside lowercase `'derived_from'`, with different factor strengths. A closure matching only one case silently under-selects by tens of thousands of rows.

```sql
CREATE OR REPLACE FUNCTION public.epigraph_privatization_closure(
    p_seeds uuid[], p_edge_types text[], p_direction text,
    p_max_depth int, p_node_cap int
) RETURNS TABLE (claim_id uuid, depth int, via text)
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    WITH RECURSIVE norm AS (SELECT array_agg(lower(t)) AS t FROM unnest(p_edge_types) AS t),
    walk AS (
        SELECT s AS id, 0 AS depth, 'seed'::text AS via, ARRAY[s] AS path
          FROM unnest(p_seeds) AS s
        UNION ALL
        SELECT nxt.id, w.depth + 1, 'closure:' || lower(nxt.rel), w.path || nxt.id
          FROM walk w
          CROSS JOIN LATERAL (
              SELECT e.target_id AS id, e.relationship AS rel
                FROM public.edges e, norm
               WHERE p_direction IN ('out','both')
                 AND e.source_id = w.id AND e.source_type = 'claim'
                 AND e.target_type = 'claim' AND lower(e.relationship) = ANY(norm.t)
              UNION ALL
              SELECT e.source_id AS id, e.relationship AS rel
                FROM public.edges e, norm
               WHERE p_direction IN ('in','both')
                 AND e.target_id = w.id AND e.target_type = 'claim'
                 AND e.source_type = 'claim' AND lower(e.relationship) = ANY(norm.t)
          ) nxt
         WHERE w.depth < p_max_depth
           AND NOT nxt.id = ANY(w.path)   -- path-array containment, matching
                                          -- repos/lineage.rs:240-245's idiom
    )
    SELECT id, MIN(depth)::int, MIN(via) FROM walk GROUP BY id LIMIT p_node_cap
$$;
```

**Edge-type tiers, and the defaults each way:**

| Tier | Edge types | Direction | Default | Rationale |
|---|---|---|---|---|
| **Restatement** | `decomposes_to`, `derived_from` / `DERIVED_FROM` | `both` | **on** | These mean *"this claim restates that one"*. Leaving either end public leaks the other's content verbatim. |
| **Epistemic** | `supports`, `contradicts`, `corroborates`, `alternative_of` | `out` | off | Semantic adjacency, not restatement. Cascades unboundedly — a 12-claim seed becomes 40k nodes at depth 3. |
| **Structural** | `within_frame`, `scoped_by`, `member_of`, `perspective_of` | — | **never** | Point at frames/perspectives/communities, which are containers. `closure.edge_types` containing any of these returns **400**. |

**Cost and the resumability boundary.** Per level the planner does one nested loop over `idx_edges_source (source_id, source_type)` and, for `both`, `idx_edges_target (target_id, target_type)` (`001:2531,2543`). Cost is `O(|frontier| × avg_degree)` index probes per level. But the recursive CTE materializes everything in one statement with no resumability. Therefore:

- **Estimate first.** Run the closure with `p_max_depth = 1` and multiply by the observed branching factor. If `est > 50_000`, refuse the single-statement form.
- **Above 50k: frontier iteration in `epigraph-privatize`.** One transaction per level; `INSERT … ON CONFLICT (plan_id,kind,entity_id) DO NOTHING`; the next level reads `WHERE depth = $level`. Dedup is the PK; no path array; `cursor_depth` makes *selection* resumable across a `kill -9`.
- `SET LOCAL statement_timeout = '120s'` on the single-statement form. A timeout demotes the plan to `state='draft'`. **Never a partial plan.**
- `node_cap` hard maximum 250,000; `max_depth` hard maximum 6. Exceeding either is a **400, not a truncation**.

### 077_privatization_guards.sql

```sql
SET LOCAL lock_timeout = '3s';

-- One target group per plan, and seal requires a KEYED group with a live epoch.
-- ALSO enforces §6.6's hardened condition 3: a target group that is brand new
-- and solely administered by the actor is a SEIZURE VEHICLE (sec F4) --
-- POST /api/v1/groups needs only groups:write, and create_with_admin inserts
-- the creator as role='admin', so a rogue instance admin manufactured a
-- compliant target group in one request.
CREATE OR REPLACE FUNCTION public.epigraph_privatization_plan_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE k text; g_created timestamptz; ep int; n_other_admins int;
BEGIN
    SELECT kind, created_at INTO k, g_created FROM public.groups
     WHERE id = NEW.target_group_id AND status = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'privatization: target group % is absent or not active',
                        NEW.target_group_id;
    END IF;
    -- MATURITY. A group younger than 24 h cannot be a privatization target.
    IF g_created > now() - interval '24 hours' THEN
        RAISE EXCEPTION 'privatization: target group % is less than 24h old; a '
                        'privatization target must pre-exist the plan',
                        NEW.target_group_id USING ERRCODE = '42501';
    END IF;
    -- PLURALITY. At least two live admins OTHER than the plan author.
    SELECT count(*) INTO n_other_admins FROM public.group_memberships
     WHERE group_id = NEW.target_group_id AND role = 'admin'
       AND revoked_at IS NULL AND agent_id <> NEW.created_by;
    IF n_other_admins < 2 THEN
        RAISE EXCEPTION 'privatization: target group % has % live admin(s) other '
                        'than the plan author; at least 2 are required',
                        NEW.target_group_id, n_other_admins USING ERRCODE = '42501';
    END IF;
    IF NEW.mode = 'seal' THEN
        IF k <> 'team' THEN
            RAISE EXCEPTION 'privatization: mode=seal requires a keyed group '
                            '(kind=team); % is kind=%', NEW.target_group_id, k;
        END IF;
        SELECT epoch INTO ep FROM public.group_key_epochs
         WHERE group_id = NEW.target_group_id AND status = 'active';
        IF NOT FOUND THEN
            RAISE EXCEPTION 'privatization: group % has no active key epoch',
                            NEW.target_group_id;
        END IF;
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS privatization_plan_guard ON public.privatization_plans;
CREATE TRIGGER privatization_plan_guard
    BEFORE INSERT OR UPDATE OF target_group_id, mode ON public.privatization_plans
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_privatization_plan_guard();

-- The approver must be an admin OF THE TARGET GROUP, not merely a different
-- instance admin (sec F4). Two instance admins who share no group cannot
-- rubber-stamp each other's seizures.
CREATE OR REPLACE FUNCTION public.epigraph_privatization_approver_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.approved_by IS NOT NULL
       AND NOT public.epigraph_is_group_admin(NEW.target_group_id, NEW.approved_by) THEN
        RAISE EXCEPTION 'privatization: approver % is not an admin of target group %',
                        NEW.approved_by, NEW.target_group_id USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS privatization_approver_guard ON public.privatization_plans;
CREATE TRIGGER privatization_approver_guard
    BEFORE UPDATE OF approved_by ON public.privatization_plans
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_privatization_approver_guard();

-- (public, Sealed) is FORBIDDEN, IN BOTH DIRECTIONS (sec F11).
-- Direction 1: sealing a public claim. Note the trigger is BEFORE INSERT OR
-- UPDATE (not "OF claim_id"), so a re-point of an existing row also fires.
CREATE OR REPLACE FUNCTION public.epigraph_no_public_sealed() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE v text;
BEGIN
    SELECT visibility INTO v FROM public.claims WHERE id = NEW.claim_id;
    IF v = 'public' THEN
        RAISE EXCEPTION 'privatization: refusing to seal claim % while it is '
                        'visibility=public. Restrict first, then seal.', NEW.claim_id
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS claim_encryption_no_public_sealed ON public.claim_encryption;
CREATE TRIGGER claim_encryption_no_public_sealed
    BEFORE INSERT OR UPDATE ON public.claim_encryption
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_no_public_sealed();
-- Direction 2: declassifying a sealed claim. Lives in
-- epigraph_claims_block_widening arm (a), migration 070 -- unconditional, no
-- GUC override. `seal_side_channels.rs` covers both directions.
```

`restrict` therefore works against any active, mature, plurally-administered group including `kind='personal'` / `'community'`; `seal` additionally requires `kind='team'` with a live epoch. **Ordering follows from the ban: restrict-then-seal is the only legal order.**

### 078_privatization_audit.sql — append-only, admin-only, plus `security_events` hardening

```sql
SET LOCAL lock_timeout = '3s';

CREATE TABLE IF NOT EXISTS public.privatization_audit (
    id             bigserial PRIMARY KEY,
    plan_id        uuid NOT NULL REFERENCES public.privatization_plans(id) ON DELETE RESTRICT,
    actor_agent_id uuid NOT NULL REFERENCES public.agents(id) ON DELETE RESTRICT,
    action         text NOT NULL,   -- 'plan.create'|'plan.approve'|'plan.dispatch'
                                    -- |'item.apply'|'item.skip'|'item.reassign'
                                    -- |'item.seal'|'item.unseal'|'item.revert'
                                    -- |'plan.abort'|'plan.drift'
    kind           text, entity_id uuid,
    before_visibility text, before_owner_group_id uuid, before_sealed boolean,
    after_visibility  text, after_owner_group_id  uuid, after_sealed  boolean,
    plan_digest    bytea,
    correlation_id varchar(64),     -- matches security_events.correlation_id
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_privatization_audit_entity
    ON public.privatization_audit (entity_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_privatization_audit_plan
    ON public.privatization_audit (plan_id, created_at DESC);

CREATE OR REPLACE FUNCTION public.epigraph_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only (attempted % on id=%)',
                    TG_TABLE_NAME, TG_OP, OLD.id;
END $$;
DROP TRIGGER IF EXISTS privatization_audit_no_mutate ON public.privatization_audit;
CREATE TRIGGER privatization_audit_no_mutate
    BEFORE UPDATE OR DELETE ON public.privatization_audit
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_audit_immutable();

-- THE SAME TRIGGER ON security_events (sec F17). The plaintext-egress record
-- must not live in a table the app role can DELETE FROM while the immutable
-- table sits next to it.
DROP TRIGGER IF EXISTS security_events_no_mutate ON public.security_events;
CREATE TRIGGER security_events_no_mutate
    BEFORE UPDATE OR DELETE ON public.security_events
    FOR EACH ROW EXECUTE FUNCTION public.epigraph_audit_immutable();

-- RLS: readable only by instance admins and epigraph_maintenance.
-- privatization_audit.entity_id is A COMPLETE INDEX OF EVERY PRIVATE CLAIM ID
-- IN THE INSTANCE.
ALTER TABLE public.privatization_audit ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS privatization_audit_read ON public.privatization_audit;
CREATE POLICY privatization_audit_read ON public.privatization_audit FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR (public.epigraph_is_instance_admin((SELECT public.epigraph_principal_id()))
            -- ROW-LEVEL SCOPING (sec F7c, adopted in a modified form): an
            -- instance admin sees plan-level rows for every plan, but ENTITY
            -- ids only for plans whose target group they administer. See §6.5.8
            -- for why the route survives rather than moving to a CLI.
            AND (entity_id IS NULL
                 OR public.epigraph_is_group_admin(
                      (SELECT p.target_group_id FROM public.privatization_plans p
                        WHERE p.id = privatization_audit.plan_id),
                      (SELECT public.epigraph_principal_id())))));
DROP POLICY IF EXISTS privatization_audit_append ON public.privatization_audit;
CREATE POLICY privatization_audit_append ON public.privatization_audit FOR INSERT TO PUBLIC
    WITH CHECK ((SELECT public.epigraph_bypass()));
```

**Where the record of authority lives, said once.** `privatization_audit` is the record of authority for every privatization action; `security_events` is the cross-cutting actor log that a login, a token mint and a privatization all land in, so an auditor can read one timeline per principal. Both are now immutable and both are RLS-protected; neither is the weak copy of the other. `seal_manifest` writes to **both**, because it is simultaneously a privatization action and a plaintext egress event.

**Retention: never GC'd.** `prune_recall_events.rs` is the precedent for retention; both audit tables are explicitly exempt.

### 079_instance_admins.sql — the D4 authority

```sql
SET LOCAL lock_timeout = '3s';
CREATE TABLE IF NOT EXISTS public.instance_admins (
    agent_id   uuid PRIMARY KEY REFERENCES public.agents(id) ON DELETE RESTRICT,
    granted_by uuid          REFERENCES public.agents(id) ON DELETE SET NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    note       text
);
CREATE INDEX IF NOT EXISTS idx_instance_admins_live ON public.instance_admins (agent_id)
    WHERE revoked_at IS NULL;

CREATE OR REPLACE FUNCTION public.epigraph_is_instance_admin(p_agent uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT p_agent IS NOT NULL AND EXISTS (
        SELECT 1 FROM public.instance_admins
         WHERE agent_id = p_agent AND revoked_at IS NULL)
$$;
REVOKE EXECUTE ON FUNCTION public.epigraph_is_instance_admin(uuid) FROM PUBLIC;
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='epigraph_app') THEN
  GRANT EXECUTE ON FUNCTION public.epigraph_is_instance_admin(uuid) TO epigraph_app;
  REVOKE INSERT, UPDATE, DELETE ON public.instance_admins FROM epigraph_app;
  GRANT  SELECT ON public.instance_admins TO epigraph_app;
END IF; END $$;

ALTER TABLE public.instance_admins ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS instance_admins_self_or_admin ON public.instance_admins;
CREATE POLICY instance_admins_self_or_admin ON public.instance_admins
    FOR SELECT TO PUBLIC
    USING ((SELECT public.epigraph_bypass())
        OR agent_id = (SELECT public.epigraph_principal_id())
        OR public.epigraph_is_instance_admin((SELECT public.epigraph_principal_id())));
-- No INSERT/UPDATE/DELETE policy: default deny. Grants are an operator action
-- through epigraph-instance-admin over epigraph_maintenance. Recorded in
-- rls_enforcement.rs's DELIBERATELY_UNCOVERED table.
```

**Migration 079 seeds nothing.** An empty `instance_admins` means nobody can privatize — the correct fail-closed initial state for a corpus that starts public.

### 080_retire_ownership.sql — last, one release later

```sql
SET LOCAL lock_timeout = '3s';
-- Pre-flight 1: the encryption_key_id quarantine must be empty. It is a VIEW
-- (064), so this is always current, and the ownership_key_id_is_uuid CHECK has
-- prevented new unparseable values since 064.
DO $$ DECLARE n bigint; BEGIN
    SELECT count(*) INTO n FROM public.ownership_key_id_quarantine;
    IF n > 0 THEN
        RAISE EXCEPTION 'refusing to DROP ownership: % quarantined encryption_key_id '
                        'rows are untriaged', n;
    END IF;
END $$;

-- Pre-flight 2 (D1): no ownership row may exist whose declaration was never
-- transcribed into a column. node_type IN ('agent','perspective','community',
-- 'context','frame') rows had nowhere to go before migration 061 widened
-- frames/contexts/perspectives/communities -- which is exactly why that
-- widening exists.
DO $$ DECLARE n bigint; BEGIN
    SELECT count(*) INTO n FROM public.ownership o
     WHERE o.partition_type <> 'public'
       AND NOT EXISTS (SELECT 1 FROM public.tenancy_transcription_log l
                        WHERE l.node_id = o.node_id);
    IF n > 0 THEN
        RAISE EXCEPTION 'refusing to DROP ownership: % non-public rows were never '
                        'transcribed to a visibility column', n;
    END IF;
END $$;

-- ONE-WAY DOOR. docs/runbooks/080-undo.sql exists only to RECREATE THE EMPTY
-- SHAPE; the rows are not recoverable. Executed as the schema owner.
DROP TRIGGER IF EXISTS ownership_write_through ON public.ownership;
DROP VIEW  IF EXISTS public.ownership_key_id_quarantine;
DROP TABLE IF EXISTS public.ownership;
```

> **Verify before writing the backfill** (§10.2 M1): `SELECT node_type, partition_type, count(*) FROM ownership GROUP BY 1,2 ORDER BY 3 DESC;` — `map-ownership-partitions.md` §6 establishes that **no write path ever inserts an `ownership` row**: `rg "INSERT INTO ownership|OwnershipRepository::assign"` hits only `repos/ownership.rs:105`, `routes/ownership.rs:97`, `tools/perspectives.rs:196`, and five test fixtures. Expected result: **0 rows**.

> **`cargo sqlx prepare` summary.** Required only where a `sqlx::query!` / `query_as!` / `query_scalar!` macro changes. `repos/claim.rs` has **24** macro call sites (**23** `query!` + **1** `query_scalar!`). Read-path ones affected: `get_by_id` (:517), `get_by_id_with_labels` (:583), `get_by_id_conn` (:1372), `enumerate_current_embedded` (:4854), `nearest_neighbors_of_claim` (:4902), `content_hashes_for` (:4945). Write-path ones: `create` (:228), `create_with_tx` (:440), `batch_create` (:1972), **and `consolidate` (:4653, `sqlx::query_scalar!`) — the one the previous revision's list omitted (ops F1)**. The ANN/hybrid/lexical paths — `search_by_embedding_scoped` (:782), `search_hybrid_scoped_since` (:910), `search_lexical_scoped_since` (:1004), `list_by_labels` (:1628), `contents_by_ids` (:1553), `find_claims_needing_embeddings` (:2697) — all use runtime `sqlx::query_as::<_,T>` and need **no** prepare. Run `DATABASE_URL=… cargo sqlx prepare --workspace -- --tests` and commit `.sqlx/` (**117** files today) in PR-06 and PR-16.

---

## 4. Enforcement plan

### 4.1 Chokepoints, layered — read side and write side

**Read side (who may see a row):**

| # | Chokepoint | Catches | Fails |
|---|---|---|---|
| 1 | The inline visibility fragment inside repo SQL | every query that goes through the repo layer | **closed** — row absent |
| 2 | `viewer: &Viewer` as a **required** parameter, with **no infallible constructor** | every caller, at compile time, exactly once | build error |
| 3 | `visibility_lint.rs`, with `PROTECTED` **generated** from §2.4 | a repo function that forgets the fragment; a *new table* nobody added to a list | build error |
| 4 | `no_inline_sql_in_tools.rs` | a tool that bypasses the repo layer (CLAUDE.md violation) | build error |
| 5 | `ViewerExtractor` — the only way an HTTP handler obtains a `Viewer` | a request with no principal reaching a handler body | **401 + RFC 6750 challenge, before body parse** |
| 6 | `FORCE ROW LEVEL SECURITY` | anything reaching the DB outside the repo layer: psql, a new crate, a migration script, an analytics job, a federated tool | **closed** — row absent |
| 7 | RLS canary + the six boot assertions + the §0.5 session-GUC probe | RLS silently not in force; a transaction pooler silently emptying the GUCs | process refuses to serve |

**Write side (D1 — who may create a row, and may it be undeclared):**

| # | Chokepoint | Catches | Fails |
|---|---|---|---|
| W1 | `NOT NULL` with **no `DEFAULT`** on every tier-A tenancy column | any INSERT naming neither column and hitting no inheritance arm | `23502` |
| W2 | `epigraph_claims_require_tenancy()` `BEFORE INSERT` | the same, with a diagnosable message; and a successor trying to *widen* (via `supersedes` **or** `step_lineage_id`) | `23502` / `42501` |
| W3 | Table `CHECK`s: `visibility IN ('public','group')`, the pairing invariant, the co-owner shape | a black-hole row or an unknown visibility value | `23514` |
| W4 | `epigraph_claims_block_widening()` `BEFORE UPDATE` — arm (a) sealed-unconditional, arm (b) declassify-GUC | a silent `group → public` declassification; a `(public, Sealed)` stub | `42501` |
| W5 | RLS `WITH CHECK (owner_group_id = ANY(epigraph_writable_groups()))` | a `reader`-role member writing into their group, *including publicly* | `42501` |
| W6 | `entity_types.tenancy_tier` precondition check in the registration handler + `tenancy_coverage.rs` | a newly-registered entity type with no visibility declaration | 400 / build error |
| W7 | Boot assertion `pg_trigger.tgenabled = 'O'` on every tenancy trigger | someone disabled a trigger or set `session_replication_role='replica'` | process refuses to serve |
| W8 | `jobs_app` RLS policy + the handler's own re-validation (§6.5.5) | an unprivileged `INSERT INTO jobs` dispatching an unapproved privatization with full bypass | `42501` / handler refusal |

Read layers 1–5 and write layers W1–W5 are the primary mechanism. Read 6–7 and W7–W8 are the backstop. **Both are mandatory.**

The step from the draft is layer 2. In the draft, `Viewer` had an infallible constructor (`Viewer::anonymous()`), so "unauthenticated ⇒ no `Viewer`" was a review convention. With `Anonymous` deleted, `Viewer` has **no infallible constructor** — `Viewer::resolve(pool, principal: Uuid)` demands a `Uuid` obtainable only from an authenticated `AuthContext.agent_id`, and `Viewer::system` demands a `MaintenanceLease` only `ScopedPool::unscoped_for_maintenance` can mint. "Unauthenticated ⇒ no `Viewer` ⇒ no repo call" becomes a **compile-time fact**.

### 4.2 Why it cannot be forgotten — the specific failure this addresses

The existing model is opt-in and its measured adoption is **7 of 85** MCP tools (`grep -n mcp_requester crates/epigraph-mcp/src/server.rs` → 7 sites: 424, 438, 452, 768, 782, 796, 810; `grep -c "^    async fn " server.rs` → 85, with 83 `#[tool(` attributes), plus 4 of ~20 HTTP route modules. Adding the missing calls fixes today's 78 and leaves the mechanism intact, so tool 86 leaks. The A3/A5 pass already ran that experiment and left a comment at `routes/mod.rs:794-796` claiming one bypass remained while a dozen anonymous handlers returned claim content. **That comment, and the matching one at `bearer.rs:63-65`, must be deleted in the same commit that inverts the router.**

Layer 3 is the piece the previous pass lacked, and it now has a generated table list rather than a literal:

```rust
// crates/epigraph-db/tests/visibility_lint.rs
//
// Fails the build if any SQL literal in crates/epigraph-db/src/repos/ SELECTs
// from a protected table without the visibility predicate. An exemption
// requires the literal marker `-- VISIBILITY-EXEMPT: <reason>` INSIDE the SQL,
// so it appears in every diff and every review.
//
// PROTECTED IS NOT A LITERAL LIST. It is computed at test time by running
// §2.4's Generator A and Generator B against the live epigraph_db_repo_test,
// unioned with the manually-registered additions (harvester_fragments) and the
// D4 tables, minus the `tenancy_exempt` rows. That is what makes the previous
// revision's eight-table omission (challenges, reasoning_traces,
// experiment_triples, experiment_entity_mentions, claim_clusters,
// claim_cluster_membership, claim_neighborhood_membership,
// claim_signature_revocations) impossible to repeat.
fn protected_tables(pool: &PgPool) -> BTreeSet<String>;

#[test] fn every_protected_select_carries_the_visibility_predicate();
#[test] fn every_protected_table_has_a_forced_policy();      // relforcerowsecurity
#[test] fn every_protected_table_covers_all_four_commands(); // pg_policy.polcmd
```

This is a text lint, not a type system, and it is not dressed up as one. It is the only mechanism that survives the failure mode actually measured here.

### 4.3 `Viewer` — two shapes, no anonymous, no forgeable bypass

The draft gave `Viewer` three shapes and justified `Anonymous` twice — first on partial-index-predicate grounds, then on RLS-implication grounds. **Both justifications are about the SQL a shape emits, and D3 removes every caller that could emit it.**

The "keep it but make it match nothing" option is rejected on three grounds:

1. **It is invisible to the entire test strategy.** §8's adversarial suite is written as *"assert a stranger CANNOT read"*. A `Viewer` that over-restricts passes every one of those tests, producing silent, permanent empty result sets — R2's *"fail-closed regressions look like data loss, not errors"*. (This is the same blind spot §0.5 closes for the FORCE/GUC case, and it is why §8.4 now carries a positive class.)
2. **It defeats the ratchet design.** A second ratchet on `Viewer::anonymous()` would have to go *up* on some routes and *down* on others, so there is no monotone invariant.
3. **Deletion moves the check from runtime to the type system.**

```rust
// crates/epigraph-db/src/visibility.rs   (NEW, ~180 LOC)

/// Read authority for one principal, for one request.
///
/// INVARIANTS, enforced by construction:
///   * No `Default`, no `From<Option<Uuid>>`, no `From<&AuthContext>`,
///     no zero-argument `unrestricted()`.
///   * D3: there is NO anonymous shape. A caller without an `agents.id` cannot
///     build a `Viewer` at all; the 401 happens in the extractor.
///   * The only unrestricted shape requires a `MaintenanceLease`, which only
///     `ScopedPool::unscoped_for_maintenance` can mint.
#[derive(Clone, Debug)]
pub struct Viewer { shape: ViewerShape }

#[derive(Clone, Debug)]
enum ViewerShape {
    /// An authenticated `agents.id` plus its live group set.
    /// `group_ids` ALWAYS contains the principal's personal group.
    /// `writable` is the subset where role >= writer.
    Scoped { principal: Uuid, group_ids: Vec<Uuid>, writable: Vec<Uuid> },
    /// UNRESTRICTED. Background jobs and CLI bins only, ON A MAINTENANCE
    /// CONNECTION. Unconstructible without a `MaintenanceLease`.
    Bypass { reason: SystemReason },
}

/// Closed set of legitimate bypass reasons. A `&'static str` ratchet is a grep
/// over source text, defeated by `concat!`, a `const REASON`, or a macro. A
/// closed enum makes the ratchet `SystemReason::ALL.len()`, makes "add a
/// bypass" a visible enum diff, and makes the exhaustiveness test a `match`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SystemReason {
    EmbeddingBackfill,
    BeliefRecomputation,
    DedupSweep,
    ThemeClustering,
    TenancyBackfill,
    PrivatizationSelection,   // D4 preview: selection must be unfiltered to be correct
    PrivatizationApply,       // D4: the job handler, on the maintenance pool
    PrivatizationReseal,      // §6.7
    SchemaContractTest,
    RlsCanaryProbe,
}
impl SystemReason { pub const ALL: &'static [SystemReason] = &[ /* … */ ]; }

/// Proof that the caller holds a maintenance-role connection.
/// Minted ONLY by `ScopedPool::unscoped_for_maintenance(reason)`.
/// Not `Clone`, not `Copy`, no public constructor.
pub struct MaintenanceLease(pub(crate) ());

impl Viewer {
    /// The ONLY constructor reachable from a request path. ONE round trip:
    ///   SELECT group_id, role FROM group_memberships
    ///    WHERE agent_id = $1 AND revoked_at IS NULL
    /// Always unions in the principal's personal group.
    pub async fn resolve(pool: &PgPool, principal: Uuid) -> Result<Self, DbError>;

    pub fn system(_lease: &MaintenanceLease, reason: SystemReason) -> Self;

    /// Test-only. `#[cfg(test)]` on the DEFINITION, not behind a cargo feature —
    /// a feature can be enabled from a dependent crate's build.
    #[cfg(test)]
    pub fn test_scoped(principal: Uuid, group_ids: Vec<Uuid>) -> Self;

    /// TWO fragments, not three. `{alias}` is substituted by the caller; `$V` is
    /// the single optional bind.
    ///
    /// The `Scoped` fragment is written INLINE (no `epigraph_visible()` call).
    /// Its disjuncts are ORDERED: the literal `visibility = 'public'` FIRST, so
    /// that (a) it is cheap-first for the executor, and (b) it syntactically
    /// matches the leading disjunct of the RLS policy USING clause in migration
    /// 073 — see §4.5.
    pub const fn predicate_fragment(&self) -> &'static str {
        match self.shape {
            ViewerShape::Scoped { .. } =>
                " AND ({alias}.visibility = 'public' \
                       OR {alias}.owner_group_id = ANY($V::uuid[])) ",
            ViewerShape::Bypass { .. } => " ",
        }
    }
    /// The edges variant carries the co-ownership INTERSECTION (migration 068).
    pub const fn edge_predicate_fragment(&self) -> &'static str;

    pub fn group_bind(&self) -> Option<&[Uuid]>;
    /// `Some` for `Scoped`, `None` for `Bypass`. NOT flattened to `Option<Uuid>`
    /// as a convenience target — callers must `match`.
    pub fn principal(&self) -> Option<Uuid>;
    pub fn writable_groups(&self) -> &[Uuid];
}
```

**Note the type of `Viewer::system`.** The draft had `system(reason: &'static str)` freely callable. That is *unsound* once RLS is FORCEd: a `Bypass` viewer emits no predicate, but the database policy still filters, so `Viewer::system(...)` on an ordinary `epigraph_app` connection returns **zero rows**, not all rows. `MaintenanceLease` makes the coupling unforgeable.

Applied to `ClaimRepository::search_hybrid_scoped_since` (`repos/claim.rs:910`), the predicate lands **inside both CTEs, above both `LIMIT $3`**:

```sql
WITH dense AS (
    SELECT c.id,
           row_number() OVER (ORDER BY c.embedding <=> $1::vector) AS rank,
           1 - (c.embedding <=> $1::vector) AS cos
    FROM claims c
    WHERE c.embedding IS NOT NULL AND c.is_current
      AND ($6::text[] IS NULL OR c.labels @> $6::text[])
      AND ($7::uuid   IS NULL OR c.agent_id = $7::uuid)
      AND ($8::timestamptz IS NULL OR c.created_at >= $8::timestamptz)
      /* {VISIBILITY:c} */
    ORDER BY c.embedding <=> $1::vector
    LIMIT $3
),
lex AS (
    -- NOTE the FROM shape. Do NOT write
    --   FROM claims c, websearch_to_tsquery('english', $2) q JOIN ownership o ...
    -- The JOIN binds to `q`, putting `c` out of scope in the ON clause, and
    -- PostgreSQL raises "invalid reference to FROM-clause entry for table c".
    -- With tenancy denormalised onto claims there is no join at all.
    SELECT c.id,
           row_number() OVER (ORDER BY ts_rank_cd(c.content_tsv, q) DESC) AS rank
    FROM claims c, websearch_to_tsquery('english', $2) q
    WHERE c.content_tsv @@ q AND c.is_current
      AND ($6::text[] IS NULL OR c.labels @> $6::text[])
      AND ($7::uuid   IS NULL OR c.agent_id = $7::uuid)
      AND ($8::timestamptz IS NULL OR c.created_at >= $8::timestamptz)
      /* {VISIBILITY:c} */
    ORDER BY ts_rank_cd(c.content_tsv, q) DESC
    LIMIT $3
)
...
```

Two consequences worth naming. The predicate is applied **before** `LIMIT`, so page 1 of 10 results returns 10, not 3. And it lands in the `lex` CTE, closing the `content_tsv` GIN leak that `recall`'s embedder-down fallback reaches (`tools/memory.rs:305` → `claim.rs:1004`) — a leak that encrypting `content` would never have touched, because `content_tsv` is `GENERATED ALWAYS` and cannot be selectively withheld at the column level.

### 4.4 The extractor — where the 401 happens, and what it must carry

```rust
// crates/epigraph-api/src/middleware/bearer.rs  (extend)

/// FromRequestParts extractor. The ONLY way an HTTP handler obtains a Viewer.
/// Handlers take `viewer: Viewer`, never `Option<Viewer>`.
///
/// 401 (RFC 6750 `invalid_token`) when:
///   - no AuthContext in extensions        → no credential
///   - AuthContext.agent_id is None        → credential with no principal
/// The second case is NOT 403: the token is structurally deficient and the
/// remedy is to re-mint it, which is what `invalid_token` tells the client.
///
/// Emits `visibility.viewer.rejected{reason, route}` on every 401.
pub struct ViewerExtractor(pub Viewer);
```

**The 401 must carry a `WWW-Authenticate` challenge (ops F15).** Verified: `ApiError::Unauthorized` (`crates/epigraph-api/src/errors.rs:80-84`) returns a bare JSON body — `(StatusCode::UNAUTHORIZED, "Unauthorized", Some(json!({"reason": reason})))` — with **no header**. RFC 6750 §3 *requires* the challenge, and the RFC 9728 `resource_metadata` form exists only in `crates/epigraph-mcp/src/auth.rs` (`challenge_header` at `:132-140`, `unauthorized` at `:155-165`) and was never ported. Turning 104 routes into 401s without it gives every OAuth/MCP client an undiscoverable failure. **PR-03 ports `challenge_header` into `epigraph-api`'s `IntoResponse` for `Unauthorized`, `InvalidSignature` and `SignatureError`**, with the resource-metadata URL from `ApiConfig`, and the same boot-time `validate_resource_metadata_url` fail-fast.

Handlers change shape from `auth_ctx: Option<axum::Extension<AuthContext>>` — the fail-open idiom `if let Some(axum::Extension(ref auth)) = auth_ctx { check_scopes(…) }`, verified at **39** sites — to `ViewerExtractor(viewer): ViewerExtractor`. Because `FromRequestParts` runs before any `FromRequest` body extractor (documented at `bearer.rs:106-113`), the 401 lands before body parse.

**Tier-B projection (`agents`).** `AgentRepository::get_public_profile(pool, viewer, id)` returns `properties`, `orcid`, `ror_id` only when `profile_visibility='public'`, or the viewer *is* the agent, or the viewer shares a live group with it. `id`, `display_name`, `public_key`, `key_kind` are always returned. Repo-layer projection, not RLS, because column-level RLS does not exist; the row policy in 073 is `USING (true)` with an explicit `-- VISIBILITY-EXEMPT:` marker.

**In-repo clients must be fixed with the router.** `scripts/_api_client.py:42-48` mints tokens with `agent_id: Optional[uuid.UUID] = None` and a hardcoded `DEFAULT_CLIENT_ID` (verified). Every bootstrap script it backs 401s under `ViewerExtractor` until PR-02 populates `oauth_clients.agent_id` **and** `mint_bearer_token` emits the claim. **`scripts/_api_client.py` is in PR-03's file list** — it is the client-side half of §4.7 path B.

### 4.5 Qual/GUC coherence, and the mechanism that makes it hold (sec F1)

The property: *the app-emitted qual implies the RLS policy's disjunct, so the RLS filter can never reject a row the index returned.* Under D3 that transfers from `Anonymous` to `Scoped` **only if `$V` and the `epigraph.group_ids` GUC hold the same set**. They are populated by two different code paths (`Viewer::resolve` → bind; `ScopedPool` → `set_config`). If they drift, RLS silently drops rows: fail-closed, invisible, indistinguishable from data loss.

**The previous revision's `qual_guc_coherence.rs` tested that `$V` and the GUC agree *inside* `begin_as` — and §0.3 of that same document said `begin_as` was not on the hot path. The test could not detect the case where the GUCs were never set at all, which was the normal case.** §0.5 fixes the mechanism; this section fixes the test.

**Requirements:**

1. **Both `acquire_as` and `begin_as` take the `Viewer` itself** and emit the identical `set_config` triple from the *same* `Viewer` value that supplies `$V`. A `Viewer` may not be constructed and then a connection acquired from a different one — enforced by making the GUC-emitting code a private function taking `&Viewer`, with no other caller.
2. **`begin_as` carries a `debug_assert` that the connection is inside a transaction** — `set_config(…, is_local = true)` is a silent no-op on a pooled connection.
3. **`after_release` scrubs, and closes the connection if the scrub fails.**

`crates/epigraph-db/tests/qual_guc_coherence.rs`:

- for a `Scoped` viewer over N groups, `SELECT epigraph_session_groups()` equals `viewer.group_bind()`, sorted — **under `acquire_as`, under `begin_as`, and after a checkout/release/checkout cycle**;
- `epigraph_writable_groups()` equals `viewer.writable_groups()`, sorted;
- **the leak test:** acquire as viewer A, release, acquire again with **no** `acquire_as`, and assert `epigraph_session_groups()` is empty — i.e. the scrub ran;
- **the positive test (the class §8.4 lacked):** with `FORCE` on, a `Scoped` viewer over group G reads back exactly its own N group-private claims through `acquire_as`, at every one of the 17 `claim.rs` read functions.

### 4.6 Write-side call sites — what breaks when the DEFAULT is dropped

`rg "INSERT INTO claims" --type rust`, with `#[cfg(test)]` module boundaries resolved by brace-matching, not by grep. In `repos/claim.rs` the two test modules span lines **3704–4018** and **4152–4443**, which is how the sites at 3722/3736/3750/3790/3804 and 4171/4366/4376 are excluded — and it is how the previous revision's *twelve* becomes **thirteen**.

**Production: 13 statements.**

| # | Site | Function | What it needs |
|---|---|---|---|
| 1 | `repos/claim.rs:228` | `ClaimRepository::create` | Add `visibility, owner_group_id` from a new `TenancyDecl` param. `sqlx::query!` → **prepare** |
| 2 | `repos/claim.rs:440` | `create_with_tx` | same; `sqlx::query!` → **prepare** |
| 3 | `repos/claim.rs:1972` | `batch_create` | same; `sqlx::query!` → **prepare** |
| 4 | `repos/claim.rs:2203` | `supersede` (fn at `:2139`) | **No change** — `supersedes` is bound, so trigger arm 2 inherits. Add a test asserting a private predecessor yields a private successor (`map-ownership-partitions.md` gap 11) |
| 5 | `repos/claim.rs:2340` | `create_strict` (reached by `create_or_get:2420`, which `routes/submit.rs:1079` `persist_packet` calls) | Add both columns. Runtime `sqlx::query_as` → no prepare |
| 6 | `repos/claim.rs:2472` | `create_with_id_if_absent` | Add both columns. Runtime → no prepare |
| 7 | `repos/claim.rs:2900` | `evolve_step` (fn at `:2845`) | Binds `step_lineage_id` → trigger arm 3 covers it. **Prefer explicit:** read the lineage head's tenancy in the same tx and bind it |
| 8 | **`repos/claim.rs:4653`** | **`ClaimRepository::consolidate`** (fn at `:4544`) | **MISSED BY THE PREVIOUS REVISION (ops F1).** Verified production — both `#[cfg(test)]` blocks close before it — and live via MCP `consolidate_claims`. Binds **neither `supersedes` nor `step_lineage_id`** (predecessors are retired separately, *after* the insert), so at migration 070 it falls through arms 1–3 to arm 5 and raises `23502`. `sqlx::query_scalar!` → **prepare** (the previous revision's list said "`create`, `create_with_tx`, `batch_create`", so CI would have failed with "no cached data for this query"). **And it needs a tenancy rule**, see below |
| 9 | `crates/epigraph-ingest-executor/src/workflow_steps.rs:212` | `add_step` | Binds `step_lineage_id` → arm 3. Crate is pure-DB; takes a `TenancyDecl` from its caller |
| 10 | `crates/epigraph-api/src/routes/hypothesis.rs:55` | `create_hypothesis` | Explicit declaration from `AuthContext`. Also on CLAUDE.md's embedding-inline list |
| 11 | `routes/policies.rs:163` | `create_challenge` | Explicit declaration from `AuthContext` |
| 12 | `crates/epigraph-cli/src/bin/hypothesis.rs:111` | `create` | CLI: `--group <uuid>` / `--public`, **required flag, no default** |
| 13 | `crates/epigraph-cli/src/bin/method_search.rs:220` | `run` | Same. This site has **no `agent_id`** in its column list — it must acquire one before it can name an owner group |

**`consolidate`'s tenancy rule, which no prior revision states.** `consolidate` merges 2..N claims that may span groups, and the merged row's tenancy is undefined. Left alone it would be a *widening* primitive: merge one private and one public claim and the result is whatever the trigger falls through to. The rule:

```
merged.visibility     = 'group' if ANY source is 'group', else 'public'
merged.owner_group_id = the single distinct owner among 'group'-visible sources
                        (if sources span two or more DIFFERENT groups → REFUSE, 409)
                        else the acting agent's personal group
```

Refusing the cross-group merge is correct and is not a regression: merging claims owned by two groups into one row is a disclosure to both, and neither group authorized it. `consolidate_claims`'s MCP scope stays `claims:write`; the cross-group case returns an error naming the two groups.

**Tests: 160 statements across 120 files** — `epigraph-mcp` 33, `epigraph-db` 27, `epigraph-engine` 25, `epigraph-api` 15, `epigraph-cli` 12, `epigraph-jobs` 3, plus `tests/engine-integration/src/harness.rs`, two Python files under `tests/theme/`, and the SQL fixture `crates/epigraph-jobs/tests/fixtures/seed_two_cliques.sql:25`. These are what arm 4 (`epigraph_seed`) exists for. (§10.1 Q3 asks whether to pay for the edits instead.)

**Other tier-A tables:** production `INSERT INTO evidence` sites are `repos/evidence.rs:68`, `repos/evidence.rs:396`, `routes/submit.rs:1303`. `INSERT INTO edges` has 104 sites across 56 files, overwhelmingly tests — edges are covered by the endpoint-derivation trigger and need **no** call-site edits. The tables added in §2.4 (`challenges`, `reasoning_traces`, `experiment_triples`, …) are all claim-derived and are covered by 066(c)'s statement trigger, so they need no call-site edits either — which is the second strong argument for keeping that trigger.

### 4.7 The unauthenticated surface — invert the router (D3)

**How anonymity is admitted today.** `routes/mod.rs:515` opens the `public` Router; `:798-801` layers `optional_bearer_auth_middleware`. That middleware (`middleware/bearer.rs:66-103`) passes a request with **no `Authorization` header straight through with no `AuthContext`** (`bearer.rs:101`, comment: *"anonymous pass-through"*); only a *present-but-invalid* token 401s.

Counts, verified: `public` router (`mod.rs:515-780`) **109** `.route(` registrations; `protected` (`:155-490`) **125**; `oauth` (`:804-833`) **11**; total in the file **379**. A second `create_router` under `#[cfg(not(feature = "db"))]` (`mod.rs:863`, public block `:1029-1204`) mirrors the shape and **needs identical treatment** — it is the router integration tests build against.

**The rule is not "audit 104 handlers" — it is invert the split.** The `public` Router is reduced to the allowlist below and **every other registration moves into `protected`**.

| Route | `mod.rs` | Justification | Condition |
|---|---|---|---|
| `GET /health` | 516 | `health.rs:16` — takes no state, returns a static struct | none |
| `GET /metrics` | 517, **and 1031** | Prometheus text exposition. Registered on **both** router variants (verified), and there is **no second listener anywhere in `bin/server.rs`** | **Q5 (§10.1) must be decided before PR-03.** Binding it to a separate internal listener is new engineering, not a config flip; the scrape-token option is a one-day change. Do not leave it on the public listener under D3 |
| `GET /api/v1/openapi.json` | 587 | static schema | none |
| the 11 `/oauth/*` and `/.well-known/*` | 804–833 | Bootstrapping and RFC 8414/9728 discovery must precede authentication | `/oauth/register` **must stop auto-activating `client_type=agent`** and the IdP allowlist **must fail closed** (§4.9) |

Discretionary, recommended to move: `GET /api/v1/mcp/tools` (`mod.rs:780` → `mcp_tools.rs:16`) — no claim content, not a D3 violation, but the same catalog is available to an authenticated caller over MCP `list_tools`, so the anonymous copy gives a scanner a free capability map.

**The other 104 registrations move to `protected`.** Highest-value, sources verified: `POST /api/v1/search/semantic` (536 → `search.rs:430-433`, verbatim claim text corpus-wide); `GET /api/v1/query/rag` (543 → `rag.rs:256-259`, content at `:402`); `GET /lineage/:claim_id` (535); `GET /api/v1/claims` (537, plus a `content_contains` ILIKE oracle); `GET /claims`, `/claims/:id`, `/api/v1/claims/:id` (518, 519, 542); `GET /api/v1/themes/:id/embeddings` (582 → `crud.rs:1553-1589`, fail-open scope at `:1559`, ≤5000 raw 1536-d vectors); `GET /api/v1/ownership/:node_id` (665) and `/api/v1/agents/:id/owned-nodes` (667) — the ACL itself; `/api/v1/agents/:id/timeline` (532); `/api/v1/claims/:id/compound_neighborhood` (565, raw `SELECT content`); `GET /api/v1/admin/stats` (568); `GET /api/v1/groups/:id` (774); `GET /api/v1/structural-features/:owner_id` (671, §4.8); `POST /api/v1/embeddings/neighborhood-density` (696); `GET /api/v1/skills` (724, reads `claims.labels`); `GET /api/v1/claims/needing-embeddings` (539 — a **maintenance** endpoint in the anonymous router; moves behind `claims:admin`); **and `GET /api/v1/challenges` (547, `challenge::list_challenges`), which returns `challenges.explanation` for a claim (§2.4)**; plus `/api/v1/events`, `/graph/*`, `/triples/query`, `/entities/:id/neighborhood`, all `/frames/*`, all `/belief*`, `/api/v1/edges`, `/api/v1/evidence/:id`, `/api/v1/papers`, `/api/v1/perspectives*`, `/communities*`, `/contexts*`, `/workflows*`, `/methods*`, `/tasks*`, `/spans`, `/activities/:id`, `/conflicts/*`, `/voids/density`, `/sheaf/*`, and all 12 `political::*`.

```rust
// crates/epigraph-api/tests/public_router_allowlist.rs
//
// Walks BOTH create_router variants (routes/mod.rs:153 and :863) and asserts
// the set of routes reachable without an Authorization header is EXACTLY the
// allowlist below. A new .route() added to `public` fails the build.
const ANONYMOUS_ALLOWLIST: &[&str] = &[
    "/health",
    "/metrics",                                    // pending §10.1 Q5
    "/api/v1/openapi.json",
    "/oauth/token", "/oauth/register", "/oauth/revoke", "/oauth/introspect",
    "/oauth/authorize", "/oauth/callback", "/oauth/authorize/consent",
    "/oauth/:provider/auth-url", "/oauth/:provider/exchange",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
];
```

`optional_bearer_auth_middleware` survives **only** on the allowlist router. Everywhere else it is replaced by `bearer_auth_middleware` (`bearer.rs:17`), which 401s at `:55`.

#### The five paths that serve a request with no `agent_id` today

| # | Path | Evidence | Under D3 |
|---|---|---|---|
| **A** | Public router, no `Authorization` → no `AuthContext`. **109 routes.** | `mod.rs:798-801`; `bearer.rs:100-102` | Closed by the allowlist inversion |
| **B** | **Valid Bearer whose JWT carries no `agent_id`.** **This is currently every token.** `OAuthClientRepository::create` is called with `agent_id = None` at `register.rs:249` (comment: *"linked later via ensure_agent_by_content"*; `grep -rn ensure_agent_by_content crates/` → **the only hit is that comment; the function does not exist**), and `token.rs:423`, `:565`, `:746` propagate `client.agent_id` verbatim into the JWT | as cited | **BLOCKING.** `Viewer::resolve` needs a `Uuid`. **PR-02 is a hard prerequisite for PR-03.** |
| **C** | MCP `--allow-unauthenticated-http`: injects an `AuthContext` with **every** scope in `SCOPE_MAP` and `agent_id: None` | `main.rs:453-461` → `auth.rs:201-203` → `:179-191` (`agent_id: None` at `:188`) | Restricted to unix sockets (`main.rs:255`). Keep, but set `agent_id: Some(server_agent_id)` |
| **D** | MCP stdio: no `Parts`, so `is_http_call == false` and `enforce_tool_scope` never runs | `server.rs:1434`, `:1495-1502`; requester falls back to `Some(server_agent_id)` at `redaction.rs:62` | Keep the write trust-gate; reads become `Viewer::resolve(pool, server_agent_id)` — **a principal, never a `Bypass`** |
| **E** | `require_signature` success injects `VerifiedAgent`, **never** an `AuthContext` | `middleware/auth.rs:516-523` | Unreachable through `create_router` (§4.10); deleted |

**Path B becomes a §9 gate:** *% of active OAuth clients whose `agent_id` is non-null must be 100 % before the inversion.*

#### MCP is already fully authenticated over HTTP

`crates/epigraph-mcp/src/auth.rs:76-125` 401s any request lacking a valid Bearer (with the RFC 9728 challenge), and `server.rs:1495-1502` runs `enforce_tool_scope` on every HTTP call, failing closed for a missing `AuthContext` (`:231-239`) and for any tool absent from `SCOPE_MAP` (`:240-248`). `SCOPE_MAP` (`scope_map.rs:24-111`) covers 43 `claims:read` + 37 `claims:write` + 3 `claims:admin` tools. **No MCP tool is reachable unauthenticated over HTTP.** The rule for the two non-HTTP transports, once: **a transport-level trust gate grants a principal, never a bypass.**

### 4.8 `COARSE_EDGE_TYPES` and the structural-features endpoint

`COARSE_EDGE_TYPES` (`access_control.rs:16-32`, 15 entries, asserted by two tests) has exactly one live consumer: `GET /api/v1/structural-features/:owner_id` (`routes/structural.rs:173`, registered at `mod.rs:671`, **inside the `public` Router**). It returns per-owner node counts by type, edge counts by coarse relationship, and degree distribution, with an *optional* Laplace mechanism (`structural.rs:491-497`) whose `epsilon` defaults to `0.0` — **noise off by default**, asserted at `structural.rs:568`.

Three things change; the constant survives:

1. **The route moves to `protected`** (D3).
2. **Its three queries gain the visibility predicate.** All three currently join `ownership` (`structural.rs:151,178,205`) — which PR-22 drops — and none filters by visibility. Each becomes a `repos/structural.rs` function taking `viewer: &Viewer`; counts become *visible-set* counts; the `ownership` join is replaced by `claims.owner_group_id` / `claims.agent_id`.
3. **`epsilon` stops defaulting to zero.** `#[serde(default = "default_epsilon")] -> 1.0`; `epsilon = 0.0` requires `claims:admin`. A differential-privacy parameter whose default disables the mechanism is not a mechanism.

### 4.9 Leak re-rating under D3 — and the two facts that dominate it

`map-enforcement-leaks.md` rated on an attacker model D3 changes. The re-rating is dominated by **two** facts about how cheaply an attacker becomes authenticated. The previous revision found one and stopped a step short (sec F6).

> **Fact 1 — `crates/epigraph-api/src/oauth/register.rs:192-218`.** `POST /oauth/register` with `client_type: "agent"` returns `status = "active"` with eleven scopes including `claims:read`, `claims:write`, `evidence:write`, `edges:write`, `ingest:write` (verified at `:200-214`), and `/oauth/register` is on the unauthenticated `oauth` router (`mod.rs:806`). Comment at `:201`: *"Agents are auto-activated with full write scopes."*

> **Fact 2 — the IdP provisioning gate is OFF BY DEFAULT.** `ExternalIdentityProvider::allowed_emails()` and `allowed_domains()` both default to `&[]` (`oauth/providers/traits.rs:51-65`), documented verbatim as *"An empty slice together with an empty `allowed_domains` means allow-all (the gate is opt-in)."* `provision.rs:43-45` is the only consumer: `let allowlist_configured = !allowed_emails.is_empty() || !allowed_domains.is_empty(); if allowlist_configured { … }` — i.e. **no allowlist ⇒ no check**. So on a default deployment, any Google account completes `/oauth/authorize` → `provision.rs` → an active client. Separately, the DCR path (`register.rs:78`, `is_dcr = req.client_type.is_none()`) returns `status = "active"` with `dcr_scopes()` = `PENDING_SERVICE_SCOPES` (`:53-67`): `claims:read`, `evidence:read`, `edges:read`, `agents:read`, `groups:read`, plus seven `analysis:*`. DCR is partially bounded by the redirect-host allowlist at `register.rs:84-90` (claude.ai / claude.com only, verified) — but the `client_type: "agent"` path carries no `redirect_uris` and so is not bounded by it at all.

**Under D2 the whole legacy corpus is explicitly `public`; under D3 `public` = any authenticated agent. So after all 22 PRs, a default-configured instance is readable by anyone with a Google account** — and PR-02's `ensure_for_client` now hands each of them an `agents.id` and a personal group, i.e. a first-class `Scoped` viewer. **PR-02 therefore closes both facts**, and the leak table below carries three ratings rather than two.

| # | Leak | Map | D3 alone | D3 + both PR-02 gates | Note |
|---|---|---|---|---|---|
| 1 | `POST /search/semantic` verbatim content (`search.rs:430`) | blocker | **blocker** | major | Closed for real only by PR-06's predicate |
| 2 | MCP `recall` cross-tenant content (`memory.rs:399`, `claim.rs:910-960`) | blocker | **blocker** | **blocker** | Already required `claims:read` |
| 3 | MCP `assign_ownership` declassification (`perspectives.rs:176-205`, `ownership.rs:103-110`, `scope_map.rs:71`) | blocker | **blocker** | **blocker** | `claims:write`. PR-11/PR-14 |
| 4 | `/themes/:id/embeddings` — 5000 raw vectors (`crud.rs:1553-1589`, fail-open scope `:1559`) | blocker | **major** | major | `PENDING_SERVICE_SCOPES` grants `claims:read`, so it still leaks to any registrant. PR-07's ids + 2-D projection is the fix |
| 5 | MCP `get_recall_events` — others' raw search text (`recall_events.rs:51-98`) | blocker | **blocker** | **blocker** | MCP-only, `claims:read` |
| 6 | `/ownership/:node_id`, `/agents/:id/owned-nodes` — ACL enumeration | blocker | **major** | minor | Both handlers take `(State, Path)` only. PR-14 deletes both routes. **Largest genuine D3 win** |
| 7 | MCP `traverse` / `get_neighborhood` (`graph.rs:109`, `:20-79`) | blocker | **blocker** | **blocker** | MCP-only |
| 8 | `get_provenance` / `get_provenance_chain` (`provenance.rs:28`, `provenance_chain.rs:72`) | major | **major** | major | MCP-only |
| 9 | `/lineage/:claim_id`, `/query/rag`, `/compound_neighborhood` | major | **major** | major | Same shape as #1 |
| 10 | MCP `patch_claim` write-guard bypass (`server.rs:533-539`, `claims.rs:940-978`) | major | **major** | **major** | `claims:write` |
| 11 | Webhook fan-out (`webhooks.rs:255-289`) | major | **major** | major | `list_webhooks(State)` / `get_webhook(State, Path)` take no auth and are **on the protected router**, so anonymity was never the vector. PR-10 is the only fix |
| 12 | `content_tsv` GIN lexical leg unfiltered (`claim.rs:936-946`) | major | **major** | major | Reached via `recall`'s embedder-down fallback |
| 13 | `sweep_semantic_duplicates` BLAKE3 oracle (`dedup_sweep.rs:103-121`, `:166`) | major | **major** | **major** | `claims:write` |
| 14 | Triples/entities expose facts from private text (`rdf.rs:67-133`, `embed.rs:145`) | major | **major** | major | MCP + public HTTP |
| 15 | `embedding_neighborhood_density` (`embeddings.rs:96-108`) | major | **major** | major | MCP + public HTTP |
| 16 | `theme_cluster`, `wipe_first` default true (`themes.rs:60-79`) | major | **major** | **major** | `claims:write` |
| 17 | `/agents/:id/timeline` (`timeline.rs:43-46`) | major | **minor** | minor | An authenticated caller can still read any agent's timeline — needs its own predicate |
| 18 | Redaction hides only `content` (`types.rs:1033-1044`, `redaction.rs:32-35`) | minor | **closed** | closed | PR-14 deletes redaction |
| 19 | Existence oracle (`claims.rs:512` vs `:513-515`) | minor | **closed** | closed | Requires the written rule in §8.5 |
| 20 | Aggregate `COUNT(*)` (`batch.rs:127-146`, `admin.rs:126`) | minor | **minor** | minor | Permanently accepted (§10.2) |
| 21 | MCP `list_events` cross-agent payloads (`events.rs:12-50`) | minor | **minor** | minor | Also public HTTP at `mod.rs:590` |
| 22 | `/structural-features/:owner_id` anonymous coarse structure (`structural.rs:173`, `epsilon` default 0.0) | *unrated* | **minor** | minor | Missed by the map entirely. §4.8; PR-08 |
| 23 | **NEW — `GET /api/v1/challenges` returns `challenges.explanation` for any claim** (`mod.rs:547`, `:1037`) | *unrated* | **major** | major | Missed by the map **and** by the previous plan's tier-A list. §2.4; PR-03 moves the route, PR-06 filters the query |
| 24 | Stale security comments at `routes/mod.rs:794-796` and `bearer.rs:63-65` | minor | **delete** | delete | They document the anonymous-read design and are now actively misleading |

**Summary.** Of 8 map-rated blockers, D3 alone downgrades **two** (#4, #6); D3 plus the auto-activation kill downgrades **three**. The other five were never anonymous. **D3 is a real but narrow win: it closes the drive-by-scraper class and nothing else.** PR-06's SQL predicate remains the mechanism, and PR-02's two registration gates are what give D3 any teeth at all.

**Consequence for sequencing.** The auto-activation kill (`register.rs:199-215` → `status: "pending"`, empty `granted_scopes`) **and** the fail-closed IdP allowlist land in PR-02, and PR-03 may not merge before them. Both are one-hunk changes independent of the rest of PR-02's identity work; if PR-02 slips they are cherry-picked into PR-03.

**The fail-closed allowlist, concretely (sec F6).** `provision.rs`'s `allowlist_configured` inversion becomes:

```rust
// crates/epigraph-api/src/oauth/providers/provision.rs
let allowed_emails  = provider.allowed_emails();
let allowed_domains = provider.allowed_domains();
if allowed_emails.is_empty() && allowed_domains.is_empty() && !state.config.allow_all_identities {
    // FAIL CLOSED. Previously this branch was the ALLOW-ALL path.
    return Err(deny("provider has no identity allowlist and \
                     allow_all_identities is false"));
}
```

plus a boot assertion in `AppState::with_db`: refuse to serve when any registered provider has an empty allowlist and `EPIGRAPH_ENV=production` and `allow_all_identities` is not explicitly `true`. **PR-02 acceptance gains: "a Google identity outside `allowed_domains` cannot provision."** And §10.2 records the honest ceiling: *D3 raises the bar from zero credentials to one credential from whoever the IdP gate admits.*

### 4.10 `require_signatures` — one live consumer, one dead branch

**The middleware fallback does not exist.** `routes/mod.rs:491-496` documents the intent, but `Router::layer` makes the **last-applied layer outermost**, so at `:497-507` `bearer_auth_middleware` runs first — and it has no fall-through: `bearer.rs:53-56` returns `Unauthorized { reason: "Missing Authorization header" }`. `require_signature` additionally short-circuits when an `AuthContext` is already present. **Therefore `require_signature` is unreachable through either `create_router`.** Corroborated: `tests/routes/submit_packet_tests.rs:218` builds the router with `require_signatures: true` and then mints a **Bearer token** (`:242-259`) to reach the endpoint; the only tests exercising `X-Signature` call the middleware directly.

**But the flag is not dead** — `routes/submit.rs:689` gates **payload-level** Ed25519 verification inside `submit_packet` (format `:690-716`, key lookup `:727`, `hex::decode_to_slice` `:768`, verify over `EpistemicPacket::signable_bytes` `:781`). That path is live and correct.

**Disposition (PR-03):** delete the `if state.config.require_signatures { … }` branch at `:497-513` and its twin at `:1013-1027`; layer `bearer_auth_middleware` unconditionally on `protected`; delete `require_signature` from `middleware/mod.rs`. **Keep** `ApiConfig.require_signatures` (`state.rs:261`, default `false` at `:649`) and **rename it `require_packet_signatures`**, updating `state.rs:679,:686,:691` and eleven test constructions. `VerifiedAgent` is retained only if `claims.rs:296` still wants it; the fallback chain at `claims.rs:392` collapses to `AuthContext` only, and **the "zero fallback" arm must be deleted** — a zero public key is exactly the served-with-no-principal shape D3 forbids.

### 4.11 Repo-layer call sites (Tier 0)

`repos/claim.rs` — 17 read functions gain `viewer: &Viewer` immediately after `pool`:

| Function | Line | Query kind | `sqlx prepare`? |
|---|---|---|---|
| `get_by_id` | 517 | `sqlx::query!` | **yes** |
| `get_by_id_with_labels` | 583 | macro | **yes** |
| `search_by_embedding` | 650 | runtime | no |
| `search_by_embedding_since` | 677 | runtime | no |
| `search_by_embedding_current` | 764 | runtime | no |
| `search_by_embedding_scoped` | 782 | runtime | no |
| `search_hybrid_scoped` | 870 | runtime | no |
| `search_hybrid_scoped_since` | 910 | runtime | no |
| `search_lexical_scoped` | 985 | runtime | no |
| `search_lexical_scoped_since` | 1004 | runtime | no |
| `get_by_id_conn` | 1372 | macro | **yes** |
| `contents_by_ids` | 1553 | runtime | no |
| `list_by_labels` | 1628 | runtime | no |
| `search_by_label_and_text` | 1795 | runtime | no |
| `enumerate_current_embedded` | 4854 | `sqlx::query!` | **yes** |
| `nearest_neighbors_of_claim` | 4902 | `sqlx::query!` | **yes** |
| `content_hashes_for` | 4945 | `sqlx::query!` | **yes** |

**Each of these 17 gains a positive `FORCE`-mode test** (§0.5, §4.5): a `Scoped` viewer over group G reads back exactly its own group-private rows. Same treatment in `repos/{triple,lineage,provenance_chain,recall_event,event,claim_theme,evidence,edge,structural,challenge,reasoning_trace}.rs` — the last two are new consumers created by §2.4's additions.

`find_claims_needing_embeddings` (`claim.rs:2697`) takes a `Bypass` viewer (`SystemReason::EmbeddingBackfill`) with a `-- VISIBILITY-EXEMPT:` marker, and gains a **policy** fix in the same edit. It currently filters only `telemetry` + `properties->>'event'` + `is_current` (`:2697-2728`); it gains

```sql
AND NOT EXISTS (SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = c.id)
```

**Keying the exclusion on `claim_encryption` and NOT on `visibility` is load-bearing.** It lets a `restrict`-mode private claim keep its embedding (so its owning group keeps semantic recall — the point of §2.3, and a deliberate departure from `routes/claims.rs:590`, which skips embedding for any non-public tier and thereby makes a private claim invisible to its own owner's `recall`). It is *also* what makes unseal cheap.

**But it does not make unseal free, and the previous revision overstated that (ops F14).** `find_claims_needing_embeddings` is `ORDER BY created_at LIMIT $1` with no priority and no `updated_at` notion, so a freshly unsealed 2019 claim queues behind every other embedding-less row, `embed_backfill --limit` defaults to 500 per run, and for the whole window the CLAUDE.md `live_missing` audit is non-zero and indistinguishable from a leaking write path. **Fix: `unseal-commit` enqueues an `EmbeddingGeneration` job per item** (the handler already exists in `epigraph-jobs/src/lib.rs`), and the audit SQL in §6.5.4 carries the exemption explicitly.

`claim_from_row` is **NOT touched.** Its signature is `(id, content, agent_id, trace_id, truth_value, created_at, updated_at) -> Claim` (`claim.rs:142-150`, ~20 callers). Because the filter is in SQL, a `Claim` that comes back is *already authorized*. Administrative reads get their own `#[derive(sqlx::FromRow)] struct ClaimTenancyRow` in `repos/claim_tenancy.rs`.

**`batch_check_content_access` is deleted, not rewritten.** Its replacement is the *absence* of one: `Viewer::resolve` issues a single membership lookup per request and the predicate does the rest. Today it is a sequential loop issuing up to 2 queries **per node**, so a 100-row recall page goes from ~200 queries to 1.

### 4.12 HTTP and MCP call sites

**HTTP (PR-07).** All 104 non-allowlisted registrations move to `protected`; all **39** fail-open sites become `ViewerExtractor`; **both** `create_router` variants. The 32 already-hardened `check_content_access` sites (`claims.rs:875,1019`; `belief.rs:1894,2004`; `edges.rs:1488,1491,1603,1607,1719,1721,1922,2070,2206,2439`; `graph_query.rs:296`; `tools/claims.rs:449,513`; `tools/paper_queries.rs:98,162,217,277`) are a mechanical substitution.

**The RAG public-access guarantee is REVOKED.** `rag.rs:1102-1118` (`test_rag_returns_200_via_full_router`) flips `OK` → `UNAUTHORIZED`, as does `rag.rs:1341-1348`. **Documented breaking API change, announced with PR-14's.**

**MCP (PR-09).** Most of the 78 unguarded tools need **no change**: `recall`, `recall_with_context`, `query_*`, `find_workflow`'s semantic path all inherit the filter the moment the repo function requires a `Viewer`. Work is needed only where a tool writes its own SQL — which CLAUDE.md forbids anyway: `tools/embeddings.rs:96-108`, `tools/batch.rs:127-146`, `tools/themes.rs:60-79`, `tools/recall_events.rs:51-98`, `tools/events.rs:12-50`, `tools/graph.rs`, `tools/rdf.rs`, `tools/provenance*.rs`. Each moves to a repo function; `no_inline_sql_in_tools.rs` then holds the line at zero.

`mcp_requester` (`tools/redaction.rs:55-63`) becomes `mcp_viewer`. Today:

```rust
pub fn mcp_requester(auth: Option<&AuthContext>, server_agent_id: Uuid) -> Option<Uuid> {
    match auth {
        Some(a) => a.agent_id.or(Some(a.client_id)),
        None    => Some(server_agent_id),
    }
}
```

Two D3 problems. **`a.agent_id.or(Some(a.client_id))`** substitutes an `oauth_clients.id` for an `agents.id`; it can never match `group_memberships.agent_id`, so it silently degenerates to "public only" — the correct *outcome* under D3, arrived at by accident through a type confusion, with no error and no metric. **`None => Some(server_agent_id)`** is the stdio path.

```rust
// crates/epigraph-mcp/src/tools/viewer.rs
pub async fn mcp_viewer(
    pool: &PgPool, auth: Option<&AuthContext>,
    server_agent_id: Uuid,      // stdio identity only
    is_http_call: bool,
) -> Result<Viewer, McpError> {
    match (is_http_call, auth) {
        (true, Some(a)) => match a.agent_id {
            Some(id) => Viewer::resolve(pool, id).await.map_err(internal_error),
            // Authenticated, but the token carries no agents.id. NOT flattened
            // to client_id. Hard reject.
            None => Err(unauthorized("token carries no agent principal")),
        },
        // HTTP without an AuthContext is unreachable (server.rs:1495 gate), but
        // the arm is written so it cannot become reachable silently.
        (true, None) => Err(unauthorized("no auth context")),
        // stdio: the process boundary is the trust gate for WRITES only
        // (server.rs:1424-1429). Reads become honest -- a PRINCIPAL, not a
        // Bypass. This also bounds the ~1,198 orphan agents from
        // migrations/057_label_legacy_orphan_agents.sql:1-20.
        (false, _) => Viewer::resolve(pool, server_agent_id).await.map_err(internal_error),
    }
}
```

### 4.13 Ratchets and lints

| Artifact | Status |
|---|---|
| `crates/epigraph-db/tests/viewer_ratchet.rs` | `SystemReason::ALL.len()` + `match` exhaustiveness; monotone-decreasing |
| `crates/epigraph-db/tests/visibility_lint.rs` | **`PROTECTED` is generated** from §2.4's two generators + `tenancy_exempt`, never a literal |
| `crates/epigraph-mcp/tests/no_inline_sql_in_tools.rs` | zero inline SQL in tools |
| `crates/epigraph-db/tests/no_unscoped_pool.rs` | asserted call-site count on `unscoped_for_maintenance` |
| **NEW** `no_anonymous_viewer.rs` | fails if `Anonymous` / `anonymous()` / `ViewerShape::Anonymous` reappear under `visibility.rs` |
| **NEW** `no_bypass_in_handlers.rs` | fails if `Viewer::system(` or `MaintenanceLease` appears under `routes/` or `tools/` |
| **NEW** `public_router_allowlist.rs` | §4.7; walks both `create_router` variants |
| **NEW** `qual_guc_coherence.rs` | §4.5, incl. the scrub test and the positive `FORCE` class |
| **NEW** `tenancy_coverage.rs` | §2.4/§3-065; the generators + `tenancy_exempt` |
| **NEW** `tenancy_required.rs` | §8.2; the D1 acceptance suite |
| **NEW** `locked_decisions.rs` | §0.2; D1/D3/D4 as catalog-and-route-table predicates |
| **NEW** `no_unmaintained_dsn.rs` | §7 PR-15; fails if a file under `crates/epigraph-jobs/`, `crates/epigraph-cli/src/bin/` or `scripts/` reads `DATABASE_URL` without a `MAINTENANCE_DATABASE_URL` fallback and a `SELECT epigraph_bypass()` startup assertion |

---

## 5. Crate & code layout

### 5.1 Moves into the kernel workspace (PR-19 only, ~350 LOC)

`crates/epigraph-privacy/` joins `Cargo.toml` members between `epigraph-crypto` and `epigraph-db`.

| Lands as | From | Verdict |
|---|---|---|
| `src/encryptor.rs` | `ENT/epigraph-privacy/src/encryptor.rs` (228 L, 7 tests) | **Port.** `build_aad(entity_id, epoch)` (:12-17) is the best crypto in either repo; transplant and replay resistance are both tested (:161-180). **Three changes:** append a 1-byte **field tag** (today `encrypt_claim_content` and `encrypt_edge_properties` emit byte-identical AAD for the same UUID+epoch); accept a pre-padded plaintext (§6.5.4); and add `encrypt_version_content` / `encrypt_evidence_content` for the widened TCB (§6.5.6) |
| `src/tier.rs` → `Confidentiality` | `ENT/…/tier.rs` (54 L, 2 tests) | **Port, renamed.** `Confidentiality::{Plaintext, Sealed}`. The `Public` variant is dropped — "public" is a *visibility*, not a storage encoding |
| `src/group.rs` | `ENT/…/group.rs` | **Port.** `GroupRole::{Reader,Writer,Admin}` becomes the single canonical vocabulary and its `can_write()` is finally *enforced*. `from_db_str` rejects `member` and `creator` |
| `src/errors.rs` | `ENT/…/errors.rs` | Port as-is |
| `src/rewrap.rs` | **new** | Explicit client-side cross-group re-wrap: unwrap under A's key, re-wrap under B's real X25519 public key. Replaces `sharing.rs` |
| `→ crates/epigraph-cli/src/bin/epigraph-group.rs` | `ENT/…/key_manager.rs` (275 L, 9 tests) | **Port, CLIENT-side only.** DB-free by design (:1-5); redacting `Debug` impls (:27-35,:47-55); `rotate_group_key` (:124) `checked_add`s the epoch. `wrap_key_for_member` (:89) produces exactly the hex `wrapped_key_share` that `routes/groups.rs:56-58` already expects. **This is the `--init-group` ceremony that `routes/groups.rs:103-108` documents and that `rg 'init-group\|init_group'` proves exists nowhere.** Never linked into the server |
| `→ crates/epigraph-db/src/pool.rs` | `ENT/…/rls.rs` (18 L, 0 tests) | **Absorbed into `ScopedPool` (§0.5).** Highest leverage per line in the enterprise repo — `routes/claims.rs:830` already carries the call site as a comment — but it belongs next to the pool, it needs the tests it does not have, and it needs the `acquire_as` variant the enterprise version has no concept of |

**Two `epigraph-crypto` defects are prerequisites of `seal`, and only of `seal`.** `restrict` ships without touching either — another reason it is the default.

1. `ecdh_shared_secret` (`crates/epigraph-crypto/src/key_exchange.rs:57-65`) returns `*shared.as_bytes()` **verbatim** as the AES-256 key — no KDF, no contributory/low-order check, no ephemeral. Both inputs are long-term identity keys, so every (admin, member) pair has one fixed wrapping key forever. **Fix:** `blake3::derive_key("epigraph-key-wrap-v2", dh_output || sorted(pk_a, pk_b))`, plus `was_contributory()`.
2. `wrap_group_key` uses the **fixed literal AAD** `b"epigraph-key-wrap"` (`key_exchange.rs:76`), so a 60-byte share transplants across groups, epochs and members undetected. **Fix:** AAD = `group_id || epoch_le || member_agent_id`.

### 5.2 Stays out, permanently

`provider.rs` (server-side key custody, §2.7); `sharing.rs`; `mpc/`; `signals.rs`; the whole of `epigraph-policy`; the whole of `epigraph-orchestrator`; `epigraph-praxis` (its `Default` sets `require_signatures: false` directly beneath a doc comment saying not to).

### 5.3 Kernel files

```
crates/epigraph-db/src/visibility.rs             NEW  Viewer, ViewerShape, SystemReason,
                                                      MaintenanceLease, predicate_fragment
crates/epigraph-db/src/pool.rs                   NEW  ScopedPool: acquire_as, begin_as,
                                                      unscoped_for_maintenance, after_release scrub
crates/epigraph-db/src/access_control.rs         SHRINK → deleted in PR-14
                                                      (COARSE_EDGE_TYPES → repos/structural.rs)
crates/epigraph-db/src/repos/claim.rs            EDIT 17 read fns + Viewer; 8 write fns + TenancyDecl
                                                      (incl. consolidate:4653 + its meet rule)
crates/epigraph-db/src/repos/claim_tenancy.rs    NEW  set_visibility / get_visibility / ClaimTenancyRow
crates/epigraph-db/src/repos/structural.rs       NEW  the three structural-features queries + Viewer
crates/epigraph-db/src/repos/challenge.rs        EDIT + Viewer (new tier-A table, §2.4)
crates/epigraph-db/src/repos/reasoning_trace.rs  EDIT + Viewer (new tier-A table, §2.4)
crates/epigraph-db/src/repos/privatization.rs    NEW  ALL D4 SQL (CLAUDE.md: no SQL in routes/tools)
crates/epigraph-db/src/repos/instance_admin.rs   NEW  is_active / grant / revoke / list
crates/epigraph-db/src/repos/group.rs            EDIT + create_with_admin (group + epoch 0 + creator
                                                      membership, ONE tx)
crates/epigraph-db/src/repos/group_membership.rs EDIT + update_wrapped_key, list_live_for_agent, *_conn
crates/epigraph-db/src/repos/group_key_epoch.rs  EDIT + rotate_tx (retire_epoch already exists at :82)
crates/epigraph-db/src/repos/agent.rs            EDIT + ensure_for_client, ensure_personal_group,
                                                      get_public_profile(viewer)
crates/epigraph-db/src/repos/{embedding_share,re_encryption_key}.rs   DELETE (zero callers, verified)
crates/epigraph-db/src/repos/pattern_template.rs KEEP (live callers at routes/isomorphism.rs:11,138,143,253)
crates/epigraph-db/tests/{visibility_lint,viewer_ratchet,schema_contract,no_unscoped_pool,
    no_anonymous_viewer,qual_guc_coherence,tenancy_coverage,tenancy_required,locked_decisions,
    rls_enforcement,privatization_closure,privatization_hull,privatization_boundary,
    privatization_resume,privatization_revert,privatization_drift,seal_side_channels}.rs   NEW
crates/epigraph-crypto/src/proxy_re.rs           DELETE
crates/epigraph-crypto/src/key_exchange.rs       EDIT (the two §5.1 fixes; PR-19)
crates/epigraph-authz/                           NEW crate: GroupPolicyGate (no SQL, repo calls only)
crates/epigraph-interfaces/src/{encryption,orchestration}.rs           DELETE
crates/epigraph-interfaces/src/policy.rs         REWRITE (ResourceRef, Decision)
crates/epigraph-api/src/routes/mpc.rs            DELETE
crates/epigraph-api/src/routes/privatization.rs  NEW  the D4 HTTP surface
crates/epigraph-api/src/middleware/instance_authz.rs  NEW  require_instance_admin_for_group
crates/epigraph-api/src/middleware/bearer.rs     EDIT + ViewerExtractor; delete require_signature
crates/epigraph-api/src/errors.rs                EDIT + RFC 6750 WWW-Authenticate challenge (ops F15)
crates/epigraph-api/src/oauth/providers/provision.rs  EDIT fail-closed allowlist (sec F6)
crates/epigraph-api/Cargo.toml                   EDIT remove `enterprise` feature (:18, :52)
crates/epigraph-api/tests/{public_router_allowlist,no_bypass_in_handlers,
    tenant_isolation_http,privatization_authz,group_lifecycle,structural_features_authz,
    webhook_tenancy,group_rotation,backfill_idempotence}.rs             NEW
crates/epigraph-mcp/src/tools/viewer.rs          NEW  mcp_viewer
crates/epigraph-mcp/src/tools/privatization.rs   NEW  the six D4 MCP tools
crates/epigraph-mcp/src/tools/redaction.rs       DELETE in PR-14
crates/epigraph-jobs/src/privatization.rs        NEW  Apply / Revert / Reseal handlers
crates/epigraph-jobs/src/pool.rs                 NEW  MAINTENANCE_DATABASE_URL + bypass assertion (PR-15)
crates/epigraph-cli/src/pool.rs                  NEW  shared maintenance pool constructor (PR-15)
crates/epigraph-cli/src/bin/epigraph-tenancy-backfill.rs   NEW (incl. `verify` subcommand)
crates/epigraph-cli/src/bin/epigraph-group.rs             NEW (PR-19)
crates/epigraph-cli/src/bin/epigraph-privatize.rs         NEW (PR-18 selection; PR-21 seal)
crates/epigraph-cli/src/bin/epigraph-instance-admin.rs    NEW (PR-18)
scripts/_api_client.py                           EDIT emit agent_id in the JWT (PR-03)
scripts/theme_lib.py                             EDIT MAINTENANCE_DATABASE_URL (PR-15)
scripts/fuzzy_dedup_claims.py                    EDIT MAINTENANCE_DATABASE_URL (PR-15)
.github/workflows/ci.yml                         EDIT MIGRATION_DATABASE_URL for epigraph-migrate (PR-16)
docs/tenancy.md                                  NEW
docs/runbooks/{070,075,080}-undo.sql             NEW
migrations/README.md                             EDIT reserve 060–085 (PR-01)
```

(`crates/epigraph-cli/src/bin` has **26** binaries today, verified; **14** read `DATABASE_URL`.)

---

## 6. API + MCP surface

### 6.1 Scopes — `crates/epigraph-core/src/canonical_scopes.rs`

```rust
pub const ADMIN_ONLY_SCOPES: &[&str] = &[
    "claims:admin", "clients:admin", "entity-types:write",
    "groups:admin",
    "instance:admin",     // NEW — the D4 authority (§6.6)
];
pub const WRITE_SCOPES: &[&str] = &[ /* … existing 10 … */ , "groups:write" ];
// READ_SCOPES already contains "groups:read" at :38 — today it is passed to
// check_scopes NOWHERE. PR-02 makes it load-bearing.
```

`oauth/register.rs:54-67`, `:202-214` and `routes/agents.rs:132-140` are three divergent hardcoded grant lists; PR-02 consolidates all three onto `canonical_scopes`. Maintaining three lists is precisely how `groups:read` became decorative.

**`instance:admin` is a NEVER-GRANTED scope.** Not in `PENDING_SERVICE_SCOPES`, not in the agent auto-activation set, not grantable by `POST /oauth/register`. Granted only by an operator via `bootstrap_clients` or a direct `oauth_clients` update. A scope is a claim the token makes about itself, not an authorization the instance made — which is why §6.6 requires three further conditions on top of it.

### 6.2 HTTP — existing routes

| Route | Change | Why |
|---|---|---|
| **the 104 non-allowlisted `public` registrations** | **move to `protected`**, both `create_router` variants | D3. §4.7 |
| `POST /api/v1/groups` | `RequireScopeGroupsWrite`; `create_with_admin` inserts group + epoch 0 + **creator membership `role='admin'`** in one tx | `routes/groups.rs:110-182` inserts no membership, so `require_group_admin` (`group_authz.rs:22-36`) 403s the first `add_member` — groups are unadministrable by construction |
| `POST /api/v1/groups` | `did_key` from the **group's** client-supplied public key via `epigraph_crypto::did_key` (`did_key.rs:47-54`) | `groups.rs:145` emits `did:key:<hex(creator_pubkey)>`, which the kernel's own parser rejects (`did_key.rs:64-66`) and which, under `UNIQUE(did_key)`, makes the second group any creator makes a 23505 → 500 |
| `POST /groups/:id/members` | `groups:admin`; validates the wrapped share (`EncryptedPayload::from_bytes`, 60 bytes for a 32-byte key); `role` default `writer`; **rejects** when there is no active epoch | `groups.rs:224-227` stores caller hex verbatim with no length check; `key_exchange.rs:76`'s fixed AAD lets a blob transplant; `groups.rs:236` silently pins to epoch 0 |
| `DELETE /groups/:id/members/:agent_id` | 404 when not a member; refuses to remove the last `admin`; sets `group_key_epochs.status='rotating'` **and `groups.reseal_required_at = now()`** (§6.7) | `repos/group_membership.rs:67-79` discards `rows_affected`; nothing prevents bricking a group |
| `GET /api/v1/groups/:id` | **public → protected**, `groups:read` + membership. Response gains `reseal_required_at` | `routes/mod.rs:774` is inside `public` |
| `POST /api/v1/claims` | `request.agent_id` **ignored**; author = `auth.principal_agent_id`; 403 on mismatch; body **must** carry an explicit `visibility` + `owner_group_id` (or omit both and inherit) | `claims.rs:47,:420,:428`; only `claims:write` is checked (`:300-302`) — any token forges authorship. Also removes the `[0u8;32]` public-key fallback at `:392-408` |
| `GET /claims/:id`, `GET /claims` | membership gating no longer depends on the caller passing `?group_id=` | `claims.rs:797`, `:929` — a query parameter must not decide whether authorization runs |
| `POST /api/v1/groups/:id/rotate` | **NEW.** One tx: retire N, create N+1, `update_wrapped_key` for every live member. **Rejected unless the retiring epoch's key is RECOVERABLE** — `wrapped_key IS NOT NULL` **or** `groups.properties->>'kms_key_ref' IS NOT NULL`. Response states, verbatim, that rotation **does not** revoke access to already-sealed content (§6.7) | `routes/mod.rs:415` is a comment; `groups.rs:351-352` points at `epigraph-api-enterprise`, absent from the enterprise repo |
| `GET /api/v1/groups/:id/epochs`, `GET /api/v1/me/groups` | **NEW.** `groups:read` | "what can I see?" |
| `GET /api/v1/themes/:id/embeddings` | ids + 2-D projection, never raw vectors; `claims:admin` | `crud.rs:1553-1589` |
| `GET /api/v1/structural-features/:owner_id` | `protected`; `Viewer`-filtered counts; `epsilon` defaults to `1.0`; `epsilon=0.0` requires `claims:admin` | §4.8 |
| `GET /api/v1/challenges` | `protected`; the query gains the visibility predicate | §2.4 / §4.9 #23 |
| `POST /oauth/register` | `client_type="agent"` no longer auto-activates | `register.rs:200-214`. **§4.9 fact 1** |
| `/oauth/:provider/*`, `/oauth/token` (external grants) | provisioning allowlist **fails closed**; `allow_all_identities` config key; production boot assertion | `provision.rs:43-45`, `traits.rs:51-65`. **§4.9 fact 2** |
| `PATCH /api/v1/claims/:id/visibility` | **REWRITTEN.** `instance:admin` + the three §6.6 conditions; constructs a one-item plan and **enqueues** it | §6.5.7 |
| — | `enterprise` feature and `routes/mpc.rs` deleted | `cargo check --features enterprise` fails at `mpc.rs:8` |

JWT: `EpiGraphClaims` gains `#[serde(default)] pub active_group: Option<Uuid>` only. Additive and optional so in-flight tokens still deserialize (agent access 15 m, human 1 h; refresh 24 h/30 d/90 d). Audience stays `"epigraph-api"`. **Membership is deliberately NOT in the token** — for `restrict`, revocation takes effect on the next request, not the next refresh. (For `seal`, see §6.7: it does not take effect at all on already-sealed content, and that difference is now written down.)

### 6.3 Identity prerequisite (blocking, PR-02)

```rust
/// Idempotently materialise the agents row for an OAuth client, so
/// AuthContext.agent_id is never None on an authenticated request. This IS the
/// missing `ensure_agent_by_content` referenced at oauth/register.rs:249 and
/// absent from the repository.
pub async fn ensure_for_client(
    conn: &mut PgConnection, client_id: Uuid, client_type: &str,
) -> Result<AgentId, DbError>;
```

Called at all three token-mint sites (`oauth/token.rs:416-428`, `:558-570`, `:739-751`) and from `oauth/providers/provision.rs:156-168`, and it `UPDATE oauth_clients SET agent_id = $1` — an UPDATE `repos/oauth_client.rs` does not have today (`agent_id` appears only at :21, :71, :80, :92).

Because `agents.public_key bytea NOT NULL CHECK (octet_length = 32)` (`001:423,:440`) forbids a keyless human principal, the derived key is `blake3::derive_key("epigraph-oauth-client", client_uuid)` with `agents.key_kind='derived'`. **This is a placeholder, not a key**, and every signature path gains `AND key_kind = 'ed25519'` — specifically `routes/submit.rs:717-806`. `ensure_personal_group` runs in the same transaction, so **every principal has a personal group from its first token**, which makes D2's derivation total.

**These writes must survive `FORCE`.** `ensure_for_client` runs on the app pool at token-mint time; migration 073's `agents_provision` / `agents_self_update` policies exist for exactly this, and `rls_enforcement.rs` carries a direct regression: *mint a token as `epigraph_app` with `FORCE` on, and assert the `agents` row and the `oauth_clients.agent_id` update both land.* Without it, PR-17 breaks every authentication (sec F13).

### 6.4 MCP — `#[tool_router]` impl **and** `SCOPE_MAP` together

Both `crates/epigraph-mcp/src/server.rs` (**85** `async fn`, **83** `#[tool(`) and `scope_map.rs` must change or the two bidirectional coverage tests (`scope_map.rs:136-149`, `:153-166`) fail.

```rust
// ADDED to SCOPE_MAP
("list_my_groups",           "groups:read"),
("get_group",                "groups:read"),
("create_group",             "groups:write"),
("add_group_member",         "groups:admin"),
("revoke_group_member",      "groups:admin"),
("rotate_group_key",         "groups:admin"),
// D4 — instance:admin, NOT claims:admin
("preview_privatization",    "instance:admin"),
("get_privatization_plan",   "instance:admin"),
("list_privatization_plans", "instance:admin"),
("apply_privatization",      "instance:admin"),
("revert_privatization",     "instance:admin"),
("set_claim_visibility",     "instance:admin"),

// REMOVED from SCOPE_MAP and from the router (BREAKING)
-("assign_ownership", "claims:write"),
-("update_partition",  "claims:admin"),
```

`assign_ownership` is a one-call declassification-and-ownership-theft primitive at `claims:write` while its HTTP twin requires `claims:admin` (`routes/ownership.rs:89`, `RequireScopeAdmin`). Every `epigraph-wo` token loses it. That is intended.

**A third coverage test**, which keeps the 7-of-85 gap from silently reopening:

```rust
/// Every tool that reaches claim content must derive a Viewer. Enforced by
/// source inspection because the type system cannot see across the dispatch
/// boundary — a tool takes params, not a Viewer.
#[test]
fn every_content_reading_tool_derives_a_viewer() {
    for (tool, module_path) in TOOL_MODULE_MAP {
        let src = std::fs::read_to_string(module_path).unwrap();
        if !src.contains("ClaimRepository::") { continue; }
        assert!(src.contains("mcp_viewer("),
            "{tool} ({module_path}) reads claims but never derives a Viewer.");
    }
}
```

Per CLAUDE.md, federated tools mounted via `EPIGRAPH_MCP_EXTENSIONS` are **not** added to `SCOPE_MAP`.

### 6.5 The admin privatization surface (D4)

#### 6.5.1 Selection — a persisted plan, never a stateless request

```jsonc
{
  "seeds": {                          // exactly one of these three
    "ids":       { "claims": ["uuid", ...] },
    "predicate": { "labels": ["harvester","internal"],
                   "exclude_labels": ["public-release"],
                   "agent_id": "uuid",
                   "properties_contains": {"source":"acme-nda"},
                   "created_before": "2026-01-01T00:00:00Z",
                   "current_only": true },
    "saved_query": { "name": "nda-corpus" }        // 501 in v1
  },
  "closure": {
    "edge_types": ["decomposes_to","derived_from"],   // case-insensitive (§3/076)
    "direction":  "both",                             // "out" | "in" | "both"
    "max_depth":  3,
    "node_cap":   250000
  }
}
```

**Recommended primary: `predicate` seeds + `closure`.** `ids` does not scale and cannot be re-run after ingest; a predicate is the only selector an operator can hold in their head *and* re-apply. The predicate arm reuses `ClaimRepository::list_by_labels` (`claim.rs:1628`) verbatim. **`ids` is also required** — it expresses "these seventeen specific claims", which is what incident response looks like, and it is the substrate for the one-item plan behind `PATCH /claims/:id/visibility`.

**`saved_query` returns `501` in v1.** A saved query re-evaluated at apply time is a *standing* privatization rule, which must run on every insert — a trigger, i.e. the write path. Ship the schema slot; do not ship the semantics.

All selection SQL lives in `repos/privatization.rs`. No SQL in routes or MCP tools.

#### 6.5.2 Preview / dry-run — and why it is not a cross-tenant read oracle (sec F7)

`POST /api/v1/admin/privatization/plans` runs selection and returns `201` with the full preview. **There is no `?dry_run=true`; plan creation *is* the dry run.**

Selection must run unfiltered to be correct, so it uses `SystemReason::PrivatizationSelection`. The previous revision then returned a `sample` of *"25 items, stratified by depth, with a 120-char content preview"* and a `conflicts[]` array naming items already owned by a **third** group, with `current_owner_group_id`, `current_owner_display_name` and `current_visibility` — and nothing excluded already-private-to-others items from `sample`. **An instance admin who is not a member of group B could craft a `predicate` selector on labels and read 120-char previews of B's private claims, and with `on_conflict='abort'` never even apply.** Three changes close it:

1. **Selection counts under `Bypass`; rendering is under the ACTOR'S `Viewer`.** `sample` and `conflicts[].id` are populated from a second pass that runs with the actor's own `Viewer`. An item the actor cannot read appears **as a count and a reason** — never with content and never with an id.
2. **`GET /plans/:id`, `/items`, `/seal-manifest`, `/unseal-manifest` carry the same three-condition check as `POST /plans`.** The previous revision required `instance:admin` **+ group admin in target** to *create* a plan and only `instance:admin` to *read* one — so any instance admin could read any other admin's preview, its content sample, and the complete entity-id list of their private region.
3. **`GET /audit` is row-scoped in the database** (migration 078's policy), not merely in the handler: plan-level rows for every plan, entity ids only for plans whose target group the caller administers.

```jsonc
// 201 Created
{
  "plan_id": "…", "state": "previewed", "mode": "restrict",
  "target_group_id": "…", "target_group_display_name": "acme-nda",
  "plan_digest": "b3:9f2c…",              // BLAKE3 over sorted (kind,id); apply must echo
  "expires_at": "2026-08-26T18:03:00Z",   // 4h; a stale plan must be re-previewed

  "counts": {
    "claims": { "seeds": 17, "closure": 4912,
                "hull_supersedes": 88, "hull_step_lineage": 31, "total": 5048 },
    "evidence": 1204,
    "propagated_rows": {                  // trigger-driven, not plan items — but SHOWN
      "claim_versions": 611, "triples": 18400, "entity_mentions": 22119,
      "mass_functions": 3002, "ds_combined_beliefs": 1540,
      "ds_bayesian_divergence": 402, "claim_frames": 77,
      "harvester_claim_provenance": 5048,
      // sec F2 additions — these WERE NOT PROPAGATED before this revision
      "challenges": 214, "reasoning_traces": 1877, "experiment_triples": 96,
      "experiment_entity_mentions": 140, "claim_clusters": 5048,
      "claim_cluster_membership": 5048, "claim_neighborhood_membership": 4903,
      "claim_signature_revocations": 3, "harvester_fragments": 4102
    },
    "already_private_same_group": 12,
    "not_visible_to_actor": 6,            // ← count only; no ids, no content (sec F7)
    "by_depth": { "0": 17, "1": 903, "2": 2601, "3": 1527 }
  },

  "sample": [ /* 25 items the ACTOR can read, stratified by depth, 120-char preview */ ],

  "reachability_delta": {
    "authenticated_non_members": {        // the D3 "public" class
      "claims_lost": 5036, "evidence_lost": 1204,
      "principals_affected": 1198
    },
    "by_group": [
      { "group_id":"…","display_name":"partner-b","claims_lost":140,
        "reason":"140 items are currently public and partner-b reads them" }
    ],
    "authors_losing_own_claims": [        // claims.agent_id NOT IN target group
      { "agent_id":"…","display_name":"harvester-3","claims":902,
        "member_of_target": false }       // ← the loudest signal in the response
    ]
  },

  "boundary_edges": {
    "total": 3411, "private_to_public": 2990, "public_to_private": 421,
    "private_to_other_private_group": 6,  // ← requires edges.co_owner_group_id (§3/068)
    "by_relationship": { "supports": 1802, "contradicts": 640,
                         "within_frame": 511, "relates_to": 458 },
    "sample": [ /* ACTOR-VISIBLE only */ ]
  },

  "side_effects": {
    "mode": "restrict",
    "content": "unchanged (plaintext retained in claims.content)",
    "content_tsv": "unchanged (GENERATED ALWAYS; protected only by the row predicate)",
    "embedding": "retained on 5019 claims; group members keep semantic recall",
    "embeddings_nulled": 0,
    "hnsw_index_churn": "none (idx_claims_embedding_hnsw is not visibility-partial)",
    "revocation": "removing a member takes effect on that member's NEXT REQUEST for
                   restrict-mode content. It does NOT revoke access to anything
                   sealed before a subsequent re-seal (§6.7).",
    "defends_against": ["every API and MCP caller, incl. authenticated non-members"],
    "does_NOT_defend_against": ["pg_dump","physical/logical replicas","filesystem backups",
                                "epigraph_maintenance role members","direct psql as owner"]
  },

  "conflicts": [
    { "kind":"claim","id":"…",            // id present ONLY if the actor can read it
      "current_owner_group_id":"…","current_owner_display_name":"partner-b",
      "current_visibility":"group",
      "resolution_required":"on_conflict=abort|skip|reassign" }
  ],

  "requires_second_approver": true,       // item_count > 1000 OR authors_losing_count > 0
  "warnings": [
    "closure.edge_types omits 'derived_from': 411 claims reachable in one hop via
     DERIVED_FROM (paraphrase restatements, migrations/011) will remain public",
    "6 boundary edges cross into group partner-b; these become co-owned (§3/068)",
    "6 selected items are not visible to you; they are counted but not enumerated"
  ]
}
```

Four fields actually prevent mistakes: **`authors_losing_own_claims`** (privatizing into a group the author is not in is nearly always the wrong plan); **`boundary_edges.by_relationship`** (what the outside can still count); **`warnings` about omitted closure edge types** (computed by re-running the closure at depth 1 with the *complement* of the chosen edge types, restricted to the restatement tier); and **`side_effects.revocation`**, which is the single sentence §6.7 exists to make true.

`GET …/plans/:id/items?state=&depth=&cursor=` paginates the full item list beyond the sample, under the same three-condition check and the same actor-`Viewer` rendering.

#### 6.5.3 Boundary edges and the meet rule

> **An edge is visible iff both of its endpoints are visible.** Edge tenancy is the *meet* of its endpoints' tenancies, recomputed whenever either endpoint's tenancy changes.

Migration 066(b) applies it on *write*; privatization applies it on *update*, which 066(b) does not do because it is `BEFORE INSERT OR UPDATE OF source_id, target_id` and privatization changes neither. Migration 068 makes the cross-group case expressible.

```sql
-- repos/privatization.rs :: seal_boundary_edges(tx, plan_id, batch_ids, target_group)
WITH ep AS (   -- endpoint tenancy for every edge touching this batch
  SELECT e.id,
         COALESCE(cs.visibility, es.visibility, 'public')     AS sv,
         COALESCE(cs.owner_group_id, es.owner_group_id,
                  '00000000-0000-0000-0000-000000000000'::uuid) AS sg,
         COALESCE(ct.visibility, et.visibility, 'public')     AS tv,
         COALESCE(ct.owner_group_id, et.owner_group_id,
                  '00000000-0000-0000-0000-000000000000'::uuid) AS tg
    FROM public.edges e
    LEFT JOIN public.claims   cs ON e.source_type='claim'    AND cs.id = e.source_id
    LEFT JOIN public.evidence es ON e.source_type='evidence' AND es.id = e.source_id
    LEFT JOIN public.claims   ct ON e.target_type='claim'    AND ct.id = e.target_id
    LEFT JOIN public.evidence et ON e.target_type='evidence' AND et.id = e.target_id
   WHERE (e.source_id = ANY($1::uuid[]) AND e.source_type = ANY(ARRAY['claim','evidence']))
      OR (e.target_id = ANY($1::uuid[]) AND e.target_type = ANY(ARRAY['claim','evidence']))
   ORDER BY e.id                            -- ops F12: fixed lock order
)
UPDATE public.edges e
   SET visibility        = CASE WHEN ep.sv='public' AND ep.tv='public'
                                THEN 'public' ELSE 'group' END,
       owner_group_id    = CASE WHEN ep.sv='public' AND ep.tv='public'
                                THEN '00000000-0000-0000-0000-000000000000'::uuid
                                WHEN ep.sv='public' THEN ep.tg
                                ELSE ep.sg END,
       co_owner_group_id = CASE WHEN ep.sv='group' AND ep.tv='group' AND ep.sg <> ep.tg
                                THEN ep.tg ELSE NULL END
  FROM ep WHERE ep.id = e.id
   AND (e.visibility, e.owner_group_id, e.co_owner_group_id)
       IS DISTINCT FROM ( … the three CASEs … );
```

The `IS DISTINCT FROM` guard makes it idempotent, which is what makes the batch resumable. The `COALESCE(..., 'public')` on a missing endpoint is deliberate: an edge pointing at a `frame`/`agent`/`paper`/`task` has no tenancy, contributes `public` to the meet, and never *blocks* privatization.

#### 6.5.4 Side channels — `restrict` vs `seal`

**`restrict` (default).** `visibility='group'`, `owner_group_id=target`. `claims.content` keeps plaintext. `content_tsv` untouched. `embedding` **retained**.

> `content`, `content_tsv` and `embedding` are three columns of the **same row**. RLS is row-level. The predicate that hides `content` hides `content_tsv` and `embedding` identically and atomically. Retaining the embedding therefore leaks **nothing beyond what retaining `content` already leaks** — and `restrict` retains `content` by definition. Dropping it would cost the owning group its own semantic recall and buy zero confidentiality.

So in `restrict` mode the CLAUDE.md embedding invariant is **preserved unchanged**. `content_tsv` is the same story with one extra requirement: the predicate must land **inside the `lex` CTE, above `LIMIT`** (§4.3). Without that, the GIN index is a full-corpus lexical oracle for anyone with `claims:read`.

**`seal`** = `restrict` + `Confidentiality::Sealed`. **And `seal` must actually seal (sec F3).** The previous revision's seal-commit wrote `claim_encryption`, then `UPDATE claims SET content = '[sealed:'||id||']', content_hash = $ct_hash, embedding = NULL` — and stopped. Against `seal`'s own stated threat model (`pg_dump`, physical/logical replicas, filesystem backups, `epigraph_maintenance` role members, direct psql as owner) the following survived in plaintext:

| Survivor | Where | Why it defeats seal |
|---|---|---|
| `claim_versions.content` | `001:589-591`, `text NOT NULL` | The complete plaintext version history. The previous revision pulled `claim_versions` into the mandatory hull *for visibility* and never encrypted it. **One `pg_dump` recovers the sealed claim verbatim.** |
| `evidence.raw_content` and `evidence.embedding vector(1536)` | `001:903`, `:910` | The previous revision nulled `claims.embedding` only, and its `sealed_with_embedding` audit clause was written over `claims` alone — so a sealed claim's evidence kept a plaintext-derived ANN vector and the audit reported zero |
| `triples.subject_name` / `object_literal`, `entity_mentions.surface_form`, `reasoning_traces.explanation`, `challenges.explanation`, `experiment_triples.predicate`, `harvester_fragments.content_text` | §2.4 | Plaintext extractions the plan itself calls named leak surfaces for *visibility*, left in the clear for *confidentiality* |
| `claims.labels text[]` and `claims.properties jsonb` | `001:607-608` | `claim_encryption.encrypted_labels` existed but nothing emptied `claims.labels`. And §6.5.1's own selector filters on `properties_contains: {"source":"acme-nda"}` — the plan conceded `properties` carries the sensitivity in the same document where it left it plaintext |

The previous revision's careful `pad_to` bucketing analysis was defending a side channel two orders of magnitude smaller than the plaintext sitting in `claim_versions`.

**`docs/tenancy.md` therefore carries an explicit SEAL TCB, and seal-commit encrypts-or-deletes every member in the same transaction as the `claims` UPDATE:**

| Column | Treatment on seal | Restored on unseal |
|---|---|---|
| `claims.content` | → `'[sealed:'||id||']'`; ciphertext to `claim_encryption.encrypted_content` | yes, from client plaintext |
| `claims.content_hash` | → `BLAKE3(ciphertext)` | yes, verified against client plaintext |
| `claims.embedding` | → `NULL` | via an enqueued `EmbeddingGeneration` job (§4.11) |
| `claims.labels` | → `ARRAY[]::text[]`; ciphertext to `claim_encryption.encrypted_labels` | yes |
| `claims.properties` | → `'{}'::jsonb`; ciphertext to `claim_encryption.encrypted_properties` | yes |
| `claim_versions.content` | ciphertext to `claim_version_encryption`; column → `'[sealed:'||claim_id||']'` | yes |
| `evidence.raw_content` | ciphertext to `evidence_encryption`; column → sentinel | yes |
| `evidence.embedding` | → `NULL` | via the backfill |
| `evidence.properties` | ciphertext to `evidence_encryption.encrypted_properties`; column → `'{}'` | yes |
| `triples.subject_name`, `triples.object_literal` | **DELETED** (rows removed) | re-extracted on unseal by the existing extraction path, or left absent |
| `entity_mentions.surface_form` | **DELETED** | same |
| `reasoning_traces.explanation`, `challenges.explanation`, `experiment_triples.predicate` | **DELETED** | same |
| `harvester_fragments.content_text`, `context_window` | **DELETED** | not recoverable; stated in the preview |

Deleting rather than encrypting the extractions is deliberate: they are *derived*, re-derivable from the plaintext on unseal, and encrypting each one would multiply the key ceremony by five table shapes for no confidentiality gain. **The preview's `side_effects` block states, for `mode='seal'`, exactly which derived rows are destroyed and that `harvester_fragments` source text is not recoverable.**

**And the test is corpus-wide, not per-column.** `seal_side_channels.rs` replaces the previous revision's column-by-column assertions with:

> Seal a fixture claim whose plaintext contains a unique 32-byte nonce token. Then assert (a) `pg_dump --data-only` of the whole test database, piped through `grep -c <nonce>`, returns **0**; and (b) no `vector` column on any row derived from that claim is non-NULL.

That test, and only that test, would have caught `claim_versions.content`.

**Putting ciphertext (or base64 of it) into `claims.content` is NOT safe.** `content_tsv` is `GENERATED ALWAYS AS (to_tsvector('english', content)) STORED` (migration 050, verified); it **cannot** be nulled while `content` holds anything. AES-GCM is length-preserving (`|ct| = |pt| + 16`), base64 of that is `⌈(|pt|+28)/3⌉·4`, and the English parser splits a base64 blob into a token count monotone in its length. So `length(content)`, `array_length(tsvector_to_array(content_tsv),1)` and the GIN posting count are all **monotone functions of the plaintext length** — recoverable from a `pg_dump`, from `pg_stats`, and from a replica.

```
claims.content   := '[sealed:' || claims.id::text || ']'
   -> length constant modulo the uuid; to_tsvector yields 1-2 fixed tokens
   -> satisfies claims_content_not_empty (migrations/001:629)
   -> ID-SUFFIXED, so content_hash is unique per claim. Fixes the verified
      kernel defect where fully_private forces content := '[private]'
      (routes/claims.rs:410-415), making content_hash = BLAKE3("[private]")
      identical for every such claim and 409-ing the second one
      (claims.rs:453-470): an agent can currently create exactly ONE
      fully_private claim, ever.
```

**Ciphertext length padding.** `octet_length(encrypted_content)` still leaks plaintext length. Pad the plaintext to a bucket before encryption: `pad_to ∈ {0, 256, 1024, 4096}`, default `256`, ISO/IEC 7816-4 (`plaintext || 0x80 || 0x00*`), applied client-side and stripped on decrypt. `pad_to = 0` requires an explicit override and is recorded in the audit row.

**The CLAUDE.md audit SQL gains two clauses:**

```sql
SELECT COUNT(*) FILTER (WHERE is_current AND embedding IS NULL
         AND NOT ('telemetry' = ANY(labels)) AND (properties->>'event') IS NULL
         AND NOT EXISTS (SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = claims.id)
         -- ops F14: an unseal in flight is not an embedding gap. The window is
         -- bounded because unseal-commit enqueues EmbeddingGeneration per item.
         AND NOT EXISTS (SELECT 1 FROM jobs j
                          WHERE j.job_type = 'embedding_generation'
                            AND j.state IN ('pending','running')
                            AND j.payload->>'claim_id' = claims.id::text)
       ) AS live_missing,
       COUNT(*) FILTER (WHERE NOT is_current AND embedding IS NOT NULL) AS stale_present,
       -- A sealed claim that still carries a plaintext-derived vector is a
       -- CONFIDENTIALITY VIOLATION, not an embedding gap. Must be zero.
       COUNT(*) FILTER (WHERE embedding IS NOT NULL
         AND EXISTS (SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = claims.id)
       ) AS sealed_with_embedding
FROM claims;
-- AND the same sealed_with_embedding clause over `evidence`, which the previous
-- revision's audit omitted entirely (sec F3):
SELECT COUNT(*) FROM evidence e
 WHERE e.embedding IS NOT NULL
   AND EXISTS (SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = e.claim_id);
-- must be 0
```

`sealed_with_embedding > 0` on either table is a page-the-on-call condition.

**The four candidate embedding treatments, adjudicated:**

| Option | Verdict |
|---|---|
| Keep the embedding, protected only by the visibility predicate | **Adopted for `restrict`.** Leaks nothing beyond retained `content`; preserves group-internal semantic recall |
| Drop the embedding, lose semantic recall inside the group | **Adopted for `seal` only.** Unavoidable: the server holds no key |
| Re-embed under a group-scoped index | **Rejected.** The vector is plaintext-derived regardless of index; and in `seal` mode the server has no plaintext |
| `embedding_shares` / MPC | **Rejected outright.** No Rust in either repo writes that table; `SimulatedMpc::cosine_similarity` reconstructs **both** embeddings in the clear |

**Mode selection guidance.** **`restrict` is the default and is right for ~95 % of privatizations**: fully reversible, preserves semantic and lexical recall for the owning group, and the threat it does not cover (`pg_dump`, replicas, backups) is a **hosting** problem with hosting answers that apply uniformly and are cheaper than per-row application crypto. **`seal` is for data whose confidentiality must survive the operator**: regulatory holds, NDA corpora, cross-tenant SaaS. It costs the group its own server-side recall, destroys the derived extractions listed above, and is not server-reversible. The preview states all of it before the admin clicks.

#### 6.5.5 Atomicity, scale, reversibility — and where authorization actually happens

**Not one transaction. A job.** A 100k-item plan would hold row locks on `claims`, `evidence`, `edges` and seventeen derived tables for minutes. It runs on the substrate that already exists — `crates/epigraph-jobs` (`JobHandler` at `lib.rs:382`, `PostgresJobQueue`, retry/backoff `:599-607`, stale-job recovery in `tests/recover_stale_jobs_test.rs`, backed by `jobs` at `001:1141`).

```rust
// crates/epigraph-jobs/src/privatization.rs
pub struct PrivatizationApplyHandler  { pool: MaintenancePool }   // NOT PgPool (ops F5)
pub struct PrivatizationRevertHandler { pool: MaintenancePool }
pub struct PrivatizationResealHandler { pool: MaintenancePool }   // §6.7
```

**The pool type is load-bearing (ops F5).** Verified: `crates/epigraph-api/src/bin/server.rs:203-240` builds `job_pool` from the **same `DATABASE_URL`** as the API pool. After PR-17 points that at `epigraph_app`, `epigraph_bypass()` is false and `epigraph_session_groups()` is empty, so `claims_tenancy`'s `WITH CHECK` rejects the very first `UPDATE claims SET visibility='group'` with `42501` — and every write `epigraph_propagate_tenancy` fans out to fails the same way (`SECURITY DEFINER` does **not** bypass RLS; `epigraph_bypass()` deliberately keys on `session_user`, which `SECURITY DEFINER` does not change — correct for security, fatal here). **PR-15 gives the job pool `MAINTENANCE_DATABASE_URL` and a startup assertion that `SELECT epigraph_bypass()` is true, and it lands before PR-17.** PR-18's acceptance gains: *apply and revert both succeed with `relforcerowsecurity` true on every protected table* — which is a different statement from "Depends on: PR-17".

**The handler re-validates. The HTTP layer's checks are not the authorization (sec F5).** `POST …/apply` validates, flips `state='applying'`, enqueues, returns `202`. The handler then runs with `epigraph_bypass()` true, so every RLS `WITH CHECK`, the `writable_groups` gate and the `epigraph.allow_declassify` guard are inert for it — and `jobs` is written by the ordinary app role (`PostgresJobQueue::enqueue`, `epigraph-jobs/src/lib.rs:3135`). **Anything that can insert a `jobs` row could otherwise apply an unapproved, un-second-approved, stale-digest plan with full RLS bypass, and the 409/428 responses would be decorative.** Two defences:

1. **Migration 073's `jobs_app` policy** forbids the app role from enqueueing `job_type IN ('privatization_apply','privatization_revert','privatization_reseal')` at all; the route enqueues through a repo function on the maintenance pool.
2. **The handler re-reads the plan `FOR UPDATE` and refuses unless every one of the following holds**, before it touches a single row:
   - `state = 'applying'`;
   - `approved_by IS NOT NULL AND approved_by <> created_by` whenever `item_count > 1000` **or** `authors_losing_count > 0`;
   - the approver is a live `role='admin'` of `target_group_id` (migration 077's trigger already enforces this on write; the handler re-checks because membership can be revoked between approve and dispatch);
   - the stored `plan_digest` equals a digest **recomputed from `privatization_plan_items` at dispatch time**;
   - `acknowledge_author_loss` is true whenever `mode='seal' AND authors_losing_count > 0`;
   - `dispatched_by` matches the `agent_id` on the `security_events` row the HTTP layer wrote for this `correlation_id`.

   Every refusal writes `privatization_audit(action='plan.abort')` and sets `state='failed'`. `privatization_authz.rs` carries the direct regression: **enqueue a `privatization_apply` job by hand and assert the handler refuses.**

**Batch = 50 items initially, ramped by measurement; one transaction each; `ORDER BY depth DESC, kind, entity_id`.**

> **The ordering invariant: deepest-first.** At every commit boundary the private set is **closed downward under the content-derivation relation** — every derivation-descendant of a private item is already private. The inverse order would leave a private parent with public `decomposes_to` children, and a `kill -9` would leave that state permanently.

**Batch size and cost, corrected (ops F11).** The previous revision claimed batch = 500 and *"every UPDATE carries `IS DISTINCT FROM`, so re-running a batch is a no-op"* — false for nine of its ten propagation arms as written, and its `FOR EACH ROW` trigger issued ten UPDATEs per claim, i.e. 5,000 statements per batch, while `seal_boundary_edges` scanned `edges` twice more over the same ids. Using its own preview numbers (22,119 `entity_mentions` and 18,400 `triples` for ~5,000 claims — and now seventeen derived tables, not eight), one 500-claim batch row-locks well over 10,000 derived rows plus the edge set until commit, with the job pool's `statement_timeout` defaulting to **45 minutes** (`server.rs:~226`, verified) so nothing kills it. Corrections:

- 066(d) is **statement-level** with `REFERENCING NEW TABLE`, so it is ten-ish set-based UPDATEs *per batch*, not per row;
- **every** arm carries `IS DISTINCT FROM`;
- **start at batch = 50** and ramp on measured p95 lock-wait, to a ceiling of 500;
- `SET LOCAL lock_timeout = '3s'` **and** `SET LOCAL statement_timeout = '60s'` on the apply path, not only on selection.

Per batch, in one tx: `SELECT … FOR UPDATE LIMIT $batch` (**`FOR UPDATE`, not `SKIP LOCKED`** — every item must be processed exactly once), then the claims UPDATE (firing `epigraph_propagate_tenancy` → seventeen derived tables + evidence + harvester fragments), the evidence UPDATE, the boundary-edge meet UPDATE (`ORDER BY e.id`), the item state UPDATE, the plan cursor UPDATE, and the audit INSERT.

**Concurrency and lock order (ops F12).** `privatization_one_active_per_group` is unique on `target_group_id` and a per-plan advisory lock is per-plan, so two plans against *different* groups could touch the same boundary `edges` rows in opposite orders; and `ClaimRepository::consolidate` independently takes `SELECT … FROM claims WHERE id = ANY($1) FOR UPDATE` (`claim.rs:4575`) then rewrites the edge set (`:4672`) — opposite lock order to the apply batch. Deepest-first guarantees the *closure* invariant, not lock order. Fixes: **one global advisory lock for privatization apply** (`pg_advisory_xact_lock(hashtext('epigraph.privatization'))` — there is no stated need for concurrent plans), and `ORDER BY e.id` inside every batch edge UPDATE.

**`seal` ordering: restrict first, then seal**, because the `(public, Sealed)` guard raises if a claim is sealed while still public.

**What a partially applied privatization looks like** after `kill -9`:

- `state = 'applying'`, `cursor_*` at the last committed batch.
- A **downward-closed prefix** is private; the rest public. Every private item's derived rows, evidence, versions and touching edges are consistent (same tx). No item is half-applied.
- Boundary edges at the frontier are `('group', target)` on the applied side — *more* restrictive than the final state. Fails safe.
- Recovery is automatic: stale-job recovery re-dispatches and the handler resumes from `state='pending'` (re-running the full re-validation above).
- To stop: `POST …/abort` sets `state='failed'`; the applied prefix stays applied. Then `POST …/revert` un-applies exactly the items with `state='applied'` — which is why `before_visibility`/`before_owner_group_id` are captured per item at *selection* time.

**Post-apply drift re-scan (sec F9).** Freezing selection into `privatization_plan_items` is right for the TOCTOU it names, and it creates the inverse hole the previous revision did not name: a writer who inserts a `decomposes_to` / `derived_from` child, or an `evolve_step` revision, **between preview and apply** keeps a verbatim restatement of the now-private parent public, permanently, silently. Standing rules are deferred (`saved_query` → 501). So:

1. **On successful apply, re-run the closure at depth 1** over the applied set, restricted to the **restatement tier**, plus `epigraph_content_lineage_hull` over the applied ids. A non-empty result sets `state='applied_with_drift'`, writes `drift_ids`, emits one `privatization_audit(action='plan.drift')` row per id, and **auto-creates a follow-up plan in `previewed`** against the same target group.
2. **And close the write path**, so drift is rare rather than routine: an arm is added to the tier-A require-tenancy triggers so that inserting a **restatement-tier edge** (`decomposes_to`, `derived_from`/`DERIVED_FROM`) whose other endpoint is `visibility='group'` **raises** unless the new claim declares the same tenancy. This is an `AFTER INSERT` companion on `edges` rather than a `claims` arm, because the edge is what carries the relationship.

`privatization_drift.rs` is the regression: apply a plan, insert a `derived_from` child mid-flight, and assert (a) the write is refused by the edge guard, and (b) if the guard is bypassed on the maintenance pool, the post-apply rescan reports it and the follow-up plan exists.

**Refusal thresholds.** `item_count > 250_000` → refuse at selection. `item_count > 1_000` **or `authors_losing_count > 0`** → `requires_second_approver`; `apply` returns `428` until a different instance admin **who is an admin of the target group** approves. `authors_losing_own_claims` non-empty **and** `mode='seal'` → `apply` requires `acknowledge_author_loss=true`. Plan older than 4 h → `410 Gone`.

**`restrict` is fully reversible.** `POST …/revert` walks items **`ORDER BY depth ASC`** (the mirror invariant) and restores `(before_visibility, before_owner_group_id)`. The propagation trigger un-propagates; the boundary-edge meet re-runs. `content`, `content_tsv` and `embedding` were **never touched**, so there is no re-derivation and no new code path. **This is the single strongest argument for `restrict` as the default and it is said out loud in `docs/tenancy.md`.**

**`seal` gets an undo path too (ops F13).** The previous revision marked `revert` *"`restrict` only"* while also running a restrict pass first inside every seal plan — so a `seal` plan applied to the wrong subgraph had **no path back to `visibility='public'` anywhere in the surface**: `revert` refused on mode; `unseal-commit` restored `content` and dropped the `claim_encryption` row but left visibility untouched; and `epigraph_claims_block_widening` blocked the direct UPDATE. The only route left was raw psql as the table owner — the thing `FORCE` exists to eliminate. **Fix:** `revert` is permitted on a `mode='seal'` plan once every item is unsealed —

```sql
NOT EXISTS (SELECT 1 FROM claim_encryption ce
             JOIN privatization_plan_items i
               ON i.entity_id = ce.claim_id AND i.kind = 'claim'
            WHERE i.plan_id = $1)
```

— and returns `409` with the count of still-sealed items otherwise. `privatization_revert.rs` covers both modes.

#### 6.5.6 `seal` — a two-phase, client-driven protocol; the server never sees a key

```rust
// crates/epigraph-privacy/src/encryptor.rs  (ported per PR-19)
pub fn encrypt_claim_content(
    content: &str, epoch_key: &[u8; 32], claim_id: Uuid, epoch: u32,
) -> Result<EncryptedPayload, PrivacyError>;
// AAD = claim_id (16B) || epoch (4B LE) || FIELD_TAG (1B)   <- tag added per §5.1
// epoch_key = epigraph_crypto::derive_epoch_key(&base_key, epoch)
//           = blake3::derive_key("epigraph-epoch-key-v1", base_key || epoch_le)
// EncryptedPayload::to_bytes() = nonce(12) || ct+tag
//
// FIELD_TAG distinguishes: content=0x01, labels=0x02, properties=0x03,
// version_content=0x04, evidence_content=0x05, evidence_properties=0x06.
// Without it, two fields of the same claim at the same epoch produce
// byte-identical AAD and are transplantable into each other.
```

```
1. GET /admin/privatization/plans/:id/seal-manifest   (all three §6.6 conditions)
     -> 200 NDJSON stream, page 500:
        { epoch,
          items: [ { claim_id, content, labels, properties,
                     versions: [{id, content}],
                     evidence: [{id, raw_content, properties}] } ],
          manifest_digest }
        THIS IS THE ONLY RESPONSE IN THE SYSTEM that returns plaintext the caller
        may not otherwise be entitled to. Logged to BOTH security_events and
        privatization_audit.
2. client: epoch_key = derive_epoch_key(unwrap(my wrapped_key_share), epoch)
           for each field: pad(plaintext, pad_to) -> encrypt_*(..., FIELD_TAG)
3. POST /admin/privatization/plans/:id/seal-commit
     { manifest_digest,
       items: [ { claim_id, content_ct_b64, labels_ct_b64, properties_ct_b64,
                  content_hash_b64,
                  versions: [{id, ct_b64}], evidence: [{id, ct_b64, props_ct_b64}] } ] }
   server verifies: manifest_digest matches; every claim_id is in the plan;
     EncryptedPayload::from_bytes parses (>= 28 bytes, <= 10 MiB — the existing
     guard at encryption.rs:47-57); content_hash == BLAKE3(content ciphertext);
     octet_length ≡ 0 mod pad_to when pad_to > 0; EVERY TCB member listed in
     §6.5.4 is present for every item (a partial commit is REFUSED, not applied).
   then, one tx per batch, the FULL TCB mutation:
     INSERT claim_encryption / claim_version_encryption / evidence_encryption;
     UPDATE claims SET content='[sealed:'||id||']', content_hash=$h,
                       embedding=NULL, labels=ARRAY[]::text[], properties='{}';
     UPDATE claim_versions SET content='[sealed:'||claim_id||']';
     UPDATE evidence SET raw_content='[sealed]', embedding=NULL, properties='{}';
     DELETE FROM triples / entity_mentions / reasoning_traces / challenges
                 / experiment_triples WHERE claim_id = ANY($batch);
     UPDATE harvester_fragments SET content_text='[sealed]', context_window=NULL
       FROM harvester_claim_provenance p
      WHERE p.fragment_id = harvester_fragments.id AND p.claim_id = ANY($batch);
```

**Unseal is the mirror:**

```
1. GET  …/unseal-manifest   -> { epoch, items:[{claim_id, ciphertexts…}] }
2. client decrypts + unpads -> plaintext
3. POST …/unseal-commit     { items: [{claim_id, content, labels, properties,
                                       content_hash_b64, versions, evidence}] }
   server, per batch, one tx:
     verify BLAKE3(content) == $hash and non-emptiness (claims_content_not_empty);
     UPDATE claims SET content=$c, content_hash=$h, labels=$l, properties=$p;
       -- content_tsv REGENERATES AUTOMATICALLY: GENERATED ALWAYS (migration 050).
       -- There is NO tsvector code path to write.
     UPDATE claim_versions / evidence back from their manifests;
     DELETE FROM claim_encryption / claim_version_encryption / evidence_encryption;
     ENQUEUE one embedding_generation job per claim and per evidence row (ops F14)
       -- NOT "the existing backfill will get to it": find_claims_needing_embeddings
       -- is ORDER BY created_at LIMIT $1 with no priority, so a 2019 claim queues
       -- behind every other embedding-less row while live_missing reads non-zero.
     -- The DELETED extractions (triples, entity_mentions, reasoning_traces,
     -- challenges, experiment_triples, harvester_fragments text) are NOT
     -- restored by unseal. Re-extraction is a separate, explicit operation and
     -- harvester source text is gone. STATED IN THE SEAL PREVIEW.
```

**Where keys come from in production**, in order of preference:

1. **KMS/HSM-held base key.** The group base key never exists in plaintext outside a KMS. `epigraph-group --init-group` generates it inside AWS/GCP KMS or Vault Transit and stores only the handle in `groups.properties->>'kms_key_ref'`; `derive_epoch_key` runs client-side after a single `Decrypt`/`Export` under an IAM/Vault policy scoped to the group's admins. Epoch keys are ephemeral and never persisted.
2. **Per-member X25519 wrapping.** `group_memberships.wrapped_key_share bytea NOT NULL` already holds exactly this and `add_member` already expects the hex (`routes/groups.rs:58, :224-227`). **Blocked on the two `key_exchange.rs` fixes in §5.1.**
3. **Development only:** a file-held base key under `EPIGRAPH_GROUP_KEY_FILE`, refused when `EPIGRAPH_ENV=production`.

`group_key_epochs.wrapped_key` stays NULL under (1) and (2), which is why §6.2 restates the rotation guard as *recoverable* rather than *non-NULL*.

#### 6.5.7 The HTTP surface

All under `/api/v1/admin/privatization`, in the **`protected`** router. New file `routes/privatization.rs`; all SQL in `repos/privatization.rs`.

| Method | Path | Auth | Body / Query | Response |
|---|---|---|---|---|
| `POST` | `/plans` | **§6.6 (all three)** | `{ mode, target_group_id, selector, on_conflict?, pad_to? }` | `201` full preview |
| `GET` | `/plans` | `instance:admin`; rows filtered to plans whose target group the caller administers | `?state=&target_group_id=&limit=&cursor=` | `200 { plans, next_cursor }` |
| `GET` | `/plans/:id` | **§6.6 (all three)** — *not `instance:admin` alone* (sec F7b) | — | `200` preview + live progress |
| `GET` | `/plans/:id/items` | **§6.6 (all three)** | `?state=&kind=&depth=&limit=&cursor=` | `200 { items, next_cursor }`; items the actor cannot read appear as counts |
| `POST` | `/plans/:id/approve` | **§6.6**, and the actor **≠ `created_by`** | — | `200`; `409` if same actor |
| `POST` | `/plans/:id/apply` | **§6.6** | `{ plan_digest, acknowledge_author_loss? }` | `202 { job_id }`; `409` digest mismatch; `428` needs approver |
| `POST` | `/plans/:id/abort` | **§6.6** | — | `200`; stops the job, keeps the applied prefix |
| `POST` | `/plans/:id/revert` | **§6.6** | `{ plan_digest }` | `202 { job_id }`; **`409` if `mode='seal'` and any item is still sealed** |
| `GET` | `/plans/:id/seal-manifest` | **§6.6**, `mode='seal'` | `?cursor=&limit=500` | `200` NDJSON + `manifest_digest`; dual-logged |
| `POST` | `/plans/:id/seal-commit` | **§6.6** | `{ manifest_digest, items }` | `200 { committed, rejected }` |
| `GET` | `/plans/:id/unseal-manifest` | **§6.6** | — | `200` NDJSON ciphertext stream |
| `POST` | `/plans/:id/unseal-commit` | **§6.6** | `{ items }` | `200` |
| `GET` | `/audit` | `instance:admin`; **rows scoped by migration 078's policy** | `?entity_id=&plan_id=&since=&limit=` | `200 { events }`; every read writes a `security_events` row |

Plus the retained sugar, rewritten:

```
PATCH /api/v1/claims/:id/visibility
  body: { visibility: "public"|"group", owner_group_id: uuid, mode?: "restrict"|"seal" }
  auth: §6.6, all three conditions
  behaviour: constructs a one-item plan (selector = {seeds:{ids:{claims:[id]}}}, no
             closure, HULL STILL APPLIED), and ENQUEUES it — it does NOT apply
             synchronously. Returns 202 with the plan preview and a job id.
             Auto-approval applies only when item_count = 1 AND
             authors_losing_count = 0; otherwise 428.
```

> **Why it stopped applying synchronously.** The previous revision applied it inline in the HTTP handler, on the app pool, whose `epigraph_propagate_tenancy` UPDATEs are RLS-filtered with no row-count check (sec F10) — so it propagated only to derived rows already `visibility='public'`, accidentally working for a first privatization and silently failing for every re-privatization and every third-group conflict. Routing it through the same job is what makes §6.5.7's stated goal, *"exactly one code path"*, actually true.

> **This replaces the draft's version, which was `claims:write` + `GroupPolicyGate`.** `claims:write` on a declassification/reclassification primitive is precisely the `assign_ownership` mistake this plan deletes.

**Deliberately not exposed over MCP:** `seal-manifest` / `seal-commit` / `unseal-*`. They stream plaintext and consume key-derived ciphertext; an agent tool is the wrong shape for a key ceremony, and the stdio transport's identity default is not an authorization surface a manifest should trust. `epigraph-privatize` CLI only.

**Federation.** A federated server **cannot be trusted to enforce privatization**, and unlike a live read it may hold *copies* of claim content ingested before privatization. `POST …/apply` emits a `privatization.applied` webhook carrying the affected claim ids **only to subscriptions owned by an agent in `target_group_id`** (PR-10's persisted schema), so a downstream can purge. It cannot be enforced; it can be notified, and that distinction is ledgered (§10.2).

#### 6.5.8 Why `/audit` stays an HTTP route

The security critique's F7(c) proposed scoping `/audit` to the caller's administered plans and moving the instance-wide view to *"an `epigraph_maintenance` CLI query, not an HTTP route."* The scoping is adopted (migration 078's policy). **Moving the instance-wide view to a maintenance CLI is not**: `epigraph_maintenance` bypasses RLS entirely and writes no `security_events` row, so it makes the most sensitive read in the system *less* controlled and *less* observable than the route it replaces. An auditor needs the instance-wide timeline; the right answer is that they get plan-level rows for every plan, entity ids only where they administer the target group, and that **every `/audit` read is itself logged**. Concentrating audit reads in a role that leaves no trace is the opposite of an audit control.

### 6.6 Who is authorized to privatize — the instance-admin question

**Group admin is necessary but not sufficient.** A group admin who could privatize arbitrary public claims into their own group would be performing a **seizure**: exclusive read control over other authors' work, and under `seal`, unrecoverable. The `writable_groups` / `GroupPolicyGate` model cannot express this, because the operation's *subject* is public data owned by nobody in particular.

**Three simultaneous conditions, checked in this order — and condition 3 is now real (sec F4).**

The previous revision's condition 3 was *"group admin in the target group"*, justified as preventing *"an instance admin from privatizing into a group they cannot administer."* **It prevented nothing.** `POST /api/v1/groups` requires only `groups:write`, and PR-02's own `create_with_admin` inserts the creator as `role='admin'` — so a rogue instance admin manufactured a compliant target group in one request and was its sole admin by construction. Migration 077's guard adds two conditions the attacker cannot manufacture in one request: **the target group must be ≥ 24 h old, and must have ≥ 2 live admins other than the plan author.** And the second approver must be an admin **of the target group**, not merely a different instance admin — otherwise two instance admins who share no group rubber-stamp each other.

Condition 3 also does real work an honest operator cares about, which is why it is hardened rather than deleted: privatizing into a group you cannot administer means you cannot later unseal, revert, or add members to it.

```rust
// crates/epigraph-api/src/middleware/instance_authz.rs   (NEW)
pub async fn require_instance_admin_for_group(
    auth: &AuthContext, target_group_id: Uuid, pool: &PgPool,
) -> Result<Uuid, ApiError> {
    // 1. Token scope. Necessary, NEVER sufficient: oauth/register.rs:200-214
    //    auto-activates a self-asserted "agent" client with full write scopes
    //    (PR-02 kills that, but the lesson stands — a scope is a claim the token
    //    makes about itself, not an authorization the instance made).
    if !auth.has_scope("instance:admin") {
        return Err(ApiError::Forbidden { reason: "instance:admin required".into() });
    }
    // 2. DB-backed instance admin. Seeded ONLY by the epigraph-instance-admin
    //    CLI. There is no HTTP route that writes instance_admins.
    let agent_id = auth.agent_id.ok_or(ApiError::Unauthorized)?;
    if !InstanceAdminRepository::is_active(pool, agent_id).await? {
        return Err(ApiError::Forbidden { reason: "not an instance administrator".into() });
    }
    // 3. Group admin in the TARGET group, PLUS maturity and plurality.
    //    role == 'admin' ONLY. 'creator' is dropped: it is unstorable under
    //    group_memberships_role_check, so middleware/group_authz.rs:32's
    //    `role_str != "creator"` branch is DEAD CODE.
    let g = GroupRepository::get(pool, target_group_id).await?
        .ok_or(ApiError::NotFound { entity: "group".into(), id: target_group_id })?;
    if g.created_at > Utc::now() - Duration::hours(24) {
        return Err(ApiError::Forbidden {
            reason: "target group must pre-exist the plan by 24h".into() });
    }
    if GroupMembershipRepository::count_live_admins_excluding(pool, target_group_id, agent_id)
        .await? < 2 {
        return Err(ApiError::Forbidden {
            reason: "target group needs >= 2 live admins besides you".into() });
    }
    match GroupMembershipRepository::get_member_role(pool, target_group_id, agent_id).await? {
        Some(r) if r == "admin" => Ok(agent_id),
        _ => Err(ApiError::Forbidden {
            reason: "admin role in the target group required".into() }),
    }
}
```

**Selected nodes already belonging to a different group are never silently reassigned.** Reassigning a claim from A to B is simultaneously a *disclosure to B* and a *revocation from A* — two authorizations, neither implied by "privatize this subgraph". Preview enumerates every such item in `conflicts[]` (under the actor's `Viewer`) and the plan cannot leave `previewed` until `on_conflict` is decided:

- **`abort` (default)** — `apply` returns `409` with the conflict list.
- **`skip`** — conflicting items are `state='skipped'` and counted in the audit. **A warning is emitted**: skipping leaves a hole in the closure, and the preview recomputes `boundary_edges` under the skip.
- **`reassign`** — permitted only when the actor is `role='admin'` in **both** the current owner group and the target group, *and* holds `instance:admin`. A separate `security_events` row per reassigned item.

### 6.7 What rotation and member removal actually revoke — said out loud (sec F12)

PR-20's rotation retires epoch N, creates N+1, and re-wraps for live members. It does **not** re-encrypt `claim_encryption`, whose rows stay bound to epoch N through `claim_encryption_epoch_fkey (group_id, epoch)`. Migration 060 keeps retired epochs (`status='retired'`, `retired_at`), and `group_memberships` rows for revoked members are kept (`revoked_at` set) with `wrapped_key_share bytea NOT NULL` intact.

> **A member removed at epoch N who kept their share can decrypt every claim sealed before the rotation, forever.** Rotation gates only *future* ciphertext.

Meanwhile `restrict`-mode revocation takes effect on the member's **next request**, because membership is deliberately not in the JWT (§6.2). **Two opposite revocation semantics under one word**, and the previous revision stated only the flattering one. What ships:

1. **The sentence is in `docs/tenancy.md`, in the preview's `side_effects.revocation`, and in the `POST /groups/:id/rotate` response body.** Verbatim, not paraphrased.
2. **`DELETE /groups/:id/members/:agent_id` sets `groups.reseal_required_at = now()`** alongside `status='rotating'`. `GET /api/v1/groups/:id` surfaces it, and a Prometheus gauge `epigraph_groups_reseal_required` counts groups where it is non-NULL and older than 7 days.
3. **`PrivatizationResealHandler`** (`mode='reseal'`) exists as an **operator-initiated plan**: it selects every `claim_encryption` row bound to a retired epoch of the group and drives the same two-phase manifest protocol (unseal under N, re-seal under N+1), clearing `reseal_required_at` when the last row moves.

**What is deliberately NOT built:** `remove_member` does not *automatically* enqueue a re-seal. The security critique proposed that, and it is not implementable as stated: re-sealing requires the group key, which by §6.5.6 the server does not have. The server can mark, measure and prepare the manifest; only a key-holding admin can complete it. Automating a job that can only ever fail would convert a stated, visible gap into a red queue nobody trusts.

---

## 7. Work breakdown — 22 ordered PRs

Each is independently landable, reviewable, and each leaves `main` green. Feature branch, `gh pr merge --merge --delete-branch`, Epistemic Commit Protocol messages.

> **A note on "revertible" (ops, reversibility section).** The previous revision said each PR is *"independently landable, reviewable, and revertible."* That is true of the **Rust** and false of the **schema**: `ls migrations/ | grep -c '\.down\.sql'` → **0**, so `sqlx migrate revert` is unavailable for every one of 060–080. The genuine rollbacks are `ALTER TABLE … NO FORCE ROW LEVEL SECURITY` plus reverting `DATABASE_URL` (sub-minute, no data change), and reverting Rust. The three one-way doors — 070's `DROP DEFAULT`, 075's `FORCE` once `epigraph_app` is the connecting role, and 080's `DROP TABLE ownership` — each ship with a checked-in `docs/runbooks/<n>-undo.sql` naming the role that can execute it.

The previous revision had 21 PRs. **PR-15 is new** (the maintenance-DSN fleet, ops F5/F6), and PR-16 onward shift by one.

---

**PR-01 — `fix(db): create the group tenancy tables the kernel repos have queried since day one`**

*Evidence:* `GET /api/v1/claims/:id` returns 500 for every claim on a stock kernel DB (`routes/claims.rs:841` and `:1000` call `ClaimEncryptionRepository::get_by_claim_id_conn` unconditionally; no migration creates the table — documented in-tree at `tests/common/mod.rs:372-380`).
*Files:* `migrations/060_group_tenancy_tables.sql` (incl. the three guarded roles); **`migrations/README.md` — reserve 060–085** (ops F2; 21 named migrations at 060–080 plus headroom); **`bin/server.rs:213` — `run_migrations` behind `EPIGRAPH_MIGRATE_ON_BOOT`, default off** (ops F9: migrations 071/072/080 are *designed* to `RAISE`, and `server.rs:213` is `.expect("Failed to apply pending migrations")`, so any environment where the flag is not set before the deploy that ships them has an api binary that panics on every boot; the flag change is two lines and independently safe, so it belongs here, not in PR-16); delete `repos/{embedding_share,re_encryption_key}.rs`, `epigraph-crypto/src/proxy_re.rs`, `routes/mpc.rs`; edit `repos/mod.rs`, `epigraph-db/src/lib.rs`, `epigraph-crypto/src/lib.rs`, `epigraph-api/Cargo.toml` (drop `enterprise`); delete `tests/common/mod.rs::ensure_claim_encryption_table` (:390-405) and its caller (`read_path_authz_test.rs:27`); new `crates/epigraph-db/tests/schema_contract.rs`.
*Acceptance:* `GET /api/v1/claims/:id` returns 200 against a freshly migrated `epigraph_db_repo_test`; `cargo check --workspace` clean; `cargo check -p epigraph-api --features enterprise` no longer exists as a target; **a full CI run (all 8 `#[sqlx::test]` packages plus the 15 direct `sqlx::migrate!` sites) passes with no `42710 role already exists`**; `migrations/README.md` reserves 060–085.
*Tests:* `schema_contract.rs` (every table, exact column/type/nullability from `information_schema`); `read_path_authz_test.rs` (19 cases) passes with the stand-in deleted; a test asserting `DELETE FROM groups` raises; a test that applies 060 twice against the same database and succeeds.
*W0 gate (before merge):* run `SELECT version, description, checksum FROM _sqlx_migrations ORDER BY version DESC LIMIT 25` against **prod** and confirm nothing at 060+.

---

**PR-02 — `fix(api): give every authenticated principal an agents.id, make groups administrable, and close both registration gates`**

*Evidence:* `oauth_clients.agent_id` is never populated (`register.rs:249` names `ensure_agent_by_content`, which `grep -rn` proves does not exist), so `AuthContext.agent_id` is always `None` and `require_group_admin` (`group_authz.rs:18-20`) rejects every caller; `create_group` inserts no creator membership so the first `add_member` always 403s; `register.rs:192-214` hands any unauthenticated caller an active client with eleven scopes including `claims:write`; and `provision.rs:43-45` treats an empty provider allowlist as **allow-all**, documented as such at `traits.rs:51-65`.
*Files:* `repos/agent.rs` (`ensure_for_client`, `ensure_personal_group`, `get_public_profile`), `repos/oauth_client.rs` (the missing UPDATE), `repos/group.rs` (`create_with_admin`, `count_live_admins_excluding`), `oauth/token.rs`, `oauth/providers/provision.rs` (**fail-closed allowlist + `allow_all_identities`**), `oauth/providers/traits.rs` (doc-comment correction), `oauth/register.rs` (**auto-activation kill: `status: "pending"`, empty `granted_scopes`**), `routes/groups.rs` (role vocabulary, `did_key`, membership bootstrap), `middleware/group_authz.rs` (`admin` only; delete the dead `creator` branch), `epigraph-core/src/canonical_scopes.rs` (+`instance:admin` as never-granted), `routes/agents.rs`, `routes/mod.rs` (`GET /groups/:id` → protected), `state.rs` (boot assertion for the production allowlist).
*Acceptance:* create-group → add-member → get-member-role round-trips end to end; **`AuthContext.agent_id` is non-null for every authenticated request**; `role` omitted defaults to `reader` (CORRECTED — the plan said `writer`; the shipped `migrations/060:240` column DEFAULT, `group_memberships_role_check`, `routes/groups.rs::default_role` and `middleware/group_authz.rs` all agree on `reader`, which is also least privilege) and does not 500; a second group by the same creator succeeds; `POST /oauth/register` with `client_type: "agent"` returns `status: "pending"` and zero **granted** scopes (`allowed_scopes` still carries `AGENT_PROVISION_SCOPES` — that is the admin-approval input for `POST /api/v1/admin/clients/:id/approve` and must not be stripped); **a Google identity outside `allowed_domains` cannot provision**; the process refuses to boot with `EPIGRAPH_ENV=production`, a configured provider, an empty allowlist and no `allow_all_identities`.
*Tests:* `tests/group_lifecycle.rs`; a test asserting the four role vocabularies agree; a test asserting a `derived` key is refused by `submit.rs`'s verifier; a negative test that a freshly registered agent client cannot read a claim; **a negative test for the IdP allowlist**.
*Blocking:* **PR-03 may not merge before this lands.** If PR-02 slips, the two one-hunk registration gates are cherry-picked into PR-03.

*Carried out of PR-02 (as shipped):*
- **`AgentRepository::get_public_profile` → PR-04.** Both its prerequisites are PR-04 deliverables and neither exists yet: `crates/epigraph-db/src/visibility.rs` (the `Viewer` type §2.4's signature takes) and the `agents.profile_visibility` column §2.4 describes as existing but which appears in zero files under `crates/` or `migrations/`. It is named in no PR-02 acceptance criterion and no PR-02 test. See the 062 row in §3.1: PR-04 must also CREATE the column.
- **Placement corrections (code is right, Files list is stale):** `count_live_admins_excluding` lives in `repos/group_membership.rs`, not `repos/group.rs` (it queries `group_memberships` only, next to `get_member_role`); the production boot assertion lives in `oauth/providers/{mod.rs,build_registry}`, not `state.rs` (`AppState::with_db` is a sync constructor that installs `ProviderRegistry::empty()` and structurally never sees a parsed allowlist).
- **Two rollout actions with no in-release fix**, documented in `docs/deploy.md`: (1) `groups:write` / `groups:admin` are newly REQUIRED and `oauth_clients.granted_scopes` is per-client data, so `bootstrap_canonical_clients` was made convergent and must be re-run; (2) `EPIGRAPH_ENV` is new and therefore unset everywhere, so **unset is treated as production** — otherwise the fail-closed allowlist would land as a silent auth outage rather than a refused boot.

---

**PR-03 — `security(api): invert the router to an anonymous allowlist, add the RFC 6750 challenge, and make the Viewer unforgeable` (D3)**

*Evidence:* 109 `public` registrations reachable with no `Authorization` header (`mod.rs:515-780` + `:798-801` + `bearer.rs:100-102`); of those, 104 return claim content, claim-derived structure, ACLs, embeddings or aggregates. `require_signature` is unreachable through either `create_router` (§4.10). `ApiError::Unauthorized` (`errors.rs:80-84`) emits no `WWW-Authenticate` header, so 104 new 401s would be undiscoverable to every OAuth client.
*Files:* `routes/mod.rs` (both variants: reduce `public` to the 14-route allowlist, move 104 registrations to `protected`, delete the `require_signatures` branches at `:497-513` and `:1013-1027`, **delete the stale comments at `:794-796`**), `middleware/bearer.rs` (`ViewerExtractor`; **delete the stale comment at `:63-65`**), **`errors.rs` (port `challenge_header` from `epigraph-mcp/src/auth.rs:132-140` + boot-time `validate_resource_metadata_url`)**, `middleware/mod.rs` (delete `require_signature`), `state.rs` (rename → `require_packet_signatures`, `:261,:649,:679,:686,:691` + 11 test constructions; add `resource_metadata_url`), `routes/claims.rs:392` (collapse the fallback chain; delete the zero-public-key arm), `crates/epigraph-db/src/visibility.rs` (the two-shape `Viewer`, `SystemReason`, `MaintenanceLease`), **`scripts/_api_client.py:42-48` (emit `agent_id` in the JWT)**.
*Acceptance:* `public_router_allowlist.rs` passes against **both** router variants; every one of the 104 moved routes returns 401 **with a `WWW-Authenticate: Bearer …, error="invalid_token"` header**; `no_anonymous_viewer.rs` and `no_bypass_in_handlers.rs` pass; every in-repo Python script that talks to the API still works; `cargo check --workspace` clean; **§10.1 Q5 (`/metrics`) is decided and implemented**.
*Tests:* `public_router_allowlist.rs`, `no_anonymous_viewer.rs`, `no_bypass_in_handlers.rs`; `read_path_authz_test.rs:125` (`get_claim_anonymous_public_claim_is_full`) **renamed and inverted** to `get_claim_anonymous_is_401`; `:141` unchanged; `rag.rs:1102-1118` and `:1341-1348` flip `OK` → `UNAUTHORIZED`; `routes/mod.rs:1257` (`router_has_expected_routes`) updated; a negative test that an `AuthContext { agent_id: None }` token 401s with `invalid_token` on a protected content route; a test asserting the challenge header is present on every 401 shape.
*Breaking:* the RAG and evidence-search public-access guarantees are revoked. Announce with PR-14's changes.

---

**PR-04 — `feat(db): add tenancy columns, the world and seed groups, the ScopedPool, and the resolvable Viewer`**

*Files:* migrations 061/062/063; `crates/epigraph-db/src/pool.rs` (`ScopedPool`, **`acquire_as`**, `begin_as(&Viewer)`, `unscoped_for_maintenance → (Conn, MaintenanceLease)`, the `after_release` scrub); `visibility.rs` gains `resolve` and `predicate_fragment`; `state.rs` gains the **§0.5 session-GUC probe**. `cargo sqlx prepare` **not** needed.
*Acceptance:* `ADD COLUMN` completes in < 1 s on a 5M-row `claims` fixture (metadata-only); `CREATE INDEX CONCURRENTLY` runs inside the migration and holds no `ACCESS EXCLUSIVE`; **`idx_claims_embedding_hnsw_public` does not exist** (asserted); the session-GUC probe passes against the target cluster **and** correctly refuses against a pgbouncer-in-transaction-mode fixture; **migration 062 has been applied and rolled forward once against a throwaway database before it goes anywhere else** (ops F8 — this is the repo's first `-- no-transaction` migration ever); the pgvector version gate (§10.2 M2) is confirmed.
*Tests:* `qual_guc_coherence.rs` (incl. the scrub test); a `predicate_fragment` unit test asserting **exactly two** distinct strings, the `Scoped` one containing no function call and ordering `visibility = 'public'` first; a test asserting `-- no-transaction` is honoured (migration succeeds, `pg_index.indisvalid` true for all five indexes); a test applying 061 twice; `viewer_ratchet.rs` records the initial `SystemReason::ALL.len()`; `locked_decisions.rs` created with its D3 assertions.

---

**PR-05 — `feat(db): project communities onto groups, de-overload ownership.encryption_key_id, and classify every entity type`**

*Files:* migrations 064/065; `access_control.rs` reads `community_id`, never `encryption_key_id`; `repos/ownership.rs:101` stops writing it; `routes/admin.rs` entity-type registration requires `tenancy_tier` **and performs the §2.5 precondition check**.
*Acceptance:* every `communities` row has a `groups` row and every `community_members ⋈ perspectives` pair a `group_memberships` row; `ownership_key_id_quarantine` is a **view** and is reported, not swallowed; `POST /api/v1/admin/entity-types` without `tenancy_tier` returns 400, and with `tenancy_tier='columns'` on a table lacking policies/FORCE returns 400; `tenancy_tier='unclassified'` is unregisterable.
*Tests:* `tenancy_coverage.rs` (both generators + `tenancy_exempt`); first-ever integration coverage of the `community` partition arm (every existing fixture inserts `'private'`: `tests/common/mod.rs:503-505`, `read_path_redaction.rs:250-251`, `query_claims_redaction.rs:42-43`, `query_claims_by_label.rs:165-166`, `get_claim.rs:92-93`).

---

**PR-06 — `feat(db): make the visibility predicate a required parameter on every claim read`**

Split into two commits on one branch. **Commit 1** adds `viewer: &Viewer` to all 17 `claim.rs` read functions plus the ten other repos and passes a `Bypass` viewer at every existing call site — it compiles, all tests pass, **nothing changes**. **Commit 2** inserts the `{VISIBILITY:alias}` fragment into each query body. `cargo sqlx prepare --workspace -- --tests` + committed `.sqlx/` (6 read-path macro sites: `claim.rs:517,583,1372,4854,4902,4945`).
*Acceptance:* `visibility_lint.rs` passes with zero non-exempt violations **against the generated `PROTECTED` set**; `viewer_ratchet.rs` is monotone-decreasing from PR-04's baseline; **`EXPLAIN (ANALYZE, BUFFERS)` on the `Scoped` dense CTE against a restored production snapshot under `epigraph_app` shows `idx_claims_embedding_hnsw` chosen, and recall@10 versus a `Bypass` ground-truth run is ≥ 0.95 at the measured `f_group`** (§9.4 W10).
*Tests:* `visibility_lint.rs`, `viewer_ratchet.rs`, `crates/epigraph-db/tests/tenant_isolation.rs` (§8), **plus the positive class: each of the 17 read functions returns a `Scoped` viewer's own group-private rows** (§4.5).

---

**PR-07 — `security(api): derive a Viewer on every HTTP read path`**

*Files:* all 39 fail-open sites → `ViewerExtractor`; the 32 hardened `check_content_access` sites → `Viewer`; `routes/crud.rs:1553-1589` returns ids + a 2-D projection at `claims:admin`; `routes/challenge.rs` gains the predicate (§2.4 / §4.9 #23).
*Acceptance:* no handler that returns claim content lacks a `ViewerExtractor` (route-table test); `/themes/:id/embeddings` returns zero raw 1536-d vectors at any `limit`; `GET /api/v1/challenges` returns no `explanation` for a claim the caller cannot read.
*Tests:* `tests/tenant_isolation_http.rs`.

---

**PR-08 — `security(api): authenticate, scope, and viewer-filter the structural-features endpoint`**

*Evidence:* `GET /api/v1/structural-features/:owner_id` is registered inside the `public` Router (`mod.rs:671`), joins `ownership` in three unfiltered queries (`structural.rs:151,178,205`), and its Laplace `epsilon` defaults to `0.0` — noise off (`structural.rs:491-497`, asserted at `:568`). Missed by `map-enforcement-leaks.md` entirely.
*Files:* `routes/mod.rs` (→ `protected`), new `repos/structural.rs` (three queries + `Viewer`; `COARSE_EDGE_TYPES` moves here), `routes/structural.rs` (`epsilon` default 1.0; `epsilon=0.0` requires `claims:admin`).
*Acceptance:* anonymous request returns 401; an authenticated non-member's counts exclude every private node; `epsilon=0.0` without `claims:admin` returns 403.
*Tests:* `tests/structural_features_authz.rs`; the two existing `COARSE_EDGE_TYPES` assertions move with the constant.

---

**PR-09 — `security(mcp): derive a Viewer on every content-reading tool and move inline SQL to the repo layer`**

*Files:* the eight tools with inline SQL (`embeddings.rs`, `batch.rs`, `themes.rs`, `recall_events.rs`, `events.rs`, `graph.rs`, `rdf.rs`, `provenance*.rs`); new `tools/viewer.rs::mcp_viewer`; `auth.rs::unauthenticated_context()` gains `agent_id: Some(server_agent_id)`; the stdio read default becomes `Viewer::resolve(pool, server_agent_id)`; `theme_cluster` clusters within the viewer's visible set (which is the control for `claim_themes`'s `tenancy_exempt` residual, §2.4).
*Acceptance:* `no_inline_sql_in_tools.rs` passes at zero; `every_content_reading_tool_derives_a_viewer` passes; `theme_cluster`'s `wipe_first` default flips to `false`.
*Tests:* `crates/epigraph-mcp/tests/tenant_isolation_mcp.rs` + the MCP/HTTP parity suite (§8.4 #16).

---

**PR-10 — `security(api): filter webhook fan-out and federation forwarding by tenancy`**

The two surfaces RLS structurally cannot reach — an in-process bus is not SQL.
*Evidence:* `routes/webhooks.rs:255-289` filters only `sub.active` and `sub.event_types`; the payload carries `claim_id`, `agent_id`, `initial_truth` (`epigraph-events/src/events.rs:96-103`). `WebhookSubscription` is `Arc<RwLock<HashMap<Uuid, WebhookSubscription>>>` in `state.rs:82-104` with **no table**, and its `owner_id` is an `oauth_clients.id`, not an `agents.id`, and `None` for pre-auth subscriptions. There is nothing to join, which is why a filter is not enough and a migration is required.
*Files:* a migration persisting subscriptions with an `agent_id` FK; `owner_group_id` added to `EpiGraphEvent`; `routes/webhooks.rs:145,162` gain auth extractors; `epigraph-mcp/src/federation/` forwards the `Viewer` group set as a header.
*Acceptance:* a subscription owned by group A never receives an event for a group-B claim; `list_webhooks` requires auth.
*Tests:* `tests/webhook_tenancy.rs`.
*Note:* this is the one migration whose number is not fixed in §3.1. It takes the next unused number in the reserved 060–085 range at the time it lands (081 if nothing else has claimed it), and the §3.1 table is updated in the same commit. It is numbered rather than slotted because PR-10 lands in week 6–8, ahead of PR-13's 068/069, and renumbering the whole series to keep landing order and version order identical would burn version numbers in a space shared with `epigraph-internal` (ops F2) for no operational gain — sqlx applies by version, and `set_ignore_missing(true)` (`crates/epigraph-api/src/lib.rs:54`) already tolerates the ordering.

---

**PR-11 — `security(authz): replace assign_ownership with a fail-closed, resource-aware write gate`**

*Files:* new `crates/epigraph-authz`; `epigraph-interfaces/src/policy.rs` rewrite (`ResourceRef`, `Decision`); `AllowAllPolicyGate` behind `#[cfg(any(test, feature = "insecure-allow-all"))]`; delete `EncryptionProvider` and `OrchestrationBackend`; the 13 write call sites.
*Acceptance:* a `reader`-role member cannot write to their group; a fresh `AppState` denies by default (the inverse of today's `default_gate_allows_all`).
*Tests:* `crates/epigraph-authz/tests/fail_closed.rs`; updated `epigraph-core/tests/extensions.rs`.

---

**PR-12 — `feat(cli): batched, resumable tenancy backfill, with write-side stamping`**

*Files:* `epigraph-tenancy-backfill` (with a `verify` subcommand whose **exit code replaces migration 071's in-transaction guard**, ops F16); migrations 066 (triggers, statement-level) and 067 (compat shim, maintenance-owned).
*Acceptance:* resumable across a `kill -9`; `FOR UPDATE SKIP LOCKED`, 5–10 k rows/batch; every entity in `tenancy_backfill_progress` reaches complete; **`SELECT count(*) FROM claims WHERE owner_group_id = <world>` is 0** (D2's derivation is total); a final `LEFT JOIN … WHERE owner_group_id IS NULL` returns zero; every `ownership` row it transcribes writes a `tenancy_transcription_log` row; **`tenancy_undeclared_writes` begins accumulating and is exported as a Prometheus gauge** (this is the instrument §9.2's W11 gate reads).
*Tests:* `tests/backfill_idempotence.rs`; a test asserting `supersede` of a `('group', G)` claim yields a `('group', G)` successor; a test asserting evidence of a group-private claim comes out group-private; **a test asserting each of the eight §2.4-added tables inherits correctly** (challenges, reasoning_traces, experiment_triples, experiment_entity_mentions, claim_clusters, claim_cluster_membership, claim_neighborhood_membership, claim_signature_revocations); a test asserting the statement trigger issues one UPDATE per table per statement, not per row.

---

**PR-13 — `feat(db): edge co-ownership so the endpoint meet is expressible`**

*Evidence:* `edges.owner_group_id` is a single uuid and cannot express two owning groups; 066(b) resolves that at write time by raising, but privatization cannot raise — an existing edge would let any writer veto privatization.
*Files:* migrations 068 (transactional: column, constraints, **and the `CREATE OR REPLACE` of both 066(b) and 066(d)** — ops F19) and 069 (`-- no-transaction` index only — ops F8); `Viewer::edge_predicate_fragment`; the `edges_tenancy` policy clause pre-staged for 073.
*Acceptance:* an edge between a group-G claim and a group-H claim is stored as `('group', G, co_owner=H)`; a viewer in G but not H cannot see it; a viewer in both can; **`epigraph_propagate_tenancy`'s body after 068 contains the three-CASE meet** (asserted by reading `pg_proc.prosrc`, so the prose/SQL divergence cannot recur).
*Tests:* `tests/privatization_boundary.rs` (all four endpoint combinations); a migration test applying 068 twice.

---

**PR-14 — `refactor(api,mcp): delete redaction; a non-visible row is absent, not blanked`**

*Files:* delete `epigraph-db/src/access_control.rs`, `epigraph-mcp/src/tools/redaction.rs`, `check_content_access` / `batch_check_content_access`, `routes/ownership.rs`, MCP `assign_ownership` / `update_partition` (and their `SCOPE_MAP` entries).
*Acceptance:* a redacted-claim response shape no longer exists; three assertions in `read_path_authz_test.rs` flip from `[REDACTED]` to absent; `get_claim(private_id)` and `get_claim(random_uuid)` produce byte-identical responses for a non-member.
*Tests:* §8.4 #15, #19.
*Breaking:* announce together with PR-03's RAG change.

---

**PR-15 — `fix(ops): give every background writer a maintenance DSN before FORCE lands` (NEW)**

*Evidence:* three verified facts that together make PR-17 an outage. (a) `bin/server.rs:203-240` builds `job_pool` from the **same `DATABASE_URL`** as the API pool, so the privatization apply/revert handler would run with `epigraph_bypass()` false and be rejected by `claims_tenancy`'s `WITH CHECK` on its first UPDATE. (b) **14 of the 26** CLI binaries read `DATABASE_URL` (`embed_backfill.rs:20`, `prune_recall_events.rs:29`, `reembed.rs:57`, `analyze_graph.rs:24`, `bridge_component.rs:216`, `bridge_sweep.rs:261`, `rerank_bridges.rs:274`, `cross_source_sweep.rs:96`, `retire_match_candidates.rs:127`, `embed_bridge.rs:339`, `ingest_document.rs:25`, `dekg.rs`, `bootstrap_clients.rs:32`, plus `hypothesis.rs`/`method_search.rs`); under `FORCE` as `epigraph_app` they see only `visibility='public'` and their `UPDATE … WHERE id = $1` statements match **zero rows and exit 0**. `embed_backfill` silently stops embedding private claims; `prune_recall_events` prunes nothing. This is R2 at fleet scale, with no error anywhere. (c) `scripts/theme_lib.py:16` hardcodes `postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph` — **a fourth role no prior revision named** — and `scripts/fuzzy_dedup_claims.py:243` writes `INSERT INTO edges (…)` directly from psycopg2.
*Files:* new `crates/epigraph-jobs/src/pool.rs` and `crates/epigraph-cli/src/pool.rs` (a shared constructor reading `MAINTENANCE_DATABASE_URL`, falling back to `DATABASE_URL` **with a WARN**, and asserting `SELECT epigraph_bypass()` is true at startup — refusing to run otherwise); `bin/server.rs` (job pool moves to the maintenance DSN); the 14 CLI binaries; `scripts/theme_lib.py`; `scripts/fuzzy_dedup_claims.py`; `docs/runbooks/` deploy checklist; new `crates/epigraph-db/tests/no_unmaintained_dsn.rs`.
*Acceptance:* every background writer either uses the maintenance pool or is on an explicit exemption list with a reason; `no_unmaintained_dsn.rs` passes; a smoke run of `embed_backfill`, `prune_recall_events` and `recompute_beliefs` against a fixture with `FORCE` on and a private claim **updates the private claim** (the positive assertion, not "does not error"); `epigraph_admin` is either mapped to `epigraph_maintenance` or documented as a fourth deliberate role.
*Depends on:* PR-01 (the roles exist). **PR-17 may not merge before this lands.**

---

**PR-16 — `feat(db): ownership is REQUIRED — drop the defaults, arm the trigger, validate` (D1)**

*Evidence:* D1. A `DEFAULT 'public'` in `pg_attrdef` is the same "public by omission" defect as `access_control.rs:68`, one layer down.
*Files:* migrations 070/071/072; **the 13 production `INSERT INTO claims` statements from §4.6** gain a `TenancyDecl` parameter (**4** of them are macros — `create` :228, `create_with_tx` :440, `batch_create` :1972, **`consolidate` :4653 `sqlx::query_scalar!`** — so `cargo sqlx prepare --workspace -- --tests` + committed `.sqlx/`); `consolidate`'s meet rule (§4.6); `epigraph_seed` granted to the test harness pools; `epigraph-migrate` takes `MIGRATION_DATABASE_URL`; **`.github/workflows/ci.yml` updated in the same PR** (ops F9 — CI runs `./target/debug/epigraph-migrate` at `ci.yml:117` with only `DATABASE_URL` set at `:30`, so omitting the workflow turns CI red on merge); boot assertions gain `tgenabled='O'`, not-a-member-of-`epigraph_seed`, and `current_user = 'epigraph_app'`.
*Acceptance:* §8.2's five SQL acceptance queries all return empty/zero — **including A4, which is now achievable because arm 4 stamps the seed group, not world**; `INSERT INTO claims` as `epigraph_app` naming neither column raises `23502` with the `docs/tenancy.md` HINT; the same as `epigraph_seed` succeeds and yields `('public', <seed group>)`; the app role cannot DDL; `epigraph-tenancy-backfill verify` exits 0 before 071 runs; **CI is green**.
*Tests:* `crates/epigraph-db/tests/tenancy_required.rs` (§8.2), including a `consolidate` case for each of same-group / cross-group / mixed-visibility.
*Deploy ordering (ops F10) — this is the largest single outage risk in the plan:* **the migrations do not ship in the same deploy step as the code.** Three steps, in order: **(i)** deploy the binaries carrying the 13 patched call sites, with 070 *not yet applied*; **(ii)** observe `tenancy_undeclared_writes` (PR-12's counter) flat at zero for **24 hours**; **(iii)** run 070/071/072. During any rolling deploy that skipped step (ii), the previous pods still run `ClaimRepository::create` without the columns and every claim write raises `23502` the instant 070 commits.

---

**PR-17 — `security(db): row-level security policies, FORCE, and a canary that proves it`**

*Files:* migrations 073/074/075; boot assertions in `AppState::with_db`; a 60-second canary health metric.
*Depends on:* **PR-15** (maintenance DSNs) and PR-16.
*Acceptance:* the process refuses to serve as a superuser or `BYPASSRLS` holder, refuses if `pg_class.relforcerowsecurity` is false on any protected table, refuses if the canary row is visible on the app connection, refuses if `current_user <> 'epigraph_app'`, refuses if the §0.5 session-GUC probe fails, and refuses if any tenancy trigger is not `tgenabled='O'`; the `group_memberships` policy does **not** recurse; **a token mint (`ensure_for_client` + `UPDATE oauth_clients SET agent_id`) succeeds under `FORCE` as `epigraph_app`** (the direct sec-F13 regression); **a `Scoped` viewer reads its own group-private rows at all 17 `claim.rs` read functions** (the sec-F1 regression); **the privatization apply job writes successfully on the maintenance pool** (the ops-F5 regression); a `recall_events` row with `agent_id IS NULL` is **not** visible to a session whose principal GUC is unset.
*Tests:* `rls_enforcement.rs` (incl. the `pg_policy.polcmd` per-command coverage table), `no_unscoped_pool.rs`, `qual_guc_coherence.rs` under `FORCE`.

---

**PR-18 — `feat(admin): privatization plans, preview, and restrict-mode apply` (D4)**

*Evidence:* D4. The draft's only surface was a single-row PATCH with no hull, no boundary handling, no preview, no audit and no revert.
*Files:* migrations 076/077/078/079; `repos/privatization.rs`; `repos/instance_admin.rs`; `routes/privatization.rs`; `middleware/instance_authz.rs`; `epigraph-jobs/src/privatization.rs` (Apply, Revert, Reseal, all on `MaintenancePool`, all re-validating per §6.5.5); the six MCP tools + `SCOPE_MAP`; `epigraph-instance-admin` and `epigraph-privatize` CLIs; `PATCH /claims/:id/visibility` rewritten as one-item-plan sugar that **enqueues**.
*Depends on:* **PR-17 (FORCE RLS)** — privatization whose enforcement is repo-layer-only is a promise, not a control. Also PR-13 (co-ownership) and PR-15 (maintenance pool).
*Acceptance:* preview of a 17-seed / depth-3 plan returns within `statement_timeout` and reports `authors_losing_own_claims`, `boundary_edges.by_relationship`, the omitted-edge-type warning, and `not_visible_to_actor` **as a count with no ids** (sec F7); `apply` with a stale digest returns 409; `approve` by `created_by` returns 409; **`approve` by an instance admin who is not an admin of the target group returns 409**; **a plan against a group younger than 24 h, or with fewer than 2 other live admins, returns 403** (sec F4); a `restrict` round trip is **bit-identical on `content`, `content_tsv` and `embedding`**; `instance_admins` is empty after migration and every privatization attempt 403s until an operator grants; **a hand-enqueued `privatization_apply` job is refused by the handler** (sec F5); **the post-apply drift rescan creates a follow-up plan when a `derived_from` child is inserted mid-flight** (sec F9); **a `mode='seal'` plan whose items are all unsealed can be reverted, and one with sealed items returns 409** (ops F13).
*Tests:* `privatization_closure.rs`, `privatization_hull.rs`, `privatization_boundary.rs`, `privatization_resume.rs`, `privatization_revert.rs`, `privatization_drift.rs`, `privatization_authz.rs` (§8.6).

---

**PR-19 — `feat(privacy): client-side content sealing with entity-bound AAD`**

*Files:* `crates/epigraph-privacy` (encryptor with the 1-byte field tag, pre-padded plaintext, and the version/evidence variants; `Confidentiality`, `GroupRole`, errors, `rewrap`); the two `key_exchange.rs` fixes from §5.1; `epigraph-group` CLI.
*Acceptance:* `encrypt_claim_content` for the same `(uuid, epoch)` in the content, labels, properties, version and evidence fields produces **five different AADs**; a wrapped share transplanted to another group/epoch/member fails to unwrap; `ecdh_shared_secret` output is a KDF result, not the raw DH point, and rejects a non-contributory exchange.
*Tests:* the 7 ported encryptor tests plus a field-tag separation test across all six tags and two transplant tests.

---

**PR-20 — `feat(api): atomic key rotation, gated on a recoverable retired epoch`**

*Files:* `repos/group_key_epoch.rs::rotate_tx`; `POST /groups/:id/rotate`; `remove_member` sets `status='rotating'` **and `groups.reseal_required_at`** (§6.7); the `epigraph_groups_reseal_required` gauge.
*Acceptance:* rotation is refused unless the retiring epoch's key is recoverable (`wrapped_key IS NOT NULL` **or** `groups.properties->>'kms_key_ref' IS NOT NULL`); after rotation every live member has a `wrapped_key_share` at epoch N+1 and exactly one epoch is `active`; **the response body and `docs/tenancy.md` both state that rotation does not revoke access to already-sealed content** (§6.7); `reseal_required_at` is set on member removal and surfaced by `GET /groups/:id`.
*Tests:* `tests/group_rotation.rs`, including an assertion that a revoked member's retained share still decrypts pre-rotation ciphertext — **written as a documented property, not a bug**, so nobody later mistakes rotation for revocation.

---

**PR-21 — `feat(admin): seal mode — client-driven subgraph encryption` (D4, second half)**

*Files:* the seal/unseal manifest protocol in `routes/privatization.rs` covering the **full §6.5.4 TCB**; `PrivatizationResealHandler`; `epigraph-privatize` seal/unseal/reseal subcommands; length padding; the CLAUDE.md audit-SQL clauses; `find_claims_needing_embeddings`' `claim_encryption` exclusion (if not already in PR-06); `unseal-commit`'s `EmbeddingGeneration` enqueue (ops F14).
*Depends on:* PR-18, PR-19, PR-20.
*Acceptance:* after `seal` — `embedding IS NULL` on the claim **and on its evidence**; `length(content)` constant modulo the uuid; `array_length(tsvector_to_array(content_tsv),1) <= 2`; `octet_length(encrypted_content) % pad_to = 0`; two claims with 1-byte and 200-byte plaintexts have **equal** ciphertext length at `pad_to=256`; `content_hash` differs between two sealed claims with identical plaintext (the `[private]` collision regression); `sealed_with_embedding` is 0 **on both `claims` and `evidence`**; **`pg_dump --data-only | grep -c <nonce>` returns 0** (the sec-F3 corpus-wide regression); `claim_versions.content` for a sealed claim is a sentinel; a seal-commit missing any TCB member is **refused, not partially applied**; unseal restores `content_tsv` with no bespoke code and enqueues an embedding job per item; **seal-then-declassify raises `42501` unconditionally** (sec F11).
*Tests:* `crates/epigraph-db/tests/seal_side_channels.rs`.

---

**PR-22 (later) — `chore(db): retire the ownership table`**

Migration 080, one release after PR-14, gated on **both** pre-flights: an empty `ownership_key_id_quarantine` **view** and zero non-public `ownership` rows without a `tenancy_transcription_log` entry.
*Acceptance:* both `DO $$` blocks pass without raising; `grep -rn "ownership" crates/ --include='*.rs'` returns only historical comments; `docs/runbooks/080-undo.sql` exists and is honest about what it cannot restore.
*Tests:* a migration test seeding an untranscribed non-public `ownership` row and asserting 080 raises.

---

## 8. Test strategy

### 8.1 Unit (`cargo test -p epigraph-db --lib`)

`Viewer` construction/shape exhaustiveness; `predicate_fragment` returns **exactly two** distinct strings, the `Scoped` one containing no function call and ordering `visibility = 'public'` first, the `Bypass` one whitespace-only; `SystemReason::ALL` matches the enum by exhaustive `match`; `Confidentiality` / `GroupRole` `from_db_str` rejects `member`, `creator`, `encrypted_content`; the visibility predicate truth table (public/group × in-group/out-of-group × NULL/empty array); the `consolidate` meet rule (§4.6) as a pure function over `Vec<(Uuid, Visibility)>`.

### 8.2 D1 acceptance — SQL and Rust

```sql
-- A1. No tier-A column carries a default.
SELECT c.table_name, c.column_name, c.column_default
  FROM information_schema.columns c
 WHERE c.table_schema = 'public'
   AND c.column_name IN ('visibility','owner_group_id')
   AND (c.column_default IS NOT NULL OR c.is_nullable = 'YES');
-- must be empty

-- A2. Every table found by §2.4's Generator A or B has both columns or a
--     tenancy_exempt row. (This is the assertion the previous revision's
--     hand-written eight-table list could not make.)
-- must be empty

-- A3. No black holes.
SELECT count(*) FROM public.claims
 WHERE visibility = 'group'
   AND owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid;
-- must be 0

-- A4. The backfill produced real stewards, not world placeholders (D2).
--     ACHIEVABLE ONLY BECAUSE arm 4 stamps the SEED group (sec F14): the
--     previous revision asserted A4 and simultaneously asserted that a
--     seed-role insert "yields ('public', world)", which cannot both hold on
--     any database where the test suite has run.
SELECT count(*) FROM public.claims
 WHERE owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid;
-- must be 0 — claims.agent_id is NOT NULL (001:606), so the derivation is total

-- A5. Every tenancy trigger is armed.
SELECT tgname, tgenabled FROM pg_trigger
 WHERE tgname LIKE '%_require_tenancy' OR tgname IN
       ('claims_propagate_tenancy','claims_block_widening','edges_tenancy');
-- every tgenabled must be 'O'
```

`crates/epigraph-db/tests/tenancy_required.rs`, run against `epigraph_db_repo_test`:

- as role `epigraph_app`, `INSERT INTO claims (content, content_hash, agent_id, truth_value)` raises `23502` with the `docs/tenancy.md` HINT;
- as role `epigraph_seed`, the same statement succeeds and yields `('public', <seed group>)` — **and `owner_group_id <> world`**;
- `ClaimRepository::supersede` of a `('group', G)` claim yields a `('group', G)` successor;
- a successor that explicitly requests `'public'` over a `'group'` predecessor raises `42501`;
- **`evolve_step` on a group-private lineage yields a group-private step, and a step that explicitly requests `'public'` in a group lineage raises `42501`** (the arm-3 gap, now symmetric with arm 2);
- **`ClaimRepository::consolidate` of two same-group private claims yields a private merged row; of a private and a public claim yields a private merged row; of two claims in *different* groups is refused** (ops F1);
- `UPDATE claims SET visibility='public'` on a group row raises `42501` unless `epigraph.allow_declassify='yes'`; **and raises unconditionally when a `claim_encryption` row exists** (sec F11);
- an `evidence` row inserted against a group-private claim comes out group-private;
- **a `challenges` / `reasoning_traces` / `experiment_triples` / `claim_cluster_membership` row inserted against a group-private claim comes out group-private** (sec F2);
- `ALTER TABLE public.claims ALTER COLUMN visibility SET DEFAULT 'public'` executed by the app role is refused.

### 8.3 Repo-level — `DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph_db_repo_test`, never the live `epigraph` DB

- `schema_contract.rs` — the only guard against runtime-`sqlx::query` schema drift.
- `tenant_isolation.rs` — the core adversarial suite, per repo function.
- `rls_enforcement.rs` — per protected table: stranger sees 0; **owner sees N** (§8.4's new positive class); a `reader` INSERT raises `42501`; a cross-group edge is co-owned and invisible to a single-group viewer; `group_memberships` policy does **not** recurse; **every table with `relrowsecurity` has a policy for each of SELECT/INSERT/UPDATE/DELETE or a recorded exemption, enumerated from `pg_policy.polcmd`**.
- `qual_guc_coherence.rs`, `tenancy_coverage.rs`, `tenancy_required.rs`, `locked_decisions.rs`.
- The nine ratchets: `visibility_lint.rs`, `viewer_ratchet.rs`, `no_unscoped_pool.rs`, `no_inline_sql_in_tools.rs`, `no_anonymous_viewer.rs`, `no_bypass_in_handlers.rs`, `public_router_allowlist.rs`, `no_unmaintained_dsn.rs`, `locked_decisions.rs`.

### 8.4 Adversarial / negative — and the positive class the previous revision lacked

The existing `read_path_authz_test.rs` (19 cases) is **not** treated as coverage. Under D3 one case is *inverted* (`:125`) and the `no_token_spoofed_owner_is_redacted` family at `:49, :163, :206, :288, :359, :542, :628, :732, :836, :907` each gains a companion asserting **401** rather than `[REDACTED]`.

> **The structural gap in the previous revision's whole suite.** Every assertion was of the form *"a stranger CANNOT read X"*. A mechanism that returns **nothing to anybody** passes all of them. That is exactly what its FORCE-plus-GUC-less design would have produced (§0.5), and no test in it could have failed. **Class P below is not optional garnish; it is the only thing that detects a fail-closed regression.**

**Class P — positive (new, mandatory):**

- **P1.** Under `FORCE`, a `Scoped` viewer over group G, through `acquire_as`, retrieves exactly its own N group-private claims — **at each of the 17 `claim.rs` read functions in §4.11**, parameterised.
- **P2.** The same through `begin_as` (`EPIGRAPH_SESSION_GUC_MODE=transaction`).
- **P3.** The same after a checkout → release → checkout cycle, proving the scrub does not strand the second request.
- **P4.** A group member's `recall` over a query semantically identical to their **own** group-private claim returns that claim, ranked, at the expected cardinality — the counterpart of N1 below.
- **P5.** `embed_backfill`, `prune_recall_events` and `recompute_beliefs` on the maintenance pool with `FORCE` on **modify a private row** and report a non-zero row count (the ops-F6 regression).
- **P6.** A token mint under `FORCE` as `epigraph_app` writes the `agents` row and the `oauth_clients.agent_id` update (the sec-F13 regression).
- **P7.** The privatization apply job, on the maintenance pool with `FORCE` on, moves a claim from `public` to `group` and propagates to **all seventeen** derived tables (the ops-F5 + sec-F2 regression).

**Class N — negative**, each mapping to a named leak:

1. Agent B's `recall` over a query semantically identical to A's private claim returns **zero** rows — not a redacted row.
2. Agent B's `recall` with the embedder forced down (lexical fallback) returns zero rows for a term appearing only in A's private claim. *(closes `content_tsv`)*
3. `POST /search/semantic` as B ranks zero of A's private claims.
4. `GET /themes/:id/embeddings` returns no vector belonging to A's private claim, at any `limit`.
5. `embedding_neighborhood_density` with a probe vector derived from A's private claim returns `count = 0` for B.
6. `content_hashes_for` **omits** — does not blank — B-invisible ids.
7. `traverse` from a public claim into a private neighbour stops at the boundary; the private id never appears.
8. `get_provenance` on a claim whose ancestor is private omits the ancestor.
9. `search_triples` / `entity_neighborhood` return no `subject_name` or `object_literal` derived from A's private claim.
10. `get_recall_events` as B returns none of A's queries — **and a `recall_events` row with `agent_id IS NULL` is invisible to a session whose principal GUC is unset** (the sec-F1 inverse-leak regression).
11. **Pagination completeness:** with 100 private + 100 public claims and `limit=10`, an authenticated non-member receives exactly 10 rows, not 3.
12. **Supersede inheritance:** parameterised over **all 13** production write statements.
13. **Revoked member:** revoking B's membership makes A's group claims invisible to B on the **next request**, with no token refresh. **And the paired case: a claim B *sealed* under the pre-revocation epoch is still decryptable by B's retained share** — asserted as the documented property in §6.7, not as a bug.
14. **Cross-group edge:** a viewer in G but not H cannot see a G↔H edge; a viewer in both can.
15. **Existence indistinguishability:** `get_claim(private_id)` and `get_claim(random_uuid)` produce byte-identical responses for a non-member.
16. **MCP/HTTP parity:** one parameterised suite asserting `traverse`, `get_provenance` and visibility-set operations reach *identical* row sets on both transports.
17. **Canary:** invisible to `epigraph_app`, visible to `epigraph_maintenance`.
18. **Trigger integrity:** `pg_trigger.tgenabled = 'O'` for all tenancy triggers.
19. **No anonymous anything:** for each of the 104 moved routes, a request with no `Authorization` header returns 401, a zero-length body, **and a `WWW-Authenticate` challenge**.
20. **New tier-A tables:** `GET /api/v1/challenges`, MCP `list_challenges`, and a direct read of `reasoning_traces` / `experiment_triples` / `claim_clusters` return nothing derived from A's private claim (sec F2).
21. **Unique-constraint oracle:** an insert colliding with `idx_edges_unique_triple` on a private edge returns a generic conflict, not `23505` naming the row (§8.5).
22. **Preview oracle:** an instance admin who is not a member of group B creates a plan whose predicate selects B's private claims; the response contains **counts only** — no ids, no content previews, no `current_owner_display_name` for those items (sec F7).
23. **Registration ceiling:** with `allow_all_identities` unset and an empty provider allowlist, an external identity cannot provision (sec F6).

### 8.5 The written rule that closes the existence oracle

> **Any operation on a resource the `Viewer` cannot read returns byte-identical status and body to a nonexistent resource. `403` is reserved for authorization failures on resources the caller can already see.**

`claims.id` is `gen_random_uuid()` (`001:602`), so there is no id enumeration. The remaining dangling-reference channels are **two**, not one: `claims.supersedes` on a public successor pointing at a now-private predecessor, **and `claims.step_lineage_id` shared with a public sibling** — which is why the D4 hull walks `supersedes` in both directions **and** unions the step lineage (§3/076, sec F8).

Unique-constraint oracles are the other residual: `idx_edges_unique_triple UNIQUE (source_id, target_id, relationship)` (`001:2561`) leaks the existence of a private edge via `23505`. Fix: map `23505` on protected tables to a generic conflict plus a `Viewer` pre-check. `groups_did_key_key` and `pattern_templates_name_key` are **not** reachable by an untrusted writer once `groups:write` gates group creation and `pattern_templates` has no registered route, so the surface is `edges` and `claims`' content-hash guard — not "every unique constraint."

### 8.6 D4 tests

- `privatization_closure.rs` — closure over a fixture with a cycle; mixed relationship case (`DERIVED_FROM` and `derived_from` must **both** match); depth bound honoured; node cap **refuses rather than truncates**; structural edge types rejected with 400.
- `privatization_hull.rs` — after a one-seed plan, all four hull arms are private: the `supersedes` chain **in both directions**, **the `step_lineage_id` siblings** (sec F8), `claim_versions`, and `evidence`. **This is the regression guard for the three verified misses.**
- `privatization_boundary.rs` — the meet rule over all four endpoint combinations including cross-group `co_owner_group_id`.
- `privatization_resume.rs` — apply, abort at batch 3 of 10, resume, assert the final state equals the uninterrupted result; assert the **downward-closure invariant holds at every commit boundary**; assert re-running a committed batch is a byte-level no-op on all seventeen derived tables (the ops-F11 idempotence claim, now actually true).
- `privatization_revert.rs` — `restrict` round trip is bit-identical on `content`, `content_tsv` and `embedding`; **`seal` revert is permitted once unsealed and 409s while sealed** (ops F13).
- `privatization_drift.rs` — insert a `derived_from` child mid-apply; assert the edge guard refuses it, and that a maintenance-pool insert is caught by the post-apply rescan and produces a follow-up plan (sec F9).
- `privatization_authz.rs` — each of §6.6's conditions failing independently produces 403, **including the 24 h maturity and 2-other-admins conditions**; `approve` by `created_by` produces 409; `approve` by a non-target-group admin produces 409; `apply` with a stale digest produces 409; `reassign` without dual group admin produces 403; **a hand-enqueued `privatization_apply` job is refused by the handler** (sec F5).
- `seal_side_channels.rs` — PR-21's acceptance list, headlined by the corpus-wide `pg_dump | grep <nonce>` assertion.
- Adversarial, in the §8.4 style: after privatizing, an authenticated non-member gets 404 from `get_claim`, zero rows from `recall`, zero from the lexical leg, no edge from `traverse`, and `content_hashes_for` **omits** rather than blanks the id.

---

## 9. Rollout & backfill

### 9.1 The adversarial starting state, stated plainly

**Zero claims have an `ownership` row** — `rg "INSERT INTO ownership|OwnershipRepository::assign"` hits only the repo itself, one HTTP handler, one MCP tool, and five test fixtures — so every claim is public *by absence* rather than by decision, and `access_control.rs:64-68` returns `Full` for absence *and* for any DB error. `migrations/057` documents ~1,198 one-shot orphan agents, and `routes/claims.rs:420` trusts a caller-supplied `request.agent_id`, so a meaningful share of any backfilled owner will be **wrong**, not missing.

That is precisely why D2 is the right call and why D4 exists: the corpus cannot be safely privatized by an automatic sweep, so it is declared public explicitly and then privatized region by region, by a named admin, with a preview and an audit trail.

### 9.2 Week plan

| Week | Action | Revert |
|---|---|---|
| 0 | **Version-space check and shadow.** Run the prod `_sqlx_migrations` query (§3.0) and confirm 060–085 is clear. Ship the predicate warn-only: every retrieval runs twice and results are compared, `visibility.shadow.divergence{route, viewer_kind, n_hidden}` emitted, callers get the unfiltered result. The shadow leg is **not** `Viewer::system("shadow")` — that needs a `MaintenanceLease` — but a `Scoped` viewer whose `group_ids` is the full group set, on the ordinary `epigraph_app` connection, which is bypass-equivalent while RLS is not yet forced | env flag |
| 1 | **PR-01** (fixes the live 500; reserves the version range; `EPIGRAPH_MIGRATE_ON_BOOT` off), **PR-02** (identity + both registration gates), **PR-03** (router inversion + RFC 6750 challenge). **Gate between PR-02 and PR-03:** *% of active OAuth clients whose `agent_id` is non-null* must be **100 %** | revert PR |
| 2–3 | PR-04, PR-05. **Gate:** `AuthContext.agent_id` non-null for **100 %** of authenticated requests over 24 h; the §0.5 session-GUC probe passes on the target cluster | env flag |
| 4 | PR-12 backfill starts; `tenancy_undeclared_writes` begins recording | config |
| 5 | **Backfill** — batched, resumable, `FOR UPDATE SKIP LOCKED`, 5–10 k rows/batch, watermarked. D2: explicit `('public', <author's personal group>)` | resumable |
| 6–8 | PR-06/07/08/09/10/11 land; `EPIGRAPH_VISIBILITY_ENFORCE=shadow`, flipped to `on` **per route**, most-hardened first | per-route flag |
| 9 | PR-13 (edge co-ownership), PR-14 (delete redaction), **PR-15 (maintenance DSN fleet)** | revert PR |
| 10 | **Gate before RLS** (§9.4), and the D1 deploy gate below | — |
| 11a | **Deploy the PR-16 binaries only.** The 13 patched `INSERT INTO claims` call sites ship; migrations 070/071/072 are **not** applied | revert PR |
| 11b | **Observe.** `tenancy_undeclared_writes` must be **flat at zero for 24 h** across every tier-A table. A non-zero count names the table and the offending write path | — |
| 11c | Run `epigraph-tenancy-backfill verify` (exit 0 required), then migrations **070**, then **071**, then **072** as three separate steps | `docs/runbooks/070-undo.sql` |
| 11d | **PR-17:** point `DATABASE_URL` at **`epigraph_app`**, confirm the six boot assertions and the session-GUC probe, then run 073/074/075 | `NO FORCE` + revert URL — **sub-minute, no data change** |
| 12 | **PR-18 — the D4 privatization surface ships.** `restrict` mode is usable on its own from this point | `revert` the plan |
| 13+ | PR-19/20 (sealing primitives, rotation), PR-21 (`seal` mode), then PR-22 (drop `ownership`) | — |

**The 11a/11b/11c split is not ceremony.** Landing the call-site edits and migration 070 in one deploy means that, during any rolling deploy, the previous pods are still running `ClaimRepository::create` without the two columns, and the instant 070 commits every claim write from an old pod raises `23502`. The undeclared-write counter is the instrument that makes step 11b a measurement rather than a hope.

### 9.3 Default visibility — settled, not open

- **D2: the backfill sets explicit `public` for every pre-existing row**, `owner_group_id` = the author's personal group. Backfilling to private is defensible on principle and catastrophic in practice: most claims' owner resolves to an orphan agent nobody authenticates as, so `recall` would go dark for everyone simultaneously.
- **D3: `public` means *any authenticated agent*.** Even the "no-op" is a strict tightening relative to today. **With the honest ceiling from §4.9 fact 2 attached:** it is a tightening *to whoever the IdP gate admits*, and PR-02 is what makes that gate exist.
- **New writes** are controlled by `EPIGRAPH_VISIBILITY_DEFAULT` = `public` | `personal` | `group:<uuid>`, per-agent-overridable via `agents.default_group_id`. **Under D1 this is not a database `DEFAULT`** — it is the value the *application* names explicitly on every INSERT.
- **D4: reclassification of the existing corpus is an explicit operator action**, never a code change and never an automatic migration.

The owner-resolution gate, restated for D1/D2:

```
% of is_current claims whose owner_group_id resolves to an agent
with a live OAuth client and key_kind='ed25519'
```

Bar: **≥ 90 %** before flipping `EPIGRAPH_VISIBILITY_DEFAULT` away from `public`. Below it, the default stays `public` and the tenancy machinery protects only newly written group content plus whatever admins have privatized through D4. That is still a real capability, and it is the honest ceiling on this database.

### 9.4 The W10 pre-RLS gate — named pass/fail criteria

**Run all of these against a restored production snapshot as the `epigraph_app` role with `FORCE ROW LEVEL SECURITY` active — never an empty `epigraph_db_repo_test`.**

1. **Partition split.** `SELECT visibility, count(*) FROM claims WHERE is_current AND embedding IS NOT NULL GROUP BY 1;` → let `f_group` = the private fraction. **Re-run monthly after PR-18 ships.**
2. **Recall@k under post-filter.** For k ∈ {10, 50, 100} and 200 sampled real `recall` query vectors: run the `Scoped` single-index plan, and the same query as `Bypass` on a maintenance connection as ground truth. Report `recall@k` and p95 latency.
3. **Plan check.** `EXPLAIN (ANALYZE, BUFFERS)` on the `Scoped` dense CTE. Record which index was chosen and whether a `Filter:` appears above the Index Scan.
4. **NEW — the positive criterion (sec F1).** For every one of the 17 `claim.rs` read functions, a `Scoped` viewer over a real group retrieves **exactly** its own group-private rows, at the expected cardinality, through `acquire_as`. Zero-rows-for-everything is a **fail**, not a pass. *This is the criterion whose absence made the previous revision's design look correct.*
5. **NEW — GUC mode cost.** Repeat criterion 2 under `EPIGRAPH_SESSION_GUC_MODE=transaction`. Record the p95 delta. If the session-GUC probe fails on the target cluster, this is the mode that ships, and the number is what the team signs off on.
6. **NEW — background fleet (ops F6).** With `FORCE` on, run `embed_backfill --limit 10`, `prune_recall_events --dry-run` and one belief recompute against a snapshot containing private claims, and assert each **touches a private row** and reports a non-zero count.

**Decision rule.** Build `062b` (the complement index + two-leg rewrite) **iff recall@10 under the single-index post-filter plan falls below 0.95 at the measured `f_group`.** Below `f_group ≈ 1 %` it will not; there, `SET LOCAL hnsw.iterative_scan = 'relaxed_order'` with `hnsw.max_scan_tuples` (**pgvector ≥ 0.8 required**) is sufficient.

Also gated at W10: the shadow delta is zero for public-corpus queries and matches the expected private count for tenant queries, over 7 days; and the pgvector version is confirmed (§10.2 M2).

---

## 10. Risks & open items

### 10.1 Risks

**R1 (highest) — pgvector post-filtering degrades ANN recall for group-scoped search.** RLS quals and the `Scoped` predicate filter the HNSW candidate set *after* the index returns it. Ask for 10, get 10 rows belonging to other groups, receive 0. `recall` is the most-used tool in the system.
*Mitigations, in order:* (a) `SET LOCAL hnsw.iterative_scan = 'relaxed_order'` with `hnsw.max_scan_tuples` — requires pgvector ≥ 0.8, **confirmed available: production runs the 0.8 series (§10.4 M2, answered 2026-08-27)**, so this is the live primary mitigation; (b) the measurement-gated **complement** partial index `062b` plus the two-leg rewrite, whose cost scales with `f_group`; (c) per-group partial HNSW for very large groups; (d) ~~if pinned below 0.8, over-fetch by factor F with documented recall degradation~~ — **no longer reachable**, retained only as the record of what the sub-0.8 world would have cost.
*Note:* D4 makes this risk **shrink over time in the common case and grow in the pathological one**, which is why criterion 1 in §9.4 is re-run monthly.

**R2 — Fail-closed regressions look like data loss, not errors.** A missed repo predicate leaks; a missed *context* silently returns fewer rows. A recall that returns 3 instead of 40 pages nobody. **This risk is now understood to have been realised inside the plan document itself**: the previous revision's FORCE-plus-GUC-less design (sec F1) would have made every group-private row invisible to its own owners, and its entire test suite was structurally incapable of noticing.
*Mitigations:* nine build-failing ratchets (§4.13); **§8.4's Class P positive assertions**, which are the only mechanism that detects over-restriction; `ViewerExtractor` emits `visibility.viewer.rejected{reason, route}` on every 401; the week-0 shadow window; the §9.4 criteria 4–6. *Residual:* a rarely-exercised path shadow traffic does not cover. Accepted.

**R3 — Ops surface: correctness moves partly outside git.** Which role the app connects as, whether `FORCE` survived, whether anyone granted `BYPASSRLS`, whether the replica has matching roles, whether anyone is a member of `epigraph_seed`, whether the tenancy triggers are still `tgenabled='O'`, **whether a transaction pooler was introduced in front of the app**. RLS gives no error when bypassed — only more rows.
*Mitigations:* the canary; `epigraph_bypass()` as role membership rather than the `BYPASSRLS` attribute; **six** fatal boot assertions (not a superuser; not `BYPASSRLS`; `relforcerowsecurity` on every protected table; canary invisible; not a member of `epigraph_seed`; `current_user = 'epigraph_app'`) **plus the §0.5 session-GUC probe and the `tgenabled` check**; `docs/tenancy.md`; and **one role name throughout** — the previous revision created `epigraph_app` and told ops to point `DATABASE_URL` at `epigraph_api` (sec F15), which is precisely this failure mode: the deploy falls back to `postgres://epigraph:epigraph@localhost/epigraph` (the schema owner), `FORCE` protects nothing, and every `relforcerowsecurity` assertion still passes. *Residual:* a superuser is unaffected by `FORCE`, and `ALTER TABLE … DISABLE TRIGGER` / `session_replication_role='replica'` defeat the write-side trigger. `pg_dump` as the owner still contains everything — RLS is not encryption, which is what `seal` is for.

**R4 — PR-06 is large and a half-landed conversion is worse than none.**
*Mitigation:* the two-commit split plus `visibility_lint`. *Residual:* during the window a function that *takes* a `Viewer` and is *passed* a `Bypass` one looks enforced and is not. `MaintenanceLease` narrows it: after PR-04 a `Bypass` cannot be constructed in a handler at all.

**R5 — Group role vocabulary and epoch width.** `group_authz.rs:32` accepts `creator`, which the CHECK forbids (dead code); `epoch` is `i32` in the DB/repos and `u32` in `crypto/epoch.rs:10-15`. Both fixed in PR-01/02, and they must land in the *same release window* as the CHECK.

**R6 — `-- no-transaction` migrations leave an INVALID index on failure, and this repo has never run one.** `head -1 migrations/*.sql | grep -c no-transaction` → **0**; `013` and `030` document a DBA pre-step precisely because the team believed it impossible. *Mitigations:* migration 062 contains **index statements only** so a failure cannot strand a column (ops F8); `IF NOT EXISTS` makes re-run safe; the runbook carries the `pg_index.indisvalid` detection query and a `DROP INDEX` step; and **062 is exercised against a throwaway database before it goes anywhere else** (PR-04 acceptance).

**R7 — `communities` / `perspectives` keep working but stop being an access-control backend.** Anyone relying on `POST /communities/:id/members` for authorization (which today performs *no* authorization beyond "has a bearer token", `routes/community.rs:198-239`) will find it inert after PR-05.

**R8 — D4 is an authority concentration.** `instance_admins` membership plus group-admin in a mature, plurally-administered target group is the power to seize public claims into a private group, and under `seal` to destroy the derived extractions. *Mitigations:* the table is empty after migration and unwritable through the app role; the 24 h maturity and 2-other-admins conditions (sec F4) mean the target group cannot be manufactured in one request; dual control above 1,000 items **or any `authors_losing_count > 0`**; the approver must administer the target group; `authors_losing_own_claims` in every preview; an append-only, row-scoped audit; `restrict` is fully reversible and `seal` is revertible once unsealed. *Residual:* an instance admin who is also an admin of a mature group with two other admins can do this, and that is by design.

**R9 — The `seal-manifest` endpoint is a deliberate plaintext egress.** Gated on all three §6.6 conditions, dual-logged to `privatization_audit` and `security_events`, both now immutable (sec F17). **There is no way to seal data the server can currently read without the server reading it.** Named, not mitigated away.

**R10 (new) — Migration version-space collision with `epigraph-internal`.** Verified from `migrations/README.md`: the private repo runs `sqlx::migrate!()` against the same `_sqlx_migrations` table; the reservation table is stale at 038; prod carries an unreconciled 035–037 → 036–038 renumbering the README says *"must be renumbered +1 on next public deploy"*; and `set_ignore_missing(true)` means a collision is not caught by the missing-version check. A checksum mismatch **panics the api binary on restart**.
*Mitigations:* PR-01 reserves 060–085 in the README as its first act, and the W0 gate queries prod's `_sqlx_migrations` directly. *Residual:* the 035–037 renumbering is a pre-existing debt this plan does not fix and must not be surprised by; the W0 query is what surfaces it.

### 10.2 Ledgered residual leaks and accepted costs — named, not open

1. **Aggregate cardinality drift.** `system_stats` / `/admin/stats` counts become visible-only under `FORCE`, but a caller who snapshotted `COUNT(*)` before and after a privatization sees the delta. Only fixable by not publishing counts.
2. **Retrieval-set drift.** An observer who cached `recall` results learns which ids disappeared. Intrinsic to D2's start-public posture, and the strongest argument for privatizing *early*.
3. **Group existence.** `groups.display_name` is not secret. Mitigation: pre-create target groups — which the 24 h maturity rule (§6.6) now requires anyway.
4. **`claim_themes` co-membership.** A theme centroid spanning private and public claims reveals topical adjacency. Registered in `tenancy_exempt` with PR-09's viewer-scoped clustering as the control; the shared-table channel remains.
5. **`harvester_fragments` source text under `seal` is destroyed, not encrypted.** Unseal does not restore it. Stated in the seal preview.
6. **Derived extractions destroyed by `seal`.** `triples`, `entity_mentions`, `reasoning_traces`, `challenges`, `experiment_triples` rows for a sealed claim are deleted and only re-derivable by an explicit re-extraction after unseal.
7. **Federated downstreams holding pre-privatization copies.** Notified via the `privatization.applied` webhook, never enforced.
8. **`restrict` mode versus `pg_dump` / replicas / backups.** By design. `seal` is the answer; hosting controls are the cheaper and more uniform one.
9. **`seal` plaintext-length leak below the padding bucket.** With `pad_to = 256`, plaintexts of 1 and 200 bytes are indistinguishable; 300 and 500 are not.
10. **`agents` PII beyond `profile_visibility`.** `display_name` and `public_key` are always readable so authorship renders.
11. **Sealed content survives revocation.** A member removed at epoch N who kept their share decrypts everything sealed before the next re-seal, forever (§6.7). Stated in `docs/tenancy.md`, in the preview, and in the rotation response.
12. **The registration ceiling.** D3 raises the bar from *zero credentials* to *one credential from whoever the IdP gate admits*. PR-02 makes that gate fail closed and adds a production boot assertion; an operator who sets `allow_all_identities: true` is back to the original posture and has said so explicitly.
13. **`epigraph_admin`.** `scripts/theme_lib.py:16` hardcodes a fourth role no design document named. PR-15 either maps it to `epigraph_maintenance` or records it as deliberate; either way it is now in the inventory.

### 10.3 Genuinely open — decisions the user must make

**Q1 — `/metrics` disposition. BLOCKS PR-03.**
`/metrics` is registered on **both** router variants (`routes/mod.rs:517` and `:1031`, verified) and there is **no second listener anywhere in `bin/server.rs`**. It is the one allowlisted route carrying a real, if coarse, channel: the Prometheus registry's request/write counters make corpus-wide write volume inferable, and under D4 the before/after delta around a privatization is inferable with it. Two acceptable answers, both operator decisions:
- **(a) A separate internal listener.** Correct, and it is **new engineering, not a config flip** — it needs a second `axum::serve` on a second bind address, a deployment change, and a scrape-config change.
- **(b) A scrape token.** A one-day change; `/metrics` moves to `protected` behind a dedicated `metrics:read` scope granted only to the scraper's client.
Leaving it on the public listener under D3 is not one of them. **The user picks (a) or (b) before PR-03 merges.**

**Q2 — Keep the `epigraph_seed` escape hatch, or pay for 160 fixture edits?**
Arm 4 of `epigraph_require_tenancy` (§3/070) lets a role-gated seed connection omit the declaration and get `('public', <seed group>)`. It exists so the 160 test `INSERT INTO claims` statements do not have to be rewritten. It is role membership, auditable in `pg_auth_members`, revocable with one `REVOKE`, boot-asserted against, and — now that it stamps a dedicated seed group rather than the world group — **greppable**: `SELECT count(*) FROM claims WHERE owner_group_id = '…dead'` measures exactly how much of the corpus took the escape hatch. **But it is still an omission path, and D1 says there should be none.** Deleting it is the only variant with zero omission surface anywhere in the system.
*Recommendation:* keep it for the rollout, delete it in a follow-up once the fixture edits can be done in bulk, and track the removal as a backlog item. **The user should say which.**

**Q3 — Does any external consumer depend on community-as-ACL? BLOCKS PR-05.**
`POST /communities/:id/members` performs no authorization today beyond "has a bearer token" (`routes/community.rs:198-239`), so nothing *should*. This is a question about consumers outside this repository, which no amount of code reading answers. **Confirm before PR-05**, because after it the endpoint is inert as an access control.

**Q4 — `allow_all_identities` for this deployment.**
PR-02 makes the IdP provisioning allowlist fail closed (§4.9 fact 2). That is a **behaviour change for any deployment currently relying on the documented allow-all default**: today, any Google account that completes `/oauth/authorize` provisions. After PR-02, provisioning requires either a configured `allowed_emails`/`allowed_domains` or an explicit `allow_all_identities: true`. **The user must say which posture this instance wants**, and if it is an allowlist, supply the domains. Without an answer, PR-02 ships fail-closed with an empty allowlist and **no external identity can provision**, which is safe and may be an outage.

**Q5 — `pad_to` default, and the strong `owner_group_id <> world` CHECK.**
`pad_to = 256` is the recommended default and can be raised per-plan for short-claim corpora where length is identifying. The unconditional `CHECK (owner_group_id <> world)` on `claims` ships once the count has been zero for a full release (§3/071–072). Neither blocks any PR; both need a decision at their own gate. Flagged here because §10.2 items 9 and the A4 invariant depend on them.

### 10.4 Genuinely open — measurements needed before a specific PR

**M1 — `ownership` row census. BEFORE PR-12 (the backfill), BLOCKS PR-22.**
No `psql` is installed on this machine (`which psql`, homebrew and Postgres.app paths all miss), so this is unmeasured:
```sql
SELECT node_type, partition_type, count(*) FROM ownership GROUP BY 1,2 ORDER BY 3 DESC;
```
Expected **0 rows** (no write path inserts one). If it is non-zero for `node_type NOT IN ('claim','evidence')`, the tier-A widening of `frames`/`contexts`/`perspectives`/`communities` in migration 061 is a **blocker** for PR-22 rather than a nicety, and each such row is a decision that must be transcribed by hand into `tenancy_transcription_log`.

**M2 — pgvector version on the target cluster. ~~BLOCKS PR-04~~ — ANSWERED 2026-08-27.**
```sql
SELECT extversion FROM pg_extension WHERE extname = 'vector';
```
If **< 0.8**, `hnsw.iterative_scan` is unavailable and R1's primary mitigation does not exist; upgrading moves onto the critical path, and the §9.4 decision rule loses its cheapest branch.

> **ANSWERED (2026-08-27, from the operator): production runs the pgvector 0.8 series.**
> `hnsw.iterative_scan` is therefore available in production, R1 mitigation (a) is viable,
> the pgvector upgrade is **off** the critical path, and §9.4's decision rule keeps its
> cheapest branch. PR-04 is unblocked on this axis.
>
> **Residual, and it is not zero.** The *patch* level was not stated. The local development
> database is pinned to **0.8.6**, the newest in the series, so local is a superset of any
> 0.8.x production. `iterative_scan` itself landed in 0.8.0 and is safe, but do not rely on
> anything introduced in 0.8.1–0.8.6 without first confirming the exact production version
> with the same query. Any such dependency would pass locally and fail in production —
> the one failure mode this plan's local environment cannot catch.

**M3 — Prod `_sqlx_migrations` head. BLOCKS PR-01 (W0 gate).**
```sql
SELECT version, description, checksum FROM _sqlx_migrations ORDER BY version DESC LIMIT 25;
```
Confirms 060–085 is clear and surfaces the unreconciled 035–037 → 036–038 renumbering the README documents (R10).

**M4 — Row counts, to size the DDL windows. BEFORE PR-04.**
```sql
SELECT (SELECT count(*) FROM claims)       AS claims,
       (SELECT count(*) FROM evidence)     AS evidence,
       (SELECT count(*) FROM edges)        AS edges,
       (SELECT count(*) FROM triples)      AS triples,
       (SELECT count(*) FROM entity_mentions) AS entity_mentions,
       (SELECT count(*) FROM reasoning_traces) AS reasoning_traces,
       (SELECT count(*) FROM challenges)   AS challenges,
       (SELECT count(*) FROM harvester_fragments) AS harvester_fragments,
       (SELECT count(*) FROM frames)       AS frames,
       (SELECT count(*) FROM contexts)     AS contexts,
       (SELECT count(*) FROM perspectives) AS perspectives,
       (SELECT count(*) FROM communities)  AS communities,
       (SELECT count(*) FROM agents)       AS agents;
```
Sizes the `ADD COLUMN` / `DROP DEFAULT` / `VALIDATE` windows across **24** tier-A tables, not the previous revision's twelve.

**M5 — Session-GUC probe against the target cluster. BLOCKS PR-04, gates PR-17.**
Run §0.5's probe against the real deployment topology: does a session GUC set on a pooled connection survive to the next statement on the same handle, and is it absent on a fresh checkout? A failure means a transaction pooler is in front and `EPIGRAPH_SESSION_GUC_MODE=transaction` is what ships — which changes the latency numbers in §9.4 criterion 5 and re-opens the `ScopedPool`-mandatory-transaction question this plan otherwise closes.

**M6 — OAuth client `agent_id` coverage. GATES PR-03.**
```sql
SELECT count(*) FILTER (WHERE agent_id IS NOT NULL)::float / NULLIF(count(*),0)
  FROM oauth_clients WHERE status = 'active';
```
Must be **1.0** before the router inversion (§4.7 path B). Below that, the inversion is a self-inflicted outage.

**M7 — Partition split `f_group`. GATES PR-06's acceptance and the `062b` decision.**
§9.4 criterion 1, re-run **monthly** after PR-18, because D4 moves it.

---

## 11. Rejected critiques and rejected alternatives

Everything below was proposed by a critique, a design proposal, a judge, or an earlier revision of this plan, and is **not** adopted as stated. The reasoning is recorded so it is not re-litigated. Items marked *(carried)* were rejected in an earlier pass and survive re-examination; items marked *(new)* answer the security and ops critiques of the previous revision, and items marked *(new — raised in review)* answer a proposal put to the plan after it was written.

### 11.1 New — the security critique of the revised plan

**Security F2's `claim_themes` row: rejected as stated, redirected.** *(new)*
F2 lists `claim_clusters / claim_themes` (`001:546, :573`) together as *"`claim_id` → cluster membership."* **Verified: `claim_themes` has no `claim_id` column.** Its full column set at `001:573-581` is `id, label, description, centroid vector(1536), claim_count, created_at, updated_at`. `claim_clusters` *does* have `claim_id` (`:548`) and is adopted into tier A; `claim_themes` cannot be, because there is nothing to key tenancy on — a theme spans tenants by construction, and stamping it `('group', G)` would either hide a mixed theme from everyone or expose it to G alone, both wrong. It goes into `tenancy_exempt` with a written residual (topical adjacency) and PR-09's viewer-scoped clustering as the control. **The finding's substance is right and its table entry is not**, and the distinction matters because F2's own prescription is to *generate* the set — a generator would never have produced `claim_themes`.

**Security F2's generated set: adopted, and shown to be necessary but not sufficient.** *(new)*
F2 proposes `SELECT table_name FROM information_schema.columns WHERE column_name = 'claim_id'` as *"the authoritative set."* It is not quite. Verified against the tree, that query misses **`harvester_fragments`** (`001:1090`) — which has no `claim_id` and no FK to `claims`, and which holds `content_text text NOT NULL`, **the source text the claim was extracted from**, reachable through `harvester_claim_provenance` (a table the query *does* find). F2 names `harvester_fragments` in its own table and then proposes a generator that cannot find it. §2.4 therefore runs **two** generators (the `claim_id` column *and* every FK referencing `claims`) plus a manually-registered addition, and the `tenancy_exempt` registry is what makes the manual part reviewable rather than forgettable. The generators found eight tables the previous revision missed; the registry is what catches the ninth.

**Security F4's first branch — "delete the claim from §6.6 and R8": rejected. Its second branch is adopted.** *(new)*
F4 is correct that condition 3 as written prevented nothing: `POST /api/v1/groups` needs only `groups:write`, `create_with_admin` makes the creator an admin, and a rogue instance admin manufactured a compliant target group in one request. But deleting the condition is wrong, because it does real work F4's threat model does not weigh: **privatizing into a group you cannot administer means you cannot later unseal it, revert it, or add a member to it.** That is a durability property, not a security one, and it is why an honest operator wants the check. §6.6 and migration 077 take F4's "make it real" branch — 24 h maturity, ≥ 2 live admins other than the author, and an approver who administers the target group — which closes the seizure vehicle while keeping the durability guarantee.

**Security F7(c) — "the instance-wide `/audit` view is an `epigraph_maintenance` CLI query, not an HTTP route": rejected. (a) and (b) adopted in full.** *(new)*
`epigraph_maintenance` **bypasses RLS entirely and writes no `security_events` row**. Moving the most sensitive read in the system into that role makes it *less* controlled and *completely unobservable* — the opposite of an audit control. And an auditor genuinely needs the instance-wide timeline. §6.5.8's answer instead: the route survives, migration 078's policy scopes it **in the database** (plan-level rows for every plan; entity ids only where the caller administers the target group), and **every `/audit` read writes its own `security_events` row**. F7(a) — compute `sample` and conflicts under the actor's `Viewer` — and F7(b) — apply the full three-condition check to `GET /plans/:id`, `/items` and both manifests — are adopted verbatim; they were the finding's real content.

**Security F12's "make `remove_member` enqueue a re-seal plan": rejected as unimplementable; the disclosure and the operator-initiated path are adopted.** *(new)*
The finding is correct and important: rotation gates only future ciphertext, a revoked member's retained `wrapped_key_share` decrypts everything sealed before the rotation forever, and the previous revision shipped two opposite revocation semantics under one word while stating only the flattering one. But `remove_member` **cannot** enqueue a re-seal that will ever succeed: re-sealing requires the group key, and by §6.5.6 the server never holds one. An automatic job that can only fail converts a stated, visible gap into a red queue nobody trusts. §6.7 ships what the server *can* do — the sentence in `docs/tenancy.md`, in the preview's `side_effects.revocation`, and in the rotation response; `groups.reseal_required_at` set on removal; a Prometheus gauge for groups stale past 7 days; and `PrivatizationResealHandler` as an **operator-initiated** plan mode driven by a key-holding admin. §8.4 N13 asserts the retained-share property as documented behaviour, so nobody later mistakes rotation for revocation.

**Security F16's `CHECK (tenancy_tier <> 'unclassified')` "on new rows": adopted in corrected form.** *(new)*
A table `CHECK` cannot distinguish new rows from existing ones. The constraint works only because migration 065 **classifies all 23 seeded types first and adds the CHECK afterwards**, at which point it is unconditional and correct. The handler-side precondition (refuse `tenancy_tier='columns'` unless the table already has both `NOT NULL` columns, a policy per command, and `relforcerowsecurity`) is adopted verbatim, as is the deletion of the three unimplementable "read paths must treat `unclassified` as DENY" sentences.

**Security F17's alternative — "drop the dual-write and record `seal_manifest` in `privatization_audit` only": rejected. The hardening is adopted.** *(new)*
The finding is right that the previous revision routed the plaintext-egress record into `security_events` (`001:1415`, verified: no immutability trigger, no policy, absent from the FORCE list, written on the app connection by `SecurityEventRepository::create` at `repos/security_event.rs:82`) while the immutable table sat next to it. But dropping the dual-write loses the property the dual-write exists for: an auditor asking *"what did this principal do?"* needs a login, a token mint and a privatization in one timeline, and `privatization_audit` will never carry logins. Migration 078 gives `security_events` the same immutability trigger, an RLS policy and a line in 075, and §3/078 states which is the record of authority — F17's actual closing demand.

**Security F6's DCR threat model: correct on the `agent` path, overstated on the DCR path.** *(new)*
F6 cites `dcr_scopes()` returning `PENDING_SERVICE_SCOPES` with `status = "active"`, which is verified (`register.rs:53-67`, `:192-197`). It omits that the DCR path is bounded by a redirect-host allowlist enforced **before** any client_id generation: `register.rs:84-90` refuses any `redirect_uri` whose host is not `https://claude.ai/` or `https://claude.com/`. So the drive-by DCR registration F6 describes requires the attacker to control a claude.ai/claude.com redirect. **The `client_type: "agent"` path carries no `redirect_uris` and is bounded by nothing**, which is the real hole, and the IdP allow-all default (F6's other half) is bounded by nothing either. Both are closed in PR-02. The correction matters only so nobody removes the redirect allowlist believing it does no work.

**Security F1's option (c) — "remove from the FORCE list every table the hot path reads": rejected.** *(new)*
That is every table that matters. `claims`, `evidence`, `edges` and the derived set *are* the hot path; a backstop covering only `groups` and `instance_admins` is not a backstop. Option (a) — every protected read inside `begin_as` — is adopted as the **fallback** mode (`EPIGRAPH_SESSION_GUC_MODE=transaction`, §0.5), costed in §9.4 criterion 5, and selected automatically when the boot probe detects a transaction pooler. Option (b) — connection-level `SET` via a checkout hook, with a written proof no transaction-pooling proxy sits in front — is adopted as the **default**, with the proof turned into a runnable boot probe rather than a written assurance. F1's real contribution is the third paragraph, and it is adopted whole: **the W10 gate gains a positive criterion, and §8.4 gains an entire positive class**, because a suite written only as "assert a stranger cannot read" cannot fail on a mechanism that returns nothing to anybody.

**Security F14's "create a `kind='personal'` group owned by the seed role": adopted with a different `kind`.** *(new)*
`kind='personal'` implies exactly one agent, and `epigraph_seed` is a database role, not an agent. Migration 061 creates `kind='seed'` instead (the `groups_kind_check` vocabulary gains it), which keeps the conditional `public_key` CHECK correct, keeps "personal group" meaning what §2.1 says it means, and preserves the whole point of F14 — A4 becomes true, the strong `owner_group_id <> world` CHECK becomes reachable, and seed-created rows become greppable by `owner_group_id`.

### 11.2 New — the ops/migration critique of the revised plan

**Ops F7's "split 061 and 069 one table (or one small group) per migration": rejected for 061, adopted for 070–072.** *(new)*
The `lock_timeout` prescription is adopted everywhere and is the finding's core value. The *split* is not, for 061, on the ops critique's **own** other finding: the version space is shared with `epigraph-internal`, the reservation table is stale, and a checksum collision panics the api binary on restart (ops F2). Burning 24 version numbers on metadata-only `ADD COLUMN`s to buy finer retry granularity trades a real, documented outage risk for a hypothetical one. §3.0's answer is better on both axes: make 061 **fully idempotent** — every `ADD COLUMN IF NOT EXISTS`, every `ADD CONSTRAINT` catalog-guarded — so a `lock_timeout` abort is retried by re-running one file with no partial state, which is what the split was trying to buy. **Migration 070 *is* split** into 070/071/072, because `VALIDATE CONSTRAINT` is a full table scan holding `SHARE UPDATE EXCLUSIVE` and genuinely must not be redone as a group — F16's point, adopted.

**Ops F1's semantic framing of `consolidate` — "a declassification primitive of exactly the shape §6.5.7 deletes `assign_ownership` for": rejected. The finding and its fix are adopted.** *(new)*
The factual core is confirmed and is the most valuable single catch in either critique: `ClaimRepository::consolidate` at `crates/epigraph-db/src/repos/claim.rs:4653` is production (both `#[cfg(test)]` blocks close at 4018 and 4443, verified by brace-matching), is live via MCP `consolidate_claims`, binds neither `supersedes` nor `step_lineage_id`, and is a `sqlx::query_scalar!` — so it breaks hard at migration 070 *and* the prepare list was short by one. But it is not `assign_ownership`-shaped: `assign_ownership` transfers an existing row's ownership away from its owner with no other effect; `consolidate` **retires its predecessors** and creates a new row. The hazard is real and different — an undefined merged tenancy that can *widen* — and §4.6's meet rule is the fix: `group` if any source is `group`; the single distinct owner among group-visible sources; **refuse when sources span two or more different groups**. Calling it a declassification primitive would imply deleting it, which would be wrong.

**Ops F3's "the migration only issuing guarded `GRANT`s" on managed Postgres: adopted in a stronger form.** *(new)*
The finding is correct that roles are cluster-scoped while databases are not, that CI's `#[sqlx::test]` template databases collide on an unguarded `CREATE ROLE` (verified: **8** crates, 696 occurrences, plus **15** direct `sqlx::migrate!` sites), and that a managed-Postgres migration role has neither `SUPERUSER` nor `CREATEROLE`. Splitting into "create out of band, migration only GRANTs" would work on managed Postgres and would break every local `cargo test` on a fresh cluster. Migration 060 instead **attempts the `CREATE ROLE` inside a `DO` block that catches `insufficient_privilege` and `duplicate_object`**, so it works in both worlds, and every `GRANT`/`REVOKE` in 060–080 is wrapped in a `pg_roles` existence check. The *fatal* check moves to `AppState::with_db`, where it belongs — production refuses to serve without the roles; a laptop does not.

**Ops "each PR is revertible" as a flat contradiction: partially rejected.** *(new)*
`ls migrations/ | grep -c '\.down\.sql'` → **0** is verified, and the critique is right that §7's wording overclaimed. But "revertible" is true of the Rust in every PR, and it is what makes the two-commit split of PR-06 and the per-route enforcement flag work at all. §7's note now says exactly which half is revertible, names the two genuine rollbacks (`NO FORCE` + revert `DATABASE_URL`; revert the Rust), and ships `docs/runbooks/{070,075,080}-undo.sql` with the executing role named — which is the finding's actionable half.

### 11.3 Carried forward — earlier rejections that survive re-examination

**The draft's partial public HNSW index (`idx_claims_embedding_hnsw_public`).** *(carried, and strengthened)*
Deferred originally on cost: because the corpus is overwhelmingly public, a "partial" index would cover essentially the same rows — 2× disk on the largest table, 2× HNSW insert on every write, and a build (`migrations/030` records 5–15 min on 150k rows for a *smaller* index). **D3 upgrades "deferred pending measurement" to "never, on structural grounds":** after D3 the only app-emitted qual is `(visibility = 'public' OR owner_group_id = ANY($V))`, and `A OR B` does not imply `A`, so the index-predicate proof cannot fire for any viewer that exists. What *is* adopted from the cost analysis is the replacement: if measurement ever justifies a partial ANN index it is the **complement** (`visibility <> 'public'`) plus a two-leg UNION rewrite, whose cost scales with `f_group` (§3/062, §9.4).

**Security F17 (of the original pass) — "the `Anonymous` fast path is defeated by RLS the moment `FORCE` lands."** *(carried, conclusion moot, property retained)*
The mechanism described (RLS quals joining `baserestrictinfo`, non-`LEAKPROOF` functions ordered ahead of user quals) is real. **Under D3 there is no anonymous viewer, so the argument has no subject.** The property that survives and transfers to `Scoped` is now a stated invariant with a mechanism behind it (§0.5) and a test that can actually fail (§4.5). Index selection remains a **named pass/fail criterion** in the W10 gate, measured against a restored production snapshot. Marking `epigraph_bypass()` `LEAKPROOF` stays **declined** — superuser-only, and with the duplicate index gone it buys nothing.

**Security F12 (original) — unique-constraint oracles as a blocker.** *(carried)* Downgraded, not rejected. The mechanism is verified (`idx_edges_unique_triple` at `001:2561`) and §8.5 carries it with a concrete fix. `groups_did_key_key` and `pattern_templates_name_key` are not reachable by an untrusted writer once `groups:write` gates group creation and `pattern_templates` has no registered route.

**Completeness S3's `epigraph_bypass()` rewrite.** *(carried)* Adopted in substance, rejected in form. Keeping `current_user` would preserve the exact escalation the security review identified — inside a `SECURITY DEFINER` frame it resolves to the function owner. §3/063 keeps the existence guard and uses `session_user`. **A `current_user` variant now exists as `epigraph_definer_bypass()`, `REVOKE`d from `PUBLIC` and called from exactly two trigger bodies** — which is the *only* place the `current_user` semantics are correct, and is what sec F10 forced.

**Completeness S10 — "PR-01 and PR-02 must be one PR."** *(carried)* Rejected as stated. Merging them produces one PR containing a schema creation, four repo deletions, a cargo-feature removal, an OAuth identity rewrite and a middleware change — un-cherry-pickable and un-revertible as a unit, which matters most for the one PR that fixes a live 500. The real constraint is narrower: *the `group_memberships_role_check` CHECK must land in the same release as `routes/groups.rs:64-66`'s `default_role()` and `middleware/group_authz.rs:32`.* §9.2 puts both in week 1. If they cannot land together, 060 ships without the role CHECK and it is added in `060b`. Stated in 060's header.

**Completeness S12's webhook remedy as a filter.** *(carried)* Rejected as under-scoped, replaced with a migration. `WebhookSubscription` is `Arc<RwLock<HashMap<Uuid, WebhookSubscription>>>` in `state.rs:82-104` with **no table**, and its `owner_id` is an `oauth_clients.id`, `None` for pre-auth subscriptions. There is nothing to join.

**Ops F9 (original) — "migration 067's guard is the right instinct in the wrong artifact."** *(carried and extended)* Accepted and extended. The guard moves to `epigraph-tenancy-backfill verify` as an exit code — and its *content* changes too, because a boolean `complete` flag in `tenancy_backfill_progress` is hand-flippable by an on-call at 2 a.m. It is three **live counts**, and the progress table is demoted to observability.

**Ops F15 (original) — "if the canary must live in `claims`, label it `telemetry`."** *(carried)* Rejected as a fallback that should not exist. A synthetic row in the epistemic corpus is wrong regardless of labelling: it counts in `system_stats`, needs an exclusion in `find_claims_needing_embeddings` and in the CLAUDE.md audit SQL, and pollutes an agent's authored set. §3/074 gives the canary its own table. **The same reasoning keeps the D4 audit trail out of `claims`.**

**"`batch_check_content_access` must be rewritten as a single set-returning query."** *(carried)* Rejected as unnecessary work. It is **deleted**, not rewritten. Its replacement is the absence of one: `Viewer::resolve` issues a single membership lookup per request and the predicate does the rest.

**The draft's `epigraph_visible()` SQL function.** *(carried)* Rejected. It bought readability at the cost of an inlining assumption and one more `SECURITY DEFINER`-adjacent surface to `REVOKE`. Only the session/bypass functions survive in 063 — and one of them, `epigraph_writable_groups()`, is **new**: the draft used it in a `WITH CHECK` and defined it nowhere.

**"Keep `Viewer::Anonymous` but make it match nothing."** *(carried)* Rejected on three grounds: it is invisible to an adversarial suite that asserts absence (R2's exact failure mode — and §0.5 is the proof that this class of blindness is not hypothetical); it defeats the ratchet design; and deleting it moves "unauthenticated ⇒ no repo call" from a review convention to a compile-time fact. `no_anonymous_viewer.rs` is the tombstone.

**"Make the `ownership` side-row mandatory instead of adding columns."** *(carried)* Rejected on five grounds (§2.2), two decisive. **(a)** It cannot be made required in Postgres without a race or a rewrite: `ownership.node_id` has no FK. **(b)** This codebase has produced the absence-means-public bug **twice, independently, from two different side tables** — `access_control.rs:68` and `epigraph_is_visible_to_group()`'s `RETURN NOT found` at `ENT/migrations/001:526`, which is the *RLS policy body*. The honest cost of the column design — a newly registered entity type has no column — is closed explicitly by `entity_types.tenancy_tier` **as a handler precondition**, not as an unimplemented promise (sec F16).

**"Pin public rows to the world group."** *(carried)* Rejected. It makes a public row owned by nobody, which is D1 in letter and violated in spirit; it makes D4 unimplementable for the legacy corpus; and it makes `reader` meaningless on the public path.

**"Keep `DEFAULT 'public'` on the tenancy columns."** *(carried)* Rejected under D1. A `DEFAULT` in `pg_attrdef` is "public by omission" relocated into the catalog. The defaults exist only as a transition artifact; migration 070 removes every one.

**"Group admin is sufficient authority to privatize."** *(carried, now with teeth)* Rejected. A group admin who could privatize arbitrary public claims into their own group would be performing a seizure. Three simultaneous conditions instead (§6.6) — and, after sec F4, conditions the attacker cannot manufacture in one request.

**"`PATCH /claims/:id/visibility` is the whole D4 surface."** *(carried)* Rejected as insufficient rather than wrong. It survives as sugar that constructs and **enqueues** a one-item plan, so the single-claim case gets the hull, the boundary meet, the audit and the revert for free. Its authorization also changes from `claims:write` to the full §6.6 check.

**"Put the ciphertext in `claims.content`."** *(carried)* Rejected. `content_tsv` is `GENERATED ALWAYS` from `content` and recomputes on every UPDATE. AES-GCM is length-preserving and base64 token counts are monotone in plaintext length, so `length(content)`, `array_length(tsvector_to_array(content_tsv),1)` and the GIN posting count all become plaintext-length oracles recoverable from a `pg_dump`, from `pg_stats`, and from a replica. The sentinel `'[sealed:' || id || ']'` has constant shape and — being id-suffixed — fixes the live bug where `content_hash = BLAKE3("[private]")` lets an agent create exactly one fully-private claim, ever.

**"Re-embed sealed content under a group-scoped ANN index," and "use `embedding_shares` / MPC."** *(carried)* Both rejected. The vector is plaintext-derived regardless of which index holds it, and in `seal` mode the server has no plaintext. `embedding_shares` is worse: no Rust in either repo writes the table, and `SimulatedMpc::cosine_similarity` reconstructs **both** embeddings in the clear.

**"Use `EncryptionProvider::encrypt(plaintext, key_id)` for sealing."** *(carried)* Rejected on three verified disqualifiers (§2.7): server-side key custody in an `Arc<RwLock<HashMap>>` seeded only by `register_key`, which both production constructors call with an empty vec — so every `encrypt()` returns `KeyNotFound` in the shipped binary; no `entity_id` parameter, so the adapter passes `Uuid::nil()` and discards exactly the transplant resistance `encryptor.rs` exists to provide; and the kernel is explicitly client-custody.

**The draft's rotation guard, "reject unless the retiring epoch's `wrapped_key` is non-NULL."** *(carried)* Rejected as stated, accepted in intent. Under KMS custody `wrapped_key` stays NULL **by design**, so the guard as written would block all rotation forever. Restated as *rejected unless the retiring epoch's key is **recoverable***.

**The draft's shadow harness (`Viewer::system("shadow")` inside the handler).** *(carried)* Rejected as no longer constructible: `Viewer::system` requires a `MaintenanceLease`. Replaced by a `Scoped` viewer whose `group_ids` is the full group set on the ordinary `epigraph_app` connection — bypass-equivalent while RLS is not yet forced.

**The draft's PR-03 "seven negative tests" and PR-07 "the 12 unenforced routes."** *(carried)* Rejected as stale-by-construction. Replaced by the structural inversion plus `public_router_allowlist.rs`, which walks **both** `create_router` variants. Only the **39** fail-open scope sites survive as a verified count.

**The draft's PR-06 acceptance criterion (`EXPLAIN` shows `idx_claims_embedding_hnsw_public` chosen for `Viewer::anonymous()`).** *(carried)* Rejected as unsatisfiable — neither the index nor the viewer will exist. Replaced by §9.4's six-part measurement with a named decision rule.

**"`require_signatures` is dead code, delete the flag."** *(carried)* Rejected as half-right. The *middleware branch* is dead — `Router::layer` makes the last-applied layer outermost, so `bearer_auth_middleware` 401s before `require_signature` is reached, which the tests corroborate. But the *flag* has a live consumer at `routes/submit.rs:689`. Delete the branch; **keep the flag and rename it `require_packet_signatures`**.

**"D3 closes the leaks."** *(carried, and sharpened)* Rejected as a framing, in the plan's own text. Of 8 map-rated blockers, D3 alone downgrades two. §4.9 now carries **three** rating columns and names **two** facts about how cheaply an attacker authenticates — the agent auto-activation and the allow-all-by-default IdP gate — because with either one open, D3 costs an attacker one HTTP request or one Google account.

**Both critiques' counts where they conflict with the tree.** *(carried)* Verified and corrected rather than adopted. Every number in this plan is from the tree at `3948445`.

---

### 11.4 New — searching sealed content by encrypting the embeddings

**"Encrypt the embeddings, encrypt the query embedding under the same key, and run cosine similarity on the ciphertext."** *(new — raised in review)*

Rejected for `seal` mode, in three parts, because the one sentence names three different mechanisms that fail for three different reasons. Recorded in full because it is the most natural idea in this space and will resurface.

**(a) With the AEAD this plan actually ships — impossible, not merely weak.** §6.5.6 seals with AES-256-GCM. The ciphertext is pseudorandom and nonce-randomised: the same vector sealed twice shares no bytes, so cosine similarity over ciphertext is noise and even an equality test fails. No parameter choice rescues this. The property being requested — that distance in plaintext space survive into ciphertext space — is exactly the property semantic security is defined to destroy.

**(b) With a secret orthogonal transform — mechanically works, and is not encryption.** For a secret orthogonal `Q` (1536×1536), `(Qv)·(Qw) = vᵀQᵀQw = vᵀw` and `‖Qv‖ = ‖v‖`. Cosine is preserved *exactly*, not approximately, and — the seductive part — **HNSW keeps working unchanged**, because the transformed space is the same metric space with the same geometry. It is nonetheless rejected, because it is a distance-preserving encoding rather than a confidentiality mechanism:

- It publishes the corpus's **entire pairwise distance geometry** to anyone holding the table. That is a topical-clustering oracle on its own — the same leak class that `claim_themes` is already ledgered for in `tenancy_exempt`, except here it covers every sealed row rather than one shared table.
- `Q` is recoverable in closed form from roughly `d` known `(v, Qv)` pairs by orthogonal Procrustes — one SVD of `CPᵀ`, then `Q = UVᵀ`. On a system whose entire premise is that agents submit claims, an attacker who can get text embedded into the target key space manufactures those pairs at will.
- `Q` is recoverable **with no known pair at all**, because `crates/epigraph-embeddings/src/config.rs:60` pins `text-embedding-3-small` — a public API. An attacker embeds any large public corpus into the same 1536-dimensional space and aligns the two point clouds by unsupervised Procrustes. It is the *model choice*, not any property of the private data, that makes this cheap.
- Once `Q` is recovered, `vec2text`-class inversion returns approximate source text — precisely the outcome §1's non-goal table calls theatre.

**(c) With homomorphic encryption — cryptographically sound, and priced out by the index rather than the arithmetic.** CKKS is built for approximate arithmetic over real vectors and encrypted dot products are its canonical application. The arithmetic is not the objection. The objections are structural:

- **ANN dies.** HNSW indexes a metric space; CKKS ciphertexts expose none, so every sealed query degrades to a **linear scan over every sealed row**. That is a change in complexity class, not a constant factor — which is why hardware speedups do not answer it.
- **Ranking is a larger problem than scoring.** The server ends holding encrypted scores it cannot compare. Either every score ships to the client to be decrypted and sorted — bandwidth linear in the sealed corpus, and the returned score vector is itself the geometry disclosure of (b) — or a homomorphic comparison/top-k circuit runs, which costs more than the dot products it ranks.
- Ciphertext expansion of roughly two to three orders of magnitude, applied to a `vector(1536)` column on the largest table in the schema.

#### Reopen this if — and only if — one of these becomes true

Each is written to be *checked* rather than argued.

1. **A practical sublinear index over HE ciphertexts exists**, together with a practical encrypted top-k. This is the load-bearing condition: (c) is rejected on complexity class, so a constant-factor win — including a dedicated FHE accelerator — does **not** reopen it. Concrete trigger: a published scheme demonstrating sublinear encrypted retrieval at ~10⁵ vectors × 1536 dimensions with stated parameters and an encrypted ranking step.
2. **The embedding model stops being public.** (b)'s third bullet dies if embeddings come from a self-hosted model whose weights are not obtainable **and** an attacker cannot get text embedded into the target group's key space. Both halves are required; either alone is insufficient. Even then the pairwise-geometry leak in (b)'s first bullet survives untouched, so this reopens (b) **only** under a threat model that accepts topical clustering while refusing content recovery. Write that threat model down before adopting it — this plan does not currently hold it.
3. **The deployment acquires a genuinely non-colluding second party** — separate operator, separate key custody, separate organisation. Real two-party computation over secret-shared embeddings is sound; `embedding_shares` was rejected because the enterprise implementation reconstructs both vectors in the clear **and** because the topology has exactly one party. The second defect is the harder one, and it is operational rather than algorithmic.
4. **A TEE posture is adopted deliberately.** An enclave holding group keys can run ordinary plaintext HNSW under `seal`'s threat model, and is the only option here that **keeps the index**. Out of scope now — key custody is client-side per §2.7, and the side-channel record is poor — but it is the most likely near-term path, and notably it does not depend on any cryptographic advance.

**What does *not* reopen it:** faster CKKS bootstrapping on its own; a larger `pad_to`; moving the vector to a separate table; or encrypting the embedding at rest under a server-held key. The last defends a stolen disk — which tablespace or full-disk encryption already does far more cheaply, without touching the query path — while conceding entirely to the live-DBA adversary that `seal` exists to address. Any scheme in which the *server* decrypts in order to search hands the key to exactly the attacker in scope.

**The standing answer in the meantime** is §6.5.4's mode split, and it is not a consolation prize. `restrict` retains a plaintext `embedding` and full HNSW recall for the owning group, because `content`, `embedding` and `content_tsv` are three columns of **one row** and RLS is row-level — the predicate hides all three atomically. Encrypted-embedding search therefore buys nothing at all against another tenant; it is only ever about the DBA. `seal` nulls the embedding, and sealed content has no semantic recall. That is a real product cost, taken deliberately and stated in `docs/tenancy.md` rather than engineered around.

---

## 12. Appendix — the one-page summary an engineer needs

**What is being built.** Tenancy columns on the row (`visibility`, `owner_group_id`), a `Viewer` that is a required parameter with no infallible constructor, the predicate inline in retrieval SQL above `LIMIT`, `FORCE ROW LEVEL SECURITY` as the backstop under a separate `epigraph_app` role, and an admin surface that privatizes regions of a public corpus with preview, batching, audit and revert.

**The four things most likely to go wrong, and what stops each.**

| Failure | What stops it |
|---|---|
| Private rows become invisible to their own owners under `FORCE` | §0.5's checkout-time GUC stamping, the boot probe, and **§8.4 Class P** — the positive assertions without which this failure is undetectable |
| A derived table nobody listed keeps the plaintext public after privatization | §2.4's two generators + `tenancy_exempt`, wired into `visibility_lint.rs`'s `PROTECTED` at test time |
| Migration 070 lands with old pods still running, and every claim write raises `23502` | §9.2's 11a/11b/11c split, gated on `tenancy_undeclared_writes` flat for 24 h |
| The privatization job, the 14 CLI binaries and two Python scripts silently no-op under `FORCE` | PR-15's `MAINTENANCE_DATABASE_URL` + `SELECT epigraph_bypass()` startup assertion, landing **before** PR-17 |

**The five commands to run before writing any code:** §10.4 M1–M5.

**The four decisions only the user can make:** §10.3 Q1–Q4 (Q5 is a follow-up gate).
