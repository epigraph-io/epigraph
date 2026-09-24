# MCP write-path e2e harness

Runs the **real `epigraph-mcp-full` binary** over a unix socket, as the **real
least-privilege role**, against a **throwaway database**, and reports what the
database actually holds afterwards.

It exists because the unit suite structurally cannot see the defects this branch
is about. `#[sqlx::test]` connects as `epigraph` — superuser, `BYPASSRLS`, owner
of every protected table — so an arm shaped *"the write now succeeds"* passes
identically on a tree where the write is refused. These scripts reach a role with
`rolbypassrls = false`, which is the only way a `42501` can be observed at all.

Every figure quoted in this branch's commit messages came from here. Committing
the harness is what makes those figures re-runnable instead of quoted: a previous
generation of this same evidence was already irreproducible, and `run-e2e.sh` had
referenced `set-config.sh` since it was authored while that file did not exist on
disk.

## Required environment

Nothing in this directory contains a credential. Both DSNs come from the
environment, and every script refuses with a usage message when either is unset.

| Variable | Required | What it is |
|---|---|---|
| `E2E_SU_DSN` | yes | Superuser DSN with DDL rights on the throwaway database — used for migrations, the CONFIG B policy replay, `TRUNCATE`, and the row counts that are the verdict. |
| `E2E_APP_DSN` | yes | The least-privilege DSN the server connects as. **`rolbypassrls` MUST be `false`** or every arm is vacuous. |
| `OPENAI_API_KEY` | for the D1 arm | `probe-embed.sh` **refuses to run without it**: with no key the embedder fails *before touching the database*, so `embedding IS NOT NULL` would measure the absence of a key rather than the presence of a write. The other scripts treat the embedder as best-effort. |
| `E2E_AGENT_KEY` | no | 32-byte hex Ed25519 seed for the server's own agent. Defaults to a deliberately public throwaway seed. |

> **`E2E_AGENT_KEY` is a parameter for a reason.** An earlier revision of these
> scripts inlined a `--agent-key` value that is the **live production**
> `epigraph-mcp-http.service` / `epigraph-mcp-auth.service` signing key. Never
> point this at a real deployment's key.

Both DSNs must name an **explicit port on the test cluster** (5433 on the
reference host). Every script sources `dsn-guard.sh` first, which refuses a DSN
with no port, on port 5432 (the production cluster), or with no host before
any `psql` or server start, and passes the DSN's port to every `psql` call as
`-p` and its host as `-h` (a `?host=/socket/dir` query parameter is honoured
for the unix-socket form). Before
that guard the scripts ignored the DSN's port, so the superuser half
(migrations, policy replay, `TRUNCATE`) went to libpq's default, 5432, unless
the caller also exported `PGPORT`. The host had the same defect one field
over, and outlived the port fix: every `psql` call hard-coded `-h 127.0.0.1`, so
a DSN naming another host (a container network, a CI service host) had its
verdict queries run against whatever listened on loopback while the server
binary wrote to the host the DSN named.

The database must be migrated `001 → head` from empty and its name should end in
`_test`. `epigraph_db_repo_test` will **not** work: it has no tenancy migrations
and fails closed at 060.

```bash
export E2E_SU_DSN='postgres://<su>:<pw>@127.0.0.1:5433/epigraph_e2e_test'
export E2E_APP_DSN='postgres://epigraph_app:<pw>@127.0.0.1:5433/epigraph_e2e_test'
```

## The two schema configurations

The whole harness turns on the difference between them.

* **CONFIG A** — the clean public migration series, `001 → head`, and nothing
  else. This is what a fresh install gets, and what production becomes after the
  R3 remediation.
* **CONFIG B** — A *plus* the three orphan `PERMISSIVE` `*_privacy` policies
  (`claims`, `evidence`, `edges`) and the two helper functions they call,
  replayed verbatim from production. **This is what production runs today.**

`set-config.sh a|b` switches between them. The orphan policies are `FOR ALL
USING (…)` with no explicit `WITH CHECK`, so PostgreSQL reuses `USING` as the
check — and the predicate reads `app.group_id`, a GUC namespace nothing in this
codebase sets. It returns `NULL`, the check degenerates to `TRUE`, and that is
precisely why production admits writes a clean schema refuses.

## Scripts

| Script | What it measures |
|---|---|
| `run-e2e.sh <binary> [label]` | `submit_claim` / `memorize` / `link_epistemic`, then row counts. The baseline "does the write path work at all" pass. |
| `probe-tools.sh <binary> <label> <a\|b>` | `challenge_claim`, `update_with_evidence`, `submit_ds_evidence`, `update_labels`. Every arm hangs off a claim authored by the server's own agent. |
| `probe-embed.sh <binary> <label> <a\|b>` | The `McpEmbedder::embed_and_store` callers that embed **executor-authored** claims (`store_workflow`, `add_step`) — the arms that distinguish *stamped* from *stamped from the right author*. |
| `probe-workflow.sh <binary> <label> <a\|b\|b2a>` | `deprecate_workflow` and `report_workflow_outcome` on their own populations, hierarchical **and** legacy-flat, in both ownership shapes. |
| `probe-unit-e.sh <binary> <label> <a\|b>` | The R3 gate's remaining tools: `ingest_workflow` (with level-3 atoms), `improve_workflow_hierarchy`, `delete_step`, `link_epistemic`'s belief wiring, `consolidate_claims` (own and foreign sources), `ingest_document_inline` (fresh, re-ingest, converged-foreign-atom) and `ingest_document_spine`, plus the authority arms: the synchronous ingest PREFLIGHT, and a REVOKED / READER ingest-system membership that must not be revived or promoted. Also the REGISTER arm the residual-register reasons cite, and the REVIEW arms: plan order under one transaction (`report_workflow_outcome` attribution), a SECOND `store_workflow` without truncating, transactional event timestamps, a hidden axis frame inside the DS transaction, and a server agent revoked in its PERSONAL group but live in a team group (warm session, fresh MCP session, and a restarted process — each asserted PASS/FAIL: refused, still revoked, +0 claims). Batch F adds the RECALL arm (#493): a recall by a revoked principal must leave it revoked, and a live member's recall must still answer. |
| `probe-batch-h.sh <binary> <label> <a\|b> [arm ...]` | The arms that need **group-private** rows, which no other script seeds: `patch_claim`, the five edge tools, `resolve_backlog_item` (public and private basis, plus an injected mid-call refusal), `submit_claim`'s DS wiring (plus an injected BBA refusal), and the three maintenance tools under three server configurations (`MAINTENANCE_DATABASE_URL` unset, set to the app login, set to `E2E_MAINT_DSN`). Every case runs on an OWN-group row, which a correctly stamped write must land, and a FOREIGN-group row, which must fail loudly and write nothing on config A. Needs `jq`. |
| `embed-verdict.sh` | How many committed claims carry a vector. |
| `drive.sh <binary> <label> <a\|b>` | `set-config` + `run-e2e` + the embedding verdict, in one call. |
| `set-config.sh a\|b` | Switches the schema configuration. Reads `helper.sql` and `fn2.sql`. |

`probe-workflow.sh`'s `b2a` mode **seeds on B, then drops the orphan policies and
measures on A**. That is the R3 remediation itself.

It used to be the only mode that could answer anything about the workflow tools,
because on a clean series `store_workflow` was *itself* refused (`new row
violates row-level security policy for table "claims"`, from the pool-bound
ingest executor), leaving nothing to deprecate and every downstream arm vacuous
by absence. **That is fixed**: the ingest executor now takes a connection stamped
from the `workflow-ingest-system` agent's viewer, so mode `a` seeds successfully
and is the primary mode. The old refusal is what mode `a` now regression-tests —
run it against a binary built before the conversion and it reproduces verbatim,
which is how the fixed and unfixed binaries are distinguished.

## Comparing two binaries

The load-bearing shape is *same config, same database, only the binary differs*:

```bash
cargo build -p epigraph-mcp --bin epigraph-mcp-full
cp "$CARGO_TARGET_DIR/debug/epigraph-mcp-full" /tmp/mcp-FIXED
git stash            # or revert the hunk under test
cargo build -p epigraph-mcp --bin epigraph-mcp-full
cp "$CARGO_TARGET_DIR/debug/epigraph-mcp-full" /tmp/mcp-BASE
git stash pop

./scripts/e2e/probe-workflow.sh /tmp/mcp-BASE  baseA b2a
./scripts/e2e/probe-workflow.sh /tmp/mcp-FIXED fixA  b2a
```

All scripts take **advisory lock `918273645`** for their whole run, because they
`TRUNCATE` a shared database and then count rows: two concurrent runs corrupt each
other's verdict, and one truncating while the other counts looks exactly like "the
write path is broken". The lock is load-bearing, not hygiene.

## Traps these scripts have already fallen into

Each was a measured false result, not a hypothetical. They are documented at the
site that hit them; they are collected here because they generalise.

1. **`agents.display_name = 'mcp-agent'` is not unique.** Every run with a
   different `--agent-key` mints another row with that display name (14 of them on
   the shared database at the time of writing). Identifying "the server's own
   agent" by display name picks an arbitrary previous run's agent, and seeding an
   "own group" fixture into it yields a `42501` that looks exactly like the defect
   under investigation. `probe-workflow.sh` reads `claims.agent_id` back off a
   `submit_claim` instead, which cannot drift.
2. **`deprecate_workflow` is polymorphic over its id.** It passes one UUID to both
   `ClaimRepository::deprecate_claim` and `WorkflowRepository::set_truth_value`,
   and those ids come from different derivations. If the id is not a claim id,
   `deprecate_claim` matches **zero rows**, no error is raised, and the tool
   reports success — indistinguishable from "the write was allowed". Read
   `probe-workflow.sh`'s IDENTITY CHECK before any verdict beneath it.
3. **The step-claim label is `workflow_step`, with an underscore.** An earlier
   `probe-embed.sh` asked for `workflow-step`; it matched nothing, every count
   read `0`, and the D1 verdict was vacuous while looking like a measurement.
4. **An absent `OPENAI_API_KEY` makes every embedding arm vacuous.** The embedder
   fails before it reaches the database, so `embedding IS NULL` says nothing about
   the write path. `probe-embed.sh` hard-refuses rather than reporting it.
5. **Every probe TRUNCATEs first, which hides collisions that span runs.**
   `store_workflow`'s constant `"Body"` phase is hashed with plain `content_hash`,
   so the SECOND workflow ever written collides on `uq_claims_content_hash_agent`
   ("Duplicate entity already exists") — on main and in production too. No probe
   saw it, because each run starts from an empty `claims` table and writes one
   workflow. A probe that asserts "tool X succeeds" on a truncated database says
   nothing about the second call. **This trap caught this branch's own
   acceptance matrix**: commit 3c921b69 reports `store_workflow` as "ingested 4"
   on both configs, and that is the FIRST workflow only. The STORE_WORKFLOW
   TWICE arm of `probe-unit-e.sh` measures the second: on this branch it fails
   loudly and atomically (`Duplicate entity already exists`, delta 0/0/0) on
   both configs; on main it fails the same way but leaves one claim and one
   `workflows` row behind. The collision itself is open work: the workflow
   builder hashes thesis/phase/step claims with plain `content_hash`, and
   switching them to `compound_content_hash` (as the document builder did)
   also changes what `verify_claim` must accept for level-2 workflow claims
   (`verify_claim_crypto.rs::tampered_non_document_level_two_reports_mismatch`
   pins the plain hash), so it is its own decision.
6. **One transaction means one `NOW()`.** Since the Unit E conversions a whole
   workflow plan (every claim, every `executes` edge, every `claim.created`
   event) shares one `created_at`. Any ordering keyed on `created_at` over
   rows one walk wrote is an ordering by the tiebreak. The PLAN ORDER arm is
   the measurement; a probe that checks order must also check that the
   timestamps actually tie, or it passes vacuously.
7. **A baseline binary must come from its OWN target dir.** Building an extracted
   copy of the same workspace (`git archive <ref> | tar -x`) with the same
   `CARGO_TARGET_DIR` is unsafe: cargo hashes path packages relative to the
   workspace root, the extracted files carry OLD mtimes, and cargo reports
   `Finished` without compiling and hands back the OTHER tree's binary. MEASURED —
   a "main" binary built that way embedded the worktree's paths. Build the
   baseline with a separate `CARGO_TARGET_DIR`, and check
   `strings <binary> | grep crates/epigraph-engine` names the tree you meant.

## Measured: batch H (the R3 prerequisites), base a3fbc4ce vs branch tip

Every script in this directory was run on both configurations, with the base
binary (built from `a3fbc4ce` in the same worktree) and the tip binary.
**drive, probe-tools, probe-embed, probe-workflow (a, b, b2a) and probe-unit-e
produced the same verdicts and row counts for both binaries.** Their only
differences are log lines and run-to-run noise (agent counts, a similarity of
0.99999 vs 1.0), so nothing previously working regressed. The per-tool table
below is `probe-batch-h.sh`, whose group-private rows are what discriminate.
"own" = the server agent's personal group, "foreign" = a team group it is not
in. Row counts are the database's, not the response's.

| tool / case | A base | A tip | B base | B tip |
|---|---|---|---|---|
| patch_claim own public | ERR 42501, 0 rows | OK | OK | OK |
| patch_claim own private | ERR not found | OK | OK | OK |
| patch_claim foreign private | ERR not found | ERR not found, 0 rows | **OK (orphan policy; caller cannot read it)** | ERR not found, 0 rows |
| patch_claim foreign public | ERR 42501 | ERR 42501, 0 rows | OK | OK |
| link_hierarchical own→own private | ERR not found | OK, edge owned by own group | OK | OK |
| link_hierarchical touching foreign private | ERR not found | ERR not found, 0 edges | ERR | ERR |
| link_alternative own↔own private | ERR not found | OK | OK | OK |
| link_epistemic own→own private (supports) | ERR not found | OK, belief_wired, BBA 1→2, edge.added | OK | OK |
| link_epistemic own→foreign public (contradicts) | ERR not found | OK edge, belief_wired=false, 0 target BBAs | same | same |
| patch_edge + delete_edge, own-group edge | ERR not found | OK, patched, retracted, 2 events | OK | OK |
| patch_edge + delete_edge, foreign-group edge | ERR not found | ERR not found, untouched | OK (orphan policy) | OK (orphan policy) |
| resolve_backlog_item, public basis | **ERR after writing: resolution=1, item still open** | OK 1/1/1 | OK | OK |
| resolve_backlog_item, own-private basis | ERR not visible | OK 1/1/1 | OK | OK |
| resolve_backlog_item, justifies edge refused (injected) | **ERR, resolution=1 left behind** | ERR, 0/0/0 | **ERR, resolution=1 left behind** | ERR, 0/0/0 |
| submit_claim / memorize fresh | OK, BBA=1 | OK, BBA=1 | OK | OK |
| submit_claim / memorize, BBA refused (injected) | **OK over claims=1 with no BBA** | ERR, claims=0 | **OK over claims=1 with no BBA** | ERR, claims=0 |
| recompute_beliefs / sweep_semantic_duplicates / backfill_embeddings, maintenance DSN unset or = app login | ERR (hard gate) | ERR, rows unchanged | ERR | ERR, rows unchanged |
| the same three, maintenance DSN bypass-capable | ERR (hard gate) | OK on FOREIGN rows: cache written, cross-group dup retired, vector stored | ERR | OK, same |

Bold cells are the success-over-nothing / partial-state shapes the R3 gate
forbids. A guard-less mutation build (maintenance pool attached unconditionally,
per-call probe skipped) turns the "unset / app login" row into **OK over zero
rows** (claims_recomputed=0, scanned=0, embedded=0), which is the hazard the
maintenance gate exists for. The HTTP half of batch H (supersede and
deprecate_workflow gate reads) is pinned by
`crates/epigraph-api/tests/write_gate_reads_are_viewer_filtered.rs`, not here.

## What this harness does not cover

It exercises tools, not the repository layer, and it says nothing about the HTTP
surface. The in-repo complement is
`crates/epigraph-mcp/tests/residual_unstamped_writes.rs`, a source ratchet over
`crates/epigraph-mcp/src` that pins which write sites still take the unstamped
pool. That ratchet catches *a converted site reverted to `server.pool`* — verified
by doing it. It does **not** catch *a site stamped from the wrong author*, because
that is invisible to a syntactic scan. These scripts are currently the only
instrument for that axis.
