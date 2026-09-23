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

The database must be migrated `001 → head` from empty and its name should end in
`_test`. `epigraph_db_repo_test` will **not** work: it has no tenancy migrations
and fails closed at 060.

```bash
export E2E_SU_DSN='postgres://<su>:<pw>@127.0.0.1:5432/epigraph_e2e_test'
export E2E_APP_DSN='postgres://epigraph_app:<pw>@127.0.0.1:5432/epigraph_e2e_test'
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
| `probe-unit-e.sh <binary> <label> <a\|b>` | The R3 gate's remaining tools: `ingest_workflow` (with level-3 atoms), `improve_workflow_hierarchy`, `delete_step`, `link_epistemic`'s belief wiring, `consolidate_claims` (own and foreign sources), `ingest_document_inline` (fresh, re-ingest, converged-foreign-atom) and `ingest_document_spine`, plus the authority arms: the synchronous ingest PREFLIGHT, and a REVOKED / READER ingest-system membership that must not be revived or promoted. Also the REGISTER arm the residual-register reasons cite, and the REVIEW arms: plan order under one transaction (`report_workflow_outcome` attribution), a SECOND `store_workflow` without truncating, transactional event timestamps, a hidden axis frame inside the DS transaction, and a server agent revoked in its PERSONAL group but live in a team group (warm session and fresh MCP session). |
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

## What this harness does not cover

It exercises tools, not the repository layer, and it says nothing about the HTTP
surface. The in-repo complement is
`crates/epigraph-mcp/tests/residual_unstamped_writes.rs`, a source ratchet over
`crates/epigraph-mcp/src` that pins which write sites still take the unstamped
pool. That ratchet catches *a converted site reverted to `server.pool`* — verified
by doing it. It does **not** catch *a site stamped from the wrong author*, because
that is invisible to a syntactic scan. These scripts are currently the only
instrument for that axis.
