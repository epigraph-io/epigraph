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
| `probe-batch-h.sh <binary> <label> <a\|b> [arm ...]` | The arms that need **group-private** rows, which no other script seeds: `patch_claim`, the five edge tools, `resolve_backlog_item` (public and private basis, plus an injected mid-call refusal), `submit_claim`'s DS wiring (plus an injected BBA refusal), `supersede_claim`, `theme_cluster` (all-or-nothing, with a pre-existing theme), and the three maintenance tools under four server configurations (`MAINTENANCE_DATABASE_URL` unset, set to the app login, set to `E2E_MAINT_DSN`, and unset with a bypass-capable APPLICATION DSN), plus `maint_auth`: the same tools over authenticated HTTP (`--jwt-secret`, secret random per run) with a `claims:write` and a `claims:admin` bearer; `caller_auth` (batch H-b): a caller that is not the server's signer authors, owns and signs its own claims, writes its own and is refused a foreign one, and a `claims:admin` bearer with a live client grant writes a foreign one through the AUDITED ADMIN PATH (audit row, admin as principal) while one without the grant is refused; and `op_http`: the operator's bearer on its linked agent's claims. Every case runs on an OWN-group row, which a correctly stamped write must land, and a FOREIGN-group row, which must fail loudly and write nothing on config A. Needs `jq`. |
| `probe-http-labels.sh <server binary> <label> <a\|b>` | **HTTP**: `PATCH /api/v1/claims/:id/labels` on the real `epigraph-api` `server` binary, connected as `E2E_APP_DSN`, with HS256 tokens minted per run under a random secret. Callers OWNER / ADMIN (`claims:admin`) / PEER / RADMIN (`claims:admin`, a READER of the team group) / NOGRANT (`claims:admin` in the token, no client grant) against own-public, own-private, another agent's public, foreign-private, world-owned and team rows. Prints the status, whether the label is on the row and the claim's `claims.admin_write` audit count, read back through the SU DSN. ADMIN and RADMIN carry an `oauth_clients` grant, which the audited admin path re-checks. Needs `python3`. |
| `probe-http-writes.sh <server binary> <label> <a\|b> [arm ...]` | **HTTP**: the claim writers batch H-a stamped — `supersede`, `DELETE /workflows/:id` and `/workflows/:id/outcome` on legacy flat workflow claims, `bp/propagate` with `apply_updates`, `themes/create-with-centroid` — for an owner, an admin and a peer, printing the status AND the rows read back (is_current, truth, counters, executions, BetP, themes). Needs `python3`. |
| `probe-operator.sh <binary> <label> <a\|b>` | OP-AUTHOR (batch H-b): an agent linked on the SU DSN and restarted on the APP DSN authors a stdio `submit_claim` owned by its operator's group, DS-wired and embedded. Every model carries a per-run nonce (agents and links survive TRUNCATE). And the stdio operator self-link's two REFUSALS through the real binary (migrations 105 + 107): `--operator-id` on the least-privilege DSN must exit non-zero with the EXECUTE-grant text and write no link or membership (OP-APP); an operator whose own personal-group row is only revoked must refuse with `RVK01` and stay revoked (OP-RVK01); a live operator on the same DSN must link (OP-LIVE, the calibration). The transport refusal, the HTTP listener's linked-signer refusal and the no-revival restart are `operator_startup_gate_test.rs`'s. OP-RVK01 and OP-LIVE run the server on `E2E_SU_DSN`, because the link function is EXECUTE-able by a maintenance or superuser login only. |
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

## Measured: batch H-a (the R3 prerequisites) at the revised tip

Every script in this directory was run on both configurations with the revised
tip's binaries, built in one worktree, and with the pushed tip before the
revision (`80398b7a`). Test cluster only, as a role with `rolbypassrls = false`.
**drive, probe-tools, probe-embed, probe-workflow (a, b, b2a) and probe-unit-e
produced the same verdicts and row counts for both binaries.** Their only
differences are log lines and run-to-run noise (agent and frame counts, a
similarity of 0.9999995 vs 1.0, and which revoked-membership warning a run
logged, which depends on agent rows that `TRUNCATE` does not clear).

The tables below are the discriminating scripts. "own" = the server agent's (or
the HTTP owner's) personal group; "foreign" = a group it is not in. Row counts
are the database's, not the response's. **Bold** = a success-over-nothing or
partial-state shape the R3 gate forbids, or an authority leak.

### MCP (`probe-batch-h.sh`, all arms)

| tool / case | A before (`a3fbc4ce`, or the hunk reverted) | A tip | B tip |
|---|---|---|---|
| patch_claim own public / own private | ERR 42501 / ERR not found | OK / OK | OK / OK |
| patch_claim foreign private / foreign public | ERR / ERR | ERR not found / ERR 42501, 0 rows | ERR not found / OK (orphan policy) |
| link_hierarchical, link_alternative own private | ERR not found | OK, edge owned by own group | OK |
| link_* touching foreign private | ERR not found | ERR not found, 0 edges | ERR not found |
| link_epistemic own→own private | ERR not found | OK, belief wired, BBA 1→2 | OK |
| patch_edge + delete_edge, own-group edge | ERR not found | OK, patched, retracted, 2 events | OK |
| patch_edge + delete_edge, edge the caller cannot read | ERR not found | ERR not found, untouched | ERR not found, untouched (**was OK on B before the read gate**) |
| resolve_backlog_item public / own-private basis | **ERR after writing a resolution** / ERR | OK 1/1/1 / OK 1/1/1 | OK / OK |
| resolve_backlog_item foreign-private basis / injected edge refusal | ERR / **resolution left behind** | ERR, 0/0/0 / ERR, 0/0/0 | same |
| submit_claim / memorize, injected BBA refusal | **OK over a claim with no BBA** | ERR, 0 rows | ERR, 0 rows |
| supersede_claim own public / own private | ERR 42501 / ERR not found | OK, retired, 1 replacement / OK | OK / OK |
| supersede_claim foreign private / foreign public | ERR / ERR | ERR not found / ERR 42501, untouched | ERR not found / OK (orphan policy) |
| theme_cluster (wipe_first) over the server agent's public claims | **ERR 42501 with an orphan theme, previous themes wiped** | ERR 42501, previous themes intact | OK, 2 themes |
| maintenance x3, `MAINTENANCE_DATABASE_URL` unset or = app login | ERR (hard gate) | ERR, rows unchanged | ERR, rows unchanged |
| maintenance x3, configured bypass-capable DSN | ERR (hard gate) | OK on FOREIGN rows (cache written, dup retired, vectors stored) | OK |
| maintenance x3, unset but the APP DSN bypass-capable | ERR (hard gate) | ERR, rows unchanged (**was OK at `80398b7a`**) | ERR |
| maintenance x3 over HTTP, claims:write bearer | n/a | Forbidden, nothing listed or retired (**was OK at `80398b7a`: foreign ids listed, one retired**) | Forbidden |
| maintenance x3 over HTTP, claims:admin bearer | n/a | OK, pair listed, one retired | OK |

### HTTP (`probe-http-writes.sh`, `probe-http-labels.sh`, real `server` binary)

| route / case | A at `80398b7a` | A tip | B tip |
|---|---|---|---|
| supersede owner own public / own private | 500 / 404 | 201, retired, version row / 201 | 201 / 201 |
| supersede admin other agent's public | 500 | 403, nothing written | 201 |
| DELETE /workflows/:id owner own flat public / private | **200, `is_current` still true** | 200, `is_current=f` | 200, f |
| DELETE /workflows/:id peer other's flat | **200, nothing written** | 403, untouched | 200 (no ownership check, see below) |
| POST /workflows/:id/outcome owner own flat public | **200, truth unchanged, execution +1** | 200, truth, counters and execution together | same |
| POST /workflows/:id/outcome owner own flat private | 404 | 200 | 200 |
| POST /bp/propagate apply, own factor | **200 `applied:true`, 0 rows** | 200, BetP 0.20→0.39 | same |
| POST /bp/propagate apply, factor into a stranger's claim | **200 `applied:true`, 0 rows** | 403, nothing written | 200 |
| POST /bp/propagate apply, factor naming a non-claim id | **200 `applied:true`, 0 rows** | 200, real claims written, `skipped_not_visible: 1` | same (**was 409 at 2fe34e17**) |
| POST /themes/create-with-centroid own / other's claims | **500 with `claim_themes +1`** / same | 201, themed / 403, +0 | 201 / 201 |
| PATCH /labels owner own public / own private | 200 / 200 | 200 / 200 | 200 / 200 |
| PATCH /labels admin other agent's public | 200 (**author's stamp lent**) | 403 | 200 |
| PATCH /labels READER-member admin, team private / public | **200 / 200 (author's stamp lent)** | 403 / 403 | 200 / 200 |
| PATCH /labels admin foreign unreadable / world-owned / peer | 404 / 403 / 403 | 404 / 403 / 403 | 404 / 200 / 403 |

The batch H-a reviewer's own scratch probes (`probe_http.py`, `probe_http2.py`,
`probe_mcp.py`, `probe_mcp_auth.py`: about 80 HTTP routes, 78 MCP cases and the
authenticated MCP arm) were re-run at the tip on both configs and diffed against
their saved `80398b7a` runs. On B the only moved rows are supersede's new
`claim_versions` row and counts that depend on accumulated test-database state
(evolve_step's factor delta, `frames/evidence`'s leftover edges, theme counts,
and one `batch_submit_claims` novelty-gate dedup that did not reproduce on a
re-run); the stale-factor `bp/propagate` 409 they exposed is fixed. On A the moved
rows are exactly the conversions in the tables above.

On config A every row above now either succeeds or fails loudly with nothing
written. Config B is unchanged except where a row is marked as a tightening
(an edge the caller cannot read, the maintenance fallback, a claims:write
bearer on the maintenance tools) or an improvement (supersede now records its
version row, which the unstamped INSERT never did on either config).

## Measured: batch H-b (cross-agent authority) at its tip

Binaries: `TIP` is this branch; `BASE` is `origin/main` at `e507a1fc` (#505 on
#503), built from the same worktree by checking the crates out at that ref.
Database: `epigraph_*_test` on the test cluster, migrated `001 -> 111`, the
server on a login in `epigraph_app` (`rolbypassrls = false`), `E2E_MAINT_DSN` a
login in `epigraph_maintenance`. "Caller" is an agent that is NOT the server's
signer. Every figure below is the database's, read back through the SU DSN.

### MCP over authenticated HTTP (`probe-batch-h.sh caller_auth op_http`)

| case | A BASE | A TIP | B TIP |
|---|---|---|---|
| caller `submit_claim`: author / owner / signer | **SERVER / server's group / none** | CALLER / caller's group / SERVER | same as A |
| `verify_claim` on it | **signed=false, signature_valid=false** | signed=true, signature_valid=true, hash match | same |
| caller `patch_claim` / `update_labels +resolved`, its OWN claim | **ERR (gate: principal is not the author), 0 rows** | OK, patched / labelled | OK |
| caller `patch_claim` / `update_labels +resolved`, a FOREIGN claim | ERR, 0 | ERR (not the author, not its operator, no admin), 0 | ERR, 0 |
| caller `update_labels` foreign, a non-retirement label | ERR 42501, 0 | ERR 42501, 0 | OK (orphan policy) |
| admin (live grant on its client record) `update_labels` / `patch_claim`, foreign public | **ERR 42501, 0 rows, no audit** | OK `admin_path=true`, written, 1 audit row each, principal = ADMIN, author recorded as target | same |
| admin, foreign PRIVATE it cannot read | ERR not found | ERR not found | ERR not found |
| admin token whose `sub` grants nothing | ERR 42501 | ERR `ADM02`, 0 rows, 0 audit rows | same |
| operator's `claims:write` bearer on its linked agent's claims: `patch_claim` / `update_labels +resolved` / `resolve_backlog_item` | **ERR 42501 x3, 0 rows** (gate admitted, stamp was the server's) | OK x3, written; the resolution is authored by the OPERATOR | OK x3 |

### stdio operator authoring (`probe-operator.sh`, OP-AUTHOR)

An agent linked on the SU DSN, restarted on the APP DSN without
`--operator-id`: `submit_claim` is authored by the agent, OWNED by the
operator's personal group, DS-wired (1 BBA) and embedded, on A and on B. OP-APP,
OP-RVK01 and OP-LIVE PASS on both, with a per-run nonce in every model so a
re-run with the same label no longer re-derives an already-linked agent.

### HTTP `PATCH /api/v1/claims/:id/labels` (`probe-http-labels.sh`, real `server`)

| caller / row | A at #505 (README table above) | A TIP | B TIP |
|---|---|---|---|
| owner own public / own private | 200 / 200 | 200 / 200, no audit | same |
| admin other agent's public | 403 | 200 via the audited path, 1 audit row | same |
| admin foreign unreadable | 404 | 404 | 404 |
| admin world-owned | 403 | 200 via the audited path, 1 audit row | same |
| READER-member admin, team private / public | 403 / 403 | 200 / 200 via the audited path: the ADMIN is the recorded principal, not the author | same |
| peer other's public | 403 | 403, 0 rows | 403 |
| admin token with no client grant | n/a | 403 ("the audited admin path refused this token"), 0 rows | same |

### What moved on config B, stated

* **Tightening.** On the `--allow-unauthenticated-http` listener the injected
  context carries `claims:admin` with a NIL `client_id`, so a cross-group write
  there now takes the admin path and is refused `ADM02`
  (`patch_claim foreign_pub`: was OK through the orphan policy, now ERR, 0
  rows). An unauthenticated socket has no admin principal to audit.
* Every other row of the H-a tables above is unchanged on both configs
  (the `patch_claim foreign_pub` message on A changed from a bare 42501 to the
  admin path's refusal; both write nothing).

## R3 checklist: what still blocks dropping the orphan policies

This branch closes the write paths above. It does **not** make the whole write
surface ready for R3. Each item below was measured by the batch H-a review (the
`probe_*.py` scratch probes) unless it says otherwise, and each needs its own
decision or conversion before the operator drops `claims_privacy`,
`evidence_privacy` and `edges_privacy`.

1. **CLOSED by batch H-b: authenticated MCP stamped from the SERVER agent, not
   the caller.** Every MCP write now authors and stamps as
   `EpiGraphMcpFull::write_identity(auth, viewer)` (the caller over HTTP, the
   server agent on stdio), measured by `probe-batch-h.sh caller_auth` above.
   Two rows that belong to it, also closed and measured there:
   - **The HTTP operator arm.** An HTTP MCP server on the app DSN with an
     unrelated signer, and the OPERATOR's `claims:write` bearer acting on public
     claims authored by its linked agent: `patch_claim`, `update_labels
     +resolved` and `resolve_backlog_item` all passed `require_owner_or_admin`
     through #503's operator arm and then failed 42501 on A with nothing
     written, because the transaction was stamped from the server agent; on B
     they succeeded only through the orphan policy. Now OK on both
     (`probe-batch-h.sh op_http`).
   - **`claims:admin` into a group the admin cannot write.** Refused on A,
     admitted on B only by the orphan policy. Now the audited admin path
     (migration 111) on both surfaces, with the admin recorded as principal and
     a `security_events` row. Supersede is deliberately NOT on that path: an
     admin supersede into a group it cannot write stays refused on A.
2. **HTTP writes still on the unstamped pool** (A refuses the owner, B admits):
   - `POST /api/v1/claims` and `POST /claims`: opaque 500;
   - `PUT` and `PATCH /api/v1/claims/:id`: 500 42501 on own public, 404 on own
     private;
   - `POST /claims/:id/dedup` (claims:admin): 409 "already superseded or
     invalid input", a misleading status for an RLS refusal;
   - `PUT /claims/:id/embedding`;
   - `POST /api/v1/evidence`, `PUT /evidence/:id`, `PUT /evidence/:id/embedding`;
   - `POST /api/v1/edges` from an own-private source: 404;
   - `POST /workflows/steps/:id/evolve`;
   - `POST /skills/share` on an own flat workflow.
   `crates/epigraph-db/tests/no_unscoped_pool.rs` is the register (274 sites) and
   `crates/epigraph-api/tests/discarded_route_writes.rs` pins the 46 `let _ =`
   writes. The remedy is the one this branch used: `AppState::write_as` plus
   `errors::write_refused` for `42501`.
3. **Workflow ingest drops embeddings on A.** `POST /workflows`,
   `/workflows/ingest` and `/workflows/steps` commit their claims, but on A every
   embedding store fails with a WARN ("Failed to store embedding for ingested
   workflow claim"). Measured 8/8 workflow claims with a NULL embedding on A, 3/9
   on B. This breaks the CLAUDE.md embedding invariant (every current,
   non-telemetry claim has a vector), so it is an R3 blocker in its own right,
   not a cosmetic warning.
4. **MCP tools still on the unstamped pool** (`residual_unstamped_writes.rs` is
   the register):
   - `evolve_step`: 42501 on A. Its population is step claims authored by
     `workflow-ingest-system`, and stamping from that system agent is H3
     (84b2a98d).
   - `refresh_workflow_promotion`'s `merge_properties`: same population, same H3
     question. Its A behaviour is inferred, not measured.
   - `mark_duplicate`: CONVERTED in batch H-b (gate read, dedup and cascade on
     one caller-stamped transaction); both retraction cascades are stamped from
     the caller with a savepoint per edge and per target, so a downstream claim
     the caller cannot write fails alone and is reported in
     `belief_cascade.errors`.
   - `consolidate_claims` with a foreign public source: 42501. Authority-correct.
   - `report_workflow_outcome` / `deprecate_workflow` on FOREIGN-owned legacy flat
     claims: 42501. Authority-correct.
   - `theme_cluster`: atomic now, but a corpus-wide job with no author stamp that
     covers it, so it fails loudly on A. It needs a maintenance path that config B
     does not lose.
4a. **A real `epigraph_maintenance` login cannot write `factors`.** MEASURED in
   batch H-b with `E2E_MAINT_DSN` a login role in `epigraph_maintenance` (every
   earlier run defaulted it to the superuser DSN): `sweep_semantic_duplicates`
   over authenticated HTTP lists the pair and then fails every merge with
   `permission denied for table factors`, identically on `BASE` and `TIP`.
   Migration 070 grants the role `SELECT, INSERT, UPDATE ON ALL TABLES` as of
   070, and says a later table must re-issue the grant; `factors` did not. A
   deployment whose `MAINTENANCE_DATABASE_URL` is a non-superuser maintenance
   login has a dedup sweep that retires nothing.
5. **Pre-existing failures on BOTH configurations** (base == tip on B, so not
   regressions, but several leave partial state on B, which is production):
   - `POST /api/v1/hypothesis`: B 500 "hypothesis_assessment frame not found",
     claim +1 left behind (A atomic). Depends on whether production has that
     frame.
   - `POST /api/v1/conventions`: A 500 leaving an agent, a group and a membership;
     B 500 leaving claims +1 and evidence +1.
   - `POST /frames/:id/evidence`: B 500 with an edge +1 left behind.
   - Refused on both configs: `POST /claims/:id/challenge` (own and foreign:
     challenge cannot serve its core use case on either config),
     `/reasoning-traces`, `PUT /perspectives/:id/source-reliability`,
     `/communities`, `/entity-mentions/batch`, `/triples/batch`,
     `/frames/:id/assign-claim`, `/conflicts/:a/:b/resolve` and `/groups`.
   - `POST /submit/packet` with a real Ed25519 signature: A fails on `claims`, B
     on `reasoning_traces`. This is the host-telemetry path.
   - MCP `challenge_claim`, `update_with_evidence` and `submit_ds_evidence` on a
     foreign public claim, and `mark_duplicate` when the duplicate has a
     belief-wired supporter.
   - Dead routes: `/coalitions` and `/propaganda-techniques` name relations that
     do not exist.
6. **Known shapes that meet the R3 gate's "succeeds while writing nothing"
   definition**, the same on both configs; each must be accepted or fixed:
   - `POST /api/v1/claims/batch`: 200 `created: 2` with ids and 0 rows, because
     `AppState::claim_store` is an in-memory map (the handler doc says so);
   - MCP `deprecate_workflow` on a hierarchical id: `deprecated_ids=[id]`, but the
     id is not a claim (README trap 2);
   - HTTP `/workflows/:id/outcome`, `/behavioral-executions`, `/skills/share` and
     `DELETE /workflows/:id` return 404 for hierarchical `workflows`-table ids.
7. **No ownership check on the HTTP flat-workflow writers.**
   `DELETE /workflows/:id` and `POST /workflows/:id/outcome` let any
   `claims:write` caller act on another agent's workflow. On B the orphan
   policies admit it; on A the stamped write now refuses it (403). The authority
   decision is #374 / H3.
8. **H3, hierarchical workflows: PARTLY closed by batch H-b, forward-only.**
   `add_step` / `delete_step` (MCP and HTTP) and a variant ingest now check the
   caller against the workflow's recorded submitter (the submitter, its
   operator, or `claims:admin`; over HTTP only, stdio unchanged). `workflows`
   recorded no owner before batch H-b, so every EXISTING workflow has no record
   and stays open to any caller, with a WARN: which authority legacy workflows
   carry is an open operator decision. `evolve_step` and
   `refresh_workflow_promotion` (item 4) are not covered: they remain on the
   unstamped pool and take no workflow-authority check. Measured by
   `epigraph-mcp/tests/workflow_caller_authority.rs` and the API
   `workflow_steps_refuse_a_caller_who_did_not_submit_the_workflow`; no e2e arm
   drives it yet.

## What this harness does not cover

It exercises tools, not the repository layer, and apart from
`probe-http-labels.sh` and `probe-http-writes.sh` it says nothing about the HTTP
surface. The in-repo complement is
`crates/epigraph-mcp/tests/residual_unstamped_writes.rs`, a source ratchet over
`crates/epigraph-mcp/src` that pins which write sites still take the unstamped
pool. That ratchet catches *a converted site reverted to `server.pool`* — verified
by doing it. It does **not** catch *a site stamped from the wrong author*, because
that is invisible to a syntactic scan. These scripts are currently the only
instrument for that axis.
