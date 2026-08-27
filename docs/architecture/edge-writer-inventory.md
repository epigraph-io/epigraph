# Edge Writer Inventory

**Status:** Reference (2026-08-26)
**Owners:** epigraph-internal
**Companion to:** [`docs/architecture/noun-claims-and-verb-edges.md`](noun-claims-and-verb-edges.md), "Edge signing"

This document answers one question for every code path that writes an `edges`
row: **is a signing key in scope where that write happens?** It is descriptive,
not prescriptive — it does not propose an edge-signing design, it establishes
the ground truth a design would have to start from.

Every count in this document is re-derivable; see
[Reproducing this inventory](#reproducing-this-inventory).

---

## Schema ground truth

`edges` has carried the signing columns since the baseline schema. In
`migrations/001_initial_schema.sql`:

| Artifact | Location | Definition |
|---|---|---|
| `signature bytea` | `migrations/001_initial_schema.sql:767` | nullable |
| `signer_id uuid` | `migrations/001_initial_schema.sql:768` | nullable |
| `content_hash bytea` | `migrations/001_initial_schema.sql:769` | nullable |
| `edges_signature_length` | `migrations/001_initial_schema.sql:774` | `signature IS NULL OR octet_length(signature) = 64` |
| `edges_signature_requires_signer` | `migrations/001_initial_schema.sql:775` | both NULL or both NOT NULL |
| `edges_signer_id_fkey` | `migrations/001_initial_schema.sql:3551` | `signer_id -> agents(id) ON DELETE SET NULL` |
| `idx_edges_signer_id` | `migrations/001_initial_schema.sql:2525` | partial btree `WHERE signer_id IS NOT NULL` |

The schema is complete and enforcing. Ed25519 signatures are 64 bytes, so
`edges_signature_length` already pins the algorithm's output width, and
`edges_signature_requires_signer` already forbids an orphan signature.

> **Do not cite "migration 073" for these columns.** `migrations/` in this
> repository runs `001`–`059`; there is no `073`. The verifiable citation is
> `001_initial_schema.sql` at the line numbers above. See
> [Doc-citation discrepancy](#doc-citation-discrepancy).

---

## Headline finding: edge signing coverage is zero, not partial

- **0 of 41** direct `INSERT INTO edges` statements under `crates/*/src/` name
  `signature` or `signer_id` in their column list.
- **0 of 88** `EdgeRepository::create*` occurrences pass a key, a signature, or
  a signer id — none of the four entry points accepts one.
- `EdgeRow` (`crates/epigraph-db/src/repos/edge.rs`) has no `signature` field,
  and no `SELECT` in that file reads one. **The read path is unimplemented
  too**, so even a hand-signed row could not be verified through the repo layer.

The only mention of the columns anywhere in `edge.rs` is a doc comment on
`list_current_claim_targets` enumerating the table's columns for a different
purpose.

Every `edges` row in the database has `signature IS NULL` and
`signer_id IS NULL`, and will continue to until a writer is changed. The
constraints have never fired because nothing has ever exercised them.

---

## Direct `INSERT INTO edges` sites

41 statements across 15 files. None goes through `EdgeRepository` — that is
what makes them "direct". `<bound>` in the relationship column means the verb
arrives as a bind parameter or is copied by an `INSERT … SELECT`, so it is not
a fixed literal at the call site.

Eight of the 41 live inside `#[cfg(test)]` / `#[cfg(all(test, feature = "db"))]`
modules that happen to sit in `src/` rather than `tests/`; they are marked
**test fixture** and are not production writers. That leaves **33 production
statements**.

### `epigraph-api` — route layer

| Call site | Enclosing fn | Relationship | Signing key in scope? |
|---|---|---|---|
| `crates/epigraph-api/src/routes/crud.rs:816` | `promote_staged_edges` | `<bound>` (copied by `INSERT … SELECT`) | no — verify-only `AppState` |
| `crates/epigraph-api/src/routes/crud.rs:846` | `promote_staged_edges` | `<bound>` (copied by `INSERT … SELECT`) | no — verify-only `AppState` |
| `crates/epigraph-api/src/routes/edges.rs:3995` | `phase2_unregistered_type_rejected_then_registered_succeeds` | `relates_to` | test fixture (`mod db_tests`) |
| `crates/epigraph-api/src/routes/edges.rs:4037` | `phase2_unregistered_type_rejected_then_registered_succeeds` | `relates_to` | test fixture (`mod db_tests`) |
| `crates/epigraph-api/src/routes/experiment_loop.rs:79` | `create_experiment` | `tests_hypothesis` | no |
| `crates/epigraph-api/src/routes/experiment_loop.rs:139` | `submit_results` | `result_of` | no |
| `crates/epigraph-api/src/routes/experiment_loop.rs:362` | `analyze_result` | `analyzes` | no |
| `crates/epigraph-api/src/routes/experiment_loop.rs:378` | `analyze_result` | `provides_evidence` | no |
| `crates/epigraph-api/src/routes/reasoning.rs:918` | `insert_edge` | `<bound>` | test fixture (`mod db_tests`) |
| `crates/epigraph-api/src/routes/submit.rs:1204` | `persist_packet` | `AUTHORED` | **partially — see below** |
| `crates/epigraph-api/src/routes/submit.rs:1220` | `persist_packet` | `HAS_TRACE` | **partially — see below** |
| `crates/epigraph-api/src/routes/submit.rs:1236` | `persist_packet` | `TRACES` | **partially — see below** |
| `crates/epigraph-api/src/routes/submit.rs:1328` | `persist_packet` | `SUPPORTS` | **partially — see below** |
| `crates/epigraph-api/src/routes/submit.rs:1345` | `persist_packet` | `USES_EVIDENCE` | **partially — see below** |

### `epigraph-cli` — binaries and rerank

| Call site | Enclosing fn | Relationship | Signing key in scope? |
|---|---|---|---|
| `crates/epigraph-cli/src/bin/dekg.rs:1133` | `handle_migrate` | `PERSPECTIVE_OF` | no — no key material |
| `crates/epigraph-cli/src/bin/dekg.rs:1157` | `handle_migrate` | `MEMBER_OF` | no — no key material |
| `crates/epigraph-cli/src/bin/dekg.rs:1182` | `handle_migrate` | `CONTRIBUTES_TO` | no — no key material |
| `crates/epigraph-cli/src/bin/experiment.rs:135` | `run` | `tests_hypothesis` | no — no key material |
| `crates/epigraph-cli/src/bin/experiment.rs:295` | `submit_results` | `result_of` | no — no key material |
| `crates/epigraph-cli/src/bin/experiment.rs:454` | `analyze` | `analyzes` | no — no key material |
| `crates/epigraph-cli/src/bin/experiment.rs:459` | `analyze` | `provides_evidence` | no — no key material |
| `crates/epigraph-cli/src/bin/method_search.rs:242` | `run` | `SUPPORTS` | no — no key material |
| `crates/epigraph-cli/src/rerank/core.rs:695` | `create_edge` | `<bound>` | no — no key material |

### `epigraph-db` — repository layer

| Call site | Enclosing fn | Relationship | Signing key in scope? |
|---|---|---|---|
| `crates/epigraph-db/src/repos/analysis.rs:170` | `link_evidence` | `interpreted_by` | no — repo layer takes no key |
| `crates/epigraph-db/src/repos/analysis.rs:190` | `link_claim` | `concludes` | no — repo layer takes no key |
| `crates/epigraph-db/src/repos/analysis.rs:232` | `persist_bundle` | `concludes` | no — repo layer takes no key |
| `crates/epigraph-db/src/repos/analysis.rs:246` | `persist_bundle` | `interpreted_by` | no — repo layer takes no key |
| `crates/epigraph-db/src/repos/claim.rs:2303` | `supersede` | `supersedes` | no — repo layer takes no key |
| `crates/epigraph-db/src/repos/claim.rs:2658` | `inherit_evidence` | `derived_from` | no — repo layer takes no key |
| `crates/epigraph-db/src/repos/claim.rs:2997` | `evolve_step` | `<bound>` | no — repo layer takes no key |
| `crates/epigraph-db/src/repos/claim.rs:4890` | `consolidate` | `supersedes` | no — repo layer takes no key |
| `crates/epigraph-db/src/repos/edge.rs:77` | `EdgeRepository::create` | `<bound>` | no — the choke point itself |
| `crates/epigraph-db/src/repos/edge.rs:164` | `EdgeRepository::create_if_not_exists` | `<bound>` | no — the choke point itself |
| `crates/epigraph-db/src/repos/edge.rs:227` | `EdgeRepository::create_symmetric_if_absent` | `<bound>` | no — the choke point itself |
| `crates/epigraph-db/src/repos/edge.rs:281` | `EdgeRepository::create_symmetric_if_absent_returning` | `<bound>` | no — the choke point itself |
| `crates/epigraph-db/src/repos/lineage.rs:1015` | `test_lca_shared_parent` | `supports` | test fixture (`mod tests`) |
| `crates/epigraph-db/src/repos/lineage.rs:1022` | `test_lca_shared_parent` | `supports` | test fixture (`mod tests`) |
| `crates/epigraph-db/src/repos/lineage.rs:1105` | `test_lca_diamond` | `supports` | test fixture (`mod tests`) |
| `crates/epigraph-db/src/repos/lineage.rs:1149` | `test_lca_self_ancestor` | `supports` | test fixture (`mod tests`) |
| `crates/epigraph-db/src/repos/semantic_link.rs:137` | `SemanticLinkRepository::create` | `<bound>` | no — repo layer takes no key |
| `crates/epigraph-db/src/repos/workflow.rs:978` | `immediate_variant_parent_returns_one_hop` | `variant_of` | test fixture (`mod tests`) |

### Writers outside `crates/*/src/`

| Writer | Kind | Signing key in scope? |
|---|---|---|
| `scripts/fuzzy_dedup_claims.py` | Python maintenance script | no — no key material |
| `crates/epigraph-jobs/tests/fixtures/seed_two_cliques.sql` | SQL test fixture | n/a |

Integration tests under `crates/*/tests/` insert edges freely; they are
fixtures, are excluded from every count in this document, and are not tracked
here.

<!-- edge-writer-files:begin -->
The files containing at least one direct `INSERT INTO edges` under
`crates/*/src/` — the set the guard test pins:

- `crates/epigraph-api/src/routes/crud.rs`
- `crates/epigraph-api/src/routes/edges.rs`
- `crates/epigraph-api/src/routes/experiment_loop.rs`
- `crates/epigraph-api/src/routes/reasoning.rs`
- `crates/epigraph-api/src/routes/submit.rs`
- `crates/epigraph-cli/src/bin/dekg.rs`
- `crates/epigraph-cli/src/bin/experiment.rs`
- `crates/epigraph-cli/src/bin/method_search.rs`
- `crates/epigraph-cli/src/rerank/core.rs`
- `crates/epigraph-db/src/repos/analysis.rs`
- `crates/epigraph-db/src/repos/claim.rs`
- `crates/epigraph-db/src/repos/edge.rs`
- `crates/epigraph-db/src/repos/lineage.rs`
- `crates/epigraph-db/src/repos/semantic_link.rs`
- `crates/epigraph-db/src/repos/workflow.rs`
<!-- edge-writer-files:end -->

<!-- signing-writer-count: 0 -->

---

## `EdgeRepository` callers

The overwhelming majority of edge writes do not appear above, because they go
through the repository. Four entry points, all in
`crates/epigraph-db/src/repos/edge.rs`:

| Entry point | Line | Occurrences under `crates/*/src/` |
|---|---|---|
| `EdgeRepository::create` | `crates/epigraph-db/src/repos/edge.rs:62` | 46 |
| `EdgeRepository::create_if_not_exists` | `crates/epigraph-db/src/repos/edge.rs:116` | 31 |
| `EdgeRepository::create_symmetric_if_absent` | `crates/epigraph-db/src/repos/edge.rs:219` | 8 |
| `EdgeRepository::create_symmetric_if_absent_returning` | `crates/epigraph-db/src/repos/edge.rs:273` | 3 |

88 occurrences on 87 lines, of which 8 lines are doc comments — **79
non-comment call lines across 25 files**. A further 16 occurrences live under
`crates/*/tests/` and are excluded.

None of the four signatures accepts a key, a signature, or a signer id. Widening
one widens all its callers, which is the main reason edge signing is a project
rather than a patch.

Caller files by crate (regenerate rather than trust this list — see
[Reproducing this inventory](#reproducing-this-inventory)):

| Crate | Caller files |
|---|---|
| `epigraph-api` | 11 — `assess.rs`, `belief.rs`, `claims.rs`, `community.rs`, `conventions.rs`, `cross_source.rs`, `crud.rs`, `edges.rs`, `perspective.rs`, `provenance.rs`, `spans.rs` (all under `crates/epigraph-api/src/routes/`) |
| `epigraph-cli` | 1 — `crates/epigraph-cli/src/decompose.rs` |
| `epigraph-engine` | 2 — `crates/epigraph-engine/src/matching/policy.rs`, `crates/epigraph-engine/src/matching/verifier.rs` |
| `epigraph-ingest-executor` | 2 — `crates/epigraph-ingest-executor/src/workflow.rs`, `crates/epigraph-ingest-executor/src/workflow_steps.rs` |
| `epigraph-mcp` | 9 — `crates/epigraph-mcp/src/claim_helper.rs`, `crates/epigraph-mcp/src/server.rs`, and `claims.rs`, `ingestion.rs`, `link_alternative.rs`, `link_epistemic.rs`, `link_hierarchical.rs`, `matching.rs`, `perspectives.rs` under `crates/epigraph-mcp/src/tools/` |

---

## Is a signing key in scope?

Three distinct regimes. This is the load-bearing section: it says where a
future signer could get key material without new plumbing, and where it could
not.

### 1. `epigraph-mcp` — a key is in scope for every edge write

`ServerState` holds `pub(crate) signer: Arc<AgentSigner>`
(`crates/epigraph-mcp/src/server.rs:26`). Every MCP tool has `&self` access to
it; ten call sites already invoke `server.signer.sign(...)` for claims and
evidence. Any MCP edge write could be signed without threading new state.

The single highest-leverage location is
`crates/epigraph-mcp/src/claim_helper.rs:39`, inside
`create_claim_idempotent`: one `EdgeRepository::create` call emitting the
`AUTHORED` agent→claim edge on behalf of many MCP writers. It is the natural
first signable edge — the agent id is right there in `claim.agent_id`, and the
signer is one field away on `ServerState`.

### 2. `epigraph-api` — verify-only, except the packet path

`AppState` carries `pub signature_state: SignatureVerificationState`
(`crates/epigraph-api/src/state.rs:149`). That type is a nonce store plus an
agent public-key registry: it *verifies* inbound signatures. **The API server
holds no private key.** An API route cannot sign anything on its own behalf
without new key plumbing and a policy decision about what identity it would be
signing as.

The exception is the packet path. `crates/epigraph-api/src/routes/submit.rs:794`
verifies a client-supplied packet signature against the submitting agent's
stored public key. By the time control reaches `persist_packet`, both a
**verified signature** and the **signer's `agent_uuid`** are in scope — and five
edges are inserted unsigned at `submit.rs:1204`, `:1220`, `:1236`, `:1328` and
`:1345`.

**This is not a free win.** The packet signature covers the canonical bytes of
the `(claim, evidence, reasoning_trace)` tuple — see
`EpistemicPacket::signable_bytes`, cited in the comment at `submit.rs:779-781`.
It does **not** cover any edge. Copying that signature onto five edge rows
would produce rows that satisfy `edges_signature_length` and
`edges_signature_requires_signer` while failing any honest verification, which
is strictly worse than leaving them NULL. What the packet path really offers is
a *verified agent identity* at edge-insert time, not a reusable signature.

Separately, `SignedRequest<T>` (`crates/epigraph-api/src/extractors/signed.rs:45`)
is a complete Axum extractor that no route uses — `crates/epigraph-api/src/extractors/mod.rs`
re-exports it, and nothing else references it outside its own unit tests.

### 3. `epigraph-cli`, `epigraph-engine`, `epigraph-db` — no key material at all

No `AgentSigner`, no keypair loading, no signer field. Every writer in these
layers — `dekg.rs`, `experiment.rs`, `method_search.rs`, `rerank/core.rs`, and
all of `crates/epigraph-db/src/repos/` — would need key material introduced
from outside before it could sign anything. For the repo layer specifically
that means a parameter change on `EdgeRepository::create`, since repositories
take a connection and data, never credentials.

---

## The wider signing pipeline is severed

Edges are not an isolated gap. The same break exists one table over, and it is
worth stating plainly so that anyone scoping edge signing does not assume the
claim path already works.

**MCP computes claim and evidence signatures and the repository throws them
away.** Ten sites assign `signature = Some(server.signer.sign(...))`:

- `crates/epigraph-mcp/src/tools/claims.rs:266` (claim), `:423`, `:850` (evidence)
- `crates/epigraph-mcp/src/tools/memory.rs:43` (claim), `:155` (evidence)
- `crates/epigraph-mcp/src/tools/ingestion.rs:530`, `:1212` (claim), `:595`, `:1274` (evidence)
- `crates/epigraph-mcp/src/tools/workflows.rs:1321` (evidence)

The claim-side values flow into `create_claim_idempotent` →
`ClaimRepository::create_or_get` → the `INSERT INTO claims` in
`crates/epigraph-db/src/repos/claim.rs`. **None of the 53 `INSERT INTO claims`
statements under `crates/*/src/` names `signature` or `signer_id`.** The
signature is computed, carried through three layers, and dropped at the SQL
boundary. (The evidence-side values do land — see below.)

**`claim_from_row` hardcodes the absence.**
`crates/epigraph-db/src/repos/claim.rs:169` reads `let signature = None;` under
the comment "No signature from legacy DB records", preceded at `:165-166` by a
zeroed placeholder public key described as "will be populated when DB schema
includes it". The schema does include it. The comments are stale, and the read
path would need changing even if a writer started populating the column.

**Only four statements in `crates/*/src/` populate signing columns, and none
targets `claims` or `edges`:**

| Statement | Target table |
|---|---|
| `crates/epigraph-api/src/routes/submit.rs:1303` | `evidence` |
| `crates/epigraph-db/src/repos/evidence.rs:68` | `evidence` |
| `crates/epigraph-db/src/repos/evidence.rs:396` | `evidence` |
| `crates/epigraph-api/src/routes/revoke_signature.rs:297` | `claim_signature_revocations` |

So `evidence` is the *only* signed table in the system today.

**A revocation endpoint exists for a column nothing writes.**
`crates/epigraph-api/src/routes/revoke_signature.rs` is a full revocation route
over `claims.signature`, recording the previous signature, signer and content
hash into `claim_signature_revocations`. Since no writer ever populates
`claims.signature`, it can only ever revoke NULL.

These are findings, not work items for this document. Fixing any of them is a
separate decision requiring a database and a migration-adjacent review.

---

## What signing edges would actually require

Non-prescriptive. These are the constraints any design has to satisfy, in
rough dependency order.

1. **A canonical byte encoding for an edge — this is the real design work.**
   `crates/epigraph-crypto/src/canonical.rs:30` provides
   `impl<T: Serialize> Canonical for T`, a blanket implementation, so any new
   `SignableEdge` struct gets `canonical_bytes()` for free. The open question
   is therefore *not* which trait to implement, it is **which fields are in the
   signed set**: `id` is server-generated, `created_at` is `now()`,
   `properties` is open-ended JSONB, and `valid_from` / `valid_to` are
   nullable. Whatever is excluded is unauthenticated and mutable after the
   fact.

2. **Do not reuse the packet signature.** As above, `EpistemicPacket`'s
   signature covers `(claim, evidence, reasoning_trace)`, not edges. Any design
   that satisfies the CHECK constraints by copying an unrelated signature onto
   edge rows produces data that is worse than NULL, because it *looks*
   authenticated.

3. **A key parameter on the repository entry points.** All four
   `EdgeRepository::create*` functions would need widening, or signed siblings
   added, with ~79 non-comment call sites in 25 files to update or default.
   The 33 direct `INSERT INTO edges` statements bypass the repository entirely
   and would need handling individually.

4. **A read path.** `EdgeRow` has no `signature` field and no `SELECT` in
   `edge.rs` reads one. Verification is impossible until reads carry the
   columns.

5. **A per-layer key story.** MCP has a signer. The API server does not, and
   the CLI/engine/db layers do not. A design that signs "all edges" implies key
   material reaching layers that today deliberately have none.

6. **Round-trip tests against a real database.** The CHECK constraints
   (`= 64` bytes, both-or-neither) have never fired. First writer to populate
   the columns is also the first to exercise them.

---

## Doc-citation discrepancy

`docs/architecture/noun-claims-and-verb-edges.md` cites migrations `042`,
`073`, `106`, `107` and `109`. This repository's `migrations/` directory
contains `001`–`059`: `042` exists; `073`, `106`, `107` and `109` do not.

The `edges` signing columns are demonstrably in `001_initial_schema.sql` (see
[Schema ground truth](#schema-ground-truth)), so the "migration 073" attribution
is wrong and has been corrected in that document's "Edge signing" section. The
remaining numbers are **flagged, not rewritten** — they may refer to a
downstream or renumbered series owned by the S2–S4 sequence, and adjudicating
them belongs to that owner, not to this inventory.

---

## Guard test

`crates/epigraph-tools/tests/edge_writer_inventory_guard.rs` keeps this
document honest. It requires no database. Three checks:

- **`inventory_lists_every_direct_edge_insert_file`** — the set of files under
  `crates/*/src/` containing `INSERT INTO edges` must equal the sentinel list
  above. Keyed on *files*, never line numbers, so ordinary edits do not break
  it; a new or renamed edge-writing file does.
- **`inventory_cited_paths_all_exist`** — every backticked `crates/…` /
  `scripts/…` path in this document must resolve to a real file.
- **`signing_writer_count_matches_documented`** — the number of direct edge
  inserts naming `signature` must equal the `signing-writer-count` sentinel.

The third is a **drift detector, not a prohibition**. It is not asserting that
edge signing must stay absent. When the first signing writer lands, that test
fails and forces this inventory to be updated — which is the intended behaviour
for a living document, and is a one-line sentinel edit, not a blocker.

`epigraph-tools` hosts the test deliberately: it has no `sqlx` dependency at
all (so no `cargo sqlx prepare` can ever be implicated), it already depends on
`walkdir` and `regex`, it already has repo-walking tests using the same
`CARGO_MANIFEST_DIR`-relative root, and no crate in the workspace depends on
it.

---

## Reproducing this inventory

Run from the repository root. Every number above comes from one of these.

```bash
# 41 direct INSERT INTO edges statements, across 15 files
grep -rn 'INSERT INTO edges' crates/*/src/ | wc -l
grep -rl 'INSERT INTO edges' crates/*/src/ | wc -l
grep -rn 'INSERT INTO edges' crates/*/src/            # the full site list

# 0 of them name the signing columns
grep -rn 'INSERT INTO edges' crates/*/src/ -A 3 | grep -c 'signer_id'

# EdgeRepository: 88 occurrences by variant; 79 non-comment lines; 25 files
grep -rno 'EdgeRepository::create[a-z_]*' crates/*/src/ \
  | sed 's/.*EdgeRepository:://' | sort | uniq -c | sort -rn
grep -rn 'EdgeRepository::create' crates/*/src/ | grep -vE ':[0-9]+: *///?' | wc -l
grep -rl 'EdgeRepository::create' crates/*/src/

# claims: 53 inserts, 0 naming the signing columns
grep -rn 'INSERT INTO claims' crates/*/src/ | wc -l
grep -rn 'INSERT INTO claims' crates/*/src/ -A 5 | grep -c 'signer_id'

# MCP computes signatures it cannot persist for claims
grep -rn 'signer.sign(' crates/epigraph-mcp/src/

# writers outside crates/*/src/
grep -rn 'INSERT INTO edges' scripts/ crates/*/tests/

# schema ground truth
grep -n 'signature\|signer_id\|content_hash' migrations/001_initial_schema.sql | head
ls migrations/*.sql | wc -l     # 58 files, 001-059
```

Counts were taken on 2026-08-26 against branch `fix/backlog-sweep-2026-08-26`.
The guard test pins the two that matter (the file set and the signing-writer
count); the rest are point-in-time and are expected to drift.
