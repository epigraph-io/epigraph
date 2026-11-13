# Evidence→claim edges on every evidence write, plus a backfill (backlog 2d60f619)

Operator ruling on the Atlas leaf view: "backfill edges and make sure the evidence filing
function requires at least one claim that evidence applies to." The leaf view draws only
stored `evidence -> claim` edges; there is no derived edge.

## Data model

No new table. The edge is an ordinary `edges` row:

| column | value |
|---|---|
| `source_type`, `source_id` | `'evidence'`, `evidence.id` |
| `target_type`, `target_id` | `'claim'`, the claim the evidence applies to |
| `relationship` | `supports` or `refutes` (canonical lower-case spelling) |
| tenancy | stamped by the edges tenancy trigger from the two endpoints (the meet), as for every edge; between two PUBLIC endpoints migration 120 (D8) owns it by the writing session's group |
| signature | attested at INSERT by the writer's `EdgeSigningKey` when it holds one |

`evidence.claim_id` is `NOT NULL` with a foreign key, and no write path attaches one
evidence row to several claims, so each evidence row gets exactly one edge. The helper still
takes a slice of claim ids and refuses an empty one, so the rule is stated where the edge is
written.

### Canonical spelling

`epigraph_core::edge::relationships::canonical_relationship` folds `SUPPORTS` / `REFUTES` to
lower case, and every `EdgeRepository` insert calls it, so a new row is stored lower case
whatever the caller passes (`edge_relationship_canonical_write.rs` pins this). The dedup probes
match both spellings (`relationship_spellings`). So the canonical spelling is `supports` /
`refutes`. Existing upper-case rows are left alone; `docs/runbooks/edge-relationship-casefold.sql`
is the existing operator fold.

### Polarity

The `evidence` row itself records no direction (`EvidenceType` has no polarity field). The
direction lives in two places:

* at write time, in the tool's own input: `update_with_evidence.supports`,
  `report_workflow_outcome.success`, and the convention deprecation (always against);
* afterwards, in the evidence's BBA (`mass_functions.evidence_id`): on a two-hypothesis frame
  index 0 is the claim's own hypothesis, so a BBA with more mass on `{1}` (or on `~0`) than on
  `{0}` (or `~1`) argues against the claim.

Writers pass the direction they hold. The backfill derives it from the evidence's
non-retracted BBAs on its claim, on any frame where the claim's hypothesis index is known
(`claim_frames.hypothesis_index`, or 0 on an unassigned two-hypothesis frame), and defaults to
`supports` when there is none or on a tie. Its report counts which rule decided each row. The
binary-frame convention is proven end to end: evidence filed through
`update_with_evidence(supports = false)` is backfilled `refutes`.

## Files

* `crates/epigraph-db/src/repos/evidence.rs`
  * `EvidenceDirection { Supports, Refutes }` and `EvidenceEdge { key, direction }`.
  * `EvidenceRepository::link_to_claims_signed_conn`: THE helper. It refuses an empty claim list. For
    each claim it calls `EdgeRepository::create_if_absent_including_retracted_signed_conn`,
    which finds an existing row in either spelling (retracted included, so a retracted edge is
    never resurrected) and attests a new one with the key.
  * `create`, `create_with_source_url`, `batch_create` and `record_derivation_conn` take the
    `EvidenceEdge` (the derivation, the key) and call the helper inside their transaction,
    after the same-tenancy de-duplication and before the commit. A refused duplicate writes
    neither the row nor the edge.
* Callers: the MCP tools (`write_submission`, `update_with_evidence`, `memorize`,
  `report_workflow_outcome`, both document ingests), the HTTP routes (`POST /evidence`, the
  two convention routes, derivation provenance on `POST /claims`) and `persist_packet`.
  `persist_packet` keeps its raw evidence INSERT and swaps its own edge write for the helper.
  The convention routes drop their separate best-effort edge writes, which are now made by the
  helper in the evidence's own transaction. `forget_convention` now writes the evidence row on
  the caller-stamped transaction its edge already used, so the row is the caller's (migration
  114's attach rule) instead of the claim owner's, and a refusal now fails the request instead
  of leaving an edge-less row.
* `migrations/211_bug_report_evidence_edge.sql`: `epigraph_submit_bug_report` (migration 207)
  is the one SQL-side evidence writer. It is redefined with one more statement, the evidence→
  claim `supports` edge, in the same definer frame, inside 206's transaction-local
  `search_path` window (the `edges` triggers name their helpers unqualified, and the pinned
  path fails them with 42883). It is unsigned, like every database-side writer.
* `crates/epigraph-db/tests/edge_writer_signing_ratchet.rs`: list the helper in `CALLS`,
  register it (Signed), restore `persist_packet` to 5 sites, drop `forget_convention` and lower
  `learn_convention`, and register the 211 function and the backfill (unsigned high water
  49 -> 51).
* The route-write registers `discarded_route_writes.rs`, `unstamped_http_edge_writes.rs` and
  `viewer_spend_lint.rs` are lowered or re-reviewed for the convention routes and the packet.
* `crates/epigraph-db/tests/evidence_insert_writes_claim_edge.rs`: a static lint. Every
  non-test Rust function that runs `INSERT INTO evidence` must call
  `link_to_claims_signed_conn`, and every live SQL function that inserts into `evidence` must
  also insert into `edges`.
* `crates/epigraph-cli/src/operator/evidence_edges.rs` plus two `epigraph-operator` verbs,
  `backfill-evidence-edges` and `reverse-evidence-edges` (the audited-repair convention of
  `regroup-claims`, `reown-workflows` and `backfill-ingest-markers`).

The helper is a signed twin listed in the signing ratchet's `CALLS`, so each caller outside
the repository is a ratchet site with its own key check (`persist_packet` Signed, the backfill
`Unsigned(NO_KEY_CLI)`).

## Write-path inventory

| Path | Before | After |
|---|---|---|
| `EvidenceRepository::create` / `create_with_source_url` | no edge | edge via helper, caller's direction and key |
| `EvidenceRepository::batch_create` (no non-test caller) | no edge | edge per row via helper |
| `EvidenceRepository::record_derivation_conn` (`POST /claims` `derived_from`) | no edge | `supports` via helper |
| MCP `submit_claim`, `batch_submit_claims` (delegates) | no edge | `supports`, server key |
| MCP `update_with_evidence` | no edge | `supports` / `refutes` from `supports`, server key |
| MCP `memorize` | no edge | `supports`, server key |
| MCP `report_workflow_outcome` | no edge | `supports` / `refutes` from `success`, server key |
| MCP `ingest_document`, `ingest_document_spine` | no edge | `supports`, walk key |
| HTTP `POST /evidence` | no edge | `supports`, API key |
| HTTP `POST /submit/packet` (`persist_packet`) | `supports` (own write) | `supports` via helper, API key |
| HTTP `POST /conventions` | `SUPPORTS`, best-effort `let _` | `supports` in the evidence's transaction |
| HTTP `DELETE /conventions/:id` | `REFUTES`, best-effort on a stamped tx | evidence and `refutes` edge in ONE caller-stamped tx |
| SQL `epigraph_submit_bug_report` (207) | no edge | `supports` (migration 211), unsigned |

No evidence row is written by `submit_ds_evidence` (BBAs only), `add_step`, `ingest_workflow`,
`store_workflow`, `POST /frames/:id/evidence` (BBAs only) or the workflow ingest routes. No
episcience crate is in this repo.

## Backfill

Runs on the operator's maintenance DSN only (`EPIGRAPH_OPERATOR_MAINTENANCE_DSN`).

* **Missing** means: no `edges` row of ANY relationship and ANY state with
  `source_id = evidence.id` and `target_id = evidence.claim_id`. A row whose only edge is
  retracted is reported on its own and never re-written.
* **Dry run (default)**: read-only (`REPEATABLE READ, READ ONLY`). Prints existing edges by
  relationship as stored, the retracted-only count, the SEALED rows it will skip (a claim with
  a `claim_encryption` row, an evidence row with an `evidence_encryption` row), and `to_write`
  by relationship, by direction rule and by tenancy (evidence and claim visibility/owner kind).
* **Direction**: from the evidence's non-retracted BBAs on its claim (mass on the claim's
  hypothesis against mass on sets without it); none or a tie is `supports`.
* **`--apply --confirm-count N --manifest-out <new file> --reason <text>`**: batches of
  `--batch-size` (default 1000) in evidence-id order, each in its own transaction. Every edge
  goes through `link_to_claims_signed_conn` (no key on the maintenance DSN). Each batch's
  edge lines are `fsync`ed before its commit, followed by a `committed_batch` line. One
  `security_events` row per applied run. `--max-batches` stops early, and a re-run continues.
* **`reverse-evidence-edges --manifest <file>`**: dry run unless `--apply`. Deletes exactly
  the edges the manifest names, only while each still has the recorded source, target and
  relationship. A re-run deletes nothing.

## Tests (fresh DB, `remote-cargo --db`)

| Test | Proves |
|---|---|
| `epigraph-db/tests/evidence_claim_edge.rs` (9) | each repository writer writes one edge, direction, batch, derivation, idempotent across spellings and retraction, empty claim list refused, refused duplicate writes none, signed, app-role RLS |
| `epigraph-db/tests/evidence_insert_writes_claim_edge.rs` (3) | a new evidence writer that skips the helper fails |
| `epigraph-db/tests/bug_report_intake.rs::the_reports_evidence_carries_a_private_supports_edge` | the SQL writer, its tenancy, row security |
| `epigraph-mcp/tests/evidence_claim_edge_mcp.rs` (6) | every MCP evidence tool, direction, tenancy, server attestation; unknown claim refused |
| `epigraph-api/tests/evidence_claim_edge_http.rs` (2) | `POST /evidence` (and unknown claim refused), both convention routes |
| `epigraph-cli/tests/operator_evidence_edges.rs` (4) | dry-run counts, apply then zero missing, reverse restores the edges table exactly, second apply writes nothing, sealed rows skipped and reported, wrong confirm count refused, BBA polarity (`update_with_evidence(supports=false)`) backfilled `refutes` |

### "Done when", and how each is proven

* *A test per write path proves it refuses evidence with no claim and writes the edge.* The
  per-path tests above. The "no claim" half is enforced by `evidence.claim_id NOT NULL` + FK on
  every path (already true on old code, so those assertions are pins), and by the helper's
  empty-slice refusal (new).
* *The backfill dry run lists counts by relationship and tenancy.* The CLI dry-run test.
* *Apply then reverse round-trips.* The CLI apply/reverse test (full edges-table snapshot).
* *After apply, zero evidence rows lack the edge.* The CLI apply test (sealed rows excepted
  and reported).

## Deploy order

Code first (every new evidence row carries its edge), then the backfill: dry run, read the
counts, `--apply`. Running it the other way round leaves a window in which new edge-less
rows appear after the backfill.
