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
| tenancy | derived by `epigraph_edges_tenancy` from the two endpoints (the meet), as for every edge |
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

Writers pass the direction they hold. The backfill derives it from the non-retracted BBAs on
two-hypothesis frames, and defaults to `supports` when there is none. Its report counts which
rule decided each row.

## Files

* `crates/epigraph-db/src/repos/evidence.rs`
  * `EvidenceDirection { Supports, Refutes }` and `EvidenceEdge { key, direction }`.
  * `EvidenceRepository::link_to_claims_conn`: THE helper. It refuses an empty claim list. For
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
  helper in the evidence's own transaction.
* `migrations/211_bug_report_evidence_edge.sql`: `epigraph_submit_bug_report` (migration 207)
  is the one SQL-side evidence writer. It is redefined with one more statement, the evidence→
  claim `supports` edge, in the same definer frame. It is unsigned, like every database-side
  writer.
* `crates/epigraph-db/tests/edge_writer_signing_ratchet.rs`: register the helper (Signed),
  update the counts of the callers whose own edge writes moved into it, and add the 211
  function.
* `crates/epigraph-db/tests/evidence_insert_writes_claim_edge.rs`: a static lint. Every
  non-test Rust function that runs `INSERT INTO evidence` must call `link_to_claims_conn`, and
  every live SQL function that inserts into `evidence` must also insert into `edges`.
* `crates/epigraph-cli/src/evidence_claim_edges.rs` plus the bin
  `backfill_evidence_claim_edges`.

## Backfill

Runs on `MAINTENANCE_DATABASE_URL` only (configured, privileged session), as the other repair
tools do.

* **Missing** means: no `edges` row of ANY relationship and ANY state with
  `source_id = evidence.id` and `target_id = evidence.claim_id`. A row whose only edge is
  retracted is reported on its own and never re-written.
* **Dry run (default)**: read-only. Prints the missing count by relationship to be written
  and by the edge tenancy it will get (visibility, owner group kind), how polarity was
  decided, derivation-provenance rows, and the SEALED rows it will skip (a claim with a
  `claim_encryption` row or evidence with an `evidence_encryption` row).
* **`--apply --manifest-out <new file>`**: batches of `--batch-size` (default 1000) in
  evidence-id order, each in its own transaction. Every edge goes through
  `link_to_claims_conn`. Each batch's created edge ids are written to the manifest and
  `fsync`ed before the batch commits, followed by a `committed_batch` line after it.
  `--max-batches` stops early, and a re-run continues where it stopped (the selection is
  "missing").
* **`--reverse --manifest <file>`**: dry run unless `--apply`. It deletes exactly the edges
  the manifest names, and only while each still has the recorded source, target and
  relationship. A re-run deletes nothing.

## Tests (fresh DB, `remote-cargo --db`)

| Test | Proves | Fails on old code because |
|---|---|---|
| `evidence_claim_edge.rs::create_writes_one_supports_edge_with_the_evidence_tenancy` | repo `create` writes the edge with the meet tenancy | no edge is written |
| `…::refutes_direction_is_stored_as_refutes` | direction | no edge |
| `…::batch_create_writes_an_edge_per_row` | batch path | no edge |
| `…::derivation_provenance_writes_a_supports_edge` | derivation path | no edge |
| `…::a_legacy_upper_case_edge_is_not_duplicated` | idempotent across spellings | helper absent (does not compile) |
| `…::no_claim_is_refused_and_writes_nothing` | empty claim list refused | helper absent (does not compile) |
| `…::a_refused_duplicate_writes_no_edge` | edge only with a row | n/a, a pin |
| `…::a_signed_writer_attests_the_edge` | the edge verifies | no edge |
| `…::app_role_group_evidence_edge_lands` | the app role's RLS admits the edge where it admits the evidence | no edge |
| `evidence_insert_writes_claim_edge.rs` | the rule cannot be skipped by a new writer | old writers do not call the helper |
| MCP: `submit_claim`, `update_with_evidence(supports=false)`, `memorize`, `report_workflow_outcome(success=false)`, `ingest_document` | each tool's evidence carries its edge, right direction | no edge (submit, memorize, workflow, ingest, update) |
| HTTP: `POST /evidence`, packet submit | route paths | POST /evidence: no edge; the packet already wrote it (a pin) |
| bug-report intake | the SQL writer | no edge |
| CLI `backfill_evidence_claim_edges`: dry-run counts, apply then zero missing, reverse restores exactly, second apply writes nothing, sealed rows skipped and reported, BBA polarity → `refutes` | the backfill | the tool does not exist |

### "Done when", and how each is proven

* *A test per write path proves it refuses evidence with no claim and writes the edge.* The
  per-path tests above. The "no claim" half is enforced by `evidence.claim_id NOT NULL` + FK
  on every path (already true on old code), and by the helper's empty-slice refusal (new).
* *The backfill dry run lists counts by relationship and tenancy.* The CLI dry-run test.
* *Apply then reverse round-trips.* The CLI apply/reverse test.
* *After apply, zero evidence rows lack the edge.* The CLI apply test (asserts zero missing,
  sealed rows excepted and reported).

## Deploy order

Code first (every new evidence row carries its edge), then the backfill: dry run, read the
counts, `--apply`. Running it the other way round leaves a window in which new edge-less
rows appear after the backfill.
