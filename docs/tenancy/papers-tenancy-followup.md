# Follow-up: tenancy for an ingested paper's own record

Status: option 2 (section 3) chosen by the 2026-11-16 design decision (backlog 34864fb5), and
implemented for the `papers` row by migration 246 (section 6). Still open: the author agents'
own tenancy, widening and merging a paper on publicize/share, the narrowing guard and the `doi:`
label on converged public claims (section 7). Until those land, an ingest's author NAMES stay
readable by every agent whatever `visibility` you pass, and so does an author's `asserts`
attribution edge onto an already-public claim the ingest converges onto, so do not ingest a
document whose author list is itself confidential.

The sections below are the original design note (operator ruling, 2026-11-11: document the gap
in the claim visibility work and close it in a follow-up), kept as written.

## 1. The gap

A `team` or `private` ingest scopes the claims it creates, with their evidence, traces and
`asserts` edges ([claim-visibility-controls.md](claim-visibility-controls.md) section 3.1). It
does not scope the rest of what it writes. Every session can read these rows whatever the ingest's
visibility:

| Row | Written by | Why it is world-readable |
|---|---|---|
| `papers` (id, `doi` or synthesized `urn:epigraph:doc:*` key, `title`, `journal`) | `ensure_paper_node` → `PaperRepository::get_or_create`, on the pool, before the walk, with no `VisibilityChoice` | `papers` has no row-level security in any migration (127: "papers and workflows carry no tenancy") |
| author agents (`agents`, one per paper author, `did_key_for_author`) | the walk's step 3 | `agents` is readable by every session (its policy is `true`) |
| `authored` edges, author agent → paper | the walk's step 3 | a paper or agent endpoint contributes `public` to the meet; 120's `epigraph_edges_tenancy` keeps such structural edges `('public', world)` |
| `processed_by` edge, paper → ingesting agent, `properties.pipeline` | `EdgeRepository::create_processed_by_stamp_if_absent_signed_conn` | same as `authored` |
| `asserts` edge, paper → an already-PUBLIC claim the walk converged onto | the walk, for every atom whose content already exists | both endpoints public, so the meet is public |
| the `doi:<doi>` label on such a converged public claim, when the agent may write it | `label_resolved_claim` | the claim is public |

So anyone can learn that a document exists, its title, DOI and journal, who wrote it, which agent
ingested it and with which pipeline, when, and which already-public statements it asserts.

## 2. Reads that disclose it

* MCP `check_already_ingested`: `find_paper_by_document_key` and
  `PaperRepository::processed_by_pipelines_in_family`. An outsider gets `already_ingested: true`
  and the `paper_id` for a document only a team may read.
* MCP `query_paper` (`tools/paper_queries.rs`): the paper row, `list_authors`, and the claim
  counts (`count_asserted_claims`, `count_claims_by_doi_label`, which already go through the
  viewer for claims).
* REST `GET /api/v1/papers` (`routes/papers.rs::list_papers`) and `POST /api/v1/papers`.
* Joins onto `papers` in `claim_context.rs`, `ego.rs`, `method.rs`, `claim.rs`, MCP `recall.rs`,
  and the engine's `edge_factor.rs` and `matching/source_key.rs`. These return paper metadata
  next to claims the viewer can read, and some may surface a paper with none.
* Any graph read that walks `authored` or `processed_by` edges (`get_neighborhood`, `traverse`).

## 3. The design question to settle first: one DOI, two tenants

`papers` is keyed on the canonical document key, and `get_or_create` converges every ingest of a
DOI onto one row, which is how two sources corroborate. Under tenancy, team A and team B may both
ingest the same DOI privately, or one privately and one publicly. Options:

1. **One row, widest wins.** The row is public if any ingest of it was public, else owned by the
   first team. A second team's private ingest reveals nothing new, but the first team's ingest is
   visible to the second team as an existing row (the dedup probe sees it). This leaks less than
   today, but does not stop it.
2. **One row per tenant.** Key `papers` on `(document key, owner_group_id)`. No cross-tenant
   disclosure. Cross-source matching and `check_already_ingested` become per tenant, and a
   publicize of the claims must also publicize or merge the paper row.
3. **Public bibliographic row, scoped stamps.** Accept that title, DOI and journal are public
   bibliographic facts (they are, for a published paper), and scope only what says *this
   tenant ingested it*: the `processed_by` and `authored` edges, the author agents, and the
   `asserts` edges onto converged public claims (with their `doi:` labels). This is wrong for
   an unpublished or internal document, whose title is itself confidential.

Option 2 is the only one that makes a confidential ingest safe. It is also the largest. The
operator should choose before any migration is written.

## 4. Migration shape (for option 2)

* `papers`: add `visibility` and `owner_group_id` with the claims' vocabulary, backfill every
  existing row to `('public', world)` (today's behaviour), then `ENABLE` and `FORCE ROW LEVEL
  SECURITY` with a 077-style `papers_tenancy` policy: read where public or the owner group is in
  the viewer's read set; write where the owner group is in the writable set.
* Replace the unique key on the document key with `(document key, owner_group_id)`, and make
  `get_or_create` take the `TenancyDecl` the ingest resolved.
* Apply the existing guards to the new columns: 074 `*_block_widening` (group → public only
  through `epigraph_publicize_claims`, extended to the paper row), 115 `*_owner_immutable`.
* Move `ensure_paper_node` into the ingest's stamped transaction, so the paper row is written
  with the same viewer and declaration as the claims.
* Edges: give `paper` an entry in `epigraph_node_tenancy`, so `authored`, `processed_by` and
  `asserts` take the meet with the paper row instead of `('public', world)`. That also scopes
  an `asserts` edge onto a converged public claim: its meet becomes the paper's tenancy.
* Labels: `label_resolved_claim` must not add `doi:<doi>` to a public claim for a non-public
  ingest (or the label must move to the scoped edge).
* Author agents: keep them public as identities (an author's name is not tenant data), but
  their `authored` edges to a scoped paper take the paper's tenancy through the meet above.
* `epigraph_publicize_claims` / `epigraph_share_claims_with_team`: when every claim a paper
  asserts has been published, offer the paper row the same act (or do it in the same call).
* An undo runbook in `docs/runbooks/`, as for 206.

## 5. Tests

On the app role (`ScopedPool::connect_downgraded_for_tests(.., "epigraph_app")`):

* A team ingest: a non-member's `check_already_ingested` returns `already_ingested: false` and
  no `paper_id`; its `query_paper`, `GET /api/v1/papers` and `get_neighborhood` from the author
  agent show no row and no `authored` / `processed_by` edge. A member sees all of them.
* A private ingest: only the home group reads the paper row.
* A team ingest whose atom converges onto an existing public claim: a non-member sees neither
  the `asserts` edge from the paper nor a `doi:` label on that claim.
* The same DOI ingested by two teams: two rows, neither visible to the other team; each team's
  `check_already_ingested` answers for its own row only.
* A public ingest behaves byte for byte as today (row, edges, dedup, `check_already_ingested`).
* Existing rows after the backfill are public, and every existing ingest test still passes.
* The guards: a non-admin cannot widen a paper row; the owner cannot be changed by a plain
  UPDATE.
* A mutation probe for each read path: drop the policy (or bind the row public) and the
  non-member assertions go red.

## 6. What migration 246 implemented (option 2, papers)

* `papers.visibility` and `papers.owner_group_id` in 183's tier-A shape (no default; 074's
  `papers_require_tenancy`; 115's owner guard plus a visibility guard, so only a maintenance
  session re-tenants a row), every existing row backfilled to `('public', world)`, and ENABLEd +
  FORCEd row security (read: public or a group in the read set; insert: a group the session
  writes; update: a readable row; no application delete; 126-style elevated write refusals).
* One row per document per SCOPE: 001's `UNIQUE (doi)` is replaced by a unique index on
  `(doi, CASE WHEN visibility = 'public' THEN world ELSE owner_group_id END)`. Every public
  ingest of a document converges on its one public row, whoever owns it (corroboration and a
  public ingest behave as before); each group's private ingest gets its own row, and neither
  group can see or collide with the other's. `PaperRepository::get_or_create` takes the
  ingest's `TenancyDecl` and matches the declared scope, not merely what the session can see.
* `epigraph_node_tenancy` has a `paper` arm and `epigraph_propagate_tenancy` meets a paper
  endpoint with its own row (219's shape), so `authored`, `processed_by` and `asserts` edges
  onto a group paper are group edges, including `asserts` onto a converged public claim.
* Writers: the MCP ingest walks (`do_ingest_document`, `do_ingest_document_spine`, and the
  detached walk of the queued entry points) write the row on the ingesting agent's stamped
  transaction with the resolved declaration, inside the walk, so a failed walk leaves no row
  (backlog b995f117; the queued entry points only read it, `PaperRepository::planned`);
  `POST /api/v1/papers` registers a public row owned by the caller's home group on the caller's
  stamped transaction.
* Ids: a new PUBLIC row's id is derived from the document key (`public_paper_id`, a UUIDv5 of
  the canonical key), so a queued ingest can announce it before its walk commits; a group's
  PRIVATE copy gets a random id, never one computable from the key (a private copy cannot share
  the public row's primary key, and a derivable id would let anyone name a group's copy and probe
  whether it exists). A row written before this keeps its random id.
* Readers: `check_already_ingested` (both arms), `query_paper` and the ingest preflight read
  the rows on the caller's stamped connection (`PaperRepository::visible_by_document_key`), so a
  document another group ingested privately answers exactly as an unknown one; `GET
  /api/v1/papers` already read on the caller's stamp and is now filtered by the row security.
* Undo: `docs/runbooks/246-undo.sql` (refuses while any paper is private or a key has two rows).

## 7. What remains (backlog 34864fb5, items 2, 3, 6, 7 and part of 8)

* Author agents (non-principal, name-derived identity nodes) carry no tenancy yet: an author's
  name is world-readable, though the `authored` edge onto a group paper is not. The walk's
  `author -asserts-> claim` attribution edge onto a claim it CONVERGES onto (an already-public
  atom) declares no tenancy, so with both endpoints public the meet leaves it public, and
  `get_neighborhood` / `traverse` from that claim tie the name to it. Private author agents
  close this; until then it is part of "do not ingest a confidential author list". Their
  deterministic name-derived key and `agents.public_key` uniqueness must become tenant-scoped
  before they can be private; principals stay public. `find_agent` / `get_agent` and the agents
  routes then need the viewer.
* Widening: `epigraph_publicize_claims` / `share_claims_with_team` do not yet widen a paper or
  merge it into the target scope's row (merge on equal document key, re-point the edges, keep
  every ingest's provenance, a `merged_into` redirect, an audited and revertible event). Until
  then a publicized claim's `asserts` edge from a group paper stays the group's.
* Narrowing: a public paper cannot be privatized by an application session at all today (the
  visibility guard); the rule for a maintenance re-tenant (privatize only while no other
  group's claim or edge references the paper, as for evidence) is open.
* The `doi:<doi>` label a non-public ingest adds to a converged public claim (section 4).
* Engine reads of `papers` (`edge_factor.rs`, `matching/source_key.rs`) run under the session
  they are given, so on an unstamped pool a group paper is invisible to them.

