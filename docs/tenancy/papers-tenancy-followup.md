# Follow-up: tenancy for an ingested paper's own record

Status: design note, not implemented. Operator ruling, 2026-11-11: document the gap in the claim
visibility work now and close it in a follow-up PR. Until that PR lands, **do not ingest a
confidential document**, whatever `visibility` you pass.

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

So anyone can learn that a document exists, its title, DOI and journal, who wrote it, which agent
ingested it and with which pipeline, and when.

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
   tenant ingested it*: the `processed_by` and `authored` edges and the author agents. This is
   wrong for an unpublished or internal document, whose title is itself confidential.

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
  `asserts` take the meet with the paper row instead of `('public', world)`.
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
* The same DOI ingested by two teams: two rows, neither visible to the other team; each team's
  `check_already_ingested` answers for its own row only.
* A public ingest behaves byte for byte as today (row, edges, dedup, `check_already_ingested`).
* Existing rows after the backfill are public, and every existing ingest test still passes.
* The guards: a non-admin cannot widen a paper row; the owner cannot be changed by a plain
  UPDATE.
* A mutation probe for each read path: drop the policy (or bind the row public) and the
  non-member assertions go red.
