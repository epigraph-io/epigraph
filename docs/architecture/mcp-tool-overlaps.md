# MCP tool overlaps: which tool to call

Several MCP tools do overlapping jobs. This page is the decision table for the
four families an agent most often confuses. Each table has one row per tool,
with its job, the shape of what it returns, its status, and when to prefer it.
The rows summarise each tool's served description (the text `tools/list` and
`list_mcp_tools` return). That description is the contract: where the two
differ, the description wins, and this page is stale.

Status is one of:

- **current**: served and supported;
- **deprecated (date)**: served, but refused from that date;
- **removed**: no longer served (a call is refused as an unknown tool).

`get_provenance` and `recall` point here from their descriptions
(backlog 4e2ce1c4). `crates/epigraph-mcp/tests/tool_overlaps_doc.rs` checks
that every row names a tool that is served, unless the row says it was removed.

## Provenance: what a claim rests on

| Tool | Job | Output shape | Status | Prefer it when |
|---|---|---|---|---|
| `get_provenance` | The ancestry bundle of one claim: ancestor claims, their evidence and reasoning traces, in topological order. It walks derivation edges only: supports, elaborates and decomposes_to (incoming), and supersedes back to the predecessor. Contradicts, refutes and corroborations are not ancestry. | `{root_claim, entities, topological_order, cycle_detected, max_depth_reached, truncated, budget_exhausted, ..._count, limits}`. Each claim entity carries content (clipped to a budget), truth_value, depth, parent_ids and evidence_ids; evidence and trace entities are listed too. Bounded by max_depth (1 to 20), max_nodes and a response budget. | current | You need the evidence and reasoning behind a claim, not just the claim graph. This is the default provenance read. |
| `get_provenance_chain` | The derivation chain behind a conclusion in one call. It walks supports, corroborates, elaborates and decomposes_to backwards and supersedes forwards; cycles are reported, not errors, and superseded ancestors are included and flagged. | Nodes in topological order (evidence first, conclusion last) plus the connecting edges. max_depth 1 to 8 (default 4); an optional relationships filter restricts the walk. | current (a planned change folds it into `get_provenance` as a chain shape, then retires it with a dated refusal; that change is not on main yet) | You need the edge list itself (which claim supports which), or want corroborates walked or a relationship filter. |
| `export_provenance_prov_o` | One claim's provenance as a W3C PROV-O JSON-LD document. | prov:Entity per claim, prov:Agent per author with prov:Attribution, prov:Relation per mapped edge; bounded, with `truncated` and `limits`. | current | You are handing provenance to an external PROV-O consumer. |

`get_neighborhood` and `traverse` are the general graph reads. Use them for
the edges provenance deliberately leaves out (contradicts, refutes,
corroborations).

## Recall: semantic search

| Tool | Job | Output shape | Status | Prefer it when |
|---|---|---|---|---|
| `recall` | Semantic and lexical (hybrid) search over claims with epistemic quality scoring. It can be pinned to one theme in SQL (theme_id or theme_label, echoed as theme_scope) and paged with offset; it reports candidate coverage. | `results` (or, with epistemic_partition=true, the same hits grouped as confirmed, uncertain and open_question), `paging.more_available`, and n_total_candidates, coverage_rate and candidate_pool_saturated. | current | You want the best-matching claims themselves, want to walk one theme to exhaustion, or need to know how much of the candidate pool you saw. |
| `recall_with_context` | Semantic search over every embedded claim, with batched structural context per hit: parent paper and section, child atoms, sibling and neighbour paragraphs, corroborates, and epistemic-edge neighbours. diverse=true spreads results across themes it picks itself. | One result per hit with `paragraph_id`, the hit's belief_score, `paper` (absent for an unattributed hit), `section`, and the context lists; or the epistemic_partition grouping. It reports below_confidence_floor. | current | You need each hit's surrounding document structure or its supporting and refuting neighbours, or want diversity across themes without choosing them. |

The two stay separate tools for now. Merging them, and the HTTP twin of
`recall_with_context`, are tracked by backlog a601168e.

## Document ingest: putting a source into the graph

| Tool | Job | Output shape | Status | Prefer it when |
|---|---|---|---|---|
| `structure_source` | Deterministically structures raw markdown or plain text into a verbatim DocumentExtraction: sections and paragraphs as byte-exact source slices, source_text and spans filled, atoms empty. Read-only; writes nothing. | A DocumentExtraction with empty atoms. | current | You start from extracted source text that must be re-verified byte for byte. Fill the atoms, then submit with `ingest_document_inline`. |
| `ingest_document_spine` | Phase 1 of the two-phase ingest: writes thesis, sections and paragraphs and ignores atoms. Synchronous and all-or-nothing; idempotent per document. | `new_paragraph_paths` (the paragraphs new to this ingest), paragraphs_deduped, paragraphs_embedding_queued, and label counts. | current | A long document where you want to atomise only the paragraphs that are new, to save extraction cost. Follow it with `ingest_document_inline` for those paths. |
| `ingest_document_inline` | Ingests a full DocumentExtraction passed in the call: paper node, claims at every level down to atoms, edges, evidence, traces, embeddings and atom mass functions. Write authority is checked synchronously; the walk is asynchronous unless wait is true. | `{status: 'queued', paper_id, document_key, title}`, or with wait=true the walk's own result (claims_ingested, claims_skipped_dedup, relationships_created, `doi` = the document_key, ...). | current | The usual ingest from an MCP-only client: the extraction is in the call, and wait=true reports a failed walk to you. |
| `ingest_document` | The same writer and the same asynchronous contract as `ingest_document_inline`, but it reads the extraction from a file inside the server's working directory. | Same as `ingest_document_inline`. | current | You run beside the server and the extraction is already a file on its disk. |

Use `check_already_ingested` and `query_paper(document_key)` to confirm an
asynchronous ingest landed.

## Claim writes: one claim, a quick memory, or many

| Tool | Job | Output shape | Status | Prefer it when |
|---|---|---|---|---|
| `submit_claim` | Writes one claim with its evidence, reasoning trace and Dempster-Shafer belief, all-or-nothing. Any evidence type, weighted by type. | claim_id, truth_value, content_hash, embedded, the belief fields; a `deduplicated` block when it matched an existing claim; an `atomicity` warning when the text asserts several things. | current | You have a source or data to cite. This is the default write. |
| `memorize` | A quick store of a fact as a testimonial claim (0.6x evidence weight); tags become labels. All-or-nothing like `submit_claim`. | As `submit_claim`, including `deduplicated` and `atomicity`. | current | You want to remember something with no source to cite. |
| `batch_submit_claims` | Up to 100 entries, each submitted exactly as `submit_claim`, each on its own transaction. A refused entry writes nothing and the others still land. | `submitted`, `errors`, `error_details`, and `results`: one object per entry in input order, either the entry's full `submit_claim` response or its error. | current | You have several independent claims to write in one call. |
| `stage_claims` | Checked only that each string was non-empty and at least 10 characters. It validated nothing `submit_claim` would refuse. | (none) | removed (backlog 90993e95) | Never. To check a claim's shape before writing it, use `screen_claim_atomicity`. |
