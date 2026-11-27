# Design specs: status index

`docs/superpowers/specs/` holds the design specs, kept as written: a spec records
what was decided when it was written, and the code may have moved on since. This
index records, for each spec, what happened to it, so a reader can tell a live
design from a historical one without re-deriving it from the tree.

`plans/` (implementation plans), `reports/` and `artifacts/` are not indexed here.

## Status vocabulary

Every spec's first `Status` line starts with one of these words, and its row
below uses the same word.

| Status | Meaning |
|---|---|
| `proposed` | Written, not yet approved. |
| `approved` | Approved, no implementation in the tree yet. |
| `in-progress` | Partly in the tree; the row says which parts. |
| `implemented` | In the tree as designed (minor file placement aside). |
| `implemented-with-deviations` | In the tree, but it differs from the text in ways a reader would trip on; the row (and usually the spec) lists them. |
| `superseded` | Replaced by a later spec or decision, named in the row. |
| `abandoned` | Dropped without a replacement. |
| `unverified` | Transitional: not yet checked against the tree. Removed from the vocabulary once every row is checked. |

## How to verify a spec

1. List what the spec says it ships: tables and migrations, functions, MCP tools,
   routes, scripts, files.
2. Look for each in `origin/main` (`git grep`, `git log -S<symbol>`, `ls`), and find
   the PR or commits that landed it.
3. Pick the status word. Prefer `in-progress` over `implemented` when part of the
   spec is missing, and `implemented-with-deviations` when what landed differs
   from the text.
4. Rewrite the spec's first `Status` line to
   `**Status:** <word> (checked against origin/main <sha>, <date>). <evidence>`,
   keeping the old line as `Original status:`, and update the row below.

A pull request that implements, deviates from or abandons a spec updates both its
`Status` line and its row here (CLAUDE.md, "Workflow").
`.github/scripts/tests/test_spec_index.py` fails when a spec has no row, a row
names a missing file, a status word is outside the vocabulary, or a checked spec's
`Status` word disagrees with its row.

## Specs

Checked against `origin/main` at `ad30094c5` on 2026-11-27, except the rows marked
`unverified`.

| File | Status | Implementing PR / commits | Deviations / superseded by |
|---|---|---|---|
| `2026-04-25-noun-claims-and-verb-edges-design.md` | implemented-with-deviations | #16; `ClaimRepository::create_or_get`, `if_not_exists` on the claim routes, `docs/architecture/noun-claims-and-verb-edges.md` | The `UNIQUE (content_hash, agent_id)` constraint the design relies on (migration 013 here) was dropped by migration 150; an advisory lock in `create_or_get_signed` and `POST /api/v1/claims` enforces the dedup instead. |
| `2026-04-26-multi-provider-identity-design.md` | implemented | #24; `crates/epigraph-api/src/oauth/providers/` (`ExternalIdentityProvider`, `ProviderRegistry`, `CloudflareAccessProvider`, `JwksCache`, `provision_external_user`), `cloudflare_access_jwt` grant | |
| `2026-04-26-s3a-epigraph-mcp-writer-migration-design.md` | implemented | #17; `crates/epigraph-mcp/src/claim_helper.rs::create_claim_idempotent` | |
| `2026-04-30-epigraph-table-graph-design.md` | implemented-with-deviations | `crates/epigraph-cli/examples/table_graph/` | The tool lives in `epigraph-cli`'s examples, not a `crates/epigraph-tools` crate; `docs/superpowers/artifacts/2026-04-30-table-graph/` holds only its README and signer key, no narratives. |
| `2026-04-30-hierarchical-workflow-primitive-design.md` | implemented-with-deviations | `workflows` table, `epigraph-ingest` workflow module, `epigraph-ingest-executor` | Listed in the spec's Status section: `store_workflow` runs the hierarchical ingest, the read and outcome tools are bridged, no migration CLI, different tool names. |
| `2026-04-30-issue-34-followups-train-design.md` | implemented-with-deviations | #82, #85; commits `5e6420b3e` (build-from-corpus), `626571f85` (theme and cluster ids on search) | Landed as separate PRs, not one train. The build-from-corpus route was later retired with the k-means prototype (`3c92cc408`). |
| `2026-05-16-backlog-retirement-design.md` | implemented | `resolve_backlog_item` (`crates/epigraph-mcp/src/tools/claims.rs`), `scripts/cleanup_backlog_labels.py`, `scripts/reconcile_backlog_labels.py`, `docs/conventions/backlog-retirement.md` | Later hardening (ownership gate on the `resolved` label) is in CLAUDE.md, "Retiring backlog items". |
| `2026-05-18-cross-source-anchor-design.md` | implemented | `scripts/classify_paper_document_type.py`, `seed_themes_from_textbooks.py`, `anchor_papers_to_themes.py`, `update_theme_workflow_steps.py`; `INSTANTIATES` in `routes/edges.rs`; `embedding_neighborhood_density` | The k-means theme prototype it extended was retired later (`3c92cc408`). |
| `2026-05-19-onboarding-docs-design.md` | implemented | `README.md`, `docs/intro/01-quickstart.md` to `05-next-steps.md` | The episcience half lives in that repository and was not checked here. |
| `2026-05-21-cross-source-matching-design.md` | implemented | Migration 036 (`match_candidates`); MCP `find_cross_source_matches`, `list_match_candidates`, `decide_match_candidate`; `GET /api/v1/claims/:id/cross_source_matches`; `cross_source_sweep`, `calibrate_matcher` | Phase 1 only, as the spec scopes it; its Phase 2 (`match_queue`, ingest hook) is left to a follow-on spec and is not in the tree. |
| `2026-05-27-alt-set-lifecycle-design.md` | implemented | Migration 043 (`alt_set_decisions` view); `suggest_alternative_sets` `exclude_settled` and `surface_reconsiderations` | |
| `2026-05-27-alternative-and-dependency-edges-design.md` | unverified | | |
| `2026-05-27-claims-belief-bounds-clamp-design.md` | unverified | | |
| `2026-05-28-locality-aware-combine-spec.md` | unverified | | |
| `2026-05-28-per-frame-evidence-type-weights-spec.md` | unverified | | |
| `2026-06-02-commit-ingestion-automation-design.md` | unverified | | |
| `2026-06-03-cross-source-bootstrap-matching-design.md` | unverified | | |
| `2026-06-03-epigraphv2-theme-system-report-design.md` | unverified | | |
| `2026-06-03-hybrid-recall-design.md` | unverified | | |
| `2026-06-03-link-epistemic-mcp-design.md` | unverified | | |
| `2026-06-03-oauth-provision-email-allowlist-design.md` | unverified | | |
| `2026-06-03-perspective-lens-reads-design.md` | unverified | | |
| `2026-06-03-plan-2.5-server-side-ingestion-idempotency.md` | unverified | | |
| `2026-06-03-plan-3-git-ingest-reconciler-design.md` | unverified | | |
| `2026-06-15-rdf-triple-matching-experiment-design.md` | unverified | | |
| `2026-06-18-deterministic-spine-ingest-design.md` | unverified | | |
| `2026-07-11-review-divergence-expected-behavior.md` | unverified | | |
| `2026-07-23-mcp-federation-gateway-design.md` | unverified | | |
| `2026-09-15-epigraph-explorer-ui-design.md` | unverified | | |
| `2026-09-26-episcience-operator-authority-design.md` | unverified | | |
| `2026-11-04-epigraph-explorer-atlas-design.md` | unverified | | |
| `2026-11-12-atlas-nested-groups-and-subgraph-view-design.md` | unverified | | |
| `2026-11-24-human-identity-visibility-design.md` | unverified | | |
