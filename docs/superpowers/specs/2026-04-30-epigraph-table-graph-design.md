# EpiGraph Table Graph — Design

**Date:** 2026-04-30 (revised after entity-table CHECK discovery)
**Author:** Jeremy Barton (with `code-graph-extractor` agent — fresh Ed25519 signer keypair)
**Status:** Spec — pending implementation plan

## Goal

Build a self-describing knowledge graph of every database table in the public `epigraph` and `episcience` repositories — what each table supports, which crates and functions read or write it, and how it relates to other tables — represented as **claims about the shape of the code** in EpiGraph's existing claim/evidence label-property graph (LPG). Cite each fact with greppable function names and content snippets so that, when those functions evolve, drift detection can flag stale claims for re-extraction.

Schema only — no row data is ingested.

## Why claims, not new entity/edge types

The first iteration of this design proposed `db_table` and `code_module` as new entity types with `WRITES_TO`/`READS_FROM`/`JOINS_WITH` edges. Implementation revealed that the `entities` table is the noun-extraction ontology (constrained by `entities_type_top_valid` to ontological types like `Material`, `Person`, `Organism`, `Concept`) — not a polymorphic landing zone. The other "entity types" in the edges API (`claim`, `paper`, `frame`, `community`) each live in dedicated tables.

Adding two new dedicated tables and edge relationships for `db_table`/`code_module` would have been architecturally heavy and bypassed EpiGraph's central abstraction: **the claim is the fact**. Code shape is just another category of fact about the world. The LPG already supports labels, properties, evidence, supersession, DST/CDST, and recall — everything the table-graph needs.

The reframe also unlocks a future loop: when an evidence row's `raw_content` (a function snippet) is no longer findable by grep at the cited symbol, the claim is flagged stale and re-extracted. Code change → graph maintenance, automatic.

## Scope

- **Repos in scope:** `/home/jeremy/epigraph` (public, canonical) and `/home/jeremy/episcience` (Apache-2.0 sibling holding `experiments`/`experiment_results`/`samples`/`protocols`/`blobs`/`countersignatures`/`sample_claims` plus the synthesis subsystem).
- **Repos out of scope:** `epigraph-internal` (slated for deprecation), `epigraph-enterprise`, `epiclaw-host`, `EpigraphV2`, archived `episcience-internal`.
- **Migration directories included:** `epigraph/migrations/*.sql` (001–023+, ~70 tables) + `episcience/migrations/*.sql` (~7 tables) + `episcience/migrations/synthesis/*.sql` (~9 tables).
- **Migration directories excluded:** `episcience/migrations/upstream/` (redundantly redefines the epigraph schema for cross-repo testing — explicit skip).
- **Surface estimate:** ~85 tables total, 18 crates (15 epigraph + 3 episcience).

## Architecture

A two-stage pipeline with a durable staging layer between extraction and ingestion. Code lives at `crates/epigraph-tools/examples/table_graph/` as a Rust binary.

```
[1] Discover         migrations/*.sql across both repos → table list
                            │
                            ▼
[2] Per-table dossier   DDL + git log (3 slices) + grep call sites + FK targets
                            │
                            ▼
[3] Claude CLI (OAuth)  structured Markdown narrative per table
                            │
                            ▼
[4] Staging files       docs/superpowers/artifacts/2026-04-30-table-graph/narratives/<table>.md
                            │
                            ▼
[5] Tier-1 ingestion    extract-claims → ingest_document (per table, dedicated agent)
```

Stage 4 is the durability layer: re-runs replace narrative MD files but only re-ingest when `content_hash` (sha256 of the dossier + narrative) changes. Stage 3 is the only LLM-call stage; everything else is deterministic Rust/shell.

The Claude CLI (not the SDK) is the LLM driver, per the prepaid-OAuth convention.

## Claim shape in EpiGraph

For each table, the per-table Markdown narrative is run through the existing `extract-claims` skill, producing a `DocumentExtraction` JSON, which is then ingested via `mcp__epigraph__ingest_document`. The hierarchical extractor naturally produces:

- **One top-level "purpose" claim:** "Table `<name>` in repo `<repo>` stores ... and is used by ..."
  - Labels: `["code-shape", "table-purpose"]`
  - Properties: `{"table": "<name>", "repo": "<repo>", "migration": "<file>"}`
- **N "call-site" sub-claims** (one per discovered call site):
  - "Crate `<crate>` writes to table `<name>` via function `<fn>`."
  - Evidence row: `raw_content = "<grep-able snippet>"`, `source_url = "<repo>/crates/<crate>"`
  - Labels: `["code-shape", "call-site", "writes-to" | "reads-from"]`
  - Properties: `{"table": "<name>", "crate": "<crate>", "fn": "<fn>", "kind": "writes_to" | "reads_from"}`
- **N "fk" sub-claims** (one per FK relationship from DDL):
  - "Table `<name>` references table `<target>` via FK `<col>`."
  - Evidence row: `raw_content = "<DDL excerpt>"`, `source_url = "<migration_path>"`
  - Labels: `["code-shape", "fk-relationship"]`
  - Properties: `{"table": "<name>", "target": "<target>", "column": "<col>"}`

All sub-claims are linked to the purpose claim through the existing `decomposes_to` relationship, which is exactly what hierarchical extraction emits by default.

## Authorship

All synthetic claims are authored by a dedicated **`code-graph-extractor` agent**. Agents are keyed by Ed25519 public key (`crates/epigraph-mcp/src/server.rs::agent_id`), so this means generating a fresh signer keypair, storing it in env, and running the ingestion CLI under it. The display name `code-graph-extractor` lives in `agents.label`. Isolating these synthetic claims from Jeremy's hand-curated knowledge makes them safe to re-extract or forget en masse.

## Extraction pipeline (per-table dossier)

For each discovered table, before the LLM call:

**a. DDL.** All `CREATE TABLE`, `ALTER TABLE`, `CREATE INDEX`, and `CREATE TRIGGER` statements concatenated from migrations that mention the table.

**b. Git context — three slices, deduped by SHA:**
1. The introducing commit (oldest hit from `git log --diff-filter=A -- migrations/<file>`)
2. All subsequent commits touching that migration file (`git log --follow -- migrations/<file>`)
3. Commits with the table name in the message body (`git log --grep="<table_name>"`)

Each slice contributes commit subject + body + author date.

**c. Call sites.** For each repo: grep the table name as a word boundary across `.rs` files (excluding `target/`, `migrations/`, `.sqlx/` cache, doc-comment-only matches). For each match, back-scan to extract the enclosing function name and grab a 2-line context window. Tag each call site as `WRITES_TO` (INSERT/UPDATE/DELETE/UPSERT/COPY) or `READS_FROM` (SELECT/sqlx::query_as).

No cap on call site count: this is schema-level data, not row data.

**d. FK targets.** Extract `REFERENCES other_table` from DDL. Deterministic, no LLM round-trip.

**e. LLM call (claude CLI, OAuth).** One call per table with the dossier. The output is a Markdown document structured for the `extract-claims` hierarchical extractor:

```markdown
# Table `<name>` (`<repo>`)

## Purpose

<one paragraph: what this table stores, why it exists, who reads/writes it>

## Call sites

- Crate `<crate>` writes to via function `<fn>`: `<snippet>`
- Crate `<crate>` reads from via function `<fn>`: `<snippet>`
...

## Foreign key relationships

- References table `<target>` via column `<col>`: `<DDL snippet>`
...

## DDL

```sql
<concatenated CREATE/ALTER>
```

## Git context

- <SHA> <date>: <subject>
...
```

`extract-claims` knows how to walk this hierarchy: the H1 becomes the purpose claim, each `## Call sites` bullet becomes a call-site claim with the embedded snippet as evidence, etc. Retry once on extractor failure with a stricter prompt; skip and log on second failure.

## Ingestion (per-table, idempotent)

For each staging MD file: spawn one `claude -p --dangerously-skip-permissions` subprocess that, in a single Claude session, (1) runs `extract-claims` on the Markdown to produce a `DocumentExtraction` JSON and (2) calls `mcp__epigraph__ingest_document` on that JSON with synthetic DOI `urn:epigraph-table:<repo>:<table_name>`. Authorship of the resulting claims is whatever signer the system MCP server is configured with — for the validated `frames` run, this surfaced as an auto-created agent labeled `epigraph-table-graph`. The pre-registered `code-graph-extractor` agent row is unused; discrimination relies on the synthetic DOI prefix.

`ingest_document` deduplicates by DOI + `PIPELINE_VERSION` (`crates/epigraph-mcp/src/tools/ingestion.rs::do_ingest_document`). To force a clean re-extraction, version-bump the synthetic DOI suffix (e.g., `:v2`).

**Idempotency keys:**
- Staging file `content_hash` (sha256 of dossier + narrative MD) — re-extraction only when this changes
- Per-table DOI + `PIPELINE_VERSION` for ingestion dedup

## Failure handling

- LLM JSON/Markdown malformed → retry once with stricter prompt; second failure skips + logs to `failed.jsonl`
- `extract-claims` fails → skip + log
- `ingest_document` fails → skip + log; replay pass at end of run
- Orphan tables (zero call sites) → still get a purpose claim noting the orphan status. Surface from the run rather than asserting up front.

## Verification

Three checks before declaring the run complete. Discrimination is via the synthetic DOI prefix `urn:epigraph-table:` rather than claim labels — the `extract-claims` skill emits claims with empty `labels` arrays regardless of MD-side hints, so labels-based filtering does not work. Each per-table paper has its 70+ atomic claims linked via `asserts` edges (paper → claim) and additional `decomposes_to` edges between claims.

1. **Coverage.** Count papers with `doi LIKE 'urn:epigraph-table:%'`; expected ~85 (one per ingested table).
2. **Recall.** Run semantic queries against the EpiGraph recall API. Pick three tables of varying prominence (e.g., `claims`, `frames`, `harvester_audit_reports`); the right narrative should surface for the right query (e.g., "what stores DST mass functions" → `mass_functions`).
3. **Per-table sanity.** For each per-table paper, count `asserts` edges to claims; expected dozens per non-trivial table (frames produced 73 claims, 159 relationships).

## Outputs

- `docs/superpowers/specs/2026-04-30-epigraph-table-graph-design.md` — this spec
- `docs/superpowers/artifacts/2026-04-30-table-graph/staging/<table>.json` — ~85 dossiers
- `docs/superpowers/artifacts/2026-04-30-table-graph/narratives/<table>.md` — ~85 LLM-generated narratives
- `crates/epigraph-tools/examples/table_graph/` — extraction + ingestion code (Rust binary)
- In EpiGraph: ~85 purpose claims + hundreds of call-site/fk sub-claims, all authored by `code-graph-extractor`, all carrying greppable evidence

## Surprising findings to watch for

- **Truly orphan tables** (no call sites) → drop candidates
- **Write-only tables** (only INSERT/UPDATE, never SELECT) → audit/log-only patterns
- **Read-only tables** (only SELECT, populated by migrations) → reference data
- **Single-crate vs cross-crate tables** → architectural seams

## Future: git-triggered re-validation

Each call-site claim's evidence carries `raw_content = "<greppable snippet>"`. A future loop:

1. On commit (or scheduled scan), grep the codebase for each evidence snippet
2. If a snippet is no longer findable verbatim at the cited function, mark the claim stale (custom label `stale: true` or supersede with a new "code drifted" claim)
3. Re-extract by version-bumping the per-table DOI

This makes the table-graph self-maintaining as the codebase evolves. Out of scope for the initial implementation but informs the design (greppable evidence is non-negotiable).

## Out of scope

- Row-level data ingestion (schema only)
- Internal/enterprise/host-CLI repos
- New entity types or edge relationships (the explicit reframe — use claims only)
- File-level or function-level entities (functions live as evidence content, not as graph nodes)
- Static-parse precision pass with `syn`/`sqlparser` — could be added later as a verification layer over the grep heuristic
- Git-triggered re-validation loop — informs design but not built in v1
