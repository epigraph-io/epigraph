# Onboarding documentation for EpiGraph and Episcience

**Status:** Draft — awaiting user review
**Owners:** Jeremy Barton
**Repos affected:** `epigraph-io/epigraph`, `epigraph-io/episcience`
**Date:** 2026-05-19

---

## 1. Problem

EpiGraph and Episcience have no top-level READMEs and no entry-point documentation for new users. A fresh clone of either repo is opaque: a Rust workspace with 17 (epigraph) or 3 (episcience) crates, 32 (epigraph) or 11 (episcience) migrations, no instructions for getting from "I have the source" to "I successfully called my first MCP tool."

New collaborators — including future contributors, downstream-app builders (WRHQ, Praxis, NDI tooling), and Astera-style residency reviewers — currently rely on synchronous onboarding from Jeremy. The cost grows with each new person and effectively caps how widely the system can be adopted.

## 2. Goals

1. A new person with basic Rust + Postgres familiarity can go from `git clone` to a successful MCP `recall_with_context` call in ~10 minutes by following written instructions only.
2. After ~1-2 hours of reading the intro tree and running the walkthroughs, that person understands the mental model well enough to design their own claims, edges, and queries.
3. Episcience layers cleanly on top: an EpiGraph-literate user can spin up episcience in ~5 additional minutes without re-reading kernel docs.
4. Both READMEs serve as effective GitHub front-doors: a visitor to github.com/epigraph-io/{repo} gets a pitch, a quickstart, and a navigable TOC into deeper material.

## 3. Non-goals

- GUI tour (`epigraph-gui` is a separate concern; we will link to it from `05-next-steps.md` but not document it).
- Harvester crate documentation (`epigraph-harvester` is excluded from the workspace and currently out of scope).
- Production deployment runbook (already covered by `docs/deploy.md`; intro tree links to it).
- OAuth mint flow for downstream services (already covered in user memory `reference_epigraph_oauth_mint.md`; out of scope for the intro tree).
- Contributor's guide beyond a brief pointer (`CLAUDE.md` already serves agent contributors; the intro tree's `05-next-steps.md` will point human contributors to it).
- Docker Compose orchestration. Neither repo ships a `docker-compose.yml` today; the quickstart uses hand-started Postgres and `cargo run`. Adding compose is a separate scope expansion if desired later.

## 4. Audience

Mixed, layered per the existing `docs/intro/` convention used by other epigraph-io projects:

- **Technical readers** (Rust devs, agent integrators, contributors): follow the full quickstart, walkthroughs, and concept guide.
- **Semi-technical readers** (researchers, PMs, founders evaluating the system): skim the README's pitch and concepts file; rely on a peer to run the quickstart, then drive MCP from Claude Code.

The READMEs and `02-concepts.md` are written for both audiences. `01-quickstart.md` and `03-walkthroughs.md` assume a terminal-comfortable reader.

## 5. Architecture

### 5.1 File layout

**`/home/jeremy/epigraph/`** — new files only:
```
README.md
docs/intro/01-quickstart.md
docs/intro/02-concepts.md
docs/intro/03-walkthroughs.md
docs/intro/04-glossary.md
docs/intro/05-next-steps.md
```

**`/home/jeremy/episcience/`** — new files only:
```
README.md
docs/intro/01-quickstart-extension.md
docs/intro/02-concepts-science.md
docs/intro/03-walkthroughs.md
docs/intro/04-glossary.md
```

Existing files (`CLAUDE.md`, `docs/architecture/`, `docs/deploy.md`, `docs/conventions/`, `scripts/README.md`) are untouched. The new intro tree cross-links into them rather than duplicating their content.

### 5.2 Why README + `docs/intro/`

- The top-level `README.md` is what GitHub renders on the repo page. Visitors get a useful first impression: pitch, status, 5-minute quickstart, TOC.
- The `docs/intro/` tree absorbs the depth (~1-2 hours of full onboarding material) without making the README a 2000-line wall.
- Numbered filenames (`01-…`, `02-…`) give a stable suggested reading order while letting individual files be referenced independently.
- The pattern mirrors existing structure in `docs/architecture/` and `docs/conventions/`, so contributors recognize where things live.

### 5.3 Layering: episcience assumes EpiGraph

Episcience's intro tree does not re-explain kernel concepts. `01-quickstart-extension.md` starts from "you have epigraph running"; `02-concepts-science.md` starts from "you understand claims, edges, agents, BetP." Where a science concept extends a kernel concept (e.g., synthesis claims extend noun-claims), episcience docs link back to the EpiGraph file rather than restate it.

## 6. Content specs

### 6.1 EpiGraph `README.md` (~150 lines)

Sections in order:
1. **What is EpiGraph?** Two paragraphs. EpiGraph is an epistemic kernel: claims (nouns), edges (verbs), agents that sign their assertions, beliefs propagated via Dempster-Shafer. It replaces static papers with a live experimental loop — hypothesis → experiment → data → analysis → belief update.
2. **Who is this for?** Bulleted: devs building epistemic apps; researchers querying the graph via Claude Code; contributors extending the kernel.
3. **Status & license.** Apache-2.0, version 0.3.0, "alpha — kernel stable, layers iterate."
4. **5-minute quickstart** (inline, ~10 commands): clone, start Postgres (`postgres://epigraph:epigraph@localhost`), `cargo build --release -p epigraph-api -p epigraph-mcp`, `cargo run --bin epigraph-migrate`, start the API, register the MCP server in `~/.mcp.json` (show the exact config, with binary name `epigraph-mcp-full`), open Claude Code, call `recall_with_context "test"`. End-state: a JSON response showing the empty corpus or hitting the user's first claim.
5. **Where to next.** Linked TOC into `docs/intro/`, plus a "Deeper material" section pointing to `docs/architecture/noun-claims-and-verb-edges.md`, `docs/deploy.md`, `CLAUDE.md` (for agents), and `scripts/README.md`.

### 6.2 EpiGraph `docs/intro/01-quickstart.md` (~200 lines)

A robust expansion of the README's 5-minute version, with:

- **Prereqs** explicit: Rust ≥1.75, PostgreSQL 16+ with the `vector` extension installed, Claude Code installed, ~$5 OpenAI credit for embeddings (set `OPENAI_API_KEY`).
- **Step 1: PostgreSQL.** Install, create role `epigraph` with password `epigraph` (no `SUPERUSER` needed for runtime use), create database `epigraph`, `CREATE EXTENSION vector;`. Add a footnote: running the test suite under `sqlx::test` additionally requires `SUPERUSER` because it `LOCK`s `pg_namespace` (memory `feedback_sqlx_test_uses_superuser`); grant it temporarily or use a separate test-only superuser role.
- **Step 2: Clone and build.** `git clone … && cd epigraph && cargo build --release -p epigraph-api -p epigraph-mcp -p epigraph-cli`. Note that the `epigraph-mcp` package produces a binary named `epigraph-mcp-full` (see `crates/epigraph-mcp/Cargo.toml`).
- **Step 3: Migrations.** `cargo run --release --bin epigraph-migrate`. Document the 2026-05-05 reconcile script as a "first-time-on-pre-existing-prod-data" footnote pointing to `docs/deploy.md`; not required for fresh installs.
- **Step 4: Start the API.** `cargo run --release -p epigraph-api --bin server`. Verify with `curl http://127.0.0.1:8080/health`.
- **Step 5: Install the MCP server.** Two options: (a) `sudo cp target/release/epigraph-mcp-full /usr/local/bin/epigraph-mcp` (rename to match `/home/jeremy/.mcp.json`) — or leave the binary name as-is and update the `~/.mcp.json` `command` to `/usr/local/bin/epigraph-mcp-full`; (b) `cargo install --path crates/epigraph-mcp` for users without `/usr/local/bin` write access (installed name will still be `epigraph-mcp-full`). Show the exact `~/.mcp.json` block to add for each option.
- **Step 6: First MCP call.** Open Claude Code in any directory, ask "use the recall tool to search for 'test'", expect a JSON `recall_with_context` response with empty results. Then ask Claude to "submit a claim that 'EpiGraph is installed correctly'" and observe the submitted-claim ID.
- **Common errors.** Tabular: `sqlx checksum mismatch` → see deploy.md; `connection refused on 5432` → start Postgres; `extension "vector" is not available` → install pgvector; `OPENAI_API_KEY not set` → export it.
- **Tear-down.** `dropdb epigraph` if reinstalling.

### 6.3 EpiGraph `docs/intro/02-concepts.md` (~400 lines)

Six sub-sections, each 50-80 lines:

1. **Noun-claims vs verb-edges.** Short version of `docs/architecture/noun-claims-and-verb-edges.md` with the textbook-ingest worked example. Link to the full doc for the worked examples and migration history.
2. **Agents and signing.** Every claim is signed; agent identity is deterministic (DID from model+prompt hash per memory `project_epigraph_agent_identity.md`). Show an example `agent_id` and what its content_hash looks like.
3. **Beliefs and DST.** What BetP (pignistic probability) means; why scalar BP is deprecated (memory `project_bp_cdst_primary.md`); how to read a belief in `get_belief` output. Brief reference to LANL Open World DST paper for the formal foundation.
4. **Perspectives, frames, themes.** Multi-viewpoint querying; how claims get scoped to a frame; what a perspective is. Pointer to `mcp__epigraph__list_perspectives`.
5. **Hierarchical extraction.** Papers → paragraphs → atoms. Why Tier 1 (`extract-claims` → `ingest_document`) is canonical (memory `feedback_tier1_ingestion_only.md`). The level=2 paragraph-primary search pattern.
6. **Backlog discipline.** `resolve_backlog_item` is the canonical retire-pattern (link to `docs/conventions/backlog-retirement.md`). What "resolved" vs "current" vs "supersedes" mean and when to use each.

### 6.4 EpiGraph `docs/intro/03-walkthroughs.md` (~500 lines)

Four end-to-end transcripts, each ~120 lines, formatted as Claude Code session logs showing exact MCP calls, responses, and brief explanatory prose between steps:

- **Walk 1: Ingest a short PDF.** Use a small public-domain paper. Call `mcp__epigraph__ingest_document` with the path. Observe the job kick off; poll with `mcp__epigraph__system_stats`; query the resulting paragraph + atom claims with `query_paper`.
- **Walk 2: Query and expand.** Call `recall_with_context` on a topic from Walk 1's paper. Then `get_neighborhood` on the top hit to explore connected claims. Then `traverse` to follow a multi-hop path.
- **Walk 3: Challenge a claim.** Pick a claim from Walk 1; call `challenge_claim` with a counter-argument; observe the challenge record. Then `verify_claim` to mark it confirmed despite the challenge.
- **Walk 4: Backlog roundtrip.** Use `submit_claim` with `labels=["backlog"]` to file an item. Query open backlog with `query_claims_by_label(labels=["backlog"], exclude_labels=["resolved"], current_only=True)`. Resolve with `resolve_backlog_item(original_id, resolution_content)`. Verify the original is now labelled `resolved`.

Each walkthrough ends with a "what just happened" paragraph that ties the MCP calls back to concepts from `02-concepts.md`.

### 6.5 EpiGraph `docs/intro/04-glossary.md` (~100 lines)

Alphabetical, two-to-four-sentence definitions, each entry linking to the file where the concept is explained in depth. Entries: agent, atom, BetP, challenge, claim, content_hash, DST, edge, evidence, factor, frame, hierarchical extraction, MCP, methodology, noun-claim, paragraph, perspective, pignistic probability, provenance, recall, signature, supports, synthesis, theme, verb-edge, workflow.

### 6.6 EpiGraph `docs/intro/05-next-steps.md` (~80 lines)

Four short sections, each one paragraph plus links:
- **Extending the kernel.** Pointers to `CLAUDE.md`, the test DB recipe (`epigraph_db_repo_test`), `cargo sqlx prepare` workflow, the noun-claims-and-verb-edges architecture doc.
- **Science-specific tooling.** Pointer to episcience's README.
- **Production deployment.** Pointer to `docs/deploy.md`.
- **Building a downstream app.** The integration pattern — depending on `epigraph-core` etc. as Cargo git deps, with `Cargo.toml` of episcience as the reference example. Pointer to `feedback_use_worktrees.md` lessons for multi-session work.

### 6.7 Episcience `README.md` (~80 lines)

1. **What is episcience?** One paragraph. Apache-2.0 layer over EpiGraph that adds the experimental loop: samples, protocols, blobs, countersignatures, synthesis claims. Where EpiGraph models *what is believed*, episcience models *how beliefs were tested*.
2. **Status & license.** Apache-2.0, version 0.1.0, "alpha — Phase 0 prereqs pinned to a specific epigraph rev per `Cargo.toml`."
3. **Prerequisites.** A running EpiGraph kernel (link to its README quickstart). Same Postgres instance is fine.
4. **5-minute extension quickstart** (inline, ~5 commands): clone, apply episcience migrations on top of the kernel DB using `sqlx migrate run`, `cargo build --release -p episcience-api`, start `episcience-server`, verify with a sample synthesis-claim submission via the `synthesize` MCP tool.
5. **TOC** into `docs/intro/` plus a "Why a separate repo?" note (the public Apache-2.0 layer separation, per memory `project_episcience_license.md`).

### 6.8 Episcience `docs/intro/01-quickstart-extension.md` (~150 lines)

- **Prereq.** EpiGraph quickstart completed; `epigraph` DB exists and migrations are applied; API is running.
- **Step 1.** Clone episcience. Local path overrides for development if also hacking on the kernel: add the `[patch."https://github.com/epigraph-io/epigraph"]` block to `~/.cargo/config.toml` (NOT to the workspace `Cargo.toml`), as documented in the existing `Cargo.toml` comments. The comment explicitly says "Don't commit personal patches."
- **Step 2.** Apply episcience migrations against the `epigraph` DB using the sqlx CLI: `cd episcience && sqlx migrate run --source migrations/ --database-url postgres://epigraph:epigraph@localhost/epigraph`. There is no `episcience-migrate` binary today; the server explicitly skips embedded migrations (see `crates/episcience-api/src/bin/episcience-server.rs`). Migrations must run after the EpiGraph kernel schema is applied (current kernel migrations through `032_claim_themes_properties.sql`); episcience depends on kernel functions like `cascade_delete_edges` and `validate_edge_reference`, which exist from kernel migrations 024-025 onward.
- **Step 3.** Build and start `episcience-server` on a separate port from `epigraph-api`. Verify `/health` on that port.
- **Step 4.** Submit a sample-bound synthesis claim via curl or the `episcience-mcp-server` MCP tool `synthesize`; observe it propagate to the EpiGraph kernel as a noun-claim with the synthesis entity type.
- **Common errors.** Missing sqlx CLI (`cargo install sqlx-cli --no-default-features --features postgres,native-tls`); migration order violations (running episcience migrations against a DB without the EpiGraph kernel schema); missing kernel functions (`cascade_delete_edges`, `validate_edge_reference`) — symptom is a CREATE TRIGGER or REFERENCES failure mid-migration; port collision with `epigraph-api`.

### 6.9 Episcience `docs/intro/02-concepts-science.md` (~300 lines)

Six sub-sections, each 40-60 lines:
1. **Experiments and experiment-results.** The experimental loop tables and their relationship to claims.
2. **Samples.** Physical or digital artifacts referenced by claims; the `samples_parent_restrict` semantics from migration 5009.
3. **Protocols.** Versioned procedures; the `protocol_version_unique` constraint from migration 5008.
4. **Blobs.** Binary attachments to claims; size/content-type semantics.
5. **Countersignatures.** Multi-party signing chains; how `countersign_chain` (migration 5010) extends the kernel's single-signer model.
6. **Synthesis claims and PROV-O edges.** How episcience separates 5 epistemic edge types from 4 PROV-O dependency edges in a separate table (memory `reference_episcience_edge_separation.md`). Why this matters for downstream consumers.

### 6.10 Episcience `docs/intro/03-walkthroughs.md` (~300 lines)

Three transcripts. (Note: there is no `experiments` route or table in episcience today; the surface exposed is samples, protocols, blobs, syntheses, countersignatures, and the `synthesize` / `recall_synthesis` / `get_synthesis` / `list_syntheses` MCP tools. Walkthroughs use only what's actually implemented.)

- **Walk 1: Stage and synthesize.** Create a sample (`POST /samples`), register a protocol (`POST /protocols`), then call the `synthesize` MCP tool to produce a synthesis claim that references the sample and protocol IDs. Observe the resulting EpiGraph noun-claim with the synthesis entity type.
- **Walk 2: Countersign.** Take Walk 1's synthesis claim; produce a countersignature from a second agent identity via the `countersign` route; observe the chain.
- **Walk 3: Multi-source synthesis.** Create three independent samples; produce three separate synthesis claims; then call `synthesize` to produce a higher-level synthesis that PROV-O-derives from the three; observe the resulting node and edges in the kernel via `recall_synthesis` and `get_synthesis`.

### 6.11 Episcience `docs/intro/04-glossary.md` (~60 lines)

Alphabetical, science-specific terms only: blob, countersignature, experiment, experiment-result, PROV-O, protocol, sample, synthesis claim. Kernel terms link back to EpiGraph's glossary.

## 7. Implementation order

1. Build and verify the EpiGraph quickstart steps locally (some commands may need adjustment from the design above based on what actually works against a clean install).
2. Write the EpiGraph intro tree files in order: glossary first (so other files can link to it), then concepts, then quickstart, then walkthroughs, then next-steps.
3. Write the EpiGraph `README.md` last (so its TOC reflects the actually-written files).
4. Run the four EpiGraph walkthroughs against the local install. Capture real transcripts. Replace the stubbed examples in `03-walkthroughs.md` with the captured output.
5. Repeat steps 1-4 for episcience: verify the extension quickstart, write glossary → concepts → quickstart → walkthroughs, capture transcripts, write README last.
6. Cross-link: ensure every "see X" link resolves, both within each repo and across repos (cross-repo links use github.com URLs since both repos are public).
7. Commit each repo's new files in a single PR per repo; PR descriptions point reviewers to the README first.

## 8. Verification

- A volunteer (not Jeremy) clones each repo cold, follows only the written instructions, and reports time-to-first-`recall_with_context` for EpiGraph and time-to-first-synthesis-claim for episcience. Targets: ≤15 minutes and ≤25 minutes respectively (≤10/≤5 from the design goals plus generous slack for prereq installation).
- Every link in every new file is checked with a Markdown link-checker.
- The walkthroughs are re-run against a fresh DB after each non-trivial epigraph or episcience release to catch drift; failures file a backlog item per CLAUDE.md.

## 9. Risks and mitigations

- **Risk: Tooling drifts faster than docs.** Mitigation: the walkthroughs are runnable transcripts, not free prose. A periodic re-run (suggested: a scheduled `loop` agent doing the four EpiGraph walkthroughs nightly) catches drift. Out of scope for this initial doc-writing pass but flagged in `05-next-steps.md` as a future hardening.
- **Risk: PostgreSQL version / pgvector install friction dominates time-to-first-call.** Mitigation: link to canonical pgvector install instructions per OS; do not duplicate them. If feedback shows this is the actual bottleneck, future work adds a `docker-compose.yml` (out of scope here).
- **Risk: Episcience migrations break against an arbitrary EpiGraph rev.** Mitigation: the episcience quickstart explicitly pins to the rev recorded in episcience `Cargo.toml`'s `[workspace.dependencies]` block; the quickstart instructs users to clone EpiGraph at that rev. Drift between latest-EpiGraph and pinned-EpiGraph is a known constraint per the existing `Cargo.toml` comment.
- **Risk: New users don't have an OpenAI key and bounce.** Mitigation: the quickstart's prereq list calls this out *before* any clone/build steps. `recall_with_context` embeds the query string on every call and so requires `OPENAI_API_KEY` even against an empty corpus — no fallback path exists today. If a no-key onboarding mode becomes a recurring ask, it's a feature request against `epigraph-mcp` (out of scope here); the quickstart explicitly notes the key as mandatory rather than papering over the constraint.
