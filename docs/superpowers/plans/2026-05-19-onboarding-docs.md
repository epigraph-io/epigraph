# Onboarding Docs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a top-level `README.md` and a `docs/intro/` tree in both `epigraph` and `episcience` so new collaborators can go from `git clone` to a successful MCP `recall_with_context` call in ~10 minutes, and complete the full onboarding (concepts + walkthroughs) in ~1-2 hours.

**Architecture:** Each repo gets a short README landing page (pitch + 5-min quickstart + TOC) plus a numbered `docs/intro/{01-quickstart,02-concepts,03-walkthroughs,04-glossary,05-next-steps}.md` tree. Episcience's tree assumes EpiGraph familiarity and links back to it rather than restating kernel material.

**Tech Stack:** Markdown, the EpiGraph kernel + MCP server, the Episcience extension + MCP server, the `sqlx-cli` for episcience migrations, Claude Code as the MCP client.

**Source spec:** `docs/superpowers/specs/2026-05-19-onboarding-docs-design.md` — every content requirement traces back to that doc; consult it for the full §6 file outlines.

---

## File Structure

### Phase A — EpiGraph (`/home/jeremy/epigraph/`)
- **Create:** `README.md` — ~150 lines, landing page, written last (after intro tree is real)
- **Create:** `docs/intro/04-glossary.md` — ~100 lines, written first so other files can link to entries
- **Create:** `docs/intro/02-concepts.md` — ~400 lines, six sub-sections
- **Create:** `docs/intro/01-quickstart.md` — ~200 lines, written after concepts so it can link to definitions
- **Create:** `docs/intro/03-walkthroughs.md` — ~500 lines, populated from captured live MCP transcripts
- **Create:** `docs/intro/05-next-steps.md` — ~80 lines

### Phase B — Episcience (`/home/jeremy/episcience/`)
- **Create:** `README.md` — ~80 lines
- **Create:** `docs/intro/04-glossary.md` — ~60 lines, science-specific terms only
- **Create:** `docs/intro/02-concepts-science.md` — ~300 lines, six sub-sections
- **Create:** `docs/intro/01-quickstart-extension.md` — ~150 lines, assumes Phase A complete
- **Create:** `docs/intro/03-walkthroughs.md` — ~300 lines, three captured transcripts
- *(No `05-next-steps.md` in episcience — keep it minimal; episcience README links back to EpiGraph's next-steps)*

### Phase C — Cross-cutting
- Link check both trees
- Open PRs (one per repo)

---

## Working assumptions

1. The implementer has a working Postgres 16+ with pgvector available locally, and the EpiGraph + Episcience repos cloned at `/home/jeremy/epigraph/` and `/home/jeremy/episcience/`.
2. The implementer has Claude Code installed and authenticated, with `OPENAI_API_KEY` set in their environment for embedding calls during walkthroughs.
3. Both repos already have a non-main feature branch checked out (e.g. `spec/cross-source-anchor` carrying the spec commit on EpiGraph). Create a new branch off the current branch for the implementation work — see Task A0 / B0.
4. If at any point a walkthrough fails because the live system behaves differently from the spec's expected output, **stop and document the discrepancy as a backlog item via `resolve_backlog_item`-friendly free text** ("backlog: docs walkthrough N expected X, got Y") — do not silently massage the docs to match broken behavior. The whole point of writing live transcripts is to catch drift between docs and reality.

---

## Phase A — EpiGraph

### Task A0: Branch and verify build

**Files:**
- None (environment-only)

- [ ] **Step 1: Create a feature branch**

```bash
cd /home/jeremy/epigraph
git checkout -b docs/onboarding-tree
```

- [ ] **Step 2: Verify the build commands the spec's quickstart will recommend**

```bash
cargo build --release -p epigraph-api -p epigraph-mcp -p epigraph-cli
```

Expected: success. If it fails, fix the build before writing docs that tell new users to run this exact command.

- [ ] **Step 3: Verify the binary names**

```bash
ls target/release/ | grep -E "epigraph-(api|mcp|migrate|server)"
```

Expected: at minimum `epigraph-mcp-full`, `server`, `epigraph-migrate` appear. Confirms the spec's §6.2 Step 5 corrections are accurate. If any expected binary is missing or renamed, update the spec FIRST, then come back to this plan.

- [ ] **Step 4: Verify the health endpoint**

Start the API:
```bash
DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph cargo run --release -p epigraph-api --bin server
```

In another shell:
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/health
```

Expected: `200`. If non-200 or wrong path, update the spec, then update Task A4 below.

- [ ] **Step 5: Stop the server (Ctrl-C in the first shell)**

No commit yet — this task only validates the environment.

---

### Task A1: Glossary (`docs/intro/04-glossary.md`)

**Files:**
- Create: `/home/jeremy/epigraph/docs/intro/04-glossary.md`

- [ ] **Step 1: Create the directory and seed the file**

```bash
mkdir -p /home/jeremy/epigraph/docs/intro
```

Write the glossary file with alphabetical entries for the following terms (each 2-4 sentences, ending with a cross-reference link to the file where the concept is explained in depth — when those files don't exist yet, leave the link as `[see 02-concepts.md §X.Y](02-concepts.md)` and refine after concepts is written):

```
agent, atom, BetP, challenge, claim, content_hash, DST, edge, evidence,
factor, frame, hierarchical extraction, MCP, methodology, noun-claim,
paragraph, perspective, pignistic probability, provenance, recall,
signature, supports, synthesis, theme, verb-edge, workflow
```

For terms that are defined in canonical existing docs, paraphrase the canonical definition and link to it. Specifically:
- **noun-claim, verb-edge** → link to `docs/architecture/noun-claims-and-verb-edges.md`
- **backlog (under "label")** → link to `docs/conventions/backlog-retirement.md`
- **BetP, pignistic probability** → reference the LANL Open World DST paper (see user memory `reference_lanl_open_world_dst.md`)

Use this header at the top:

```markdown
# Glossary

Concise definitions for the vocabulary used throughout EpiGraph. Terms are listed alphabetically; each entry links to the file where the concept is treated in depth.

---
```

- [ ] **Step 2: Verify the file renders**

Open the file and confirm each entry is 2-4 sentences and each entry has a working internal link or "(defined in this file)" if standalone.

- [ ] **Step 3: Commit**

```bash
git add docs/intro/04-glossary.md
git commit -m "docs(intro): glossary of core EpiGraph terms"
```

---

### Task A2: Concepts (`docs/intro/02-concepts.md`)

**Files:**
- Create: `/home/jeremy/epigraph/docs/intro/02-concepts.md`
- Reference (read, do not modify): `/home/jeremy/epigraph/docs/architecture/noun-claims-and-verb-edges.md`, `/home/jeremy/epigraph/docs/conventions/backlog-retirement.md`

- [ ] **Step 1: Outline the six sub-sections**

The file has six numbered sub-sections per spec §6.3, each 50-80 lines:

1. Noun-claims vs verb-edges
2. Agents and signing
3. Beliefs and DST
4. Perspectives, frames, themes
5. Hierarchical extraction
6. Backlog discipline

Each sub-section ends with a "See also" line pointing to the canonical deeper doc (architecture, conventions, or a memory reference).

- [ ] **Step 2: Write sub-section 1 (Noun-claims vs verb-edges)**

Source material: `docs/architecture/noun-claims-and-verb-edges.md` (read the full file). For the intro version: state the rule (a `claims` row = noun, an `edges` row = verb event), give the textbook-ingest worked example abbreviated to ~15 lines, list the three rules that fall out of the pattern, and link to the full architecture doc for the migration history. Do NOT include schema details.

- [ ] **Step 3: Write sub-section 2 (Agents and signing)**

Cover: every claim is signed with Ed25519 by an agent; agent identity is deterministic (DID from model+prompt hash — see user memory `project_epigraph_agent_identity.md` for the architectural decision); claim and edge signatures use the same audit guarantee. Show an example agent_id format. Mention that the OAuth mint flow (separate from agent identity) lives at `scripts/mint_epigraph_token.py` — link, do not duplicate.

- [ ] **Step 4: Write sub-section 3 (Beliefs and DST)**

Cover: BetP (pignistic probability) is the canonical belief score; scalar BP is deprecated (multiplicative collapse — see user memory `project_bp_cdst_primary.md` and `feedback_pignistic_not_bayesian.md`); show what a `get_belief` JSON response looks like with BetP and discounting. Reference the LANL Open World DST paper for the formal foundation (LA-UR-25-23655 per user memory). Keep math at the level of "BetP is a single number in [0,1] derived from a mass function" — full DST goes in deeper docs.

- [ ] **Step 5: Write sub-section 4 (Perspectives, frames, themes)**

Cover: a frame is a discernment scope, a perspective is a viewpoint that filters or weights claims, a theme is a topical grouping derived from clustering. Show how an MCP call like `mcp__epigraph__list_perspectives` returns viewpoints, and how a claim can be member of multiple themes via `claim_themes`. Keep it conceptual; reserve API details for walkthroughs.

- [ ] **Step 6: Write sub-section 5 (Hierarchical extraction)**

Cover: documents are extracted as a tree (paper → paragraphs → atoms); paragraphs (`(properties->>'level')::int = 2`) are the primary search target (recall_with_context uses paragraph-primary semantic search per `crates/epigraph-mcp/src/tools/recall.rs`); Tier 1 hierarchical extraction is the only canonical ingest path (user memory `feedback_tier1_ingestion_only.md`); Jina embeddings in the primary column break search and must be avoided.

- [ ] **Step 7: Write sub-section 6 (Backlog discipline)**

Cover: backlog items are claims with `labels=["backlog"]`; resolve via `resolve_backlog_item(original_id, resolution_content)` which creates a resolution claim AND patches the original's labels in one call; do NOT use `supersedes` (reserved for epistemic claim replacement) or raw `update_labels` (bypasses the resolution trail). Show the canonical "query open backlog" snippet from `CLAUDE.md`. Link to `docs/conventions/backlog-retirement.md` for the full spec.

- [ ] **Step 8: Add a top-of-file table-of-contents**

After the title and one-paragraph intro, add an anchored TOC linking to each of the six sub-sections. Use slug-style anchors matching the sub-section headings.

- [ ] **Step 9: Update glossary back-references**

Open `docs/intro/04-glossary.md` and replace any placeholder `[see 02-concepts.md §X.Y]` links with the actual anchors created in Step 8.

- [ ] **Step 10: Commit**

```bash
git add docs/intro/02-concepts.md docs/intro/04-glossary.md
git commit -m "docs(intro): concepts file covering noun-claims, DST, perspectives, hierarchy, backlog"
```

---

### Task A3: Quickstart (`docs/intro/01-quickstart.md`)

**Files:**
- Create: `/home/jeremy/epigraph/docs/intro/01-quickstart.md`

- [ ] **Step 1: Write the prereqs section**

Title the file `# Quickstart` and start with a prereqs list:

```markdown
## Prerequisites

- **Rust** ≥ 1.75 (`rustup show` to check)
- **PostgreSQL** 16+ with the `pgvector` extension installed and available (`SELECT extname FROM pg_extension;` should be runnable as a superuser)
- **Claude Code** installed and authenticated (the MCP client we'll use to drive EpiGraph)
- **OpenAI API key** — exported as `OPENAI_API_KEY`. **Mandatory** for the walkthroughs: `recall_with_context` embeds the query string on every call (see `crates/epigraph-mcp/src/tools/recall.rs`) and fails without a configured embedding provider, even against an empty corpus.
- **~$5 of OpenAI credit** for the embedding calls in the walkthroughs

Time budget: ~10 minutes to first MCP call if your prereqs are in place; ~30 minutes including a fresh Postgres/pgvector install.
```

- [ ] **Step 2: Write Step 1 (Postgres)**

```markdown
## Step 1 — PostgreSQL

```bash
# As a Postgres superuser:
createuser epigraph -P  # set password to 'epigraph' (or any password you wire into DATABASE_URL)
createdb -O epigraph epigraph
psql -d epigraph -c "CREATE EXTENSION IF NOT EXISTS vector;"
```

The runtime role does NOT need `SUPERUSER`. If you also intend to run the test suite (`sqlx::test`), grant `SUPERUSER` temporarily or use a separate test-only role — `sqlx::test` `LOCK`s `pg_namespace` and requires it (see `feedback_sqlx_test_uses_superuser` memory note).

Set the connection string:

```bash
export DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph
```
```

- [ ] **Step 3: Write Step 2 (Clone and build)**

```markdown
## Step 2 — Clone and build

```bash
git clone https://github.com/epigraph-io/epigraph.git
cd epigraph
cargo build --release -p epigraph-api -p epigraph-mcp -p epigraph-cli
```

Note: the `epigraph-mcp` package produces a binary named `epigraph-mcp-full` (see `crates/epigraph-mcp/Cargo.toml`'s `[[bin]]` entry). That's the binary you'll register with Claude Code in Step 5.
```

- [ ] **Step 4: Write Step 3 (Migrations)**

```markdown
## Step 3 — Migrations

```bash
cargo run --release --bin epigraph-migrate
```

This runs all 32 kernel migrations from `migrations/` (currently `001_initial_schema.sql` through `032_claim_themes_properties.sql`). For a fresh database this should complete in under a minute. If you're applying migrations to a pre-existing production database that was previously tracked under the internal-repo numbering, see the one-shot reconcile procedure in `docs/deploy.md` before running this step.
```

- [ ] **Step 5: Write Step 4 (Start the API)**

```markdown
## Step 4 — Start the API server

```bash
cargo run --release -p epigraph-api --bin server
```

In another shell, verify:

```bash
curl http://127.0.0.1:8080/health
```

Expected: `OK` (HTTP 200). The server logs its bound address; default is `127.0.0.1:8080`.
```

- [ ] **Step 6: Write Step 5 (Install MCP server)**

```markdown
## Step 5 — Install the MCP server and register it with Claude Code

Option A: copy the built binary to a path on your `$PATH` (matching the `~/.mcp.json` pattern used in this repo's deployment):

```bash
sudo cp target/release/epigraph-mcp-full /usr/local/bin/epigraph-mcp
```

Option B: `cargo install` it (installed binary is named `epigraph-mcp-full`):

```bash
cargo install --path crates/epigraph-mcp
```

Register the server in `~/.mcp.json` (creating the file if it doesn't exist). Use the exact path you installed to:

```json
{
  "mcpServers": {
    "epigraph": {
      "command": "/usr/local/bin/epigraph-mcp",
      "args": [
        "--database-url", "postgres://epigraph:epigraph@localhost:5432/epigraph"
      ],
      "env": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}",
        "EPIGRAPH_API_URL": "http://127.0.0.1:8080"
      }
    }
  }
}
```

If you used Option B and didn't rename the binary, change `"command"` to `"/home/youruser/.cargo/bin/epigraph-mcp-full"`.
```

- [ ] **Step 7: Write Step 6 (First MCP call)**

```markdown
## Step 6 — Your first MCP call

Open Claude Code (in any working directory). Tell it:

> Use the `recall_with_context` MCP tool to search for "test".

Claude should call `mcp__epigraph__recall_with_context({"query": "test"})` and you should see a JSON response with a `corpus_scope` object showing zero claims, paragraphs, papers, and themes (assuming a fresh database).

Next, ask:

> Use `submit_claim` to add this claim: "EpiGraph is installed correctly."

Claude calls `mcp__epigraph__submit_claim(...)` and returns the created claim's UUID. Call `recall_with_context "installed"` again — you should now see the freshly submitted claim in the results.

If you see the claim, your install is working end-to-end.
```

- [ ] **Step 8: Write the Common Errors section**

```markdown
## Common errors

| Symptom | Fix |
|---|---|
| `sqlx checksum mismatch` at startup | See the reconcile procedure in `docs/deploy.md`; this only happens against a pre-existing internal-numbered DB. |
| `Connection refused (os error 111)` on port 5432 | Postgres isn't running. `pg_isready` to check; start it (`brew services start postgresql@16`, `sudo systemctl start postgresql`, etc.). |
| `extension "vector" is not available` | Install pgvector — see https://github.com/pgvector/pgvector#installation for OS-specific instructions. |
| `OPENAI_API_KEY not set` from MCP server | Export the env var in the shell that launches Claude Code, or hardcode the value in `~/.mcp.json` (less secure). |
| Claude Code can't find the MCP tool | `~/.mcp.json` path wrong, or you renamed the binary inconsistently between the file and `cp`. Recheck the exact `"command"` value. |

## Tear-down

```bash
dropdb epigraph
```

Then drop the role with `dropuser epigraph` if reinstalling.
```

- [ ] **Step 9: Commit**

```bash
git add docs/intro/01-quickstart.md
git commit -m "docs(intro): six-step quickstart from clone to first MCP call"
```

---

### Task A4: Run Walkthrough 1 (Ingest a PDF) and capture transcript

**Files:**
- Create: `/tmp/walkthrough-1-transcript.md` (scratch, not committed)
- Modify (later in Task A8): `/home/jeremy/epigraph/docs/intro/03-walkthroughs.md`

- [ ] **Step 1: Acquire a small public-domain PDF**

Use a short paper. Suggestion: a 2-page arXiv preprint or a public-domain physics note. Save to `/tmp/walkthrough-1-paper.pdf`.

- [ ] **Step 2: Open Claude Code with the EpiGraph MCP server registered**

Confirm the MCP tools are available:

```
Ask Claude: "List the EpiGraph MCP tools you have available."
```

Expected: Claude reports tools including `recall_with_context`, `submit_claim`, `ingest_document`, `query_paper`, `system_stats`.

- [ ] **Step 3: Run the ingest**

```
Ask Claude: "Call mcp__epigraph__ingest_document with path '/tmp/walkthrough-1-paper.pdf'."
```

Capture the response: a job ID and a "queued" status.

- [ ] **Step 4: Poll for completion**

```
Ask Claude: "Call mcp__epigraph__system_stats every 30 seconds until the document is fully ingested."
```

Capture the progression of stats: claim count goes from N to N+M as paragraphs and atoms are added.

- [ ] **Step 5: Query the resulting claims**

```
Ask Claude: "Call mcp__epigraph__query_paper with the document path or DOI."
```

Capture the returned tree of paragraph + atom claims.

- [ ] **Step 6: Save the transcript to `/tmp/walkthrough-1-transcript.md`**

Copy the exact Claude Code session — the prompts, the tool calls, the JSON responses (truncated to ~10 lines per response with a `…` marker if longer). Add a one-paragraph "what just happened" closing that ties back to concepts §5 (hierarchical extraction).

- [ ] **Step 7: Verify the transcript is reproducible**

Re-read it. Could a new user paste each prompt into Claude Code and get something morally equivalent? If not, edit the transcript prompts to be more deterministic (specify exact tool names rather than relying on Claude to guess).

No commit yet — Task A8 commits the combined walkthroughs file.

---

### Task A5: Run Walkthrough 2 (Query and expand) and capture transcript

**Files:**
- Create: `/tmp/walkthrough-2-transcript.md`

- [ ] **Step 1: Pick a topic from Walkthrough 1's paper**

Choose a substantive phrase from the paper (e.g. "boundary condition", "neutron diffusion", whatever the paper is actually about).

- [ ] **Step 2: Run recall_with_context**

```
Ask Claude: "Call mcp__epigraph__recall_with_context with query '<your phrase>'."
```

Capture the response.

- [ ] **Step 3: Pick the top hit and expand its neighborhood**

```
Ask Claude: "Call mcp__epigraph__get_neighborhood on claim <id of top hit>."
```

Capture the response showing connected claims, edges, and (if present) the paragraph parent and atom siblings.

- [ ] **Step 4: Traverse two hops out**

```
Ask Claude: "Call mcp__epigraph__traverse from claim <id> with max_depth 2."
```

Capture the traversal result.

- [ ] **Step 5: Save the transcript to `/tmp/walkthrough-2-transcript.md`**

Same format as Walkthrough 1; closing paragraph ties back to concepts §4 (perspectives/frames/themes).

---

### Task A6: Run Walkthrough 3 (Challenge a claim) and capture transcript

**Files:**
- Create: `/tmp/walkthrough-3-transcript.md`

- [ ] **Step 1: Pick a claim from Walkthrough 1**

Any non-trivial claim is fine.

- [ ] **Step 2: Challenge it**

```
Ask Claude: "Call mcp__epigraph__challenge_claim on claim <id> with reason 'Counter-evidence: <plausible alternative interpretation>'."
```

Capture the response: a challenge record with its own ID and status.

- [ ] **Step 3: List challenges to confirm**

```
Ask Claude: "Call mcp__epigraph__list_challenges to see all open challenges."
```

Capture the list including the just-filed challenge.

- [ ] **Step 4: Verify the original claim despite the challenge**

```
Ask Claude: "Call mcp__epigraph__verify_claim on claim <id> with verification 'Holds: <reason>'."
```

Capture the verification record.

- [ ] **Step 5: Save the transcript to `/tmp/walkthrough-3-transcript.md`**

Closing paragraph ties to concepts §3 (DST belief updates under challenge/verification).

---

### Task A7: Run Walkthrough 4 (Backlog roundtrip) and capture transcript

**Files:**
- Create: `/tmp/walkthrough-4-transcript.md`

- [ ] **Step 1: File a backlog item**

```
Ask Claude: "Call mcp__epigraph__submit_claim with content 'backlog: example task for the docs walkthrough' and labels ['backlog']."
```

Capture the created claim's ID — call it `<orig>`.

- [ ] **Step 2: Query open backlog**

```
Ask Claude: "Call mcp__epigraph__query_claims_by_label with labels ['backlog'], exclude_labels ['resolved'], current_only true."
```

Capture the response; confirm `<orig>` appears in the list.

- [ ] **Step 3: Resolve it**

```
Ask Claude: "Call mcp__epigraph__resolve_backlog_item with original_id '<orig>' and resolution_content 'Done as part of the docs intro walkthrough.'"
```

Capture the response (a new resolution claim, AND the original's labels now include `["resolved"]`).

- [ ] **Step 4: Re-query open backlog**

```
Ask Claude: "Call mcp__epigraph__query_claims_by_label with labels ['backlog'], exclude_labels ['resolved'], current_only true."
```

Confirm `<orig>` no longer appears.

- [ ] **Step 5: Save the transcript to `/tmp/walkthrough-4-transcript.md`**

Closing paragraph ties to concepts §6 (backlog discipline) and links to `docs/conventions/backlog-retirement.md`.

---

### Task A8: Assemble walkthroughs file (`docs/intro/03-walkthroughs.md`)

**Files:**
- Create: `/home/jeremy/epigraph/docs/intro/03-walkthroughs.md`
- Read: the four `/tmp/walkthrough-N-transcript.md` files from Tasks A4-A7

- [ ] **Step 1: Write the file header and TOC**

```markdown
# Walkthroughs

Four end-to-end Claude Code sessions showing the EpiGraph MCP tools in action against a freshly initialized database. Each walkthrough is a verbatim transcript — prompts, tool calls, and responses — so you can paste each step into your own Claude Code session and see the same shape of response.

## Table of contents

1. [Ingest a PDF](#walkthrough-1--ingest-a-pdf)
2. [Query and expand](#walkthrough-2--query-and-expand)
3. [Challenge a claim](#walkthrough-3--challenge-a-claim)
4. [Backlog roundtrip](#walkthrough-4--backlog-roundtrip)

Each walkthrough ends with a short "what just happened" paragraph linking back to the relevant section in [02-concepts.md](02-concepts.md).

---
```

- [ ] **Step 2: Paste in Walkthrough 1**

Take `/tmp/walkthrough-1-transcript.md` and paste under a `## Walkthrough 1 — Ingest a PDF` heading. Format prompts as block quotes and JSON responses as fenced code blocks.

- [ ] **Step 3: Paste in Walkthrough 2**

Same format, under `## Walkthrough 2 — Query and expand`.

- [ ] **Step 4: Paste in Walkthrough 3**

Under `## Walkthrough 3 — Challenge a claim`.

- [ ] **Step 5: Paste in Walkthrough 4**

Under `## Walkthrough 4 — Backlog roundtrip`.

- [ ] **Step 6: Verify the file is under ~600 lines and all links work**

```bash
wc -l /home/jeremy/epigraph/docs/intro/03-walkthroughs.md
```

- [ ] **Step 7: Commit**

```bash
git add docs/intro/03-walkthroughs.md
git commit -m "docs(intro): four end-to-end walkthroughs captured live"
```

---

### Task A9: Next-steps (`docs/intro/05-next-steps.md`)

**Files:**
- Create: `/home/jeremy/epigraph/docs/intro/05-next-steps.md`

- [ ] **Step 1: Write the file**

```markdown
# Next steps

You've completed the EpiGraph onboarding. Where to from here depends on what you want to do.

## Extending the kernel

If you want to add features to EpiGraph itself, start with [`CLAUDE.md`](../../CLAUDE.md) — it documents the agent conventions (backlog retirement, schema/migrations, claim mechanics, the test database recipe, the `cargo sqlx prepare` workflow). The architecture pattern that governs how new writers should behave is [`docs/architecture/noun-claims-and-verb-edges.md`](../architecture/noun-claims-and-verb-edges.md).

## Adding science-specific tooling

If your use case involves experiments, protocols, samples, blobs, countersignatures, or synthesis claims, you want the **episcience** layer on top of the kernel. See https://github.com/epigraph-io/episcience.

## Deploying in production

See [`docs/deploy.md`](../deploy.md) for the deploy runbook including the 2026-05-05 sqlx-migrations reconcile procedure.

## Building a downstream application

The reference pattern for depending on EpiGraph from another Rust project is the [episcience `Cargo.toml`](https://github.com/epigraph-io/episcience/blob/main/Cargo.toml) — it pins specific epigraph crates to a known-good git rev and documents how to swap in local paths for development via `~/.cargo/config.toml` (not the committed `Cargo.toml`).

If you'll run multiple concurrent Claude Code sessions against the same repo, set up git worktrees per the pattern described in the user-level "use git worktrees" memory note — sessions sharing a single working tree collide on branch state.
```

- [ ] **Step 2: Commit**

```bash
git add docs/intro/05-next-steps.md
git commit -m "docs(intro): next-steps with contributor, deploy, and downstream pointers"
```

---

### Task A10: README (`README.md`)

**Files:**
- Create: `/home/jeremy/epigraph/README.md`

- [ ] **Step 1: Write the file**

```markdown
# EpiGraph

An epistemic kernel: claims (nouns), edges (verbs), agents that cryptographically sign their assertions, and beliefs propagated via Dempster-Shafer evidence combination. EpiGraph replaces the static-paper model of knowledge with a live loop — hypothesis → experiment → data → analysis → belief update — that downstream applications can interrogate, challenge, and extend.

Where most knowledge bases store *what is currently believed*, EpiGraph stores *what each agent has asserted, with what evidence, signed under what identity, and how those assertions combine into a defensible belief*. It is the substrate the rest of the epigraph-io stack builds on.

## Who is this for?

- **Developers** integrating EpiGraph into an application (build with the Rust crates, talk via the HTTP API, drive via the MCP server)
- **Researchers and analysts** querying the graph via Claude Code (the MCP tools cover recall, neighborhood traversal, challenge/verify, backlog management)
- **Contributors** extending the kernel itself (see [`CLAUDE.md`](CLAUDE.md))

## Status

- Version: 0.3.0
- License: Apache-2.0
- Maturity: alpha — kernel schema and core primitives are stable; layers built on top (workflows, hierarchical extraction, perspectives) iterate

## 5-minute quickstart

```bash
# 1. PostgreSQL with pgvector
createuser epigraph -P && createdb -O epigraph epigraph
psql -d epigraph -c "CREATE EXTENSION vector;"
export DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph

# 2. Build
git clone https://github.com/epigraph-io/epigraph.git && cd epigraph
cargo build --release -p epigraph-api -p epigraph-mcp

# 3. Migrate + start API
cargo run --release --bin epigraph-migrate
cargo run --release -p epigraph-api --bin server &

# 4. Install MCP server
sudo cp target/release/epigraph-mcp-full /usr/local/bin/epigraph-mcp

# 5. Add this to ~/.mcp.json
# {
#   "mcpServers": {
#     "epigraph": {
#       "command": "/usr/local/bin/epigraph-mcp",
#       "args": ["--database-url", "postgres://epigraph:epigraph@localhost:5432/epigraph"],
#       "env": { "OPENAI_API_KEY": "${OPENAI_API_KEY}", "EPIGRAPH_API_URL": "http://127.0.0.1:8080" }
#     }
#   }
# }

# 6. Open Claude Code and ask it to call mcp__epigraph__recall_with_context with query "test".
```

If that works, head to the [full quickstart](docs/intro/01-quickstart.md) for explanations and common-error coverage.

## Onboarding tree

- [`docs/intro/01-quickstart.md`](docs/intro/01-quickstart.md) — six-step setup, prereqs, troubleshooting
- [`docs/intro/02-concepts.md`](docs/intro/02-concepts.md) — noun-claims/verb-edges, agents and signing, DST beliefs, perspectives, hierarchical extraction, backlog discipline
- [`docs/intro/03-walkthroughs.md`](docs/intro/03-walkthroughs.md) — four end-to-end Claude Code transcripts
- [`docs/intro/04-glossary.md`](docs/intro/04-glossary.md) — vocabulary
- [`docs/intro/05-next-steps.md`](docs/intro/05-next-steps.md) — contributor, deploy, and downstream pointers

## Deeper material

- [`docs/architecture/noun-claims-and-verb-edges.md`](docs/architecture/noun-claims-and-verb-edges.md) — the canonical pattern for what gets stored as a claim vs an edge
- [`docs/conventions/backlog-retirement.md`](docs/conventions/backlog-retirement.md) — how operational backlog items are resolved
- [`docs/deploy.md`](docs/deploy.md) — production deploy runbook
- [`CLAUDE.md`](CLAUDE.md) — agent-session conventions (backlog, schema, tests, workflow)
- [`scripts/README.md`](scripts/README.md) — operational maintenance scripts
```

- [ ] **Step 2: Verify the 5-minute quickstart block matches what you actually ran in Task A0**

If anything in the build/run sequence has changed since Task A0 (binary names, ports, env vars), update the README before committing.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: top-level README with pitch, 5-minute quickstart, and intro tree TOC"
```

---

### Task A11: Link check Phase A

**Files:**
- None modified unless broken links found

- [ ] **Step 1: Install a markdown link checker if not already present**

```bash
cargo install mlc  # markdown-link-check, written in Rust
# OR: npm install -g markdown-link-check
```

- [ ] **Step 2: Run on every file in the EpiGraph intro tree and README**

```bash
cd /home/jeremy/epigraph
mlc README.md docs/intro/*.md
```

- [ ] **Step 3: Fix any broken links**

For each reported broken link, either correct the path or remove the link. Commit fixes as `docs: fix broken links found in Phase A link check`.

- [ ] **Step 4: Commit if fixes were made**

If no fixes were needed, skip the commit and proceed to Phase B.

---

## Phase B — Episcience

### Task B0: Branch and verify build

**Files:**
- None (environment-only)

- [ ] **Step 1: Create a feature branch on episcience**

```bash
cd /home/jeremy/episcience
git checkout -b docs/onboarding-tree
```

- [ ] **Step 2: Verify the build**

```bash
cargo build --release -p episcience-api
```

Expected: success. The episcience workspace pins specific epigraph crates by git rev in `Cargo.toml` — if the build fails because the pin is incompatible with the kernel migrations you applied in Task A3, update the pin first (or apply the local `[patch]` override via `~/.cargo/config.toml`).

- [ ] **Step 3: Verify the binaries**

```bash
ls target/release/ | grep -E "episcience-(server|mcp-server)"
```

Expected: both binaries present. If a binary name differs, update the spec and this plan before proceeding.

- [ ] **Step 4: Verify sqlx-cli is installed**

```bash
sqlx --version
```

If not installed: `cargo install sqlx-cli --no-default-features --features postgres,native-tls`.

- [ ] **Step 5: Apply episcience migrations against the kernel DB from Phase A**

```bash
cd /home/jeremy/episcience
sqlx migrate run --source migrations/ --database-url postgres://epigraph:epigraph@localhost/epigraph
```

Expected: success. If a migration fails with "function does not exist" or "relation does not exist", the kernel migrations weren't applied first — go back to Task A3.

- [ ] **Step 6: Start episcience-server on a separate port**

```bash
EPISCIENCE_PORT=8090 DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph \
  cargo run --release -p episcience-api --bin episcience-server
```

Verify: `curl http://127.0.0.1:8090/health` returns 200.

- [ ] **Step 7: Stop the server**

No commit yet.

---

### Task B1: Glossary (`docs/intro/04-glossary.md`)

**Files:**
- Create: `/home/jeremy/episcience/docs/intro/04-glossary.md`

- [ ] **Step 1: Create the directory and write the glossary**

```bash
mkdir -p /home/jeremy/episcience/docs/intro
```

Write the file with entries for: `blob, countersignature, experiment, experiment-result, PROV-O, protocol, sample, synthesis claim`. Each entry 2-4 sentences. End each entry with a link back to either `02-concepts-science.md` or to the EpiGraph glossary for kernel terms.

Header:

```markdown
# Glossary (science-specific)

Vocabulary for episcience's experimental loop layer. For kernel terms (claim, edge, agent, BetP, etc.) see the [EpiGraph glossary](https://github.com/epigraph-io/epigraph/blob/main/docs/intro/04-glossary.md).

---
```

- [ ] **Step 2: Commit**

```bash
git add docs/intro/04-glossary.md
git commit -m "docs(intro): science-specific glossary"
```

---

### Task B2: Concepts (`docs/intro/02-concepts-science.md`)

**Files:**
- Create: `/home/jeremy/episcience/docs/intro/02-concepts-science.md`
- Read (do not modify): `/home/jeremy/episcience/migrations/*.sql` — the science layer tables and constraints

- [ ] **Step 1: Outline the six sub-sections per spec §6.9**

1. Experiments and experiment-results
2. Samples
3. Protocols
4. Blobs
5. Countersignatures
6. Synthesis claims and PROV-O edges

Each sub-section 40-60 lines. Opens with "This builds on the kernel concept of <noun-claim/edge/etc.> — see the [EpiGraph concepts](https://github.com/epigraph-io/epigraph/blob/main/docs/intro/02-concepts.md) for the kernel pattern."

- [ ] **Step 2: Write sub-section 1 (Experiments and experiment-results)**

Caveat: there's no `experiments` route or table in the current episcience surface (verified in spec review). Cover this honestly: describe the conceptual model (an experiment is a run-time instantiation of a protocol against a sample; an experiment-result is the observed outcome captured as a claim) and note that the current API surfaces this via synthesis claims that reference protocol and sample IDs — a future `experiments` endpoint is planned but not present today.

- [ ] **Step 3: Write sub-section 2 (Samples)**

Cover: a sample is a physical or digital artifact referenced by claims; samples can have parent relationships (one sample derived from another) but parent restriction enforced by migration `5009_samples_parent_restrict.sql` prevents circular lineage. Show a `POST /samples` request shape (read it from `crates/episcience-api/src/routes/samples.rs`).

- [ ] **Step 4: Write sub-section 3 (Protocols)**

Cover: protocols are versioned procedures; `5008_protocol_version_unique.sql` enforces `(name, version)` uniqueness. Show a `POST /protocols` request shape.

- [ ] **Step 5: Write sub-section 4 (Blobs)**

Cover: binary attachments to claims; content type and size are tracked; the `5005_create_blobs.sql` migration defines the schema. Show what's referenced and how (claims reference blob IDs).

- [ ] **Step 6: Write sub-section 5 (Countersignatures)**

Cover: multi-party signing chains via `5010_countersign_chain.sql`. A countersignature is a second (or third, etc.) agent's signature on a claim already signed by another agent. Useful for peer-review style attestation. Show the chain structure.

- [ ] **Step 7: Write sub-section 6 (Synthesis claims and PROV-O edges)**

Cover: a synthesis claim is a higher-level claim derived from one or more lower-level claims via PROV-O `wasDerivedFrom` relationships. Episcience separates 5 epistemic edge types from 4 PROV-O dependency edges in a separate table (user memory `reference_episcience_edge_separation.md`) — explain why this separation matters: epistemic edges describe what supports/refutes/etc.; PROV-O edges describe what derived/was-influenced-by/etc. The two semantics shouldn't be conflated.

- [ ] **Step 8: Add TOC at top, link from glossary entries**

Same pattern as Task A2 Steps 8-9.

- [ ] **Step 9: Commit**

```bash
git add docs/intro/02-concepts-science.md docs/intro/04-glossary.md
git commit -m "docs(intro): science-layer concepts covering samples, protocols, blobs, countersign, synthesis, PROV-O"
```

---

### Task B3: Quickstart-extension (`docs/intro/01-quickstart-extension.md`)

**Files:**
- Create: `/home/jeremy/episcience/docs/intro/01-quickstart-extension.md`

- [ ] **Step 1: Write the file**

```markdown
# Quickstart — episcience extension

This guide assumes you've completed the [EpiGraph quickstart](https://github.com/epigraph-io/epigraph/blob/main/docs/intro/01-quickstart.md) and have a running kernel on `postgres://epigraph:epigraph@localhost/epigraph` with the API listening on `127.0.0.1:8080`.

Time budget: ~5 minutes if the kernel is already running.

## Prerequisites

- A completed EpiGraph quickstart (kernel migrations applied, API server running)
- The [sqlx CLI](https://github.com/launchbadge/sqlx/tree/main/sqlx-cli) installed: `cargo install sqlx-cli --no-default-features --features postgres,native-tls`

## Step 1 — Clone episcience

```bash
git clone https://github.com/epigraph-io/episcience.git
cd episcience
```

The workspace pins specific epigraph crates by git rev in `Cargo.toml`. If you're hacking on the kernel locally too, override the pin in `~/.cargo/config.toml` (NOT in the committed `Cargo.toml`):

```toml
[patch."https://github.com/epigraph-io/epigraph"]
epigraph-core   = { path = "/home/youruser/epigraph/crates/epigraph-core" }
epigraph-crypto = { path = "/home/youruser/epigraph/crates/epigraph-crypto" }
epigraph-db     = { path = "/home/youruser/epigraph/crates/epigraph-db" }
epigraph-engine = { path = "/home/youruser/epigraph/crates/epigraph-engine" }
epigraph-cli    = { path = "/home/youruser/epigraph/crates/epigraph-cli" }
epigraph-jobs   = { path = "/home/youruser/epigraph/crates/epigraph-jobs" }
epigraph-events = { path = "/home/youruser/epigraph/crates/epigraph-events" }
epigraph-embeddings = { path = "/home/youruser/epigraph/crates/epigraph-embeddings" }
```

## Step 2 — Apply episcience migrations

```bash
sqlx migrate run --source migrations/ --database-url postgres://epigraph:epigraph@localhost/epigraph
```

This applies migrations `001_initial_schema.sql` through `5010_countersign_chain.sql` (and any synthesis/* migrations) onto the existing kernel DB. Ordering matters: the episcience migrations depend on kernel functions like `cascade_delete_edges` and `validate_edge_reference`, which the EpiGraph quickstart's kernel migrations (specifically 024-025) already created.

If you see a "function does not exist" or "relation does not exist" error, the kernel migrations weren't applied first — go back to the [EpiGraph Step 3](https://github.com/epigraph-io/epigraph/blob/main/docs/intro/01-quickstart.md#step-3--migrations).

## Step 3 — Build

```bash
cargo build --release -p episcience-api
```

This produces two binaries: `episcience-server` (HTTP API) and `episcience-mcp-server` (MCP for Claude Code).

## Step 4 — Start the API

```bash
EPISCIENCE_PORT=8090 DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph \
  cargo run --release -p episcience-api --bin episcience-server
```

In another shell:

```bash
curl http://127.0.0.1:8090/health
```

Expected: 200 OK.

## Step 5 — First synthesis claim

Add the episcience MCP server to `~/.mcp.json` alongside the existing epigraph entry:

```json
{
  "mcpServers": {
    "epigraph": { /* existing */ },
    "episcience": {
      "command": "/home/youruser/episcience/target/release/episcience-mcp-server",
      "env": {
        "DATABASE_URL": "postgres://epigraph:epigraph@localhost:5432/epigraph",
        "EPISCIENCE_API_URL": "http://127.0.0.1:8090"
      }
    }
  }
}
```

Open Claude Code and ask:

> Use mcp__episcience__synthesize to create a synthesis claim with content "Verification that episcience is installed" and no source claims.

You should see a created synthesis claim ID. Then:

> Use mcp__episcience__recall_synthesis with query "verification".

The synthesis claim should appear.

## Common errors

| Symptom | Fix |
|---|---|
| `function "cascade_delete_edges" does not exist` during migration | Kernel migrations not applied. Run EpiGraph Step 3 first. |
| `Address already in use` on 8090 | Pick a different `EPISCIENCE_PORT`. |
| MCP tool not found | Path in `~/.mcp.json` wrong, or Claude Code needs a restart to pick up the new server. |
| sqlx version mismatch error | `sqlx-cli` and the workspace `sqlx` dependency drift; usually `cargo install sqlx-cli --version 0.7` resolves it (match the workspace `Cargo.toml`). |
```

- [ ] **Step 2: Commit**

```bash
git add docs/intro/01-quickstart-extension.md
git commit -m "docs(intro): episcience extension quickstart assuming kernel installed"
```

---

### Task B4: Run Walkthrough 1 (Stage and synthesize) and capture

**Files:**
- Create: `/tmp/epi-walkthrough-1-transcript.md`

- [ ] **Step 1: Open Claude Code with both MCP servers registered**

Confirm `mcp__episcience__*` tools are available.

- [ ] **Step 2: Create a sample**

```
Ask Claude: "Make a POST to http://127.0.0.1:8090/samples with body {\"name\": \"docs-walkthrough-sample\", \"description\": \"Synthetic sample for documentation walkthrough\"}."
```

Capture the response with the new sample ID.

- [ ] **Step 3: Create a protocol**

```
Ask Claude: "Make a POST to http://127.0.0.1:8090/protocols with body {\"name\": \"docs-walkthrough-protocol\", \"version\": \"1.0.0\", \"description\": \"Read this paragraph and pretend you ran the protocol\"}."
```

Capture the response.

- [ ] **Step 4: Synthesize with sample and protocol references**

```
Ask Claude: "Call mcp__episcience__synthesize with content 'Sample <sample-id> processed via protocol <protocol-id> yielded result Y' and source_claim_ids [<sample-id>, <protocol-id>]."
```

Capture the resulting synthesis claim.

- [ ] **Step 5: Verify the kernel side**

```
Ask Claude: "Call mcp__epigraph__get_claim on <synthesis-claim-id> and report the entity_type and connected edges."
```

Confirm the synthesis claim is visible as a kernel noun-claim with the synthesis entity type and PROV-O edges back to the sample and protocol claims.

- [ ] **Step 6: Save to `/tmp/epi-walkthrough-1-transcript.md`**

---

### Task B5: Run Walkthrough 2 (Countersign) and capture

**Files:**
- Create: `/tmp/epi-walkthrough-2-transcript.md`

- [ ] **Step 1: Countersign Walkthrough 1's synthesis claim**

```
Ask Claude: "Make a POST to http://127.0.0.1:8090/countersign with body {\"claim_id\": \"<synthesis-claim-id>\", \"agent_id\": \"<a-different-agent-id>\", \"signature\": \"<a valid signature>\"}."
```

If the second agent identity isn't already provisioned, document the agent-creation step too (consult `episcience-api/src/routes/countersign.rs` for required fields).

Capture the response including the chain position.

- [ ] **Step 2: Verify the chain**

Read back the synthesis claim's countersignatures. First check `crates/episcience-api/src/routes/countersign.rs` to find the exact GET path (likely `GET /countersign/<claim-id>` based on convention). If no GET route exists, query the DB directly:

```bash
psql -d epigraph -c "SELECT * FROM countersignatures WHERE claim_id = '<synthesis-claim-id>' ORDER BY chain_position;"
```

Capture either the API response or the SQL result for the transcript.

- [ ] **Step 3: Save to `/tmp/epi-walkthrough-2-transcript.md`**

---

### Task B6: Run Walkthrough 3 (Multi-source synthesis) and capture

**Files:**
- Create: `/tmp/epi-walkthrough-3-transcript.md`

- [ ] **Step 1: Create three independent samples**

Three POST /samples calls. Capture the three IDs.

- [ ] **Step 2: Synthesize each as a leaf**

Three `mcp__episcience__synthesize` calls, each referencing one sample. Capture the three synthesis claim IDs.

- [ ] **Step 3: Higher-level synthesis from all three**

One `mcp__episcience__synthesize` call referencing all three leaf synthesis claims as `source_claim_ids`. Capture.

- [ ] **Step 4: Observe in the kernel**

```
Ask Claude: "Call mcp__epigraph__recall_with_context for the higher-level synthesis's content, then mcp__epigraph__get_neighborhood on it to see the PROV-O edges back to the three leaves."
```

Capture.

- [ ] **Step 5: Also call mcp__episcience__recall_synthesis and mcp__episcience__get_synthesis on the higher-level claim**

Capture how the episcience-side surface presents the same data.

- [ ] **Step 6: Save to `/tmp/epi-walkthrough-3-transcript.md`**

---

### Task B7: Assemble walkthroughs file (`docs/intro/03-walkthroughs.md`)

**Files:**
- Create: `/home/jeremy/episcience/docs/intro/03-walkthroughs.md`

- [ ] **Step 1: Write header and TOC**

```markdown
# Walkthroughs

Three Claude Code sessions exercising episcience's exposed surface — samples, protocols, synthesis, and countersignatures. Each walkthrough assumes you've completed the [extension quickstart](01-quickstart-extension.md).

## Table of contents

1. [Stage and synthesize](#walkthrough-1--stage-and-synthesize)
2. [Countersign](#walkthrough-2--countersign)
3. [Multi-source synthesis](#walkthrough-3--multi-source-synthesis)

---
```

- [ ] **Step 2: Paste in the three transcripts**

Under `## Walkthrough 1 — Stage and synthesize`, `## Walkthrough 2 — Countersign`, `## Walkthrough 3 — Multi-source synthesis`. Each ends with a closing paragraph linking back to the relevant section in [`02-concepts-science.md`](02-concepts-science.md).

- [ ] **Step 3: Commit**

```bash
git add docs/intro/03-walkthroughs.md
git commit -m "docs(intro): three episcience walkthroughs captured live"
```

---

### Task B8: README (`README.md`)

**Files:**
- Create: `/home/jeremy/episcience/README.md`

- [ ] **Step 1: Write the file**

```markdown
# episcience

An Apache-2.0 layer over [EpiGraph](https://github.com/epigraph-io/epigraph) that adds the experimental loop: samples, protocols, blobs, countersignatures, and synthesis claims. Where EpiGraph models *what is believed*, episcience models *how beliefs were tested* — the scaffolding needed to do science (or any methodologically rigorous knowledge work) on top of the kernel.

## Status

- Version: 0.1.0
- License: Apache-2.0
- Maturity: alpha; the workspace pins specific epigraph crates by git rev in [`Cargo.toml`](Cargo.toml). The pin is currently kept on the head of `feat/phase0-integrated` (PR epigraph-io/epigraph#10); will re-pin to a merged sha once #10 lands.

## Prerequisites

A running EpiGraph kernel — same Postgres instance is fine. Start there: https://github.com/epigraph-io/epigraph#5-minute-quickstart.

## 5-minute extension quickstart

```bash
# 1. Clone
git clone https://github.com/epigraph-io/episcience.git && cd episcience

# 2. Apply episcience migrations on the kernel DB
sqlx migrate run --source migrations/ --database-url postgres://epigraph:epigraph@localhost/epigraph

# 3. Build and start (port 8090 to avoid colliding with epigraph-api on 8080)
cargo build --release -p episcience-api
EPISCIENCE_PORT=8090 DATABASE_URL=postgres://epigraph:epigraph@localhost/epigraph \
  cargo run --release -p episcience-api --bin episcience-server &

# 4. Register the MCP server in ~/.mcp.json alongside the epigraph entry
# (see docs/intro/01-quickstart-extension.md for the JSON block)

# 5. In Claude Code, call mcp__episcience__synthesize and observe the new claim
```

## Onboarding tree

- [`docs/intro/01-quickstart-extension.md`](docs/intro/01-quickstart-extension.md) — five-step setup assuming kernel installed
- [`docs/intro/02-concepts-science.md`](docs/intro/02-concepts-science.md) — experiments, samples, protocols, blobs, countersigning, synthesis, PROV-O
- [`docs/intro/03-walkthroughs.md`](docs/intro/03-walkthroughs.md) — three end-to-end transcripts
- [`docs/intro/04-glossary.md`](docs/intro/04-glossary.md) — science-specific terms (kernel terms link to the EpiGraph glossary)

## Why a separate repo?

EpiGraph is the public-Apache-2.0 epistemic kernel that other applications (some open, some closed) can depend on. Science-specific scaffolding is its own bounded concern, and lives in its own repo so it can evolve at its own pace and so consumers who don't need the science layer aren't forced to take it.

## Deeper EpiGraph material

- [EpiGraph next-steps](https://github.com/epigraph-io/epigraph/blob/main/docs/intro/05-next-steps.md) — contributor, deploy, downstream pointers
- [EpiGraph concepts](https://github.com/epigraph-io/epigraph/blob/main/docs/intro/02-concepts.md) — kernel mental model
```

- [ ] **Step 2: Verify the 5-minute block matches reality**

Same check as Task A10 Step 2 but for episcience.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: episcience README with pitch, extension quickstart, and intro TOC"
```

---

### Task B9: Link check Phase B

**Files:**
- None modified unless broken links found

- [ ] **Step 1: Run mlc**

```bash
cd /home/jeremy/episcience
mlc README.md docs/intro/*.md
```

- [ ] **Step 2: Fix broken links and commit**

Same pattern as Task A11.

---

## Phase C — Cross-cutting

### Task C1: Open PRs

**Files:**
- None

- [ ] **Step 1: Push both branches**

```bash
cd /home/jeremy/epigraph && git push -u origin docs/onboarding-tree
cd /home/jeremy/episcience && git push -u origin docs/onboarding-tree
```

- [ ] **Step 2: Open the EpiGraph PR**

```bash
cd /home/jeremy/epigraph
gh pr create --title "docs: onboarding tree (README + docs/intro/)" --body "$(cat <<'EOF'
## Summary

- Adds top-level `README.md` (pitch, status, 5-min quickstart, intro TOC, deeper-material pointers)
- Adds `docs/intro/{01-quickstart,02-concepts,03-walkthroughs,04-glossary,05-next-steps}.md`
- Spec: `docs/superpowers/specs/2026-05-19-onboarding-docs-design.md`
- Plan: `docs/superpowers/plans/2026-05-19-onboarding-docs.md`

## Test plan

- [ ] All four walkthroughs in `03-walkthroughs.md` reproduce against a fresh kernel install
- [ ] Every internal link resolves (mlc clean)
- [ ] A reader new to EpiGraph can complete the quickstart in ≤15 minutes (test with a volunteer if possible)
- [ ] No leftover transcript stubs (`<id>`, `…`, `TBD`)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Open the episcience PR**

```bash
cd /home/jeremy/episcience
gh pr create --title "docs: onboarding tree (README + docs/intro/)" --body "$(cat <<'EOF'
## Summary

- Adds top-level `README.md` (pitch, status, 5-min extension quickstart, intro TOC, links back to EpiGraph)
- Adds `docs/intro/{01-quickstart-extension,02-concepts-science,03-walkthroughs,04-glossary}.md`
- Cross-repo spec lives at: https://github.com/epigraph-io/epigraph/blob/main/docs/superpowers/specs/2026-05-19-onboarding-docs-design.md

## Test plan

- [ ] All three walkthroughs in `03-walkthroughs.md` reproduce against a fresh kernel + episcience install
- [ ] Every internal link resolves (mlc clean)
- [ ] A reader who has completed the EpiGraph quickstart can complete the episcience extension in ≤10 minutes
- [ ] No leftover transcript stubs

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 4: Report the PR URLs to the user**

---

## Notes

- **Merge style:** per user feedback memory `feedback_merge_commit_not_squash.md`, default `gh pr merge --merge --delete-branch` (not `--squash`). Wait for explicit user approval before merging.
- **Branch hygiene:** if the implementer is running Phase A in an isolated worktree (per user feedback `feedback_use_worktrees.md`), force absolute paths in every Bash block — subagents drift to the main repo otherwise (per user feedback `feedback_subagent_worktree_paths.md`).
- **Drift:** if any walkthrough fails because the live system behaves differently from the spec's expected output, file a backlog item via `mcp__epigraph__submit_claim` with `labels=["backlog"]` and the discrepancy in the content; resolve it later with `mcp__epigraph__resolve_backlog_item`. Do not silently massage the docs to fit broken behavior.
