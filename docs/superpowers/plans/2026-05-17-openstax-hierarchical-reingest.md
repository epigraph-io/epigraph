# OpenStax Hierarchical Re-Ingestion Plan

**Date:** 2026-05-17
**Author:** Claude (Opus 4.7) — drafted with Jeremy
**Status:** Draft for review — do not execute until open questions resolved

---

## Goal

Replace flat-glossary ingestions of six OpenStax textbooks with hierarchical
`DocumentExtraction`s. Preserve cross-chapter structural relationships in the
graph so downstream cross-source matching can detect cross-chapter claim
coherence. Supersede the flat claims after the hierarchical version validates.

## Inventory (verified 2026-05-17 against live `papers` table)

| # | DOI | Title | Flat claims |
|---|---|---|---|
| 1 | `openstax:anatomy-and-physiology-2e` | Anatomy and Physiology 2e | 6,780 |
| 2 | `openstax:astronomy-2e` | Astronomy 2e | 4,628 |
| 3 | `openstax:microbiology` | Microbiology | 2,728 |
| 4 | `openstax:principles-marketing` | Principles of Marketing | 2,659 |
| 5 | `openstax:physics` | Physics | 2,495 |
| 6 | `openstax:introductory-business-statistics-2e` | Intro Business Statistics 2e | 1,319 |
| 7 | `openstax:introductory-statistics-2e` | Introductory Statistics 2e | 1,244 |

**OpenStax records in the graph (verified, 9 total):**

| ID | DOI | Claims | Hierarchy signal |
|---|---|---|---|
| `8c702989` | `openstax:university-physics-volume-2` | 0 | Empty shell |
| `fe5e1308` | `openstax:principles-marketing` | 2,659 | 2 outgoing `CONTAINS` edges (unique among OpenStax papers); sampling-density spike — **possible partial hierarchical layer** |
| `dd620b87` | `openstax-introduction-business-2e` | 135 | Zero graph hierarchy; `[ChN: …]` text prefixes only |
| other 6 | (anatomy, astronomy, microbio, physics, bizstats, stats) | 1.2k–6.8k | Pure flat |

**Math to land at "six":** 9 OpenStax records − 1 empty shell − 1
already-hierarchical (per user) = 7. One more drops to reach 6. Both the
already-hierarchical pick AND the further drop are **awaiting user input**
(see Open Questions). Marketing is the leading candidate for
already-hierarchical based on `CONTAINS` edge evidence, not dd620b87. Do
not pre-commit either way until Jeremy answers.

## Architecture decisions

### D1. Per-chapter `DocumentExtraction` chunking

Each chapter ingests as its own `DocumentExtraction` JSON sharing the same
`source.doi` (e.g. `openstax:physics`). `PaperRepository::get_or_create`
(`crates/epigraph-db/src/repos/paper.rs:35`) deduplicates by DOI, so all
chapters land under one `paper_id` — same one the flat claims already use.
Each chapter is one transaction → bounded memory + clean resume on failure.

### D2. Book-level structural root

Without intervention, per-chapter chunking leaves chapters as disconnected
trees. To preserve book-level hierarchy:

1. **Pre-create a book-thesis claim** per book via `submit_claim` —
   one-sentence statement of the book's scope, labels `["openstax", "book-thesis", "<slug>"]`.
2. **Per chapter**, after `ingest_document` returns, POST a `decomposes_to`
   edge from `book_thesis_id` → `chapter_thesis_id` (the level-0 claim of
   the chapter's `DocumentExtraction`).
3. **Cross-chapter ordering** — natural fit is `section_follows`, but
   `is_valid_relationship()` (`crates/epigraph-api/src/routes/edges.rs:47`)
   rejects it from the edges API even though `ingest_document` emits it.
   Two paths:
   - **D3a (preferred):** extend `VALID_RELATIONSHIPS` with `"section_follows"`
     and `"continues_argument"` (consistency fix — the ingest pipeline already
     produces them). Two-line PR to `edges.rs`.
   - **D3b (fallback):** use `relates_to` with `properties.role = "chapter_follows"`.

### D3. Flat-claim supersession

After each book's hierarchical ingest verifies:

1. Embed-match each flat claim to its nearest hierarchical atom (cosine
   similarity ≥ 0.85, single best match).
2. Where a match exists: `supersede_claim(old=flat_id, new=hierarchical_atom_id)`.
3. Where no match: label flat claim `["openstax-flat-orphan", "<slug>"]` for
   later human triage — these may be content the hierarchical extractor
   missed.

Per memory `feedback_pignistic_not_bayesian`: supersession preserves DST
BetP via the version chain.

### D4. Cross-source matching post-pass

After all six books re-ingested:

- Run cluster_graph cross-source matching on the new hierarchical atoms only
  (exclude `cdst:contradicted` / `cdst:supported` legacy labels). Use small
  DB per memory `feedback_cluster_graph_test_db`.
- Surface cross-chapter and cross-book coherence clusters as a report for
  human review.

## Pre-flight

- [x] **Step 0.1: Fix `extract-claims` SKILL CWD bug** — `/tmp/extraction_*.json`
  fails the `canonical.starts_with(&cwd)` check in
  `crates/epigraph-mcp/src/tools/ingestion.rs:41`. Patched
  `epigraph/.claude/skills/extract-claims/SKILL.md` to use
  `/home/jeremy/tmp/extractions/`. Working dir created.

- [ ] **Step 0.2: Land `section_follows` API fix (D3a)** — add
  `"section_follows"` and `"continues_argument"` to `VALID_RELATIONSHIPS` in
  `crates/epigraph-api/src/routes/edges.rs:47`. Add regression test asserting
  `is_valid_relationship("section_follows") == true`.

- [ ] **Step 0.3: Resolve open question** — confirm `dd620b87` is the
  excluded "already-hierarchical" book. Confirm which 7th book to drop
  (Marketing recommended).

- [ ] **Step 0.4: Source fetch** — clone OpenStax CNXML/HTML from
  `github.com/openstax/<book-repo>` per memory `ad7e2d0e`. Stage in
  `/home/jeremy/tmp/openstax-sources/<slug>/`.

## Per-book execution loop

For each of the six confirmed books:

- [ ] **Step 1: Book-thesis claim** — `submit_claim(content="<one-sentence
  book scope>", labels=["openstax", "book-thesis", "<slug>"], methodology="inductive_generalization")`.
  Capture `book_thesis_id`.

- [ ] **Step 2: Per-chapter extraction** — for each chapter in the source
  CNXML:
  1. Run `extract-claims` skill against chapter text (4-stage: structure →
     compound → atom → optional thesis). Set
     `source.source_type = "Textbook"`, `source.doi = "<book_doi>"`,
     `source.metadata.chapter_index = N`.
  2. Write to `/home/jeremy/tmp/extractions/<slug>_ch<NN>.json`.
  3. **Pre-compute** `chapter_thesis_id` client-side from
     `compound_claim_id(content_hash(thesis_text), doc_title)` — the same
     deterministic UUID-v5 derivation `build_ingest_plan` uses
     (`crates/epigraph-ingest/src/document/builder.rs:48-50`). The
     `IngestDocumentResponse` does **not** return a thesis_id field
     (`ingestion.rs:85-97`), so we derive it from the inputs we control.
  4. Call `ingest_document(file_path=...)`. On `already_ingested=false`,
     proceed; on `true`, the pipeline_version edge fired — investigate
     before continuing (see R1).
  5. POST `decomposes_to`: `book_thesis_id` → `chapter_thesis_id`.
  6. If N > 1: POST `section_follows`: previous chapter `thesis_id` →
     current chapter `thesis_id`. (Requires Step 0.2 landed.)

- [ ] **Step 3: Verify book** — query `query_paper(doi=<book_doi>)`,
  confirm `claim_count` increased by expected amount, confirm
  `processed_by hierarchical_extraction_v1` edge exists on paper node.

- [ ] **Step 4: Supersede flat** — run embed-match + supersede script for
  this book's flat claims (D3 above). Confirm BetPs preserved via spot-check
  on 10 claims.

## Token / time budget

Per memory `paper-monitor` schedule: ~2k tokens per paper ingest at LLM
side. A textbook chapter is ~the size of a paper, so ~2-4k tokens per
chapter. Anatomy 2e (27 chapters) ≈ 60-100k LLM tokens. Plan for one book
per session, chunked overnight via `paper-monitor`-style scheduling, OR
run interactively with `--limit N` style checkpointing.

## Risks

- **R1: `eb571e64` idempotency** — version gate at
  `crates/epigraph-mcp/src/tools/ingestion.rs:76` short-circuits only on
  `processed_by hierarchical_extraction_v1` edge presence. Verified absent
  on Anatomy 2e and Marketing — should re-ingest cleanly. Risk: if a partial
  prior hierarchical attempt left the edge, the gate fires and silently
  returns 0 claims. Mitigation: before each book, query the paper node and
  confirm no `processed_by` edge.
- **R2: chapter-level thesis quality** — LLM extractor may degrade on a
  pure-glossary chapter (e.g. Anatomy's terminology sections) and produce
  a weak thesis. Mitigation: post-ingest spot-check chapter theses; fall
  back to thesis_derivation = "bottom-up" if the chapter has no clean
  abstract.
- **R3: SKILL extra-doc bugs** — SKILL example includes `metadata` sibling
  param to `ingest_document` that the MCP signature doesn't accept. Will
  surface as "unknown field" if followed verbatim. Already de-emphasized in
  the Step 0.1 doc fix; full removal deferred unless it bites.
- **R4: recall lag** — `3a8879fc` says hierarchically-ingested claims don't
  surface via `recall()` for some time. Cosmetic for ingest, but means
  Step 4 embed-match must query embeddings directly via SQL/HNSW, not
  recall.

## Open questions for Jeremy

1. **Which book is the already-hierarchical one to exclude?** Evidence
   points to **Principles of Marketing** (`fe5e1308`): only OpenStax paper
   with outgoing `CONTAINS` edges (2 of them) and a sampling-density spike
   suggesting a partial hierarchical layer. dd620b87 was my earlier guess
   but it has zero graph hierarchy — only `[ChN: …]` text prefixes inline.
2. **Which 7th book to drop to reach six?** After excluding the empty
   `university-physics-volume-2` shell and the already-hierarchical book,
   seven remain. Which one drops? (No strong prior from me — depends on
   priorities.)
3. **Source-fetch responsibility** — do you want me to write the OpenStax
   CNXML fetcher (per-repo `git clone` + chapter splitter), or is there an
   existing one I missed?
4. **Cross-source matching scope** — cluster only the new hierarchical
   atoms across the six books, or include adjacent papers in the graph
   already (NDI, Renaissance playbooks)?
