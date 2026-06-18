# Deterministic Verbatim Spine for Hierarchical Ingest — Design Spec

**Date:** 2026-06-18
**Status:** Approved (brainstorming) — ready for implementation planning
**Scope:** `document` ingest path only (papers / sources). The parallel
`workflow` path (`Step.compound`) is explicitly out of scope.

---

## 1. Problem

The canonical hierarchical ingest is a two-stage pipeline:

- **Extractor** — the `extract-claims` Claude skill (`.claude/skills/extract-claims/SKILL.md`),
  a 4-stage LLM cascade that emits a `DocumentExtraction` JSON.
- **Writer** — `ingest_document` / `ingest_document_inline` →
  `do_ingest_document` (`crates/epigraph-mcp/src/tools/ingestion.rs`), which
  deterministically lands the paper node, the thesis/section/paragraph/atom
  claims, the `decomposes_to` / `section_follows` / `continues_argument`
  edges, evidence, traces, embeddings, and CDST mass functions.

Today the **graph-RAG spine carries LLM paraphrase, not source text**:

- `Paragraph.compound: String` is **required** (`document/schema.rs`) — an
  LLM "compound claim" restating the paragraph. The verbatim quote
  (`supporting_text`) is **optional** (`#[serde(default)]`). Priority is
  inverted: the mandatory field is the paraphrase.
- `build_ingest_plan` (`document/builder.rs`) sets the paragraph node
  `content = paragraph.compound` and the section node
  `content = section.summary` (also LLM).
- The embedding runs over the node content:
  `embed_and_store(persisted_id, &planned.content)` — so semantic retrieval
  over the spine matches the **paraphrase**, not the prose.
- `supporting_text` is used only to format the evidence passage string.

What *is* already correct: the **edge wiring** is deterministic.
`build_ingest_plan` derives `decomposes_to` from tree nesting,
`continues_argument` from `para_ids.windows(2)`, and `section_follows` from
`section_ids.windows(2)`. The LLM `relationships[]` array only *adds*
cross-links (`supports`/`contradicts`/`refines`) on top. The tree *topology*
(what counts as a section/paragraph), however, is LLM-chosen — there is no
deterministic source→tree parser anywhere in `epigraph-ingest`;
`ingest_document` just `read_to_string` + `serde_json::from_str::<DocumentExtraction>`
on a file the LLM already wrote.

**Goal:** make the spine carry **verbatim source text**, recover structure
**deterministically where possible**, and fence the LLM to **atoms only** —
the one layer where generating claim text is the actual job.

---

## 2. Decisions (from brainstorming)

| # | Decision | Outcome |
|---|----------|---------|
| D1 | Source format at ingest time | **Varies** — some clean markup, some messy PDF text. Pipeline must handle both. |
| D2 | Messy-input structure recovery | **LLM-as-offset-segmenter** — for messy input the LLM returns boundary spans over the *raw* text; the pipeline slices verbatim and never accepts rewritten prose. Deterministic parser handles clean markup. |
| D3 | Orchestration | **Hybrid (C)** — deterministic parser + verbatim slice/verify guard live in Rust (`epigraph-ingest`); the agent/skill drives the LLM parts (offset-segmentation fallback + atomization). |
| D4 | Section node content | **Verbatim heading/title**; LLM `summary` dropped. |
| D5 | Thesis | **Verbatim-first** — use an explicit thesis/abstract span when present; LLM bottom-up synthesis only when absent, flagged via the existing `thesis_derivation`. |
| D6 | `compound` / `supporting_text` | **Removed.** Paragraph node *is* the verbatim text. |
| D7 | Migration | **Forward-only** via the pipeline-version gate (`hierarchical_extraction_v1` → `v2`). Re-ingesting the existing corpus is a separate, explicit effort. |
| D8 | Workflow path | **Out of scope.** `workflow`/`Step.compound` is a symmetric follow-up. |

**The invariant (non-negotiable):** every spine node's `content` is a byte-exact
slice of the source document. Structure-determinism may degrade on messy input;
the verbatim guarantee may not.

---

## 3. Architecture

Four stages; the LLM is fenced into stage 2.

```
raw source ─▶ [1] STRUCTURER (Rust) ─▶ verbatim tree ─▶ [2] ATOMIZER (agent/LLM)
                                                              │
                          verbatim tree + atoms ◀────────────┘
                                    │
                          [3] build_ingest_plan (Rust, ~unchanged)
                                    │
                          [4] do_ingest_document (Rust) ─▶ persist + embed verbatim
```

1. **Structurer** (new, Rust): `raw text + format hint [+ agent segmentation]`
   → `StructuredDoc` where every section heading and paragraph is a byte-range
   slice of the original. Backends: deterministic markdown/HTML parser (clean),
   or offset-slicer fed agent spans (messy). Terminates in the **verbatim guard**.
2. **Atomizer** (agent/skill, LLM): per verbatim paragraph → atoms +
   generality + evidence_type + cross-atom relationships. Never rewrites the
   paragraph.
3. **Builder** (`build_ingest_plan`): paragraph `content = text`, section
   `content = title`; spine edges already deterministic — logic untouched.
4. **Writer** (`do_ingest_document`): embeds verbatim text; re-runs the guard
   as defense-in-depth; CDST on atoms unchanged.

---

## 4. Components / files

| File | Change |
|------|--------|
| `crates/epigraph-ingest/src/document/structure.rs` | **NEW.** `StructuredDoc` types, markdown/HTML offset parser, offset-slicer, verbatim guard. Pure, no I/O, heavily unit-tested. |
| `crates/epigraph-ingest/src/document/schema.rs` | `Paragraph.compound` → `text` (verbatim, required); drop the schema-input `supporting_text` field. `Section.summary` removed. (The internal `PlannedClaim.supporting_text` in `plan.rs` is a *different* field and is retained — see §6.) |
| `crates/epigraph-ingest/src/document/builder.rs` | node content = `paragraph.text` / `section.title`; atoms' `supporting_text` ← parent `text` (grounding). Edge construction unchanged. |
| `crates/epigraph-mcp/src/tools/structure_source.rs` | **NEW tool.** `structure_source(text, source_type, format, segmentation?)` → verbatim tree. Deterministic when markup is clean; slices + verifies agent-supplied `segmentation` when messy. |
| `crates/epigraph-mcp/src/tools/ingestion.rs` | embed `text`; guard re-check before persist; `PIPELINE_VERSION_BASE` → `hierarchical_extraction_v2`. |
| `crates/epigraph-mcp/src/types.rs` | inline JSON-schema descriptions for the new `Paragraph`/`Section`; `structure_source` param/result types. |
| `.claude/skills/extract-claims/SKILL.md` | Drop Stage-2 compound. New flow: get structure (→ `structure_source` for clean, or produce offset segmentation for messy) → atomize each paragraph → `ingest_document_inline`. Council-of-Critics re-aimed at atom faithfulness + verbatim drift. |
| `crates/epigraph-ingest/Cargo.toml` | add `pulldown-cmark` (markdown source-offset parsing). |

### 3.1 `structure.rs` sketch

```rust
/// A verbatim slice of the source: (start, end) byte offsets + the exact text.
pub struct Span { pub start: usize, pub end: usize, pub text: String }

pub struct StructuredParagraph { pub span: Span }
pub struct StructuredSection { pub heading: Span, pub paragraphs: Vec<StructuredParagraph> }
pub struct StructuredDoc { pub sections: Vec<StructuredSection> }

pub enum SourceFormat { Markdown, Html, PlainText }

/// Deterministic parse for clean markup. Headings open sections; blank-line
/// blocks become paragraphs. Uses pulldown-cmark `into_offset_iter()` (which
/// yields `Range<usize>` into the original) so every node is a real slice.
pub fn parse_structure(source: &str, fmt: SourceFormat) -> Result<StructuredDoc, StructureError>;

/// Slice + verify an agent-supplied segmentation (messy fallback). Spans are
/// (section/paragraph) byte ranges over `source`; this never trusts agent text.
pub fn slice_segmentation(source: &str, seg: &Segmentation) -> Result<StructuredDoc, StructureError>;

/// The invariant. Runs in the structurer AND again in the writer.
pub fn verify_verbatim(source: &str, doc: &StructuredDoc) -> Result<(), StructureError>;
```

---

## 5. Data flow

- **Clean markup:** `source.md` → `structure_source(format=markdown)` →
  deterministic verbatim `StructuredDoc` → agent atomizes each returned
  paragraph → `ingest_document_inline(tree + atoms)` → writer guard re-check →
  persist (embed verbatim text).
- **Messy text:** agent reads the raw text, returns section/paragraph **offset
  spans** → `structure_source(text, segmentation=spans)` slices + verifies
  verbatim → same tail.

The agent must pass the **same** source text the offsets index into; the guard
catches drift and rejects with a precise diff.

---

## 6. Schema before / after

```
Paragraph  BEFORE { compound:String(req), supporting_text, atoms, generality,
                    confidence, methodology, evidence_type, page, instruments_used,
                    reagents_involved, conditions }
           AFTER  { text:String(req,verbatim), atoms, generality, confidence,
                    methodology, evidence_type, page, instruments_used,
                    reagents_involved, conditions }      # compound + supporting_text removed

Section    BEFORE { title, summary, paragraphs }
           AFTER  { title, paragraphs }                  # summary removed; title = verbatim heading
```

`DocumentExtraction`, `DocumentSource`, `thesis`, `thesis_derivation`,
`relationships`, and the atom shape (string atoms + per-paragraph
`evidence_type`/`generality`) are unchanged except that the thesis is sourced
verbatim-first (D5).

**Note on `supporting_text`:** the removal is of the *schema-input* field only.
The internal `PlannedClaim.supporting_text` (`common/plan.rs`) is retained and
is now fed the verbatim paragraph `text`. So the formatted evidence passage
(`Source: <title> (DOI: …). Passage: '<text>'`) for both the paragraph node and
its atoms now quotes the **source paragraph** — strictly better grounding than
the old LLM-selected quote.

---

## 7. Verbatim guard (the invariant, in detail)

Input: `source_text` and the ordered spans (heading + paragraph) of a
`StructuredDoc`. Assertions:

1. **Byte-exact:** `source_text[span.start..span.end] == span.text` for every span.
2. **Ordered & non-overlapping:** spans strictly increasing, no overlap.
3. **Coverage:** every inter-span gap contains only whitespace / markup
   punctuation (no dropped sentences).
4. **Non-empty:** no zero-length / whitespace-only paragraph.

On any failure → reject the whole document with `{ span, expected, got }`. The
guard never repairs by paraphrasing. It runs **twice**: in the structurer (fail
fast) and in `do_ingest_document` (defense-in-depth, since the agent assembles
the inline payload between the two).

---

## 8. Migration

Forward-only, gated by `PIPELINE_VERSION_BASE`:

- Bump `hierarchical_extraction_v1` → `hierarchical_extraction_v2`. The
  `processed_by` edge + version gate (`effective_pipeline_version`,
  `has_processed_by_edge`) makes same-version re-runs idempotent and marks v2 a
  clean boundary.
- Existing paragraph/section nodes keep their IDs (`compound_claim_id` hashes
  the old `compound`/`summary`); they are **not** rewritten.
- **Atoms keep their IDs** — `atom_id` hashes atom text, which is unchanged —
  so cross-source matching and existing CDST evidence survive.
- Re-ingesting a pre-v2 paper would mint a *new* verbatim spine alongside the
  old one. Therefore corpus backfill is an explicit, separate effort, **out of
  scope here**, and must be done deliberately (not by accidental re-ingest).

---

## 9. Testing

- **Unit (`structure.rs`):**
  - markdown headings + blank-line paragraphs → exact offsets;
  - nested headings (`#`/`##`) → correct section nesting;
  - guard rejects altered text, overlapping spans, and content-bearing gaps;
  - `slice_segmentation` round-trips agent spans to verbatim text.
- **Property test:** for any parsed `StructuredDoc`, spans + interstitial
  whitespace reconstruct the source (nothing lost, nothing invented).
- **Integration:** ingest a known markdown document → assert paragraph node
  `content` is byte-equal to the source paragraph, embeddings present,
  `continues_argument` / `section_follows` / `decomposes_to` wired, atoms
  decomposed under each paragraph, CDST present on atoms.
- **Council-of-Critics** (project convention) on every new test: reject
  tautological / mock-shaped / happy-path-only tests. The guard test uses a
  real source string and asserts byte-exactness.
- **Regression:** `ingest_document_smoke`, `link_hierarchical_smoke`,
  `pr_hierarchical_ingest_test` stay green (adjust fixtures to the new schema).
- **CI gate** (project convention): `cargo fmt --check` + `cargo clippy -D warnings`
  before commit.

---

## 10. Risks / open items

- **Markdown lib:** add `pulldown-cmark` for source offsets
  (`into_offset_iter`). HTML → normalize to markdown (thin `html2text`-style
  pass) then parse; **plaintext** → a minimal blank-line/heading hand-parser.
  Plan resolves: markdown-first, plaintext-fallback, HTML as a thin normalizer.
- **New tool surface:** `structure_source` appears in `tools/list`; document it
  and keep it scope-gated consistently with the other ingest tools.
- **Offset drift:** the agent must segment over the exact text it later submits;
  the double guard is the safety net.
- **`structure_source` standalone vs folded into `ingest_document_inline`:**
  spec keeps it standalone so the deterministic parse is independently callable
  and testable; the inline writer still re-verifies.

---

## 11. Out of scope

- The `workflow` / `Step.compound` ingest path (symmetric follow-up).
- Backfilling / re-ingesting the existing paper corpus to v2.
- Any change to atom semantics, CDST, generality scoring, or
  `relationships[]` cross-link handling.
