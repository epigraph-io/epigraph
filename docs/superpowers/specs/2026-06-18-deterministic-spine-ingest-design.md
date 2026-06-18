# Deterministic Verbatim Spine for Hierarchical Ingest — Design Spec

**Date:** 2026-06-18
**Status:** Approved (brainstorming) + Council-amended — ready for implementation planning
**Scope:** `document` ingest path only (papers / sources). The parallel
`workflow` path (`Step.compound`) is explicitly out of scope.
**Revision:** v2 of this spec — amended after an adversarial Council-of-Critics
review (28 findings survived verification; see §12).

---

## 1. Problem

The canonical hierarchical ingest is a two-stage pipeline:

- **Extractor** — the `extract-claims` Claude skill (`.claude/skills/extract-claims/SKILL.md`),
  a 4-stage LLM cascade emitting a `DocumentExtraction` JSON — *plus* a set of
  deterministic Python structured-source emitters
  (`scripts/extract_html.py`, `scripts/extract_textbook.py`,
  `scripts/lib/document_extraction.py`) that emit the *same* `DocumentExtraction`
  shape for HTML / CNXML textbooks.
- **Writer** — `ingest_document` / `ingest_document_inline` →
  `do_ingest_document` (`crates/epigraph-mcp/src/tools/ingestion.rs`), which
  deterministically lands the paper node, the thesis/section/paragraph/atom
  claims, the `decomposes_to` / `section_follows` / `continues_argument`
  edges, evidence, traces, embeddings, and CDST mass functions.

Today the **graph-RAG spine carries LLM paraphrase, not source text**:

- `Paragraph.compound: String` is **required** (`document/schema.rs:68`) — an
  LLM "compound claim" restating the paragraph. The verbatim quote
  (`supporting_text`) is **optional** (`#[serde(default)]`, `schema.rs:69`).
  Priority is inverted: the mandatory field is the paraphrase.
- `build_ingest_plan` (`document/builder.rs`) sets the paragraph node
  `content = paragraph.compound` (`:123`) and the section node
  `content = section.summary` (`:84`) — also LLM.
- The embedding runs over the node content:
  `embed_and_store(persisted_id, &planned.content)` (`ingestion.rs:388`) — so
  semantic retrieval over the spine matches the **paraphrase**, not the prose.
- `supporting_text` is used to format the evidence passage string **and** is
  written into the persisted `properties['supporting_text']` JSON
  (`builder.rs:129`); under v2 it is dropped and no in-repo reader consumes it.

What *is* already correct: the **edge wiring** is deterministic.
`build_ingest_plan` derives `decomposes_to` from tree nesting,
`continues_argument` from `para_ids.windows(2)` (`:175`), and `section_follows`
from `section_ids.windows(2)` (`:187`). The LLM `relationships[]` array only
*adds* cross-links on top (`:198`) — note `relationship` is a free `String`,
not an enforced `supports`/`contradicts`/`refines` allowlist; the closed set is
a skill convention.

What is **not** deterministic today: the tree *topology* (what counts as a
section/paragraph) is LLM-chosen — `ingest_document` does `read_to_string`
(`:71`) + `serde_json::from_str::<DocumentExtraction>` (`:75`) on a tree the LLM
already wrote. No deterministic source→tree parser exists in `epigraph-ingest`.

**Goal:** make the spine carry **verbatim source text**, recover structure
**deterministically where possible**, and fence the LLM to **atoms only** —
the one layer where generating claim text is the actual job.

---

## 2. The invariant (two tiers)

No spine node is ever an LLM paraphrase. *How* faithful the stored text is to
the raw bytes depends on the backend:

> **Tier 1 — byte-exact verbatim** (markdown / plaintext via the Rust
> structurer): every level-1 (section heading) and level-2 (paragraph) node's
> `content` is a byte-exact slice of the submitted `source_text`, enforced by
> the §7 guard (in the structurer *and* re-run in the writer).
>
> **Tier 2 — faithful de-paraphrased extraction** (HTML / CNXML via the Python
> emitters): node `content` is the full recovered element text — no LLM, no
> `first_sentence` truncation — but DOM normalization (whitespace-collapse,
> `<math>`→`[equation]`) means it is *not* a byte slice of the raw source. These
> paths emit no `source_text`/spans, so the writer runs the non-empty check
> only. True byte-spans for HTML/CNXML are a follow-up (§11).

Each node records its tier in `properties.spine_text_kind ∈ {verbatim_v2,
extracted_v2}` (and `paraphrase_v1` for the un-migrated corpus) so retrieval and
the cross-source matcher can tell them apart (§8).

Scope and carve-outs (both tiers):

- **Level 0 (thesis)** is *verbatim-first* (D5): an explicit abstract/thesis
  span when one exists; otherwise an LLM `BottomUp` synthesis, flagged via
  `thesis_derivation`. Exempt from byte-exactness.
- **Level 3 (atoms)** are LLM-generated claim text by design.
- Even Tier 1 is **byte-provenance only** — it asserts the stored text is the
  source's bytes, not that segmentation/linearization is semantically correct.

The non-negotiable invariant across **both** tiers: **no spine node is an LLM
paraphrase.** Byte-exactness is the stronger property that only Tier 1 delivers.

---

## 3. Decisions

| # | Decision | Outcome |
|---|----------|---------|
| D1 | Source format at ingest time | **Varies** — some clean markup, some messy PDF text. Pipeline must handle both. |
| D2 | Messy-input structure recovery | **LLM-as-offset-segmenter** — for messy input the LLM returns boundaries over the *raw* text; the pipeline slices verbatim and never accepts rewritten prose. Offsets are **UTF-8 byte offsets**. |
| D3 | Orchestration | **Hybrid (C)** — deterministic parser + verbatim slice/verify guard in Rust (`epigraph-ingest`); the agent/skill drives the LLM parts (offset-segmentation fallback + atomization). |
| D4 | Section node content | **Verbatim heading**; LLM `summary` dropped. Headingless input → implicit section (D7c). |
| D5 | Thesis | **Verbatim-first** — explicit thesis/abstract span when present; LLM `BottomUp` synthesis only when absent, flagged via `thesis_derivation`. |
| D6 | `compound` / `supporting_text` | **Removed** from the schema input. Paragraph node *is* the verbatim text. |
| D7 | Migration | **Forward-only** via the pipeline-version gate (`hierarchical_extraction_v1` → `v2`). Corpus re-ingest is a separate, explicit effort (§8). |
| D8 | Workflow path | **Out of scope.** `workflow`/`Step.compound` is a symmetric follow-up. |
| **D9** | **Writer-side re-verification** | `DocumentExtraction` gains **optional `source_text` + per-node byte spans**; the writer re-runs the full verbatim guard when they are present (true defense-in-depth). Absent → writer does the non-empty check only. *(Council blocker 1.)* |
| **D10** | **HTML scope** | The new **Rust structurer handles markdown + plaintext only** (both slice raw bytes). **HTML / CNXML stay on the existing Python emitters**, updated to the verbatim schema. No "normalize HTML→markdown then offset" step (it would index a synthetic intermediate, breaking byte-exactness). *(Council blocker 2.)* |

---

## 4. Architecture

Four stages; the LLM is fenced into stage 2.

```
raw source ─▶ [1] STRUCTURER (Rust md/plaintext, or Python HTML/CNXML)
                          │  verbatim tree + source_text + spans
                          ▼
              [2] ATOMIZER (agent/LLM) — atoms per verbatim paragraph
                          │
                          ▼
              [3] build_ingest_plan (Rust) — path-seeded IDs, deterministic edges
                          │
                          ▼
              [4] do_ingest_document (Rust) — re-verify guard, persist, embed verbatim
```

1. **Structurer** → `StructuredDoc` where every section heading and paragraph
   is a byte-range slice of the original, plus the `source_text` it indexes.
   Backends: deterministic markdown/plaintext parser (Rust); the existing
   Python HTML/CNXML emitters; or the offset-slicer fed agent spans (messy).
   Terminates in the **verbatim guard** (§7).
2. **Atomizer** (agent/skill, LLM): per verbatim paragraph → atoms +
   generality + evidence_type + cross-atom relationships. Never rewrites prose.
3. **Builder** (`build_ingest_plan`): node `content = paragraph.text` /
   `section.title`; **ID seed now folds in the section/paragraph path** (§Major
   D-collision fix); spine edges still derived from `windows(2)`.
4. **Writer** (`do_ingest_document`): re-runs the guard against `source_text`
   when spans are present; embeds verbatim text; CDST on atoms unchanged.

### 4.1 File change inventory

| File | Change |
|------|--------|
| `crates/epigraph-ingest/src/document/structure.rs` | **NEW.** `StructuredDoc`/`Span`/`Segmentation` types, markdown + plaintext block parser, offset-slicer, verbatim guard. Pure, no I/O, heavily unit-tested. |
| `crates/epigraph-ingest/src/document/schema.rs` | `Paragraph.compound`→`text` (verbatim, required); drop schema-input `supporting_text`; add optional `start`/`end` byte span. `Section.summary` removed; `heading` span optional. `DocumentExtraction` gains optional `source_text`. |
| `crates/epigraph-ingest/src/document/builder.rs` | node content = `paragraph.text` / `section.title`; pass a path-qualified seed `{doc_title}\u{1f}{section_path\|para_path}` to `compound_claim_id` (collision fix; `path_index` still maps the same path→UUID so `relationships[]` resolution is unaffected); atoms' `PlannedClaim.supporting_text` ← parent `text`. Edge windows logic unchanged. |
| `crates/epigraph-ingest/src/common/ids.rs` | **No signature change.** The document builder folds the section/paragraph path into the `artifact_seed` string (`{doc_title}\u{1f}{path}`, `\u{1f}` = unit separator, cannot occur in a title/path), so duplicate verbatim headings/paragraphs in one doc get distinct UUIDs without touching the shared `compound_claim_id` or its workflow callers. |
| `crates/epigraph-mcp/src/tools/structure_source.rs` | **NEW tool.** `structure_source(text, source_type, format∈{markdown,plaintext}, segmentation?)` → a `DocumentExtraction` with the verbatim section/paragraph tree, `source_text`, and per-node byte spans populated and **`atoms` left empty**. The agent fills `atoms` per paragraph and resubmits via `ingest_document_inline`, so `source_text`+spans thread straight to the writer's re-verification. Deterministic for clean markup; slices + verifies agent `segmentation` for messy. |
| `crates/epigraph-mcp/src/tools/ingestion.rs` | embed `text`; **re-run `verify_verbatim` against `source_text`+spans when present**; `PIPELINE_VERSION_BASE` → `hierarchical_extraction_v2`; over-budget paragraph split (§10). |
| `crates/epigraph-mcp/src/types.rs` | inline JSON-schema descriptions for new `Paragraph`/`Section`/`DocumentExtraction`; `structure_source` types. |
| `.claude/skills/extract-claims/SKILL.md` | Drop Stage-2 compound. New flow: structure → atomize each verbatim paragraph → `ingest_document_inline`. Council-of-Critics re-aimed at atom faithfulness + verbatim drift. |
| `scripts/extract_html.py`, `scripts/extract_textbook.py`, `scripts/lib/document_extraction.py` | Emit `text=` (verbatim) instead of `compound`; drop `summary`/`supporting_text`; emit `source_text`+spans where feasible (else writer falls back to non-empty). **CNXML textbook parser retained, not retired.** |
| `crates/epigraph-ingest/tests/structured_source_glue.rs`, `scripts/tests/test_structured_source_parsers.py` | **Compile/contract break** — reference `p.compound`/`p.supporting_text`. Update to `p.text`; regenerate fixtures. |
| `crates/epigraph-ingest/Cargo.toml` | add `pulldown-cmark` (markdown source-offset parsing). |

### 4.2 `structure.rs` sketch

```rust
/// A verbatim slice of the source: (start, end) UTF-8 byte offsets + exact text.
pub struct Span { pub start: usize, pub end: usize, pub text: String }

pub struct StructuredParagraph { pub span: Span }
pub struct StructuredSection { pub heading: Option<Span>, pub paragraphs: Vec<StructuredParagraph> }
pub struct StructuredDoc { pub source_text: String, pub sections: Vec<StructuredSection> }

pub enum SourceFormat { Markdown, PlainText }   // HTML/CNXML handled by Python emitters (D10)

/// Boundary contract for the messy path (D2). Offsets are advisory; the
/// authoritative locator is the verbatim boundary string (unique prefix+suffix),
/// so an LLM that cannot emit byte-exact offsets still succeeds.
pub struct Segmentation { /* per section/paragraph: boundary strings (+ advisory byte offsets) */ }

/// Deterministic parse for clean markup. Every TOP-LEVEL block (paragraph,
/// list incl. tight, fenced/indented code, table, thematic break, footnote def)
/// becomes its own verbatim paragraph-Span; headings open sections. Uses
/// pulldown-cmark `into_offset_iter()` (yields `Range<usize>` into the original).
/// When the document has no headings, synthesizes ONE implicit whole-document
/// section so the spine is never empty.
pub fn parse_structure(source: &str, fmt: SourceFormat) -> Result<StructuredDoc, StructureError>;

/// Slice + verify an agent Segmentation (messy fallback). Locates each boundary
/// by FIRST exact verbatim match (error if absent/ambiguous); never trusts agent text.
pub fn slice_segmentation(source: &str, seg: &Segmentation) -> Result<StructuredDoc, StructureError>;

/// The invariant (§7). Runs in the structurer AND again in the writer (D9).
pub fn verify_verbatim(source: &str, doc: &StructuredDoc) -> Result<(), StructureError>;
```

---

## 5. Data flow

- **Clean markdown/plaintext:** `source.md` → `structure_source(format=markdown)`
  → deterministic verbatim `StructuredDoc` (+ `source_text` + spans) → agent
  atomizes each returned paragraph → `ingest_document_inline(tree + atoms +
  source_text + spans)` → writer re-runs `verify_verbatim` → persist (embed
  verbatim text).
- **Messy text:** agent reads the raw text, returns a `Segmentation` (boundary
  verbatim strings, advisory offsets) → `structure_source(text, segmentation)`
  locates by exact match + slices → same tail.
- **HTML/CNXML:** the Python emitter parses the DOM, emits verbatim `text` per
  block (+ `source_text`/spans where feasible) → `ingest_document` → same tail.

The agent must pass the **same** source text the offsets/boundaries index into;
the writer guard (D9) catches drift and rejects with a precise diff.

---

## 6. Schema before / after

```
DocumentExtraction
  AFTER  { source, thesis, thesis_derivation, sections, relationships,
           source_text: Option<String> }          # NEW (D9): bytes for writer re-verify

Section
  BEFORE { title, summary, paragraphs }
  AFTER  { title, paragraphs,
           heading: Option<Span> }                 # summary removed; heading optional (D4/D7c)

Paragraph
  BEFORE { compound:String(req), supporting_text, atoms, generality,
           confidence, methodology, evidence_type, page, instruments_used,
           reagents_involved, conditions }
  AFTER  { text:String(req,verbatim), atoms, generality, confidence,
           methodology, evidence_type, page, instruments_used, reagents_involved,
           conditions, start:Option<usize>, end:Option<usize> }   # compound + supporting_text removed; span added
```

`confidence` is **retained** (default 0.8, `schema.rs::default_confidence`); its
semantics are unchanged — an evidence-clarity / source-reliability signal, never
a property of the (now-removed) compound.

**Note on `supporting_text`:** the removal is of the *schema-input* field only.
The internal `PlannedClaim.supporting_text` (`common/plan.rs`) is retained and
is now fed the verbatim paragraph `text`, so the formatted evidence passage for
both the paragraph node and its atoms quotes the **source paragraph** — verbatim
and guard-verified, rather than a near-exact LLM quote. (For atoms this means
the passage is the *full parent paragraph*: more faithful, but coarser than the
old targeted excerpt — an accepted trade.)

---

## 7. Verbatim guard (the invariant, in detail)

Input: `source_text` and the ordered spans (heading + paragraph) of a
`StructuredDoc`. Assertions:

1. **Byte-exact (fail-closed):** for every span, `source_text.get(start..end)`
   (checked — never panicking index) returns `Some(s)` with `s == span.text`.
   A `None` (offset mid-codepoint, e.g. inside β/Å/μ) → structured
   `StructureError{span, expected, got:None}`, **not** a panic.
2. **Ordered & non-overlapping:** spans strictly increasing, no overlap.
3. **Coverage — no uncaptured prose:** every *inter-span* gap contains only
   inter-block whitespace + enumerated markup punctuation (heading markers,
   list bullets, fence delimiters, table pipes). The check forbids **uncaptured
   prose**, not all non-whitespace. Pre-first-span and post-last-span regions
   (title / frontmatter / back-matter) are intentionally **out-of-spine**
   (captured via `DocumentSource` metadata + the D5 thesis span) and are *not*
   required to be whitespace — so YAML frontmatter does not trigger rejection.
4. **Non-empty:** no zero-length / whitespace-only paragraph.

On any failure → reject the whole document with `{span, expected, got}`. The
guard never repairs by paraphrasing. Per **D9** it runs in the structurer (fail
fast) **and** re-runs in `do_ingest_document` against the carried
`source_text`+spans (defense-in-depth against agent drift between the two).

---

## 8. Migration

Forward-only, gated by `PIPELINE_VERSION_BASE`:

- Bump `hierarchical_extraction_v1` → `hierarchical_extraction_v2`. The
  `processed_by` edge + version gate (`effective_pipeline_version`,
  `has_processed_by_edge`) makes same-version re-runs idempotent and marks v2 a
  clean boundary.
- Existing paragraph/section nodes keep their IDs (the old `compound_claim_id`
  hashed `compound`/`summary`); they are **not** rewritten.
- **Atoms in the untouched corpus keep their IDs** — `atom_id` hashes atom
  text, which is not rewritten — so existing CDST evidence survives. *Caveat:*
  this is a property of *not re-ingesting*. A v2 *re-atomization* of a paper
  feeds the atomizer verbatim text instead of the old compound, so atom strings
  (and thus `atom_id`, which is text-keyed and LLM-nondeterministic) may differ;
  cross-source convergence across the v1↔v2 boundary is an assumption, not a
  guarantee.
- **Dual-live hazard:** until backfilled, the same DOI can surface both a v1
  paraphrase spine and a v2 verbatim spine in retrieval. Forward-only scope
  disclaims this; the future backfill MUST `supersede` the v1 section/paragraph
  claims **and null their embeddings in the same transaction** (per the
  embedding-on-`is_current` invariant). Corpus backfill is out of scope here and
  must be done deliberately — never by accidental re-ingest.
- **Corpus-mix during transition:** level-2 recall and the cross-source matcher
  (`cross_source_sweep`) will consume a mix of v1-paraphrase and v2-verbatim
  level-2 embeddings (plus workflow `Step` nodes, out of scope per D8).
  Persist `properties.spine_text_kind ∈ {paraphrase_v1, verbatim_v2, extracted_v2}`
  (verbatim_v2 = Tier-1 byte-exact md/plaintext; extracted_v2 = Tier-2 faithful
  HTML/CNXML extraction) so the mix is filterable. Matcher candidates shift
  from claim-shaped to prose-shaped; `cross_source_sweep` stages to a review
  queue, so this needs no code change beyond the property.

---

## 9. Testing

- **Unit (`structure.rs`):**
  - markdown headings + blank-line paragraphs → exact byte offsets;
  - **every block type** — bulleted/numbered (incl. tight) list, fenced code
    block, GFM table — is captured as its own paragraph-span and **does NOT**
    trigger coverage rejection;
  - **headingless** document → one implicit whole-document section (spine
    non-empty);
  - **duplicate headings** ("Results" twice) → **distinct** `section_id`s and no
    self-loop `section_follows` (ID-collision regression);
  - **mid-codepoint** span → graceful `StructureError`, not a panic;
  - guard rejects altered text, overlapping spans, and content-bearing gaps;
  - `slice_segmentation` locates boundaries by exact match and round-trips.
- **Property test:** spans + interstitial whitespace/markup reconstruct the
  in-spine body (nothing prose lost, nothing invented).
- **Integration (no live LLM):** call `structure_source` on a known markdown doc
  → fill `atoms` with a canned set → `ingest_document_inline` (mock-embedder
  harness) → assert paragraph node `content` byte-equal to the source paragraph,
  `spine_text_kind = verbatim_v2`, `continues_argument`/`section_follows`/
  `decomposes_to` wired, atoms decomposed under each paragraph, CDST present on
  atoms; the writer re-runs `verify_verbatim` against the threaded
  `source_text`+spans. (Approach C splits structure from atomization, so the
  end-to-end test cannot call a real LLM — it injects canned atoms.)
- **Python parsers:** regenerate fixtures for `extract_html.py` /
  `extract_textbook.py`; update `structured_source_glue.rs` +
  `test_structured_source_parsers.py` to `p.text`.
- **Council-of-Critics** (project convention) on every new test: reject
  tautological / mock-shaped / happy-path-only tests; the guard test uses a real
  source string and asserts byte-exactness.
- **Regression:** `ingest_document_smoke`, `link_hierarchical_smoke`,
  `pr_hierarchical_ingest_test` stay green.
- **CI gate:** `cargo fmt --check` + `cargo clippy -D warnings` before commit.
- **Acceptance criterion:** the §2 verbatim invariant (verified by the §7 guard)
  is the governing acceptance metric. Retrieval recall is **not** gated — a
  smoke-level sanity check on v2 retrieval is acceptable but out of scope; the
  compound is removed because it is not source text, not on a claim that it hurt
  retrieval.

---

## 10. Risks / open items

- **Markdown lib:** add `pulldown-cmark` for source offsets
  (`into_offset_iter`). Reconstructing sections from heading + block events is
  the fiddly part — the plan must map block events to spans explicitly rather
  than assuming `Paragraph` events cover all content.
- **Embedding token limit:** a verbatim paragraph can exceed the OpenAI
  8191-token embed limit (vs a one-line compound). This is a *wiring* gap:
  `epigraph_embeddings::tokenizer` + `DEFAULT_MAX_TOKENS = 8191` exist but
  `McpEmbedder` never calls them, so today an over-budget text stores
  **unembedded** (best-effort `false`) and a backfill re-hits the same 400
  forever. Mitigation: truncate the **embedding input** in `embed.rs::generate`
  via the tokenizer before the OpenAI call. The **stored claim `content` stays
  full verbatim** — "never truncate the stored claim" is preserved; only the
  vector is computed over the head of a rare oversized block (giant code
  block/table, almost never real prose). Splitting over-budget blocks into
  multiple byte-exact spans is rejected here — it would cut code blocks/tables
  mid-row.
- **Level-1 retrieval shift (D4):** section nodes now embed a bare verbatim
  heading ("Introduction", "3. Results"). Section-tier recall is intentionally
  de-emphasized in favor of paragraph nodes; the plan may exclude level-1 from
  embedding entirely. A synthesized summary is rejected — it breaks §2.
- **Heading span content:** set `Section.heading` to the heading's *content*
  range (leading `#`/markup fall into the legal §7.3 gap), keeping it verbatim.
- **New tool surface:** `structure_source` appears in `tools/list`; scope-gate
  it consistently with the other ingest tools.
- **Offset drift:** the agent must segment over the exact text it later submits;
  the D9 double guard is the safety net.

---

## 11. Out of scope

- The `workflow` / `Step.compound` ingest path (symmetric follow-up).
- Backfilling / re-ingesting the existing paper corpus to v2.
- **HTML/CNXML in the Rust structurer** — handled by the existing Python
  emitters (updated to verbatim per §4.1); the Rust parser is markdown +
  plaintext only (D10).
- Any change to atom semantics, CDST, generality scoring, or `relationships[]`
  cross-link handling.

---

## 12. Council review — amendments applied

Adversarial Council-of-Critics (6 lenses → per-finding refutation → chair
synthesis). 33 findings raised, **5 refuted**, 28 kept. Verdict:
**AMEND_THEN_SHIP**. Resolutions:

| Finding (kept) | Severity | Resolution in this revision |
|----------------|----------|------------------------------|
| Writer guard unachievable (no spans/source_text) | blocker | **D9** — optional `source_text`+spans; writer re-verifies (§4.1, §7). |
| HTML normalize→markdown breaks byte-exactness | blocker | **D10** — Rust structurer = md+plaintext; HTML stays on Python emitters (§4.1, §11). |
| Coverage guard rejects clean markdown (lists/code/tables) | major | §4.2/§7.3 — every top-level block → own span; "no uncaptured prose". |
| `compound_claim_id` intra-doc collision | major | §4.1/§4.2 — fold section/paragraph path into ID material; §9 regression test. |
| Byte index panics on codepoint offset | major | §7.1 — checked `.get()`; UTF-8 byte offsets declared (D2); §9 test. |
| Headingless / pre-heading content unrepresentable | major | §4.2 — `heading: Option<Span>` + implicit whole-doc section. |
| Messy branch offset-primary / reject-only / `Segmentation` undefined | major | §4.2/§5 — `Segmentation` carries boundary strings; locate by exact match, offsets advisory. |
| §4 omits Python emitters + glue test (compile break) | major | §4.1 — emitters + glue test + CNXML-retained added. |
| ~13 minor clarity/robustness items | minor | §1 wording, §2 thesis carve-out, §6 grounding reword, §8 atom-ID + dual-live + corpus-mix, §10 embed-limit, §9 acceptance criterion. |

**Refuted (not actioned), for provenance:**
- *"`ingest_literature.rs` is a second paraphrase path"* — it writes flat claim
  nodes (no spine edges); §2 invariant is spine-scoped, so it doesn't apply.
- *"Atoms get new IDs on re-ingest, breaking §8"* — §8 already disclaims
  re-ingest continuity; captured as a clarity caveat in §8 instead.
- *"Unicode normalization breaks the guard"* — the guard is an intra-submission
  self-check (slices the same `text` the spans index), not a compare vs an
  external file; visually-identical normalized text passes.
- *"Two-column PDF stores interleaved nonsense"* — §2 already declares the
  guarantee is byte-provenance, not semantic linearization; input-quality issue
  upstream of the defined `raw source`.
- *"`paragraph.confidence` has no defined source"* — `confidence` has a serde
  default and evidence-clarity semantics independent of the removed compound.
