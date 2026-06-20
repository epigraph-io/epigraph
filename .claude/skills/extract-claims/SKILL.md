# Extract Claims — Verbatim-Spine Extraction Protocol

Extract epistemic claims from text or documents by first **structuring the source
verbatim** (deterministic Rust splits the source into byte-exact section/paragraph
spans), then **atomizing** each verbatim paragraph into atomic claims, then ingesting
the complete `DocumentExtraction` into the EpiGraph knowledge graph.

> **v2 change:** paragraph nodes now store the **verbatim source text** (Tier 1),
> not an LLM paraphrase. The old `compound` / `supporting_text` / section `summary`
> fields are removed. The LLM is fenced to **atoms only** — it never rewrites the
> spine text. See spec `docs/superpowers/specs/2026-06-18-deterministic-spine-ingest-design.md`.

## When to use

Use this skill when asked to:
- Analyze a document or text for epistemic claims
- Extract and ingest claims from research papers, reports, or discussions
- Build a knowledge graph from unstructured text using the hierarchical decomposition pipeline
- Ingest a structured claim hierarchy (thesis → verbatim sections → verbatim paragraphs → atomic claims)

## The 4-Stage Flow

```
  raw text ──▶ (1) structure_source ──▶ verbatim skeleton ──▶ (2) atomize in place
                                          (text+span filled,        (fill atoms[],
                                           atoms[] EMPTY)            generality[], …)
                                                                          │
   (4) ingest_document_inline ◀── (3) thesis + relationships ◀───────────┘
        (writer re-verifies spans)
```

### Stage 1: Structure (deterministic — `structure_source`)

Call the **`structure_source`** MCP tool to slice the raw source into a verbatim
section/paragraph tree. It returns a `DocumentExtraction` JSON with `source_text`
at the top, byte-exact `span`s on every node, the verbatim paragraph `text`
populated, and **`atoms` left EMPTY** for you to fill.

```
structure_source({
  text:   "<the full raw source>",
  source: { "title": "...", "doi": "...", "source_type": "Paper", ... },
  format: "markdown"        // or "plaintext"
})
```

- **Clean markdown / plaintext** → pass `format: "markdown"` (headings open
  sections; blank-line blocks / lists / code / tables become whole-block
  paragraph spans) or `format: "plaintext"` (blank-line blocks under one
  implicit section). Leave `segmentation` unset.
- **Messy text** (no clean structure, or the deterministic parse mis-splits) →
  pass an optional `segmentation`: per-section verbatim **boundary strings** that
  the tool LOCATES verbatim in the source and slices on. Offsets are not
  required — the boundary string is the authoritative locator, found in order
  from a forward cursor (so duplicate text resolves correctly):

  ```
  structure_source({
    text:   "<raw source>",
    source: { ... },
    format: "plaintext",
    segmentation: {
      "sections": [
        { "heading": "Intro heading line",          // verbatim, or null for an implicit section
          "paragraphs": ["Alpha block text.", "Beta block text."] }
      ]
    }
  })
  ```

`structure_source` is **read-only** (no DB writes). Its output is the skeleton you
enrich in Stages 2–3. **Never edit a paragraph's `text` or `span`** — they are
byte-exact slices of `source_text`, and the writer re-verifies them at ingest.

### Stage 2: Atomize each verbatim paragraph

For every paragraph the structurer returned, read its verbatim `text` and
decompose it into **atomic claims** — single subject-predicate-object
propositions — writing them into **that paragraph's `atoms` array**.

Each atom must:
- Be a single logical assertion (one fact, one relationship)
- Resolve all pronouns to explicit entities (no "it", "they", "this")
- Preserve exact numbers, names, chemical/gene symbols, measurements
- Contain **only** content present in the paragraph's verbatim `text` — never
  invent facts the `text` does not state

Assign each atom a **generality score** in the paragraph's parallel `generality`
array (`generality[i]` scores `atoms[i]`, index-aligned):
- **0 (Foundational)** — specific facts, measurements, observations (e.g.
  "Enzyme X has activity 5.2 μmol/min")
- **1 (Intermediate)** — general principles, methods, relationships (e.g.
  "Enzymes have optimal pH ranges")
- **2 (Specialized)** — domain-specific theoretical frameworks (e.g.
  "Michaelis-Menten kinetics apply to this system")

Set the paragraph's **`evidence_type`** (one value from the closed set below;
atoms inherit it) and **`confidence`** (0.0–1.0).

Record **cross-atom relationships** in the top-level `relationships` array, by
path, only when the source explicitly states them (see the schema below).

### Stage 3: Thesis (verbatim-first)

- If the document has an explicit thesis/abstract, set the top-level `thesis`
  string to the **verbatim** abstract/thesis sentence(s) and leave
  `thesis_derivation` at its default `"TopDown"`.
- If the thesis is implicit, synthesize it bottom-up from the atomized evidence
  and set `thesis_derivation: "BottomUp"` to flag that it was derived rather than
  quoted.

### Stage 4: Submit (`ingest_document_inline`)

Pass the enriched `DocumentExtraction` directly to **`ingest_document_inline`**:

```
ingest_document_inline({ extraction: <the enriched DocumentExtraction> })
```

Because `structure_source` populated `source_text` and per-node `span`s, the
writer **re-runs the verbatim guard** — re-verifying every paragraph `text`
against `source_text[span.start..span.end]` and rejecting any drift. The ingest
lands the full graph: paper node, claims at every level down to atoms,
`decomposes_to` / `section_follows` / `supports` edges, evidence, traces,
embeddings, and CDST mass functions for atoms.

(The file-path variant `ingest_document({ file_path })` still exists for agents
that must stage JSON on disk first, but `ingest_document_inline` is the primary,
inline path and the one this flow uses.)

#### Fire-and-forget — response is a queue acknowledgement, not confirmation

`ingest_document_inline` (and `ingest_document`) return **immediately** after
spawning a detached Tokio task; the response is:

```json
{ "status": "queued", "doi": "...", "title": "...", "note": "..." }
```

**The write may still be in flight when you receive this.** Always verify with
`check_already_ingested` (or `query_paper`) before treating the paper as landed.
Do not fire a second ingest call based on a timeout — the background task is
still running. One write at a time per paper is the correct pattern.

`ingest_document_spine`, by contrast, IS synchronous — it must return
`new_paragraph_paths` before the atomization LLM call can proceed. Spine writes
are lightweight (no atoms, no CDST) and complete within typical timeout windows.

## The DocumentExtraction JSON Schema

This is the shape `structure_source` returns and `ingest_document_inline` parses.
After Stage 1 you receive it with `text`/`span`/`source_text` filled and `atoms`
empty; you enrich it in place. Verbatim ground-truth example
(`crates/epigraph-ingest/tests/fixtures/sample_hierarchical.json`):

```json
{
  "source": {
    "title": "The Advantage of Serial Entrepreneurs",
    "doi": "10.1234/test-serial-ent",
    "source_type": "Paper",
    "authors": [
      {"name": "Shaw, K.", "affiliations": ["Stanford University"]},
      {"name": "Sorensen, A.", "affiliations": ["Stanford University"]}
    ],
    "journal": "Management Science",
    "year": 2019,
    "metadata": {}
  },
  "thesis": "Serial entrepreneurs outperform novice entrepreneurs due to transferable learning across ventures, not selection effects.",
  "thesis_derivation": "TopDown",
  "sections": [
    {
      "title": "Introduction",
      "paragraphs": [
        {
          "text": "Serial entrepreneurs are defined as founders of more than one firm. Approximately 10% of Danish entrepreneurs are serial, with 73% operating as portfolio entrepreneurs running concurrent ventures.",
          "span": { "start": 16, "end": 213 },
          "atoms": [
            "Serial entrepreneurs are defined as entrepreneurs who have founded more than one firm.",
            "Approximately 10% of entrepreneurs in Denmark are serial entrepreneurs.",
            "73% of serial entrepreneurs are portfolio entrepreneurs who run two or more businesses concurrently."
          ],
          "generality": [0, 2, 2],
          "confidence": 0.92,
          "methodology": "extraction",
          "evidence_type": "statistical"
        }
      ]
    },
    {
      "title": "Results",
      "paragraphs": [
        {
          "text": "Serial entrepreneurs achieve 67% higher sales than novice entrepreneurs. This advantage is not explained by personal characteristics such as education, gender, or age.",
          "span": { "start": 224, "end": 388 },
          "atoms": [
            "Serial entrepreneurs achieve 67% higher sales than novice entrepreneurs.",
            "The serial entrepreneur sales advantage is not explained by personal characteristics such as education, gender, or age."
          ],
          "generality": [2, 1],
          "confidence": 0.95,
          "methodology": "statistical",
          "evidence_type": "statistical"
        },
        {
          "text": "Among serial entrepreneurs, 73% are portfolio type. Portfolio entrepreneur sales are 77% above novices versus only 32% for sequential entrepreneurs.",
          "span": { "start": 390, "end": 537 },
          "atoms": [
            "Portfolio entrepreneur sales are 77% above novice entrepreneur sales.",
            "Sequential entrepreneur sales are 32% above novice entrepreneur sales.",
            "The serial entrepreneur sales advantage is concentrated in portfolio entrepreneurs."
          ],
          "generality": [2, 2, 1],
          "confidence": 0.93,
          "methodology": "statistical",
          "evidence_type": "statistical"
        }
      ]
    }
  ],
  "relationships": [
    {
      "source_path": "sections[1].paragraphs[0].atoms[0]",
      "target_path": "sections[1].paragraphs[1].atoms[2]",
      "relationship": "supports",
      "rationale": "The 67% overall advantage is explained by concentration in portfolio entrepreneurs"
    }
  ],
  "source_text": "<the full raw source string the spans index into>"
}
```

> The `span`/`heading_span` byte offsets above are illustrative — in a real
> extraction `structure_source` fills them so each `text` is byte-equal to
> `source_text[span.start..span.end]`, and the writer rejects any mismatch.
> Never hand-author or edit them.

### Schema field reference

| Field | Type | Purpose |
|-------|------|---------|
| `source` | object | Source metadata: `title`, `doi`/`uri`, `source_type` (PascalCase: `Paper`, `Textbook`, `InternalDocument`, `Report`, `Transcript`, `Legal`, `Tabular`), `authors[{name, affiliations[]}]`, `journal`, `year`, `metadata` |
| `thesis` | string \| null | The paper's main claim — verbatim abstract span when present, else a bottom-up synthesis |
| `thesis_derivation` | enum | `"TopDown"` (default — explicit/quoted) or `"BottomUp"` (synthesized) |
| `sections[]` | array | Document structure, in order. Each: `title`, optional `heading_span {start,end}`, `paragraphs[]` |
| `sections[].paragraphs[].text` | string | **Verbatim** source paragraph (Tier 1). DO NOT edit — it is a byte-exact slice |
| `sections[].paragraphs[].span` | {start,end} \| null | Byte offsets of `text` into `source_text`; the writer re-verifies against it |
| `sections[].paragraphs[].atoms` | string[] | Atomic S-P-O claims you write from `text`. **Plain strings, not objects** |
| `sections[].paragraphs[].generality` | int[] | Parallel to `atoms`: `generality[i]` scores `atoms[i]` (0/1/2) |
| `sections[].paragraphs[].confidence` | float | 0.0–1.0; evidence quality and source clarity (default 0.8) |
| `sections[].paragraphs[].methodology` | string \| null | How the paragraph's evidence was produced (e.g. `extraction`, `statistical`) |
| `sections[].paragraphs[].evidence_type` | string \| null | One value from the closed set below; atoms inherit it |
| `relationships[]` | array | Top-level inter-atom edges, **path-based** (see below) |
| `source_text` | string \| null | The original source bytes the spans index into. Present ⇒ the writer re-runs the verbatim guard |

**Atoms are plain strings, `generality` is a parallel array.** This is the most
common shape mistake: `atoms` is `["claim one", "claim two"]` (NOT objects), and
`generality` is `[0, 1]` aligned by index — `generality[i]` is the score for
`atoms[i]`. Keep the two arrays the same length.

**`relationships[]` are path-based, top-level.** Each entry references atoms by
their position path, not by id:

```json
{
  "source_path": "sections[1].paragraphs[0].atoms[0]",
  "target_path": "sections[1].paragraphs[1].atoms[2]",
  "relationship": "supports",          // supports | contradicts | refines
  "rationale": "why this edge holds"   // optional; "strength" (float) also optional
}
```

Include a relationship only when the source **explicitly** states it. Do NOT
infer relationships.

### `evidence_type` — pick one from this closed set

Choose the single value that best describes *how* the claim is supported. Set it
on the **paragraph** object (atoms inherit it). Anything outside this set is
dropped at plan-build time, so do **not** invent values:

| Value | Use when the support is… |
|-------|--------------------------|
| `empirical` | direct observation, measurement, or experiment |
| `statistical` | aggregate/quantitative analysis over a sample |
| `regulatory` | a binding rule, statute, standard, or formal approval |
| `logical` | a derivation or argument made within the text |
| `testimonial` | attributed expert testimony or a sourced statement |
| `circumstantial` | indirect or inferred support |
| `conversational` | informal/anecdotal report (e.g. a transcript remark) |

When unsure between two, prefer the stronger (higher in this table); if none
fit, omit the field rather than guessing.

```json
{
  "text": "Two empirical observations support the thesis. Both were measured directly in independent assays.",
  "atoms": ["Observation one was measured directly.", "Observation two was measured directly."],
  "generality": [0, 0],
  "confidence": 0.8,
  "methodology": "extraction",
  "evidence_type": "empirical"
}
```

## Quality Gate — Council of Critics (atom faithfulness)

The verbatim spine removes paraphrase risk at the paragraph level — the
hallucination risk that remains is in **atomization**. Apply the Council to every
paragraph's atoms:

- **The Skeptic — faithfulness:**
  - Is every atom actually stated in this paragraph's verbatim `text`, or am I
    inferring beyond it?
  - Does each atom preserve the exact numbers, names, and qualifiers in `text`?
  - Is the `confidence` justified by the evidence clarity in `text`?

- **The Logician — no invention:**
  - Does any atom assert content absent from `text`? If so, drop it.
  - Is each atom a single, falsifiable S-P-O proposition (not a multi-part assertion)?
  - Are all pronouns resolved to explicit entities?

- **The Architect — structure:**
  - Does an atom duplicate one already extracted (here or in the graph)?
  - Should two atoms be wired with a `relationships[]` edge the `text` states?
  - Is the thesis explicit (`TopDown`) or does it need `BottomUp` synthesis?

**Rejection rule:** if an atom is not grounded in the paragraph's verbatim `text`,
do NOT force-fit it — drop it and note why in the report. **Never** edit the
paragraph `text` to make an atom fit; the spine text is byte-exact and re-verified.

## Key Rules

1. **Never mutate `text` or `span`.** They are byte-exact slices of `source_text`;
   the writer re-verifies them and rejects any drift. Enrich `atoms`,
   `generality`, `evidence_type`, `confidence`, `thesis`, and `relationships` only.
2. **Atomic claims are single S-P-O propositions.**
   - ✓ "Protein X binds ligand Y"
   - ✗ "Protein X binds ligand Y and undergoes conformational change" (two atoms)
3. **Resolve all pronouns** — no "it", "they", "this", "that" in final atoms.
4. **Preserve specificity** — exact numbers, chemical names, gene symbols,
   measurements. Do NOT round or generalize.
5. **No information beyond the paragraph's `text`.** Cross-referencing prior
   knowledge to disambiguate entities ("insulin" = "human insulin, INS gene") is
   allowed; inferring new facts is not.
6. **Cross-atom relationships are explicit** — only include `supports`/
   `contradicts`/`refines` edges the source explicitly states.

## Report After Ingestion

Summarize:
- Sections and paragraphs structured (verbatim spans)
- Total atoms generated, broken down by generality (0/1/2)
- Atoms rejected by the Council (with reasons)
- Relationships identified
- Thesis derivation used (`TopDown` verbatim vs `BottomUp` synthesis)
- Confirmation message with assigned claim IDs (`paper_id` and node IDs)
