# Extract Claims — Hierarchical Extraction Protocol

Extract epistemic claims from text, documents, or conversations using a 4-stage hierarchical protocol, then ingest the complete DocumentExtraction into the EpiGraph knowledge graph.

## When to use

Use this skill when asked to:
- Analyze a document or text for epistemic claims
- Extract and ingest claims from research papers, reports, or discussions
- Build a knowledge graph from unstructured text using the hierarchical decomposition pipeline
- Ingest structured claim hierarchies (thesis → section summaries → paragraph compounds → atomic claims)

## The 4-Stage Extraction Cascade

### Stage 1: Document Structure & Section Extraction

Read the entire document and produce:
- **Document metadata**: Title, authors, publication date, source URL, document type
- **Section inventory**: Identify logical sections (abstract, introduction, methods, results, discussion, conclusion)
- **Section titles and summaries**: For each section, write a 1-2 sentence summary capturing the main point

**Output**: Section list with titles and summaries

### Stage 2: Paragraph-Level Compound Extraction

For each section, work through the prose paragraph-by-paragraph:
- Extract the main **compound claim** — a multi-part assertion that has internal logical structure but is still grounded in one section
- Provide **supporting_text** — exact or near-exact quote(s) from the document backing the compound
- Mark **confidence** (0.0–1.0) based on evidence clarity and source reliability

**Apply the Council of Critics here** — this stage has the highest hallucination risk. Each paragraph extraction must pass:
- **The Skeptic**: Is this really a claim, or noise? Is supporting text present and accurate?
- **The Logician**: Is the compound extracting actual document content, not inferring unsupported conclusions?
- **The Architect**: Does this compound relate to others or duplicate an existing claim?

**Output**: List of compound claims per section, each with supporting_text and confidence

### Stage 3: Atomic Decomposition with Generality Scoring

For each compound claim, decompose into **atomic claims** — single subject-predicate-object propositions.

Each atom must:
- Be a single logical assertion (one fact, one relationship)
- Resolve all pronouns to explicit entities
- Preserve specific numbers, names, quantitative details
- Include only information explicitly stated (no inferences beyond the compound)

Assign each atom a **generality score**:
- **0 (Foundational)**: Specific facts, measurements, observations (e.g., "Enzyme X has activity 5.2 μmol/min")
- **1 (Intermediate)**: General principles, methods, relationships (e.g., "Enzymes have optimal pH ranges")
- **2 (Specialized)**: Domain-specific theoretical frameworks (e.g., "Michaelis-Menten kinetics apply to this system")

Include **cross-atom relationships** when explicitly stated in the source:
- `supports`: Atom Y directly supports atom X
- `contradicts`: Atom Y contradicts atom X
- `refines`: Atom Y adds specificity or conditions to atom X

**Output**: Flat list of atoms with generality scores and inter-atom relationships

### Stage 4 (Optional): Bottom-Up Thesis Derivation

If the document structure is weak or thesis is implicit, perform bottom-up synthesis:
- Collect section summaries
- Identify the core hypothesis or research question
- Infer the document thesis as: "The paper demonstrates/claims that [synthesized claim from section evidence]"

**Only perform if needed**. If the document has explicit thesis/abstract, use that directly.

## The DocumentExtraction JSON Schema

Assemble all stages into a single `DocumentExtraction` JSON structure:

```json
{
  "document": {
    "id": "unique-source-hash",
    "title": "Paper/Document Title",
    "authors": ["Author One", "Author Two"],
    "publication_date": "2025-03-15",
    "source_url": "https://example.com/paper.pdf",
    "document_type": "research-paper",
    "content_hash": "sha256-hash-of-full-text"
  },
  "thesis": {
    "claim": "The core hypothesis or main finding of the document",
    "confidence": 0.85,
    "source": "Abstract, conclusion, or derived from sections"
  },
  "sections": [
    {
      "id": "section-001",
      "title": "Introduction",
      "summary": "This section contextualizes the research question within prior work and establishes the motivation.",
      "paragraphs": [
        {
          "id": "para-001",
          "compound_claim": "Protein folding is a fundamental problem in structural biology, yet current prediction methods have error rates exceeding 5 Å in many cases.",
          "supporting_text": "\"Protein folding remains challenging. State-of-the-art methods achieve ~7 Å RMSD on test sets (Smith et al. 2024).\"",
          "confidence": 0.82,
          "atoms": [
            {
              "id": "atom-001",
              "claim": "Protein folding is a problem in structural biology",
              "generality": 0,
              "resolved": true
            },
            {
              "id": "atom-002",
              "claim": "Current prediction methods have error rates exceeding 5 Å",
              "generality": 0,
              "resolved": true
            }
          ]
        }
      ]
    }
  ],
  "atoms": [
    {
      "id": "atom-global-001",
      "claim": "The protein αβγ adopts a β-barrel structure in solution",
      "generality": 0,
      "evidence_type": "empirical",
      "supporting_text": "\"Crystal structures confirm β-barrel topology (Jones et al. 2024, PDB: 8XYZ)\"",
      "confidence": 0.91,
      "resolved": true
    },
    {
      "id": "atom-global-002",
      "claim": "β-barrel proteins are thermally stable above 60°C",
      "generality": 1,
      "evidence_type": "statistical",
      "supporting_text": "\"Melting temperatures for β-barrels range 65–85°C in thermal shift assays.\"",
      "confidence": 0.78,
      "resolved": true
    }
  ],
  "relationships": [
    {
      "source_atom": "atom-global-001",
      "target_atom": "atom-global-002",
      "relationship": "supports",
      "explanation": "The β-barrel structure directly contributes to thermal stability"
    },
    {
      "source_atom": "atom-global-003",
      "target_atom": "atom-global-001",
      "relationship": "contradicts",
      "explanation": "Alternative study found α-helical structure; contradicts β-barrel claim"
    }
  ]
}
```

### Schema Explanation

| Field | Purpose |
|-------|---------|
| `document` | Source metadata (title, authors, URL, hash for integrity) |
| `thesis` | The paper's main claim or hypothesis |
| `sections` | Organized by document structure; each contains paragraph compounds and atoms |
| `atoms` | Flat list of ALL atomic claims, including implicit relationships |
| `relationships` | Inter-atom edges: supports, contradicts, refines |
| `confidence` | 0.0–1.0; based on evidence quality and source clarity |
| `generality` | 0 (specific fact), 1 (general principle), 2 (specialized theory) |
| `resolved` | Boolean; true if all pronouns are explicit, entities named |

## Submission via `ingest_document`

Once the `DocumentExtraction` is assembled:

1. **Write to file**: Save the JSON to `/tmp/extraction_<source_hash>.json`
2. **Call ingest_document**: Use the MCP tool to submit:
   ```
   ingest_document({
     file_path: "/tmp/extraction_<source_hash>.json",
     metadata: {
       extraction_method: "hierarchical",
       extractor_version: "1.0",
       timestamp: "2025-03-31T14:23:00Z"
     }
   })
   ```

The API will:
- Parse and validate the JSON schema
- Create the document node
- Ingest all sections, paragraphs, atoms, and relationships
- Return confirmation with claim IDs for reference

**This replaces the old per-claim `submit_claim` approach** — all claims are now ingested as a single DocumentExtraction transaction, preserving provenance and structure.

## Quality Gate — Council of Critics

Apply at **Stage 2 (Paragraph Extraction)** where hallucination risk is highest:

- **The Skeptic**:
  - Is the compound claim actually stated in the paragraph, or am I inferring?
  - Does the supporting_text exactly (or nearly) match the source?
  - Is the confidence justified by evidence clarity?

- **The Logician**:
  - Does the compound have falsifiable, testable structure?
  - Are all propositions atomic or properly decomposed?
  - Would future claims reference this correctly?

- **The Architect**:
  - Does this duplicate a prior extraction?
  - Should it reference or be related to other claims instead?
  - Is the document structure clear, or is Stage 4 (bottom-up thesis) needed?

**Rejection rule**: If any paragraph fails the Council, flag it explicitly in the report. Do NOT force-fit it into atoms. Reject the compound, note why, and move on.

## Key Rules for All Stages

1. **Atomic claims are single S-P-O propositions**: "Subject + verb + object" with no compound logic. Examples:
   - ✓ "Protein X binds ligand Y"
   - ✗ "Protein X binds ligand Y and undergoes conformational change" (two atoms)

2. **Resolve all pronouns**: No "it", "they", "this", "that" in final atoms. Must name the entity explicitly.

3. **Preserve specificity**: Exact numbers, chemical names, gene symbols, measurements. Do NOT round or generalize.

4. **No information beyond the source**: Cross-referencing with prior knowledge is allowed to disambiguate entities ("insulin" = "human insulin, INS gene"), but do NOT infer new facts.

5. **Supporting text must be grounded**: Every compound and atom needs exact or near-exact quotes from the document. Never invent supporting evidence.

6. **Cross-atom relationships are explicit**: Only include relationships (supports, contradicts, refines) when the source explicitly states them. Do NOT infer relationships.

## Report After Ingestion

Summarize:
- Total compounds extracted
- Total atoms generated (broken down by generality: 0/1/2)
- Atoms rejected by Council (with reasons)
- Relationships identified
- Confirmation message with assigned claim IDs
- Any Stage 4 thesis derivation performed and reasoning
