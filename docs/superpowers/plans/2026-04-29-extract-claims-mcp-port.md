# Extract-Claims MCP Tool Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the hierarchical document decomposition pipeline (extract-claims SKILL + `ingest_document` MCP tool) from V2 nano into the public `epigraph-io/epigraph` repo.

**Architecture:** The skill (markdown) instructs an LLM to produce a `DocumentExtraction` JSON. `epigraph_ingest::builder::build_ingest_plan` (already in public) converts that JSON into a flat `IngestPlan { claims, edges, path_index }`. The new `ingest_document` MCP tool consumes the plan and writes claims/edges/evidence/embeddings/CDST evidence into Postgres via the public-repo idiom (split repository calls + batch CDST). Paper-as-node pattern is preserved by adding a small `PaperRepository`.

**Tech Stack:** Rust + sqlx + Axum/rmcp; PostgreSQL with pgvector.

**Out of scope (deferred to backlog):**
- Author affiliations/roles structured fields (V2 had `ensure_author_agent(name, affiliations, roles)`; public's `Agent::new` only takes a name — store extras in agent properties JSON).
- `find_capability_claim` lookup for processed_by edges to "ingest_paper"/"extract_document" capability nodes — public has no capability registry. Skip with a warning log.
- The V2 nano `extract.rs` Rust extraction cascade (Rust-side claude-CLI invocation). Not needed; the skill drives the LLM in chat.
- Per-claim auto-CDST. Use public's existing `auto_wire_ds_batch` instead.

---

## File Structure

**New files:**
- `.claude/skills/extract-claims/SKILL.md` — the skill (verbatim port from V2)
- `crates/epigraph-db/src/repos/paper.rs` — minimal PaperRepository: `create`, `find_by_doi`, `has_processed_by_edge`
- `crates/epigraph-db/tests/paper_repo_tests.rs` — integration tests

**Modified files:**
- `crates/epigraph-db/src/repos/mod.rs` — register paper module
- `crates/epigraph-db/src/lib.rs` — re-export PaperRepository
- `crates/epigraph-db/src/repos/edge.rs` — add `create_if_not_exists`
- `crates/epigraph-mcp/src/types.rs` — `IngestDocumentParams`, `IngestDocumentResponse`
- `crates/epigraph-mcp/src/tools/ingestion.rs` — `ingest_document` function (~250 lines)
- `crates/epigraph-mcp/src/server.rs` — wire `#[tool]` method
- `crates/epigraph-mcp/Cargo.toml` — add `epigraph-ingest` dependency (if not already there)

---

## Task 1: Port the extract-claims SKILL.md

**Files:**
- Create: `.claude/skills/extract-claims/SKILL.md`

- [ ] **Step 1.1: Copy SKILL.md from V2**

```bash
mkdir -p .claude/skills/extract-claims
cp /home/jeremy/EpigraphV2/EpiGraphV2/.worktrees/textbook-provenance/epigraph-nano/.claude/skills/extract-claims/SKILL.md .claude/skills/extract-claims/SKILL.md
```

Expected: file exists at `.claude/skills/extract-claims/SKILL.md`.

- [ ] **Step 1.2: Commit**

```bash
git add .claude/skills/extract-claims/SKILL.md
git commit -m "feat(skills): add extract-claims hierarchical extraction skill

Verbatim port from V2 nano. The 4-stage protocol (sections → paragraph
compounds → atomic decomposition → optional bottom-up thesis) drives the
LLM-side extraction; the resulting DocumentExtraction JSON is consumed by
the ingest_document MCP tool (separate commit)."
```

---

## Task 2: Add PaperRepository

V2 models papers as first-class graph nodes (`paper` entity type). The schema in public already supports this (the `papers` table exists in `001_initial_schema.sql:1332` and `paper` is in the edges entity_type CHECK constraint), but no repo wraps it. We need a thin one for ingest_document.

**Files:**
- Create: `crates/epigraph-db/src/repos/paper.rs`
- Modify: `crates/epigraph-db/src/repos/mod.rs`
- Modify: `crates/epigraph-db/src/lib.rs`
- Test: `crates/epigraph-db/tests/paper_repo_tests.rs` (or extend existing integration tests file)

- [ ] **Step 2.1: Confirm papers table columns**

```bash
grep -A 8 "CREATE TABLE public.papers" migrations/001_initial_schema.sql | head -15
```

Expected schema: `id uuid, doi text, title text, journal text, created_at timestamptz`. If extra columns appear (properties jsonb?), extend the repo accordingly.

- [ ] **Step 2.2: Implement PaperRepository**

Create `crates/epigraph-db/src/repos/paper.rs`:

```rust
//! Paper entity repository — papers are first-class nodes in the graph
//! (entity_type = "paper") used by hierarchical document ingestion.

use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

/// Row representation of the `papers` table.
#[derive(Debug, Clone)]
pub struct PaperRow {
    pub id: Uuid,
    pub doi: String,
    pub title: Option<String>,
    pub journal: Option<String>,
}

pub struct PaperRepository;

impl PaperRepository {
    /// Insert a new paper row. Each ingestion gets a fresh node — re-ingesting
    /// the same DOI returns a NEW paper row, intentionally; the caller links
    /// the new paper to prior papers with the same DOI via `same_source` edges
    /// (matching V2 semantics).
    #[instrument(skip(pool))]
    pub async fn create(
        pool: &PgPool,
        doi: &str,
        title: Option<&str>,
        journal: Option<&str>,
    ) -> Result<Uuid, DbError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO papers (doi, title, journal)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
            doi,
            title,
            journal,
        )
        .fetch_one(pool)
        .await?;
        Ok(row.id)
    }

    /// Find all paper rows with the given DOI, ordered by `created_at DESC`.
    #[instrument(skip(pool))]
    pub async fn find_by_doi(pool: &PgPool, doi: &str) -> Result<Vec<PaperRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, doi, title, journal
            FROM papers
            WHERE doi = $1
            ORDER BY created_at DESC
            "#,
            doi
        )
        .fetch_all(pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| PaperRow {
                id: r.id,
                doi: r.doi,
                title: r.title,
                journal: r.journal,
            })
            .collect())
    }

    /// Returns true if `paper_id` has any outgoing `processed_by` edge whose
    /// properties.pipeline matches `pipeline_version`. Used as a re-ingestion
    /// version gate.
    #[instrument(skip(pool))]
    pub async fn has_processed_by_edge(
        pool: &PgPool,
        paper_id: Uuid,
        pipeline_version: &str,
    ) -> Result<bool, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT 1 AS exists
            FROM edges
            WHERE source_id = $1
              AND source_type = 'paper'
              AND relationship = 'processed_by'
              AND properties ->> 'pipeline' = $2
            LIMIT 1
            "#,
            paper_id,
            pipeline_version
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.is_some())
    }
}
```

- [ ] **Step 2.3: Wire PaperRepository into mod.rs and lib.rs**

In `crates/epigraph-db/src/repos/mod.rs`, add (alphabetical order):

```rust
pub mod paper;
```

In `crates/epigraph-db/src/lib.rs`, find the existing `pub use repos::{...};` block and add `paper::PaperRepository` (alphabetical).

- [ ] **Step 2.4: Build to confirm sqlx queries pass compile-time check**

```bash
cargo build -p epigraph-db
```

Expected: clean build. If sqlx complains about `DATABASE_URL`, ensure the dev database is running (`docker ps | grep epigraph-postgres` should show it on `127.0.0.1:5432`) and `DATABASE_URL` is exported per `CLAUDE.md`.

- [ ] **Step 2.5: Add integration test**

Pattern: copy an existing repo test from `crates/epigraph-db/tests/` and follow its setup. Test cases:
- `create` then `find_by_doi` returns the inserted row.
- `find_by_doi` returns empty `Vec` for unknown DOI.
- `has_processed_by_edge` returns false before any edge, true after inserting an edge with matching properties.pipeline, false for a different pipeline string.

- [ ] **Step 2.6: Run the tests**

```bash
cargo test -p epigraph-db --test paper_repo_tests
```

Expected: all three tests pass.

- [ ] **Step 2.7: Commit**

```bash
git add crates/epigraph-db/src/repos/paper.rs crates/epigraph-db/src/repos/mod.rs crates/epigraph-db/src/lib.rs crates/epigraph-db/tests/paper_repo_tests.rs
git commit -m "feat(db): add PaperRepository for hierarchical document ingestion

The papers table existed in the 001 schema but had no repo wrapper.
Hierarchical document ingestion needs paper-as-node semantics (paper
node, paper -asserts-> claim, agent -authored-> paper edges) so we
add a thin repository over create/find_by_doi/has_processed_by_edge."
```

---

## Task 3: Add `EdgeRepository::create_if_not_exists`

V2 uses `insert_edge_if_not_exists(...)` extensively for idempotent re-ingestion (paper→capability_claim processed_by edges, paper→prior_paper same_source edges, claim→atom decomposes_to edges when an atom was deduped to an existing claim). Public's `EdgeRepository::create` always INSERTs — duplicates accumulate.

There is no unique index on `(source_id, target_id, relationship)` in the edges table (verified by reading `001_initial_schema.sql` constraint section). So we implement check-then-insert in a transaction.

**Files:**
- Modify: `crates/epigraph-db/src/repos/edge.rs`

- [ ] **Step 3.1: Add the helper**

After the existing `create()` method (~line 73), append:

```rust
    /// Like `create`, but if an edge with the same
    /// `(source_id, target_id, relationship)` triple already exists, returns the
    /// existing edge id without inserting. Idempotent.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool, properties))]
    pub async fn create_if_not_exists(
        pool: &PgPool,
        source_id: Uuid,
        source_type: &str,
        target_id: Uuid,
        target_type: &str,
        relationship: &str,
        properties: Option<serde_json::Value>,
        valid_from: Option<chrono::DateTime<chrono::Utc>>,
        valid_to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Uuid, DbError> {
        let mut tx = pool.begin().await?;
        let existing = sqlx::query!(
            r#"
            SELECT id FROM edges
            WHERE source_id = $1 AND target_id = $2 AND relationship = $3
            LIMIT 1
            "#,
            source_id,
            target_id,
            relationship,
        )
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(row) = existing {
            tx.commit().await?;
            return Ok(row.id);
        }

        let properties = properties.unwrap_or(serde_json::json!({}));
        let row = sqlx::query!(
            r#"
            INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
            "#,
            source_id,
            source_type,
            target_id,
            target_type,
            relationship,
            properties,
            valid_from,
            valid_to,
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.id)
    }
```

- [ ] **Step 3.2: Add a smoke test**

Append to `crates/epigraph-db/tests/edge_repo_tests.rs` (or create if it doesn't exist; mirror an existing repo test layout):

```rust
#[sqlx::test]
async fn create_if_not_exists_is_idempotent(pool: PgPool) {
    let src = Uuid::new_v4();
    let tgt = Uuid::new_v4();
    let id1 = EdgeRepository::create_if_not_exists(
        &pool, src, "claim", tgt, "claim", "decomposes_to", None, None, None,
    )
    .await
    .unwrap();
    let id2 = EdgeRepository::create_if_not_exists(
        &pool, src, "claim", tgt, "claim", "decomposes_to", None, None, None,
    )
    .await
    .unwrap();
    assert_eq!(id1, id2, "second call must return existing id");
}
```

- [ ] **Step 3.3: Run tests**

```bash
cargo test -p epigraph-db --test edge_repo_tests create_if_not_exists_is_idempotent
```

Expected: pass.

- [ ] **Step 3.4: Commit**

```bash
git add crates/epigraph-db/src/repos/edge.rs crates/epigraph-db/tests/edge_repo_tests.rs
git commit -m "feat(db): add EdgeRepository::create_if_not_exists

Hierarchical ingestion re-runs need idempotent edge insertion (e.g.
linking deduped atoms to multiple papers via decomposes_to). Uses
check-then-insert in a transaction since the edges table has no
unique index on (source, target, relationship)."
```

---

## Task 4: Add IngestDocumentParams + IngestDocumentResponse

**Files:**
- Modify: `crates/epigraph-mcp/src/types.rs`

- [ ] **Step 4.1: Find where `IngestPaperParams` lives in types.rs**

```bash
grep -n "IngestPaperParams\|IngestPaperResponse" crates/epigraph-mcp/src/types.rs
```

- [ ] **Step 4.2: Add new types right after IngestPaperResponse**

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct IngestDocumentParams {
    /// Path to a JSON file containing a `DocumentExtraction` (hierarchical).
    /// Must be inside the current working directory.
    #[schemars(description = "Absolute or relative path to the DocumentExtraction JSON file")]
    pub file_path: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct IngestDocumentResponse {
    pub paper_id: String,
    pub paper_title: String,
    pub doi: String,
    pub authors: Vec<AuthorResponse>,
    pub claims_ingested: usize,
    pub claims_embedded: usize,
    pub claims_skipped_dedup: usize,
    pub relationships_created: usize,
    pub claims_ds_wired: Option<usize>,
    pub ds_frame_id: Option<String>,
    pub already_ingested: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AuthorResponse {
    pub agent_id: String,
    pub name: String,
}
```

If `AuthorResponse` already exists (e.g. used by `ingest_paper`), reuse it instead of redefining.

- [ ] **Step 4.3: Build to verify**

```bash
cargo build -p epigraph-mcp
```

Expected: clean build (the new types are only defined, not yet used).

- [ ] **Step 4.4: Commit**

```bash
git add crates/epigraph-mcp/src/types.rs
git commit -m "feat(mcp): add IngestDocument param/response types"
```

---

## Task 5: Implement `ingest_document` function

This is the heavy task: ~250 lines retargeting V2's nano implementation to public's PgPool+repos pattern.

**Files:**
- Modify: `crates/epigraph-mcp/src/tools/ingestion.rs`
- Modify: `crates/epigraph-mcp/Cargo.toml` (if `epigraph-ingest` not yet a dep)

Reference V2 source: `/home/jeremy/EpigraphV2/EpiGraphV2/.worktrees/textbook-provenance/epigraph-nano/src/mcp.rs:4515-5310`. Use the existing public `do_ingest` (lines 146-299 of `ingestion.rs`) as the idiom template.

- [ ] **Step 5.1: Confirm Cargo.toml dep**

```bash
grep epigraph-ingest crates/epigraph-mcp/Cargo.toml
```

If absent, add under `[dependencies]`: `epigraph-ingest = { path = "../epigraph-ingest" }`.

- [ ] **Step 5.2: Add imports at top of ingestion.rs**

After the existing `use` block:

```rust
use epigraph_ingest::builder::{build_ingest_plan, PlannedClaim};
use epigraph_ingest::schema::DocumentExtraction;
use epigraph_db::PaperRepository;
use crate::types::{IngestDocumentParams, IngestDocumentResponse, AuthorResponse};
```

(Adjust `PlannedClaim` import path if the symbol is private — read `crates/epigraph-ingest/src/builder.rs:60-onward` to confirm the correct re-export. If private, walk plan via the public `IngestPlan` accessor only.)

- [ ] **Step 5.3: Add the entry function and helper**

Append to ingestion.rs:

```rust
const PIPELINE_VERSION: &str = "hierarchical_extraction_v1";

pub async fn ingest_document(
    server: &EpiGraphMcpFull,
    params: IngestDocumentParams,
) -> Result<CallToolResult, McpError> {
    let canonical = std::fs::canonicalize(&params.file_path)
        .map_err(|e| invalid_params(format!("invalid file path: {e}")))?;
    let cwd = std::env::current_dir()
        .map_err(|e| internal_error(format!("cannot determine CWD: {e}")))?;
    if !canonical.starts_with(&cwd) {
        return Err(invalid_params(
            "file path must be within the working directory",
        ));
    }
    let data = tokio::fs::read_to_string(&canonical)
        .await
        .map_err(|e| invalid_params(format!("cannot read {}: {e}", canonical.display())))?;
    let extraction: DocumentExtraction =
        serde_json::from_str(&data).map_err(|e| invalid_params(format!("invalid JSON: {e}")))?;

    do_ingest_document(server, &extraction, &params.file_path).await
}

#[allow(clippy::too_many_lines)]
async fn do_ingest_document(
    server: &EpiGraphMcpFull,
    extraction: &DocumentExtraction,
    source_path: &str,
) -> Result<CallToolResult, McpError> {
    let plan = build_ingest_plan(extraction);
    let pool = &server.pool;
    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();

    let paper_title = extraction.source.title.clone();
    let doi = resolve_doi(extraction);

    // ── 1. Version gate ──
    let prior_papers = PaperRepository::find_by_doi(pool, &doi)
        .await
        .map_err(internal_error)?;
    for prior in &prior_papers {
        if PaperRepository::has_processed_by_edge(pool, prior.id, PIPELINE_VERSION)
            .await
            .map_err(internal_error)?
        {
            return success_json(&IngestDocumentResponse {
                paper_id: prior.id.to_string(),
                paper_title,
                doi,
                authors: vec![],
                claims_ingested: 0,
                claims_embedded: 0,
                claims_skipped_dedup: 0,
                relationships_created: 0,
                claims_ds_wired: None,
                ds_frame_id: None,
                already_ingested: true,
            });
        }
    }

    // ── 2. Create fresh paper node + same_source links ──
    let paper_id = PaperRepository::create(
        pool,
        &doi,
        Some(&paper_title),
        extraction.source.journal.as_deref(),
    )
    .await
    .map_err(internal_error)?;
    for prior in &prior_papers {
        let _ = EdgeRepository::create_if_not_exists(
            pool, paper_id, "paper", prior.id, "paper", "same_source",
            Some(serde_json::json!({"doi": &doi})), None, None,
        )
        .await;
    }

    // ── 3. Ensure author agents + agent --authored--> paper ──
    let mut author_responses = Vec::new();
    let mut author_agent_map: HashMap<usize, Uuid> = HashMap::new();
    for (idx, author) in extraction.source.authors.iter().enumerate() {
        if author.name.is_empty() { continue; }
        // Public's Agent::new doesn't model affiliations/roles; store in properties
        // is a TODO. For now: name only (matches existing ingest_paper pattern).
        let author_agent = epigraph_core::Agent::new([0u8; 32], Some(author.name.clone()));
        let created = AgentRepository::create(pool, &author_agent)
            .await
            .map_err(internal_error)?;
        EdgeRepository::create(
            pool, created.id.into(), "agent", paper_id, "paper", "authored",
            Some(serde_json::json!({
                "position": idx,
                "role": author.roles.first().map(String::as_str).unwrap_or("author"),
            })),
            None, None,
        )
        .await
        .map_err(internal_error)?;
        author_agent_map.insert(idx, created.id.into());
        author_responses.push(AuthorResponse {
            agent_id: created.id.as_uuid().to_string(),
            name: author.name.clone(),
        });
    }

    // ── 4. Walk planned claims: dedup → claim/trace/evidence/embed ──
    let source_url = if doi.starts_with("10.") {
        format!("https://doi.org/{doi}")
    } else {
        format!("doi:{doi}")
    };

    let mut claim_ids: Vec<String> = Vec::new();
    let mut id_map: HashMap<Uuid, Uuid> = HashMap::new();
    let mut embedded_count = 0usize;
    let mut dedup_count = 0usize;
    let mut ds_entries: Vec<BatchDsEntry> = Vec::new();

    for planned in plan.iter_claims() { // adjust accessor based on actual API
        // ClaimRepository::create dedupes by content hash automatically; we
        // detect dedup by comparing returned id to the one we tried to insert.
        let confidence = planned.confidence.clamp(0.0, 1.0);
        let methodology = methodology_from_planned(planned);
        let weight = methodology.weight_modifier();
        let raw_truth = (confidence * weight).clamp(0.01, 0.99);

        let mut claim = Claim::new(
            planned.content.clone(),
            agent_id_typed,
            pub_key,
            TruthValue::clamped(raw_truth),
        );
        claim.id = ClaimId::from_uuid(planned.id);
        claim.content_hash = ContentHasher::hash(planned.content.as_bytes());
        claim.signature = Some(server.signer.sign(&claim.content_hash));

        let evidence_text = planned
            .supporting_text
            .as_deref()
            .unwrap_or(&planned.content);
        let formatted_evidence =
            format!("Source: {paper_title} (DOI: {doi}). Passage: '{evidence_text}'");
        let evidence_hash = ContentHasher::hash(formatted_evidence.as_bytes());
        let mut evidence = Evidence::new(
            agent_id_typed,
            pub_key,
            evidence_hash,
            EvidenceType::Literature {
                doi: doi.clone(),
                extraction_target: format!("level_{}", planned.level),
                page_range: None,
            },
            Some(formatted_evidence),
            claim.id,
        );
        evidence.signature = Some(server.signer.sign(&evidence_hash));

        let trace = ReasoningTrace::new(
            agent_id_typed,
            pub_key,
            methodology,
            vec![TraceInput::Evidence { id: evidence.id }],
            confidence,
            format!("Extracted from '{paper_title}' (DOI: {doi}). Level: {}.", planned.level),
        );

        let persisted = ClaimRepository::create(pool, &claim)
            .await
            .map_err(internal_error)?;
        let persisted_id: Uuid = persisted.id.into();
        if persisted_id != planned.id {
            // Deduped to an existing claim — link via paper -asserts-> existing,
            // skip trace/evidence/embed for this iteration.
            dedup_count += 1;
            EdgeRepository::create_if_not_exists(
                pool, paper_id, "paper", persisted_id, "claim", "asserts",
                Some(planned.properties.clone()), None, None,
            )
            .await
            .map_err(internal_error)?;
            id_map.insert(planned.id, persisted_id);
            claim_ids.push(persisted_id.to_string());
            continue;
        }

        ReasoningTraceRepository::create(pool, &trace, claim.id)
            .await
            .map_err(internal_error)?;
        EvidenceRepository::create(pool, &evidence)
            .await
            .map_err(internal_error)?;
        ClaimRepository::update_trace_id(pool, claim.id, trace.id)
            .await
            .map_err(internal_error)?;

        // Paper -asserts-> claim
        EdgeRepository::create(
            pool, paper_id, "paper", persisted_id, "claim", "asserts",
            Some(planned.properties.clone()), None, None,
        )
        .await
        .map_err(internal_error)?;

        if server.embedder.embed_and_store(persisted_id, &planned.content).await {
            embedded_count += 1;
        }

        // Atoms only → CDST batch
        if planned.level == 3 {
            ds_entries.push(BatchDsEntry {
                claim_id: persisted_id,
                confidence,
                weight,
            });
        }

        id_map.insert(planned.id, persisted_id);
        claim_ids.push(persisted_id.to_string());
    }

    // ── 5. Plan edges (decomposes_to, section_follows, supports/contradicts/refines, author placeholders) ──
    let mut relationships_created = 0usize;
    for edge in plan.iter_edges() {
        let (src, src_type) = if edge.source_type == "author_placeholder" {
            let idx = edge.properties["author_index"].as_u64().unwrap_or(0) as usize;
            let Some(&agent_uuid) = author_agent_map.get(&idx) else { continue };
            (agent_uuid, "agent".to_string())
        } else {
            let mapped = id_map.get(&edge.source_id).copied().unwrap_or(edge.source_id);
            (mapped, edge.source_type.clone())
        };
        let tgt = id_map.get(&edge.target_id).copied().unwrap_or(edge.target_id);
        EdgeRepository::create_if_not_exists(
            pool, src, &src_type, tgt, &edge.target_type, &edge.relationship,
            Some(edge.properties.clone()), None, None,
        )
        .await
        .map_err(internal_error)?;
        relationships_created += 1;
    }

    // ── 6. Auto-CDST batch wire (atoms only) ──
    let (claims_ds_wired, ds_frame_id) =
        match ds_auto::auto_wire_ds_batch(pool, &ds_entries, agent_id).await {
            Ok((fid, count)) => (Some(count), Some(fid.to_string())),
            Err(e) => {
                tracing::warn!("ds auto-wire batch failed: {e}");
                (None, None)
            }
        };

    success_json(&IngestDocumentResponse {
        paper_id: paper_id.to_string(),
        paper_title,
        doi,
        authors: author_responses,
        claims_ingested: claim_ids.len() - dedup_count,
        claims_embedded: embedded_count,
        claims_skipped_dedup: dedup_count,
        relationships_created,
        claims_ds_wired,
        ds_frame_id,
        already_ingested: false,
    })
}

fn resolve_doi(extraction: &DocumentExtraction) -> String {
    if let Some(d) = &extraction.source.doi {
        return d.clone();
    }
    if let Some(uri) = &extraction.source.uri {
        // arXiv ID pattern: \d{4}\.\d{4,5}
        if let Some(caps) = regex_lite::Regex::new(r"(\d{4}\.\d{4,5})")
            .ok()
            .and_then(|re| re.captures(uri).map(|c| c.get(1).map(|m| m.as_str().to_string())))
            .flatten()
        {
            return format!("10.48550/arXiv.{caps}");
        }
        return uri.clone();
    }
    "unknown".to_string()
}

fn methodology_from_planned(planned: &PlannedClaim) -> Methodology {
    match planned.methodology.as_deref() {
        Some("statistical" | "instrumental" | "computational") => Methodology::StatisticalAnalysis,
        Some("deductive") => Methodology::DeductiveLogic,
        Some("inductive" | "visual_inspection") => Methodology::InductiveGeneralization,
        _ => Methodology::ExpertElicitation,
    }
}
```

> **Note on iteration accessors:** Adjust `plan.iter_claims()` / `plan.iter_edges()` based on the actual `IngestPlan` API in `crates/epigraph-ingest/src/builder.rs`. Read it first; if the fields are `pub claims: Vec<PlannedClaim>` and `pub edges: Vec<PlannedEdge>`, use `&plan.claims` and `&plan.edges` directly.

> **Note on regex_lite:** the dependency may not exist in epigraph-mcp's Cargo.toml. If not, prefer `regex` (already a workspace dep) or hand-roll the arXiv pattern with simple string ops to avoid a new dep.

- [ ] **Step 5.4: Build incrementally and fix import/type errors**

```bash
cargo build -p epigraph-mcp 2>&1 | head -80
```

Iterate on import paths and field accessors until clean. Most likely fixups:
- `Methodology::weight_modifier` may not exist on the public enum — match against existing `lit_methodology` and the way `do_ingest` derives `weight`.
- `plan.iter_claims()` likely doesn't exist — use `&plan.claims`.
- `Claim::new` signature may differ slightly.

- [ ] **Step 5.5: Commit**

```bash
git add crates/epigraph-mcp/src/tools/ingestion.rs crates/epigraph-mcp/Cargo.toml
git commit -m "feat(mcp): add ingest_document tool for hierarchical ingestion

Ports the V2 nano ingest_document into public-mcp, retargeting NanoDb
methods onto PgPool + repos. Paper-as-node pattern preserved; author
affiliations/roles deferred (stored as TODO). Auto-CDST uses the
existing batch helper rather than per-claim wiring."
```

---

## Task 6: Wire `ingest_document` as MCP `#[tool]` method

**Files:**
- Modify: `crates/epigraph-mcp/src/server.rs` (or wherever `#[tool]` methods on `EpiGraphMcpFull` are declared — likely an `impl` block in `tools/mod.rs` or `server.rs`)

- [ ] **Step 6.1: Find existing `#[tool]` on `ingest_paper`**

```bash
grep -rn "fn ingest_paper" crates/epigraph-mcp/src/
```

- [ ] **Step 6.2: Mirror the wiring**

Right after `ingest_paper`'s tool method, add:

```rust
    /// Ingest a hierarchical DocumentExtraction JSON file into the graph.
    #[tool(description = "Ingest a hierarchical DocumentExtraction JSON file. \
        Builds paper -> section -> paragraph -> atom claim hierarchy with edges.")]
    pub async fn ingest_document(
        &self,
        Parameters(params): Parameters<IngestDocumentParams>,
    ) -> Result<CallToolResult, McpError> {
        if self.read_only {
            return Err(invalid_params("read-only mode: ingest_document not allowed"));
        }
        tools::ingestion::ingest_document(self, params).await
    }
```

- [ ] **Step 6.3: Build**

```bash
cargo build -p epigraph-mcp
```

Expected: clean.

- [ ] **Step 6.4: Commit**

```bash
git add crates/epigraph-mcp/src/server.rs
git commit -m "feat(mcp): expose ingest_document as #[tool] method"
```

---

## Task 7: End-to-end smoke test against a real DB

**Files:**
- Create: `crates/epigraph-mcp/tests/ingest_document_smoke.rs`

The faithful test: parse a tiny synthetic DocumentExtraction (1 thesis, 1 section, 1 paragraph, 2 atoms, 1 supports relationship), run `ingest_document`, then assert claims/edges exist with the right shapes.

- [ ] **Step 7.1: Write the test**

Use `#[sqlx::test]` for an isolated DB. Fixture:

```rust
const FIXTURE: &str = r#"{
  "source": {
    "title": "Test Paper",
    "doi": "10.1234/test",
    "source_type": "Paper",
    "authors": [{"name": "Alice", "affiliations": [], "roles": ["author"]}]
  },
  "thesis": "T",
  "thesis_derivation": "TopDown",
  "sections": [{
    "title": "Intro",
    "summary": "S",
    "paragraphs": [{
      "compound": "C",
      "supporting_text": "ST",
      "atoms": ["Atom 1", "Atom 2"],
      "generality": [3, 3],
      "confidence": 0.8
    }]
  }],
  "relationships": [
    {"source_path": "atoms[0]", "target_path": "atoms[1]", "relationship": "supports"}
  ]
}"#;
```

Write to a temp file under CWD, call `ingest_document`, then query:
- `papers` row exists with the doi
- claims with content "T", "S", "C", "Atom 1", "Atom 2" all exist
- edges: paper->thesis (asserts), thesis->section (decomposes_to), section->paragraph (decomposes_to), paragraph->atoms (decomposes_to), atom1->atom2 (supports), agent->paper (authored)

- [ ] **Step 7.2: Run**

```bash
cargo test -p epigraph-mcp --test ingest_document_smoke
```

Expected: pass. If it fails, fix the implementation, not the test.

- [ ] **Step 7.3: Run idempotency check (re-ingest same fixture)**

Add a second test: call `ingest_document` twice, assert second response has `already_ingested: true` and zero new edges.

- [ ] **Step 7.4: Commit**

```bash
git add crates/epigraph-mcp/tests/ingest_document_smoke.rs
git commit -m "test(mcp): smoke-test hierarchical ingest_document end-to-end

Verifies paper node, claim hierarchy, decomposes_to/supports edges,
author authored edge, and version-gated re-ingest skip."
```

---

## Task 8: Verification + workflow lint

- [ ] **Step 8.1: Full build**

```bash
cargo build --workspace
```

- [ ] **Step 8.2: Full test**

```bash
cargo test --workspace
```

Watch for regressions in unrelated crates — none expected, but verify.

- [ ] **Step 8.3: Clippy**

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Fix lints before merging. The new `do_ingest_document` is large; `#[allow(clippy::too_many_lines)]` is justified, mirroring `do_ingest`.

- [ ] **Step 8.4: Format check**

```bash
cargo fmt --check
```

- [ ] **Step 8.5: Open PR description** (do not push without user's go-ahead)

Draft body covers: skill port, ingest_document MCP tool, PaperRepository, EdgeRepository::create_if_not_exists, deferred items (capability claims, author affiliations, per-claim CDST).

---

## Self-review checklist

- Spec coverage: ✓ skill (T1), ingest_document (T5+T6), prerequisites (T2-T4), tests (T7), CI hygiene (T8).
- Placeholders: none — every code block is the actual code to write (placeholder hints noted in-line for accessors that depend on the local `IngestPlan` API, which the engineer will resolve at compile time).
- Type consistency: `IngestDocumentParams`/`IngestDocumentResponse`/`AuthorResponse` introduced in T4 and used unchanged in T5/T6/T7. `PIPELINE_VERSION` constant defined in T5 and queried in T2's `has_processed_by_edge`.
- Deferred items are explicit, not silent gaps.
