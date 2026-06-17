//! # Triple Extractor — Architectural Gap Documentation
//!
//! ## Audit Summary (k1 / triples-fix-k1)
//!
//! This module is a **stub placeholder** for a triple-extraction pipeline that
//! does not yet exist.  The audit below records the gap so that future
//! implementors have a clear starting point.
//!
//! ---
//!
//! ## (a) Table Counts
//!
//! A read-only audit of the production database (`epigraph`) confirms:
//!
//! ```text
//! SELECT COUNT(*) FROM entities;          -- 0
//! SELECT COUNT(*) FROM entity_mentions;   -- 0
//! SELECT COUNT(*) FROM triples;           -- 0
//! ```
//!
//! All three tables are empty despite the claim corpus containing tens of
//! thousands of current claims.  No extraction pipeline has ever populated them.
//!
//! ---
//!
//! ## (b) Write-Path Trace
//!
//! The only code paths that can write to these three tables are:
//!
//! | Route / Method | Repository call | Table written |
//! |---|---|---|
//! | `POST /api/v1/entities` → `routes/entities.rs:create_entity` | `EntityRepository::upsert` | `entities` |
//! | `POST /api/v1/entity-mentions/batch` → `routes/entities.rs:batch_create_mentions` | `TripleRepository::batch_create_mentions` | `entity_mentions` |
//! | `POST /api/v1/triples/batch` → `routes/entities.rs:batch_create_triples` | `TripleRepository::batch_create_triples` | `triples` |
//!
//! **None of the ingestion paths call these methods:**
//!
//! * `memorize` (`crates/epigraph-mcp/src/tools/memory.rs`) — creates a
//!   testimonial Evidence claim and a ReasoningTrace only; zero calls to
//!   `EntityRepository` or `TripleRepository`.
//!
//! * `submit_claim` (`crates/epigraph-mcp/src/tools/claims.rs`) — creates
//!   Evidence, ReasoningTrace, DERIVED_FROM/HAS_TRACE edges, DS mass functions,
//!   and an embedding; zero calls to `EntityRepository` or `TripleRepository`.
//!
//! * `ingest_document` / `do_ingest_document`
//!   (`crates/epigraph-mcp/src/tools/ingestion.rs`) — creates a Paper node,
//!   author agents, hierarchical claims (thesis → sections → paragraphs →
//!   atoms), decomposes_to / section_follows / supports edges, embeddings, and
//!   CDST mass functions; zero calls to `EntityRepository` or
//!   `TripleRepository`.
//!
//! Write access to entities/entity_mentions/triples is **exclusively through the
//! three REST endpoints above**, which are never invoked by any automated
//! pipeline.
//!
//! ---
//!
//! ## (c) `claim_has_triples()` Always Returns `false`
//!
//! `TripleRepository::claim_has_triples` is defined in
//! `crates/epigraph-db/src/repos/triple.rs` as an idempotency guard
//! (`SELECT EXISTS(SELECT 1 FROM triples WHERE claim_id = $1)`).
//!
//! Because the `triples` table is empty, this function returns `false` for
//! every claim in the corpus — the guard was designed for a future extraction
//! loop that has not yet been written.  A `grep` over the entire codebase
//! confirms `claim_has_triples` has **zero call sites** outside its own
//! definition; it is unused dead code at this revision.
//!
//! ---
//!
//! ## (d) The Gap
//!
//! Triple extraction is **never called** during any ingestion path.
//! The database schema (`entities`, `entity_mentions`, `triples`), the
//! repository layer (`EntityRepository`, `TripleRepository`), and the REST
//! endpoints are all present and functional.  What is missing is an *extraction
//! step* — an NER + relation-extraction pass over claim content — that would:
//!
//! 1. Parse the natural-language text of a newly-ingested claim.
//! 2. Identify named entities and resolve them to canonical `entities` rows.
//! 3. Extract subject–predicate–object triples and persist them via
//!    `TripleRepository::batch_create_triples`.
//! 4. Record entity mentions via `TripleRepository::batch_create_mentions`.
//! 5. Use `TripleRepository::claim_has_triples` as an idempotency guard to skip
//!    re-extraction on subsequent ingest runs.
//!
//! This module (`triple_extractor`) is the **intended home** for that logic.
//! It is intentionally empty until the extraction pipeline is designed and
//! implemented (see backlog item `triples-fix-k1`).
