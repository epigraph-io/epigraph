# Essence binding — completed design, NOT YET BUILT

**Status:** design complete and judged feasible; implementation never ran.
**Backlog item:** `7c909c49`
**Date:** 2026-08-26

## Why this exists as a document rather than as code

This design was produced by the Design phase of the `blob-manifest-anchor` workflow run and was
judged `feasible: true`. It was then **silently dropped before the Build phase by an orchestration
bug, not by any technical judgement**: the design agent returned its track id as `essence-binding`
while the driver's dependency-order array looked up `essence`, so the lookup missed and the track
was skipped. The other four tracks (blob, manifest, anchor, obligation) all built and landed SOUND.

The design below is therefore untouched, complete, and ready to execute.

## Reconciliation required before building

The design was written during the Design phase, BEFORE the blob track landed. Two of its statements
are now stale and must be adjusted:

1. It says *"epigraph has no blob store on this branch"* and plans to port one as part of this work.
   That is no longer true — the blob store landed on `feat/blob-manifest-anchor` as commit `4ce6d0a`
   with `migrations/070_blobs.sql`. **Build on it; do not port it again.** Note the shipped blob
   store deliberately has NO subject column: association is an edge (`claim -[derived_from]-> blob`),
   with `blob` registered in `entity_types`.
2. It reserves migrations **070 and 071**. Both are taken, as are 072 and 073.
   **The next free migration is 074.**

Decision 17 (blob store port scope) and decision 18 (migration numbering) are the two to rewrite.
Everything else stands.

## Settled decisions

### 1

OPEN QUESTION 1 — WHERE THE DIGEST LIVES: neither `papers` nor a paper noun-claim. The per-run artifact node is `source_artifacts`, a table that has existed since migration 001 with an unused `content_hash BYTEA` column, is a registered entity type since 054 ('source_artifact' -> 'source_artifacts'), is already legal on both sides of `edges_entity_types_valid`, already resolves in `validate_edge_reference`, and has ZERO Rust writers in the workspace (`grep -rn source_artifacts crates/ --include='*.rs'` returns nothing). The task brief's grep missed it because it searched for source_digest/blob_id/essence/content_bytes, not content_hash. We wire it: one `source_artifacts` row per (paper, exact bytes) = one rendition, joined by `paper -has_essence-> source_artifact`.

### 2

WHY NOT A COLUMN ON `papers`: `papers.doi` is UNIQUE and the only writer is `PaperRepository::get_or_create` (crates/epigraph-db/src/repos/paper.rs:36), so `papers` models the DOCUMENT IDENTITY, not a byte payload. A preprint and the published PDF share a DOI and have different bytes. A scalar `papers.essence_digest` would be silently overwritten on the next re-ingest, and every claim already asserted under the previous rendition would stop resolving — which is exactly the 'asserts edge from a paper node that does not resolve' failure (claim 4bd57e79 / paper 8f7e4a1d) this track exists to kill, reintroduced one level up.

### 3

WHY NOT A NOUN-CLAIM: claims are content-addressed, supersedable, and carry an is_current/embedding lifecycle (`ClaimRepository::supersede` nulls the embedding, claim.rs:1401). An artifact anchor that flips `is_current=false` when somebody supersedes a thesis takes the artifact's essence with it. There is also no paper noun-claim today — level 0 is the THESIS, which is document content, not the artifact. And `blobs.id` cannot be an FK target from a JSONB property.

### 4

OPEN QUESTION 2 — DIGEST REQUIRED FOR ASSERTS WRITERS: enforced twice. (a) Compile time: new `EdgeRepository::upsert_asserts_edge(pool, paper_id, claim_id, essence_digest: &[u8;32], properties)` takes the digest as a NON-Option positional argument, so the four ingestion call sites physically cannot omit it. (b) Runtime, unbypassable: DB CHECK `edges_paper_asserts_requires_essence`. Layer (b) is load-bearing, not belt-and-braces: `crates/epigraph-api/src/routes/edges.rs:65` allowlists 'asserts' on the generic `POST /api/v1/edges` endpoint, so a Rust-only guard is trivially routed around.

### 5

THE CHECK IS `NOT VALID`: new INSERT/UPDATE is enforced, pre-essence rows are grandfathered. A VALIDATEd constraint would fail on the existing corpus, and migrations are append-only + checksum-verified (migrations/README.md), so a failing migration panics the api binary on restart. Legacy unbound edges are reported by the verifier as `unbound_claim`, not hidden.

### 6

THE CHECK USES A REGEX, NOT `jsonb_typeof(...) = 'string'`: a missing key makes `->` return SQL NULL, `jsonb_typeof(NULL)` is NULL, and a CHECK that evaluates to NULL PASSES. `COALESCE(properties ->> 'essence_digest', '') ~ '^[0-9a-f]{64}$'` is NULL-safe and additionally forces a well-formed 32-byte lowercase hex digest rather than any string.

### 7

ONLY `source_type = 'paper'` IS CONSTRAINED. `do_ingest_document` rewrites the builder's `author_placeholder -asserts-> claim` plan edges into `agent -asserts-> claim` (ingestion.rs:659-667), and those stay unconstrained — an author asserting a claim is a different relation from a document asserting one. A test pins this so the constraint can never become collateral damage on the author path.

### 8

ESSENCE BYTES — ONE RULE, ALWAYS AVAILABLE, NO CONFIG: (1) if `extraction.source_text` is Some and non-empty, essence bytes = `source_text.as_bytes()` and `essence_kind = 'source_text'` — this is literally the document, and the D9 verbatim guard (`verify_extraction_verbatim`) already proves every span-backed paragraph is a byte-exact slice of it; (2) otherwise essence bytes = `serde_json::to_vec(extraction)` and `essence_kind = 'extraction_json'` — the extraction envelope IS the artifact the run consumed when no upstream text was supplied. There is no third branch and no 'no bytes' branch, so the writer can never be in a state where it has nothing to bind. Empty payload is a hard error (and `blobs_size_positive` would reject it anyway).

### 9

RULE (2) IS DETERMINISTIC: `serde_json` is built WITHOUT `preserve_order` in this workspace (verified — Cargo.lock's serde_json entry pulls itoa/memchr/serde/serde_core/zmij, no indexmap), so `Value::Object` is a sorted BTreeMap and `source.metadata` key order is normalized. Struct fields serialize in declaration order. Consequence: the same logical extraction ingested via `ingest_document` (file path) and via `ingest_document_inline` produces the SAME digest and converges on one rendition row.

### 10

ANTI-INERT — NAMED LIVE CALL SITES: essence binding is invoked at three points in crates/epigraph-mcp/src/tools/ingestion.rs, immediately after each `PaperRepository::get_or_create`: line 235 (`ensure_paper_node`, the SYNCHRONOUS pre-flight both MCP entry points run before spawning the detached task, so the caller gets a hard error if the bytes cannot be stored), line 394 (`do_ingest_document`), line 1086 (`do_ingest_document_spine`). The digest it returns is then consumed by the four `asserts` writes at ingestion.rs:552, 626, 1233, 1305, which all switch from `EdgeRepository::create_if_not_exists(.., "asserts", ..)` to `EdgeRepository::upsert_asserts_edge(.., &essence.digest, ..)`. Nothing new is defined without a caller.

### 11

ANTI-INERT — EXISTING TESTS ALREADY DRIVE THOSE SITES: `crates/epigraph-mcp/tests/ingest_document_smoke.rs` (Tier 2, no source_text), `crates/epigraph-mcp/tests/verbatim_spine_e2e.rs` (Tier 1, real source_text through structure_source -> ingest_document_inline), `ingest_document_spine_smoke.rs`, `spine_node_identity_test.rs`, `recall_with_context.rs`. All of them exercise the new code on the first run; if the binding were inert or misordered these go red immediately.

### 12

ANTI-DISABLED — NO ON/OFF SWITCH, AND THE DEFAULT IS ON: the only configuration is WHERE bytes go, never WHETHER. `EPIGRAPH_BLOB_DIR` if set, else `std::env::temp_dir().join("epigraph-blobs")`, created on demand, with a one-time `tracing::warn!` naming the resolved path and telling operators to pin it. Because the default resolves with zero configuration, every existing ingestion test above runs the ON path as-is. A wiped temp dir does not silently degrade — it surfaces as a loud `bytes_missing` verifier failure. One dedicated test (`essence_blob_dir_override.rs`, its own single-test binary so `set_var` cannot race) proves the override path.

### 13

OPEN QUESTION 3 — VERIFIER: new MCP tool `verify_paper_essence` (scope `claims:read`), accepting `doi` or `paper_id`, `strict` defaulting to TRUE. It FAILS CLOSED — returns an MCP error, not a soft report — on any of: `no_essence` (paper has zero has_essence renditions), `blob_row_missing` / `bytes_missing` / `digest_mismatch` (the rendition an asserts edge names does not resolve to bytes on disk that re-hash to it), `unbound_claim` (asserts edge with no essence_digest — the legacy grandfathered rows), `unknown_digest` (asserts edge names a digest with no rendition on this paper), `atom_unbound`, `paragraph_not_in_essence`. `stale_binding` (claim bound to an older but still-resolvable rendition) is a WARN, because multi-rendition history is legitimate — that is the whole reason the digest lives per-rendition.

### 14

VERIFIER WALK, paper -> paragraph -> atom: `paper -asserts-> claim` partitioned by `claims.properties->>'level'` (set by `ClaimRepository::set_properties` from the builder's `"level": 0..3`); level-2 paragraphs are followed through `decomposes_to` (crates/epigraph-ingest/src/common/edges.rs:32) to level-3 atoms. `atom_unbound` fires when an atom reached that way carries this paper's `doi:<doi>` label — proving it belongs to this paper — but has NO `asserts` edge from it. That is precisely the incident shape reported for claim 4bd57e79.

### 15

VERIFIER HAS REAL TEETH BEYOND NULL-CHECKING: for `essence_kind = 'source_text'` renditions it additionally requires every level-2 claim's `content` to be a byte substring of the essence bytes read back off disk. This is sound because the D9 guard already forces Tier-1 paragraphs to be verbatim slices. Atoms are NOT containment-checked (they are LLM rewrites, not verbatim), and `extraction_json` renditions are not containment-checked (paragraph text is JSON-escaped there) — both documented in the tool's rustdoc so nobody mistakes the gap for a bug.

### 16

OPEN QUESTION 4 — EXACT HASH ONLY: BLAKE3-256 via `epigraph_crypto::ContentHasher::hash`, the same hasher `claims.content_hash` and `ids::content_hash` already use, so the artifact digest and the claim digest are the same primitive. Perceptual / tolerant / near-duplicate essence is explicitly NOT built (see out_of_scope) and is recorded as the follow-up.

### 17

BLOB STORE PORT SCOPE: epigraph has no blob store on this branch (verified: `grep -ril blob crates/` returns only unrelated hits in security_event.rs/agent.rs). This commit ports the minimum slice from episcience — `migrations/5005_create_blobs.sql` -> `070_blobs.sql` (minus `sample_id`, which has no epigraph table), `episcience-core/src/blob.rs` -> `epigraph-core/src/blob.rs`, `episcience-db/src/repos/blob.rs` -> `epigraph-db/src/repos/blob.rs`. Two deliberate deviations from the original: a UNIQUE index on `content_hash` (so `find_by_hash` has a single-row contract, which the essence lookup needs), and `store` becomes an ON CONFLICT no-op-update upsert returning the existing row instead of racing on the insert.

### 18

MIGRATION NUMBERING: 070 and 071. Latest applied on the dedicated test DB is 059 (`sqlx migrate info` confirms 59/installed). 060-069 is left as headroom for the concurrent workflow on the sibling branch, per the run brief.

### 19

RECOMMENDED COMMIT SPLIT (Epistemic Commit Protocol, one decision per commit): (1) `feat(db): port the content-addressed blob store into the kernel` — 070_blobs.sql, core BlobRef, BlobRepository, DbError::Io, blob_store_roundtrip.rs; (2) the subject given here — 071, source_artifacts wiring, upsert_asserts_edge, the ingestion call sites, the CHECK and its fixture fallout; (3) `feat(mcp): fail closed when a paper's asserted claims name bytes we cannot produce` — the verifier tool + registration + tests. The `commit_subject` field carries (2), the track's core decision.

### 20

SQLX OFFLINE: every new `query!`/`query_as!` in blob.rs, source_artifact.rs, paper.rs and edge.rs requires `DATABASE_URL=postgresql://postgres@127.0.0.1:55471/epigraph_blob_test cargo sqlx prepare --workspace -- --tests` followed by `git add .sqlx`, then confirm `env -u DATABASE_URL SQLX_OFFLINE=true cargo check --workspace --locked` passes.

## Explicitly out of scope

The design names these as deliberate non-goals. Respect them — several are traps that look like
natural extensions.

- Perceptual / tolerant / fuzzy essence. Exact BLAKE3-256 only. Two PDF renditions of the same paper, an OCR pass, or a whitespace-normalized export produce different digests and therefore different renditions — by design. Near-duplicate essence matching (SimHash/MinHash over normalized text, or a `essence_similar_to` edge between renditions) is the named follow-up and must not be attempted here.
- Persisting `ByteSpan` (schema.rs Paragraph.span / Section.heading_span) onto claims so the verifier can re-slice each paragraph out of the essence bytes BY OFFSET instead of by substring containment. Strictly stronger, but it touches `epigraph-ingest/src/document/builder.rs` and the shared walker that `workflow/builder.rs` also uses — a separate atomic change.
- Re-deriving `build_ingest_plan` from the essence bytes and proving the persisted claim id set matches the re-derived deterministic ids. The strongest possible check (ids are already deterministic, so it is cheap), but it belongs in its own commit on top of this one.
- Backfilling essence for the existing corpus of `asserts` edges. The CHECK is NOT VALID precisely so this is not required; the verifier reports those edges as `unbound_claim`. A real backfill needs the original bytes, which for most of the corpus no longer exist.
- Making `edges_paper_asserts_requires_essence` VALIDATEd. It would fail on legacy rows, and per migrations/README.md a failed migration panics the api binary on restart.
- Workflow ingestion (`store_workflow`, `workflow_ingest`, `improve_workflow_hierarchy`, `add_step`, epigraph-ingest-executor). Workflows root on the `workflows` table, not `papers`, and emit no `paper -asserts-> claim` edge. Untouched. `workflow/builder.rs:270`'s 'asserts' is an author_placeholder edge that becomes `agent -asserts->`, outside the constraint.
- A general-purpose blob surface: `attach_blob` MCP tool, `POST /api/v1/eln/blobs` multipart upload, blob download route, base64 payload handling. episcience has all of these (episcience-api/src/mcp/blobs.rs, routes/blobs.rs); this commit ports only the repo slice essence binding needs. Do not add `attach_blob` to SCOPE_MAP.
- S3 / object-store backends, blob garbage collection of unreferenced payloads, blob size limits and quotas, and blob encryption/redaction under the group-tenancy scheme.
- Adding `has_essence` to `GRAPH_VIEW_RELATIONSHIPS` in crates/epigraph-api/src/routes/graph.rs (its `EXPECTED_INCLUDED` mirror test would also need editing). Essence edges are integrity infrastructure, not GUI node expansion.
- A CLI verifier binary and a scheduled `epigraph-jobs` sweep that verifies every paper nightly. The MCP tool is the surface for this commit.
- Repairing the specific reported incident (claim 4bd57e79 / paper 8f7e4a1d) in the production graph. NEVER call an EpiGraph MCP write tool against the production graph. This ships the verifier that names such rows; the repair is an operator action.
- Fixing the pre-existing CLAUDE.md layering violation in crates/epigraph-api/src/routes/papers.rs, which inlines papers SQL instead of calling PaperRepository. Real, but unrelated to essence binding — do not fold it in.

## Verification the design commits to

Per decision 20: every new `query!`/`query_as!` requires
`cargo sqlx prepare --workspace -- --tests` then `git add .sqlx`, followed by
`env -u DATABASE_URL SQLX_OFFLINE=true cargo check --workspace --locked`.

Decisions 10-12 are the anti-inert and anti-disabled guards: named live call sites in
`crates/epigraph-mcp/src/tools/ingestion.rs` (lines 235, 394, 1086), existing ingestion tests that
already drive them, and no on/off switch — only *where* bytes go, never *whether*.
