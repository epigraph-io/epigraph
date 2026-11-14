-- 226: a per-source licence on `papers`, gating whether the ingest writers
-- may retain a verbatim source passage in `evidence.raw_content`
-- (backlog 8709d128).
--
-- ===================================================================
-- 0. WHY
-- ===================================================================
--
-- The hierarchical ingest writers (`do_ingest_document`,
-- `do_ingest_document_spine`) wrote every evidence row as
-- `Source: <title> (DOI: <doi>). Passage: '<verbatim source paragraph>'`,
-- so the evidence table republished publisher text wholesale. They now
-- write the citation, a locator (extraction path, section title, byte span
-- when known) and a BLAKE3 hash of the passage instead, and keep the
-- passage text only when the source's licence permits redistribution.
-- No column recorded a source's licence, so nothing could grant that.
--
-- SCOPE: this removes the passage from EVIDENCE rows only. A level-2
-- paragraph claim's own `content` is still the paragraph text, and that
-- text is embedded, so the graph still holds publisher text through
-- claims. That copy is a separate decision, not made here.
--
-- The locator's byte span (and so a reproducible hash check against the
-- original source) exists only for Tier-1 extractions, which carry
-- `source_text`. A Tier-2 locator indexes the extractor's output, and its
-- hash covers the extracted text.
--
-- ===================================================================
-- 1. THE REPRESENTATION: papers.licence text, nullable
-- ===================================================================
--
-- An SPDX-style identifier (`CC-BY-4.0`, `CC0-1.0`, `public-domain`).
-- NULL means "unknown", which the writers treat as all rights reserved:
-- the passage is NOT retained. Which identifiers count as open is decided
-- in the application (`passage_retention_permitted` in
-- `epigraph-mcp/src/tools/ingestion.rs`), not here, so widening or
-- narrowing the allowlist needs no migration. The CHECK only refuses an
-- empty or padded value, which would otherwise read as "declared" while
-- naming nothing.
--
-- The ingest path never WRITES this column: an extraction cannot declare
-- its own source open-licensed. By convention an operator sets it out of
-- band. This is a convention, not an enforced guarantee: `papers` is a
-- REGISTRY table that the application role can still UPDATE (that role can
-- equally write `evidence.raw_content` directly, so the column grants
-- nothing the role lacked).
--
-- `papers` carries no tenancy (127), so there is no policy to restate.
-- Existing rows keep NULL, so nothing already written changes meaning.
-- Stripping the passages already stored is a separate data repair.
-- Undo: docs/runbooks/226-undo.sql.

-- ADD COLUMN and the CHECK take ACCESS EXCLUSIVE on `papers`, which every
-- ingest touches: fail fast rather than queue every reader behind a
-- long-running ingest transaction (as 199 and 208 do).
SET LOCAL lock_timeout = '3s';

ALTER TABLE public.papers
    ADD COLUMN IF NOT EXISTS licence text;

ALTER TABLE public.papers
    DROP CONSTRAINT IF EXISTS papers_licence_nonblank;
ALTER TABLE public.papers
    ADD CONSTRAINT papers_licence_nonblank
    CHECK (licence IS NULL OR (licence <> '' AND licence = btrim(licence)));

COMMENT ON COLUMN public.papers.licence IS
    'SPDX-style licence of the source (e.g. CC-BY-4.0). NULL = unknown, treated as '
    'all rights reserved: ingest stores a passage locator and hash, never the text. '
    'Set by an operator by convention, never by ingest (migration 226, backlog 8709d128).';
