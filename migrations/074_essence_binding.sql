-- Migration 074: bind every asserted claim to the BYTES it was extracted from
-- (backlog 7c909c49 — "essence binding").
--
-- NUMBERING -- `sqlx migrate info` on this branch shows 1..59 plus 70..73
-- installed. 060..069 are deliberately left clear (070_blobs.sql's own
-- numbering note reserves them as headroom for the concurrently-developed
-- sibling branch), so taking 060 now would collide there. 074 is the first
-- free number above everything installed.
--
-- EVIDENCE
-- A `paper -asserts-> claim` edge names a DOI. A DOI is a DOCUMENT identity,
-- not a byte payload: a preprint and the published PDF share one, an OCR pass
-- and a whitespace-normalised export share one. Nothing in the tree tied a
-- claim to the artifact it was actually read off — `grep -rni essence crates/
-- migrations/` returned zero hits, and `source_artifacts.content_hash` (a
-- column present since migration 001) had zero writers in the entire
-- workspace. So "which bytes produced this claim?" was unanswerable, and a
-- claim whose paper node no longer resolves to anything readable could not be
-- distinguished from a healthy one.
--
-- DECISION -- (i) the rendition key, (ii) the write-side guard.
--
-- (i) `source_artifacts` is the per-rendition node: one row per exact byte
--     payload, joined to its document by a `paper -has_essence-> source_artifact`
--     edge. It already exists, is a registered entity type since 054, and
--     resolves on validate_edge_reference's fast path (055). What it lacks is
--     any uniqueness on `content_hash`, so "one row per rendition" was
--     unenforceable. The partial unique index below supplies it. The key is
--     GLOBAL content addressing, matching the `blobs` model: two papers over
--     identical bytes converge on ONE rendition row with TWO has_essence
--     edges. Per-paper uniqueness is not expressible on this table anyway,
--     because the paper linkage is an edge and not a column.
--
-- (ii) A TRIGGER, NOT A CHECK. The obvious form of the guard is
--         ALTER TABLE edges ADD CONSTRAINT ... CHECK (...) NOT VALID
--      on the theory that NOT VALID grandfathers the pre-essence corpus.
--      That theory is FALSE and was measured: PostgreSQL's NOT VALID skips
--      only the initial full-table scan and still enforces the CHECK on every
--      subsequent INSERT **and UPDATE**. A probe that inserted a legacy
--      unbound `asserts` edge, added the CHECK exactly as designed, and then
--      ran `ClaimRepository::mark_duplicate` died with:
--
--        PgDatabaseError code "23514", constraint
--        "edges_paper_asserts_requires_essence"
--        Failing row: (..., paper, claim, asserts, {}, {}, ...)
--
--      because `mark_duplicate_with_repair` runs
--        UPDATE edges SET target_id = $1
--         WHERE target_id = $2 AND target_type = 'claim'
--           AND relationship != 'supersedes'
--      (crates/epigraph-db/src/repos/claim.rs:3211), which retargets exactly a
--      grandfathered `asserts` row. The same exposure exists at claim.rs:3284
--      (dedup re-source), claim.rs:4745/4758 (retraction cascade) and
--      edge.rs:671 (update_valid_to_and_properties). A CHECK would have broken
--      dedup and retraction across the whole existing corpus.
--
--      A BEFORE INSERT OR UPDATE ... FOR EACH ROW trigger has OLD, so it can
--      separate the three cases a CHECK provably cannot:
--        1. a NEW paper/asserts edge MUST carry a well-formed digest;
--        2. an UPDATE of a row that never carried one is grandfathered, so
--           dedup and the retraction cascade keep working;
--        3. an UPDATE may NOT strip or corrupt a digest that was present.
--      (3) is strictly stronger than any NOT VALID CHECK, which cannot tell
--      "was already unbound" from "is being unbound".
--
--      The guard is at the DB and not only in Rust because
--      crates/epigraph-api/src/routes/edges.rs allowlists 'asserts' on the
--      generic POST /api/v1/edges and EdgeRepository::create_if_not_exists has
--      no relationship allowlist of its own — a Rust-only guard is trivially
--      routed around.
--
-- REGEX, NOT jsonb_typeof. A missing key makes `->>` return SQL NULL, and a
-- NULL predicate is not a rejection, so the test must be NULL-safe:
-- `COALESCE(properties ->> 'essence_digest', '') ~ '^[0-9a-f]{64}$'` both
-- handles the absent key and forces a well-formed 32-byte lowercase-hex
-- BLAKE3-256 digest rather than any string at all.
--
-- SCOPE. Only `source_type = 'paper'` is constrained. `do_ingest_document`
-- rewrites the builder's `author_placeholder -asserts-> claim` plan edges into
-- `agent -asserts-> claim` (ingestion.rs:663-668); an AUTHOR asserting a claim
-- is a different relation from a DOCUMENT asserting one and stays free.

-- ── (i) the rendition key ───────────────────────────────────────────────────

-- Partial: `source_artifacts` is a general-purpose table whose other
-- artifact_types may legitimately repeat a hash or carry none at all. Only
-- essence renditions are content-addressed.
CREATE UNIQUE INDEX IF NOT EXISTS uq_source_artifacts_essence_hash
    ON source_artifacts (content_hash)
    WHERE artifact_type = 'essence' AND content_hash IS NOT NULL;

COMMENT ON COLUMN source_artifacts.content_hash IS
    'BLAKE3-256 digest of the artifact bytes (epigraph_crypto::ContentHasher). '
    'For artifact_type = ''essence'' this is the rendition key: unique across '
    'the table (uq_source_artifacts_essence_hash), and the same digest every '
    'paper -asserts-> claim edge extracted from these bytes carries in '
    'properties.essence_digest. The bytes themselves live in the '
    'content-addressed blob store under the identical digest.';

-- ── (ii) the write-side guard ───────────────────────────────────────────────

CREATE OR REPLACE FUNCTION enforce_paper_asserts_essence() RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
    -- Defensive re-statement of the trigger's WHEN clause: a future
    -- CREATE OR REPLACE that widens the trigger must not silently widen the
    -- rule to every edge in the graph.
    IF NEW.source_type <> 'paper' OR NEW.relationship <> 'asserts' THEN
        RETURN NEW;
    END IF;

    -- Bound: a well-formed BLAKE3-256 digest in lowercase hex.
    IF COALESCE(NEW.properties ->> 'essence_digest', '') ~ '^[0-9a-f]{64}$' THEN
        RETURN NEW;
    END IF;

    -- Grandfathered: an UPDATE of a row that was ALREADY an unbound
    -- paper/asserts edge. OLD's source_type/relationship are re-checked so an
    -- UPDATE cannot launder some other edge into an unbound asserts edge by
    -- rewriting its endpoints.
    IF TG_OP = 'UPDATE'
       AND OLD.source_type = 'paper'
       AND OLD.relationship = 'asserts'
       AND COALESCE(OLD.properties ->> 'essence_digest', '') !~ '^[0-9a-f]{64}$'
    THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'paper -asserts-> claim requires properties.essence_digest (64 lowercase hex chars); got %', COALESCE(NEW.properties ->> 'essence_digest', '<absent>')
        USING ERRCODE    = 'check_violation',
              CONSTRAINT = 'edges_paper_asserts_requires_essence',
              DETAIL     = format('source_id=%s target_id=%s', NEW.source_id, NEW.target_id),
              HINT       = 'Write this edge with EdgeRepository::upsert_asserts_edge, which takes the digest of the source artifact bytes as a non-optional argument.';
END;
$fn$;

COMMENT ON FUNCTION enforce_paper_asserts_essence() IS
    'Requires properties.essence_digest (64 lowercase hex) on every NEW '
    'paper -asserts-> claim edge, while letting pre-essence rows still be '
    'UPDATEd. This is a TRIGGER and not a CHECK ... NOT VALID on purpose: a '
    'NOT VALID CHECK is still enforced on UPDATE, which breaks '
    'mark_duplicate''s edge retarget (claim.rs:3211) over the legacy corpus. '
    'Only a trigger sees OLD, and only OLD distinguishes "was already unbound" '
    '(allow) from "is being unbound" (reject).';

DROP TRIGGER IF EXISTS edges_paper_asserts_requires_essence ON edges;
CREATE TRIGGER edges_paper_asserts_requires_essence
    BEFORE INSERT OR UPDATE ON edges
    FOR EACH ROW
    -- WHEN keeps the plpgsql body off the hot path: every non-asserts edge
    -- write pays a cheap boolean and never enters the function.
    WHEN (NEW.source_type = 'paper' AND NEW.relationship = 'asserts')
    EXECUTE FUNCTION enforce_paper_asserts_essence();

COMMENT ON TRIGGER edges_paper_asserts_requires_essence ON edges IS
    'Essence binding (backlog 7c909c49): a document may not assert a claim '
    'without naming the bytes the claim was extracted from.';
