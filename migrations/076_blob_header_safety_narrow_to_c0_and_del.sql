-- Migration 076: narrow `blobs_filename_safe` and `blobs_mime_type_safe` from
-- `[[:cntrl:]]` to the bytes that actually terminate an HTTP header.
--
-- EVIDENCE
-- `[[:cntrl:]]` does not mean "Unicode control character". Postgres resolves a
-- POSIX character class through the database's ctype, and this cluster --
-- `server_encoding = SQL_ASCII`, `datctype = C` -- applies it BYTE-WISE, where
-- the C-locale `iscntrl` counts 0x80..0x9F as control. Measured on PG 16.2:
--
--   SELECT chr(127) ~ '[[:cntrl:]]';   -> t   -- U+007F, expected
--   SELECT chr(159) ~ '[[:cntrl:]]';   -> t   -- raw byte 0x9F
--   SELECT 'a—b'    ~ '[[:cntrl:]]';   -> t   -- U+2014, bytes E2 80 94
--   SELECT 'a’b'    ~ '[[:cntrl:]]';   -> t   -- U+2019, bytes E2 80 99
--   SELECT 'a​b'    ~ '[[:cntrl:]]';   -> t   -- U+200B, bytes E2 80 8B
--
-- So every character whose UTF-8 encoding carries a byte in 0x80..0x9F trips
-- it: all of General Punctuation (em/en dash, curly quotes, ellipsis, bullet,
-- ZWSP) and, arbitrarily, some scripts but not others -- `あ.czi` (E3 81 82) was
-- refused while `Müller_gel.tif` (C3 BC) was accepted.
--
-- The Rust guards use `char::is_control`, which is Unicode `Cc` and covers none
-- of those. `BlobRepository::store` fsyncs the bytes BEFORE the INSERT, so a
-- value that passes the guard and is then refused by the CHECK leaves an orphan
-- file with no row. Measured end to end through the real router, before this
-- migration:
--
--   POST /api/v1/blobs?filename=probe.bin&mime_type=text/plain;%20x=a%E2%80%94b
--     -> 500 {"error":"DatabaseError"}, 1 file on disk, 0 rows
--        (violates check constraint "blobs_mime_type_safe")
--
-- That is precisely the "orphan file plus opaque 500" failure migration 075 was
-- written to eliminate, reintroduced from the database side. `blobs_filename_safe`
-- (migration 070) carried the same flaw first; 075 copied the house form.
--
-- DECISION
-- Reject exactly the characters that break a header value: C0 (U+0000..U+001F)
-- and DEL (U+007F). `http`'s header-value grammar accepts every other byte --
-- verified by round-tripping `Content-Type: text/plain; x=a—b` through
-- `GET /api/v1/blobs/:id/content` for 200 OK -- so nothing wider is defensible,
-- and anything wider rejects legitimate instrument filenames.
--
-- This restores the invariant the guards are supposed to have: whatever Rust
-- admits, the database admits. The Rust guard stays strictly the stricter of
-- the two -- it additionally rejects U+0080..U+009F, which are `Cc` but whose
-- UTF-8 bytes (C2 80..C2 9F) contain nothing in C0/DEL.
--
-- WHY `E'...'` AND NOT A PLAIN LITERAL -- a plain `'[\x00-\x1F\x7F]'` is not
-- escape-neutral. With `standard_conforming_strings = off` the literal's own
-- escape processing turns `\x00` into a NUL byte and the statement dies:
--     ERROR: invalid byte sequence for encoding "SQL_ASCII": 0x00
-- The `E''` form resolves to the identical pattern `[\x00-\x1F\x7F]` under both
-- settings (verified with the setting forced each way), so the constraint means
-- the same thing whatever session applies it.
--
-- NO REPAIR PASS -- unlike 075 this migration needs none, and must not have one.
-- The new rejected set is a strict subset of the old, so every row that already
-- satisfies the constraint satisfies the new one and `ADD CONSTRAINT` validates
-- trivially.
--
-- 070 AND 075 ARE LEFT BYTE-IDENTICAL, DELIBERATELY -- including 075's repair
-- `UPDATE ... WHERE mime_type ~ '[[:cntrl:]]'`, which over-reaches onto General
-- Punctuation exactly as its CHECK did, and including the claim in its DECISION
-- note that `[[:cntrl:]]` "stops at U+007F", which the probes above refute.
-- Both files are applied migrations. `epigraph_api::run_migrations` embeds them
-- with `sqlx::migrate!` and validates checksums before the HTTP listener binds,
-- so editing either one turns every database that already ran it into a startup
-- panic -- measured: after a comment-only edit, `sqlx migrate info` reports
--     75/installed (different checksum) blob mime type safe
-- and migrations/README.md documents the consequence. What that immutability
-- costs is bounded:
--   * a database migrating from before 070 -- production included, since
--     070_blobs.sql is NOT an ancestor of `main`, so no production database has
--     a `blobs` table -- creates the table empty at 070 and reaches 075 in the
--     same invocation, where the UPDATE matches 0 rows;
--   * the only rows it can still relabel sit on a database parked at 070..074
--     whose mime_type is non-ASCII, i.e. already outside the Content-Type
--     grammar. Bytes, filename, content hash and provenance are untouched; only
--     an exotic label becomes the default one.
-- Trading a certain startup failure for that is the worse deal. This migration
-- leaves the schema correct on every database either way, and the
-- `COMMENT ON CONSTRAINT` below replaces 075's inaccurate one in the catalog.
--
-- NUMBERING -- 075 is taken by 075_blob_mime_type_safe.sql on this branch, so
-- 076 is the first unused number.
--
-- WHY BOTH CONSTRAINTS ARE RESTATED HERE -- `blobs_filename_safe` comes from
-- 070 and `blobs_mime_type_safe` from 075. Replacing a CHECK is lossless (it
-- carries no data), so this converges every database, fresh or existing, on one
-- pair of definitions without rewriting either file.

ALTER TABLE blobs DROP CONSTRAINT IF EXISTS blobs_filename_safe;
ALTER TABLE blobs
    ADD CONSTRAINT blobs_filename_safe
    CHECK (filename !~ E'[\\x00-\\x1F\\x7F"\\\\/]');

ALTER TABLE blobs DROP CONSTRAINT IF EXISTS blobs_mime_type_safe;
ALTER TABLE blobs
    ADD CONSTRAINT blobs_mime_type_safe
    CHECK (mime_type !~ E'[\\x00-\\x1F\\x7F]');

COMMENT ON CONSTRAINT blobs_filename_safe ON blobs IS
    'filename is echoed into the Content-Disposition response header of '
    'GET /api/v1/blobs/:id/content, inside a quoted string. C0 and DEL '
    'terminate the header; a double quote, a backslash or a slash ends the '
    'quoted string or smuggles a path. '
    'Non-ASCII is NOT rejected: it breaks no header, and instrument files '
    'legitimately carry it. Also enforced, more strictly, in Rust by '
    'epigraph_core::blob::sanitize_filename.';

COMMENT ON CONSTRAINT blobs_mime_type_safe ON blobs IS
    'mime_type is echoed into the Content-Type response header of '
    'GET /api/v1/blobs/:id/content. C0 and DEL there make the row permanently '
    'undownloadable. Nothing wider: the guard must never reject a value Rust '
    'accepts, or store() fsyncs the bytes and then dies on the INSERT. Also '
    'enforced, more strictly, in Rust by epigraph_core::blob::sanitize_mime_type.';
