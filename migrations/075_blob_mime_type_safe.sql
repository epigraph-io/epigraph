-- Migration 075: constrain blobs.mime_type the way 070 already constrains
-- blobs.filename.
--
-- EVIDENCE
-- Migration 070 introduced BOTH the filename hardening and the mime_type
-- column, but only the filename got guards. `filename` is defended three ways:
-- `epigraph_core::blob::sanitize_filename` in Rust, `blobs_filename_safe` here
-- in SQL, and a read-time re-check in `download_blob`. `mime_type` had none of
-- the three -- it was declared `varchar(255) NOT NULL` with no CHECK, and the
-- only Rust guard was an emptiness test.
--
-- The consequence was measured against a live server, not inferred. Uploading
-- `mime_type=text/plain%0AX-Injected:%20yes` answered 201 Created, fsynced the
-- bytes and committed the row; every subsequent
-- `GET /api/v1/blobs/:id/content` then answered
--   500 {"message":"Internal error: failed to build blob response:
--        failed to parse header value"}
-- because `http::Response::builder` defers an invalid header until `.body()`.
-- Not header injection -- a permanent, stored denial of the read path. A
-- mime_type carrying DEL (U+007F) does the same.
--
-- DECISION
-- Mirror `blobs_filename_safe`, with the character set moved from the
-- quoted-string grammar to the header-value grammar: `/`, `;`, `=` and space
-- are required mime syntax (`text/csv; charset=utf-8`) and must stay legal, so
-- only control characters are rejected. `[[:cntrl:]]` is the house form already
-- used by `blobs_filename_safe`; under this cluster's `C` ctype it matches
-- U+0000..U+001F and U+007F, verified with
--   SELECT E'a\x7F' ~ '[[:cntrl:]]';  -> t
-- The Rust guard (`epigraph_core::blob::sanitize_mime_type`) is deliberately
-- the stricter of the two -- `char::is_control` is Unicode Cc, so it also
-- covers U+0080..U+009F -- because it runs first on every write path and this
-- CHECK only has to catch what bypasses it.
--
-- REPAIR BEFORE CONSTRAIN -- `ALTER TABLE ... ADD CONSTRAINT` validates the
-- existing rows and aborts the whole migration on the first violator, so any
-- row poisoned while the write path was open must be repaired first. Rows are
-- reset to the same default the upload path uses when no mime is supplied
-- rather than deleted: the bytes are still valid evidence, only the label on
-- them was unusable, and losing an instrument file to a bad Content-Type would
-- be a far worse outcome than an imprecise one.
--
-- NUMBERING -- 074 is taken by 074_essence_binding.sql on this branch, so 075
-- is the first unused number. (The next-free pointer recorded in commit
-- 8d5b735 said 074; a0e858b consumed it.)

UPDATE blobs
   SET mime_type = 'application/octet-stream'
 WHERE mime_type ~ '[[:cntrl:]]'
    OR length(trim(mime_type)) = 0;

ALTER TABLE blobs
    ADD CONSTRAINT blobs_mime_type_not_empty CHECK (length(trim(mime_type)) > 0),
    ADD CONSTRAINT blobs_mime_type_safe      CHECK (mime_type !~ '[[:cntrl:]]');

COMMENT ON CONSTRAINT blobs_mime_type_safe ON blobs IS
    'mime_type is echoed into the Content-Type response header of '
    'GET /api/v1/blobs/:id/content. A control character there makes the row '
    'permanently undownloadable. Also enforced, more strictly, in Rust by '
    'epigraph_core::blob::sanitize_mime_type.';
