"""Tests for scripts/cleanup_backlog_labels.py `page_claims`.

It paged `GET /api/v1/claims/by-labels` by `offset`, so a claim written
between two page reads shifted every later row by one and the walk returned the
last row of the earlier page twice (backlog b444e39f). It now follows the
route's keyset cursor: the `X-Next-Cursor` header passed back as `after`.
"""
import contextlib
import io
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
# The module sys.exit()s at import time without a token.
os.environ.setdefault("EPIGRAPH_TOKEN", "t")
import cleanup_backlog_labels as cbl  # noqa: E402
from _by_labels_fake import (  # noqa: E402
    KeysetServer,
    LegacyServer,
    StuckCursorServer,
    make_rows,
)


def _page(server, current_only=False):
    with mock.patch.object(cbl.httpx, "get", side_effect=server.get), \
            contextlib.redirect_stderr(io.StringIO()):
        return cbl.page_claims("http://fake", ["backlog"], ["resolved"], current_only=current_only)


class CleanupPageClaimsTests(unittest.TestCase):
    def test_a_write_between_pages_neither_duplicates_nor_drops_a_row(self):
        rows = make_rows(250)
        newer = make_rows(1, prefix="n")[0]
        server = KeysetServer(rows, insert_after_first_page=newer)

        got = [r["id"] for r in _page(server)]

        self.assertEqual(len(got), len(set(got)), "a row came back twice")
        self.assertEqual(got, [r["id"] for r in rows])

    def test_pages_by_cursor_never_by_offset(self):
        server = KeysetServer(make_rows(250))

        _page(server)

        self.assertEqual(len(server.calls), 3, server.calls)
        self.assertNotIn("after", server.calls[0])
        for call in server.calls:
            self.assertFalse(call.get("offset"), f"offset sent: {call!r}")
        self.assertEqual(server.calls[1]["after"], "k1." + make_rows(250)[99]["id"])

    def test_filters_are_forwarded_on_every_page(self):
        server = KeysetServer(make_rows(150))

        _page(server, current_only=True)

        for call in server.calls:
            self.assertEqual(call["labels"], "backlog")
            self.assertEqual(call["exclude_labels"], "resolved")
            self.assertEqual(call["current_only"], "true")

    def test_exact_multiple_of_page_size_ends_on_the_empty_page(self):
        server = KeysetServer(make_rows(200))

        got = _page(server)

        self.assertEqual(len(got), 200)
        self.assertEqual(len(server.calls), 3)

    def test_a_full_page_without_a_cursor_header_is_an_error(self):
        # A server that predates keyset paging: stopping here would silently
        # truncate the walk at 100 rows.
        with self.assertRaises(RuntimeError) as cm:
            _page(LegacyServer(make_rows(250)))
        self.assertIn("x-next-cursor", str(cm.exception).lower())

    def test_a_repeated_cursor_is_an_error(self):
        server = StuckCursorServer()

        with self.assertRaises(RuntimeError) as cm:
            _page(server)

        self.assertIn("repeated", str(cm.exception))
        self.assertEqual(server.calls, 2)


if __name__ == "__main__":
    unittest.main()
