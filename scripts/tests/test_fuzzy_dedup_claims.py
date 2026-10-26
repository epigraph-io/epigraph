"""Tests for scripts/fuzzy_dedup_claims.py.

The script used to mark duplicates with its own SQL: a raw `UPDATE claims SET
supersedes = ..., is_current = false` plus hand-written re-pointing of mass
functions, edges, evidence and traces. That wrote no `same_as` identity edge
carrying `properties.dedup` and no revert record, so its marks could not be
un-marked and were invisible to `label_dedup_index_view`. It must mark through
`POST /api/v1/claims/{dup}/dedup` instead, and read the database only.

These tests drive `main()` against a REAL local HTTP server (the standard
library's `http.server` on 127.0.0.1, recording every request it receives) and
a recording database cursor that answers the script's two reads and records
every statement. No request library is patched.
"""
import contextlib
import http.server
import io
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import fuzzy_dedup_claims as fdc  # noqa: E402

CANON = "11111111-aaaa-4aaa-8aaa-000000000001"
DUP_A = "22222222-bbbb-4bbb-8bbb-000000000002"
DUP_B = "33333333-cccc-4ccc-8ccc-000000000003"
# Already superseded by some other claim: skipped, never posted.
DUP_SUPERSEDED = "44444444-dddd-4ddd-8ddd-000000000004"
ELSEWHERE = "55555555-eeee-4eee-8eee-000000000005"

# Any statement that writes. The script must issue none of them.
WRITE_SQL = re.compile(r"^\s*(UPDATE|DELETE|INSERT|ALTER|TRUNCATE)\b", re.I | re.M)


class _Recorder(http.server.BaseHTTPRequestHandler):
    """Records each request; answers POST /api/v1/claims/<id>/dedup with the
    status configured for that id (default 200), or hangs up without an answer
    when it is configured as "drop"."""

    requests: list = []
    statuses: dict = {}

    def do_POST(self):  # noqa: N802 (http.server naming)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        type(self).requests.append(
            {
                "method": "POST",
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "content_type": self.headers.get("Content-Type"),
                "body": json.loads(body) if body else None,
            }
        )
        m = re.fullmatch(r"/api/v1/claims/([0-9a-f-]{36})/dedup", self.path)
        status = type(self).statuses.get(m.group(1), 200) if m else 404
        if status == "drop":
            # Hang up without an HTTP answer (a reset / dead upstream).
            self.close_connection = True
            return
        if status == 200:
            payload = {"duplicate_id": m.group(1), "canonical_id": CANON, "mode": "dedup"}
        else:
            payload = {"error": "Forbidden", "message": "not_owner"}
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        type(self).requests.append({"method": "GET", "path": self.path})
        self.send_response(404)
        self.end_headers()

    do_PATCH = do_PUT = do_DELETE = do_GET  # noqa: N815

    def log_message(self, *args):
        return None


class _Cursor:
    """Answers the script's two reads from `claims` and records every statement."""

    def __init__(self, claims: dict, log: list):
        self.claims = claims
        self.log = log
        self._one = None
        self._all = []
        self.rowcount = 0

    def execute(self, sql, params=None):
        self.log.append(sql)
        self.rowcount = 1
        if "trace_count" in sql:
            ids = params[0]
            # (id, is_deduped, trace_count, mf_count, edge_count, is_current)
            self._all = [
                (
                    i,
                    self.claims[i].get("deduped", False),
                    0,
                    0,
                    0,
                    self.claims[i]["is_current"],
                )
                for i in ids
                if i in self.claims
            ]
        elif "supersedes" in sql and sql.lstrip().upper().startswith("SELECT"):
            c = self.claims.get(params[0])
            # (is_deduped, supersedes, is_current)
            self._one = (
                None
                if c is None
                else (c.get("deduped", False), c["supersedes"], c["is_current"])
            )

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all

    def close(self):
        return None


class _Conn:
    def __init__(self, cursor):
        self._cursor = cursor
        self.autocommit = False
        self.commits = 0
        self.sessions: list = []

    def cursor(self):
        return self._cursor

    def set_session(self, **kwargs):
        self.sessions.append(kwargs)

    def commit(self):
        self.commits += 1

    def rollback(self):
        return None

    def close(self):
        return None


class FuzzyDedupThroughTheEndpointTests(unittest.TestCase):
    def setUp(self):
        _Recorder.requests = []
        _Recorder.statuses = {}
        self.server = http.server.HTTPServer(("127.0.0.1", 0), _Recorder)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.tmp = tempfile.TemporaryDirectory()
        self.input = os.path.join(self.tmp.name, "semantic-dedup.json")
        with open(self.input, "w") as fh:
            json.dump(
                {"groups": [{"rep": CANON, "members": [CANON, DUP_A, DUP_B, DUP_SUPERSEDED]}]},
                fh,
            )
        self.claims = {
            CANON: {"is_current": True, "supersedes": None},
            DUP_A: {"is_current": True, "supersedes": None},
            DUP_B: {"is_current": True, "supersedes": None},
            DUP_SUPERSEDED: {"is_current": False, "supersedes": ELSEWHERE},
        }
        self.sql = []
        self.conn = _Conn(_Cursor(self.claims, self.sql))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def _run(self, argv, env):
        out = io.StringIO()
        environ = {
            k: v
            for k, v in os.environ.items()
            if k not in ("EPIGRAPH_TOKEN", "EPIGRAPH_API_BASE")
        }
        environ.update(env)
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(fdc.psycopg2, "connect", return_value=self.conn), \
                mock.patch.object(sys, "argv", ["fuzzy_dedup_claims.py", "--input", self.input, *argv]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            try:
                rc = fdc.main()
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue()

    def _posts(self):
        return [r for r in _Recorder.requests if r["method"] == "POST"]

    def _writes(self):
        return [s for s in self.sql if WRITE_SQL.search(s)]

    def test_execute_marks_each_duplicate_through_the_dedup_endpoint(self):
        rc, out = self._run(
            ["--execute"], {"EPIGRAPH_TOKEN": "tok-123", "EPIGRAPH_API_BASE": self.base}
        )

        self.assertEqual(self._writes(), [], "the script must not write SQL")
        self.assertTrue(
            self.conn.sessions and all(kw.get("readonly") is True for kw in self.conn.sessions),
            f"the database session must be read-only: {self.conn.sessions}",
        )
        posts = self._posts()
        self.assertEqual(
            sorted(p["path"] for p in posts),
            sorted(f"/api/v1/claims/{d}/dedup" for d in (DUP_A, DUP_B)),
            out,
        )
        for p in posts:
            self.assertEqual(p["body"]["canonical_id"], CANON)
            self.assertEqual(p["authorization"], "Bearer tok-123")
            self.assertEqual(p["content_type"], "application/json")
        self.assertEqual(
            [r for r in _Recorder.requests if r["method"] != "POST"], [], "POST only"
        )
        self.assertEqual(rc, 0, out)
        self.assertIn("duplicates_marked:", out)
        self.assertRegex(out, r"duplicates_marked:\s+2\b")
        self.assertRegex(out, r"duplicates_skipped_already_superseded:\s+1\b")

    def test_a_refused_mark_is_reported_and_fails_the_run(self):
        _Recorder.statuses = {DUP_B: 403}
        rc, out = self._run(
            ["--execute"], {"EPIGRAPH_TOKEN": "tok-123", "EPIGRAPH_API_BASE": self.base}
        )

        self.assertEqual(self._writes(), [])
        self.assertEqual(len(self._posts()), 2, out)
        self.assertRegex(out, r"duplicates_marked:\s+1\b")
        self.assertRegex(out, r"duplicates_refused:\s+1\b")
        self.assertIn(DUP_B, out, "the refused duplicate is named")
        self.assertIn("403", out)
        self.assertEqual(rc, 1, out)

    def test_dry_run_posts_nothing_and_writes_nothing(self):
        rc, out = self._run([], {"EPIGRAPH_TOKEN": "tok-123", "EPIGRAPH_API_BASE": self.base})

        self.assertEqual(self._posts(), [])
        self.assertEqual(self._writes(), [])
        self.assertTrue(self.conn.sessions, "the session is configured before any read")
        self.assertTrue(
            all(kw.get("readonly") is True for kw in self.conn.sessions),
            f"the database session must be read-only: {self.conn.sessions}",
        )
        self.assertRegex(out, r"duplicates_would_mark:\s+2\b")
        self.assertEqual(rc, 0, out)

    def test_execute_without_a_token_refuses_before_any_request(self):
        rc, out = self._run(["--execute"], {"EPIGRAPH_API_BASE": self.base})

        self.assertNotEqual(rc, 0, out)
        self.assertEqual(_Recorder.requests, [])
        self.assertEqual(self._writes(), [])

    def test_a_member_already_marked_is_never_picked_as_the_canonical(self):
        # The snapshot's rep was marked a duplicate since: the canonical must
        # be a current member, and the retired rep is not posted onto.
        self.claims[CANON] = {"is_current": False, "supersedes": ELSEWHERE}
        rc, out = self._run(
            ["--execute"], {"EPIGRAPH_TOKEN": "tok-123", "EPIGRAPH_API_BASE": self.base}
        )

        posts = self._posts()
        self.assertEqual(len(posts), 1, out)
        canonical = posts[0]["body"]["canonical_id"]
        self.assertIn(canonical, (DUP_A, DUP_B))
        self.assertNotIn(CANON, posts[0]["path"])
        self.assertEqual(rc, 0, out)

    def _single_group(self, members):
        with open(self.input, "w") as fh:
            json.dump({"groups": [{"rep": members[0], "members": members}]}, fh)

    def test_a_lone_live_member_still_reports_its_already_superseded_duplicate(self):
        # One live member (the canonical) and one member superseded by another
        # claim: nothing to mark, but the skipped member is counted, not
        # folded into "already deduped". The same in a dry run and executed.
        self._single_group([CANON, DUP_SUPERSEDED])
        for argv in ([], ["--execute"]):
            with self.subTest(argv=argv):
                _Recorder.requests = []
                rc, out = self._run(
                    argv, {"EPIGRAPH_TOKEN": "tok-123", "EPIGRAPH_API_BASE": self.base}
                )
                self.assertEqual(self._posts(), [], out)
                self.assertRegex(out, r"duplicates_skipped_already_superseded:\s+1\b")
                self.assertEqual(rc, 0, out)

    def test_an_unmarked_legacy_claim_is_live_again(self):
        # A pre-2026-10 mark by this script left the `deduped` label; once the
        # identity-edge backfill made it a normal dedup record and it was
        # un-marked (operator ruling R-7) it is CURRENT again, with the label
        # still on it. It is live: picked as the canonical when it is the
        # snapshot's rep, and marked like any other member when it is not. A
        # labelled member still retired stays passed over.
        self.claims[CANON] = {"is_current": True, "supersedes": None, "deduped": True}
        self.claims[DUP_A] = {"is_current": True, "supersedes": None, "deduped": True}
        self.claims[DUP_B] = {"is_current": False, "supersedes": ELSEWHERE, "deduped": True}
        rc, out = self._run(
            ["--execute"], {"EPIGRAPH_TOKEN": "tok-123", "EPIGRAPH_API_BASE": self.base}
        )
        posts = self._posts()
        self.assertEqual([p["path"] for p in posts], [f"/api/v1/claims/{DUP_A}/dedup"], out)
        self.assertEqual(posts[0]["body"]["canonical_id"], CANON, out)
        # DUP_B (still a retired legacy mark) is passed over silently, as
        # before; DUP_SUPERSEDED is still counted.
        self.assertRegex(out, r"duplicates_skipped_already_superseded:\s+1\b")
        self.assertEqual(rc, 0, out)

    def test_a_rerun_passes_over_its_own_earlier_marks(self):
        # DUP_A was marked onto CANON by an earlier run (the endpoint set
        # supersedes = CANON). A re-run neither re-posts it nor reports it as
        # superseded elsewhere; DUP_B is still marked, DUP_SUPERSEDED counted.
        self.claims[DUP_A] = {"is_current": False, "supersedes": CANON}
        rc, out = self._run(
            ["--execute"], {"EPIGRAPH_TOKEN": "tok-123", "EPIGRAPH_API_BASE": self.base}
        )
        self.assertEqual(
            [p["path"] for p in self._posts()], [f"/api/v1/claims/{DUP_B}/dedup"], out
        )
        self.assertRegex(out, r"duplicates_marked:\s+1\b")
        self.assertRegex(out, r"duplicates_skipped_already_superseded:\s+1\b")
        self.assertEqual(rc, 0, out)

    def test_a_dropped_connection_is_a_refusal_and_keeps_the_clusters_other_marks(self):
        # DUP_A is marked (200), then the upstream hangs up on DUP_B. DUP_A's
        # mark is real and must stay counted; DUP_B is a refusal, not a failed
        # cluster that discards the count.
        _Recorder.statuses = {DUP_B: "drop"}
        rc, out = self._run(
            ["--execute"], {"EPIGRAPH_TOKEN": "tok-123", "EPIGRAPH_API_BASE": self.base}
        )
        self.assertEqual(len(self._posts()), 2, out)
        self.assertRegex(out, r"duplicates_marked:\s+1\b")
        self.assertRegex(out, r"duplicates_refused:\s+1\b")
        self.assertRegex(out, r"clusters_failed:\s+0\b")
        self.assertIn(DUP_B, out, "the unanswered duplicate is named")
        self.assertEqual(rc, 1, out)

    def test_an_unreachable_api_refuses_each_duplicate_and_fails_the_run(self):
        import socket

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            closed = f"http://127.0.0.1:{sock.getsockname()[1]}"
        rc, out = self._run(
            ["--execute"], {"EPIGRAPH_TOKEN": "tok-123", "EPIGRAPH_API_BASE": closed}
        )
        self.assertEqual(_Recorder.requests, [])
        self.assertRegex(out, r"duplicates_marked:\s+0\b")
        self.assertRegex(out, r"duplicates_refused:\s+2\b")
        self.assertRegex(out, r"clusters_failed:\s+0\b")
        self.assertEqual(rc, 1, out)


if __name__ == "__main__":
    unittest.main()
