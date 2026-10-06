"""Tests for scripts/reconcile_backlog_labels.py (drain unit U058, item I007).

The reconciler's dry run used to count `patched` only inside `if args.apply:`,
so every dry run printed `patched=0` however many unambiguous free-text
resolutions existed: the operator was never told what an apply would do. And
`--apply` exited 0 even when every PATCH was refused (403), so a host timer
running it could never alert. These tests drive `main()` against a stubbed
`/api/v1/claims/by-labels` and PATCH endpoint.
"""
import contextlib
import datetime
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
# The module sys.exit()s at import time without a token.
os.environ.setdefault("EPIGRAPH_TOKEN", "t")
import reconcile_backlog_labels as rbl  # noqa: E402

B1 = "11111111-aaaa-4aaa-8aaa-000000000001"
B2 = "22222222-bbbb-4bbb-8bbb-000000000002"
# Two open backlog items sharing an 8-hex prefix: ambiguous by construction.
B3 = "33333333-cccc-4ccc-8ccc-000000000003"
B3_PEER = "33333333-dddd-4ddd-8ddd-000000000004"
R1 = "aaaaaaaa-0000-4000-8000-0000000000a1"
R2 = "bbbbbbbb-0000-4000-8000-0000000000b2"
R3 = "cccccccc-0000-4000-8000-0000000000c3"


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _fake_get(backlog: list[dict], resolved: list[dict]):
    def fake_get(url, params=None, headers=None, timeout=None):
        labels = params["labels"]
        if labels == "backlog":
            return _Resp(backlog)
        if labels == "resolved":
            return _Resp(resolved)
        raise AssertionError(f"unexpected by-labels query {params!r}")

    return fake_get


def _refused(url, json=None, headers=None, timeout=None):
    req = rbl.httpx.Request("PATCH", url)
    resp = rbl.httpx.Response(403, request=req)
    raise rbl.httpx.HTTPStatusError("403 Forbidden", request=req, response=resp)


class ReconcilerMainTests(unittest.TestCase):
    def setUp(self):
        # main() mkdirs docs/superpowers/reports/ relative to cwd.
        self._old_cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._old_cwd)
        self._tmp.cleanup()

    def _run(self, argv, backlog, resolved, patch_side_effect):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(rbl.httpx, "get", side_effect=_fake_get(backlog, resolved)), \
                mock.patch.object(rbl.httpx, "patch", side_effect=patch_side_effect) as patch, \
                mock.patch.object(sys, "argv", ["reconcile_backlog_labels.py", *argv]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = rbl.main()
        return rc, out.getvalue(), err.getvalue(), patch

    @staticmethod
    def _summary(stdout: str) -> str:
        lines = [ln for ln in stdout.splitlines() if ln.startswith("Reconciler:")]
        assert len(lines) == 1, stdout
        return lines[0]

    def test_dry_run_reports_unambiguous_match_without_patching(self):
        now = _now_iso()
        backlog = [{"id": B1, "content": "x", "created_at": now}]
        resolved = [{"id": R1, "content": f"Resolves {B1}: done", "created_at": now}]

        rc, out, _err, patch = self._run(
            [], backlog, resolved, AssertionError("dry run must not PATCH")
        )

        self.assertEqual(rc, 0)
        patch.assert_not_called()
        summary = self._summary(out)
        self.assertIn("patched=1", summary)
        self.assertIn("needs_review=0", summary)
        self.assertIn("apply=False", summary)
        self.assertIn(f"WOULD-PATCH {B1} via {R1}", out.splitlines())

    def test_dry_run_lists_only_unambiguous_matches(self):
        # B1: full-UUID match (would patch). B2: 8-hex prefix match (would
        # patch). B3: prefix shared with B3_PEER -> needs review, NOT listed.
        now = _now_iso()
        backlog = [
            {"id": B1, "content": "x", "created_at": now},
            {"id": B2, "content": "x", "created_at": now},
            {"id": B3, "content": "x", "created_at": now},
            {"id": B3_PEER, "content": "x", "created_at": now},
        ]
        resolved = [
            {"id": R1, "content": f"closes {B1}", "created_at": now},
            {"id": R2, "content": f"fixes {B2[:8]} in the router", "created_at": now},
            {"id": R3, "content": f"resolves {B3[:8]}", "created_at": now},
        ]

        rc, out, _err, patch = self._run(
            [], backlog, resolved, AssertionError("dry run must not PATCH")
        )

        self.assertEqual(rc, 0)
        patch.assert_not_called()
        would = sorted(ln for ln in out.splitlines() if ln.startswith("WOULD-PATCH "))
        self.assertEqual(would, [f"WOULD-PATCH {B1} via {R1}", f"WOULD-PATCH {B2} via {R2}"])
        summary = self._summary(out)
        self.assertIn("patched=2", summary)
        # B3 and B3_PEER both carry the ambiguous prefix; both go to review.
        self.assertIn("needs_review=2", summary)

    def test_apply_exits_nonzero_when_a_patch_is_refused(self):
        now = _now_iso()
        backlog = [{"id": B1, "content": "x", "created_at": now}]
        resolved = [{"id": R1, "content": f"Resolves {B1}", "created_at": now}]

        rc, out, err, patch = self._run(["--apply"], backlog, resolved, _refused)

        self.assertEqual(rc, 1)
        patch.assert_called_once()
        self.assertIn(f"FAIL {B1}", err)
        summary = self._summary(out)
        self.assertIn("patched=0", summary)
        self.assertIn("apply=True", summary)
        self.assertNotIn("WOULD-PATCH", out)

    def test_apply_counts_successful_patches_and_exits_zero(self):
        now = _now_iso()
        backlog = [
            {"id": B1, "content": "x", "created_at": now},
            {"id": B2, "content": "x", "created_at": now},
        ]
        resolved = [
            {"id": R1, "content": f"Resolves {B1}", "created_at": now},
            {"id": R2, "content": f"Resolves {B2}", "created_at": now},
        ]

        def ok(url, json=None, headers=None, timeout=None):
            return _Resp({"id": url.rsplit("/", 2)[-2], "labels": ["backlog", "resolved"]})

        rc, out, err, patch = self._run(
            ["--apply", "--base-url", "http://api.test"], backlog, resolved, ok
        )

        self.assertEqual(rc, 0)
        self.assertEqual(patch.call_count, 2)
        patched_urls = sorted(c.args[0] for c in patch.call_args_list)
        self.assertEqual(
            patched_urls,
            sorted(f"http://api.test/api/v1/claims/{b}/labels" for b in (B1, B2)),
        )
        self.assertEqual(err, "")
        self.assertIn("patched=2", self._summary(out))

    def test_apply_partial_refusal_counts_successes_and_still_fails(self):
        now = _now_iso()
        backlog = [
            {"id": B1, "content": "x", "created_at": now},
            {"id": B2, "content": "x", "created_at": now},
        ]
        resolved = [
            {"id": R1, "content": f"Resolves {B1}", "created_at": now},
            {"id": R2, "content": f"Resolves {B2}", "created_at": now},
        ]

        def ok_for_b1_refused_for_b2(url, json=None, headers=None, timeout=None):
            if B2 in url:
                return _refused(url, json=json, headers=headers, timeout=timeout)
            return _Resp({})

        rc, out, err, _patch = self._run(
            ["--apply"], backlog, resolved, ok_for_b1_refused_for_b2
        )

        self.assertEqual(rc, 1)
        self.assertIn(f"FAIL {B2}", err)
        self.assertNotIn(f"FAIL {B1}", err)
        self.assertIn("patched=1", self._summary(out))


if __name__ == "__main__":
    unittest.main()
