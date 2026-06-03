import datetime, json, os, subprocess, sys, tempfile, unittest
from unittest import mock
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import git_ingest_reconciler as gir  # noqa: E402

class AuthTests(unittest.TestCase):
    def test_pat_env_injected_as_gh_token(self):
        env = gir.gh_env({"EPIGRAPH_GIT_INGEST_GITHUB_PAT": "ghp_abc"})
        self.assertEqual(env.get("GH_TOKEN"), "ghp_abc")
    def test_no_pat_falls_back_to_gh_auth(self):
        env = gir.gh_env({})  # no PAT
        self.assertNotIn("GH_TOKEN", env)  # gh uses its own stored auth

class ConfigTests(unittest.TestCase):
    def test_defaults_and_repos(self):
        cfg = gir.load_config_str('repos = ["epigraph-io/epigraph"]\n')
        self.assertEqual(cfg.repos, ["epigraph-io/epigraph"])
        self.assertEqual(cfg.endpoint, "http://127.0.0.1:8080")  # default
        self.assertGreater(cfg.window_minutes, 0)

class RangeTests(unittest.TestCase):
    def _git(self, d, *a): subprocess.run(["git","-C",d,*a], check=True, capture_output=True)
    def test_merge_commit_two_parents(self):
        with tempfile.TemporaryDirectory() as d:
            self._git(d,"init","-qb","main"); self._git(d,"config","user.email","t@t"); self._git(d,"config","user.name","t")
            Path(d,"a").write_text("1"); self._git(d,"add","."); self._git(d,"commit","-qm","base")
            self._git(d,"checkout","-qb","feat")
            Path(d,"b").write_text("2"); self._git(d,"add","."); self._git(d,"commit","-qm","feat(x): add b")
            self._git(d,"checkout","-q","main")
            self._git(d,"merge","--no-ff","-qm","Merge pull request #1","feat")
            sha = subprocess.run(["git","-C",d,"rev-parse","HEAD"],capture_output=True,text=True).stdout.strip()
            rng = gir.compute_rev_range(d, sha)
            self.assertEqual(rng, f"{sha}^1..{sha}^2")
    def test_single_parent_squash(self):
        with tempfile.TemporaryDirectory() as d:
            self._git(d,"init","-qb","main"); self._git(d,"config","user.email","t@t"); self._git(d,"config","user.name","t")
            Path(d,"a").write_text("1"); self._git(d,"add","."); self._git(d,"commit","-qm","base")
            Path(d,"a").write_text("2"); self._git(d,"add","."); self._git(d,"commit","-qm","squash")
            sha = subprocess.run(["git","-C",d,"rev-parse","HEAD"],capture_output=True,text=True).stdout.strip()
            self.assertEqual(gir.compute_rev_range(d, sha), f"{sha}~1..{sha}")

class DiscoverTests(unittest.TestCase):
    def test_filters_to_merged_within_window(self):
        now = datetime.datetime(2026, 6, 3, 12, 0, tzinfo=datetime.timezone.utc)
        rows = [
            {"number":1,"title":"feat: x","body":"b","merge_commit_sha":"aaa","base":{"sha":"bbb"},
             "user":{"login":"u"},"merged_at":"2026-06-03T11:30:00Z"},      # in window
            {"number":2,"title":"old","body":"","merge_commit_sha":"ccc","base":{"sha":"ddd"},
             "user":{"login":"u"},"merged_at":"2026-06-01T00:00:00Z"},        # too old
            {"number":3,"title":"open","body":"","merge_commit_sha":None,"base":{"sha":"e"},
             "user":{"login":"u"},"merged_at":None},                          # not merged
        ]
        with mock.patch.object(gir, "_gh_json", return_value=rows):
            prs = gir.discover_merged_prs("epigraph-io/epigraph", {}, window_minutes=60, now=now)
        self.assertEqual([p.number for p in prs], [1])
        self.assertEqual(prs[0].merge_sha, "aaa")
        self.assertEqual(prs[0].base_sha, "bbb")
        self.assertEqual(prs[0].author, "u")

    def test_paginated_slurp_pages_parse_through_real_gh_json(self):
        # Regression for the --paginate + json.loads defect: gh --paginate WITHOUT
        # --slurp emits one JSON array per page, concatenated ("[...]\n[...]"), which
        # a single json.loads cannot parse. --slurp wraps all pages in ONE outer
        # array. This test mocks subprocess.run (NOT _gh_json), so the real parse
        # path runs against the two-page slurp shape; the older DiscoverTests mocked
        # _gh_json and never exercised it.
        now = datetime.datetime(2026, 6, 3, 12, 0, tzinfo=datetime.timezone.utc)
        page1 = [
            {"number": 1, "title": "feat: x", "body": "b", "merge_commit_sha": "aaa",
             "base": {"sha": "bbb"}, "user": {"login": "u"},
             "merged_at": "2026-06-03T11:30:00Z"},               # in window
            {"number": 2, "title": "old", "body": "", "merge_commit_sha": "ccc",
             "base": {"sha": "ddd"}, "user": {"login": "u"},
             "merged_at": "2026-06-01T00:00:00Z"},                # too old
        ]
        page2 = [
            {"number": 4, "title": "feat: y", "body": "", "merge_commit_sha": "eee",
             "base": {"sha": "fff"}, "user": {"login": "v"},
             "merged_at": "2026-06-03T11:45:00Z"},               # in window (page 2)
            {"number": 3, "title": "open", "body": "", "merge_commit_sha": None,
             "base": {"sha": "e"}, "user": {"login": "u"}, "merged_at": None},  # not merged
        ]
        # --slurp output is one outer array of pages, each page a JSON array.
        slurp_stdout = json.dumps([page1, page2])
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=slurp_stdout, stderr="")
        with mock.patch.object(gir.subprocess, "run", return_value=completed) as run:
            prs = gir.discover_merged_prs("epigraph-io/epigraph", {}, window_minutes=60, now=now)
        # Both pages' in-window merged PRs survive (1 from page1, 4 from page2); the
        # too-old #2 and unmerged #3 are dropped. Proves cross-page flattening works.
        self.assertEqual(sorted(p.number for p in prs), [1, 4])
        # The call MUST request --slurp (alongside --paginate); without it the real
        # gh would emit concatenated arrays and json.loads would raise. This pins
        # the fix so a future drop of --slurp fails the suite.
        called_args = run.call_args.args[0]
        self.assertIn("--paginate", called_args)
        self.assertIn("--slurp", called_args)

    def test_concatenated_pages_without_slurp_would_crash(self):
        # Documents WHY --slurp is required: the pre-fix shape (concatenated
        # per-page arrays, no outer wrapper) is what plain --paginate emits, and a
        # single json.loads raises JSONDecodeError ("Extra data") on it.
        concatenated = '[{"number": 1}]\n[{"number": 2}]\n'
        with self.assertRaises(json.JSONDecodeError):
            json.loads(concatenated)

if __name__ == "__main__":
    unittest.main()
