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

class MirrorTests(unittest.TestCase):
    def test_clone_then_fetch(self):
        with tempfile.TemporaryDirectory() as remote, tempfile.TemporaryDirectory() as state:
            subprocess.run(["git","init","-qb","main",remote],check=True,capture_output=True)
            for cmd in (["config","user.email","t@t"],["config","user.name","t"]):
                subprocess.run(["git","-C",remote,*cmd],check=True,capture_output=True)
            Path(remote,"a").write_text("1")
            subprocess.run(["git","-C",remote,"add","."],check=True,capture_output=True)
            subprocess.run(["git","-C",remote,"commit","-qm","c1"],check=True,capture_output=True)
            mirror = gir.ensure_mirror(remote, state, {})         # first call clones
            self.assertTrue(Path(mirror, ".git").exists() or Path(mirror, "HEAD").exists())
            mirror2 = gir.ensure_mirror(remote, state, {})        # second call fetches
            self.assertEqual(mirror, mirror2)

class ArgvTests(unittest.TestCase):
    def test_build_ingest_argv(self):
        pr = gir.PullRequest(number=252, title="fix(api): x", body="Resolves d531c585",
                             merge_sha="2a31f8d", base_sha="b72e271", author="tylorsama",
                             merged_at="2026-06-02T15:10:01Z")
        argv = gir.build_ingest_argv(pr, mirror="/m", endpoint="http://127.0.0.1:8080",
                                     rev_range="2a31f8d^1..2a31f8d^2", slug="epigraph-io/epigraph",
                                     default_orchestrator_id="7b3a0c1e-0000-4000-8000-000000000001",
                                     ingest_git_bin="ingest_git", dry_run=True)
        self.assertEqual(argv[0], "ingest_git")
        self.assertIn("--pr-ingest", argv)
        # spot-check key flag/value pairs:
        def val(flag): return argv[argv.index(flag)+1]
        self.assertEqual(val("--repo-slug"), "epigraph-io/epigraph")
        self.assertEqual(val("--pr-number"), "252")
        self.assertEqual(val("--merge-sha"), "2a31f8d")
        self.assertEqual(val("--rev-range"), "2a31f8d^1..2a31f8d^2")
        self.assertEqual(val("--merged-at"), "2026-06-02T15:10:01Z")
        self.assertEqual(val("--orchestrator-id"), "7b3a0c1e-0000-4000-8000-000000000001")
        self.assertEqual(val("--repo"), "/m")
        self.assertEqual(val("--endpoint"), "http://127.0.0.1:8080")
        self.assertIn("--dry-run", argv)

class MainLoopTests(unittest.TestCase):
    def test_runs_all_prs_and_isolates_failures(self):
        cfg = gir.Config(repos=["o/r"], endpoint="http://x", state_dir="/tmp/st",
                         default_orchestrator_id=None)
        prs = [gir.PullRequest(1,"a","",f"s1","b","u","2026-06-03T11:59:00Z"),
               gir.PullRequest(2,"b","",f"s2","b","u","2026-06-03T11:59:00Z")]
        calls = []
        with mock.patch.object(gir,"ensure_mirror",return_value="/m"), \
             mock.patch.object(gir,"discover_merged_prs",return_value=prs), \
             mock.patch.object(gir,"ingest_pr",side_effect=lambda pr,*a,**k:(calls.append(pr.number) or (1 if pr.number==1 else 0))):
            n_ok, n_fail = gir.run_once(cfg, dry_run=False)
        self.assertEqual(calls, [1,2])          # both attempted (failure isolated)
        self.assertEqual((n_ok,n_fail),(1,1))

if __name__ == "__main__":
    unittest.main()
