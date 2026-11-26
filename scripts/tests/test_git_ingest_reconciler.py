import dataclasses, datetime, json, os, subprocess, sys, tempfile, unittest
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

def _api_commits(d, shas):
    """The PR commits API's rows for `shas` (oldest first), built from the
    repo's own commits: GitHub's rebase merge keeps each commit's author,
    author date and message, and gives it a new sha."""
    rows = []
    for sha in shas:
        email, date, msg = subprocess.run(
            ["git", "-C", d, "show", "-s", "--format=%ae%x00%aI%x00%B", sha],
            capture_output=True, text=True, check=True).stdout.split("\0")
        rows.append({"sha": "pre-rebase-" + sha[:7],
                     "commit": {"author": {"email": email, "date": date}, "message": msg}})
    return rows

class RebaseRangeTests(unittest.TestCase):
    """Backlog 39dfef78: a rebase-merged PR's commits land on main as a linear
    run with one parent each, so the one-parent `M~1..M` dropped all but the
    last of them."""
    def _git(self, d, *a, env=None):
        return subprocess.run(["git", "-C", d, *a], check=True, capture_output=True,
                              text=True, env=env).stdout.strip()
    def _repo(self, d):
        self._git(d, "init", "-qb", "main"); self._git(d, "config", "user.email", "t@t")
        self._git(d, "config", "user.name", "t")
        Path(d, "a").write_text("0"); self._git(d, "add", "."); self._git(d, "commit", "-qm", "base")
    def _commit(self, d, f, msg, date):
        env = dict(os.environ, GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
        Path(d, f).write_text(msg); self._git(d, "add", ".")
        self._git(d, "commit", "-qm", msg, env=env)
        return self._git(d, "rev-parse", "HEAD")

    def _ingested_range(self, d, pr, commits_rows):
        """Run the reconciler over one PR whose mirror is `d`, the PR commits
        API answering `commits_rows`; return the --rev-range ingest_git got."""
        real_run = subprocess.run
        seen = []
        def run(argv, **kw):
            if argv[0] == "ingest_git":
                seen.append(argv); return subprocess.CompletedProcess(argv, 0, "", "")
            return real_run(argv, **kw)
        with tempfile.TemporaryDirectory() as st:
            cfg = gir.Config(repos=["o/r"], endpoint="http://x", state_dir=st, author_key_file="/k")
            with mock.patch.object(gir, "ensure_mirror", return_value=d), \
                 mock.patch.object(gir, "discover_merged_prs", return_value=[pr]), \
                 mock.patch.object(gir, "fetch_pr_commits", create=True, return_value=commits_rows), \
                 mock.patch.object(gir.subprocess, "run", side_effect=run):
                self.assertEqual(gir.run_once(cfg, dry_run=False), (1, 0))
        (argv,) = seen
        return argv[argv.index("--rev-range") + 1]

    def test_rebase_merge_ingests_every_pr_commit(self):
        with tempfile.TemporaryDirectory() as d:
            self._repo(d)
            shas = [self._commit(d, f"f{i}", f"feat(x): step {i}", f"2026-06-0{i}T10:00:00+02:00")
                    for i in (1, 2, 3)]
            m = shas[-1]
            pr = gir.PullRequest(9, "feat(x): steps", "", m, "", "u", "2026-06-04T00:00:00Z")
            rng = self._ingested_range(d, pr, _api_commits(d, shas))
            self.assertEqual(rng, f"{m}~3..{m}")
            self.assertEqual(self._git(d, "rev-list", "--reverse", rng).split(), shas)

    def test_squash_merge_of_a_multi_commit_pr_stays_one_commit(self):
        # The API lists the PR's 3 branch commits, but main holds one squash
        # commit on top of unrelated history: `M~3..M` would claim two
        # commits from other PRs.
        with tempfile.TemporaryDirectory() as d:
            self._repo(d)
            self._commit(d, "o1", "fix(y): other pr", "2026-06-01T09:00:00Z")
            self._commit(d, "o2", "fix(z): another pr", "2026-06-01T09:30:00Z")
            m = self._commit(d, "sq", "feat(x): steps (#9)", "2026-06-04T00:00:00Z")
            rows = [{"sha": f"b{i}", "commit": {"author": {"email": "t@t", "date": f"2026-06-0{i}T08:00:00Z"},
                                                 "message": f"feat(x): step {i}"}} for i in (1, 2, 3)]
            pr = gir.PullRequest(9, "feat(x): steps", "", m, "", "u", "2026-06-04T00:00:00Z")
            self.assertEqual(self._ingested_range(d, pr, rows), f"{m}~1..{m}")

    def test_pr_commits_api_cap_falls_back_to_the_tip_commit(self):
        # The commits API lists at most 250 commits, so an answer that long may
        # be truncated and cannot prove a rebase run, even one that matches
        # main; the tip is still ingested. (The cap is lowered to 3 here so the
        # fixture stays small.)
        with tempfile.TemporaryDirectory() as d:
            self._repo(d)
            shas = [self._commit(d, f"f{i}", f"feat(x): step {i}", f"2026-06-0{i}T10:00:00Z")
                    for i in (1, 2, 3)]
            m = shas[-1]
            with mock.patch.object(gir, "PR_COMMITS_API_CAP", 3), \
                 self.assertLogs(gir.LOG, level="WARNING"):
                self.assertEqual(gir.compute_rev_range(d, m, _api_commits(d, shas)), f"{m}~1..{m}")
            self.assertEqual(gir.compute_rev_range(d, m, _api_commits(d, shas)), f"{m}~3..{m}")

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
            prs = gir.discover_merged_prs("epigraph-io/epigraph", {}, now - datetime.timedelta(minutes=60))
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
            prs = gir.discover_merged_prs("epigraph-io/epigraph", {}, now - datetime.timedelta(minutes=60))
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
        self.assertNotIn("--orchestrator-id", argv)  # a fallback goes in the env
        self.assertNotIn("--token", argv)
        self.assertEqual(val("--repo"), "/m")
        self.assertEqual(val("--endpoint"), "http://127.0.0.1:8080")
        self.assertIn("--dry-run", argv)

UTC = datetime.timezone.utc

def _row(n, merged_at, updated_at=None, sha=None):
    """A merged PR as the pulls API lists it."""
    return {"number": n, "title": f"fix(x): pr {n}", "body": "", "merge_commit_sha": sha or f"m{n}",
            "base": {"sha": "b"}, "user": {"login": "u"}, "merged_at": merged_at,
            "updated_at": updated_at or merged_at}

class FakeGitHub:
    """Answers `_gh_json` like GitHub: the closed-PR listing (most recently
    updated first, one page) and single PRs by number."""
    def __init__(self, rows):
        self.rows = rows; self.calls = []
    def __call__(self, args, env):
        self.calls.append(args)
        path = args[0]
        if path.endswith("/pulls"):
            if any(a.startswith("page=") and a != "page=1" for a in args):
                return []
            return sorted(self.rows, key=lambda r: r["updated_at"], reverse=True)
        number = int(path.rsplit("/", 1)[1])
        for r in self.rows:
            if r["number"] == number:
                return r
        raise subprocess.CalledProcessError(1, ["gh", "api", path], stderr="HTTP 404")

class StateTests(unittest.TestCase):
    """Backlog 39dfef78: the reconciler kept no state, so a PR merged while it
    was down for longer than the window, or one whose ingest failed, was never
    ingested. It now keeps a per-repo cursor and a retry list."""
    T0 = datetime.datetime(2026, 6, 3, 12, 0, tzinfo=UTC)

    def setUp(self):
        st = tempfile.TemporaryDirectory(); self.addCleanup(st.cleanup)
        self.cfg = gir.Config(repos=["o/r"], endpoint="http://x", state_dir=st.name,
                              window_minutes=60, author_key_file="/k")

    def _run(self, gh, at, results=None, dry_run=False):
        """One reconciler run at `at`; `results` maps a PR number to its
        ingest outcome (an int return code, or an exception to raise),
        default 0. Returns ((ok, fail), [PR numbers attempted])."""
        attempted = []
        def ingest(pr, *a, **k):
            attempted.append(pr.number)
            res = (results or {}).get(pr.number, 0)
            if isinstance(res, Exception):
                raise res
            return res
        with mock.patch.object(gir, "ensure_mirror", return_value="/m"), \
             mock.patch.object(gir, "_gh_json", side_effect=gh), \
             mock.patch.object(gir, "ingest_pr", side_effect=ingest):
            return gir.run_once(self.cfg, dry_run=dry_run, now=at), attempted

    def test_a_gap_longer_than_the_window_is_caught_up(self):
        h = datetime.timedelta(hours=1)
        gh = FakeGitHub([])
        self.assertEqual(self._run(gh, self.T0), ((0, 0), []))
        # Down for 10 h; the PR merged 9 h before the next run, far outside
        # its 60-minute window.
        gh.rows = [_row(5, "2026-06-03T13:00:00Z")]
        self.assertEqual(self._run(gh, self.T0 + 10 * h), ((1, 0), [5]))

    def test_the_first_run_scans_only_the_window(self):
        gh = FakeGitHub([_row(5, "2026-06-03T09:00:00Z"), _row(6, "2026-06-03T11:30:00Z")])
        self.assertEqual(self._run(gh, self.T0), ((1, 0), [6]))

    def test_a_failed_pr_is_retried_until_it_is_ingested(self):
        h = datetime.timedelta(hours=1)
        gh = FakeGitHub([_row(5, "2026-06-03T11:50:00Z")])
        # Run 1: the ingest raises (e.g. the range could not be computed).
        self.assertEqual(self._run(gh, self.T0, {5: RuntimeError("git rev-list failed")}),
                         ((0, 1), [5]))
        # Run 2, 3 h later: still inside the cursor's overlap; ingest_git exits 1.
        self.assertEqual(self._run(gh, self.T0 + 3 * h, {5: 1}), ((0, 1), [5]))
        # Run 3, 6 h later: the PR is outside the scan (cutoff = run 2 - 60
        # min), so only the retry list brings it back, and it now succeeds.
        self.assertEqual(self._run(gh, self.T0 + 6 * h), ((1, 0), [5]))
        st = gir.load_state(self.cfg.state_dir, "o/r")
        self.assertEqual(st.retry, {})
        # Run 4: ingested, so neither scanned nor retried again.
        self.assertEqual(self._run(gh, self.T0 + 9 * h), ((0, 0), []))

    def test_a_retried_pr_counts_its_attempts_and_keeps_the_run_failing(self):
        h = datetime.timedelta(hours=1)
        gh = FakeGitHub([_row(5, "2026-06-03T11:50:00Z")])
        for i in range(3):
            self.assertEqual(self._run(gh, self.T0 + 5 * i * h, {5: 1}), ((0, 1), [5]))
        self.assertEqual(gir.load_state(self.cfg.state_dir, "o/r").retry[5]["attempts"], 3)

    def test_a_repo_whose_discovery_fails_keeps_its_cursor(self):
        h = datetime.timedelta(hours=1)
        gh = FakeGitHub([])
        self._run(gh, self.T0)
        def down(args, env): raise subprocess.CalledProcessError(1, ["gh"])
        self.assertEqual(self._run(down, self.T0 + 5 * h), ((0, 1), []))
        gh.rows = [_row(5, "2026-06-03T13:00:00Z")]  # merged during the outage
        self.assertEqual(self._run(gh, self.T0 + 10 * h), ((1, 0), [5]))

    def test_a_dry_run_writes_no_state(self):
        gh = FakeGitHub([_row(5, "2026-06-03T11:50:00Z")])
        self.assertEqual(self._run(gh, self.T0, {5: 1}, dry_run=True), ((0, 1), [5]))
        self.assertEqual(list(Path(self.cfg.state_dir).iterdir()), [])

    def test_an_unreadable_state_file_fails_the_repo_instead_of_rescanning(self):
        # Silently starting over would drop the retry list.
        Path(self.cfg.state_dir, "o__r.state.json").write_text("{not json")
        gh = FakeGitHub([_row(5, "2026-06-03T11:50:00Z")])
        self.assertEqual(self._run(gh, self.T0), ((0, 1), []))

class MainLoopTests(unittest.TestCase):
    def test_runs_all_prs_and_isolates_failures(self):
        st = tempfile.TemporaryDirectory(); self.addCleanup(st.cleanup)
        cfg = gir.Config(repos=["o/r"], endpoint="http://x", state_dir=st.name,
                         default_orchestrator_id=None, author_key_file="/k")
        prs = [gir.PullRequest(1,"a","",f"s1","b","u","2026-06-03T11:59:00Z"),
               gir.PullRequest(2,"b","",f"s2","b","u","2026-06-03T11:59:00Z")]
        calls = []
        with mock.patch.object(gir,"ensure_mirror",return_value="/m"), \
             mock.patch.object(gir,"discover_merged_prs",return_value=prs), \
             mock.patch.object(gir,"ingest_pr",side_effect=lambda pr,*a,**k:(calls.append(pr.number) or (1 if pr.number==1 else 0))):
            n_ok, n_fail = gir.run_once(cfg, dry_run=False)
        self.assertEqual(calls, [1,2])          # both attempted (failure isolated)
        self.assertEqual((n_ok,n_fail),(1,1))

ORCH = "7b3a0c1e-0000-4000-8000-000000000001"
SECRET = "tok-very-secret-value"
KEYF = "/s/author.key"

class ChildEnvTests(unittest.TestCase):
    """Backlog 7d9e60c6 (1) and (2): what run_once hands each ingest_git child."""
    def _run(self, cfg, environ, dry_run=False):
        st = tempfile.TemporaryDirectory(); self.addCleanup(st.cleanup)
        cfg = dataclasses.replace(cfg, state_dir=st.name)  # no retry list leaks in
        pr = gir.PullRequest(7, "fix(x): y", "body", "s7", "b", "u", "2026-06-03T11:59:00Z")
        seen = []
        def fake_run(argv, **kw):
            seen.append((argv, kw.get("env")))
            return subprocess.CompletedProcess(argv, 0, "", "")
        with mock.patch.dict(os.environ, environ, clear=True), \
             mock.patch.object(gir, "ensure_mirror", return_value="/m"), \
             mock.patch.object(gir, "discover_merged_prs", return_value=[pr]), \
             mock.patch.object(gir, "compute_rev_range", return_value="s7^1..s7^2"), \
             mock.patch.object(gir.subprocess, "run", side_effect=fake_run), \
             self.assertLogs(gir.LOG, level="DEBUG") as logs:
            result = gir.run_once(cfg, dry_run=dry_run)
        return result, seen, "\n".join(logs.output)

    def test_token_file_reaches_child_env_not_argv_or_log(self):
        with tempfile.TemporaryDirectory() as d:
            tf = Path(d, "token"); tf.write_text(SECRET + "\n")
            cfg = gir.Config(repos=["o/r"], endpoint="http://x", state_dir=d, token_file=str(tf),
                             author_key_file=KEYF)
            (ok, fail), seen, log = self._run(cfg, {"PATH": "/usr/bin", "GH_TOKEN": "ghp_x",
                                                    "EPIGRAPH_GIT_INGEST_GITHUB_PAT": "ghp_y"})
        self.assertEqual((ok, fail), (1, 0))
        (argv, env), = seen
        self.assertEqual(env["EPIGRAPH_TOKEN"], SECRET)
        self.assertNotIn(SECRET, " ".join(argv))
        self.assertNotIn("--token", argv)
        self.assertNotIn(SECRET, log)
        self.assertIn("ingest PR #7", log)  # the argv is still logged
        self.assertNotIn("GH_TOKEN", env)  # GitHub creds stay with gh
        self.assertNotIn("EPIGRAPH_GIT_INGEST_GITHUB_PAT", env)

    def test_inherited_epigraph_token_is_passed_when_no_token_file(self):
        cfg = gir.Config(repos=["o/r"], endpoint="http://x", state_dir="/tmp/st",
                         author_key_file=KEYF)
        _, seen, log = self._run(cfg, {"PATH": "/usr/bin", "EPIGRAPH_TOKEN": SECRET})
        self.assertEqual(seen[0][1]["EPIGRAPH_TOKEN"], SECRET)
        self.assertNotIn(SECRET, log)

    def test_unreadable_token_file_fails_the_run_without_ingesting(self):
        cfg = gir.Config(repos=["o/r"], endpoint="http://x", state_dir="/tmp/st",
                         token_file="/nonexistent/token", author_key_file=KEYF)
        (ok, fail), seen, _ = self._run(cfg, {"PATH": "/usr/bin"})
        self.assertEqual((ok, fail, seen), (0, 1, []))

    def test_dry_run_does_not_read_the_token_file(self):
        # A dry run makes no API call; an unreadable token_file must not fail it.
        cfg = gir.Config(repos=["o/r"], endpoint="http://x", state_dir="/tmp/st",
                         token_file="/nonexistent/token")
        (ok, fail), seen, _ = self._run(cfg, {"PATH": "/usr/bin"}, dry_run=True)
        self.assertEqual((ok, fail), (1, 0))
        (argv, env), = seen
        self.assertIn("--dry-run", argv)
        self.assertNotIn("EPIGRAPH_TOKEN", env)

    def test_live_run_without_an_author_key_file_fails_before_ingesting(self):
        # Without the host secret ingest_git refuses every live PR; the run says
        # so once, up front, instead of failing PR by PR.
        cfg = gir.Config(repos=["o/r"], endpoint="http://x", state_dir="/tmp/st")
        (ok, fail), seen, log = self._run(cfg, {"PATH": "/usr/bin", "EPIGRAPH_TOKEN": SECRET})
        self.assertEqual((ok, fail, seen), (0, 1, []))
        self.assertIn("author key file", log)

    def test_author_key_file_reaches_the_argv_from_config_or_env(self):
        cfg = gir.Config(repos=["o/r"], endpoint="http://x", state_dir="/tmp/st",
                         author_key_file=KEYF)
        _, seen, _ = self._run(cfg, {"PATH": "/usr/bin"})
        argv = seen[0][0]
        self.assertEqual(argv[argv.index("--author-key-file") + 1], KEYF)
        cfg = gir.Config(repos=["o/r"], endpoint="http://x", state_dir="/tmp/st")
        _, seen, _ = self._run(cfg, {"PATH": "/usr/bin", "EPIGRAPH_GIT_AUTHOR_KEY_FILE": "/env/k"})
        argv = seen[0][0]
        self.assertEqual(argv[argv.index("--author-key-file") + 1], "/env/k")

    def test_default_orchestrator_is_an_env_fallback_not_a_flag(self):
        # `--orchestrator-id` beats a PR's Epigraph-Orchestrator-Id trailer in
        # ingest_git; the env fallback does not.
        cfg = gir.Config(repos=["o/r"], endpoint="http://x", state_dir="/tmp/st",
                         default_orchestrator_id=ORCH, author_key_file=KEYF)
        _, seen, _ = self._run(cfg, {"PATH": "/usr/bin"})
        (argv, env), = seen
        self.assertNotIn("--orchestrator-id", argv)
        self.assertNotIn(ORCH, argv)
        self.assertEqual(env["EPIGRAPH_DEFAULT_ORCHESTRATOR_ID"], ORCH)

    def test_config_reads_token_file_key(self):
        cfg = gir.load_config_str('token_file = "/s/tok"\ndefault_orchestrator_id = "%s"\n'
                                  'author_key_file = "/s/key"\n' % ORCH)
        self.assertEqual((cfg.token_file, cfg.default_orchestrator_id, cfg.author_key_file),
                         ("/s/tok", ORCH, "/s/key"))

def _resolve_ingest_git():
    """Locate the built `ingest_git` binary across the tree's possible target
    dirs. The global ~/.cargo/config.toml sets build.target-dir to
    /home/jeremy/.cargo-target, so the binary is OUTSIDE both REPO/.cargo-target
    and an unset $CARGO_TARGET_DIR. `cargo metadata`'s target_directory honors
    both the global config and $CARGO_TARGET_DIR, so it is the one authoritative
    source; the remaining candidates are belt-and-suspenders for CI variants."""
    cands = []
    try:
        md = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--no-deps"],
            cwd=str(REPO), capture_output=True, text=True, check=True,
        )
        cands.append(Path(json.loads(md.stdout)["target_directory"]) / "debug" / "ingest_git")
    except Exception:
        pass
    if os.environ.get("CARGO_TARGET_DIR"):
        cands.append(Path(os.environ["CARGO_TARGET_DIR"]) / "debug" / "ingest_git")
    cands.append(REPO / ".cargo-target" / "debug" / "ingest_git")
    cands.append(REPO / "target" / "debug" / "ingest_git")
    return next((c for c in cands if c.exists()), None)

class IntegrationTest(unittest.TestCase):
    def test_dry_run_against_real_repo_and_binary(self):
        binp = _resolve_ingest_git()
        if binp is None:
            self.skipTest("ingest_git binary not built (run cargo build --bin ingest_git)")
        with tempfile.TemporaryDirectory() as d:
            g = lambda *a: subprocess.run(["git","-C",d,*a],check=True,capture_output=True)
            subprocess.run(["git","init","-qb","main",d],check=True,capture_output=True)
            g("config","user.email","t@t"); g("config","user.name","t")
            Path(d,"a").write_text("1"); g("add","."); g("commit","-qm","base")
            g("checkout","-qb","feat")
            Path(d,"b").write_text("2"); g("add","."); g("commit","-qm","feat(x): add b\n\nEvidence:\n- e")
            g("checkout","-q","main")
            g("merge","--no-ff","-qm","Merge pull request #1 from feat","feat")
            sha = subprocess.run(["git","-C",d,"rev-parse","HEAD"],capture_output=True,text=True).stdout.strip()
            pr = gir.PullRequest(1,"feat(x): add b","Evidence: x",sha,"","t","2026-06-03T12:00:00Z")
            rc = gir.ingest_pr(pr, d, "http://127.0.0.1:8080", "test/repo",
                               ingest_git_bin=str(binp), dry_run=True)
            self.assertEqual(rc, 0, "ingest_git --pr-ingest --dry-run should parse the real repo and exit 0")

if __name__ == "__main__":
    unittest.main()
