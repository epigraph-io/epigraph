# Plan 3 — Server-side git-ingest reconciler — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A standalone VPC cron driver, `scripts/git_ingest_reconciler.py`, that discovers newly-merged PRs across configured repos (read-only GitHub access), and for each runs `ingest_git --pr-ingest` against the localhost EpiGraph API — continuous, cross-repo, idempotent commit ingestion with no external CI and no write-token spray.

**Architecture:** Stdlib-only Python (no third-party deps). GitHub discovery + auth via the `gh` CLI (auth chain = `EPIGRAPH_GIT_INGEST_GITHUB_PAT` → `GH_TOKEN` injection, else `gh`'s own stored auth). Per repo: maintain a local mirror clone (`git fetch`), discover merged PRs in an overlapping time window, compute each PR's own commit range from its merge commit, and invoke the `ingest_git` binary (built on the VPC from this tree). Stateless (idempotency-tolerant per Plan 2.5). Spec: `docs/superpowers/specs/2026-06-03-plan-3-git-ingest-reconciler-design.md`.

**Tech stack:** Python 3.12 stdlib (`argparse, os, subprocess, json, datetime, pathlib, tempfile, fcntl, logging, re`), the `gh` CLI, `git`, the `ingest_git` Rust binary. Tests: stdlib `unittest` (matches `scripts/tests/test_structured_source_parsers.py`).

**Conventions (every task):** Work in `/home/jeremy/epigraph-wt-gir` (absolute paths, `cd` first). Foreground commands only. Gate before each commit: `python3 -m py_compile scripts/git_ingest_reconciler.py` and `python3 -m unittest -v scripts.tests.test_git_ingest_reconciler` (run from repo root; ruff/black are not installed, do not invoke them). Do not push. Full Evidence/Reasoning/Verification commit messages per CLAUDE.md.

**Grounding (verified on this tree, `origin/dev` `bcaf3a1`):**
- `ingest_git` arg parser (`crates/epigraph-cli/src/bin/ingest_git.rs`) accepts: `--pr-ingest`, `--repo-slug`, `--pr-number`, `--pr-title`, `--pr-body`, `--merge-sha`, `--merged-at`, `--pr-author`, `--rev-range`, `--orchestrator-id`, plus `--repo/-r`, `--endpoint/-e`, `--dry-run/-n`.
- Precedent script `scripts/reconcile_backlog_labels.py`: `argparse`, env-var tokens, idempotent, "safe to run repeatedly".
- Test convention: `scripts/tests/test_*.py`, stdlib `unittest`, `REPO = Path(__file__).resolve().parents[2]`, `sys.path.insert(0, str(REPO / "scripts"))` to import the module under test. Run via `python3 -m unittest`.
- `gh` 2.93 present; honors `GH_TOKEN`/`GITHUB_TOKEN` env (PAT injection) else its own `gh auth` token.

---

## File structure
- **Create** `scripts/git_ingest_reconciler.py` — the driver (all functions below).
- **Create** `scripts/tests/test_git_ingest_reconciler.py` — unit + one integration test.
- **Create** `scripts/git_ingest_reconciler.config.example.toml` — config template.
- **Modify** `docs/` or add `scripts/README` note — install/cron instructions (Task 8).

The driver is one focused module (~250 lines) with small pure functions (config, auth, range, discovery, argv build) plus thin IO wrappers (mirror, subprocess, main loop), so most logic is unit-testable without network or a live API.

---

## Task 1: Module skeleton, config, and GitHub auth chain

**Files:** Create `scripts/git_ingest_reconciler.py`; create `scripts/tests/test_git_ingest_reconciler.py`.

- [ ] **Step 1: Failing test**
```python
import os, sys, unittest
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

if __name__ == "__main__":
    unittest.main()
```
- [ ] **Step 2: Run → fails** (module missing). `cd /home/jeremy/epigraph-wt-gir && python3 -m unittest -v scripts.tests.test_git_ingest_reconciler`.
- [ ] **Step 3: Implement** the skeleton + `gh_env` + `load_config_str`/`load_config`:
```python
#!/usr/bin/env python3
"""Server-side git-ingest reconciler (Plan 3).

Discovers newly-merged PRs across configured repos (read-only GitHub access via
the `gh` CLI) and runs `ingest_git --pr-ingest` against the localhost EpiGraph
API for each. Idempotent (Plan 2.5), stateless, safe to run repeatedly on a cron.

Auth: EPIGRAPH_GIT_INGEST_GITHUB_PAT (read-only) injected as GH_TOKEN, else the
host's existing `gh auth` token. Writes go to the localhost API, not GitHub —
no GitHub write scope is ever used.
"""
import argparse, datetime, json, logging, os, subprocess, sys, tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

LOG = logging.getLogger("git_ingest_reconciler")
DEFAULT_ENDPOINT = "http://127.0.0.1:8080"
DEFAULT_WINDOW_MINUTES = 60
DEFAULT_STATE_DIR = "/var/lib/epiclaw/git-ingest"

def gh_env(environ: dict | None = None) -> dict:
    """Build the env for `gh` subprocesses. If a read-only PAT is configured,
    inject it as GH_TOKEN; otherwise return a copy without GH_TOKEN so `gh`
    uses its own stored auth (the CLI-bearer fallback)."""
    environ = dict(os.environ if environ is None else environ)
    pat = environ.get("EPIGRAPH_GIT_INGEST_GITHUB_PAT")
    env = dict(environ)
    env.pop("GH_TOKEN", None)
    env.pop("GITHUB_TOKEN", None)
    if pat:
        env["GH_TOKEN"] = pat
    return env

@dataclass
class Config:
    repos: list[str] = field(default_factory=list)
    endpoint: str = DEFAULT_ENDPOINT
    window_minutes: int = DEFAULT_WINDOW_MINUTES
    state_dir: str = DEFAULT_STATE_DIR
    default_orchestrator_id: str | None = None
    ingest_git_bin: str = "ingest_git"

def load_config_str(text: str) -> Config:
    data = tomllib.loads(text)
    return Config(
        repos=list(data.get("repos", [])),
        endpoint=data.get("endpoint", DEFAULT_ENDPOINT),
        window_minutes=int(data.get("window_minutes", DEFAULT_WINDOW_MINUTES)),
        state_dir=data.get("state_dir", DEFAULT_STATE_DIR),
        default_orchestrator_id=data.get("default_orchestrator_id"),
        ingest_git_bin=data.get("ingest_git_bin", "ingest_git"),
    )

def load_config(path: str) -> Config:
    return load_config_str(Path(path).read_text())
```
- [ ] **Step 4: Run → passes.**
- [ ] **Step 5: Commit** (`feat(scripts): git-ingest reconciler skeleton — config + gh auth chain`).

---

## Task 2: Commit-range computation

**Files:** Modify `scripts/git_ingest_reconciler.py` + test file.

- [ ] **Step 1: Failing test** (builds a real temp git repo):
```python
import subprocess, tempfile, unittest
class RangeTests(unittest.TestCase):
    def _git(self, d, *a): subprocess.run(["git","-C",d,*a], check=True, capture_output=True)
    def test_merge_commit_two_parents(self):
        with tempfile.TemporaryDirectory() as d:
            self._git(d,"init","-q"); self._git(d,"config","user.email","t@t"); self._git(d,"config","user.name","t")
            Path(d,"a").write_text("1"); self._git(d,"add","."); self._git(d,"commit","-qm","base")
            self._git(d,"checkout","-qb","feat")
            Path(d,"b").write_text("2"); self._git(d,"add","."); self._git(d,"commit","-qm","feat(x): add b")
            self._git(d,"checkout","-q","master") if _has_master(d) else self._git(d,"checkout","-q","main")
            self._git(d,"merge","--no-ff","-qm","Merge pull request #1","feat")
            sha = subprocess.run(["git","-C",d,"rev-parse","HEAD"],capture_output=True,text=True).stdout.strip()
            rng = gir.compute_rev_range(d, sha)
            self.assertEqual(rng, f"{sha}^1..{sha}^2")
    def test_single_parent_squash(self):
        with tempfile.TemporaryDirectory() as d:
            self._git(d,"init","-q"); self._git(d,"config","user.email","t@t"); self._git(d,"config","user.name","t")
            Path(d,"a").write_text("1"); self._git(d,"add","."); self._git(d,"commit","-qm","base")
            Path(d,"a").write_text("2"); self._git(d,"add","."); self._git(d,"commit","-qm","squash")
            sha = subprocess.run(["git","-C",d,"rev-parse","HEAD"],capture_output=True,text=True).stdout.strip()
            self.assertEqual(gir.compute_rev_range(d, sha), f"{sha}~1..{sha}")
```
> Add a tiny `_has_master(d)` helper in the test (check `git branch`), or just create the repo with `git init -b main`. Prefer `git init -b main` to avoid the default-branch ambiguity — rewrite both tests to `self._git(d,"init","-qb","main")` and drop the checkout-to-master line.
- [ ] **Step 2: Run → fails** (`compute_rev_range` missing).
- [ ] **Step 3: Implement**:
```python
def compute_rev_range(mirror: str, merge_sha: str) -> str:
    """The PR's own commits. For a --merge commit (2 parents): base..head =
    `M^1..M^2`. For a squash (1 parent): the single commit `M~1..M`. Rebase
    merges (the PR's commits as a linear run with one parent each) are not
    distinguishable from a single squash here; logged by the caller and handled
    as the squash case for the tip commit."""
    out = subprocess.run(
        ["git", "-C", mirror, "rev-list", "--parents", "-n", "1", merge_sha],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    n_parents = len(out) - 1  # first token is the commit itself
    if n_parents >= 2:
        return f"{merge_sha}^1..{merge_sha}^2"
    return f"{merge_sha}~1..{merge_sha}"
```
- [ ] **Step 4: Run → passes.**
- [ ] **Step 5: Commit** (`feat(scripts): compute PR commit range from merge commit parents`).

---

## Task 3: Merged-PR discovery via `gh api`

**Files:** Modify driver + test.

- [ ] **Step 1: Failing test** (mock `subprocess.run` to return a fixture):
```python
from unittest import mock
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
```
- [ ] **Step 2: Run → fails.**
- [ ] **Step 3: Implement** `PullRequest` + `_gh_json` + `discover_merged_prs`:
```python
@dataclass
class PullRequest:
    number: int; title: str; body: str; merge_sha: str
    base_sha: str; author: str; merged_at: str

def _gh_json(args: list[str], env: dict) -> list | dict:
    """Run `gh api ...` and parse JSON stdout."""
    res = subprocess.run(["gh", "api", *args], check=True, capture_output=True, text=True, env=env)
    return json.loads(res.stdout)

def discover_merged_prs(slug: str, env: dict, window_minutes: int, now: datetime.datetime) -> list[PullRequest]:
    cutoff = now - datetime.timedelta(minutes=window_minutes)
    rows = _gh_json(
        [f"repos/{slug}/pulls", "-X", "GET",
         "--field", "state=closed", "--field", "sort=updated",
         "--field", "direction=desc", "--field", "per_page=50", "--paginate"],
        env,
    )
    out = []
    for r in rows:
        ma = r.get("merged_at")
        if not ma or not r.get("merge_commit_sha"):
            continue
        when = datetime.datetime.fromisoformat(ma.replace("Z", "+00:00"))
        if when < cutoff:
            continue
        out.append(PullRequest(
            number=int(r["number"]), title=r.get("title") or "",
            body=r.get("body") or "", merge_sha=r["merge_commit_sha"],
            base_sha=(r.get("base") or {}).get("sha") or "",
            author=(r.get("user") or {}).get("login") or "", merged_at=ma,
        ))
    return out
```
> `--paginate` with `--field direction=desc` over `state=closed` can be large; `per_page=50` + the window filter keeps it bounded for the pilot. If a repo's volume makes this heavy, the spec's optional cursor (deferred) is the mitigation. Note it in the commit body.
- [ ] **Step 4: Run → passes.**
- [ ] **Step 5: Commit** (`feat(scripts): discover merged PRs in a time window via gh api`).

---

## Task 4: Mirror clone management

**Files:** Modify driver + test.

- [ ] **Step 1: Failing test** (use a local repo as the "remote"):
```python
class MirrorTests(unittest.TestCase):
    def test_clone_then_fetch(self):
        with tempfile.TemporaryDirectory() as remote, tempfile.TemporaryDirectory() as state:
            subprocess.run(["git","init","-qb","main",remote],check=True,capture_output=True)
            for cmd in (["config","user.email","t@t"],["config","user.name","t")):
                subprocess.run(["git","-C",remote,*cmd],check=True,capture_output=True)
            Path(remote,"a").write_text("1")
            subprocess.run(["git","-C",remote,"add","."],check=True,capture_output=True)
            subprocess.run(["git","-C",remote,"commit","-qm","c1"],check=True,capture_output=True)
            mirror = gir.ensure_mirror(remote, state, {})         # first call clones
            self.assertTrue(Path(mirror, ".git").exists() or Path(mirror, "HEAD").exists())
            mirror2 = gir.ensure_mirror(remote, state, {})        # second call fetches
            self.assertEqual(mirror, mirror2)
```
> The "slug" here is a local path used as the clone URL; in production it is `https://github.com/<slug>.git`. Have `ensure_mirror` accept a `clone_url` and a `key` (the slug, sanitized for the dir name); the test passes the remote path as both.
- [ ] **Step 2: Run → fails.**
- [ ] **Step 3: Implement**:
```python
def _mirror_dir(state_dir: str, slug_key: str) -> Path:
    return Path(state_dir) / slug_key.replace("/", "__")

def ensure_mirror(clone_url: str, state_dir: str, env: dict, slug_key: str | None = None) -> str:
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    d = _mirror_dir(state_dir, slug_key or clone_url)
    if (d / "HEAD").exists() or (d / ".git").exists():
        subprocess.run(["git", "-C", str(d), "fetch", "--prune", "origin"],
                       check=True, capture_output=True, env=env)
    else:
        subprocess.run(["git", "clone", "--quiet", clone_url, str(d)],
                       check=True, capture_output=True, env=env)
    return str(d)
```
> Production `clone_url` = `https://github.com/<slug>.git`; `gh`'s credential helper / a PAT in `GH_TOKEN` covers private-repo fetch. For the pilot (public `epigraph`) no creds are needed.
- [ ] **Step 4: Run → passes.**
- [ ] **Step 5: Commit** (`feat(scripts): maintain per-repo mirror clones (clone-or-fetch)`).

---

## Task 5: Build the ingester invocation

**Files:** Modify driver + test.

- [ ] **Step 1: Failing test** (assert the exact argv; no subprocess):
```python
class ArgvTests(unittest.TestCase):
    def test_build_ingest_argv(self):
        pr = gir.PullRequest(number=252, title="fix(api): x", body="Resolves d531c585",
                             merge_sha="2a31f8d", base_sha="b72e271", author="tylorsama",
                             merged_at="2026-06-02T15:10:01Z")
        argv = gir.build_ingest_argv(pr, mirror="/m", endpoint="http://127.0.0.1:8080",
                                     rev_range="2a31f8d^1..2a31f8d^2",
                                     default_orchestrator_id="7b3a0c1e-0000-4000-8000-000000000001",
                                     ingest_git_bin="ingest_git", dry_run=True)
        self.assertEqual(argv[0], "ingest_git")
        self.assertIn("--pr-ingest", argv)
        self.assertEqual(argv[argv.index("--repo-slug")+1], "epigraph-io/epigraph") if False else None
        # spot-check key flag/value pairs:
        def val(flag): return argv[argv.index(flag)+1]
        self.assertEqual(val("--pr-number"), "252")
        self.assertEqual(val("--merge-sha"), "2a31f8d")
        self.assertEqual(val("--rev-range"), "2a31f8d^1..2a31f8d^2")
        self.assertEqual(val("--merged-at"), "2026-06-02T15:10:01Z")
        self.assertEqual(val("--orchestrator-id"), "7b3a0c1e-0000-4000-8000-000000000001")
        self.assertEqual(val("--repo"), "/m")
        self.assertEqual(val("--endpoint"), "http://127.0.0.1:8080")
        self.assertIn("--dry-run", argv)
```
> Drop the dead `if False` line when implementing the test; it's a leftover — pass `slug` into `build_ingest_argv` and assert `val("--repo-slug")`.
- [ ] **Step 2: Run → fails.**
- [ ] **Step 3: Implement** (`build_ingest_argv` takes `slug` too):
```python
def build_ingest_argv(pr, mirror, endpoint, rev_range, slug, *,
                      default_orchestrator_id=None, ingest_git_bin="ingest_git", dry_run=False):
    argv = [ingest_git_bin, "--pr-ingest",
            "--repo-slug", slug, "--pr-number", str(pr.number),
            "--pr-title", pr.title, "--pr-body", pr.body,
            "--merge-sha", pr.merge_sha, "--merged-at", pr.merged_at,
            "--pr-author", pr.author, "--rev-range", rev_range,
            "--repo", mirror, "--endpoint", endpoint]
    if default_orchestrator_id:
        argv += ["--orchestrator-id", default_orchestrator_id]
    if dry_run:
        argv += ["--dry-run"]
    return argv

def ingest_pr(pr, mirror, endpoint, slug, *, default_orchestrator_id=None,
              ingest_git_bin="ingest_git", dry_run=False) -> int:
    rng = compute_rev_range(mirror, pr.merge_sha)
    argv = build_ingest_argv(pr, mirror, endpoint, rng, slug,
                             default_orchestrator_id=default_orchestrator_id,
                             ingest_git_bin=ingest_git_bin, dry_run=dry_run)
    LOG.info("ingest PR #%s (%s): %s", pr.number, slug, " ".join(argv))
    res = subprocess.run(argv, capture_output=True, text=True)
    if res.returncode != 0:
        LOG.error("ingest PR #%s failed (%s): %s", pr.number, res.returncode, res.stderr.strip()[:500])
    return res.returncode
```
> The test calls `build_ingest_argv` with `slug` — update the test signature accordingly. Note the `--orchestrator-id` is only passed when configured; otherwise the ingester resolves the trailer / `EPIGRAPH_DEFAULT_ORCHESTRATOR_ID` itself.
- [ ] **Step 4: Run → passes.**
- [ ] **Step 5: Commit** (`feat(scripts): build + run the ingest_git --pr-ingest invocation`).

---

## Task 6: Main loop, lock, CLI

**Files:** Modify driver + test.

- [ ] **Step 1: Failing test** (mock the IO functions; assert iteration + failure isolation):
```python
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
```
- [ ] **Step 2: Run → fails.**
- [ ] **Step 3: Implement** `run_once` + `main` (+ `fcntl` lock):
```python
def run_once(cfg: Config, *, dry_run: bool, now: datetime.datetime | None = None) -> tuple[int, int]:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    env = gh_env()
    ok = fail = 0
    for slug in cfg.repos:
        try:
            mirror = ensure_mirror(f"https://github.com/{slug}.git", cfg.state_dir, env, slug_key=slug)
            prs = discover_merged_prs(slug, env, cfg.window_minutes, now)
        except Exception as e:  # repo-level failure: log + continue
            LOG.error("repo %s discovery failed: %s", slug, e); fail += 1; continue
        for pr in prs:
            try:
                rc = ingest_pr(pr, mirror, cfg.endpoint, slug,
                               default_orchestrator_id=cfg.default_orchestrator_id,
                               ingest_git_bin=cfg.ingest_git_bin, dry_run=dry_run)
                ok += (rc == 0); fail += (rc != 0)
            except Exception as e:
                LOG.error("PR #%s (%s) ingest raised: %s", pr.number, slug, e); fail += 1
    return ok, fail

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Server-side git-ingest reconciler (Plan 3)")
    ap.add_argument("--config", default=os.environ.get("GIT_INGEST_CONFIG",
                    str(Path(DEFAULT_STATE_DIR) / "config.toml")))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--log-level", default="INFO")
    args = ap.parse_args(argv)
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    lock_path = Path(cfg.state_dir) / ".lock"; lock_path.parent.mkdir(parents=True, exist_ok=True)
    import fcntl
    with open(lock_path, "w") as lf:
        try:
            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            LOG.warning("another run holds the lock; exiting"); return 0
        ok, fail = run_once(cfg, dry_run=args.dry_run)
        LOG.info("done: %s ingested, %s failed", ok, fail)
        return 1 if fail else 0

if __name__ == "__main__":
    sys.exit(main())
```
- [ ] **Step 4: Run → passes.**
- [ ] **Step 5: Commit** (`feat(scripts): reconciler main loop with flock + per-PR failure isolation`).

---

## Task 7: Integration test — real git + real ingest_git (dry-run)

**Files:** Modify test file.

- [ ] **Step 1: Build the binary once** (needed by the test): `cd /home/jeremy/epigraph-wt-gir && cargo build --bin ingest_git`. (Foreground; this is a one-time cost.)
- [ ] **Step 2: Write the integration test** — real temp repo with a merge-commit shape + the real binary in dry-run, bypassing `gh` discovery by constructing the `PullRequest` directly:
```python
import shutil
class IntegrationTest(unittest.TestCase):
    def test_dry_run_against_real_repo_and_binary(self):
        binp = REPO / ".cargo-target/debug/ingest_git"
        binp = binp if binp.exists() else Path(os.environ.get("CARGO_TARGET_DIR","")) / "debug/ingest_git"
        if not binp.exists():
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
```
> This validates the driver↔ingest_git boundary against real `git` + the real binary, with no network and no DB. The full HTTP find-or-create / idempotency path is already proven by Plan 2.5's Rust integration tests (`idempotency_2p5_tests`) and is exercised manually via the live dry-run in §7 of the spec. State that scoping in the commit body.
- [ ] **Step 3: Run → passes** (or skips cleanly if the binary is somehow absent — but Step 1 built it). `python3 -m unittest -v scripts.tests.test_git_ingest_reconciler`.
- [ ] **Step 4: Commit** (`test(scripts): integration test of reconciler against real git + ingest_git dry-run`).

---

## Task 8: Config template + install/cron note

**Files:** Create `scripts/git_ingest_reconciler.config.example.toml`; add an install note (a `## git-ingest reconciler` section in `scripts/README.md` if it exists, else create `scripts/git_ingest_reconciler.README.md`).

- [ ] **Step 1: Write the config template**
```toml
# scripts/git_ingest_reconciler.config.example.toml — copy to the state dir as config.toml
repos = ["epigraph-io/epigraph"]   # pilot: epigraph only; add slugs to expand
endpoint = "http://127.0.0.1:8080"
window_minutes = 240               # generous overlap; idempotency (Plan 2.5) tolerates re-scan
state_dir = "/var/lib/epiclaw/git-ingest"
ingest_git_bin = "/home/jeremy/.cargo-target/debug/ingest_git"  # or the deployed release path
# default_orchestrator_id = "<uuid of a registered agent>"  # used when a PR lacks the trailer
```
- [ ] **Step 2: Write the install note** — covering: copy config to `state_dir/config.toml`; set `EPIGRAPH_GIT_INGEST_GITHUB_PAT` (read-only) or rely on `gh auth`; the cron line:
```
*/15 * * * *  EPIGRAPH_GIT_INGEST_GITHUB_PAT=... /usr/bin/python3 /home/jeremy/epigraph/scripts/git_ingest_reconciler.py --config /var/lib/epiclaw/git-ingest/config.toml >> /var/log/git-ingest.log 2>&1
```
  and the **hard rule**: do NOT enable the cron until Plan 2.5 is in prod (`dev → main` + redeploy); until then run only with `--dry-run`.
- [ ] **Step 3: Verify** the template parses: `cd /home/jeremy/epigraph-wt-gir && python3 -c "import sys; sys.path.insert(0,'scripts'); import git_ingest_reconciler as g; print(g.load_config('scripts/git_ingest_reconciler.config.example.toml').repos)"` → prints `['epigraph-io/epigraph']`.
- [ ] **Step 4: Commit** (`docs(scripts): config template + cron install note for the git-ingest reconciler`).

---

## Self-review
- **Spec coverage:** auth chain §3.2 → Task 1; range §3.6 → Task 2; discovery §3.5 → Task 3; mirrors §3.4 → Task 4; ingester invocation §3.7 + dry-run §3.8 → Task 5; main loop/lock/error-isolation §3.1/§6 → Task 6; testing §9 → Tasks 1-7; cron wiring §3.9 + config §3.3 + rollout §7 (don't-enable-until-2.5) → Task 8. Stateless/no-cursor §5 → honored (no cursor code). Security §8 → no write token; dry-run default-safe.
- **Placeholder scan:** the `>` notes are real adapt points (use `git init -b main` in tests; pass `slug` to `build_ingest_argv`; drop the `if False` leftover) each with the fix inline — no blank TODOs.
- **Type consistency:** `Config`, `PullRequest`, `gh_env`, `load_config(_str)`, `compute_rev_range`, `discover_merged_prs`, `ensure_mirror`, `build_ingest_argv`, `ingest_pr`, `run_once`, `main` names are used identically across tasks. `build_ingest_argv` takes `slug` (Task 5 fixes the Step-1 test signature to match). `ingest_pr` computes the range internally (Task 5) so `run_once` (Task 6) does not pass `rev_range`.
- **Gate:** `python3 -m py_compile` + `python3 -m unittest` (ruff/black absent). Task 7 builds `ingest_git` once.
