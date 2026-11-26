#!/usr/bin/env python3
"""Server-side git-ingest reconciler (Plan 3).

Discovers newly-merged PRs across configured repos (read-only GitHub access via
the `gh` CLI) and runs `ingest_git --pr-ingest` against the localhost EpiGraph
API for each. Idempotent (Plan 2.5), safe to run repeatedly on a cron.

State: per repo, a cursor (the start of the last complete run) and a retry
list of PRs whose ingest failed (`RepoState`, a JSON file in `state_dir`). A
run scans the PRs merged since `cursor - window_minutes` and re-tries the
retry list, so neither an outage longer than the window nor a failed ingest
loses a PR. A dry run reads the state and writes none.

Auth: EPIGRAPH_GIT_INGEST_GITHUB_PAT (read-only) injected as GH_TOKEN, else the
host's existing `gh auth` token. Writes go to the localhost API, not GitHub —
no GitHub write scope is ever used.

API auth: `ingest_git` gets its Bearer token as EPIGRAPH_TOKEN in its
environment, never on its command line or in the log. The token is read from the
config's `token_file` on each run, else inherited from the reconciler's own
EPIGRAPH_TOKEN. The config's `default_orchestrator_id` is handed over the same way,
as EPIGRAPH_DEFAULT_ORCHESTRATOR_ID, so a PR's Epigraph-Orchestrator-Id trailer
still wins over it.

Author keys: a live run needs the host secret that keys every author and
repo-root agent key (`ingest_git --author-key-file`). It comes from the config's
`author_key_file`, else the reconciler's own EPIGRAPH_GIT_AUTHOR_KEY_FILE. A live
run without one fails before any PR is ingested; a dry run needs neither it nor
the token.
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
    token_file: str | None = None
    author_key_file: str | None = None

def load_config_str(text: str) -> Config:
    data = tomllib.loads(text)
    return Config(
        repos=list(data.get("repos", [])),
        endpoint=data.get("endpoint", DEFAULT_ENDPOINT),
        window_minutes=int(data.get("window_minutes", DEFAULT_WINDOW_MINUTES)),
        state_dir=data.get("state_dir", DEFAULT_STATE_DIR),
        default_orchestrator_id=data.get("default_orchestrator_id"),
        ingest_git_bin=data.get("ingest_git_bin", "ingest_git"),
        token_file=data.get("token_file"),
        author_key_file=data.get("author_key_file"),
    )

def load_config(path: str) -> Config:
    return load_config_str(Path(path).read_text())

# GitHub credentials are for `gh` only; `ingest_git` talks to the EpiGraph API.
_GITHUB_CRED_VARS = ("EPIGRAPH_GIT_INGEST_GITHUB_PAT", "GH_TOKEN", "GITHUB_TOKEN")

def read_token(cfg: "Config", environ: dict | None = None) -> str | None:
    """The API Bearer token for `ingest_git`: the content of `token_file` when
    configured (re-read every run, so whatever refreshes the file is picked up),
    else the reconciler's own EPIGRAPH_TOKEN. Raises OSError when `token_file`
    is configured but unreadable. Never logs the value."""
    environ = os.environ if environ is None else environ
    if cfg.token_file:
        tok = Path(cfg.token_file).read_text().strip()
    else:
        tok = (environ.get("EPIGRAPH_TOKEN") or "").strip()
    return tok or None

def resolve_author_key_file(cfg: "Config", environ: dict | None = None) -> str | None:
    """The path of the host secret that keys the author agents: the config's
    `author_key_file`, else the reconciler's own EPIGRAPH_GIT_AUTHOR_KEY_FILE.
    The path is not secret (the file is), so it goes on the argv."""
    environ = os.environ if environ is None else environ
    return cfg.author_key_file or (environ.get("EPIGRAPH_GIT_AUTHOR_KEY_FILE") or "").strip() or None

def ingest_env(token: str | None, default_orchestrator_id: str | None,
               environ: dict | None = None) -> dict:
    """The environment for an `ingest_git` child: the reconciler's own, minus
    GitHub credentials, plus EPIGRAPH_TOKEN (the API token, kept off argv) and
    EPIGRAPH_DEFAULT_ORCHESTRATOR_ID (a fallback `ingest_git` uses only when
    neither `--orchestrator-id` nor an Epigraph-Orchestrator-Id trailer names
    one). Passing the default as `--orchestrator-id` would override the trailer."""
    env = dict(os.environ if environ is None else environ)
    for k in _GITHUB_CRED_VARS:
        env.pop(k, None)
    if token:
        env["EPIGRAPH_TOKEN"] = token
    else:
        env.pop("EPIGRAPH_TOKEN", None)
    if default_orchestrator_id:
        env["EPIGRAPH_DEFAULT_ORCHESTRATOR_ID"] = default_orchestrator_id
    return env

# The PR commits API lists at most this many commits; an answer this long may
# be truncated, so it cannot prove which commits a rebase merge put on main.
PR_COMMITS_API_CAP = 250

def _parse_ts(s: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))

def _commit_identity(email: str, date: str, message: str) -> tuple:
    """What GitHub's rebase merge keeps of a commit (it changes the sha and the
    committer): the author email, the author date as an instant, and the
    message's first line."""
    first = (message or "").strip().split("\n", 1)[0].strip()
    return ((email or "").strip().lower(), _parse_ts(date), first)

def _first_parent_identities(mirror: str, sha: str, n: int) -> list[tuple]:
    """The identities of `sha` and its first-parent ancestors, `n` at most,
    oldest first."""
    out = subprocess.run(
        ["git", "-C", mirror, "log", "--first-parent", "-n", str(n),
         "--format=%x1e%ae%x00%aI%x00%B", sha],
        check=True, capture_output=True, text=True,
    ).stdout
    ids = [_commit_identity(*rec.split("\0", 2)) for rec in out.split("\x1e") if rec.strip()]
    return list(reversed(ids))

def compute_rev_range(mirror: str, merge_sha: str, pr_commits=None) -> str:
    """The PR's own commits on the mirror.

    - A --merge commit (2 parents): base..head, `M^1..M^2`.
    - One parent, a squash or a rebase merge. A rebase merge puts the PR's n
      commits on main as a linear run ending at M; a squash puts one commit.
      `pr_commits` is the PR commits API's answer (oldest first), or a
      zero-argument callable returning it, read only on this path. When the n
      first-parent commits ending at M carry the API commits' author, author
      date and first message line, in order, the PR was rebase-merged and the
      range is `M~n..M`; otherwise it is the single commit `M~1..M`.

    Matching on identity, not on the count alone, keeps a squash of an
    n-commit PR from claiming the n-1 commits of other PRs below it."""
    out = subprocess.run(
        ["git", "-C", mirror, "rev-list", "--parents", "-n", "1", merge_sha],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    n_parents = len(out) - 1  # first token is the commit itself
    if n_parents >= 2:
        return f"{merge_sha}^1..{merge_sha}^2"
    single = f"{merge_sha}~1..{merge_sha}"
    rows = pr_commits() if callable(pr_commits) else pr_commits
    n = len(rows or [])
    if n <= 1:
        return single
    if n >= PR_COMMITS_API_CAP:
        LOG.warning("%s: the PR lists %s+ commits, past what the commits API returns; "
                    "ingesting only the tip commit", merge_sha, n)
        return single
    want = [_commit_identity(((r.get("commit") or {}).get("author") or {}).get("email", ""),
                             ((r.get("commit") or {}).get("author") or {}).get("date", ""),
                             (r.get("commit") or {}).get("message", ""))
            for r in rows]
    if _first_parent_identities(mirror, merge_sha, n) == want:
        return f"{merge_sha}~{n}..{merge_sha}"
    LOG.info("%s: one parent and the PR's %s commits are not on main as a run; "
             "treating it as a squash merge", merge_sha, n)
    return single

def fetch_pr_commits(slug: str, number: int, env: dict) -> list[dict]:
    """The PR's commits as the PR commits API lists them, oldest first."""
    return _gh_json([f"repos/{slug}/pulls/{number}/commits", "-X", "GET",
                     "--field", "per_page=100", "--paginate", "--slurp"], env)

@dataclass
class PullRequest:
    number: int; title: str; body: str; merge_sha: str
    base_sha: str; author: str; merged_at: str

def _gh_json(args: list[str], env: dict) -> list | dict:
    """Run `gh api ...` and parse JSON stdout.

    With `--paginate` alone, `gh` emits one separate JSON array/object PER page
    (concatenated, e.g. `[...]\n[...]`), which a single `json.loads` cannot
    parse (raises `Extra data`). `--slurp` (gh >= 2.83) wraps all pages in one
    outer JSON array, so the whole stdout is a single valid document. When
    `--slurp` is in args we therefore flatten the outer page array back into
    the flat list of rows the callers expect; otherwise we return the parsed
    document as-is."""
    res = subprocess.run(["gh", "api", *args], check=True, capture_output=True, text=True, env=env)
    data = json.loads(res.stdout)
    if "--slurp" in args:
        return [row for page in data for row in (page if isinstance(page, list) else [page])]
    return data

def _pr_from_row(r: dict) -> "PullRequest | None":
    """A merged PR from a pulls API row; None when the row is not merged."""
    ma = r.get("merged_at")
    if not ma or not r.get("merge_commit_sha"):
        return None
    return PullRequest(
        number=int(r["number"]), title=r.get("title") or "",
        body=r.get("body") or "", merge_sha=r["merge_commit_sha"],
        base_sha=(r.get("base") or {}).get("sha") or "",
        author=(r.get("user") or {}).get("login") or "", merged_at=ma,
    )

def discover_merged_prs(slug: str, env: dict, cutoff: datetime.datetime) -> list[PullRequest]:
    """The repo's PRs merged at or after `cutoff`."""
    rows = _gh_json(
        [f"repos/{slug}/pulls", "-X", "GET",
         "--field", "state=closed", "--field", "sort=updated",
         "--field", "direction=desc", "--field", "per_page=50",
         "--paginate", "--slurp"],
        env,
    )
    out = []
    for r in rows:
        pr = _pr_from_row(r)
        if pr is not None and _parse_ts(pr.merged_at) >= cutoff:
            out.append(pr)
    return out

def fetch_pr(slug: str, number: int, env: dict) -> "PullRequest | None":
    """One PR by number (for the retry list); None when it is not merged."""
    return _pr_from_row(_gh_json([f"repos/{slug}/pulls/{number}"], env))

# -----------------------------------------------------------------------------
# Per-repo state: the cursor and the retry list
# -----------------------------------------------------------------------------

@dataclass
class RepoState:
    """What the reconciler keeps per repo between runs, in
    `<state_dir>/<owner>__<repo>.state.json`.

    `cursor`: the start time of the last run whose discovery succeeded and
    whose every merged PR was either ingested or put on the retry list. The
    next run scans PRs merged since `cursor - window_minutes`, so the window is
    an overlap, not a horizon: a reconciler that was down for a day catches up.

    `retry`: PR number -> {"attempts", "last_failed_at"} for each PR whose
    ingest failed. Each run fetches them by number, wherever they fall
    relative to the scan, until they are ingested."""
    cursor: str | None = None
    retry: dict[int, dict] = field(default_factory=dict)

def _state_path(state_dir: str, slug: str) -> Path:
    d = _mirror_dir(state_dir, slug)
    return d.with_name(d.name + ".state.json")

def load_state(state_dir: str, slug: str) -> RepoState:
    """The repo's state; empty when it has none yet. An unreadable or malformed
    file raises: starting over would drop the retry list without a word."""
    p = _state_path(state_dir, slug)
    if not p.exists():
        return RepoState()
    data = json.loads(p.read_text())
    return RepoState(cursor=data.get("cursor"),
                     retry={int(k): dict(v) for k, v in (data.get("retry") or {}).items()})

def save_state(state_dir: str, slug: str, st: RepoState) -> None:
    """Write the repo's state atomically (temp file, then rename)."""
    p = _state_path(state_dir, slug)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps({"cursor": st.cursor,
                       "retry": {str(k): v for k, v in sorted(st.retry.items())}},
                      indent=2, sort_keys=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=p.name + ".")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(body + "\n")
        os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise

def compute_cutoff(cursor: str | None, now: datetime.datetime, window_minutes: int) -> datetime.datetime:
    """The earliest merge time a run scans: `window_minutes` before the cursor
    (before `now` on a first run, or if the cursor is in the future)."""
    since = now if cursor is None else min(_parse_ts(cursor), now)
    return since - datetime.timedelta(minutes=window_minutes)

def _record_failure(st: RepoState, number: int, now: datetime.datetime) -> None:
    prev = st.retry.get(number, {})
    st.retry[number] = {"attempts": int(prev.get("attempts", 0)) + 1,
                        "last_failed_at": now.isoformat()}

def _mirror_dir(state_dir: str, slug_key: str) -> Path:
    return Path(state_dir) / slug_key.replace("/", "__")

def ensure_mirror(clone_url: str, state_dir: str, env: dict, slug_key: str | None = None) -> str:
    """Maintain a per-repo local clone under `state_dir`. First call clones;
    subsequent calls fetch+prune. `slug_key` (the repo slug) names the dir
    (sanitised); defaults to `clone_url` so callers that pass a path can use it
    directly. Production `clone_url` = `https://github.com/<slug>.git`; `gh`'s
    credential helper or a PAT in `GH_TOKEN` (via `gh_env`) covers private
    fetch. For the public-`epigraph` pilot no creds are needed."""
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    d = _mirror_dir(state_dir, slug_key or clone_url)
    if (d / "HEAD").exists() or (d / ".git").exists():
        subprocess.run(["git", "-C", str(d), "fetch", "--prune", "origin"],
                       check=True, capture_output=True, env=env)
    else:
        subprocess.run(["git", "clone", "--quiet", clone_url, str(d)],
                       check=True, capture_output=True, env=env)
    return str(d)

def build_ingest_argv(pr, mirror, endpoint, rev_range, slug, *,
                      ingest_git_bin="ingest_git", dry_run=False, author_key_file=None):
    """Assemble the `ingest_git --pr-ingest` argv for one merged PR. `slug` is
    the repo slug (`owner/repo`), `mirror` the local clone the binary reads, and
    `rev_range` the PR's own commit range (from `compute_rev_range`). It carries
    neither the token nor `--orchestrator-id`: both go in the child's
    environment (`ingest_env`), so the argv is safe to log."""
    argv = [ingest_git_bin, "--pr-ingest",
            "--repo-slug", slug, "--pr-number", str(pr.number),
            "--pr-title", pr.title, "--pr-body", pr.body,
            "--merge-sha", pr.merge_sha, "--merged-at", pr.merged_at,
            "--pr-author", pr.author, "--rev-range", rev_range,
            "--repo", mirror, "--endpoint", endpoint]
    if author_key_file:
        argv += ["--author-key-file", author_key_file]
    if dry_run:
        argv += ["--dry-run"]
    return argv

def ingest_pr(pr, mirror, endpoint, slug, *, env=None, github_env=None,
              ingest_git_bin="ingest_git", dry_run=False, author_key_file=None) -> int:
    """Compute the PR's commit range from the mirror, build the argv, and run
    `ingest_git` with `env` (from `ingest_env`; None inherits the reconciler's).
    `github_env` (from `gh_env`) lets a one-parent merge read the PR commits
    API to tell a rebase merge from a squash; None skips the call and treats it
    as a squash. Returns the subprocess return code; logs (not raises) on a
    non-zero exit so the caller can isolate per-PR failures."""
    commits = None
    if github_env is not None:
        commits = lambda: fetch_pr_commits(slug, pr.number, github_env)  # noqa: E731
    rng = compute_rev_range(mirror, pr.merge_sha, commits)
    argv = build_ingest_argv(pr, mirror, endpoint, rng, slug,
                             ingest_git_bin=ingest_git_bin, dry_run=dry_run,
                             author_key_file=author_key_file)
    LOG.info("ingest PR #%s (%s): %s", pr.number, slug, " ".join(argv))
    res = subprocess.run(argv, capture_output=True, text=True, env=env)
    if res.returncode != 0:
        LOG.error("ingest PR #%s failed (%s): %s", pr.number, res.returncode, res.stderr.strip()[:500])
    return res.returncode

def run_once(cfg: Config, *, dry_run: bool, now: datetime.datetime | None = None) -> tuple[int, int]:
    """Reconcile every configured repo once: the PRs merged since the repo's
    cutoff (`compute_cutoff`) plus its retry list. Repo-level failures
    (state/mirror/discovery) and per-PR failures are both logged and isolated —
    one bad repo or PR never aborts the rest — and counted into the failure
    tally. A repo-level failure keeps the repo's cursor; a failed PR joins the
    retry list. A dry run reads the state and writes none. Returns (ok, fail)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    env = gh_env()
    key_file = resolve_author_key_file(cfg)
    token = None
    if not dry_run:  # a dry run makes no API call, so it needs no token or key
        if key_file is None:
            LOG.error("no author key file (author_key_file / EPIGRAPH_GIT_AUTHOR_KEY_FILE): "
                      "ingest_git refuses a live run without it")
            return 0, 1
        try:
            token = read_token(cfg)
        except OSError as e:
            LOG.error("cannot read token_file %s: %s", cfg.token_file, e.strerror or e)
            return 0, 1
        if token is None:
            LOG.warning("no API token (token_file / EPIGRAPH_TOKEN): writes will be refused")
    child_env = ingest_env(token, cfg.default_orchestrator_id)
    ok = fail = 0
    for slug in cfg.repos:
        try:
            state = load_state(cfg.state_dir, slug)
            mirror = ensure_mirror(f"https://github.com/{slug}.git", cfg.state_dir, env, slug_key=slug)
            cutoff = compute_cutoff(state.cursor, now, cfg.window_minutes)
            prs = discover_merged_prs(slug, env, cutoff)
        except Exception as e:  # repo-level failure: log + continue, cursor kept
            LOG.error("repo %s discovery failed: %s", slug, e); fail += 1; continue
        found = {pr.number for pr in prs}
        for number in sorted(set(state.retry) - found):
            try:
                pr = fetch_pr(slug, number, env)
            except Exception as e:
                LOG.error("PR #%s (%s) retry lookup failed: %s", number, slug, e)
                _record_failure(state, number, now); fail += 1; continue
            if pr is None:
                LOG.warning("PR #%s (%s) is on the retry list but not merged; dropping it", number, slug)
                del state.retry[number]; continue
            LOG.info("retrying PR #%s (%s), attempt %s", number, slug,
                     state.retry[number].get("attempts", 0) + 1)
            prs.append(pr)
        for pr in prs:
            try:
                rc = ingest_pr(pr, mirror, cfg.endpoint, slug, env=child_env, github_env=env,
                               ingest_git_bin=cfg.ingest_git_bin, dry_run=dry_run,
                               author_key_file=key_file)
            except Exception as e:
                LOG.error("PR #%s (%s) ingest raised: %s", pr.number, slug, e); rc = None
            if rc == 0:
                ok += 1; state.retry.pop(pr.number, None)
            else:
                fail += 1; _record_failure(state, pr.number, now)
        # Every merged PR since the cutoff is now ingested or on the retry list.
        state.cursor = now.isoformat()
        if not dry_run:
            try:
                save_state(cfg.state_dir, slug, state)
            except OSError as e:
                LOG.error("repo %s: cannot save state: %s", slug, e); fail += 1
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
