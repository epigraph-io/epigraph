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

def discover_merged_prs(slug: str, env: dict, window_minutes: int, now: datetime.datetime) -> list[PullRequest]:
    cutoff = now - datetime.timedelta(minutes=window_minutes)
    rows = _gh_json(
        [f"repos/{slug}/pulls", "-X", "GET",
         "--field", "state=closed", "--field", "sort=updated",
         "--field", "direction=desc", "--field", "per_page=50",
         "--paginate", "--slurp"],
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
                      default_orchestrator_id=None, ingest_git_bin="ingest_git", dry_run=False):
    """Assemble the `ingest_git --pr-ingest` argv for one merged PR. `slug` is
    the repo slug (`owner/repo`), `mirror` the local clone the binary reads, and
    `rev_range` the PR's own commit range (from `compute_rev_range`). The
    `--orchestrator-id` flag is only emitted when configured; otherwise the
    ingester resolves the trailer / `EPIGRAPH_DEFAULT_ORCHESTRATOR_ID` itself."""
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
    """Compute the PR's commit range from the mirror, build the argv, and run
    `ingest_git`. Returns the subprocess return code; logs (not raises) on a
    non-zero exit so the caller can isolate per-PR failures."""
    rng = compute_rev_range(mirror, pr.merge_sha)
    argv = build_ingest_argv(pr, mirror, endpoint, rng, slug,
                             default_orchestrator_id=default_orchestrator_id,
                             ingest_git_bin=ingest_git_bin, dry_run=dry_run)
    LOG.info("ingest PR #%s (%s): %s", pr.number, slug, " ".join(argv))
    res = subprocess.run(argv, capture_output=True, text=True)
    if res.returncode != 0:
        LOG.error("ingest PR #%s failed (%s): %s", pr.number, res.returncode, res.stderr.strip()[:500])
    return res.returncode

def run_once(cfg: Config, *, dry_run: bool, now: datetime.datetime | None = None) -> tuple[int, int]:
    """Reconcile every configured repo once. Repo-level failures (mirror/discovery)
    and per-PR failures are both logged and isolated — one bad repo or PR never
    aborts the rest — and counted into the failure tally. Returns (ok, fail)."""
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
