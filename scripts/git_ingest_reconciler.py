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
