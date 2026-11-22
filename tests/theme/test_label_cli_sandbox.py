"""The labelling Claude CLI gets only the Write tool and no database credentials (backlog b67a5e64, review follow-up).

label_themes_llm runs `claude -p ... --dangerously-skip-permissions` with a
prompt that quotes public member text, which any public-claim author
controls. Since theme_pipeline hands the label step its DSN through the
environment (MAINTENANCE_DATABASE_URL and DATABASE_URL), a CLI that inherited
that environment and had Bash could print the maintenance DSN on an injected
instruction. The CLI must be started with `--tools Write` (the only tool the
file-answer path needs) and an environment with no *DATABASE_URL* variable
and no PGPASSWORD.

These tests run the REAL call_claude_cli, and in the last one the real label
subprocess through theme_pipeline.run_label_step, against a stub `claude`
first on PATH that records its argv and its environment.
"""
import json
import os
import stat

from scripts import label_themes_llm as L
from scripts import theme_pipeline as T
from tests.theme.conftest import TEST_DSN
from tests.theme.test_label_excludes_intake import _claim
from tests.theme.test_label_exit_code import GOOD, _cleanup, _labels, _theme

SECRET = "s3cret-pw-cli-sandbox"
DSN = f"postgres://maint:{SECRET}@localhost:5432/sandbox_test"

STUB = """#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_CLAUDE_LOG"], "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "env": dict(os.environ)}) + "\\n")
sys.stdout.write(json.dumps({"result": os.environ.get("STUB_CLAUDE_ANSWER", "")}))
"""


def _stub(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "claude"
    exe.write_text(STUB)
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    log = tmp_path / "claude_calls.jsonl"
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    # The stub's own log path is not a credential; it must survive the scrub.
    monkeypatch.setenv("STUB_CLAUDE_LOG", str(log))
    monkeypatch.setenv("STUB_CLAUDE_ANSWER", json.dumps(GOOD))
    monkeypatch.setattr(L, "RESULT_POLL_ATTEMPTS", 1, raising=False)
    monkeypatch.setattr(L, "RESULT_POLL_INTERVAL", 0.0, raising=False)

    def calls():
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    return calls


def _assert_sandboxed(call, *secrets):
    argv, env = call["argv"], call["env"]
    assert "--tools" in argv, argv
    assert argv[argv.index("--tools") + 1] == "Write", argv
    leaked = {k for k in env if "DATABASE_URL" in k.upper() or k.upper() == "PGPASSWORD"}
    assert not leaked, f"database credential variables reached the CLI: {sorted(leaked)}"
    for secret in secrets:
        assert not any(secret in v for v in env.values()), "a DSN value reached the CLI"


def test_the_cli_gets_write_only_and_no_database_credentials(tmp_path, monkeypatch):
    calls = _stub(tmp_path, monkeypatch)
    monkeypatch.setenv("MAINTENANCE_DATABASE_URL", DSN)
    monkeypatch.setenv("DATABASE_URL", DSN)
    monkeypatch.setenv("EPIGRAPH_READONLY_DATABASE_URL", DSN)
    monkeypatch.setenv("PGPASSWORD", SECRET)
    monkeypatch.setenv("UNRELATED_VARIABLE", "kept")

    out = L.call_claude_cli("label this", str(tmp_path / "none.json"), cwd=str(tmp_path))

    assert out == GOOD  # the stub was the CLI called, and its answer was used
    [call] = calls()
    _assert_sandboxed(call, SECRET)
    # HOME, PATH and the CLI's auth state must still pass through.
    assert call["env"]["UNRELATED_VARIABLE"] == "kept"
    assert call["env"]["PATH"] == os.environ["PATH"]
    # The scrub copies; this process's own environment is untouched.
    assert os.environ["DATABASE_URL"] == DSN


def test_the_scrub_matches_names_case_insensitively():
    env = L.claude_cli_env({
        "database_url": DSN, "My_Database_Url": DSN, "pgpassword": SECRET,
        "HOME": "/home/x", "PGHOST": "localhost",
    })
    assert env == {"HOME": "/home/x", "PGHOST": "localhost"}


def test_the_pipeline_label_step_hands_the_cli_no_dsn(db, seed_agent, monkeypatch, tmp_path):
    """End to end: theme_pipeline puts the DSN in the label subprocess's
    environment; the CLI that subprocess spawns must still see none of it."""
    with db.cursor() as cur:
        theme = _theme(cur, "auto-7", 4)
        ids = [_claim(cur, seed_agent, "cli sandbox member", theme_id=theme, seed=4)]
    db.commit()
    calls = _stub(tmp_path, monkeypatch)
    monkeypatch.delenv("MAINTENANCE_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    try:
        assert T.run_label_step(TEST_DSN) == 0
        assert _labels(db, [theme])[theme] == GOOD["label"]
        made = calls()
        assert made, "the label step never called the CLI"
        for call in made:
            _assert_sandboxed(call, TEST_DSN)
    finally:
        _cleanup(db, ids)
