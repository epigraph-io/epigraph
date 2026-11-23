"""theme_pipeline hands the label step its database URL through the environment, not argv (backlog b67a5e64).

A process's argv is readable by every local user (`ps`, /proc/<pid>/cmdline),
its environment only by the same user and root. The label step used to run as
`label_themes_llm.py --relabel-all --database-url <url>`, so a URL that came
from the environment, password included, was in the process list for the whole
step. It must still label the SAME database the pipeline wrote to, whatever
the pipeline's own environment names.
"""
import json
import os
import stat

from scripts import theme_pipeline as T
from tests.theme.conftest import TEST_DSN
from tests.theme.test_label_excludes_intake import _claim
from tests.theme.test_label_exit_code import GOOD, _cleanup, _labels, _theme

SECRET = "s3cret-pw-label-step"
URL = f"postgres://maint:{SECRET}@localhost:5432/scratch_test"


def test_the_label_step_puts_no_database_url_on_argv(monkeypatch):
    seen = {}

    class Done:
        returncode = 0

    def fake_run(cmd, check, env=None):
        seen["cmd"], seen["env"] = cmd, env
        return Done()

    monkeypatch.setattr(T.subprocess, "run", fake_run)
    assert T.run_label_step(URL) == 0
    argv = " ".join(seen["cmd"])
    assert SECRET not in argv and "scratch_test" not in argv, seen["cmd"]
    assert "--database-url" not in seen["cmd"]
    assert "--relabel-all" in seen["cmd"]
    # The child resolves its DSN from the environment it is handed
    # (maintenance_dsn: MAINTENANCE_DATABASE_URL, then DATABASE_URL).
    assert seen["env"]["MAINTENANCE_DATABASE_URL"] == URL


def test_the_child_environment_names_only_the_pipeline_database(monkeypatch):
    """Both variables are overridden: with only MAINTENANCE_DATABASE_URL set,
    a parent DATABASE_URL naming another database makes the child's
    maintenance_dsn refuse to start."""
    monkeypatch.setenv("MAINTENANCE_DATABASE_URL", "postgres://a@localhost/other_one")
    monkeypatch.setenv("DATABASE_URL", "postgres://b@localhost/other_two")
    monkeypatch.setenv("UNRELATED_VARIABLE", "kept")
    env = T.label_env(URL)
    assert env["MAINTENANCE_DATABASE_URL"] == URL
    assert env["DATABASE_URL"] == URL
    assert env["UNRELATED_VARIABLE"] == "kept"  # PATH, HOME, CLI auth pass through
    assert os.environ["DATABASE_URL"] == "postgres://b@localhost/other_two"  # parent untouched


def test_the_label_step_refuses_a_missing_url():
    import pytest
    with pytest.raises(ValueError):
        T.label_env(None)


def test_the_real_label_step_labels_the_pipeline_database_with_no_url_on_argv(
    db, seed_agent, monkeypatch, tmp_path
):
    """End to end: the parent environment names other databases, the label
    subprocess still labels the pipeline's (TEST_DSN), and the fake `claude`
    it spawns reads its parent's /proc cmdline to show the URL is not there."""
    with db.cursor() as cur:
        theme = _theme(cur, "auto-6", 3)
        ids = [_claim(cur, seed_agent, "label-step dsn member", theme_id=theme, seed=3)]
    db.commit()
    seen_argv = tmp_path / "label_argv.txt"
    exe = tmp_path / "claude"
    exe.write_text(
        "#!/bin/sh\n"
        f"tr '\\0' ' ' < /proc/$PPID/cmdline > '{seen_argv}'\n"
        "cat <<'JSON'\n" + json.dumps({"result": json.dumps(GOOD)}) + "\nJSON\n"
    )
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")
    other = TEST_DSN.rsplit("/", 1)[0] + "/not_the_pipeline_db"
    monkeypatch.setenv("MAINTENANCE_DATABASE_URL", other)
    monkeypatch.setenv("DATABASE_URL", other)
    try:
        assert T.run_label_step(TEST_DSN) == 0
        assert _labels(db, [theme])[theme] == GOOD["label"]
        argv = seen_argv.read_text()
        assert "label_themes_llm.py" in argv, argv
        assert TEST_DSN not in argv and "--database-url" not in argv, argv
    finally:
        _cleanup(db, ids)
