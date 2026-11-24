"""label_themes_llm exits non-zero when any theme or neighbourhood fails to label (backlog b67a5e64).

theme_pipeline reports `label_failed` (and its `label` subcommand exits
non-zero) only from the label subprocess's exit code. The script used to count
per-item failures and exit 0 anyway, so a run that left themes unlabelled, or
keeping labels built before the public-only rule, reported success.

The main() arms drive the script in-process with the Claude CLI replaced; the
pipeline arm runs the real label subprocess through theme_pipeline.run_label_step
with a fake `claude` executable first on PATH.
"""
import os
import stat
import sys

from scripts import label_themes_llm as L
from scripts import theme_pipeline as T
from tests.theme.conftest import TEST_DSN, make_embedding
from tests.theme.test_label_excludes_intake import _claim
from tests.theme.test_label_neighborhoods import _cleanup as _cleanup_nbrs
from tests.theme.test_label_neighborhoods import _nbr, _run
from tests.theme.test_label_neighborhoods import _theme as _nbr_theme

GOOD = {"label": "Exit code label", "description": "Exit code description"}


def _theme(cur, label, seed):
    cur.execute(
        "INSERT INTO claim_themes (label, description, claim_count, centroid) "
        "VALUES (%s, '', 1, %s::vector) RETURNING id",
        (label, make_embedding(seed)),
    )
    return cur.fetchone()[0]


def _labels(db, themes):
    with db.cursor() as cur:
        cur.execute("SELECT id, label FROM claim_themes WHERE id = ANY(%s)", (themes,))
        out = dict(cur.fetchall())
    db.rollback()
    return out


def _cleanup(db, ids):
    db.rollback()
    with db.cursor() as cur:
        cur.execute("UPDATE claims SET theme_id = NULL WHERE id::text = ANY(%s)", (ids,))
        cur.execute("DELETE FROM claim_themes")
        cur.execute("DELETE FROM claims WHERE id::text = ANY(%s)", (ids,))
    db.commit()


def _main(monkeypatch, answer_for, *extra):
    """label_themes_llm.main against the test DB; the CLI answers
    answer_for(prompt). Returns main's return value."""
    monkeypatch.setattr(L, "call_claude_cli",
                        lambda prompt, result_path, cwd, timeout=120: answer_for(prompt))
    monkeypatch.delenv("MAINTENANCE_DATABASE_URL", raising=False)
    monkeypatch.setattr(sys, "argv", ["label_themes_llm.py", "--database-url", TEST_DSN, *extra])
    return L.main()


def test_a_theme_that_fails_to_label_makes_main_fail(db, seed_agent, monkeypatch):
    with db.cursor() as cur:
        ok = _theme(cur, "auto-1", 3)
        bad = _theme(cur, "auto-2", 9)
        ids = [
            _claim(cur, seed_agent, "exit-code member answered", theme_id=ok, seed=3),
            _claim(cur, seed_agent, "exit-code member unanswered", theme_id=bad, seed=9),
        ]
    db.commit()
    try:
        # Every theme answered: success.
        assert _main(monkeypatch, lambda p: GOOD) == 0
        assert set(_labels(db, [ok, bad]).values()) == {GOOD["label"]}

        # One of two themes gets no valid answer: the run fails, though the
        # other theme is still labelled.
        rc = _main(monkeypatch, lambda p: None if "unanswered" in p else
                   {"label": "Second pass", "description": ""}, "--relabel-all")
        assert rc not in (0, None), rc
        labels = _labels(db, [ok, bad])
        assert labels[ok] == "Second pass"
        assert labels[bad] == GOOD["label"]  # kept, not overwritten

        # --dry-run makes no LLM call, so nothing can fail.
        assert _main(monkeypatch, lambda p: None, "--relabel-all", "--dry-run") == 0
    finally:
        _cleanup(db, ids)


def test_a_neighbourhood_that_fails_to_label_makes_main_fail(db, seed_agent, monkeypatch):
    with db.cursor() as cur:
        theme = _nbr_theme(cur)
        a = _claim(cur, seed_agent, "exit-code neighbourhood answered")
        b = _claim(cur, seed_agent, "exit-code neighbourhood unanswered")
        run = _run(cur, 0)
        _nbr(cur, run, theme, "neighborhood-1", [a])
        _nbr(cur, run, theme, "neighborhood-2", [b])
    db.commit()
    try:
        rc = _main(monkeypatch, lambda p: None if "unanswered" in p else GOOD, "--neighborhoods")
        assert rc not in (0, None), rc
        assert _main(monkeypatch, lambda p: GOOD, "--neighborhoods", "--relabel-all") == 0
    finally:
        _cleanup_nbrs(db, [run], [a, b], None, theme)


def _fake_claude(tmp_path, monkeypatch, result):
    """Put a `claude` first on PATH that prints a CLI envelope whose `result`
    is `result` and writes no result file."""
    import json
    exe = tmp_path / "claude"
    envelope = json.dumps({"result": result})
    exe.write_text("#!/bin/sh\ncat <<'JSON'\n" + envelope + "\nJSON\n")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.delenv("MAINTENANCE_DATABASE_URL", raising=False)


def test_the_pipeline_label_step_fails_when_a_theme_is_left_unlabelled(
    db, seed_agent, monkeypatch, tmp_path
):
    """The real label subprocess, as theme_pipeline runs it: a theme the CLI
    gives no valid answer for makes the step's exit code non-zero (it was 0),
    and a valid inline answer still exits 0 and is stored."""
    with db.cursor() as cur:
        theme = _theme(cur, "auto-5", 3)
        ids = [_claim(cur, seed_agent, "exit-code pipeline member", theme_id=theme, seed=3)]
    db.commit()
    try:
        _fake_claude(tmp_path, monkeypatch, "I cannot help with that.")
        assert T.run_label_step(TEST_DSN) != 0
        assert _labels(db, [theme])[theme] == "auto-5"

        import json
        _fake_claude(tmp_path, monkeypatch, json.dumps(GOOD))
        assert T.run_label_step(TEST_DSN) == 0
        assert _labels(db, [theme])[theme] == GOOD["label"]
    finally:
        _cleanup(db, ids)
