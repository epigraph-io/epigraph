"""label_themes_llm accepts a label the model answers INLINE (backlog b6191a3c).

The labeller asks Haiku to Write its {label, description} JSON to a result
file, then polls for the file. About two answers in three come back inline in
the `--output-format json` envelope's `result` instead, with no file written,
and the old `call_claude_cli` discarded stdout, so each of those themes failed
with "Result file not found".

These tests run the REAL `call_claude_cli` against a stub `claude` executable
on PATH (every other labeller test replaces `call_claude_cli` wholesale, which
is why none of them could see this). The stub records the prompt it was given,
prints a canned envelope and writes no file. Covered:

* an inline answer (inside a code fence, after prose) is stored, in theme mode
  and in `--neighborhoods` mode, and the prompt still quotes public members
  only (the public-members-only rule is unchanged: the inline answer is the
  same LLM output built from the same public-only prompt);
* a non-dict inline answer, an inline dict missing a key, an error envelope
  and an envelope with no JSON object in it are all refused, and the stored
  label is left as it was.
"""
import json
import os
import stat
import sys

import pytest

from scripts import label_themes_llm as L
from tests.theme.conftest import script_dsn
from tests.theme.test_label_excludes_intake import PUBLIC_TEXT, _claim, _group
from tests.theme.test_label_neighborhoods import _label, _nbr, _run
from tests.theme.test_label_neighborhoods import _theme as _plain_theme
from tests.theme.test_label_public_only import _private, _stored
from tests.theme.test_label_public_only import _theme as _centroid_theme

PRIVATE_TEXT = "inline-answer group-private member osprey-cobalt"
INLINE_LABEL = "Inline Answered Topic"
INLINE_DESCRIPTION = "Claims the stub model labelled inline, without a file."

STUB = """#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_CLAUDE_ARGV"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
sys.stdout.write(os.environ["STUB_CLAUDE_STDOUT"])
"""


def envelope(result, is_error=False):
    """The shape `claude -p --output-format json` prints."""
    return json.dumps({
        "type": "result",
        "subtype": "error_during_execution" if is_error else "success",
        "is_error": is_error,
        "num_turns": 1,
        "result": result,
        "session_id": "00000000-0000-0000-0000-000000000000",
    })


def fenced(obj):
    return "Here is the label:\n```json\n" + json.dumps(obj, indent=2) + "\n```\n"


GOOD = fenced({"label": INLINE_LABEL, "description": INLINE_DESCRIPTION})


@pytest.fixture
def stub_claude(tmp_path, monkeypatch):
    """Put a stub `claude` first on PATH. Returns (set_stdout, prompts, result_dir):
    set_stdout(text) sets what the stub prints; prompts() lists the -p prompts
    it was called with. RESULT_DIR points at an empty directory the stub never
    writes to, so a stale file from a real run cannot satisfy a test."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "claude"
    exe.write_text(STUB)
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    argv_log = tmp_path / "argv.jsonl"
    result_dir = tmp_path / "results"
    result_dir.mkdir()
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("STUB_CLAUDE_ARGV", str(argv_log))
    monkeypatch.setenv("STUB_CLAUDE_STDOUT", "")
    monkeypatch.setattr(L, "RESULT_DIR", str(result_dir))
    # The file poll is the fallback for an answer written to disk; with no
    # file ever written it only adds wall time.
    monkeypatch.setattr(L, "RESULT_POLL_ATTEMPTS", 1, raising=False)
    monkeypatch.setattr(L, "RESULT_POLL_INTERVAL", 0.0, raising=False)

    def set_stdout(text):
        monkeypatch.setenv("STUB_CLAUDE_STDOUT", text)

    def prompts():
        if not argv_log.exists():
            return []
        out = []
        for line in argv_log.read_text().splitlines():
            argv = json.loads(line)
            out.append(argv[argv.index("-p") + 1])
        return out

    return set_stdout, prompts, result_dir


# ---------------------------------------------------------------------------
# call_claude_cli alone (no database)
# ---------------------------------------------------------------------------


def _call(stub, stdout, tmp_path):
    set_stdout, prompts, result_dir = stub
    set_stdout(stdout)
    result_path = str(result_dir / "theme_deadbeef.json")
    out = L.call_claude_cli("label this", result_path, cwd=str(tmp_path))
    assert prompts() == ["label this"], "the stub claude was not the one called"
    assert not os.path.exists(result_path)
    return out


def test_an_inline_answer_is_accepted(stub_claude, tmp_path):
    out = _call(stub_claude, envelope(GOOD), tmp_path)
    assert out == {"label": INLINE_LABEL, "description": INLINE_DESCRIPTION}


@pytest.mark.parametrize("stdout", [
    # Not a dict: a list (even one wrapping a well-formed answer), a string.
    envelope(fenced([{"label": INLINE_LABEL, "description": INLINE_DESCRIPTION}])),
    envelope('"Inline Answered Topic"'),
    # A dict missing a key, or with a non-string or empty label.
    envelope(fenced({"label": INLINE_LABEL})),
    envelope(fenced({"description": INLINE_DESCRIPTION})),
    envelope(fenced({"label": 7, "description": INLINE_DESCRIPTION})),
    envelope(fenced({"label": "  ", "description": INLINE_DESCRIPTION})),
    # An error envelope, even one carrying a well-formed object.
    envelope(GOOD, is_error=True),
    # No object at all, an empty result, and stdout that is not an envelope.
    envelope("I wrote the file."),
    envelope(""),
    "not json at all",
    "",
], ids=[
    "list", "string", "no-description", "no-label", "label-not-str", "blank-label",
    "is-error", "prose-only", "empty-result", "not-an-envelope", "no-stdout",
])
def test_an_unusable_inline_answer_is_refused(stub_claude, tmp_path, stdout):
    assert _call(stub_claude, stdout, tmp_path) is None


# The schema the prompt shows, spelled out here (not read from the module) so
# the refusal is checked against the literal text a model would echo.
TEMPLATE = {
    "label": "short topic name (3-8 words)",
    "description": "One sentence describing the cluster's subject matter, "
                   "methodology focus, or domain.",
}
ANSWER = {"label": INLINE_LABEL, "description": INLINE_DESCRIPTION}


@pytest.mark.parametrize("result", [
    "Per claim [1] and [2], the answer is: " + json.dumps(ANSWER),
    "The schema was " + json.dumps(TEMPLATE) + ", so:\n" + fenced(ANSWER),
], ids=["citation-first", "schema-echo-first"])
def test_the_answer_after_a_refused_value_is_found(stub_claude, tmp_path, result):
    """A `[1]` citation or an echo of the prompt's schema before the answer is
    skipped, not taken for the answer (which would refuse a good answer, or
    store the placeholder label)."""
    assert _call(stub_claude, envelope(result), tmp_path) == ANSWER


def test_an_echo_of_the_schema_alone_is_refused_inline(stub_claude, tmp_path):
    assert _call(stub_claude, envelope(fenced(TEMPLATE)), tmp_path) is None


def test_an_echo_of_the_schema_alone_is_refused_in_the_file(stub_claude, tmp_path):
    set_stdout, _prompts, result_dir = stub_claude
    set_stdout(envelope("I wrote the file."))
    result_path = result_dir / "theme_0badf11e.json"
    result_path.write_text(json.dumps(TEMPLATE))
    assert L.call_claude_cli("label this", str(result_path), cwd=str(tmp_path)) is None


def test_the_prompt_shows_the_schema_the_refusal_names():
    """The refused placeholder is the one the prompt actually shows."""
    assert (L.TEMPLATE_LABEL, L.TEMPLATE_DESCRIPTION) == (
        TEMPLATE["label"], TEMPLATE["description"])
    prompt, _path = L.build_prompt(
        {"id": "deadbeef-0000", "claim_count": 1,
         "samples": [{"agent": "a", "content": "c"}]})
    assert f'"label": "{L.TEMPLATE_LABEL}"' in prompt
    assert f'"description": "{L.TEMPLATE_DESCRIPTION}"' in prompt


def test_the_envelope_itself_is_never_taken_for_the_answer(stub_claude, tmp_path):
    """The envelope is the first {...} on stdout and carries no label; a raw scan
    of stdout would decode it first. Its `result` is what is parsed."""
    stdout = json.dumps({
        "type": "result", "is_error": False,
        "label": "envelope-level label", "description": "not the answer",
        "result": "no answer here",
    })
    assert _call(stub_claude, stdout, tmp_path) is None


def test_a_file_answer_still_wins(stub_claude, tmp_path):
    """The Write-tool path is unchanged: a valid file is read, whatever stdout says."""
    set_stdout, _prompts, result_dir = stub_claude
    set_stdout(envelope(GOOD))
    result_path = result_dir / "theme_cafef00d.json"
    result_path.write_text(json.dumps({"label": "From The File", "description": "d"}))
    out = L.call_claude_cli("label this", str(result_path), cwd=str(tmp_path))
    assert out == {"label": "From The File", "description": "d"}


# ---------------------------------------------------------------------------
# main(), both modes, against the test database
# ---------------------------------------------------------------------------


def _main(monkeypatch, *extra):
    monkeypatch.delenv("MAINTENANCE_DATABASE_URL", raising=False)
    monkeypatch.setattr(sys, "argv", ["label_themes_llm.py", "--database-url", script_dsn(), *extra])
    L.main()


def _cleanup_themes(db, ids, group):
    db.rollback()
    with db.cursor() as cur:
        cur.execute("UPDATE claims SET theme_id = NULL WHERE id::text = ANY(%s)", (ids,))
        cur.execute("DELETE FROM claim_themes")
        cur.execute("DELETE FROM claims WHERE id::text = ANY(%s)", (ids,))
        cur.execute("SET LOCAL epigraph.allow_group_delete = 'yes'")
        cur.execute("DELETE FROM groups WHERE id = %s", (group,))
    db.commit()


def test_theme_mode_stores_an_inline_answer(db, seed_agent, monkeypatch, stub_claude):
    set_stdout, prompts, _ = stub_claude
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        theme = _centroid_theme(cur, "auto-1")
        ids = [
            _claim(cur, seed_agent, PUBLIC_TEXT, theme_id=theme),
            _private(cur, seed_agent, group, PRIVATE_TEXT, theme_id=theme),
        ]
    db.commit()
    try:
        # Refused answers leave the placeholder in place.
        for bad in (envelope(fenced([1, 2])), envelope(fenced({"label": INLINE_LABEL}))):
            set_stdout(bad)
            _main(monkeypatch)
            db.rollback()
            assert _stored(db, theme) == ("auto-1", "")

        set_stdout(envelope(GOOD))
        _main(monkeypatch)
        db.rollback()
        assert _stored(db, theme) == (INLINE_LABEL, INLINE_DESCRIPTION)

        sent = prompts()
        assert len(sent) == 3, sent
        assert all(PUBLIC_TEXT in p for p in sent)
        assert not any("osprey-cobalt" in p for p in sent), sent
    finally:
        _cleanup_themes(db, ids, group)


def test_neighbourhood_mode_stores_an_inline_answer(db, seed_agent, monkeypatch, stub_claude):
    set_stdout, prompts, _ = stub_claude
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        theme = _plain_theme(cur)
        pub = _claim(cur, seed_agent, PUBLIC_TEXT)
        priv = _claim(cur, seed_agent, PRIVATE_TEXT, owner=group, visibility="group")
        ids = [pub, priv]
        run = _run(cur, 0)
        nbr = _nbr(cur, run, theme, "neighborhood-1", [pub, priv])
    db.commit()
    try:
        for bad in (envelope('["Inline Answered Topic"]'),
                    envelope(fenced({"description": INLINE_DESCRIPTION}))):
            set_stdout(bad)
            _main(monkeypatch, "--neighborhoods")
            db.rollback()
            assert _label(db, nbr) == "neighborhood-1"

        set_stdout(envelope(GOOD))
        _main(monkeypatch, "--neighborhoods")
        db.rollback()
        assert _label(db, nbr) == INLINE_LABEL

        sent = prompts()
        assert len(sent) == 3, sent
        assert all(PUBLIC_TEXT in p for p in sent)
        assert not any("osprey-cobalt" in p for p in sent), sent
    finally:
        db.rollback()
        with db.cursor() as cur:
            cur.execute("DELETE FROM graph_cluster_runs WHERE run_id::text = %s", (run,))
        db.commit()
        _cleanup_themes(db, ids, group)
