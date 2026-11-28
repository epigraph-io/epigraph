"""maintain_themes.py never installs packages at run time (backlog 8afe831f).

It used to answer a missing `requests` (at import) or `scikit-learn` (in
`auto_split_theme`) by running pip in a subprocess: on the host that runs the
maintenance jobs, that fetched whatever the index served at that moment,
unpinned and unhashed, into the interpreter the job runs under. A missing
package is now an ImportError that names `scripts/requirements.txt`, the
hash-locked file to install from, and nothing is spawned.

Each arm hides the package by setting its `sys.modules` entry to None (an
import of it raises ImportError, whether or not it is installed) and replaces
`subprocess.Popen`, which `check_call`, `run` and `call` all go through, with a
tripwire that records the attempt and refuses it.
"""
from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

REQUIREMENTS = "scripts/requirements.txt"


@pytest.fixture
def spawned(monkeypatch):
    """Every subprocess the code under test tries to start, refused."""
    calls = []

    def _tripwire(args, *a, **kw):
        calls.append(args)
        raise AssertionError(f"maintain_themes spawned a subprocess: {args!r}")

    monkeypatch.setattr(subprocess, "Popen", _tripwire)
    return calls


@pytest.fixture
def fresh_import(monkeypatch):
    """Import maintain_themes anew under a token and a neutral argv (its
    import-time code reads both), and drop it again afterwards."""
    monkeypatch.setenv("EPIGRAPH_TOKEN", "test-token-not-a-secret")
    monkeypatch.setattr(sys, "argv", ["maintain_themes.py", "--dry-run"])
    monkeypatch.delitem(sys.modules, "maintain_themes", raising=False)

    def _import():
        return importlib.import_module("maintain_themes")

    yield _import
    sys.modules.pop("maintain_themes", None)


def _hide(monkeypatch, *names):
    for name in names:
        monkeypatch.setitem(sys.modules, name, None)


def test_a_missing_requests_is_an_import_error_naming_the_requirements_file(
    monkeypatch, spawned, fresh_import
):
    _hide(monkeypatch, "requests")
    with pytest.raises(ImportError) as err:
        fresh_import()
    msg = str(err.value)
    assert REQUIREMENTS in msg, msg
    assert "requests" in msg, msg
    assert spawned == [], f"a subprocess was started: {spawned!r}"


def test_a_missing_scikit_learn_is_an_import_error_naming_the_requirements_file(
    monkeypatch, spawned, fresh_import
):
    pytest.importorskip("requests")
    module = fresh_import()

    def _no_api(*_a, **_kw):
        raise AssertionError("auto_split_theme reached the API before checking its imports")

    monkeypatch.setattr(module, "api_get", _no_api)
    _hide(monkeypatch, "sklearn", "sklearn.cluster")
    with pytest.raises(ImportError) as err:
        module.auto_split_theme("00000000-0000-0000-0000-000000000000", "label")
    msg = str(err.value)
    assert REQUIREMENTS in msg, msg
    assert "scikit-learn" in msg, msg
    assert spawned == [], f"a subprocess was started: {spawned!r}"


def test_no_script_installs_packages_at_run_time():
    """The static half: no file under scripts/ invokes pip's install command
    through a subprocess. The needle is assembled so this file does not match
    itself."""
    needle = '"pip", ' + '"install"'
    hits = [
        f"{p.relative_to(REPO)}:{n}"
        for p in sorted(SCRIPTS.rglob("*.py"))
        if "__pycache__" not in p.parts
        for n, line in enumerate(p.read_text().splitlines(), 1)
        if needle in line
    ]
    assert hits == [], "run-time pip installs:\n" + "\n".join(hits)
