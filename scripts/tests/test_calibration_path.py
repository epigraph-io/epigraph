"""The Python belief backfills resolve calibration the way the engine does.

Backlog af23a73d: the Rust engine serves the calibration file `CALIBRATION_PATH`
names (`CalibrationConfig::cached` in crates/epigraph-engine/src/calibration.rs),
while backfill_source_strength.py and backfill_intra_source_evidence_discount.py
read the repo-root calibration.toml and never looked at `CALIBRATION_PATH`. A
deployment that overrides calibration would have been backfilled with weights
the engine does not serve.

These tests drive each script's `main()` up to the database connection (patched
to stop the run) and assert which file it loaded, from the values it printed.
The fixture's values differ from the repo file's, so a script that ignores
`CALIBRATION_PATH` prints the repo's numbers and fails.

They also pin the "mirrors <Rust fn>" header each of the three Python belief
backfills carries, and check that the named function exists in the named file.

Run: python3 -m pytest -q scripts/tests/test_calibration_path.py
"""
import io
import re
import sys
import types
from contextlib import redirect_stdout
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
try:  # the scripts import psycopg2 at module load; the logic under test does not
    import psycopg2  # noqa: F401
except ImportError:  # pragma: no cover - environment without psycopg2
    extras = types.ModuleType("psycopg2.extras")
    extras.RealDictCursor = object
    stub = types.ModuleType("psycopg2")
    stub.extras = extras
    sys.modules["psycopg2"] = stub
    sys.modules["psycopg2.extras"] = extras

import backfill_intra_source_evidence_discount as intra  # noqa: E402
import backfill_source_strength as strength  # noqa: E402

# Values the repo's calibration.toml does not hold, so they identify the fixture.
FIXTURE_INTRA = 0.137
FIXTURE_EMPIRICAL = 0.613
FIXTURE_CONVERSATIONAL = 0.271
FIXTURE_TOML = f"""
[evidence_type_weights]
empirical = {FIXTURE_EMPIRICAL}
conversational = {FIXTURE_CONVERSATIONAL}

[evidence_type_aliases]
observation = "empirical"

[evidence_locality]
intra_evidence_locality_factor = {FIXTURE_INTRA}
"""


class _StopAtConnect(Exception):
    """Raised in place of psycopg2.connect: the run has loaded calibration."""


@pytest.fixture
def fixture_calibration(tmp_path):
    path = tmp_path / "override-calibration.toml"
    path.write_text(FIXTURE_TOML)
    return path


def _run_main(module, monkeypatch, argv):
    """Run module.main() until it connects; return what it printed."""

    def stop(*_a, **_k):
        raise _StopAtConnect

    monkeypatch.setattr(module.psycopg2, "connect", stop)
    monkeypatch.setattr(sys, "argv", [module.__file__, "--database-url", "postgres://unused/x", *argv])
    out = io.StringIO()
    with redirect_stdout(out), pytest.raises(_StopAtConnect):
        module.main()
    return out.getvalue()


def test_repo_calibration_differs_from_the_fixture():
    # Non-vacuity: if the repo file held the fixture's values, the tests below
    # could not tell which file a script loaded.
    assert intra.load_intra_factor(intra.DEFAULT_CALIBRATION) != FIXTURE_INTRA
    weights = strength.load_weight_map(strength.DEFAULT_CALIBRATION)
    assert weights["empirical"] != FIXTURE_EMPIRICAL
    assert weights["conversational"] != FIXTURE_CONVERSATIONAL


def test_source_strength_loads_calibration_path(monkeypatch, fixture_calibration):
    monkeypatch.setenv("CALIBRATION_PATH", str(fixture_calibration))
    out = _run_main(strength, monkeypatch, [])
    assert f"CALIBRATION_PATH={fixture_calibration}" in out
    assert f"agent-only tier (conversational) = {FIXTURE_CONVERSATIONAL}" in out
    # The fixture's two canonical keys, its alias, and the hard-coded DB-vocab
    # aliases whose targets the fixture does not define resolve to nothing.
    assert re.search(r"loaded 3 evidence-type weights", out), out


def test_intra_source_loads_calibration_path(monkeypatch, fixture_calibration):
    monkeypatch.setenv("CALIBRATION_PATH", str(fixture_calibration))
    out = _run_main(intra, monkeypatch, [])
    assert f"CALIBRATION_PATH={fixture_calibration}" in out
    assert f"intra_evidence_locality_factor = {FIXTURE_INTRA}" in out


@pytest.mark.parametrize("module", [strength, intra], ids=["source_strength", "intra_source"])
def test_without_calibration_path_the_repo_file_is_used(module, monkeypatch):
    monkeypatch.delenv("CALIBRATION_PATH", raising=False)
    out = _run_main(module, monkeypatch, [])
    assert str(module.DEFAULT_CALIBRATION) in out
    assert "CALIBRATION_PATH unset" in out


@pytest.mark.parametrize("module", [strength, intra], ids=["source_strength", "intra_source"])
def test_an_explicit_flag_beats_calibration_path(module, monkeypatch, fixture_calibration):
    monkeypatch.setenv("CALIBRATION_PATH", str(fixture_calibration))
    out = _run_main(module, monkeypatch, ["--calibration", str(module.DEFAULT_CALIBRATION)])
    assert f"--calibration {module.DEFAULT_CALIBRATION}" in out
    assert str(fixture_calibration) not in out


@pytest.mark.parametrize("module", [strength, intra], ids=["source_strength", "intra_source"])
def test_an_unreadable_calibration_path_is_refused_not_ignored(module, monkeypatch, tmp_path):
    # These scripts write mass_functions: silently falling back to the repo file
    # would hide that the override the operator set was never read. (The engine
    # itself logs and serves its embedded copy here, so the message must not
    # send the operator looking for a different file; it says to fix or unset
    # the variable.)
    missing = tmp_path / "absent.toml"
    monkeypatch.setenv("CALIBRATION_PATH", str(missing))
    monkeypatch.setattr(sys, "argv", [module.__file__, "--database-url", "postgres://unused/x"])
    with pytest.raises(SystemExit) as exc:
        module.main()
    message = str(exc.value.code)
    assert str(missing) in message
    assert "fix or unset CALIBRATION_PATH" in message
    assert "engine would serve" not in message


# (script, Rust file, Rust function) each Python belief backfill mirrors.
MIRRORS = [
    (
        "backfill_source_strength.py",
        "crates/epigraph-engine/src/calibration.rs",
        "get_evidence_type_weight",
    ),
    (
        "backfill_intra_source_evidence_discount.py",
        "crates/epigraph-engine/src/edge_factor.rs",
        "edge_intra_locality_factor",
    ),
    (
        "migrate_provenance_bba.py",
        "crates/epigraph-ds/src/mass.rs",
        "from_pignistic_prior",
    ),
    (
        "migrate_provenance_bba.py",
        "crates/epigraph-mcp/src/tools/ds_auto.rs",
        "auto_wire_ds_update",
    ),
]


@pytest.mark.parametrize("script,rust_file,rust_fn", MIRRORS)
def test_header_names_the_rust_function_it_mirrors(script, rust_file, rust_fn):
    source = (REPO / "scripts" / script).read_text()
    docstring = source.split('"""', 2)[1]
    mirrors = [line for line in docstring.splitlines() if line.startswith("Mirrors:")]
    assert mirrors, f"{script}'s module docstring has no `Mirrors:` line"
    header = " ".join(docstring.split("Mirrors:", 1)[1].split("\n\n", 1)[0].split())
    assert rust_fn in header, f"{script}'s Mirrors line does not name {rust_fn}: {header}"
    assert rust_file in header, f"{script}'s Mirrors line does not name {rust_file}: {header}"
    rust = (REPO / rust_file).read_text()
    assert re.search(rf"\bfn {re.escape(rust_fn)}\b", rust), f"{rust_file} has no fn {rust_fn}"
