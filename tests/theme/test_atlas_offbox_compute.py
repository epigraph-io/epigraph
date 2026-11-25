"""The reference off-box command of the Atlas nightly's hook (backlog 691d283a).

scripts/atlas_offbox_compute.py is what `atlas_nightly --offbox-command` and
`theme_cap_split.py offbox` run, with three arguments and a cleared
environment (PATH, HOME and LANG only, as both callers give it). No DB: it
runs where only numpy, scikit-learn and umap-learn exist. The theme-cap kind
is driven end to end against a database in test_theme_cap_split.py; here the
atlas-meaning kind runs on the committed W4 fixture export.
"""
import json
import os
import pathlib
import stat
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "atlas_offbox_compute.py"
FIXTURE = REPO / "crates" / "epigraph-cli" / "tests" / "fixtures" / "atlas_meaning"


def _call(*args):
    # The environment the hook gives: nothing but these.
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG") if k in os.environ}
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], env=env,
                          capture_output=True, text=True)


def test_atlas_meaning_kind_computes_the_committed_result_into_a_new_private_file(tmp_path):
    out = tmp_path / "result.json"
    proc = _call("atlas-meaning", FIXTURE / "export", out)
    assert proc.returncode == 0, proc.stderr
    got = json.loads(out.read_text())
    want = json.loads((FIXTURE / "result.json").read_text())
    assert got["themes"] == want["themes"]
    assert (got["format"], got["map"], got["hierarchy"]) == (
        want["format"], want["map"], want["hierarchy"])
    assert stat.S_IMODE(out.stat().st_mode) == 0o600

    # An existing result file is never overwritten.
    out.write_text("kept")
    again = _call("atlas-meaning", FIXTURE / "export", out)
    assert again.returncode != 0
    assert out.read_text() == "kept"


def test_usage_errors_exit_2(tmp_path):
    assert _call("atlas-links", FIXTURE / "export", tmp_path / "r.json").returncode == 2
    assert _call("theme-cap", FIXTURE / "export").returncode == 2
    assert not (tmp_path / "r.json").exists()
