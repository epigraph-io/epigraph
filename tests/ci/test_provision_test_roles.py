"""Tests for tests/ci/provision_test_roles.py's guards (backlog 9d02a5e0 review).

The script creates a cluster-wide login in `epigraph_maintenance`, which
bypasses row security on every EpiGraph database of that cluster. A `_test`
database name is not enough to keep it off a real cluster, so it must also
refuse outside GitHub Actions without an explicit opt-in, and it must never
use a password written in this public repo. Each refusal case runs the script
in a subprocess against a DSN that points at a closed port: a script that got
past its guard would try to connect and fail with a different exit code.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import urllib.parse
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "provision_test_roles.py"
sys.path.insert(0, str(SCRIPT.parent))
import provision_test_roles as prov  # noqa: E402

# Spelled out, not read from the module, so the refusal cases exercise the
# script's behaviour and do not depend on its constants.
OPT_IN = "EPIGRAPH_PROVISION_TEST_ROLES"


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run(tmp_path: Path, **env_over: str):
    env = {k: v for k, v in os.environ.items()
           if k not in ("GITHUB_ACTIONS", OPT_IN, "TEST_ROLES_DATABASE_URL")}
    env.update(env_over)
    out = tmp_path / "env"
    proc = subprocess.run([sys.executable, str(SCRIPT), "--env-file", str(out)],
                          env=env, capture_output=True, text=True, timeout=60)
    return proc, out


def test_refuses_a_test_database_outside_actions_without_the_opt_in(tmp_path):
    dsn = f"postgres://u:p@127.0.0.1:{closed_port()}/epigraph_py_test"
    proc, out = run(tmp_path, TEST_ROLES_DATABASE_URL=dsn)
    assert proc.returncode == 64, proc.stderr
    assert "opt-in" in proc.stderr
    assert not out.exists()


def test_refuses_a_non_test_database_even_with_the_opt_in(tmp_path):
    dsn = f"postgres://u:p@127.0.0.1:{closed_port()}/epigraph"
    proc, out = run(tmp_path, TEST_ROLES_DATABASE_URL=dsn, **{OPT_IN: "1"})
    assert proc.returncode == 64, proc.stderr
    assert "_test" in proc.stderr
    assert not out.exists()


def test_the_opt_in_passes_the_guard_and_reaches_the_database(tmp_path):
    # The positive control for the two refusals: with the opt-in and a _test
    # name the script gets past the guard and fails only on the closed port.
    dsn = f"postgres://u:p@127.0.0.1:{closed_port()}/epigraph_py_test"
    proc, out = run(tmp_path, TEST_ROLES_DATABASE_URL=dsn, **{OPT_IN: "1"})
    assert proc.returncode not in (0, 64), proc.stderr
    assert not out.exists()


def test_the_login_dsn_keeps_the_fixture_location_and_carries_the_given_password():
    pw = "a/b:c@d"
    dsn = prov.login_dsn("postgres://epigraph:epigraph@db.example:6543/epigraph_py_test", pw)
    parts = urllib.parse.urlsplit(dsn)
    assert parts.username == prov.LOGIN
    assert urllib.parse.unquote(parts.password) == pw
    assert (parts.hostname, parts.port, parts.path) == ("db.example", 6543, "/epigraph_py_test")
