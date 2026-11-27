"""Maintenance scripts refuse to start when no database is configured (backlog 62bdae04).

About twenty scripts under `scripts/` used to fall back to a hard-coded DSN
naming a database called `epigraph` on localhost, under one of four role names,
when neither `MAINTENANCE_DATABASE_URL` nor `DATABASE_URL` was set. On a host
that runs a live deployment, a run with a forgotten environment file then wrote
to (or read from) that deployment instead of failing. Every DSN now comes from
the environment or `--database-url`; with neither, the script exits before it
opens a connection.

Three layers, each of which fails on the pre-fix tree:

* the resolver itself (`maintenance_dsn`, `theme_lib.maintenance_dsn`) raises
  instead of returning `None` or a default, and takes no fallback argument;
* a static scan of `scripts/`: no code literal names a database called
  `epigraph`, and no `--database-url` default is computed by calling the
  resolver at parser-build time (which would raise before `--database-url`
  or `--help` could be read);
* the scripts themselves, run with every DSN variable removed and
  `psycopg2.connect` replaced by a tripwire, exit without attempting a
  connection. Nothing here can reach a real database: the tripwire is
  installed before the script is loaded, and on the pre-fix tree it is what
  records the default DSN the script would have used.
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import maintenance_dsn as md  # noqa: E402

DSN_VARS = ("MAINTENANCE_DATABASE_URL", "DATABASE_URL", "DATABASE_ADMIN_URL")


@pytest.fixture
def no_dsn_env(monkeypatch):
    for var in DSN_VARS:
        monkeypatch.delenv(var, raising=False)


# --- the resolver ----------------------------------------------------------


def test_maintenance_dsn_refuses_when_nothing_is_configured(no_dsn_env):
    with pytest.raises(md.NoDatabaseConfigured) as err:
        md.maintenance_dsn()
    # The refusal names both variables and the flag, so the operator knows
    # which one to set.
    msg = str(err.value)
    assert "MAINTENANCE_DATABASE_URL" in msg and "DATABASE_URL" in msg
    assert "--database-url" in msg


def test_theme_lib_binding_refuses_too(no_dsn_env):
    theme_lib = pytest.importorskip("theme_lib")
    with pytest.raises(md.NoDatabaseConfigured):
        theme_lib.maintenance_dsn()
    assert not hasattr(theme_lib, "DEFAULT_DATABASE_URL")


def test_no_dsn_is_a_runtime_error(no_dsn_env):
    # Callers that already handle the database-mismatch refusal (RuntimeError)
    # handle this one the same way.
    assert issubclass(md.NoDatabaseConfigured, RuntimeError)


def test_the_resolver_takes_no_fallback(no_dsn_env):
    """A fallback argument is how the hard-coded defaults got in. With the
    parameter gone, a caller that still passes one fails loudly (TypeError)
    instead of silently connecting to whatever it names."""
    with pytest.raises(TypeError):
        md.maintenance_dsn("postgres://someone@localhost:5432/somewhere")
    theme_lib = pytest.importorskip("theme_lib")
    with pytest.raises(TypeError):
        theme_lib.maintenance_dsn("postgres://someone@localhost:5432/somewhere")


def test_the_precedence_is_unchanged(monkeypatch):
    monkeypatch.delenv("MAINTENANCE_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgres://app@localhost/one_db")
    assert md.maintenance_dsn() == "postgres://app@localhost/one_db"
    monkeypatch.setenv("MAINTENANCE_DATABASE_URL", "postgres://maint@localhost/one_db")
    assert md.maintenance_dsn() == "postgres://maint@localhost/one_db"
    monkeypatch.delenv("DATABASE_URL")
    assert md.maintenance_dsn() == "postgres://maint@localhost/one_db"


# --- static scan of scripts/ -----------------------------------------------

# A URL DSN whose database is exactly `epigraph`, or a key=value DSN naming it.
_LIVE_DB_URL = re.compile(r"postgres(?:ql)?://[^\s'\"/]*/epigraph(?![\w-])")
_LIVE_DB_KV = re.compile(r"\bdbname\s*=\s*epigraph(?![\w-])")


def _python_files():
    # This file is excluded: its calibration samples are the old spellings.
    here = Path(__file__).resolve()
    return sorted(
        p for p in SCRIPTS.rglob("*.py")
        if "__pycache__" not in p.parts and p.resolve() != here
    )


def _docstring_nodes(tree):
    """String constants that are docstrings (module, class, function)."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                out.add(id(body[0].value))
    return out


def _is_resolver_call(node):
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
    return name == "maintenance_dsn"


def test_the_scan_covers_the_script_family():
    files = _python_files()
    names = {p.name for p in files}
    # Calibration: the scan must actually read the scripts it is about.
    assert {"maintenance_dsn.py", "theme_lib.py", "cluster_claims.py", "theme_pipeline.py"} <= names
    assert len(files) > 40, len(files)
    # And its patterns must fire on the spellings that used to be there.
    assert _LIVE_DB_URL.search('X = "postgres://epigraph_admin:epigraph_admin@localhost:5432/epigraph"')
    assert _LIVE_DB_URL.search("postgres://epigraph:epigraph@127.0.0.1:5432/epigraph")
    assert _LIVE_DB_KV.search("dbname=epigraph user=epigraph host=localhost")
    assert not _LIVE_DB_URL.search("postgres://u:p@localhost:5432/epigraph_py_test")


def test_no_script_code_names_a_database_called_epigraph():
    """Docstrings (usage examples) are allowed to; code is not, because a code
    literal is a default something can connect to."""
    findings = []
    for path in _python_files():
        src = path.read_text()
        tree = ast.parse(src, filename=str(path))
        docs = _docstring_nodes(tree)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docs
                and (_LIVE_DB_URL.search(node.value) or _LIVE_DB_KV.search(node.value))
            ):
                findings.append(f"{path.relative_to(REPO)}:{node.lineno}: {node.value!r}")
    assert not findings, "hard-coded DSN defaults:\n" + "\n".join(findings)


def test_no_database_url_default_is_resolved_at_parser_build_time():
    """`add_argument(..., default=maintenance_dsn())` runs the resolver before
    the command line is read, so a refusing resolver would break
    `--database-url X` and `--help`. Resolve after parse_args instead:
    `args.database_url = args.database_url or maintenance_dsn()`."""
    findings = []
    for path in _python_files():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_argument"):
                continue
            for kw in node.keywords:
                if kw.arg == "default" and any(_is_resolver_call(n) for n in ast.walk(kw.value)):
                    findings.append(f"{path.relative_to(REPO)}:{node.lineno}")
    assert not findings, "resolver called in an argparse default:\n" + "\n".join(findings)


# --- the scripts, run with no DSN and a connect tripwire --------------------

_TRIPWIRE = 97
_BOOTSTRAP = r"""
import runpy, sys
import psycopg2

def _tripwire(*args, **kwargs):
    sys.stderr.write("CONNECT-ATTEMPTED\n")
    sys.stderr.flush()
    raise SystemExit(%d)

psycopg2.connect = _tripwire
path = sys.argv[1]
sys.argv = sys.argv[1:]
sys.path.insert(0, %r)
runpy.run_path(path, run_name="__main__")
""" % (_TRIPWIRE, str(SCRIPTS))

# (script, extra argv, text the refusal must contain). Each of these, on the
# pre-fix tree, reaches psycopg2.connect with its hard-coded default.
_SCRIPTS = [
    # Resolved through maintenance_dsn.maintenance_dsn.
    ("audit_mixed_bbas.py", [], "MAINTENANCE_DATABASE_URL"),
    ("audit_claims_content_hash_agent.py", [], "MAINTENANCE_DATABASE_URL"),
    ("backfill_locality_tag.py", [], "MAINTENANCE_DATABASE_URL"),
    ("link_mass_function_evidence.py", [], "MAINTENANCE_DATABASE_URL"),
    # Resolved through theme_lib.maintenance_dsn.
    ("theme_pipeline.py", ["discover"], "MAINTENANCE_DATABASE_URL"),
    # Read-only scripts deliberately NOT on the maintenance DSN: they require
    # DATABASE_URL (or the flag) and never fall back to a role of their own.
    ("subcluster_outliers.py", [], "DATABASE_URL"),
    ("lib/tiered_enrichment.py",
     ["--tier", "1", "--claim-id", "00000000-0000-0000-0000-000000000001"], "--database-url"),
    # Refuses at import: both halves of its read/write split are required.
    ("run_assessment_worker.py", [], "DATABASE_URL"),
]


def _run_without_dsn(script, argv):
    env = {k: v for k, v in os.environ.items() if k not in DSN_VARS and not k.startswith("PG")}
    return subprocess.run(
        [sys.executable, "-c", _BOOTSTRAP, str(SCRIPTS / script), *argv],
        env=env, capture_output=True, text=True, timeout=120, cwd=str(REPO),
    )


@pytest.mark.parametrize("script,argv,needle", _SCRIPTS, ids=[s[0] for s in _SCRIPTS])
def test_the_script_refuses_before_connecting(script, argv, needle):
    proc = _run_without_dsn(script, argv)
    assert "CONNECT-ATTEMPTED" not in proc.stderr and proc.returncode != _TRIPWIRE, (
        f"{script} tried to connect with no DSN configured (a hard-coded default)\n"
        f"{proc.stderr[-2000:]}"
    )
    assert proc.returncode != 0, f"{script} exited 0 with no DSN:\n{proc.stderr[-2000:]}"
    assert needle in proc.stderr, f"{script}'s refusal does not name {needle}:\n{proc.stderr[-2000:]}"


def test_an_explicit_database_url_still_wins():
    """The flag is read: with no environment at all, `--database-url` reaches
    connect (the tripwire), so the refusal is about a MISSING DSN only."""
    proc = _run_without_dsn("audit_mixed_bbas.py",
                            ["--database-url", "postgres://nobody@127.0.0.1:1/never_test"])
    assert "CONNECT-ATTEMPTED" in proc.stderr, proc.stderr[-2000:]
    assert proc.returncode == _TRIPWIRE


def test_tiered_enrichment_claim_lookup_ignores_an_exported_database_url():
    """`--claim-id` reads only the login named on its command line. An exported
    DATABASE_URL (possibly a privileged login set for another job) is not used:
    the lookup refuses before connecting. The pre-62bdae04 code never read the
    variable either; its default was a hard-coded read-only role."""
    env = {k: v for k, v in os.environ.items() if k not in DSN_VARS and not k.startswith("PG")}
    env["DATABASE_URL"] = "postgres://privileged@127.0.0.1:1/never_test"
    proc = subprocess.run(
        [sys.executable, "-c", _BOOTSTRAP, str(SCRIPTS / "lib/tiered_enrichment.py"),
         "--tier", "1", "--claim-id", "00000000-0000-0000-0000-000000000001"],
        env=env, capture_output=True, text=True, timeout=120, cwd=str(REPO),
    )
    assert "CONNECT-ATTEMPTED" not in proc.stderr and proc.returncode != _TRIPWIRE, (
        f"--claim-id connected on DATABASE_URL\n{proc.stderr[-2000:]}"
    )
    assert proc.returncode != 0
    assert "--database-url" in proc.stderr, proc.stderr[-2000:]
