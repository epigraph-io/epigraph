"""Run an operator script hermetically, with every database/ML dependency stubbed.

Used by `test_no_default_database.py` to prove, end to end, that a script
started with no DSN in its environment refuses BEFORE it opens a connection.
The static half of that rule is `crates/epigraph-db/tests/scripts_have_no_default_dsn.rs`;
this is the behavioural half, and it exists because the static half cannot see
the trap that matters most: handing `None` to the driver does not raise. libpq
falls back to PG* environment variables, `.pgpass` and a database named after
the OS user, so a script that "has no default" can still reach a local
`epigraph` database silently.

Invoked as:

    python3 _offline_script_harness.py <script path> [script args...]

The stubbed driver's connect entry point never touches a socket. It writes the
DSN it was handed to stderr after `REACHED_CONNECT_MARKER` and exits with
`REACHED_CONNECT_EXIT`, so a test can tell "refused up front" from "got as far
as connecting". Every other attribute of a stubbed module is an inert,
permissive placeholder, which is enough for these scripts to import and parse
their arguments; nothing past the connect call is expected to work.

Stubs are installed ahead of the real finders on purpose: this must never reach
a real database, even on a machine where the real driver is installed.
"""
import importlib.abc
import importlib.machinery
import os
import runpy
import sys
import types

REACHED_CONNECT_MARKER = "OFFLINE-HARNESS: reached the driver's connect with dsn="
REACHED_CONNECT_EXIT = 97

# Top-level names whose import is intercepted: the database driver, and the
# third-party packages these scripts import at top level. Nothing from the
# standard library is stubbed.
STUBBED = {
    "psycopg2",
    "numpy",
    "umap",
    "sklearn",
    "requests",
    "jwt",
    "anthropic",
    "httpx",
}


class _Inert:
    """Absorbs any use a module-level statement might make of a stubbed name."""

    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return self

    def __call__(self, *args, **kwargs):
        return self

    def __getitem__(self, key):
        return self

    def __iter__(self):
        return iter(())

    def __or__(self, other):
        return self

    __ror__ = __or__


_INERT = _Inert()


class _DriverError(Exception):
    """Stands in for the driver's exception hierarchy in `except` clauses."""


def _reached_connect(*args, **kwargs):
    dsn = args[0] if args else kwargs.get("dsn")
    sys.stderr.write(f"{REACHED_CONNECT_MARKER}{dsn!r}\n")
    sys.stderr.flush()
    os._exit(REACHED_CONNECT_EXIT)


class _StubModule(types.ModuleType):
    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return _INERT


class _StubLoader(importlib.abc.Loader):
    def create_module(self, spec):
        module = _StubModule(spec.name)
        module.__path__ = []  # a package, so `import psycopg2.extras` resolves
        if spec.name == "psycopg2":
            module.connect = _reached_connect
            for exc in ("Error", "DatabaseError", "OperationalError", "InterfaceError",
                        "IntegrityError", "ProgrammingError"):
                setattr(module, exc, _DriverError)
        return module

    def exec_module(self, module):
        return None


class _StubFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname.split(".", 1)[0] in STUBBED:
            return importlib.machinery.ModuleSpec(fullname, _StubLoader(), is_package=True)
        return None


def run(script, argv):
    sys.meta_path.insert(0, _StubFinder())
    script = os.path.abspath(script)
    # Match `python3 scripts/foo.py`: the script's own directory is sys.path[0],
    # which is what lets `from maintenance_dsn import ...` resolve.
    sys.path.insert(0, os.path.dirname(script))
    sys.argv = [script, *argv]
    runpy.run_path(script, run_name="__main__")


if __name__ == "__main__":
    run(sys.argv[1], sys.argv[2:])
