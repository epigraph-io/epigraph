"""The CI Python dependency files are hash-locked, complete and current.

tests/requirements-ci.in lists the direct pins the suites need;
tests/requirements-ci.txt is compiled from it (uv pip compile
--generate-hashes) and holds every package pip installs, each pinned with `==`
and carrying sha256 hashes. The `python` job installs it with
--require-hashes, so a substituted or re-uploaded wheel fails the install
instead of running in CI, and the `audit` job runs pip-audit over it.
tests/requirements-audit.{in,txt} do the same for the pip-audit tool itself,
and scripts/requirements.{in,txt} for the operator scripts on the host that
runs them (backlog 8afe831f).

These tests fail when a pin loses its hash, when a requirement is added to
the compiled file by hand without a hash, or when the `.in` file changes and
the `.txt` is not recompiled.
"""

import re
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]
SCRIPTS = TESTS.parent / "scripts"
CI_LOCK = TESTS / "requirements-ci.txt"
SCRIPTS_LOCK = SCRIPTS / "requirements.txt"
LOCKS = [
    (TESTS / "requirements-ci.in", CI_LOCK),
    (TESTS / "requirements-audit.in", TESTS / "requirements-audit.txt"),
    (SCRIPTS / "requirements.in", SCRIPTS_LOCK),
]
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?==([^\s;\\]+)")
HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}\b")


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def requirements(path):
    """{canonical name: (version, [hashes])} for every requirement in a pip
    requirements file, joining backslash continuations. Raises on a line
    that is not an `==` pin."""
    logical, current = [], ""
    for raw in path.read_text().splitlines():
        line = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("--hash") else raw.rstrip()
        if raw.lstrip().startswith("#") or not line.strip():
            if current:
                logical.append(current)
                current = ""
            continue
        if line.endswith("\\"):
            current += line[:-1] + " "
            continue
        logical.append(current + line)
        current = ""
    if current:
        logical.append(current)

    out = {}
    for entry in logical:
        entry = entry.strip()
        match = PIN.match(entry)
        assert match, "%s: not an == pin: %r" % (path.name, entry)
        name = canonical(match.group(1))
        assert name not in out, "%s: %s pinned twice" % (path.name, name)
        out[name] = (match.group(3), HASH.findall(entry))
    return out


@pytest.mark.parametrize("source,compiled", LOCKS, ids=lambda p: p.name)
def test_every_installed_package_is_pinned_with_hashes(source, compiled):
    reqs = requirements(compiled)
    assert reqs, compiled
    unhashed = sorted(name for name, (_, hashes) in reqs.items() if not hashes)
    assert not unhashed, (
        "%s: pins without --hash (recompile with the command in its header): %s"
        % (compiled.name, ", ".join(unhashed))
    )


@pytest.mark.parametrize("source,compiled", LOCKS, ids=lambda p: p.name)
def test_the_compiled_file_matches_its_source(source, compiled):
    direct = requirements(source)
    locked = requirements(compiled)
    assert direct, source
    stale = sorted(
        "%s==%s (compiled: %s)" % (name, version, locked.get(name, ("missing",))[0])
        for name, (version, _) in direct.items()
        if locked.get(name, (None,))[0] != version
    )
    assert not stale, (
        "%s changed without recompiling %s: %s" % (source.name, compiled.name, "; ".join(stale))
    )


def test_the_parser_rejects_what_the_lock_must_not_contain(tmp_path):
    # Non-vacuity: the checks above read real pins and would see a gap.
    good = "pytest==9.0.2 \\\n    --hash=sha256:" + "a" * 64 + "\n"
    f = tmp_path / "r.txt"
    f.write_text(good + "numpy==1.26.4\n")
    reqs = requirements(f)
    assert reqs["pytest"] == ("9.0.2", ["--hash=sha256:" + "a" * 64])
    assert reqs["numpy"] == ("1.26.4", [])
    f.write_text(good + "numpy>=1.26\n")
    with pytest.raises(AssertionError, match="not an == pin"):
        requirements(f)


def test_the_scripts_lock_is_the_ci_lock_restricted():
    """scripts/requirements.txt installs nothing CI does not test: every
    package it pins, transitive ones included, has the same version and the
    same hashes in tests/requirements-ci.txt. So the scripts run on the
    versions their suites passed on, and the `audit` job's pip-audit over the
    CI lock covers every package the scripts install."""
    ci = requirements(CI_LOCK)
    scripts = requirements(SCRIPTS_LOCK)
    assert scripts, SCRIPTS_LOCK
    drift = sorted(
        "%s==%s (CI: %s)" % (name, version, ci.get(name, ("missing",))[0])
        for name, (version, hashes) in scripts.items()
        if name not in ci or ci[name][0] != version or set(ci[name][1]) != set(hashes)
    )
    assert not drift, (
        "scripts/requirements.txt pins what tests/requirements-ci.txt does not (recompile it "
        "with the -c command in scripts/requirements.in): %s" % "; ".join(drift)
    )
    # The scripts need their own runtime packages and not the test runner.
    for needed in ("requests", "scikit-learn", "numpy", "umap-learn", "psycopg2-binary"):
        assert needed in scripts, needed
    assert "pytest" not in scripts
