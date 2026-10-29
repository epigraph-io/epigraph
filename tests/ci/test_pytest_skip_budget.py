"""Tests for tests/ci/pytest_skip_budget.py, the python CI job's skip budget.

The job's anti-vacuity guarantee rests on that checker: if it ever returned 0
for a run that skipped or ran nothing, the advisory job would stay green with
its coverage gone. Each case below runs a real pytest in a subprocess on a
throwaway test file, so the JUnit XML the checker reads is the shape pytest
actually writes (module-level collection skips, unittest skips and xfails
included), not a hand-written imitation of it.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest  # noqa: F401  (tmp_path/capsys fixtures)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pytest_skip_budget as budget  # noqa: E402


def junit_for(tmp_path: Path, source: str) -> str:
    """Run pytest on one test file holding `source`; return its JUnit XML path."""
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "test_sample.py").write_text(textwrap.dedent(source))
    xml = tmp_path / "junit.xml"
    env = {k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"}
    subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "--rootdir", str(tmp_path), "-c", str(tmp_path / "pytest.ini"),
         "--junitxml", str(xml), str(tmp_path / "test_sample.py")],
        cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
    )
    assert xml.exists(), "pytest wrote no JUnit XML"
    return str(xml)


ONE_SKIP = """
    import pytest

    def test_runs():
        assert True

    def test_skips():
        pytest.skip("needs a service")
"""


def test_a_skip_on_the_allowlist_passes(tmp_path, capsys):
    xml = junit_for(tmp_path, ONE_SKIP)
    assert budget.main([xml, "--allow", "test_sample::test_skips"]) == 0
    assert "OK (1 allowed skip(s) of 2 tests)" in capsys.readouterr().out


def test_a_skip_outside_the_allowlist_fails_and_is_named(tmp_path, capsys):
    xml = junit_for(tmp_path, ONE_SKIP)
    assert budget.main([xml, "--allow", "test_sample::test_runs"]) == 1
    out = capsys.readouterr().out
    assert "NOT ALLOWED (skip): test_sample::test_skips: needs a service" in out


def test_a_skip_with_no_allowlist_fails(tmp_path):
    assert budget.main([junit_for(tmp_path, ONE_SKIP)]) == 1


def test_an_allowlisted_test_that_ran_is_fine(tmp_path, capsys):
    # The allowlist is a ceiling, not an expectation.
    xml = junit_for(tmp_path, "def test_runs():\n    assert True\n")
    assert budget.main([xml, "--allow", "test_sample::test_runs"]) == 0
    assert "OK (0 allowed skip(s) of 1 tests)" in capsys.readouterr().out


def test_an_empty_run_fails(tmp_path, capsys):
    xml = junit_for(tmp_path, "HELPER = 1\n")
    assert budget.main([xml]) == 1
    assert "has no test cases" in capsys.readouterr().err


def test_a_module_level_collection_skip_fails(tmp_path, capsys):
    # pytest records a module skipped at collection as one testcase with an
    # EMPTY classname and the dotted module path as its name, so its id is
    # "::test_sample". Allowing the module's test functions does not cover it.
    xml = junit_for(tmp_path, """
        import pytest
        pytest.skip("no database driver", allow_module_level=True)

        def test_never_collected():
            assert True
    """)
    assert budget.main([xml, "--allow", "test_sample::test_never_collected"]) == 1
    assert "NOT ALLOWED (skip): ::test_sample: " in capsys.readouterr().out


def test_an_importorskip_fails(tmp_path, capsys):
    xml = junit_for(tmp_path, """
        import pytest
        pytest.importorskip("a_module_that_is_not_installed_anywhere")

        def test_never_collected():
            assert True
    """)
    assert budget.main([xml]) == 1
    assert "NOT ALLOWED (skip): ::test_sample: " in capsys.readouterr().out


def test_a_module_level_skip_can_be_allowed_by_its_module_id(tmp_path):
    xml = junit_for(tmp_path, """
        import pytest
        pytest.skip("no database driver", allow_module_level=True)
    """)
    assert budget.main([xml, "--allow", "::test_sample"]) == 0


def test_a_unittest_skiptest_is_identified_by_module_and_class(tmp_path):
    # The shape of the job's real skips (test_git_ingest_reconciler.py is a
    # unittest.TestCase): classname is module.Class.
    source = """
        import unittest

        class Integration(unittest.TestCase):
            def test_binary(self):
                self.skipTest("binary not built")
    """
    xml = junit_for(tmp_path, source)
    assert budget.main([xml]) == 1
    assert budget.main([xml, "--allow", "test_sample.Integration::test_binary"]) == 0


XFAIL = """
    import pytest

    @pytest.mark.xfail(reason="known regression")
    def test_expected_to_fail():
        assert False
"""


def test_an_xfail_counts_against_the_budget_and_is_labelled_xfail(tmp_path, capsys):
    # JUnit writes an xfail as <skipped type="pytest.xfail">. The assertion did
    # not hold, so it is lost coverage like a skip and needs an --allow entry;
    # the report says "xfail" so the failure message is not a misleading "skip".
    xml = junit_for(tmp_path, XFAIL)
    assert budget.main([xml]) == 1
    assert "NOT ALLOWED (xfail): test_sample::test_expected_to_fail: known regression" in (
        capsys.readouterr().out
    )


def test_an_allowlisted_xfail_passes(tmp_path):
    xml = junit_for(tmp_path, XFAIL)
    assert budget.main([xml, "--allow", "test_sample::test_expected_to_fail"]) == 0


def test_a_failing_test_is_not_the_checkers_business(tmp_path):
    # pytest's own exit code fails the step on a failure; the checker only
    # judges skips, so a failure with no skips is within budget.
    xml = junit_for(tmp_path, "def test_breaks():\n    assert False\n")
    assert budget.main([xml]) == 0


def test_skipped_tests_counts_every_case_and_kinds_each_skip(tmp_path):
    total, skipped = budget.skipped_tests(junit_for(tmp_path, ONE_SKIP + XFAIL))
    assert total == 3
    assert [(t, k) for t, k, _ in skipped] == [
        ("test_sample::test_skips", "skip"),
        ("test_sample::test_expected_to_fail", "xfail"),
    ]
