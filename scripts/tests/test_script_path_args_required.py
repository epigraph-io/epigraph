"""The input/output path of four scripts is a required argument (backlog d65e1279).

fuzzy_dedup_claims.py (--input), compute_semantic_dedup.py (--output),
extract_html.py and extract_textbook.py (--output) used to default these
paths to one developer's home directory or a sibling checkout. Run anywhere
else without the flag, they read a file that is not there or wrote into a
directory nobody chose. Now argparse refuses the run (exit 2, naming the flag)
before anything is read, connected to or written.

Each run below is boxed in so that a regression cannot do damage while it
fails: the database variables are removed from the environment,
psycopg2.connect raises, and pathlib's mkdir/write_text raise. The extract
scripts get an input that does not exist.
"""
import contextlib
import io
import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
sys.path.insert(0, str(SCRIPTS))
import compute_semantic_dedup  # noqa: E402
import extract_html  # noqa: E402
import extract_textbook  # noqa: E402
import fuzzy_dedup_claims  # noqa: E402

MISSING = "/nonexistent/d65e1279"

# (module, argv without the path flag, the flag argparse must name)
CASES = [
    (fuzzy_dedup_claims, ["fuzzy_dedup_claims.py"], "--input"),
    (compute_semantic_dedup, ["compute_semantic_dedup.py"], "--output"),
    (extract_html, ["extract_html.py", f"{MISSING}/page.html", "--from-file"], "--output"),
    (extract_textbook, ["extract_textbook.py", MISSING], "--output"),
]


def _refuse(*_args, **_kwargs):
    raise AssertionError("the run got past argument parsing and tried to connect or write")


class PathArgumentsAreRequired(unittest.TestCase):
    def test_a_run_without_the_path_flag_is_refused_by_the_parser(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("MAINTENANCE_DATABASE_URL", "DATABASE_URL")}
        for module, argv, flag in CASES:
            with self.subTest(script=argv[0]):
                stderr = io.StringIO()
                with contextlib.ExitStack() as stack:
                    stack.enter_context(mock.patch.dict(os.environ, env, clear=True))
                    stack.enter_context(mock.patch.object(sys, "argv", argv))
                    stack.enter_context(mock.patch("psycopg2.connect", _refuse))
                    stack.enter_context(mock.patch.object(Path, "mkdir", _refuse))
                    stack.enter_context(mock.patch.object(Path, "write_text", _refuse))
                    stack.enter_context(contextlib.redirect_stderr(stderr))
                    with self.assertRaises(SystemExit) as cm:
                        module.main()
                self.assertEqual(cm.exception.code, 2, stderr.getvalue())
                self.assertRegex(
                    stderr.getvalue(),
                    rf"the following arguments are required: .*{re.escape(flag)}\b",
                )

    def test_the_scripts_name_no_home_directory(self):
        for _module, argv, _flag in CASES:
            with self.subTest(script=argv[0]):
                source = (SCRIPTS / argv[0]).read_text(encoding="utf-8")
                self.assertNotIn("/home/", source)


if __name__ == "__main__":
    unittest.main()
