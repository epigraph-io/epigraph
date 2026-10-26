#!/usr/bin/env python3
"""Fail a CI pytest step whose run skipped a test that is not on its allowlist.

`pytest -rs` lists skips but passes with them, so a test that skips for an
environmental reason (a binary not found, a database not provisioned, a missing
env var) leaves the step green with that coverage silently gone. The `python`
job in .github/workflows/ci.yml runs each suite with `--junitxml` and then this
checker, naming the skips it expects; any other skip fails the step.

usage: pytest_skip_budget.py <junit.xml> [--allow <classname>::<name>]...

A test is identified as it appears in the JUnit XML: its `classname` (the
dotted module path, plus the class for unittest/class-based tests) and its
`name`, joined by `::`. An allowed test that did not skip is fine: the
allowlist is a ceiling, not an expectation. A run with no test cases fails,
since an empty run is the other way a suite can pass while running nothing.
Standard library only, so it runs before or without the test venv.
"""
from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET


def skipped_tests(junit_path: str) -> tuple[int, list[tuple[str, str]]]:
    """Return (number of test cases, [(test id, skip message)] for skipped ones)."""
    root = ET.parse(junit_path).getroot()
    total = 0
    skipped = []
    for case in root.iter("testcase"):
        total += 1
        skip = case.find("skipped")
        if skip is None:
            continue
        test_id = f"{case.get('classname', '')}::{case.get('name', '')}"
        message = (skip.get("message") or "").strip().splitlines()
        skipped.append((test_id, message[0] if message else ""))
    return total, skipped


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("junit")
    ap.add_argument("--allow", action="append", default=[], metavar="CLASSNAME::NAME")
    args = ap.parse_args(argv)

    total, skipped = skipped_tests(args.junit)
    if total == 0:
        print(f"skip budget: {args.junit} has no test cases", file=sys.stderr)
        return 1
    allowed = set(args.allow)
    over = [(t, m) for t, m in skipped if t not in allowed]
    for t, m in skipped:
        tag = "allowed" if t in allowed else "NOT ALLOWED"
        print(f"skip budget: {tag}: {t}: {m}")
    if over:
        print(
            f"skip budget: {len(over)} skip(s) outside the allowlist "
            f"({len(skipped)} skipped of {total})",
            file=sys.stderr,
        )
        return 1
    print(f"skip budget: OK ({len(skipped)} allowed skip(s) of {total} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
