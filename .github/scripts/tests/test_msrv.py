"""Tests for .github/scripts/msrv.py: the declared build floor and the check
that every workspace member carries it.

Run from the repository root (the `plan` job does):

    python3 -m unittest discover -s .github/scripts/tests -v

MSRV_SCRIPT points the tests at another revision of the script, and MSRV_ROOT
at another checkout (the live-repository test reads its manifests).
"""

import importlib.util
import os
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.environ.get("MSRV_SCRIPT") or os.path.join(HERE, "..", "msrv.py")
ROOT = os.environ.get("MSRV_ROOT") or os.path.join(HERE, "..", "..", "..")


def load():
    spec = importlib.util.spec_from_file_location("msrv", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


msrv = load()


def write(root, rel, body):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(textwrap.dedent(body))


WORKSPACE = """\
    [workspace]
    members = ["crates/a", "crates/b"]

    [workspace.package]
    rust-version = "1.88"
    """


def member(name, extra=""):
    return f"""\
    [package]
    name = "{name}"
    version = "0.1.0"
    {extra}
    """


class LiveRepository(unittest.TestCase):
    def test_every_member_inherits_the_declared_floor(self):
        floor, findings = msrv.check(ROOT)
        self.assertEqual(findings, [], "every workspace member must carry the floor")
        self.assertIsNotNone(floor)

    def test_the_floor_is_not_below_what_the_locked_dependencies_declare(self):
        # rmcp 3.9, time 0.3.47, jsonwebtoken 10.4, webauthn-rs 0.5.5 and
        # serde_with 3.21 in Cargo.lock all declare rust-version 1.88; a floor
        # below that is one no toolchain at it can build (the MSRV workflow
        # proves the build; this pins the number it starts from).
        floor, _ = msrv.check(ROOT)
        self.assertGreaterEqual(
            tuple(int(p) for p in floor.split(".")), (1, 88), f"declared floor {floor}"
        )


class Fixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        write(self.root, "Cargo.toml", WORKSPACE)

    def tearDown(self):
        self.tmp.cleanup()

    def test_inheriting_members_pass(self):
        write(self.root, "crates/a/Cargo.toml", member("a", "rust-version.workspace = true"))
        write(self.root, "crates/b/Cargo.toml", member("b", 'rust-version = "1.88"'))
        self.assertEqual(msrv.check(self.root), ("1.88", []))
        self.assertEqual(msrv.main(["msrv.py", "--root", self.root, "floor"]), 0)

    def test_a_member_without_rust_version_is_a_finding(self):
        write(self.root, "crates/a/Cargo.toml", member("a", "rust-version.workspace = true"))
        write(self.root, "crates/b/Cargo.toml", member("b"))
        floor, findings = msrv.check(self.root)
        self.assertEqual(floor, "1.88")
        self.assertEqual(len(findings), 1)
        self.assertIn("crates/b/Cargo.toml", findings[0])
        self.assertEqual(msrv.main(["msrv.py", "--root", self.root, "floor"]), 1)

    def test_a_member_with_a_different_literal_is_a_finding(self):
        write(self.root, "crates/a/Cargo.toml", member("a", 'rust-version = "1.75"'))
        write(self.root, "crates/b/Cargo.toml", member("b", "rust-version.workspace = true"))
        _, findings = msrv.check(self.root)
        self.assertEqual(len(findings), 1)
        self.assertIn("1.75", findings[0])

    def test_no_workspace_floor_is_a_finding(self):
        write(self.root, "Cargo.toml", '[workspace]\nmembers = ["crates/a"]\n')
        write(self.root, "crates/a/Cargo.toml", member("a"))
        floor, findings = msrv.check(self.root)
        self.assertIsNone(floor)
        self.assertEqual(len(findings), 1)

    def test_member_globs_are_expanded(self):
        write(self.root, "Cargo.toml", WORKSPACE.replace('"crates/a", "crates/b"', '"crates/*"'))
        write(self.root, "crates/a/Cargo.toml", member("a", "rust-version.workspace = true"))
        write(self.root, "crates/b/Cargo.toml", member("b"))
        _, findings = msrv.check(self.root)
        self.assertEqual([f.split(":")[0] for f in findings], ["crates/b/Cargo.toml"])


if __name__ == "__main__":
    unittest.main()
