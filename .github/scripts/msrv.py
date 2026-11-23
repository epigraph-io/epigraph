#!/usr/bin/env python3
"""The workspace's declared build floor (MSRV), and the check that every member
declares it (CI helper, stdlib only).

    .github/scripts/msrv.py floor     # prints `version=<rust-version>`; exit 1 on a finding

The floor is `[workspace.package] rust-version` in the root Cargo.toml. Every
`[workspace] members` crate must inherit it (`rust-version.workspace = true`)
or declare the same literal: cargo refuses a toolchain older than a package's
`rust-version` with a clear message, and clippy reads it as the MSRV for its
version-gated lints and for `incompatible_msrv` (a std API newer than the
floor). A member that declares nothing has no MSRV, so neither guard covers
it. The MSRV workflow (.github/workflows/msrv.yml) builds the workspace with
exactly the printed toolchain, so the declared floor cannot drift below what
the lockfile and the code need.

Run from the repository root, or pass the root with `--root <dir>`.
"""

import glob
import os
import sys
import tomllib


def _load(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def members(root, workspace):
    """Member manifest paths, globs expanded the way cargo expands them."""
    out = []
    for pattern in workspace.get("members", []):
        for d in sorted(glob.glob(os.path.join(root, pattern))):
            manifest = os.path.join(d, "Cargo.toml")
            if os.path.isfile(manifest):
                out.append(manifest)
    return out


def check(root):
    """(declared floor or None, [finding, ...]). No findings means every member
    carries the floor."""
    manifest = _load(os.path.join(root, "Cargo.toml"))
    workspace = manifest.get("workspace", {})
    floor = workspace.get("package", {}).get("rust-version")
    findings = []
    if not isinstance(floor, str) or not floor:
        return None, ["root Cargo.toml declares no [workspace.package] rust-version"]
    for path in members(root, workspace):
        package = _load(path).get("package", {})
        declared = package.get("rust-version")
        rel = os.path.relpath(path, root)
        if declared is None:
            findings.append(f"{rel}: no rust-version (add `rust-version.workspace = true`)")
        elif isinstance(declared, dict):
            if declared.get("workspace") is not True:
                findings.append(f"{rel}: rust-version table does not inherit the workspace's")
        elif declared != floor:
            findings.append(f"{rel}: rust-version {declared} differs from the workspace's {floor}")
    return floor, findings


def main(argv):
    args = list(argv[1:])
    root = "."
    if "--root" in args:
        i = args.index("--root")
        root = args[i + 1]
        del args[i : i + 2]
    if args != ["floor"]:
        print(__doc__, file=sys.stderr)
        return 64
    floor, findings = check(root)
    for f in findings:
        print(f"msrv: {f}", file=sys.stderr)
    if findings:
        return 1
    print(f"version={floor}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
