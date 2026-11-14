#!/usr/bin/env python3
"""Plan and select the `test` shards of .github/workflows/ci.yml.

The Rust suite used to run as one job: six `cargo test` steps, one after the
other, on one runner (about 200 minutes). It now runs as one job per shard,
each with its own Postgres service container. This script is the single source
of truth for what the shards are and which test targets each one runs, so the
workflow matrix, the per-shard `cargo test` arguments and the coverage check
cannot drift apart.

    test-shard.py matrix               JSON matrix for `strategy.matrix`
    test-shard.py args <shard-id>      cargo arguments for one shard
    test-shard.py doc <shard-id>       the package whose doc tests the shard runs,
                                       or nothing
    test-shard.py check                prove the shards cover every target once

A sharded package's integration-test binaries are sorted by name and dealt
round-robin across its shards; shard 1 also takes the package's unit tests
(`--lib --bins`) and its doc tests. Nothing about how a binary runs changes:
the same `--test-threads`, the same order within a shard, a fresh migrated
database per shard exactly as the single job had one fresh database.

A test target whose `required-features` are not all enabled by the package's
default features is NOT run by a plain `cargo test -p <package>` either, so it
is left out here and listed by `check`; such targets need their own step with
the feature enabled (see the `lint-features` job).
"""

import json
import subprocess
import sys

# Packages whose tests need the shared, migrated DATABASE_URL database or are
# simply too long for one job. `threads` is passed as `--test-threads`; see the
# comments in ci.yml for why each package has the value it has.
SHARDED = [
    # (package, shards, test threads)
    ("epigraph-cli", 2, 1),
    ("epigraph-db", 2, 4),
    ("epigraph-api", 4, 1),
    ("epigraph-mcp", 3, 1),
]
# Packages small enough to share one job, run by one `cargo test` invocation.
GROUPED = [
    ("engine-embeddings", ["epigraph-engine", "epigraph-embeddings"], 1),
]
# Every other workspace member runs in the `workspace-rest` shard, selected by
# exclusion so that a crate added to the workspace is tested without anyone
# having to remember to list it here.


def metadata():
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return {p["name"]: p for p in json.loads(out)["packages"]}


def default_features(pkg):
    """The feature names a plain build of `pkg` enables."""
    features = pkg["features"]
    seen, todo = set(), ["default"]
    while todo:
        name = todo.pop()
        if name in seen or name not in features:
            continue
        seen.add(name)
        todo.extend(f for f in features[name] if ":" not in f and "/" not in f)
    seen.discard("default")
    return seen


def targets(pkg):
    """(runnable test-target names, [(name, missing features)], has_lib, has_bins)."""
    enabled = default_features(pkg)
    runnable, skipped = [], []
    has_lib = has_bins = False
    for t in pkg["targets"]:
        missing = sorted(set(t.get("required-features") or []) - enabled)
        if "test" in t["kind"]:
            if missing:
                skipped.append((t["name"], missing))
            else:
                runnable.append(t["name"])
        elif "lib" in t["kind"] or "proc-macro" in t["kind"]:
            has_lib = True
        elif "bin" in t["kind"] and not missing:
            has_bins = True
    return sorted(runnable), skipped, has_lib, has_bins


def plan(pkgs):
    """Every shard: id -> description dict."""
    shards = {}
    excluded = []
    for package, total, threads in SHARDED:
        runnable, _skipped, has_lib, has_bins = targets(pkgs[package])
        excluded.append(package)
        for i in range(total):
            mine = [t for j, t in enumerate(runnable) if j % total == i]
            args = ["-p", package]
            if i == 0:
                if has_lib:
                    args.append("--lib")
                if has_bins:
                    args.append("--bins")
            for t in mine:
                args += ["--test", t]
            shards[f"{package.removeprefix('epigraph-')}-{i + 1}of{total}"] = {
                "package": package,
                "args": args,
                "doc": i == 0 and has_lib,
                "threads": threads,
                "tests": mine,
                "cache": package,
            }
    for name, members, threads in GROUPED:
        excluded += members
        args = []
        for m in members:
            args += ["-p", m]
        shards[name] = {
            "package": " ".join(members),
            "args": args,
            "doc": False,  # a plain `cargo test -p` already runs doc tests
            "threads": threads,
            "tests": None,
            "cache": name,
        }
    rest = ["--workspace"]
    for e in excluded:
        rest += ["--exclude", e]
    shards["workspace-rest"] = {
        "package": "workspace-rest",
        "args": rest,
        "doc": False,
        "threads": 1,
        "tests": None,
        "cache": "workspace-rest",
    }
    return shards


def check(pkgs, shards):
    ok = True
    for package, total, _threads in SHARDED:
        runnable, skipped, has_lib, has_bins = targets(pkgs[package])
        mine = [s for s in shards.values() if s["package"] == package]
        dealt = [t for s in mine for t in s["tests"]]
        if sorted(dealt) != runnable:
            ok = False
            print(f"FAIL {package}: shards do not cover the test targets exactly once")
            print("  missing:", sorted(set(runnable) - set(dealt)))
            print("  repeated:", sorted({t for t in dealt if dealt.count(t) > 1}))
        first = mine[0]["args"]
        if has_lib and "--lib" not in first:
            ok = False
            print(f"FAIL {package}: unit tests (--lib) are in no shard")
        if has_bins and "--bins" not in first:
            ok = False
            print(f"FAIL {package}: binary unit tests (--bins) are in no shard")
        sizes = "/".join(str(len(s["tests"])) for s in mine)
        print(f"ok   {package}: {len(runnable)} test targets in {total} shards ({sizes})")
        for name, missing in skipped:
            print(f"     not run here: {name} (needs feature {', '.join(missing)})")
    named = {p for p, _, _ in SHARDED} | {m for _, ms, _ in GROUPED for m in ms}
    unknown = sorted(named - set(pkgs))
    if unknown:
        ok = False
        print("FAIL: not workspace members:", unknown)
    rest = sorted(set(pkgs) - named)
    print(f"ok   workspace-rest: {len(rest)} packages by exclusion ({', '.join(rest)})")
    return ok


def main(argv):
    if len(argv) < 2 or argv[1] not in ("matrix", "args", "doc", "check"):
        print(__doc__, file=sys.stderr)
        return 2
    pkgs = metadata()
    shards = plan(pkgs)
    mode = argv[1]
    if mode == "check":
        return 0 if check(pkgs, shards) else 1
    if mode == "matrix":
        # `save`: only one shard per cache key writes the dependency cache.
        seen = set()
        include = []
        for sid, s in shards.items():
            include.append(
                {
                    "shard": sid,
                    "threads": s["threads"],
                    "cache": s["cache"],
                    "save": s["cache"] not in seen,
                }
            )
            seen.add(s["cache"])
        print(json.dumps({"include": include}))
        return 0
    if len(argv) != 3 or argv[2] not in shards:
        print(f"unknown shard; known: {', '.join(shards)}", file=sys.stderr)
        return 2
    shard = shards[argv[2]]
    if mode == "args":
        print(" ".join(shard["args"]))
    else:
        print(shard["package"] if shard["doc"] else "")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
