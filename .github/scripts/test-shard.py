#!/usr/bin/env python3
"""Plan and select the `test` shards of .github/workflows/ci.yml.

The Rust suite used to run as one job: six `cargo test` steps, one after the
other, on one runner (about 200 minutes). It now runs as one job per shard,
each with its own Postgres service container. This script is the single source
of truth for what the shards are and which test targets each one runs, so the
workflow matrix, the per-shard `cargo test` arguments and the coverage check
cannot drift apart.

    test-shard.py matrix               JSON matrix for `strategy.matrix` (every shard)
    test-shard.py matrix --base REF    the same, holding only the shards that a
                                       change since REF affects (see below),
                                       uncommitted and untracked files included
    test-shard.py affected [--base] REF  that matrix on stdout, and why each
                                       shard was selected on stderr
    test-shard.py args <shard-id>      cargo arguments for one shard
    test-shard.py doc <shard-id>       the package whose doc tests the shard runs,
                                       or nothing
    test-shard.py check                prove the shards cover every target once,
                                       and that every whole-tree source scan is
                                       declared in WALKERS
    test-shard.py ci-plan              the `plan` job: GITHUB_OUTPUT lines for
                                       this event (matrix, run flags, runner)
    test-shard.py gate                 the `test` job: fail unless every job the
                                       plan asked for succeeded
    test-shard.py scan-args <targets>  the source-scans shard's cargo invocations,
                                       one "<threads> <args>" line per package

A sharded package's integration-test binaries are sorted by name and dealt
round-robin across its shards; shard 1 also takes the package's unit tests
(`--lib --bins`) and its doc tests. Nothing about how a binary runs changes:
the same `--test-threads`, the same order within a shard, a fresh migrated
database per shard exactly as the single job had one fresh database.

A test target whose `required-features` are not all enabled by the package's
default features is NOT run by a plain `cargo test -p <package>` either, so it
is left out here and listed by `check`; such targets need their own step with
the feature enabled (see the `lint-features` job).

AFFECTED SHARDS. On a pull request the plan holds only the shards whose
packages the change can affect, so a one-crate change does not occupy a
runner per shard of every package (the org's runner cap is shared by every
PR). A package is affected when

  * a file under its directory changed. Outside `tests/`, `benches/` and
    `examples/` that is a change to what its dependents compile, so every
    workspace package that depends on it, transitively and including
    dev-dependencies, is affected too;
  * its sources read a changed file from outside its own directory. Many
    tests here are source scans (ratchets) that read another crate's source,
    a migration, a runbook or `calibration.toml`. `scan_reads` finds those
    reads from the string literals in the package's sources, so a new one is
    picked up without an edit here. A read by library or binary code (in
    `src/`, before any `#[cfg(test)]`) changes what the package does, so it
    reaches dependents too; a read by a unit test runs the whole package; a
    read by an integration-test target (or a helper module that targets
    declare with `mod <name>;`) runs ONLY those targets, all of them together
    in one `source-scans` shard, unless a selected shard already runs that
    package in full. A scan that WALKS a directory it reaches by climbing out
    of its crate cannot be resolved from literals: it must be declared in
    WALKERS, and `check` fails on one that is not. A test that any deleted
    path can break, wherever it is (doc_links: a link may target any file),
    is declared in DELETION_READERS, and every path the change deletes or
    renames away counts as a read of it.

Every shard runs (FULL) when the change touches a path in FULL_PATHS (a
migration changes every database test; the lock file, the toolchain or this
script change everything), on any event but `pull_request`, on a pull request
from a branch in FULL_BRANCHES (the staging and integration PRs, where the
whole suite belongs), with the FULL_LABEL label, or when the diff cannot be
computed. Whatever is selected, `check` always runs over the full plan.

LIGHT PLAN (operator ruling 2026-11-27, "light CI on fix PRs"). A pull
request from a branch in LIGHT_BRANCHES (the backlog burndown's
`fix/triage-*` PRs) runs neither every shard nor the affected ones: its plan
holds only the `source-scans` shard over LIGHT_TARGETS, the cross-crate
ratchets and registers that parallel burndown PRs break, and turns off every
other gated job (`test-extra`, `lint-features`, and the ci.yml jobs that
read the plan's `mode` output). The diff is not consulted, so a migration or a
`.github/` change on such a head is still light. These PRs reach `main` only
through a staging PR (FULL_BRANCHES), whose full run is the authoritative
one. The FULL_LABEL label still runs every shard on a light head. `check`
fails if a LIGHT_TARGETS entry is not a test target of its package.
"""

import fnmatch
import json
import os
import posixpath
import re
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

# --- What a change can affect (see AFFECTED SHARDS in the module docstring) ---

# A changed path under one of these prefixes, or equal to one of these files,
# runs every shard. `migrations/` changes every database test; `.github/`
# holds this script, its tests and the workflow; the rest change what every
# crate compiles against. Only the ROOT Cargo.toml is listed: a crate's own
# manifest is a change to that crate.
FULL_PATHS = ("migrations/", ".github/", ".sqlx/", ".cargo/")
FULL_FILES = ("Cargo.lock", "Cargo.toml")
FULL_GLOBS = ("rust-toolchain*",)
# Pull requests from these head branches run every shard: they are the
# staging and integration PRs, where the operator's rule puts the
# whole-package suites. fnmatch: `*` also matches `/`.
FULL_BRANCHES = ("integration/*", "staging/*", "backlog/base-*", "atlas/*-base")
# A pull request carrying this label runs every shard.
FULL_LABEL = "ci:full"
# The events that run every shard. Anything else that is not `pull_request`
# also runs every shard: an unknown event is never narrowed.
FULL_EVENTS = ("push", "merge_group", "workflow_dispatch", "schedule")
# Pull requests from these head branches get the LIGHT plan (see LIGHT PLAN in
# the module docstring): the backlog burndown's fix PRs, which reach main only
# through a staging PR. fnmatch, as FULL_BRANCHES.
LIGHT_BRANCHES = ("fix/triage-*",)
# What the light plan runs, in the `source-scans` shard: the ratchets and
# registers that a parallel burndown PR most often breaks (the ones the staging
# runs of 2026-11-23..27 had to re-derive or fix), all source scans or catalog
# checks that run in seconds once built. Their cost is compiling five
# packages' test targets, not running them. A name here that is not a test
# target of its package fails `check`, so a renamed ratchet fails `plan`
# instead of the shard.
LIGHT_TARGETS = {
    "epigraph-api": (
        "no_inline_sql_in_routes",
        "router_extension_seam_lint",
        "viewer_route_table_lint",
        "viewer_spend_lint",
    ),
    "epigraph-db": (
        "bba_retract_read_lint",
        "definer_search_path_ratchet",
        "edge_writer_signing_ratchet",
        "maintenance_surface_register",
        "no_unscoped_pool",
        "personal_group_mint_ratchet",
        "refusal_code_coverage",
        "tenancy_coverage",
        "viewer_ratchet",
        "visibility_act_callers_ratchet",
        "visibility_lint",
        "write_gate_lint",
    ),
    "epigraph-engine": ("belief_fold_literal_ratchet", "viewer_calls_register"),
    "epigraph-ingest-executor": ("viewer_calls_register",),
    "epigraph-mcp": (
        "no_inline_sql_in_tools",
        "raw_pool_register",
        "tool_viewer_coverage",
        "write_identity_ratchet",
    ),
}
# A change under these directories of a package is visible to that package's
# own tests only: no dependent compiles them.
LOCAL_ONLY = ("tests/", "benches/", "examples/")

# Source scans that walk a directory reached by climbing out of their crate,
# with the paths they read that their string literals do not already name.
# `scan_reads` flags such a file (a climb to the repository root or to
# `crates/`, or `.parent()` on CARGO_MANIFEST_DIR, plus a directory walk) and
# `check` fails unless it is listed here, so a new whole-tree ratchet cannot
# silently go unrun on the pull requests it constrains. Globs are fnmatch: `*`
# also matches `/`. An empty tuple says the literal roots the scan names
# (already found by `scan_reads`) are all it walks.
WALKERS = {
    # api's own src is a change to api, so only the other crates are listed.
    "crates/epigraph-api/tests/admin_scope_literals.rs": (
        "crates/epigraph-mcp/src/*",
        "crates/epigraph-auth/src/*",
    ),
    "crates/epigraph-api/tests/delegated_run_token_viewer.rs": ("crates/epigraph-mcp/src/*",),
    # Every listed crate's src and manifest, and the workspace manifest: the
    # crate-layering register (#1163).
    "crates/epigraph-api/tests/crate_layering_ratchet.rs": ("crates/*/src/*", "*Cargo.toml"),
    # `Viewer::public_only` is built only in routes/guest.rs: every crate's src.
    # The API's error texts, and the engine error collections it serves.
    "crates/epigraph-api/tests/error_text_ratchet.rs": ("crates/*/src/*",),
    "crates/epigraph-api/tests/guest_public_reads.rs": ("crates/*/src/*",),
    # Only provider provisioning may mint a `<provider>:<subject>` client id:
    # every `OAuthClientRepository::create(` caller under these crates' src.
    "crates/epigraph-api/tests/identity_provisioning.rs": (
        "crates/epigraph-cli/src/*",
        "crates/epigraph-db/src/*",
        "crates/epigraph-mcp/src/*",
    ),
    "crates/epigraph-api/tests/no_redaction_sentinel.rs": ("crates/*/src/*",),
    # No retired OAuth scope literal in any crate's src outside the two
    # RETIRED_SCOPES lists (backlog 7b2e8e26).
    "crates/epigraph-api/tests/retired_scopes.rs": ("crates/*/src/*",),
    # Every `<name>.timer` named under crates/*/src must have its unit file in
    # deploy/systemd/, which it also walks (backlog 21be383b).
    "crates/epigraph-cli/tests/maintenance_units.rs": ("crates/*/src/*", "deploy/systemd/*"),
    # README.md, docs/README.md, docs/intro/*.md and the names under docs/,
    # docs/architecture and docs/audits (the index must link every entry under
    # docs/; a dated audit lives in docs/audits). A link TARGET elsewhere can
    # be anywhere in the tree; deleting or renaming one is DELETION_READERS'
    # job.
    "crates/epigraph-core/tests/doc_links.rs": ("README.md", "docs/*"),
    # Every `#[ignore]` under a member's src/ or tests/. Not `crates/*/tests/*`:
    # that would put source-scans on every test-only change. A new `#[ignore]`
    # in a test file is caught by a full run (main, staging, `ci:full`).
    "crates/epigraph-core/tests/ignored_tests_have_a_lane.rs": (
        "crates/*/src/*",
        "tests/engine-integration/*",
    ),
    # Every member's manifest: crates/ and tests/engine-integration.
    "crates/epigraph-core/tests/workspace_layout.rs": ("crates/*/Cargo.toml", "tests/*/Cargo.toml"),
    "crates/epigraph-crypto/tests/entity_signing_sites.rs": ("crates/*/src/*",),
    # Every read of agent identity columns in every crate's src.
    "crates/epigraph-db/tests/agent_name_disclosure_lint.rs": ("crates/*/src/*",),
    "crates/epigraph-db/tests/belief_lint/mod.rs": ("crates/*/src/*", "scripts/*"),
    "crates/epigraph-db/tests/custodian_role.rs": ("crates/*/src/*",),
    "crates/epigraph-db/tests/edge_writer_signing_ratchet.rs": ("crates/*/src/*",),
    "crates/epigraph-db/tests/elevated_access.rs": ("migrations/*",),
    # Every Cargo.toml in the repository.
    "crates/epigraph-db/tests/locked_decisions.rs": ("*Cargo.toml",),
    "crates/epigraph-db/tests/maintenance_surface_register.rs": (),
    "crates/epigraph-db/tests/no_hybrid_bypass_spend.rs": (),
    # It walks `repo_root().join("scripts")` for *.py files.
    "crates/epigraph-db/tests/no_unmaintained_dsn.rs": ("scripts/*",),
    "crates/epigraph-db/tests/no_unscoped_pool.rs": (),
    "crates/epigraph-db/tests/owner_scoped_delete.rs": ("crates/*/src/*",),
    "crates/epigraph-db/tests/personal_group_mint_ratchet.rs": ("crates/*/src/*", "migrations/*"),
    # Every coded refusal in every crate's src against the refusal_codes
    # registry (#1168).
    "crates/epigraph-db/tests/refusal_code_matches_ratchet.rs": ("crates/*/src/*",),
    "crates/epigraph-db/tests/schema_contract.rs": (),
    # Every vector writer in every crate's src.
    "crates/epigraph-db/tests/sealed_vector_writer_ratchet.rs": ("crates/*/src/*",),
    "crates/epigraph-db/tests/system_agent_single_resolver.rs": ("crates/*/src/*",),
    "crates/epigraph-db/tests/tenancy_migration_shape.rs": (),
    "crates/epigraph-db/tests/unstamped_http_edge_writes.rs": (),
    # Every file of that name anywhere in the tree.
    "crates/epigraph-db/tests/viewer_fixture_single_source.rs": ("*viewer_fixture.rs",),
    # Every Rust source under crates/ and the workspace tests/ (backlog triage T04).
    "crates/epigraph-db/tests/visibility_act_callers_ratchet.rs": ("crates/*.rs", "tests/*.rs"),
    # One pgvector formatter and one embedding client: scans every production
    # source under crates/*/src and services/*/src.
    "crates/epigraph-embeddings/tests/embedding_stack_ratchet.rs": (
        "crates/*/src/*",
        "services/*/src/*",
    ),
    # Every environment read under crates/*/src (via support/rust_sources.rs)
    # and services/*/src, against the docs it names and each service's README.
    "crates/epigraph-engine/tests/env_var_docs.rs": ("services/*/src/*", "services/*/README.md"),
    # The shared walker behind calibration_single_loader_ratchet.rs,
    # belief_mode_readers.rs and env_var_docs.rs (each `#[path]`-includes it).
    "crates/epigraph-engine/tests/support/rust_sources.rs": (
        "crates/*/src/*",
        "crates/*/build.rs",
    ),
    "crates/epigraph-mcp/tests/plan_order_under_one_transaction.rs": ("crates/*/src/*",),
    "crates/epigraph-mcp/tests/raw_pool_register.rs": (),
    "crates/epigraph-mcp/tests/residual_unstamped_writes.rs": ("crates/*/src/*",),
    # The stamp-borrow and server-agent-resolution ratchets scan every member's
    # src since the Ctx move (#1163, #1177).
    "crates/epigraph-mcp/tests/write_identity_ratchet.rs": ("crates/*/src/*", "tests/*/src/*"),
    # `Ctx` is defined once; the `test-support` feature is enabled by
    # dev-dependencies only: every member's src and every manifest (#1163).
    "crates/epigraph-service/tests/ctx_is_the_only_definition.rs": ("crates/*/src/*", "*Cargo.toml"),
}

# Tests that read files a change can only break by deleting or renaming them,
# wherever they are: the change's deleted paths are reads of these (the value
# says why). doc_links resolves every relative link in README.md and
# docs/intro/, and a link can point anywhere in the tree, so a pull request
# that deletes or renames a link target must run it. Narrower than a glob of
# the whole tree: an added or edited file cannot break a link.
DELETION_READERS = {
    "crates/epigraph-core/tests/doc_links.rs": "a deleted path may be a link target",
}

# Jobs other than the shards that test or lint particular packages; each runs
# only when one of its packages is affected. The workflow test checks that
# every `-p <package>` in these jobs' steps is listed here.
EXTRA_JOBS = {
    "test-extra": ("epigraph-api", "epigraph-jobs", "engine-integration-tests"),
    "lint-features": ("epigraph-api", "epigraph-cli"),
}

# The runner for the shards when the SHARD_RUNS_ON variable is unset or
# unusable, and always for a pull request from a fork.
HOSTED_RUNNER = "ubuntu-latest"
# `max-parallel` when SHARD_MAX_PARALLEL is unset: GitHub's matrix limit, so
# in effect unlimited.
UNLIMITED_PARALLEL = 256


def manifest_of(script):
    """The workspace manifest to plan, or None for the cwd's workspace.

    In place (`<workspace>/.github/scripts/test-shard.py`) the script plans the
    tree it belongs to, so a run from another directory does not pair another
    checkout's packages with this tree's files. A COPY elsewhere (the local
    gate runs one from its cache, and one from each mirror's `.ci-shards/`)
    plans the workspace of the directory it is run from, as `cargo metadata`
    does by default."""
    here = os.path.dirname(os.path.abspath(script))
    if os.path.basename(here) != "scripts" or os.path.basename(os.path.dirname(here)) != ".github":
        return None
    manifest = os.path.join(os.path.dirname(os.path.dirname(here)), "Cargo.toml")
    return manifest if os.path.isfile(manifest) else None


MANIFEST = manifest_of(__file__)


def load():
    """(repository root, {package name: cargo metadata package})."""
    where = ["--manifest-path", MANIFEST] if MANIFEST else []
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"] + where,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    meta = json.loads(out)
    return meta["workspace_root"], {p["name"]: p for p in meta["packages"]}


def metadata():
    return load()[1]


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


# --------------------------------------------------------------------------
# Affected shards
# --------------------------------------------------------------------------


def git_files(root):
    out = subprocess.run(
        ["git", "-C", root, "ls-files"], check=True, capture_output=True, text=True
    ).stdout
    return [f for f in out.splitlines() if f]


def package_dirs(root, pkgs):
    """{package: its directory relative to the repository root}."""
    return {
        name: posixpath.relpath(
            posixpath.dirname(p["manifest_path"].replace(os.sep, "/")),
            root.replace(os.sep, "/"),
        )
        for name, p in pkgs.items()
    }


def owner(path, dirs):
    """The package whose directory holds `path` (the deepest one), or None."""
    best = None
    for name, d in dirs.items():
        if path.startswith(d + "/") and (best is None or len(d) > len(dirs[best])):
            best = name
    return best


def reverse_deps(pkgs):
    """{package: workspace packages that depend on it, dev-dependencies included}."""
    rdeps = {n: set() for n in pkgs}
    for name, p in pkgs.items():
        for dep in p["dependencies"]:
            if dep["name"] in rdeps and dep["name"] != name:
                rdeps[dep["name"]].add(name)
    return rdeps


_INCLUDE = re.compile(r'(?:include_str|include_bytes|include)!\(\s*"([^"]+)"|#\[path\s*=\s*"([^"]+)"\]')
_RAW = re.compile(r'\br(#*)"(.*?)"\1', re.S)
_STRING = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
_WALK = re.compile(r"\bread_dir\b|\bWalkDir\b|\bwalkdir::|\bglob\(")
_PARENT_CLIMB = re.compile(r"CARGO_MANIFEST_DIR[^;]*?\.parent\(\)", re.S)
_CFG_TEST = "#[cfg(test)]"

# What a read reaches, in `scan_reads`'s results.
PROPAGATES = "propagates"  # the package and everything that depends on it
PACKAGE = "package"  # every shard of the package
TARGETS = "targets"  # only the named test targets of the package


def test_targets(root, pkgs, dirs):
    """{repo-relative source file: (package, test target)} for runnable tests."""
    out = {}
    for name, pkg in pkgs.items():
        runnable = set(targets(pkg)[0])
        for t in pkg["targets"]:
            if "test" in t["kind"] and t["name"] in runnable:
                rel = posixpath.relpath(t["src_path"].replace(os.sep, "/"), root.replace(os.sep, "/"))
                out[rel] = (name, t["name"])
    return out


def scan_reads(root, pkgs, dirs, files, read=None, gone=()):
    """What each package's sources read from outside its own directory.

    `files` is the tree being tested (HEAD). `gone` are paths that may exist
    only on the other side of the diff: the change's paths, so a literal
    naming a file the change deletes or renames away still counts as a read
    of it. Without them a PR deleting `docs/tenancy.md` selects nothing, and
    the tests that read it fail first on main.

    Returns (reads, walkers). `reads` is a list of
    (package, kind, pattern, reach, test targets, source file): kind "prefix"
    (a string literal named a path that exists) or "glob" (from WALKERS), and
    reach PROPAGATES (read by library or binary code), PACKAGE (by a unit test
    or a test helper no target can be found for) or TARGETS (by those
    integration-test targets only). `walkers` is the set of files that walk a
    directory they reached by climbing out of their crate.
    """
    if read is None:
        def read(f):
            with open(os.path.join(root, f), encoding="utf-8", errors="replace") as fh:
                return fh.read()
    tracked = set(files)
    known = tracked | set(gone)
    tracked_dirs = set()
    for f in known:
        while "/" in f:
            f = f.rsplit("/", 1)[0]
            tracked_dirs.add(f)
    top = {f.split("/", 1)[0] for f in known}
    top_dirs = {d for d in top if d in tracked_dirs} - {"crates"}
    package_roots = set(dirs.values())
    roots = test_targets(root, pkgs, dirs)
    texts = {}

    def text_of(f):
        if f not in texts:
            texts[f] = "\n".join(
                line for line in read(f).splitlines() if not line.lstrip().startswith("//")
            )
        return texts[f]

    def exists(path):
        return path in known or path in tracked_dirs

    def reach(name, f, before_cfg_test):
        """(reach, targets) of a read made by file `f` of package `name`."""
        d = dirs[name]
        if f.startswith(d + "/src/") or f == d + "/build.rs":
            return (PROPAGATES, ()) if before_cfg_test else (PACKAGE, ())
        if f in roots:
            return TARGETS, (roots[f][1],)
        if f.startswith(d + "/tests/"):
            # A helper module: the targets that declare it with `mod <name>;`.
            rest = f[len(d) + len("/tests/") :]
            stem = rest[: -len("/mod.rs")] if rest.endswith("/mod.rs") else rest[: -len(".rs")]
            if "/" not in stem:
                decl = re.compile(r"\bmod\s+" + re.escape(stem) + r"\s*;")
                top_only = False
            else:
                # A helper in a subdirectory, pulled in by a target at the top
                # of tests/ with `#[path = "<dir>/<file>.rs"] mod <name>;`
                # (the path is relative to that target's directory).
                decl = re.compile(r'#\[\s*path\s*=\s*"' + re.escape(rest) + r'"\s*\]')
                top_only = True
            users = sorted(
                t
                for src, (p, t) in roots.items()
                if p == name
                and (not top_only or src.rsplit("/", 1)[0] == d + "/tests")
                and decl.search(text_of(src))
            )
            if users:
                return TARGETS, tuple(users)
        return PACKAGE, ()

    reads, walkers = [], set()
    for f in files:
        name = owner(f, dirs)
        if name is None or not f.endswith(".rs"):
            continue
        d = dirs[name]

        def outside(path):
            return path != d and not path.startswith(d + "/")

        text = text_of(f)
        cut = text.find(_CFG_TEST)
        cut = len(text) if cut < 0 else cut
        found = {}  # path -> read before the first #[cfg(test)]

        def note(path, pos):
            if path in package_roots:
                path += "/Cargo.toml"  # naming a crate directory is naming the crate
            found[path] = found.get(path, False) or pos < cut

        for m in _INCLUDE.finditer(text):
            lit = m.group(1) or m.group(2)
            path = posixpath.normpath(posixpath.join(posixpath.dirname(f), lit))
            if outside(path) and exists(path):
                note(path, m.start())
        # A char literal holding a quote would pair the wrong quotes.
        body = text.replace("'\"'", "'.'").replace("'\\\"'", "'..'")
        literals = [(m.group(2), m.start()) for m in _RAW.finditer(body)]
        blanked = _RAW.sub(lambda m: '"' + " " * (len(m.group(0)) - 2) + '"', body)
        literals += [(m.group(1), m.start()) for m in _STRING.finditer(blanked)]
        climbs = bool(_PARENT_CLIMB.search(text))
        bare = []  # (top-level directory, position) joined alone, e.g. join("scripts")
        for lit, pos in literals:
            if not lit or any(c.isspace() for c in lit) or "\\" in lit:
                continue
            segs = [s for s in lit.strip("/").split("/") if s]
            if not segs:
                continue
            if ".." in segs:
                # Relative to the manifest directory (CARGO_MANIFEST_DIR).
                path = posixpath.normpath(posixpath.join(d, lit.lstrip("/")))
                if not outside(path):
                    continue
                if path in (".", "crates") or path.startswith(".."):
                    climbs = True  # a bare climb: what it reads is decided at run time
                elif exists(path):
                    note(path, pos)
                continue
            rel = "/".join(segs)
            if len(segs) == 1 and "." not in rel and rel in top_dirs:
                # Only as a path: `root.join("scripts")`, not a table or
                # word that happens to share a directory's name.
                if blanked[:pos].rstrip().endswith("join("):
                    bare.append((rel, pos))
                continue
            if segs[0] in top and (len(segs) >= 2 or "." in rel) and exists(rel):
                path = rel  # relative to the repository root
            elif len(segs) >= 2 and exists("crates/" + rel):
                path = "crates/" + rel  # relative to crates/
            else:
                continue
            if outside(path):
                note(path, pos)
        if climbs and _WALK.search(text):
            walkers.add(f)
            # A walk from a top-level directory it names alone reads all of
            # it. `crates` is left to WALKERS, whose globs say which part of
            # each crate a ratchet reads; widening those to every file under
            # crates/ would put source-scans on every crate change.
            for path, pos in bare:
                note(path, pos)
        for path, before in sorted(found.items()):
            r, ts = reach(name, f, before)
            reads.append((name, "prefix", path, r, ts, f))
    for f, globs in sorted(WALKERS.items()):
        name = owner(f, dirs)
        if name is None or f not in tracked:
            continue
        r, ts = reach(name, f, True)
        for g in globs:
            reads.append((name, "glob", g, r, ts, f))
    # A path of the change that is not on disk is deleted or renamed away.
    # The disk, not `files`: it is the tree under test both in CI (the
    # checkout) and in a local run (the working tree, where an untracked new
    # file is in the change but not in `git ls-files`).
    deleted = sorted(p for p in set(gone) if not os.path.lexists(os.path.join(root, p)))
    for f in sorted(DELETION_READERS):
        name = owner(f, dirs)
        if name is None or f not in tracked:
            continue
        r, ts = reach(name, f, True)
        for p in deleted:
            reads.append((name, "prefix", p, r, ts, f))
    return reads, walkers


def path_matches(path, kind, pattern):
    if kind == "glob":
        return fnmatch.fnmatchcase(path, pattern)
    return path == pattern or path.startswith(pattern + "/")


def full_reason_for_paths(changed):
    """Why this set of changed paths runs every shard, or None."""
    for f in sorted(changed):
        if f in FULL_FILES or f.startswith(FULL_PATHS):
            return f"{f} changed"
        if any(fnmatch.fnmatchcase(f, g) for g in FULL_GLOBS):
            return f"{f} changed"
    return None


def affected(changed, pkgs, dirs, reads):
    """(whole, partial) for a change that does not run everything.

    `whole` is {package: why} for the packages every shard of which runs;
    `partial` is {package: {test target: why}} for packages that only some
    of their own test targets can notice (they read a changed file), and is
    never a package that is also in `whole`."""
    rdeps = reverse_deps(pkgs)
    whole, partial = {}, {}
    todo = []

    def mark(name, why, propagates):
        whole.setdefault(name, why)
        if propagates:
            todo.append(name)

    for f in sorted(changed):
        name = owner(f, dirs)
        if name is not None:
            local = f[len(dirs[name]) + 1 :].startswith(LOCAL_ONLY)
            mark(name, f"{f} changed", not local)
    for name, kind, pattern, reach, ts, source in reads:
        hit = next((f for f in sorted(changed) if path_matches(f, kind, pattern)), None)
        if hit is None:
            continue
        why = f"{source} reads {hit}"
        if reach == TARGETS:
            for t in ts:
                partial.setdefault(name, {}).setdefault(t, why)
        else:
            mark(name, why, reach == PROPAGATES)
    seen = set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        for dependent in sorted(rdeps[name]):
            whole.setdefault(dependent, f"depends on {name}")
            todo.append(dependent)
    partial = {p: ts for p, ts in partial.items() if p not in whole}
    return whole, partial


# The shard that runs only the test targets that read a changed file, for
# packages whose code the change does not touch. It exists only in an
# affected plan, so main never saves a cache under its name: it restores
# epigraph-api's, whose dependency graph covers nearly every crate.
SCANS = "source-scans"
SCANS_CACHE = "epigraph-api"


def threads_of(package):
    for p, _total, threads in SHARDED:
        if p == package:
            return threads
    for _name, members, threads in GROUPED:
        if package in members:
            return threads
    return 1


def scan_invocations(partial):
    """One (test threads, cargo arguments) per package of the source-scans shard."""
    return [
        (threads_of(p), ["-p", p] + [a for t in sorted(ts) for a in ("--test", t)])
        for p, ts in sorted(partial.items())
    ]


def covered_by(shards, sid, pkgs):
    """The packages shard `sid` runs every test of, together with its siblings."""
    if sid == "workspace-rest":
        named = {p for p, _, _ in SHARDED} | {m for _, ms, _ in GROUPED for m in ms}
        return set(pkgs) - named
    return set(shards[sid]["package"].split())


def shards_for(shards, whole):
    """The ids of the shards that test a wholly affected package."""
    named = {p for p, _, _ in SHARDED} | {m for _, ms, _ in GROUPED for m in ms}
    ids = []
    for sid, s in shards.items():
        if sid == "workspace-rest":
            hit = any(p not in named for p in whole)
        else:
            hit = any(p in whole for p in s["package"].split())
        if hit:
            ids.append(sid)
    return ids


def matrix_for(shards, ids, partial=None):
    """`strategy.matrix` for these shards (plus source-scans when `partial`
    names any target); `include` may be empty."""
    # `save`: only one shard per cache key writes the dependency cache.
    seen = set()
    include = []
    for sid in ids:
        s = shards[sid]
        include.append(
            {
                "shard": sid,
                "threads": s["threads"],
                "cache": s["cache"],
                "save": s["cache"] not in seen,
                "targets": "",
            }
        )
        seen.add(s["cache"])
    if partial:
        include.append(
            {
                "shard": SCANS,
                "threads": 1,
                "cache": SCANS_CACHE,
                "save": False,
                "targets": json.dumps(partial_targets(partial), separators=(",", ":")),
            }
        )
    return {"include": include}


def partial_targets(partial):
    return {p: sorted(ts) for p, ts in sorted(partial.items())}


def run_flags(ids, whole, full):
    """{job id: whether it runs}; the `test` gate holds the plan to it."""
    flags = {"test-shard": bool(ids)}
    for job, packages in EXTRA_JOBS.items():
        flags[job] = full or any(p in whole for p in packages)
    return flags


def changed_paths(root, base, worktree=False):
    """Paths changed between the merge base of `base` and HEAD, and HEAD.

    With `worktree`, also the uncommitted and the untracked (not ignored)
    files: a local gate tests the working tree, not HEAD, so selecting from
    HEAD alone would leave an uncommitted change untested and pass.
    `--no-renames`: a file moved out of a crate is a change to that crate too.
    Raises CalledProcessError when `base` is unknown (a shallow clone)."""
    commands = [["diff", "--no-renames", "--name-only", f"{base}...HEAD"]]
    if worktree:
        commands += [["diff", "--no-renames", "--name-only", "HEAD"], ["ls-files", "--others", "--exclude-standard"]]
    paths = set()
    for command in commands:
        out = subprocess.run(
            ["git", "-C", root] + command, check=True, capture_output=True, text=True
        ).stdout
        paths.update(f for f in out.splitlines() if f)
    return sorted(paths)


def head_is_merge(root):
    out = subprocess.run(
        ["git", "-C", root, "rev-list", "--parents", "-n", "1", "HEAD"],
        capture_output=True,
        text=True,
    ).stdout.split()
    return len(out) == 3


def event_full_reason(event, head_ref, labels):
    """Why this event runs every shard regardless of the diff, or None."""
    if event != "pull_request":
        return f"event {event or '(none)'}"
    for pattern in FULL_BRANCHES:
        if fnmatch.fnmatchcase(head_ref or "", pattern):
            return f"head branch {head_ref} matches {pattern}"
    if FULL_LABEL in (labels or ()):
        return f"label {FULL_LABEL}"
    return None


def event_light_reason(event, head_ref):
    """Why this event gets the light plan, or None. Asked only after
    `event_full_reason` returned None, so the FULL_LABEL label wins."""
    if event != "pull_request":
        return None
    for pattern in LIGHT_BRANCHES:
        if fnmatch.fnmatchcase(head_ref or "", pattern):
            return f"head branch {head_ref} matches {pattern}"
    return None


def light_targets():
    """LIGHT_TARGETS in `affected`'s `partial` shape: {package: {target: why}}."""
    return {p: {t: "light plan" for t in ts} for p, ts in LIGHT_TARGETS.items()}


def check_light_targets(pkgs, out=None):
    """Fail on a LIGHT_TARGETS package or test target that does not exist."""
    out = sys.stdout if out is None else out
    ok = True
    for package, names in sorted(LIGHT_TARGETS.items()):
        if package not in pkgs:
            ok = False
            print(f"FAIL LIGHT_TARGETS: {package} is not a workspace member", file=out)
            continue
        known = {t["name"] for t in pkgs[package]["targets"] if "test" in t["kind"]}
        for name in sorted(set(names) - known):
            ok = False
            print(f"FAIL LIGHT_TARGETS: {package} has no test target {name}", file=out)
    if ok:
        n = sum(len(ts) for ts in LIGHT_TARGETS.values())
        print(f"ok   light plan: {n} test targets in {len(LIGHT_TARGETS)} packages, all present", file=out)
    return ok


def shard_runner(event, head_repo, repository, raw):
    """(the shards' `runs-on`, a warning or None).

    SHARD_RUNS_ON (a repository variable, JSON: a label, a list of labels, or
    {"group": ..., "labels": [...]}) is honoured only for an event whose code
    the repository's own members pushed: a push, a merge-queue run, a manual
    or scheduled run, or a pull request whose head is in this repository. A
    pull request from a fork always gets the GitHub-hosted runner whatever the
    variable says: self-hosted runners must never run code from a fork of a
    public repository. A deleted fork has no head repository and is a fork.

    This protects the unmodified workflow only. A fork's pull request runs the
    fork's own copy of this script and of ci.yml, so the boundary has to be a
    GitHub-side setting (see ci.yml, SELF-HOSTED SHARD RUNNERS).
    """
    if not raw or not raw.strip():
        return HOSTED_RUNNER, None
    if event == "pull_request":
        if not head_repo or head_repo != repository:
            return HOSTED_RUNNER, None
    elif event not in FULL_EVENTS:
        return HOSTED_RUNNER, None
    try:
        value = json.loads(raw)
    except ValueError:
        return HOSTED_RUNNER, f"SHARD_RUNS_ON is not JSON ({raw!r}); using {HOSTED_RUNNER}"

    def label(x):
        return isinstance(x, str) and x.strip() != ""

    ok = (
        label(value)
        or (isinstance(value, list) and value and all(label(x) for x in value))
        or (
            isinstance(value, dict)
            and value
            and set(value) <= {"group", "labels"}
            and ("group" not in value or label(value["group"]))
            and (
                "labels" not in value
                or label(value["labels"])
                or (
                    isinstance(value["labels"], list)
                    and value["labels"]
                    and all(label(x) for x in value["labels"])
                )
            )
        )
    )
    if not ok:
        return HOSTED_RUNNER, f"SHARD_RUNS_ON is not a runs-on value ({raw!r}); using {HOSTED_RUNNER}"
    return value, None


def max_parallel(raw):
    """(the shards' `max-parallel`, a warning or None)."""
    if not raw or not raw.strip():
        return UNLIMITED_PARALLEL, None
    try:
        n = int(raw.strip())
    except ValueError:
        n = 0
    if n < 1:
        return UNLIMITED_PARALLEL, f"SHARD_MAX_PARALLEL is not a positive integer ({raw!r}); not capping"
    return n, None


def decide(root, pkgs, shards, env, changed=None, reads=None):
    """The plan for one workflow run, from its environment.

    `changed` (the diff) is computed from DIFF_BASE when not given, and
    `reads` (`scan_reads`'s first result) from the tree. Returns a
    dict: mode ("full", "affected" or "light"), reason, ids (the matrix's
    shard ids, source-scans included), whole and partial (see `affected`;
    in a light plan `partial` is LIGHT_TARGETS), matrix, run, runs_on,
    max_parallel, warnings."""
    event = env.get("GITHUB_EVENT_NAME", "")
    try:
        labels = json.loads(env.get("PR_LABELS") or "[]")
    except ValueError:
        labels = []
    warnings = []
    head_ref = env.get("GITHUB_HEAD_REF", "")
    reason = event_full_reason(event, head_ref, labels)
    light = event_light_reason(event, head_ref) if reason is None else None
    if light is not None:
        # The diff is not consulted: a light head is light whatever it
        # touches (migrations and .github/ included). Its staging PR is full.
        mode, reason = "light", light
        whole, partial, ids = {}, light_targets(), []
    elif reason is None and changed is None:
        base = env.get("DIFF_BASE", "")
        if not base:
            reason = "no DIFF_BASE to diff against"
        elif base == "HEAD^1" and not head_is_merge(root):
            # HEAD^1...HEAD is the PR's change only on the test merge commit;
            # on anything else it is one commit of it.
            reason = "HEAD is not a merge commit, so HEAD^1 is not the PR's base"
        else:
            try:
                changed = changed_paths(root, base, worktree=bool(env.get("DIFF_WORKTREE")))
            except subprocess.CalledProcessError as e:
                reason = f"cannot diff against {base}: {(e.stderr or '').strip()}"
    if light is None and reason is None:
        reason = full_reason_for_paths(changed)
    if light is not None:
        pass
    elif reason is None:
        dirs = package_dirs(root, pkgs)
        if reads is None:
            reads, _walkers = scan_reads(root, pkgs, dirs, git_files(root), gone=changed)
        whole, partial = affected(changed, pkgs, dirs, reads)
        ids = shards_for(shards, whole)
        # A package one of the selected shards already runs in full needs no
        # targets of its own (workspace-rest runs all of its members).
        covered = {p for sid in ids for p in covered_by(shards, sid, pkgs)}
        partial = {p: ts for p, ts in partial.items() if p not in covered}
        mode = "affected"
        reason = f"{len(changed)} changed paths"
    else:
        whole, partial = {p: "full run" for p in pkgs}, {}
        ids = list(shards)
        mode = "full"
    runs_on, w = shard_runner(
        event, env.get("HEAD_REPO", ""), env.get("GITHUB_REPOSITORY", ""), env.get("SHARD_RUNS_ON", "")
    )
    if w:
        warnings.append(w)
    cap, w = max_parallel(env.get("SHARD_MAX_PARALLEL", ""))
    if w:
        warnings.append(w)
    matrix = matrix_for(shards, ids, partial)
    ids = [e["shard"] for e in matrix["include"]]
    return {
        "mode": mode,
        "reason": reason,
        "ids": ids,
        "total": len(shards),
        "whole": whole,
        "partial": partial,
        "matrix": matrix,
        "run": run_flags(ids, whole, mode == "full"),
        "runs_on": runs_on,
        "max_parallel": cap,
        "warnings": warnings,
    }


def explain(d, out):
    print(f"mode: {d['mode']} ({d['reason']})", file=out)
    print(f"shards: {len(d['ids'])} (the full plan has {d['total']})", file=out)
    for sid in d["ids"]:
        print(f"  {sid}", file=out)
    if d["mode"] == "light":
        print(f"light plan: only these test targets ({SCANS}); the staging PR runs the rest", file=out)
        for name, ts in sorted(d["partial"].items()):
            print(f"  {name}: {' '.join(sorted(ts))}", file=out)
    if d["mode"] == "affected":
        print(f"wholly affected packages: {len(d['whole'])}", file=out)
        for name, why in sorted(d["whole"].items()):
            print(f"  {name}: {why}", file=out)
        if d["partial"]:
            print(f"test targets that read a changed file ({SCANS}):", file=out)
            for name, ts in sorted(d["partial"].items()):
                for t, why in sorted(ts.items()):
                    print(f"  {name} --test {t}: {why}", file=out)
    print("jobs: " + ", ".join(f"{j}={'run' if r else 'skip'}" for j, r in d["run"].items()), file=out)
    print(f"runs-on: {json.dumps(d['runs_on'])}; max-parallel: {d['max_parallel']}", file=out)


def gate(needs):
    """Problems with this run's results; empty when the `test` gate passes.

    `needs` is the `needs` context. A job the plan asked for must succeed. A
    job the plan skipped must be skipped (an empty matrix is a skipped
    `test-shard`, not a failure). Any job the plan does not gate must succeed.
    Nothing passes unless the plan itself succeeded."""
    plan_job = needs.get("plan") or {}
    if plan_job.get("result") != "success":
        return [f"plan: {plan_job.get('result', 'missing')}"]
    try:
        run = json.loads((plan_job.get("outputs") or {}).get("run") or "")
    except ValueError:
        return ["plan: no `run` output"]
    problems = []
    for name, job in sorted(needs.items()):
        if name == "plan":
            continue
        result = job.get("result")
        if run.get(name, True):
            if result != "success":
                problems.append(f"{name}: {result} (the plan asked for it)")
        elif result != "skipped":
            problems.append(f"{name}: {result} (the plan skipped it)")
    return problems


def check_walkers(walkers, declared=None, out=None):
    declared = WALKERS if declared is None else declared
    out = sys.stdout if out is None else out
    ok = True
    for f in sorted(walkers - set(declared)):
        ok = False
        print(f"FAIL {f}: walks a directory outside its crate; declare what it reads in WALKERS", file=out)
    for f in sorted(set(declared) - walkers):
        ok = False
        print(f"FAIL {f}: listed in WALKERS but no longer walks outside its crate; remove it", file=out)
    if ok:
        print(f"ok   whole-tree source scans: {len(walkers)}, all declared in WALKERS", file=out)
    return ok


def main(argv):
    modes = ("matrix", "args", "doc", "check", "affected", "ci-plan", "gate", "scan-args")
    if len(argv) < 2 or argv[1] not in modes:
        print(__doc__, file=sys.stderr)
        return 2
    mode = argv[1]
    if mode == "scan-args":
        # The source-scans shard: one line per cargo invocation,
        # "<test threads> <cargo arguments>", from the matrix's `targets`.
        if len(argv) != 3:
            print("scan-args needs the matrix's targets JSON", file=sys.stderr)
            return 2
        for threads, args in scan_invocations(json.loads(argv[2])):
            print(threads, " ".join(args))
        return 0
    if mode == "gate":
        problems = gate(json.loads(os.environ["NEEDS"]))
        for name, job in sorted(json.loads(os.environ["NEEDS"]).items()):
            print(f"{job.get('result', '?'):10s} {name}")
        if problems:
            print("not successful:", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            return 1
        return 0
    root, pkgs = load()
    shards = plan(pkgs)
    if mode == "check":
        ok = check(pkgs, shards)
        _reads, walkers = scan_reads(root, pkgs, package_dirs(root, pkgs), git_files(root))
        ok = check_walkers(walkers) and ok
        ok = check_light_targets(pkgs) and ok
        unknown = sorted({p for ps in EXTRA_JOBS.values() for p in ps} - set(pkgs))
        if unknown:
            ok = False
            print("FAIL EXTRA_JOBS: not workspace members:", unknown)
        return 0 if ok else 1
    base = None
    if mode == "affected" and len(argv) == 3 and not argv[2].startswith("-"):
        base = argv[2]
    elif mode in ("matrix", "affected") and "--base" in argv:
        i = argv.index("--base")
        if i + 1 >= len(argv):
            print("--base needs a ref", file=sys.stderr)
            return 2
        base = argv[i + 1]
    elif mode == "affected":
        print("affected needs a base ref: affected [--base] REF", file=sys.stderr)
        return 2
    if base is not None:
        # A local run: the working tree is what gets tested.
        env = {"GITHUB_EVENT_NAME": "pull_request", "DIFF_BASE": base, "DIFF_WORKTREE": "1"}
        d = decide(root, pkgs, shards, env)
        if mode == "affected":
            explain(d, sys.stderr)
        print(json.dumps(d["matrix"]))
        return 0
    if mode == "matrix":
        print(json.dumps(matrix_for(shards, list(shards))))
        return 0
    if mode == "ci-plan":
        d = decide(root, pkgs, shards, os.environ)
        for w in d["warnings"]:
            print(f"::warning::{w}", file=sys.stderr)
        explain(d, sys.stderr)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write("### Test shard plan\n\n```\n")
                explain(d, fh)
                fh.write("```\n")
        print(f"matrix={json.dumps(d['matrix'])}")
        print(f"count={len(d['ids'])}")
        print(f"run={json.dumps(d['run'])}")
        print(f"runs_on={json.dumps(d['runs_on'])}")
        print(f"max_parallel={d['max_parallel']}")
        print(f"mode={d['mode']}")
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
