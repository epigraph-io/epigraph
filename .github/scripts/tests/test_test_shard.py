"""Tests for .github/scripts/test-shard.py: the affected-shard selection, the
runner switch and its fork guard, the `test` gate, and the CI job graph that
wires them together.

Run from the repository root (the `plan` job does):

    python3 -m unittest discover -s .github/scripts/tests -v

The planner is loaded BY PATH, from TEST_SHARD_SCRIPT when it is set, so the
same tests can be pointed at another revision of the script:

    git show <rev>:.github/scripts/test-shard.py > /tmp/old.py
    TEST_SHARD_SCRIPT=/tmp/old.py python3 -m unittest discover -s .github/scripts/tests

and TEST_SHARD_WORKFLOW does the same for ci.yml.

The selection tests use the real workspace (`cargo metadata`, `git ls-files`)
rather than a hand-written graph: what they pin is that THIS repository's
dependency edges and source scans produce the selection, so an edge or a
ratchet that moves shows up here.
"""

import importlib.util
import io
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.environ.get("TEST_SHARD_SCRIPT") or os.path.join(HERE, "..", "test-shard.py")
WORKFLOW = os.environ.get("TEST_SHARD_WORKFLOW") or os.path.join(HERE, "..", "..", "workflows", "ci.yml")


def load_planner():
    spec = importlib.util.spec_from_file_location("test_shard", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ts = load_planner()
_WORKSPACE = None


def workspace():
    """(root, pkgs, shards), loaded once: `cargo metadata` takes a second."""
    global _WORKSPACE
    if _WORKSPACE is None:
        root, pkgs = ts.load()
        _WORKSPACE = (root, pkgs, ts.plan(pkgs))
    return _WORKSPACE


_READS = None


def reads():
    """The real tree's source-scan reads, scanned once."""
    global _READS
    if _READS is None:
        root, pkgs, _shards = workspace()
        _READS = ts.scan_reads(root, pkgs, ts.package_dirs(root, pkgs), ts.git_files(root))
    return _READS


def pr_plan(changed, **env):
    """The plan for a same-repository pull request with this diff."""
    root, pkgs, shards = workspace()
    base = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_HEAD_REF": "feature/x"}
    base.update(env)
    return ts.decide(root, pkgs, shards, base, changed=list(changed), reads=reads()[0])


def shard_ids(d):
    return set(d["ids"])


def shards_of(package):
    _root, _pkgs, shards = workspace()
    return {sid for sid, s in shards.items() if package in s["package"].split()}


class AffectedSelection(unittest.TestCase):
    def test_db_source_change_pulls_in_its_reverse_dependencies(self):
        d = pr_plan(["crates/epigraph-db/src/lib.rs"])
        self.assertEqual(d["mode"], "affected")
        for dependent in ("epigraph-api", "epigraph-mcp", "epigraph-cli", "epigraph-engine"):
            self.assertIn(dependent, d["whole"], dependent)
            self.assertEqual(
                d["whole"][dependent].split()[0], "depends", f"{dependent}: {d['whole'][dependent]}"
            )
        for package in ("epigraph-db", "epigraph-api", "epigraph-mcp", "epigraph-cli"):
            self.assertLessEqual(shards_of(package), shard_ids(d), package)
        self.assertIn("engine-embeddings", shard_ids(d))
        # jobs and engine-integration-tests depend on db, so the gated jobs run.
        self.assertTrue(all(d["run"].values()), d["run"])

    def test_a_dependency_is_not_pulled_in_by_its_dependent(self):
        # epigraph-api depends on epigraph-db; an api change must not run db's
        # whole suite. It runs only db's test targets that read api's sources.
        d = pr_plan(["crates/epigraph-api/src/lib.rs"])
        self.assertNotIn("epigraph-db", d["whole"])
        self.assertFalse(shards_of("epigraph-db") & shard_ids(d))
        self.assertIn(ts.SCANS, shard_ids(d))
        self.assertTrue(d["partial"].get("epigraph-db"), d["partial"])
        self.assertLessEqual(shards_of("epigraph-api") | shards_of("epigraph-cli"), shard_ids(d))

    def test_docs_only_change_runs_no_shard_and_no_gated_job(self):
        # A doc no Rust source reads (the runbooks, docs/intro and README.md
        # are read by tests; see the next test).
        d = pr_plan(["docs/superpowers/plans/2026-11-14-a-plan.md", "docs/deploy.md"])
        self.assertEqual(d["mode"], "affected")
        self.assertEqual(d["ids"], [])
        self.assertEqual(d["matrix"], {"include": []})
        self.assertEqual(d["run"], {job: False for job in d["run"]})

    def test_python_outside_scripts_runs_no_shard(self):
        d = pr_plan(["services/kanban/board.py", "tests/dedup/test_x.py", "tests/theme/conftest.py"])
        self.assertEqual(d["ids"], [])

    def test_a_runbook_read_by_db_tests_runs_only_those_targets(self):
        d = pr_plan(["docs/runbooks/124-undo.sql"])
        self.assertEqual(d["ids"], [ts.SCANS])
        self.assertEqual(set(d["partial"]), {"epigraph-db"})
        self.assertEqual(d["whole"], {})

    def test_a_test_only_change_does_not_reach_dependents(self):
        # A new file: no other package's scan names it, so only db runs.
        d = pr_plan(["crates/epigraph-db/tests/a_new_test_file.rs"])
        self.assertEqual(set(d["whole"]), {"epigraph-db"})
        self.assertEqual(shard_ids(d), shards_of("epigraph-db"))

    def test_migrations_change_runs_the_full_set(self):
        d = pr_plan(["migrations/999_new.sql"])
        self.assertEqual(d["mode"], "full")
        _root, _pkgs, shards = workspace()
        self.assertEqual(d["ids"], list(shards))
        self.assertTrue(all(d["run"].values()))

    def test_shard_script_change_runs_the_full_set(self):
        d = pr_plan([".github/scripts/test-shard.py"])
        self.assertEqual(d["mode"], "full")

    def test_every_listed_full_path_runs_the_full_set(self):
        for path in (
            "Cargo.lock",
            "Cargo.toml",
            ".github/workflows/explorer.yml",
            "rust-toolchain.toml",
            ".sqlx/query-abc.json",
            ".cargo/config.toml",
        ):
            self.assertEqual(pr_plan(["docs/x.md", path])["mode"], "full", path)

    def test_a_crate_manifest_is_that_crate_not_the_full_set(self):
        d = pr_plan(["crates/epigraph-tools/Cargo.toml"])
        self.assertEqual(d["mode"], "affected")
        self.assertIn("epigraph-tools", d["whole"])

    def test_source_scans_shard_runs_per_package_at_its_thread_count(self):
        d = pr_plan(["crates/epigraph-api/src/lib.rs"])
        entry = [e for e in d["matrix"]["include"] if e["shard"] == ts.SCANS]
        self.assertEqual(len(entry), 1)
        self.assertFalse(entry[0]["save"])
        invocations = dict(
            (args[1], (threads, args)) for threads, args in ts.scan_invocations(json.loads(entry[0]["targets"]))
        )
        threads, args = invocations["epigraph-db"]
        self.assertEqual(threads, 4)
        self.assertEqual(args[:2], ["-p", "epigraph-db"])
        self.assertEqual(args[2::2], ["--test"] * (len(args[2:]) // 2))
        self.assertTrue(args[3:])

    def test_a_new_script_runs_the_dsn_lint_that_walks_scripts(self):
        # no_unmaintained_dsn walks repo_root().join("scripts") for *.py and
        # fails on a new psycopg2.connect( that skips the maintenance DSN; a
        # script it does not already name must still select it.
        for path in ("scripts/a_new_backfill.py", "scripts/lib/a_new_helper.py"):
            d = pr_plan([path])
            self.assertIn("no_unmaintained_dsn", d["partial"].get("epigraph-db", {}), path)

    def test_deleting_a_file_a_test_reads_still_runs_that_test(self):
        # The PR's HEAD no longer has docs/tenancy.md; the tests that read it
        # (and would fail on main) must still be selected. decide() computes
        # the reads itself here, against HEAD's file list without the file.
        from unittest import mock

        root, pkgs, shards = workspace()
        present = pr_plan(["docs/tenancy.md"])
        self.assertTrue(present["partial"], "the fixture file is no longer read by any test")
        head = [f for f in ts.git_files(root) if f != "docs/tenancy.md"]
        with mock.patch.object(ts, "git_files", return_value=head):
            env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_HEAD_REF": "feature/x"}
            gone = ts.decide(root, pkgs, shards, env, changed=["docs/tenancy.md"])
        self.assertEqual(gone["partial"], present["partial"])
        self.assertEqual(gone["ids"], [ts.SCANS])

    def test_a_package_a_selected_shard_covers_gets_no_scan_targets(self):
        # A db source change selects workspace-rest (jobs etc. depend on db),
        # which runs epigraph-crypto in full, so crypto's ratchet is not also
        # in source-scans.
        d = pr_plan(["crates/epigraph-db/src/lib.rs"])
        self.assertNotIn(ts.SCANS, shard_ids(d))


class SourceScanDetection(unittest.TestCase):
    """`scan_reads` on a synthetic tree, so the rules are pinned independent
    of what this repository's tests happen to read today."""

    def tree(self, files):
        root = tempfile.mkdtemp()
        for path, text in files.items():
            full = os.path.join(root, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as fh:
                fh.write(text)
        pkgs = {}
        for name in ("alpha", "beta"):
            d = os.path.join(root, "crates", name)
            pkgs[name] = {
                "manifest_path": os.path.join(d, "Cargo.toml"),
                "dependencies": [],
                "features": {},
                "targets": [
                    {"kind": ["lib"], "name": name, "src_path": os.path.join(d, "src", "lib.rs")},
                    {"kind": ["test"], "name": "scan", "src_path": os.path.join(d, "tests", "scan.rs")},
                ],
            }
        dirs = ts.package_dirs(root, pkgs)
        return root, pkgs, dirs, sorted(files)

    BASE = {
        "crates/alpha/Cargo.toml": "",
        "crates/alpha/src/lib.rs": "",
        "crates/beta/Cargo.toml": "",
        "crates/beta/src/lib.rs": "",
        "crates/beta/src/routes.rs": "",
        "docs/runbooks/1-undo.sql": "",
        "calibration.toml": "",
    }

    def test_literal_reads_are_found_relative_to_the_manifest_and_the_root(self):
        files = dict(self.BASE)
        files["crates/alpha/tests/scan.rs"] = (
            'const A: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../beta/src/routes.rs");\n'
            'fn f(root: &Path) { root.join("docs/runbooks/1-undo.sql"); }\n'
            '// "calibration.toml" in a comment is not a read\n'
        )
        root, pkgs, dirs, names = self.tree(files)
        reads, walkers = ts.scan_reads(root, pkgs, dirs, names)
        found = {(r[0], r[2], r[3], r[4]) for r in reads}
        self.assertIn(("alpha", "crates/beta/src/routes.rs", ts.TARGETS, ("scan",)), found)
        self.assertIn(("alpha", "docs/runbooks/1-undo.sql", ts.TARGETS, ("scan",)), found)
        self.assertNotIn("calibration.toml", {r[2] for r in reads})
        self.assertEqual(walkers, set())

    def test_an_include_in_library_code_propagates(self):
        files = dict(self.BASE)
        files["crates/alpha/src/lib.rs"] = 'const C: &str = include_str!("../../../calibration.toml");\n'
        root, pkgs, dirs, names = self.tree(files)
        reads, _ = ts.scan_reads(root, pkgs, dirs, names)
        self.assertIn(("alpha", "calibration.toml", ts.PROPAGATES), {(r[0], r[2], r[3]) for r in reads})

    def test_a_read_in_a_unit_test_module_stays_in_the_package(self):
        files = dict(self.BASE)
        files["crates/alpha/src/lib.rs"] = '#[cfg(test)]\nmod tests { const P: &str = "docs/runbooks/1-undo.sql"; }\n'
        root, pkgs, dirs, names = self.tree(files)
        reads, _ = ts.scan_reads(root, pkgs, dirs, names)
        self.assertEqual({(r[2], r[3]) for r in reads}, {("docs/runbooks/1-undo.sql", ts.PACKAGE)})

    def test_an_undeclared_whole_tree_walk_is_flagged(self):
        files = dict(self.BASE)
        files["crates/alpha/tests/scan.rs"] = (
            'fn root() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).join("../..") }\n'
            'fn walk() { for e in std::fs::read_dir(root().join("crates")).unwrap() {} }\n'
        )
        root, pkgs, dirs, names = self.tree(files)
        _reads, walkers = ts.scan_reads(root, pkgs, dirs, names)
        self.assertEqual(walkers, {"crates/alpha/tests/scan.rs"})
        out = io.StringIO()
        self.assertFalse(ts.check_walkers(walkers, declared={}, out=out))
        self.assertIn("FAIL crates/alpha/tests/scan.rs", out.getvalue())
        self.assertTrue(ts.check_walkers(walkers, declared={"crates/alpha/tests/scan.rs": ()}, out=out))

    def test_a_walk_from_a_joined_top_level_directory_reads_all_of_it(self):
        files = dict(self.BASE)
        files["scripts/old.py"] = ""
        files["crates/alpha/tests/scan.rs"] = (
            'fn root() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).join("../..") }\n'
            'fn walk() { for e in std::fs::read_dir(root().join("scripts")).unwrap() {} }\n'
        )
        files["crates/beta/tests/scan.rs"] = (
            'fn root() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).join("../..") }\n'
            'const TABLES: &[&str] = &["scripts"];\n'
            'fn walk() { for e in std::fs::read_dir(root().join("crates")).unwrap() {} }\n'
        )
        root, pkgs, dirs, names = self.tree(files)
        reads, walkers = ts.scan_reads(root, pkgs, dirs, names)
        self.assertEqual(walkers, {"crates/alpha/tests/scan.rs", "crates/beta/tests/scan.rs"})
        found = {(r[0], r[2], r[3], r[4]) for r in reads}
        self.assertIn(("alpha", "scripts", ts.TARGETS, ("scan",)), found)
        # A word that is not joined onto a path is not a read, and `crates`
        # is left to WALKERS' globs.
        self.assertNotIn("beta", {r[0] for r in reads})
        whole, partial = ts.affected(["scripts/new.py"], pkgs, dirs, reads)
        self.assertEqual((whole, set(partial)), ({}, {"alpha"}))

    def test_a_read_of_a_deleted_file_is_still_a_read(self):
        files = dict(self.BASE)
        files["crates/alpha/tests/scan.rs"] = 'fn f(root: &Path) { root.join("docs/runbooks/2-undo.sql"); }\n'
        root, pkgs, dirs, names = self.tree(files)
        # 2-undo.sql exists only in the base: the change deletes it.
        reads, _ = ts.scan_reads(root, pkgs, dirs, names)
        self.assertEqual(reads, [])
        reads, _ = ts.scan_reads(root, pkgs, dirs, names, gone=["docs/runbooks/2-undo.sql"])
        whole, partial = ts.affected(["docs/runbooks/2-undo.sql"], pkgs, dirs, reads)
        self.assertEqual(whole, {})
        self.assertEqual({p: set(ts_) for p, ts_ in partial.items()}, {"alpha": {"scan"}})

    def test_the_real_tree_declares_every_walker(self):
        self.assertEqual(reads()[1], set(ts.WALKERS))


class ScriptLocation(unittest.TestCase):
    """Which workspace the planner plans, in place and as a copy."""

    def test_in_place_it_plans_its_own_workspace(self):
        root, _pkgs, _shards = workspace()
        here = os.path.join(root, ".github", "scripts", "test-shard.py")
        self.assertEqual(ts.manifest_of(here), os.path.join(root, "Cargo.toml"))

    def test_a_copy_plans_the_workspace_it_is_run_from(self):
        # The local gate (ci-shards) runs copies from its cache directory and
        # from each mirror's .ci-shards/. A copy must not climb two levels
        # from wherever it was put and plan, or fail on, that directory.
        import shutil
        import subprocess
        import sys

        root, _pkgs, shards = workspace()
        with tempfile.TemporaryDirectory() as tmp:
            for sub in ("cache", os.path.join("mirror", ".ci-shards"), os.path.join("x", "scripts")):
                copy = os.path.join(tmp, sub, "test-shard.py")
                os.makedirs(os.path.dirname(copy))
                shutil.copy(SCRIPT, copy)
                out = subprocess.run(
                    [sys.executable, copy, "matrix"], cwd=root, capture_output=True, text=True
                )
                self.assertEqual(out.returncode, 0, f"{sub}: {out.stderr[-400:]}")
                ids = [e["shard"] for e in json.loads(out.stdout)["include"]]
                self.assertEqual(ids, list(shards), sub)


class EventPolicy(unittest.TestCase):
    def test_non_pull_request_events_run_the_full_set(self):
        for event in ("push", "merge_group", "workflow_dispatch", "schedule", "something_new"):
            d = pr_plan(["docs/x.md"], GITHUB_EVENT_NAME=event)
            self.assertEqual(d["mode"], "full", event)

    def test_staging_and_integration_heads_run_the_full_set(self):
        for head in (
            "integration/2026-11-14",
            "integration/a/b",
            "staging/nightly-1114",
            "backlog/base-20261114",
            "atlas/w3-base",
        ):
            self.assertEqual(pr_plan(["docs/x.md"], GITHUB_HEAD_REF=head)["mode"], "full", head)

    def test_ordinary_heads_are_narrowed(self):
        for head in ("perf/ci-affected-shards", "atlas/w3", "backlog/b07", "claude/staging-fix"):
            self.assertEqual(pr_plan(["docs/x.md"], GITHUB_HEAD_REF=head)["mode"], "affected", head)

    def test_the_ci_full_label_runs_the_full_set(self):
        d = pr_plan(["docs/x.md"], PR_LABELS=json.dumps(["documentation", "ci:full"]))
        self.assertEqual(d["mode"], "full")
        d = pr_plan(["docs/x.md"], PR_LABELS=json.dumps(["documentation"]))
        self.assertEqual(d["mode"], "affected")

    def test_an_undiffable_pull_request_runs_the_full_set(self):
        root, pkgs, shards = workspace()
        env = {"GITHUB_EVENT_NAME": "pull_request", "DIFF_BASE": "no-such-ref-anywhere"}
        self.assertEqual(ts.decide(root, pkgs, shards, env)["mode"], "full")
        env = {"GITHUB_EVENT_NAME": "pull_request"}
        self.assertEqual(ts.decide(root, pkgs, shards, env)["mode"], "full")


class RunnerSwitch(unittest.TestCase):
    REPO = "epigraph-io/epigraph"
    SELF = '["self-hosted", "linux", "epigraph-shard"]'

    def test_unset_variable_means_github_hosted(self):
        self.assertEqual(ts.shard_runner("pull_request", self.REPO, self.REPO, ""), ("ubuntu-latest", None))
        self.assertEqual(ts.shard_runner("push", "", self.REPO, ""), ("ubuntu-latest", None))

    def test_same_repository_pull_request_uses_the_variable(self):
        runs_on, warning = ts.shard_runner("pull_request", self.REPO, self.REPO, self.SELF)
        self.assertEqual(runs_on, ["self-hosted", "linux", "epigraph-shard"])
        self.assertIsNone(warning)

    def test_fork_pull_request_never_gets_a_self_hosted_runner(self):
        for head in ("someone/epigraph", "epigraph-io/epigraph-fork", "EPIGRAPH-IO/EPIGRAPH", "", None):
            runs_on, _ = ts.shard_runner("pull_request", head, self.REPO, self.SELF)
            self.assertEqual(runs_on, "ubuntu-latest", head)

    def test_fork_guard_holds_for_every_runs_on_shape(self):
        for raw in ('"self-hosted"', '{"group": "aws-lanes"}', '{"group": "g", "labels": ["x"]}'):
            self.assertEqual(ts.shard_runner("pull_request", "x/y", self.REPO, raw)[0], "ubuntu-latest", raw)
            self.assertNotEqual(ts.shard_runner("push", "", self.REPO, raw)[0], "ubuntu-latest", raw)

    def test_trusted_events_use_the_variable_and_others_do_not(self):
        for event in ("push", "merge_group", "workflow_dispatch", "schedule"):
            self.assertEqual(ts.shard_runner(event, "", self.REPO, self.SELF)[0][0], "self-hosted", event)
        for event in ("pull_request_target", "issue_comment", "workflow_run"):
            self.assertEqual(ts.shard_runner(event, self.REPO, self.REPO, self.SELF)[0], "ubuntu-latest", event)

    def test_an_unusable_variable_falls_back_with_a_warning(self):
        for raw in ("self-hosted", "[]", '[""]', "{}", '{"label": "x"}', "3", '["a", 1]'):
            runs_on, warning = ts.shard_runner("push", "", self.REPO, raw)
            self.assertEqual(runs_on, "ubuntu-latest", raw)
            self.assertIsNotNone(warning, raw)

    def test_the_plan_carries_the_guarded_runner(self):
        fork = pr_plan(["docs/x.md"], HEAD_REPO="someone/epigraph", GITHUB_REPOSITORY=self.REPO, SHARD_RUNS_ON=self.SELF)
        self.assertEqual(fork["runs_on"], "ubuntu-latest")
        own = pr_plan(["docs/x.md"], HEAD_REPO=self.REPO, GITHUB_REPOSITORY=self.REPO, SHARD_RUNS_ON=self.SELF)
        self.assertEqual(own["runs_on"][0], "self-hosted")

    def test_max_parallel(self):
        self.assertEqual(ts.max_parallel(""), (256, None))
        self.assertEqual(ts.max_parallel(" 4 "), (4, None))
        for raw in ("0", "-2", "four", "2.5"):
            cap, warning = ts.max_parallel(raw)
            self.assertEqual(cap, 256, raw)
            self.assertIsNotNone(warning, raw)


class Gate(unittest.TestCase):
    def needs(self, run, **results):
        out = {"plan": {"result": "success", "outputs": {"run": json.dumps(run)}}}
        for name, result in results.items():
            out[name.replace("_", "-")] = {"result": result, "outputs": {}}
        return out

    RUN_NONE = {"test-shard": False, "test-extra": False, "lint-features": False}
    RUN_ALL = {"test-shard": True, "test-extra": True, "lint-features": True}

    def test_empty_matrix_with_skipped_jobs_passes(self):
        needs = self.needs(self.RUN_NONE, test_shard="skipped", test_extra="skipped", lint_features="skipped")
        self.assertEqual(ts.gate(needs), [])

    def test_all_requested_and_successful_passes(self):
        needs = self.needs(self.RUN_ALL, test_shard="success", test_extra="success", lint_features="success")
        self.assertEqual(ts.gate(needs), [])

    def test_a_requested_job_that_was_skipped_fails(self):
        needs = self.needs(self.RUN_ALL, test_shard="skipped", test_extra="success", lint_features="success")
        self.assertEqual(len(ts.gate(needs)), 1)

    def test_a_failure_or_cancellation_fails(self):
        for result in ("failure", "cancelled"):
            needs = self.needs(self.RUN_ALL, test_shard=result, test_extra="success", lint_features="success")
            self.assertTrue(ts.gate(needs), result)

    def test_a_skipped_job_that_ran_and_failed_fails(self):
        needs = self.needs(self.RUN_NONE, test_shard="failure", test_extra="skipped", lint_features="skipped")
        self.assertTrue(ts.gate(needs))

    def test_nothing_passes_without_a_successful_plan(self):
        for plan in ({"result": "failure", "outputs": {}}, {"result": "success", "outputs": {}}):
            needs = {"plan": plan, "test-shard": {"result": "skipped"}}
            self.assertTrue(ts.gate(needs), plan)
        self.assertTrue(ts.gate({"test-shard": {"result": "success"}}))

    def test_a_job_the_plan_does_not_gate_must_succeed(self):
        needs = self.needs(self.RUN_NONE, test_shard="skipped", something_new="skipped")
        self.assertTrue(ts.gate(needs))


class Workflow(unittest.TestCase):
    """The job graph in ci.yml that the planner's outputs drive."""

    @classmethod
    def setUpClass(cls):
        import yaml  # the `plan` job installs it when the image lacks it

        with open(WORKFLOW) as fh:
            cls.text = fh.read()
        cls.ci = yaml.safe_load(cls.text)
        cls.jobs = cls.ci["jobs"]

    def test_shards_run_on_the_planner_runner_only(self):
        self.assertEqual(self.jobs["test-shard"]["runs-on"], "${{ fromJSON(needs.plan.outputs.runs_on) }}")
        # The variable reaches the planner and nothing else: an expression that
        # read it directly would bypass the fork guard.
        self.assertEqual(self.text.count("vars.SHARD_RUNS_ON"), 1)
        step = [s for s in self.jobs["plan"]["steps"] if s.get("id") == "plan"][0]
        self.assertEqual(step["env"]["SHARD_RUNS_ON"], "${{ vars.SHARD_RUNS_ON }}")
        self.assertEqual(step["env"]["HEAD_REPO"], "${{ github.event.pull_request.head.repo.full_name }}")
        for name, job in self.jobs.items():
            if name != "test-shard":
                self.assertNotIn("needs.plan.outputs.runs_on", json.dumps(job.get("runs-on")), name)

    def test_shard_matrix_cap_and_skip_come_from_the_plan(self):
        shard = self.jobs["test-shard"]
        self.assertEqual(shard["needs"], "plan")
        self.assertEqual(shard["strategy"]["matrix"], "${{ fromJSON(needs.plan.outputs.matrix) }}")
        self.assertEqual(shard["strategy"]["max-parallel"], "${{ fromJSON(needs.plan.outputs.max_parallel) }}")
        self.assertFalse(shard["strategy"]["fail-fast"])
        self.assertEqual(shard["if"], "${{ fromJSON(needs.plan.outputs.run)['test-shard'] }}")

    def test_gated_jobs_follow_their_run_flag(self):
        for job in ts.EXTRA_JOBS:
            self.assertEqual(self.jobs[job]["needs"], "plan", job)
            self.assertEqual(self.jobs[job]["if"], "${{ fromJSON(needs.plan.outputs.run)['%s'] }}" % job, job)

    def test_gated_jobs_test_only_their_listed_packages(self):
        import re

        # The test and lint commands; `cargo build -p epigraph-api --bin
        # epigraph-migrate` is how every database job migrates, not a test of
        # epigraph-api.
        for job, packages in ts.EXTRA_JOBS.items():
            runs = " ".join(
                line
                for s in self.jobs[job]["steps"]
                for line in s.get("run", "").splitlines()
                if line.lstrip().startswith(("cargo test", "cargo clippy", "cargo check"))
            )
            named = set(re.findall(r"(?<![\w-])-p\s+([a-z][a-z0-9-]*)", runs))
            self.assertTrue(named, job)
            self.assertLessEqual(named, set(packages), job)

    def test_the_gate_needs_plan_and_every_blocking_test_job(self):
        gate = self.jobs["test"]
        self.assertEqual(gate["if"], "${{ !cancelled() }}")
        self.assertEqual(set(gate["needs"]), {"plan", "test-shard", "test-extra", "lint-features"})
        run = " ".join(s.get("run", "") for s in gate["steps"])
        self.assertIn("test-shard.py gate", run)
        env = [s for s in gate["steps"] if "run" in s][0]["env"]
        self.assertEqual(env["NEEDS"], "${{ toJSON(needs) }}")

    def test_plan_outputs_are_the_ones_the_jobs_read(self):
        outputs = set(self.jobs["plan"]["outputs"])
        used = set(__import__("re").findall(r"needs\.plan\.outputs\.(\w+)", self.text))
        self.assertLessEqual(used, outputs)

    def test_plan_can_diff_a_pull_request_and_still_checks_the_full_plan(self):
        steps = self.jobs["plan"]["steps"]
        checkout = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")][0]
        self.assertGreaterEqual(checkout["with"]["fetch-depth"], 2)
        runs = [s.get("run", "") for s in steps]
        self.assertTrue(any(r.strip() == "python3 .github/scripts/test-shard.py check" for r in runs))
        self.assertTrue(any("unittest discover -s .github/scripts/tests" in r for r in runs))
        self.assertTrue(any("DIFF_BASE=HEAD^1" in r and "ci-plan" in r for r in runs))

    def test_machine_altering_steps_are_github_hosted_only(self):
        for step in self.jobs["test-shard"]["steps"]:
            run = step.get("run", "")
            if "rm -rf" in run:
                self.assertEqual(step.get("if"), "runner.environment == 'github-hosted'", step.get("name"))
            if "apt-get install" in run:
                self.assertIn("command -v mold", run, step.get("name"))

    def test_source_scans_shard_has_its_own_test_step(self):
        steps = {s.get("name"): s for s in self.jobs["test-shard"]["steps"]}
        self.assertEqual(steps["Test"]["if"], "matrix.shard != 'source-scans'")
        self.assertEqual(steps["Test (source scans)"]["if"], "matrix.shard == '%s'" % ts.SCANS)
        self.assertIn("scan-args", steps["Test (source scans)"]["run"])

    def run_step(self, name, env):
        """Run a test-shard step's body under bash -eo pipefail, as the local
        gate does (it ignores `if:`), with a fake `cargo` that logs its
        arguments and, like a test that spawns a child, reads its stdin.
        Returns the logged invocations."""
        import subprocess

        step = [s for s in self.jobs["test-shard"]["steps"] if s.get("name") == name][0]
        root = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "log")
            fake = os.path.join(tmp, "cargo")
            with open(fake, "w") as fh:
                fh.write('#!/bin/sh\ncat > /dev/null\necho "$*" >> "%s"\n' % log)
            os.chmod(fake, 0o755)
            full = dict(os.environ, PATH=tmp + os.pathsep + os.environ["PATH"], **env)
            out = subprocess.run(
                ["bash", "-eo", "pipefail", "-c", step["run"]],
                cwd=root,
                env=full,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(out.returncode, 0, out.stderr)
            if not os.path.exists(log):
                return []
            with open(log) as fh:
                return fh.read().splitlines()

    def test_each_test_step_is_a_no_op_on_the_other_steps_shard(self):
        self.assertEqual(self.run_step("Test", {"SHARD": ts.SCANS, "THREADS": "1"}), [])
        # The literal a runner without the matrix context would pass.
        for shard in ("db-1of2", "${{ matrix.shard }}"):
            env = {"SHARD": shard, "TARGETS": "${{ matrix.targets }}"}
            self.assertEqual(self.run_step("Test (source scans)", env), [], shard)

    def test_source_scans_runs_every_invocation_even_if_a_test_reads_stdin(self):
        targets = json.dumps({"epigraph-db": ["a", "b"], "epigraph-cli": ["c"]})
        calls = self.run_step("Test (source scans)", {"SHARD": ts.SCANS, "TARGETS": targets})
        self.assertEqual(len(calls), 2, calls)
        self.assertTrue(calls[0].startswith("test --locked --no-fail-fast -p epigraph-cli --test c"), calls)
        self.assertIn("-p epigraph-db --test a --test b -- --test-threads=4", calls[1])


if __name__ == "__main__":
    unittest.main()
