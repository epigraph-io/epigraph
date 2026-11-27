"""Unit tests for the orchestrator's pure decision logic."""
from scripts import theme_pipeline as T


def test_select_clusters_to_split_picks_high_variance():
    stats = [
        {"cluster_id": 0, "size": 5000, "p95_dist": 0.9, "mean_boundary": 0.8},
        {"cluster_id": 1, "size": 300, "p95_dist": 0.9, "mean_boundary": 0.8},   # too small
        {"cluster_id": 2, "size": 5000, "p95_dist": 0.1, "mean_boundary": 0.1},  # coherent
    ]
    picked = T.select_clusters_to_split(stats, min_size=2000, p95_threshold=0.5,
                                        boundary_threshold=0.5)
    assert picked == [0]


def test_oversized_cluster_splits_even_when_tight_in_umap_space():
    """The 2026-08-17 prod run's actual failure.

    Distances are measured in UMAP-32 normalized space, where a coherent
    cluster's p95 lands around 0.03 — two orders of magnitude below the 0.5
    threshold. Every one of the six giants therefore failed BOTH variance
    tests and survived untouched, while 67 crumbs were split. These are the
    real numbers read off cluster_run 16138781.
    """
    stats = [
        {"cluster_id": 0, "size": 51772, "p95_dist": 0.035, "mean_boundary": 0.360},
        {"cluster_id": 4, "size": 50684, "p95_dist": 0.037, "mean_boundary": 0.399},
        {"cluster_id": 5, "size": 45271, "p95_dist": 0.065, "mean_boundary": 0.418},
        {"cluster_id": 24, "size": 1961, "p95_dist": 0.036, "mean_boundary": 0.826},
    ]
    picked = T.select_clusters_to_split(stats)
    assert picked == [0, 4, 5], (
        "clusters holding tens of thousands of claims must be split on size alone; "
        f"got {picked}"
    )


def test_small_cluster_is_never_split_by_the_size_trigger():
    """The size trigger must not drag in clusters below min_size."""
    stats = [{"cluster_id": 1, "size": 300, "p95_dist": 0.9, "mean_boundary": 0.9}]
    assert T.select_clusters_to_split(stats, min_size=2000) == []


def test_size_trigger_is_independent_of_variance_thresholds():
    """Raising the variance thresholds out of reach must not disarm the size trigger.

    Guards the regression directly: if someone re-tunes p95_threshold instead of
    keeping an absolute ceiling, oversized clusters silently stop splitting again.
    """
    stats = [{"cluster_id": 0, "size": 40000, "p95_dist": 0.0, "mean_boundary": 0.0}]
    picked = T.select_clusters_to_split(
        stats, p95_threshold=99.0, boundary_threshold=99.0, max_size=8000
    )
    assert picked == [0]


def test_target_k_does_not_stop_the_loop_while_a_giant_remains():
    """`target_k reached` fired before any giant was split in the prod run.

    k hit 76 against target_k=72 by splitting small clusters, so the loop
    declared success with 81.7% of the corpus in six themes.
    """
    assert T.stop_reason(
        current_k=76, target_k=72, iterations=1, max_iter=8,
        n_selected=6, n_oversized=6,
    ) is None


def test_target_k_still_stops_once_nothing_is_oversized():
    assert T.stop_reason(
        current_k=76, target_k=72, iterations=1, max_iter=8,
        n_selected=6, n_oversized=0,
    ) == "target_k reached"


def test_max_iter_beats_an_unsplittable_giant():
    """A giant that refuses to shrink must not loop forever."""
    assert T.stop_reason(
        current_k=76, target_k=72, iterations=8, max_iter=8,
        n_selected=1, n_oversized=1,
    ) == "max_iter reached"


def test_stop_reason_target_reached():
    assert T.stop_reason(current_k=72, target_k=72, iterations=3, max_iter=10,
                         n_selected=5) == "target_k reached"


def test_stop_reason_no_candidates():
    assert T.stop_reason(current_k=20, target_k=72, iterations=3, max_iter=10,
                         n_selected=0) == "no split candidates"


def test_stop_reason_max_iter():
    assert T.stop_reason(current_k=30, target_k=72, iterations=10, max_iter=10,
                         n_selected=5) == "max_iter reached"


def test_stop_reason_continue():
    assert T.stop_reason(current_k=30, target_k=72, iterations=2, max_iter=10,
                         n_selected=5) is None


# --- label step: same database, absolute script path, failure surfaced --------

def test_label_env_forwards_the_pipeline_database_url():
    """Left to itself the label script resolves its own DSN and relabels a
    different database than the one just clustered. The URL goes through the
    child's environment, not argv (tests/theme/test_label_step_dsn.py)."""
    env = T.label_env("postgres://u:p@localhost/scratch_test")
    assert env["MAINTENANCE_DATABASE_URL"] == "postgres://u:p@localhost/scratch_test"
    assert "--relabel-all" in T.label_command()


def test_label_command_script_path_does_not_depend_on_cwd(tmp_path, monkeypatch):
    import os
    monkeypatch.chdir(tmp_path)
    script = T.label_command()[1]
    assert os.path.isabs(script)
    assert os.path.isfile(script)
    assert os.path.basename(script) == "label_themes_llm.py"


def test_run_label_step_refuses_a_missing_url():
    import pytest
    with pytest.raises(ValueError):
        T.run_label_step(None)


def test_run_label_step_returns_the_subprocess_exit_code(monkeypatch):
    seen = {}

    class Done:
        returncode = 3

    def fake_run(cmd, check, env=None):
        seen["cmd"], seen["check"], seen["env"] = cmd, check, env
        return Done()

    monkeypatch.setattr(T.subprocess, "run", fake_run)
    assert T.run_label_step("postgres://u:p@localhost/scratch_test") == 3
    assert seen["cmd"] == T.label_command()
    assert seen["env"]["DATABASE_URL"] == "postgres://u:p@localhost/scratch_test"


def test_run_label_step_reports_a_step_that_could_not_start(monkeypatch):
    def fake_run(cmd, check, env=None):
        raise FileNotFoundError("no interpreter")

    monkeypatch.setattr(T.subprocess, "run", fake_run)
    assert T.run_label_step("postgres://u:p@localhost/scratch_test") != 0


def test_grow_result_does_not_call_a_failed_label_step_grown():
    assert T.grow_result("r1", 72, 0) == {"status": "grown", "run_id": "r1", "k": 72}
    failed = T.grow_result("r1", 72, 2)
    assert failed["status"] == "label_failed"
    assert failed["label_returncode"] == 2
    assert failed["run_id"] == "r1" and failed["k"] == 72


def test_grow_labels_the_database_it_was_given_and_surfaces_failure(monkeypatch):
    """grow's label step gets args.database_url, and its failure reaches the
    returned status (it used to return "grown" whatever the subprocess did)."""
    import argparse
    labelled = []

    def fake_label(url):
        labelled.append(url)
        return 1

    monkeypatch.setattr(T, "cluster_stats", lambda conn, run_id: [])
    monkeypatch.setattr(T, "current_k", lambda conn, run_id: 5)
    monkeypatch.setattr(T.project_to_themes, "check_full_rebuild", lambda conn, confirm: None)
    monkeypatch.setattr(T.project_to_themes, "project_run", lambda conn, run_id, **kw: None)
    monkeypatch.setattr(T, "run_label_step", fake_label)
    args = argparse.Namespace(
        from_run_id="run-x", database_url="postgres://u:p@localhost/scratch_test",
        min_size=2000, max_size=T.DEFAULT_MAX_SIZE, target_k=72, max_iter=8,
        dry_run=False, confirm_full_rebuild=False,
    )
    result = T.grow(_Conn([]), args)
    assert labelled == ["postgres://u:p@localhost/scratch_test"]
    assert result["status"] == "label_failed"
    assert result["run_id"] == "run-x"


def test_a_fresh_grow_dry_run_writes_nothing(monkeypatch):
    """`grow --dry-run` without --from-run-id used to run base clustering
    (seed_phase commits a new run and overwrites the reducer file; assign_batch
    commits claim_clusters) and only checked dry_run afterwards. That run then
    became the newest one `project` / `discover` pick by default. Every write
    step is a tripwire here; the dry run must reach none of them."""
    import argparse

    def tripwire(name):
        def hit(*_a, **_k):
            raise AssertionError(f"dry run reached the write step {name}")
        return hit

    monkeypatch.setattr(T.theme_lib, "new_run_id", tripwire("new_run_id"))
    monkeypatch.setattr(T.cluster_claims, "seed_phase", tripwire("seed_phase"))
    monkeypatch.setattr(T.cluster_claims, "assign_batch", tripwire("assign_batch"))
    monkeypatch.setattr(T.refine_clusters, "auto_refine", tripwire("auto_refine"))
    monkeypatch.setattr(T.project_to_themes, "project_run", tripwire("project_run"))
    monkeypatch.setattr(T, "run_label_step", tripwire("run_label_step"))
    args = argparse.Namespace(
        from_run_id=None, database_url="postgres://u:p@localhost/scratch_test",
        sample_size=5000, k=None, all_claims=False, batch_size=20000,
        min_size=2000, max_size=T.DEFAULT_MAX_SIZE, target_k=72, max_iter=8,
        dry_run=True,
    )
    result = T.grow(None, args)
    assert result["status"] == "dry-run"
    assert result["run_id"] is None


def test_a_resumed_grow_dry_run_reports_candidates_without_writing(monkeypatch):
    """With --from-run-id the dry run still inspects the existing run (reads
    only) and stops before splitting, projecting or labelling."""
    import argparse

    def tripwire(name):
        def hit(*_a, **_k):
            raise AssertionError(f"dry run reached the write step {name}")
        return hit

    stats = [{"cluster_id": 0, "size": 9000, "p95_dist": 0.01, "mean_boundary": 0.1}]
    monkeypatch.setattr(T, "cluster_stats", lambda conn, run_id: stats)
    monkeypatch.setattr(T, "current_k", lambda conn, run_id: 1)
    monkeypatch.setattr(T.refine_clusters, "auto_refine", tripwire("auto_refine"))
    monkeypatch.setattr(T.project_to_themes, "project_run", tripwire("project_run"))
    monkeypatch.setattr(T, "run_label_step", tripwire("run_label_step"))
    args = argparse.Namespace(
        from_run_id="run-x", database_url="postgres://u:p@localhost/scratch_test",
        min_size=2000, max_size=T.DEFAULT_MAX_SIZE, target_k=72, max_iter=8,
        dry_run=True,
    )
    result = T.grow(None, args)
    assert result == {"status": "dry-run", "run_id": "run-x", "k": 1}


# --- the full-rebuild guard (backlog 18ae37e7) ---------------------------------

class _Conn:
    """A connection stand-in that records the calls made on it into `log`."""

    def __init__(self, log):
        self.log = log

    def rollback(self):
        self.log.append("rollback")


def _grow_args(**kw):
    import argparse
    base = dict(
        from_run_id=None, database_url="postgres://u:p@localhost/scratch_test",
        sample_size=5000, k=None, all_claims=False, batch_size=20000,
        min_size=2000, max_size=T.DEFAULT_MAX_SIZE, target_k=72, max_iter=8,
        dry_run=False, confirm_full_rebuild=False,
    )
    base.update(kw)
    return argparse.Namespace(**base)


def test_grow_refuses_an_unconfirmed_rebuild_before_clustering(monkeypatch):
    """grow projects at the very END of a long clustering run; the guard has
    to fire before the run starts, not after it has been paid for."""
    import pytest

    def tripwire(name):
        def hit(*_a, **_k):
            raise AssertionError(f"an unconfirmed grow reached {name}")
        return hit

    def refuse(conn, confirm):
        assert confirm is False
        raise T.project_to_themes.FullRebuildRefused("claim_themes: 9 themes")

    monkeypatch.setattr(T.project_to_themes, "check_full_rebuild", refuse)
    monkeypatch.setattr(T.theme_lib, "new_run_id", tripwire("new_run_id"))
    monkeypatch.setattr(T.cluster_claims, "seed_phase", tripwire("seed_phase"))
    monkeypatch.setattr(T.cluster_claims, "assign_batch", tripwire("assign_batch"))
    monkeypatch.setattr(T, "cluster_stats", tripwire("cluster_stats"))
    monkeypatch.setattr(T.project_to_themes, "project_run", tripwire("project_run"))
    with pytest.raises(T.project_to_themes.FullRebuildRefused):
        T.grow(None, _grow_args())
    with pytest.raises(T.project_to_themes.FullRebuildRefused):
        T.grow(None, _grow_args(from_run_id="run-x"))


def test_grow_forwards_the_confirmation_to_the_projection(monkeypatch):
    seen = {}
    monkeypatch.setattr(T.project_to_themes, "check_full_rebuild",
                        lambda conn, confirm: seen.setdefault("checked", confirm))
    monkeypatch.setattr(T, "cluster_stats", lambda conn, run_id: [])
    monkeypatch.setattr(T, "current_k", lambda conn, run_id: 5)

    def fake_project_run(conn, run_id, *, confirm_full_rebuild=False):
        seen["projected"] = confirm_full_rebuild

    monkeypatch.setattr(T.project_to_themes, "project_run", fake_project_run)
    monkeypatch.setattr(T, "run_label_step", lambda url: 0)
    result = T.grow(_Conn([]), _grow_args(from_run_id="run-x", confirm_full_rebuild=True))
    assert seen == {"checked": True, "projected": True}
    assert result["status"] == "grown"


def test_grow_ends_the_checks_read_transaction_before_clustering(monkeypatch):
    """The check reads claim_themes and every table cascading from it. Left
    open, its transaction would hold those locks through the whole UMAP fit."""
    log = []

    class Stop(Exception):
        pass

    def stop_at_seed(*_a, **_k):
        log.append("seed_phase")
        raise Stop

    monkeypatch.setattr(T.project_to_themes, "check_full_rebuild",
                        lambda conn, confirm: log.append("check"))
    monkeypatch.setattr(T.theme_lib, "new_run_id", lambda: "run-new")
    monkeypatch.setattr(T.cluster_claims, "seed_phase", stop_at_seed)
    import pytest
    with pytest.raises(Stop):
        T.grow(_Conn(log), _grow_args(confirm_full_rebuild=True))
    assert log == ["check", "rollback", "seed_phase"]


def test_pipeline_cli_takes_the_flag_and_exits_nonzero_on_a_refusal(monkeypatch, capsys):
    import pytest
    seen = {}

    class Conn:
        def rollback(self):
            seen["rolled_back"] = True

        def close(self):
            seen["closed"] = True

    def refuse(conn, run_id, *, confirm_full_rebuild=False):
        seen["confirm"] = confirm_full_rebuild
        raise T.project_to_themes.FullRebuildRefused("claim_themes: 4 themes")

    monkeypatch.setattr(T.theme_lib, "connect", lambda url: Conn())
    monkeypatch.setattr(T.theme_lib, "set_statement_timeout", lambda conn, ms: None)
    monkeypatch.setattr(T.project_to_themes, "project_run", refuse)
    monkeypatch.setattr(T.sys, "argv", ["theme_pipeline.py", "project", "--run-id", "r1",
                                        "--database-url", "postgres://u:p@localhost/x"])
    with pytest.raises(SystemExit) as exc:
        T.main()
    assert exc.value.code == 1
    assert seen == {"confirm": False, "rolled_back": True, "closed": True}
    assert "claim_themes: 4 themes" in capsys.readouterr().err

    monkeypatch.setattr(T.sys, "argv", ["theme_pipeline.py", "project", "--run-id", "r1",
                                        "--database-url", "postgres://u:p@localhost/x",
                                        "--i-understand-full-rebuild"])
    seen.clear()
    with pytest.raises(SystemExit):
        T.main()
    assert seen["confirm"] is True
