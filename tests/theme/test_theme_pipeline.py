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
