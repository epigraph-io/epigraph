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
