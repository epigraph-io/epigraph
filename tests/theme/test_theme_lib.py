"""Unit tests for the shared theme-clustering helpers (pure functions only)."""
import numpy as np
import pytest

from scripts import theme_lib


def test_parse_embeddings_shape_and_dtype():
    rows = ["[0.0, 1.0, 2.0]", "[3.0, 4.0, 5.0]"]
    arr = theme_lib.parse_embeddings(rows)
    assert arr.dtype == np.float32
    assert arr.shape == (2, 3)
    assert arr[1, 2] == pytest.approx(5.0)


def test_parse_embeddings_empty():
    arr = theme_lib.parse_embeddings([])
    assert arr.shape == (0,)


def test_boundary_metrics_basic():
    # Distances to 3 centroids; nearest=index1 (0.2), second=0.5.
    dists = np.array([0.5, 0.2, 0.9], dtype=np.float32)
    nearest, nearest_dist, second_dist, boundary, sil = theme_lib.boundary_metrics(dists)
    assert nearest == 1
    assert nearest_dist == pytest.approx(0.2)
    assert second_dist == pytest.approx(0.5)
    assert boundary == pytest.approx(0.2 / 0.5)
    assert sil == pytest.approx(1.0 - 0.2 / 0.5)


def test_boundary_metrics_zero_second_is_safe():
    # Degenerate: only one centroid distance non-trivial; second is 0.0.
    dists = np.array([0.0, 0.0], dtype=np.float32)
    nearest, nearest_dist, second_dist, boundary, sil = theme_lib.boundary_metrics(dists)
    assert boundary == 0.0  # guarded division
    assert sil == 1.0
