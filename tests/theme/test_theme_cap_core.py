"""The theme-cap split's pure core and its export file format (no DB).

Atlas W1 (backlog 8c4aefda): every theme over the cap is split, by UMAP over its
members' embeddings and then clustering, until every part is at or under the cap.
The split is a pure function of (claim ids, embeddings, cap, seed), so it can run
off the prod box on ids and embeddings alone. The CLI (names, role guard, the
off-box `compute` step) and the DB arm are tests/theme/test_theme_cap_split.py.
"""
import uuid

import numpy as np
import pytest

from scripts import theme_cap_core as core


def _blobs(n_blobs=5, per_blob=900, dim=64, seed=7):
    """`n_blobs` tight, well-separated clusters. Returns (ids, X, blob_of_id)."""
    rng = np.random.RandomState(seed)
    ids, rows, blob_of = [], [], {}
    for b in range(n_blobs):
        centre = rng.normal(size=dim)
        for _ in range(per_blob):
            cid = str(uuid.UUID(int=rng.randint(0, 2**62) << 64 | rng.randint(0, 2**62)))
            ids.append(cid)
            rows.append(centre + 0.05 * rng.normal(size=dim))
            blob_of[cid] = b
    return ids, np.asarray(rows, dtype=np.float32), blob_of


@pytest.fixture(scope="module")
def blobs_split():
    ids, x, blob_of = _blobs()
    return ids, x, blob_of, core.split_to_cap(ids, x, cap=2000, seed=42)


def test_blobs_split_under_cap_without_cutting_a_blob(blobs_split):
    ids, _, blob_of, parts = blobs_split

    assert len(parts) >= 3, "4,500 claims under a 2,000 cap needs at least three parts"
    assert all(len(p) <= 2000 for p in parts)
    assert sorted(c for p in parts for c in p) == sorted(ids), "parts must cover every id once"
    # Chunking by id would also satisfy the cap. Only a split that follows the
    # embeddings keeps each blob whole, so this is what proves the clustering ran.
    part_of_blob = {}
    for i, part in enumerate(parts):
        for cid in part:
            part_of_blob.setdefault(blob_of[cid], set()).add(i)
    assert all(len(v) == 1 for v in part_of_blob.values()), f"a blob was cut: {part_of_blob}"


def test_parts_are_ordered_largest_first_then_smallest_id(blobs_split):
    _, _, _, parts = blobs_split
    keys = [(-len(p), min(p)) for p in parts]
    assert keys == sorted(keys)
    assert all(p == sorted(p) for p in parts)


def test_split_is_deterministic_and_input_order_free(blobs_split):
    ids, x, _, parts = blobs_split
    perm = np.random.RandomState(3).permutation(len(ids))
    again = core.split_to_cap([ids[i] for i in perm], x[perm], cap=2000, seed=42)
    assert again == parts


def test_degenerate_identical_embeddings_terminate_under_cap():
    ids = [str(uuid.UUID(int=i + 1)) for i in range(151)]
    x = np.ones((151, 8), dtype=np.float32)

    parts = core.split_to_cap(ids, x, cap=50, seed=42)

    assert all(len(p) <= 50 for p in parts)
    assert sorted(c for p in parts for c in p) == sorted(ids)
    assert core.split_to_cap(ids, x, cap=50, seed=42) == parts


def test_a_theme_at_the_cap_is_one_part():
    ids = [str(uuid.UUID(int=i + 1)) for i in range(40)]
    x = np.random.RandomState(1).normal(size=(40, 8)).astype(np.float32)
    assert core.split_to_cap(ids, x, cap=40) == [sorted(ids)]


def test_validate_parts_rejects_overlap_gap_and_over_cap():
    members = ["a", "b", "c", "d"]
    core.validate_parts(members, [["a", "b"], ["c", "d"]], cap=2)
    with pytest.raises(ValueError, match="cover"):
        core.validate_parts(members, [["a", "b"], ["c"]], cap=2)
    with pytest.raises(ValueError, match="more than one part"):
        core.validate_parts(members, [["a", "b"], ["b", "c", "d"]], cap=3)
    with pytest.raises(ValueError, match="over the cap"):
        core.validate_parts(members, [["a", "b", "c"], ["d"]], cap=2)


def test_export_file_is_ids_and_embeddings_only_and_loads_without_pickle(tmp_path):
    ids = [str(uuid.UUID(int=i + 1)) for i in range(5)]
    x = np.arange(15, dtype=np.float32).reshape(5, 3)
    path = tmp_path / "t.npz"

    core.write_theme_npz(path, ids, x)

    with np.load(path, allow_pickle=False) as z:
        assert sorted(z.files) == ["claim_ids", "embeddings"]
        assert z["claim_ids"].dtype.kind == "U"
    got_ids, got_x = core.read_theme_npz(path)
    assert got_ids == ids
    assert np.array_equal(got_x, x)
