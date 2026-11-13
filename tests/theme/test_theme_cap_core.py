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


def _uuid(rng):
    return str(uuid.UUID(int=rng.randint(0, 2**62) << 64 | rng.randint(0, 2**62)))


def test_a_small_separated_cluster_stays_whole_just_over_the_cap():
    """A theme just over the cap gets k = 2. When one of the two clusters is a
    small separated subtopic (under cap // 20), merging it back leaves one
    group; the split must then split the dominant cluster by its geometry, not
    cut the whole theme into halves by claim id (each a random sample of it)."""
    rng = np.random.RandomState(0)
    dim = 64
    core_c, out_c = rng.normal(size=dim), rng.normal(size=dim)
    x = np.vstack([core_c + 0.3 * rng.normal(size=(412, dim)),
                   out_c + 0.05 * rng.normal(size=(12, dim))]).astype(np.float32)
    ids = [_uuid(rng) for _ in range(len(x))]
    outliers = set(ids[412:])

    parts, stats = core.split_to_cap_with_stats(ids, x, cap=400, seed=42)

    assert len(parts) >= 2 and all(len(p) <= 400 for p in parts)
    assert sorted(c for p in parts for c in p) == sorted(ids)
    holding = [len(outliers & set(p)) for p in parts]
    assert sorted(holding)[-1] == len(outliers), f"the separated cluster was cut: {holding}"
    assert stats == {"id_chunk_cuts": 0}, "an id-order cut ran on separable embeddings"
    assert core.split_to_cap(ids, x, cap=400, seed=42) == parts


def _moons(n=300, dim=32, seed=5, noise=0.03):
    """Two interleaved half-circles: no straight cut separates them, so k-means
    on the raw (normalised) vectors mixes them, while k-means in UMAP's space,
    whose neighbour graph keeps each moon connected, does not."""
    rng = np.random.RandomState(seed)
    t0, t1 = rng.uniform(0, np.pi, size=n), rng.uniform(0, np.pi, size=n)
    pts = np.vstack([np.c_[np.cos(t0), np.sin(t0)], np.c_[1 - np.cos(t1), 0.5 - np.sin(t1)]])
    pts += noise * rng.normal(size=pts.shape)
    x = np.zeros((2 * n, dim), dtype=np.float32)
    x[:, 0] = 10.0  # a shared offset, so normalising barely bends the moons
    x[:, 1:3] = pts
    x[:, 3:] = noise * rng.normal(size=(2 * n, dim - 3))
    ids = [_uuid(rng) for _ in range(2 * n)]
    return ids, x, {c: int(i >= n) for i, c in enumerate(ids)}


def test_the_split_follows_umap_structure_not_raw_kmeans():
    """UMAP is the method the backlog item names. Without it (k-means on the
    normalised vectors alone) each part holds roughly a quarter of the other
    moon; with it each part is exactly one moon."""
    ids, x, moon_of = _moons()

    parts = core.split_to_cap(ids, x, cap=400, seed=42)

    assert len(parts) == 2
    assert [len({moon_of[c] for c in p}) for p in parts] == [1, 1], \
        [[sum(moon_of[c] == m for c in p) for m in (0, 1)] for p in parts]


def test_degenerate_identical_embeddings_terminate_under_cap():
    ids = [str(uuid.UUID(int=i + 1)) for i in range(151)]
    x = np.ones((151, 8), dtype=np.float32)

    parts, stats = core.split_to_cap_with_stats(ids, x, cap=50, seed=42)

    assert stats["id_chunk_cuts"] >= 1, "identical vectors can only be cut by id"
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
