"""cluster_claims stores and loads UMAP centroids at their own size (backlog 58452334).

Before migration 222 the 32-d UMAP centroids were zero-padded into the
vector(1536) `centroid` column and sliced back out on load. The script now
writes and reads `umap_centroid vector(32)`; the padded column is left NULL.
"""
import numpy as np
import pytest

from scripts import cluster_claims as C

RUN = "00000000-0000-0000-0000-00000000c222"
OTHER_RUN = "00000000-0000-0000-0000-00000000d222"


def _centroids(k=3, seed=7):
    return np.random.RandomState(seed).normal(0, 1, (k, C.UMAP_DIM)).astype(np.float32)


def test_centroids_are_stored_as_32_d_vectors_and_load_back(db):
    want = _centroids()
    C.store_centroids(db, RUN, want)
    with db.cursor() as cur:
        cur.execute(
            "SELECT cluster_id, vector_dims(umap_centroid), centroid IS NULL "
            "FROM cluster_centroids WHERE cluster_run_id = %s ORDER BY cluster_id",
            (RUN,),
        )
        assert cur.fetchall() == [(0, 32, True), (1, 32, True), (2, 32, True)]
        cur.execute(
            "SELECT format_type(atttypid, atttypmod) FROM pg_attribute "
            "WHERE attrelid = 'cluster_centroids'::regclass AND attname = 'umap_centroid'"
        )
        assert cur.fetchone()[0] == "vector(32)"

    got, run = C.load_centroids_from_db(db, RUN)
    assert run == RUN
    assert got.shape == (3, C.UMAP_DIM)
    np.testing.assert_allclose(got, want, rtol=1e-6)

    # Re-seeding the same run replaces the centroids in place.
    C.store_centroids(db, RUN, want * 2)
    got, _ = C.load_centroids_from_db(db, RUN)
    np.testing.assert_allclose(got, want * 2, rtol=1e-6)


def test_store_refuses_centroids_of_another_size(db):
    with pytest.raises(ValueError):
        C.store_centroids(db, RUN, np.zeros((2, 1536), dtype=np.float32))


def test_load_refuses_a_run_222_could_not_backfill(db, capsys):
    """A legacy row whose padded `centroid` had a non-zero tail kept a NULL
    umap_centroid; loading its run exits with a reason instead of building a
    centroid matrix with a hole in it."""
    C.store_centroids(db, OTHER_RUN, _centroids(k=1))
    tail = [0.0] * 1536
    tail[0], tail[40] = 1.0, 1.0
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO cluster_centroids (cluster_run_id, cluster_id, centroid) "
            "VALUES (%s, 1, %s::vector)",
            (OTHER_RUN, "[" + ",".join(map(str, tail)) + "]"),
        )
    db.commit()
    with pytest.raises(SystemExit):
        C.load_centroids_from_db(db, OTHER_RUN)
    assert "no umap_centroid for cluster(s) [1]" in capsys.readouterr().err
