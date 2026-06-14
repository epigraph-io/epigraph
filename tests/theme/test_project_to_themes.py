"""Unit + integration tests for cluster → theme projection."""
import json
import pytest

from scripts import project_to_themes as P
from tests.theme.conftest import make_embedding


def test_theme_properties_records_lineage():
    props = P.theme_properties("run-123", 7)
    assert props["source"] == "cluster_run"
    assert props["cluster_run_id"] == "run-123"
    assert props["cluster_id"] == 7


def _seed_run(db, agent_id):
    """Two clusters, 3 claims each, with cluster_labels + claim_clusters."""
    run_id = "11111111-1111-1111-1111-111111111111"
    claim_ids = []
    with db.cursor() as cur:
        for cl in range(2):
            for i in range(3):
                content = f"c{cl}-{i}"
                cur.execute(
                    "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding) "
                    "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector) RETURNING id::text",
                    (content, content, agent_id, make_embedding(cl)),
                )
                cid = cur.fetchone()[0]
                claim_ids.append(cid)
                cur.execute(
                    "INSERT INTO claim_clusters (claim_id, cluster_id, centroid_distance, "
                    "second_centroid_dist, boundary_ratio, silhouette_score, cluster_run_id, "
                    "centroid_distances) VALUES (%s,%s,0.1,0.5,0.2,0.8,%s,%s)",
                    (cid, cl, run_id, [0.1, 0.5]),
                )
            cur.execute(
                "INSERT INTO cluster_labels (cluster_run_id, cluster_id, label, sample_count) "
                "VALUES (%s,%s,%s,3)",
                (run_id, cl, f"cluster-{cl}"),
            )
    db.commit()
    return run_id, claim_ids


def test_project_run_materialises_themes(db, seed_agent):
    run_id, claim_ids = _seed_run(db, seed_agent)

    P.project_run(db, run_id)

    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM claim_themes")
        assert cur.fetchone()[0] == 2  # one theme per cluster
        cur.execute("SELECT count(*) FROM claims WHERE theme_id IS NULL AND id::text = ANY(%s)",
                    (claim_ids,))
        assert cur.fetchone()[0] == 0  # every seeded claim now themed
        cur.execute("SELECT count(*) FROM claim_themes WHERE centroid IS NULL")
        assert cur.fetchone()[0] == 0  # real 1536-d centroid set
        cur.execute("SELECT properties->>'cluster_run_id' FROM claim_themes LIMIT 1")
        assert cur.fetchone()[0] == run_id
