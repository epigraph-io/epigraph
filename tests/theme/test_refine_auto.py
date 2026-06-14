"""Unit + integration tests for refine_clusters.py --auto."""
import pytest

from scripts import refine_clusters as R
from tests.theme.conftest import make_embedding


def test_build_subcluster_prompt_contains_samples():
    prompt = R.build_subcluster_label_prompt(["alpha claim", "beta claim"])
    assert "alpha claim" in prompt and "beta claim" in prompt
    assert "theme name" in prompt.lower()


def test_parse_subcluster_label_strips_noise():
    assert R.parse_subcluster_label('"DNA Origami"') == "DNA Origami"
    assert R.parse_subcluster_label("Electrostatic Actuation.\nblah") == "Electrostatic Actuation"
    assert R.parse_subcluster_label("") == ""


def test_auto_refine_splits_cluster(db, seed_agent, monkeypatch):
    run_id = "22222222-2222-2222-2222-222222222222"
    # One cluster (id=0) holding two embedding blobs -> should split into 2.
    with db.cursor() as cur:
        for blob in range(2):
            for i in range(15):
                content = f"blob{blob}-{i}"
                cur.execute(
                    "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding) "
                    "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector) RETURNING id::text",
                    (content, content, seed_agent, make_embedding(blob * 50)),
                )
                cid = cur.fetchone()[0]
                cur.execute(
                    "INSERT INTO claim_clusters (claim_id, cluster_id, centroid_distance, "
                    "second_centroid_dist, boundary_ratio, silhouette_score, cluster_run_id, "
                    "centroid_distances) VALUES (%s,0,0.4,0.5,0.8,0.2,%s,%s)",
                    (cid, run_id, [0.4, 0.5]),
                )
    db.commit()

    # Avoid real claude: deterministic labels.
    monkeypatch.setattr(R, "llm_label_subcluster", lambda samples, idx: f"sub-{idx}")

    result = R.auto_refine(db, cluster_id=0, run_id=run_id, min_sub_size=5)
    assert result["split"] is True
    assert result["n_subclusters"] >= 2

    with db.cursor() as cur:
        cur.execute("SELECT count(DISTINCT cluster_id) FROM claim_clusters WHERE cluster_run_id=%s",
                    (run_id,))
        assert cur.fetchone()[0] >= 2  # cluster 0 replaced by 0*100+sub ids


def test_auto_refine_no_id_collision_with_sibling(db, seed_agent, monkeypatch):
    """Splitting cluster 0 in a consolidated run must NOT reuse sibling ids.

    Regression for the cluster_id*100+sub scheme, which produced ids {0,1,2}
    for a 3-way split of cluster 0 and silently merged them into siblings 1,2.
    Monotonic allocation (max+1) must keep sibling cluster 1 intact and place
    new sub-ids strictly above the existing max.
    """
    run_id = "33333333-3333-3333-3333-333333333333"
    sib_ids = []
    with db.cursor() as cur:
        # cluster 0: two well-separated blobs -> should split.
        for blob in range(2):
            for i in range(15):
                content = f"t3-c0b{blob}-{i}"
                cur.execute(
                    "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding) "
                    "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector) RETURNING id::text",
                    (content, content, seed_agent, make_embedding(blob * 70)),
                )
                cid = cur.fetchone()[0]
                cur.execute(
                    "INSERT INTO claim_clusters (claim_id, cluster_id, centroid_distance, "
                    "second_centroid_dist, boundary_ratio, silhouette_score, cluster_run_id, "
                    "centroid_distances) VALUES (%s,0,0.4,0.5,0.8,0.2,%s,%s)",
                    (cid, run_id, [0.4, 0.5]),
                )
        # cluster 1: sibling that MUST remain intact (id collision target).
        for i in range(10):
            content = f"t3-c1-{i}"
            cur.execute(
                "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding) "
                "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector) RETURNING id::text",
                (content, content, seed_agent, make_embedding(200)),
            )
            cid = cur.fetchone()[0]
            sib_ids.append(cid)
            cur.execute(
                "INSERT INTO claim_clusters (claim_id, cluster_id, centroid_distance, "
                "second_centroid_dist, boundary_ratio, silhouette_score, cluster_run_id, "
                "centroid_distances) VALUES (%s,1,0.1,0.5,0.2,0.8,%s,%s)",
                (cid, run_id, [0.1, 0.5]),
            )
    db.commit()

    monkeypatch.setattr(R, "llm_label_subcluster", lambda samples, idx: f"sub-{idx}")
    result = R.auto_refine(db, cluster_id=0, run_id=run_id, min_sub_size=5)
    assert result["split"] is True

    with db.cursor() as cur:
        # Sibling cluster 1 untouched — all 10 still cluster_id=1.
        cur.execute(
            "SELECT count(*) FROM claim_clusters WHERE cluster_run_id=%s AND cluster_id=1 "
            "AND claim_id = ANY(%s::uuid[])",
            (run_id, sib_ids),
        )
        assert cur.fetchone()[0] == 10
        # New sub-cluster ids are allocated above the prior max (1), never onto it.
        cur.execute(
            "SELECT DISTINCT cluster_id FROM claim_clusters WHERE cluster_run_id=%s ORDER BY cluster_id",
            (run_id,),
        )
        cids = [r[0] for r in cur.fetchall()]
        assert 1 in cids                       # sibling preserved
        assert max(cids) >= 2                  # splits placed above the max
        # No new claim landed on the sibling id beyond the original 10.
        cur.execute("SELECT count(*) FROM claim_clusters WHERE cluster_run_id=%s AND cluster_id=1", (run_id,))
        assert cur.fetchone()[0] == 10
