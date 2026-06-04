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
