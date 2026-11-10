"""Bug reports filed through the intake (migration 207) never reach a stored label.

A theme or cluster label is shown to anyone who can read one member of the
theme, so a label built from an intake report's text would publish wording only
the intake group may read. Each test seeds the same members, calibrates that the
sampler DOES read the report's text while no intake is configured, then
configures the intake and checks the report's text is gone from the sample (or
the stored label) while the other members' text stays.
"""
import uuid

import numpy as np

from scripts import cluster_claims as C
from scripts import evidential_clustering as E
from scripts import label_themes_llm as L
from tests.theme.conftest import make_embedding

PUBLIC_TEXT = "intake-exclusion public member"
REPORT_TEXT = "intake-exclusion private bug report zebra-quartz"


def _group(cur, agent_id):
    gid = str(uuid.uuid4())
    cur.execute(
        "INSERT INTO groups (id, display_name, did_key, public_key, kind, created_by_agent_id) "
        "VALUES (%s, 'intake', 'did:test:team:' || %s, sha256(%s::bytea), 'team', %s)",
        (gid, gid, gid, agent_id),
    )
    return gid


def _claim(cur, agent_id, content, theme_id=None, owner=None):
    """A claim; group-private and owned by `owner` when given, else as seeded
    elsewhere in this suite (tenancy columns inherited)."""
    if owner is None:
        cur.execute(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, "
            "                    theme_id) "
            "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector, %s) RETURNING id::text",
            (content, content, agent_id, make_embedding(3), theme_id),
        )
    else:
        cur.execute(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, "
            "                    theme_id, visibility, owner_group_id) "
            "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector, %s, 'group', %s) "
            "RETURNING id::text",
            (content, content, agent_id, make_embedding(3), theme_id, owner),
        )
    return cur.fetchone()[0]


def _configure(cur, group):
    cur.execute(
        "INSERT INTO bug_report_intake_settings (intake_group_id) VALUES (%s)", (group,)
    )


def _cleanup(db, ids, group):
    db.rollback()
    with db.cursor() as cur:
        cur.execute("DELETE FROM bug_report_intake_settings")
        cur.execute("DELETE FROM cluster_labels")
        cur.execute("DELETE FROM claim_clusters")
        cur.execute("DELETE FROM claims WHERE id::text = ANY(%s)", (ids,))
        cur.execute("SET LOCAL epigraph.allow_group_delete = 'yes'")
        cur.execute("DELETE FROM groups WHERE id = %s", (group,))
    db.commit()


def test_the_theme_label_sample_leaves_out_intake_reports(db, seed_agent):
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        cur.execute(
            "INSERT INTO claim_themes (label, description, claim_count, centroid) "
            "VALUES ('auto-1', '', 2, %s::vector) RETURNING id",
            (make_embedding(3),),
        )
        theme = cur.fetchone()[0]
        _claim(cur, seed_agent, PUBLIC_TEXT, theme_id=theme)
        _claim(cur, seed_agent, REPORT_TEXT, theme_id=theme, owner=group)

    def sampled():
        [t] = [t for t in L.load_themes_with_samples(db) if t["id"] == str(theme)]
        return [s["content"] for s in t["samples"]]

    # CALIBRATION: no intake configured, so the group's claim is an ordinary one.
    assert sorted(sampled()) == sorted([PUBLIC_TEXT, REPORT_TEXT])
    with db.cursor() as cur:
        _configure(cur, group)
    assert sampled() == [PUBLIC_TEXT]
    db.rollback()  # nothing above was committed


def test_cluster_labels_leave_out_intake_reports(db, seed_agent):
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        ids = [
            _claim(cur, seed_agent, PUBLIC_TEXT),
            _claim(cur, seed_agent, REPORT_TEXT, owner=group),
        ]
    db.commit()
    try:
        reduced = np.zeros((2, 2), dtype=np.float32)
        labels = np.zeros(2, dtype=int)
        centroids = np.zeros((1, 2), dtype=np.float32)

        def label(run_id):
            C.label_clusters(db, ids, reduced, labels, centroids, 1, run_id)
            with db.cursor() as cur:
                cur.execute(
                    "SELECT label FROM cluster_labels WHERE cluster_run_id = %s", (run_id,)
                )
                return cur.fetchone()[0]

        def ds_label(run_id):
            beliefs = {
                cid: {0: {"belief": 0.9, "plausibility": 0.95, "ignorance": 0.05}}
                for cid in ids
            }
            E.store_results(db, ids, beliefs, {}, 1, {}, {}, run_id)
            with db.cursor() as cur:
                cur.execute(
                    "SELECT label FROM cluster_labels WHERE cluster_run_id = %s", (run_id,)
                )
                return cur.fetchone()[0]

        # CALIBRATION: unconfigured, both texts reach both labels.
        for write in (label, ds_label):
            got = write(str(uuid.uuid4()))
            assert PUBLIC_TEXT in got and REPORT_TEXT in got, got

        with db.cursor() as cur:
            _configure(cur, group)
        db.commit()
        for write in (label, ds_label):
            got = write(str(uuid.uuid4()))
            assert PUBLIC_TEXT in got, got
            assert REPORT_TEXT not in got, got
    finally:
        _cleanup(db, ids, group)
