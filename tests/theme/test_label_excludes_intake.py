"""Bug reports filed through the intake (migration 207) never reach a stored label.

A theme or cluster label is shown to anyone who can read one member of the
theme, so a label built from an intake report's text would publish wording only
the intake group may read. Each test seeds the same members, calibrates that the
sampler DOES read the report's text while no intake is configured, then
configures the intake and checks the report's text is gone from the sample (or
the stored label) while the other members' text stays.

The reports here are PUBLIC claims owned by the intake group, so the
public-only rule (theme_lib.public_label_source, tested on group-private members
in test_label_public_only.py) does not exclude them and only the intake conjunct
can. A group-private report is excluded by the public-only rule alone.

One test per path from member text to a stored label (theme_lib.public_label_source
names them): label_themes_llm.load_themes_with_samples,
cluster_claims.label_clusters, evidential_clustering.store_results,
refine_clusters.auto_refine (the theme_pipeline grow loop's split labeller) and
refine_clusters.interactive_label (an operator reads members, then types the
sub-labels that are stored).
"""
import uuid

import numpy as np

from scripts import cluster_claims as C
from scripts import evidential_clustering as E
from scripts import label_themes_llm as L
from scripts import refine_clusters as R
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


def _claim(cur, agent_id, content, theme_id=None, owner=None, seed=3, visibility="public"):
    """A claim owned by `owner` with `visibility` when `owner` is given, else as
    seeded elsewhere in this suite (tenancy columns inherited, which on a fresh
    migrated database is public)."""
    if owner is None:
        cur.execute(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, "
            "                    theme_id) "
            "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector, %s) RETURNING id::text",
            (content, content, agent_id, make_embedding(seed), theme_id),
        )
    else:
        cur.execute(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, "
            "                    theme_id, visibility, owner_group_id) "
            "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector, %s, %s, %s) "
            "RETURNING id::text",
            (content, content, agent_id, make_embedding(seed), theme_id, visibility, owner),
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


REFINE_RUN = str(uuid.uuid4())


def _refine_members(cur, agent_id, group, text=REPORT_TEXT, visibility="public"):
    """Cluster 0's members: blob A (8 public, 7 claims owned by `group`) and
    blob B (15 owned by `group` only). Returns (public ids, group-owned ids)."""
    public = [_claim(cur, agent_id, f"{PUBLIC_TEXT} a{i}", seed=0) for i in range(8)]
    owned = [
        _claim(cur, agent_id, f"{text} a{i}", owner=group, seed=0, visibility=visibility)
        for i in range(7)
    ] + [
        _claim(cur, agent_id, f"{text} b{i}", owner=group, seed=50, visibility=visibility)
        for i in range(15)
    ]
    return public, owned


def _place_in_cluster_0(db, ids):
    """(Re)seed `ids` as cluster 0 of REFINE_RUN, clearing any earlier split."""
    with db.cursor() as cur:
        cur.execute("DELETE FROM cluster_labels")
        cur.execute("DELETE FROM claim_clusters")
        for i, cid in enumerate(ids):
            # Distinct boundary ratios: the interactive path orders by them.
            cur.execute(
                "INSERT INTO claim_clusters (claim_id, cluster_id, centroid_distance, "
                "second_centroid_dist, boundary_ratio, silhouette_score, cluster_run_id, "
                "centroid_distances) VALUES (%s,0,0.4,0.5,%s,0.2,%s,%s)",
                (cid, 0.99 - i * 0.01, REFINE_RUN, [0.4, 0.5]),
            )
    db.commit()


def _split(db):
    """{cluster_id: frozenset(member ids)} and {cluster_id: label} of REFINE_RUN."""
    with db.cursor() as cur:
        cur.execute(
            "SELECT cluster_id, array_agg(claim_id::text) FROM claim_clusters "
            "WHERE cluster_run_id = %s GROUP BY cluster_id",
            (REFINE_RUN,),
        )
        parts = {c: frozenset(m) for c, m in cur.fetchall()}
        cur.execute(
            "SELECT cluster_id, label FROM cluster_labels WHERE cluster_run_id = %s",
            (REFINE_RUN,),
        )
        labels = dict(cur.fetchall())
    return parts, labels


def test_auto_refine_labels_leave_out_intake_reports(db, seed_agent, monkeypatch):
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        public, reports = _refine_members(cur, seed_agent, group)
    db.commit()
    ids = public + reports
    asked = []

    def labeller(samples, idx):
        asked.append(list(samples))
        return f"LBL {samples[0]}" if samples else ""

    monkeypatch.setattr(R, "llm_label_subcluster", labeller)
    try:
        # CALIBRATION: unconfigured, the reports' text reaches the labeller.
        _place_in_cluster_0(db, ids)
        before = R.auto_refine(db, cluster_id=0, run_id=REFINE_RUN, min_sub_size=5)
        assert before["split"] is True, before
        assert any(REPORT_TEXT in s for call in asked for s in call), asked
        parts_before, _ = _split(db)

        with db.cursor() as cur:
            _configure(cur, group)
        db.commit()
        asked.clear()
        _place_in_cluster_0(db, ids)
        after = R.auto_refine(db, cluster_id=0, run_id=REFINE_RUN, min_sub_size=5)
        parts, labels = _split(db)

        # The split itself is unchanged: reports still cluster and are reassigned.
        assert after["n_subclusters"] == before["n_subclusters"], (before, after)
        assert set(parts.values()) == set(parts_before.values())
        # No report text reached the labeller or a stored label; public text did.
        assert asked and all(call for call in asked), asked
        assert not any(REPORT_TEXT in s for call in asked for s in call), asked
        assert any(PUBLIC_TEXT in s for call in asked for s in call), asked
        assert labels and not any(REPORT_TEXT in lbl for lbl in labels.values()), labels
        # A sub-cluster of reports only is never sent to the labeller: it keeps
        # the placeholder name.
        only_reports = [c for c, m in parts.items() if m <= set(reports)]
        assert only_reports, parts
        for c in only_reports:
            assert labels[c] == f"cluster-{c}", labels
    finally:
        _cleanup(db, ids, group)


def test_interactive_refinement_never_shows_an_intake_report(db, seed_agent, monkeypatch, capsys):
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        public, reports = _refine_members(cur, seed_agent, group)
    db.commit()
    ids = public + reports
    answers = []

    def operator(_prompt=""):
        # Two sub-label names, then label every claim shown as sub-label 0.
        return answers.pop(0) if answers else "0"

    monkeypatch.setattr("builtins.input", operator)
    try:
        _place_in_cluster_0(db, ids)
        # CALIBRATION: unconfigured, the operator is shown the reports' text.
        answers[:] = ["x,y"]
        R.interactive_label(db, 0, REFINE_RUN)
        assert REPORT_TEXT in capsys.readouterr().err

        with db.cursor() as cur:
            _configure(cur, group)
        db.commit()
        answers[:] = ["x,y"]
        labeled, _, names = R.interactive_label(db, 0, REFINE_RUN)
        shown = capsys.readouterr().err
        assert REPORT_TEXT not in shown
        assert PUBLIC_TEXT in shown
        assert names == ["x", "y"]
        # Every claim the operator labelled is one it was shown.
        assert labeled and set(labeled) <= set(public), labeled
    finally:
        _cleanup(db, ids, group)
