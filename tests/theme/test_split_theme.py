"""Integration tests for splitting one oversized theme by k-means."""
import json

import pytest

from scripts import split_theme as S
from scripts import label_themes_llm as L
from tests.theme.conftest import make_embedding

RUN_ID = "22222222-2222-2222-2222-222222222222"


def _seed_theme(db, agent_id, sizes=(6, 4)):
    """One theme whose members form len(sizes) well-separated groups.

    Group g sits on dominant axis g+1 (make_embedding), so k-means can only
    recover the groups as seeded. Returns (theme_id, [ids of group 0, ...]).
    """
    groups = []
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO claim_themes (label, description, claim_count, properties) "
            "VALUES ('Parent Theme Name', 'whole-theme description', %s, %s::jsonb) "
            "RETURNING id::text",
            (sum(sizes), json.dumps({"source": "cluster_run", "cluster_run_id": RUN_ID,
                                      "cluster_id": 7})),
        )
        theme_id = cur.fetchone()[0]
        for g, n in enumerate(sizes):
            ids = []
            for i in range(n):
                content = f"split-g{g}-{i}"
                cur.execute(
                    "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, theme_id) "
                    "VALUES (%s, sha256(%s::bytea), 0.5, %s, %s::vector, %s) RETURNING id::text",
                    (content, content, agent_id, make_embedding(g + 1), theme_id),
                )
                ids.append(cur.fetchone()[0])
            groups.append(ids)
    db.commit()
    return theme_id, groups


def _theme_of(db, ids):
    with db.cursor() as cur:
        cur.execute("SELECT DISTINCT theme_id::text FROM claims WHERE id = ANY(%s::uuid[])", (ids,))
        return [r[0] for r in cur.fetchall()]


def test_split_moves_each_group_to_its_own_theme(db, seed_agent):
    theme_id, (big, small) = _seed_theme(db, seed_agent)

    parts = S.plan_split(db, theme_id, k=2, min_part=2)
    result = S.apply_split(db, theme_id, {"source": "cluster_run", "cluster_run_id": RUN_ID,
                                          "cluster_id": 7}, parts)

    assert [n for _, n in result] == [6, 4]
    assert _theme_of(db, big) == [theme_id]          # largest part keeps the id
    (new_id,) = _theme_of(db, small)
    assert new_id != theme_id
    with db.cursor() as cur:
        cur.execute("SELECT id::text, label, description, claim_count, centroid IS NULL, properties "
                    "FROM claim_themes ORDER BY claim_count DESC")
        rows = cur.fetchall()
    assert [(r[0], r[3]) for r in rows] == [(theme_id, 6), (new_id, 4)]
    for part, (_, label, desc, _, centroid_null, props) in enumerate(rows):
        assert label == S.placeholder_label(theme_id, part)
        assert L.is_placeholder_label(label)      # a default labelling run names it
        assert desc == ""
        assert not centroid_null
        assert props["split_part"] == part
        assert props["split_of"] == theme_id
        assert (props["cluster_run_id"], props["cluster_id"]) == (RUN_ID, 7)


def test_kept_part_centroid_is_the_mean_of_its_own_members(db, seed_agent):
    theme_id, (big, small) = _seed_theme(db, seed_agent)

    S.apply_split(db, theme_id, {}, S.plan_split(db, theme_id, k=2, min_part=2))

    with db.cursor() as cur:
        cur.execute(
            "SELECT ct.centroid <=> (SELECT avg(embedding) FROM claims WHERE id = ANY(%s::uuid[])) "
            "FROM claim_themes ct WHERE ct.id = %s",
            (big, theme_id),
        )
        assert cur.fetchone()[0] < 1e-6, "kept part's centroid still averages the moved members"


def test_lopsided_split_is_refused_before_any_write(db, seed_agent):
    theme_id, (big, small) = _seed_theme(db, seed_agent)

    with pytest.raises(ValueError, match="smallest part"):
        S.plan_split(db, theme_id, k=2, min_part=5)   # the 4-claim group is too small

    with db.cursor() as cur:
        cur.execute("SELECT count(*), min(label) FROM claim_themes")
        assert cur.fetchone() == (1, "Parent Theme Name")
    assert _theme_of(db, big + small) == [theme_id]
