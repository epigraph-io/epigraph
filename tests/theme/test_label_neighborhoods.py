"""label_themes_llm --neighborhoods names graph neighbourhoods from PUBLIC members only (backlog 01e0b839).

GET /api/v1/graph/themes/:id/expand returns graph_neighborhoods.label as stored,
to every viewer who can read one member of the neighbourhood, so a label built
from a group-private member's text would publish wording only its group may read.
The clustering job stores `neighborhood-N` placeholders (older runs stored the
dominant frame's UUID); this run replaces placeholders in the LATEST run with an
LLM name from public members, gives a neighbourhood with no public member
NO_PUBLIC_MEMBER_LABEL without an LLM call, and leaves real names alone.
"""
import sys
import uuid

import pytest

from scripts import label_themes_llm as L
from tests.theme.conftest import TEST_DSN
from tests.theme.test_label_excludes_intake import PUBLIC_TEXT, _claim, _group

PRIVATE_TEXT = "neighbourhood-label private member heron-garnet"
OLD_RUN_PUBLIC = "older-run public member"


def _run(cur, days_ago):
    cur.execute(
        "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded, completed_at) "
        "VALUES (gen_random_uuid(), 0, false, now() - make_interval(days => %s)) "
        "RETURNING run_id::text",
        (days_ago,),
    )
    return cur.fetchone()[0]


def _theme(cur):
    cur.execute(
        "INSERT INTO claim_themes (label, description, claim_count) "
        "VALUES ('Neighbourhood test theme', '', 0) RETURNING id::text"
    )
    return cur.fetchone()[0]


def _nbr(cur, run, theme, label, members):
    cur.execute(
        "INSERT INTO graph_neighborhoods (run_id, theme_id, label, size) "
        "VALUES (%s, %s, %s, %s) RETURNING id::text",
        (run, theme, label, len(members)),
    )
    nid = cur.fetchone()[0]
    for m in members:
        cur.execute(
            "INSERT INTO claim_neighborhood_membership (run_id, claim_id, neighborhood_id) "
            "VALUES (%s, %s, %s)",
            (run, m, nid),
        )
    return nid


def _label(db, nid):
    with db.cursor() as cur:
        cur.execute("SELECT label FROM graph_neighborhoods WHERE id = %s", (nid,))
        return cur.fetchone()[0]


def _run_labeller(monkeypatch, *extra):
    prompts = []

    def fake_cli(prompt, result_path, cwd, timeout=120):
        prompts.append((prompt, result_path))
        return {"label": "LLM neighbourhood name", "description": "ignored"}

    monkeypatch.setattr(L, "call_claude_cli", fake_cli)
    monkeypatch.delenv("MAINTENANCE_DATABASE_URL", raising=False)
    monkeypatch.setattr(
        sys, "argv", ["label_themes_llm.py", "--database-url", TEST_DSN, "--neighborhoods", *extra]
    )
    L.main()
    return prompts


def _cleanup(db, runs, ids, group, theme):
    db.rollback()
    with db.cursor() as cur:
        cur.execute("DELETE FROM graph_cluster_runs WHERE run_id::text = ANY(%s)", (runs,))
        cur.execute("UPDATE claims SET theme_id = NULL WHERE id::text = ANY(%s)", (ids,))
        cur.execute("DELETE FROM claim_themes WHERE id = %s", (theme,))
        cur.execute("DELETE FROM claims WHERE id::text = ANY(%s)", (ids,))
        cur.execute("SET LOCAL epigraph.allow_group_delete = 'yes'")
        cur.execute("DELETE FROM groups WHERE id = %s", (group,))
    db.commit()


def test_neighbourhoods_of_the_latest_run_are_named_from_public_members_only(
    db, seed_agent, monkeypatch
):
    with db.cursor() as cur:
        group = _group(cur, seed_agent)
        theme = _theme(cur)
        pub = _claim(cur, seed_agent, PUBLIC_TEXT)
        priv = _claim(cur, seed_agent, PRIVATE_TEXT, owner=group, visibility="group")
        priv_only = _claim(cur, seed_agent, f"{PRIVATE_TEXT} 2", owner=group, visibility="group")
        named_member = _claim(cur, seed_agent, "member of a named neighbourhood")
        old_member = _claim(cur, seed_agent, OLD_RUN_PUBLIC)
        ids = [pub, priv, priv_only, named_member, old_member]
        old_run = _run(cur, 2)
        latest = _run(cur, 0)
        mixed = _nbr(cur, latest, theme, "neighborhood-1", [pub, priv])
        private_only = _nbr(cur, latest, theme, str(uuid.uuid4()), [priv_only])
        named = _nbr(cur, latest, theme, "Already Named Neighbourhood", [named_member])
        older = _nbr(cur, old_run, theme, "neighborhood-1", [old_member])
    db.commit()
    try:
        # --dry-run writes nothing and calls no LLM.
        assert _run_labeller(monkeypatch, "--dry-run") == []
        db.rollback()
        assert _label(db, mixed) == "neighborhood-1"

        prompts = _run_labeller(monkeypatch)
        db.rollback()
        # One LLM call: the mixed neighbourhood, quoting its public member only.
        assert len(prompts) == 1, prompts
        prompt, result_path = prompts[0]
        assert PUBLIC_TEXT in prompt
        assert "heron-garnet" not in prompt, prompt
        assert "1 claims" in prompt  # the count is of public members only
        assert "/neighborhood_" in result_path, result_path
        assert _label(db, mixed) == "LLM neighbourhood name"
        # No public member: the placeholder, which a later run re-examines.
        assert _label(db, private_only) == L.NO_PUBLIC_MEMBER_LABEL
        assert L.is_neighborhood_placeholder_label(_label(db, private_only))
        # A real name is kept; an older run is not the one the route serves.
        assert _label(db, named) == "Already Named Neighbourhood"
        assert _label(db, older) == "neighborhood-1"

        # --run-id targets another run explicitly.
        prompts = _run_labeller(monkeypatch, "--run-id", old_run)
        db.rollback()
        assert len(prompts) == 1 and OLD_RUN_PUBLIC in prompts[0][0]
        assert _label(db, older) == "LLM neighbourhood name"
    finally:
        _cleanup(db, [old_run, latest], ids, group, theme)


@pytest.mark.parametrize("label", [
    "neighborhood-1",
    "neighborhood-12",
    str(uuid.uuid4()),
    L.NO_PUBLIC_MEMBER_LABEL,
    "",
    "auto-3",
])
def test_neighbourhood_placeholders_are_relabelled(label):
    assert L.is_neighborhood_placeholder_label(label)


@pytest.mark.parametrize("label", [
    "Graphene Edge States",
    "Protein Folding Intermediates",
])
def test_neighbourhood_names_are_kept(label):
    assert not L.is_neighborhood_placeholder_label(label)


def test_a_newer_bridge_run_is_not_the_run_labelled(db):
    """latest_cluster_run picks the run expand serves: the newest LOUVAIN run.

    POST /api/v1/clusters/build-from-bridges writes algo = 'louvain_bridge'
    rows into the same graph_cluster_runs table; such a run has no
    neighbourhoods and ClusterRunRepository::latest skips it (backlog
    523dcb4f). Both runs are dated in the future so no run another test left
    behind can outrank them, and the bridge run is the newer of the two, so a
    lookup ordered by completed_at alone picks it and fails here.
    """
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded, completed_at) "
            "VALUES (gen_random_uuid(), 0, false, now() + interval '1 day') "
            "RETURNING run_id::text, algo"
        )
        louvain, algo = cur.fetchone()
        cur.execute(
            "INSERT INTO graph_cluster_runs (run_id, cluster_count, degraded, algo, completed_at) "
            "VALUES (gen_random_uuid(), 0, false, 'louvain_bridge', now() + interval '2 days') "
            "RETURNING run_id::text"
        )
        bridge = cur.fetchone()[0]
    db.commit()
    try:
        # The runner inserts without naming algo; migration 028's default is
        # the literal the lookup filters on.
        assert algo == "louvain"
        assert L.latest_cluster_run(db) == louvain, (
            f"the louvain_bridge run {bridge} must not be the run --neighborhoods labels"
        )
    finally:
        db.rollback()
        with db.cursor() as cur:
            cur.execute(
                "DELETE FROM graph_cluster_runs WHERE run_id::text = ANY(%s)", ([louvain, bridge],)
            )
        db.commit()
